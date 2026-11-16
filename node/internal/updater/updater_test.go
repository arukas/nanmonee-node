package updater

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// artifactBytes builds the smallest thing that parses as an x86_64 ELF
// executable, which is all checkExecutable inspects.
func artifactBytes(t *testing.T) []byte {
	t.Helper()
	header := make([]byte, 64)
	copy(header[0:4], []byte{0x7f, 'E', 'L', 'F'})
	header[4] = 2                                    // ELFCLASS64
	header[5] = 1                                    // ELFDATA2LSB
	header[6] = 1                                    // EV_CURRENT
	binary.LittleEndian.PutUint16(header[16:18], 2)  // ET_EXEC
	binary.LittleEndian.PutUint16(header[18:20], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(header[20:24], 1)  // version
	binary.LittleEndian.PutUint16(header[52:54], 64) // ehsize

	return header
}

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)

	return hex.EncodeToString(sum[:])
}

// writeConfig writes an owner-only config file and returns its path.
func writeConfig(t *testing.T, config Config, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "updater.json")
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// os.WriteFile honours the umask, so set the mode explicitly.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod config: %v", err)
	}

	return path
}

func TestLoadRequiresAnOwnerOnlyConfig(t *testing.T) {
	config := Config{PanelURL: "https://panel.example", VpsID: 4, Token: strings.Repeat("a", 64)}

	if _, err := Load(writeConfig(t, config, 0o644)); err == nil {
		t.Fatal("a group or world readable config must be refused")
	}

	loaded, err := Load(writeConfig(t, config, 0o400))
	if err != nil {
		t.Fatalf("load owner-only config: %v", err)
	}
	if loaded.ReleaseDir != "/opt/nanmonee-node" || loaded.StateDir != "/var/lib/nanmonee-node-updater" {
		t.Fatalf("defaults = %+v", loaded)
	}
	if loaded.TimeoutSeconds != 120 {
		t.Fatalf("timeout = %d, want the default", loaded.TimeoutSeconds)
	}
}

func TestLoadRejectsUnknownFieldsAndBadIdentity(t *testing.T) {
	base := Config{PanelURL: "https://panel.example", VpsID: 4, Token: strings.Repeat("a", 64)}

	tests := map[string]func() string{
		"unknown field": func() string {
			path := writeConfig(t, base, 0o400)
			content, _ := os.ReadFile(path)
			var document map[string]any
			_ = json.Unmarshal(content, &document)
			document["extra"] = true
			updated, _ := json.Marshal(document)
			_ = os.WriteFile(path, updated, 0o400)

			return path
		},
		"short token": func() string {
			config := base
			config.Token = "abc"

			return writeConfig(t, config, 0o400)
		},
		"zero vps": func() string {
			config := base
			config.VpsID = 0

			return writeConfig(t, config, 0o400)
		},
		"relative release dir": func() string {
			config := base
			config.ReleaseDir = "opt/nanmonee-node"

			return writeConfig(t, config, 0o400)
		},
	}

	for name, make := range tests {
		if _, err := Load(make()); err == nil {
			t.Fatalf("%s: an invalid config was accepted", name)
		}
	}
}

func TestNewClientRequiresHTTPS(t *testing.T) {
	if _, err := NewClient(Config{PanelURL: "http://panel.example", VpsID: 1, Token: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("a plain http panel URL must be refused")
	}
}

func TestCheckSendsIdentityAndParsesAnInstruction(t *testing.T) {
	var received CheckRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Nanmonee-Vps-Id") != "7" || !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing updater identity headers")
		}
		_ = json.NewDecoder(request.Body).Decode(&received)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"request_id":"6b0f0f3e-1f1e-4e5a-9d3f-0a1b2c3d4e5f","action":"install","version":"0.11.0","artifacts":{"nanmonee-node":{"url":"https://example.test/nanmonee-node","sha256":"abc"}},"restart_units":["nanmonee-node@1.service"]}`)
	}))
	defer server.Close()

	client, err := NewClient(Config{PanelURL: server.URL, VpsID: 7, Token: strings.Repeat("b", 64)})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.Transport = server.Client().Transport

	instruction, err := client.Check(CheckRequest{UpdaterVersion: Version, CurrentVersion: optional("0.10.0-n1")})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !instruction.Install() || instruction.Version != "0.11.0" {
		t.Fatalf("instruction = %+v", instruction)
	}
	if received.CurrentVersion == nil || *received.CurrentVersion != "0.10.0-n1" {
		t.Fatalf("the panel did not receive the current version: %+v", received)
	}
	if len(instruction.RestartUnits) != 1 || instruction.RestartUnits[0] != "nanmonee-node@1.service" {
		t.Fatalf("restart units = %v", instruction.RestartUnits)
	}
}

func TestCheckRejectsAnUnknownAction(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"action":"delete-everything"}`)
	}))
	defer server.Close()

	client, _ := NewClient(Config{PanelURL: server.URL, VpsID: 1, Token: strings.Repeat("c", 64)})
	client.Transport = server.Client().Transport

	if _, err := client.Check(CheckRequest{UpdaterVersion: Version}); err == nil {
		t.Fatal("an unknown action must be refused")
	}
}

func TestCheckDoesNotFollowRedirects(t *testing.T) {
	redirected := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/vps/updater/v1/check" {
			http.Redirect(writer, request, "https://elsewhere.test/steal", http.StatusTemporaryRedirect)

			return
		}
		redirected = true
	}))
	defer server.Close()

	client, _ := NewClient(Config{PanelURL: server.URL, VpsID: 1, Token: strings.Repeat("d", 64)})
	client.Transport = server.Client().Transport

	if _, err := client.Check(CheckRequest{UpdaterVersion: Version}); err == nil {
		t.Fatal("a redirect must fail the check")
	}
	if redirected {
		t.Fatal("the token followed a redirect")
	}
}

func TestStageDownloadsVerifiesAndPublishes(t *testing.T) {
	// The updater unit runs with UMask=0077; reproduce it so a mode that only
	// survives under the test runner's default umask cannot pass this test.
	previous := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previous) })

	binary := artifactBytes(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/nanmonee-node":
			_, _ = writer.Write(binary)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	releaseDir := t.TempDir()
	client, _ := NewClient(Config{PanelURL: server.URL, VpsID: 1, Token: strings.Repeat("e", 64)})
	client.Transport = server.Client().Transport

	release, err := client.Stage(releaseDir, "0.11.0", map[string]Artifact{
		"nanmonee-node": {URL: server.URL + "/nanmonee-node", SHA256: digestOf(binary)},
	})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if release.Version != "0.11.0" {
		t.Fatalf("release = %+v", release)
	}
	staged, err := os.ReadFile(filepath.Join(release.Dir, "bin", "nanmonee-node"))
	if err != nil {
		t.Fatalf("read staged binary: %v", err)
	}
	if !bytes.Equal(staged, binary) {
		t.Fatal("the staged binary differs from the downloaded one")
	}
	// Nothing else may be left behind: a failed attempt must not accumulate
	// staging directories next to published releases.
	entries, err := os.ReadDir(filepath.Join(releaseDir, "releases"))
	if err != nil {
		t.Fatalf("list releases: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "0.11.0" {
		t.Fatalf("releases = %v", entries)
	}

	// The node units run as an unprivileged user: a published release whose
	// directories or binary stay 0700 would make every restart fail at exec.
	for _, path := range []string{
		filepath.Join(releaseDir, "releases"),
		filepath.Join(releaseDir, "releases", "0.11.0"),
		filepath.Join(release.Dir, "bin"),
		filepath.Join(release.Dir, "bin", "nanmonee-node"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Fatalf("%s mode = %o, want 755", path, info.Mode().Perm())
		}
	}
}

func TestStageRejectsABadDigestAndLeavesNothingBehind(t *testing.T) {
	binary := artifactBytes(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(binary)
	}))
	defer server.Close()

	releaseDir := t.TempDir()
	client, _ := NewClient(Config{PanelURL: server.URL, VpsID: 1, Token: strings.Repeat("f", 64)})
	client.Transport = server.Client().Transport

	_, err := client.Stage(releaseDir, "0.11.0", map[string]Artifact{
		"nanmonee-node": {URL: server.URL + "/nanmonee-node", SHA256: strings.Repeat("0", 64)},
	})
	if err == nil {
		t.Fatal("a digest mismatch must fail the stage")
	}
	entries, _ := os.ReadDir(filepath.Join(releaseDir, "releases"))
	if len(entries) != 0 {
		t.Fatalf("a failed stage left %v behind", entries)
	}
}

func TestStageRejectsNonExecutablePayloads(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "#!/bin/sh\necho hi\n")
	}))
	defer server.Close()

	client, _ := NewClient(Config{PanelURL: server.URL, VpsID: 1, Token: strings.Repeat("1", 64)})
	client.Transport = server.Client().Transport

	payload := []byte("#!/bin/sh\necho hi\n")
	_, err := client.Stage(t.TempDir(), "0.11.0", map[string]Artifact{
		"nanmonee-node": {URL: server.URL + "/nanmonee-node", SHA256: digestOf(payload)},
	})
	if err == nil {
		t.Fatal("a script must not be installed as the agent binary")
	}
}

func TestStageRejectsUnusableNames(t *testing.T) {
	client, _ := NewClient(Config{PanelURL: "https://panel.test", VpsID: 1, Token: strings.Repeat("2", 64)})

	for _, version := range []string{"", "..", "a/b", `a\b`} {
		if _, err := client.Stage(t.TempDir(), version, nil); err == nil {
			t.Fatalf("version %q was accepted", version)
		}
	}
	if _, err := client.Stage(t.TempDir(), "0.11.0", map[string]Artifact{
		"../evil": {URL: "https://example.test/x", SHA256: strings.Repeat("a", 64)},
	}); err == nil {
		t.Fatal("an artifact name escaping the release directory was accepted")
	}
}

func TestActivateAndRestoreFlipCurrentAtomically(t *testing.T) {
	releaseDir := t.TempDir()
	for _, version := range []string{"0.10.0-n1", "0.11.0"} {
		if err := os.MkdirAll(filepath.Join(releaseDir, "releases", version, "bin"), 0o755); err != nil {
			t.Fatalf("prepare release: %v", err)
		}
	}
	if err := Activate(releaseDir, Release{Version: "0.10.0-n1"}); err != nil {
		t.Fatalf("activate: %v", err)
	}
	version, target, err := CurrentVersion(releaseDir)
	if err != nil || version != "0.10.0-n1" || target != "releases/0.10.0-n1" {
		t.Fatalf("current = %q / %q / %v", version, target, err)
	}

	if err := Activate(releaseDir, Release{Version: "0.11.0"}); err != nil {
		t.Fatalf("re-activate: %v", err)
	}
	if version, _, _ := CurrentVersion(releaseDir); version != "0.11.0" {
		t.Fatalf("current = %q, want the new release", version)
	}

	if err := Restore(releaseDir, "releases/0.10.0-n1"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if version, _, _ := CurrentVersion(releaseDir); version != "0.10.0-n1" {
		t.Fatalf("current = %q, want the restored release", version)
	}
}

func TestValidUnitAcceptsOnlyThisProjectsInstances(t *testing.T) {
	for _, unit := range []string{"nanmonee-node@1.service", "nanmonee-node@42.service"} {
		if !validUnit(unit) {
			t.Fatalf("%q was rejected", unit)
		}
	}
	for _, unit := range []string{
		"nanmonee-node@.service", "nanmonee-node@1.service --no-block", "ssh.service",
		"nanmonee-node@1;reboot.service", "nanmonee-node@a.service", "",
	} {
		if validUnit(unit) {
			t.Fatalf("%q was accepted", unit)
		}
	}
}

// newTestRunner wires a runner against a temporary release tree and records the
// systemd calls it would have made.
func newTestRunner(t *testing.T, releaseDir string, restart func(string) error) (*Runner, *[]string, *[]string) {
	t.Helper()
	restarted := &[]string{}
	checked := &[]string{}

	runner := &Runner{
		Config:     Config{ReleaseDir: releaseDir},
		ReleaseDir: releaseDir,
		Restart: func(unit string) error {
			*restarted = append(*restarted, unit)
			if restart != nil {
				return restart(unit)
			}

			return nil
		},
		HealthCheck: func(unit string) error {
			*checked = append(*checked, unit)

			return nil
		},
		Log: log.New(io.Discard, "", 0),
	}

	return runner, restarted, checked
}

func TestInstallActivatesAndRestartsEveryUnit(t *testing.T) {
	binary := artifactBytes(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(binary)
	}))
	defer server.Close()

	releaseDir := t.TempDir()
	client, _ := NewClient(Config{PanelURL: server.URL, VpsID: 1, Token: strings.Repeat("3", 64)})
	client.Transport = server.Client().Transport

	runner, restarted, checked := newTestRunner(t, releaseDir, nil)
	runner.Client = client

	requestID := "0e6d1a2b-3c4d-5e6f-7a8b-9c0d1e2f3a4b"
	result := runner.install(Instruction{
		RequestID:    &requestID,
		Action:       "install",
		Version:      "0.11.0",
		Artifacts:    map[string]Artifact{"nanmonee-node": {URL: server.URL + "/bin", SHA256: digestOf(binary)}},
		RestartUnits: []string{"nanmonee-node@1.service", "nanmonee-node@2.service"},
	}, "")

	if result.Outcome != "succeeded" || result.InstalledVersion == nil || *result.InstalledVersion != "0.11.0" {
		t.Fatalf("result = %+v", result)
	}
	if len(*restarted) != 2 || len(*checked) != 2 {
		t.Fatalf("restarted %v, checked %v", *restarted, *checked)
	}
	if version, _, _ := CurrentVersion(releaseDir); version != "0.11.0" {
		t.Fatalf("current = %q", version)
	}
}

func TestAFailedRestartRollsBackToThePreviousRelease(t *testing.T) {
	binary := artifactBytes(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(binary)
	}))
	defer server.Close()

	releaseDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(releaseDir, "releases", "0.10.0-n1", "bin"), 0o755); err != nil {
		t.Fatalf("prepare the previous release: %v", err)
	}
	if err := Activate(releaseDir, Release{Version: "0.10.0-n1"}); err != nil {
		t.Fatalf("activate the previous release: %v", err)
	}

	client, _ := NewClient(Config{PanelURL: server.URL, VpsID: 1, Token: strings.Repeat("4", 64)})
	client.Transport = server.Client().Transport

	failed := false
	runner, _, _ := newTestRunner(t, releaseDir, func(string) error {
		if !failed {
			failed = true

			return errors.New("unit refused to start")
		}

		return nil
	})
	runner.Client = client

	requestID := "1f7e2b3c-4d5e-6f70-8192-a3b4c5d6e7f8"
	result := runner.install(Instruction{
		RequestID:    &requestID,
		Action:       "install",
		Version:      "0.11.0",
		Artifacts:    map[string]Artifact{"nanmonee-node": {URL: server.URL + "/bin", SHA256: digestOf(binary)}},
		RestartUnits: []string{"nanmonee-node@1.service"},
	}, "releases/0.10.0-n1")

	if result.Outcome != "failed" || result.Error == nil || !strings.Contains(*result.Error, "refused to start") {
		t.Fatalf("result = %+v", result)
	}
	if version, _, _ := CurrentVersion(releaseDir); version != "0.10.0-n1" {
		t.Fatalf("current = %q, want the rollback target", version)
	}
}

func TestInstallReportsWhenThereIsNoPreviousReleaseToRollBackTo(t *testing.T) {
	binary := artifactBytes(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(binary)
	}))
	defer server.Close()

	releaseDir := t.TempDir()
	client, _ := NewClient(Config{PanelURL: server.URL, VpsID: 1, Token: strings.Repeat("5", 64)})
	client.Transport = server.Client().Transport

	runner, _, _ := newTestRunner(t, releaseDir, func(string) error { return errors.New("boom") })
	runner.Client = client

	requestID := "2a8f3c4d-5e6f-7081-92a3-b4c5d6e7f809"
	result := runner.install(Instruction{
		RequestID:    &requestID,
		Action:       "install",
		Version:      "0.11.0",
		Artifacts:    map[string]Artifact{"nanmonee-node": {URL: server.URL + "/bin", SHA256: digestOf(binary)}},
		RestartUnits: []string{"nanmonee-node@1.service"},
	}, "")

	if result.Outcome != "failed" || result.Error == nil || !strings.Contains(*result.Error, "rollback failed") {
		t.Fatalf("result = %+v", result)
	}
}

func TestInstallRefusesAUnitThePanelDidNotOwn(t *testing.T) {
	binary := artifactBytes(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(binary)
	}))
	defer server.Close()

	releaseDir := t.TempDir()
	client, _ := NewClient(Config{PanelURL: server.URL, VpsID: 1, Token: strings.Repeat("6", 64)})
	client.Transport = server.Client().Transport

	runner, restarted, _ := newTestRunner(t, releaseDir, nil)
	runner.Client = client

	requestID := "3b9a4d5e-6f70-8192-a3b4-c5d6e7f80912"
	result := runner.install(Instruction{
		RequestID: &requestID,
		Action:    "install",
		Version:   "0.11.0",
		Artifacts: map[string]Artifact{"nanmonee-node": {URL: server.URL + "/bin", SHA256: digestOf(binary)}},
		// Only this project's own instances may be restarted.
		RestartUnits: []string{"ssh.service"},
	}, "")

	if result.Outcome != "failed" || len(*restarted) != 0 {
		t.Fatalf("result = %+v, restarted %v", result, *restarted)
	}
}
