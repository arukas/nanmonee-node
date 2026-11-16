// Package updater implements the root-side half of a panel-driven agent
// upgrade.
//
// The split is deliberate: the running agent never holds privilege and never
// replaces itself. A separate root binary, installed and enabled by the
// operator, asks the panel what this host should run, downloads and verifies
// the artifacts, flips the `current` symlink atomically and restarts the node
// units. Nothing here is reachable from the node API.
package updater

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Protocol names the checkpoint document so the panel and updater cannot
// silently disagree about its shape.
const Protocol = "nanmonee-updater-v1"

// SupportedMachine is the only CPU architecture a published release targets.
const SupportedMachine = elf.EM_X86_64

// maxArtifactBytes bounds one download. The agent binary is a few tens of
// megabytes; anything near this ceiling is a mistake, not a build.
const maxArtifactBytes = 128 << 20

// maxRedirects bounds release-host redirects (GitHub sends artifacts to another
// https host). Every hop must stay on https.
const maxRedirects = 5

// Config is the updater's owner-only startup document.
type Config struct {
	PanelURL       string `json:"panel_url"`
	VpsID          int64  `json:"vps_id"`
	Token          string `json:"token"`
	ReleaseDir     string `json:"release_dir"`
	StateDir       string `json:"state_dir"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// Load reads and validates the updater config. The file must be owner-only:
// it carries the token that authorizes replacing a binary on this host.
func Load(path string) (Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Config{}, fmt.Errorf("read updater config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Config{}, errors.New("the updater config must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Config{}, fmt.Errorf("the updater config %s is readable by other users; run: chmod 0400 %s", path, path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read updater config: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("parse updater config: %w", err)
	}
	if decoder.More() {
		return Config{}, errors.New("the updater config carries trailing content")
	}

	if config.VpsID <= 0 {
		return Config{}, errors.New("the updater config requires a positive vps_id")
	}
	if len(config.Token) != 64 {
		return Config{}, errors.New("the updater config requires a 64 character hex token")
	}
	if config.ReleaseDir == "" {
		config.ReleaseDir = "/opt/nanmonee-node"
	}
	if config.StateDir == "" {
		config.StateDir = "/var/lib/nanmonee-node-updater"
	}
	if !filepath.IsAbs(config.ReleaseDir) || !filepath.IsAbs(config.StateDir) {
		return Config{}, errors.New("release_dir and state_dir must be absolute paths")
	}
	if config.TimeoutSeconds <= 0 || config.TimeoutSeconds > 600 {
		config.TimeoutSeconds = 120
	}

	return config, nil
}

// Artifact is one downloadable file plus the digest it must match.
type Artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// Instruction is the panel's answer: either `noop` or a release to install.
type Instruction struct {
	RequestID    *string             `json:"request_id"`
	Action       string              `json:"action"`
	Reason       string              `json:"reason"`
	Version      string              `json:"version"`
	Artifacts    map[string]Artifact `json:"artifacts"`
	RestartUnits []string            `json:"restart_units"`
}

// Install reports that the panel wants this host on Version.
func (i Instruction) Install() bool { return i.Action == "install" }

// Result is the outcome the updater reports back for one request.
type Result struct {
	RequestID        string  `json:"request_id"`
	Outcome          string  `json:"outcome"`
	InstalledVersion *string `json:"installed_version"`
	Error            *string `json:"error"`
}

// CheckRequest is the body posted to the panel.
type CheckRequest struct {
	UpdaterVersion string  `json:"updater_version"`
	CurrentVersion *string `json:"current_version"`
	CurrentRelease *string `json:"current_release"`
	Result         *Result `json:"result"`
}

// Client talks to the panel's updater endpoint.
type Client struct {
	base  string
	vpsID int64
	token string
	// Transport is the TLS configuration used for both the panel and the release
	// host. It is a field so an acceptance run against a private CA does not need
	// a rebuild; nil means the default transport.
	Transport http.RoundTripper
	// Timeout bounds one request; zero means the config default.
	Timeout time.Duration
}

// NewClient validates the endpoint and returns a client that refuses to send
// the token anywhere but https.
func NewClient(config Config) (*Client, error) {
	if !strings.HasPrefix(config.PanelURL, "https://") {
		return nil, errors.New("panel_url must be an https URL")
	}
	if strings.HasSuffix(config.PanelURL, "/") {
		config.PanelURL = strings.TrimSuffix(config.PanelURL, "/")
	}

	return &Client{
		base:    config.PanelURL,
		vpsID:   config.VpsID,
		token:   config.Token,
		Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
	}, nil
}

// requestTimeout is the per-request bound, defaulted for a test-built client.
func (c *Client) requestTimeout() time.Duration {
	if c.Timeout <= 0 {
		return 120 * time.Second
	}

	return c.Timeout
}

// panelHTTP returns a client that never follows a redirect, because the bearer
// token must not reach another host.
func (c *Client) panelHTTP() *http.Client {
	return &http.Client{
		Timeout:   c.requestTimeout(),
		Transport: c.Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Check sends this host's identity and, when present, the result of the last
// request, and returns what the panel wants next.
func (c *Client) Check(payload CheckRequest) (Instruction, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return Instruction{}, err
	}
	endpoint := c.base + "/api/vps/updater/v1/check"
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return Instruction{}, errors.New("build the updater request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "nanmonee-node-updater/"+Version)
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("X-Nanmonee-Vps-Id", strconv.FormatInt(c.vpsID, 10))

	response, err := c.panelHTTP().Do(request)
	if err != nil {
		// *url.Error embeds the URL; never surface it with the token attached.
		return Instruction{}, errors.New("the panel is unreachable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return Instruction{}, fmt.Errorf("the panel answered status %d", response.StatusCode)
	}

	var instruction Instruction
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&instruction); err != nil {
		return Instruction{}, fmt.Errorf("parse the panel answer: %w", err)
	}
	switch instruction.Action {
	case "noop", "install":
	default:
		return Instruction{}, fmt.Errorf("the panel asked for an unknown action %q", instruction.Action)
	}

	return instruction, nil
}

// Release is one staged, verified release directory.
type Release struct {
	Version string
	Dir     string
}

// CurrentVersion reads the version a `current` symlink points at, so the updater
// can report what the host actually runs rather than what it remembers doing.
func CurrentVersion(releaseDir string) (version, release string, err error) {
	target, err := os.Readlink(filepath.Join(releaseDir, "current"))
	if err != nil {
		return "", "", err
	}
	return filepath.Base(target), target, nil
}

// Stage downloads and verifies every artifact into a fresh directory. The
// release becomes visible only when Activate renames it, so a failed download
// leaves nothing half-installed under releases/.
func (c *Client) Stage(releaseDir, version string, artifacts map[string]Artifact) (Release, error) {
	if version == "" || strings.ContainsAny(version, "/\\") || version == "." || version == ".." {
		return Release{}, errors.New("the panel named an unusable version")
	}
	releases := filepath.Join(releaseDir, "releases")
	if err := os.MkdirAll(releases, 0o755); err != nil {
		return Release{}, fmt.Errorf("create the releases directory: %w", err)
	}
	// The updater unit runs with UMask=0077, so every mode passed to MkdirAll or
	// OpenFile is masked down to 0700. Node units run as an unprivileged user
	// and would then fail to traverse or exec the release, so the modes that
	// must be readable are set explicitly instead of relying on the umask.
	if err := os.Chmod(releases, 0o755); err != nil {
		return Release{}, fmt.Errorf("make the releases directory readable: %w", err)
	}

	staging, err := os.MkdirTemp(releases, "."+version+".incoming-")
	if err != nil {
		return Release{}, fmt.Errorf("create a staging directory: %w", err)
	}
	// MkdirTemp creates 0700. The node units run as an unprivileged user and
	// must traverse this directory after the rename, so widen it here rather
	// than leaving a published release nobody but root can exec.
	if err := os.Chmod(staging, 0o755); err != nil {
		_ = os.RemoveAll(staging)
		return Release{}, fmt.Errorf("make the staging directory readable: %w", err)
	}
	// A failed stage removes only the staging directory, never a published one.
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(staging)
		}
	}()

	binary := filepath.Join(staging, "bin")
	if err := os.Mkdir(binary, 0o755); err != nil {
		return Release{}, fmt.Errorf("create the staging bin directory: %w", err)
	}
	if err := os.Chmod(binary, 0o755); err != nil {
		return Release{}, fmt.Errorf("make the staging bin directory readable: %w", err)
	}
	for name, artifact := range artifacts {
		if name != filepath.Base(name) || name == "" {
			return Release{}, fmt.Errorf("the panel named an unusable artifact %q", name)
		}
		if len(artifact.SHA256) != 64 {
			return Release{}, fmt.Errorf("the panel sent no digest for %s", name)
		}
		destination := filepath.Join(binary, name)
		if err := c.download(artifact, destination); err != nil {
			return Release{}, err
		}
	}
	if _, err := os.Stat(filepath.Join(binary, "nanmonee-node")); err != nil {
		return Release{}, errors.New("the release does not contain nanmonee-node")
	}

	final := filepath.Join(releases, version)
	// A previous attempt may have published this version already; the panel only
	// dispatches a version the host is not running, so replacing it is safe.
	if err := os.RemoveAll(final); err != nil {
		return Release{}, fmt.Errorf("clear the previous copy of this release: %w", err)
	}
	if err := os.Rename(staging, final); err != nil {
		return Release{}, fmt.Errorf("publish the release directory: %w", err)
	}
	success = true

	return Release{Version: version, Dir: final}, nil
}

// download streams one artifact to destination, verifying the digest as it
// writes so a corrupted body never reaches the filesystem complete.
func (c *Client) download(artifact Artifact, destination string) error {
	if !strings.HasPrefix(artifact.URL, "https://") {
		return errors.New("release artifacts must be served over https")
	}
	client := &http.Client{
		Timeout:   c.requestTimeout(),
		Transport: c.Transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			// Redirects are allowed for object stores, but https only.
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			if request.URL.Scheme != "https" {
				return errors.New("a redirect left https")
			}
			return nil
		},
	}

	response, err := client.Get(artifact.URL)
	if err != nil {
		return fmt.Errorf("download %s: %w", filepath.Base(destination), err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: the release host answered status %d", filepath.Base(destination), response.StatusCode)
	}

	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(destination), err)
	}

	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, digest), io.LimitReader(response.Body, maxArtifactBytes+1))
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(destination), copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(destination), closeErr)
	}
	// UMask=0077 turns the 0755 above into 0600; the node user must be able to
	// execute what it is restarted with.
	if err := os.Chmod(destination, 0o755); err != nil {
		return fmt.Errorf("make %s executable: %w", filepath.Base(destination), err)
	}
	if written > maxArtifactBytes {
		return fmt.Errorf("%s exceeds the size limit", filepath.Base(destination))
	}
	if !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), artifact.SHA256) {
		return fmt.Errorf("%s does not match its digest", filepath.Base(destination))
	}

	// A digest proves the bytes are the ones the panel named; the ELF header
	// proves they are a binary this machine can execute. Both are cheap, and a
	// wrong-architecture release would otherwise only fail at restart time.
	if strings.HasPrefix(filepath.Base(destination), "nanmonee-") {
		if err := checkExecutable(destination); err != nil {
			return err
		}
	}

	return nil
}

// checkExecutable confirms the file is an ELF executable built for this
// architecture.
func checkExecutable(path string) error {
	file, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("%s is not an executable binary", filepath.Base(path))
	}
	defer file.Close()
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return fmt.Errorf("%s is not an executable binary", filepath.Base(path))
	}
	if file.Machine != SupportedMachine {
		return fmt.Errorf("%s targets %s, but this host runs x86_64", filepath.Base(path), file.Machine)
	}

	return nil
}

// Activate points `current` at the staged release. The symlink is replaced by
// renaming a sibling into place, so a reader never observes a missing current.
func Activate(releaseDir string, release Release) error {
	current := filepath.Join(releaseDir, "current")
	temporary := filepath.Join(releaseDir, ".current."+strconv.Itoa(os.Getpid()))

	_ = os.Remove(temporary)
	if err := os.Symlink(filepath.Join("releases", release.Version), temporary); err != nil {
		return fmt.Errorf("create the new current symlink: %w", err)
	}
	if err := os.Rename(temporary, current); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("replace the current symlink: %w", err)
	}

	return nil
}

// Restore points `current` back at a previous target after a failed restart.
func Restore(releaseDir, target string) error {
	if target == "" {
		return errors.New("no previous release to restore")
	}
	current := filepath.Join(releaseDir, "current")
	temporary := filepath.Join(releaseDir, ".current."+strconv.Itoa(os.Getpid()))

	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return fmt.Errorf("create the rollback symlink: %w", err)
	}
	if err := os.Rename(temporary, current); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("restore the current symlink: %w", err)
	}

	return nil
}
