package runtime

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	testUUIDA = "11111111-1111-4111-8111-111111111111"
	testUUIDB = "22222222-2222-4222-8222-222222222222"
	testUUIDC = "33333333-3333-4333-8333-333333333333"
)

type fakeKernel struct {
	mu           sync.Mutex
	users        []kernelUser
	updateErr    error
	updates      int
	beforeUpdate func()
	closed       bool
}

func (k *fakeKernel) UpdateUsers(users []kernelUser) error {
	if k.beforeUpdate != nil {
		k.beforeUpdate()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.updateErr != nil {
		return k.updateErr
	}
	k.updates++
	k.users = append([]kernelUser(nil), users...)
	return nil
}

func (k *fakeKernel) Close() error {
	k.mu.Lock()
	k.closed = true
	k.mu.Unlock()
	return nil
}

type fakeKernelFactory struct {
	mu      sync.Mutex
	kernels []*fakeKernel
	fail    error
}

func (f *fakeKernelFactory) make(_ context.Context, _ Config, users []kernelUser, _ *connectionTracker) (kernel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	kernel := &fakeKernel{users: append([]kernelUser(nil), users...)}
	f.kernels = append(f.kernels, kernel)
	return kernel, nil
}

func testConfig() VlessConfig {
	return VlessConfig{
		Listen:            "127.0.0.1",
		Port:              31001,
		ServerName:        "www.apple.com",
		HandshakeServer:   "www.apple.com",
		HandshakePort:     443,
		RealityPrivateKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		RealityShortID:    "0123456789abcdef",
	}
}

func newTestRuntime(t *testing.T) (*Runtime, *fakeKernelFactory) {
	t.Helper()
	factory := new(fakeKernelFactory)
	runtime, err := newRuntimeWithFactory(VlessRuntimeConfig(testConfig()), factory.make)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime, factory
}

func applyInput(runtime *Runtime, revision uint64, users ...User) ApplyInput {
	config := VlessRuntimeConfig(testConfig())
	return ApplyInput{
		ExpectedRuntimeID:     runtime.Status().RuntimeID,
		ExpectedStateRevision: revision,
		Config:                &config,
		Users:                 &users,
	}
}

func TestEmptyStartApplyRotateRevokeRestoreAndCumulativeUsage(t *testing.T) {
	runtime, factory := newTestRuntime(t)
	status := runtime.Status()
	if status.State != StateEmpty || status.StateRevision != 0 || status.RuntimeID == "" || status.ConfigSHA256 == "" || status.AuthorizationSHA256 == "" {
		t.Fatalf("invalid empty status: %+v", status)
	}

	status, err := runtime.Apply(context.Background(), applyInput(runtime, 0, User{MemberID: 1, UUID: testUUIDA}, User{MemberID: 2, UUID: testUUIDB}))
	if err != nil || status.State != StateRunning || status.StateRevision != 1 {
		t.Fatalf("first apply failed: %+v, %v", status, err)
	}
	firstAuthorization := status.AuthorizationSHA256
	status, err = runtime.Apply(context.Background(), applyInput(runtime, 1, User{MemberID: 1, UUID: testUUIDA}, User{MemberID: 2, UUID: testUUIDB}))
	if err != nil || status.StateRevision != 1 || factory.kernels[0].updateErr != nil {
		t.Fatalf("idempotent apply reloaded or failed: %+v, %v", status, err)
	}

	runtime.tracker.mu.Lock()
	runtime.tracker.usage[1].upload.add(17)
	runtime.tracker.usage[1].download.add(19)
	runtime.tracker.mu.Unlock()

	rotated, err := runtime.Apply(context.Background(), applyInput(runtime, 1, User{MemberID: 1, UUID: testUUIDC}, User{MemberID: 2, UUID: testUUIDB}))
	if err != nil || rotated.StateRevision != 2 || rotated.AuthorizationSHA256 == firstAuthorization {
		t.Fatalf("rotation failed: %+v, %v", rotated, err)
	}
	revoked, err := runtime.Apply(context.Background(), applyInput(runtime, 2, User{MemberID: 2, UUID: testUUIDB}))
	if err != nil || revoked.StateRevision != 3 {
		t.Fatalf("revocation failed: %+v, %v", revoked, err)
	}
	restored, err := runtime.Apply(context.Background(), applyInput(runtime, 3, User{MemberID: 1, UUID: testUUIDC}, User{MemberID: 2, UUID: testUUIDB}))
	if err != nil || restored.StateRevision != 4 {
		t.Fatalf("restore failed: %+v, %v", restored, err)
	}
	usage, err := runtime.Usage()
	if err != nil || usage.RuntimeID != status.RuntimeID || usage.Members[1] != [2]int64{17, 19} {
		t.Fatalf("cumulative usage changed across updates: %+v, %v", usage, err)
	}
}

func TestApplyRejectsInvalidAndStaleSnapshotsWithoutSideEffects(t *testing.T) {
	runtime, _ := newTestRuntime(t)
	valid := applyInput(runtime, 0, User{MemberID: 1, UUID: testUUIDA})
	if _, err := runtime.Apply(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	before := runtime.Status()

	tests := map[string]func(ApplyInput) ApplyInput{
		"missing config": func(input ApplyInput) ApplyInput { input.Config = nil; return input },
		"missing users":  func(input ApplyInput) ApplyInput { input.Users = nil; return input },
		"invalid uuid":   func(input ApplyInput) ApplyInput { (*input.Users)[0].UUID = "not-a-uuid"; return input },
		"duplicate member": func(input ApplyInput) ApplyInput {
			*input.Users = append(*input.Users, User{MemberID: 1, UUID: testUUIDB})
			return input
		},
		"duplicate credential": func(input ApplyInput) ApplyInput {
			*input.Users = append(*input.Users, User{MemberID: 2, UUID: testUUIDA})
			return input
		},
		"stale revision": func(input ApplyInput) ApplyInput { input.ExpectedStateRevision = 0; return input },
		"stale runtime":  func(input ApplyInput) ApplyInput { input.ExpectedRuntimeID = "old-runtime"; return input },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := applyInput(runtime, 1, User{MemberID: 1, UUID: testUUIDA})
			_, err := runtime.Apply(context.Background(), mutate(input))
			if err == nil {
				t.Fatal("invalid snapshot was accepted")
			}
			after := runtime.Status()
			if after.StateRevision != before.StateRevision || after.AuthorizationSHA256 != before.AuthorizationSHA256 || after.ConfigSHA256 != before.ConfigSHA256 {
				t.Fatalf("rejected snapshot changed state: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestFailedHotUpdateDoesNotReviveRemovedIdentity(t *testing.T) {
	runtime, factory := newTestRuntime(t)
	if _, err := runtime.Apply(context.Background(), applyInput(runtime, 0, User{MemberID: 1, UUID: testUUIDA}, User{MemberID: 2, UUID: testUUIDB})); err != nil {
		t.Fatal(err)
	}
	bTCP, bUDP, bTrackedTCP, bTrackedUDP := routeTestConnections(runtime.tracker, "m2.g1")
	defer bTrackedTCP.Close()
	defer bTrackedUDP.Close()
	factory.kernels[0].updateErr = errors.New("injected update failure")

	status, err := runtime.Apply(context.Background(), applyInput(runtime, 1, User{MemberID: 2, UUID: testUUIDB}))
	if err == nil || status.State != StateDegraded || status.StateRevision != 2 {
		t.Fatalf("failed update was not observable: %+v, %v", status, err)
	}
	aTCP, aUDP, _, _ := routeTestConnections(runtime.tracker, "m1.g1")
	if aTCP.closes.Load() != 1 || aUDP.closes.Load() != 1 {
		t.Fatal("failed update revived revoked A")
	}
	if bTCP.closes.Load() != 0 || bUDP.closes.Load() != 0 {
		t.Fatal("failed hot update closed retained B")
	}
}

func TestConcurrentApplyAllowsOnlyOneWriterAtExpectedRevision(t *testing.T) {
	runtime, _ := newTestRuntime(t)
	const writers = 12
	start := make(chan struct{})
	results := make(chan error, writers)
	var wait sync.WaitGroup
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := runtime.Apply(context.Background(), applyInput(runtime, 0, User{MemberID: 1, UUID: testUUIDA}))
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 || runtime.Status().StateRevision != 1 {
		t.Fatalf("concurrent writers were not serialized: successes=%d status=%+v", succeeded, runtime.Status())
	}
}

func TestCancellationAfterSuccessfulKernelUpdateCommitsObservableState(t *testing.T) {
	runtime, factory := newTestRuntime(t)
	if _, err := runtime.Apply(context.Background(), applyInput(runtime, 0, User{MemberID: 1, UUID: testUUIDA})); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	factory.kernels[0].beforeUpdate = func() {
		close(started)
		<-release
	}
	ctx, cancel := context.WithCancel(context.Background())
	type applyResult struct {
		status Status
		err    error
	}
	result := make(chan applyResult, 1)
	go func() {
		status, err := runtime.Apply(ctx, applyInput(runtime, 1, User{MemberID: 1, UUID: testUUIDA}, User{MemberID: 2, UUID: testUUIDB}))
		result <- applyResult{status: status, err: err}
	}()
	<-started
	cancel()
	close(release)
	applied := <-result
	if !errors.Is(applied.err, context.Canceled) {
		t.Fatalf("cancellation was not returned to the caller: %v", applied.err)
	}
	if applied.status.State != StateRunning || applied.status.StateRevision != 2 {
		t.Fatalf("successful write was hidden by cancellation: %+v", applied.status)
	}
}

func TestClearAllAndRestore(t *testing.T) {
	runtime, _ := newTestRuntime(t)
	if _, err := runtime.Apply(context.Background(), applyInput(runtime, 0, User{MemberID: 1, UUID: testUUIDA})); err != nil {
		t.Fatal(err)
	}
	cleared, err := runtime.Apply(context.Background(), applyInput(runtime, 1))
	if err != nil || cleared.State != StateEmpty || cleared.StateRevision != 2 {
		t.Fatalf("clear all failed: %+v, %v", cleared, err)
	}
	aTCP, aUDP, _, _ := routeTestConnections(runtime.tracker, "m1.g1")
	if aTCP.closes.Load() != 1 || aUDP.closes.Load() != 1 {
		t.Fatal("clear all left the old identity authorized")
	}
	restored, err := runtime.Apply(context.Background(), applyInput(runtime, 2, User{MemberID: 1, UUID: testUUIDA}))
	if err != nil || restored.State != StateRunning || restored.StateRevision != 3 {
		t.Fatalf("restore from empty failed: %+v, %v", restored, err)
	}
}

func TestFailedConfigRebuildDoesNotReviveAndCanBeRepaired(t *testing.T) {
	runtime, factory := newTestRuntime(t)
	if _, err := runtime.Apply(context.Background(), applyInput(runtime, 0, User{MemberID: 1, UUID: testUUIDA}, User{MemberID: 2, UUID: testUUIDB})); err != nil {
		t.Fatal(err)
	}
	config := VlessRuntimeConfig(testConfig())
	config.Vless.Port++
	users := []User{{MemberID: 2, UUID: testUUIDB}}
	input := ApplyInput{ExpectedRuntimeID: runtime.Status().RuntimeID, ExpectedStateRevision: 1, Config: &config, Users: &users}
	factory.fail = errors.New("injected listen failure")
	status, err := runtime.Apply(context.Background(), input)
	if err == nil || status.State != StateDegraded || status.StateRevision != 2 || status.ConfigSHA256 != "" {
		t.Fatalf("config failure was not observable: %+v, %v", status, err)
	}
	aTCP, aUDP, _, _ := routeTestConnections(runtime.tracker, "m1.g1")
	if aTCP.closes.Load() != 1 || aUDP.closes.Load() != 1 {
		t.Fatal("config failure revived removed A")
	}
	factory.fail = nil
	input.ExpectedStateRevision = 2
	repaired, err := runtime.Apply(context.Background(), input)
	if err != nil || repaired.State != StateRunning || repaired.StateRevision != 3 || repaired.ConfigSHA256 == "" {
		t.Fatalf("explicit repair did not recover: %+v, %v", repaired, err)
	}
	aTCP, aUDP, _, _ = routeTestConnections(runtime.tracker, "m1.g1")
	if aTCP.closes.Load() != 1 || aUDP.closes.Load() != 1 {
		t.Fatal("repair silently restored removed A")
	}
}

func TestPanelOwnedRuntimeRefusesExternalWritesAndKeepsQueriesWorking(t *testing.T) {
	factory := new(fakeKernelFactory)
	owned, err := newPanelOwnedWithFactory(ProtocolVless, factory.make)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()

	initial := owned.Status()
	if !initial.PanelOwned || initial.Configured || initial.State != StateEmpty {
		t.Fatalf("a fresh panel-owned runtime must be empty and unconfigured: %+v", initial)
	}
	_, err = owned.Apply(context.Background(), ApplyInput{
		ExpectedRuntimeID:     initial.RuntimeID,
		ExpectedStateRevision: initial.StateRevision,
		Config:                &Config{},
	})
	if !errors.Is(err, ErrFailedPrecondition) {
		t.Fatalf("external write was accepted: %v", err)
	}
	if len(factory.kernels) != 0 {
		t.Fatal("a refused write still touched the kernel")
	}
	usage, err := owned.Usage()
	if err != nil || usage.RuntimeID != initial.RuntimeID {
		t.Fatalf("queries must keep working after a refused write: %v", err)
	}
}

func TestPanelApplyStartsTheKernelOnlyOnTheFirstSnapshot(t *testing.T) {
	factory := new(fakeKernelFactory)
	owned, err := newPanelOwnedWithFactory(ProtocolVless, factory.make)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()

	status, err := owned.ApplyPanel(context.Background(), VlessRuntimeConfig(testConfig()), []User{{MemberID: 3, UUID: testUUIDA}})
	if err != nil {
		t.Fatal(err)
	}
	if len(factory.kernels) != 1 || !status.Configured || status.State != StateRunning {
		t.Fatalf("the first snapshot did not start the kernel: %+v", status)
	}
	if _, err := owned.ApplyPanel(context.Background(), VlessRuntimeConfig(testConfig()), nil); err != nil {
		t.Fatal(err)
	}
	if len(factory.kernels) != 1 {
		t.Fatal("an unchanged config restarted the kernel")
	}
	if owned.Status().State != StateEmpty {
		t.Fatal("an empty snapshot did not revoke every member")
	}
}

func TestRevokeAllClosesStreamsAndFailsClosed(t *testing.T) {
	factory := new(fakeKernelFactory)
	owned, err := newPanelOwnedWithFactory(ProtocolVless, factory.make)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()

	if _, err := owned.ApplyPanel(context.Background(), VlessRuntimeConfig(testConfig()), []User{{MemberID: 4, UUID: testUUIDA}}); err != nil {
		t.Fatal(err)
	}
	status, err := owned.RevokeAll("test revocation")
	if err != nil {
		t.Fatal(err)
	}
	if status.LastError != "test revocation" || status.State != StateDegraded {
		t.Fatalf("revocation was not recorded: %+v", status)
	}
	if len(factory.kernels) != 1 {
		t.Fatal("revocation must keep the kernel for a later snapshot")
	}
}

func TestRevokeAllFailsClosedWhenTheKernelUpdateFails(t *testing.T) {
	factory := new(fakeKernelFactory)
	owned, err := newPanelOwnedWithFactory(ProtocolVless, factory.make)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()
	if _, err := owned.ApplyPanel(context.Background(), VlessRuntimeConfig(testConfig()), []User{{MemberID: 4, UUID: testUUIDA}}); err != nil {
		t.Fatal(err)
	}
	identity := factory.kernels[0].users[0].Name
	tcp, udp, _, _ := routeTestConnections(owned.tracker, identity)
	factory.kernels[0].updateErr = errors.New("kernel update failed")
	status, err := owned.RevokeAll("panel rejected node")
	if !errors.Is(err, ErrRuntime) {
		t.Fatalf("kernel failure was hidden: %v", err)
	}
	if tcp.closes.Load() != 1 || udp.closes.Load() != 1 || len(owned.users) != 0 || status.LastError == "" {
		t.Fatal("a failed kernel update left revoked streams authorized")
	}
	lateTCP, lateUDP, _, _ := routeTestConnections(owned.tracker, identity)
	if lateTCP.closes.Load() != 1 || lateUDP.closes.Load() != 1 {
		t.Fatal("late registration bypassed failed revocation")
	}
}

func TestHysteria2ConfigValidation(t *testing.T) {
	files := newTestTLSFiles(t)
	valid := hysteria2TestConfig(t, files, 51443)
	if err := ValidateHysteria2Config(valid); err != nil {
		t.Fatalf("valid Hysteria2 config rejected: %v", err)
	}
	cases := map[string]func(*Hysteria2Config){
		"relative certificate": func(config *Hysteria2Config) { config.CertificatePath = "cert.pem" },
		"relative key":         func(config *Hysteria2Config) { config.PrivateKeyPath = "key.pem" },
		"missing certificate":  func(config *Hysteria2Config) { config.CertificatePath = filepath.Join(t.TempDir(), "missing.pem") },
		"directory certificate": func(config *Hysteria2Config) {
			config.CertificatePath = t.TempDir()
		},
		"empty server name": func(config *Hysteria2Config) { config.ServerName = "" },
		"zero port":         func(config *Hysteria2Config) { config.Port = 0 },
		"invalid listen":    func(config *Hysteria2Config) { config.Listen = "not-an-ip" },
	}
	for name, mutate := range cases {
		config := valid
		mutate(&config)
		if err := ValidateHysteria2Config(config); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestPanelErrorAloneDoesNotForceAUserReapply(t *testing.T) {
	runtime, factory := newTestRuntime(t)
	input := applyInput(runtime, 0, User{MemberID: 1, UUID: testUUIDA}, User{MemberID: 2, UUID: testUUIDB})
	if _, err := runtime.Apply(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	kernel := factory.kernels[0]
	kernel.mu.Lock()
	updates := kernel.updates
	kernel.mu.Unlock()

	// A transient pull failure only surfaces an error; it does not mean the
	// snapshot differs from what the kernel already runs.
	runtime.RecordError("panel unreachable")
	status, err := runtime.Apply(context.Background(), applyInput(runtime, 1, User{MemberID: 1, UUID: testUUIDA}, User{MemberID: 2, UUID: testUUIDB}))
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateDegraded {
		t.Fatalf("panel error was not surfaced: %+v", status)
	}
	kernel.mu.Lock()
	after := kernel.updates
	kernel.mu.Unlock()
	if after != updates {
		t.Fatalf("identical snapshot after a panel error rewrote users: %d -> %d", updates, after)
	}
}

func TestFailedConfigRebuildClearsConfigured(t *testing.T) {
	runtime, factory := newTestRuntime(t)
	if !runtime.Status().Configured {
		t.Fatal("a fresh runtime should be configured")
	}
	config := testConfig()
	config.Port = 31002
	applied := VlessRuntimeConfig(config)
	factory.mu.Lock()
	factory.fail = errors.New("bind failure")
	factory.mu.Unlock()
	status, err := runtime.Apply(context.Background(), ApplyInput{
		ExpectedRuntimeID:     runtime.Status().RuntimeID,
		ExpectedStateRevision: 0,
		Config:                &applied,
		Users:                 &[]User{},
	})
	if err == nil {
		t.Fatal("a failed rebuild was reported as success")
	}
	if status.Configured {
		t.Fatalf("failed rebuild still claims a configured kernel: %+v", status)
	}
	if status.State != StateDegraded {
		t.Fatalf("failed rebuild not degraded: %+v", status)
	}
	factory.mu.Lock()
	factory.fail = nil
	factory.mu.Unlock()
	if _, err := runtime.Apply(context.Background(), ApplyInput{
		ExpectedRuntimeID:     runtime.Status().RuntimeID,
		ExpectedStateRevision: status.StateRevision,
		Config:                &applied,
		Users:                 &[]User{{MemberID: 1, UUID: testUUIDA}},
	}); err != nil {
		t.Fatal(err)
	}
	if !runtime.Status().Configured {
		t.Fatal("recovered runtime is still unconfigured")
	}
}

func TestRemovedMemberReceivesANewGenerationAfterReturning(t *testing.T) {
	runtime, factory := newTestRuntime(t)
	if _, err := runtime.Apply(context.Background(), applyInput(runtime, 0, User{MemberID: 1, UUID: testUUIDA}, User{MemberID: 2, UUID: testUUIDB})); err != nil {
		t.Fatal(err)
	}
	kernel := factory.kernels[0]
	kernel.mu.Lock()
	first := identityFor(kernel.users, 2)
	kernel.mu.Unlock()
	if first != "m2.g1" {
		t.Fatalf("unexpected first generation %q", first)
	}
	if _, err := runtime.Apply(context.Background(), applyInput(runtime, 1, User{MemberID: 1, UUID: testUUIDA})); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	pruned := len(runtime.generations)
	runtime.mu.Unlock()
	if pruned != 1 {
		t.Fatalf("removed member still keeps a generation counter: %d entries", pruned)
	}
	if _, err := runtime.Apply(context.Background(), applyInput(runtime, 2, User{MemberID: 1, UUID: testUUIDA}, User{MemberID: 2, UUID: testUUIDB})); err != nil {
		t.Fatal(err)
	}
	kernel.mu.Lock()
	second := identityFor(kernel.users, 2)
	kernel.mu.Unlock()
	if second == first {
		t.Fatalf("re-added member reused generation %q", second)
	}
}

func identityFor(users []kernelUser, memberID int64) string {
	prefix := fmt.Sprintf("m%d.", memberID)
	for _, user := range users {
		if strings.HasPrefix(user.Name, prefix) {
			return user.Name
		}
	}
	return ""
}

func TestFailedRevocationRetriesEmptySnapshot(t *testing.T) {
	runtime, factory := newTestRuntime(t)
	config := VlessRuntimeConfig(testConfig())
	if _, err := runtime.ApplyPanel(context.Background(), config, []User{{MemberID: 1, UUID: testUUIDA}}); err != nil {
		t.Fatal(err)
	}
	k := factory.kernels[0]
	k.updateErr = errors.New("injected revoke failure")
	if _, err := runtime.RevokeAll("node rejected"); err == nil {
		t.Fatal("expected a revoke error")
	}
	k.updateErr = nil
	before := k.updates
	if _, err := runtime.ApplyPanel(context.Background(), config, nil); err != nil {
		t.Fatal(err)
	}
	if k.updates != before+1 || len(k.users) != 0 {
		t.Fatal("the failed kernel revocation was skipped for an empty snapshot")
	}
}

func TestUserOnlyUpdateDoesNotRequireCertificateFiles(t *testing.T) {
	files := newTestTLSFiles(t)
	config := Hysteria2RuntimeConfig(hysteria2TestConfig(t, files, freeUDPPort(t)))
	factory := new(fakeKernelFactory)
	runtime, err := newRuntimeWithFactory(config, factory.make)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	users := []User{{MemberID: 1, UUID: testUUIDA}, {MemberID: 2, UUID: testUUIDB}}
	if _, err = runtime.ApplyPanel(context.Background(), config, users); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(files.certificatePath); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.ApplyPanel(context.Background(), config, users[1:]); err != nil {
		t.Fatalf("a missing certificate prevented revocation on a running kernel: %v", err)
	}
	if len(runtime.users) != 1 || runtime.users[0].MemberID != 2 {
		t.Fatal("the revoked member was retained")
	}
	users = nil
	_, err = runtime.Apply(context.Background(), ApplyInput{ExpectedRuntimeID: runtime.runtimeID, ExpectedStateRevision: runtime.revision, Config: &config, Users: &users})
	if err != nil || len(runtime.users) != 0 {
		t.Fatalf("self-managed revocation needs certificate files: %v", err)
	}
}

func TestRuntimeRefusesAProtocolChange(t *testing.T) {
	runtime, _ := newTestRuntime(t)
	files := newTestTLSFiles(t)
	config := Hysteria2RuntimeConfig(hysteria2TestConfig(t, files, freeUDPPort(t)))
	users := []User{}
	before := runtime.Status()
	_, err := runtime.Apply(context.Background(), ApplyInput{ExpectedRuntimeID: before.RuntimeID, ExpectedStateRevision: before.StateRevision, Config: &config, Users: &users})
	if !errors.Is(err, ErrInvalidArgument) || runtime.Status() != before {
		t.Fatalf("self-managed protocol change was not rejected without mutation: %v", err)
	}
	_, err = runtime.ApplyPanel(context.Background(), config, users)
	if !errors.Is(err, ErrInvalidArgument) || runtime.Status() != before {
		t.Fatalf("panel protocol change was not rejected without mutation: %v", err)
	}
}
