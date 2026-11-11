package control

import (
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	nodev1 "nanmonee/node/api/node/v1"
	noderuntime "nanmonee/node/internal/runtime"
	"nanmonee/node/internal/worker"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

const testControlSecret = "test-only-control-secret"

func testKey() string {
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

func newTestControl(t *testing.T) (uint32, nodev1.NodeControlClient) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyPort := proxyListener.Addr().(*net.TCPAddr).Port
	_ = proxyListener.Close()
	runtime, err := noderuntime.New(noderuntime.VlessRuntimeConfig(noderuntime.VlessConfig{
		Listen:            "127.0.0.1",
		Port:              uint32(proxyPort),
		ServerName:        "www.apple.com",
		HandshakeServer:   "www.apple.com",
		HandshakePort:     443,
		RealityPrivateKey: testKey(),
		RealityShortID:    "0123456789abcdef",
	}))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(runtime, testControlSecret, nil)
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		server.Stop()
		_ = runtime.Close()
		_ = listener.Close()
	})
	return uint32(proxyPort), nodev1.NewNodeControlClient(connection)
}

func authorizedContext() context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+testControlSecret)
}

func getStatus(t *testing.T, client nodev1.NodeControlClient) *nodev1.Status {
	t.Helper()
	response, err := client.GetStatus(authorizedContext(), &nodev1.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return response.Status
}

func testSnapshot(status *nodev1.Status, port uint32, users ...*nodev1.User) *nodev1.ApplySnapshotRequest {
	return &nodev1.ApplySnapshotRequest{
		ExpectedRuntimeId:     status.RuntimeId,
		ExpectedStateRevision: status.StateRevision,
		Config: &nodev1.NodeConfig{Protocol: &nodev1.NodeConfig_Vless{Vless: &nodev1.VlessConfig{
			Listen:            "127.0.0.1",
			Port:              port,
			ServerName:        "www.apple.com",
			HandshakeServer:   "www.apple.com",
			HandshakePort:     443,
			RealityPrivateKey: testKey(),
			RealityShortId:    "0123456789abcdef",
		}}},
		Users: &nodev1.UserSnapshot{Users: users},
	}
}

func TestGRPCAuthenticationAndSafeStatus(t *testing.T) {
	_, client := newTestControl(t)
	if _, err := client.GetStatus(context.Background(), &nodev1.GetStatusRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing secret returned %v", err)
	}
	wrong := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer wrong")
	if _, err := client.GetStatus(wrong, &nodev1.GetStatusRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong secret returned %v", err)
	}
	current := getStatus(t, client)
	if current.AgentVersion == "" || current.ApiVersion != "nanmonee-node-v1" || current.CoreVersion != "v1.14.4" || current.CoreCommit != "c005f35300ce76427dc285481ec5695f5b179cd2" || len(current.SupportedProtocols) != 1 || current.SupportedProtocols[0] != "vless" {
		t.Fatalf("unexpected version status: %+v", current)
	}
	encoded, err := protojson.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testControlSecret, testKey()} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("status exposed a secret")
		}
	}
}

func TestGRPCApplyValidationRevisionAndRequestLimit(t *testing.T) {
	port, client := newTestControl(t)
	current := getStatus(t, client)
	request := testSnapshot(current, port, &nodev1.User{MemberId: 1, Uuid: "11111111-1111-4111-8111-111111111111"}, &nodev1.User{MemberId: 2, Uuid: "22222222-2222-4222-8222-222222222222"})
	response, err := client.ApplySnapshot(authorizedContext(), request)
	if err != nil || response.Status.State != nodev1.RuntimeState_RUNTIME_STATE_RUNNING || response.Status.StateRevision != 1 {
		t.Fatalf("valid apply failed: %+v, %v", response, err)
	}

	current = getStatus(t, client)
	invalid := testSnapshot(current, port)
	invalid.Config = nil
	if _, err := client.ApplySnapshot(authorizedContext(), invalid); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing config returned %v", err)
	}
	invalid = testSnapshot(current, port)
	invalid.Users = nil
	if _, err := client.ApplySnapshot(authorizedContext(), invalid); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing users returned %v", err)
	}
	invalid = testSnapshot(current, port, &nodev1.User{MemberId: 1, Uuid: "invalid"})
	if _, err := client.ApplySnapshot(authorizedContext(), invalid); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid UUID returned %v", err)
	}
	invalid = testSnapshot(current, port)
	invalid.ExpectedStateRevision = 0
	if _, err := client.ApplySnapshot(authorizedContext(), invalid); status.Code(err) != codes.Aborted {
		t.Fatalf("stale revision returned %v", err)
	}
	invalid = testSnapshot(current, port)
	invalid.ExpectedRuntimeId = "old-runtime"
	if _, err := client.ApplySnapshot(authorizedContext(), invalid); status.Code(err) != codes.Aborted {
		t.Fatalf("stale runtime returned %v", err)
	}
	invalid = testSnapshot(current, port)
	invalid.Config.GetVless().RealityShortId = strings.Repeat("0", 1<<20)
	if _, err := client.ApplySnapshot(authorizedContext(), invalid); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversize request returned %v", err)
	}
	if getStatus(t, client).StateRevision != 1 {
		t.Fatal("rejected requests changed state")
	}
}

func TestGRPCRejectsASnapshotWithoutAProtocolConfig(t *testing.T) {
	port, client := newTestControl(t)
	current := getStatus(t, client)
	request := testSnapshot(current, port)
	request.Config = &nodev1.NodeConfig{}
	if _, err := client.ApplySnapshot(authorizedContext(), request); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an empty protocol config returned %v", err)
	}
	if after := getStatus(t, client); after.StateRevision != current.StateRevision || after.RuntimeId != current.RuntimeId {
		t.Fatalf("the rejected snapshot changed the runtime: before=%+v after=%+v", current, after)
	}
}

func TestGRPCCancellationAndUsageSnapshotAreObservable(t *testing.T) {
	port, client := newTestControl(t)
	before := getStatus(t, client)
	ctx, cancel := context.WithCancel(authorizedContext())
	cancel()
	if _, err := client.ApplySnapshot(ctx, testSnapshot(before, port)); status.Code(err) != codes.Canceled {
		t.Fatalf("canceled apply returned %v", err)
	}
	if getStatus(t, client).StateRevision != before.StateRevision {
		t.Fatal("canceled request unexpectedly changed revision")
	}
	first, err := client.GetUsageSnapshot(authorizedContext(), &nodev1.GetUsageSnapshotRequest{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.GetUsageSnapshot(authorizedContext(), &nodev1.GetUsageSnapshotRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if first.RuntimeId != before.RuntimeId || second.RuntimeId != before.RuntimeId || len(first.Usage) != 0 || len(second.Usage) != 0 {
		t.Fatalf("usage snapshot changed unexpectedly: %+v %+v", first, second)
	}
}

func TestGRPCRejectsOversizedRealityShortIDWithoutStoppingRuntime(t *testing.T) {
	port, client := newTestControl(t)
	current := getStatus(t, client)
	users := []*nodev1.User{{MemberId: 1, Uuid: "11111111-1111-4111-8111-111111111111"}}
	if _, err := client.ApplySnapshot(authorizedContext(), testSnapshot(current, port, users...)); err != nil {
		t.Fatal(err)
	}
	before := getStatus(t, client)
	for _, length := range []int{9, 16} {
		request := testSnapshot(before, port, users...)
		request.Config.GetVless().RealityShortId = strings.Repeat("ab", length)
		if _, err := client.ApplySnapshot(authorizedContext(), request); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%d-byte short ID returned %v", length, err)
		}
		after := getStatus(t, client)
		if after.State != before.State || after.StateRevision != before.StateRevision || after.ConfigSha256 != before.ConfigSha256 || after.AuthorizationSha256 != before.AuthorizationSha256 {
			t.Fatalf("rejected short ID changed the runtime: before=%+v after=%+v", before, after)
		}
		listener, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), time.Second)
		if err != nil {
			t.Fatalf("rejected short ID stopped the original listener: %v", err)
		}
		_ = listener.Close()
	}
}

type staticObserver struct{ observation worker.Observation }

func (o staticObserver) Observation() worker.Observation { return o.observation }

func newPanelOwnedControl(t *testing.T, observation worker.Observation) (nodev1.NodeControlClient, *noderuntime.Runtime) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	owned, err := noderuntime.NewPanelOwned(noderuntime.ProtocolVless)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(owned, testControlSecret, staticObserver{observation: observation})
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		server.Stop()
		_ = owned.Close()
		_ = listener.Close()
	})
	return nodev1.NewNodeControlClient(connection), owned
}

func TestPanelOwnedStatusSurfacesObservationsAndRejectsExternalApply(t *testing.T) {
	client, owned := newPanelOwnedControl(t, worker.Observation{
		PanelHost:      "panel.example.com",
		LastPullAt:     time.Unix(1_700_000_000, 0),
		LastError:      "",
		PendingBatches: 3,
		PendingMembers: 5,
	})
	reported := getStatus(t, client)
	if !reported.PanelOwned || reported.Configured {
		t.Fatalf("panel ownership not surfaced: %+v", reported)
	}
	if reported.Panel == nil || reported.Panel.Host != "panel.example.com" || reported.Panel.PendingBatches != 3 {
		t.Fatalf("observations not surfaced: %+v", reported.Panel)
	}

	_, err := client.ApplySnapshot(authorizedContext(), testSnapshot(getStatus(t, client), 12345, &nodev1.User{MemberId: 1, Uuid: "11111111-1111-4111-8111-111111111111"}))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("external apply returned %v", err)
	}
	if _, err := owned.Usage(); err != nil {
		t.Fatalf("queries stopped working: %v", err)
	}
}

func TestSelfManagedStatusKeepsPanelFieldsEmpty(t *testing.T) {
	_, client := newTestControl(t)
	reported := getStatus(t, client)
	if reported.PanelOwned || !reported.Configured {
		t.Fatalf("self-managed status misreported: %+v", reported)
	}
	if reported.Panel != nil {
		t.Fatal("a self-managed node must not report panel observations")
	}
}
