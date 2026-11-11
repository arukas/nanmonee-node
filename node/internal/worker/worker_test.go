package worker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nanmonee/node/internal/panel"
	noderuntime "nanmonee/node/internal/runtime"
	"nanmonee/node/internal/traffic"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakePanel is a minimal but faithful panel: it negotiates capabilities and
// serves config, users, and reports from programmable state.
type fakePanel struct {
	mu              sync.Mutex
	configBody      string
	usersBody       string
	configStatus    int
	usersStatus     int
	reportStatus    int
	configETag      string
	usersETag       string
	configCalls     atomic.Int32
	usersCalls      atomic.Int32
	reportCalls     atomic.Int32
	conditionalHits atomic.Int32
	inFlight        atomic.Int32
	maxInFlight     atomic.Int32
	reports         []map[string]any
	onReport        func()
}

func newFakePanel(t *testing.T) (*fakePanel, *httptest.Server) {
	t.Helper()
	fake := &fakePanel{
		configBody: `{"protocol":"vless","listen_ip":"::","server_port":31470,"network":"tcp","flow":"xtls-rprx-vision","tls_settings":{"server_name":"www.apple.com","dest":"www.apple.com:443","private_key":"` + repeat("A", 43) + `","short_id":["0123456789abcdef"]}}`,
		usersBody:  `{"users":[{"id":11,"uuid":"11111111-1111-4111-8111-111111111111"}]}`,
		configETag: `"cfg-1"`,
		usersETag:  `"usr-1"`,
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		switch r.URL.Path {
		case "/api/node/v1/handshake":
			_, _ = w.Write([]byte(`{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1"}}`))
		case "/api/node/v1/config":
			current := fake.inFlight.Add(1)
			defer fake.inFlight.Add(-1)
			for {
				observed := fake.maxInFlight.Load()
				if current <= observed || fake.maxInFlight.CompareAndSwap(observed, current) {
					break
				}
			}
			fake.configCalls.Add(1)
			if fake.configStatus != 0 {
				w.WriteHeader(fake.configStatus)
				return
			}
			if r.Header.Get("If-None-Match") == fake.configETag {
				fake.conditionalHits.Add(1)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", fake.configETag)
			_, _ = w.Write([]byte(fake.configBody))
		case "/api/node/v1/users":
			fake.usersCalls.Add(1)
			if fake.usersStatus != 0 {
				w.WriteHeader(fake.usersStatus)
				return
			}
			if r.Header.Get("If-None-Match") == fake.usersETag {
				fake.conditionalHits.Add(1)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", fake.usersETag)
			_, _ = w.Write([]byte(fake.usersBody))
		case "/api/node/v1/report":
			fake.reportCalls.Add(1)
			if fake.onReport != nil {
				fake.onReport()
			}
			if fake.reportStatus != 0 {
				w.WriteHeader(fake.reportStatus)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			fake.reports = append(fake.reports, body)
			ack, _ := json.Marshal(map[string]any{"protocol": body["protocol"], "batch_id": body["batch_id"]})
			_, _ = w.Write(ack)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return fake, server
}

func repeat(value string, count int) string {
	repeated := make([]byte, 0, count*len(value))
	for index := 0; index < count; index++ {
		repeated = append(repeated, value...)
	}
	return string(repeated)
}

func newTestWorker(t *testing.T, server *httptest.Server) (*Worker, *traffic.Spool) {
	t.Helper()
	client, err := panel.NewClient(panel.Options{
		URL: server.URL, Token: testToken, NodeID: 7, NodeType: "vless", HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	engineRuntime, err := noderuntime.NewPanelOwned(noderuntime.ProtocolVless)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engineRuntime.Close() })
	spool, err := traffic.Open(t.TempDir(), client.Identity(), engineRuntime.Status().RuntimeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	engine, err := New(Options{Client: client, Runtime: engineRuntime, Spool: spool})
	if err != nil {
		t.Fatal(err)
	}
	return engine, spool
}

func TestWorkerAppliesTheFirstSnapshotAndKeepsExternalWritesShut(t *testing.T) {
	_, server := newFakePanel(t)
	engine, _ := newTestWorker(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := engine.handshake(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engine.sync(ctx, true); err != nil {
		t.Fatal(err)
	}
	status := engine.runtime.Status()
	if !status.PanelOwned || !status.Configured || status.State != noderuntime.StateRunning {
		t.Fatalf("unexpected status after the first snapshot: %+v", status)
	}
	_, err := engine.runtime.Apply(context.Background(), noderuntime.ApplyInput{})
	if !errors.Is(err, noderuntime.ErrFailedPrecondition) {
		t.Fatalf("external apply was not refused: %v", err)
	}
}

func TestEmptyUserListRevokesEveryone(t *testing.T) {
	fake, server := newFakePanel(t)
	engine, _ := newTestWorker(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := engine.handshake(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engine.sync(ctx, true); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.usersBody = `{"users":[]}`
	fake.usersETag = `"usr-2"`
	fake.usersStatus = 0
	fake.mu.Unlock()

	if err := engine.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	status := engine.runtime.Status()
	if status.State != noderuntime.StateEmpty {
		t.Fatalf("an empty snapshot did not revoke: %+v", status)
	}
}

func TestRejectionRevokesButKeepsTheQueue(t *testing.T) {
	fake, server := newFakePanel(t)
	engine, spool := newTestWorker(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := engine.handshake(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engine.sync(ctx, true); err != nil {
		t.Fatal(err)
	}
	// Queue one batch with a failing panel, then get rejected.
	fake.mu.Lock()
	fake.reportStatus = http.StatusInternalServerError
	fake.mu.Unlock()
	send := func(batch panel.TrafficBatch) error {
		return engine.client.ReportTrafficBatch(ctx, batch)
	}
	if err := spool.Report(map[int][2]int64{11: {40, 60}}, "rt-test", send); !traffic.Persisted(err) {
		t.Fatalf("sample was not persisted: %v", err)
	}
	if spool.Pending() == 0 {
		t.Fatal("no batch was queued")
	}

	fake.mu.Lock()
	fake.usersStatus = http.StatusForbidden
	fake.mu.Unlock()
	err := engine.sync(ctx, false)
	if !errors.Is(err, panel.ErrRejected) {
		t.Fatalf("rejection not surfaced: %v", err)
	}
	status := engine.runtime.Status()
	// A fresh panel-owned runtime has never authorized anyone; the digests must match.
	empty, err := noderuntime.NewPanelOwned(noderuntime.ProtocolVless)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = empty.Close() })
	if status.AuthorizationSHA256 != empty.Status().AuthorizationSHA256 {
		t.Fatalf("rejection did not revoke every member: %+v", status)
	}
	if status.LastError == "" {
		t.Fatal("rejection was not recorded")
	}
	if spool.Pending() == 0 {
		t.Fatal("rejection discarded queued traffic")
	}
	if !engine.Observation().Rejected {
		t.Fatal("rejection was not observable")
	}
}

func TestOutageKeepsTheLastAuthorization(t *testing.T) {
	fake, server := newFakePanel(t)
	engine, _ := newTestWorker(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := engine.handshake(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engine.sync(ctx, true); err != nil {
		t.Fatal(err)
	}
	before := engine.runtime.Status()

	fake.mu.Lock()
	fake.usersStatus = http.StatusInternalServerError
	fake.usersETag = `"usr-2"`
	fake.mu.Unlock()

	if err := engine.sync(ctx, false); !errors.Is(err, panel.ErrTransient) {
		t.Fatalf("outage not surfaced: %v", err)
	}
	after := engine.runtime.Status()
	if after.AuthorizationSHA256 != before.AuthorizationSHA256 {
		t.Fatal("an outage changed the authorization")
	}
	if after.LastError == "" {
		t.Fatal("an outage was not recorded")
	}
}

func TestMalformedUsersKeepTheLastAuthorization(t *testing.T) {
	fake, server := newFakePanel(t)
	engine, _ := newTestWorker(t, server)
	if err := engine.sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	before := engine.runtime.Status()
	fake.mu.Lock()
	fake.usersBody = `{}`
	fake.usersETag = `"broken"`
	fake.mu.Unlock()
	if err := engine.sync(context.Background(), false); !errors.Is(err, panel.ErrTransient) {
		t.Fatalf("incomplete response was not treated as a temporary fault: %v", err)
	}
	if engine.runtime.Status().AuthorizationSHA256 != before.AuthorizationSHA256 {
		t.Fatal("incomplete response revoked the last valid authorization")
	}
}

func TestReportRejectionRevokesAndKeepsTheOriginalBatch(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fake, server := newFakePanel(t)
			engine, spool := newTestWorker(t, server)
			if err := engine.sync(context.Background(), true); err != nil {
				t.Fatal(err)
			}
			var original panel.TrafficBatch
			if err := spool.Report(map[int][2]int64{11: {40, 60}}, "previous-runtime", func(batch panel.TrafficBatch) error {
				original = batch
				return errors.New("confirmation lost")
			}); !traffic.Persisted(err) {
				t.Fatal(err)
			}
			fake.mu.Lock()
			fake.reportStatus = status
			fake.mu.Unlock()
			_ = engine.collect(context.Background(), true)
			if !engine.Observation().Rejected || engine.hasConfig || engine.hasUsers || engine.configETag != "" || engine.usersETag != "" {
				t.Fatal("report rejection did not revoke and clear cached snapshots")
			}
			empty, err := noderuntime.NewPanelOwned(noderuntime.ProtocolVless)
			if err != nil {
				t.Fatal(err)
			}
			defer empty.Close()
			if engine.runtime.Status().AuthorizationSHA256 != empty.Status().AuthorizationSHA256 || spool.Pending() != 1 {
				t.Fatal("report rejection retained authorization or dropped queued traffic")
			}
			if err := spool.Report(nil, engine.runtime.Status().RuntimeID, func(batch panel.TrafficBatch) error {
				if batch.BatchID != original.BatchID || batch.Traffic[11] != [2]int64{40, 60} {
					t.Fatal("rejection changed the immutable batch")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReportConflictDropsOnlyTheConflictingBatch(t *testing.T) {
	fake, server := newFakePanel(t)
	engine, spool := newTestWorker(t, server)
	if err := engine.sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := spool.Report(map[int][2]int64{11: {40, 60}}, "previous-runtime", func(panel.TrafficBatch) error {
		return errors.New("confirmation lost")
	}); !traffic.Persisted(err) {
		t.Fatal(err)
	}
	before := engine.runtime.Status()
	fake.mu.Lock()
	fake.reportStatus = http.StatusConflict
	fake.mu.Unlock()
	if err := engine.collect(context.Background(), true); err != nil {
		t.Fatalf("a conflicting batch was treated as a node-wide fault: %v", err)
	}
	// The panel already stores this batch ID with different bytes, so the batch can
	// never be accepted; dropping it must neither deauthorize members nor block the
	// queue behind it.
	if engine.Observation().Rejected || !engine.hasConfig || !engine.hasUsers || spool.Pending() != 0 {
		t.Fatal("a conflicting batch was not confined to that batch")
	}
	if after := engine.runtime.Status(); after.AuthorizationSHA256 != before.AuthorizationSHA256 || after.RuntimeID != before.RuntimeID {
		t.Fatal("a conflicting batch changed the authorization")
	}
}

func TestShutdownStopsTheRuntimeBeforeTheFinalReport(t *testing.T) {
	fake, server := newFakePanel(t)
	engine, spool := newTestWorker(t, server)
	if err := engine.sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := spool.Report(map[int][2]int64{11: {40, 60}}, "previous-runtime", func(panel.TrafficBatch) error {
		return errors.New("confirmation lost")
	}); !traffic.Persisted(err) {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.onReport = func() {
		_, err := engine.runtime.ApplyPanel(context.Background(), noderuntime.Config{}, nil)
		if !errors.Is(err, noderuntime.ErrFailedPrecondition) {
			t.Error("the proxy was still running during the final report")
		}
	}
	fake.mu.Unlock()
	if err := engine.shutdown(); err != nil {
		t.Fatal(err)
	}
	if spool.Pending() != 0 || fake.reportCalls.Load() != 1 {
		t.Fatal("the final report did not drain the persisted batch")
	}
}

func Test304WithoutACacheIsTreatedAsAFault(t *testing.T) {
	fake, server := newFakePanel(t)
	engine, _ := newTestWorker(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The panel answers 304 to a request that carried no If-None-Match.
	fake.mu.Lock()
	fake.configETag = ""
	fake.mu.Unlock()

	err := engine.pullConfig(ctx, true)
	if !errors.Is(err, panel.ErrTransient) {
		t.Fatalf("an uncacheable 304 was accepted: %v", err)
	}
	engine.mu.Lock()
	holds := engine.hasConfig
	engine.mu.Unlock()
	if holds {
		t.Fatal("a 304 was recorded as content")
	}
}

func TestConditionalPullIsSentOnlyAfterACachedSnapshot(t *testing.T) {
	fake, server := newFakePanel(t)
	engine, _ := newTestWorker(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := engine.handshake(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engine.sync(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := engine.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	if fake.conditionalHits.Load() != 2 {
		t.Fatalf("expected two conditional hits, got %d", fake.conditionalHits.Load())
	}
	if fake.configCalls.Load() != 2 || fake.usersCalls.Load() != 2 {
		t.Fatalf("unexpected pull counts: config %d users %d", fake.configCalls.Load(), fake.usersCalls.Load())
	}
}

func TestTrafficIsReportedExactlyOnce(t *testing.T) {
	fake, server := newFakePanel(t)
	engine, spool := newTestWorker(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := engine.handshake(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engine.sync(ctx, true); err != nil {
		t.Fatal(err)
	}
	_ = engine.collect(ctx, true)
	_ = engine.collect(ctx, true)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.reportCalls.Load() != 0 {
		t.Fatalf("zero traffic produced %d reports", fake.reportCalls.Load())
	}
	if spool.Pending() != 0 {
		t.Fatal("an empty sample queued a batch")
	}
}

func TestPanelsAreNeverPolledConcurrently(t *testing.T) {
	fake, server := newFakePanel(t)
	engine, _ := newTestWorker(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := engine.handshake(ctx); err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(ctx)
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		_ = engine.Run(runCtx)
	}()
	time.Sleep(300 * time.Millisecond)
	stop()
	wait.Wait()

	if observed := fake.maxInFlight.Load(); observed > 1 {
		t.Fatalf("%d panel requests overlapped", observed)
	}
	if fake.configCalls.Load() == 0 {
		t.Fatal("the worker never pulled")
	}
}

func TestSampleTickPersistsWithoutReporting(t *testing.T) {
	fake, server := newFakePanel(t)
	engine, spool := newTestWorker(t, server)
	if err := spool.Sample(map[int][2]int64{11: {40, 60}}, "previous-runtime"); err != nil {
		t.Fatal(err)
	}
	if err := engine.collect(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if fake.reportCalls.Load() != 0 || spool.Pending() != 1 {
		t.Fatal("the sample tick sent traffic before the report tick")
	}
	if err := engine.collect(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if fake.reportCalls.Load() != 1 || spool.Pending() != 0 {
		t.Fatal("the report tick did not drain the sampled batch")
	}
}

func TestPanelInboundProtocolsMapToTheRuntime(t *testing.T) {
	mapped, err := inboundConfig(panel.InboundConfig{Protocol: "hysteria2", Hysteria2: panel.Hysteria2Config{
		Listen: "::", Port: 51443, ServerName: "rn-sea.acris.cc",
		CertificatePath: "/etc/nanmonee/tls-hysteria2/fullchain.pem",
		PrivateKeyPath:  "/etc/nanmonee/tls-hysteria2/privkey.pem",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if mapped.Protocol != noderuntime.ProtocolHysteria2 || mapped.Hysteria2 != (noderuntime.Hysteria2Config{
		Listen: "::", Port: 51443, ServerName: "rn-sea.acris.cc",
		CertificatePath: "/etc/nanmonee/tls-hysteria2/fullchain.pem",
		PrivateKeyPath:  "/etc/nanmonee/tls-hysteria2/privkey.pem",
	}) {
		t.Fatalf("unexpected Hysteria2 mapping: %+v", mapped)
	}
	if mapped.Vless.Port != 0 {
		t.Fatal("the Hysteria2 mapping carried VLESS settings")
	}
	mappedAnyTLS, err := inboundConfig(panel.InboundConfig{Protocol: "anytls", Anytls: panel.AnytlsConfig{
		Listen: "::", Port: 31472, ServerName: "rn-sea.acris.cc",
		CertificatePath: "/etc/nanmonee-node/tls-anytls/fullchain.pem",
		PrivateKeyPath:  "/etc/nanmonee-node/tls-anytls/privkey.pem",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if mappedAnyTLS.Protocol != noderuntime.ProtocolAnytls || mappedAnyTLS.Anytls != (noderuntime.AnytlsConfig{
		Listen: "::", Port: 31472, ServerName: "rn-sea.acris.cc",
		CertificatePath: "/etc/nanmonee-node/tls-anytls/fullchain.pem",
		PrivateKeyPath:  "/etc/nanmonee-node/tls-anytls/privkey.pem",
	}) {
		t.Fatalf("unexpected AnyTLS mapping: %+v", mappedAnyTLS)
	}
	mappedTUIC, err := inboundConfig(panel.InboundConfig{Protocol: "tuic", Tuic: panel.TuicConfig{
		Listen: "::", Port: 10544, ServerName: "rn-sea.acris.cc",
		CertificatePath: "/etc/nanmonee-node/tls-tuic/fullchain.pem",
		PrivateKeyPath:  "/etc/nanmonee-node/tls-tuic/privkey.pem",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if mappedTUIC.Protocol != noderuntime.ProtocolTuic || mappedTUIC.Tuic != (noderuntime.TuicConfig{
		Listen: "::", Port: 10544, ServerName: "rn-sea.acris.cc",
		CertificatePath: "/etc/nanmonee-node/tls-tuic/fullchain.pem",
		PrivateKeyPath:  "/etc/nanmonee-node/tls-tuic/privkey.pem",
	}) {
		t.Fatalf("unexpected TUIC mapping: %+v", mappedTUIC)
	}
	if mappedTUIC.Vless.Port != 0 || mappedTUIC.Anytls.Port != 0 {
		t.Fatal("the TUIC mapping carried another protocol's settings")
	}
	for _, protocol := range []string{"", "hysteria", "quic"} {
		if _, err := inboundConfig(panel.InboundConfig{Protocol: protocol}); !errors.Is(err, panel.ErrIncompatible) {
			t.Fatalf("protocol %q was accepted: %v", protocol, err)
		}
	}
}

func TestPanelOwnedHysteria2StatusReportsItsOnlyProtocol(t *testing.T) {
	engineRuntime, err := noderuntime.NewPanelOwned(noderuntime.ProtocolHysteria2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engineRuntime.Close() })
	status := engineRuntime.Status()
	if status.Protocol != noderuntime.ProtocolHysteria2 || !status.PanelOwned {
		t.Fatalf("unexpected panel-owned status: %+v", status)
	}
	if _, err := inboundConfig(panel.InboundConfig{Protocol: "vless", Vless: panel.VlessConfig{Port: 31470}}); err != nil {
		t.Fatalf("the VLESS mapping regressed: %v", err)
	}
}
