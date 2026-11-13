package worker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// probePanel is a fake panel that serves a target list and records samples.
type probePanel struct {
	mu      sync.Mutex
	targets []map[string]any
	samples []map[string]any
	server  *httptest.Server
}

func newProbePanel(t *testing.T) *probePanel {
	t.Helper()
	fake := &probePanel{}
	fake.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/node/v1/probes":
			fake.mu.Lock()
			targets := fake.targets
			fake.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"targets": targets})
		case r.Method == http.MethodPost && r.URL.Path == "/api/node/v1/probes":
			var body struct {
				Results []map[string]any `json:"results"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			fake.mu.Lock()
			fake.samples = append(fake.samples, body.Results...)
			fake.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": len(body.Results)})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *probePanel) setTargets(targets ...map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// A variadic call with no arguments yields a nil slice, which would encode
	// as JSON null; the panel always sends an empty array, so normalise it.
	f.targets = make([]map[string]any, 0, len(targets))
	f.targets = append(f.targets, targets...)
}

func (f *probePanel) recorded() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]map[string]any, len(f.samples))
	copy(out, f.samples)
	return out
}

func TestProbeTargetsAreMeasuredOncePerInterval(t *testing.T) {
	fake := newProbePanel(t)
	fake.setTargets(map[string]any{
		"id": 1, "name": "本机", "type": "tcp",
		"host": "127.0.0.1", "port": closedPort(t),
		"interval_seconds": 3600, "timeout_ms": 300,
	})

	engine, _ := newTestWorker(t, fake.server)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := engine.refreshProbeTargets(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engine.runProbes(ctx); err != nil {
		t.Fatal(err)
	}

	first := fake.recorded()
	if len(first) != 1 {
		t.Fatalf("recorded %d samples, want 1", len(first))
	}
	// A closed port reports an error rather than a latency, and the error still
	// travels to the panel as data.
	if first[0]["latency_ms"] != nil {
		t.Fatalf("latency = %v, want null for a closed port", first[0]["latency_ms"])
	}
	if errText, _ := first[0]["error"].(string); errText == "" {
		t.Fatal("expected an error message for the closed port")
	}

	// The interval has not elapsed, so a second tick measures nothing.
	if err := engine.runProbes(ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(fake.recorded()); got != 1 {
		t.Fatalf("recorded %d samples after a second tick, want still 1", got)
	}
}

func TestProbeSkipsTargetsRemovedByThePanel(t *testing.T) {
	fake := newProbePanel(t)
	fake.setTargets(map[string]any{
		"id": 9, "name": "临时", "type": "tcp",
		"host": "127.0.0.1", "port": closedPort(t),
		"interval_seconds": 3600, "timeout_ms": 300,
	})
	engine, _ := newTestWorker(t, fake.server)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := engine.refreshProbeTargets(ctx); err != nil {
		t.Fatal(err)
	}

	// The panel drops the target before it is measured.
	fake.setTargets()
	if err := engine.refreshProbeTargets(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engine.runProbes(ctx); err != nil {
		t.Fatal(err)
	}

	if got := len(fake.recorded()); got != 0 {
		t.Fatalf("recorded %d samples for a removed target, want 0", got)
	}
}

func TestUnsupportedProbeTypeIsReportedNotFatal(t *testing.T) {
	fake := newProbePanel(t)
	fake.setTargets(map[string]any{
		"id": 3, "name": "怪类型", "type": "gopher",
		"host": "127.0.0.1", "port": 70,
		"interval_seconds": 3600, "timeout_ms": 300,
	})
	engine, _ := newTestWorker(t, fake.server)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := engine.refreshProbeTargets(ctx); err != nil {
		t.Fatal(err)
	}
	if err := engine.runProbes(ctx); err != nil {
		t.Fatalf("an unsupported type must not fail the run: %v", err)
	}

	samples := fake.recorded()
	if len(samples) != 1 {
		t.Fatalf("recorded %d samples, want 1", len(samples))
	}
	if samples[0]["error"] != "unsupported probe type" {
		t.Fatalf("error = %v", samples[0]["error"])
	}
}

// closedPort reserves a TCP port and closes it, so a dial is refused quickly
// and the probe fails deterministically.
func closedPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}
