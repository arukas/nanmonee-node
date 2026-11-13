package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMeasureHTTPRecordsALatencyForASuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := Measure(context.Background(), Target{
		ID: 7, Type: TypeHTTP, Host: hostOf(t, server.URL), Port: portOf(t, server.URL),
		Timeout: 2 * time.Second,
	})

	if result.Err != "" {
		t.Fatalf("expected a latency, got error %q", result.Err)
	}
	if result.TargetID != 7 {
		t.Fatalf("target id = %d, want 7", result.TargetID)
	}
	if result.LatencyMS == nil || *result.LatencyMS < 0 {
		t.Fatalf("latency = %v, want a non-negative value", result.LatencyMS)
	}
	if result.SampledAt.IsZero() {
		t.Fatal("sampled_at must be set")
	}
}

func TestMeasureHTTPTreatsAnErrorStatusAsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	result := Measure(context.Background(), Target{
		Type: TypeHTTP, Host: hostOf(t, server.URL), Port: portOf(t, server.URL),
		Timeout: 2 * time.Second,
	})

	if result.LatencyMS != nil {
		t.Fatalf("latency = %d, want nil for a 500", *result.LatencyMS)
	}
	if !strings.Contains(result.Err, "500") {
		t.Fatalf("error = %q, want it to mention the status", result.Err)
	}
}

func TestMeasureHTTPDoesNotFollowARedirect(t *testing.T) {
	var followed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			followed.Store(true)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer server.Close()

	result := Measure(context.Background(), Target{
		Type: TypeHTTP, Host: hostOf(t, server.URL), Port: portOf(t, server.URL),
		Timeout: 2 * time.Second,
	})

	// 302 is inside the accepted 2xx/3xx band, so it is a successful probe.
	if result.Err != "" {
		t.Fatalf("expected a 302 to count as reachable, got %q", result.Err)
	}
	if followed.Load() {
		t.Fatal("a redirect must not be followed")
	}
}

func TestMeasureTCPTimesAHandshakeAndFailsOnAClosedPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := listener.Addr().(*net.TCPAddr)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	ok := Measure(context.Background(), Target{
		Type: TypeTCP, Host: "127.0.0.1", Port: address.Port, Timeout: time.Second,
	})
	if ok.Err != "" || ok.LatencyMS == nil {
		t.Fatalf("open port: err=%q latency=%v", ok.Err, ok.LatencyMS)
	}

	listener.Close()
	closed := Measure(context.Background(), Target{
		Type: TypeTCP, Host: "127.0.0.1", Port: address.Port, Timeout: 500 * time.Millisecond,
	})
	if closed.LatencyMS != nil || closed.Err == "" {
		t.Fatalf("closed port must fail: err=%q latency=%v", closed.Err, closed.LatencyMS)
	}
}

func TestMeasureRejectsAnUnknownType(t *testing.T) {
	result := Measure(context.Background(), Target{Type: Type("smtp"), Host: "127.0.0.1"})

	if result.LatencyMS != nil {
		t.Fatalf("latency = %d, want nil", *result.LatencyMS)
	}
	if result.Err == "" {
		t.Fatal("expected an error for an unsupported type")
	}
}

func TestMeasureHonoursTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A non-routable address keeps this deterministic: nothing answers, so the
	// cancelled context is what ends the attempt.
	result := Measure(ctx, Target{
		Type: TypeTCP, Host: "192.0.2.1", Port: 9, Timeout: 2 * time.Second,
	})

	if result.LatencyMS != nil {
		t.Fatalf("latency = %d, want nil for a cancelled context", *result.LatencyMS)
	}
}

func TestShortenCountsRunes(t *testing.T) {
	if got := shorten("网络不可达", 3); got != "网络不" {
		t.Fatalf("shorten = %q", got)
	}
	if got := shorten("ok", 10); got != "ok" {
		t.Fatalf("shorten = %q", got)
	}
}

func TestResolvePrefersIPv4(t *testing.T) {
	ip, err := resolve("127.0.0.1")
	if err != nil {
		t.Fatalf("resolve literal: %v", err)
	}
	if ip.String() != "127.0.0.1" {
		t.Fatalf("ip = %s", ip)
	}

	if _, err := resolve("this-host-does-not-exist.invalid"); err == nil {
		t.Fatal("expected a resolution error")
	}
}

func hostOf(t *testing.T, rawURL string) string {
	t.Helper()
	host, _, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://"))
	if err != nil {
		t.Fatalf("split %q: %v", rawURL, err)
	}
	return host
}

func portOf(t *testing.T, rawURL string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://"))
	if err != nil {
		t.Fatalf("split %q: %v", rawURL, err)
	}
	var value int
	for _, r := range port {
		value = value*10 + int(r-'0')
	}
	return value
}
