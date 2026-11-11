package panel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestClient(t *testing.T, url string) *Client {
	t.Helper()
	return newTypedTestClient(t, url, NodeTypeVless)
}

func newTypedTestClient(t *testing.T, url, nodeType string) *Client {
	t.Helper()
	client, err := NewClient(Options{URL: url, Token: testToken, NodeID: 7, NodeType: nodeType})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// newTLSTestClient keeps production validation intact while trusting the
// self-signed test certificate.
func newTLSTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	return newTypedTLSTestClient(t, server, NodeTypeVless)
}

func newTypedTLSTestClient(t *testing.T, server *httptest.Server, nodeType string) *Client {
	t.Helper()
	client := newTypedTestClient(t, server.URL, nodeType)
	trusted := server.Client()
	client.http = &http.Client{
		Timeout:       trusted.Timeout,
		Transport:     trusted.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return client
}

func assertNodeAuth(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
		t.Errorf("authorization header = %q", got)
	}
	if got := r.Header.Get("X-Nanmonee-Node-Id"); got != "7" {
		t.Errorf("node id header = %q", got)
	}
	if r.URL.RawQuery != "" {
		t.Errorf("request must not carry credentials in the query: %s", r.URL.RawQuery)
	}
}

func TestNewClientRejectsUnsafeEndpoints(t *testing.T) {
	for _, url := range []string{
		"http://panel.example.com",
		"https://user:pass@panel.example.com",
		"https://panel.example.com/?x=1",
		"https://panel.example.com/#frag",
	} {
		if _, err := NewClient(Options{URL: url, Token: testToken, NodeID: 1, NodeType: "vless"}); err == nil {
			t.Fatalf("accepted unsafe URL %q", url)
		}
	}
	if _, err := NewClient(Options{URL: "https://panel.example.com", Token: "short", NodeID: 1, NodeType: "vless"}); err == nil {
		t.Fatal("accepted a short token")
	}
	if _, err := NewClient(Options{URL: "https://panel.example.com", Token: testToken, NodeID: 0, NodeType: "vless"}); err == nil {
		t.Fatal("accepted a zero node ID")
	}
	if _, err := NewClient(Options{URL: "https://panel.example.com", Token: testToken, NodeID: 1, NodeType: "quic"}); err == nil {
		t.Fatal("accepted an unsupported node type")
	}
}

func TestHandshakeRequiresMatchingCapabilities(t *testing.T) {
	accepted := `{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1"}}`
	for _, testCase := range []struct {
		body string
		ok   bool
	}{
		{accepted, true},
		{`{"websocket":{"enabled":true},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1"}}`, false},
		{`{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v2","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1"}}`, false},
		{`{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":999},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1"}}`, false},
		{`{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v2","node_backend_protocol":"nanmonee-node-v1"}}`, false},
		{`{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1"}}`, false},
		{`{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v2"}}`, false},
		{`{"websocket":{"enabled":false},"settings":{"pull_interval":0,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1"}}`, false},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error("handshake body is not JSON")
			}
			if body["node_backend_protocol"] != BackendProtocol || body["report_protocol"] != TrafficProtocol || body["access_protocol"] != AccessProtocol {
				t.Error("handshake did not advertise every protocol")
			}
			assertNodeAuth(t, r)
			_, _ = w.Write([]byte(testCase.body))
		}))
		_, err := newTLSTestClient(t, server).Handshake(context.Background())
		server.Close()
		if (err == nil) != testCase.ok {
			t.Fatalf("body %s: unexpected outcome %v", testCase.body, err)
		}
		if err != nil && !errors.Is(err, ErrIncompatible) {
			t.Fatalf("mismatch was not classified as incompatible: %v", err)
		}
	}
}

func TestStatusCodesMapToTheThreeFailureClasses(t *testing.T) {
	for _, testCase := range []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, ErrRejected},
		{http.StatusForbidden, ErrRejected},
		{http.StatusConflict, ErrRejected},
		{http.StatusInternalServerError, ErrTransient},
		{http.StatusBadGateway, ErrTransient},
		{http.StatusTooManyRequests, ErrTransient},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(testCase.status)
		}))
		_, err := newTLSTestClient(t, server).Config(context.Background(), "")
		server.Close()
		if !errors.Is(err, testCase.want) {
			t.Fatalf("status %d mapped to %v", testCase.status, err)
		}
	}
}

func TestTransportAndParseFailuresAreTransientAndLeakNoSecret(t *testing.T) {
	closed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := closed.URL
	closed.Close()
	_, err := newTestClient(t, url).Users(context.Background(), "")
	if !errors.Is(err, ErrTransient) {
		t.Fatalf("transport failure classified as %v", err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatal("error leaked the panel token")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("error lost the underlying reason: %v", err)
	}

	malformed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	_, err = newTLSTestClient(t, malformed).Users(context.Background(), "")
	malformed.Close()
	if !errors.Is(err, ErrTransient) || strings.Contains(err.Error(), testToken) {
		t.Fatalf("malformed document handled as %v", err)
	}

	oversized := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", maxResponseBytes+16)))
	}))
	_, err = newTLSTestClient(t, oversized).Users(context.Background(), "")
	oversized.Close()
	if !errors.Is(err, ErrTransient) {
		t.Fatalf("oversized response handled as %v", err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the client followed a redirect to another host")
	}))
	defer target.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusFound)
	}))
	defer origin.Close()

	client := newTestClient(t, origin.URL)
	client.http = origin.Client()
	client.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	_, err := client.Config(context.Background(), "")
	if !errors.Is(err, ErrTransient) {
		t.Fatalf("redirect produced %v", err)
	}
}

func TestConfigParsesRealitySettings(t *testing.T) {
	document := `{"protocol":"vless","listen_ip":"::","server_port":31470,"network":"tcp","flow":"xtls-rprx-vision",
		"tls_settings":{"server_name":"www.apple.com","dest":"www.apple.com:443","private_key":"` + strings.Repeat("A", 43) + `","short_id":["0123456789abcdef"]}}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertNodeAuth(t, r)
		w.Header().Set("ETag", `"abc"`)
		_, _ = w.Write([]byte(document))
	}))
	defer server.Close()

	snapshot, err := newTLSTestClient(t, server).Config(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Config.Protocol != "vless" || snapshot.Config.Vless.Port != 31470 || snapshot.Config.Vless.HandshakeServer != "www.apple.com" || snapshot.Config.Vless.HandshakePort != 443 {
		t.Fatalf("unexpected config: %+v", snapshot.Config)
	}
	if snapshot.Config.Vless.ShortID != "0123456789abcdef" || snapshot.ETag != `"abc"` {
		t.Fatalf("unexpected short ID or ETag: %+v", snapshot)
	}
}

func TestConfigRejectsUnsupportedShapes(t *testing.T) {
	for name, document := range map[string]string{
		"hysteria2":     `{"protocol":"hysteria2","server_port":443}`,
		"ws transport":  `{"protocol":"vless","network":"ws","server_port":443,"tls_settings":{"server_name":"a","dest":"a:443","private_key":"k","short_id":"s"}}`,
		"wrong flow":    `{"protocol":"vless","network":"tcp","flow":"xtls-rprx-direct","server_port":443,"tls_settings":{"server_name":"www.apple.com","dest":"www.apple.com:443","private_key":"` + strings.Repeat("A", 43) + `","short_id":"0123456789abcdef"}}`,
		"bad dest":      `{"protocol":"vless","network":"tcp","flow":"xtls-rprx-vision","server_port":443,"tls_settings":{"server_name":"a","dest":"nope","private_key":"k","short_id":"s"}}`,
		"empty shortID": `{"protocol":"vless","network":"tcp","flow":"xtls-rprx-vision","server_port":443,"tls_settings":{"server_name":"a","dest":"a:443","private_key":"k","short_id":[]}}`,
		"zero port":     `{"protocol":"vless","network":"tcp","flow":"xtls-rprx-vision","server_port":0,"tls_settings":{"server_name":"a","dest":"a:443","private_key":"k","short_id":"s"}}`,
		"no key":        `{"protocol":"vless","network":"tcp","flow":"xtls-rprx-vision","server_port":443,"tls_settings":{"server_name":"a","dest":"a:443","short_id":"s"}}`,
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(document))
		}))
		_, err := newTLSTestClient(t, server).Config(context.Background(), "")
		server.Close()
		if !errors.Is(err, ErrIncompatible) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}

func TestIncompleteConfigDocumentsAreTransient(t *testing.T) {
	for _, document := range []string{`{}`, `null`, `{"protocol":"vless"}`, `{"protocol":"vless","network":"tcp"}`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(document))
		}))
		_, err := newTLSTestClient(t, server).Config(context.Background(), "")
		server.Close()
		if !errors.Is(err, ErrTransient) {
			t.Fatalf("incomplete config was not treated as a temporary fault: %v", err)
		}
	}
}

func TestConditionalRequestsAndUserSnapshot(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/node/v1/users" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("If-None-Match") == `"v2"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v2"`)
		_, _ = w.Write([]byte(`{"users":[{"id":3,"uuid":"11111111-1111-4111-8111-111111111111"},{"id":9,"uuid":"22222222-2222-4222-8222-222222222222"}]}`))
	}))
	defer server.Close()
	client := newTLSTestClient(t, server)

	full, err := client.Users(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Members) != 2 || full.Members[0].MemberID != 3 || full.ETag != `"v2"` {
		t.Fatalf("unexpected users: %+v", full)
	}
	unchanged, err := client.Users(context.Background(), `"v2"`)
	if err != nil {
		t.Fatal(err)
	}
	if !unchanged.NotModified || len(unchanged.Members) != 0 {
		t.Fatalf("304 was not reported: %+v", unchanged)
	}
}

func TestIncompleteUsersDocumentsAreNotEmptySnapshots(t *testing.T) {
	for _, document := range []string{`{}`, `null`, `{"users":null}`, `{"users":{}}`} {
		t.Run(document, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(document))
			}))
			defer server.Close()
			if _, err := newTLSTestClient(t, server).Users(context.Background(), ""); !errors.Is(err, ErrTransient) {
				t.Fatalf("incomplete users document was accepted as a revocation: %v", err)
			}
		})
	}
}

func TestReportRequiresExactEchoAndSendsBodyCredentials(t *testing.T) {
	var seen map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Error("report request must not carry a query string")
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatal(err)
		}
		ack, _ := json.Marshal(map[string]any{"protocol": seen["protocol"], "batch_id": seen["batch_id"]})
		_, _ = w.Write(ack)
	}))
	defer server.Close()
	client := newTLSTestClient(t, server)
	batch := TrafficBatch{Protocol: TrafficProtocol, BatchID: "0123456789abcdef0123456789abcdef", SampledFrom: 1, SampledTo: 2, Traffic: map[int][2]int64{4: {7, 9}}}
	if err := client.ReportTrafficBatch(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if _, present := seen["token"]; present {
		t.Fatal("report body must not contain the token")
	}
	if _, present := seen["node_id"]; present {
		t.Fatal("report body must not contain the node id")
	}
	if _, isObject := seen["traffic"].(map[string]any); !isObject {
		t.Fatal("traffic must be a JSON object")
	}

	mismatched := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"protocol":"nanmonee-traffic-v1","batch_id":"ffffffffffffffffffffffffffffffff"}`))
	}))
	defer mismatched.Close()
	if err := newTLSTestClient(t, mismatched).ReportTrafficBatch(context.Background(), batch); !errors.Is(err, ErrTransient) {
		t.Fatalf("mismatched acknowledgement accepted: %v", err)
	}
}

func TestReportConflictIsABatchRejectionNotANodeRejection(t *testing.T) {
	for _, testCase := range []struct {
		status int
		batch  bool
	}{
		{http.StatusConflict, true},
		{http.StatusUnauthorized, false},
		{http.StatusForbidden, false},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(testCase.status)
		}))
		err := newTLSTestClient(t, server).ReportTrafficBatch(context.Background(), TrafficBatch{
			Protocol: TrafficProtocol, BatchID: "0123456789abcdef0123456789abcdef", SampledTo: 2, Traffic: map[int][2]int64{4: {7, 9}},
		})
		server.Close()
		var batchRejected *BatchRejectedError
		if errors.As(err, &batchRejected) != testCase.batch || errors.Is(err, ErrBatchRejected) != testCase.batch {
			t.Fatalf("status %d produced %v", testCase.status, err)
		}
		// A batch conflict must never look like a node-wide rejection: the worker
		// would revoke every member for a fault that concerns one batch.
		if errors.Is(err, ErrRejected) == testCase.batch {
			t.Fatalf("status %d was classified as a node rejection: %v", testCase.status, err)
		}
	}
}

func TestAnyTLSHandshakeAndConfig(t *testing.T) {
	const accepted = `{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","anytls_auth_protocol":"nanmonee-anytls-auth-v1"}}`
	const document = `{"protocol":"anytls","version":2,"listen_ip":"::","server_port":31472,"server_name":"rn-sea.acris.cc","cert_config":{"cert_mode":"file","cert_file":"/etc/nanmonee-node/tls-anytls/fullchain.pem","key_file":"/etc/nanmonee-node/tls-anytls/privkey.pem"}}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/node/v1/handshake":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error("handshake body is not JSON")
			}
			if body["anytls_auth_protocol"] != AnyTLSAuthProtocol {
				t.Errorf("AnyTLS handshake was incomplete: %v", body)
			}
			if _, loaded := body["hysteria2_identity_protocol"]; loaded {
				t.Error("AnyTLS node advertised the Hysteria2 capability")
			}
			assertNodeAuth(t, r)
			_, _ = w.Write([]byte(accepted))
		case "/api/node/v1/config":
			assertNodeAuth(t, r)
			_, _ = w.Write([]byte(document))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := newTypedTLSTestClient(t, server, NodeTypeAnytls)
	if client.Protocol() != "anytls" {
		t.Fatalf("AnyTLS node reported protocol %q", client.Protocol())
	}
	if _, err := client.Handshake(context.Background()); err != nil {
		t.Fatalf("AnyTLS handshake rejected: %v", err)
	}
	snapshot, err := client.Config(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	want := InboundConfig{Protocol: "anytls", Anytls: AnytlsConfig{
		Listen: "::", Port: 31472, ServerName: "rn-sea.acris.cc",
		CertificatePath: "/etc/nanmonee-node/tls-anytls/fullchain.pem",
		PrivateKeyPath:  "/etc/nanmonee-node/tls-anytls/privkey.pem",
	}}
	if snapshot.Config != want {
		t.Fatalf("unexpected AnyTLS config: %+v", snapshot.Config)
	}
	if snapshot.Config.Hysteria2.Port != 0 || snapshot.Config.Vless.Port != 0 {
		t.Fatal("the AnyTLS mapping carried another protocol's settings")
	}
}

func TestAnyTLSCapabilityIsMandatoryAndExclusive(t *testing.T) {
	const base = `"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000}`
	// Every foreign-capability case also carries the AnyTLS capability, so only a
	// deliberate exclusivity check can reject it.
	const own = `"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","anytls_auth_protocol":"nanmonee-anytls-auth-v1"`
	for name, testCase := range map[string]struct {
		nodeType string
		body     string
	}{
		"anytls without capability":        {NodeTypeAnytls, `{` + base + `,"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1"}}`},
		"anytls with hysteria2 capability": {NodeTypeAnytls, `{` + base + `,"authorization":{` + own + `,"hysteria2_identity_protocol":"nanmonee-hysteria2-identity-v1"}}`},
		"anytls with tuic capability":      {NodeTypeAnytls, `{` + base + `,"authorization":{` + own + `,"tuic_identity_protocol":"nanmonee-tuic-identity-v1"}}`},
		"vless with anytls capability":     {NodeTypeVless, `{` + base + `,"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","anytls_auth_protocol":"nanmonee-anytls-auth-v1"}}`},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(testCase.body))
		}))
		_, err := newTypedTLSTestClient(t, server, testCase.nodeType).Handshake(context.Background())
		server.Close()
		if !errors.Is(err, ErrIncompatible) {
			t.Fatalf("%s was accepted: %v", name, err)
		}
	}
}

func TestHysteria2CapabilityIsExclusive(t *testing.T) {
	const base = `"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000}`
	const own = `"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","hysteria2_identity_protocol":"nanmonee-hysteria2-identity-v1"`
	accepted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{` + base + `,"authorization":{` + own + `}}`))
	}))
	if _, err := newTypedTLSTestClient(t, accepted, NodeTypeHysteria).Handshake(context.Background()); err != nil {
		t.Fatalf("the matching capability was rejected: %v", err)
	}
	accepted.Close()
	for name, body := range map[string]string{
		"hysteria with anytls capability": `{` + base + `,"authorization":{` + own + `,"anytls_auth_protocol":"nanmonee-anytls-auth-v1"}}`,
		"hysteria with tuic capability":   `{` + base + `,"authorization":{` + own + `,"tuic_identity_protocol":"nanmonee-tuic-identity-v1"}}`,
		"hysteria without capability":     `{` + base + `,"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1"}}`,
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		_, err := newTypedTLSTestClient(t, server, NodeTypeHysteria).Handshake(context.Background())
		server.Close()
		if !errors.Is(err, ErrIncompatible) {
			t.Fatalf("%s was accepted: %v", name, err)
		}
	}
}

func TestAnyTLSConfigRejectsUnsupportedShapes(t *testing.T) {
	valid := `{"protocol":"anytls","version":2,"listen_ip":"::","server_port":31472,"server_name":"rn-sea.acris.cc","cert_config":{"cert_mode":"file","cert_file":"/etc/nanmonee-node/tls-anytls/fullchain.pem","key_file":"/etc/nanmonee-node/tls-anytls/privkey.pem"}}`
	replace := func(from, to string) string {
		return strings.Replace(valid, from, to, 1)
	}
	for name, document := range map[string]string{
		"hysteria2 protocol": replace(`"protocol":"anytls"`, `"protocol":"hysteria2"`),
		"version 1":          replace(`"version":2`, `"version":1`),
		"cert mode":          replace(`"cert_mode":"file"`, `"cert_mode":"none"`),
		"relative cert":      replace(`/etc/nanmonee-node/tls-anytls/fullchain.pem`, `fullchain.pem`),
		"relative key":       replace(`/etc/nanmonee-node/tls-anytls/privkey.pem`, `privkey.pem`),
		"zero port":          replace(`"server_port":31472`, `"server_port":0`),
		"invalid listen":     replace(`"listen_ip":"::"`, `"listen_ip":"not-an-ip"`),
		"no server name":     replace(`"server_name":"rn-sea.acris.cc"`, `"server_name":""`),
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(document))
		}))
		_, err := newTypedTLSTestClient(t, server, NodeTypeAnytls).Config(context.Background(), "")
		server.Close()
		if !errors.Is(err, ErrIncompatible) {
			t.Fatalf("%s was accepted: %v", name, err)
		}
	}
}

func TestTUICHandshakeAndConfig(t *testing.T) {
	const accepted = `{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","tuic_identity_protocol":"nanmonee-tuic-identity-v1"}}`
	const document = `{"protocol":"tuic","version":2,"listen_ip":"::","server_port":10544,"server_name":"rn-sea.acris.cc","cert_config":{"cert_mode":"file","cert_file":"/etc/nanmonee-node/tls-tuic/fullchain.pem","key_file":"/etc/nanmonee-node/tls-tuic/privkey.pem"}}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/node/v1/handshake":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error("handshake body is not JSON")
			}
			if body["tuic_identity_protocol"] != TUICIdentityProtocol {
				t.Errorf("TUIC handshake was incomplete: %v", body)
			}
			if _, loaded := body["anytls_auth_protocol"]; loaded {
				t.Error("TUIC node advertised the AnyTLS capability")
			}
			assertNodeAuth(t, r)
			_, _ = w.Write([]byte(accepted))
		case "/api/node/v1/config":
			assertNodeAuth(t, r)
			_, _ = w.Write([]byte(document))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := newTypedTLSTestClient(t, server, NodeTypeTuic)
	if client.Protocol() != "tuic" {
		t.Fatalf("TUIC node reported protocol %q", client.Protocol())
	}
	if _, err := client.Handshake(context.Background()); err != nil {
		t.Fatalf("TUIC handshake rejected: %v", err)
	}
	snapshot, err := client.Config(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	want := InboundConfig{Protocol: "tuic", Tuic: TuicConfig{
		Listen: "::", Port: 10544, ServerName: "rn-sea.acris.cc",
		CertificatePath: "/etc/nanmonee-node/tls-tuic/fullchain.pem",
		PrivateKeyPath:  "/etc/nanmonee-node/tls-tuic/privkey.pem",
	}}
	if snapshot.Config != want {
		t.Fatalf("unexpected TUIC config: %+v", snapshot.Config)
	}
	if snapshot.Config.Hysteria2.Port != 0 || snapshot.Config.Anytls.Port != 0 || snapshot.Config.Vless.Port != 0 {
		t.Fatal("the TUIC mapping carried another protocol's settings")
	}
}

func TestTUICCapabilityIsMandatoryAndExclusive(t *testing.T) {
	const base = `"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000}`
	// Foreign-capability cases for a TUIC node also carry the TUIC capability, so
	// only the exclusivity check can reject them.
	const own = `"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","tuic_identity_protocol":"nanmonee-tuic-identity-v1"`
	for name, testCase := range map[string]struct {
		nodeType string
		body     string
	}{
		"tuic without capability":        {NodeTypeTuic, `{` + base + `,"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1"}}`},
		"tuic with anytls capability":    {NodeTypeTuic, `{` + base + `,"authorization":{` + own + `,"anytls_auth_protocol":"nanmonee-anytls-auth-v1"}}`},
		"tuic with hysteria2 capability": {NodeTypeTuic, `{` + base + `,"authorization":{` + own + `,"hysteria2_identity_protocol":"nanmonee-hysteria2-identity-v1"}}`},
		"vless with tuic capability":     {NodeTypeVless, `{` + base + `,"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","tuic_identity_protocol":"nanmonee-tuic-identity-v1"}}`},
		"anytls with tuic capability":    {NodeTypeAnytls, `{` + base + `,"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","anytls_auth_protocol":"nanmonee-anytls-auth-v1","tuic_identity_protocol":"nanmonee-tuic-identity-v1"}}`},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(testCase.body))
		}))
		_, err := newTypedTLSTestClient(t, server, testCase.nodeType).Handshake(context.Background())
		server.Close()
		if !errors.Is(err, ErrIncompatible) {
			t.Fatalf("%s was accepted: %v", name, err)
		}
	}
}

func TestTUICConfigRejectsUnsupportedShapes(t *testing.T) {
	valid := `{"protocol":"tuic","version":2,"listen_ip":"::","server_port":10544,"server_name":"rn-sea.acris.cc","cert_config":{"cert_mode":"file","cert_file":"/etc/nanmonee-node/tls-tuic/fullchain.pem","key_file":"/etc/nanmonee-node/tls-tuic/privkey.pem"}}`
	replace := func(from, to string) string {
		return strings.Replace(valid, from, to, 1)
	}
	for name, document := range map[string]string{
		"anytls protocol": replace(`"protocol":"tuic"`, `"protocol":"anytls"`),
		"version 1":       replace(`"version":2`, `"version":1`),
		"cert mode":       replace(`"cert_mode":"file"`, `"cert_mode":"none"`),
		"relative cert":   replace(`/etc/nanmonee-node/tls-tuic/fullchain.pem`, `fullchain.pem`),
		"relative key":    replace(`/etc/nanmonee-node/tls-tuic/privkey.pem`, `privkey.pem`),
		"zero port":       replace(`"server_port":10544`, `"server_port":0`),
		"invalid listen":  replace(`"listen_ip":"::"`, `"listen_ip":"not-an-ip"`),
		"no server name":  replace(`"server_name":"rn-sea.acris.cc"`, `"server_name":""`),
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(document))
		}))
		_, err := newTypedTLSTestClient(t, server, NodeTypeTuic).Config(context.Background(), "")
		server.Close()
		if !errors.Is(err, ErrIncompatible) {
			t.Fatalf("%s was accepted: %v", name, err)
		}
	}
}
