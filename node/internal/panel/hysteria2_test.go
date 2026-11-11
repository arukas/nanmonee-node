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

func newHysteriaTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	client, err := NewClient(Options{URL: server.URL, Token: testToken, NodeID: 7, NodeType: NodeTypeHysteria})
	if err != nil {
		t.Fatal(err)
	}
	trusted := server.Client()
	client.http = &http.Client{
		Timeout:       trusted.Timeout,
		Transport:     trusted.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return client
}

func TestHysteria2ClientSendsAndRequiresItsIdentityCapability(t *testing.T) {
	accepted := `{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","hysteria2_identity_protocol":"nanmonee-hysteria2-identity-v1"}}`
	var received map[string]any
	var lastRequest *http.Request
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastRequest = r
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("request body: %v", err)
		}
		_, _ = w.Write([]byte(accepted))
	}))
	defer server.Close()

	handshake, err := newHysteriaTestClient(t, server).Handshake(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if handshake.Authorization.Hysteria2IdentityProtocol != Hysteria2IdentityProtocol {
		t.Fatalf("identity capability was not confirmed: %+v", handshake.Authorization)
	}
	if received["hysteria2_identity_protocol"] != Hysteria2IdentityProtocol {
		t.Fatalf("the agent did not announce its capability: %+v", received)
	}
	assertNodeAuth(t, lastRequest)

	for name, document := range map[string]string{
		"missing":       `{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1"}}`,
		"wrong":         `{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","hysteria2_identity_protocol":"nanmonee-hysteria2-identity-v2"}}`,
		"empty":         `{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","hysteria2_identity_protocol":""}}`,
		"unexpected":    `{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","hysteria2_identity_protocol":"nanmonee-anytls-auth-v1"}}`,
		"wrong backend": `{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"xboard-node-v1","hysteria2_identity_protocol":"nanmonee-hysteria2-identity-v1"}}`,
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(document))
		}))
		_, err := newHysteriaTestClient(t, server).Handshake(context.Background())
		server.Close()
		if !errors.Is(err, ErrIncompatible) {
			t.Fatalf("%s identity capability was accepted: %v", name, err)
		}
	}
}

func TestVlessClientRejectsTheHysteria2Capability(t *testing.T) {
	document := `{"websocket":{"enabled":false},"settings":{"pull_interval":60,"push_interval":60},"reporting":{"protocol":"nanmonee-traffic-v1","max_entries":1000},"authorization":{"protocol":"nanmonee-access-v1","node_backend_protocol":"nanmonee-node-v1","hysteria2_identity_protocol":"nanmonee-hysteria2-identity-v1"}}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(document))
	}))
	defer server.Close()
	_, err := newTLSTestClient(t, server).Handshake(context.Background())
	if !errors.Is(err, ErrIncompatible) {
		t.Fatalf("a VLESS node accepted the Hysteria2 capability: %v", err)
	}
}

func TestHysteria2ConfigIsParsedAndHotUpdatable(t *testing.T) {
	document := `{"protocol":"hysteria2","version":2,"listen_ip":"::","server_port":51443,"server_name":"rn-sea.acris.cc","cert_config":{"cert_mode":"file","cert_file":"/etc/nanmonee/tls-hysteria2/fullchain.pem","key_file":"/etc/nanmonee/tls-hysteria2/privkey.pem"}}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertNodeAuth(t, r)
		w.Header().Set("ETag", `"hy2"`)
		_, _ = w.Write([]byte(document))
	}))
	defer server.Close()

	client := newHysteriaTestClient(t, server)
	snapshot, err := client.Config(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Config.Protocol != "hysteria2" || snapshot.Config.Hysteria2 != (Hysteria2Config{
		Listen:          "::",
		Port:            51443,
		ServerName:      "rn-sea.acris.cc",
		CertificatePath: "/etc/nanmonee/tls-hysteria2/fullchain.pem",
		PrivateKeyPath:  "/etc/nanmonee/tls-hysteria2/privkey.pem",
	}) {
		t.Fatalf("unexpected config: %+v", snapshot.Config)
	}
	if snapshot.ETag != `"hy2"` || client.Protocol() != "hysteria2" || client.NodeType() != "hysteria2" {
		t.Fatalf("unexpected identity: %+v", snapshot)
	}
}

func TestHysteria2ConfigRejectsIncompatibleDocuments(t *testing.T) {
	document := `{"protocol":"hysteria2","version":2,"listen_ip":"::","server_port":51443,"server_name":"rn-sea.acris.cc","cert_config":{"cert_mode":"file","cert_file":"/etc/c.pem","key_file":"/etc/k.pem"}}`
	for name, test := range map[string]struct{ from, to, reason string }{
		"vless document":       {`"protocol":"hysteria2"`, `"protocol":"vless"`, "protocol"},
		"legacy protocol":      {`"protocol":"hysteria2"`, `"protocol":"hysteria"`, "protocol"},
		"version 1":            {`"version":2`, `"version":1`, "version"},
		"no version":           {`"version":2,`, ``, "version"},
		"inline cert":          {`"cert_mode":"file"`, `"cert_mode":"inline"`, "certificate mode"},
		"missing cert file":    {`"cert_file":"/etc/c.pem",`, ``, "certificate path"},
		"relative cert file":   {`"cert_file":"/etc/c.pem"`, `"cert_file":"tls/c.pem"`, "certificate path"},
		"relative private key": {`"key_file":"/etc/k.pem"`, `"key_file":"k.pem"`, "private key path"},
		"no server name":       {`"server_name":"rn-sea.acris.cc",`, ``, "server name"},
		"conflicting names":    {`"server_name":"rn-sea.acris.cc",`, `"server_name":"rn-sea.acris.cc","tls_settings":{"server_name":"b.example"},`, "conflicting server names"},
		"no listen":            {`"listen_ip":"::",`, ``, "listen address"},
		"bad listen":           {`"listen_ip":"::"`, `"listen_ip":"not-an-ip"`, "listen address"},
		"zero port":            {`"server_port":51443`, `"server_port":0`, "server port"},
		"huge port":            {`"server_port":51443`, `"server_port":70000`, "server port"},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := strings.Replace(document, test.from, test.to, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(invalid))
			}))
			defer server.Close()
			_, err := newHysteriaTestClient(t, server).Config(context.Background(), "")
			if !errors.Is(err, ErrIncompatible) || !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("expected rejection for %s: %v", test.reason, err)
			}
		})
	}
	// The server name may be carried only by tls_settings; it is not ambiguous.
	document = strings.Replace(document, `"server_name":"rn-sea.acris.cc"`, `"tls_settings":{"server_name":"rn-sea.acris.cc"}`, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(document))
	}))
	defer server.Close()
	snapshot, err := newHysteriaTestClient(t, server).Config(context.Background(), "")
	if err != nil || snapshot.Config.Hysteria2.ServerName != "rn-sea.acris.cc" {
		t.Fatalf("the fallback server name was rejected: %+v %v", snapshot.Config, err)
	}
}

func TestHysteria2IncompleteDocumentsAreTransient(t *testing.T) {
	for _, document := range []string{`{}`, `null`, `{"protocol":"hysteria"}`, `{"protocol":"hysteria","version":2}`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(document))
		}))
		_, err := newHysteriaTestClient(t, server).Config(context.Background(), "")
		server.Close()
		if !errors.Is(err, ErrTransient) && !errors.Is(err, ErrIncompatible) {
			t.Fatalf("%s was not treated as a fault: %v", document, err)
		}
	}
}

func TestHysteria2IdentityIsStableAndSecretFree(t *testing.T) {
	client, err := NewClient(Options{URL: "https://panel.example.com", Token: testToken, NodeID: 7, NodeType: NodeTypeHysteria})
	if err != nil {
		t.Fatal(err)
	}
	if client.Identity() != "https://panel.example.com|7|hysteria2" {
		t.Fatalf("unexpected identity: %s", client.Identity())
	}
	if strings.Contains(client.Identity(), testToken) {
		t.Fatal("identity leaked the token")
	}
}
