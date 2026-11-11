package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `{
  "control": {"listen": "127.0.0.1:39535", "secret": "12345678901234567890123456789012"},
  "vless": {
    "listen": "127.0.0.1",
    "port": 31460,
    "server_name": "www.apple.com",
    "handshake_server": "www.apple.com",
    "handshake_port": 443,
    "reality_private_key": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
    "reality_short_id": "0123456789abcdef"
  }
}`

func writeConfig(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node.json")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRequiresLoopbackAndOwnerOnlyConfig(t *testing.T) {
	config, err := Load(writeConfig(t, validConfig, 0600))
	if err != nil || config.Control.Listen != "127.0.0.1:39535" || config.Inbound.Vless.Port != 31460 {
		t.Fatalf("valid config rejected: %+v, %v", config, err)
	}

	tests := map[string]string{
		"public control listen": strings.Replace(validConfig, "127.0.0.1:39535", "0.0.0.0:39535", 1),
		"unknown field":         strings.Replace(validConfig, `"control":`, `"unknown": true, "control":`, 1),
		"short secret":          strings.Replace(validConfig, "12345678901234567890123456789012", "short", 1),
		"trailing document":     validConfig + `{}`,
		"invalid proxy port":    strings.Replace(validConfig, `"port": 31460`, `"port": 0`, 1),
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, content, 0600)); err == nil {
				t.Fatal("invalid config was accepted")
			}
		})
	}
	if _, err := Load(writeConfig(t, validConfig, 0644)); err == nil {
		t.Fatal("group/world-readable secret config was accepted")
	}
}

func TestLoadErrorDoesNotEchoSecret(t *testing.T) {
	content := strings.Replace(validConfig, `"port": 31460`, `"port": 0`, 1)
	_, err := Load(writeConfig(t, content, 0600))
	if err == nil || strings.Contains(err.Error(), "12345678901234567890123456789012") {
		t.Fatalf("config error exposed secret: %v", err)
	}
}

const panelFileConfig = `{
  "control": {"listen": "127.0.0.1:39535", "secret": "12345678901234567890123456789012"},
  "panel": {
    "url": "https://panel.example.com",
    "token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "node_id": 12,
    "protocol": "vless"
  },
  "traffic": {"data_dir": "/var/lib/nanmonee-node"}
}`

func TestPanelModeIsExclusiveAndNeedsATrafficDirectory(t *testing.T) {
	config, err := Load(writeConfig(t, panelFileConfig, 0600))
	if err != nil {
		t.Fatalf("panel config rejected: %v", err)
	}
	if !config.PanelOwned || config.Panel.NodeID != 12 || config.DataDir != "/var/lib/nanmonee-node" {
		t.Fatalf("panel fields were not decoded: %+v", config)
	}
	if config.Inbound.Protocol != "" || config.Inbound.Vless.Port != 0 {
		t.Fatal("panel mode must not carry a local listener")
	}

	both := strings.Replace(panelFileConfig, `"traffic":`, `"vless": {"listen": "127.0.0.1", "port": 31460}, "traffic":`, 1)
	if _, err := Load(writeConfig(t, both, 0600)); err == nil {
		t.Fatal("accepted both a local VLESS listener and a panel")
	}
	if _, err := Load(writeConfig(t, validConfig, 0600)); err != nil {
		t.Fatalf("self-managed config regressed: %v", err)
	}
	for name, content := range map[string]string{
		"missing data dir":  strings.Replace(panelFileConfig, `"traffic": {"data_dir": "/var/lib/nanmonee-node"}`, `"traffic": {}`, 1),
		"relative data dir": strings.Replace(panelFileConfig, "/var/lib/nanmonee-node", "relative/dir", 1),
		"plain http panel":  strings.Replace(panelFileConfig, "https://panel.example.com", "http://panel.example.com", 1),
		"empty token":       strings.Replace(panelFileConfig, `"token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`, `"token": ""`, 1),
	} {
		if _, err := Load(writeConfig(t, content, 0600)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestExportedAgentSectionIsVerified(t *testing.T) {
	withAgent := strings.Replace(panelFileConfig, `"traffic":`, `"agent": {"backend_protocol": "nanmonee-node-v1", "kernel": "singbox"}, "traffic":`, 1)
	if _, err := Load(writeConfig(t, withAgent, 0600)); err != nil {
		t.Fatalf("the exported agent section was rejected: %v", err)
	}
	for name, content := range map[string]string{
		"wrong backend protocol": strings.Replace(withAgent, `"nanmonee-node-v1"`, `"xboard-node-v1"`, 1),
		"unknown kernel":         strings.Replace(withAgent, `"singbox"`, `"xray"`, 1),
	} {
		if _, err := Load(writeConfig(t, content, 0600)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	// The section is optional so an operator can hand-write a minimal file.
	if _, err := Load(writeConfig(t, panelFileConfig, 0600)); err != nil {
		t.Fatalf("an absent agent section was rejected: %v", err)
	}
}

func TestHysteria2SelfManagedConfigIsExclusive(t *testing.T) {
	directory := t.TempDir()
	certificate := filepath.Join(directory, "cert.pem")
	privateKey := filepath.Join(directory, "key.pem")
	for _, path := range []string{certificate, privateKey} {
		if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	hysteria2 := `{
  "control": {"listen": "127.0.0.1:39535", "secret": "12345678901234567890123456789012"},
  "hysteria2": {"listen": "::", "port": 51443, "server_name": "rn-sea.acris.cc", "certificate_path": "` + certificate + `", "private_key_path": "` + privateKey + `"}
}`
	config, err := Load(writeConfig(t, hysteria2, 0600))
	if err != nil || config.Inbound.Protocol != "hysteria2" || config.Inbound.Hysteria2.Port != 51443 || config.PanelOwned {
		t.Fatalf("valid Hysteria2 config rejected: %+v %v", config, err)
	}
	both := strings.Replace(hysteria2, `"hysteria2":`, `"vless": {"listen": "127.0.0.1", "port": 31460}, "hysteria2":`, 1)
	if _, err := Load(writeConfig(t, both, 0600)); err == nil {
		t.Fatal("accepted both a VLESS and a Hysteria2 listener")
	}
	panelAndHysteria := strings.Replace(panelFileConfig, `"protocol": "vless"`, `"protocol": "hysteria2"`, 1)
	panelAndHysteria = strings.Replace(panelAndHysteria, `"traffic":`, `"hysteria2": {"listen": "::", "port": 51443, "server_name": "rn-sea.acris.cc", "certificate_path": "`+certificate+`", "private_key_path": "`+privateKey+`"}, "traffic":`, 1)
	if _, err := Load(writeConfig(t, panelAndHysteria, 0600)); err == nil {
		t.Fatal("accepted a local Hysteria2 listener together with a panel")
	}
	for name, content := range map[string]string{
		"relative certificate": strings.Replace(hysteria2, certificate, "cert.pem", 1),
		"zero port":            strings.Replace(hysteria2, `"port": 51443`, `"port": 0`, 1),
		"empty server name":    strings.Replace(hysteria2, `"server_name": "rn-sea.acris.cc"`, `"server_name": ""`, 1),
	} {
		if _, err := Load(writeConfig(t, content, 0600)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestAnyTLSSelfManagedConfigIsExclusive(t *testing.T) {
	directory := t.TempDir()
	certificate := filepath.Join(directory, "cert.pem")
	privateKey := filepath.Join(directory, "key.pem")
	for _, path := range []string{certificate, privateKey} {
		if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	anytls := `{
  "control": {"listen": "127.0.0.1:39536", "secret": "12345678901234567890123456789012"},
  "anytls": {"listen": "::", "port": 31472, "server_name": "rn-sea.acris.cc", "certificate_path": "` + certificate + `", "private_key_path": "` + privateKey + `"}
}`
	config, err := Load(writeConfig(t, anytls, 0600))
	if err != nil || config.Inbound.Protocol != "anytls" || config.Inbound.Anytls.Port != 31472 || config.PanelOwned {
		t.Fatalf("valid AnyTLS config rejected: %+v %v", config, err)
	}
	both := strings.Replace(anytls, `"anytls":`, `"vless": {"listen": "127.0.0.1", "port": 31460}, "anytls":`, 1)
	if _, err := Load(writeConfig(t, both, 0600)); err == nil {
		t.Fatal("accepted both a VLESS and an AnyTLS listener")
	}
	panelAndAnyTLS := strings.Replace(panelFileConfig, `"protocol": "vless"`, `"protocol": "anytls"`, 1)
	panelAndAnyTLS = strings.Replace(panelAndAnyTLS, `"traffic":`, `"anytls": {"listen": "::", "port": 31472, "server_name": "rn-sea.acris.cc", "certificate_path": "`+certificate+`", "private_key_path": "`+privateKey+`"}, "traffic":`, 1)
	if _, err := Load(writeConfig(t, panelAndAnyTLS, 0600)); err == nil {
		t.Fatal("accepted a local AnyTLS listener together with a panel")
	}
	for name, content := range map[string]string{
		"relative certificate": strings.Replace(anytls, certificate, "cert.pem", 1),
		"zero port":            strings.Replace(anytls, `"port": 31472`, `"port": 0`, 1),
		"empty server name":    strings.Replace(anytls, `"server_name": "rn-sea.acris.cc"`, `"server_name": ""`, 1),
	} {
		if _, err := Load(writeConfig(t, content, 0600)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestTUICSelfManagedConfigIsExclusive(t *testing.T) {
	directory := t.TempDir()
	certificate := filepath.Join(directory, "cert.pem")
	privateKey := filepath.Join(directory, "key.pem")
	for _, path := range []string{certificate, privateKey} {
		if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	tuic := `{
  "control": {"listen": "127.0.0.1:39537", "secret": "12345678901234567890123456789012"},
  "tuic": {"listen": "::", "port": 10544, "server_name": "rn-sea.acris.cc", "certificate_path": "` + certificate + `", "private_key_path": "` + privateKey + `"}
}`
	config, err := Load(writeConfig(t, tuic, 0600))
	if err != nil || config.Inbound.Protocol != "tuic" || config.Inbound.Tuic.Port != 10544 || config.PanelOwned {
		t.Fatalf("valid TUIC config rejected: %+v %v", config, err)
	}
	both := strings.Replace(tuic, `"tuic":`, `"vless": {"listen": "127.0.0.1", "port": 31460}, "tuic":`, 1)
	if _, err := Load(writeConfig(t, both, 0600)); err == nil {
		t.Fatal("accepted both a VLESS and a TUIC listener")
	}
	panelAndTUIC := strings.Replace(panelFileConfig, `"protocol": "vless"`, `"protocol": "tuic"`, 1)
	panelAndTUIC = strings.Replace(panelAndTUIC, `"traffic":`, `"tuic": {"listen": "::", "port": 10544, "server_name": "rn-sea.acris.cc", "certificate_path": "`+certificate+`", "private_key_path": "`+privateKey+`"}, "traffic":`, 1)
	if _, err := Load(writeConfig(t, panelAndTUIC, 0600)); err == nil {
		t.Fatal("accepted a local TUIC listener together with a panel")
	}
	for name, content := range map[string]string{
		"relative certificate": strings.Replace(tuic, certificate, "cert.pem", 1),
		"zero port":            strings.Replace(tuic, `"port": 10544`, `"port": 0`, 1),
		"empty server name":    strings.Replace(tuic, `"server_name": "rn-sea.acris.cc"`, `"server_name": ""`, 1),
	} {
		if _, err := Load(writeConfig(t, content, 0600)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestPanelNodeTypeSelectsTheRuntimeProtocol(t *testing.T) {
	for nodeType, want := range map[string]string{"vless": "vless", "hysteria2": "hysteria2", "anytls": "anytls", "tuic": "tuic"} {
		protocol, err := ProtocolForNodeType(nodeType)
		if err != nil || protocol != want {
			t.Fatalf("node type %q mapped to %q: %v", nodeType, protocol, err)
		}
	}
	if _, err := ProtocolForNodeType("quic"); err == nil {
		t.Fatal("an unsupported node type was mapped")
	}
}

func TestPanelConfigCarriesTheHysteriaProtocol(t *testing.T) {
	content := strings.Replace(panelFileConfig, `"protocol": "vless"`, `"protocol": "hysteria2"`, 1)
	config, err := Load(writeConfig(t, content, 0600))
	if err != nil || config.Panel.NodeType != "hysteria2" || config.Inbound.Protocol != "" {
		t.Fatalf("panel Hysteria2 config rejected: %+v %v", config, err)
	}
}

func TestPanelConfigCarriesTheAnyTLSNodeType(t *testing.T) {
	content := strings.Replace(panelFileConfig, `"protocol": "vless"`, `"protocol": "anytls"`, 1)
	config, err := Load(writeConfig(t, content, 0600))
	if err != nil || config.Panel.NodeType != "anytls" || config.Inbound.Protocol != "" {
		t.Fatalf("panel AnyTLS config rejected: %+v %v", config, err)
	}
}
