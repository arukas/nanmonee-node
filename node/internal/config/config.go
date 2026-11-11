package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"nanmonee/node/internal/panel"
	noderuntime "nanmonee/node/internal/runtime"
)

const maxConfigBytes = 64 << 10

type Control struct {
	Listen string `json:"listen"`
	Secret string `json:"secret"`
}

type vlessConfig struct {
	Listen            string `json:"listen"`
	Port              uint32 `json:"port"`
	ServerName        string `json:"server_name"`
	HandshakeServer   string `json:"handshake_server"`
	HandshakePort     uint32 `json:"handshake_port"`
	RealityPrivateKey string `json:"reality_private_key"`
	RealityShortID    string `json:"reality_short_id"`
}

type hysteria2Config struct {
	Listen          string `json:"listen"`
	Port            uint32 `json:"port"`
	ServerName      string `json:"server_name"`
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
}

type anytlsConfig struct {
	Listen          string `json:"listen"`
	Port            uint32 `json:"port"`
	ServerName      string `json:"server_name"`
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
}

type tuicConfig struct {
	Listen          string `json:"listen"`
	Port            uint32 `json:"port"`
	ServerName      string `json:"server_name"`
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
}

type panelConfig struct {
	URL      string `json:"url"`
	Token    string `json:"token"`
	NodeID   int64  `json:"node_id"`
	NodeType string `json:"protocol"`
}

type agentConfig struct {
	BackendProtocol string `json:"backend_protocol"`
	Kernel          string `json:"kernel"`
}

type trafficConfig struct {
	DataDir string `json:"data_dir"`
}

type diskConfig struct {
	Control   *Control         `json:"control"`
	Vless     *vlessConfig     `json:"vless"`
	Hysteria2 *hysteria2Config `json:"hysteria2"`
	Anytls    *anytlsConfig    `json:"anytls"`
	Tuic      *tuicConfig      `json:"tuic"`
	Panel     *panelConfig     `json:"panel"`
	Agent     *agentConfig     `json:"agent"`
	Traffic   *trafficConfig   `json:"traffic"`
}

// Config is the validated startup configuration. Exactly one of Inbound and
// Panel is set: a panel-owned node learns its inbound from the panel.
type Config struct {
	Control Control
	Inbound noderuntime.Config
	Panel   panel.Options
	DataDir string
	// PanelOwned means the worker, not the control plane, writes authorizations.
	PanelOwned bool
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open startup config: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return Config{}, errors.New("startup config must be a regular owner-only file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil || len(content) > maxConfigBytes {
		return Config{}, errors.New("startup config exceeds the size limit")
	}
	var disk diskConfig
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&disk); err != nil {
		return Config{}, errors.New("startup config is not valid JSON")
	}
	if err := ensureEOF(decoder); err != nil {
		return Config{}, errors.New("startup config contains multiple JSON values")
	}
	if disk.Control == nil {
		return Config{}, errors.New("startup config must contain a control section")
	}
	address, err := netip.ParseAddrPort(disk.Control.Listen)
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 {
		return Config{}, errors.New("control listen must be an explicit loopback address and port")
	}
	secretLength := len(disk.Control.Secret)
	if secretLength < 32 || secretLength > 256 || strings.ContainsAny(disk.Control.Secret, " \t\r\n") {
		return Config{}, errors.New("control secret must be 32 to 256 non-whitespace characters")
	}
	inboundSections := 0
	for _, present := range []bool{disk.Vless != nil, disk.Hysteria2 != nil, disk.Anytls != nil, disk.Tuic != nil, disk.Panel != nil} {
		if present {
			inboundSections++
		}
	}
	if inboundSections != 1 {
		return Config{}, errors.New("startup config must set exactly one of vless, hysteria2, anytls, tuic, or panel")
	}
	config := Config{Control: *disk.Control}
	if disk.Panel != nil {
		if err := checkAgent(disk.Agent); err != nil {
			return Config{}, err
		}
		options, dataDir, err := loadPanel(*disk.Panel, disk.Traffic)
		if err != nil {
			return Config{}, err
		}
		config.Panel = options
		config.DataDir = dataDir
		config.PanelOwned = true
		return config, nil
	}
	if disk.Vless != nil {
		config.Inbound = noderuntime.VlessRuntimeConfig(noderuntime.VlessConfig{
			Listen:            disk.Vless.Listen,
			Port:              disk.Vless.Port,
			ServerName:        disk.Vless.ServerName,
			HandshakeServer:   disk.Vless.HandshakeServer,
			HandshakePort:     disk.Vless.HandshakePort,
			RealityPrivateKey: disk.Vless.RealityPrivateKey,
			RealityShortID:    disk.Vless.RealityShortID,
		})
		if err := noderuntime.ValidateConfig(config.Inbound); err != nil {
			return Config{}, errors.New("startup VLESS config is invalid")
		}
		return config, nil
	}
	if disk.Hysteria2 != nil {
		config.Inbound = noderuntime.Hysteria2RuntimeConfig(noderuntime.Hysteria2Config{
			Listen:          disk.Hysteria2.Listen,
			Port:            disk.Hysteria2.Port,
			ServerName:      disk.Hysteria2.ServerName,
			CertificatePath: disk.Hysteria2.CertificatePath,
			PrivateKeyPath:  disk.Hysteria2.PrivateKeyPath,
		})
		if err := noderuntime.ValidateConfig(config.Inbound); err != nil {
			return Config{}, errors.New("startup Hysteria2 config is invalid")
		}
		return config, nil
	}
	if disk.Anytls != nil {
		config.Inbound = noderuntime.AnytlsRuntimeConfig(noderuntime.AnytlsConfig{
			Listen:          disk.Anytls.Listen,
			Port:            disk.Anytls.Port,
			ServerName:      disk.Anytls.ServerName,
			CertificatePath: disk.Anytls.CertificatePath,
			PrivateKeyPath:  disk.Anytls.PrivateKeyPath,
		})
		if err := noderuntime.ValidateConfig(config.Inbound); err != nil {
			return Config{}, errors.New("startup AnyTLS config is invalid")
		}
		return config, nil
	}
	config.Inbound = noderuntime.TuicRuntimeConfig(noderuntime.TuicConfig{
		Listen:          disk.Tuic.Listen,
		Port:            disk.Tuic.Port,
		ServerName:      disk.Tuic.ServerName,
		CertificatePath: disk.Tuic.CertificatePath,
		PrivateKeyPath:  disk.Tuic.PrivateKeyPath,
	})
	if err := noderuntime.ValidateConfig(config.Inbound); err != nil {
		return Config{}, errors.New("startup TUIC config is invalid")
	}
	return config, nil
}

// ProtocolForNodeType maps the panel's node type onto the runtime protocol.
func ProtocolForNodeType(nodeType string) (string, error) {
	switch nodeType {
	case panel.NodeTypeVless:
		return noderuntime.ProtocolVless, nil
	case panel.NodeTypeHysteria:
		return noderuntime.ProtocolHysteria2, nil
	case panel.NodeTypeAnytls:
		return noderuntime.ProtocolAnytls, nil
	case panel.NodeTypeTuic:
		return noderuntime.ProtocolTuic, nil
	default:
		return "", fmt.Errorf("unsupported panel node type %q", nodeType)
	}
}

// checkAgent verifies the exported agent section when the operator keeps it.
// A mismatch fails closed instead of silently running a different contract.
func checkAgent(agent *agentConfig) error {
	if agent == nil {
		return nil
	}
	if agent.BackendProtocol != panel.BackendProtocol {
		return fmt.Errorf("agent.backend_protocol must be %s", panel.BackendProtocol)
	}
	if agent.Kernel != "singbox" {
		return errors.New("agent.kernel must be singbox")
	}
	return nil
}

func loadPanel(options panelConfig, traffic *trafficConfig) (panel.Options, string, error) {
	if traffic == nil || traffic.DataDir == "" {
		return panel.Options{}, "", errors.New("a panel node requires traffic.data_dir for its durable queue")
	}
	if !filepath.IsAbs(traffic.DataDir) {
		return panel.Options{}, "", errors.New("traffic.data_dir must be an absolute path")
	}
	validated := panel.Options{
		URL:      options.URL,
		Token:    options.Token,
		NodeID:   options.NodeID,
		NodeType: options.NodeType,
	}
	if _, err := panel.Validate(validated); err != nil {
		return panel.Options{}, "", err
	}
	return validated, traffic.DataDir, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}
