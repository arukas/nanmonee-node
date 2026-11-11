package panel

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Protocol identifiers negotiated with the panel. Both directions must agree on
// the same values; anything else is a hard failure rather than a downgrade.
const (
	// BackendProtocol identifies this agent implementation to the panel.
	BackendProtocol = "nanmonee-node-v1"
	// TrafficProtocol identifies the reliable batch report format.
	TrafficProtocol = "nanmonee-traffic-v1"
	// AccessProtocol identifies the member authorization snapshot format.
	AccessProtocol = "nanmonee-access-v1"
	// Hysteria2IdentityProtocol is the capability the panel and this agent must
	// both confirm before a Hysteria2 node may authenticate members by name.
	Hysteria2IdentityProtocol = "nanmonee-hysteria2-identity-v1"
	// AnyTLSAuthProtocol is the capability the panel and this agent must both
	// confirm before an AnyTLS node may authenticate streams by password.
	AnyTLSAuthProtocol = "nanmonee-anytls-auth-v1"
	// TUICIdentityProtocol is the capability the panel and this agent must both
	// confirm before a TUIC node may authenticate QUIC sessions by UUID.
	TUICIdentityProtocol = "nanmonee-tuic-identity-v1"

	// NodeTypeVless is the panel node type for a Reality/Vision node.
	NodeTypeVless = "vless"
	// NodeTypeHysteria is the panel protocol for a Hysteria2 node.
	NodeTypeHysteria = "hysteria2"
	// NodeTypeAnytls is the panel node type for an AnyTLS node.
	NodeTypeAnytls = "anytls"
	// NodeTypeTuic is the panel node type for a TUIC v5 node.
	NodeTypeTuic = "tuic"

	// MaxBatchEntries is the panel's per-batch member limit.
	MaxBatchEntries = 1000
)

// Kernel identity reported to the panel during the handshake. The panel does not
// validate it today, but it makes the agent inspectable in panel-side records.
const (
	KernelVersion = "v1.14.4"
	KernelCommit  = "c005f35300ce76427dc285481ec5695f5b179cd2"
)

var (
	// ErrRejected means the panel explicitly denied this node. Existing
	// authorizations must be dropped; queued traffic must be kept.
	ErrRejected = errors.New("panel rejected the node")
	// ErrTransient means the failure may clear on its own. The last accepted
	// authorization stays in force.
	ErrTransient = errors.New("panel is temporarily unavailable")
	// ErrIncompatible means the panel and agent do not share a protocol or
	// version. Retrying cannot help.
	ErrIncompatible = errors.New("panel and agent are incompatible")
	// ErrBatchRejected means the panel refused one immutable traffic batch and
	// will refuse it forever; it says nothing about the node identity, so the
	// authorization and the rest of the queue stay valid.
	ErrBatchRejected = errors.New("panel permanently rejected one traffic batch")
)

// RejectedError carries the HTTP status that produced a rejection.
type RejectedError struct{ StatusCode int }

func (e *RejectedError) Error() string {
	return fmt.Sprintf("panel rejected the node with status %d", e.StatusCode)
}

func (e *RejectedError) Unwrap() error { return ErrRejected }

// BatchRejectedError is a conflict on a single batch: the panel already stored
// this batch ID with different content, so resending can never succeed.
type BatchRejectedError struct{ StatusCode int }

func (e *BatchRejectedError) Error() string {
	return fmt.Sprintf("panel rejected this batch with status %d", e.StatusCode)
}

func (e *BatchRejectedError) Unwrap() error { return ErrBatchRejected }

// HandshakeRequest is the POST body sent to /api/node/v1/handshake.
type HandshakeRequest struct {
	BackendProtocol           string `json:"node_backend_protocol"`
	BackendVersion            string `json:"node_backend_version"`
	KernelVersion             string `json:"kernel_version"`
	KernelCommit              string `json:"kernel_commit"`
	ReportProtocol            string `json:"report_protocol"`
	AccessProtocol            string `json:"access_protocol"`
	Hysteria2IdentityProtocol string `json:"hysteria2_identity_protocol,omitempty"`
	AnyTLSAuthProtocol        string `json:"anytls_auth_protocol,omitempty"`
	TUICIdentityProtocol      string `json:"tuic_identity_protocol,omitempty"`
}

// HandshakeResponse is the negotiated capability set.
type HandshakeResponse struct {
	WebSocket struct {
		Enabled bool `json:"enabled"`
	} `json:"websocket"`
	Settings struct {
		PullInterval int `json:"pull_interval"`
		PushInterval int `json:"push_interval"`
	} `json:"settings"`
	Reporting struct {
		Protocol   string `json:"protocol"`
		MaxEntries int    `json:"max_entries"`
	} `json:"reporting"`
	Authorization struct {
		Protocol                  string `json:"protocol"`
		BackendProtocol           string `json:"node_backend_protocol"`
		Hysteria2IdentityProtocol string `json:"hysteria2_identity_protocol"`
		AnyTLSAuthProtocol        string `json:"anytls_auth_protocol"`
		TUICIdentityProtocol      string `json:"tuic_identity_protocol"`
	} `json:"authorization"`
}

// VlessConfig is the inbound description returned by /api/node/v1/config.
type VlessConfig struct {
	Listen          string
	Port            uint32
	ServerName      string
	HandshakeServer string
	HandshakePort   uint32
	PrivateKey      string
	ShortID         string
}

// Hysteria2Config is the TLS inbound description returned by /api/node/v1/config.
type Hysteria2Config struct {
	Listen          string
	Port            uint32
	ServerName      string
	CertificatePath string
	PrivateKeyPath  string
}

// AnytlsConfig is the TLS inbound description returned by /api/node/v1/config.
type AnytlsConfig struct {
	Listen          string
	Port            uint32
	ServerName      string
	CertificatePath string
	PrivateKeyPath  string
}

// TuicConfig is the TUIC v5 inbound description returned by /api/node/v1/config.
type TuicConfig struct {
	Listen          string
	Port            uint32
	ServerName      string
	CertificatePath string
	PrivateKeyPath  string
}

// InboundConfig is the protocol-neutral shape the worker applies. Protocol uses
// the runtime spelling: "vless", "hysteria2", "anytls", or "tuic".
type InboundConfig struct {
	Protocol  string
	Vless     VlessConfig
	Hysteria2 Hysteria2Config
	Anytls    AnytlsConfig
	Tuic      TuicConfig
}

// ConfigSnapshot pairs the inbound description with its opaque content tag.
type ConfigSnapshot struct {
	Config InboundConfig
	ETag   string
	// NotModified reports that the panel answered 304 for our If-None-Match.
	NotModified bool
}

// Member is one authorized VLESS user.
type Member struct {
	MemberID int64
	UUID     string
}

// UserSnapshot is the authorization payload with its opaque content tag.
type UserSnapshot struct {
	Members []Member
	ETag    string
	// NotModified reports that the panel answered 304 for our If-None-Match.
	NotModified bool
}

// TrafficBatch is the immutable unit the panel accounts for exactly once.
type TrafficBatch struct {
	Protocol    string           `json:"protocol"`
	BatchID     string           `json:"batch_id"`
	SampledFrom int64            `json:"sampled_from"`
	SampledTo   int64            `json:"sampled_to"`
	Traffic     map[int][2]int64 `json:"traffic"`
}

// batchAck is the confirmation returned by /api/node/v1/report.
type batchAck struct {
	Protocol string `json:"protocol"`
	BatchID  string `json:"batch_id"`
}

// configResponse mirrors the panel's /api/node/v1/config document.
type configResponse struct {
	Protocol    string `json:"protocol"`
	Version     int    `json:"version"`
	ListenIP    string `json:"listen_ip"`
	ServerPort  uint32 `json:"server_port"`
	ServerName  string `json:"server_name"`
	Network     string `json:"network"`
	Flow        string `json:"flow"`
	TLSSettings struct {
		ServerName string          `json:"server_name"`
		Dest       string          `json:"dest"`
		PrivateKey string          `json:"private_key"`
		ShortID    json.RawMessage `json:"short_id"`
	} `json:"tls_settings"`
	CertConfig struct {
		CertMode string `json:"cert_mode"`
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
	} `json:"cert_config"`
}

// userResponse mirrors the panel's /api/node/v1/users document.
type userResponse struct {
	Users []struct {
		ID   int64  `json:"id"`
		UUID string `json:"uuid"`
	} `json:"users"`
}
