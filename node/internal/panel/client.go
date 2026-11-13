package panel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// maxResponseBytes bounds every panel response we are willing to buffer.
	maxResponseBytes = 8 << 20
	// AgentVersion is reported to the panel and to the control plane.
	AgentVersion = "0.10.0-n1"
)

// Options configures a Client. URL, Token, NodeID and NodeType are required.
type Options struct {
	URL      string
	Token    string
	NodeID   int64
	NodeType string
	// Timeout bounds one HTTP round trip.
	Timeout time.Duration
	// HTTPClient overrides the transport, mainly so tests can trust a local
	// certificate. Redirect handling and the timeout are always enforced here.
	HTTPClient *http.Client
}

// Client talks to the four node-facing panel endpoints under /api/node/v1.
type Client struct {
	base     *url.URL
	token    string
	nodeID   int64
	nodeType string
	http     *http.Client
}

// NewClient validates the endpoint and returns a client that never follows
// redirects, so panel credentials cannot leak to a third host.
func NewClient(options Options) (*Client, error) {
	base, err := Validate(options)
	if err != nil {
		return nil, err
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	// Redirects are never followed: the token must not reach another host.
	refuseRedirects := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client := &http.Client{Timeout: timeout, CheckRedirect: refuseRedirects}
	if options.HTTPClient != nil {
		client.Transport = options.HTTPClient.Transport
	} else {
		client.Transport = &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
		}
	}
	return &Client{
		base:     base,
		token:    options.Token,
		nodeID:   options.NodeID,
		nodeType: options.NodeType,
		http:     client,
	}, nil
}

// Validate checks the panel endpoint without opening a connection, so the
// startup loader rejects a bad credential before the kernel ever starts.
func Validate(options Options) (*url.URL, error) {
	if options.NodeID <= 0 {
		return nil, errors.New("panel node ID must be positive")
	}
	switch options.NodeType {
	case NodeTypeVless, NodeTypeHysteria, NodeTypeAnytls, NodeTypeTuic:
	default:
		return nil, errors.New("only the vless, hysteria, anytls, and tuic node types are supported")
	}
	if len(options.Token) < 32 || len(options.Token) > 256 || strings.ContainsAny(options.Token, " \t\r\n") {
		return nil, errors.New("panel token must be 32 to 256 non-whitespace characters")
	}
	base, err := url.Parse(options.URL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("panel URL must be an https origin without userinfo, query, or fragment")
	}
	return base, nil
}

// Identity is the stable, secret-free string that names this node's spool.
func (c *Client) Identity() string {
	return c.base.Scheme + "://" + c.base.Host + c.base.Path + "|" + strconv.FormatInt(c.nodeID, 10) + "|" + c.nodeType
}

// Host is safe to log; the token is not part of it.
func (c *Client) Host() string { return c.base.Host }

// NodeType is the canonical protocol: "vless", "hysteria2", "anytls", or "tuic".
func (c *Client) NodeType() string { return c.nodeType }

// Protocol is the runtime-side name; it is identical to the canonical protocol.
func (c *Client) Protocol() string { return c.nodeType }

// Handshake negotiates capabilities. It fails closed on any mismatch.
func (c *Client) Handshake(ctx context.Context) (HandshakeResponse, error) {
	request := HandshakeRequest{
		BackendProtocol: BackendProtocol,
		BackendVersion:  AgentVersion,
		KernelVersion:   KernelVersion,
		KernelCommit:    KernelCommit,
		ReportProtocol:  TrafficProtocol,
		AccessProtocol:  AccessProtocol,
	}
	if c.nodeType == NodeTypeHysteria {
		request.Hysteria2IdentityProtocol = Hysteria2IdentityProtocol
	}
	if c.nodeType == NodeTypeAnytls {
		request.AnyTLSAuthProtocol = AnyTLSAuthProtocol
	}
	if c.nodeType == NodeTypeTuic {
		request.TUICIdentityProtocol = TUICIdentityProtocol
	}
	body, err := json.Marshal(request)
	if err != nil {
		return HandshakeResponse{}, err
	}
	response, err := c.doJSON(ctx, http.MethodPost, "/api/node/v1/handshake", body, "")
	if err != nil {
		return HandshakeResponse{}, err
	}
	var handshake HandshakeResponse
	if err := decodeStrict(response, &handshake); err != nil {
		return HandshakeResponse{}, err
	}
	if err := validateHandshake(handshake, c.nodeType); err != nil {
		return HandshakeResponse{}, err
	}
	return handshake, nil
}

func validateHandshake(handshake HandshakeResponse, nodeType string) error {
	if handshake.WebSocket.Enabled {
		return fmt.Errorf("%w: the panel expects websocket streaming", ErrIncompatible)
	}
	if handshake.Reporting.Protocol != TrafficProtocol || handshake.Reporting.MaxEntries != MaxBatchEntries {
		return fmt.Errorf("%w: the panel does not accept %s batches of %d entries", ErrIncompatible, TrafficProtocol, MaxBatchEntries)
	}
	if handshake.Authorization.Protocol != AccessProtocol {
		return fmt.Errorf("%w: the panel does not accept %s snapshots", ErrIncompatible, AccessProtocol)
	}
	if handshake.Authorization.BackendProtocol != BackendProtocol {
		return fmt.Errorf("%w: the panel does not accept backend protocol %s", ErrIncompatible, BackendProtocol)
	}
	switch nodeType {
	case NodeTypeHysteria:
		if handshake.Authorization.Hysteria2IdentityProtocol != Hysteria2IdentityProtocol {
			return fmt.Errorf("%w: the panel did not confirm %s", ErrIncompatible, Hysteria2IdentityProtocol)
		}
		if handshake.Authorization.AnyTLSAuthProtocol != "" {
			return fmt.Errorf("%w: the panel returned an AnyTLS capability for a Hysteria2 node", ErrIncompatible)
		}
		if handshake.Authorization.TUICIdentityProtocol != "" {
			return fmt.Errorf("%w: the panel returned a TUIC capability for a Hysteria2 node", ErrIncompatible)
		}
	case NodeTypeAnytls:
		if handshake.Authorization.AnyTLSAuthProtocol != AnyTLSAuthProtocol {
			return fmt.Errorf("%w: the panel did not confirm %s", ErrIncompatible, AnyTLSAuthProtocol)
		}
		if handshake.Authorization.Hysteria2IdentityProtocol != "" {
			return fmt.Errorf("%w: the panel returned a Hysteria2 capability for an AnyTLS node", ErrIncompatible)
		}
		if handshake.Authorization.TUICIdentityProtocol != "" {
			return fmt.Errorf("%w: the panel returned a TUIC capability for an AnyTLS node", ErrIncompatible)
		}
	case NodeTypeTuic:
		if handshake.Authorization.TUICIdentityProtocol != TUICIdentityProtocol {
			return fmt.Errorf("%w: the panel did not confirm %s", ErrIncompatible, TUICIdentityProtocol)
		}
		if handshake.Authorization.Hysteria2IdentityProtocol != "" {
			return fmt.Errorf("%w: the panel returned a Hysteria2 capability for a TUIC node", ErrIncompatible)
		}
		if handshake.Authorization.AnyTLSAuthProtocol != "" {
			return fmt.Errorf("%w: the panel returned an AnyTLS capability for a TUIC node", ErrIncompatible)
		}
	default:
		if handshake.Authorization.Hysteria2IdentityProtocol != "" {
			return fmt.Errorf("%w: the panel returned a Hysteria2 capability for a VLESS node", ErrIncompatible)
		}
		if handshake.Authorization.AnyTLSAuthProtocol != "" {
			return fmt.Errorf("%w: the panel returned an AnyTLS capability for a VLESS node", ErrIncompatible)
		}
		if handshake.Authorization.TUICIdentityProtocol != "" {
			return fmt.Errorf("%w: the panel returned a TUIC capability for a VLESS node", ErrIncompatible)
		}
	}
	if handshake.Settings.PullInterval <= 0 || handshake.Settings.PushInterval <= 0 {
		return fmt.Errorf("%w: the panel returned invalid intervals", ErrIncompatible)
	}
	return nil
}

// Config fetches the VLESS inbound. An empty etag forces a full response.
func (c *Client) Config(ctx context.Context, etag string) (ConfigSnapshot, error) {
	response, err := c.do(ctx, http.MethodGet, "/api/node/v1/config", nil, nil, etag)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	if response.status == http.StatusNotModified {
		return ConfigSnapshot{ETag: etag, NotModified: true}, nil
	}
	var document configResponse
	if err := decodeStrict(response, &document); err != nil {
		return ConfigSnapshot{}, err
	}
	config, err := document.inbound(c.nodeType)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	return ConfigSnapshot{Config: config, ETag: response.etag}, nil
}

func (d configResponse) inbound(nodeType string) (InboundConfig, error) {
	switch nodeType {
	case NodeTypeHysteria:
		config, err := d.hysteria2()
		return InboundConfig{Protocol: "hysteria2", Hysteria2: config}, err
	case NodeTypeAnytls:
		config, err := d.anytls()
		return InboundConfig{Protocol: "anytls", Anytls: config}, err
	case NodeTypeTuic:
		config, err := d.tuic()
		return InboundConfig{Protocol: "tuic", Tuic: config}, err
	default:
		config, err := d.vless()
		return InboundConfig{Protocol: "vless", Vless: config}, err
	}
}

func (d configResponse) hysteria2() (Hysteria2Config, error) {
	if d.Protocol == "" {
		return Hysteria2Config{}, fmt.Errorf("%w: the panel returned no protocol", ErrTransient)
	}
	if d.Protocol != NodeTypeHysteria {
		return Hysteria2Config{}, fmt.Errorf("%w: the panel offered protocol %q to a Hysteria2 node", ErrIncompatible, d.Protocol)
	}
	if d.Version != 2 {
		return Hysteria2Config{}, fmt.Errorf("%w: the panel offered Hysteria2 version %d", ErrIncompatible, d.Version)
	}
	if d.ServerPort == 0 || d.ServerPort > 65535 {
		return Hysteria2Config{}, fmt.Errorf("%w: the panel returned an invalid server port", ErrIncompatible)
	}
	if d.ListenIP == "" {
		return Hysteria2Config{}, fmt.Errorf("%w: the panel returned no listen address", ErrIncompatible)
	}
	if _, err := netip.ParseAddr(d.ListenIP); err != nil {
		return Hysteria2Config{}, fmt.Errorf("%w: the panel returned an invalid listen address", ErrIncompatible)
	}
	serverName := d.ServerName
	if serverName != "" && d.TLSSettings.ServerName != "" && serverName != d.TLSSettings.ServerName {
		return Hysteria2Config{}, fmt.Errorf("%w: the panel returned conflicting server names", ErrIncompatible)
	}
	if serverName == "" {
		serverName = d.TLSSettings.ServerName
	}
	if serverName == "" {
		return Hysteria2Config{}, fmt.Errorf("%w: the panel returned no TLS server name", ErrIncompatible)
	}
	if d.CertConfig.CertMode != "file" {
		return Hysteria2Config{}, fmt.Errorf("%w: the panel returned certificate mode %q", ErrIncompatible, d.CertConfig.CertMode)
	}
	for label, path := range map[string]string{"certificate": d.CertConfig.CertFile, "private key": d.CertConfig.KeyFile} {
		if !filepath.IsAbs(path) {
			return Hysteria2Config{}, fmt.Errorf("%w: the panel returned a relative %s path", ErrIncompatible, label)
		}
	}
	return Hysteria2Config{
		Listen:          d.ListenIP,
		Port:            d.ServerPort,
		ServerName:      serverName,
		CertificatePath: d.CertConfig.CertFile,
		PrivateKeyPath:  d.CertConfig.KeyFile,
	}, nil
}

func (d configResponse) anytls() (AnytlsConfig, error) {
	if d.Protocol == "" {
		return AnytlsConfig{}, fmt.Errorf("%w: the panel returned no protocol", ErrTransient)
	}
	if d.Protocol != NodeTypeAnytls {
		return AnytlsConfig{}, fmt.Errorf("%w: the panel offered protocol %q to an AnyTLS node", ErrIncompatible, d.Protocol)
	}
	if d.Version != 2 {
		return AnytlsConfig{}, fmt.Errorf("%w: the panel offered AnyTLS version %d", ErrIncompatible, d.Version)
	}
	if d.ServerPort == 0 || d.ServerPort > 65535 {
		return AnytlsConfig{}, fmt.Errorf("%w: the panel returned an invalid server port", ErrIncompatible)
	}
	if d.ListenIP == "" {
		return AnytlsConfig{}, fmt.Errorf("%w: the panel returned no listen address", ErrIncompatible)
	}
	if _, err := netip.ParseAddr(d.ListenIP); err != nil {
		return AnytlsConfig{}, fmt.Errorf("%w: the panel returned an invalid listen address", ErrIncompatible)
	}
	serverName := d.ServerName
	if serverName != "" && d.TLSSettings.ServerName != "" && serverName != d.TLSSettings.ServerName {
		return AnytlsConfig{}, fmt.Errorf("%w: the panel returned conflicting server names", ErrIncompatible)
	}
	if serverName == "" {
		serverName = d.TLSSettings.ServerName
	}
	if serverName == "" {
		return AnytlsConfig{}, fmt.Errorf("%w: the panel returned no TLS server name", ErrIncompatible)
	}
	if d.CertConfig.CertMode != "file" {
		return AnytlsConfig{}, fmt.Errorf("%w: the panel returned certificate mode %q", ErrIncompatible, d.CertConfig.CertMode)
	}
	for label, path := range map[string]string{"certificate": d.CertConfig.CertFile, "private key": d.CertConfig.KeyFile} {
		if !filepath.IsAbs(path) {
			return AnytlsConfig{}, fmt.Errorf("%w: the panel returned a relative %s path", ErrIncompatible, label)
		}
	}
	return AnytlsConfig{
		Listen:          d.ListenIP,
		Port:            d.ServerPort,
		ServerName:      serverName,
		CertificatePath: d.CertConfig.CertFile,
		PrivateKeyPath:  d.CertConfig.KeyFile,
	}, nil
}

func (d configResponse) tuic() (TuicConfig, error) {
	if d.Protocol == "" {
		return TuicConfig{}, fmt.Errorf("%w: the panel returned no protocol", ErrTransient)
	}
	if d.Protocol != NodeTypeTuic {
		return TuicConfig{}, fmt.Errorf("%w: the panel offered protocol %q to a TUIC node", ErrIncompatible, d.Protocol)
	}
	if d.Version != 2 {
		return TuicConfig{}, fmt.Errorf("%w: the panel offered TUIC version %d", ErrIncompatible, d.Version)
	}
	if d.ServerPort == 0 || d.ServerPort > 65535 {
		return TuicConfig{}, fmt.Errorf("%w: the panel returned an invalid server port", ErrIncompatible)
	}
	if d.ListenIP == "" {
		return TuicConfig{}, fmt.Errorf("%w: the panel returned no listen address", ErrIncompatible)
	}
	if _, err := netip.ParseAddr(d.ListenIP); err != nil {
		return TuicConfig{}, fmt.Errorf("%w: the panel returned an invalid listen address", ErrIncompatible)
	}
	serverName := d.ServerName
	if serverName != "" && d.TLSSettings.ServerName != "" && serverName != d.TLSSettings.ServerName {
		return TuicConfig{}, fmt.Errorf("%w: the panel returned conflicting server names", ErrIncompatible)
	}
	if serverName == "" {
		serverName = d.TLSSettings.ServerName
	}
	if serverName == "" {
		return TuicConfig{}, fmt.Errorf("%w: the panel returned no TLS server name", ErrIncompatible)
	}
	if d.CertConfig.CertMode != "file" {
		return TuicConfig{}, fmt.Errorf("%w: the panel returned certificate mode %q", ErrIncompatible, d.CertConfig.CertMode)
	}
	for label, path := range map[string]string{"certificate": d.CertConfig.CertFile, "private key": d.CertConfig.KeyFile} {
		if !filepath.IsAbs(path) {
			return TuicConfig{}, fmt.Errorf("%w: the panel returned a relative %s path", ErrIncompatible, label)
		}
	}
	return TuicConfig{
		Listen:          d.ListenIP,
		Port:            d.ServerPort,
		ServerName:      serverName,
		CertificatePath: d.CertConfig.CertFile,
		PrivateKeyPath:  d.CertConfig.KeyFile,
	}, nil
}

func (d configResponse) vless() (VlessConfig, error) {
	if d.Protocol == "" {
		return VlessConfig{}, fmt.Errorf("%w: the panel returned no protocol", ErrTransient)
	}
	if d.Protocol != "vless" {
		return VlessConfig{}, fmt.Errorf("%w: the panel offered protocol %q", ErrIncompatible, d.Protocol)
	}
	if d.Network != "" && d.Network != "tcp" {
		return VlessConfig{}, fmt.Errorf("%w: the panel offered transport %q", ErrIncompatible, d.Network)
	}
	if d.Flow != "" && d.Flow != "xtls-rprx-vision" {
		return VlessConfig{}, fmt.Errorf("%w: the panel offered flow %q", ErrIncompatible, d.Flow)
	}
	if d.Network == "" || d.Flow == "" {
		return VlessConfig{}, fmt.Errorf("%w: the panel returned incomplete VLESS settings", ErrTransient)
	}
	host, port, err := splitDestination(d.TLSSettings.Dest)
	if err != nil {
		return VlessConfig{}, err
	}
	shortID, err := firstShortID(d.TLSSettings.ShortID)
	if err != nil {
		return VlessConfig{}, err
	}
	if d.ServerPort == 0 || d.ServerPort > 65535 {
		return VlessConfig{}, fmt.Errorf("%w: the panel returned an invalid server port", ErrIncompatible)
	}
	if d.TLSSettings.ServerName == "" || d.TLSSettings.PrivateKey == "" {
		return VlessConfig{}, fmt.Errorf("%w: the panel returned incomplete Reality settings", ErrIncompatible)
	}
	return VlessConfig{
		Listen:          "::",
		Port:            d.ServerPort,
		ServerName:      d.TLSSettings.ServerName,
		HandshakeServer: host,
		HandshakePort:   port,
		PrivateKey:      d.TLSSettings.PrivateKey,
		ShortID:         shortID,
	}, nil
}

// splitDestination parses the "host:port" Reality destination. IPv6 forms are
// bracketed by the panel; a bare IPv6 literal is rejected rather than guessed.
func splitDestination(destination string) (string, uint32, error) {
	if destination == "" {
		return "", 0, fmt.Errorf("%w: the panel returned no Reality destination", ErrIncompatible)
	}
	index := strings.LastIndex(destination, ":")
	if index <= 0 || index == len(destination)-1 {
		return "", 0, fmt.Errorf("%w: the Reality destination is malformed", ErrIncompatible)
	}
	host := strings.TrimSuffix(strings.TrimPrefix(destination[:index], "["), "]")
	port, err := strconv.ParseUint(destination[index+1:], 10, 16)
	if err != nil || port == 0 || host == "" {
		return "", 0, fmt.Errorf("%w: the Reality destination is malformed", ErrIncompatible)
	}
	return host, uint32(port), nil
}

// firstShortID accepts both the list form and a bare string.
func firstShortID(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("%w: the panel returned no Reality short ID", ErrIncompatible)
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		if len(list) == 0 || list[0] == "" {
			return "", fmt.Errorf("%w: the panel returned an empty Reality short ID", ErrIncompatible)
		}
		return list[0], nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil && single != "" {
		return single, nil
	}
	return "", fmt.Errorf("%w: the Reality short ID is malformed", ErrIncompatible)
}

// Users fetches the authorized members. An empty etag forces a full response.
func (c *Client) Users(ctx context.Context, etag string) (UserSnapshot, error) {
	response, err := c.do(ctx, http.MethodGet, "/api/node/v1/users", nil, nil, etag)
	if err != nil {
		return UserSnapshot{}, err
	}
	if response.status == http.StatusNotModified {
		return UserSnapshot{ETag: etag, NotModified: true}, nil
	}
	var document userResponse
	if err := decodeStrict(response, &document); err != nil {
		return UserSnapshot{}, err
	}
	if document.Users == nil {
		return UserSnapshot{}, fmt.Errorf("%w: the panel returned no users array", ErrTransient)
	}
	members := make([]Member, 0, len(document.Users))
	for _, user := range document.Users {
		members = append(members, Member{MemberID: user.ID, UUID: user.UUID})
	}
	return UserSnapshot{Members: members, ETag: response.etag}, nil
}

// ProbeTargets pulls the addresses this node should measure.
//
// The list is global rather than per node, and the panel returns it without an
// ETag, so every pull is a full document.
func (c *Client) ProbeTargets(ctx context.Context) ([]ProbeTarget, error) {
	response, err := c.do(ctx, http.MethodGet, "/api/node/v1/probes", nil, nil, "")
	if err != nil {
		return nil, err
	}
	var document probeTargetResponse
	if err := decodeStrict(response, &document); err != nil {
		return nil, err
	}
	if document.Targets == nil {
		return nil, fmt.Errorf("%w: the panel returned no targets array", ErrTransient)
	}
	return document.Targets, nil
}

// ReportProbeSamples submits measurements and requires the panel to accept them.
func (c *Client) ReportProbeSamples(ctx context.Context, samples ProbeSamples) error {
	payload, err := json.Marshal(samples)
	if err != nil {
		return err
	}
	response, err := c.do(ctx, http.MethodPost, "/api/node/v1/probes", nil, payload, "")
	if err != nil {
		return err
	}
	var ack struct {
		Accepted int `json:"accepted"`
	}
	if err := decodeStrict(response, &ack); err != nil {
		return err
	}
	if ack.Accepted < 0 || ack.Accepted > len(samples.Results) {
		return fmt.Errorf("%w: the panel acknowledged %d of %d probe samples", ErrTransient, ack.Accepted, len(samples.Results))
	}
	return nil
}

// ReportTrafficBatch submits one immutable batch and requires an exact echo.
func (c *Client) ReportTrafficBatch(ctx context.Context, batch TrafficBatch) error {
	// The panel authenticates the report from the JSON body only, and rejects
	// any POST that also carries a query string.
	payload, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	response, err := c.do(ctx, http.MethodPost, "/api/node/v1/report", nil, payload, "")
	if err != nil {
		// A conflict here is the panel refusing this one batch because it already
		// stored the same ID with different bytes. The node identity is still
		// valid, so it must not be reported as a node-wide rejection.
		var rejected *RejectedError
		if errors.As(err, &rejected) && rejected.StatusCode == http.StatusConflict {
			return &BatchRejectedError{StatusCode: rejected.StatusCode}
		}
		return err
	}
	var ack batchAck
	if err := decodeStrict(response, &ack); err != nil {
		return err
	}
	if ack.Protocol != TrafficProtocol || ack.BatchID != batch.BatchID {
		return fmt.Errorf("%w: the panel acknowledged a different batch", ErrTransient)
	}
	return nil
}

type rawResponse struct {
	status int
	body   []byte
	etag   string
}

// do performs one request and normalizes every failure into the three sentinel
// classes. Errors never include the request URL, which carries the token.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body []byte, etag string) (rawResponse, error) {
	target := *c.base
	target.Path = strings.TrimSuffix(c.base.Path, "/") + path
	target.RawQuery = query.Encode()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return rawResponse{}, fmt.Errorf("%w: build %s request", ErrTransient, path)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "nanmonee-node/"+AgentVersion)
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("X-Nanmonee-Node-Id", strconv.FormatInt(c.nodeID, 10))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := c.http.Do(request)
	if err != nil {
		// *url.Error embeds the full URL; the headers still must not be logged.
		var urlError *url.Error
		if errors.As(err, &urlError) {
			err = urlError.Err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return rawResponse{}, ctxErr
		}
		return rawResponse{}, fmt.Errorf("%w: %s %s: %v", ErrTransient, method, path, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusConflict {
		return rawResponse{}, &RejectedError{StatusCode: response.StatusCode}
	}
	if response.StatusCode == http.StatusNotModified {
		return rawResponse{status: http.StatusNotModified}, nil
	}
	if response.StatusCode != http.StatusOK {
		// Read a bounded prefix only; never echo a body that might contain secrets.
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return rawResponse{}, fmt.Errorf("%w: %s %s returned status %d", ErrTransient, method, path, response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return rawResponse{}, fmt.Errorf("%w: read %s response", ErrTransient, path)
	}
	if len(content) > maxResponseBytes {
		return rawResponse{}, fmt.Errorf("%w: the %s response exceeds the size limit", ErrTransient, path)
	}
	return rawResponse{status: response.StatusCode, body: content, etag: response.Header.Get("ETag")}, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body []byte, etag string) (rawResponse, error) {
	return c.do(ctx, method, path, nil, body, etag)
}

func decodeStrict(response rawResponse, target any) error {
	if len(response.body) == 0 {
		return fmt.Errorf("%w: the panel returned an empty document", ErrTransient)
	}
	if err := json.Unmarshal(response.body, target); err != nil {
		return fmt.Errorf("%w: the panel returned malformed JSON", ErrTransient)
	}
	return nil
}
