package runtime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/gofrs/uuid/v5"
)

var (
	ErrInvalidArgument    = errors.New("invalid snapshot")
	ErrConflict           = errors.New("snapshot state conflict")
	ErrFailedPrecondition = errors.New("runtime state does not allow apply")
	ErrResourceExhausted  = errors.New("snapshot resource limit exceeded")
	ErrRuntime            = errors.New("runtime apply failed")
)

const (
	StateEmpty    = "empty"
	StateRunning  = "running"
	StateDegraded = "degraded"
)

const (
	// ProtocolVless is the Reality/XTLS-Vision inbound this agent has served since T35.
	ProtocolVless = "vless"
	// ProtocolHysteria2 is the QUIC inbound added in T37.
	ProtocolHysteria2 = "hysteria2"
	// ProtocolAnytls is the multiplexed TLS inbound added in T38.
	ProtocolAnytls = "anytls"
	// ProtocolTuic is the QUIC inbound added in T39.
	ProtocolTuic = "tuic"
)

type VlessConfig struct {
	Listen            string
	Port              uint32
	ServerName        string
	HandshakeServer   string
	HandshakePort     uint32
	RealityPrivateKey string
	RealityShortID    string
}

// Hysteria2Config carries the listener and the absolute certificate paths. The
// key is read from disk by the kernel; its content never crosses this boundary.
type Hysteria2Config struct {
	Listen          string
	Port            uint32
	ServerName      string
	CertificatePath string
	PrivateKeyPath  string
}

// AnytlsConfig carries the listener and the absolute certificate paths for the
// TLS inbound. AnyTLS authenticates multiplexed streams with a per-member
// password over an ordinary TLS session.
type AnytlsConfig struct {
	Listen          string
	Port            uint32
	ServerName      string
	CertificatePath string
	PrivateKeyPath  string
}

// TuicConfig carries the listener and the absolute certificate paths for the
// TUIC v5 inbound. The node pins ALPN h3, cubic congestion control, native UDP
// relay and 0-RTT disabled; none of those are configurable from the panel.
type TuicConfig struct {
	Listen          string
	Port            uint32
	ServerName      string
	CertificatePath string
	PrivateKeyPath  string
}

// Config is the inbound this runtime serves. Exactly one protocol is active per
// process: a node is deployed as a VLESS, Hysteria2, AnyTLS, or TUIC endpoint.
type Config struct {
	Protocol  string
	Vless     VlessConfig
	Hysteria2 Hysteria2Config
	Anytls    AnytlsConfig
	Tuic      TuicConfig
}

// VlessRuntimeConfig wraps a VLESS inbound as a runtime Config.
func VlessRuntimeConfig(config VlessConfig) Config {
	return Config{Protocol: ProtocolVless, Vless: config}
}

// Hysteria2RuntimeConfig wraps a Hysteria2 inbound as a runtime Config.
func Hysteria2RuntimeConfig(config Hysteria2Config) Config {
	return Config{Protocol: ProtocolHysteria2, Hysteria2: config}
}

// AnytlsRuntimeConfig wraps an AnyTLS inbound as a runtime Config.
func AnytlsRuntimeConfig(config AnytlsConfig) Config {
	return Config{Protocol: ProtocolAnytls, Anytls: config}
}

// TuicRuntimeConfig wraps a TUIC v5 inbound as a runtime Config.
func TuicRuntimeConfig(config TuicConfig) Config {
	return Config{Protocol: ProtocolTuic, Tuic: config}
}

// ValidProtocol reports whether the runtime understands this protocol.
func ValidProtocol(protocol string) bool {
	return protocol == ProtocolVless || protocol == ProtocolHysteria2 ||
		protocol == ProtocolAnytls || protocol == ProtocolTuic
}

type User struct {
	MemberID int64
	UUID     string
}

type ApplyInput struct {
	ExpectedRuntimeID     string
	ExpectedStateRevision uint64
	Config                *Config
	Users                 *[]User
}

type Status struct {
	State               string
	RuntimeID           string
	StateRevision       uint64
	ConfigSHA256        string
	AuthorizationSHA256 string
	LastError           string
	// Protocol is the inbound this process serves: "vless", "hysteria2", or
	// "anytls".
	Protocol string
	// PanelOwned is true when the panel worker is the only writer.
	PanelOwned bool
	// Configured is false until a valid inbound configuration was applied.
	Configured bool
}

type UsageSnapshot struct {
	RuntimeID string
	Members   map[int64][2]int64
}

// kernelUser is the protocol-neutral credential the kernel receives. The name is
// the non-secret member/generation identity; the secret is the member UUID that
// VLESS presents as its UUID and Hysteria2/AnyTLS present as their password.
type kernelUser struct {
	Name   string
	Secret string
}

type kernel interface {
	UpdateUsers(users []kernelUser) error
	Close() error
}

type kernelFactory func(ctx context.Context, config Config, users []kernelUser, tracker *connectionTracker) (kernel, error)

type Runtime struct {
	mu                  sync.Mutex
	factory             kernelFactory
	tracker             *connectionTracker
	kernel              kernel
	runtimeID           string
	revision            uint64
	protocol            string
	config              Config
	users               []User
	identities          map[string]int64
	generations         map[int64]uint64
	generationFloor     uint64
	configDigest        string
	authorizationDigest string
	lastError           string
	applyFailed         bool
	configured          bool
	externalWrites      bool
	closed              bool
}

// New starts a self-managed runtime whose inbound comes from the startup file.
func New(config Config) (*Runtime, error) {
	return newRuntimeWithFactory(config, newSingBoxKernel)
}

// NewPanelOwned returns a runtime that starts without a kernel and refuses
// external writes. The panel worker becomes the only writer, so the proxy is
// closed until the first successful snapshot arrives. The protocol is fixed at
// startup so status can report it before any snapshot exists.
func NewPanelOwned(protocol string) (*Runtime, error) {
	runtime, err := newPanelOwnedWithFactory(protocol, newSingBoxKernel)
	if err != nil {
		return nil, err
	}
	return runtime, nil
}

func newPanelOwnedWithFactory(protocol string, factory kernelFactory) (*Runtime, error) {
	if !ValidProtocol(protocol) {
		return nil, fmt.Errorf("%w: unsupported protocol %q", ErrInvalidArgument, protocol)
	}
	runtimeID, err := newRuntimeID()
	if err != nil {
		return nil, err
	}
	return &Runtime{
		factory:             factory,
		tracker:             newConnectionTracker(),
		runtimeID:           runtimeID,
		protocol:            protocol,
		identities:          make(map[string]int64),
		generations:         make(map[int64]uint64),
		authorizationDigest: digestUsers(nil),
		externalWrites:      false,
	}, nil
}

func newRuntimeWithFactory(config Config, factory kernelFactory) (*Runtime, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	runtimeID, err := newRuntimeID()
	if err != nil {
		return nil, err
	}
	runtime := &Runtime{
		factory:             factory,
		tracker:             newConnectionTracker(),
		runtimeID:           runtimeID,
		protocol:            config.Protocol,
		config:              config,
		identities:          make(map[string]int64),
		generations:         make(map[int64]uint64),
		configDigest:        digestConfig(config),
		authorizationDigest: digestUsers(nil),
		configured:          true,
		externalWrites:      true,
	}
	kernel, err := factory(context.Background(), config, nil, runtime.tracker)
	if err != nil {
		return nil, fmt.Errorf("%w: initial kernel start", ErrRuntime)
	}
	runtime.kernel = kernel
	return runtime, nil
}

func newRuntimeID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func (r *Runtime) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.statusLocked()
}

func (r *Runtime) statusLocked() Status {
	state := StateRunning
	if r.lastError != "" {
		state = StateDegraded
	} else if len(r.users) == 0 {
		state = StateEmpty
	}
	return Status{
		State:               state,
		RuntimeID:           r.runtimeID,
		StateRevision:       r.revision,
		ConfigSHA256:        r.configDigest,
		AuthorizationSHA256: r.authorizationDigest,
		LastError:           r.lastError,
		Protocol:            r.protocol,
		PanelOwned:          !r.externalWrites,
		Configured:          r.configured,
	}
}

func (r *Runtime) Usage() (UsageSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	usage, err := r.tracker.usageSnapshot()
	if err != nil {
		return UsageSnapshot{}, err
	}
	return UsageSnapshot{RuntimeID: r.runtimeID, Members: usage}, nil
}

func (r *Runtime) Apply(ctx context.Context, input ApplyInput) (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.externalWrites {
		return r.statusLocked(), ErrFailedPrecondition
	}
	if input.ExpectedRuntimeID != r.runtimeID || input.ExpectedStateRevision != r.revision {
		return r.statusLocked(), ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return r.statusLocked(), err
	}
	if input.Config == nil || input.Users == nil {
		return r.statusLocked(), fmt.Errorf("%w: config and users messages are required", ErrInvalidArgument)
	}
	if input.Config.Protocol != r.protocol {
		return r.statusLocked(), fmt.Errorf("%w: runtime protocol is fixed at startup", ErrInvalidArgument)
	}
	// A user-only update uses the running listener's TLS state, not its files.
	if r.kernel == nil || r.config != *input.Config {
		if err := validateConfig(*input.Config); err != nil {
			return r.statusLocked(), err
		}
	}
	users, err := validateUsers(*input.Users)
	if err != nil {
		return r.statusLocked(), err
	}
	if r.kernel != nil && !r.applyFailed && r.config == *input.Config && usersEqual(r.users, users) {
		return r.statusLocked(), nil
	}

	identities, kernelUsers := r.prepareUsers(users)
	r.tracker.stage(identities)
	if r.config != *input.Config || r.kernel == nil {
		return r.applyConfigLocked(ctx, *input.Config, users, identities, kernelUsers)
	}

	err = r.kernel.UpdateUsers(kernelUsers)
	if err == nil {
		r.tracker.setAuthorized(identities)
		r.users = users
		r.identities = identities
		r.authorizationDigest = digestUsers(users)
		r.lastError = ""
		r.applyFailed = false
		r.revision++
		if ctx.Err() != nil {
			return r.statusLocked(), ctx.Err()
		}
		return r.statusLocked(), nil
	}
	r.recordFailedApply(users, identities)
	if ctx.Err() != nil {
		return r.statusLocked(), ctx.Err()
	}
	return r.statusLocked(), fmt.Errorf("%w: %s user update", ErrRuntime, input.Config.Protocol)
}

func (r *Runtime) applyConfigLocked(ctx context.Context, config Config, users []User, identities map[string]int64, kernelUsers []kernelUser) (Status, error) {
	oldKernel := r.kernel
	r.kernel = nil
	if oldKernel != nil {
		_ = oldKernel.Close()
	}
	newKernel, err := r.factory(ctx, config, kernelUsers, r.tracker)
	if err == nil && ctx.Err() != nil {
		_ = newKernel.Close()
		err = ctx.Err()
	}
	if err == nil {
		r.kernel = newKernel
		r.config = config
		r.users = users
		r.identities = identities
		r.configured = true
		r.configDigest = digestConfig(config)
		r.authorizationDigest = digestUsers(users)
		r.lastError = ""
		r.applyFailed = false
		r.tracker.setAuthorized(identities)
		r.revision++
		return r.statusLocked(), nil
	}
	r.config = config
	r.configDigest = ""
	r.configured = false
	r.recordFailedApply(users, identities)
	if ctx.Err() != nil {
		return r.statusLocked(), ctx.Err()
	}
	return r.statusLocked(), fmt.Errorf("%w: %s configuration", ErrRuntime, config.Protocol)
}

// ApplyPanel writes a snapshot that came from the panel. It is the only writer
// allowed while the panel owns authorization, so it does not take a compare and
// swap token; the worker serializes its own calls instead.
func (r *Runtime) ApplyPanel(ctx context.Context, config Config, users []User) (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.statusLocked(), ErrFailedPrecondition
	}
	if err := ctx.Err(); err != nil {
		return r.statusLocked(), err
	}
	if config.Protocol != r.protocol {
		return r.statusLocked(), fmt.Errorf("%w: runtime protocol is fixed at startup", ErrInvalidArgument)
	}
	if r.kernel == nil || r.config != config {
		if err := validateConfig(config); err != nil {
			return r.statusLocked(), err
		}
	}
	validated, err := validateUsers(users)
	if err != nil {
		return r.statusLocked(), err
	}
	if r.kernel != nil && !r.applyFailed && r.configured && r.config == config && usersEqual(r.users, validated) {
		return r.statusLocked(), nil
	}
	identities, kernelUsers := r.prepareUsers(validated)
	r.tracker.stage(identities)
	if !r.configured || r.config != config || r.kernel == nil {
		return r.applyConfigLocked(ctx, config, validated, identities, kernelUsers)
	}
	if err := r.kernel.UpdateUsers(kernelUsers); err != nil {
		r.recordFailedApply(validated, identities)
		return r.statusLocked(), fmt.Errorf("%w: %s user update", ErrRuntime, config.Protocol)
	}
	r.tracker.setAuthorized(identities)
	r.users = validated
	r.identities = identities
	r.authorizationDigest = digestUsers(validated)
	r.lastError = ""
	r.applyFailed = false
	r.revision++
	return r.statusLocked(), nil
}

// RevokeAll drops every authorization and closes all established streams. It
// keeps the kernel and the configuration, so the node can resume on the next
// successful snapshot without a restart.
func (r *Runtime) RevokeAll(reason string) (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.statusLocked(), ErrFailedPrecondition
	}
	r.tracker.stage(nil)
	r.tracker.setAuthorized(nil)
	r.users = nil
	r.identities = map[string]int64{}
	r.authorizationDigest = digestUsers(nil)
	r.lastError = reason
	r.revision++
	if r.kernel != nil {
		if err := r.kernel.UpdateUsers(nil); err != nil {
			r.applyFailed = true
			return r.statusLocked(), fmt.Errorf("%w: %s user revoke", ErrRuntime, r.protocol)
		}
	}
	r.applyFailed = false
	return r.statusLocked(), nil
}

// RecordError keeps the current authorization and surfaces the failure.
func (r *Runtime) RecordError(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastError = reason
}

// ClearError removes a previously recorded failure without touching users.
func (r *Runtime) ClearError() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastError = ""
}

func (r *Runtime) recordFailedApply(desired []User, desiredIdentities map[string]int64) {
	retained := make([]User, 0, len(r.users))
	retainedIdentities := make(map[string]int64)
	for _, user := range r.users {
		for identity, memberID := range r.identities {
			if memberID == user.MemberID && desiredIdentities[identity] == memberID {
				retained = append(retained, user)
				retainedIdentities[identity] = memberID
			}
		}
	}
	r.users = retained
	r.identities = retainedIdentities
	r.authorizationDigest = digestUsers(retained)
	r.lastError = "last snapshot apply failed; authorization gate reflects retained members"
	r.applyFailed = true
	r.revision++
}

func (r *Runtime) prepareUsers(users []User) (map[string]int64, []kernelUser) {
	currentUUIDs := make(map[int64]string, len(r.users))
	for _, user := range r.users {
		currentUUIDs[user.MemberID] = user.UUID
	}
	currentIdentities := make(map[int64]string, len(r.identities))
	for identity, memberID := range r.identities {
		currentIdentities[memberID] = identity
	}
	identities := make(map[string]int64, len(users))
	kernelUsers := make([]kernelUser, 0, len(users))
	for _, user := range users {
		identity := currentIdentities[user.MemberID]
		if currentUUIDs[user.MemberID] != user.UUID {
			identity = ""
		}
		if identity == "" {
			// The counter is per member and must never go backwards: a member
			// that is removed and re-added has to receive a fresh generation, or
			// old sessions could be revived. Counters of members that are gone
			// are dropped and folded into generationFloor, which keeps the map
			// proportional to the live member set without ever reusing a number.
			generation := r.generations[user.MemberID]
			if r.generationFloor > generation {
				generation = r.generationFloor
			}
			generation++
			r.generations[user.MemberID] = generation
			identity = fmt.Sprintf("m%d.g%d", user.MemberID, generation)
		}
		identities[identity] = user.MemberID
		kernelUsers = append(kernelUsers, kernelUser{Name: identity, Secret: user.UUID})
	}
	live := make(map[int64]struct{}, len(users))
	for _, user := range users {
		live[user.MemberID] = struct{}{}
	}
	for memberID, generation := range r.generations {
		if _, ok := live[memberID]; ok {
			continue
		}
		if generation > r.generationFloor {
			r.generationFloor = generation
		}
		delete(r.generations, memberID)
	}
	return identities, kernelUsers
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	r.tracker.stage(nil)
	if r.kernel != nil {
		return r.kernel.Close()
	}
	return nil
}

// ValidateConfig checks an inbound before any kernel is created.
func ValidateConfig(config Config) error {
	return validateConfig(config)
}

// ValidateVlessConfig checks a VLESS inbound.
func ValidateVlessConfig(config VlessConfig) error {
	return validateConfig(VlessRuntimeConfig(config))
}

// ValidateHysteria2Config checks a Hysteria2 inbound, including that the pinned
// certificate files are absolute, regular, and readable by this service user.
func ValidateHysteria2Config(config Hysteria2Config) error {
	return validateConfig(Hysteria2RuntimeConfig(config))
}

// ValidateAnyTLSConfig checks an AnyTLS inbound, including that the pinned
// certificate files are absolute, regular, and readable by this service user.
func ValidateAnyTLSConfig(config AnytlsConfig) error {
	return validateConfig(AnytlsRuntimeConfig(config))
}

// ValidateTUICConfig checks a TUIC v5 inbound, including that the pinned
// certificate files are absolute, regular, and readable by this service user.
func ValidateTUICConfig(config TuicConfig) error {
	return validateConfig(TuicRuntimeConfig(config))
}

func validateConfig(config Config) error {
	switch config.Protocol {
	case ProtocolVless:
		return validateVlessConfig(config.Vless)
	case ProtocolHysteria2:
		return validateHysteria2Config(config.Hysteria2)
	case ProtocolAnytls:
		return validateAnytlsConfig(config.Anytls)
	case ProtocolTuic:
		return validateTuicConfig(config.Tuic)
	default:
		return fmt.Errorf("%w: unsupported protocol %q", ErrInvalidArgument, config.Protocol)
	}
}

func validateVlessConfig(config VlessConfig) error {
	if _, err := netip.ParseAddr(config.Listen); err != nil || config.Port == 0 || config.Port > 65535 || config.HandshakePort == 0 || config.HandshakePort > 65535 {
		return fmt.Errorf("%w: listen or port", ErrInvalidArgument)
	}
	if !validHostname(config.ServerName) || !validHostname(config.HandshakeServer) {
		return fmt.Errorf("%w: Reality host", ErrInvalidArgument)
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(config.RealityPrivateKey)
	if err != nil || len(privateKey) != 32 {
		return fmt.Errorf("%w: Reality private key", ErrInvalidArgument)
	}
	shortID, err := hex.DecodeString(config.RealityShortID)
	if err != nil || len(shortID) == 0 || len(shortID) > 8 {
		return fmt.Errorf("%w: Reality short ID", ErrInvalidArgument)
	}
	return nil
}

func validateHysteria2Config(config Hysteria2Config) error {
	if _, err := netip.ParseAddr(config.Listen); err != nil || config.Port == 0 || config.Port > 65535 {
		return fmt.Errorf("%w: Hysteria2 listen or port", ErrInvalidArgument)
	}
	if !validHostname(config.ServerName) {
		return fmt.Errorf("%w: Hysteria2 server name", ErrInvalidArgument)
	}
	for label, path := range map[string]string{"certificate": config.CertificatePath, "private key": config.PrivateKeyPath} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			return fmt.Errorf("%w: Hysteria2 %s path", ErrInvalidArgument, label)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("%w: Hysteria2 %s file is not readable", ErrInvalidArgument, label)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("%w: Hysteria2 %s file is not readable by this user", ErrInvalidArgument, label)
		}
		_ = file.Close()
	}
	return nil
}

func validateAnytlsConfig(config AnytlsConfig) error {
	if _, err := netip.ParseAddr(config.Listen); err != nil || config.Port == 0 || config.Port > 65535 {
		return fmt.Errorf("%w: AnyTLS listen or port", ErrInvalidArgument)
	}
	if !validHostname(config.ServerName) {
		return fmt.Errorf("%w: AnyTLS server name", ErrInvalidArgument)
	}
	for label, path := range map[string]string{"certificate": config.CertificatePath, "private key": config.PrivateKeyPath} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			return fmt.Errorf("%w: AnyTLS %s path", ErrInvalidArgument, label)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("%w: AnyTLS %s file is not readable", ErrInvalidArgument, label)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("%w: AnyTLS %s file is not readable by this user", ErrInvalidArgument, label)
		}
		_ = file.Close()
	}
	return nil
}

func validateTuicConfig(config TuicConfig) error {
	if _, err := netip.ParseAddr(config.Listen); err != nil || config.Port == 0 || config.Port > 65535 {
		return fmt.Errorf("%w: TUIC listen or port", ErrInvalidArgument)
	}
	if !validHostname(config.ServerName) {
		return fmt.Errorf("%w: TUIC server name", ErrInvalidArgument)
	}
	for label, path := range map[string]string{"certificate": config.CertificatePath, "private key": config.PrivateKeyPath} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			return fmt.Errorf("%w: TUIC %s path", ErrInvalidArgument, label)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("%w: TUIC %s file is not readable", ErrInvalidArgument, label)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("%w: TUIC %s file is not readable by this user", ErrInvalidArgument, label)
		}
		_ = file.Close()
	}
	return nil
}

func validHostname(value string) bool {
	return value != "" && len(value) <= 253 && !strings.ContainsAny(value, " \t\r\n/@:")
}

func validateUsers(input []User) ([]User, error) {
	if len(input) > 10000 {
		return nil, ErrResourceExhausted
	}
	users := append([]User(nil), input...)
	memberIDs := make(map[int64]bool, len(users))
	credentials := make(map[string]bool, len(users))
	for index := range users {
		user := &users[index]
		if user.MemberID <= 0 || memberIDs[user.MemberID] {
			return nil, fmt.Errorf("%w: member ID", ErrInvalidArgument)
		}
		parsed, err := uuid.FromString(user.UUID)
		if err != nil || parsed.String() != strings.ToLower(user.UUID) {
			return nil, fmt.Errorf("%w: member credential", ErrInvalidArgument)
		}
		user.UUID = parsed.String()
		if credentials[user.UUID] {
			return nil, fmt.Errorf("%w: duplicate credential", ErrInvalidArgument)
		}
		memberIDs[user.MemberID] = true
		credentials[user.UUID] = true
	}
	sort.Slice(users, func(i, j int) bool { return users[i].MemberID < users[j].MemberID })
	return users, nil
}

func usersEqual(left, right []User) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func digestConfig(config Config) string {
	encoded, _ := json.Marshal(config)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func digestUsers(users []User) string {
	encoded, _ := json.Marshal(users)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
