package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
)

// Both inbounds are updated through their own concrete option type. The runtime
// hands the kernel a protocol-neutral credential list and each adapter maps it.
type vlessUserUpdater interface {
	UpdateUsers(users []option.VLESSUser) error
}

type hysteria2UserUpdater interface {
	UpdateUsers(users []option.Hysteria2User) error
}

type anytlsUserUpdater interface {
	UpdateUsers(users []option.AnyTLSUser) error
}

type tuicUserUpdater interface {
	UpdateUsers(users []option.TUICUser) error
}

type vlessKernel struct {
	box     *box.Box
	inbound vlessUserUpdater
}

type hysteria2Kernel struct {
	box     *box.Box
	inbound hysteria2UserUpdater
}

type anytlsKernel struct {
	box     *box.Box
	inbound anytlsUserUpdater
}

type tuicKernel struct {
	box     *box.Box
	inbound tuicUserUpdater
}

func newSingBoxKernel(ctx context.Context, config Config, users []kernelUser, tracker *connectionTracker) (kernel, error) {
	switch config.Protocol {
	case ProtocolVless:
		return newVlessKernel(ctx, config.Vless, users, tracker)
	case ProtocolHysteria2:
		return newHysteria2Kernel(ctx, config.Hysteria2, users, tracker)
	case ProtocolAnytls:
		return newAnytlsKernel(ctx, config.Anytls, users, tracker)
	case ProtocolTuic:
		return newTuicKernel(ctx, config.Tuic, users, tracker)
	default:
		return nil, fmt.Errorf("unsupported inbound protocol %q", config.Protocol)
	}
}

func newVlessKernel(ctx context.Context, config VlessConfig, users []kernelUser, tracker *connectionTracker) (kernel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	listen, _ := netip.ParseAddr(config.Listen)
	options := option.Options{
		Log: &option.LogOptions{Disabled: true},
		Inbounds: []option.Inbound{{
			Type: "vless",
			Tag:  "vless",
			Options: &option.VLESSInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(listen)),
					ListenPort: uint16(config.Port),
				},
				Users: vlessUsers(users),
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
					Enabled:    true,
					ServerName: config.ServerName,
					Reality: &option.InboundRealityOptions{
						Enabled: true,
						Handshake: option.InboundRealityHandshakeOptions{ServerOptions: option.ServerOptions{
							Server:     config.HandshakeServer,
							ServerPort: uint16(config.HandshakePort),
						}},
						PrivateKey: config.RealityPrivateKey,
						ShortID:    badoption.Listable[string]{config.RealityShortID},
					},
				}},
			},
		}},
		Outbounds: []option.Outbound{{Type: "direct", Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		Route:     &option.RouteOptions{Final: "direct"},
	}
	instance, err := startBox(ctx, options, tracker)
	if err != nil {
		return nil, err
	}
	inbound, loaded := instance.Inbound().Get("vless")
	if !loaded {
		_ = instance.Close()
		return nil, errors.New("VLESS inbound missing after start")
	}
	updater, supported := inbound.(vlessUserUpdater)
	if !supported {
		_ = instance.Close()
		return nil, errors.New("VLESS hot update is unavailable in this kernel")
	}
	if err := ctx.Err(); err != nil {
		_ = instance.Close()
		return nil, err
	}
	return &vlessKernel{box: instance, inbound: updater}, nil
}

func newHysteria2Kernel(ctx context.Context, config Hysteria2Config, users []kernelUser, tracker *connectionTracker) (kernel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	listen, _ := netip.ParseAddr(config.Listen)
	options := option.Options{
		Log: &option.LogOptions{Disabled: true},
		Inbounds: []option.Inbound{{
			Type: "hysteria2",
			Tag:  "hysteria2",
			Options: &option.Hysteria2InboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(listen)),
					ListenPort: uint16(config.Port),
				},
				Users: hysteria2Users(users),
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
					Enabled:         true,
					ServerName:      config.ServerName,
					CertificatePath: config.CertificatePath,
					KeyPath:         config.PrivateKeyPath,
				}},
			},
		}},
		Outbounds: []option.Outbound{{Type: "direct", Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		Route:     &option.RouteOptions{Final: "direct"},
	}
	instance, err := startBox(ctx, options, tracker)
	if err != nil {
		return nil, err
	}
	inbound, loaded := instance.Inbound().Get("hysteria2")
	if !loaded {
		_ = instance.Close()
		return nil, errors.New("Hysteria2 inbound missing after start")
	}
	updater, supported := inbound.(hysteria2UserUpdater)
	if !supported {
		_ = instance.Close()
		return nil, errors.New("Hysteria2 hot update is unavailable in this kernel")
	}
	if err := ctx.Err(); err != nil {
		_ = instance.Close()
		return nil, err
	}
	return &hysteria2Kernel{box: instance, inbound: updater}, nil
}

func newAnytlsKernel(ctx context.Context, config AnytlsConfig, users []kernelUser, tracker *connectionTracker) (kernel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	listen, _ := netip.ParseAddr(config.Listen)
	options := option.Options{
		Log: &option.LogOptions{Disabled: true},
		Inbounds: []option.Inbound{{
			Type: "anytls",
			Tag:  "anytls",
			Options: &option.AnyTLSInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(listen)),
					ListenPort: uint16(config.Port),
				},
				Users: anytlsUsers(users),
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
					Enabled:         true,
					ServerName:      config.ServerName,
					CertificatePath: config.CertificatePath,
					KeyPath:         config.PrivateKeyPath,
				}},
			},
		}},
		Outbounds: []option.Outbound{{Type: "direct", Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		Route:     &option.RouteOptions{Final: "direct"},
	}
	instance, err := startBox(ctx, options, tracker)
	if err != nil {
		return nil, err
	}
	inbound, loaded := instance.Inbound().Get("anytls")
	if !loaded {
		_ = instance.Close()
		return nil, errors.New("AnyTLS inbound missing after start")
	}
	updater, supported := inbound.(anytlsUserUpdater)
	if !supported {
		_ = instance.Close()
		return nil, errors.New("AnyTLS hot update is unavailable in this kernel")
	}
	if err := ctx.Err(); err != nil {
		_ = instance.Close()
		return nil, err
	}
	return &anytlsKernel{box: instance, inbound: updater}, nil
}

func newTuicKernel(ctx context.Context, config TuicConfig, users []kernelUser, tracker *connectionTracker) (kernel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	listen, _ := netip.ParseAddr(config.Listen)
	options := option.Options{
		Log: &option.LogOptions{Disabled: true},
		Inbounds: []option.Inbound{{
			Type: "tuic",
			Tag:  "tuic",
			Options: &option.TUICInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(listen)),
					ListenPort: uint16(config.Port),
				},
				Users:             tuicUsers(users),
				CongestionControl: "cubic",
				ZeroRTTHandshake:  false,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
					Enabled:         true,
					ServerName:      config.ServerName,
					ALPN:            badoption.Listable[string]{"h3"},
					CertificatePath: config.CertificatePath,
					KeyPath:         config.PrivateKeyPath,
				}},
			},
		}},
		Outbounds: []option.Outbound{{Type: "direct", Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		Route:     &option.RouteOptions{Final: "direct"},
	}
	instance, err := startBox(ctx, options, tracker)
	if err != nil {
		return nil, err
	}
	inbound, loaded := instance.Inbound().Get("tuic")
	if !loaded {
		_ = instance.Close()
		return nil, errors.New("TUIC inbound missing after start")
	}
	updater, supported := inbound.(tuicUserUpdater)
	if !supported {
		_ = instance.Close()
		return nil, errors.New("TUIC hot update is unavailable in this kernel")
	}
	if err := ctx.Err(); err != nil {
		_ = instance.Close()
		return nil, err
	}
	return &tuicKernel{box: instance, inbound: updater}, nil
}

func startBox(ctx context.Context, options option.Options, tracker *connectionTracker) (*box.Box, error) {
	instance, err := box.New(box.Options{Context: include.Context(context.Background()), Options: options})
	if err != nil {
		return nil, fmt.Errorf("create sing-box: %w", err)
	}
	instance.Router().AppendTracker(tracker)
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return nil, fmt.Errorf("start sing-box: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = instance.Close()
		return nil, err
	}
	return instance, nil
}

func vlessUsers(users []kernelUser) []option.VLESSUser {
	converted := make([]option.VLESSUser, 0, len(users))
	for _, user := range users {
		converted = append(converted, option.VLESSUser{Name: user.Name, UUID: user.Secret, Flow: "xtls-rprx-vision"})
	}
	return converted
}

func hysteria2Users(users []kernelUser) []option.Hysteria2User {
	converted := make([]option.Hysteria2User, 0, len(users))
	for _, user := range users {
		converted = append(converted, option.Hysteria2User{Name: user.Name, Password: user.Secret})
	}
	return converted
}

func anytlsUsers(users []kernelUser) []option.AnyTLSUser {
	converted := make([]option.AnyTLSUser, 0, len(users))
	for _, user := range users {
		converted = append(converted, option.AnyTLSUser{Name: user.Name, Password: user.Secret})
	}
	return converted
}

func (k *vlessKernel) UpdateUsers(users []kernelUser) error {
	return k.inbound.UpdateUsers(vlessUsers(users))
}

func (k *vlessKernel) Close() error {
	return k.box.Close()
}

func (k *hysteria2Kernel) UpdateUsers(users []kernelUser) error {
	return k.inbound.UpdateUsers(hysteria2Users(users))
}

func (k *hysteria2Kernel) Close() error {
	return k.box.Close()
}

func (k *anytlsKernel) UpdateUsers(users []kernelUser) error {
	return k.inbound.UpdateUsers(anytlsUsers(users))
}

func (k *tuicKernel) UpdateUsers(users []kernelUser) error {
	return k.inbound.UpdateUsers(tuicUsers(users))
}

func (k *tuicKernel) Close() error {
	return k.box.Close()
}

func (k *anytlsKernel) Close() error {
	return k.box.Close()
}

// tuicUsers binds each member to its own generation. TUIC authenticates with
// UUID and password; the client password is the connection UUID, matching the
// exported subscription, so the kernel identity stays separate from the secret.
func tuicUsers(users []kernelUser) []option.TUICUser {
	converted := make([]option.TUICUser, 0, len(users))
	for _, user := range users {
		converted = append(converted, option.TUICUser{Name: user.Name, UUID: user.Secret, Password: user.Secret})
	}
	return converted
}
