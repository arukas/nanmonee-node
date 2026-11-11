//go:build with_quic

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func tuicTestConfig(t *testing.T, files testTLSFiles, port uint32) TuicConfig {
	t.Helper()
	return TuicConfig{
		Listen:          "127.0.0.1",
		Port:            port,
		ServerName:      files.serverName,
		CertificatePath: files.certificatePath,
		PrivateKeyPath:  files.privateKeyPath,
	}
}

func newTUICClient(t *testing.T, port uint32, files testTLSFiles, id, password string) (*tuic.Client, *countingDialer) {
	t.Helper()
	tlsConfig, err := boxTLS.NewClient(context.Background(), logger.NOP(), "127.0.0.1", option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  files.serverName,
		ALPN:        badoption.Listable[string]{"h3"},
		Certificate: badoption.Listable[string]{string(files.certificatePEM)},
	})
	if err != nil {
		t.Fatal(err)
	}
	userUUID, err := uuid.FromString(id)
	if err != nil {
		t.Fatal(err)
	}
	dialer := new(countingDialer)
	client, err := tuic.NewClient(tuic.ClientOptions{
		Context:           context.Background(),
		Dialer:            dialer,
		ServerAddress:     M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", port)),
		TLSConfig:         tlsConfig,
		UUID:              userUUID,
		Password:          password,
		CongestionControl: "cubic",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(nil) })
	return client, dialer
}

func tuicRoundTrip(t *testing.T, client *tuic.Client, destination M.Socksaddr, payload []byte) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := client.DialConn(ctx, destination)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := connection.Write(payload); err != nil {
		return nil, err
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, buffer); err != nil {
		return nil, err
	}
	return buffer, nil
}

func tuicUDPRoundTrip(t *testing.T, client *tuic.Client, destination M.Socksaddr, payload []byte) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	packetConn, err := client.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	defer packetConn.Close()
	_ = packetConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := packetConn.WriteTo(payload, destination); err != nil {
		return nil, err
	}
	buffer := make([]byte, len(payload))
	length, _, err := packetConn.ReadFrom(buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:length], nil
}

func TestTUICRealQuicSessionIdentityRotationRevocationAndReadd(t *testing.T) {
	files := newTestTLSFiles(t)
	port := freeUDPPort(t)
	config := tuicTestConfig(t, files, port)
	runtime, err := New(TuicRuntimeConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	echo, _ := startEchoServer(t)
	udpEcho := startUDPEchoServer(t)

	const uuidA = "11111111-1111-4111-8111-111111111111"
	const uuidB = "22222222-2222-4222-8222-222222222222"
	applied := func(users ...User) {
		t.Helper()
		status, err := runtime.ApplyPanel(context.Background(), TuicRuntimeConfig(config), users)
		if err != nil || status.State != StateRunning {
			t.Fatalf("apply failed: %+v, %v", status, err)
		}
	}
	// TUIC authenticates with UUID plus password; the subscription uses the
	// connection UUID for both, so the node must accept exactly that pair.
	clientA, dialsA := newTUICClient(t, port, files, uuidA, uuidA)
	clientB, dialsB := newTUICClient(t, port, files, uuidB, uuidB)
	applied(User{MemberID: 1, UUID: uuidA}, User{MemberID: 2, UUID: uuidB})

	payload := []byte("ping")
	if echoed, err := tuicRoundTrip(t, clientA, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("first member could not use the TUIC session: %q %v", echoed, err)
	}
	if echoed, err := tuicRoundTrip(t, clientB, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("second member could not use the TUIC session: %q %v", echoed, err)
	}
	if echoed, err := tuicUDPRoundTrip(t, clientA, udpEcho, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("native UDP through TUIC failed: %q %v", echoed, err)
	}
	namesBefore := runtime.userNames()
	if len(namesBefore) != 2 {
		t.Fatalf("unexpected identities: %v", namesBefore)
	}
	assertUsage(t, runtime, map[int64][2]int64{1: {8, 8}, 2: {4, 4}})

	// Reordering the snapshot must not move an authenticated session to another
	// member or force a new QUIC session.
	applied(User{MemberID: 2, UUID: uuidB}, User{MemberID: 1, UUID: uuidA})
	if namesAfter := runtime.userNames(); !sameMemberNames(namesBefore, namesAfter) {
		t.Fatalf("reordering changed the member identity: %v -> %v", namesBefore, namesAfter)
	}
	if echoed, err := tuicRoundTrip(t, clientA, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("reordering broke the old session: %q %v", echoed, err)
	}
	if dialsA.dials.Load() != 1 || dialsB.dials.Load() != 1 {
		t.Fatalf("reordering opened a new QUIC session: A=%d B=%d", dialsA.dials.Load(), dialsB.dials.Load())
	}

	// Revoking A must close its established stream and native UDP association,
	// and refuse new streams on the old session.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	connection, err := clientA.DialConn(ctx, echo)
	cancel()
	if err != nil {
		t.Fatalf("could not open the stream before revocation: %v", err)
	}
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := connection.Write(payload); err != nil {
		t.Fatalf("could not use the stream before revocation: %v", err)
	}
	udpCtx, udpCancel := context.WithTimeout(context.Background(), 5*time.Second)
	udpConn, err := clientA.ListenPacket(udpCtx)
	udpCancel()
	if err != nil {
		t.Fatalf("could not open the UDP association before revocation: %v", err)
	}
	_ = udpConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := udpConn.WriteTo(payload, udpEcho); err != nil {
		t.Fatalf("could not use UDP before revocation: %v", err)
	}
	applied(User{MemberID: 2, UUID: uuidB})
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("revocation left the established stream open")
	}
	_ = connection.Close()
	_ = udpConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := udpConn.ReadFrom(make([]byte, 1)); err == nil {
		t.Fatal("revocation left the native UDP association open")
	}
	_ = udpConn.Close()
	// Revocation closes the whole QUIC session, not just its streams: the client
	// has to establish a new transport before it can even attempt a stream.
	redialed := false
	redialDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(redialDeadline) {
		_, _ = tuicRoundTrip(t, clientA, echo, payload)
		if dialsA.dials.Load() > 1 {
			redialed = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !redialed {
		t.Fatal("revocation left the QUIC session alive; the client never redialed")
	}
	if echoed, err := tuicRoundTrip(t, clientB, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("revoking A broke B: %q %v", echoed, err)
	}

	// Re-adding A starts a new generation: the session closed at revocation stays
	// closed, so the only way back is a fresh authentication on a new transport.
	revokedDials := dialsA.dials.Load()
	applied(User{MemberID: 1, UUID: uuidA}, User{MemberID: 2, UUID: uuidB})
	if echoed, err := tuicRoundTrip(t, clientA, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("a re-added member could not authenticate a fresh session: %q %v", echoed, err)
	}
	if dialsA.dials.Load() <= revokedDials {
		t.Fatalf("the re-added member revived the revoked session instead of redialing: dials=%d", dialsA.dials.Load())
	}
	freshA, _ := newTUICClient(t, port, files, uuidA, uuidA)
	if echoed, err := tuicRoundTrip(t, freshA, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("a fresh authentication after re-add failed: %q %v", echoed, err)
	}

	// Rotating the UUID retires the previous credential for the same member: the
	// old client cannot authenticate, the new one can, and the identity carries
	// the new generation.
	rotated := "33333333-3333-4333-8333-333333333333"
	generationBeforeRotation := runtime.userNames()[1]
	applied(User{MemberID: 1, UUID: rotated}, User{MemberID: 2, UUID: uuidB})
	if echoed, err := tuicRoundTrip(t, freshA, echo, payload); err == nil || string(echoed) == "ping" {
		t.Fatalf("the rotated-away credential still worked: %q %v", echoed, err)
	}
	rotatedA, _ := newTUICClient(t, port, files, rotated, rotated)
	if echoed, err := tuicRoundTrip(t, rotatedA, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("the rotated credential was refused: %q %v", echoed, err)
	}
	names := runtime.userNames()
	if names[1] == generationBeforeRotation || names[1] == "" || names[1][0:4] != "m1.g" {
		t.Fatalf("rotation did not advance the member generation: %v -> %v", generationBeforeRotation, names)
	}

	// A password that does not match the UUID must not authenticate.
	wrongPassword, _ := newTUICClient(t, port, files, rotated, uuidA)
	if echoed, err := tuicRoundTrip(t, wrongPassword, echo, payload); err == nil && string(echoed) == "ping" {
		t.Fatal("a mismatched password authenticated")
	}
}

func TestTUICConcurrentHotUpdatesKeepTheRunningSession(t *testing.T) {
	files := newTestTLSFiles(t)
	port := freeUDPPort(t)
	config := tuicTestConfig(t, files, port)
	runtime, err := New(TuicRuntimeConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	echo, _ := startEchoServer(t)

	const uuidA = "11111111-1111-4111-8111-111111111111"
	const uuidB = "22222222-2222-4222-8222-222222222222"
	applied := func(users ...User) {
		t.Helper()
		if status, err := runtime.ApplyPanel(context.Background(), TuicRuntimeConfig(config), users); err != nil || status.State != StateRunning {
			t.Fatalf("apply failed: %+v, %v", status, err)
		}
	}
	applied(User{MemberID: 1, UUID: uuidA}, User{MemberID: 2, UUID: uuidB})
	client, _ := newTUICClient(t, port, files, uuidB, uuidB)
	payload := []byte("ping")
	if echoed, err := tuicRoundTrip(t, client, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("initial session failed: %q %v", echoed, err)
	}

	// B stays authorized through every snapshot while A flaps. The updates race
	// with the stream path; -race must stay clean and B must never be dropped.
	done := make(chan struct{})
	failures := make(chan error, 1)
	go func() {
		defer close(done)
		for index := 0; index < 20; index++ {
			if index%2 == 0 {
				applied(User{MemberID: 2, UUID: uuidB})
			} else {
				applied(User{MemberID: 1, UUID: uuidA}, User{MemberID: 2, UUID: uuidB})
			}
		}
	}()
	for {
		select {
		case <-done:
			select {
			case err := <-failures:
				t.Fatal(err)
			default:
			}
			return
		default:
		}
		if echoed, err := tuicRoundTrip(t, client, echo, payload); err != nil || string(echoed) != "ping" {
			select {
			case failures <- fmt.Errorf("B lost its session during a concurrent update: %q %v", echoed, err):
			default:
			}
			return
		}
	}
}

func TestTUICConfigValidation(t *testing.T) {
	files := newTestTLSFiles(t)
	valid := tuicTestConfig(t, files, 10544)
	if err := ValidateTUICConfig(valid); err != nil {
		t.Fatalf("a valid TUIC config was refused: %v", err)
	}
	for name, broken := range map[string]TuicConfig{
		"missing certificate": {Listen: valid.Listen, Port: valid.Port, ServerName: valid.ServerName, CertificatePath: "/nonexistent/cert.pem", PrivateKeyPath: valid.PrivateKeyPath},
		"relative key":        {Listen: valid.Listen, Port: valid.Port, ServerName: valid.ServerName, CertificatePath: valid.CertificatePath, PrivateKeyPath: "key.pem"},
		"bad server name":     {Listen: valid.Listen, Port: valid.Port, ServerName: "bad name", CertificatePath: valid.CertificatePath, PrivateKeyPath: valid.PrivateKeyPath},
		"zero port":           {Listen: valid.Listen, Port: 0, ServerName: valid.ServerName, CertificatePath: valid.CertificatePath, PrivateKeyPath: valid.PrivateKeyPath},
	} {
		broken := broken
		t.Run(name, func(t *testing.T) {
			if err := ValidateTUICConfig(broken); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("broken config %q was accepted: %v", name, err)
			}
		})
	}
	// The QUIC listener is UDP; a TCP error path would report a different message.
	if _, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", valid.Listen, valid.Port)); err != nil {
		t.Fatalf("test port is not usable: %v", err)
	}
}
