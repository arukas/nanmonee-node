package runtime

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func freeTCPPort(t *testing.T) uint32 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return uint32(port)
}

func anytlsTestConfig(t *testing.T, files testTLSFiles, port uint32) AnytlsConfig {
	t.Helper()
	return AnytlsConfig{
		Listen:          "127.0.0.1",
		Port:            port,
		ServerName:      files.serverName,
		CertificatePath: files.certificatePath,
		PrivateKeyPath:  files.privateKeyPath,
	}
}

// countingTLSDialer establishes one verified TLS session per dial so the tests
// can prove later streams reused the session that was already authenticated.
type countingTLSDialer struct {
	dials     atomic.Int32
	address   string
	tlsConfig *stdtls.Config
}

func (d *countingTLSDialer) Dial(ctx context.Context) (net.Conn, error) {
	d.dials.Add(1)
	dialer := &net.Dialer{}
	return tlsDialWithDialer(dialer, d.address, d.tlsConfig)
}

func tlsDialWithDialer(dialer *net.Dialer, address string, config *stdtls.Config) (net.Conn, error) {
	return stdtls.DialWithDialer(dialer, "tcp", address, config)
}

func newAnytlsClient(t *testing.T, port uint32, files testTLSFiles, password string) (*anytls.Client, *countingTLSDialer) {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(files.certificatePEM) {
		t.Fatal("test certificate was not usable as a root")
	}
	dialer := &countingTLSDialer{
		address: fmt.Sprintf("127.0.0.1:%d", port),
		tlsConfig: &stdtls.Config{
			RootCAs:    roots,
			ServerName: files.serverName,
			MinVersion: stdtls.VersionTLS12,
		},
	}
	client, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: password,
		DialOut:  util.DialOutFunc(dialer.Dial),
		Logger:   logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, dialer
}

// anytlsProxyRoundTrip opens one multiplexed stream, echoes the payload, and
// returns what came back.
func anytlsProxyRoundTrip(t *testing.T, client *anytls.Client, destination M.Socksaddr, payload []byte) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := client.CreateProxy(ctx, destination)
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

// streamDialer adapts an AnyTLS client to the UDP-over-TCP bridge.
type streamDialer struct {
	client *anytls.Client
}

func (d streamDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.client.CreateProxy(ctx, destination)
}

func (d streamDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func anytlsUDPRoundTrip(t *testing.T, client *anytls.Client, destination M.Socksaddr, payload []byte) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bridge := &uot.Client{Dialer: streamDialer{client: client}, Version: uot.Version}
	connection, err := bridge.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := connection.Write(payload); err != nil {
		return "", err
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, buffer); err != nil {
		return "", err
	}
	return string(buffer), nil
}

func TestAnyTLSRealSessionIdentityRotationRevocationAndReadd(t *testing.T) {
	files := newTestTLSFiles(t)
	port := freeTCPPort(t)
	config := anytlsTestConfig(t, files, port)
	runtime, err := New(AnytlsRuntimeConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	echo, _ := startEchoServer(t)

	const passwordA = "11111111-1111-4111-8111-111111111111"
	const passwordB = "22222222-2222-4222-8222-222222222222"
	clientA, dialsA := newAnytlsClient(t, port, files, passwordA)
	clientB, dialsB := newAnytlsClient(t, port, files, passwordB)

	applied := func(users ...User) {
		t.Helper()
		status, err := runtime.ApplyPanel(context.Background(), AnytlsRuntimeConfig(config), users)
		if err != nil || status.State != StateRunning {
			t.Fatalf("apply failed: %+v, %v", status, err)
		}
	}
	applied(User{MemberID: 1, UUID: passwordA}, User{MemberID: 2, UUID: passwordB})

	payload := []byte("ping")
	if echoed, err := anytlsProxyRoundTrip(t, clientA, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("first member could not use the TLS session: %q %v", echoed, err)
	}
	if echoed, err := anytlsProxyRoundTrip(t, clientB, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("second member could not use the TLS session: %q %v", echoed, err)
	}
	namesBefore := runtime.userNames()
	if len(namesBefore) != 2 {
		t.Fatalf("unexpected identities: %v", namesBefore)
	}
	assertUsage(t, runtime, map[int64][2]int64{1: {4, 4}, 2: {4, 4}})

	// Reordering the snapshot must not move an authenticated session to another
	// member or force a new TLS session.
	applied(User{MemberID: 2, UUID: passwordB}, User{MemberID: 1, UUID: passwordA})
	if namesAfter := runtime.userNames(); !sameMemberNames(namesBefore, namesAfter) {
		t.Fatalf("reordering changed the member identity: %v -> %v", namesBefore, namesAfter)
	}
	if echoed, err := anytlsProxyRoundTrip(t, clientA, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("reordering broke the old session: %q %v", echoed, err)
	}
	if dialsA.dials.Load() != 1 || dialsB.dials.Load() != 1 {
		t.Fatalf("reordering opened a new TLS session: A=%d B=%d", dialsA.dials.Load(), dialsB.dials.Load())
	}

	// An established stream must be closed by revocation, not merely starved of
	// new streams.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	held, err := clientA.CreateProxy(ctx, echo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.Write([]byte("held")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(held, reply); err != nil {
		t.Fatal(err)
	}
	applied(User{MemberID: 2, UUID: passwordB})
	if _, err := held.Write([]byte("after")); err == nil {
		_ = held.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := held.Read(reply); err == nil {
			t.Fatal("revocation left the established stream usable")
		}
	}
	_ = held.Close()
	if echoed, err := anytlsProxyRoundTrip(t, clientA, echo, payload); err == nil {
		t.Fatalf("new stream was accepted for a revoked member: %q", echoed)
	}
	if echoed, err := anytlsProxyRoundTrip(t, clientB, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("revoking one member broke the other: %q %v", echoed, err)
	}
	assertUsage(t, runtime, map[int64][2]int64{1: {12, 12}, 2: {8, 8}})

	// Restoring and rotating a credential must work without restarting the node.
	applied(User{MemberID: 1, UUID: passwordA}, User{MemberID: 2, UUID: passwordB})
	if echoed, err := anytlsProxyRoundTrip(t, clientA, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("restored member could not connect: %q %v", echoed, err)
	}
	const rotated = "33333333-3333-4333-8333-333333333333"
	applied(User{MemberID: 1, UUID: rotated}, User{MemberID: 2, UUID: passwordB})
	if echoed, err := anytlsProxyRoundTrip(t, clientA, echo, payload); err == nil {
		t.Fatalf("rotated identity was still accepted: %q", echoed)
	}
	rotatedClient, _ := newAnytlsClient(t, port, files, rotated)
	if echoed, err := anytlsProxyRoundTrip(t, rotatedClient, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("rotated credential was not usable: %q %v", echoed, err)
	}
}

func TestAnyTLSRealUDPOverTCPRevocation(t *testing.T) {
	files := newTestTLSFiles(t)
	port := freeTCPPort(t)
	config := anytlsTestConfig(t, files, port)
	runtime, err := New(AnytlsRuntimeConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	echo := startUDPEchoServer(t)

	const passwordA = "11111111-1111-4111-8111-111111111111"
	client, _ := newAnytlsClient(t, port, files, passwordA)
	if _, err := runtime.ApplyPanel(context.Background(), AnytlsRuntimeConfig(config), []User{{MemberID: 1, UUID: passwordA}}); err != nil {
		t.Fatal(err)
	}
	if reply, err := anytlsUDPRoundTrip(t, client, echo, []byte("dns")); err != nil || reply != "dns" {
		t.Fatalf("UDP over TCP failed before revocation: %q %v", reply, err)
	}
	assertUsage(t, runtime, map[int64][2]int64{1: {3, 3}})

	// The datagram bridge runs inside an AnyTLS stream, so revocation closes it
	// exactly like a TCP stream.
	if _, err := runtime.ApplyPanel(context.Background(), AnytlsRuntimeConfig(config), nil); err != nil {
		t.Fatal(err)
	}
	if reply, err := anytlsUDPRoundTrip(t, client, echo, []byte("dns")); err == nil {
		t.Fatalf("revocation left the UDP stream usable: %q", reply)
	}
	if _, err := runtime.ApplyPanel(context.Background(), AnytlsRuntimeConfig(config), []User{{MemberID: 1, UUID: passwordA}}); err != nil {
		t.Fatal(err)
	}
	if reply, err := anytlsUDPRoundTrip(t, client, echo, []byte("dns")); err != nil || reply != "dns" {
		t.Fatalf("UDP over TCP did not recover after re-authorization: %q %v", reply, err)
	}
}

func TestAnyTLSConcurrentAuthenticationUpdatesAndClose(t *testing.T) {
	files := newTestTLSFiles(t)
	port := freeTCPPort(t)
	config := anytlsTestConfig(t, files, port)
	runtime, err := New(AnytlsRuntimeConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	echo, _ := startEchoServer(t)
	const passwordA = "11111111-1111-4111-8111-111111111111"
	const passwordB = "22222222-2222-4222-8222-222222222222"
	if _, err := runtime.ApplyPanel(context.Background(), AnytlsRuntimeConfig(config), []User{{MemberID: 1, UUID: passwordA}, {MemberID: 2, UUID: passwordB}}); err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	stop := make(chan struct{})
	for index := 0; index < 6; index++ {
		password := passwordA
		if index%2 == 1 {
			password = passwordB
		}
		client, _ := newAnytlsClient(t, port, files, password)
		wait.Add(1)
		go func() {
			defer wait.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = anytlsProxyRoundTrip(t, client, echo, []byte("x"))
			}
		}()
	}
	for round := 0; round < 50; round++ {
		users := []User{{MemberID: 1, UUID: passwordA}, {MemberID: 2, UUID: passwordB}}
		if round%2 == 1 {
			users = users[:1]
		}
		if _, err := runtime.ApplyPanel(context.Background(), AnytlsRuntimeConfig(config), users); err != nil {
			t.Fatalf("concurrent update failed: %v", err)
		}
	}
	close(stop)
	wait.Wait()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAnyTLSConfigValidation(t *testing.T) {
	files := newTestTLSFiles(t)
	valid := anytlsTestConfig(t, files, 31472)
	if err := ValidateAnyTLSConfig(valid); err != nil {
		t.Fatalf("valid AnyTLS config rejected: %v", err)
	}
	cases := map[string]func(*AnytlsConfig){
		"relative certificate": func(config *AnytlsConfig) { config.CertificatePath = "cert.pem" },
		"relative key":         func(config *AnytlsConfig) { config.PrivateKeyPath = "key.pem" },
		"missing certificate":  func(config *AnytlsConfig) { config.CertificatePath = filepath.Join(t.TempDir(), "missing.pem") },
		"directory certificate": func(config *AnytlsConfig) {
			config.CertificatePath = t.TempDir()
		},
		"empty server name": func(config *AnytlsConfig) { config.ServerName = "" },
		"zero port":         func(config *AnytlsConfig) { config.Port = 0 },
		"invalid listen":    func(config *AnytlsConfig) { config.Listen = "not-an-ip" },
	}
	for name, mutate := range cases {
		config := valid
		mutate(&config)
		if err := ValidateAnyTLSConfig(config); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
