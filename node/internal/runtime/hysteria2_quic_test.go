package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// countingDialer records how many QUIC sessions the client opened. A dial is
// made once per QUIC connection, so a constant count proves later streams were
// multiplexed on the very session that was authenticated before the update.
type countingDialer struct {
	dials atomic.Int32
}

func (d *countingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	return N.SystemDialer.DialContext(ctx, network, destination)
}

func (d *countingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

type testTLSFiles struct {
	certificatePath string
	privateKeyPath  string
	certificatePEM  []byte
	serverName      string
}

func newTestTLSFiles(t *testing.T) testTLSFiles {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hysteria2.test"},
		DNSNames:     []string{"hysteria2.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	files := testTLSFiles{
		certificatePath: filepath.Join(directory, "cert.pem"),
		privateKeyPath:  filepath.Join(directory, "key.pem"),
		certificatePEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		serverName:      "hysteria2.test",
	}
	if err := os.WriteFile(files.certificatePath, files.certificatePEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files.privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return files
}

func freeUDPPort(t *testing.T) uint32 {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	_ = listener.Close()
	return uint32(port)
}

func hysteria2TestConfig(t *testing.T, files testTLSFiles, port uint32) Hysteria2Config {
	t.Helper()
	return Hysteria2Config{
		Listen:          "127.0.0.1",
		Port:            port,
		ServerName:      files.serverName,
		CertificatePath: files.certificatePath,
		PrivateKeyPath:  files.privateKeyPath,
	}
}

func startEchoServer(t *testing.T) (M.Socksaddr, *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var accepted atomic.Int64
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return M.ParseSocksaddr(listener.Addr().String()), &accepted
}

func startUDPEchoServer(t *testing.T) M.Socksaddr {
	t.Helper()
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			length, address, err := connection.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = connection.WriteTo(buffer[:length], address)
		}
	}()
	return M.ParseSocksaddr(connection.LocalAddr().String())
}

// newHysteria2Client builds a real sing-quic client that verifies the server
// certificate against the generated CA instead of skipping verification.
func newHysteria2Client(t *testing.T, port uint32, files testTLSFiles, password string) (*hysteria2.Client, *countingDialer) {
	t.Helper()
	tlsConfig, err := tls.NewClient(context.Background(), logger.NOP(), "127.0.0.1", option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  files.serverName,
		Certificate: badoption.Listable[string]{string(files.certificatePEM)},
	})
	if err != nil {
		t.Fatal(err)
	}
	dialer := new(countingDialer)
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:       context.Background(),
		Dialer:        dialer,
		Logger:        logger.NOP(),
		ServerAddress: M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", port)),
		Password:      password,
		TLSConfig:     tlsConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(nil) })
	return client, dialer
}

// roundTrip opens one logical stream, echoes payload, and returns what came back.
func roundTrip(t *testing.T, client *hysteria2.Client, destination M.Socksaddr, payload []byte) ([]byte, error) {
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

func TestHysteria2RealQuicSessionIdentityRotationRevocationAndReadd(t *testing.T) {
	files := newTestTLSFiles(t)
	port := freeUDPPort(t)
	config := hysteria2TestConfig(t, files, port)
	runtime, err := New(Hysteria2RuntimeConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	echo, accepted := startEchoServer(t)

	const passwordA = "11111111-1111-4111-8111-111111111111"
	const passwordB = "22222222-2222-4222-8222-222222222222"
	clientA, dialsA := newHysteria2Client(t, port, files, passwordA)
	clientB, dialsB := newHysteria2Client(t, port, files, passwordB)

	applied := func(users ...User) {
		t.Helper()
		status, err := runtime.ApplyPanel(context.Background(), Hysteria2RuntimeConfig(config), users)
		if err != nil || status.State != StateRunning {
			t.Fatalf("apply failed: %+v, %v", status, err)
		}
	}
	applied(User{MemberID: 1, UUID: passwordA}, User{MemberID: 2, UUID: passwordB})

	payload := []byte("ping")
	if echoed, err := roundTrip(t, clientA, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("first member could not use the QUIC session: %q %v", echoed, err)
	}
	if echoed, err := roundTrip(t, clientB, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("second member could not use the QUIC session: %q %v", echoed, err)
	}
	namesBefore := runtime.userNames()
	if len(namesBefore) != 2 {
		t.Fatalf("unexpected identities: %v", namesBefore)
	}
	assertUsage(t, runtime, map[int64][2]int64{1: {4, 4}, 2: {4, 4}})

	// Reordering the snapshot must not move an authenticated session to another
	// member or force a new QUIC session.
	applied(User{MemberID: 2, UUID: passwordB}, User{MemberID: 1, UUID: passwordA})
	if namesAfter := runtime.userNames(); !sameMemberNames(namesBefore, namesAfter) {
		t.Fatalf("reordering changed the member identity: %v -> %v", namesBefore, namesAfter)
	}
	if echoed, err := roundTrip(t, clientA, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("reordering broke the old session: %q %v", echoed, err)
	}
	if dialsA.dials.Load() != 1 || dialsB.dials.Load() != 1 {
		t.Fatalf("reordering opened a new QUIC session: A=%d B=%d", dialsA.dials.Load(), dialsB.dials.Load())
	}

	// Revoking A must close its established stream and refuse new streams on the
	// same, still authenticated QUIC session.
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
	applied(User{MemberID: 2, UUID: passwordB})
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("revocation left the established stream open")
	}
	_ = connection.Close()
	if echoed, err := roundTrip(t, clientA, echo, payload); err == nil || string(echoed) == "ping" {
		t.Fatalf("new stream on the old revoked session was accepted: %q %v", echoed, err)
	}
	redialDeadline := time.Now().Add(5 * time.Second)
	for dialsA.dials.Load() == 1 && time.Now().Before(redialDeadline) {
		_, _ = roundTrip(t, clientA, echo, payload)
		time.Sleep(50 * time.Millisecond)
	}
	if dialsA.dials.Load() == 1 {
		t.Fatal("revocation left the QUIC session alive; the client never redialed")
	}
	if echoed, err := roundTrip(t, clientB, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("revoking A broke B: %q %v", echoed, err)
	}

	// Re-adding A with the same password must not revive the old session: the
	// identity is bound to a credential generation, not to the password value.
	applied(User{MemberID: 1, UUID: passwordA}, User{MemberID: 2, UUID: passwordB})
	revokedDials := dialsA.dials.Load()
	if echoed, err := roundTrip(t, clientA, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("the same client could not reconnect after re-authorization: %q %v", echoed, err)
	}
	if dialsA.dials.Load() <= revokedDials {
		t.Fatal("re-authorization reused the revoked QUIC session")
	}
	freshA, _ := newHysteria2Client(t, port, files, passwordA)
	if echoed, err := roundTrip(t, freshA, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("a fresh authentication after re-add failed: %q %v", echoed, err)
	}

	// Rotating a credential must reject the old session and accept a new one.
	const passwordC = "33333333-3333-4333-8333-333333333333"
	applied(User{MemberID: 1, UUID: passwordC}, User{MemberID: 2, UUID: passwordB})
	if echoed, err := roundTrip(t, clientA, echo, payload); err == nil || string(echoed) == "ping" {
		t.Fatalf("rotation left the old credential usable: %q %v", echoed, err)
	}
	clientC, dialsC := newHysteria2Client(t, port, files, passwordC)
	if echoed, err := roundTrip(t, clientC, echo, payload); err != nil || string(echoed) != "ping" {
		t.Fatalf("the rotated credential was rejected: %q %v", echoed, err)
	}
	if dialsC.dials.Load() != 1 {
		t.Fatalf("unexpected session count for the rotated credential: %d", dialsC.dials.Load())
	}
	if accepted.Load() == 0 {
		t.Fatal("the echo target never saw the proxied connections")
	}
}

func TestHysteria2RealQuicUDPRevocationAndReauthorization(t *testing.T) {
	files := newTestTLSFiles(t)
	port := freeUDPPort(t)
	config := hysteria2TestConfig(t, files, port)
	runtime, err := New(Hysteria2RuntimeConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	echo := startUDPEchoServer(t)
	const passwordA = "11111111-1111-4111-8111-111111111111"
	client, dials := newHysteria2Client(t, port, files, passwordA)
	applied := func(users ...User) {
		t.Helper()
		if _, err := runtime.ApplyPanel(context.Background(), Hysteria2RuntimeConfig(config), users); err != nil {
			t.Fatal(err)
		}
	}
	applied(User{MemberID: 1, UUID: passwordA})

	exchange := func(conn net.PacketConn) (string, error) {
		// The QUIC datagram socket supports read deadlines only.
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.WriteTo([]byte("dns"), echo); err != nil {
			return "", err
		}
		buffer := make([]byte, 16)
		length, _, err := conn.ReadFrom(buffer)
		if err != nil {
			return "", err
		}
		return string(buffer[:length]), nil
	}

	connection, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reply, err := exchange(connection); err != nil || reply != "dns" {
		t.Fatalf("UDP session failed before revocation: %q %v", reply, err)
	}
	assertUsage(t, runtime, map[int64][2]int64{1: {3, 3}})

	// Hysteria2 has no per-datagram error channel, so a refused destination
	// shows up as silence: the tracker closes the server-side session instead of
	// forwarding the datagram.
	applied()
	if _, err := exchange(connection); err == nil {
		t.Fatal("revocation left the established UDP session usable")
	}
	_ = connection.Close()
	// The whole transport is retired, so the same client must authenticate a
	// new QUIC session after access is restored.
	applied(User{MemberID: 1, UUID: passwordA})
	deadline := time.Now().Add(5 * time.Second)
	for {
		resumed, resumeErr := client.ListenPacket(context.Background())
		if resumeErr == nil {
			reply, exchangeErr := exchange(resumed)
			_ = resumed.Close()
			if exchangeErr == nil && reply == "dns" {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the same UDP client did not recover after re-authorization")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if dials.dials.Load() <= 1 {
		t.Fatal("UDP re-authorization reused the revoked QUIC session")
	}

}

func TestHysteria2ConcurrentAuthenticationUpdatesAndClose(t *testing.T) {
	files := newTestTLSFiles(t)
	port := freeUDPPort(t)
	config := hysteria2TestConfig(t, files, port)
	runtime, err := New(Hysteria2RuntimeConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	echo, _ := startEchoServer(t)
	const passwordA = "11111111-1111-4111-8111-111111111111"
	const passwordB = "22222222-2222-4222-8222-222222222222"
	if _, err := runtime.ApplyPanel(context.Background(), Hysteria2RuntimeConfig(config), []User{{MemberID: 1, UUID: passwordA}, {MemberID: 2, UUID: passwordB}}); err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	stop := make(chan struct{})
	for index := 0; index < 6; index++ {
		password := passwordA
		if index%2 == 1 {
			password = passwordB
		}
		client, _ := newHysteria2Client(t, port, files, password)
		wait.Add(1)
		go func() {
			defer wait.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = roundTrip(t, client, echo, []byte("x"))
			}
		}()
	}
	for round := 0; round < 50; round++ {
		users := []User{{MemberID: 1, UUID: passwordA}, {MemberID: 2, UUID: passwordB}}
		if round%2 == 1 {
			users = users[:1]
		}
		if _, err := runtime.ApplyPanel(context.Background(), Hysteria2RuntimeConfig(config), users); err != nil {
			t.Fatalf("concurrent update failed: %v", err)
		}
	}
	close(stop)
	wait.Wait()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

// assertUsage waits until the routed bytes are visible: a datagram reply can
// reach the client before the server-side read counter is flushed.
func assertUsage(t *testing.T, runtime *Runtime, want map[int64][2]int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		usage, err := runtime.Usage()
		if err != nil {
			t.Fatal(err)
		}
		matched := true
		for memberID, counters := range want {
			if usage.Members[memberID] != counters {
				matched = false
			}
		}
		if matched {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("metering is not exact: got %+v, want %+v", usage.Members, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// userNames reads the current identity set under the runtime lock.
func (r *Runtime) userNames() map[int64]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make(map[int64]string, len(r.identities))
	for name, memberID := range r.identities {
		names[memberID] = name
	}
	return names
}

func sameMemberNames(left, right map[int64]string) bool {
	if len(left) != len(right) {
		return false
	}
	for memberID, name := range left {
		if right[memberID] != name {
			return false
		}
	}
	return true
}
