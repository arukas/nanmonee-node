package runtime

import (
	"context"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type closeCountingConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *closeCountingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

type testPacketConn struct {
	packets [][]byte
	closes  atomic.Int32
}

func (c *testPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if len(c.packets) == 0 {
		return M.Socksaddr{}, io.EOF
	}
	_, _ = buffer.Write(c.packets[0])
	c.packets = c.packets[1:]
	return M.ParseSocksaddr("192.0.2.10:53"), nil
}

func (c *testPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *testPacketConn) Close() error {
	c.closes.Add(1)
	return nil
}

func (c *testPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *testPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *testPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testPacketConn) SetWriteDeadline(time.Time) error { return nil }

func routeTestConnections(tracker *connectionTracker, identity string) (*closeCountingConn, *testPacketConn, net.Conn, N.PacketConn) {
	tcp, peer := net.Pipe()
	_ = peer.Close()
	rawTCP := &closeCountingConn{Conn: tcp}
	rawUDP := new(testPacketConn)
	metadata := adapter.InboundContext{User: identity}
	return rawTCP, rawUDP, tracker.RoutedConnection(context.Background(), rawTCP, metadata, nil, nil), tracker.RoutedPacketConnection(context.Background(), rawUDP, metadata, nil, nil)
}

func TestRevocationClosesOnlyRevokedConnectionsAndRejectsLateRegistration(t *testing.T) {
	tracker := newConnectionTracker()
	tracker.setAuthorized(map[string]int64{"m1.g1": 1, "m2.g1": 2})
	aTCP, aUDP, aTrackedTCP, aTrackedUDP := routeTestConnections(tracker, "m1.g1")
	bTCP, bUDP, bTrackedTCP, bTrackedUDP := routeTestConnections(tracker, "m2.g1")
	defer bTrackedTCP.Close()
	defer bTrackedUDP.Close()

	tracker.stage(map[string]int64{"m2.g1": 2})
	if aTCP.closes.Load() != 1 || aUDP.closes.Load() != 1 {
		t.Fatalf("revoked connections were not closed exactly once: TCP=%d UDP=%d", aTCP.closes.Load(), aUDP.closes.Load())
	}
	if bTCP.closes.Load() != 0 || bUDP.closes.Load() != 0 {
		t.Fatal("revoking A closed B connections")
	}
	_ = aTrackedTCP.Close()
	_ = aTrackedUDP.Close()
	if aTCP.closes.Load() != 1 || aUDP.closes.Load() != 1 {
		t.Fatal("repeated close reached the underlying connections")
	}

	lateTCP, lateUDP, _, _ := routeTestConnections(tracker, "m1.g1")
	if lateTCP.closes.Load() != 1 || lateUDP.closes.Load() != 1 {
		t.Fatal("late registration bypassed revocation")
	}
	if tracker.activeCount() != 2 {
		t.Fatalf("unexpected remaining connections: %d", tracker.activeCount())
	}
}

func TestPacketCopyCountsUnequalDirectionsIncludingCachedPackets(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "cached"}[cached], func(t *testing.T) {
			tracker := newConnectionTracker()
			tracker.setAuthorized(map[string]int64{"m1.g1": 1})
			inbound := &testPacketConn{packets: [][]byte{[]byte("hello")}}
			var source N.PacketConn = inbound
			if cached {
				inbound.packets = nil
				source = bufio.NewCachedPacketConn(inbound, buf.As([]byte("hello")), M.ParseSocksaddr("192.0.2.10:53"))
			}
			wrapped := tracker.RoutedPacketConnection(context.Background(), source, adapter.InboundContext{User: "m1.g1"}, nil, nil)
			_, _ = bufio.CopyPacket(&testPacketConn{}, wrapped)
			_, _ = bufio.CopyPacket(wrapped, &testPacketConn{packets: [][]byte{[]byte("bye")}})
			usage, err := tracker.usageSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			if usage[1] != [2]int64{5, 3} {
				t.Fatalf("packet directions were lost or swapped: %v", usage[1])
			}
			_ = wrapped.Close()
		})
	}
}

func TestConcurrentRevocationDoesNotLeaveLateRegistration(t *testing.T) {
	tracker := newConnectionTracker()
	tracker.setAuthorized(map[string]int64{"m1.g1": 1, "m2.g1": 2})
	_, _, bTCP, bUDP := routeTestConnections(tracker, "m2.g1")
	defer bTCP.Close()
	defer bUDP.Close()

	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			rawTCP, rawUDP, trackedTCP, trackedUDP := routeTestConnections(tracker, "m1.g1")
			_ = rawTCP
			_ = rawUDP
			_ = trackedTCP.Close()
			_ = trackedUDP.Close()
		}()
	}
	tracker.stage(map[string]int64{"m2.g1": 2})
	wait.Wait()
	lateTCP, lateUDP, _, _ := routeTestConnections(tracker, "m1.g1")
	if lateTCP.closes.Load() != 1 || lateUDP.closes.Load() != 1 || tracker.activeCount() != 2 {
		t.Fatal("concurrent revocation left an A connection registered")
	}
}

func TestUsageSnapshotKeepsHistoryAndRejectsOverflow(t *testing.T) {
	tracker := newConnectionTracker()
	tracker.setAuthorized(map[string]int64{"m1.g1": 1})
	tracker.identities["m1.g1"] = 1
	tracker.usage[1].upload.add(11)
	tracker.stage(map[string]int64{})
	usage, err := tracker.usageSnapshot()
	if err != nil || usage[1] != [2]int64{11, 0} {
		t.Fatalf("revocation erased cumulative usage: %v, %v", usage, err)
	}
	tracker.usage[1].download.add(math.MaxInt64)
	tracker.usage[1].download.add(1)
	if _, err := tracker.usageSnapshot(); err == nil {
		t.Fatal("counter overflow was silently truncated")
	}
}
