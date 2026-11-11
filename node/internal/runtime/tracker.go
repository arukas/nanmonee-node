package runtime

import (
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

var errCounterOverflow = errors.New("member byte counter overflow")

type byteCounter struct {
	value    atomic.Int64
	overflow atomic.Bool
}

func (c *byteCounter) add(n int64) {
	if n < 0 {
		c.overflow.Store(true)
		return
	}
	for {
		current := c.value.Load()
		if current < 0 || n > math.MaxInt64-current {
			c.overflow.Store(true)
			c.value.CompareAndSwap(current, math.MaxInt64)
			return
		}
		if c.value.CompareAndSwap(current, current+n) {
			return
		}
	}
}

func (c *byteCounter) snapshot() (int64, error) {
	if c.overflow.Load() {
		return 0, errCounterOverflow
	}
	value := c.value.Load()
	if value < 0 {
		return 0, errCounterOverflow
	}
	return value, nil
}

type memberUsage struct {
	upload   byteCounter
	download byteCounter
}

type connectionReference struct {
	identity string
	closer   interface{ Close() error }
}

type connectionTracker struct {
	mu          sync.Mutex
	identities  map[string]int64
	allowed     map[string]bool
	usage       map[int64]*memberUsage
	connections map[uint64]connectionReference
	nextID      atomic.Uint64
}

func newConnectionTracker() *connectionTracker {
	return &connectionTracker{
		identities:  make(map[string]int64),
		allowed:     make(map[string]bool),
		usage:       make(map[int64]*memberUsage),
		connections: make(map[uint64]connectionReference),
	}
}

func (t *connectionTracker) setAuthorized(identities map[string]int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.identities = cloneIdentities(identities)
	t.allowed = make(map[string]bool, len(identities))
	for identity, memberID := range identities {
		t.allowed[identity] = true
		t.usageFor(memberID)
	}
}

func (t *connectionTracker) stage(identities map[string]int64) {
	t.mu.Lock()
	allowed := make(map[string]bool, len(identities))
	for identity, memberID := range identities {
		allowed[identity] = t.allowed[identity]
		t.usageFor(memberID)
	}
	t.identities = cloneIdentities(identities)
	t.allowed = allowed
	var revoked []ioCloser
	for _, connection := range t.connections {
		if !allowed[connection.identity] {
			revoked = append(revoked, connection.closer)
		}
	}
	t.mu.Unlock()
	for _, connection := range revoked {
		_ = connection.Close()
	}
}

func cloneIdentities(identities map[string]int64) map[string]int64 {
	cloned := make(map[string]int64, len(identities))
	for identity, memberID := range identities {
		cloned[identity] = memberID
	}
	return cloned
}

func (t *connectionTracker) usageFor(memberID int64) *memberUsage {
	usage, loaded := t.usage[memberID]
	if !loaded {
		usage = new(memberUsage)
		t.usage[memberID] = usage
	}
	return usage
}

func (t *connectionTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	t.mu.Lock()
	memberID, known := t.identities[metadata.User]
	if !known || !t.allowed[metadata.User] {
		t.mu.Unlock()
		_ = conn.Close()
		return conn
	}
	usage := t.usageFor(memberID)
	id := t.nextID.Add(1)
	tracked := &trackedConn{
		CounterConn: bufio.NewCounterConn(conn, []N.CountFunc{usage.upload.add}, []N.CountFunc{usage.download.add}),
		tracker:     t,
		id:          id,
	}
	t.connections[id] = connectionReference{identity: metadata.User, closer: tracked}
	t.mu.Unlock()
	return tracked
}

func (t *connectionTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	t.mu.Lock()
	memberID, known := t.identities[metadata.User]
	if !known || !t.allowed[metadata.User] {
		t.mu.Unlock()
		_ = conn.Close()
		return conn
	}
	usage := t.usageFor(memberID)
	id := t.nextID.Add(1)
	tracked := &trackedPacketConn{
		CounterPacketConn: bufio.NewCounterPacketConn(conn, []N.CountFunc{usage.upload.add}, []N.CountFunc{usage.download.add}),
		tracker:           t,
		id:                id,
	}
	t.connections[id] = connectionReference{identity: metadata.User, closer: tracked}
	t.mu.Unlock()
	return tracked
}

func (t *connectionTracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return new(noopFlowTracker)
}

func (t *connectionTracker) remove(id uint64) {
	t.mu.Lock()
	delete(t.connections, id)
	t.mu.Unlock()
}

func (t *connectionTracker) activeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.connections)
}

func (t *connectionTracker) usageSnapshot() (map[int64][2]int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make(map[int64][2]int64, len(t.usage))
	for memberID, usage := range t.usage {
		upload, err := usage.upload.snapshot()
		if err != nil {
			return nil, err
		}
		download, err := usage.download.snapshot()
		if err != nil {
			return nil, err
		}
		result[memberID] = [2]int64{upload, download}
	}
	return result, nil
}

type ioCloser interface {
	Close() error
}

type trackedConn struct {
	*bufio.CounterConn
	tracker  *connectionTracker
	id       uint64
	once     sync.Once
	closeErr error
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.tracker.remove(c.id)
		c.closeErr = c.CounterConn.Close()
	})
	return c.closeErr
}

func (c *trackedConn) ReaderReplaceable() bool { return true }
func (c *trackedConn) WriterReplaceable() bool { return true }

type trackedPacketConn struct {
	*bufio.CounterPacketConn
	tracker  *connectionTracker
	id       uint64
	once     sync.Once
	closeErr error
}

func (c *trackedPacketConn) Close() error {
	c.once.Do(func() {
		c.tracker.remove(c.id)
		c.closeErr = c.CounterPacketConn.Close()
	})
	return c.closeErr
}

func (c *trackedPacketConn) ReaderReplaceable() bool { return true }
func (c *trackedPacketConn) WriterReplaceable() bool { return false }

type noopFlowTracker struct{}

func (noopFlowTracker) AttachFlow(tun.FlowHandle)     {}
func (noopFlowTracker) CountForward(int)              {}
func (noopFlowTracker) CountReverse(int)              {}
func (noopFlowTracker) FlowEstablished()              {}
func (noopFlowTracker) CloseFlow(tun.FlowCloseReason) {}
