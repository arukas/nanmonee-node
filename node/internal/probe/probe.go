// Package probe measures one-way latency from this node to an address.
//
// The node dials the target itself, so a result describes this node's own path
// and not a third-party vantage point. Three methods are supported, matching
// what the panel can configure:
//
//   - icmp   — an ICMP echo round trip, using an unprivileged datagram socket
//   - tcp    — the time to complete a TCP handshake
//   - http   — a full HTTP request, succeeding on 2xx/3xx
//
// Every method reports a millisecond latency, or an error describing why no
// measurement exists. The caller decides how to send that to the panel.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Type is the measurement a target asks for.
type Type string

const (
	TypeICMP  Type = "icmp"
	TypeTCP   Type = "tcp"
	TypeHTTP  Type = "http"
	TypeHTTPS Type = "https"
)

// ErrUnsupportedType reports a type this package cannot measure.
var ErrUnsupportedType = errors.New("probe: unsupported type")

// Target is one configured destination.
type Target struct {
	ID      int64
	Type    Type
	Host    string
	Port    int
	Timeout time.Duration
}

// Result is one measurement attempt.
type Result struct {
	TargetID  int64
	LatencyMS *int64
	Err       string
	SampledAt time.Time
}

// Measure runs one probe and never returns a nil Result.
func Measure(ctx context.Context, target Target) Result {
	started := time.Now()
	latency, err := measure(ctx, target)

	result := Result{TargetID: target.ID, SampledAt: started}
	if err != nil {
		// The panel stores a short reason, not a Go error chain.
		result.Err = shorten(err.Error(), 120)
		return result
	}

	ms := latency.Milliseconds()
	result.LatencyMS = &ms
	return result
}

func measure(ctx context.Context, target Target) (time.Duration, error) {
	if target.Timeout <= 0 {
		target.Timeout = 3 * time.Second
	}

	switch target.Type {
	case TypeICMP:
		return measureICMP(ctx, target)
	case TypeTCP:
		return measureTCP(ctx, target)
	case TypeHTTP, TypeHTTPS:
		return measureHTTP(ctx, target)
	default:
		return 0, ErrUnsupportedType
	}
}

// measureTCP times the TCP handshake. A refused or filtered port is a failure,
// because the point is reachability rather than mere name resolution.
func measureTCP(ctx context.Context, target Target) (time.Duration, error) {
	port := target.Port
	if port == 0 {
		port = 443
	}

	address := net.JoinHostPort(target.Host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: target.Timeout}

	started := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(started)
	conn.Close()

	return elapsed, nil
}

// measureHTTP issues a full request. DNS resolution happens inside the timed
// region, unlike a TCP-style measurement, because a user-visible HTTP latency
// includes it.
func measureHTTP(ctx context.Context, target Target) (time.Duration, error) {
	scheme := "http"
	if target.Type == TypeHTTPS {
		scheme = "https"
	}

	host := target.Host
	if target.Port != 0 && target.Port != defaultPort(scheme) {
		host = net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	}

	transport := &http.Transport{
		// A shared client would reuse a warm connection and report a latency that
		// no longer describes the path.
		DisableKeepAlives:   true,
		DisableCompression:  true,
		TLSHandshakeTimeout: target.Timeout,
		DialContext:         (&net.Dialer{Timeout: target.Timeout}).DialContext,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   target.Timeout,
		Transport: transport,
		// The status code is the measurement; a redirect target is not followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+"/", nil)
	if err != nil {
		return 0, err
	}

	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(started)
	response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return 0, fmt.Errorf("unexpected status %d", response.StatusCode)
	}

	return elapsed, nil
}

func defaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

func shorten(value string, max int) string {
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max])
}

// icmpNetwork picks the unprivileged datagram socket for the address family.
// A privileged raw socket needs CAP_NET_RAW, which the node service does not
// hold; the datagram form is allowed for an unprivileged user on Linux.
func icmpNetwork(ip net.IP) string {
	if ip.To4() != nil {
		return "udp4"
	}
	return "udp6"
}

// measureICMP sends one echo request and waits for the matching reply.
func measureICMP(ctx context.Context, target Target) (time.Duration, error) {
	ip, err := resolve(target.Host)
	if err != nil {
		return 0, err
	}

	conn, err := icmp.ListenPacket(icmpNetwork(ip), "")
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// A stale reply from a previous run must not be attributed to this request:
	// the deadline also bounds how long the read blocks.
	deadline := time.Now().Add(target.Timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, err
	}

	echo := icmp.Message{
		Type: echoRequestType(ip),
		Code: 0,
		Body: &icmp.Echo{ID: 1, Seq: 1, Data: []byte("nanmonee-probe")},
	}
	payload, err := echo.Marshal(nil)
	if err != nil {
		return 0, err
	}

	started := time.Now()
	if _, err := conn.WriteTo(payload, &net.IPAddr{IP: ip}); err != nil {
		return 0, err
	}

	buffer := make([]byte, 1500)
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}

		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			return 0, err
		}
		elapsed := time.Since(started)

		if addr, ok := peer.(*net.IPAddr); !ok || !addr.IP.Equal(ip) {
			continue
		}

		reply, err := icmp.ParseMessage(protocolNumber(ip), buffer[:n])
		if err != nil {
			continue
		}
		if reply.Type != echoReplyType(ip) {
			continue
		}
		if body, ok := reply.Body.(*icmp.Echo); !ok || body.Seq != 1 {
			continue
		}

		return elapsed, nil
	}
}

func echoRequestType(ip net.IP) icmp.Type {
	if ip.To4() != nil {
		return ipv4.ICMPTypeEcho
	}
	return ipv6.ICMPTypeEchoRequest
}

func echoReplyType(ip net.IP) icmp.Type {
	if ip.To4() != nil {
		return ipv4.ICMPTypeEchoReply
	}
	return ipv6.ICMPTypeEchoReply
}

func protocolNumber(ip net.IP) int {
	if ip.To4() != nil {
		return 1
	}
	return 58
}

// resolve maps a host to one address, preferring IPv4 so a dual-stack name does
// not silently measure a different family than the operator expects.
func resolve(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}

	addresses, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no address for %s", host)
	}

	for _, address := range addresses {
		if address.IP.To4() != nil {
			return address.IP, nil
		}
	}

	return addresses[0].IP, nil
}
