package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrUpstreamUnavailable = errors.New("configured upstream proxy is unavailable")

const upstreamHandshakeTimeout = 10 * time.Second

type upstreamMemberState struct {
	member              UpstreamRouteMember
	currentWeight       int64
	consecutiveFailures int
	circuitOpenUntil    time.Time
}

// upstreamDialer owns the gateway-local health state for one immutable route.
// It can dial only configured proxy endpoints. It never falls back to dialing
// the requested target directly after a proxy or group route is selected.
type upstreamDialer struct {
	route     UpstreamRoute
	baseDial  DialContextFunc
	tlsConfig *tls.Config
	now       func() time.Time

	mu      sync.Mutex
	members map[string]*upstreamMemberState
}

func newUpstreamDialer(route UpstreamRoute, baseDial DialContextFunc, tlsConfig *tls.Config, now func() time.Time) (*upstreamDialer, error) {
	if err := validateUpstreamRoute(&route); err != nil {
		return nil, err
	}
	if baseDial == nil {
		return nil, errors.New("upstream proxy base dialer is required")
	}
	if now == nil {
		now = time.Now
	}
	dialer := &upstreamDialer{route: route, baseDial: baseDial, tlsConfig: tlsConfig, now: now}
	if route.Group != nil {
		dialer.members = make(map[string]*upstreamMemberState, len(route.Group.Members))
		for _, member := range route.Group.Members {
			copy := member
			dialer.members[member.Proxy.ID] = &upstreamMemberState{member: copy}
		}
	}
	return dialer, nil
}

func (d *upstreamDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("%w: network is not supported", ErrUpstreamUnavailable)
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return nil, fmt.Errorf("%w: target is invalid", ErrUpstreamUnavailable)
	}
	if d.route.Proxy != nil {
		connection, err := d.dialEndpoint(ctx, *d.route.Proxy, target)
		if err != nil {
			return nil, fmt.Errorf("%w: proxy connection failed", ErrUpstreamUnavailable)
		}
		return connection, nil
	}

	member, err := d.selectGroupMember()
	if err != nil {
		return nil, err
	}
	connection, dialErr := d.dialEndpoint(ctx, member.Proxy, target)
	d.recordGroupResult(member.Proxy.ID, dialErr == nil)
	if dialErr != nil {
		return nil, fmt.Errorf("%w: proxy group member connection failed", ErrUpstreamUnavailable)
	}
	return connection, nil
}

func (d *upstreamDialer) selectGroupMember() (UpstreamRouteMember, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now().UTC()
	priority := -1
	candidates := make([]WeightedCandidate, 0, len(d.members))
	for _, member := range d.members {
		if !member.circuitOpenUntil.IsZero() && !now.Before(member.circuitOpenUntil) {
			member.circuitOpenUntil = time.Time{}
			member.consecutiveFailures = 0
			member.currentWeight = 0
		}
		if !member.circuitOpenUntil.IsZero() {
			continue
		}
		if priority == -1 || member.member.Priority < priority {
			priority = member.member.Priority
			candidates = candidates[:0]
		}
		if member.member.Priority == priority {
			candidates = append(candidates, WeightedCandidate{
				ID: member.member.Proxy.ID, Weight: member.member.Weight, CurrentWeight: member.currentWeight,
			})
		}
	}
	if len(candidates) == 0 {
		return UpstreamRouteMember{}, ErrUpstreamUnavailable
	}
	selectedID, next, err := SelectSmoothWeighted(candidates)
	if err != nil {
		return UpstreamRouteMember{}, ErrUpstreamUnavailable
	}
	for _, candidate := range next {
		d.members[candidate.ID].currentWeight = candidate.CurrentWeight
	}
	selected := d.members[selectedID]
	if selected == nil {
		return UpstreamRouteMember{}, ErrUpstreamUnavailable
	}
	return selected.member, nil
}

func (d *upstreamDialer) recordGroupResult(proxyID string, success bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	member := d.members[proxyID]
	if member == nil || d.route.Group == nil {
		return
	}
	if success {
		member.consecutiveFailures = 0
		member.circuitOpenUntil = time.Time{}
		return
	}
	member.consecutiveFailures++
	if member.consecutiveFailures >= d.route.Group.FailureThreshold {
		member.circuitOpenUntil = d.now().UTC().Add(time.Duration(d.route.Group.CooldownSeconds) * time.Second)
		member.currentWeight = 0
	}
}

func (d *upstreamDialer) dialEndpoint(ctx context.Context, endpoint UpstreamEndpoint, target string) (net.Conn, error) {
	address := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
	connection, err := d.baseDial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(upstreamHandshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()
		return nil, err
	}
	rawConnection := connection
	stopCancellation := context.AfterFunc(ctx, func() { _ = rawConnection.SetDeadline(time.Now()) })
	defer stopCancellation()
	keep := false
	defer func() {
		if !keep {
			_ = connection.Close()
		}
	}()

	switch endpoint.Protocol {
	case UpstreamProtocolHTTPS:
		config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Host}
		if d.tlsConfig != nil {
			config = d.tlsConfig.Clone()
			if strings.TrimSpace(config.ServerName) == "" {
				config.ServerName = endpoint.Host
			}
			if config.MinVersion == 0 {
				config.MinVersion = tls.VersionTLS12
			}
		}
		secure := tls.Client(connection, config)
		if err := secure.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		connection = secure
		fallthrough
	case UpstreamProtocolHTTP:
		connected, err := connectHTTPProxy(connection, endpoint, target)
		if err != nil {
			return nil, err
		}
		connection = connected
	case UpstreamProtocolSOCKS5:
		if err := connectSOCKS5Proxy(connection, endpoint, target); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported upstream proxy protocol")
	}
	if !stopCancellation() && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := rawConnection.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	keep = true
	return connection, nil
}

type bufferedProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedProxyConn) Read(content []byte) (int, error) {
	return c.reader.Read(content)
}

func connectHTTPProxy(connection net.Conn, endpoint UpstreamEndpoint, target string) (net.Conn, error) {
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if endpoint.Username != "" {
		token := base64.StdEncoding.EncodeToString([]byte(endpoint.Username + ":" + endpoint.Password))
		request.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if err := request.Write(connection); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(connection, 32<<10)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("upstream HTTP proxy rejected CONNECT")
	}
	if reader.Buffered() == 0 {
		return connection, nil
	}
	return &bufferedProxyConn{Conn: connection, reader: reader}, nil
}

func connectSOCKS5Proxy(connection net.Conn, endpoint UpstreamEndpoint, target string) error {
	methods := []byte{0x00}
	if endpoint.Username != "" {
		methods = []byte{0x02}
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if err := writeAll(connection, greeting); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil || response[0] != 0x05 || response[1] == 0xff {
		return errors.New("upstream SOCKS5 negotiation failed")
	}
	if endpoint.Username != "" {
		if response[1] != 0x02 {
			return errors.New("upstream SOCKS5 refused username authentication")
		}
		auth := []byte{0x01, byte(len(endpoint.Username))}
		auth = append(auth, endpoint.Username...)
		auth = append(auth, byte(len(endpoint.Password)))
		auth = append(auth, endpoint.Password...)
		if err := writeAll(connection, auth); err != nil {
			return err
		}
		if _, err := io.ReadFull(connection, response); err != nil || response[0] != 0x01 || response[1] != 0x00 {
			return errors.New("upstream SOCKS5 authentication failed")
		}
	} else if response[1] != 0x00 {
		return errors.New("upstream SOCKS5 selected an unexpected authentication method")
	}

	host, rawPort, err := net.SplitHostPort(target)
	if err != nil {
		return errors.New("upstream SOCKS5 target is invalid")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("upstream SOCKS5 target port is invalid")
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("upstream SOCKS5 target must be a pinned IP address")
	}
	address = address.Unmap()
	request := []byte{0x05, 0x01, 0x00}
	if address.Is4() {
		request = append(request, 0x01)
		bytes := address.As4()
		request = append(request, bytes[:]...)
	} else {
		request = append(request, 0x04)
		bytes := address.As16()
		request = append(request, bytes[:]...)
	}
	request = append(request, byte(port>>8), byte(port))
	if err := writeAll(connection, request); err != nil {
		return err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil || header[0] != 0x05 || header[1] != 0x00 {
		return errors.New("upstream SOCKS5 CONNECT failed")
	}
	length := 0
	switch header[3] {
	case 0x01:
		length = 4
	case 0x04:
		length = 16
	case 0x03:
		one := []byte{0}
		if _, err := io.ReadFull(connection, one); err != nil {
			return err
		}
		length = int(one[0])
	default:
		return errors.New("upstream SOCKS5 returned an invalid address type")
	}
	_, err = io.CopyN(io.Discard, connection, int64(length+2))
	return err
}
