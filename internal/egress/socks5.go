package egress

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"cyberstrike-ai/internal/boundary"
)

const (
	DefaultSOCKS5ListenAddress = "0.0.0.0:1080"
	maxSOCKS5Connections       = 128
	maxSOCKS5UDPPacket         = 64 << 10
)

// SOCKS5Proxy carries policy-checked raw TCP and UDP traffic. It deliberately
// supports no client authentication because it is reachable only from the
// per-conversation internal network and has one immutable policy.
type SOCKS5Proxy struct {
	policy       *boundary.Policy
	dialContext  DialContextFunc
	dialUDP      DialContextFunc
	lookupNetIP  LookupNetIPFunc
	now          func() time.Time
	activitySink ActivitySink
	guard        *requestGuard
	upstream     bool
	sem          chan struct{}
	udpSem       chan struct{}
	tcpPacer     *trafficPacer
	udpPacer     *trafficPacer
}

func NewSOCKS5Proxy(httpProxy *Proxy, upstream bool) (*SOCKS5Proxy, error) {
	if httpProxy == nil || httpProxy.policy == nil || httpProxy.dialContext == nil || httpProxy.lookupNetIP == nil {
		return nil, errors.New("egress SOCKS5 proxy dependencies are unavailable")
	}
	udpDialer := &net.Dialer{Timeout: 10 * time.Second}
	return &SOCKS5Proxy{
		policy: httpProxy.policy, dialContext: httpProxy.dialContext, lookupNetIP: httpProxy.lookupNetIP,
		now: httpProxy.now, activitySink: httpProxy.activitySink, guard: httpProxy.guard,
		upstream: upstream, dialUDP: udpDialer.DialContext,
		sem: make(chan struct{}, maxSOCKS5Connections), udpSem: make(chan struct{}, maxSOCKS5Connections),
		tcpPacer: httpProxy.tcpPacer, udpPacer: httpProxy.udpPacer,
	}, nil
}

func (p *SOCKS5Proxy) Serve(ctx context.Context, listener net.Listener) error {
	if p == nil || listener == nil {
		return errors.New("egress SOCKS5 listener is unavailable")
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case p.sem <- struct{}{}:
			go func() { defer func() { <-p.sem }(); p.handle(ctx, connection) }()
		default:
			_ = connection.Close()
		}
	}
}

func (p *SOCKS5Proxy) handle(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReaderSize(connection, 32<<10)
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil || header[0] != 5 || header[1] == 0 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}
	noAuth := false
	for _, method := range methods {
		noAuth = noAuth || method == 0
	}
	if !noAuth {
		_, _ = connection.Write([]byte{5, 0xff})
		return
	}
	if _, err := connection.Write([]byte{5, 0}); err != nil {
		return
	}
	requestHeader := make([]byte, 4)
	if _, err := io.ReadFull(reader, requestHeader); err != nil || requestHeader[0] != 5 || requestHeader[2] != 0 {
		return
	}
	host, port, err := readSOCKS5Address(reader, requestHeader[3], requestHeader[1] == 3)
	if err != nil {
		_ = writeSOCKS5Reply(connection, 8, nil)
		return
	}
	_ = connection.SetDeadline(time.Time{})
	switch requestHeader[1] {
	case 1:
		p.handleConnect(ctx, connection, reader, host, port)
	case 3:
		p.handleUDPAssociate(ctx, connection)
	default:
		_ = writeSOCKS5Reply(connection, 7, nil)
	}
}

func (p *SOCKS5Proxy) resolveAndAuthorize(ctx context.Context, host string, port int, protocol string) (boundary.Decision, []netip.Addr, error) {
	preflight, err := p.policy.EvaluateNetwork(host, port, protocol, nil, p.now().UTC())
	if err != nil || !proxyDecisionAllowed(preflight) {
		return preflight, nil, errors.New("network target denied")
	}
	addresses := make([]netip.Addr, 0, 4)
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		addresses = append(addresses, address.Unmap())
	} else {
		resolved, lookupErr := p.lookupNetIP(ctx, "ip", host)
		if lookupErr != nil {
			return preflight, nil, lookupErr
		}
		addresses, err = canonicalDNSAddresses(resolved)
		if err != nil {
			return preflight, nil, err
		}
	}
	final, err := p.policy.EvaluateNetwork(host, port, protocol, addresses, p.now().UTC())
	if err != nil || !proxyDecisionAllowed(final) || final.RuleID != preflight.RuleID || final.Effect != preflight.Effect {
		return final, addresses, errors.New("resolved network target denied")
	}
	return final, addresses, nil
}

func (p *SOCKS5Proxy) handleConnect(ctx context.Context, client net.Conn, clientReader *bufio.Reader, host string, port int) {
	started := p.now().UTC()
	event := ActivityEvent{Timestamp: started, RequestType: ActivityRequestTCP, Domain: host, Port: port, Decision: ActivityDecisionBlocked, Outcome: "policy_denied"}
	decision, addresses, err := p.resolveAndAuthorize(ctx, host, port, "tcp")
	event.RuleID, event.Reason, event.BlockMatch, event.ResolvedIPs = decision.RuleID, decision.Reason, decision.BlockMatch, activityIPStrings(addresses)
	defer func() {
		event.LatencyMS = activityLatencyMS(started, p.now().UTC())
		emitActivity(p.activitySink, event)
	}()
	if err != nil {
		if proxyDecisionAllowed(decision) {
			// Resolver/target preparation failures happened after policy allowed
			// the request. Keep them as connection results, never as fabricated
			// boundary denials.
			event.Decision, event.Outcome = ActivityDecisionAllowed, "dns_failed"
			event.Reason, event.RuleID, event.BlockMatch = "", "", nil
		}
		_ = writeSOCKS5Reply(client, 2, nil)
		return
	}
	if err := p.tcpPacer.Wait(ctx); err != nil {
		event.Outcome = "rate_wait_canceled"
		_ = writeSOCKS5Reply(client, 1, nil)
		return
	}
	release, block, _ := p.guard.acquire(decision, started)
	if block != nil {
		event.Reason, event.Outcome, event.RetryAfterMS = block.reason, block.outcome, block.retryAfterMS
		event.BlockMatch = governanceBlockMatch(decision, block.reason)
		_ = writeSOCKS5Reply(client, 2, nil)
		return
	}
	defer release()
	event.Decision, event.Outcome = ActivityDecisionAllowed, "dial_failed"
	var upstream net.Conn
	for _, address := range addresses {
		upstream, err = p.dialContext(ctx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(port)))
		if err == nil {
			event.ConnectedIP = address.String()
			break
		}
	}
	if upstream == nil {
		_ = writeSOCKS5Reply(client, 5, nil)
		return
	}
	defer upstream.Close()
	if err := writeSOCKS5Reply(client, 0, upstream.LocalAddr()); err != nil {
		event.Outcome = "client_write_failed"
		return
	}
	event.Outcome = "completed"
	event.BytesUp, event.BytesDown = tunnelConnections(client, clientReader, upstream)
}

func (p *SOCKS5Proxy) handleUDPAssociate(ctx context.Context, control net.Conn) {
	if p.upstream {
		_ = writeSOCKS5Reply(control, 7, nil)
		return
	}
	local, ok := control.LocalAddr().(*net.TCPAddr)
	if !ok || local.IP == nil || local.IP.IsUnspecified() {
		_ = writeSOCKS5Reply(control, 1, nil)
		return
	}
	network := "udp6"
	if local.IP.To4() != nil {
		network = "udp4"
	}
	// Bind only the address on which this Agent reached SOCKS. The gateway is
	// also attached to its egress network; an all-interface UDP relay would
	// unnecessarily expose the association there.
	relay, err := net.ListenUDP(network, &net.UDPAddr{IP: local.IP})
	if err != nil {
		_ = writeSOCKS5Reply(control, 1, nil)
		return
	}
	defer relay.Close()
	if err := writeSOCKS5Reply(control, 0, relay.LocalAddr()); err != nil {
		return
	}
	associationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _, _ = io.Copy(io.Discard, control); cancel(); _ = relay.Close() }()
	buffer := make([]byte, maxSOCKS5UDPPacket)
	var clientAddress *net.UDPAddr
	for {
		_ = relay.SetReadDeadline(time.Now().Add(time.Second))
		count, source, readErr := relay.ReadFromUDP(buffer)
		if readErr != nil {
			if associationCtx.Err() != nil || errors.Is(readErr, net.ErrClosed) {
				return
			}
			if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return
		}
		if clientAddress == nil {
			clientAddress = source
		}
		if source.String() != clientAddress.String() {
			continue
		}
		packet := append([]byte(nil), buffer[:count]...)
		select {
		case p.udpSem <- struct{}{}:
			go func() { defer func() { <-p.udpSem }(); p.forwardUDP(associationCtx, relay, clientAddress, packet) }()
		default:
		}
	}
}

func (p *SOCKS5Proxy) forwardUDP(ctx context.Context, relay *net.UDPConn, client *net.UDPAddr, packet []byte) {
	started := p.now().UTC()
	host, port, payload, err := parseSOCKS5UDPDatagram(packet)
	if err != nil {
		return
	}
	event := ActivityEvent{Timestamp: started, RequestType: ActivityRequestUDP, Domain: host, Port: port, Decision: ActivityDecisionBlocked, Outcome: "policy_denied", BytesUp: int64(len(payload))}
	decision, addresses, authErr := p.resolveAndAuthorize(ctx, host, port, "udp")
	event.RuleID, event.Reason, event.BlockMatch, event.ResolvedIPs = decision.RuleID, decision.Reason, decision.BlockMatch, activityIPStrings(addresses)
	defer func() {
		event.LatencyMS = activityLatencyMS(started, p.now().UTC())
		emitActivity(p.activitySink, event)
	}()
	if authErr != nil {
		if proxyDecisionAllowed(decision) {
			event.Decision, event.Outcome = ActivityDecisionAllowed, "dns_failed"
			event.Reason, event.RuleID, event.BlockMatch = "", "", nil
		}
		return
	}
	if err := p.udpPacer.Wait(ctx); err != nil {
		event.Outcome = "rate_wait_canceled"
		return
	}
	release, block, _ := p.guard.acquire(decision, started)
	if block != nil {
		event.Reason, event.Outcome, event.RetryAfterMS = block.reason, block.outcome, block.retryAfterMS
		event.BlockMatch = governanceBlockMatch(decision, block.reason)
		return
	}
	defer release()
	event.Decision, event.Outcome = ActivityDecisionAllowed, "send_failed"
	for _, address := range addresses {
		upstream, dialErr := p.dialUDP(ctx, "udp", netip.AddrPortFrom(address, uint16(port)).String())
		if dialErr != nil {
			continue
		}
		event.ConnectedIP = address.String()
		_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = upstream.Write(payload); err != nil {
			_ = upstream.Close()
			continue
		}
		event.Outcome = "sent"
		response := make([]byte, maxSOCKS5UDPPacket)
		responseCount, responseErr := upstream.Read(response)
		_ = upstream.Close()
		if responseErr == nil {
			event.BytesDown = int64(responseCount)
			encoded := encodeSOCKS5UDPDatagram(address.String(), port, response[:responseCount])
			_, _ = relay.WriteToUDP(encoded, client)
			event.Outcome = "completed"
		}
		return
	}
}

func readSOCKS5Address(reader io.Reader, addressType byte, allowZeroPort bool) (string, int, error) {
	var raw []byte
	switch addressType {
	case 1:
		raw = make([]byte, 4)
	case 4:
		raw = make([]byte, 16)
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(reader, length); err != nil || length[0] == 0 {
			return "", 0, errors.New("invalid domain")
		}
		raw = make([]byte, int(length[0]))
	default:
		return "", 0, errors.New("unsupported address type")
	}
	if _, err := io.ReadFull(reader, raw); err != nil {
		return "", 0, err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return "", 0, err
	}
	host := string(raw)
	if addressType == 1 || addressType == 4 {
		host = net.IP(raw).String()
	}
	normalized, err := boundary.NormalizeHost(host)
	if err != nil {
		return "", 0, err
	}
	port := int(binary.BigEndian.Uint16(portBytes))
	if port == 0 && !allowZeroPort {
		return "", 0, errors.New("invalid port")
	}
	return normalized, port, nil
}

func writeSOCKS5Reply(writer io.Writer, code byte, address net.Addr) error {
	ip := net.IPv4zero
	port := 0
	if tcp, ok := address.(*net.TCPAddr); ok {
		ip, port = tcp.IP, tcp.Port
	}
	if udp, ok := address.(*net.UDPAddr); ok {
		ip, port = udp.IP, udp.Port
	}
	if ip == nil || ip.IsUnspecified() {
		ip = net.IPv4zero
	}
	reply := []byte{5, code, 0}
	if ipv4 := ip.To4(); ipv4 != nil {
		reply = append(reply, 1)
		reply = append(reply, ipv4...)
	} else {
		reply = append(reply, 4)
		reply = append(reply, ip.To16()...)
	}
	reply = append(reply, byte(port>>8), byte(port))
	return writeAll(writer, reply)
}

func parseSOCKS5UDPDatagram(packet []byte) (string, int, []byte, error) {
	if len(packet) < 7 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", 0, nil, errors.New("fragmented or invalid UDP datagram")
	}
	reader := &countingReader{Reader: bytesReader(packet[4:])}
	host, port, err := readSOCKS5Address(reader, packet[3], false)
	if err != nil {
		return "", 0, nil, err
	}
	offset := 4 + reader.count
	if offset > len(packet) {
		return "", 0, nil, errors.New("invalid UDP datagram")
	}
	return host, port, packet[offset:], nil
}

type sliceReader struct{ data []byte }

func bytesReader(data []byte) *sliceReader { return &sliceReader{data: data} }
func (r *sliceReader) Read(target []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	count := copy(target, r.data)
	r.data = r.data[count:]
	return count, nil
}

type countingReader struct {
	io.Reader
	count int
}

func (r *countingReader) Read(target []byte) (int, error) {
	count, err := r.Reader.Read(target)
	r.count += count
	return count, err
}

func encodeSOCKS5UDPDatagram(host string, port int, payload []byte) []byte {
	result := []byte{0, 0, 0}
	address, err := netip.ParseAddr(host)
	if err == nil && address.Is4() {
		raw := address.As4()
		result = append(result, 1)
		result = append(result, raw[:]...)
	} else if err == nil {
		raw := address.As16()
		result = append(result, 4)
		result = append(result, raw[:]...)
	} else {
		result = append(result, 3, byte(len(host)))
		result = append(result, host...)
	}
	result = append(result, byte(port>>8), byte(port))
	return append(result, payload...)
}
