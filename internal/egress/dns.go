package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/boundary"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	DefaultDNSListenAddress = "0.0.0.0:53"
	defaultDNSAnswerTTL     = 30
	defaultDNSLookupTimeout = 5 * time.Second
	maxDNSAddresses         = 64
	maxConcurrentDNSQueries = 32
	maxTCPDNSQueries        = 32
)

type DNSOptions struct {
	LookupNetIP   LookupNetIPFunc
	Now           func() time.Time
	AnswerTTL     uint32
	LookupTimeout time.Duration
	ActivitySink  ActivitySink
}

// PolicyDNS resolves only names that are usable by an active rule in the
// immutable boundary snapshot. It validates the complete upstream answer set
// before returning any address to prevent mixed public/private rebinding.
type PolicyDNS struct {
	policy        *boundary.Policy
	lookupNetIP   LookupNetIPFunc
	now           func() time.Time
	answerTTL     uint32
	lookupTimeout time.Duration
	activitySink  ActivitySink
}

func NewPolicyDNS(policy *boundary.Policy, options DNSOptions) (*PolicyDNS, error) {
	if policy == nil {
		return nil, errors.New("egress DNS policy is required")
	}
	if options.LookupTimeout < 0 {
		return nil, errors.New("egress DNS lookup timeout must not be negative")
	}
	lookup := options.LookupNetIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	ttl := options.AnswerTTL
	if ttl == 0 {
		ttl = defaultDNSAnswerTTL
	}
	timeout := options.LookupTimeout
	if timeout == 0 {
		timeout = defaultDNSLookupTimeout
	}
	return &PolicyDNS{policy: policy, lookupNetIP: lookup, now: now, answerTTL: ttl, lookupTimeout: timeout, activitySink: options.ActivitySink}, nil
}

func (d *PolicyDNS) HandleQuery(ctx context.Context, packet []byte) ([]byte, error) {
	if d == nil || d.policy == nil {
		return nil, errors.New("egress DNS is unavailable")
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(packet)
	if err != nil {
		return nil, err
	}
	if header.Response {
		return nil, nil
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || header.Truncated {
		return buildDNSResponse(header, nil, dnsmessage.RCodeFormatError, nil, d.answerTTL)
	}
	question := questions[0]
	startedAt := d.now().UTC()
	event := ActivityEvent{Timestamp: startedAt, RequestType: ActivityRequestDNS, Domain: strings.TrimSuffix(question.Name.String(), "."), Decision: ActivityDecisionBlocked, Outcome: "rejected"}
	defer func() {
		event.LatencyMS = activityLatencyMS(startedAt, d.now().UTC())
		emitActivity(d.activitySink, event)
	}()
	if header.OpCode != 0 {
		event.Outcome = "unsupported_opcode"
		return buildDNSResponse(header, &question, dnsmessage.RCodeNotImplemented, nil, d.answerTTL)
	}
	if question.Class != dnsmessage.ClassINET {
		event.Outcome = "unsupported_class"
		return buildDNSResponse(header, &question, dnsmessage.RCodeRefused, nil, d.answerTTL)
	}
	host := question.Name.String()
	initial, err := d.policy.EvaluateDNS(host, nil, d.now().UTC())
	if initial.Host != "" {
		event.Domain = initial.Host
	}
	event.RuleID = initial.RuleID
	event.Reason = initial.Reason
	if err != nil || !initial.Allowed {
		event.Outcome = "policy_denied"
		return buildDNSResponse(header, &question, dnsmessage.RCodeNameError, nil, d.answerTTL)
	}
	if question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA {
		event.Outcome = "unsupported_query_type"
		return buildDNSResponse(header, &question, dnsmessage.RCodeNotImplemented, nil, d.answerTTL)
	}

	lookupCtx, cancel := context.WithTimeout(ctx, d.lookupTimeout)
	defer cancel()
	resolved, err := d.lookupNetIP(lookupCtx, "ip", initial.Host)
	if err != nil {
		event.Decision = ActivityDecisionAllowed
		event.Outcome = "lookup_failed"
		return buildDNSResponse(header, &question, dnsmessage.RCodeServerFailure, nil, d.answerTTL)
	}
	addresses, err := canonicalDNSAddresses(resolved)
	if err != nil {
		event.Decision = ActivityDecisionAllowed
		event.Outcome = "invalid_answer"
		return buildDNSResponse(header, &question, dnsmessage.RCodeServerFailure, nil, d.answerTTL)
	}
	event.ResolvedIPs = activityIPStrings(addresses)
	final, err := d.policy.EvaluateDNS(initial.Host, addresses, d.now().UTC())
	event.RuleID = final.RuleID
	event.Reason = final.Reason
	if err != nil || !final.Allowed || final.RuleID != initial.RuleID || final.Effect != initial.Effect {
		event.Outcome = "policy_denied_after_resolution"
		return buildDNSResponse(header, &question, dnsmessage.RCodeNameError, nil, d.answerTTL)
	}
	event.Decision = ActivityDecisionAllowed
	event.Outcome = "resolved"
	return buildDNSResponse(header, &question, dnsmessage.RCodeSuccess, addresses, d.answerTTL)
}

func canonicalDNSAddresses(resolved []netip.Addr) ([]netip.Addr, error) {
	if len(resolved) == 0 || len(resolved) > maxDNSAddresses {
		return nil, errors.New("upstream DNS returned an invalid address count")
	}
	addresses := make([]netip.Addr, 0, len(resolved))
	seen := make(map[netip.Addr]struct{}, len(resolved))
	for _, address := range resolved {
		address = address.Unmap()
		if !address.IsValid() || address.Zone() != "" {
			return nil, errors.New("upstream DNS returned an invalid address")
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	if len(addresses) == 0 {
		return nil, errors.New("upstream DNS returned no unique addresses")
	}
	return addresses, nil
}

func buildDNSResponse(header dnsmessage.Header, question *dnsmessage.Question, rcode dnsmessage.RCode, addresses []netip.Addr, ttl uint32) ([]byte, error) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: header.ID, Response: true, OpCode: header.OpCode,
		RecursionDesired: header.RecursionDesired, RecursionAvailable: true, RCode: rcode,
	})
	builder.EnableCompression()
	if question != nil {
		if err := builder.StartQuestions(); err != nil {
			return nil, err
		}
		if err := builder.Question(*question); err != nil {
			return nil, err
		}
	}
	if rcode == dnsmessage.RCodeSuccess && question != nil {
		if err := builder.StartAnswers(); err != nil {
			return nil, err
		}
		resourceHeader := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: ttl}
		for _, address := range addresses {
			switch {
			case question.Type == dnsmessage.TypeA && address.Is4():
				if err := builder.AResource(resourceHeader, dnsmessage.AResource{A: address.As4()}); err != nil {
					return nil, err
				}
			case question.Type == dnsmessage.TypeAAAA && address.Is6():
				if err := builder.AAAAResource(resourceHeader, dnsmessage.AAAAResource{AAAA: address.As16()}); err != nil {
					return nil, err
				}
			}
		}
	}
	return builder.Finish()
}

func listenPolicyDNS(address string) (net.PacketConn, net.Listener, error) {
	packet, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("listen for policy DNS UDP: %w", err)
	}
	tcpAddress := address
	_, rawPort, splitErr := net.SplitHostPort(address)
	if splitErr == nil && rawPort == "0" {
		host, _, _ := net.SplitHostPort(address)
		udpAddress, ok := packet.LocalAddr().(*net.UDPAddr)
		if !ok {
			_ = packet.Close()
			return nil, nil, errors.New("policy DNS UDP listener returned an unexpected address")
		}
		tcpAddress = net.JoinHostPort(host, strconv.Itoa(udpAddress.Port))
	}
	listener, err := net.Listen("tcp", tcpAddress)
	if err != nil {
		_ = packet.Close()
		return nil, nil, fmt.Errorf("listen for policy DNS TCP: %w", err)
	}
	return packet, listener, nil
}

func servePolicyDNSUDP(ctx context.Context, packet net.PacketConn, handler *PolicyDNS) error {
	var workers sync.WaitGroup
	defer workers.Wait()
	semaphore := make(chan struct{}, maxConcurrentDNSQueries)
	buffer := make([]byte, 64<<10)
	for {
		count, peer, err := packet.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read policy DNS UDP query: %w", err)
		}
		query := append([]byte(nil), buffer[:count]...)
		select {
		case semaphore <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-semaphore }()
				response, handleErr := handler.HandleQuery(ctx, query)
				if handleErr == nil && len(response) != 0 {
					_, _ = packet.WriteTo(response, peer)
				}
			}()
		default:
			// Dropping overload is fail-closed and avoids an unbounded goroutine
			// or resolver queue controlled by an Agent.
		}
	}
}

func servePolicyDNSTCP(ctx context.Context, listener net.Listener, handler *PolicyDNS) error {
	semaphore := make(chan struct{}, maxConcurrentDNSQueries)
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept policy DNS TCP connection: %w", err)
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				defer connection.Close()
				servePolicyDNSTCPConnection(ctx, connection, handler)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func servePolicyDNSTCPConnection(ctx context.Context, connection net.Conn, handler *PolicyDNS) {
	var length [2]byte
	for queryIndex := 0; queryIndex < maxTCPDNSQueries; queryIndex++ {
		_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(length[:]))
		if size < 12 {
			return
		}
		query := make([]byte, size)
		if _, err := io.ReadFull(connection, query); err != nil {
			return
		}
		response, err := handler.HandleQuery(ctx, query)
		if err != nil || len(response) == 0 || len(response) > int(^uint16(0)) {
			return
		}
		binary.BigEndian.PutUint16(length[:], uint16(len(response)))
		if err := writeAll(connection, append(length[:], response...)); err != nil {
			return
		}
	}
}

func closeGatewayListeners(proxy net.Listener, dnsPacket net.PacketConn, dnsTCP net.Listener) {
	if proxy != nil {
		_ = proxy.Close()
	}
	if dnsPacket != nil {
		_ = dnsPacket.Close()
	}
	if dnsTCP != nil {
		_ = dnsTCP.Close()
	}
}

func normalizedDNSListenAddress(raw string) string {
	if value := strings.TrimSpace(raw); value != "" {
		return value
	}
	return DefaultDNSListenAddress
}
