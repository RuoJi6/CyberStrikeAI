package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
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
	maxDNSRecords           = 128
	maxDNSRecordTextBytes   = 1024
)

const dnsTypeCAA dnsmessage.Type = 257

type DNSExchangeFunc func(context.Context, []byte) ([]byte, error)

type DNSOptions struct {
	LookupNetIP   LookupNetIPFunc
	Now           func() time.Time
	AnswerTTL     uint32
	LookupTimeout time.Duration
	ActivitySink  ActivitySink
	DNSLeases     *DNSLeaseStore
	Exchange      DNSExchangeFunc
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
	dnsLeases     *DNSLeaseStore
	exchange      DNSExchangeFunc
	legacyLookup  bool
}

func NewPolicyDNS(policy *boundary.Policy, options DNSOptions) (*PolicyDNS, error) {
	if policy == nil {
		return nil, errors.New("egress DNS policy is required")
	}
	if options.LookupTimeout < 0 {
		return nil, errors.New("egress DNS lookup timeout must not be negative")
	}
	lookup := options.LookupNetIP
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
	exchange := options.Exchange
	legacyLookup := exchange == nil && lookup != nil
	if exchange == nil && !legacyLookup {
		var err error
		exchange, err = systemDNSExchange()
		if err != nil {
			return nil, err
		}
	}
	return &PolicyDNS{
		policy: policy, lookupNetIP: lookup, now: now, answerTTL: ttl, lookupTimeout: timeout,
		activitySink: options.ActivitySink, dnsLeases: options.DNSLeases, exchange: exchange, legacyLookup: legacyLookup,
	}, nil
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
	event := ActivityEvent{
		Timestamp: startedAt, RequestType: ActivityRequestDNS, Domain: strings.TrimSuffix(question.Name.String(), "."),
		DNSQueryType: strings.ToLower(dnsQueryTypeName(question.Type)), Decision: ActivityDecisionBlocked, Outcome: "rejected",
	}
	defer func() {
		event.LatencyMS = activityLatencyMS(startedAt, d.now().UTC())
		emitActivity(d.activitySink, event)
	}()
	if header.OpCode != 0 {
		event.Outcome = "unsupported_opcode"
		setDNSSystemBlock(&event, event.Outcome, fmt.Sprintf("opcode-%d", header.OpCode))
		return buildDNSResponse(header, &question, dnsmessage.RCodeNotImplemented, nil, d.answerTTL)
	}
	if question.Class != dnsmessage.ClassINET {
		event.Outcome = "unsupported_class"
		setDNSSystemBlock(&event, event.Outcome, fmt.Sprintf("class-%d", question.Class))
		return buildDNSResponse(header, &question, dnsmessage.RCodeRefused, nil, d.answerTTL)
	}
	if !supportedDNSQueryType(question.Type) {
		event.Outcome = "unsupported_query_type"
		setDNSSystemBlock(&event, event.Outcome, strings.ToLower(dnsQueryTypeName(question.Type)))
		return buildDNSResponse(header, &question, dnsmessage.RCodeNotImplemented, nil, d.answerTTL)
	}
	policyHost, err := dnsPolicyHost(question)
	if err != nil {
		event.Outcome = "invalid_query_name"
		setDNSSystemBlock(&event, event.Outcome, "invalid-query-name")
		return buildDNSResponse(header, &question, dnsmessage.RCodeRefused, nil, d.answerTTL)
	}
	initial, err := d.policy.EvaluateDNS(policyHost, nil, d.now().UTC())
	if initial.Host != "" && question.Type != dnsmessage.TypeSRV {
		event.Domain = initial.Host
	}
	event.RuleID = initial.RuleID
	event.Reason = initial.Reason
	event.BlockMatch = initial.BlockMatch
	if err != nil || !initial.Allowed {
		event.Outcome = "policy_denied"
		return buildDNSResponse(header, &question, dnsmessage.RCodeNameError, nil, d.answerTTL)
	}
	if d.legacyLookup {
		return d.handleLegacyAddressQuery(ctx, header, question, initial, &event)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, d.lookupTimeout)
	defer cancel()
	response, err := d.exchange(lookupCtx, packet)
	if err != nil {
		event.Decision = ActivityDecisionAllowed
		event.Outcome = "lookup_failed"
		return buildDNSResponse(header, &question, dnsmessage.RCodeServerFailure, nil, d.answerTTL)
	}
	metadata, err := inspectDNSResponse(response, header.ID, question)
	if err != nil {
		event.Decision = ActivityDecisionAllowed
		event.Outcome = "invalid_answer"
		return buildDNSResponse(header, &question, dnsmessage.RCodeServerFailure, nil, d.answerTTL)
	}
	event.DNSAnswers = metadata.records
	addresses := metadata.addresses
	event.ResolvedIPs = activityIPStrings(addresses)
	if len(addresses) != 0 {
		final, finalErr := d.policy.EvaluateDNS(initial.Host, addresses, d.now().UTC())
		event.RuleID = final.RuleID
		event.Reason = final.Reason
		event.BlockMatch = final.BlockMatch
		if finalErr != nil || !final.Allowed || final.RuleID != initial.RuleID || final.Effect != initial.Effect {
			event.Outcome = "policy_denied_after_resolution"
			return buildDNSResponse(header, &question, dnsmessage.RCodeNameError, nil, d.answerTTL)
		}
	}
	event.Decision = ActivityDecisionAllowed
	event.Outcome = dnsResponseOutcome(metadata.rcode)
	if d.dnsLeases != nil && len(addresses) != 0 {
		d.dnsLeases.Remember(initial.Host, addresses, metadata.addressTTL, d.now().UTC())
	}
	return response, nil
}

func (d *PolicyDNS) handleLegacyAddressQuery(ctx context.Context, header dnsmessage.Header, question dnsmessage.Question, initial boundary.DNSDecision, event *ActivityEvent) ([]byte, error) {
	if question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA {
		event.Outcome = "unsupported_query_type"
		setDNSSystemBlock(event, event.Outcome, strings.ToLower(dnsQueryTypeName(question.Type)))
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
	event.RuleID, event.Reason, event.BlockMatch = final.RuleID, final.Reason, final.BlockMatch
	if err != nil || !final.Allowed || final.RuleID != initial.RuleID || final.Effect != initial.Effect {
		event.Outcome = "policy_denied_after_resolution"
		return buildDNSResponse(header, &question, dnsmessage.RCodeNameError, nil, d.answerTTL)
	}
	event.Decision, event.Outcome = ActivityDecisionAllowed, "resolved"
	if d.dnsLeases != nil {
		d.dnsLeases.Remember(initial.Host, addresses, d.answerTTL, d.now().UTC())
	}
	return buildDNSResponse(header, &question, dnsmessage.RCodeSuccess, addresses, d.answerTTL)
}

func setDNSSystemBlock(event *ActivityEvent, reason, value string) {
	if event == nil {
		return
	}
	host := strings.TrimSpace(event.Domain)
	if normalized, err := boundary.NormalizeHost(host); err == nil {
		host = normalized
	} else {
		host = "invalid-dns-name"
	}
	event.Reason = reason
	event.BlockMatch = &boundary.BlockMatch{
		Source: boundary.MatchSourceSystem, Type: boundary.MatchTypeProtocol, Value: value,
		RequestURL: "dns://" + host, DecisionPhase: boundary.DecisionPhaseRequest,
	}
}

type dnsResponseMetadata struct {
	rcode      dnsmessage.RCode
	addresses  []netip.Addr
	records    []string
	addressTTL uint32
}

func inspectDNSResponse(packet []byte, expectedID uint16, expectedQuestion dnsmessage.Question) (dnsResponseMetadata, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(packet)
	if err != nil || !header.Response || header.ID != expectedID || header.Truncated {
		return dnsResponseMetadata{}, errors.New("upstream DNS response header is invalid")
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || questions[0] != expectedQuestion {
		return dnsResponseMetadata{}, errors.New("upstream DNS response question mismatch")
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return dnsResponseMetadata{}, err
	}
	authorities, err := parser.AllAuthorities()
	if err != nil {
		return dnsResponseMetadata{}, err
	}
	additionals, err := parser.AllAdditionals()
	if err != nil {
		return dnsResponseMetadata{}, err
	}
	resources := append(append(append([]dnsmessage.Resource(nil), answers...), authorities...), additionals...)
	metadata := dnsResponseMetadata{rcode: header.RCode}
	seenAddresses := make(map[netip.Addr]struct{})
	for _, resource := range resources {
		record, addresses, ttl, ok := summarizeDNSResource(resource)
		if ok && len(metadata.records) < maxDNSRecords {
			metadata.records = append(metadata.records, record)
		}
		for _, raw := range addresses {
			address := raw.Unmap()
			if !address.IsValid() || address.Zone() != "" {
				return dnsResponseMetadata{}, errors.New("upstream DNS response contains an invalid address")
			}
			if _, duplicate := seenAddresses[address]; !duplicate {
				seenAddresses[address] = struct{}{}
				metadata.addresses = append(metadata.addresses, address)
			}
			if ttl != 0 && (metadata.addressTTL == 0 || ttl < metadata.addressTTL) {
				metadata.addressTTL = ttl
			}
		}
	}
	if len(metadata.addresses) > maxDNSAddresses {
		return dnsResponseMetadata{}, errors.New("upstream DNS response contains too many addresses")
	}
	return metadata, nil
}

func summarizeDNSResource(resource dnsmessage.Resource) (string, []netip.Addr, uint32, bool) {
	name := strings.TrimSuffix(resource.Header.Name.String(), ".")
	prefix := name + " " + dnsQueryTypeName(resource.Header.Type) + " "
	var value string
	var addresses []netip.Addr
	switch body := resource.Body.(type) {
	case *dnsmessage.AResource:
		address := netip.AddrFrom4(body.A)
		value, addresses = address.String(), []netip.Addr{address}
	case *dnsmessage.AAAAResource:
		address := netip.AddrFrom16(body.AAAA).Unmap()
		value, addresses = address.String(), []netip.Addr{address}
	case *dnsmessage.CNAMEResource:
		value = strings.TrimSuffix(body.CNAME.String(), ".")
	case *dnsmessage.NSResource:
		value = strings.TrimSuffix(body.NS.String(), ".")
	case *dnsmessage.PTRResource:
		value = strings.TrimSuffix(body.PTR.String(), ".")
	case *dnsmessage.MXResource:
		value = strconv.Itoa(int(body.Pref)) + " " + strings.TrimSuffix(body.MX.String(), ".")
	case *dnsmessage.TXTResource:
		value = strings.Join(body.TXT, " ")
	case *dnsmessage.SRVResource:
		value = fmt.Sprintf("%d %d %d %s", body.Priority, body.Weight, body.Port, strings.TrimSuffix(body.Target.String(), "."))
	case *dnsmessage.UnknownResource:
		if resource.Header.Type == dnsTypeCAA && len(body.Data) >= 2 && int(body.Data[1])+2 <= len(body.Data) {
			tagLength := int(body.Data[1])
			value = fmt.Sprintf("%d %s %s", body.Data[0], body.Data[2:2+tagLength], body.Data[2+tagLength:])
		} else {
			return "", nil, 0, false
		}
	default:
		return "", nil, 0, false
	}
	record := prefix + strings.TrimSpace(value)
	if len(record) > maxDNSRecordTextBytes {
		record = record[:maxDNSRecordTextBytes]
	}
	return record, addresses, resource.Header.TTL, true
}

func supportedDNSQueryType(recordType dnsmessage.Type) bool {
	switch recordType {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeCNAME, dnsmessage.TypeNS, dnsmessage.TypeMX,
		dnsmessage.TypeTXT, dnsmessage.TypeSRV, dnsmessage.TypePTR, dnsTypeCAA:
		return true
	default:
		return false
	}
}

// dnsPolicyHost returns the hostname that boundary rules should evaluate for a
// DNS question. SRV owner names intentionally begin with underscore labels,
// which are not hostnames and must not be passed to boundary.NormalizeHost.
// The complete owner name is still forwarded upstream and written to audit.
func dnsPolicyHost(question dnsmessage.Question) (string, error) {
	owner := strings.TrimSuffix(question.Name.String(), ".")
	if question.Type != dnsmessage.TypeSRV {
		return owner, nil
	}
	labels := strings.Split(owner, ".")
	if len(labels) < 3 || len(labels[0]) < 2 || (labels[1] != "_tcp" && labels[1] != "_udp") {
		return "", errors.New("SRV query name must be _service._tcp.example.com or _service._udp.example.com")
	}
	service := strings.TrimPrefix(labels[0], "_")
	for index, character := range service {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || (character == '-' && index > 0 && index < len(service)-1) {
			continue
		}
		return "", errors.New("SRV service label is invalid")
	}
	return strings.Join(labels[2:], "."), nil
}

func dnsQueryTypeName(recordType dnsmessage.Type) string {
	switch recordType {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsmessage.TypePTR:
		return "PTR"
	case dnsTypeCAA:
		return "CAA"
	case dnsmessage.TypeOPT:
		return "OPT"
	default:
		return "TYPE" + strconv.Itoa(int(recordType))
	}
}

func dnsResponseOutcome(rcode dnsmessage.RCode) string {
	if rcode == dnsmessage.RCodeSuccess {
		return "resolved"
	}
	return "upstream_" + strings.ToLower(rcode.String())
}

func systemDNSExchange() (DNSExchangeFunc, error) {
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read gateway resolver configuration: %w", err)
	}
	servers := make([]string, 0, 3)
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "nameserver" {
			if address, parseErr := netip.ParseAddr(fields[1]); parseErr == nil && address.IsValid() && address.Zone() == "" {
				servers = append(servers, net.JoinHostPort(address.String(), "53"))
			}
		}
	}
	if len(servers) == 0 {
		return nil, errors.New("gateway resolver configuration has no valid nameserver")
	}
	return func(ctx context.Context, query []byte) ([]byte, error) {
		var failures []error
		for _, server := range servers {
			response, exchangeErr := exchangeDNSPacket(ctx, "udp", server, query)
			if exchangeErr == nil {
				var parser dnsmessage.Parser
				header, parseErr := parser.Start(response)
				if parseErr == nil && header.Truncated {
					response, exchangeErr = exchangeDNSPacket(ctx, "tcp", server, query)
				}
			}
			if exchangeErr == nil {
				return response, nil
			}
			failures = append(failures, exchangeErr)
		}
		return nil, errors.Join(failures...)
	}, nil
}

func exchangeDNSPacket(ctx context.Context, network, address string, query []byte) ([]byte, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if network == "tcp" {
		if len(query) > int(^uint16(0)) {
			return nil, errors.New("DNS query is too large")
		}
		framed := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
		copy(framed[2:], query)
		if err := writeAll(connection, framed); err != nil {
			return nil, err
		}
		var length [2]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return nil, err
		}
		response := make([]byte, int(binary.BigEndian.Uint16(length[:])))
		if _, err := io.ReadFull(connection, response); err != nil {
			return nil, err
		}
		return response, nil
	}
	if err := writeAll(connection, query); err != nil {
		return nil, err
	}
	response := make([]byte, 64<<10)
	count, err := connection.Read(response)
	if err != nil {
		return nil, err
	}
	return response[:count], nil
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
