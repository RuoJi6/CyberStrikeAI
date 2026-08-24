package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
	"golang.org/x/net/dns/dnsmessage"
)

func TestPolicyDNSReturnsOnlyAuthorizedValidatedAddresses(t *testing.T) {
	policy := testDNSPolicy(t,
		boundary.Rule{ID: "visit", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example", Schemes: []string{"http"}}},
		boundary.Rule{ID: "blocked", Effect: boundary.EffectBlocked, Target: boundary.RuleTarget{Host: "blocked.example"}},
	)
	var lookups atomic.Int32
	handler, err := NewPolicyDNS(policy, DNSOptions{
		Now: func() time.Time { return time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC) },
		LookupNetIP: func(_ context.Context, network, host string) ([]netip.Addr, error) {
			lookups.Add(1)
			if network != "ip" || host != "allowed.example" {
				t.Fatalf("lookup = %q %q", network, host)
			}
			return []netip.Addr{
				netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("2001:4860:4860::8888"),
				netip.MustParseAddr("93.184.216.34"),
			}, nil
		},
		AnswerTTL: 17,
	})
	if err != nil {
		t.Fatal(err)
	}

	response, err := handler.HandleQuery(context.Background(), dnsQuery(t, 7, "ALLOWED.EXAMPLE.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	header, answers := parseDNSResponse(t, response)
	if header.ID != 7 || header.RCode != dnsmessage.RCodeSuccess || !header.Response || !header.RecursionAvailable || len(answers) != 1 || answers[0].Header.TTL != 17 {
		t.Fatalf("A response = %#v / %#v", header, answers)
	}
	a, ok := answers[0].Body.(*dnsmessage.AResource)
	if !ok || netip.AddrFrom4(a.A).String() != "93.184.216.34" {
		t.Fatalf("A answer = %#v", answers[0].Body)
	}

	response, err = handler.HandleQuery(context.Background(), dnsQuery(t, 8, "allowed.example.", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	header, answers = parseDNSResponse(t, response)
	if header.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 {
		t.Fatalf("AAAA response = %#v / %#v", header, answers)
	}
	aaaa, ok := answers[0].Body.(*dnsmessage.AAAAResource)
	if !ok || netip.AddrFrom16(aaaa.AAAA).String() != "2001:4860:4860::8888" || lookups.Load() != 2 {
		t.Fatalf("AAAA answer = %#v, lookups=%d", answers[0].Body, lookups.Load())
	}
}

func TestPolicyDNSReturnsNXDOMAINWithoutLookupForDeniedNames(t *testing.T) {
	policy := testDNSPolicy(t,
		boundary.Rule{ID: "visit", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example"}},
		boundary.Rule{ID: "blocked", Effect: boundary.EffectBlocked, Target: boundary.RuleTarget{Host: "blocked.example"}},
	)
	var lookups atomic.Int32
	handler, err := NewPolicyDNS(policy, DNSOptions{LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"unknown.example.", "blocked.example.", "metadata.google.internal."} {
		response, queryErr := handler.HandleQuery(context.Background(), dnsQuery(t, 9, host, dnsmessage.TypeA))
		if queryErr != nil {
			t.Fatal(queryErr)
		}
		header, answers := parseDNSResponse(t, response)
		if header.RCode != dnsmessage.RCodeNameError || len(answers) != 0 {
			t.Fatalf("%s response = %#v / %#v", host, header, answers)
		}
	}
	if lookups.Load() != 0 {
		t.Fatalf("denied names triggered %d upstream lookups", lookups.Load())
	}
}

func TestPolicyDNSFailsClosedForRebindingAndResolverFailure(t *testing.T) {
	policy := testDNSPolicy(t, boundary.Rule{ID: "visit", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example"}})
	tests := []struct {
		name      string
		resolved  []netip.Addr
		lookupErr error
		want      dnsmessage.RCode
	}{
		{name: "private", resolved: []netip.Addr{netip.MustParseAddr("192.168.1.10")}, want: dnsmessage.RCodeNameError},
		{name: "mixed", resolved: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, want: dnsmessage.RCodeNameError},
		{name: "empty", want: dnsmessage.RCodeServerFailure},
		{name: "resolver failure", lookupErr: errors.New("resolver unavailable"), want: dnsmessage.RCodeServerFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewPolicyDNS(policy, DNSOptions{LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
				return test.resolved, test.lookupErr
			}})
			if err != nil {
				t.Fatal(err)
			}
			response, err := handler.HandleQuery(context.Background(), dnsQuery(t, 10, "allowed.example.", dnsmessage.TypeA))
			if err != nil {
				t.Fatal(err)
			}
			header, answers := parseDNSResponse(t, response)
			if header.RCode != test.want || len(answers) != 0 {
				t.Fatalf("response = %#v / %#v", header, answers)
			}
		})
	}
}

func TestPolicyDNSForwardsFullRecordTypesAndAuditsAnswers(t *testing.T) {
	now := time.Date(2026, 8, 24, 14, 30, 0, 0, time.UTC)
	policy := testDNSPolicy(t, boundary.Rule{ID: "visit", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example"}})
	tests := []struct {
		name       string
		queryType  dnsmessage.Type
		wantRecord string
		answer     func(*dnsmessage.Builder, dnsmessage.ResourceHeader) error
	}{
		{name: "A", queryType: dnsmessage.TypeA, wantRecord: "allowed.example A 93.184.216.34", answer: func(builder *dnsmessage.Builder, header dnsmessage.ResourceHeader) error {
			return builder.AResource(header, dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}})
		}},
		{name: "AAAA", queryType: dnsmessage.TypeAAAA, wantRecord: "allowed.example AAAA 2001:4860:4860::8888", answer: func(builder *dnsmessage.Builder, header dnsmessage.ResourceHeader) error {
			return builder.AAAAResource(header, dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:4860:4860::8888").As16()})
		}},
		{name: "CNAME", queryType: dnsmessage.TypeCNAME, wantRecord: "allowed.example CNAME alias.allowed.example", answer: func(builder *dnsmessage.Builder, header dnsmessage.ResourceHeader) error {
			return builder.CNAMEResource(header, dnsmessage.CNAMEResource{CNAME: dnsName(t, "alias.allowed.example.")})
		}},
		{name: "NS", queryType: dnsmessage.TypeNS, wantRecord: "allowed.example NS ns1.allowed.example", answer: func(builder *dnsmessage.Builder, header dnsmessage.ResourceHeader) error {
			return builder.NSResource(header, dnsmessage.NSResource{NS: dnsName(t, "ns1.allowed.example.")})
		}},
		{name: "MX", queryType: dnsmessage.TypeMX, wantRecord: "allowed.example MX 10 mail.allowed.example", answer: func(builder *dnsmessage.Builder, header dnsmessage.ResourceHeader) error {
			return builder.MXResource(header, dnsmessage.MXResource{Pref: 10, MX: dnsName(t, "mail.allowed.example.")})
		}},
		{name: "TXT", queryType: dnsmessage.TypeTXT, wantRecord: "allowed.example TXT v=spf1 -all", answer: func(builder *dnsmessage.Builder, header dnsmessage.ResourceHeader) error {
			return builder.TXTResource(header, dnsmessage.TXTResource{TXT: []string{"v=spf1", "-all"}})
		}},
		{name: "SRV", queryType: dnsmessage.TypeSRV, wantRecord: "_mysql._tcp.allowed.example SRV 10 20 3306 mysql.allowed.example", answer: func(builder *dnsmessage.Builder, header dnsmessage.ResourceHeader) error {
			return builder.SRVResource(header, dnsmessage.SRVResource{Priority: 10, Weight: 20, Port: 3306, Target: dnsName(t, "mysql.allowed.example.")})
		}},
		{name: "PTR", queryType: dnsmessage.TypePTR, wantRecord: "allowed.example PTR ptr.allowed.example", answer: func(builder *dnsmessage.Builder, header dnsmessage.ResourceHeader) error {
			return builder.PTRResource(header, dnsmessage.PTRResource{PTR: dnsName(t, "ptr.allowed.example.")})
		}},
		{name: "CAA", queryType: dnsTypeCAA, wantRecord: "allowed.example CAA 0 issue letsencrypt.org", answer: func(builder *dnsmessage.Builder, header dnsmessage.ResourceHeader) error {
			return builder.UnknownResource(header, dnsmessage.UnknownResource{Type: dnsTypeCAA, Data: append([]byte{0, 5}, []byte("issueletsencrypt.org")...)})
		}},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var captured ActivityEvent
			handler, err := NewPolicyDNS(policy, DNSOptions{
				Now: func() time.Time { return now },
				Exchange: func(_ context.Context, query []byte) ([]byte, error) {
					return dnsAnswerResponse(t, query, test.answer)
				},
				ActivitySink: func(event ActivityEvent) { captured = event },
			})
			if err != nil {
				t.Fatal(err)
			}
			queryName := "allowed.example."
			if test.queryType == dnsmessage.TypeSRV {
				queryName = "_mysql._tcp.allowed.example."
			}
			query := dnsQuery(t, uint16(100+index), queryName, test.queryType)
			response, err := handler.HandleQuery(context.Background(), query)
			if err != nil {
				t.Fatal(err)
			}
			header, answers := parseDNSResponse(t, response)
			if header.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 {
				t.Fatalf("response = %#v / %#v", header, answers)
			}
			if captured.Event != ActivityEventName || captured.Decision != ActivityDecisionAllowed || captured.DNSQueryType != strings.ToLower(test.name) ||
				len(captured.DNSAnswers) != 1 || captured.DNSAnswers[0] != test.wantRecord {
				t.Fatalf("activity = %#v", captured)
			}
		})
	}
}

func TestPolicyDNSMatchesSRVBoundaryAgainstBaseDomainAndPreservesOwnerName(t *testing.T) {
	now := time.Date(2026, 8, 24, 14, 45, 0, 0, time.UTC)
	policy := testDNSPolicy(t, boundary.Rule{ID: "mysql", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example"}})
	var captured ActivityEvent
	exchanged := false
	handler, err := NewPolicyDNS(policy, DNSOptions{
		Now: func() time.Time { return now },
		Exchange: func(_ context.Context, query []byte) ([]byte, error) {
			exchanged = true
			return dnsAnswerResponse(t, query, func(builder *dnsmessage.Builder, header dnsmessage.ResourceHeader) error {
				return builder.SRVResource(header, dnsmessage.SRVResource{
					Priority: 10, Weight: 20, Port: 3306, Target: dnsName(t, "mysql.allowed.example."),
				})
			})
		},
		ActivitySink: func(event ActivityEvent) { captured = event },
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := handler.HandleQuery(context.Background(), dnsQuery(t, 150, "_mysql._tcp.allowed.example.", dnsmessage.TypeSRV))
	if err != nil {
		t.Fatal(err)
	}
	header, answers := parseDNSResponse(t, response)
	if !exchanged || header.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 {
		t.Fatalf("SRV response = exchanged %v / %#v / %#v", exchanged, header, answers)
	}
	if captured.Domain != "_mysql._tcp.allowed.example" || captured.DNSQueryType != "srv" || captured.RuleID != "mysql" || captured.Decision != ActivityDecisionAllowed {
		t.Fatalf("SRV activity = %#v", captured)
	}
}

func TestPolicyDNSPreservesCNAMEChainAndCreatesTTLBoundAddressLease(t *testing.T) {
	now := time.Date(2026, 8, 24, 15, 0, 0, 0, time.UTC)
	policy := testDNSPolicy(t, boundary.Rule{ID: "visit", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example"}})
	leases := NewDNSLeaseStore()
	var captured ActivityEvent
	handler, err := NewPolicyDNS(policy, DNSOptions{
		Now:       func() time.Time { return now },
		DNSLeases: leases,
		Exchange: func(_ context.Context, query []byte) ([]byte, error) {
			return dnsCNAMEChainResponse(t, query)
		},
		ActivitySink: func(event ActivityEvent) { captured = event },
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := handler.HandleQuery(context.Background(), dnsQuery(t, 200, "allowed.example.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	header, answers := parseDNSResponse(t, response)
	if header.RCode != dnsmessage.RCodeSuccess || len(answers) != 2 || len(captured.DNSAnswers) != 2 {
		t.Fatalf("CNAME response = %#v / %#v / %#v", header, answers, captured)
	}
	address := netip.MustParseAddr("93.184.216.34")
	if domains := leases.Domains(address, now.Add(16*time.Second)); len(domains) != 1 || domains[0] != "allowed.example" {
		t.Fatalf("active DNS lease = %#v", domains)
	}
	if domains := leases.Domains(address, now.Add(18*time.Second)); len(domains) != 0 {
		t.Fatalf("expired DNS lease = %#v", domains)
	}
}

func TestPolicyDNSServesUDPAndTCPOnTheSamePort(t *testing.T) {
	policy := testDNSPolicy(t, boundary.Rule{ID: "visit", Effect: boundary.EffectAllowVisit, Target: boundary.RuleTarget{Host: "allowed.example"}})
	handler, err := NewPolicyDNS(policy, DNSOptions{LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	packet, listener, err := listenPolicyDNS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpPort := packet.LocalAddr().(*net.UDPAddr).Port
	tcpPort := listener.Addr().(*net.TCPAddr).Port
	if udpPort != tcpPort {
		t.Fatalf("DNS listener ports differ: UDP %d TCP %d", udpPort, tcpPort)
	}
	ctx, cancel := context.WithCancel(context.Background())
	udpDone := make(chan error, 1)
	tcpDone := make(chan error, 1)
	go func() { udpDone <- servePolicyDNSUDP(ctx, packet, handler) }()
	go func() { tcpDone <- servePolicyDNSTCP(ctx, listener, handler) }()

	query := dnsQuery(t, 11, "allowed.example.", dnsmessage.TypeA)
	udpConnection, err := net.Dial("udp", packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = udpConnection.SetDeadline(time.Now().Add(time.Second))
	if _, err := udpConnection.Write(query); err != nil {
		t.Fatal(err)
	}
	udpResponse := make([]byte, 512)
	count, err := udpConnection.Read(udpResponse)
	_ = udpConnection.Close()
	if err != nil {
		t.Fatal(err)
	}
	header, _ := parseDNSResponse(t, udpResponse[:count])
	if header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("UDP response = %#v", header)
	}

	tcpConnection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = tcpConnection.SetDeadline(time.Now().Add(time.Second))
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := tcpConnection.Write(framed); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(tcpConnection, framed[:2]); err != nil {
		t.Fatal(err)
	}
	tcpResponse := make([]byte, int(binary.BigEndian.Uint16(framed[:2])))
	if _, err := io.ReadFull(tcpConnection, tcpResponse); err != nil {
		t.Fatal(err)
	}
	_ = tcpConnection.Close()
	header, _ = parseDNSResponse(t, tcpResponse)
	if header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("TCP response = %#v", header)
	}

	cancel()
	closeGatewayListeners(nil, packet, listener)
	for name, done := range map[string]<-chan error{"UDP": udpDone, "TCP": tcpDone} {
		select {
		case serveErr := <-done:
			if serveErr != nil {
				t.Fatalf("%s server: %v", name, serveErr)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s server did not stop", name)
		}
	}
}

func testDNSPolicy(t *testing.T, rules ...boundary.Rule) *boundary.Policy {
	t.Helper()
	policy, err := boundary.NewPolicy(rules)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func dnsQuery(t *testing.T, id uint16, host string, queryType dnsmessage.Type) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(host)
	if err != nil {
		t.Fatal(err)
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: queryType, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	query, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func dnsName(t *testing.T, value string) dnsmessage.Name {
	t.Helper()
	name, err := dnsmessage.NewName(value)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func dnsAnswerResponse(t *testing.T, query []byte, answer func(*dnsmessage.Builder, dnsmessage.ResourceHeader) error) ([]byte, error) {
	t.Helper()
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 {
		return nil, errors.New("unexpected DNS test query")
	}
	question := questions[0]
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionDesired: header.RecursionDesired, RecursionAvailable: true})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	resourceHeader := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 17}
	if err := answer(&builder, resourceHeader); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func dnsCNAMEChainResponse(t *testing.T, query []byte) ([]byte, error) {
	t.Helper()
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 {
		return nil, errors.New("unexpected DNS CNAME test query")
	}
	question := questions[0]
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionDesired: true, RecursionAvailable: true})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	if err := builder.CNAMEResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.CNAMEResource{CNAME: dnsName(t, "alias.allowed.example.")}); err != nil {
		return nil, err
	}
	alias := dnsName(t, "alias.allowed.example.")
	if err := builder.AResource(dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 17}, dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func parseDNSResponse(t *testing.T, packet []byte) (dnsmessage.Header, []dnsmessage.Resource) {
	t.Helper()
	var parser dnsmessage.Parser
	header, err := parser.Start(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.AllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	return header, answers
}
