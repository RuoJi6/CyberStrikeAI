package egress

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
)

func TestSOCKS5ConnectCarriesAuthorizedRawTCPAndAuditsIt(t *testing.T) {
	events := make(chan ActivityEvent, 1)
	proxy, err := NewProxy(testProxyPolicy(t, boundary.Rule{
		ID: "ssh", Effect: boundary.EffectAllowAttack,
		Target: boundary.RuleTarget{Host: "ssh.example", Schemes: []string{"tcp"}, Ports: []int{22}},
	}), ProxyOptions{
		LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "93.184.216.34:22" {
				t.Fatalf("dial = %s %s", network, address)
			}
			gateway, target := net.Pipe()
			go func() {
				defer target.Close()
				payload := make([]byte, 4)
				_, _ = io.ReadFull(target, payload)
				_, _ = target.Write(append([]byte("SSH:"), payload...))
			}()
			return gateway, nil
		},
		ActivitySink: func(event ActivityEvent) { events <- event },
	})
	if err != nil {
		t.Fatal(err)
	}
	socks, err := NewSOCKS5Proxy(proxy, false)
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer client.Close()
	go socks.handle(context.Background(), server)
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil || method[0] != 5 || method[1] != 0 {
		t.Fatalf("method reply = %v, err=%v", method, err)
	}
	host := []byte("ssh.example")
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	request = binary.BigEndian.AppendUint16(request, 22)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 0 {
		t.Fatalf("CONNECT reply = %v, err=%v", reply, err)
	}
	if _, err := client.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("SSH:PING"))
	if _, err := io.ReadFull(client, response); err != nil || string(response) != "SSH:PING" {
		t.Fatalf("tunnel response = %q, err=%v", response, err)
	}
	_ = client.Close()
	select {
	case event := <-events:
		if event.RequestType != ActivityRequestTCP || event.Decision != ActivityDecisionAllowed || event.RuleID != "ssh" || event.Outcome != "completed" || event.BytesUp != 4 || event.BytesDown != 8 {
			t.Fatalf("TCP activity = %#v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TCP activity was not emitted")
	}
}

func TestSOCKS5ResolverFailureIsAConnectionResultNotABoundaryBlock(t *testing.T) {
	events := make(chan ActivityEvent, 1)
	proxy, err := NewProxy(testProxyPolicy(t, boundary.Rule{
		ID: "tcp", Effect: boundary.EffectAllowAttack,
		Target: boundary.RuleTarget{Host: "unresolved.example", Schemes: []string{"tcp"}, Ports: []int{22}},
	}), ProxyOptions{
		LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("resolver unavailable")
		},
		ActivitySink: func(event ActivityEvent) { events <- event },
	})
	if err != nil {
		t.Fatal(err)
	}
	socks, err := NewSOCKS5Proxy(proxy, false)
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		socks.handleConnect(context.Background(), server, bufio.NewReader(server), "unresolved.example", 22)
		_ = server.Close()
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 2 {
		t.Fatalf("SOCKS failure reply = %v, %v", reply, err)
	}
	_ = client.Close()
	<-done
	select {
	case event := <-events:
		if event.Decision != ActivityDecisionAllowed || event.Outcome != "dns_failed" || event.Reason != "" || event.RuleID != "" || event.BlockMatch != nil {
			t.Fatalf("resolver activity = %#v", event)
		}
	default:
		t.Fatal("resolver failure activity was not emitted")
	}
}

func TestSOCKS5UDPDatagramCarriesAuthorizedPayloadAndAuditsIt(t *testing.T) {
	events := make(chan ActivityEvent, 1)
	proxy, err := NewProxy(testProxyPolicy(t, boundary.Rule{
		ID: "udp-test", Effect: boundary.EffectAllowAttack,
		Target: boundary.RuleTarget{Host: "udp.example", Schemes: []string{"udp"}, Ports: []int{123}},
	}), ProxyOptions{
		LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
		ActivitySink: func(event ActivityEvent) { events <- event },
	})
	if err != nil {
		t.Fatal(err)
	}
	socks, err := NewSOCKS5Proxy(proxy, false)
	if err != nil {
		t.Fatal(err)
	}
	socks.dialUDP = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "93.184.216.34:123" {
			t.Fatalf("UDP dial = %s %s", network, address)
		}
		gateway, target := net.Pipe()
		go func() {
			defer target.Close()
			payload := make([]byte, 4)
			_, _ = io.ReadFull(target, payload)
			_, _ = target.Write(append([]byte("NTP:"), payload...))
		}()
		return gateway, nil
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	packet := encodeSOCKS5UDPDatagram("udp.example", 123, []byte("PING"))
	socks.forwardUDP(context.Background(), relay, client.LocalAddr().(*net.UDPAddr), packet)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	response := make([]byte, 128)
	count, _, err := client.ReadFromUDP(response)
	if err != nil {
		t.Fatal(err)
	}
	host, port, payload, err := parseSOCKS5UDPDatagram(response[:count])
	if err != nil || host != "93.184.216.34" || port != 123 || string(payload) != "NTP:PING" {
		t.Fatalf("UDP response = host=%q port=%d payload=%q err=%v", host, port, payload, err)
	}
	select {
	case event := <-events:
		if event.RequestType != ActivityRequestUDP || event.Decision != ActivityDecisionAllowed || event.RuleID != "udp-test" || event.Outcome != "completed" || event.BytesUp != 4 || event.BytesDown != 8 {
			t.Fatalf("UDP activity = %#v", event)
		}
	default:
		t.Fatal("UDP activity was not emitted")
	}
}

func TestSOCKS5UDPResolverFailureIsNotABoundaryBlock(t *testing.T) {
	events := make(chan ActivityEvent, 1)
	proxy, err := NewProxy(testProxyPolicy(t, boundary.Rule{
		ID: "udp", Effect: boundary.EffectAllowAttack,
		Target: boundary.RuleTarget{Host: "unresolved.example", Schemes: []string{"udp"}, Ports: []int{53}},
	}), ProxyOptions{
		LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("resolver unavailable")
		},
		ActivitySink: func(event ActivityEvent) { events <- event },
	})
	if err != nil {
		t.Fatal(err)
	}
	socks, err := NewSOCKS5Proxy(proxy, false)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	socks.forwardUDP(context.Background(), relay, client.LocalAddr().(*net.UDPAddr), encodeSOCKS5UDPDatagram("unresolved.example", 53, []byte("query")))
	select {
	case event := <-events:
		if event.Decision != ActivityDecisionAllowed || event.Outcome != "dns_failed" || event.Reason != "" || event.BlockMatch != nil {
			t.Fatalf("UDP resolver activity = %#v", event)
		}
	default:
		t.Fatal("UDP resolver failure activity was not emitted")
	}
}

func TestSOCKS5UDPAssociateAcceptsTheStandardZeroPortRequest(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			(&SOCKS5Proxy{}).handle(ctx, connection)
		}
	}()

	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil || method[0] != 5 || method[1] != 0 {
		t.Fatalf("method reply = %v, err=%v", method, err)
	}
	if _, err := client.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil || reply[0] != 5 || reply[1] != 0 || reply[3] != 1 || binary.BigEndian.Uint16(reply[8:]) == 0 {
		t.Fatalf("UDP ASSOCIATE reply = %v, err=%v", reply, err)
	}
	_ = client.Close()
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("UDP association did not close with its control connection")
	}
}

func TestSOCKS5RejectsFragmentedAndMalformedUDPDatagrams(t *testing.T) {
	for _, packet := range [][]byte{
		{0, 0, 1, 1, 1, 2, 3, 4, 0, 53},
		{0, 0, 0, 3, 0, 0, 53},
		{0, 0, 0, 9, 0, 53},
	} {
		if _, _, _, err := parseSOCKS5UDPDatagram(packet); err == nil {
			t.Fatalf("malformed packet accepted: %v", packet)
		}
	}
}
