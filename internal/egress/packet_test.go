package egress

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
)

func TestPacketFilterUsesOnlyActivePolicyDNSLeases(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	policy, err := boundary.NewPolicy([]boundary.Rule{{
		ID: "ssh-target", Effect: boundary.EffectAllowAttack,
		Target: boundary.RuleTarget{Host: "target.example", Schemes: []string{"tcp"}, Ports: []int{22}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	leases := NewDNSLeaseStore()
	address := netip.MustParseAddr("47.116.200.74")
	leases.Remember("target.example", []netip.Addr{address}, 30, now)
	var events []ActivityEvent
	filter, err := newPacketFilter(policy, PacketOptions{Now: func() time.Time { return now }, DNSLeases: leases, ActivitySink: func(event ActivityEvent) {
		events = append(events, event)
	}})
	if err != nil {
		t.Fatal(err)
	}
	allowed, event, parsed := filter.evaluate(testIPv4Packet(6, address, 22))
	if !parsed || !allowed || event.Domain != "target.example" || event.ConnectedIP != address.String() || event.RuleID != "ssh-target" || event.Decision != ActivityDecisionAllowed {
		t.Fatalf("active lease decision = %#v, parsed=%v allowed=%v", event, parsed, allowed)
	}
	now = now.Add(31 * time.Second)
	allowed, event, parsed = filter.evaluate(testIPv4Packet(6, address, 22))
	if !parsed || allowed || event.Reason != boundary.ReasonDefaultDeny || event.Decision != ActivityDecisionBlocked {
		t.Fatalf("expired lease decision = %#v, parsed=%v allowed=%v", event, parsed, allowed)
	}
	if len(events) != 2 {
		t.Fatalf("activity events = %d", len(events))
	}
}

func TestPacketFilterDefaultAllowSupportsTCPUDPAndICMPButBlocksReservedTargets(t *testing.T) {
	policy, err := boundary.NewPolicyWithDefault(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := newPacketFilter(policy, PacketOptions{})
	if err != nil {
		t.Fatal(err)
	}
	public := netip.MustParseAddr("47.116.200.74")
	for _, packet := range [][]byte{
		testIPv4Packet(6, public, 443), testIPv4Packet(17, public, 123), testIPv4Packet(1, public, 0),
	} {
		if allowed, _, parsed := filter.evaluate(packet); !parsed || !allowed {
			t.Fatalf("public packet parsed=%v allowed=%v", parsed, allowed)
		}
	}
	if allowed, event, parsed := filter.evaluate(testIPv4Packet(6, netip.MustParseAddr("127.0.0.1"), 80)); !parsed || allowed || event.Reason != boundary.ReasonForbiddenAddress {
		t.Fatalf("reserved target decision = %#v, parsed=%v allowed=%v", event, parsed, allowed)
	}
}

func TestPacketFilterDropsMalformedAndUnsupportedPackets(t *testing.T) {
	policy, _ := boundary.NewPolicyWithDefault(nil, true)
	filter, _ := newPacketFilter(policy, PacketOptions{})
	for _, packet := range [][]byte{{}, {0x60}, testIPv4Packet(47, netip.MustParseAddr("47.116.200.74"), 0)} {
		if allowed, _, parsed := filter.evaluate(packet); parsed || allowed {
			t.Fatalf("malformed packet parsed=%v allowed=%v packet=%x", parsed, allowed, packet)
		}
	}
}

func TestPacketDispositionRejectsOnlyEvaluatedTCPAndUDPPolicyDenials(t *testing.T) {
	tests := []struct {
		name      string
		allowed   bool
		evaluated bool
		kind      string
		want      packetDisposition
	}{
		{name: "allowed TCP", allowed: true, evaluated: true, kind: ActivityRequestTCP, want: packetDispositionAccept},
		{name: "blocked TCP", evaluated: true, kind: ActivityRequestTCP, want: packetDispositionReject},
		{name: "blocked UDP", evaluated: true, kind: ActivityRequestUDP, want: packetDispositionReject},
		{name: "blocked ICMP stays silent", evaluated: true, kind: ActivityRequestICMP, want: packetDispositionDrop},
		{name: "malformed packet stays silent", kind: ActivityRequestTCP, want: packetDispositionDrop},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := dispositionForPacket(test.allowed, test.evaluated, ActivityEvent{RequestType: test.kind}); got != test.want {
				t.Fatalf("disposition = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPacketFilterAppliesPortRulesIndependentlyDuringMixedScan(t *testing.T) {
	now := time.Date(2026, 8, 25, 16, 0, 0, 0, time.UTC)
	policy, err := boundary.NewPolicy([]boundary.Rule{
		{
			ID: "block-example-81", Effect: boundary.EffectBlocked,
			Target: boundary.RuleTarget{Host: "example.com", Schemes: []string{"tcp"}, Ports: []int{81}},
		},
		{
			ID: "allow-example", Effect: boundary.EffectAllowVisit,
			Target: boundary.RuleTarget{Host: "example.com", Schemes: []string{"tcp"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr("93.184.216.34")
	leases := NewDNSLeaseStore()
	leases.Remember("example.com", []netip.Addr{address}, 60, now)
	filter, err := newPacketFilter(policy, PacketOptions{Now: func() time.Time { return now }, DNSLeases: leases})
	if err != nil {
		t.Fatal(err)
	}

	allowed, event, evaluated := filter.evaluate(testIPv4Packet(6, address, 80))
	if !evaluated || !allowed || event.RuleID != "allow-example" || dispositionForPacket(allowed, evaluated, event) != packetDispositionAccept {
		t.Fatalf("allowed port decision = %#v, evaluated=%v allowed=%v", event, evaluated, allowed)
	}
	allowed, event, evaluated = filter.evaluate(testIPv4Packet(6, address, 81))
	if !evaluated || allowed || event.RuleID != "block-example-81" || event.Reason != boundary.ReasonBlockedTarget || dispositionForPacket(allowed, evaluated, event) != packetDispositionReject {
		t.Fatalf("blocked port decision = %#v, evaluated=%v allowed=%v", event, evaluated, allowed)
	}
}

func testIPv4Packet(protocol byte, destination netip.Addr, port int) []byte {
	length := 20
	if protocol == 6 || protocol == 17 {
		length += 8
	}
	packet := make([]byte, length)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], netip.MustParseAddr("172.30.0.3").AsSlice())
	copy(packet[16:20], destination.AsSlice())
	if protocol == 6 || protocol == 17 {
		binary.BigEndian.PutUint16(packet[20:22], 40000)
		binary.BigEndian.PutUint16(packet[22:24], uint16(port))
	}
	return packet
}
