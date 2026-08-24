package egress

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"cyberstrike-ai/internal/boundary"
)

const (
	defaultPacketQueueNumber = 100
	maxPacketCaptureBytes    = 65535
	maxPacketQueueLength     = 4096
)

type PacketOptions struct {
	QueueNumber  uint16
	Now          func() time.Time
	ActivitySink ActivitySink
	DNSLeases    *DNSLeaseStore
}

type packetFilter struct {
	policy       *boundary.Policy
	now          func() time.Time
	activitySink ActivitySink
	dnsLeases    *DNSLeaseStore
}

type packetTarget struct {
	protocol string
	address  netip.Addr
	port     int
	size     int
}

func newPacketFilter(policy *boundary.Policy, options PacketOptions) (*packetFilter, error) {
	if policy == nil {
		return nil, errors.New("egress packet policy is required")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	leases := options.DNSLeases
	if leases == nil {
		leases = NewDNSLeaseStore()
	}
	return &packetFilter{policy: policy, now: now, activitySink: options.ActivitySink, dnsLeases: leases}, nil
}

// evaluate returns true only when the complete destination is approved. The
// parser supports IPv4 TCP, UDP and ICMP, which are the protocols routed by the
// per-conversation Docker networks. Anything malformed or unsupported is
// dropped without trusting packet-controlled metadata.
func (f *packetFilter) evaluate(packet []byte) (bool, ActivityEvent, bool) {
	target, ok := parseIPv4PacketTarget(packet)
	if !ok {
		return false, ActivityEvent{}, false
	}
	now := f.now().UTC()
	event := ActivityEvent{
		Timestamp: now, RequestType: target.protocol, Domain: target.address.String(),
		ConnectedIP: target.address.String(), Port: target.port,
		Decision: ActivityDecisionBlocked, Outcome: "policy_denied", BytesUp: int64(target.size),
	}
	direct, err := f.policy.EvaluateNetwork(target.address.String(), target.port, target.protocol, []netip.Addr{target.address}, now)
	if err != nil {
		event.Reason = boundary.ReasonDefaultDeny
		emitActivity(f.activitySink, event)
		return false, event, true
	}
	event.RuleID, event.Reason = direct.RuleID, direct.Reason
	if direct.Allowed {
		event.Decision, event.Outcome = ActivityDecisionAllowed, "forwarded"
		emitActivity(f.activitySink, event)
		return true, event, true
	}
	// An explicit IP/CIDR or reserved-address denial always wins. Only a plain
	// default-deny may be satisfied by a still-valid policy DNS lease.
	if direct.Reason != boundary.ReasonDefaultDeny {
		emitActivity(f.activitySink, event)
		return false, event, true
	}
	for _, domain := range f.dnsLeases.Domains(target.address, now) {
		decision, decisionErr := f.policy.EvaluateNetwork(domain, target.port, target.protocol, []netip.Addr{target.address}, now)
		if decisionErr != nil || !decision.Allowed {
			continue
		}
		event.Domain = domain
		event.ResolvedIPs = []string{target.address.String()}
		event.RuleID, event.Reason = decision.RuleID, decision.Reason
		event.Decision, event.Outcome = ActivityDecisionAllowed, "forwarded"
		emitActivity(f.activitySink, event)
		return true, event, true
	}
	emitActivity(f.activitySink, event)
	return false, event, true
}

func parseIPv4PacketTarget(packet []byte) (packetTarget, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return packetTarget{}, false
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return packetTarget{}, false
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength < headerLength || totalLength > len(packet) {
		return packetTarget{}, false
	}
	address := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	target := packetTarget{address: address, size: totalLength}
	switch packet[9] {
	case 1:
		target.protocol = ActivityRequestICMP
	case 6:
		if totalLength < headerLength+4 {
			return packetTarget{}, false
		}
		target.protocol = ActivityRequestTCP
		target.port = int(binary.BigEndian.Uint16(packet[headerLength+2 : headerLength+4]))
	case 17:
		if totalLength < headerLength+4 {
			return packetTarget{}, false
		}
		target.protocol = ActivityRequestUDP
		target.port = int(binary.BigEndian.Uint16(packet[headerLength+2 : headerLength+4]))
	default:
		return packetTarget{}, false
	}
	return target, true
}
