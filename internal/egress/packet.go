package egress

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"

	"cyberstrike-ai/internal/boundary"
)

const (
	defaultPacketQueueNumber = 100
	maxPacketCaptureBytes    = 65535
	maxPacketQueueLength     = 4096
	// packetPolicyRejectMark is attached only to a parsed TCP/UDP packet that
	// the immutable boundary policy denied. NF_REPEAT sends the marked packet
	// back through the nftables chain, where it is rejected with an explicit
	// administrative-prohibited response instead of being silently dropped.
	packetPolicyRejectMark uint32 = 0x4353424b // "CSBK"
	tcpAttemptDedupWindow         = 10 * time.Second
	tcpAttemptRetention           = 30 * time.Second
	maxTCPAttemptEntries          = 4096
)

type packetDisposition uint8

const (
	packetDispositionDrop packetDisposition = iota
	packetDispositionAccept
	packetDispositionReject
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
	attemptMu    sync.Mutex
	tcpAttempts  map[tcpAttemptKey]time.Time
}

type packetTarget struct {
	protocol string
	address  netip.Addr
	source   int
	port     int
	size     int
	observe  bool
}

type tcpAttemptKey struct {
	address netip.Addr
	source  int
	port    int
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
	return &packetFilter{
		policy: policy, now: now, activitySink: options.ActivitySink, dnsLeases: leases,
		tcpAttempts: make(map[tcpAttemptKey]time.Time),
	}, nil
}

// dispositionForPacket keeps malformed, unsupported and ICMP packets on the
// fail-closed drop path. Only a fully parsed policy denial for TCP or UDP gets
// an active rejection. This makes a mixed port scan fail fast per blocked
// destination tuple without terminating or changing the verdict of any other
// port in the same tool process.
func dispositionForPacket(allowed, evaluated bool, event ActivityEvent) packetDisposition {
	if allowed {
		return packetDispositionAccept
	}
	if evaluated && (event.RequestType == ActivityRequestTCP || event.RequestType == ActivityRequestUDP) {
		return packetDispositionReject
	}
	return packetDispositionDrop
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
	observe := f.shouldObserve(target, now)
	event := ActivityEvent{
		Timestamp: now, RequestType: target.protocol, Domain: target.address.String(),
		ConnectedIP: target.address.String(), Port: target.port,
		Decision: ActivityDecisionBlocked, Outcome: "policy_denied", BytesUp: int64(target.size),
	}
	direct, err := f.policy.EvaluateNetwork(target.address.String(), target.port, target.protocol, []netip.Addr{target.address}, now)
	if err != nil {
		event.Reason = boundary.ReasonDefaultDeny
		if observe {
			emitActivity(f.activitySink, event)
		}
		return false, event, true
	}
	event.RuleID, event.Reason = direct.RuleID, direct.Reason
	if direct.Allowed {
		event.Decision, event.Outcome = ActivityDecisionAllowed, "forwarded"
		if observe {
			emitActivity(f.activitySink, event)
		}
		return true, event, true
	}
	// An explicit IP/CIDR or reserved-address denial always wins. Only a plain
	// default-deny may be satisfied by a still-valid policy DNS lease.
	if direct.Reason != boundary.ReasonDefaultDeny {
		if observe {
			emitActivity(f.activitySink, event)
		}
		return false, event, true
	}
	var explicitDenial *boundary.Decision
	for _, domain := range f.dnsLeases.Domains(target.address, now) {
		decision, decisionErr := f.policy.EvaluateNetwork(domain, target.port, target.protocol, []netip.Addr{target.address}, now)
		if decisionErr != nil {
			continue
		}
		if !decision.Allowed {
			if decision.RuleID != "" && explicitDenial == nil {
				copy := decision
				explicitDenial = &copy
			}
			continue
		}
		event.Domain = domain
		event.ResolvedIPs = []string{target.address.String()}
		event.RuleID, event.Reason = decision.RuleID, decision.Reason
		event.Decision, event.Outcome = ActivityDecisionAllowed, "forwarded"
		if observe {
			emitActivity(f.activitySink, event)
		}
		return true, event, true
	}
	if explicitDenial != nil {
		event.Domain = explicitDenial.Target.Host
		event.ResolvedIPs = []string{target.address.String()}
		event.RuleID, event.Reason = explicitDenial.RuleID, explicitDenial.Reason
	}
	if observe {
		emitActivity(f.activitySink, event)
	}
	return false, event, true
}

// shouldObserve suppresses retransmitted SYN packets while preserving each
// new TCP connection attempt. A retransmission retains the same source port;
// scanners, brute-force clients and database tools normally allocate a new
// ephemeral source port for every new attempt, so their true request count is
// still available to the behavioural aggregator.
func (f *packetFilter) shouldObserve(target packetTarget, now time.Time) bool {
	if !target.observe || target.protocol != ActivityRequestTCP {
		return target.observe
	}
	key := tcpAttemptKey{address: target.address, source: target.source, port: target.port}
	f.attemptMu.Lock()
	defer f.attemptMu.Unlock()
	if previous, ok := f.tcpAttempts[key]; ok && now.Sub(previous) >= 0 && now.Sub(previous) < tcpAttemptDedupWindow {
		return false
	}
	f.tcpAttempts[key] = now
	if len(f.tcpAttempts) > maxTCPAttemptEntries {
		for candidate, seenAt := range f.tcpAttempts {
			if now.Sub(seenAt) >= tcpAttemptRetention || now.Before(seenAt) {
				delete(f.tcpAttempts, candidate)
			}
		}
	}
	return true
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
		if totalLength < headerLength+1 {
			return packetTarget{}, false
		}
		target.protocol = ActivityRequestICMP
		// Only an echo request represents a new observable attempt. Replies and
		// control packets are still enforced but do not multiply audit rows.
		target.observe = packet[headerLength] == 8
	case 6:
		if totalLength < headerLength+14 {
			return packetTarget{}, false
		}
		target.protocol = ActivityRequestTCP
		target.source = int(binary.BigEndian.Uint16(packet[headerLength : headerLength+2]))
		target.port = int(binary.BigEndian.Uint16(packet[headerLength+2 : headerLength+4]))
		flags := packet[headerLength+13]
		// Audit one connection attempt, not every packet in a long-lived SSH,
		// MySQL or SMB flow. SYN retransmits remain observable attempts and are
		// compacted by the behavioural aggregator when they form a burst.
		target.observe = flags&0x02 != 0 && flags&0x10 == 0
	case 17:
		if totalLength < headerLength+4 {
			return packetTarget{}, false
		}
		target.protocol = ActivityRequestUDP
		target.port = int(binary.BigEndian.Uint16(packet[headerLength+2 : headerLength+4]))
		target.observe = true
	default:
		return packetTarget{}, false
	}
	return target, true
}
