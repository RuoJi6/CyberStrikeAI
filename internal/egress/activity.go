package egress

import (
	"net/netip"
	"strings"
	"time"
)

const (
	ActivityEventName = "egress_activity"

	ActivityRequestDNS     = "dns"
	ActivityRequestHTTP    = "http"
	ActivityRequestHTTPS   = "https"
	ActivityRequestCONNECT = "connect"
	ActivityRequestHealth  = "health"

	ActivityDecisionAllowed = "allowed"
	ActivityDecisionBlocked = "blocked"
)

// ActivityEvent is the credential-free event emitted by a conversation
// gateway. It deliberately excludes headers, request/response bodies, query
// strings, userinfo and raw provider errors.
type ActivityEvent struct {
	Event           string    `json:"event"`
	Timestamp       time.Time `json:"timestamp"`
	RequestType     string    `json:"requestType"`
	Domain          string    `json:"domain"`
	ResolvedIPs     []string  `json:"resolvedIps,omitempty"`
	ConnectedIP     string    `json:"connectedIp,omitempty"`
	Port            int       `json:"port,omitempty"`
	Decision        string    `json:"decision"`
	RuleID          string    `json:"ruleId,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	UpstreamRouteID string    `json:"upstreamRouteId,omitempty"`
	Method          string    `json:"method,omitempty"`
	Path            string    `json:"path,omitempty"`
	HTTPStatus      int       `json:"httpStatus,omitempty"`
	Outcome         string    `json:"outcome"`
	LatencyMS       int64     `json:"latencyMs"`
	BytesUp         int64     `json:"bytesUp,omitempty"`
	BytesDown       int64     `json:"bytesDown,omitempty"`
	RetryAfterMS    int64     `json:"retryAfterMs,omitempty"`
	SnapshotID      string    `json:"snapshotId"`
	SnapshotSHA256  string    `json:"snapshotSha256"`
}

// ActivitySink is best-effort observability. Enforcement must never depend on
// a consumer being present or successfully accepting an event.
type ActivitySink func(ActivityEvent)

func emitActivity(sink ActivitySink, event ActivityEvent) {
	if sink == nil {
		return
	}
	defer func() { _ = recover() }()
	event.Event = ActivityEventName
	event.Timestamp = event.Timestamp.UTC()
	if event.LatencyMS < 0 {
		event.LatencyMS = 0
	}
	sink(event)
}

func activityLatencyMS(start, end time.Time) int64 {
	duration := end.Sub(start)
	if duration < 0 {
		return 0
	}
	return duration.Milliseconds()
}

func activityIPStrings(addresses []netip.Addr) []string {
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if address.IsValid() && address.Zone() == "" {
			result = append(result, address.String())
		}
	}
	return result
}

func activityHTTPPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	const maxPathBytes = 1024
	if len(path) > maxPathBytes {
		path = path[:maxPathBytes]
	}
	return path
}
