package egress

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/networkprovenance"
	"github.com/google/uuid"
)

const (
	ActivityEventName = "egress_activity"

	ActivityRequestDNS     = "dns"
	ActivityRequestHTTP    = "http"
	ActivityRequestHTTPS   = "https"
	ActivityRequestCONNECT = "connect"
	ActivityRequestTCP     = "tcp"
	ActivityRequestUDP     = "udp"
	ActivityRequestICMP    = "icmp"
	ActivityRequestHealth  = "health"

	ActivityDecisionAllowed = "allowed"
	ActivityDecisionBlocked = "blocked"
)

const MaxHTTPPacketBodyBytes = 32 << 10

// HTTPPacket is the bounded HTTP transaction captured by a conversation
// gateway. Request and response bodies are preserved up to
// MaxHTTPPacketBodyBytes per direction and carry an explicit
// encoding/truncation marker.
type HTTPPacket struct {
	RequestLine           string              `json:"requestLine"`
	RequestHeaders        map[string][]string `json:"requestHeaders"`
	RequestBody           string              `json:"requestBody,omitempty"`
	RequestBodyEncoding   string              `json:"requestBodyEncoding,omitempty"`
	RequestBodyTruncated  bool                `json:"requestBodyTruncated,omitempty"`
	ResponseLine          string              `json:"responseLine,omitempty"`
	ResponseHeaders       map[string][]string `json:"responseHeaders,omitempty"`
	ResponseBody          string              `json:"responseBody,omitempty"`
	ResponseBodyEncoding  string              `json:"responseBodyEncoding,omitempty"`
	ResponseBodyTruncated bool                `json:"responseBodyTruncated,omitempty"`
	SensitiveDataRedacted bool                `json:"sensitiveDataRedacted"`
}

func validHTTPPacketLine(value string, required bool) bool {
	if value == "" {
		return !required
	}
	if len(value) > 65536 || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validHTTPPacketHeaders(headers map[string][]string) bool {
	if len(headers) > 128 {
		return false
	}
	for name, values := range headers {
		if !validHTTPPacketHeaderName(name) || len(values) > 128 {
			return false
		}
		for _, value := range values {
			if len(value) > 65536 || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n") {
				return false
			}
		}
	}
	return true
}

// HTTP field names use the RFC token grammar. In particular, underscores and
// the other tchar punctuation are legal even though the conventional spelling
// of most fields only uses letters and hyphens. Reject separators and control
// bytes so a captured field name cannot alter the surrounding JSON or HTTP
// representation when it is later rendered.
func validHTTPPacketHeaderName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for _, character := range name {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') {
			continue
		}
		switch character {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func validHTTPPacketBody(body, encoding string) bool {
	if body == "" {
		return encoding == ""
	}
	switch encoding {
	case "utf8":
		return len(body) <= MaxHTTPPacketBodyBytes && utf8.ValidString(body)
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(body)
		return err == nil && len(decoded) <= MaxHTTPPacketBodyBytes
	default:
		return false
	}
}

func ValidateHTTPPacket(packet *HTTPPacket) error {
	if packet == nil {
		return nil
	}
	if !validHTTPPacketLine(packet.RequestLine, true) || !validHTTPPacketLine(packet.ResponseLine, false) ||
		!validHTTPPacketHeaders(packet.RequestHeaders) || !validHTTPPacketHeaders(packet.ResponseHeaders) ||
		!validHTTPPacketBody(packet.RequestBody, packet.RequestBodyEncoding) ||
		!validHTTPPacketBody(packet.ResponseBody, packet.ResponseBodyEncoding) {
		return errors.New("invalid bounded HTTP packet")
	}
	return nil
}

// ActivityEvent is the bounded event emitted by a conversation gateway.
// HTTP/HTTPS events may include a bounded packet projection for on-demand
// audit inspection. Raw provider errors and environment values remain excluded.
type ActivityEvent struct {
	EventID                   string                                `json:"eventId"`
	Event                     string                                `json:"event"`
	Timestamp                 time.Time                             `json:"timestamp"`
	RequestType               string                                `json:"requestType"`
	Domain                    string                                `json:"domain"`
	DNSQueryType              string                                `json:"dnsQueryType,omitempty"`
	DNSAnswers                []string                              `json:"dnsAnswers,omitempty"`
	ResolvedIPs               []string                              `json:"resolvedIps,omitempty"`
	ConnectedIP               string                                `json:"connectedIp,omitempty"`
	Port                      int                                   `json:"port,omitempty"`
	Decision                  string                                `json:"decision"`
	RuleID                    string                                `json:"ruleId,omitempty"`
	Reason                    string                                `json:"reason,omitempty"`
	UpstreamRouteID           string                                `json:"upstreamRouteId,omitempty"`
	Method                    string                                `json:"method,omitempty"`
	Path                      string                                `json:"path,omitempty"`
	HTTPStatus                int                                   `json:"httpStatus,omitempty"`
	Outcome                   string                                `json:"outcome"`
	LatencyMS                 int64                                 `json:"latencyMs"`
	BytesUp                   int64                                 `json:"bytesUp,omitempty"`
	BytesDown                 int64                                 `json:"bytesDown,omitempty"`
	HTTPPacket                *HTTPPacket                           `json:"httpPacket,omitempty"`
	RetryAfterMS              int64                                 `json:"retryAfterMs,omitempty"`
	SnapshotID                string                                `json:"snapshotId"`
	SnapshotSHA256            string                                `json:"snapshotSha256"`
	AggregateCount            int64                                 `json:"aggregateCount,omitempty"`
	AggregateKind             string                                `json:"aggregateKind,omitempty"`
	AggregateFirstAt          *time.Time                            `json:"aggregateFirstAt,omitempty"`
	AggregateLastAt           *time.Time                            `json:"aggregateLastAt,omitempty"`
	AggregateDistinctTargets  int                                   `json:"aggregateDistinctTargets,omitempty"`
	AggregateDistinctPorts    int                                   `json:"aggregateDistinctPorts,omitempty"`
	AggregateDistinctVariants int                                   `json:"aggregateDistinctVariants,omitempty"`
	Provenance                networkprovenance.NetworkProvenanceV1 `json:"provenance"`
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
	if event.EventID == "" {
		event.EventID = uuid.NewString()
	}
	event.Timestamp = event.Timestamp.UTC()
	event.Provenance = event.Provenance.Normalized()
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
