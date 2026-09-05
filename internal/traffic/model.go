package traffic

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/boundary"
)

const (
	RuntimeModeHost      = "host"
	RuntimeModeContainer = "container"
	RuntimeModeUnknown   = "unknown"

	CaptureCoverageEnforced   = "enforced"
	CaptureCoverageBestEffort = "best_effort"
	CaptureCoverageUnknown    = "unknown"

	StageClientRequest    = "client_request"
	StageDecodedRequest   = "decoded_request"
	StageUpstreamRequest  = "upstream_request"
	StageUpstreamResponse = "upstream_response"
	StageDecodedResponse  = "decoded_response"
	StageClientResponse   = "client_response"

	MessageKindRequest  = "request"
	MessageKindResponse = "response"

	BodyEncodingUTF8   = "utf8"
	BodyEncodingBase64 = "base64"

	EvidenceRolePrimary    = "primary"
	EvidenceRoleSupporting = "supporting"
	EvidenceRoleRetest     = "retest"

	// MaxStoredBodyBytes is a persistence safety limit, not a claim that larger
	// messages are complete. Callers must preserve BodyLength and set Complete
	// false whenever a body is truncated to this bound.
	MaxStoredBodyBytes = 10 << 20
)

var validStages = map[string]string{
	StageClientRequest:    MessageKindRequest,
	StageDecodedRequest:   MessageKindRequest,
	StageUpstreamRequest:  MessageKindRequest,
	StageUpstreamResponse: MessageKindResponse,
	StageDecodedResponse:  MessageKindResponse,
	StageClientResponse:   MessageKindResponse,
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Transaction struct {
	ID                   string               `json:"id"`
	EventID              string               `json:"event_id,omitempty"`
	ConversationID       string               `json:"conversation_id,omitempty"`
	ProjectID            string               `json:"project_id,omitempty"`
	AgentID              string               `json:"agent_id,omitempty"`
	ToolName             string               `json:"tool_name,omitempty"`
	ExecutionID          string               `json:"execution_id,omitempty"`
	ToolCallID           string               `json:"tool_call_id,omitempty"`
	ActivityScopeID      string               `json:"activity_scope_id,omitempty"`
	RuntimeGeneration    int                  `json:"runtime_generation,omitempty"`
	RuntimeInstanceID    string               `json:"runtime_instance_id,omitempty"`
	AttributionStatus    string               `json:"attribution_status,omitempty"`
	DeclaredActivityKind string               `json:"declared_activity_kind,omitempty"`
	ObservedActivityKind string               `json:"observed_activity_kind,omitempty"`
	RuntimeMode          string               `json:"runtime_mode"`
	CaptureCoverage      string               `json:"capture_coverage"`
	Scheme               string               `json:"scheme"`
	Host                 string               `json:"host"`
	Port                 int                  `json:"port"`
	Method               string               `json:"method"`
	Path                 string               `json:"path"`
	HTTPStatus           int                  `json:"http_status,omitempty"`
	Outcome              string               `json:"outcome,omitempty"`
	ErrorCode            string               `json:"error_code,omitempty"`
	ErrorSummary         string               `json:"error_summary,omitempty"`
	StartedAt            time.Time            `json:"started_at"`
	CompletedAt          *time.Time           `json:"completed_at,omitempty"`
	LatencyMS            int64                `json:"latency_ms"`
	BytesUp              int64                `json:"bytes_up"`
	BytesDown            int64                `json:"bytes_down"`
	BoundarySnapshotID   string               `json:"boundary_snapshot_id,omitempty"`
	RuleID               string               `json:"rule_id,omitempty"`
	BlockMatch           *boundary.BlockMatch `json:"block_match,omitempty"`
	UpstreamRouteID      string               `json:"upstream_route_id,omitempty"`
	TransformBindingID   string               `json:"transform_binding_id,omitempty"`
	TransformRevisionID  string               `json:"transform_revision_id,omitempty"`
	TransformResult      string               `json:"transform_result,omitempty"`
	AggregateKind        string               `json:"aggregate_kind,omitempty"`
	AggregateCount       int64                `json:"aggregate_count,omitempty"`
	AggregateFirstAt     *time.Time           `json:"aggregate_first_at,omitempty"`
	AggregateLastAt      *time.Time           `json:"aggregate_last_at,omitempty"`
	AggregateSummaryJSON string               `json:"aggregate_summary_json,omitempty"`
	CreatedAt            time.Time            `json:"created_at"`
	UpdatedAt            time.Time            `json:"updated_at"`
}

type Message struct {
	ID              string    `json:"id"`
	TransactionID   string    `json:"transaction_id"`
	Stage           string    `json:"stage"`
	Kind            string    `json:"kind"`
	Method          string    `json:"method,omitempty"`
	Path            string    `json:"path,omitempty"`
	Status          int       `json:"status,omitempty"`
	Protocol        string    `json:"protocol,omitempty"`
	Headers         []Header  `json:"headers"`
	ContentType     string    `json:"content_type,omitempty"`
	Body            string    `json:"body,omitempty"`
	BodyEncoding    string    `json:"body_encoding,omitempty"`
	BodySHA256      string    `json:"body_sha256"`
	BodyLength      int64     `json:"body_length"`
	BodyStoredBytes int64     `json:"body_stored_bytes"`
	Complete        bool      `json:"complete"`
	BodyView        *BodyView `json:"body_view,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type TransactionDetail struct {
	Transaction Transaction    `json:"transaction"`
	Messages    []Message      `json:"messages"`
	Evidence    []EvidenceLink `json:"evidence"`
}

type EvidenceLink struct {
	VulnerabilityID  string    `json:"vulnerability_id"`
	TransactionID    string    `json:"traffic_transaction_id"`
	Role             string    `json:"role"`
	Note             string    `json:"note,omitempty"`
	CreatedByAgentID string    `json:"created_by_agent_id,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

func NormalizeRuntimeMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case RuntimeModeHost:
		return RuntimeModeHost
	case RuntimeModeContainer:
		return RuntimeModeContainer
	default:
		return RuntimeModeUnknown
	}
}

func NormalizeCaptureCoverage(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case CaptureCoverageEnforced:
		return CaptureCoverageEnforced
	case CaptureCoverageBestEffort:
		return CaptureCoverageBestEffort
	default:
		return CaptureCoverageUnknown
	}
}

func NormalizeEvidenceRole(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case EvidenceRolePrimary:
		return EvidenceRolePrimary, true
	case EvidenceRoleSupporting:
		return EvidenceRoleSupporting, true
	case EvidenceRoleRetest:
		return EvidenceRoleRetest, true
	default:
		return "", false
	}
}

func HeadersFromHTTP(headers http.Header) []Header {
	result := make([]Header, 0, len(headers))
	for name, values := range headers {
		for _, value := range values {
			result = append(result, Header{Name: http.CanonicalHeaderKey(name), Value: value})
		}
	}
	return result
}

func EncodeBody(content []byte) (body, encoding, digest string) {
	sum := sha256.Sum256(content)
	digest = hex.EncodeToString(sum[:])
	if len(content) == 0 {
		return "", "", digest
	}
	if utf8.Valid(content) {
		return string(content), BodyEncodingUTF8, digest
	}
	return base64.StdEncoding.EncodeToString(content), BodyEncodingBase64, digest
}

func DecodeBody(message Message) ([]byte, error) {
	if message.Body == "" {
		if message.BodyEncoding != "" {
			return nil, errors.New("empty traffic body must not declare an encoding")
		}
		return nil, nil
	}
	switch message.BodyEncoding {
	case BodyEncodingUTF8:
		if !utf8.ValidString(message.Body) {
			return nil, errors.New("traffic body is not valid UTF-8")
		}
		return []byte(message.Body), nil
	case BodyEncodingBase64:
		content, err := base64.StdEncoding.DecodeString(message.Body)
		if err != nil {
			return nil, fmt.Errorf("decode traffic body: %w", err)
		}
		return content, nil
	default:
		return nil, errors.New("traffic body encoding must be utf8 or base64")
	}
}

func ValidateMessage(message Message) error {
	wantKind, ok := validStages[message.Stage]
	if !ok || message.Kind != wantKind {
		return errors.New("invalid traffic message stage or kind")
	}
	if len(message.Headers) > 256 {
		return errors.New("traffic message has too many headers")
	}
	headerBytes := 0
	for _, header := range message.Headers {
		name := strings.TrimSpace(header.Name)
		if name == "" || name != header.Name || len(name) > 256 || strings.ContainsAny(name, "\r\n\x00") || strings.ContainsAny(header.Value, "\r\n\x00") {
			return errors.New("traffic message contains an invalid header")
		}
		headerBytes += len(name) + len(header.Value)
	}
	if headerBytes > 256<<10 {
		return errors.New("traffic message headers are too large")
	}
	content, err := DecodeBody(message)
	if err != nil {
		return err
	}
	if len(content) > MaxStoredBodyBytes {
		return errors.New("traffic message stored body exceeds the hard limit")
	}
	if message.BodyStoredBytes == 0 && len(content) > 0 {
		message.BodyStoredBytes = int64(len(content))
	}
	if message.BodyStoredBytes != int64(len(content)) || message.BodyLength < message.BodyStoredBytes {
		return errors.New("traffic message body lengths are inconsistent")
	}
	if message.Complete && message.BodyLength != message.BodyStoredBytes {
		return errors.New("complete traffic message body length is inconsistent")
	}
	if message.BodySHA256 != "" {
		sum := sha256.Sum256(content)
		if message.BodySHA256 != hex.EncodeToString(sum[:]) {
			return errors.New("traffic message body hash does not match")
		}
	}
	if message.Kind == MessageKindRequest {
		validTarget := strings.HasPrefix(message.Path, "/")
		if strings.EqualFold(message.Method, http.MethodConnect) {
			validTarget = strings.TrimSpace(message.Path) == message.Path && message.Path != "" && !strings.ContainsAny(message.Path, " \t\r\n\x00")
		}
		if strings.TrimSpace(message.Method) == "" || !validTarget || message.Status != 0 {
			return errors.New("invalid traffic request message")
		}
	} else if message.Status < 100 || message.Status > 999 {
		return errors.New("invalid traffic response message")
	}
	return nil
}

func ValidateTransaction(transaction Transaction) error {
	if strings.TrimSpace(transaction.ConversationID) == "" {
		return errors.New("traffic transaction conversation is required")
	}
	if len(transaction.EventID) > 128 || strings.TrimSpace(transaction.EventID) != transaction.EventID || strings.ContainsAny(transaction.EventID, "\r\n\x00") {
		return errors.New("traffic transaction event id is invalid")
	}
	if transaction.Scheme != "http" && transaction.Scheme != "https" {
		return errors.New("traffic transaction scheme must be http or https")
	}
	if strings.TrimSpace(transaction.Host) == "" || transaction.Port < 1 || transaction.Port > 65535 {
		return errors.New("traffic transaction target is invalid")
	}
	if strings.TrimSpace(transaction.Method) == "" || !strings.HasPrefix(transaction.Path, "/") {
		return errors.New("traffic transaction request is invalid")
	}
	if err := boundary.ValidateBlockMatch(transaction.BlockMatch); err != nil {
		return fmt.Errorf("traffic transaction block match is invalid: %w", err)
	}
	if transaction.HTTPStatus < 0 || transaction.HTTPStatus > 999 || transaction.LatencyMS < 0 || transaction.BytesUp < 0 || transaction.BytesDown < 0 || transaction.AggregateCount < 0 {
		return errors.New("traffic transaction numeric values are invalid")
	}
	for _, value := range []struct {
		name  string
		text  string
		limit int
	}{
		{name: "outcome", text: transaction.Outcome, limit: 128},
		{name: "error code", text: transaction.ErrorCode, limit: 128},
		{name: "error summary", text: transaction.ErrorSummary, limit: 1024},
	} {
		if len(value.text) > value.limit || strings.TrimSpace(value.text) != value.text || strings.ContainsAny(value.text, "\r\n\x00") {
			return fmt.Errorf("traffic transaction %s is invalid", value.name)
		}
	}
	if transaction.StartedAt.IsZero() {
		return errors.New("traffic transaction start time is required")
	}
	if transaction.CompletedAt != nil && transaction.CompletedAt.Before(transaction.StartedAt) {
		return errors.New("traffic transaction completion precedes its start")
	}
	return nil
}
