package traffictransform

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"cyberstrike-ai/internal/traffic"
)

const (
	ProtocolVersion = "traffic-transform/v1"
	SDKVersion      = "1"
	LanguagePython3 = "python3"
	Entrypoint      = "transform.py"

	ModeObserve = "observe"
	ModeInline  = "inline"

	ActionPass    = "pass"
	ActionReplace = "replace"
	ActionBlock   = "block"
	ActionError   = "error"

	HookDecodeRequest  Hook = "decode_request"
	HookMutateRequest  Hook = "mutate_request"
	HookEncodeRequest  Hook = "encode_request"
	HookDecodeResponse Hook = "decode_response"
	HookMutateResponse Hook = "mutate_response"
	HookEncodeResponse Hook = "encode_response"

	DirectionRequest  = "request"
	DirectionResponse = "response"

	ValidationPending = "pending"
	ValidationPassed  = "passed"
	ValidationFailed  = "failed"

	BindingDraft    = "draft"
	BindingActive   = "active"
	BindingDisabled = "disabled"

	FailurePolicyContinue = "continue"
	FailurePolicyClosed   = "closed"

	MaxSourceBytes      = 256 << 10
	MaxInvocationBytes  = 16 << 20
	MaxTransformBody    = 10 << 20
	MaxStateJSONBytes   = 64 << 10
	DefaultDeadlineMS   = 250
	MaximumDeadlineMS   = 5000
	MaxAnnotations      = 32
	MaxAnnotationLength = 1024
)

var (
	hookOrder = []Hook{
		HookDecodeRequest,
		HookMutateRequest,
		HookEncodeRequest,
		HookDecodeResponse,
		HookMutateResponse,
		HookEncodeResponse,
	}
	validHook = map[Hook]bool{
		HookDecodeRequest: true, HookMutateRequest: true, HookEncodeRequest: true,
		HookDecodeResponse: true, HookMutateResponse: true, HookEncodeResponse: true,
	}
	sha256Pattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	headerNameToken = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)
)

type Hook string

type Transform struct {
	ID                string    `json:"id"`
	ConversationID    string    `json:"conversationId,omitempty"`
	ProjectID         string    `json:"projectId,omitempty"`
	CurrentRevisionID string    `json:"currentRevisionId,omitempty"`
	Name              string    `json:"name"`
	Description       string    `json:"description,omitempty"`
	Language          string    `json:"language"`
	OwnerUserID       string    `json:"ownerUserId,omitempty"`
	CreatedByAgentID  string    `json:"createdByAgentId,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type Revision struct {
	ID               string          `json:"id"`
	TransformID      string          `json:"transformId"`
	ProtocolVersion  string          `json:"protocolVersion"`
	Language         string          `json:"language"`
	Entrypoint       string          `json:"entrypoint"`
	SDKVersion       string          `json:"sdkVersion"`
	Source           string          `json:"source,omitempty"`
	SourceSHA256     string          `json:"sourceSha256"`
	Hooks            []Hook          `json:"hooks"`
	Requirements     []string        `json:"requirements"`
	ValidationStatus string          `json:"validationStatus"`
	ValidationReport json.RawMessage `json:"validationReport,omitempty"`
	CreatedByAgentID string          `json:"createdByAgentId,omitempty"`
	CreatedAt        time.Time       `json:"createdAt"`
}

type Binding struct {
	ID               string         `json:"id"`
	ConversationID   string         `json:"conversationId"`
	TransformID      string         `json:"transformId"`
	RevisionID       string         `json:"revisionId"`
	Mode             string         `json:"mode"`
	Matcher          Matcher        `json:"matcher"`
	Config           map[string]any `json:"config,omitempty"`
	Priority         int            `json:"priority"`
	FailurePolicy    string         `json:"failurePolicy"`
	Status           string         `json:"status"`
	ApprovedByUserID string         `json:"approvedByUserId,omitempty"`
	ApprovedAt       *time.Time     `json:"approvedAt,omitempty"`
	CreatedAt        time.Time      `json:"createdAt"`
	UpdatedAt        time.Time      `json:"updatedAt"`
}

type Matcher struct {
	Schemes      []string `json:"schemes,omitempty"`
	Hosts        []string `json:"hosts,omitempty"`
	Methods      []string `json:"methods,omitempty"`
	PathPrefixes []string `json:"pathPrefixes,omitempty"`
	ContentTypes []string `json:"contentTypes,omitempty"`
}

type Manifest struct {
	ProtocolVersion string   `json:"protocolVersion"`
	Language        string   `json:"language"`
	Entrypoint      string   `json:"entrypoint"`
	SDKVersion      string   `json:"sdkVersion"`
	Hooks           []Hook   `json:"hooks"`
	Requirements    []string `json:"requirements"`
}

type Body struct {
	Encoding string `json:"encoding"`
	Data     string `json:"data"`
	Length   int64  `json:"length"`
	SHA256   string `json:"sha256"`
	Complete bool   `json:"complete"`
}

type Message struct {
	Kind    string           `json:"kind"`
	Method  string           `json:"method,omitempty"`
	Path    string           `json:"path,omitempty"`
	Status  int              `json:"status,omitempty"`
	Headers []traffic.Header `json:"headers"`
	Body    Body             `json:"body"`
}

type InvocationContext struct {
	TransactionID  string         `json:"transactionId"`
	ConversationID string         `json:"conversationId"`
	Direction      string         `json:"direction"`
	Scheme         string         `json:"scheme"`
	Host           string         `json:"host"`
	Port           int            `json:"port"`
	Method         string         `json:"method,omitempty"`
	Path           string         `json:"path,omitempty"`
	ContentType    string         `json:"contentType,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
	Config         map[string]any `json:"config"`
}

type Invocation struct {
	ProtocolVersion  string            `json:"protocolVersion"`
	InvocationID     string            `json:"invocationId"`
	RevisionID       string            `json:"revisionId"`
	RevisionSHA256   string            `json:"revisionSha256"`
	BindingID        string            `json:"bindingId,omitempty"`
	Hook             Hook              `json:"hook"`
	Mode             string            `json:"mode"`
	DeadlineMS       int               `json:"deadlineMs"`
	Context          InvocationContext `json:"context"`
	Message          Message           `json:"message"`
	OriginalWire     *Message          `json:"originalWire,omitempty"`
	TransactionState map[string]any    `json:"transactionState"`
}

type Annotation struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type TransformError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Result struct {
	ProtocolVersion string          `json:"protocolVersion"`
	InvocationID    string          `json:"invocationId"`
	Action          string          `json:"action"`
	Message         *Message        `json:"message,omitempty"`
	Annotations     []Annotation    `json:"annotations,omitempty"`
	StatePatch      map[string]any  `json:"statePatch,omitempty"`
	Error           *TransformError `json:"error,omitempty"`
}

type ValidationIssue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ValidationReport struct {
	Valid        bool              `json:"valid"`
	SourceSHA256 string            `json:"sourceSha256"`
	Hooks        []Hook            `json:"hooks"`
	Issues       []ValidationIssue `json:"issues"`
	Runner       string            `json:"runner,omitempty"`
}

type DryRunReport struct {
	RevisionID       string         `json:"revisionId"`
	TransactionID    string         `json:"transactionId"`
	HookResults      []HookRun      `json:"hookResults"`
	RoundTripMatched bool           `json:"roundTripMatched"`
	FinalMessage     *Message       `json:"finalMessage,omitempty"`
	State            map[string]any `json:"state"`
}

type HookRun struct {
	InvocationID  string          `json:"invocationId"`
	Hook          Hook            `json:"hook"`
	Action        string          `json:"action"`
	DurationMS    int64           `json:"durationMs"`
	InputSHA256   string          `json:"inputSha256"`
	OutputSHA256  string          `json:"outputSha256,omitempty"`
	OutputMessage *Message        `json:"outputMessage,omitempty"`
	Annotations   []Annotation    `json:"annotations,omitempty"`
	Error         *TransformError `json:"error,omitempty"`
}

type Run struct {
	ID             string       `json:"id"`
	BindingID      string       `json:"bindingId,omitempty"`
	RevisionID     string       `json:"revisionId"`
	TransactionID  string       `json:"transactionId,omitempty"`
	InvocationID   string       `json:"invocationId"`
	Kind           string       `json:"kind"`
	Hook           Hook         `json:"hook"`
	Mode           string       `json:"mode"`
	Action         string       `json:"action"`
	InputSHA256    string       `json:"inputSha256"`
	OutputSHA256   string       `json:"outputSha256,omitempty"`
	DurationMS     int64        `json:"durationMs"`
	ErrorCode      string       `json:"errorCode,omitempty"`
	ErrorSummary   string       `json:"errorSummary,omitempty"`
	Annotations    []Annotation `json:"annotations,omitempty"`
	RunnerIdentity string       `json:"runnerIdentity,omitempty"`
	CreatedAt      time.Time    `json:"createdAt"`
}

func SourceDigest(source string) string {
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}

func CanonicalHooks(hooks []Hook) ([]Hook, error) {
	wanted := make(map[Hook]bool, len(hooks))
	for _, hook := range hooks {
		if !validHook[hook] {
			return nil, fmt.Errorf("unsupported traffic transform hook %q", hook)
		}
		wanted[hook] = true
	}
	if len(wanted) == 0 {
		return nil, errors.New("traffic transform requires at least one hook")
	}
	result := make([]Hook, 0, len(wanted))
	for _, hook := range hookOrder {
		if wanted[hook] {
			result = append(result, hook)
		}
	}
	return result, nil
}

func ManifestForRevision(revision Revision) Manifest {
	return Manifest{
		ProtocolVersion: revision.ProtocolVersion,
		Language:        revision.Language,
		Entrypoint:      revision.Entrypoint,
		SDKVersion:      revision.SDKVersion,
		Hooks:           append([]Hook(nil), revision.Hooks...),
		Requirements:    append([]string(nil), revision.Requirements...),
	}
}

func NewMessage(kind, method, path string, status int, headers []traffic.Header, content []byte, complete bool) Message {
	sum := sha256.Sum256(content)
	return Message{
		Kind:    kind,
		Method:  method,
		Path:    path,
		Status:  status,
		Headers: append([]traffic.Header(nil), headers...),
		Body: Body{
			Encoding: "base64",
			Data:     base64.StdEncoding.EncodeToString(content),
			Length:   int64(len(content)),
			SHA256:   hex.EncodeToString(sum[:]),
			Complete: complete,
		},
	}
}

func (m Message) BodyBytes() ([]byte, error) {
	if m.Body.Encoding != "base64" {
		return nil, errors.New("traffic transform body encoding must be base64")
	}
	content, err := base64.StdEncoding.DecodeString(m.Body.Data)
	if err != nil {
		return nil, fmt.Errorf("decode traffic transform body: %w", err)
	}
	return content, nil
}

func (m Matcher) Normalize() Matcher {
	normalizeList := func(values []string, lower bool) []string {
		seen := map[string]bool{}
		out := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.TrimSpace(value)
			if lower {
				value = strings.ToLower(value)
			}
			if value != "" && !seen[value] {
				seen[value] = true
				out = append(out, value)
			}
		}
		sort.Strings(out)
		return out
	}
	return Matcher{
		Schemes:      normalizeList(m.Schemes, true),
		Hosts:        normalizeList(m.Hosts, true),
		Methods:      normalizeList(m.Methods, false),
		PathPrefixes: normalizeList(m.PathPrefixes, false),
		ContentTypes: normalizeList(m.ContentTypes, true),
	}
}

func (m Matcher) Matches(ctx InvocationContext) bool {
	m = m.Normalize()
	matchList := func(values []string, value string, fold bool) bool {
		if len(values) == 0 {
			return true
		}
		for _, candidate := range values {
			if (fold && strings.EqualFold(candidate, value)) || (!fold && candidate == value) {
				return true
			}
		}
		return false
	}
	if !matchList(m.Schemes, ctx.Scheme, true) || !matchList(m.Hosts, ctx.Host, true) || !matchList(m.Methods, ctx.Method, true) {
		return false
	}
	if len(m.PathPrefixes) > 0 {
		matched := false
		for _, prefix := range m.PathPrefixes {
			if strings.HasPrefix(ctx.Path, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	contentType := strings.TrimSpace(strings.Split(ctx.ContentType, ";")[0])
	return matchList(m.ContentTypes, contentType, true)
}

func ValidateInvocation(inv Invocation) error {
	if inv.ProtocolVersion != ProtocolVersion {
		return errors.New("unsupported traffic transform protocol")
	}
	if strings.TrimSpace(inv.InvocationID) == "" || strings.TrimSpace(inv.RevisionID) == "" || !sha256Pattern.MatchString(inv.RevisionSHA256) {
		return errors.New("invalid traffic transform invocation identity")
	}
	if !validHook[inv.Hook] {
		return errors.New("invalid traffic transform hook")
	}
	if inv.Mode != ModeObserve && inv.Mode != ModeInline {
		return errors.New("invalid traffic transform mode")
	}
	if inv.Mode == ModeObserve && inv.Hook != HookDecodeRequest && inv.Hook != HookDecodeResponse {
		return errors.New("observe mode only permits decode hooks")
	}
	if inv.DeadlineMS <= 0 || inv.DeadlineMS > MaximumDeadlineMS {
		return errors.New("invalid traffic transform deadline")
	}
	if err := ValidateContext(inv.Context); err != nil {
		return err
	}
	if err := ValidateMessage(inv.Message, inv.Mode == ModeInline); err != nil {
		return err
	}
	if inv.OriginalWire != nil {
		if err := ValidateMessage(*inv.OriginalWire, true); err != nil {
			return fmt.Errorf("invalid original wire message: %w", err)
		}
	}
	if err := validateJSONMap(inv.TransactionState, MaxStateJSONBytes); err != nil {
		return fmt.Errorf("invalid transaction state: %w", err)
	}
	return nil
}

func ValidateContext(ctx InvocationContext) error {
	if strings.TrimSpace(ctx.TransactionID) == "" || strings.TrimSpace(ctx.ConversationID) == "" {
		return errors.New("traffic transform context is missing transaction identity")
	}
	if ctx.Direction != DirectionRequest && ctx.Direction != DirectionResponse {
		return errors.New("invalid traffic transform direction")
	}
	if ctx.Scheme != "http" && ctx.Scheme != "https" {
		return errors.New("invalid traffic transform scheme")
	}
	if strings.TrimSpace(ctx.Host) == "" || ctx.Port <= 0 || ctx.Port > 65535 {
		return errors.New("invalid traffic transform target")
	}
	if strings.ContainsAny(ctx.Path, "\r\n\x00") {
		return errors.New("invalid traffic transform path")
	}
	if ctx.Timestamp.IsZero() {
		return errors.New("traffic transform timestamp is required")
	}
	if err := validateJSONMap(ctx.Config, MaxStateJSONBytes); err != nil {
		return fmt.Errorf("invalid traffic transform config: %w", err)
	}
	return nil
}

func ValidateMessage(message Message, requireComplete bool) error {
	if message.Kind != traffic.MessageKindRequest && message.Kind != traffic.MessageKindResponse {
		return errors.New("invalid traffic transform message kind")
	}
	if message.Kind == traffic.MessageKindRequest {
		if strings.TrimSpace(message.Method) == "" || message.Status != 0 {
			return errors.New("invalid transformed request metadata")
		}
	} else if message.Status < 100 || message.Status > 999 || message.Method != "" || message.Path != "" {
		return errors.New("invalid transformed response metadata")
	}
	if len(message.Headers) > 256 {
		return errors.New("too many transformed headers")
	}
	headerBytes := 0
	for _, header := range message.Headers {
		if !headerNameToken.MatchString(header.Name) || strings.ContainsAny(header.Value, "\r\n\x00") {
			return errors.New("invalid transformed header")
		}
		if isManagedHeader(header.Name) {
			return fmt.Errorf("transform cannot control managed header %s", header.Name)
		}
		headerBytes += len(header.Name) + len(header.Value)
	}
	if headerBytes > 256<<10 {
		return errors.New("transformed headers are too large")
	}
	content, err := message.BodyBytes()
	if err != nil {
		return err
	}
	if len(content) > MaxTransformBody || int64(len(content)) != message.Body.Length {
		return errors.New("invalid transformed body length")
	}
	sum := sha256.Sum256(content)
	if message.Body.SHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("invalid transformed body digest")
	}
	if requireComplete && !message.Body.Complete {
		return errors.New("inline transform requires a complete body")
	}
	return nil
}

func ValidateResult(inv Invocation, result Result) error {
	if result.ProtocolVersion != ProtocolVersion || result.InvocationID != inv.InvocationID {
		return errors.New("traffic transform result identity mismatch")
	}
	switch result.Action {
	case ActionPass:
		if result.Message != nil || result.Error != nil {
			return errors.New("pass result must not include a message or error")
		}
	case ActionReplace:
		if result.Message == nil || result.Error != nil {
			return errors.New("replace result requires only a message")
		}
		if err := ValidateMessage(*result.Message, inv.Mode == ModeInline); err != nil {
			return err
		}
		if result.Message.Kind != inv.Message.Kind {
			return errors.New("transform cannot change message direction")
		}
	case ActionBlock:
		if inv.Mode != ModeInline || result.Message != nil || result.Error != nil {
			return errors.New("block is only valid for approved inline execution")
		}
	case ActionError:
		if result.Error == nil || strings.TrimSpace(result.Error.Code) == "" || result.Message != nil {
			return errors.New("error result requires a structured error")
		}
	default:
		return errors.New("invalid traffic transform action")
	}
	if len(result.Annotations) > MaxAnnotations {
		return errors.New("too many traffic transform annotations")
	}
	for _, annotation := range result.Annotations {
		if strings.TrimSpace(annotation.Key) == "" || len(annotation.Key) > 128 || len(annotation.Value) > MaxAnnotationLength || strings.ContainsAny(annotation.Key, "\r\n\x00") {
			return errors.New("invalid traffic transform annotation")
		}
	}
	if err := validateJSONMap(result.StatePatch, MaxStateJSONBytes); err != nil {
		return fmt.Errorf("invalid traffic transform state patch: %w", err)
	}
	return nil
}

func ContentType(headers []traffic.Header) string {
	for _, header := range headers {
		if strings.EqualFold(header.Name, "Content-Type") {
			return header.Value
		}
	}
	return ""
}

func isManagedHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Host", "Connection", "Proxy-Authorization", "Proxy-Authenticate", "Transfer-Encoding", "Content-Length", "Trailer", "Upgrade":
		return true
	default:
		return strings.HasPrefix(strings.ToLower(name), "x-cyberstrike-")
	}
}

func validateJSONMap(value map[string]any, maxBytes int) error {
	if value == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) > maxBytes {
		return errors.New("JSON object is too large")
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return err
	}
	if decoded != nil {
		if _, ok := decoded.(map[string]any); !ok {
			return errors.New("value must be a JSON object")
		}
	}
	return nil
}
