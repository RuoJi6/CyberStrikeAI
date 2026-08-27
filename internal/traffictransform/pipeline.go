package traffictransform

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/traffic"

	"github.com/google/uuid"
)

type Pipeline struct {
	client Client
	now    func() time.Time
}

func NewPipeline(client Client) *Pipeline {
	return &Pipeline{client: client, now: func() time.Time { return time.Now().UTC() }}
}

func MessageFromTraffic(message traffic.Message) (Message, error) {
	content, err := traffic.DecodeBody(message)
	if err != nil {
		return Message{}, err
	}
	headers := make([]traffic.Header, 0, len(message.Headers))
	for _, header := range message.Headers {
		if !isManagedHeader(header.Name) {
			headers = append(headers, header)
		}
	}
	result := NewMessage(message.Kind, message.Method, message.Path, message.Status, headers, content, message.Complete)
	if err := ValidateMessage(result, false); err != nil {
		return Message{}, err
	}
	return result, nil
}

func MessageToTraffic(transactionID, stage string, message Message, createdAt time.Time) (traffic.Message, error) {
	content, err := message.BodyBytes()
	if err != nil {
		return traffic.Message{}, err
	}
	body, encoding, digest := traffic.EncodeBody(content)
	result := traffic.Message{
		TransactionID:   transactionID,
		Stage:           stage,
		Kind:            message.Kind,
		Method:          message.Method,
		Path:            message.Path,
		Status:          message.Status,
		Protocol:        "HTTP/1.1",
		Headers:         append([]traffic.Header(nil), message.Headers...),
		ContentType:     ContentType(message.Headers),
		Body:            body,
		BodyEncoding:    encoding,
		BodySHA256:      digest,
		BodyLength:      int64(len(content)),
		BodyStoredBytes: int64(len(content)),
		Complete:        message.Body.Complete,
		CreatedAt:       createdAt,
	}
	if err := traffic.ValidateMessage(result); err != nil {
		return traffic.Message{}, err
	}
	return result, nil
}

type DryRunInput struct {
	Revision    Revision
	BindingID   string
	Transaction traffic.Transaction
	Message     traffic.Message
	Config      map[string]any
	Direction   string
	DeadlineMS  int
}

func (p *Pipeline) DryRun(ctx context.Context, input DryRunInput) (DryRunReport, error) {
	if p == nil || p.client == nil {
		return DryRunReport{}, errors.New("traffic transform runner is unavailable")
	}
	if input.Revision.ValidationStatus != ValidationPassed {
		return DryRunReport{}, errors.New("traffic transform revision has not passed runner validation")
	}
	if input.Direction == "" {
		input.Direction = input.Message.Kind
	}
	if input.Direction != DirectionRequest && input.Direction != DirectionResponse {
		return DryRunReport{}, errors.New("traffic transform dry-run direction must be request or response")
	}
	if input.Message.Kind != input.Direction {
		return DryRunReport{}, errors.New("traffic transform dry-run message direction mismatch")
	}
	if !input.Message.Complete {
		return DryRunReport{}, errors.New("traffic transform dry-run requires a complete captured body")
	}
	deadlineMS := input.DeadlineMS
	if deadlineMS <= 0 {
		deadlineMS = DefaultDeadlineMS
	}
	if deadlineMS > MaximumDeadlineMS {
		return DryRunReport{}, errors.New("traffic transform dry-run deadline is too large")
	}
	wire, err := MessageFromTraffic(input.Message)
	if err != nil {
		return DryRunReport{}, err
	}
	current := wire
	original := wire
	state := map[string]any{}
	report := DryRunReport{
		RevisionID:    input.Revision.ID,
		TransactionID: input.Transaction.ID,
		State:         state,
	}
	hooks := hooksForDirection(input.Direction)
	implemented := make(map[Hook]bool, len(input.Revision.Hooks))
	for _, hook := range input.Revision.Hooks {
		implemented[hook] = true
	}
	for _, hook := range hooks {
		if !implemented[hook] {
			continue
		}
		invocation := Invocation{
			ProtocolVersion: ProtocolVersion,
			InvocationID:    uuid.NewString(),
			RevisionID:      input.Revision.ID,
			RevisionSHA256:  input.Revision.SourceSHA256,
			BindingID:       strings.TrimSpace(input.BindingID),
			Hook:            hook,
			Mode:            ModeInline,
			DeadlineMS:      deadlineMS,
			Context: InvocationContext{
				TransactionID:  input.Transaction.ID,
				ConversationID: input.Transaction.ConversationID,
				Direction:      input.Direction,
				Scheme:         input.Transaction.Scheme,
				Host:           input.Transaction.Host,
				Port:           input.Transaction.Port,
				Method:         input.Transaction.Method,
				Path:           input.Transaction.Path,
				ContentType:    ContentType(current.Headers),
				Timestamp:      p.now(),
				Config:         cloneJSONMap(input.Config),
			},
			Message:          current,
			TransactionState: cloneJSONMap(state),
		}
		if hook == HookEncodeRequest || hook == HookEncodeResponse {
			originalCopy := original
			invocation.OriginalWire = &originalCopy
		}
		started := p.now()
		result, invokeErr := p.client.Invoke(ctx, invocation)
		duration := p.now().Sub(started).Milliseconds()
		run := HookRun{
			Hook:        hook,
			DurationMS:  max(duration, 0),
			InputSHA256: current.Body.SHA256,
		}
		if invokeErr != nil {
			run.Action = ActionError
			run.Error = &TransformError{Code: "runner_unavailable", Message: invokeErr.Error()}
			report.HookResults = append(report.HookResults, run)
			return report, fmt.Errorf("invoke traffic transform %s: %w", hook, invokeErr)
		}
		run.Action = result.Action
		run.Annotations = append([]Annotation(nil), result.Annotations...)
		run.Error = result.Error
		if result.Message != nil {
			run.OutputSHA256 = result.Message.Body.SHA256
			messageCopy := *result.Message
			run.OutputMessage = &messageCopy
		}
		report.HookResults = append(report.HookResults, run)
		if err := applyStatePatch(state, result.StatePatch); err != nil {
			return report, err
		}
		switch result.Action {
		case ActionPass:
			continue
		case ActionReplace:
			current = *result.Message
		case ActionBlock:
			return report, errors.New("traffic transform dry-run was blocked by the script")
		case ActionError:
			return report, fmt.Errorf("traffic transform %s failed: %s: %s", hook, result.Error.Code, result.Error.Message)
		default:
			return report, errors.New("traffic transform returned an unsupported action")
		}
	}
	final := current
	report.FinalMessage = &final
	report.RoundTripMatched = final.Body.SHA256 == original.Body.SHA256
	return report, nil
}

func hooksForDirection(direction string) []Hook {
	if direction == DirectionResponse {
		return []Hook{HookDecodeResponse, HookMutateResponse, HookEncodeResponse}
	}
	return []Hook{HookDecodeRequest, HookMutateRequest, HookEncodeRequest}
}

func applyStatePatch(state map[string]any, patch map[string]any) error {
	for key, value := range patch {
		key = strings.TrimSpace(key)
		if key == "" || len(key) > 128 {
			return errors.New("traffic transform returned an invalid state key")
		}
		if value == nil {
			delete(state, key)
		} else {
			state[key] = value
		}
	}
	return validateJSONMap(state, MaxStateJSONBytes)
}

func cloneJSONMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}
