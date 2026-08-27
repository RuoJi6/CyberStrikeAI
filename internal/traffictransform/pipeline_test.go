package traffictransform

import (
	"context"
	"testing"
	"time"

	"cyberstrike-ai/internal/traffic"
)

type pipelineClient struct {
	t     *testing.T
	hooks []Hook
}

func (client *pipelineClient) Health(context.Context) (RunnerHealth, error) {
	return RunnerHealth{Status: "ok", ProtocolVersion: ProtocolVersion, RunnerGeneration: "test"}, nil
}

func (client *pipelineClient) Invoke(_ context.Context, invocation Invocation) (Result, error) {
	client.hooks = append(client.hooks, invocation.Hook)
	message := invocation.Message
	content, _ := message.BodyBytes()
	switch invocation.Hook {
	case HookDecodeRequest:
		message = NewMessage(message.Kind, message.Method, message.Path, message.Status, message.Headers, append([]byte("plain:"), content...), true)
		return Result{ProtocolVersion: ProtocolVersion, InvocationID: invocation.InvocationID, Action: ActionReplace, Message: &message, StatePatch: map[string]any{"nonce": "one"}}, nil
	case HookMutateRequest:
		if invocation.TransactionState["nonce"] != "one" {
			client.t.Fatalf("state = %#v", invocation.TransactionState)
		}
		return Result{ProtocolVersion: ProtocolVersion, InvocationID: invocation.InvocationID, Action: ActionPass}, nil
	case HookEncodeRequest:
		return Result{ProtocolVersion: ProtocolVersion, InvocationID: invocation.InvocationID, Action: ActionReplace, Message: invocation.OriginalWire}, nil
	default:
		client.t.Fatalf("unexpected hook %s", invocation.Hook)
		return Result{}, nil
	}
}

func TestPipelineDryRunOrdersHooksAndChecksRoundTrip(t *testing.T) {
	raw := []byte{0, 1, 2, 3}
	body, encoding, digest := traffic.EncodeBody(raw)
	message := traffic.Message{
		Stage: traffic.StageClientRequest, Kind: traffic.MessageKindRequest,
		Method: "POST", Path: "/encrypted", Headers: []traffic.Header{{Name: "Content-Type", Value: "application/octet-stream"}, {Name: "Content-Length", Value: "4"}},
		Body: body, BodyEncoding: encoding, BodySHA256: digest,
		BodyLength: int64(len(raw)), BodyStoredBytes: int64(len(raw)), Complete: true,
	}
	client := &pipelineClient{t: t}
	pipeline := NewPipeline(client)
	clock := time.Now().UTC()
	pipeline.now = func() time.Time {
		clock = clock.Add(time.Millisecond)
		return clock
	}
	report, err := pipeline.DryRun(context.Background(), DryRunInput{
		Revision: Revision{
			ID: "revision", TransformID: "transform", SourceSHA256: SourceDigest("source"), ValidationStatus: ValidationPassed,
			Hooks: []Hook{HookDecodeRequest, HookMutateRequest, HookEncodeRequest},
		},
		Transaction: traffic.Transaction{
			ID: "transaction", ConversationID: "conversation", Scheme: "https", Host: "example.test", Port: 443,
			Method: "POST", Path: "/encrypted",
		},
		Message:   message,
		Direction: DirectionRequest,
	})
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if !report.RoundTripMatched || len(report.HookResults) != 3 || report.State["nonce"] != "one" {
		t.Fatalf("report = %#v", report)
	}
	want := []Hook{HookDecodeRequest, HookMutateRequest, HookEncodeRequest}
	for index := range want {
		if client.hooks[index] != want[index] {
			t.Fatalf("hooks = %#v", client.hooks)
		}
	}
}
