package traffictransform

import (
	"bytes"
	"testing"
	"time"

	"cyberstrike-ai/internal/traffic"
)

func TestPrepareRevisionPinsInventoryAndHooks(t *testing.T) {
	revision, report := PrepareRevision(Revision{
		Source: `from cyberstrike_transform import Message

def decode_request(ctx, wire: Message) -> Message:
    return wire
`,
		Hooks:        []Hook{HookDecodeRequest, HookDecodeRequest},
		Requirements: []string{"cryptography==38.0.4"},
	}, DefaultRunnerInventory())
	if !report.Valid || revision.ValidationStatus != ValidationPending {
		t.Fatalf("PrepareRevision report = %#v", report)
	}
	if len(revision.Hooks) != 1 || revision.Hooks[0] != HookDecodeRequest {
		t.Fatalf("canonical hooks = %#v", revision.Hooks)
	}
	if revision.SourceSHA256 != report.SourceSHA256 || len(revision.SourceSHA256) != 64 {
		t.Fatalf("source digest = %q / %q", revision.SourceSHA256, report.SourceSHA256)
	}

	_, bad := PrepareRevision(Revision{
		Source:       "def decode_request(ctx, wire): return wire\n",
		Hooks:        []Hook{HookDecodeRequest},
		Requirements: []string{"requests==2.32.0"},
	}, DefaultRunnerInventory())
	if bad.Valid || len(bad.Issues) == 0 || bad.Issues[len(bad.Issues)-1].Code != "dependency_unavailable" {
		t.Fatalf("unavailable dependency report = %#v", bad)
	}
}

func TestInvocationAndResultValidation(t *testing.T) {
	raw := []byte{0x00, 0x01, 0xff}
	message := NewMessage(traffic.MessageKindRequest, "POST", "/encrypted", 0, []traffic.Header{{Name: "Content-Type", Value: "application/octet-stream"}}, raw, true)
	inv := Invocation{
		ProtocolVersion: ProtocolVersion,
		InvocationID:    "inv-1",
		RevisionID:      "rev-1",
		RevisionSHA256:  SourceDigest("source"),
		Hook:            HookDecodeRequest,
		Mode:            ModeObserve,
		DeadlineMS:      DefaultDeadlineMS,
		Context: InvocationContext{
			TransactionID: "transaction-1", ConversationID: "conversation-1", Direction: DirectionRequest,
			Scheme: "https", Host: "api.example.test", Port: 443, Method: "POST", Path: "/encrypted",
			Timestamp: time.Now().UTC(), Config: map[string]any{},
		},
		Message:          message,
		TransactionState: map[string]any{},
	}
	if err := ValidateInvocation(inv); err != nil {
		t.Fatalf("ValidateInvocation: %v", err)
	}
	decoded, err := message.BodyBytes()
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatalf("BodyBytes = %x / %v", decoded, err)
	}
	result := Result{ProtocolVersion: ProtocolVersion, InvocationID: inv.InvocationID, Action: ActionReplace, Message: &message}
	if err := ValidateResult(inv, result); err != nil {
		t.Fatalf("ValidateResult: %v", err)
	}
	result.Message.Headers = append(result.Message.Headers, traffic.Header{Name: "Content-Length", Value: "999"})
	if err := ValidateResult(inv, result); err == nil {
		t.Fatal("expected managed header to be rejected")
	}
}

func TestObserveRejectsMutationAndInlineRequiresApproval(t *testing.T) {
	message := NewMessage(traffic.MessageKindRequest, "GET", "/", 0, nil, nil, true)
	inv := Invocation{
		ProtocolVersion: ProtocolVersion, InvocationID: "inv", RevisionID: "rev", RevisionSHA256: SourceDigest("x"),
		Hook: HookMutateRequest, Mode: ModeObserve, DeadlineMS: 100,
		Context: InvocationContext{TransactionID: "txn", ConversationID: "conv", Direction: DirectionRequest, Scheme: "https", Host: "example.test", Port: 443, Method: "GET", Path: "/", Timestamp: time.Now().UTC()},
		Message: message,
	}
	if err := ValidateInvocation(inv); err == nil {
		t.Fatal("expected observe mutation to be rejected")
	}

	revision := Revision{ID: "rev", TransformID: "transform", ValidationStatus: ValidationPassed}
	binding := Binding{ConversationID: "conv", TransformID: "transform", RevisionID: "rev", Mode: ModeInline, FailurePolicy: FailurePolicyClosed}
	if err := ValidateBinding(binding, revision); err == nil {
		t.Fatal("expected unapproved inline binding to be rejected")
	}
	approved := time.Now().UTC()
	binding.ApprovedAt = &approved
	binding.ApprovedByUserID = "user"
	if err := ValidateBinding(binding, revision); err != nil {
		t.Fatalf("approved inline binding: %v", err)
	}
}

func TestMatcherNormalizesAndMatches(t *testing.T) {
	matcher := Matcher{
		Schemes:      []string{"HTTPS", "https"},
		Hosts:        []string{"API.Example.Test"},
		Methods:      []string{"POST"},
		PathPrefixes: []string{"/v1/"},
		ContentTypes: []string{"application/json"},
	}
	ctx := InvocationContext{Scheme: "https", Host: "api.example.test", Method: "post", Path: "/v1/order", ContentType: "application/json; charset=utf-8"}
	if !matcher.Matches(ctx) {
		t.Fatal("expected matcher to match normalized context")
	}
	ctx.Path = "/v2/order"
	if matcher.Matches(ctx) {
		t.Fatal("unexpected path match")
	}
}
