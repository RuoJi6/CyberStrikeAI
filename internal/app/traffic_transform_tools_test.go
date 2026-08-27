package app

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/traffic"
	"cyberstrike-ai/internal/traffictransform"

	"go.uber.org/zap"
)

type toolTransformRunner struct{}

func (toolTransformRunner) Health(context.Context) (traffictransform.RunnerHealth, error) {
	return traffictransform.RunnerHealth{Status: "ok", ProtocolVersion: traffictransform.ProtocolVersion, RunnerGeneration: "tool-test"}, nil
}

func (toolTransformRunner) LoadRevision(_ context.Context, revision traffictransform.Revision) (traffictransform.LoadResult, error) {
	return traffictransform.LoadResult{
		ProtocolVersion:  traffictransform.ProtocolVersion,
		RevisionID:       revision.ID,
		SourceSHA256:     revision.SourceSHA256,
		Valid:            true,
		Hooks:            revision.Hooks,
		RunnerGeneration: "tool-test",
	}, nil
}

func (toolTransformRunner) Invoke(_ context.Context, invocation traffictransform.Invocation) (traffictransform.Result, error) {
	message := invocation.Message
	return traffictransform.Result{
		ProtocolVersion: traffictransform.ProtocolVersion,
		InvocationID:    invocation.InvocationID,
		Action:          traffictransform.ActionReplace,
		Message:         &message,
	}, nil
}

func TestTrafficTransformAgentToolsCreateValidateDryRunAndObserve(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-transform-tools.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	user, err := db.CreateRBACUser("transform-agent", "Transform Agent", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := db.CreateConversation("transform tools", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(user.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	transaction := &traffic.Transaction{
		ConversationID:  conversation.ID,
		RuntimeMode:     traffic.RuntimeModeContainer,
		CaptureCoverage: traffic.CaptureCoverageEnforced,
		Scheme:          "https", Host: "api.example.test", Port: 443,
		Method: "POST", Path: "/encrypted", StartedAt: now,
	}
	body, encoding, digest := traffic.EncodeBody([]byte{0, 1, 2, 3})
	detail, err := db.CreateTrafficTransaction(context.Background(), transaction, []traffic.Message{{
		Stage: traffic.StageClientRequest, Kind: traffic.MessageKindRequest,
		Method: "POST", Path: "/encrypted", Headers: []traffic.Header{{Name: "Content-Type", Value: "application/octet-stream"}},
		Body: body, BodyEncoding: encoding, BodySHA256: digest,
		BodyLength: 4, BodyStoredBytes: 4, Complete: true,
	}})
	if err != nil {
		t.Fatal(err)
	}

	permissions := map[string]bool{
		"traffic:read": true, "traffic:read_sensitive": true,
		"traffic_transform:write": true, "traffic_transform:activate_observe": true,
		"vulnerability:write": true,
	}
	principal := authctx.NewPrincipal(user.ID, user.Username, database.RBACScopeAssigned, permissions)
	ctx := authctx.WithPrincipal(mcp.WithMCPConversationID(context.Background(), conversation.ID), principal)
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerTrafficTransformTools(server, db, toolTransformRunner{}, zap.NewNop())
	vulnerability, err := db.CreateVulnerability(&database.Vulnerability{
		ConversationID: conversation.ID, Title: "encrypted endpoint", Severity: "high", Status: "open",
	})
	if err != nil {
		t.Fatal(err)
	}
	linked, _, err := server.CallTool(ctx, builtin.ToolLinkTrafficEvidence, map[string]interface{}{
		"vulnerability_id": vulnerability.ID,
		"transaction_id":   detail.Transaction.ID,
		"role":             "primary",
		"note":             "representative packet",
	})
	if err != nil || linked == nil || linked.IsError {
		t.Fatalf("link result=%#v err=%v text=%q", linked, err, toolResultText(linked))
	}
	links, err := db.ListTrafficEvidenceForVulnerability(context.Background(), vulnerability.ID)
	if err != nil || len(links) != 1 || links[0].TransactionID != detail.Transaction.ID {
		t.Fatalf("evidence links=%#v err=%v", links, err)
	}

	created, _, err := server.CallTool(ctx, builtin.ToolCreateTrafficTransform, map[string]interface{}{
		"name":        "reverse codec",
		"description": "test codec",
		"source":      "def decode_request(ctx, wire):\n    return wire\n",
		"hooks":       []interface{}{"decode_request"},
	})
	if err != nil || created == nil || created.IsError {
		t.Fatalf("create result=%#v err=%v text=%q", created, err, toolResultText(created))
	}
	var createPayload struct {
		Revision struct {
			ID string `json:"id"`
		} `json:"revision"`
	}
	if err := json.Unmarshal([]byte(toolResultText(created)), &createPayload); err != nil || createPayload.Revision.ID == "" {
		t.Fatalf("create payload=%q err=%v", toolResultText(created), err)
	}

	validated, _, err := server.CallTool(ctx, builtin.ToolValidateTrafficTransform, map[string]interface{}{"revision_id": createPayload.Revision.ID})
	if err != nil || validated == nil || validated.IsError {
		t.Fatalf("validate result=%#v err=%v text=%q", validated, err, toolResultText(validated))
	}
	tested, _, err := server.CallTool(ctx, builtin.ToolTestTrafficTransform, map[string]interface{}{
		"revision_id":    createPayload.Revision.ID,
		"transaction_id": detail.Transaction.ID,
		"direction":      "request",
	})
	if err != nil || tested == nil || tested.IsError {
		t.Fatalf("test result=%#v err=%v text=%q", tested, err, toolResultText(tested))
	}
	var testPayload map[string]any
	if err := json.Unmarshal([]byte(toolResultText(tested)), &testPayload); err != nil || testPayload["untrustedContent"] != true {
		t.Fatalf("test payload=%q err=%v", toolResultText(tested), err)
	}
	activated, _, err := server.CallTool(ctx, builtin.ToolActivateTrafficTransform, map[string]interface{}{
		"revision_id": createPayload.Revision.ID,
		"mode":        "observe",
		"matcher":     map[string]interface{}{"hosts": []interface{}{"api.example.test"}},
	})
	if err != nil || activated == nil || activated.IsError {
		t.Fatalf("activate result=%#v err=%v text=%q", activated, err, toolResultText(activated))
	}
	bindings, err := db.ListActiveTrafficTransformBindings(context.Background(), conversation.ID)
	if err != nil || len(bindings) != 1 || bindings[0].Mode != traffictransform.ModeObserve {
		t.Fatalf("bindings=%#v err=%v", bindings, err)
	}
}

func TestImportedTrafficRunsActiveObserveDecode(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-observe.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, _ := db.CreateConversation("observe", database.ConversationCreateMeta{})
	transform, err := db.CreateTrafficTransform(context.Background(), &traffictransform.Transform{
		ConversationID: conversation.ID, Name: "passive decoder",
	})
	if err != nil {
		t.Fatal(err)
	}
	revision, report, err := db.CreateTrafficTransformRevision(context.Background(), &traffictransform.Revision{
		TransformID: transform.ID,
		Source:      "def decode_request(ctx, wire):\n    return wire\n",
		Hooks:       []traffictransform.Hook{traffictransform.HookDecodeRequest},
	}, traffictransform.DefaultRunnerInventory())
	if err != nil {
		t.Fatal(err)
	}
	report.Runner = "tool-test"
	if err := db.SetTrafficTransformRevisionValidation(context.Background(), revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, report); err != nil {
		t.Fatal(err)
	}
	binding, err := db.CreateTrafficTransformBinding(context.Background(), &traffictransform.Binding{
		ConversationID: conversation.ID, TransformID: transform.ID, RevisionID: revision.ID,
		Mode: traffictransform.ModeObserve, Matcher: traffictransform.Matcher{Hosts: []string{"api.example.test"}},
		Config: map[string]any{"test_key": "agent-visible"}, Priority: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err = db.ActivateTrafficTransformBinding(context.Background(), binding.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	body, encoding, digest := traffic.EncodeBody([]byte("ciphertext"))
	detail, err := db.CreateTrafficTransaction(context.Background(), &traffic.Transaction{
		ConversationID: conversation.ID, RuntimeMode: traffic.RuntimeModeContainer,
		CaptureCoverage: traffic.CaptureCoverageEnforced, Scheme: "https", Host: "api.example.test",
		Port: 443, Method: "POST", Path: "/encrypted", StartedAt: now,
	}, []traffic.Message{{
		Stage: traffic.StageUpstreamRequest, Kind: traffic.MessageKindRequest, Method: "POST", Path: "/encrypted",
		Headers: []traffic.Header{{Name: "Content-Type", Value: "application/octet-stream"}},
		Body:    body, BodyEncoding: encoding, BodySHA256: digest, BodyLength: 10, BodyStoredBytes: 10, Complete: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	observeImportedTraffic(context.Background(), db, toolTransformRunner{}, detail, zap.NewNop())
	observed, err := db.GetTrafficTransaction(context.Background(), detail.Transaction.ID)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Transaction.TransformBindingID != binding.ID || observed.Transaction.TransformRevisionID != revision.ID || observed.Transaction.TransformResult != "observe_passed" {
		t.Fatalf("observed transaction = %#v", observed.Transaction)
	}
	foundDecoded := false
	for _, message := range observed.Messages {
		foundDecoded = foundDecoded || message.Stage == traffic.StageDecodedRequest
	}
	if !foundDecoded {
		t.Fatalf("decoded request missing: %#v", observed.Messages)
	}
	storedBinding, err := db.GetTrafficTransformBinding(context.Background(), binding.ID)
	if err != nil || storedBinding.Config["test_key"] != "agent-visible" {
		t.Fatalf("binding config = %#v / %v", storedBinding, err)
	}
}
