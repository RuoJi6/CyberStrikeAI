package app

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
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

func TestTrafficTransformToolDescriptionsRouteMITMRequests(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-transform-descriptions.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := mcp.NewServer(zap.NewNop())
	registerTrafficTransformTools(server, db, nil, zap.NewNop())
	tools := make(map[string]mcp.Tool)
	for _, tool := range server.GetAllTools() {
		tools[tool.Name] = tool
	}
	tests := []struct {
		name          string
		description   string
		shortContains string
	}{
		{builtin.ToolListTrafficTransactions, "先用它选择目标网站", "MITM"},
		{builtin.ToolGetTrafficTransaction, "为 configure_traffic_decoder 提供试跑样本", "MITM"},
		{builtin.ToolConfigureTrafficDecoder, "一次完成创建、Runner 校验、历史包试跑", "一次完成"},
		{builtin.ToolManageTrafficTransform, "可编辑、启用、停用或删除网站作用范围", "编辑或删除"},
		{builtin.ToolCreateTrafficTransform, "普通网站流量解密请改用 configure_traffic_decoder", "低级接口"},
		{builtin.ToolValidateTrafficTransform, "configure_traffic_decoder 自动完成", "低级接口"},
		{builtin.ToolTestTrafficTransform, "不连接目标或修改真实流量", "低级接口"},
		{builtin.ToolActivateTrafficTransform, "不会在发包前运行", "低级接口"},
		{builtin.ToolDeactivateTrafficTransform, "不删除脚本 revision", "保留脚本和历史证据"},
	}
	for _, test := range tests {
		tool, ok := tools[test.name]
		if !ok {
			t.Fatalf("tool %s is not registered", test.name)
		}
		if !strings.Contains(tool.Description, test.description) {
			t.Errorf("tool %s description does not contain %q: %q", test.name, test.description, tool.Description)
		}
		if !strings.Contains(tool.ShortDescription, test.shortContains) {
			t.Errorf("tool %s short description does not contain %q: %q", test.name, test.shortContains, tool.ShortDescription)
		}
	}
}

func TestConfigureAndManageTrafficDecoderLifecycle(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-decoder-lifecycle.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	user, err := db.CreateRBACUser("decoder-agent", "Decoder Agent", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := db.CreateConversation("decoder lifecycle", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(user.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	body, encoding, digest := traffic.EncodeBody([]byte("ciphertext"))
	detail, err := db.CreateTrafficTransaction(context.Background(), &traffic.Transaction{
		ConversationID: conversation.ID, RuntimeMode: traffic.RuntimeModeHost,
		CaptureCoverage: traffic.CaptureCoverageBestEffort, Scheme: "https", Host: "api.example.test",
		Port: 443, Method: "POST", Path: "/encrypted/item", StartedAt: time.Now().UTC(),
	}, []traffic.Message{{
		Stage: traffic.StageClientRequest, Kind: traffic.MessageKindRequest,
		Method: "POST", Path: "/encrypted/item", Headers: []traffic.Header{{Name: "Content-Type", Value: "application/octet-stream"}},
		Body: body, BodyEncoding: encoding, BodySHA256: digest,
		BodyLength: 10, BodyStoredBytes: 10, Complete: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	permissions := map[string]bool{
		"traffic:read": true, "traffic:read_sensitive": true,
		"traffic_transform:write": true, "traffic_transform:activate_observe": true,
	}
	principal := authctx.NewPrincipal(user.ID, user.Username, database.RBACScopeAssigned, permissions)
	ctx := authctx.WithPrincipal(mcp.WithMCPConversationID(context.Background(), conversation.ID), principal)
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerTrafficTransformTools(server, db, toolTransformRunner{}, zap.NewNop())

	configured, _, err := server.CallTool(ctx, builtin.ToolConfigureTrafficDecoder, map[string]interface{}{
		"transaction_id": detail.Transaction.ID,
		"name":           "example decoder",
		"direction":      "request",
		"source":         "from cyberstrike_transform import body_decoder\n\n@body_decoder(content_type=\"text/plain\")\ndef decode_request(body: bytes) -> bytes:\n    return body[::-1]\n",
		"activate":       true,
		"path_prefix":    "/encrypted/",
		"method":         "POST",
	})
	if err != nil || configured == nil || configured.IsError {
		t.Fatalf("configure result=%#v err=%v text=%q", configured, err, toolResultText(configured))
	}
	var configuredPayload struct {
		Status    string `json:"status"`
		Transform struct {
			ID                string `json:"id"`
			CurrentRevisionID string `json:"currentRevisionId"`
		} `json:"transform"`
		Revision struct {
			ID string `json:"id"`
		} `json:"revision"`
		Binding traffictransform.Binding `json:"binding"`
	}
	if err := json.Unmarshal([]byte(toolResultText(configured)), &configuredPayload); err != nil {
		t.Fatal(err)
	}
	if configuredPayload.Status != "active" || configuredPayload.Transform.ID == "" || configuredPayload.Revision.ID == "" || configuredPayload.Binding.Status != traffictransform.BindingActive {
		t.Fatalf("unexpected configure payload: %#v", configuredPayload)
	}
	if configuredPayload.Transform.CurrentRevisionID != configuredPayload.Revision.ID || configuredPayload.Binding.Matcher.Hosts[0] != "api.example.test" {
		t.Fatalf("revision or exact host not promoted: %#v", configuredPayload)
	}

	edited, _, err := server.CallTool(ctx, builtin.ToolConfigureTrafficDecoder, map[string]interface{}{
		"transaction_id": detail.Transaction.ID,
		"transform_id":   configuredPayload.Transform.ID,
		"name":           "example decoder edited",
		"direction":      "request",
		"source":         "from cyberstrike_transform import body_decoder\n\n@body_decoder(content_type=\"text/plain\")\ndef decode_request(body: bytes) -> bytes:\n    return body.upper()\n",
	})
	if err != nil || edited == nil || edited.IsError {
		t.Fatalf("edit result=%#v err=%v text=%q", edited, err, toolResultText(edited))
	}
	var editedPayload struct {
		Transform traffictransform.Transform `json:"transform"`
		Revision  traffictransform.Revision  `json:"revision"`
	}
	if err := json.Unmarshal([]byte(toolResultText(edited)), &editedPayload); err != nil {
		t.Fatal(err)
	}
	if editedPayload.Transform.ID != configuredPayload.Transform.ID || editedPayload.Revision.ID == configuredPayload.Revision.ID || editedPayload.Transform.CurrentRevisionID != editedPayload.Revision.ID {
		t.Fatalf("edit did not create one promoted revision: %#v", editedPayload)
	}
	updatedBinding, err := db.GetTrafficTransformBinding(context.Background(), configuredPayload.Binding.ID)
	if err != nil || updatedBinding.RevisionID != editedPayload.Revision.ID {
		t.Fatalf("observe scope was not moved to edited revision: %#v / %v", updatedBinding, err)
	}

	managed, _, err := server.CallTool(ctx, builtin.ToolManageTrafficTransform, map[string]interface{}{
		"action":     "update_scope",
		"binding_id": configuredPayload.Binding.ID,
		"scope": map[string]interface{}{
			"schemes":      []interface{}{"https"},
			"hosts":        []interface{}{"changed.example.test"},
			"methods":      []interface{}{"GET"},
			"pathPrefixes": []interface{}{`/v2/`},
		},
		"priority": 25,
	})
	if err != nil || managed == nil || managed.IsError {
		t.Fatalf("update scope result=%#v err=%v text=%q", managed, err, toolResultText(managed))
	}
	updatedBinding, err = db.GetTrafficTransformBinding(context.Background(), configuredPayload.Binding.ID)
	if err != nil || updatedBinding.Matcher.Hosts[0] != "changed.example.test" || updatedBinding.Priority != 25 {
		t.Fatalf("scope not updated: %#v / %v", updatedBinding, err)
	}

	deletedScope, _, err := server.CallTool(ctx, builtin.ToolManageTrafficTransform, map[string]interface{}{
		"action": "delete_scope", "binding_id": configuredPayload.Binding.ID,
	})
	if err != nil || deletedScope == nil || deletedScope.IsError {
		t.Fatalf("delete scope result=%#v err=%v text=%q", deletedScope, err, toolResultText(deletedScope))
	}
	deletedScript, _, err := server.CallTool(ctx, builtin.ToolManageTrafficTransform, map[string]interface{}{
		"action": "delete_script", "transform_id": configuredPayload.Transform.ID,
	})
	if err != nil || deletedScript == nil || deletedScript.IsError {
		t.Fatalf("delete script result=%#v err=%v text=%q", deletedScript, err, toolResultText(deletedScript))
	}
	visible, err := db.ListTrafficTransformsForConversation(context.Background(), conversation.ID)
	if err != nil || len(visible) != 0 {
		t.Fatalf("deleted script remains visible: %#v / %v", visible, err)
	}
}

func TestTrafficDecoderBodyPreviewIsCompactAndBinarySafe(t *testing.T) {
	textPreview := trafficDecoderBodyPreview([]byte(strings.Repeat("a", 5000)))
	if textPreview["encoding"] != "utf8" || textPreview["truncated"] != true || len(textPreview["data"].(string)) != 4096 {
		t.Fatalf("unexpected text preview: %#v", textPreview)
	}
	binaryPreview := trafficDecoderBodyPreview([]byte{0xff, 0x00, 0x01})
	if binaryPreview["encoding"] != "base64" || binaryPreview["data"] != "/wAB" || binaryPreview["truncated"] != false {
		t.Fatalf("unexpected binary preview: %#v", binaryPreview)
	}
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
	rejected, _, rejectedErr := server.CallTool(ctx, builtin.ToolActivateTrafficTransform, map[string]interface{}{
		"revision_id": createPayload.Revision.ID,
		"mode":        "observe",
		"matcher":     map[string]interface{}{"hosts": []interface{}{}},
	})
	if rejectedErr == nil && (rejected == nil || !rejected.IsError) {
		t.Fatalf("empty host matcher was accepted: result=%#v text=%q", rejected, toolResultText(rejected))
	}
	bindingsBeforeActivation, listErr := db.ListActiveTrafficTransformBindings(context.Background(), conversation.ID)
	if listErr != nil || len(bindingsBeforeActivation) != 0 {
		t.Fatalf("rejected activation created binding: %#v / %v", bindingsBeforeActivation, listErr)
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

	otherDetail, err := db.CreateTrafficTransaction(context.Background(), &traffic.Transaction{
		ConversationID: conversation.ID, RuntimeMode: traffic.RuntimeModeContainer,
		CaptureCoverage: traffic.CaptureCoverageEnforced, Scheme: "https", Host: "other.example.test",
		Port: 443, Method: "POST", Path: "/encrypted", StartedAt: now.Add(time.Second),
	}, []traffic.Message{{
		Stage: traffic.StageUpstreamRequest, Kind: traffic.MessageKindRequest, Method: "POST", Path: "/encrypted",
		Headers: []traffic.Header{{Name: "Content-Type", Value: "application/octet-stream"}},
		Body:    body, BodyEncoding: encoding, BodySHA256: digest, BodyLength: 10, BodyStoredBytes: 10, Complete: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	observeImportedTraffic(context.Background(), db, toolTransformRunner{}, otherDetail, zap.NewNop())
	unmatched, err := db.GetTrafficTransaction(context.Background(), otherDetail.Transaction.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unmatched.Transaction.TransformBindingID != "" || unmatched.Transaction.TransformRevisionID != "" {
		t.Fatalf("non-matching website entered transform runner: %#v", unmatched.Transaction)
	}
	for _, message := range unmatched.Messages {
		if message.Stage == traffic.StageDecodedRequest || message.Stage == traffic.StageDecodedResponse {
			t.Fatalf("non-matching website produced decoded evidence: %#v", unmatched.Messages)
		}
	}
}
