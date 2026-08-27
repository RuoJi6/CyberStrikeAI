package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffic"
	"cyberstrike-ai/internal/traffictransform"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type handlerTestTransformRunner struct{}

func (handlerTestTransformRunner) Health(context.Context) (traffictransform.RunnerHealth, error) {
	return traffictransform.RunnerHealth{Status: "ok", ProtocolVersion: traffictransform.ProtocolVersion, RunnerGeneration: "handler-test"}, nil
}

func (handlerTestTransformRunner) LoadRevision(_ context.Context, revision traffictransform.Revision) (traffictransform.LoadResult, error) {
	return traffictransform.LoadResult{
		ProtocolVersion: traffictransform.ProtocolVersion, RevisionID: revision.ID, SourceSHA256: revision.SourceSHA256,
		Valid: true, Hooks: append([]traffictransform.Hook(nil), revision.Hooks...), RunnerGeneration: "handler-test",
	}, nil
}

func (handlerTestTransformRunner) Invoke(_ context.Context, invocation traffictransform.Invocation) (traffictransform.Result, error) {
	message := invocation.Message
	message.Headers = append(message.Headers, traffic.Header{Name: "X-Traffic-Decoded", Value: "true"})
	return traffictransform.Result{
		ProtocolVersion: traffictransform.ProtocolVersion, InvocationID: invocation.InvocationID,
		Action: traffictransform.ActionReplace, Message: &message,
	}, nil
}

func TestTrafficTransformDashboardSeparatesMetadataFromSourceAndConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-transform-dashboard.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	conversation, err := db.CreateConversation("target conversation", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	transform, err := db.CreateTrafficTransform(context.Background(), &traffictransform.Transform{
		ConversationID: conversation.ID, Name: "example decoder", Description: "Agent generated",
		CreatedByAgentID: "agent-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	source := "def decode_request(ctx, wire):\n    return wire  # source-only-marker\n"
	revision, report, err := db.CreateTrafficTransformRevision(context.Background(), &traffictransform.Revision{
		TransformID: transform.ID, Source: source, Hooks: []traffictransform.Hook{traffictransform.HookDecodeRequest},
	}, traffictransform.DefaultRunnerInventory())
	if err != nil {
		t.Fatal(err)
	}
	report.Runner = "handler-test"
	if err := db.SetTrafficTransformRevisionValidation(context.Background(), revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, report); err != nil {
		t.Fatal(err)
	}
	binding, err := db.CreateTrafficTransformBinding(context.Background(), &traffictransform.Binding{
		ConversationID: conversation.ID, TransformID: transform.ID, RevisionID: revision.ID,
		Mode: traffictransform.ModeObserve, Matcher: traffictransform.Matcher{Hosts: []string{"api.example.test"}},
		Config: map[string]any{"key": "config-only-marker"}, Priority: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ActivateTrafficTransformBinding(context.Background(), binding.ID, ""); err != nil {
		t.Fatal(err)
	}

	handler := NewTrafficHandler(db, zap.NewNop())
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/traffic-transforms", nil)
	c.Set(security.ContextSessionKey, security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"traffic_transform:read": true},
	})
	handler.ListTrafficTransformsDashboard(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("dashboard status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, "source-only-marker") || strings.Contains(body, "config-only-marker") {
		t.Fatalf("dashboard leaked source or config: %s", body)
	}
	if !strings.Contains(body, "api.example.test") || !strings.Contains(body, "target conversation") {
		t.Fatalf("dashboard missing matcher or conversation: %s", body)
	}
	var dashboard map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &dashboard); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"scripts", "cases", "conversations", "runs"} {
		if len(dashboard[key]) == 0 {
			t.Fatalf("dashboard missing %s: %s", key, body)
		}
	}

	sourceRecorder := httptest.NewRecorder()
	sourceContext, _ := gin.CreateTestContext(sourceRecorder)
	sourceContext.Request = httptest.NewRequest(http.MethodGet, "/api/traffic-transform-revisions/"+revision.ID+"/source", nil)
	sourceContext.Params = gin.Params{{Key: "id", Value: revision.ID}}
	sourceContext.Set(security.ContextSessionKey, security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"traffic_transform:read": true, "traffic_transform:read_source": true},
	})
	handler.GetTrafficTransformRevisionSource(sourceContext)
	if sourceRecorder.Code != http.StatusOK || !strings.Contains(sourceRecorder.Body.String(), "source-only-marker") {
		t.Fatalf("source response=%d body=%s", sourceRecorder.Code, sourceRecorder.Body.String())
	}
}

func TestManualTrafficTransformValidatesTestsAndActivatesScopedScript(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-transform-manual.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("manual transform", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	transaction := &traffic.Transaction{
		ConversationID: conversation.ID, RuntimeMode: traffic.RuntimeModeContainer, CaptureCoverage: traffic.CaptureCoverageEnforced,
		Scheme: "https", Host: "api.example.test", Port: 443, Method: "GET", Path: "/v1/data", StartedAt: time.Now().UTC(),
	}
	if _, err := db.CreateTrafficTransaction(context.Background(), transaction, []traffic.Message{{
		Stage: traffic.StageClientRequest, Kind: traffic.MessageKindRequest, Method: "GET", Path: "/v1/data", Protocol: "HTTP/1.1",
		Headers: []traffic.Header{{Name: "Accept", Value: "application/json"}}, Complete: true,
	}}); err != nil {
		t.Fatal(err)
	}
	handler := NewTrafficHandler(db, zap.NewNop())
	handler.SetTrafficTransformRunner(handlerTestTransformRunner{})
	payload := map[string]any{
		"conversationId": conversation.ID, "name": "minimal decoder", "transactionId": transaction.ID,
		"direction": "request", "activate": true,
		"source": "from cyberstrike_transform import Message\n\ndef decode_request(ctx, wire: Message) -> Message:\n    return wire.set_header(\"X-Traffic-Decoded\", \"true\")\n",
		"hooks":  []string{"decode_request"}, "matcher": map[string]any{"hosts": []string{"api.example.test"}},
	}
	encoded, _ := json.Marshal(payload)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/traffic-transforms/manual", strings.NewReader(string(encoded)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set(security.ContextSessionKey, security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{
			"traffic_transform:write": true, "traffic_transform:activate_observe": true,
			"traffic:read": true, "traffic:read_sensitive": true,
		},
	})
	handler.CreateManualTrafficTransform(c)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, expected := range []string{`"validation":{"valid":true`, `"roundTripMatched":true`, `"name":"X-Traffic-Decoded"`, `"status":"active"`, `"api.example.test"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("response missing %s: %s", expected, body)
		}
	}
}

func TestTrafficTransformBindingScopeAndStatusControls(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-transform-controls.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("controlled transform", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	transform, err := db.CreateTrafficTransform(context.Background(), &traffictransform.Transform{ConversationID: conversation.ID, Name: "site decoder"})
	if err != nil {
		t.Fatal(err)
	}
	revision, report, err := db.CreateTrafficTransformRevision(context.Background(), &traffictransform.Revision{
		TransformID: transform.ID, Source: "def decode_request(ctx, wire):\n    return wire\n", Hooks: []traffictransform.Hook{traffictransform.HookDecodeRequest},
	}, traffictransform.DefaultRunnerInventory())
	if err != nil {
		t.Fatal(err)
	}
	report.Runner = "handler-test"
	if err := db.SetTrafficTransformRevisionValidation(context.Background(), revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, report); err != nil {
		t.Fatal(err)
	}
	binding, err := db.CreateTrafficTransformBinding(context.Background(), &traffictransform.Binding{
		ConversationID: conversation.ID, TransformID: transform.ID, RevisionID: revision.ID,
		Mode: traffictransform.ModeObserve, Matcher: traffictransform.Matcher{Hosts: []string{"old.example.test"}},
		Config: map[string]any{"secret": "must-not-leak"}, Priority: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err = db.ActivateTrafficTransformBinding(context.Background(), binding.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewTrafficHandler(db, zap.NewNop())
	session := security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"traffic_transform:activate_observe": true},
	}

	requestBody := `{"matcher":{"hosts":["API.Example.Test","api.example.test"],"schemes":["https"],"methods":["post"],"pathPrefixes":["/wechat/api/"],"contentTypes":["application/json"]},"priority":25}`
	updateRecorder := httptest.NewRecorder()
	updateContext, _ := gin.CreateTestContext(updateRecorder)
	updateContext.Request = httptest.NewRequest(http.MethodPut, "/api/traffic-transform-bindings/"+binding.ID+"/scope", strings.NewReader(requestBody))
	updateContext.Request.Header.Set("Content-Type", "application/json")
	updateContext.Params = gin.Params{{Key: "id", Value: binding.ID}}
	updateContext.Set(security.ContextSessionKey, session)
	handler.UpdateTrafficTransformBindingScope(updateContext)
	if updateRecorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updateRecorder.Code, updateRecorder.Body.String())
	}
	if strings.Contains(updateRecorder.Body.String(), "must-not-leak") || strings.Contains(updateRecorder.Body.String(), `"config"`) {
		t.Fatalf("scope response leaked binding config: %s", updateRecorder.Body.String())
	}
	updated, err := db.GetTrafficTransformBinding(context.Background(), binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Priority != 25 || len(updated.Matcher.Hosts) != 1 || updated.Matcher.Hosts[0] != "api.example.test" || len(updated.Matcher.Methods) != 1 || updated.Matcher.Methods[0] != "POST" {
		t.Fatalf("updated binding = %#v", updated)
	}
	if updated.Config["secret"] != "must-not-leak" {
		t.Fatalf("scope update changed config: %#v", updated.Config)
	}

	for _, action := range []struct {
		name       string
		handler    func(*gin.Context)
		wantStatus string
	}{
		{name: "disable", handler: handler.DisableTrafficTransformBinding, wantStatus: traffictransform.BindingDisabled},
		{name: "activate", handler: handler.ActivateTrafficTransformBinding, wantStatus: traffictransform.BindingActive},
	} {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/api/traffic-transform-bindings/"+binding.ID+"/"+action.name, nil)
		ctx.Params = gin.Params{{Key: "id", Value: binding.ID}}
		ctx.Set(security.ContextSessionKey, session)
		action.handler(ctx)
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"`+action.wantStatus+`"`) {
			t.Fatalf("%s status=%d body=%s", action.name, recorder.Code, recorder.Body.String())
		}
	}
	activeDeleteRecorder := httptest.NewRecorder()
	activeDeleteContext, _ := gin.CreateTestContext(activeDeleteRecorder)
	activeDeleteContext.Request = httptest.NewRequest(http.MethodDelete, "/api/traffic-transform-bindings/"+binding.ID, nil)
	activeDeleteContext.Params = gin.Params{{Key: "id", Value: binding.ID}}
	activeDeleteContext.Set(security.ContextSessionKey, session)
	handler.DeleteTrafficTransformBinding(activeDeleteContext)
	if activeDeleteRecorder.Code != http.StatusConflict {
		t.Fatalf("active delete status=%d body=%s", activeDeleteRecorder.Code, activeDeleteRecorder.Body.String())
	}

	emptyRecorder := httptest.NewRecorder()
	emptyContext, _ := gin.CreateTestContext(emptyRecorder)
	emptyContext.Request = httptest.NewRequest(http.MethodPut, "/api/traffic-transform-bindings/"+binding.ID+"/scope", strings.NewReader(`{"matcher":{"hosts":[]}}`))
	emptyContext.Request.Header.Set("Content-Type", "application/json")
	emptyContext.Params = gin.Params{{Key: "id", Value: binding.ID}}
	emptyContext.Set(security.ContextSessionKey, session)
	handler.UpdateTrafficTransformBindingScope(emptyContext)
	if emptyRecorder.Code != http.StatusBadRequest {
		t.Fatalf("empty hosts status=%d body=%s", emptyRecorder.Code, emptyRecorder.Body.String())
	}

	deniedRecorder := httptest.NewRecorder()
	deniedContext, _ := gin.CreateTestContext(deniedRecorder)
	deniedContext.Request = httptest.NewRequest(http.MethodPost, "/api/traffic-transform-bindings/"+binding.ID+"/disable", nil)
	deniedContext.Params = gin.Params{{Key: "id", Value: binding.ID}}
	deniedContext.Set(security.ContextSessionKey, security.Session{
		UserID: "viewer", Scope: database.RBACScopeAssigned,
		Permissions: map[string]bool{"traffic_transform:activate_observe": true},
	})
	handler.DisableTrafficTransformBinding(deniedContext)
	if deniedRecorder.Code != http.StatusNotFound {
		t.Fatalf("unassigned status=%d body=%s", deniedRecorder.Code, deniedRecorder.Body.String())
	}

	disableRecorder := httptest.NewRecorder()
	disableContext, _ := gin.CreateTestContext(disableRecorder)
	disableContext.Request = httptest.NewRequest(http.MethodPost, "/api/traffic-transform-bindings/"+binding.ID+"/disable", nil)
	disableContext.Params = gin.Params{{Key: "id", Value: binding.ID}}
	disableContext.Set(security.ContextSessionKey, session)
	handler.DisableTrafficTransformBinding(disableContext)
	if disableRecorder.Code != http.StatusOK {
		t.Fatalf("disable before delete status=%d body=%s", disableRecorder.Code, disableRecorder.Body.String())
	}

	deleteRecorder := httptest.NewRecorder()
	deleteContext, _ := gin.CreateTestContext(deleteRecorder)
	deleteContext.Request = httptest.NewRequest(http.MethodDelete, "/api/traffic-transform-bindings/"+binding.ID, nil)
	deleteContext.Params = gin.Params{{Key: "id", Value: binding.ID}}
	deleteContext.Set(security.ContextSessionKey, session)
	handler.DeleteTrafficTransformBinding(deleteContext)
	if deleteContext.Writer.Status() != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", deleteContext.Writer.Status(), deleteRecorder.Body.String())
	}
	if _, err := db.GetTrafficTransformBinding(context.Background(), binding.ID); err == nil {
		t.Fatal("deleted binding still exists")
	}
}

func TestCreateTrafficTransformBindingForExistingScript(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-transform-create-binding.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("new scope target", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeHost})
	if err != nil {
		t.Fatal(err)
	}
	transform, err := db.CreateTrafficTransform(context.Background(), &traffictransform.Transform{
		ConversationID: conversation.ID, Name: "existing decoder",
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
	if err := db.SetTrafficTransformRevisionValidation(context.Background(), revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, report); err != nil {
		t.Fatal(err)
	}
	transform, err = db.PromoteTrafficTransformRevision(context.Background(), transform.ID, revision.ID, transform.Name, transform.Description)
	if err != nil {
		t.Fatal(err)
	}

	handler := NewTrafficHandler(db, zap.NewNop())
	payload := `{"transformId":"` + transform.ID + `","conversationId":"` + conversation.ID + `","matcher":{"hosts":["API.Example.Test"],"schemes":["https"],"methods":["post"],"pathPrefixes":["/wechat/api/"]},"priority":25,"activate":true}`
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/traffic-transform-bindings", strings.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set(security.ContextSessionKey, security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"traffic_transform:activate_observe": true},
	})
	handler.CreateTrafficTransformBinding(c)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create binding status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"status":"active"`) || !strings.Contains(recorder.Body.String(), `"hosts":["api.example.test"]`) {
		t.Fatalf("unexpected create binding response: %s", recorder.Body.String())
	}
	bindings, err := db.ListActiveTrafficTransformBindings(context.Background(), conversation.ID)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("active bindings=%#v err=%v", bindings, err)
	}
	if bindings[0].RevisionID != transform.CurrentRevisionID || bindings[0].Priority != 25 || bindings[0].Matcher.Methods[0] != "POST" {
		t.Fatalf("created binding=%#v", bindings[0])
	}
}

func TestTrafficTransformScriptCanCreateRevisionAndSoftDelete(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-transform-script-edit.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	conversation, _ := db.CreateConversation("script edit", database.ConversationCreateMeta{})
	transform, _ := db.CreateTrafficTransform(ctx, &traffictransform.Transform{ConversationID: conversation.ID, Name: "editable codec"})
	oldSource := "def decode_request(ctx, wire):\n    return wire\n"
	revision, report, err := db.CreateTrafficTransformRevision(ctx, &traffictransform.Revision{
		TransformID: transform.ID, Source: oldSource, Hooks: []traffictransform.Hook{traffictransform.HookDecodeRequest},
	}, traffictransform.DefaultRunnerInventory())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetTrafficTransformRevisionValidation(ctx, revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, report); err != nil {
		t.Fatal(err)
	}
	transform, err = db.PromoteTrafficTransformRevision(ctx, transform.ID, revision.ID, transform.Name, transform.Description)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewTrafficHandler(db, zap.NewNop())
	handler.SetTrafficTransformRunner(handlerTestTransformRunner{})
	session := security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"traffic_transform:write": true, "traffic_transform:read_source": true},
	}
	newSource := "def decode_request(ctx, wire):\n    return wire.set_header(\"X-Edited\", \"true\")\n"
	payload, _ := json.Marshal(map[string]any{
		"baseRevisionId": revision.ID, "name": "edited codec", "description": "new revision", "source": newSource,
	})
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/traffic-transforms/"+transform.ID, strings.NewReader(string(payload)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: transform.ID}}
	c.Set(security.ContextSessionKey, session)
	handler.UpdateTrafficTransform(c)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"name":"edited codec"`) {
		t.Fatalf("edit status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	updated, err := db.GetTrafficTransform(ctx, transform.ID)
	if err != nil || updated.CurrentRevisionID == revision.ID || updated.Name != "edited codec" {
		t.Fatalf("updated transform = %#v / %v", updated, err)
	}
	newRevision, err := db.GetTrafficTransformRevision(ctx, updated.CurrentRevisionID)
	if err != nil || newRevision.Source != newSource || newRevision.ValidationStatus != traffictransform.ValidationPassed {
		t.Fatalf("new revision = %#v / %v", newRevision, err)
	}

	deleteRecorder := httptest.NewRecorder()
	deleteContext, _ := gin.CreateTestContext(deleteRecorder)
	deleteContext.Request = httptest.NewRequest(http.MethodDelete, "/api/traffic-transforms/"+transform.ID, nil)
	deleteContext.Params = gin.Params{{Key: "id", Value: transform.ID}}
	deleteContext.Set(security.ContextSessionKey, session)
	handler.DeleteTrafficTransform(deleteContext)
	if deleteContext.Writer.Status() != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", deleteContext.Writer.Status(), deleteRecorder.Body.String())
	}
	visible, err := db.ListTrafficTransforms(ctx, 10)
	if err != nil || len(visible) != 0 {
		t.Fatalf("visible after soft delete = %#v / %v", visible, err)
	}
	if _, err := db.GetTrafficTransformRevision(ctx, updated.CurrentRevisionID); err != nil {
		t.Fatalf("current revision was deleted with script: %v", err)
	}
}
