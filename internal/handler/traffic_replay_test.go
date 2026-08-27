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

func TestTrafficReplayUsesOriginalConversationBoundaryAndSameOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-replay.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("replay", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	body, encoding, _ := traffic.EncodeBody([]byte("hello"))
	item := &traffic.Transaction{
		ConversationID: conversation.ID, RuntimeMode: traffic.RuntimeModeContainer,
		CaptureCoverage: traffic.CaptureCoverageEnforced, Scheme: "https", Host: "api.example.test", Port: 443,
		Method: "POST", Path: "/v1/original", StartedAt: time.Now().UTC(),
	}
	if _, err := db.CreateTrafficTransaction(context.Background(), item, []traffic.Message{{
		Stage: traffic.StageClientRequest, Kind: traffic.MessageKindRequest, Method: "POST", Path: "/v1/original", Protocol: "HTTP/1.1",
		Headers: []traffic.Header{{Name: "Content-Type", Value: "text/plain"}}, Body: body, BodyEncoding: encoding,
		BodyLength: 5, BodyStoredBytes: 5, Complete: true,
	}}); err != nil {
		t.Fatal(err)
	}

	handler := NewTrafficHandler(db, zap.NewNop())
	var gotConversation string
	var gotCommand []string
	handler.SetTrafficReplayExecutor(func(_ context.Context, conversationID string, request security.ExecutionRequest) (security.ExecutionResult, error) {
		gotConversation = conversationID
		gotCommand = append([]string(nil), request.Command...)
		return security.ExecutionResult{Output: "HTTP/1.1 201 Created\r\n\r\nok\n__CYBERSTRIKE_REPLAY_STATUS__:201\n", Location: "container"}, nil
	})
	payload, _ := json.Marshal(trafficReplayRequest{
		Method: "PATCH", URL: "https://api.example.test/v1/changed?x=1",
		Headers: []traffic.Header{{Name: "Content-Type", Value: "application/json"}}, Body: `{"ok":true}`,
	})
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/traffic-transactions/"+item.ID+"/replay", strings.NewReader(string(payload)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: item.ID}}
	c.Set(security.ContextSessionKey, security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"traffic:replay": true, "traffic:read_sensitive": true},
	})
	handler.Replay(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if gotConversation != conversation.ID {
		t.Fatalf("conversation=%q want %q", gotConversation, conversation.ID)
	}
	command := strings.Join(gotCommand, "\x00")
	for _, wanted := range []string{"curl", "PATCH", "https://api.example.test/v1/changed?x=1", `{"ok":true}`} {
		if !strings.Contains(command, wanted) {
			t.Fatalf("command missing %q: %#v", wanted, gotCommand)
		}
	}
	if !strings.Contains(recorder.Body.String(), `"executionLocation":"container"`) || !strings.Contains(recorder.Body.String(), `"httpStatus":201`) {
		t.Fatalf("response=%s", recorder.Body.String())
	}
}

func TestTrafficReplayRejectsCrossOriginTarget(t *testing.T) {
	transaction := traffic.Transaction{Scheme: "https", Host: "api.example.test", Port: 443}
	if _, err := validateTrafficReplayTarget(transaction, "https://other.example.test/path"); err == nil {
		t.Fatal("cross-origin replay target unexpectedly accepted")
	}
	if _, err := validateTrafficReplayTarget(transaction, "https://api.example.test:8443/path"); err == nil {
		t.Fatal("cross-port replay target unexpectedly accepted")
	}
	if target, err := validateTrafficReplayTarget(transaction, "https://api.example.test/path?q=1"); err != nil || target.Path != "/path" {
		t.Fatalf("same-origin target=%#v err=%v", target, err)
	}
}

func TestTrafficReplayAppliesFirstMatchingTransformBeforeSending(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-replay-transform.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("transform replay", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	body, encoding, digest := traffic.EncodeBody([]byte(`{"cipher":"value"}`))
	item := &traffic.Transaction{
		ConversationID: conversation.ID, RuntimeMode: traffic.RuntimeModeContainer,
		CaptureCoverage: traffic.CaptureCoverageEnforced, Scheme: "https", Host: "api.example.test", Port: 443,
		Method: "POST", Path: "/v1/original", StartedAt: time.Now().UTC(),
	}
	if _, err := db.CreateTrafficTransaction(context.Background(), item, []traffic.Message{{
		Stage: traffic.StageClientRequest, Kind: traffic.MessageKindRequest, Method: "POST", Path: item.Path, Protocol: "HTTP/1.1",
		Headers: []traffic.Header{{Name: "Content-Type", Value: "application/json"}}, Body: body, BodyEncoding: encoding,
		BodySHA256: digest, BodyLength: int64(len(`{"cipher":"value"}`)), BodyStoredBytes: int64(len(`{"cipher":"value"}`)), Complete: true,
	}}); err != nil {
		t.Fatal(err)
	}
	transform, err := db.CreateTrafficTransform(context.Background(), &traffictransform.Transform{ConversationID: conversation.ID, Name: "replay-codec"})
	if err != nil {
		t.Fatal(err)
	}
	revision, report, err := db.CreateTrafficTransformRevision(context.Background(), &traffictransform.Revision{
		TransformID: transform.ID, Source: "def encode_request(ctx, message, original_wire):\n    return message\n",
		Hooks: []traffictransform.Hook{traffictransform.HookEncodeRequest},
	}, traffictransform.DefaultRunnerInventory())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetTrafficTransformRevisionValidation(context.Background(), revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, report); err != nil {
		t.Fatal(err)
	}
	binding, err := db.CreateTrafficTransformBinding(context.Background(), &traffictransform.Binding{
		ConversationID: conversation.ID, TransformID: transform.ID, RevisionID: revision.ID,
		Mode: traffictransform.ModeObserve, Matcher: traffictransform.Matcher{
			Schemes: []string{"https"}, Hosts: []string{"api.example.test"}, Methods: []string{"POST"}, PathPrefixes: []string{"/v1/"},
		}, Priority: 10, FailurePolicy: traffictransform.FailurePolicyContinue,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ActivateTrafficTransformBinding(context.Background(), binding.ID, ""); err != nil {
		t.Fatal(err)
	}

	handler := NewTrafficHandler(db, zap.NewNop())
	handler.SetTrafficTransformRunner(handlerTestTransformRunner{})
	var gotCommand []string
	handler.SetTrafficReplayExecutor(func(_ context.Context, _ string, request security.ExecutionRequest) (security.ExecutionResult, error) {
		gotCommand = append([]string(nil), request.Command...)
		return security.ExecutionResult{Output: "HTTP/1.1 200 OK\r\n\r\nok\n__CYBERSTRIKE_REPLAY_STATUS__:200\n", Location: "container"}, nil
	})
	payload, _ := json.Marshal(trafficReplayRequest{
		Method: "POST", URL: "https://api.example.test/v1/changed",
		Headers: []traffic.Header{{Name: "Content-Type", Value: "application/json"}}, Body: `{"cipher":"changed"}`,
	})
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/traffic-transactions/"+item.ID+"/replay", strings.NewReader(string(payload)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: item.ID}}
	c.Set(security.ContextSessionKey, security.Session{
		UserID: "admin", Scope: database.RBACScopeAll,
		Permissions: map[string]bool{"traffic:replay": true, "traffic:read_sensitive": true},
	})
	handler.Replay(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	command := strings.Join(gotCommand, "\x00")
	if !strings.Contains(command, "X-Traffic-Decoded: true") {
		t.Fatalf("matched transform header missing from command: %#v", gotCommand)
	}
	attribution := "X-Cyberstrike-Execution-Id: " + trafficReplayTransformAttributionPrefix + binding.ID + ":" + revision.ID
	if !strings.Contains(command, attribution) {
		t.Fatalf("internal replay attribution missing from command: %#v", gotCommand)
	}
	if !strings.Contains(recorder.Body.String(), `"applied":true`) || !strings.Contains(recorder.Body.String(), `"transformName":"replay-codec"`) {
		t.Fatalf("response does not report matched transform: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"strategy":"inline"`) {
		t.Fatalf("response does not report inline strategy: %s", recorder.Body.String())
	}
	var runCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM traffic_transform_runs WHERE transaction_id = ? AND mode = 'inline'`, item.ID).Scan(&runCount); err != nil || runCount != 1 {
		t.Fatalf("inline replay runs=%d err=%v", runCount, err)
	}
}

func TestReplayTransformAttributionDecoratesCapturedTransaction(t *testing.T) {
	item := traffic.Transaction{ExecutionID: trafficReplayTransformAttributionPrefix + "binding-1:revision-1"}
	decorateReplayTransformTransaction(&item)
	if item.TransformBindingID != "binding-1" || item.TransformRevisionID != "revision-1" || item.TransformResult != "replay_applied" {
		t.Fatalf("decorated transaction=%#v", item)
	}
	if err := validateTrafficReplayHeaders([]traffic.Header{{Name: "X-Cyberstrike-Execution-Id", Value: "spoof"}}); err == nil {
		t.Fatal("user-controlled internal replay attribution unexpectedly accepted")
	}
}

func TestTrafficReplayObservesDecoderWithoutEncoderAndSendsOriginalWire(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-replay-no-encoder.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("decoder only", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeHost})
	if err != nil {
		t.Fatal(err)
	}
	item := &traffic.Transaction{
		ConversationID: conversation.ID, RuntimeMode: traffic.RuntimeModeHost, CaptureCoverage: traffic.CaptureCoverageBestEffort,
		Scheme: "https", Host: "api.example.test", Port: 443, Method: "GET", Path: "/safe", StartedAt: time.Now().UTC(),
	}
	if _, err := db.CreateTrafficTransaction(context.Background(), item, []traffic.Message{{
		Stage: traffic.StageClientRequest, Kind: traffic.MessageKindRequest, Method: "GET", Path: "/safe", Protocol: "HTTP/1.1", Complete: true,
	}}); err != nil {
		t.Fatal(err)
	}
	transform, _ := db.CreateTrafficTransform(context.Background(), &traffictransform.Transform{ConversationID: conversation.ID, Name: "decoder-only"})
	revision, report, err := db.CreateTrafficTransformRevision(context.Background(), &traffictransform.Revision{
		TransformID: transform.ID, Source: "def decode_request(ctx, wire):\n    return wire\n", Hooks: []traffictransform.Hook{traffictransform.HookDecodeRequest},
	}, traffictransform.DefaultRunnerInventory())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetTrafficTransformRevisionValidation(context.Background(), revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, report); err != nil {
		t.Fatal(err)
	}
	binding, err := db.CreateTrafficTransformBinding(context.Background(), &traffictransform.Binding{
		ConversationID: conversation.ID, TransformID: transform.ID, RevisionID: revision.ID, Mode: traffictransform.ModeObserve,
		Matcher: traffictransform.Matcher{Hosts: []string{"api.example.test"}}, Priority: 1, FailurePolicy: traffictransform.FailurePolicyContinue,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ActivateTrafficTransformBinding(context.Background(), binding.ID, ""); err != nil {
		t.Fatal(err)
	}
	handler := NewTrafficHandler(db, zap.NewNop())
	handler.SetTrafficTransformRunner(handlerTestTransformRunner{})
	executed := false
	var gotCommand []string
	handler.SetTrafficReplayExecutor(func(_ context.Context, _ string, request security.ExecutionRequest) (security.ExecutionResult, error) {
		executed = true
		gotCommand = append([]string(nil), request.Command...)
		return security.ExecutionResult{Output: "HTTP/1.1 200 OK\r\n\r\nok\n__CYBERSTRIKE_REPLAY_STATUS__:200\n", Location: "host"}, nil
	})
	payload, _ := json.Marshal(trafficReplayRequest{Method: "GET", URL: "https://api.example.test/safe"})
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/replay", strings.NewReader(string(payload)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: item.ID}}
	c.Set(security.ContextSessionKey, security.Session{UserID: "admin", Scope: database.RBACScopeAll, Permissions: map[string]bool{"traffic:replay": true, "traffic:read_sensitive": true}})
	handler.Replay(c)
	if recorder.Code != http.StatusOK || !executed {
		t.Fatalf("status=%d executed=%v body=%s", recorder.Code, executed, recorder.Body.String())
	}
	command := strings.Join(gotCommand, "\x00")
	if strings.Contains(command, "X-Traffic-Decoded: true") {
		t.Fatalf("observe decoder output unexpectedly changed replay wire: %#v", gotCommand)
	}
	attribution := "X-Cyberstrike-Execution-Id: " + trafficReplayTransformAttributionPrefix + binding.ID + ":" + revision.ID
	if !strings.Contains(command, attribution) {
		t.Fatalf("observe replay attribution missing from command: %#v", gotCommand)
	}
	if !strings.Contains(recorder.Body.String(), `"applied":true`) || !strings.Contains(recorder.Body.String(), `"strategy":"observe"`) {
		t.Fatalf("response does not report observe strategy: %s", recorder.Body.String())
	}
	var runCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM traffic_transform_runs WHERE transaction_id = ? AND mode = 'observe' AND hook = 'decode_request'`, item.ID).Scan(&runCount); err != nil || runCount != 1 {
		t.Fatalf("observe replay runs=%d err=%v", runCount, err)
	}
}

func TestTrafficReplayBlocksMutationWithoutEncoder(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-replay-mutate-no-encoder.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("unsafe mutation", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeHost})
	if err != nil {
		t.Fatal(err)
	}
	item := &traffic.Transaction{
		ConversationID: conversation.ID, RuntimeMode: traffic.RuntimeModeHost, CaptureCoverage: traffic.CaptureCoverageBestEffort,
		Scheme: "https", Host: "api.example.test", Port: 443, Method: "POST", Path: "/unsafe", StartedAt: time.Now().UTC(),
	}
	body, encoding, digest := traffic.EncodeBody([]byte("ciphertext"))
	if _, err := db.CreateTrafficTransaction(context.Background(), item, []traffic.Message{{
		Stage: traffic.StageClientRequest, Kind: traffic.MessageKindRequest, Method: "POST", Path: "/unsafe", Protocol: "HTTP/1.1",
		Body: body, BodyEncoding: encoding, BodySHA256: digest, BodyLength: 10, BodyStoredBytes: 10, Complete: true,
	}}); err != nil {
		t.Fatal(err)
	}
	transform, err := db.CreateTrafficTransform(context.Background(), &traffictransform.Transform{ConversationID: conversation.ID, Name: "unsafe-mutator"})
	if err != nil {
		t.Fatal(err)
	}
	revision, report, err := db.CreateTrafficTransformRevision(context.Background(), &traffictransform.Revision{
		TransformID: transform.ID,
		Source:      "def decode_request(ctx, wire):\n    return wire\n\ndef mutate_request(ctx, message):\n    return message\n",
		Hooks:       []traffictransform.Hook{traffictransform.HookDecodeRequest, traffictransform.HookMutateRequest},
	}, traffictransform.DefaultRunnerInventory())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetTrafficTransformRevisionValidation(context.Background(), revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, report); err != nil {
		t.Fatal(err)
	}
	binding, err := db.CreateTrafficTransformBinding(context.Background(), &traffictransform.Binding{
		ConversationID: conversation.ID, TransformID: transform.ID, RevisionID: revision.ID, Mode: traffictransform.ModeObserve,
		Matcher: traffictransform.Matcher{Hosts: []string{"api.example.test"}}, Priority: 1, FailurePolicy: traffictransform.FailurePolicyContinue,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ActivateTrafficTransformBinding(context.Background(), binding.ID, ""); err != nil {
		t.Fatal(err)
	}
	handler := NewTrafficHandler(db, zap.NewNop())
	handler.SetTrafficTransformRunner(handlerTestTransformRunner{})
	executed := false
	handler.SetTrafficReplayExecutor(func(_ context.Context, _ string, _ security.ExecutionRequest) (security.ExecutionResult, error) {
		executed = true
		return security.ExecutionResult{}, nil
	})
	payload, _ := json.Marshal(trafficReplayRequest{Method: "POST", URL: "https://api.example.test/unsafe", Body: "ciphertext"})
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/replay", strings.NewReader(string(payload)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: item.ID}}
	c.Set(security.ContextSessionKey, security.Session{UserID: "admin", Scope: database.RBACScopeAll, Permissions: map[string]bool{"traffic:replay": true, "traffic:read_sensitive": true}})
	handler.Replay(c)
	if recorder.Code != http.StatusUnprocessableEntity || executed || !strings.Contains(recorder.Body.String(), "mutate_request") || !strings.Contains(recorder.Body.String(), "encode_request") {
		t.Fatalf("status=%d executed=%v body=%s", recorder.Code, executed, recorder.Body.String())
	}
}
