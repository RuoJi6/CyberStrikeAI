package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type fakeEgressActivityStreamer struct {
	events   []egress.ActivityEvent
	err      error
	tail     int
	called   int
	seenSpec containerruntime.RuntimeSpec
}

func (f *fakeEgressActivityStreamer) StreamEgressActivity(_ context.Context, spec containerruntime.RuntimeSpec, options containerruntime.ActivityStreamOptions, sink containerruntime.RuntimeActivitySink) error {
	f.called++
	f.tail = options.Tail
	f.seenSpec = spec
	for _, event := range f.events {
		if err := sink(event); err != nil {
			return err
		}
	}
	return f.err
}

func TestConversationEgressActivitySSEIsRBACScopedAndCredentialFree(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("activity conversation", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	spec := handlerInitializationSpec(conversation.ID)
	spec.Security.NetworkMode = containerruntime.NetworkInternal
	spec.EgressGateway = &containerruntime.EgressGatewaySpec{
		Image:            containerruntime.ImageReference{Repository: "gateway", Digest: "sha256:" + strings.Repeat("b", 64), Platform: "linux/arm64"},
		Resources:        containerruntime.EgressGatewayResources{NanoCPUs: 1, MemoryBytes: 2, PIDs: 3, NoFileSoft: 4, NoFileHard: 5, TmpfsBytes: 6, LogMaxBytes: 7, LogMaxFiles: 8},
		BoundarySnapshot: &containerruntime.EgressBoundarySnapshotSpec{ID: "12345678-1234-1234-1234-123456789abc", SHA256: "sha256:" + strings.Repeat("c", 64)},
	}
	record := containerruntime.InitializationRecord{ConversationID: conversation.ID, RuntimeID: spec.ID, Status: containerruntime.InitializationCreated, RuntimeStatus: containerruntime.StatusRunning, Spec: spec}
	streamer := &fakeEgressActivityStreamer{events: []egress.ActivityEvent{{
		Event: egress.ActivityEventName, Timestamp: time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC), RequestType: egress.ActivityRequestHTTP,
		Domain: "allowed.example", Port: 80, Decision: egress.ActivityDecisionAllowed, RuleID: "visit-1", Reason: "allow-visit",
		Method: http.MethodGet, Path: "/safe", HTTPStatus: 200, Outcome: "completed", SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}}}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerInitializationProvider(fakeContainerInitializationProvider{record: record})
	handler.SetEgressActivityStreamer(streamer)

	response := performEgressActivityRequest(owner, conversation.ID, "/api/conversations/"+conversation.ID+"/egress-activity/stream?tail=37", handler)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/event-stream; charset=utf-8" {
		t.Fatalf("status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{"event: ready", "event: activity", `"conversationId":"` + conversation.ID + `"`, `"agent":"container-agent"`, `"tool":""`, `"domain":"allowed.example"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q in %s", expected, body)
		}
	}
	for _, forbidden := range []string{"provider-gateway-secret", "Authorization", "private-token"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("SSE leaked %q: %s", forbidden, body)
		}
	}
	if streamer.called != 1 || streamer.tail != 37 || streamer.seenSpec.ConversationID != conversation.ID {
		t.Fatalf("stream call = %#v", streamer)
	}

	other, err := db.CreateRBACUser("activity-other", "Other", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	denied := performEgressActivityRequest(other, conversation.ID, "/api/conversations/"+conversation.ID+"/egress-activity/stream", handler)
	if denied.Code != http.StatusForbidden || streamer.called != 1 {
		t.Fatalf("foreign status=%d calls=%d body=%s", denied.Code, streamer.called, denied.Body.String())
	}
}

func TestConversationEgressActivityReturnsOnlySafeStreamErrorCode(t *testing.T) {
	if got := safeEgressActivityStreamError(errors.New("provider id secret password")); got != "unavailable" {
		t.Fatalf("safe error = %q", got)
	}
	if got := safeEgressActivityStreamError(containerruntime.ErrRuntimeStateConflict); got != "runtime_drift" {
		t.Fatalf("drift error = %q", got)
	}
}

func TestConversationEgressActivityOpenAPIContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/api/openapi/spec", nil)
	NewOpenAPIHandler(nil, zap.NewNop(), nil, nil).GetOpenAPISpec(context)
	var document struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if _, ok := document.Paths["/api/conversations/{id}/egress-activity/stream"]; !ok {
		t.Fatal("egress activity SSE path missing")
	}
}

func performEgressActivityRequest(user *database.RBACUser, conversationID, path string, handler *ConversationHandler) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, path, nil)
	context.Params = gin.Params{{Key: "id", Value: conversationID}}
	context.Set(security.ContextSessionKey, security.Session{UserID: user.ID, Username: user.Username, Scope: database.RBACScopeAssigned, Permissions: map[string]bool{"chat:read": true}})
	handler.StreamConversationEgressActivity(context)
	return recorder
}
