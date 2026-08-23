package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type fakeEgressHealthController struct {
	called int
	spec   containerruntime.RuntimeSpec
	err    error
}

func (f *fakeEgressHealthController) RecoverEgressHealth(_ context.Context, spec containerruntime.RuntimeSpec) error {
	f.called++
	f.spec = spec
	return f.err
}

func TestConversationEgressHealthIsRBACScopedAndManualRecoveryIsAudited(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("egress health", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	spec := handlerInitializationSpec(conversation.ID)
	spec.Security.NetworkMode = containerruntime.NetworkInternal
	spec.EgressGateway = &containerruntime.EgressGatewaySpec{
		Image: containerruntime.ImageReference{Repository: "ghcr.io/example/cyberstrike-egress", Digest: "sha256:" + strings.Repeat("b", 64), Platform: "linux/arm64"},
		Resources: containerruntime.EgressGatewayResources{
			NanoCPUs: 250_000_000, MemoryBytes: 128 << 20, PIDs: 64,
			NoFileSoft: 512, NoFileHard: 1024, TmpfsBytes: 16 << 20,
			LogMaxBytes: 2 << 20, LogMaxFiles: 2,
		},
		BoundarySnapshot: &containerruntime.EgressBoundarySnapshotSpec{
			ID: "12345678-1234-4234-8234-123456789abc", SHA256: "sha256:" + strings.Repeat("c", 64),
		},
	}
	ctx := context.Background()
	if _, _, err := db.Queue(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(ctx, conversation.ID); err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	if _, err := db.Complete(ctx, conversation.ID, containerruntime.Runtime{ID: spec.ID, ProviderID: "provider-health", Status: containerruntime.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	record, err := db.GetContainerInitialization(ctx, conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	paused := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestHealth,
		Decision: egress.ActivityDecisionBlocked, Reason: "waf_challenge", Outcome: "health_paused",
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	if inserted, err := db.ApplyEgressHealthEvent(ctx, database.EgressAuditRuntimeTarget{Record: record, ConversationTitle: conversation.Title}, paused); err != nil || !inserted {
		t.Fatalf("seed paused health = %v, %v", inserted, err)
	}

	controller := &fakeEgressHealthController{}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetEgressHealthController(controller)
	get := performConversationRequest(owner, http.MethodGet, "/api/conversations/"+conversation.ID+"/egress-health", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.GetConversationEgressHealth(c)
	})
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"status":"paused"`) || !strings.Contains(get.Body.String(), `"manualRecoveryRequired":true`) {
		t.Fatalf("get health = %d %s", get.Code, get.Body.String())
	}
	recoverResponse := performConversationRequest(owner, http.MethodPost, "/api/conversations/"+conversation.ID+"/egress-health/recover", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.RecoverConversationEgressHealth(c)
	})
	if recoverResponse.Code != http.StatusOK || controller.called != 1 || controller.spec.ConversationID != conversation.ID {
		t.Fatalf("recover = %d %s controller=%#v", recoverResponse.Code, recoverResponse.Body.String(), controller)
	}
	var recovered database.EgressHealthState
	if err := json.Unmarshal(recoverResponse.Body.Bytes(), &recovered); err != nil || recovered.Status != database.EgressHealthHealthy || recovered.ManualRecoveryRequired {
		t.Fatalf("recovered state = %#v, %v", recovered, err)
	}
	events, err := db.ListEgressAuditEvents(ctx, database.EgressAuditFilter{ConversationID: conversation.ID, EventType: "health", Scope: database.RBACScopeAll, Limit: 10})
	if err != nil || len(events) != 2 || events[0].Outcome != "health_recovered" {
		t.Fatalf("health audits = %#v, %v", events, err)
	}

	other, err := db.CreateRBACUser("egress-health-other", "Other", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	denied := performConversationRequest(other, http.MethodPost, "/api/conversations/"+conversation.ID+"/egress-health/recover", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.RecoverConversationEgressHealth(c)
	})
	if denied.Code != http.StatusForbidden || controller.called != 1 {
		t.Fatalf("foreign recovery = %d %s calls=%d", denied.Code, denied.Body.String(), controller.called)
	}
}

func TestConversationEgressHealthOpenAPIContract(t *testing.T) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/openapi/spec", nil)
	NewOpenAPIHandler(nil, zap.NewNop(), nil, nil).GetOpenAPISpec(c)
	var document map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	paths := document["paths"].(map[string]interface{})
	schemas := document["components"].(map[string]interface{})["schemas"].(map[string]interface{})
	for _, path := range []string{"/api/conversations/{id}/egress-health", "/api/conversations/{id}/egress-health/recover"} {
		if _, ok := paths[path]; !ok {
			t.Fatalf("OpenAPI path %s is missing", path)
		}
	}
	schema, ok := schemas["EgressHealthState"].(map[string]interface{})
	if !ok || schema["additionalProperties"] != false {
		t.Fatalf("EgressHealthState schema = %#v", schema)
	}
}
