package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type fakeConversationContainerLifecycle struct {
	record          containerruntime.InitializationRecord
	err             error
	action          string
	conversationID  string
	removeWorkspace bool
	deleteCalls     int
	rebuild         func(context.Context, string) (containerruntime.InitializationRecord, error)
	actions         []string
}

type fakeConversationContainerInitializationStarter struct {
	record containerruntime.InitializationRecord
	err    error
	calls  int
}

func (f *fakeConversationContainerInitializationStarter) StartConversationAsync(_ context.Context, _ string) (containerruntime.InitializationRecord, error) {
	f.calls++
	return f.record, f.err
}

func (f *fakeConversationContainerLifecycle) call(_ context.Context, action, conversationID string) (containerruntime.InitializationRecord, error) {
	f.action = action
	f.actions = append(f.actions, action)
	f.conversationID = conversationID
	return f.record, f.err
}

func (f *fakeConversationContainerLifecycle) Start(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	return f.call(ctx, "start", id)
}

func (f *fakeConversationContainerLifecycle) Stop(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	return f.call(ctx, "stop", id)
}

func (f *fakeConversationContainerLifecycle) Rebuild(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	if f.rebuild != nil {
		f.action = "rebuild"
		f.actions = append(f.actions, "rebuild")
		f.conversationID = id
		return f.rebuild(ctx, id)
	}
	return f.call(ctx, "rebuild", id)
}

func (f *fakeConversationContainerLifecycle) Delete(_ context.Context, id string, removeWorkspace bool) error {
	f.action = "delete"
	f.conversationID = id
	f.removeWorkspace = removeWorkspace
	f.deleteCalls++
	return f.err
}

func (f *fakeConversationContainerLifecycle) Reconcile(ctx context.Context, id string) (containerruntime.InitializationRecord, error) {
	return f.call(ctx, "reconcile", id)
}

func TestConversationContainerLifecycleIsRBACScopedAndSanitized(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("container lifecycle", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", conversation.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	controller := &fakeConversationContainerLifecycle{record: containerruntime.InitializationRecord{
		ConversationID: conversation.ID, RuntimeStatus: containerruntime.StatusRunning,
		LifecycleOperation: containerruntime.LifecycleOperationStart, LifecycleState: containerruntime.LifecycleIdle,
	}}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerLifecycleController(controller)

	response := performConversationRequest(owner, http.MethodPost, "/api/conversations/"+conversation.ID+"/container/start", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.StartConversationContainer(c)
	})
	if response.Code != http.StatusOK || controller.action != "start" || controller.conversationID != conversation.ID {
		t.Fatalf("start response=%d %s call=%s/%s", response.Code, response.Body.String(), controller.action, controller.conversationID)
	}
	if _, err := db.GetConversationBoundarySnapshot(context.Background(), conversation.ID); err != nil {
		t.Fatalf("start did not bind boundary snapshot first: %v", err)
	}
	conversationEgress, err := db.GetConversationEgressBinding(context.Background(), conversation.ID)
	if err != nil || conversationEgress.State != database.ConversationEgressStateActive || conversationEgress.Mode != database.ConversationEgressModeNone {
		t.Fatalf("start did not bind upstream egress first: %#v / %v", conversationEgress, err)
	}

	other, err := db.CreateRBACUser("container-lifecycle-other", "Other", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	controller.action = ""
	response = performConversationRequest(other, http.MethodPost, "/api/conversations/"+conversation.ID+"/container/stop", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.StopConversationContainer(c)
	})
	if response.Code != http.StatusForbidden || controller.action != "" {
		t.Fatalf("foreign response=%d %s call=%s", response.Code, response.Body.String(), controller.action)
	}

	controller.err = errors.New("secret engine path /var/run/docker.sock")
	response = performConversationRequest(owner, http.MethodPost, "/api/conversations/"+conversation.ID+"/container/start", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.StartConversationContainer(c)
	})
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "/var/run/docker.sock") {
		t.Fatalf("unsanitized failure=%d %s", response.Code, response.Body.String())
	}
}

func TestConversationContainerManualStartRecreatesDeletedRuntime(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("recreate deleted runtime", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	starter := &fakeConversationContainerInitializationStarter{record: containerruntime.InitializationRecord{
		ConversationID: conversation.ID,
		Status:         containerruntime.InitializationQueued,
	}}
	controller := &fakeConversationContainerLifecycle{}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerInitializationProvider(db)
	handler.SetContainerInitializationStarter(starter)
	handler.SetContainerLifecycleController(controller)

	response := performConversationRequest(owner, http.MethodPost, "/api/conversations/"+conversation.ID+"/container/start", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.StartConversationContainer(c)
	})
	if response.Code != http.StatusOK || starter.calls != 1 || controller.action != "" {
		t.Fatalf("start response=%d %s starter=%d lifecycle=%s", response.Code, response.Body.String(), starter.calls, controller.action)
	}
}

func TestConversationContainerStartFailsClosedBeforeControllerWhenEgressBindingFails(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("egress binding failure", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", conversation.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE conversation_egress_bindings`); err != nil {
		t.Fatal(err)
	}
	controller := &fakeConversationContainerLifecycle{}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerLifecycleController(controller)
	response := performConversationRequest(owner, http.MethodPost, "/api/conversations/"+conversation.ID+"/container/start", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.StartConversationContainer(c)
	})
	if response.Code != http.StatusInternalServerError || controller.action != "" {
		t.Fatalf("response=%d %s controller=%s", response.Code, response.Body.String(), controller.action)
	}
	if _, err := db.GetConversationBoundarySnapshot(context.Background(), conversation.ID); !errors.Is(err, database.ErrConversationBoundarySnapshotNotFound) {
		t.Fatalf("boundary froze after egress failure: %v", err)
	}
}

func TestDeleteConversationContainerReportsWorkspacePolicy(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("delete runtime", database.ConversationCreateMeta{
		RuntimeMode:   database.ConversationRuntimeModeContainer,
		WorkspaceMode: database.ConversationWorkspaceModeEphemeral,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	controller := &fakeConversationContainerLifecycle{}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerLifecycleController(controller)

	response := performConversationRequest(owner, http.MethodDelete, "/api/conversations/"+conversation.ID+"/container?remove_workspace=true", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		c.Request.URL.RawQuery = "remove_workspace=true"
		handler.DeleteConversationContainer(c)
	})
	if response.Code != http.StatusOK || controller.action != "delete" || !controller.removeWorkspace {
		t.Fatalf("delete response=%d %s call=%s remove=%v", response.Code, response.Body.String(), controller.action, controller.removeWorkspace)
	}
	var ephemeral map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &ephemeral); err != nil {
		t.Fatal(err)
	}
	if ephemeral["workspacePersistent"] != false || ephemeral["workspaceDeleted"] != true || !strings.Contains(ephemeral["workspaceDeletionWarning"].(string), "删除容器会永久删除") {
		t.Fatalf("ephemeral response = %#v", ephemeral)
	}

	persistent, err := db.CreateConversation("persistent runtime", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", persistent.ID); err != nil {
		t.Fatal(err)
	}
	controller = &fakeConversationContainerLifecycle{}
	handler.SetContainerLifecycleController(controller)
	response = performConversationRequest(owner, http.MethodDelete, "/api/conversations/"+persistent.ID+"/container", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: persistent.ID}}
		handler.DeleteConversationContainer(c)
	})
	var retained map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &retained); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || controller.removeWorkspace || retained["workspacePersistent"] != true || retained["workspaceRetained"] != true || retained["workspaceDeleted"] != false {
		t.Fatalf("persistent response=%d %#v", response.Code, retained)
	}
}

func TestConversationContainerLifecycleMapsStateConflict(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("conflict runtime", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	controller := &fakeConversationContainerLifecycle{err: containerruntime.ErrRuntimeStateConflict}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerLifecycleController(controller)
	response := performConversationRequest(owner, http.MethodPost, "/api/conversations/"+conversation.ID+"/container/rebuild", nil, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.RebuildConversationContainer(c)
	})
	if response.Code != http.StatusConflict {
		t.Fatalf("conflict response=%d %s", response.Code, response.Body.String())
	}
}

func TestConversationContainerBoundaryChangeRequiresSuccessfulExplicitRebuild(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	ctx := context.Background()
	oldPolicy, err := db.CreateBoundaryPolicy(ctx, database.BoundaryPolicy{ID: "lifecycle-old-policy", Name: "Old", OwnerUserID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	newPolicy, err := db.CreateBoundaryPolicy(ctx, database.BoundaryPolicy{ID: "lifecycle-new-policy", Name: "New", OwnerUserID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := db.CreateConversation("boundary rebuild", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer, BoundaryPolicyID: oldPolicy.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	initial, err := db.EnsureConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	spec := handlerBoundaryRuntimeSpec(conversation.ID)
	if _, _, err := db.Queue(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(ctx, conversation.ID); err != nil || !claimed {
		t.Fatalf("claim runtime = %v, %v", claimed, err)
	}
	if _, err := db.Complete(ctx, conversation.ID, containerruntime.Runtime{
		ID: spec.ID, ProviderID: "handler-provider-1", Status: containerruntime.StatusStopped,
	}); err != nil {
		t.Fatal(err)
	}
	controller := &fakeConversationContainerLifecycle{}
	controller.rebuild = func(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
		if _, err := db.BeginLifecycle(ctx, conversationID, containerruntime.LifecycleOperationRebuild); err != nil {
			return containerruntime.InitializationRecord{}, err
		}
		return db.CompleteLifecycle(ctx, conversationID, containerruntime.LifecycleOperationRebuild, containerruntime.LifecycleCompletion{
			Runtime:             containerruntime.Runtime{ID: spec.ID, ProviderID: "handler-provider-2", Status: containerruntime.StatusStopped},
			IncrementGeneration: true,
		})
	}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerLifecycleController(controller)

	response := performConversationRequest(owner, http.MethodPost, "/api/conversations/"+conversation.ID+"/container/rebuild", map[string]interface{}{
		"boundaryPolicyId": newPolicy.ID,
	}, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
		handler.RebuildConversationContainer(c)
	})
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing boundary:read response=%d %s", response.Code, response.Body.String())
	}
	if pending, err := db.HasPendingConversationBoundaryRebuild(ctx, conversation.ID); err != nil || pending {
		t.Fatalf("unauthorized rebuild staged a snapshot: %v, %v", pending, err)
	}
	response = performBoundaryRebuildRequest(owner, conversation.ID, map[string]interface{}{
		"boundaryPolicyId": nil,
	}, handler.RebuildConversationContainer)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("null policy response=%d %s", response.Code, response.Body.String())
	}
	response = performBoundaryRebuildRequest(owner, conversation.ID, map[string]interface{}{
		"boundaryPolicyId": newPolicy.ID, "unexpected": true,
	}, handler.RebuildConversationContainer)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown field response=%d %s", response.Code, response.Body.String())
	}

	response = performBoundaryRebuildRequest(owner, conversation.ID, map[string]interface{}{
		"boundaryPolicyId": newPolicy.ID,
		"networkAccess":    map[string]interface{}{"allowRestrictedTargets": true},
	}, handler.RebuildConversationContainer)
	if response.Code != http.StatusOK {
		t.Fatalf("rebuild response=%d %s", response.Code, response.Body.String())
	}
	active, err := db.GetConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil || active.PolicyID != newPolicy.ID || active.SnapshotID == initial.SnapshotID || active.RuntimeGeneration != 2 {
		t.Fatalf("active snapshot = %#v, %v", active, err)
	}
	if access, accessErr := db.GetConversationNetworkAccess(ctx, conversation.ID); accessErr != nil || !access.AllowRestrictedTargets {
		t.Fatalf("active network access = %#v, %v", access, accessErr)
	}

	controller.rebuild = func(context.Context, string) (containerruntime.InitializationRecord, error) {
		return containerruntime.InitializationRecord{}, containerruntime.ErrRuntimeStateConflict
	}
	response = performBoundaryRebuildRequest(owner, conversation.ID, map[string]interface{}{
		"boundaryPolicyId": oldPolicy.ID,
		"networkAccess":    map[string]interface{}{"allowRestrictedTargets": false},
	}, handler.RebuildConversationContainer)
	if response.Code != http.StatusConflict {
		t.Fatalf("failed rebuild response=%d %s", response.Code, response.Body.String())
	}
	afterFailure, err := db.GetConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil || afterFailure.SnapshotID != active.SnapshotID || afterFailure.RuntimeGeneration != active.RuntimeGeneration {
		t.Fatalf("failed rebuild changed active snapshot: %#v, %v", afterFailure, err)
	}
	if access, accessErr := db.GetConversationNetworkAccess(ctx, conversation.ID); accessErr != nil || !access.AllowRestrictedTargets {
		t.Fatalf("failed rebuild changed active network access = %#v, %v", access, accessErr)
	}
	pending, err := db.HasPendingConversationBoundaryRebuild(ctx, conversation.ID)
	if err != nil || pending {
		t.Fatalf("failed rebuild pending state = %v, %v", pending, err)
	}
}

func TestConversationContainerNetworkSettingsSeparatesActiveAndPendingAccess(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	ctx := context.Background()
	conversation, err := db.CreateConversation("network access state", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	active, err := db.EnsureConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.EnsureConversationEgressBinding(ctx, conversation.ID); err != nil {
		t.Fatal(err)
	}
	spec := handlerBoundaryRuntimeSpec(conversation.ID)
	if _, _, err := db.Queue(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(ctx, conversation.ID); err != nil || !claimed {
		t.Fatalf("claim runtime = %v, %v", claimed, err)
	}
	if _, err := db.Complete(ctx, conversation.ID, containerruntime.Runtime{
		ID: spec.ID, ProviderID: "network-settings-provider", Status: containerruntime.StatusStopped,
	}); err != nil {
		t.Fatal(err)
	}
	pending, err := db.PrepareConversationBoundaryRebuild(ctx, conversation.ID, "", database.ConversationNetworkAccess{AllowRestrictedTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewConversationHandler(db, zap.NewNop())
	payload, _ := json.Marshal(nil)
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/conversations/"+conversation.ID+"/container/network-settings", bytes.NewReader(payload))
	c.Params = gin.Params{{Key: "id", Value: conversation.ID}}
	c.Set(security.ContextSessionKey, security.Session{
		UserID: owner.ID, Username: owner.Username, Scope: database.RBACScopeAssigned,
		Permissions: map[string]bool{"boundary:read": true, "egress:read": true},
	})
	handler.GetConversationContainerNetworkSettings(c)
	if response.Code != http.StatusOK {
		t.Fatalf("network settings response = %d: %s", response.Code, response.Body.String())
	}
	var result struct {
		BoundarySnapshotID        string                             `json:"boundarySnapshotId"`
		NetworkAccess             database.ConversationNetworkAccess `json:"networkAccess"`
		PendingBoundarySnapshotID string                             `json:"pendingBoundarySnapshotId"`
		PendingNetworkAccess      database.ConversationNetworkAccess `json:"pendingNetworkAccess"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.BoundarySnapshotID != active.SnapshotID || result.NetworkAccess.AllowRestrictedTargets || result.PendingBoundarySnapshotID != pending.SnapshotID || !result.PendingNetworkAccess.AllowRestrictedTargets {
		t.Fatalf("active/pending network settings = %#v", result)
	}
}

func TestConversationContainerRebuildCarriesStagedDirectEgressRoute(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("direct egress rebuild", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	prepared := false
	controller := &fakeConversationContainerLifecycle{}
	controller.rebuild = func(ctx context.Context, _ string) (containerruntime.InitializationRecord, error) {
		route, ok := containerruntime.EgressRebuildRouteFromContext(ctx)
		if !ok || route != nil {
			t.Fatalf("egress rebuild context = %#v, %v", route, ok)
		}
		return containerruntime.InitializationRecord{ConversationID: conversation.ID, RuntimeGeneration: 2}, nil
	}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerLifecycleController(controller)
	handler.SetConversationEgressRebuildPreparer(func(context.Context, string, string, string, string, bool) (*containerruntime.EgressUpstreamRouteSpec, error) {
		prepared = true
		return nil, nil
	})
	response := performBoundaryRebuildRequest(owner, conversation.ID, map[string]interface{}{"egressMode": "none"}, handler.RebuildConversationContainer)
	if response.Code != http.StatusOK || !prepared {
		t.Fatalf("response=%d %s prepared=%v", response.Code, response.Body.String(), prepared)
	}
}

func TestConversationContainerNetworkChangeStopsRunningRuntimeBeforeRebuild(t *testing.T) {
	db, owner := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("running network rebuild", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(owner.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	spec := handlerBoundaryRuntimeSpec(conversation.ID)
	if _, _, err := db.Queue(context.Background(), spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(context.Background(), conversation.ID); err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	if _, err := db.Complete(context.Background(), conversation.ID, containerruntime.Runtime{
		ID: spec.ID, ProviderID: "running-provider", Status: containerruntime.StatusRunning,
	}); err != nil {
		t.Fatal(err)
	}
	controller := &fakeConversationContainerLifecycle{record: containerruntime.InitializationRecord{ConversationID: conversation.ID, RuntimeStatus: containerruntime.StatusStopped}}
	controller.rebuild = func(ctx context.Context, _ string) (containerruntime.InitializationRecord, error) {
		if route, ok := containerruntime.EgressRebuildRouteFromContext(ctx); !ok || route != nil {
			t.Fatalf("egress rebuild context = %#v, %v", route, ok)
		}
		return containerruntime.InitializationRecord{ConversationID: conversation.ID, RuntimeGeneration: 2}, nil
	}
	handler := NewConversationHandler(db, zap.NewNop())
	handler.SetContainerLifecycleController(controller)
	handler.SetConversationEgressRebuildPreparer(func(context.Context, string, string, string, string, bool) (*containerruntime.EgressUpstreamRouteSpec, error) {
		return nil, nil
	})
	response := performBoundaryRebuildRequest(owner, conversation.ID, map[string]interface{}{"egressMode": "none"}, handler.RebuildConversationContainer)
	if response.Code != http.StatusOK || len(controller.actions) != 2 || controller.actions[0] != "stop" || controller.actions[1] != "rebuild" {
		t.Fatalf("response=%d %s actions=%v", response.Code, response.Body.String(), controller.actions)
	}
}

func performBoundaryRebuildRequest(user *database.RBACUser, conversationID string, body interface{}, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/conversations/"+conversationID+"/container/rebuild", bytes.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: conversationID}}
	c.Set(security.ContextSessionKey, security.Session{
		UserID: user.ID, Username: user.Username, Scope: database.RBACScopeAssigned,
		Permissions:      map[string]bool{"chat:write": true, "boundary:read": true, "egress:read": true},
		PermissionScopes: map[string]string{"boundary:read": database.RBACScopeOwn, "egress:read": database.RBACScopeOwn},
	})
	handler(c)
	return response
}

func handlerBoundaryRuntimeSpec(conversationID string) containerruntime.RuntimeSpec {
	return containerruntime.RuntimeSpec{
		ID: containerruntime.RuntimeID("runtime-" + conversationID), ConversationID: conversationID,
		Image: containerruntime.ImageReference{
			Repository: "ghcr.io/usestrix/strix-sandbox",
			Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:   "linux/arm64",
		},
		Resources: containerruntime.ResourceLimits{
			NanoCPUs: 1_000_000_000, MemoryBytes: 512 << 20, PIDs: 128,
			NoFileSoft: 1024, NoFileHard: 2048, WorkspaceBytes: 1 << 30,
			MaxConcurrentExec: 2, MaxQueuedExec: 8, LogMaxBytes: 10 << 20, LogMaxFiles: 3,
		},
		Security: containerruntime.SecurityProfile{
			ReadOnlyRootFS: true, NoNewPrivileges: true, DropAllCapabilities: true,
			NetworkMode: containerruntime.NetworkNone, SeccompProfile: "default", TmpfsBytes: 64 << 20,
		},
		Workspace: containerruntime.WorkspaceSpec{MountPath: "/workspace"},
	}
}
