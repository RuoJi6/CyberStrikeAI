package asm

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
)

func TestAgentContinuationSettingsPersistOnResource(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	view, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
		AgentContinuation: &AgentContinuationSettings{
			Behavior: ContinuationNotifyOnly, RunningPrompt: "running {{task_id}}", IdlePrompt: "idle {{task_id}}",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.AgentContinuation.Behavior != ContinuationNotifyOnly || view.AgentContinuation.RunningPrompt != "running {{task_id}}" {
		t.Fatalf("unexpected continuation settings: %#v", view.AgentContinuation)
	}
	reloaded, err := service.GetResource(view.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.AgentContinuation != view.AgentContinuation {
		t.Fatalf("continuation settings were not persisted: %#v", reloaded.AgentContinuation)
	}
	updated, err := service.UpdateResource(view.ID, UpdateResourceInput{AgentContinuation: &AgentContinuationSettings{
		Behavior: ContinuationNone, RunningPrompt: "updated running", IdlePrompt: "updated idle",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.AgentContinuation.Behavior != ContinuationNone || updated.AgentContinuation.IdlePrompt != "updated idle" {
		t.Fatalf("standalone continuation update was not persisted: %#v", updated.AgentContinuation)
	}
}

func TestAgentContinuationSettingsRejectUnknownBehaviorWithoutAutoRun(t *testing.T) {
	settings := normalizeAgentContinuationSettings(&AgentContinuationSettings{
		Behavior:      "unexpected",
		RunningPrompt: strings.Repeat("续", 8100),
		IdlePrompt:    "idle",
	})
	if settings.Behavior != ContinuationNone {
		t.Fatalf("unknown behavior must fail closed, got %q", settings.Behavior)
	}
	if len([]rune(settings.RunningPrompt)) != 8000 || !strings.HasSuffix(settings.RunningPrompt, "续") {
		t.Fatalf("prompt was not truncated on a Unicode boundary: runes=%d", len([]rune(settings.RunningPrompt)))
	}
}

func TestManualASMTaskDoesNotCreateAgentContinuation(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{
		Name: "manual", Target: "192.0.2.30", Options: map[string]interface{}{"task_mode": "direct"},
	})
	if err != nil {
		t.Fatal(err)
	}
	continuation := valueMap(valueMap(created)["agent_continuation"])
	if meaningfulString(continuation["status"]) != "not_linked" {
		t.Fatalf("manual task must remain unlinked: %#v", continuation)
	}
	if meaningfulString(continuation["wait_strategy"]) != "manual_follow_up" {
		t.Fatalf("manual task must explain its non-blocking follow-up strategy: %#v", continuation)
	}
	if _, exists := continuation["agent_guidance"]; exists {
		t.Fatalf("task result must not duplicate static MCP guidance: %#v", continuation)
	}
	items, err := service.db.ListPendingASMAgentContinuations(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("manual task created continuation rows: %#v", items)
	}
}

func TestManagedASMTaskResumeCreatesAgentContinuation(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{
		Name: "manual", Target: "192.0.2.31",
	})
	if err != nil {
		t.Fatal(err)
	}
	localID := meaningfulString(valueMap(created)["local_task_id"])
	result, err := service.ManageTask(context.Background(), resource.ID, TaskManageRequest{
		Action: "resume", TaskID: "7", ConversationID: "conversation-resume", OwnerUserID: "user-resume",
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata := valueMap(result)
	if meaningfulString(metadata["local_task_id"]) != localID {
		t.Fatalf("managed task did not return its local task ID: %#v", metadata)
	}
	continuation := valueMap(metadata["agent_continuation"])
	if meaningfulString(continuation["status"]) != "waiting" || meaningfulString(continuation["wait_strategy"]) != "system_managed" {
		t.Fatalf("managed task was not bound to Agent continuation: %#v", continuation)
	}
	items, err := service.db.ListPendingASMAgentContinuations(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ConversationID != "conversation-resume" || items[0].OwnerUserID != "user-resume" {
		t.Fatalf("unexpected managed-task continuation rows: %#v", items)
	}
}

func TestAgentContinuationHistoryExplainsScanningAndReadyPhases(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{
		Name: "diagnostic", Target: "192.0.2.40", ConversationID: "conversation-diagnostic", OwnerUserID: "user-diagnostic",
	})
	if err != nil {
		t.Fatal(err)
	}
	continuationID := meaningfulString(valueMap(valueMap(created)["agent_continuation"])["id"])
	page, err := service.ListAgentContinuations(AgentContinuationHistoryFilter{
		Page: 1, PageSize: 20, Access: database.RBACListAccess{Scope: database.RBACScopeAll},
	})
	if err != nil || len(page.Items) != 1 || page.Items[0].Phase != "scanning" {
		t.Fatalf("unexpected scanning diagnostic: page=%#v err=%v", page, err)
	}
	item, err := service.db.GetASMAgentContinuation(continuationID)
	if err != nil {
		t.Fatal(err)
	}
	item.Status = "ready"
	if err := service.db.UpdateASMAgentContinuation(item); err != nil {
		t.Fatal(err)
	}
	page, err = service.ListAgentContinuations(AgentContinuationHistoryFilter{
		Page: 1, PageSize: 20, Access: database.RBACListAccess{Scope: database.RBACScopeAll},
	})
	if err != nil || page.Items[0].Phase != "awaiting_agent" || page.StatusCounts["ready"] != 1 {
		t.Fatalf("unexpected ready diagnostic: page=%#v err=%v", page, err)
	}
}

func TestCompletedASMTaskQueuesLinkedAgentWhileActive(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
		AgentContinuation: &AgentContinuationSettings{
			Behavior:      ContinuationAuto,
			RunningPrompt: "running {{task_id}} {{provider}} {{targets}}",
			IdlePrompt:    "idle {{task_id}}",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{
		Name: "authorized", Target: "192.0.2.10", Options: map[string]interface{}{"task_mode": "direct"},
		ConversationID: "conversation-1", OwnerUserID: "user-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	continuation := valueMap(valueMap(created)["agent_continuation"])
	if meaningfulString(continuation["wait_strategy"]) != "system_managed" {
		t.Fatalf("linked task must tell the Agent to use system-managed waiting: %#v", continuation)
	}
	if _, exists := continuation["agent_guidance"]; exists {
		t.Fatalf("task result must not duplicate static MCP guidance: %#v", continuation)
	}
	localID := meaningfulString(valueMap(created)["local_task_id"])
	task, err := service.db.GetASMTask(localID)
	if err != nil {
		t.Fatal(err)
	}
	task.Status = "completed"
	if err := service.db.UpdateASMTask(task); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, resultType := range providerResultTypes(task.Provider) {
		if err := service.db.UpsertASMResultSyncState(database.ASMResultSyncState{
			TaskID: task.ID, AssetType: resultType.ID, Status: "completed", SyncedAt: &now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	agentActive := true
	agentStartedAt := time.Now().UTC().Add(-3 * time.Minute).Truncate(time.Millisecond)
	prompts := make(chan string, 1)
	release := make(chan struct{})
	service.workerCtx = context.Background()
	service.SetAgentContinuationHooks(
		func(string) (bool, time.Time) { return agentActive, agentStartedAt },
		func(_ context.Context, item *database.ASMAgentContinuation, prompt string) error {
			if item.ConversationID != "conversation-1" || item.OwnerUserID != "user-1" {
				t.Fatalf("unexpected continuation origin: %#v", item)
			}
			prompts <- prompt
			<-release
			return nil
		},
	)
	service.reconcileAgentContinuations(context.Background())
	select {
	case prompt := <-prompts:
		if !strings.Contains(prompt, "running "+localID) || !strings.Contains(prompt, "XingRin") || !strings.Contains(prompt, "192.0.2.10") {
			t.Fatalf("running prompt variables were not rendered: %q", prompt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("linked Agent continuation was not admitted to the TurnLoop queue")
	}
	item, err := service.db.GetASMAgentContinuation(meaningfulString(continuation["id"]))
	if err != nil {
		t.Fatal(err)
	}
	if item.Status != "queued" || !item.AgentWasRunning || item.Attempts != 0 || item.AgentStartedAt == nil || !item.AgentStartedAt.Equal(agentStartedAt) {
		t.Fatalf("unexpected queued continuation state: %#v", item)
	}
	agentActive = false
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		completed, readErr := service.db.GetASMAgentContinuation(item.ID)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if completed.Status == "completed" {
			if completed.CompletedAt == nil || continuationHistoryPhase(completed, nil) != "success" {
				t.Fatalf("completed continuation did not become green success: %#v", completed)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("continuation stayed %q instead of completed", completed.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCompletedASMTaskUsesIdlePromptWhenAgentAlreadyStopped(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	conversation, err := service.db.CreateConversation("restart fallback", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.db.AddMessage(conversation.ID, "user", "authorized target", nil); err != nil {
		t.Fatal(err)
	}
	pendingAssistant, err := service.db.AddMessage(conversation.ID, "assistant", "处理中...", nil)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
		AgentContinuation: &AgentContinuationSettings{
			Behavior: ContinuationAuto, RunningPrompt: "running {{task_id}}", IdlePrompt: "idle {{task_id}} {{targets}}",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{
		Name: "authorized", Target: "192.0.2.20", Options: map[string]interface{}{"task_mode": "direct"},
		ConversationID: conversation.ID, OwnerUserID: "user-idle",
	})
	if err != nil {
		t.Fatal(err)
	}
	localID := meaningfulString(valueMap(created)["local_task_id"])
	task, err := service.db.GetASMTask(localID)
	if err != nil {
		t.Fatal(err)
	}
	task.Status = "completed"
	if err := service.db.UpdateASMTask(task); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, resultType := range providerResultTypes(task.Provider) {
		if err := service.db.UpsertASMResultSyncState(database.ASMResultSyncState{
			TaskID: task.ID, AssetType: resultType.ID, Status: "completed", SyncedAt: &now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	prompts := make(chan string, 1)
	continuations := make(chan database.ASMAgentContinuation, 1)
	service.workerCtx = context.Background()
	service.SetAgentContinuationHooks(
		func(string) (bool, time.Time) { return false, time.Time{} },
		func(_ context.Context, item *database.ASMAgentContinuation, prompt string) error {
			prompts <- prompt
			continuations <- *item
			return nil
		},
	)
	service.reconcileAgentContinuations(context.Background())
	select {
	case prompt := <-prompts:
		if !strings.Contains(prompt, "idle "+localID+" 192.0.2.20") {
			t.Fatalf("idle prompt variables were not rendered: %q", prompt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle Agent conversation was not resumed")
	}
	select {
	case item := <-continuations:
		if item.AgentWasRunning || item.AgentStartedAt == nil || !item.AgentStartedAt.Equal(pendingAssistant.CreatedAt) {
			t.Fatalf("restart fallback did not preserve pending turn start: %#v", item)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("missing persisted restart fallback metadata")
	}
}

func TestUserStoppedConversationNeverResumesAfterASMCompletes(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{
		Name: "user-stop", Target: "192.0.2.40", ConversationID: "conversation-stopped", OwnerUserID: "user-stopped",
	})
	if err != nil {
		t.Fatal(err)
	}
	continuation := valueMap(valueMap(created)["agent_continuation"])
	continuationID := meaningfulString(continuation["id"])
	if continuationID == "" {
		t.Fatalf("missing continuation metadata: %#v", continuation)
	}
	affected, err := service.db.StopASMAgentContinuationsForConversation("conversation-stopped", "user stopped")
	if err != nil || affected != 1 {
		t.Fatalf("failed to persist user stop: affected=%d err=%v", affected, err)
	}

	ran := make(chan struct{}, 1)
	service.workerCtx = context.Background()
	service.SetAgentContinuationHooks(func(string) (bool, time.Time) { return false, time.Time{} }, func(context.Context, *database.ASMAgentContinuation, string) error {
		ran <- struct{}{}
		return nil
	})
	service.reconcileAgentContinuations(context.Background())
	select {
	case <-ran:
		t.Fatal("user-stopped conversation was resumed")
	default:
	}
	stored, err := service.db.GetASMAgentContinuation(continuationID)
	if err != nil || stored.Status != "user_stopped" || stored.CompletedAt == nil {
		t.Fatalf("unexpected persisted stop state: %#v err=%v", stored, err)
	}
	staleWorkerCopy := *stored
	staleWorkerCopy.Status = "completed"
	staleWorkerCopy.LastError = ""
	if err := service.db.UpdateASMAgentContinuation(&staleWorkerCopy); err != nil {
		t.Fatalf("stale worker update should be ignored: %v", err)
	}
	stored, err = service.db.GetASMAgentContinuation(continuationID)
	if err != nil || stored.Status != "user_stopped" {
		t.Fatalf("stale worker overwrote durable user stop: %#v err=%v", stored, err)
	}
}

func TestAgentResultReadConsumesOnlyMatchingPendingContinuationTasks(t *testing.T) {
	service, adapter := newTaskHistoryTestService(t)
	adapter.createScans = []interface{}{
		map[string]interface{}{"id": 71, "status": "initiated", "targetName": "192.0.2.71"},
		map[string]interface{}{"id": 72, "status": "initiated", "targetName": "192.0.2.72"},
	}
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
		AgentContinuation: &AgentContinuationSettings{
			Behavior: ContinuationAuto, RunningPrompt: "running {{task_id}}", IdlePrompt: "resume {{task_id}}",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{
		Name: "two results", Target: "192.0.2.71 192.0.2.72",
		ConversationID: "conversation-result-reader", OwnerUserID: "user-result-reader",
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata := valueMap(created)
	localIDs, _ := metadata["local_task_ids"].([]string)
	continuationID := meaningfulString(valueMap(metadata["agent_continuation"])["id"])
	if len(localIDs) != 2 || continuationID == "" {
		t.Fatalf("missing multi-task continuation metadata: %#v", metadata)
	}

	// Stale pages and results from a task that is not complete must not consume
	// the future completion notification.
	consumption, err := service.MarkAgentTaskResultConsumed(
		"conversation-result-reader", resource.ID, localIDs[0], "asm_list_assets", TaskResultsView{Stale: true},
	)
	if err != nil || consumption.Consumed {
		t.Fatalf("stale result incorrectly consumed continuation: %#v err=%v", consumption, err)
	}
	consumption, err = service.MarkAgentTaskResultConsumed(
		"conversation-result-reader", resource.ID, localIDs[0], "asm_list_assets", TaskResultsView{},
	)
	if err != nil || consumption.Consumed {
		t.Fatalf("unfinished task incorrectly consumed continuation: %#v err=%v", consumption, err)
	}

	for _, taskID := range localIDs {
		task, readErr := service.db.GetASMTask(taskID)
		if readErr != nil {
			t.Fatal(readErr)
		}
		task.Status, task.Progress = "completed", 100
		if updateErr := service.db.UpdateASMTask(task); updateErr != nil {
			t.Fatal(updateErr)
		}
	}
	consumption, err = service.MarkAgentTaskResultConsumed(
		"another-conversation", resource.ID, localIDs[0], "asm_list_assets", TaskResultsView{},
	)
	if err != nil || consumption.Consumed {
		t.Fatalf("another conversation incorrectly consumed continuation: %#v err=%v", consumption, err)
	}

	first, err := service.MarkAgentTaskResultConsumed(
		"conversation-result-reader", resource.ID, localIDs[0], "asm_list_assets", TaskResultsView{},
	)
	if err != nil || !first.Consumed || len(first.SuppressedContinuationIDs) != 0 {
		t.Fatalf("first result was not recorded as a partial consumption: %#v err=%v", first, err)
	}
	stored, err := service.db.GetASMAgentContinuation(continuationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "waiting" || !strings.Contains(stored.ConsumedTaskIDsJSON, localIDs[0]) {
		t.Fatalf("partial consumption changed terminal state incorrectly: %#v", stored)
	}
	prompt, pending, err := service.PrepareAgentContinuationPrompt(stored)
	if err != nil || !pending || strings.Contains(prompt, localIDs[0]) || !strings.Contains(prompt, localIDs[1]) {
		t.Fatalf("partial continuation prompt did not retain only unread task: prompt=%q pending=%v err=%v", prompt, pending, err)
	}

	second, err := service.MarkAgentTaskResultConsumed(
		"conversation-result-reader", resource.ID, localIDs[1], "asm_list_assets", TaskResultsView{},
	)
	if err != nil || !second.Consumed || len(second.SuppressedContinuationIDs) != 1 || second.SuppressedContinuationIDs[0] != continuationID {
		t.Fatalf("all-read continuation was not suppressed: %#v err=%v", second, err)
	}
	stored, err = service.db.GetASMAgentContinuation(continuationID)
	if err != nil || stored.Status != "agent_consumed" || stored.CompletedAt == nil || continuationHistoryPhase(stored, nil) != "agent_consumed" {
		t.Fatalf("unexpected fully consumed continuation state: %#v err=%v", stored, err)
	}
	if claimed, accepted, claimErr := service.db.ClaimASMAgentContinuationForDelivery(continuationID); claimErr != nil || accepted || claimed.Status != "agent_consumed" {
		t.Fatalf("consumed continuation was claimed for duplicate delivery: claimed=%#v accepted=%v err=%v", claimed, accepted, claimErr)
	}
}

func TestUserStopAfterContinuationDeliveryKeepsSuccess(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	now := time.Now().UTC()
	item := &database.ASMAgentContinuation{
		ID: "asmcont-delivered", TaskIDsJSON: "[]", ConversationID: "conversation-delivered",
		OwnerUserID: "user-delivered", Behavior: ContinuationAuto, Status: "completed",
		AgentWasRunning: true, Attempts: 1, CompletedAt: &now,
	}
	if err := service.db.CreateASMAgentContinuation(item); err != nil {
		t.Fatal(err)
	}
	affected, err := service.db.StopASMAgentContinuationsForConversation(item.ConversationID, "user stopped later Agent work")
	if err != nil {
		t.Fatal(err)
	}
	if affected != 0 {
		t.Fatalf("delivered continuation was incorrectly changed by later stop: affected=%d", affected)
	}
	stored, err := service.db.GetASMAgentContinuation(item.ID)
	if err != nil || stored.Status != "completed" || continuationHistoryPhase(stored, nil) != "success" {
		t.Fatalf("delivered continuation lost success: %#v err=%v", stored, err)
	}
	if pending, err := service.db.ListPendingASMAgentContinuations(10); err != nil || len(pending) != 0 {
		t.Fatalf("delivered notification would be sent again: pending=%#v err=%v", pending, err)
	}
}

func TestLegacyUserStopWithPersistedNotificationSelfHealsToSuccess(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	conversation, err := service.db.CreateConversation("legacy delivered", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	const taskID = "asmtask_legacy_delivered"
	if _, err := service.db.AddMessage(conversation.ID, "user", "ASM 扫描结果已完成。\n任务 ID："+taskID, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rawTaskIDs, _ := json.Marshal([]string{taskID})
	item := &database.ASMAgentContinuation{
		ID: "asmcont-legacy-delivered", TaskIDsJSON: string(rawTaskIDs), ConversationID: conversation.ID,
		OwnerUserID: "legacy-user", Behavior: ContinuationAuto, Status: "user_stopped",
		AgentWasRunning: true, Attempts: 1, CompletedAt: &now,
	}
	if err := service.db.CreateASMAgentContinuation(item); err != nil {
		t.Fatal(err)
	}
	service.reconcileDeliveredAgentContinuations()
	stored, err := service.db.GetASMAgentContinuation(item.ID)
	if err != nil || stored.Status != "completed" {
		t.Fatalf("legacy delivered continuation was not repaired: %#v err=%v", stored, err)
	}
}

func TestLegacyUserStopWithoutNotificationStaysStopped(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	conversation, err := service.db.CreateConversation("legacy never delivered", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	rawTaskIDs, _ := json.Marshal([]string{"asmtask_never_delivered"})
	item := &database.ASMAgentContinuation{
		ID: "asmcont-never-delivered", TaskIDsJSON: string(rawTaskIDs), ConversationID: conversation.ID,
		OwnerUserID: "legacy-user", Behavior: ContinuationAuto, Status: "user_stopped", Attempts: 1,
	}
	if err := service.db.CreateASMAgentContinuation(item); err != nil {
		t.Fatal(err)
	}
	service.reconcileDeliveredAgentContinuations()
	stored, err := service.db.GetASMAgentContinuation(item.ID)
	if err != nil || stored.Status != "user_stopped" {
		t.Fatalf("never-delivered continuation was incorrectly promoted: %#v err=%v", stored, err)
	}
}

func TestRepairMissingASMContinuationTurnTiming(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	conversation, err := service.db.CreateConversation("repair continuation timing", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.db.AddMessage(conversation.ID, "user", "authorized target", nil); err != nil {
		t.Fatal(err)
	}
	original, err := service.db.AddMessage(conversation.ID, "assistant", "处理中...", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.db.AddMessage(conversation.ID, "user", "ASM 扫描结果已完成。\n任务 ID：asmtask_repair_timing", nil); err != nil {
		t.Fatal(err)
	}
	resumed, err := service.db.AddMessage(conversation.ID, "assistant", "continuation complete", nil)
	if err != nil {
		t.Fatal(err)
	}

	repaired, err := service.db.RepairMissingASMContinuationTurnTimings(10)
	if err != nil || repaired != 1 {
		t.Fatalf("repair timing: repaired=%d err=%v", repaired, err)
	}
	messages, err := service.db.GetMessagesLite(conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]database.Message, len(messages))
	for _, message := range messages {
		byID[message.ID] = message
	}
	repairedOriginal := byID[original.ID]
	if repairedOriginal.Content == "处理中..." || repairedOriginal.UpdatedAt.Before(repairedOriginal.CreatedAt) {
		t.Fatalf("stale foreground timer was not finalized: %#v", repairedOriginal)
	}
	repairedResumed := byID[resumed.ID]
	if repairedResumed.TurnStartedAt == nil || !repairedResumed.TurnStartedAt.Equal(original.CreatedAt) {
		t.Fatalf("resumed turn did not inherit original start: %#v", repairedResumed)
	}
	summary, err := service.db.GetProcessDetailsSummary(resumed.ID)
	if err != nil || summary.StartedAt == nil || !summary.StartedAt.Equal(original.CreatedAt) {
		t.Fatalf("summary did not use repaired cumulative start: %#v err=%v", summary, err)
	}
}

func TestRepairRestartInterruptedASMContinuationTurnTiming(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	conversation, err := service.db.CreateConversation("repair restarted timing", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.db.AddMessage(conversation.ID, "user", "authorized target", nil); err != nil {
		t.Fatal(err)
	}
	original, err := service.db.AddMessage(conversation.ID, "assistant", "任务因服务重启已中断。", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.db.AddMessage(conversation.ID, "user", "ASM 扫描结果已完成。\n任务 ID：asmtask_restart_timing", nil); err != nil {
		t.Fatal(err)
	}
	resumed, err := service.db.AddMessage(conversation.ID, "assistant", "continuation complete", nil)
	if err != nil {
		t.Fatal(err)
	}

	repaired, err := service.db.RepairMissingASMContinuationTurnTimings(10)
	if err != nil || repaired != 1 {
		t.Fatalf("repair restarted timing: repaired=%d err=%v", repaired, err)
	}
	messages, err := service.db.GetMessagesLite(conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range messages {
		if message.ID == resumed.ID {
			if message.TurnStartedAt == nil || !message.TurnStartedAt.Equal(original.CreatedAt) {
				t.Fatalf("restart-interrupted turn did not inherit original start: %#v", message)
			}
			return
		}
	}
	t.Fatal("resumed message not found")
}
