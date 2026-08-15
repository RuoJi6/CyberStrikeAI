package asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

type taskHistoryTestAdapter struct {
	assetsErr   error
	assetCalls  int
	detailCalls int
	createScans []interface{}
	gotTaskID   string
	stoppedID   string
}

func (a *taskHistoryTestAdapter) Provider() string { return ProviderXingRin }
func (a *taskHistoryTestAdapter) Capabilities() []string {
	return []string{"create_task", "get_task", "list_assets"}
}
func (a *taskHistoryTestAdapter) Test(context.Context, *Connection) (interface{}, error) {
	return map[string]interface{}{"connected": true}, nil
}
func (a *taskHistoryTestAdapter) CreateTask(context.Context, *Connection, TaskRequest) (interface{}, error) {
	scans := a.createScans
	if len(scans) == 0 {
		scans = []interface{}{map[string]interface{}{"id": 7, "status": "initiated"}}
	}
	return map[string]interface{}{
		"provider": ProviderXingRin,
		"response": map[string]interface{}{"count": len(scans), "scans": scans},
	}, nil
}
func (a *taskHistoryTestAdapter) ListTasks(context.Context, *Connection, TaskFilter) (interface{}, error) {
	return map[string]interface{}{"tasks": map[string]interface{}{"results": []interface{}{
		map[string]interface{}{"id": 8, "status": "completed", "progress": 100, "targetName": "192.0.2.11", "createdAt": "2026-08-11T12:00:00Z"},
	}}}, nil
}
func (a *taskHistoryTestAdapter) GetTask(_ context.Context, _ *Connection, taskID string) (interface{}, error) {
	a.gotTaskID = taskID
	return map[string]interface{}{"tasks": map[string]interface{}{"results": []interface{}{map[string]interface{}{
		"id": 7, "status": "running", "progress": 42, "currentStage": "site_scan",
		"summary": map[string]interface{}{"websites": 1},
	}}}}, nil
}
func (a *taskHistoryTestAdapter) ListAssets(_ context.Context, _ *Connection, filter AssetFilter) (interface{}, error) {
	a.assetCalls++
	if a.assetsErr != nil {
		return nil, a.assetsErr
	}
	if filter.Type == "vulnerability" {
		return map[string]interface{}{"results": map[string]interface{}{"results": []interface{}{
			map[string]interface{}{"hash": "hash-one", "url": "https://example.test", "severity": "high"},
		}}}, nil
	}
	return map[string]interface{}{"results": map[string]interface{}{"results": []interface{}{
		map[string]interface{}{"url": "https://example.test", "screenshot": "/shot.png"},
	}}}, nil
}
func (a *taskHistoryTestAdapter) StopTask(_ context.Context, _ *Connection, id string) (interface{}, error) {
	a.stoppedID = id
	return map[string]interface{}{}, nil
}
func (a *taskHistoryTestAdapter) ManageTask(context.Context, *Connection, TaskManageRequest) (interface{}, error) {
	return map[string]interface{}{}, nil
}
func (a *taskHistoryTestAdapter) GetAssetDetail(context.Context, *Connection, AssetDetailFilter) (interface{}, error) {
	a.detailCalls++
	return map[string]interface{}{"request": "GET /", "response": "HTTP/1.1 200 OK"}, nil
}
func (a *taskHistoryTestAdapter) FetchScreenshot(context.Context, *Connection, string) ([]byte, string, error) {
	return []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00}, "image/png", nil
}

func newTaskHistoryTestService(t *testing.T) (*Service, *taskHistoryTestAdapter) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "asm-history.db")
	db, err := database.NewDB(dbPath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service, err := NewService(db, dbPath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	adapter := &taskHistoryTestAdapter{}
	service.RegisterAdapter(adapter)
	return service, adapter
}

func TestTaskHistoryRecordsSyncsAndCachesResults(t *testing.T) {
	service, adapter := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{
		Name: "authorized", Target: "192.0.2.10", Options: map[string]interface{}{"rate_limit": 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	createdMap := valueMap(created)
	localID := meaningfulString(createdMap["local_task_id"])
	if localID == "" || createdMap["history_recorded"] != true {
		t.Fatalf("task history metadata missing: %#v", createdMap)
	}

	page, err := service.ListTaskHistory(TaskHistoryFilter{Query: "192.0.2.10"})
	if err != nil || page.Total != 1 || len(page.Tasks) != 1 {
		t.Fatalf("unexpected task history page: %#v, err=%v", page, err)
	}
	if page.Tasks[0].RemoteTaskID != "7" || page.Tasks[0].Status != "submitted" {
		t.Fatalf("unexpected recorded task: %#v", page.Tasks[0])
	}

	synced, err := service.SyncTaskHistory(context.Background(), localID)
	if err != nil {
		t.Fatal(err)
	}
	if synced.Status != "running" || synced.Progress != 42 || synced.Stage != "site_scan" || synced.Summary["websites"] != float64(1) {
		t.Fatalf("unexpected synced task: %#v", synced)
	}

	taskRecord, err := service.db.GetASMTask(localID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.syncTaskResultType(context.Background(), taskRecord, "site"); err != nil {
		t.Fatal(err)
	}
	results, err := service.ListTaskHistoryResults(context.Background(), localID, AssetFilter{Type: "site"})
	if err != nil || results.Stale {
		t.Fatalf("unexpected live results: %#v, err=%v", results, err)
	}
	adapter.assetsErr = errors.New("remote unavailable")
	callsBeforeLocalRead := adapter.assetCalls
	cached, err := service.ListTaskHistoryResults(context.Background(), localID, AssetFilter{Type: "site"})
	if err != nil || cached.Stale || cached.CachedAt == nil || cached.Source != "local" {
		t.Fatalf("expected local database result without upstream request: %#v, err=%v", cached, err)
	}
	if adapter.assetCalls != callsBeforeLocalRead {
		t.Fatalf("local result read unexpectedly called upstream: before=%d after=%d", callsBeforeLocalRead, adapter.assetCalls)
	}
	if _, err := service.ListTasks(context.Background(), resource.ID, TaskFilter{Page: 1, PageSize: 20}); err != nil {
		t.Fatal(err)
	}
	imported, err := service.ListTaskHistory(TaskHistoryFilter{Query: "192.0.2.11"})
	if err != nil || imported.Total != 1 || imported.Tasks[0].RemoteTaskID != "8" || imported.Tasks[0].Status != "completed" {
		t.Fatalf("unexpected imported remote task: %#v err=%v", imported, err)
	}
	if _, err := service.StopTask(context.Background(), resource.ID, "7"); err != nil {
		t.Fatal(err)
	}
	stopped, err := service.GetTaskHistory(localID)
	if err != nil || stopped.Status != "stopped" || stopped.Stage != "stopped" {
		t.Fatalf("local stop lifecycle was not recorded: %#v err=%v", stopped, err)
	}
	if _, err := service.ManageTask(context.Background(), resource.ID, TaskManageRequest{Action: "resume", TaskID: "7"}); err != nil {
		t.Fatal(err)
	}
	resumed, err := service.GetTaskHistory(localID)
	if err != nil || resumed.Status != "running" || resumed.Stage != "resume" || resumed.Progress != 0 {
		t.Fatalf("local resume lifecycle was not recorded: %#v err=%v", resumed, err)
	}
}

func TestTaskHistoryRecordsEveryXingRinChildInOneBatch(t *testing.T) {
	service, adapter := newTaskHistoryTestService(t)
	adapter.createScans = []interface{}{
		map[string]interface{}{"id": 31, "status": "initiated", "targetName": "192.0.2.31"},
		map[string]interface{}{"id": 32, "status": "running", "targetName": "192.0.2.32"},
	}
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin batch", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{
		Name: "two targets", Target: "192.0.2.31 192.0.2.32",
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata := valueMap(created)
	if metadata["history_recorded"] != true || numberInt(metadata["history_recorded_count"]) != 2 {
		t.Fatalf("unexpected history metadata: %#v", metadata)
	}
	batchID := meaningfulString(metadata["batch_id"])
	localIDs, _ := metadata["local_task_ids"].([]string)
	if batchID == "" || len(localIDs) != 2 || meaningfulString(metadata["local_task_id"]) != localIDs[0] {
		t.Fatalf("missing compatible batch metadata: %#v", metadata)
	}
	page, err := service.ListTaskHistory(TaskHistoryFilter{Query: "192.0.2.3", Page: 1, PageSize: 20})
	if err != nil || page.Total != 2 || len(page.Tasks) != 2 {
		t.Fatalf("unexpected batch history: %#v err=%v", page, err)
	}
	seen := map[string]TaskHistoryView{}
	for _, task := range page.Tasks {
		seen[task.RemoteTaskID] = task
		if task.BatchID != batchID || task.BatchSize != 2 {
			t.Fatalf("task missing batch relationship: %#v", task)
		}
	}
	if seen["31"].Target != "192.0.2.31" || seen["31"].BatchIndex != 0 || seen["31"].Status != "submitted" {
		t.Fatalf("unexpected first child: %#v", seen["31"])
	}
	if seen["32"].Target != "192.0.2.32" || seen["32"].BatchIndex != 1 || seen["32"].Status != "running" {
		t.Fatalf("unexpected second child: %#v", seen["32"])
	}
}

func TestTaskHistoryExposesProviderExecutionProfile(t *testing.T) {
	item := &database.ASMTask{
		ID: "scope-profile", Provider: ProviderScopeSentry,
		OptionsJSON: `{"template_id":"template-1","_execution_profile":{"kind":"template","label":"ScopeSentry 模板","id":"template-1","name":"CyberStrikeAI · 全量扫描","port_scope":"all","enabled_capabilities":["port_scan","vulnerability_scan"]}}`,
		DetailJSON:  `{}`,
	}
	view := taskHistoryView(item)
	if meaningfulString(view.ExecutionProfile["id"]) != "template-1" || meaningfulString(view.ExecutionProfile["name"]) != "CyberStrikeAI · 全量扫描" {
		t.Fatalf("template profile was not exposed: %#v", view.ExecutionProfile)
	}

	legacy := &database.ASMTask{
		ID: "scope-legacy", Provider: ProviderScopeSentry,
		OptionsJSON: `{"template_id":"legacy-template"}`,
		DetailJSON:  `{"task":{"data":{"template":"legacy-template"}}}`,
	}
	legacyView := taskHistoryView(legacy)
	if meaningfulString(legacyView.ExecutionProfile["id"]) != "legacy-template" {
		t.Fatalf("legacy template id was not recovered: %#v", legacyView.ExecutionProfile)
	}

	resolvedLegacy := &database.ASMTask{
		ID: "scope-resolved-legacy", Provider: ProviderScopeSentry,
		OptionsJSON: `{"template_id":"legacy-template","_execution_profile":{"kind":"template","id":"legacy-template","name":""}}`,
		DetailJSON:  `{"execution_profile":{"kind":"template","label":"ScopeSentry 模板","id":"legacy-template","name":"外网全量模板"}}`,
	}
	resolvedLegacyView := taskHistoryView(resolvedLegacy)
	if meaningfulString(resolvedLegacyView.ExecutionProfile["name"]) != "外网全量模板" {
		t.Fatalf("resolved template name did not fill the stored empty profile: %#v", resolvedLegacyView.ExecutionProfile)
	}

	arlLegacy := &database.ASMTask{
		ID: "arl-policy-name", Provider: ProviderARL, OptionsJSON: `{}`,
		DetailJSON: `{"tasks":{"items":[{"options":{"policy_name":"CyberStrikeAI · 快速探测"}}]}}`,
	}
	arlLegacyView := taskHistoryView(arlLegacy)
	if meaningfulString(arlLegacyView.ExecutionProfile["name"]) != "CyberStrikeAI · 快速探测" {
		t.Fatalf("legacy ARL policy name was not recovered: %#v", arlLegacyView.ExecutionProfile)
	}

	arlReturned := &database.ASMTask{
		ID: "arl-returned-profile", Provider: ProviderARL, OptionsJSON: `{"policy_id":"policy-1"}`,
		DetailJSON: `{"execution_profile":{"kind":"policy","label":"ARL 策略","id":"policy-1","name":"外网全量策略"}}`,
	}
	arlReturnedView := taskHistoryView(arlReturned)
	if meaningfulString(arlReturnedView.ExecutionProfile["name"]) != "外网全量策略" {
		t.Fatalf("returned ARL execution profile was not preserved: %#v", arlReturnedView.ExecutionProfile)
	}
}

func TestCreatedTaskEntriesIncludesEveryARLItem(t *testing.T) {
	entries := createdTaskEntries(ProviderARL, TaskRequest{Target: "192.0.2.41 192.0.2.42"}, map[string]interface{}{
		"response": map[string]interface{}{"items": []interface{}{
			map[string]interface{}{"task_id": "aaaaaaaaaaaaaaaaaaaaaaaa", "target": "192.0.2.41", "status": "waiting"},
			map[string]interface{}{"task_id": "bbbbbbbbbbbbbbbbbbbbbbbb", "target": "192.0.2.42", "status": "running"},
		}},
	})
	if len(entries) != 2 || entries[0].RemoteID != "aaaaaaaaaaaaaaaaaaaaaaaa" || entries[1].RemoteID != "bbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("unexpected ARL creation entries: %#v", entries)
	}
	if entries[0].Target != "192.0.2.41" || entries[1].Target != "192.0.2.42" {
		t.Fatalf("unexpected ARL targets: %#v", entries)
	}
}

func TestTaskHistoryScreenshotCache(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	localID := meaningfulString(valueMap(created)["local_task_id"])
	result, err := service.SyncTaskScreenshots(context.Background(), localID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Discovered != 1 || result.Downloaded != 1 || len(result.Screenshots) != 1 {
		t.Fatalf("unexpected screenshot sync: %#v", result)
	}
	item, err := service.GetScreenshotFile(result.Screenshots[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(item.FilePath); err != nil || info.Size() == 0 {
		t.Fatalf("cached screenshot missing: info=%v err=%v", info, err)
	}
	second, err := service.SyncTaskScreenshots(context.Background(), localID)
	if err != nil || second.Skipped != 1 || second.Downloaded != 0 {
		t.Fatalf("expected screenshot cache hit: %#v err=%v", second, err)
	}
}

func TestTaskHistoryScreenshotCachePrefersLocalizedResult(t *testing.T) {
	service, adapter := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	localID := meaningfulString(valueMap(created)["local_task_id"])
	if err := service.db.ReplaceASMResultItems(localID, "screenshot", []database.ASMResultItem{{
		ItemKey: "shot-one", ProviderKey: "1",
		PayloadJSON: `{"url":"https://example.test","screenshot_path":"/shot.png"}`,
		SearchText:  "https://example.test", SortOrder: 0,
	}}); err != nil {
		t.Fatal(err)
	}
	before := adapter.assetCalls
	result, err := service.SyncTaskScreenshots(context.Background(), localID)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.assetCalls != before {
		t.Fatalf("localized screenshot discovery called upstream: before=%d after=%d", before, adapter.assetCalls)
	}
	if result.Downloaded != 1 || len(result.Screenshots) != 1 {
		t.Fatalf("unexpected localized screenshot sync: %#v", result)
	}
}

func TestStopTaskHistoryResolvesRemoteTaskID(t *testing.T) {
	service, adapter := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	localID := meaningfulString(valueMap(created)["local_task_id"])
	view, err := service.StopTaskHistory(context.Background(), localID)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.stoppedID != "7" || view.Status != "stopped" {
		t.Fatalf("unexpected stop mapping: remote=%q view=%#v", adapter.stoppedID, view)
	}
}

func TestMCPTaskToolsResolveLocalTaskID(t *testing.T) {
	service, adapter := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	localID := meaningfulString(valueMap(created)["local_task_id"])
	if _, err := service.GetTask(context.Background(), resource.ID, localID); err != nil {
		t.Fatal(err)
	}
	if adapter.gotTaskID != "7" {
		t.Fatalf("get task received %q instead of provider ID", adapter.gotTaskID)
	}
	if _, err := service.ListAssets(context.Background(), resource.ID, AssetFilter{TaskID: localID, Type: "site"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.StopTask(context.Background(), resource.ID, localID); err != nil {
		t.Fatal(err)
	}
	if adapter.stoppedID != "7" {
		t.Fatalf("stop task received %q instead of provider ID", adapter.stoppedID)
	}
}

func TestTaskHistoryResultDetailUsesProviderAdapter(t *testing.T) {
	service, adapter := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	localID := meaningfulString(valueMap(created)["local_task_id"])
	detail, err := service.GetTaskHistoryResultDetail(context.Background(), localID, AssetDetailFilter{Type: "vulnerability", Key: "hash-one"})
	if err != nil || adapter.detailCalls != 1 || !strings.Contains(fmt.Sprint(detail), "HTTP/1.1 200 OK") {
		t.Fatalf("unexpected result detail: %#v calls=%d err=%v", detail, adapter.detailCalls, err)
	}
	if _, err := service.GetTaskHistoryResultDetail(context.Background(), localID, AssetDetailFilter{Type: "vulnerability"}); err == nil {
		t.Fatal("empty detail key was accepted")
	}
}

func TestMCPListAssetsReadsCompletedLocalResultWithoutUpstream(t *testing.T) {
	service, adapter := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	localID := meaningfulString(valueMap(created)["local_task_id"])
	task, err := service.db.GetASMTask(localID)
	if err != nil {
		t.Fatal(err)
	}
	task.Status, task.Progress = "completed", 100
	if err := service.db.UpdateASMTask(task); err != nil {
		t.Fatal(err)
	}
	if _, err := service.syncTaskResultType(context.Background(), task, "site"); err != nil {
		t.Fatal(err)
	}
	calls := adapter.assetCalls
	adapter.assetsErr = errors.New("upstream must not be called")
	result, err := service.ListAssets(context.Background(), resource.ID, AssetFilter{TaskID: "7", Type: "site", Page: 1, PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.assetCalls != calls {
		t.Fatalf("MCP local read called upstream: before=%d after=%d", calls, adapter.assetCalls)
	}
	view, ok := result.(TaskResultsView)
	if !ok || view.Source != "local" || view.Stale {
		t.Fatalf("unexpected MCP local result: %#v", result)
	}
}

func TestRequestTaskResultsSyncMarksQueuedTypesPending(t *testing.T) {
	service, _ := newTaskHistoryTestService(t)
	resource, err := service.CreateResource(CreateResourceInput{
		Name: "XingRin", Provider: ProviderXingRin, BaseURL: "https://asm.example.test",
		Username: "admin", Credential: "secret", AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateTask(context.Background(), resource.ID, TaskRequest{Target: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	localID := meaningfulString(valueMap(created)["local_task_id"])
	task, err := service.db.GetASMTask(localID)
	if err != nil {
		t.Fatal(err)
	}
	task.Status, task.Progress = "completed", 100
	if err := service.db.UpdateASMTask(task); err != nil {
		t.Fatal(err)
	}

	service.resultSyncSem <- struct{}{}
	view, err := service.RequestTaskResultsSync(localID)
	if err != nil {
		<-service.resultSyncSem
		t.Fatal(err)
	}
	if view.Status != "pending" || len(view.Types) != len(providerResultTypes(ProviderXingRin)) {
		<-service.resultSyncSem
		t.Fatalf("unexpected queued result sync view: %#v", view)
	}
	for _, state := range view.Types {
		if state.Status != "pending" {
			<-service.resultSyncSem
			t.Fatalf("result type %s was not marked pending: %#v", state.AssetType, state)
		}
	}
	<-service.resultSyncSem

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, getErr := service.GetTaskHistory(localID)
		if getErr == nil && current.ResultSync.Status == "completed" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("queued result sync did not complete")
}

func TestResolveScreenshotURLRequiresSameOrigin(t *testing.T) {
	if got, err := resolveScreenshotURL("https://asm.example.test/base", "/image/one.png"); err != nil || got != "https://asm.example.test/image/one.png" {
		t.Fatalf("unexpected resolved URL: %q err=%v", got, err)
	}
	for _, reference := range []string{"https://attacker.example/one.png", "//attacker.example/one.png", "file:///tmp/one.png"} {
		if _, err := resolveScreenshotURL("https://asm.example.test", reference); err == nil {
			t.Fatalf("expected reference to be rejected: %s", reference)
		}
	}
}

func TestTaskCollectionSupportsARLItemsEnvelope(t *testing.T) {
	payload := map[string]interface{}{"tasks": map[string]interface{}{"items": []interface{}{
		map[string]interface{}{"_id": "0123456789abcdef01234567", "status": "done"},
	}}}
	items := taskCollection(ProviderARL, payload)
	if len(items) != 1 || meaningfulString(valueMap(items[0])["_id"]) != "0123456789abcdef01234567" {
		t.Fatalf("unexpected ARL task collection: %#v", items)
	}
}

func TestARLTaskCreationSupportsItemsEnvelope(t *testing.T) {
	payload := map[string]interface{}{
		"response": map[string]interface{}{
			"items": []interface{}{map[string]interface{}{
				"task_id": "6a7bd803e30e79c5bea45807",
				"status":  "waiting",
			}},
		},
	}
	if got := remoteTaskID(ProviderARL, payload); got != "6a7bd803e30e79c5bea45807" {
		t.Fatalf("unexpected ARL remote task ID: %q", got)
	}
	if got := creationStatus(ProviderARL, payload); got != "submitted" {
		t.Fatalf("unexpected ARL creation status: %q", got)
	}
}

func TestNormalizeARLTaskStages(t *testing.T) {
	for input, expected := range map[string]string{
		"waiting":   "submitted",
		"port_scan": "running",
		"find_site": "running",
		"stop":      "stopped",
	} {
		if got := normalizeTaskStatus(input); got != expected {
			t.Errorf("normalizeTaskStatus(%q) = %q, want %q", input, got, expected)
		}
	}
	if got := normalizeProviderTaskStatus(ProviderARL, "future_pipeline_stage"); got != "running" {
		t.Fatalf("future ARL pipeline stage was not treated as running: %q", got)
	}
}

func TestScopeSentryTaskCollectionIncludesScheduledDefinitions(t *testing.T) {
	payload := map[string]interface{}{
		"tasks": map[string]interface{}{"data": map[string]interface{}{"list": []interface{}{
			map[string]interface{}{"id": "64b000000000000000000001", "name": "immediate"},
		}}},
		"scheduled_tasks": map[string]interface{}{"data": map[string]interface{}{"list": []interface{}{
			map[string]interface{}{"id": "64b000000000000000000002", "name": "scheduled", "stage": "scheduled"},
		}}},
	}
	items := taskCollection(ProviderScopeSentry, payload)
	if len(items) != 2 {
		t.Fatalf("taskCollection len=%d items=%#v", len(items), items)
	}
}
