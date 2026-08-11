package asm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

type taskHistoryTestAdapter struct {
	assetsErr error
}

func (a *taskHistoryTestAdapter) Provider() string { return ProviderXingRin }
func (a *taskHistoryTestAdapter) Capabilities() []string {
	return []string{"create_task", "get_task", "list_assets"}
}
func (a *taskHistoryTestAdapter) Test(context.Context, *Connection) (interface{}, error) {
	return map[string]interface{}{"connected": true}, nil
}
func (a *taskHistoryTestAdapter) CreateTask(context.Context, *Connection, TaskRequest) (interface{}, error) {
	return map[string]interface{}{
		"provider": ProviderXingRin,
		"response": map[string]interface{}{"scans": []interface{}{map[string]interface{}{"id": 7, "status": "initiated"}}},
	}, nil
}
func (a *taskHistoryTestAdapter) ListTasks(context.Context, *Connection, TaskFilter) (interface{}, error) {
	return map[string]interface{}{"tasks": map[string]interface{}{"results": []interface{}{
		map[string]interface{}{"id": 8, "status": "completed", "progress": 100, "targetName": "192.0.2.11", "createdAt": "2026-08-11T12:00:00Z"},
	}}}, nil
}
func (a *taskHistoryTestAdapter) GetTask(context.Context, *Connection, string) (interface{}, error) {
	return map[string]interface{}{"tasks": map[string]interface{}{"results": []interface{}{map[string]interface{}{
		"id": 7, "status": "running", "progress": 42, "currentStage": "site_scan",
		"summary": map[string]interface{}{"websites": 1},
	}}}}, nil
}
func (a *taskHistoryTestAdapter) ListAssets(context.Context, *Connection, AssetFilter) (interface{}, error) {
	if a.assetsErr != nil {
		return nil, a.assetsErr
	}
	return map[string]interface{}{"results": map[string]interface{}{"results": []interface{}{
		map[string]interface{}{"url": "https://example.test", "screenshot": "/shot.png"},
	}}}, nil
}
func (a *taskHistoryTestAdapter) StopTask(context.Context, *Connection, string) (interface{}, error) {
	return map[string]interface{}{}, nil
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

	results, err := service.ListTaskHistoryResults(context.Background(), localID, AssetFilter{Type: "site"})
	if err != nil || results.Stale {
		t.Fatalf("unexpected live results: %#v, err=%v", results, err)
	}
	adapter.assetsErr = errors.New("remote unavailable")
	cached, err := service.ListTaskHistoryResults(context.Background(), localID, AssetFilter{Type: "site"})
	if err != nil || !cached.Stale || cached.CachedAt == nil {
		t.Fatalf("expected cached fallback: %#v, err=%v", cached, err)
	}
	if _, err := service.ListTasks(context.Background(), resource.ID, TaskFilter{Page: 1, PageSize: 20}); err != nil {
		t.Fatal(err)
	}
	imported, err := service.ListTaskHistory(TaskHistoryFilter{Query: "192.0.2.11"})
	if err != nil || imported.Total != 1 || imported.Tasks[0].RemoteTaskID != "8" || imported.Tasks[0].Status != "completed" {
		t.Fatalf("unexpected imported remote task: %#v err=%v", imported, err)
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
