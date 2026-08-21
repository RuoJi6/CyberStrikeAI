package database

import (
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/mcp"

	"go.uber.org/zap"
)

func TestToolExecutionAuditIdentityRoundTripsAcrossQueries(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "tool-execution-audit.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, column := range []string{"execution_location", "container_id", "image_digest"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('tool_executions') WHERE name = ?", column).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("tool_executions column %q count = %d", column, count)
		}
	}

	want := &mcp.ToolExecution{
		ID:                "execution-audit-1",
		ToolName:          "exec",
		Arguments:         map[string]interface{}{"command": "id"},
		Status:            mcp.ToolExecutionStatusCompleted,
		StartTime:         time.Now().UTC().Truncate(time.Millisecond),
		ExecutionLocation: "container",
		ContainerID:       "docker-container-abc",
		ImageDigest:       "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	if err := db.SaveToolExecution(want); err != nil {
		t.Fatal(err)
	}

	assertIdentity := func(label string, got *mcp.ToolExecution) {
		t.Helper()
		if got == nil || got.ExecutionLocation != want.ExecutionLocation || got.ContainerID != want.ContainerID || got.ImageDigest != want.ImageDigest {
			t.Fatalf("%s identity = %#v", label, got)
		}
	}
	got, err := db.GetToolExecution(want.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertIdentity("detail", got)
	all, err := db.LoadToolExecutionsWithPagination(0, 10, "", "")
	if err != nil || len(all) != 1 {
		t.Fatalf("all = %#v err=%v", all, err)
	}
	assertIdentity("all", all[0])
	list, err := db.LoadToolExecutionListPage(0, 10, "", "")
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %#v err=%v", list, err)
	}
	assertIdentity("list", list[0])
	batch, err := db.GetToolExecutionsByIds([]string{want.ID})
	if err != nil || len(batch) != 1 {
		t.Fatalf("batch = %#v err=%v", batch, err)
	}
	assertIdentity("batch", batch[0])
}
