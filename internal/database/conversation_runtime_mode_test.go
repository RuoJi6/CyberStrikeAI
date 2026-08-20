package database

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestConversationRuntimeModeCreateAndRead(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "runtime-mode.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	hostConversation, err := db.CreateConversation("host", ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("CreateConversation host: %v", err)
	}
	if hostConversation.RuntimeMode != ConversationRuntimeModeHost {
		t.Fatalf("default runtime mode = %q, want host", hostConversation.RuntimeMode)
	}

	containerConversation, err := db.CreateConversation("container", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer, WorkspacePersistent: true,
	})
	if err != nil {
		t.Fatalf("CreateConversation container: %v", err)
	}
	if containerConversation.RuntimeMode != ConversationRuntimeModeContainer {
		t.Fatalf("container runtime mode = %q", containerConversation.RuntimeMode)
	}
	if !containerConversation.WorkspacePersistent {
		t.Fatal("container workspace persistence was not returned")
	}

	got, err := db.GetConversationLite(containerConversation.ID)
	if err != nil {
		t.Fatalf("GetConversationLite: %v", err)
	}
	if got.RuntimeMode != ConversationRuntimeModeContainer {
		t.Fatalf("stored runtime mode = %q", got.RuntimeMode)
	}
	if !got.WorkspacePersistent {
		t.Fatal("stored workspace persistence is false")
	}
	persistent, err := db.GetConversationWorkspacePersistent(containerConversation.ID)
	if err != nil || !persistent {
		t.Fatalf("workspace-only lookup = %v, err=%v", persistent, err)
	}
	mode, err := db.GetConversationRuntimeMode(containerConversation.ID)
	if err != nil || mode != ConversationRuntimeModeContainer {
		t.Fatalf("runtime-only lookup = %q, err=%v", mode, err)
	}

	list, err := db.ListConversations(20, 0, "", "", "")
	if err != nil {
		t.Fatalf("ListConversations: %v", err)
	}
	found := false
	for _, conversation := range list {
		if conversation.ID == containerConversation.ID {
			found = true
			if conversation.RuntimeMode != ConversationRuntimeModeContainer {
				t.Fatalf("listed runtime mode = %q", conversation.RuntimeMode)
			}
			if !conversation.WorkspacePersistent {
				t.Fatal("listed workspace persistence is false")
			}
		}
	}
	if !found {
		t.Fatal("container conversation missing from list")
	}

	if _, err := db.CreateConversation("invalid", ConversationCreateMeta{RuntimeMode: "docker"}); err == nil {
		t.Fatal("invalid runtime mode was accepted")
	}
	if _, err := db.CreateConversation("host persistent", ConversationCreateMeta{WorkspacePersistent: true}); err == nil {
		t.Fatal("host conversation accepted workspace persistence")
	}
}

func TestMigrateConversationsRuntimeModeDefaultsExistingRowsToHost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-runtime-mode.db")
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	if _, err := raw.Exec(`
		CREATE TABLE conversations (
			id TEXT PRIMARY KEY,
			title TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if _, err := raw.Exec(
		"INSERT INTO conversations (id, title, created_at, updated_at) VALUES (?, ?, ?, ?)",
		"legacy", "legacy", time.Now(), time.Now(),
	); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	db := &DB{DB: raw, logger: zap.NewNop()}
	if err := db.migrateConversationsTable(); err != nil {
		t.Fatalf("migrateConversationsTable: %v", err)
	}

	var mode string
	if err := raw.QueryRow("SELECT runtime_mode FROM conversations WHERE id = 'legacy'").Scan(&mode); err != nil {
		t.Fatalf("query migrated mode: %v", err)
	}
	if mode != ConversationRuntimeModeHost {
		t.Fatalf("legacy runtime mode = %q, want host", mode)
	}
	var persistent int
	if err := raw.QueryRow("SELECT workspace_persistent FROM conversations WHERE id = 'legacy'").Scan(&persistent); err != nil {
		t.Fatalf("query migrated workspace persistence: %v", err)
	}
	if persistent != 0 {
		t.Fatalf("legacy workspace persistence = %d, want 0", persistent)
	}
	if _, err := raw.Exec("UPDATE conversations SET runtime_mode = 'invalid' WHERE id = 'legacy'"); err == nil {
		t.Fatal("runtime_mode CHECK constraint did not reject invalid value")
	}
	if _, err := raw.Exec("UPDATE conversations SET workspace_persistent = 2 WHERE id = 'legacy'"); err == nil {
		t.Fatal("workspace_persistent CHECK constraint did not reject invalid value")
	}
}
