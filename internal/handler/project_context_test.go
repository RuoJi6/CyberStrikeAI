package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

func TestBuildWorkspaceBlockUsesContainerPathWithoutCreatingHostWorkspace(t *testing.T) {
	db, _ := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("container", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeContainer,
	})
	if err != nil {
		t.Fatal(err)
	}
	hostRoot := filepath.Join(t.TempDir(), "host-workspaces")
	h := &AgentHandler{
		db:     db,
		config: &config.Config{Agent: config.AgentConfig{WorkspaceRootDir: hostRoot}},
		logger: zap.NewNop(),
	}

	block := h.buildWorkspaceBlock(conversation.ID)
	if !strings.Contains(block, "/workspace") || strings.Contains(block, hostRoot) {
		t.Fatalf("container workspace block = %q", block)
	}
	if _, err := os.Stat(hostRoot); !os.IsNotExist(err) {
		t.Fatalf("container context created host workspace %q: %v", hostRoot, err)
	}
}

func TestBuildWorkspaceBlockKeepsHostConversationWorkspace(t *testing.T) {
	db, _ := setupConversationRBACTest(t)
	conversation, err := db.CreateConversation("host", database.ConversationCreateMeta{
		RuntimeMode: database.ConversationRuntimeModeHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	hostRoot := filepath.Join(t.TempDir(), "host-workspaces")
	h := &AgentHandler{
		db:     db,
		config: &config.Config{Agent: config.AgentConfig{WorkspaceRootDir: hostRoot}},
		logger: zap.NewNop(),
	}

	block := h.buildWorkspaceBlock(conversation.ID)
	if !strings.Contains(block, hostRoot) {
		t.Fatalf("host workspace block = %q", block)
	}
}

func TestBuildWorkspaceBlockFailsClosedWhenRuntimeModeCannotBeRead(t *testing.T) {
	db, _ := setupConversationRBACTest(t)
	hostRoot := filepath.Join(t.TempDir(), "must-not-be-created")
	h := &AgentHandler{
		db:     db,
		config: &config.Config{Agent: config.AgentConfig{WorkspaceRootDir: hostRoot}},
		logger: zap.NewNop(),
	}

	if block := h.buildWorkspaceBlock("missing-conversation"); block != "" {
		t.Fatalf("unexpected workspace fallback: %q", block)
	}
	if _, err := os.Stat(hostRoot); !os.IsNotExist(err) {
		t.Fatalf("runtime lookup failure created host workspace %q: %v", hostRoot, err)
	}
}
