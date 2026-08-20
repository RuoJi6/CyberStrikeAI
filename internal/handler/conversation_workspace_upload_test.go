package handler

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
)

type recordingConversationUploadImporter struct {
	paths   []string
	content []string
}

func (i *recordingConversationUploadImporter) ImportConversationUpload(_ context.Context, _ string, workspacePath string, content io.Reader, _ int64) (string, error) {
	data, err := io.ReadAll(content)
	if err != nil {
		return "", err
	}
	i.paths = append(i.paths, workspacePath)
	i.content = append(i.content, string(data))
	return workspacePath, nil
}

func TestConversationUploadWorkspacePathIsConversationScoped(t *testing.T) {
	t.Chdir(t.TempDir())
	conversationID := "conversation-01"
	hostPath := filepath.Join("chat_uploads", "2026-08-20", conversationID, "nested", "input.txt")
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostPath, []byte("input"), 0o644); err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	workspacePath, err := conversationUploadWorkspacePath(absolute, conversationID)
	if err != nil {
		t.Fatal(err)
	}
	if workspacePath != "/workspace/uploads/2026-08-20/nested/input.txt" {
		t.Fatalf("workspace path = %q", workspacePath)
	}
	if _, err := conversationUploadWorkspacePath(absolute, "conversation-02"); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("cross-conversation path error = %v", err)
	}
}

func TestConversationUploadRejectsSymlinkSource(t *testing.T) {
	t.Chdir(t.TempDir())
	conversationID := "conversation-01"
	directory := filepath.Join("chat_uploads", "2026-08-20", conversationID)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "link.txt")
	if err := os.Symlink(outside, symlink); err != nil {
		t.Fatal(err)
	}
	absolute, _ := filepath.Abs(symlink)
	if _, err := conversationUploadWorkspacePath(absolute, conversationID); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink attachment error = %v", err)
	}
}

func TestSyncConversationUploadsImportsDurablePendingFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	conversationID := "conversation-01"
	files := map[string]string{
		filepath.Join("chat_uploads", "2026-08-19", conversationID, "first.txt"):    "first",
		filepath.Join("chat_uploads", "2026-08-20", conversationID, "second.txt"):   "second",
		filepath.Join("chat_uploads", "2026-08-20", "conversation-02", "other.txt"): "other",
	}
	for filePath, content := range files {
		if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	importer := &recordingConversationUploadImporter{}
	handler := &AgentHandler{containerUploadImporter: importer}
	err := handler.syncConversationUploadsToWorkspace(context.Background(), &database.Conversation{
		ID: conversationID, RuntimeMode: database.ConversationRuntimeModeContainer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(importer.paths, ",") != "/workspace/uploads/2026-08-19/first.txt,/workspace/uploads/2026-08-20/second.txt" {
		t.Fatalf("imported paths = %#v", importer.paths)
	}
	if strings.Join(importer.content, ",") != "first,second" {
		t.Fatalf("imported content = %#v", importer.content)
	}
}

func TestSafeChatUploadBaseNameNormalizesWindowsTraversal(t *testing.T) {
	if got := safeChatUploadBaseName(`..\..\payload.sh`); got != "payload.sh" {
		t.Fatalf("safe upload base name = %q", got)
	}
}
