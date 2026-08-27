package trafficspool

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/traffic"
)

type memoryStore struct {
	items map[string]traffic.TransactionDetail
}

func (s *memoryStore) CreateTrafficTransaction(_ context.Context, item *traffic.Transaction, messages []traffic.Message) (*traffic.TransactionDetail, error) {
	if s.items == nil {
		s.items = make(map[string]traffic.TransactionDetail)
	}
	detail := traffic.TransactionDetail{Transaction: *item, Messages: messages}
	s.items[item.ID] = detail
	return &detail, nil
}

func TestWriterAndCollectorRoundTrip(t *testing.T) {
	root := t.TempDir()
	conversationID := "conversation-01"
	conversationRoot := filepath.Join(root, conversationID)
	writer, err := NewWriter(conversationRoot, conversationID)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	item := traffic.Transaction{
		ID: "transaction-01", ConversationID: conversationID,
		RuntimeMode: traffic.RuntimeModeContainer, CaptureCoverage: traffic.CaptureCoverageEnforced,
		Scheme: "https", Host: "example.test", Port: 443, Method: "GET", Path: "/", StartedAt: time.Now().UTC(),
	}
	if err := writer.Write(context.Background(), item, nil); err != nil {
		t.Fatalf("Write: %v", err)
	}
	readyPath := filepath.Join(conversationRoot, item.ID+".ready")
	info, err := os.Stat(readyPath)
	if err != nil {
		t.Fatalf("ready envelope: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("ready envelope mode = %v", info.Mode().Perm())
	}
	store := &memoryStore{}
	collector, err := NewCollector(root, store)
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	report, err := collector.Reconcile(context.Background())
	if err != nil || report.Imported != 1 || len(store.items) != 1 || store.items[item.ID].Transaction.ConversationID != conversationID {
		t.Fatalf("Reconcile = %#v, %#v, %v", report, store.items, err)
	}
	if _, err := os.Stat(filepath.Join(conversationRoot, item.ID+".ready")); !os.IsNotExist(err) {
		t.Fatalf("ready envelope was not acknowledged: %v", err)
	}
}

func TestCollectorQuarantinesMalformedEnvelope(t *testing.T) {
	root := t.TempDir()
	conversationRoot := filepath.Join(root, "conversation-01")
	if err := os.MkdirAll(conversationRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(conversationRoot, "transaction-01.ready")
	if err := os.WriteFile(ready, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	collector, err := NewCollector(root, &memoryStore{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := collector.Reconcile(context.Background())
	if err != nil || report.Quarantined != 1 {
		t.Fatalf("Reconcile = %#v, %v", report, err)
	}
	if _, err := os.Stat(filepath.Join(conversationRoot, "transaction-01.bad")); err != nil {
		t.Fatalf("quarantine file: %v", err)
	}
}

func TestCollectorQuarantinesSemanticallyInvalidEnvelopeWithoutBlockingValidRecords(t *testing.T) {
	root := t.TempDir()
	conversationID := "conversation-01"
	conversationRoot := filepath.Join(root, conversationID)
	writer, err := NewWriter(conversationRoot, conversationID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	invalid := traffic.Transaction{
		ID: "a-invalid", ConversationID: conversationID,
		RuntimeMode: traffic.RuntimeModeContainer, CaptureCoverage: traffic.CaptureCoverageEnforced,
		Scheme: "https", Host: "example.test", Port: 443, Method: "CONNECT", Path: "example.test:443", StartedAt: now,
	}
	if err := writer.Write(context.Background(), invalid, nil); err != nil {
		t.Fatal(err)
	}
	valid := invalid
	valid.ID, valid.Method, valid.Path = "b-valid", "GET", "/"
	if err := writer.Write(context.Background(), valid, nil); err != nil {
		t.Fatal(err)
	}
	store := &memoryStore{}
	collector, err := NewCollector(root, store)
	if err != nil {
		t.Fatal(err)
	}
	report, err := collector.Reconcile(context.Background())
	if err != nil || report.Quarantined != 1 || report.Imported != 1 || len(store.items) != 1 {
		t.Fatalf("Reconcile = %#v / %#v / %v", report, store.items, err)
	}
}

func TestDirectoryDerivesOnlyCanonicalConversationPath(t *testing.T) {
	root := t.TempDir()
	directory, err := NewDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	path, err := directory.ConversationPath("conversation-01")
	if err != nil || path != filepath.Join(directory.Root(), "conversation-01") {
		t.Fatalf("ConversationPath = %q / %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o703 {
		t.Fatalf("conversation directory mode = %v / %v", info.Mode().Perm(), err)
	}
	for _, invalid := range []string{"", "../escape", "conversation/child", ".hidden"} {
		if _, err := directory.ConversationPath(invalid); err == nil {
			t.Fatalf("expected %q to be rejected", invalid)
		}
	}
}

func TestWriterDoesNotMutateExistingBindDirectoryPermissions(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conversation-01")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWriter(root, "conversation-01"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("writer directory mode = %v", info.Mode().Perm())
	}
	if err := os.Chmod(root, 0o703); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWriter(root, "conversation-01"); err != nil {
		t.Fatalf("write-only bind directory: %v", err)
	}
	info, err = os.Stat(root)
	if err != nil || info.Mode().Perm() != 0o703 {
		t.Fatalf("writer changed bind directory mode = %v / %v", info.Mode().Perm(), err)
	}
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWriter(root, "conversation-01"); err == nil {
		t.Fatal("expected group-readable writer directory to be rejected")
	}
}
