package egress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSnapshotID = "12345678-1234-1234-1234-123456789abc"

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(content []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(content)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func testSnapshot(t *testing.T, content string) SnapshotReference {
	t.Helper()
	digest := sha256.Sum256([]byte(content))
	return SnapshotReference{ID: testSnapshotID, SHA256: "sha256:" + hex.EncodeToString(digest[:])}
}

func TestSnapshotStorePublishesImmutableReadOnlyFile(t *testing.T) {
	store, err := NewSnapshotStore(filepath.Join(t.TempDir(), "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Stat(store.Root())
	if err != nil {
		t.Fatal(err)
	}
	if rootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("snapshot root mode = %o, want 700", rootInfo.Mode().Perm())
	}
	content := `{"schemaVersion":1,"policyId":"","rules":[]}`
	reference := testSnapshot(t, content)
	padded := reference
	padded.ID = " " + padded.ID
	if _, err := store.Path(padded); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("padded snapshot id error = %v", err)
	}
	padded = reference
	padded.SHA256 += " "
	if _, err := store.Path(padded); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("padded snapshot digest error = %v", err)
	}
	path, err := store.Put(reference, content)
	if err != nil {
		t.Fatalf("put snapshot: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o444 || filepath.Dir(path) != store.Root() {
		t.Fatalf("snapshot path/mode = %q / %o", path, info.Mode().Perm())
	}
	if second, err := store.Put(reference, content); err != nil || second != path {
		t.Fatalf("idempotent put = %q, %v", second, err)
	}
	if _, err := store.Put(reference, strings.Replace(content, `[]`, `[{}]`, 1)); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("conflicting put error = %v", err)
	}
}

func TestLoadSnapshotRejectsDigestSchemaAndFileDrift(t *testing.T) {
	valid := `{"schemaVersion":1,"policyId":"policy-1","rules":[{}]}`
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte(valid), 0o444); err != nil {
		t.Fatal(err)
	}
	reference := testSnapshot(t, valid)
	if _, err := LoadSnapshot(path, reference); err != nil {
		t.Fatalf("load valid snapshot: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSnapshot(path, reference); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("writable snapshot error = %v", err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	tampered := reference
	tampered.SHA256 = "sha256:" + strings.Repeat("a", 64)
	if _, err := LoadSnapshot(path, tampered); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("digest drift error = %v", err)
	}
	unknown := `{"schemaVersion":1,"policyId":"","rules":[],"extra":true}`
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(unknown), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSnapshot(path, testSnapshot(t, unknown)); !errors.Is(err, ErrSnapshotIntegrity) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestConfiguredGatewayReportsSnapshotAndStopsOnCancellation(t *testing.T) {
	content := `{"schemaVersion":1,"policyId":"","rules":[]}`
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte(content), 0o444); err != nil {
		t.Fatal(err)
	}
	reference := testSnapshot(t, content)
	ctx, cancel := context.WithCancel(context.Background())
	var output lockedBuffer
	done := make(chan error, 1)
	go func() { done <- RunWithSnapshot(ctx, path, reference, &output) }()
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(output.String(), reference.SHA256) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(output.String(), `"event":"boundary_snapshot_loaded"`) {
		t.Fatalf("startup report = %q", output.String())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gateway shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway did not stop")
	}
}
