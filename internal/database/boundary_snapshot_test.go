package database

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
	"go.uber.org/zap"
)

func newBoundarySnapshotTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "boundary-snapshot.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func createSnapshotTestPolicy(t *testing.T, db *DB) BoundaryPolicy {
	t.Helper()
	ctx := context.Background()
	policy, err := db.CreateBoundaryPolicy(ctx, BoundaryPolicy{ID: "policy-canonical", Name: "Canonical policy"})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []BoundaryPolicyRule{
		{ID: "rule-b", PolicyID: policy.ID, Effect: boundary.EffectBlocked, Host: "blocked.example", Position: 1},
		{
			ID: "rule-a", PolicyID: policy.ID, Effect: boundary.EffectAllowVisit, Host: "API.EXAMPLE.",
			Schemes: []string{"https", "HTTP", "https"}, Ports: []int{443, 80, 443},
			PathPrefixes: []string{"/v1//", "/"}, Methods: []string{"post", "GET"},
			RateLimit: BoundaryRateLimit{RequestsPerSecond: 2.5, Burst: 4}, Position: 1,
		},
	} {
		if _, err := db.CreateBoundaryPolicyRule(ctx, rule); err != nil {
			t.Fatal(err)
		}
	}
	return policy
}

func createSnapshotTestConversation(t *testing.T, db *DB, policyID string) *Conversation {
	t.Helper()
	conversation, err := db.CreateConversation("snapshot", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer, BoundaryPolicyID: policyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return conversation
}

func TestConversationBoundarySnapshotCanonicalJSONAndSHA256(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	policy := createSnapshotTestPolicy(t, db)
	conversation := createSnapshotTestConversation(t, db, policy.ID)

	snapshot, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	const wantCanonical = `{"schemaVersion":1,"policyId":"policy-canonical","rules":[{"id":"rule-a","effect":"allow-visit","host":"api.example","schemes":["http","https"],"ports":[80,443],"pathPrefixes":["/","/v1/"],"methods":["GET","POST"],"authProfileId":null,"rateLimit":{"requestsPerSecond":2.5,"burst":4},"expiresAt":null,"position":1},{"id":"rule-b","effect":"blocked","host":"blocked.example","schemes":[],"ports":[],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":1}]}`
	const wantSHA256 = "sha256:bd40ddba728f458b9fa80c966b41e250e9a526ef3d57a4a88475e1edb1999c11"
	if snapshot.CanonicalJSON != wantCanonical {
		t.Fatalf("canonical JSON = %s", snapshot.CanonicalJSON)
	}
	if snapshot.SHA256 != wantSHA256 {
		t.Fatalf("sha256 = %s", snapshot.SHA256)
	}
	if snapshot.Document.PolicyID != policy.ID || len(snapshot.Document.Rules) != 2 || snapshot.Document.Rules[0].ID != "rule-a" {
		t.Fatalf("document = %#v", snapshot.Document)
	}
	var selectionCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversation_boundary_policy_selections WHERE conversation_id = ?`, conversation.ID).Scan(&selectionCount); err != nil {
		t.Fatal(err)
	}
	if selectionCount != 0 {
		t.Fatalf("selection count = %d", selectionCount)
	}
	loaded, err := db.GetConversationBoundarySnapshot(context.Background(), conversation.ID)
	if err != nil || loaded.CanonicalJSON != snapshot.CanonicalJSON || loaded.SHA256 != snapshot.SHA256 {
		t.Fatalf("loaded = %#v, %v", loaded, err)
	}
}

func TestConversationBoundarySnapshotConcurrentEnsureIsIdempotent(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	policy := createSnapshotTestPolicy(t, db)
	conversation := createSnapshotTestConversation(t, db, policy.ID)

	const workers = 20
	start := make(chan struct{})
	results := make(chan ConversationBoundarySnapshot, workers)
	errorsCh := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversation.ID)
			if err != nil {
				errorsCh <- err
				return
			}
			results <- result
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		t.Errorf("concurrent ensure: %v", err)
	}
	var first ConversationBoundarySnapshot
	for result := range results {
		if first.SnapshotID == "" {
			first = result
			continue
		}
		if result.SnapshotID != first.SnapshotID || result.SHA256 != first.SHA256 || result.CanonicalJSON != first.CanonicalJSON {
			t.Errorf("non-idempotent result = %#v; first = %#v", result, first)
		}
	}
	var snapshots, bindings int
	if err := db.QueryRow(`SELECT COUNT(*) FROM boundary_policy_snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversation_boundary_bindings WHERE conversation_id = ?`, conversation.ID).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if snapshots != 1 || bindings != 1 {
		t.Fatalf("snapshots/bindings = %d/%d", snapshots, bindings)
	}
}

func TestConversationBoundarySnapshotDoesNotFollowDraftEdits(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	policy := createSnapshotTestPolicy(t, db)
	firstConversation := createSnapshotTestConversation(t, db, policy.ID)
	first, err := db.EnsureConversationBoundarySnapshot(context.Background(), firstConversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		UPDATE boundary_policy_rules SET host = ?, updated_at = ? WHERE id = ?
	`, "changed.example", formatSQLiteUTC(time.Now().UTC()), "rule-a"); err != nil {
		t.Fatal(err)
	}
	again, err := db.EnsureConversationBoundarySnapshot(context.Background(), firstConversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.SnapshotID != first.SnapshotID || again.SHA256 != first.SHA256 || again.CanonicalJSON != first.CanonicalJSON {
		t.Fatalf("bound snapshot changed: before=%#v after=%#v", first, again)
	}

	secondConversation := createSnapshotTestConversation(t, db, policy.ID)
	second, err := db.EnsureConversationBoundarySnapshot(context.Background(), secondConversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second.SHA256 == first.SHA256 || second.CanonicalJSON == first.CanonicalJSON {
		t.Fatalf("new conversation did not capture edited draft: first=%s second=%s", first.SHA256, second.SHA256)
	}
}

func TestConversationBoundarySnapshotDefaultDenyAndSelectionValidation(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	conversation := createSnapshotTestConversation(t, db, "")
	snapshot, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.PolicyID != "" || len(snapshot.Document.Rules) != 0 || snapshot.CanonicalJSON != `{"schemaVersion":1,"policyId":"","rules":[]}` {
		t.Fatalf("default-deny snapshot = %#v", snapshot)
	}
	host, err := db.CreateConversation("host", ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeHost})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SelectConversationBoundaryPolicy(context.Background(), host.ID, "missing"); err == nil {
		t.Fatal("host conversation accepted a boundary policy")
	}
	if _, err := db.CreateConversation("invalid host", ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeHost, BoundaryPolicyID: "missing"}); err == nil {
		t.Fatal("host conversation creation accepted a boundary policy")
	}
	if _, err := db.CreateConversation("missing policy", ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeContainer, BoundaryPolicyID: "missing"}); err == nil {
		t.Fatal("missing boundary policy was accepted")
	}
}

func TestConversationBoundarySnapshotSQLiteImmutabilityAndCascade(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	policy := createSnapshotTestPolicy(t, db)
	conversation := createSnapshotTestConversation(t, db, policy.ID)
	snapshot, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE boundary_policy_snapshots SET source_policy_id = '' WHERE id = ?`, snapshot.SnapshotID); err == nil {
		t.Fatal("SQLite updated an immutable snapshot")
	}
	if _, err := db.Exec(`DELETE FROM boundary_policy_snapshots WHERE id = ?`, snapshot.SnapshotID); err == nil {
		t.Fatal("SQLite deleted an immutable snapshot")
	}
	if _, err := db.Exec(`UPDATE conversation_boundary_bindings SET bound_at = ? WHERE conversation_id = ?`, formatSQLiteUTC(time.Now()), conversation.ID); err == nil {
		t.Fatal("SQLite updated an immutable binding")
	}
	if _, err := db.Exec(`DELETE FROM conversation_boundary_bindings WHERE conversation_id = ?`, conversation.ID); err == nil {
		t.Fatal("SQLite deleted a live immutable binding")
	}
	if err := db.DeleteConversation(conversation.ID); err != nil {
		t.Fatalf("conversation cascade was blocked: %v", err)
	}
	var bindings, snapshots int
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversation_boundary_bindings WHERE conversation_id = ?`, conversation.ID).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM boundary_policy_snapshots WHERE id = ?`, snapshot.SnapshotID).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if bindings != 0 || snapshots != 1 {
		t.Fatalf("post-delete bindings/snapshots = %d/%d", bindings, snapshots)
	}
}

func TestConversationBoundarySnapshotDetectsTamperedDigest(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	conversation := createSnapshotTestConversation(t, db, "")
	now := formatSQLiteUTC(time.Now().UTC())
	canonical := `{"schemaVersion":1,"policyId":"","rules":[]}`
	badDigest := "sha256:" + "0" + "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := db.Exec(`
		INSERT INTO boundary_policy_snapshots (id, source_policy_id, canonical_json, sha256, created_at)
		VALUES ('tampered', '', ?, ?, ?)
	`, canonical, badDigest, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO conversation_boundary_bindings (conversation_id, snapshot_id, bound_at)
		VALUES (?, 'tampered', ?)
	`, conversation.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetConversationBoundarySnapshot(context.Background(), conversation.ID); !errors.Is(err, ErrBoundarySnapshotIntegrity) {
		t.Fatalf("tampered digest error = %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO boundary_policy_snapshots (id, source_policy_id, canonical_json, sha256, created_at)
		VALUES ('noncanonical', '', ?, ?, ?)
	`, `{ "schemaVersion": 1, "policyId": "", "rules": [] }`, badDigest, now); err == nil {
		t.Fatal("SQLite accepted non-canonical JSON")
	}
}

func TestEnsureContainerRuntimeBoundarySnapshotsOnlyMigratesDurableRuntimes(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	policy := createSnapshotTestPolicy(t, db)
	unused := createSnapshotTestConversation(t, db, policy.ID)
	queued := createSnapshotTestConversation(t, db, policy.ID)
	if _, _, err := db.Queue(context.Background(), databaseRuntimeSpec(queued.ID), false); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureContainerRuntimeBoundarySnapshots(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetConversationBoundarySnapshot(context.Background(), queued.ID); err != nil {
		t.Fatalf("durable runtime snapshot = %v", err)
	}
	if _, err := db.GetConversationBoundarySnapshot(context.Background(), unused.ID); !errors.Is(err, ErrConversationBoundarySnapshotNotFound) {
		t.Fatalf("unused conversation was frozen during migration: %v", err)
	}
	var selected string
	if err := db.QueryRow(`SELECT policy_id FROM conversation_boundary_policy_selections WHERE conversation_id = ?`, unused.ID).Scan(&selected); err != nil || selected != policy.ID {
		t.Fatalf("unused selection = %q, %v", selected, err)
	}
}
