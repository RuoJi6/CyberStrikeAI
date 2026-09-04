package database

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/boundary"
	containerruntime "cyberstrike-ai/internal/runtime/container"
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
	const wantCanonical = `{"schemaVersion":5,"policyId":"policy-canonical","rules":[{"id":"rule-a","effect":"allow-visit","host":"api.example","schemes":["http","https"],"ports":[80,443],"pathPrefixes":["/","/v1/"],"methods":["GET","POST"],"authProfileId":null,"rateLimit":{"requestsPerSecond":2.5,"burst":4},"expiresAt":null,"position":1},{"id":"rule-b","effect":"blocked","host":"blocked.example","schemes":[],"ports":[],"pathPrefixes":[],"methods":[],"authProfileId":null,"rateLimit":{"requestsPerSecond":0,"burst":0},"expiresAt":null,"position":1}],"tlsInspection":{"enabled":true,"bypassDomains":[]},"networkAccess":{"allowRestrictedTargets":false}}`
	const wantSHA256 = "sha256:fdca0dcb3cc94d7502611a4814f2b54d5d6d44d2dbace2aef021a35e9d9287fc"
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

func TestConversationBoundarySnapshotFreezesTLSInspectionAndCanonicalBypassDomains(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	policy, err := db.CreateBoundaryPolicy(context.Background(), BoundaryPolicy{
		ID: "tls-policy", Name: "TLS inspection", TLSInspectionEnabled: true,
		TLSBypassDomains: []string{"Pinned.Example.", "updates.example", "pinned.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateBoundaryPolicyRule(context.Background(), BoundaryPolicyRule{
		ID: "allow", PolicyID: policy.ID, Effect: boundary.EffectAllowVisit,
		Host: "target.example", Schemes: []string{"https"}, Methods: []string{"GET"},
	}); err != nil {
		t.Fatal(err)
	}
	conversation := createSnapshotTestConversation(t, db, policy.ID)
	snapshot, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Document.SchemaVersion != 5 || snapshot.Document.TLSInspection == nil || !snapshot.Document.TLSInspection.Enabled || len(snapshot.Document.TLSInspection.BypassDomains) != 2 || snapshot.Document.TLSInspection.BypassDomains[0] != "pinned.example" || snapshot.Document.NetworkAccess == nil || snapshot.Document.NetworkAccess.AllowRestrictedTargets {
		t.Fatalf("TLS snapshot = %#v", snapshot.Document)
	}
	if !strings.Contains(snapshot.CanonicalJSON, `"tlsInspection":{"enabled":true,"bypassDomains":["pinned.example","updates.example"]}`) {
		t.Fatalf("TLS canonical JSON = %s", snapshot.CanonicalJSON)
	}
	if _, err := db.UpdateBoundaryPolicy(context.Background(), BoundaryPolicy{ID: policy.ID, Name: policy.Name}); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.GetConversationBoundarySnapshot(context.Background(), conversation.ID)
	if err != nil || loaded.CanonicalJSON != snapshot.CanonicalJSON || loaded.Document.TLSInspection == nil {
		t.Fatalf("TLS snapshot changed with draft: %#v err=%v", loaded, err)
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
	var snapshots, bindings, activations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM boundary_policy_snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversation_boundary_bindings WHERE conversation_id = ?`, conversation.ID).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversation_boundary_activations WHERE conversation_id = ?`, conversation.ID).Scan(&activations); err != nil {
		t.Fatal(err)
	}
	if snapshots != 1 || bindings != 1 || activations != 1 {
		t.Fatalf("snapshots/bindings/activations = %d/%d/%d", snapshots, bindings, activations)
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

func TestConversationBoundarySnapshotDefaultAllowAndSelectionValidation(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	conversation := createSnapshotTestConversation(t, db, "")
	snapshot, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.PolicyID != "" || len(snapshot.Document.Rules) != 0 || snapshot.Document.DefaultAction != "allow" || snapshot.Document.TLSInspection == nil || !snapshot.Document.TLSInspection.Enabled || len(snapshot.Document.TLSInspection.BypassDomains) != 0 || snapshot.Document.NetworkAccess == nil || snapshot.Document.NetworkAccess.AllowRestrictedTargets || snapshot.CanonicalJSON != `{"schemaVersion":5,"policyId":"","rules":[],"tlsInspection":{"enabled":true,"bypassDomains":[]},"defaultAction":"allow","networkAccess":{"allowRestrictedTargets":false}}` {
		t.Fatalf("default-allow snapshot = %#v", snapshot)
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

func TestConversationBoundarySnapshotCapturesInitialNetworkAccess(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	conversation, err := db.CreateConversation("restricted targets", ConversationCreateMeta{
		RuntimeMode:   ConversationRuntimeModeContainer,
		NetworkAccess: ConversationNetworkAccess{AllowRestrictedTargets: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Document.SchemaVersion != boundaryPolicyNetworkAccessSchemaVersion || snapshot.Document.NetworkAccess == nil || !snapshot.Document.NetworkAccess.AllowRestrictedTargets {
		t.Fatalf("initial network access snapshot = %#v", snapshot.Document)
	}
	access, err := db.GetConversationNetworkAccess(context.Background(), conversation.ID)
	if err != nil || !access.AllowRestrictedTargets {
		t.Fatalf("stored network access = %#v, %v", access, err)
	}
	if _, err := db.CreateConversation("host restricted targets", ConversationCreateMeta{
		RuntimeMode:   ConversationRuntimeModeHost,
		NetworkAccess: ConversationNetworkAccess{AllowRestrictedTargets: true},
	}); err == nil {
		t.Fatal("host conversation accepted restricted target access")
	}
}

func TestLegacyNoBoundarySnapshotRemainsValid(t *testing.T) {
	document := BoundaryPolicySnapshotDocument{
		SchemaVersion: boundaryPolicyOpenSnapshotSchemaVersion,
		PolicyID:      "",
		Rules:         []BoundaryPolicySnapshotRule{},
		DefaultAction: "allow",
	}
	canonical, digest, err := canonicalBoundarySnapshot(document)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != `{"schemaVersion":3,"policyId":"","rules":[],"defaultAction":"allow"}` || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("legacy snapshot canonicalization = %q / %q", canonical, digest)
	}
	loaded, err := validateCanonicalBoundarySnapshot(canonical, digest)
	if err != nil || loaded.SchemaVersion != boundaryPolicyOpenSnapshotSchemaVersion || loaded.TLSInspection != nil {
		t.Fatalf("legacy snapshot validation = %#v / %v", loaded, err)
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
	if _, err := db.Exec(`UPDATE conversation_boundary_activations SET runtime_generation = 2 WHERE conversation_id = ?`, conversation.ID); err == nil {
		t.Fatal("SQLite updated an immutable activation")
	}
	if _, err := db.Exec(`DELETE FROM conversation_boundary_activations WHERE conversation_id = ?`, conversation.ID); err == nil {
		t.Fatal("SQLite deleted a live immutable activation")
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
	if _, err := db.Exec(`
		INSERT INTO conversation_boundary_activations (id, conversation_id, snapshot_id, runtime_generation, activated_at)
		VALUES ('tampered', ?, 'tampered', 1, ?)
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

func TestConversationBoundaryRebuildActivatesOnlyWithRuntimeGeneration(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	policy := createSnapshotTestPolicy(t, db)
	conversation := createSnapshotTestConversation(t, db, policy.ID)
	ctx := context.Background()
	initial, err := db.EnsureConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)
	if _, _, err := db.Queue(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(ctx, conversation.ID); err != nil || !claimed {
		t.Fatalf("claim runtime = %v, %v", claimed, err)
	}
	if _, err := db.Complete(ctx, conversation.ID, containerruntime.Runtime{
		ID: spec.ID, ProviderID: "provider-generation-1", Status: containerruntime.StatusStopped,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE boundary_policy_rules SET host = ? WHERE id = ?`, "rebuilt.example", "rule-a"); err != nil {
		t.Fatal(err)
	}
	pending, err := db.PrepareConversationBoundaryRebuild(ctx, conversation.ID, policy.ID, ConversationNetworkAccess{AllowRestrictedTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if pending.SnapshotID == initial.SnapshotID || pending.SHA256 == initial.SHA256 || pending.RuntimeGeneration != 2 {
		t.Fatalf("pending snapshot = %#v; initial = %#v", pending, initial)
	}
	if pending.Document.NetworkAccess == nil || !pending.Document.NetworkAccess.AllowRestrictedTargets {
		t.Fatalf("pending network access = %#v", pending.Document.NetworkAccess)
	}
	if access, accessErr := db.GetConversationNetworkAccess(ctx, conversation.ID); accessErr != nil || access.AllowRestrictedTargets {
		t.Fatalf("pending setting changed active access = %#v, %v", access, accessErr)
	}
	resolvedPending, err := db.GetPendingConversationBoundarySnapshot(ctx, conversation.ID, pending.SnapshotID)
	if err != nil || resolvedPending.SnapshotID != pending.SnapshotID || resolvedPending.SHA256 != pending.SHA256 || resolvedPending.CanonicalJSON != pending.CanonicalJSON {
		t.Fatalf("resolved exact pending snapshot = %#v, %v", resolvedPending, err)
	}
	if _, err := db.GetPendingConversationBoundarySnapshot(ctx, conversation.ID, initial.SnapshotID); !errors.Is(err, ErrConversationBoundarySnapshotNotFound) {
		t.Fatalf("active snapshot resolved as pending: %v", err)
	}
	otherConversation := createSnapshotTestConversation(t, db, policy.ID)
	if _, err := db.GetPendingConversationBoundarySnapshot(ctx, otherConversation.ID, pending.SnapshotID); !errors.Is(err, ErrConversationBoundarySnapshotNotFound) {
		t.Fatalf("cross-conversation pending snapshot resolved: %v", err)
	}
	active, err := db.GetConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil || active.SnapshotID != initial.SnapshotID || active.RuntimeGeneration != 1 {
		t.Fatalf("snapshot changed before rebuild: %#v, %v", active, err)
	}
	if _, err := db.PrepareConversationBoundaryRebuild(ctx, conversation.ID, policy.ID); !errors.Is(err, ErrConversationBoundaryRebuildPending) {
		t.Fatalf("concurrent prepare error = %v", err)
	}
	hasPending, err := db.HasPendingConversationBoundaryRebuild(ctx, conversation.ID)
	if err != nil || !hasPending {
		t.Fatalf("pending state = %v, %v", hasPending, err)
	}
	if _, err := db.BeginLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationRebuild); !errors.Is(err, containerruntime.ErrRuntimeStateConflict) {
		t.Fatalf("maintenance rebuild stole pending snapshot: %v", err)
	}
	rebuildCtx := containerruntime.WithBoundaryRebuildSnapshot(ctx, pending.SnapshotID)
	if _, err := db.BeginLifecycle(rebuildCtx, conversation.ID, containerruntime.LifecycleOperationRebuild); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE conversation_boundary_rebuilds SET expected_runtime_generation = 3 WHERE conversation_id = ?`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CompleteLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationRebuild, containerruntime.LifecycleCompletion{
		Runtime:             containerruntime.Runtime{ID: spec.ID, ProviderID: "provider-generation-2", Status: containerruntime.StatusStopped},
		IncrementGeneration: true,
	}); !errors.Is(err, containerruntime.ErrRuntimeStateConflict) {
		t.Fatalf("generation mismatch completion error = %v", err)
	}
	rolledBack, err := db.GetContainerInitialization(ctx, conversation.ID)
	if err != nil || rolledBack.RuntimeGeneration != 1 || rolledBack.LifecycleState != containerruntime.LifecycleInProgress {
		t.Fatalf("non-atomic lifecycle rollback = %#v, %v", rolledBack, err)
	}
	active, err = db.GetConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil || active.SnapshotID != initial.SnapshotID || active.RuntimeGeneration != 1 {
		t.Fatalf("non-atomic snapshot rollback = %#v, %v", active, err)
	}
	if access, accessErr := db.GetConversationNetworkAccess(ctx, conversation.ID); accessErr != nil || access.AllowRestrictedTargets {
		t.Fatalf("failed rebuild changed active access = %#v, %v", access, accessErr)
	}
	if _, err := db.Exec(`UPDATE conversation_boundary_rebuilds SET expected_runtime_generation = 2 WHERE conversation_id = ?`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := db.CompleteLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationRebuild, containerruntime.LifecycleCompletion{
		Runtime:             containerruntime.Runtime{ID: spec.ID, ProviderID: "provider-generation-2", Status: containerruntime.StatusStopped},
		IncrementGeneration: true,
	})
	if err != nil || rebuilt.RuntimeGeneration != 2 {
		t.Fatalf("complete rebuild = %#v, %v", rebuilt, err)
	}
	active, err = db.GetConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil || active.SnapshotID != pending.SnapshotID || active.RuntimeGeneration != rebuilt.RuntimeGeneration {
		t.Fatalf("active rebuilt snapshot = %#v, %v", active, err)
	}
	if access, accessErr := db.GetConversationNetworkAccess(ctx, conversation.ID); accessErr != nil || !access.AllowRestrictedTargets {
		t.Fatalf("successful rebuild did not activate access = %#v, %v", access, accessErr)
	}
	hasPending, err = db.HasPendingConversationBoundaryRebuild(ctx, conversation.ID)
	if err != nil || hasPending {
		t.Fatalf("completed pending state = %v, %v", hasPending, err)
	}
	var activations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversation_boundary_activations WHERE conversation_id = ?`, conversation.ID).Scan(&activations); err != nil {
		t.Fatal(err)
	}
	if activations != 2 {
		t.Fatalf("activation history = %d", activations)
	}

	if _, err := db.BeginLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationRebuild); err != nil {
		t.Fatal(err)
	}
	maintained, err := db.CompleteLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationRebuild, containerruntime.LifecycleCompletion{
		Runtime:             containerruntime.Runtime{ID: spec.ID, ProviderID: "provider-generation-3", Status: containerruntime.StatusStopped},
		IncrementGeneration: true,
	})
	if err != nil || maintained.RuntimeGeneration != 3 {
		t.Fatalf("maintenance rebuild = %#v, %v", maintained, err)
	}
	active, err = db.GetConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil || active.SnapshotID != pending.SnapshotID || active.RuntimeGeneration != 3 {
		t.Fatalf("maintenance snapshot = %#v, %v", active, err)
	}
}

func TestConversationBoundaryRebuildAllowsGatewayRolloutAndTLSAuthorityReplacement(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	policy := createSnapshotTestPolicy(t, db)
	conversation := createSnapshotTestConversation(t, db, policy.ID)
	ctx := context.Background()
	initial, err := db.EnsureConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)
	spec.Security.NetworkMode = containerruntime.NetworkInternal
	spec.EgressGateway = databaseGatewaySpec()
	spec.EgressGateway.BoundarySnapshot = &containerruntime.EgressBoundarySnapshotSpec{ID: initial.SnapshotID, SHA256: initial.SHA256}
	spec.EgressGateway.TLSAuthority = &containerruntime.EgressTLSAuthoritySpec{
		ID: initial.SnapshotID, BoundarySnapshotID: initial.SnapshotID,
		CertificateSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PrivateKeySHA256:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	if _, _, err := db.Queue(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(ctx, conversation.ID); err != nil || !claimed {
		t.Fatalf("claim runtime = %v, %v", claimed, err)
	}
	if _, err := db.Complete(ctx, conversation.ID, containerruntime.Runtime{
		ID: spec.ID, ProviderID: "provider-generation-1", Status: containerruntime.StatusStopped,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE boundary_policy_rules SET host = ? WHERE id = ?`, "rolled-out.example", "rule-a"); err != nil {
		t.Fatal(err)
	}
	pending, err := db.PrepareConversationBoundaryRebuild(ctx, conversation.ID, policy.ID)
	if err != nil {
		t.Fatal(err)
	}
	rebuildCtx := containerruntime.WithBoundaryRebuildSnapshot(ctx, pending.SnapshotID)
	if _, err := db.BeginLifecycle(rebuildCtx, conversation.ID, containerruntime.LifecycleOperationRebuild); err != nil {
		t.Fatal(err)
	}

	replacement := spec
	gateway := *spec.EgressGateway
	gateway.Image.Digest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	gateway.BoundarySnapshot = &containerruntime.EgressBoundarySnapshotSpec{ID: pending.SnapshotID, SHA256: pending.SHA256}
	gateway.TLSAuthority = &containerruntime.EgressTLSAuthoritySpec{
		ID: pending.SnapshotID, BoundarySnapshotID: pending.SnapshotID,
		CertificateSHA256: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		PrivateKeySHA256:  "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}
	replacement.EgressGateway = &gateway
	observed := containerruntime.Runtime{
		ID: spec.ID, ProviderID: "provider-generation-2", Status: containerruntime.StatusStopped,
		Image: replacement.Image, SpecDigest: containerruntime.RuntimeSpecDigest(replacement),
	}
	rebuilt, err := db.CompleteLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationRebuild, containerruntime.LifecycleCompletion{
		Runtime: observed, IncrementGeneration: true, ReplacementSpec: &replacement,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.RuntimeGeneration != 2 || rebuilt.Spec.EgressGateway == nil ||
		rebuilt.Spec.EgressGateway.Image.Digest != gateway.Image.Digest ||
		rebuilt.Spec.EgressGateway.BoundarySnapshot == nil || rebuilt.Spec.EgressGateway.BoundarySnapshot.ID != pending.SnapshotID ||
		rebuilt.Spec.EgressGateway.TLSAuthority == nil || rebuilt.Spec.EgressGateway.TLSAuthority.BoundarySnapshotID != pending.SnapshotID {
		t.Fatalf("gateway and boundary replacement = %#v", rebuilt)
	}

	if _, err := db.BeginLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationRebuild); err != nil {
		t.Fatal(err)
	}
	rotatedSpec := rebuilt.Spec
	rotatedGateway := *rotatedSpec.EgressGateway
	rotatedGateway.TLSAuthority = &containerruntime.EgressTLSAuthoritySpec{
		ID: "12345678-1234-4234-8234-123456789abc", BoundarySnapshotID: pending.SnapshotID,
		CertificateSHA256: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		PrivateKeySHA256:  "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	rotatedSpec.EgressGateway = &rotatedGateway
	rotatedRuntime := containerruntime.Runtime{
		ID: spec.ID, ProviderID: "provider-generation-3", Status: containerruntime.StatusStopped,
		Image: rotatedSpec.Image, SpecDigest: containerruntime.RuntimeSpecDigest(rotatedSpec),
	}
	rotated, err := db.CompleteLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationRebuild, containerruntime.LifecycleCompletion{
		Runtime: rotatedRuntime, IncrementGeneration: true, ReplacementSpec: &rotatedSpec,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RuntimeGeneration != 3 || rotated.Spec.EgressGateway == nil || rotated.Spec.EgressGateway.TLSAuthority == nil || rotated.Spec.EgressGateway.TLSAuthority.ID != rotatedGateway.TLSAuthority.ID {
		t.Fatalf("same-snapshot TLS authority rotation = %#v", rotated)
	}
}

func TestConversationBoundaryRebuildCancellationAndStartupRecoveryKeepActiveSnapshot(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	policy := createSnapshotTestPolicy(t, db)
	conversation := createSnapshotTestConversation(t, db, policy.ID)
	ctx := context.Background()
	initial, err := db.EnsureConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)
	if _, _, err := db.Queue(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(ctx, conversation.ID); err != nil || !claimed {
		t.Fatalf("claim runtime = %v, %v", claimed, err)
	}
	if _, err := db.Complete(ctx, conversation.ID, containerruntime.Runtime{ID: spec.ID, ProviderID: "provider", Status: containerruntime.StatusStopped}); err != nil {
		t.Fatal(err)
	}
	firstPending, err := db.PrepareConversationBoundaryRebuild(ctx, conversation.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CancelConversationBoundaryRebuild(ctx, conversation.ID, firstPending.SnapshotID); err != nil {
		t.Fatal(err)
	}
	secondPending, err := db.PrepareConversationBoundaryRebuild(ctx, conversation.ID, policy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if secondPending.SnapshotID == firstPending.SnapshotID {
		t.Fatal("pending snapshot was reused")
	}
	count, err := db.MarkPendingConversationBoundaryRebuildsInterrupted(ctx)
	if err != nil || count != 1 {
		t.Fatalf("recovered pending rebuilds = %d, %v", count, err)
	}
	if pending, err := db.HasPendingConversationBoundaryRebuild(ctx, conversation.ID); err != nil || !pending {
		t.Fatalf("interrupted rebuild did not remain fail-closed: %v, %v", pending, err)
	}
	replacement, err := db.PrepareConversationBoundaryRebuild(ctx, conversation.ID, "")
	if err != nil || replacement.SnapshotID == secondPending.SnapshotID {
		t.Fatalf("replace interrupted rebuild = %#v, %v", replacement, err)
	}
	if err := db.CancelConversationBoundaryRebuild(ctx, conversation.ID, replacement.SnapshotID); err != nil {
		t.Fatal(err)
	}
	active, err := db.GetConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil || active.SnapshotID != initial.SnapshotID || active.RuntimeGeneration != 1 {
		t.Fatalf("active snapshot after cancellation = %#v, %v", active, err)
	}
}

func TestConversationBoundaryRebuildConcurrentPrepareCreatesOnePendingSnapshot(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	policy := createSnapshotTestPolicy(t, db)
	conversation := createSnapshotTestConversation(t, db, policy.ID)
	ctx := context.Background()
	if _, err := db.EnsureConversationBoundarySnapshot(ctx, conversation.ID); err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)
	if _, _, err := db.Queue(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(ctx, conversation.ID); err != nil || !claimed {
		t.Fatalf("claim runtime = %v, %v", claimed, err)
	}
	if _, err := db.Complete(ctx, conversation.ID, containerruntime.Runtime{ID: spec.ID, ProviderID: "provider", Status: containerruntime.StatusStopped}); err != nil {
		t.Fatal(err)
	}

	const workers = 12
	start := make(chan struct{})
	errorsCh := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := db.PrepareConversationBoundaryRebuild(ctx, conversation.ID, policy.ID)
			errorsCh <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsCh)
	succeeded, pending := 0, 0
	for err := range errorsCh {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrConversationBoundaryRebuildPending):
			pending++
		default:
			t.Errorf("concurrent prepare error = %v", err)
		}
	}
	if succeeded != 1 || pending != workers-1 {
		t.Fatalf("concurrent prepare success/pending = %d/%d", succeeded, pending)
	}
	var snapshots, rebuilds int
	if err := db.QueryRow(`SELECT COUNT(*) FROM boundary_policy_snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversation_boundary_rebuilds`).Scan(&rebuilds); err != nil {
		t.Fatal(err)
	}
	if snapshots != 2 || rebuilds != 1 {
		t.Fatalf("concurrent snapshots/rebuilds = %d/%d", snapshots, rebuilds)
	}
}

func TestEnsureContainerRuntimeBoundarySnapshotsOnlyMigratesDurableRuntimes(t *testing.T) {
	db := newBoundarySnapshotTestDB(t)
	policy := createSnapshotTestPolicy(t, db)
	unused := createSnapshotTestConversation(t, db, policy.ID)
	queued := createSnapshotTestConversation(t, db, policy.ID)
	staleLocal := createSnapshotTestConversation(t, db, policy.ID)
	if _, _, err := db.Queue(context.Background(), databaseRuntimeSpec(queued.ID), false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.Queue(context.Background(), databaseRuntimeSpec(staleLocal.ID), false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE conversations SET runtime_mode = ? WHERE id = ?`, ConversationRuntimeModeHost, staleLocal.ID); err != nil {
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
	if _, err := db.GetConversationBoundarySnapshot(context.Background(), staleLocal.ID); !errors.Is(err, ErrConversationBoundarySnapshotNotFound) {
		t.Fatalf("stale local runtime was frozen during migration: %v", err)
	}
	var selected string
	if err := db.QueryRow(`SELECT policy_id FROM conversation_boundary_policy_selections WHERE conversation_id = ?`, unused.ID).Scan(&selected); err != nil || selected != policy.ID {
		t.Fatalf("unused selection = %q, %v", selected, err)
	}
}

func TestConversationBoundaryActivationMigrationUsesDurableRuntimeGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundary-activation-migration.db")
	db, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	policy := createSnapshotTestPolicy(t, db)
	conversation := createSnapshotTestConversation(t, db, policy.ID)
	snapshot, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)
	if _, _, err := db.Queue(context.Background(), spec, false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE conversation_container_runtimes SET runtime_generation = 4 WHERE conversation_id = ?`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TRIGGER conversation_boundary_activations_no_live_delete`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM conversation_boundary_activations WHERE conversation_id = ?`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	active, err := reopened.GetConversationBoundarySnapshot(context.Background(), conversation.ID)
	if err != nil || active.SnapshotID != snapshot.SnapshotID || active.RuntimeGeneration != 4 {
		t.Fatalf("migrated activation = %#v, %v", active, err)
	}
}
