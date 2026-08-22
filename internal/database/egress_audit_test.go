package database

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/egress"
	containerruntime "cyberstrike-ai/internal/runtime/container"

	"go.uber.org/zap"
)

func TestEgressAuditPersistsNetworkAndLifecycleEventsWithScopedSearch(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	conversation, spec := createRunningEgressAuditRuntimeWithRoute(t, db, "persistent audit", true)
	if _, err := db.Exec(`UPDATE conversations SET owner_user_id = ? WHERE id = ?`, "owner-a", conversation.ID); err != nil {
		t.Fatal(err)
	}

	targets, err := db.ListRunningEgressAuditRuntimeTargets(ctx)
	if err != nil || len(targets) != 1 || targets[0].Record.ConversationID != conversation.ID || targets[0].ConversationTitle != conversation.Title {
		t.Fatalf("running audit targets = %#v, %v", targets, err)
	}
	event := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestHTTP,
		Domain: "allowed.example", ResolvedIPs: []string{"93.184.216.34"}, ConnectedIP: "93.184.216.34",
		Port: 80, Decision: egress.ActivityDecisionAllowed, RuleID: "allow-example", Reason: "allow-visit",
		UpstreamRouteID: spec.EgressGateway.UpstreamRoute.ID, Method: "GET", Path: "/safe", HTTPStatus: 200, Outcome: "completed", LatencyMS: 12, BytesDown: 42,
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	inserted, err := db.AppendEgressNetworkAuditEvent(ctx, targets[0], event)
	if err != nil || !inserted {
		t.Fatalf("append network event = %v, %v", inserted, err)
	}
	inserted, err = db.AppendEgressNetworkAuditEvent(ctx, targets[0], event)
	if err != nil || inserted {
		t.Fatalf("duplicate network event = %v, %v", inserted, err)
	}
	rateLimited := event
	rateLimited.Timestamp = event.Timestamp.Add(time.Millisecond)
	rateLimited.Decision = egress.ActivityDecisionBlocked
	rateLimited.Reason = "rate_limit_exceeded"
	rateLimited.Outcome = "rate_limited"
	rateLimited.UpstreamRouteID = spec.EgressGateway.UpstreamRoute.ID
	rateLimited.HTTPStatus = 429
	inserted, err = db.AppendEgressNetworkAuditEvent(ctx, targets[0], rateLimited)
	if err != nil || !inserted {
		t.Fatalf("append rate-limit/upstream event = %v, %v", inserted, err)
	}

	if _, err := db.BeginLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationStop); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CompleteLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationStop, containerruntime.LifecycleCompletion{
		Runtime: containerruntime.Runtime{ID: spec.ID, ProviderID: "provider-audit", Status: containerruntime.StatusStopped},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.BeginLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationDelete); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationDelete); err != nil {
		t.Fatal(err)
	}

	all := EgressAuditFilter{Scope: RBACScopeAll, Limit: 20}
	items, err := db.ListEgressAuditEvents(ctx, all)
	if err != nil || len(items) != 5 {
		t.Fatalf("all audit events = %#v, %v", items, err)
	}
	wantTypes := map[string]int{"create": 1, "http": 2, "stop": 1, "delete": 1}
	for _, item := range items {
		wantTypes[item.EventType]--
		if item.ConversationID != conversation.ID || item.AgentID != "container-agent" || item.RuntimeGeneration != 1 {
			t.Fatalf("audit identity = %#v", item)
		}
		if item.Outcome == "rate_limited" && (item.HTTPStatus != 429 || item.UpstreamRouteID != conversation.ID || item.Decision != egress.ActivityDecisionBlocked) {
			t.Fatalf("rate-limit/upstream audit = %#v", item)
		}
	}
	for eventType, remaining := range wantTypes {
		if remaining != 0 {
			t.Fatalf("event type %s remaining = %d; events = %#v", eventType, remaining, items)
		}
	}
	integrity, err := db.VerifyEgressAuditIntegrity(ctx, EgressAuditFilter{Scope: RBACScopeAll})
	if err != nil || integrity.Status != "verified" || integrity.Conversations != 1 || integrity.Events != 5 {
		t.Fatalf("audit integrity = %#v, %v", integrity, err)
	}
	for _, item := range items {
		if item.ChainSequence < 1 || !egressAuditHashPattern.MatchString(item.PreviousHash) || !egressAuditHashPattern.MatchString(item.EventHash) {
			t.Fatalf("audit chain projection = %#v", item)
		}
	}

	network := all
	network.Category = "network"
	network.EventType = "http"
	network.Decision = "allowed"
	network.Query = "allowed.example"
	items, err = db.ListEgressAuditEvents(ctx, network)
	if err != nil || len(items) != 1 || items[0].RuleID != "allow-example" || items[0].Path != "/safe" {
		t.Fatalf("filtered network events = %#v, %v", items, err)
	}
	if total, err := db.CountEgressAuditEvents(ctx, network); err != nil || total != 1 {
		t.Fatalf("filtered count = %d, %v", total, err)
	}
	summary, err := db.SummarizeEgressAuditEvents(ctx, all)
	if err != nil || summary.Total != 5 || summary.Network != 2 || summary.Lifecycle != 3 || summary.Blocked != 1 || summary.Failures != 0 {
		t.Fatalf("audit summary = %#v, %v", summary, err)
	}

	owner := all
	owner.UserID, owner.Scope = "owner-a", RBACScopeOwn
	if total, err := db.CountEgressAuditEvents(ctx, owner); err != nil || total != 5 {
		t.Fatalf("owner scoped count = %d, %v", total, err)
	}
	other := all
	other.UserID, other.Scope = "owner-b", RBACScopeOwn
	if total, err := db.CountEgressAuditEvents(ctx, other); err != nil || total != 0 {
		t.Fatalf("other scoped count = %d, %v", total, err)
	}
	if _, err := db.GetEgressAuditEvent(ctx, items[0].ID, "owner-b", RBACScopeOwn); err == nil {
		t.Fatal("other owner resolved a protected audit event")
	}
}

func TestEgressAuditChainIsAppendOnlyAndDetectsTampering(t *testing.T) {
	for _, test := range []struct {
		name   string
		tamper func(*testing.T, *DB, string)
	}{
		{
			name: "modified event",
			tamper: func(t *testing.T, db *DB, conversationID string) {
				if _, err := db.Exec(`DROP TRIGGER trg_egress_audit_append_only_update`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`UPDATE egress_audit_events SET message = 'tampered' WHERE conversation_id = ? AND chain_sequence = 1`, conversationID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "deleted event",
			tamper: func(t *testing.T, db *DB, conversationID string) {
				if _, err := db.Exec(`DROP TRIGGER trg_egress_audit_append_only_delete`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`DELETE FROM egress_audit_events WHERE conversation_id = ? AND chain_sequence = 1`, conversationID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "reordered sequence",
			tamper: func(t *testing.T, db *DB, conversationID string) {
				if _, err := db.Exec(`DROP TRIGGER trg_egress_audit_append_only_update`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`UPDATE egress_audit_events SET chain_sequence = 100 WHERE conversation_id = ? AND chain_sequence = 1`, conversationID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "modified chain head",
			tamper: func(t *testing.T, db *DB, conversationID string) {
				if _, err := db.Exec(`UPDATE egress_audit_chain_heads SET last_hash = ? WHERE conversation_id = ?`, strings.Repeat("a", 64), conversationID); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := newContainerRuntimeTestDB(t)
			conversation, spec := createRunningEgressAuditRuntime(t, db, "audit integrity "+test.name)
			targets, err := db.ListRunningEgressAuditRuntimeTargets(context.Background())
			if err != nil || len(targets) != 1 {
				t.Fatalf("targets = %#v, %v", targets, err)
			}
			event := egress.ActivityEvent{
				Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestHTTP,
				Domain: "allowed.example", ResolvedIPs: []string{"93.184.216.34"}, ConnectedIP: "93.184.216.34",
				Port: 80, Decision: egress.ActivityDecisionAllowed, RuleID: "allow-example", Reason: "allow-visit",
				Method: "GET", Path: "/safe", HTTPStatus: 200, Outcome: "completed",
				SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
			}
			if inserted, err := db.AppendEgressNetworkAuditEvent(context.Background(), targets[0], event); err != nil || !inserted {
				t.Fatalf("append = %v, %v", inserted, err)
			}
			if _, err := db.Exec(`UPDATE egress_audit_events SET message = 'blocked update' WHERE conversation_id = ?`, conversation.ID); err == nil {
				t.Fatal("append-only event update unexpectedly succeeded")
			}
			if _, err := db.Exec(`DELETE FROM egress_audit_events WHERE conversation_id = ?`, conversation.ID); err == nil {
				t.Fatal("append-only event delete unexpectedly succeeded")
			}
			test.tamper(t, db, conversation.ID)
			if integrity, err := db.VerifyEgressAuditIntegrity(context.Background(), EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll}); !errors.Is(err, ErrEgressAuditIntegrity) || integrity.Status == "verified" {
				t.Fatalf("tamper verification = %#v, %v", integrity, err)
			}
		})
	}
}

func TestEgressAuditChainMigratesLegacyRowsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress-audit-chain-migration.db")
	db, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	conversation, _ := createRunningEgressAuditRuntime(t, db, "legacy audit chain")
	if _, err := db.Exec(`DROP TRIGGER trg_egress_audit_append_only_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE egress_audit_events SET chain_sequence = 0, previous_hash = '', event_hash = '' WHERE conversation_id = ?`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM egress_audit_chain_heads WHERE conversation_id = ?`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	var firstHash string
	for attempt := 0; attempt < 2; attempt++ {
		reopened, err := NewDB(path, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		items, err := reopened.ListEgressAuditEvents(context.Background(), EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll, Limit: 20})
		if err != nil || len(items) != 1 || items[0].ChainSequence != 1 || !egressAuditHashPattern.MatchString(items[0].EventHash) {
			_ = reopened.Close()
			t.Fatalf("migration attempt %d = %#v, %v", attempt, items, err)
		}
		if attempt == 0 {
			firstHash = items[0].EventHash
		} else if items[0].EventHash != firstHash {
			t.Fatalf("migration changed stable hash: %q != %q", items[0].EventHash, firstHash)
		}
		if _, err := reopened.VerifyEgressAuditIntegrity(context.Background(), EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll}); err != nil {
			t.Fatal(err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEgressAuditChainTamperingFailsDatabaseStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress-audit-chain-startup.db")
	db, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	conversation, _ := createRunningEgressAuditRuntime(t, db, "tampered startup")
	if _, err := db.Exec(`DROP TRIGGER trg_egress_audit_append_only_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE egress_audit_events SET lifecycle_state = 'tampered' WHERE conversation_id = ?`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDB(path, zap.NewNop())
	if reopened != nil {
		_ = reopened.Close()
	}
	if !errors.Is(err, ErrEgressAuditIntegrity) {
		t.Fatalf("tampered startup error = %v", err)
	}
}

func TestEgressAuditChainSerializesConcurrentWriters(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, spec := createRunningEgressAuditRuntime(t, db, "concurrent audit chain")
	targets, err := db.ListRunningEgressAuditRuntimeTargets(context.Background())
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets = %#v, %v", targets, err)
	}
	const writers = 20
	start := time.Now().UTC()
	errorsByWriter := make(chan error, writers)
	var wait sync.WaitGroup
	for index := 0; index < writers; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			event := egress.ActivityEvent{
				Event: egress.ActivityEventName, Timestamp: start.Add(time.Duration(index) * time.Millisecond), RequestType: egress.ActivityRequestHTTP,
				Domain: "allowed.example", ResolvedIPs: []string{"93.184.216.34"}, ConnectedIP: "93.184.216.34",
				Port: 80, Decision: egress.ActivityDecisionAllowed, RuleID: "allow-example", Reason: "allow-visit",
				Method: "GET", Path: "/safe", HTTPStatus: 200, Outcome: "completed", LatencyMS: int64(index),
				SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
			}
			inserted, err := db.AppendEgressNetworkAuditEvent(context.Background(), targets[0], event)
			if err != nil {
				errorsByWriter <- err
				return
			}
			if !inserted {
				errorsByWriter <- errors.New("unique concurrent audit event was ignored")
			}
		}()
	}
	wait.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		t.Fatal(err)
	}
	integrity, err := db.VerifyEgressAuditIntegrity(context.Background(), EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll})
	if err != nil || integrity.Events != writers+1 {
		t.Fatalf("concurrent chain integrity = %#v, %v", integrity, err)
	}
	items, err := db.ListEgressAuditEvents(context.Background(), EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll, Limit: 100})
	if err != nil || len(items) != writers+1 {
		t.Fatalf("concurrent chain rows = %d, %v", len(items), err)
	}
	sequences := make(map[int64]struct{}, len(items))
	for _, item := range items {
		sequences[item.ChainSequence] = struct{}{}
	}
	for sequence := int64(1); sequence <= writers+1; sequence++ {
		if _, ok := sequences[sequence]; !ok {
			t.Fatalf("missing chain sequence %d: %#v", sequence, sequences)
		}
	}
}

func TestEgressAuditBackfillsOneStableBaselineForExistingRuntime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress-audit-backfill.db")
	db, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	createRunningEgressAuditRuntime(t, db, "legacy runtime")
	if _, err := db.Exec(`DROP TRIGGER trg_egress_audit_append_only_delete`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM egress_audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM egress_audit_chain_heads`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		reopened, err := NewDB(path, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		items, err := reopened.ListEgressAuditEvents(context.Background(), EgressAuditFilter{Scope: RBACScopeAll, Limit: 20})
		if err != nil || len(items) != 1 || items[0].EventType != "reconcile" || items[0].LifecycleOperation != "reconcile" || items[0].Result != "success" {
			_ = reopened.Close()
			t.Fatalf("baseline attempt %d = %#v, %v", attempt, items, err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEgressAuditLifecycleFailuresDoNotPersistProviderErrors(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	failedConversation, err := db.CreateConversation("failed initialization", ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	failedSpec := databaseRuntimeSpec(failedConversation.ID)
	if _, _, err := db.Queue(ctx, failedSpec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(ctx, failedConversation.ID); err != nil || !claimed {
		t.Fatalf("claim failed fixture = %v, %v", claimed, err)
	}
	if _, err := db.Fail(ctx, failedConversation.ID, "Authorization: secret-token"); err != nil {
		t.Fatal(err)
	}

	runningConversation, _ := createRunningEgressAuditRuntime(t, db, "failed lifecycle")
	if _, err := db.BeginLifecycle(ctx, runningConversation.ID, containerruntime.LifecycleOperationStart); err != nil {
		t.Fatal(err)
	}
	if _, err := db.FailLifecycle(ctx, runningConversation.ID, containerruntime.LifecycleOperationStart, containerruntime.LifecycleFailure{
		Message: "proxy password=secret-token", RuntimeStatus: containerruntime.StatusStopped,
	}); err != nil {
		t.Fatal(err)
	}
	items, err := db.ListEgressAuditEvents(ctx, EgressAuditFilter{Scope: RBACScopeAll, Limit: 20, Decision: "failure"})
	if err != nil || len(items) != 2 {
		t.Fatalf("failure audit events = %#v, %v", items, err)
	}
	for _, item := range items {
		if item.Result != "failure" || strings.Contains(strings.ToLower(item.Message), "secret") || strings.Contains(strings.ToLower(item.Message), "authorization") || strings.Contains(strings.ToLower(item.Message), "password") {
			t.Fatalf("unsafe lifecycle failure audit = %#v", item)
		}
	}
}

func TestEgressAuditRejectsUnsafeNetworkProjectionBeforePersistence(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	conversation, spec := createRunningEgressAuditRuntime(t, db, "safe audit boundary")
	targets, err := db.ListRunningEgressAuditRuntimeTargets(ctx)
	if err != nil || len(targets) != 1 {
		t.Fatalf("running targets = %#v, %v", targets, err)
	}
	valid := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestHTTP,
		Domain: "allowed.example", ResolvedIPs: []string{"93.184.216.34"}, ConnectedIP: "93.184.216.34",
		Port: 80, Decision: egress.ActivityDecisionAllowed, RuleID: "allow-example", Reason: "allow-visit",
		Method: "GET", Path: "/safe", HTTPStatus: 200, Outcome: "completed", LatencyMS: 12, BytesDown: 42,
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	tests := map[string]func(*egress.ActivityEvent){
		"query string":        func(event *egress.ActivityEvent) { event.Path = "/safe?authorization=secret-token" },
		"fragment":            func(event *egress.ActivityEvent) { event.Path = "/safe#private-fragment" },
		"noncanonical domain": func(event *egress.ActivityEvent) { event.Domain = "Allowed.Example" },
		"control in rule":     func(event *egress.ActivityEvent) { event.RuleID = "rule\nAuthorization: secret-token" },
		"snapshot drift": func(event *egress.ActivityEvent) {
			event.SnapshotSHA256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"unexpected route":     func(event *egress.ActivityEvent) { event.UpstreamRouteID = "credential-route" },
		"noncanonical address": func(event *egress.ActivityEvent) { event.ConnectedIP = "::ffff:93.184.216.34" },
		"too many addresses":   func(event *egress.ActivityEvent) { event.ResolvedIPs = make([]string, 65) },
		"unsafe counter":       func(event *egress.ActivityEvent) { event.BytesDown = maxEgressAuditSafeInteger + 1 },
		"future timestamp":     func(event *egress.ActivityEvent) { event.Timestamp = time.Now().UTC().Add(6 * time.Minute) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.ResolvedIPs = append([]string(nil), valid.ResolvedIPs...)
			mutate(&candidate)
			inserted, err := db.AppendEgressNetworkAuditEvent(ctx, targets[0], candidate)
			if err == nil || inserted || strings.Contains(strings.ToLower(err.Error()), "secret-token") {
				t.Fatalf("unsafe event result = inserted %v, err %v", inserted, err)
			}
		})
	}
	filter := EgressAuditFilter{ConversationID: conversation.ID, Category: "network", Scope: RBACScopeAll, Limit: 20}
	if total, err := db.CountEgressAuditEvents(ctx, filter); err != nil || total != 0 {
		t.Fatalf("unsafe events persisted = %d, %v", total, err)
	}

	rows, err := db.Query(`PRAGMA table_info(egress_audit_events)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var index, notNull, primaryKey int
		var name, columnType string
		var defaultValue interface{}
		if err := rows.Scan(&index, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(name)
		for _, forbidden := range []string{"header", "body", "query", "cookie", "authorization", "credential", "secret"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("audit schema contains forbidden column %q", name)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func createRunningEgressAuditRuntime(t *testing.T, db *DB, title string) (*Conversation, containerruntime.RuntimeSpec) {
	return createRunningEgressAuditRuntimeWithRoute(t, db, title, false)
}

func createRunningEgressAuditRuntimeWithRoute(t *testing.T, db *DB, title string, withRoute bool) (*Conversation, containerruntime.RuntimeSpec) {
	t.Helper()
	ctx := context.Background()
	conversation, err := db.CreateConversation(title, ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)
	spec.Security.NetworkMode = containerruntime.NetworkInternal
	spec.EgressGateway = databaseGatewaySpec()
	spec.EgressGateway.BoundarySnapshot = &containerruntime.EgressBoundarySnapshotSpec{
		ID: "11111111-1111-4111-8111-111111111111", SHA256: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
	if withRoute {
		spec.EgressGateway.UpstreamRoute = &containerruntime.EgressUpstreamRouteSpec{
			ID: conversation.ID, SHA256: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		}
	}
	if _, _, err := db.Queue(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(ctx, conversation.ID); err != nil || !claimed {
		t.Fatalf("claim runtime = %v, %v", claimed, err)
	}
	if _, err := db.Complete(ctx, conversation.ID, containerruntime.Runtime{
		ID: spec.ID, ProviderID: "provider-audit", Status: containerruntime.StatusRunning,
	}); err != nil {
		t.Fatal(err)
	}
	return conversation, spec
}
