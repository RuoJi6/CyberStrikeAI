package database

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/networkprovenance"
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
		HTTPPacket: &egress.HTTPPacket{RequestLine: "GET /safe?token=plain HTTP/1.1", RequestHeaders: map[string][]string{"Authorization": {"Bearer plain-token"}}, ResponseLine: "HTTP/1.1 200 OK", ResponseHeaders: map[string][]string{"Content-Type": {"text/plain"}}, ResponseBody: "complete", ResponseBodyEncoding: "utf8"},
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
		if item.HTTPPacket != nil {
			t.Fatalf("list projection unexpectedly included packet = %#v", item.HTTPPacket)
		}
	}
	var packetEventID string
	for _, item := range items {
		if item.EventType == "http" && item.Decision == egress.ActivityDecisionAllowed {
			packetEventID = item.ID
			break
		}
	}
	detail, err := db.GetEgressAuditEvent(ctx, packetEventID, "owner-a", RBACScopeOwn)
	if err != nil || detail.HTTPPacket == nil || detail.HTTPPacket.RequestLine != "GET /safe?token=plain HTTP/1.1" || detail.HTTPPacket.RequestHeaders["Authorization"][0] != "Bearer plain-token" || detail.HTTPPacket.ResponseBody != "complete" {
		t.Fatalf("packet detail = %#v, %v", detail, err)
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
	ownerConversations, err := db.ListEgressAuditConversations(ctx, owner.UserID, owner.Scope)
	if err != nil || len(ownerConversations) != 1 || ownerConversations[0].ConversationID != items[0].ConversationID {
		t.Fatalf("owner audit conversations = %#v, %v", ownerConversations, err)
	}
	other := all
	other.UserID, other.Scope = "owner-b", RBACScopeOwn
	if total, err := db.CountEgressAuditEvents(ctx, other); err != nil || total != 0 {
		t.Fatalf("other scoped count = %d, %v", total, err)
	}
	if conversations, err := db.ListEgressAuditConversations(ctx, other.UserID, other.Scope); err != nil || len(conversations) != 0 {
		t.Fatalf("other audit conversations = %#v, %v", conversations, err)
	}
	if _, err := db.GetEgressAuditEvent(ctx, items[0].ID, "owner-b", RBACScopeOwn); err == nil {
		t.Fatal("other owner resolved a protected audit event")
	}
}

func TestSignedAuditTargetAllowsOnlyRuntimeBoundUnattributedNonHTTP(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, _ := createRunningEgressAuditRuntime(t, db, "signed non-http audit")
	targets, err := db.ListRunningEgressAuditRuntimeTargets(context.Background())
	if err != nil || len(targets) != 1 {
		t.Fatalf("audit target = %#v, %v", targets, err)
	}
	target := targets[0]
	signer, err := networkprovenance.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	target.Record.Spec.EgressGateway.AttributionPublicKey = signer.PublicKeyEncoded()
	target.Record.Spec.EgressGateway.AttributionRuntimeGeneration = target.Record.RuntimeGeneration
	target.Record.Spec.EgressGateway.AttributionInstanceID = "87654321-4321-4321-8321-cba987654321"
	audience := networkprovenance.ExpectedAudience{
		ConversationID: conversation.ID, RuntimeMode: networkprovenance.RuntimeModeContainer,
		RuntimeGeneration: target.Record.RuntimeGeneration, RuntimeInstanceID: target.Record.Spec.EgressGateway.AttributionInstanceID,
	}
	base := egress.ActivityEvent{
		EventID: "event-runtime-bound", Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), Domain: "allowed.example",
		Decision: egress.ActivityDecisionAllowed, Outcome: "resolved",
		SnapshotID: target.Record.Spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: target.Record.Spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	dns := base
	dns.RequestType = egress.ActivityRequestDNS
	dns.Provenance = networkprovenance.ForAudience(audience, networkprovenance.AttributionUnattributed)
	if err := validateEgressNetworkAuditEvent(target, dns); err != nil {
		t.Fatalf("runtime-bound unattributed DNS rejected: %v", err)
	}
	health := base
	health.EventID, health.RequestType, health.Decision, health.Reason, health.Outcome, health.RetryAfterMS = "event-runtime-health", egress.ActivityRequestHealth, egress.ActivityDecisionBlocked, "upstream_rate_limited", "cooldown_started", 1000
	health.Provenance = dns.Provenance
	if err := validateEgressNetworkAuditEvent(target, health); err != nil {
		t.Fatalf("runtime-bound unattributed health rejected: %v", err)
	}
	httpEvent := base
	httpEvent.EventID, httpEvent.RequestType, httpEvent.Method, httpEvent.Path, httpEvent.Port, httpEvent.Outcome = "event-invalid-http", egress.ActivityRequestHTTP, "GET", "/", 80, "attribution_rejected"
	httpEvent.Decision = egress.ActivityDecisionBlocked
	httpEvent.Provenance = networkprovenance.ForAudience(audience, networkprovenance.AttributionInvalid)
	if err := validateEgressNetworkAuditEvent(target, httpEvent); err != nil {
		t.Fatalf("runtime-bound invalid HTTP rejected: %v", err)
	}
	httpEvent.Provenance = dns.Provenance
	if err := validateEgressNetworkAuditEvent(target, httpEvent); err == nil {
		t.Fatal("signed HTTP audit accepted unattributed provenance")
	}
}

func TestEgressAuditPersistsCompactBatchMetadataAndWeightedSummary(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	conversation, spec := createRunningEgressAuditRuntime(t, db, "compact audit")
	targets, err := db.ListRunningEgressAuditRuntimeTargets(ctx)
	if err != nil || len(targets) != 1 || targets[0].AuditMode != EgressAuditModeCompact {
		t.Fatalf("targets = %#v, %v", targets, err)
	}
	firstAt := time.Now().UTC()
	lastAt := firstAt.Add(500 * time.Millisecond)
	event := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: firstAt, RequestType: egress.ActivityRequestTCP,
		Domain: "47.116.200.74", ConnectedIP: "47.116.200.74", Port: 22,
		Decision: egress.ActivityDecisionBlocked, RuleID: "block-ssh", Reason: "blocked-target", Outcome: "policy_denied",
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
		AggregateCount: 20, AggregateKind: "connection-burst", AggregateFirstAt: &firstAt, AggregateLastAt: &lastAt,
		AggregateDistinctTargets: 1, AggregateDistinctPorts: 1, AggregateDistinctVariants: 1,
	}
	if inserted, err := db.AppendEgressNetworkAuditEvent(ctx, targets[0], event); err != nil || !inserted {
		t.Fatalf("append aggregate = %v, %v", inserted, err)
	}
	items, err := db.ListEgressAuditEvents(ctx, EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll, Limit: 10})
	if err != nil || len(items) != 2 || items[0].AggregateCount != 20 || items[0].AggregateKind != "connection-burst" || items[0].AggregateLastAt == nil {
		t.Fatalf("aggregate projection = %#v, %v", items, err)
	}
	summary, err := db.SummarizeEgressAuditEvents(ctx, EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll})
	if err != nil || summary.Total != 21 || summary.Network != 20 || summary.Lifecycle != 1 || summary.Blocked != 20 {
		t.Fatalf("weighted summary = %#v, %v", summary, err)
	}
	if _, err := db.VerifyEgressAuditIntegrity(ctx, EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll}); err != nil {
		t.Fatal(err)
	}
}

func TestEgressAuditDoesNotAppendRecalculatedAggregateOverSealedFirstSample(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	conversation, spec := createRunningEgressAuditRuntime(t, db, "aggregate replay")
	targets, err := db.ListRunningEgressAuditRuntimeTargets(ctx)
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets = %#v, %v", targets, err)
	}
	firstAt := time.Now().UTC()
	event := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: firstAt, RequestType: egress.ActivityRequestTCP,
		Domain: "47.116.200.74", ConnectedIP: "47.116.200.74", Port: 22,
		Decision: egress.ActivityDecisionAllowed, RuleID: "allow-ssh", Reason: "allow-visit", Outcome: "forwarded",
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	if inserted, err := db.AppendEgressNetworkAuditEvent(ctx, targets[0], event); err != nil || !inserted {
		t.Fatalf("append first sample = %v, %v", inserted, err)
	}
	aggregate := event
	lastAt := firstAt.Add(20 * time.Second)
	aggregate.AggregateCount = 20
	aggregate.AggregateKind = "connection-burst"
	aggregate.AggregateFirstAt = &firstAt
	aggregate.AggregateLastAt = &lastAt
	aggregate.AggregateDistinctTargets = 1
	aggregate.AggregateDistinctPorts = 1
	aggregate.AggregateDistinctVariants = 1
	if inserted, err := db.AppendEgressNetworkAuditEvent(ctx, targets[0], aggregate); err != nil || inserted {
		t.Fatalf("recalculated replay aggregate = %v, %v", inserted, err)
	}
	items, err := db.ListEgressAuditEvents(ctx, EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll, Limit: 10})
	if err != nil || len(items) != 2 || items[0].AggregateCount != 0 {
		t.Fatalf("immutable first-sample projection = %#v, %v", items, err)
	}
	if _, err := db.VerifyEgressAuditIntegrity(ctx, EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll}); err != nil {
		t.Fatal(err)
	}
}

func TestPurgeEgressAuditEventsRebuildsAndVerifiesAffectedChains(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	conversation, spec := createRunningEgressAuditRuntime(t, db, "audit purge")
	targets, err := db.ListRunningEgressAuditRuntimeTargets(ctx)
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets = %#v, %v", targets, err)
	}
	for index := 0; index < 2; index++ {
		event := egress.ActivityEvent{
			Event: egress.ActivityEventName, Timestamp: time.Now().UTC().Add(time.Duration(index+1) * time.Millisecond), RequestType: egress.ActivityRequestHTTP,
			Domain: "purge.example", Port: 80, Decision: egress.ActivityDecisionAllowed, RuleID: "allow-purge", Reason: "allow-visit",
			Method: "GET", Path: fmt.Sprintf("/item/%d", index), HTTPStatus: 200, Outcome: "completed",
			SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
		}
		if inserted, err := db.AppendEgressNetworkAuditEvent(ctx, targets[0], event); err != nil || !inserted {
			t.Fatalf("append %d = %v, %v", index, inserted, err)
		}
	}
	items, err := db.ListEgressAuditEvents(ctx, EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll, Limit: 10})
	if err != nil || len(items) != 3 {
		t.Fatalf("items before purge = %#v, %v", items, err)
	}
	selectedID := items[0].ID
	deleted, err := db.PurgeEgressAuditEvents(ctx, EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll}, []string{selectedID})
	if err != nil || deleted != 1 {
		t.Fatalf("selected purge = %d, %v", deleted, err)
	}
	items, err = db.ListEgressAuditEvents(ctx, EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll, Limit: 10})
	if err != nil || len(items) != 2 || items[0].ChainSequence != 2 || items[1].ChainSequence != 1 {
		t.Fatalf("items after selected purge = %#v, %v", items, err)
	}
	if _, err := db.VerifyEgressAuditIntegrity(ctx, EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll}); err != nil {
		t.Fatal(err)
	}
	deleted, err = db.PurgeEgressAuditEvents(ctx, EgressAuditFilter{ConversationID: conversation.ID, Category: "network", Scope: RBACScopeAll}, nil)
	if err != nil || deleted != 1 {
		t.Fatalf("filtered purge = %d, %v", deleted, err)
	}
	items, err = db.ListEgressAuditEvents(ctx, EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll, Limit: 10})
	if err != nil || len(items) != 1 || items[0].Category != "lifecycle" || items[0].ChainSequence != 1 {
		t.Fatalf("remaining lifecycle = %#v, %v", items, err)
	}
	if integrity, err := db.VerifyEgressAuditIntegrity(ctx, EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll}); err != nil || integrity.Events != 1 {
		t.Fatalf("integrity after purge = %#v, %v", integrity, err)
	}
}

func TestConversationEgressAuditSettingControlsCollectorTargets(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	conversation, spec := createRunningEgressAuditRuntime(t, db, "audit toggle")
	if enabled, err := db.GetConversationEgressAuditEnabled(ctx, conversation.ID); err != nil || !enabled {
		t.Fatalf("default audit setting = %v, %v", enabled, err)
	}
	targets, err := db.ListRunningEgressAuditRuntimeTargets(ctx)
	if err != nil || len(targets) != 1 {
		t.Fatalf("default collector targets = %#v, %v", targets, err)
	}
	disabledEvent := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestHTTP,
		Domain: "fuzz.example", Port: 80, Decision: egress.ActivityDecisionAllowed, RuleID: "allow-fuzz", Reason: "allow-visit",
		Method: "GET", Path: "/disabled", HTTPStatus: 200, Outcome: "completed",
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	if err := db.SetConversationEgressAuditEnabled(ctx, conversation.ID, false); err != nil {
		t.Fatal(err)
	}
	if enabled, err := db.GetConversationEgressAuditEnabled(ctx, conversation.ID); err != nil || enabled {
		t.Fatalf("disabled audit setting = %v, %v", enabled, err)
	}
	if targets, err := db.ListRunningEgressAuditRuntimeTargets(ctx); err != nil || len(targets) != 1 {
		t.Fatalf("disabled audit runtime must remain available to realtime ingestion: %#v, %v", targets, err)
	}
	if inserted, err := db.AppendEgressNetworkAuditEvent(ctx, targets[0], disabledEvent); err != nil || inserted {
		t.Fatalf("disabled event persistence = %v, %v", inserted, err)
	}
	if err := db.SetConversationEgressAuditEnabled(ctx, conversation.ID, true); err != nil {
		t.Fatal(err)
	}
	if inserted, err := db.AppendEgressNetworkAuditEvent(ctx, targets[0], disabledEvent); err != nil || inserted {
		t.Fatalf("disabled log replay persistence = %v, %v", inserted, err)
	}
	liveEvent := disabledEvent
	liveEvent.Timestamp = time.Now().UTC().Add(time.Second)
	liveEvent.Path = "/enabled"
	if inserted, err := db.AppendEgressNetworkAuditEvent(ctx, targets[0], liveEvent); err != nil || !inserted {
		t.Fatalf("re-enabled event persistence = %v, %v", inserted, err)
	}
	if targets, err := db.ListRunningEgressAuditRuntimeTargets(ctx); err != nil || len(targets) != 1 || targets[0].Record.ConversationID != conversation.ID {
		t.Fatalf("re-enabled collector targets = %#v, %v", targets, err)
	}
}

func TestCreateContainerConversationPersistsInitialEgressAuditSetting(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	disabled := false
	conversation, err := db.CreateConversation("audit disabled at creation", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer, EgressAuditEnabled: &disabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if enabled, err := db.GetConversationEgressAuditEnabled(context.Background(), conversation.ID); err != nil || enabled {
		t.Fatalf("initial audit setting = %v, %v", enabled, err)
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
			name: "modified HTTP packet",
			tamper: func(t *testing.T, db *DB, conversationID string) {
				if _, err := db.Exec(`DROP TRIGGER trg_egress_audit_append_only_update`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`UPDATE egress_audit_events SET http_packet_json = '{"requestLine":"GET /tampered HTTP/1.1","requestHeaders":{},"sensitiveDataRedacted":false}' WHERE conversation_id = ? AND category = 'network'`, conversationID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "modified provenance",
			tamper: func(t *testing.T, db *DB, conversationID string) {
				if _, err := db.Exec(`DROP TRIGGER trg_egress_audit_append_only_update`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`UPDATE egress_audit_events SET execution_id = 'tampered-execution' WHERE conversation_id = ? AND category = 'network'`, conversationID); err != nil {
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
				HTTPPacket: &egress.HTTPPacket{RequestLine: "GET /safe HTTP/1.1", RequestHeaders: map[string][]string{}},
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

func TestEgressAuditHashVersionFallbacksRemainCompatible(t *testing.T) {
	base := []interface{}{"previous", "1", "event"}
	v1 := egressAuditHashValues(base...)
	if got := egressAuditHashValuesWithPacket(append(append([]interface{}{}, base...), "")...); got != v1 {
		t.Fatalf("empty packet did not preserve v1 hash: %q != %q", got, v1)
	}
	packetValues := append(append([]interface{}{}, base...), `{"requestLine":"GET / HTTP/1.1"}`)
	v2 := egressAuditHashValuesWithPacket(packetValues...)
	if v2 == v1 {
		t.Fatal("v2 packet hash reused v1 domain")
	}
	if got := egressAuditHashValuesWithDNS(append(append([]interface{}{}, packetValues...), "", "[]")...); got != v2 {
		t.Fatalf("empty DNS projection did not preserve v2 hash: %q != %q", got, v2)
	}
	dnsValues := append(append([]interface{}{}, packetValues...), "A", `["93.184.216.34"]`)
	v3 := egressAuditHashValuesWithDNS(dnsValues...)
	if v3 == v2 {
		t.Fatal("v3 DNS hash reused v2 domain")
	}
	emptyProvenance := []interface{}{"", "", "", "", "", "", "", "", "", ""}
	if got := egressAuditHashValuesWithProvenance(append(append([]interface{}{}, dnsValues...), emptyProvenance...)...); got != v3 {
		t.Fatalf("empty provenance did not preserve v3 hash: %q != %q", got, v3)
	}
	provenance := []interface{}{"event-id", "container", "gateway", "curl", "execution", "call", "call", "verified", "normal", "single"}
	v4 := egressAuditHashValuesWithProvenance(append(append([]interface{}{}, dnsValues...), provenance...)...)
	if v4 == v3 {
		t.Fatal("v4 provenance hash reused v3 domain")
	}
}

func TestEgressAuditLegacyRowsProjectAndFilterAsContainerUnattributed(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	conversation, _ := createRunningEgressAuditRuntime(t, db, "legacy provenance projection")
	if _, err := db.Exec(`DROP TRIGGER trg_egress_audit_append_only_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE egress_audit_events SET source_event_id = '', runtime_mode = '', runtime_instance_id = '', tool_name = '', execution_id = '', tool_call_id = '', activity_scope_id = '', attribution_status = '', declared_activity_kind = '', observed_activity_kind = '' WHERE conversation_id = ?`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	items, err := db.ListEgressAuditEvents(context.Background(), EgressAuditFilter{
		ConversationID: conversation.ID, RuntimeMode: "container", AttributionStatus: "legacy_unattributed",
		Scope: RBACScopeAll, Limit: 20,
	})
	if err != nil || len(items) != 1 {
		t.Fatalf("legacy provenance filter = %#v, %v", items, err)
	}
	if items[0].RuntimeMode != "container" || items[0].AttributionStatus != "legacy_unattributed" || items[0].HashVersion != 1 ||
		items[0].DeclaredActivityKind != "unknown" || items[0].ObservedActivityKind != "single" {
		t.Fatalf("legacy provenance projection = %#v", items[0])
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
		// dns_query_type is bounded resolver metadata (for example A, MX or
		// SRV), not an HTTP query string. Keep the broad secret-material guard
		// while explicitly allowing this audited DNS discriminator.
		if lower == "dns_query_type" {
			continue
		}
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

func TestEgressAuditPersistsSRVOwnerAndFollowingDNSEvents(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	conversation, spec := createRunningEgressAuditRuntime(t, db, "complete DNS audit")
	targets, err := db.ListRunningEgressAuditRuntimeTargets(ctx)
	if err != nil || len(targets) != 1 {
		t.Fatalf("running targets = %#v, %v", targets, err)
	}

	base := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestDNS,
		Decision: egress.ActivityDecisionAllowed, RuleID: "allow-dns", Reason: "allow-visit", Outcome: "upstream_rcodenameerror",
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	srv := base
	srv.Domain = "_sip._tcp.sip.voice.google.com"
	srv.DNSQueryType = "srv"
	inserted, err := db.AppendEgressNetworkAuditEvent(ctx, targets[0], srv)
	if err != nil || !inserted {
		t.Fatalf("append SRV event = %v, %v", inserted, err)
	}
	caa := base
	caa.Timestamp = base.Timestamp.Add(time.Millisecond)
	caa.Domain = "google.com"
	caa.DNSQueryType = "caa"
	inserted, err = db.AppendEgressNetworkAuditEvent(ctx, targets[0], caa)
	if err != nil || !inserted {
		t.Fatalf("append event after SRV = %v, %v", inserted, err)
	}

	items, err := db.ListEgressAuditEvents(ctx, EgressAuditFilter{ConversationID: conversation.ID, Category: "network", Scope: RBACScopeAll, Limit: 10})
	if err != nil || len(items) != 2 {
		t.Fatalf("DNS audit events = %#v, %v", items, err)
	}
	wantTypes := map[string]bool{"srv": false, "caa": false}
	for _, item := range items {
		wantTypes[item.DNSQueryType] = true
	}
	if !wantTypes["srv"] || !wantTypes["caa"] {
		t.Fatalf("DNS query types = %#v", wantTypes)
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
