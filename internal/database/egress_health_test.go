package database

import (
	"context"
	"testing"
	"time"

	"cyberstrike-ai/internal/egress"
)

func TestEgressHealthEventsPersistReplaySafelyAndRemainHashChained(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	conversation, spec := createRunningEgressAuditRuntimeWithRoute(t, db, "health audit", false)
	targets, err := db.ListRunningEgressAuditRuntimeTargets(ctx)
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets = %#v, %v", targets, err)
	}
	target := targets[0]
	now := time.Now().UTC()
	health := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: now, RequestType: egress.ActivityRequestHealth,
		Domain: "allowed.example", Decision: egress.ActivityDecisionBlocked, RuleID: "attack-rule",
		Reason: "upstream_rate_limited", Outcome: "cooldown_started", RetryAfterMS: 30000,
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	inserted, err := db.ApplyEgressHealthEvent(ctx, target, health)
	if err != nil || !inserted {
		t.Fatalf("cooldown event = %v, %v", inserted, err)
	}
	inserted, err = db.ApplyEgressHealthEvent(ctx, target, health)
	if err != nil || inserted {
		t.Fatalf("duplicate cooldown event = %v, %v", inserted, err)
	}
	state, err := db.GetConversationEgressHealthState(ctx, conversation.ID)
	if err != nil || state.Status != EgressHealthCooldown || state.Signal != "upstream_rate_limited" || state.CooldownUntil == nil || state.ManualRecoveryRequired {
		t.Fatalf("cooldown state = %#v, %v", state, err)
	}

	paused := health
	paused.Timestamp = now.Add(time.Second)
	paused.Reason = "captcha_challenge"
	paused.Outcome = "health_paused"
	paused.RetryAfterMS = 0
	if inserted, err := db.ApplyEgressHealthEvent(ctx, target, paused); err != nil || !inserted {
		t.Fatalf("pause event = %v, %v", inserted, err)
	}
	state, err = db.GetConversationEgressHealthState(ctx, conversation.ID)
	if err != nil || state.Status != EgressHealthPaused || state.Signal != "captcha_challenge" || !state.ManualRecoveryRequired || state.CooldownUntil != nil {
		t.Fatalf("paused state = %#v, %v", state, err)
	}

	state, err = db.RecordManualEgressRecovery(ctx, target)
	if err != nil || state.Status != EgressHealthHealthy || state.Signal != "" || state.ManualRecoveryRequired || state.CooldownUntil != nil {
		t.Fatalf("manual recovery state = %#v, %v", state, err)
	}
	recoveredAt := state.UpdatedAt
	lateReplay := health
	lateReplay.Timestamp = now.Add(-time.Minute)
	lateReplay.RuleID = "replayed-rule"
	if inserted, err := db.ApplyEgressHealthEvent(ctx, target, lateReplay); err != nil || !inserted {
		t.Fatalf("late replay audit = %v, %v", inserted, err)
	}
	state, err = db.GetConversationEgressHealthState(ctx, conversation.ID)
	if err != nil || state.Status != EgressHealthHealthy || !state.UpdatedAt.Equal(recoveredAt) {
		t.Fatalf("late replay regressed state = %#v, %v", state, err)
	}

	events, err := db.ListEgressAuditEvents(ctx, EgressAuditFilter{
		ConversationID: conversation.ID, EventType: "health", Scope: RBACScopeAll, Limit: 20,
	})
	if err != nil || len(events) != 4 {
		t.Fatalf("health audit events = %#v, %v", events, err)
	}
	want := map[string]int{"cooldown_started": 2, "health_paused": 1, "health_recovered": 1}
	for _, event := range events {
		want[event.Outcome]--
		if event.EventType != "health" || event.Category != "lifecycle" || event.LifecycleOperation != "health" || event.ChainSequence < 1 || event.EventHash == "" {
			t.Fatalf("health audit projection = %#v", event)
		}
	}
	for outcome, remaining := range want {
		if remaining != 0 {
			t.Fatalf("outcome %s remaining = %d", outcome, remaining)
		}
	}
	integrity, err := db.VerifyEgressAuditIntegrity(ctx, EgressAuditFilter{ConversationID: conversation.ID, Scope: RBACScopeAll})
	if err != nil || integrity.Status != "verified" {
		t.Fatalf("health audit integrity = %#v, %v", integrity, err)
	}
}

func TestEgressHealthRejectsUnknownOrSensitiveShapes(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	_, spec := createRunningEgressAuditRuntimeWithRoute(t, db, "health validation", false)
	targets, err := db.ListRunningEgressAuditRuntimeTargets(ctx)
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets = %#v, %v", targets, err)
	}
	valid := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestHealth,
		Decision: egress.ActivityDecisionBlocked, Reason: "waf_challenge", Outcome: "health_paused",
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	for name, mutate := range map[string]func(*egress.ActivityEvent){
		"unknown signal":  func(event *egress.ActivityEvent) { event.Reason = "raw_provider_error" },
		"body counter":    func(event *egress.ActivityEvent) { event.BytesDown = 1 },
		"query path":      func(event *egress.ActivityEvent) { event.Path = "/?secret=value" },
		"unbounded retry": func(event *egress.ActivityEvent) { event.RetryAfterMS = int64(time.Hour/time.Millisecond) + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := db.ApplyEgressHealthEvent(ctx, targets[0], candidate); err == nil {
				t.Fatalf("invalid health event accepted: %#v", candidate)
			}
		})
	}
}

func TestEgressHealthStateDoesNotLeakAcrossRuntimeGenerations(t *testing.T) {
	db := newContainerRuntimeTestDB(t)
	ctx := context.Background()
	conversation, spec := createRunningEgressAuditRuntimeWithRoute(t, db, "health generation", false)
	targets, err := db.ListRunningEgressAuditRuntimeTargets(ctx)
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets = %#v, %v", targets, err)
	}
	paused := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: time.Now().UTC(), RequestType: egress.ActivityRequestHealth,
		Decision: egress.ActivityDecisionBlocked, Reason: "captcha_challenge", Outcome: "health_paused",
		SnapshotID: spec.EgressGateway.BoundarySnapshot.ID, SnapshotSHA256: spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	if inserted, err := db.ApplyEgressHealthEvent(ctx, targets[0], paused); err != nil || !inserted {
		t.Fatalf("pause generation one = %v, %v", inserted, err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes SET runtime_generation = runtime_generation + 1 WHERE conversation_id = ?
	`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	state, err := db.GetConversationEgressHealthState(ctx, conversation.ID)
	if err != nil || state.RuntimeGeneration != 2 || state.Status != EgressHealthHealthy || state.Signal != "" || state.ManualRecoveryRequired {
		t.Fatalf("generation two state = %#v, %v", state, err)
	}
}
