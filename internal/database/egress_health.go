package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/egress"
)

const createConversationEgressHealthTable = `
CREATE TABLE IF NOT EXISTS conversation_egress_health (
	conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
	runtime_generation INTEGER NOT NULL DEFAULT 0,
	snapshot_id TEXT NOT NULL DEFAULT '',
	snapshot_sha256 TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'healthy',
	signal TEXT NOT NULL DEFAULT '',
	cooldown_until DATETIME,
	manual_recovery_required INTEGER NOT NULL DEFAULT 0,
	updated_at DATETIME NOT NULL,
	CHECK (runtime_generation >= 0),
	CHECK (status IN ('healthy', 'cooldown', 'paused')),
	CHECK (manual_recovery_required IN (0, 1))
);`

const (
	EgressHealthHealthy  = "healthy"
	EgressHealthCooldown = "cooldown"
	EgressHealthPaused   = "paused"
)

// EgressHealthState is a credential-free mutable projection of immutable
// health lifecycle events. It deliberately contains no response headers or
// bodies and can be safely returned to the container-management UI.
type EgressHealthState struct {
	ConversationID         string     `json:"conversationId"`
	RuntimeGeneration      int        `json:"runtimeGeneration"`
	SnapshotID             string     `json:"snapshotId,omitempty"`
	SnapshotSHA256         string     `json:"snapshotSha256,omitempty"`
	Status                 string     `json:"status"`
	Signal                 string     `json:"signal,omitempty"`
	CooldownUntil          *time.Time `json:"cooldownUntil,omitempty"`
	ManualRecoveryRequired bool       `json:"manualRecoveryRequired"`
	UpdatedAt              time.Time  `json:"updatedAt"`
}

type egressHealthProjection struct {
	status         string
	signal         string
	cooldownUntil  *time.Time
	manualRecovery bool
	forceUpdate    bool
	result         string
	message        string
}

func (db *DB) ApplyEgressHealthEvent(ctx context.Context, target EgressAuditRuntimeTarget, event egress.ActivityEvent) (bool, error) {
	projection, err := validateEgressHealthEvent(target, event, false)
	if err != nil {
		return false, err
	}
	return db.appendEgressHealthEvent(ctx, target, event, projection)
}

func (db *DB) RecordManualEgressRecovery(ctx context.Context, target EgressAuditRuntimeTarget) (EgressHealthState, error) {
	if ctx == nil {
		return EgressHealthState{}, errors.New("egress health context is required")
	}
	record := target.Record
	if err := validateEgressHealthTarget(target); err != nil {
		return EgressHealthState{}, err
	}
	now := time.Now().UTC()
	event := egress.ActivityEvent{
		Event: egress.ActivityEventName, Timestamp: now, RequestType: egress.ActivityRequestHealth,
		Decision: egress.ActivityDecisionAllowed, Reason: "manual_recovery", Outcome: "health_recovered",
		SnapshotID:     record.Spec.EgressGateway.BoundarySnapshot.ID,
		SnapshotSHA256: record.Spec.EgressGateway.BoundarySnapshot.SHA256,
	}
	if record.Spec.EgressGateway.UpstreamRoute != nil {
		event.UpstreamRouteID = record.Spec.EgressGateway.UpstreamRoute.ID
	}
	projection, err := validateEgressHealthEvent(target, event, true)
	if err != nil {
		return EgressHealthState{}, err
	}
	if _, err := db.appendEgressHealthEvent(ctx, target, event, projection); err != nil {
		return EgressHealthState{}, err
	}
	return db.GetConversationEgressHealthState(ctx, record.ConversationID)
}

func (db *DB) appendEgressHealthEvent(ctx context.Context, target EgressAuditRuntimeTarget, event egress.ActivityEvent, projection egressHealthProjection) (bool, error) {
	if ctx == nil {
		return false, errors.New("egress health context is required")
	}
	record := target.Record
	keyPayload := struct {
		ConversationID    string
		ContainerID       string
		RuntimeGeneration int
		Event             egress.ActivityEvent
	}{record.ConversationID, record.ProviderID, record.RuntimeGeneration, event}
	encoded, err := json.Marshal(keyPayload)
	if err != nil {
		return false, fmt.Errorf("encode egress health event key: %w", err)
	}
	digest := sha256.Sum256(encoded)
	eventKey := "health:" + hex.EncodeToString(digest[:])
	id := "eh-" + hex.EncodeToString(digest[:16])
	recordedAt := time.Now().UTC()
	var cooldownUntil interface{}
	if projection.cooldownUntil != nil {
		cooldownUntil = formatSQLiteUTC(*projection.cooldownUntil)
	}
	blockMatchJSON := ""
	if event.BlockMatch != nil {
		if err := boundary.ValidateBlockMatch(event.BlockMatch); err != nil {
			return false, err
		}
		encodedMatch, err := json.Marshal(event.BlockMatch)
		if err != nil {
			return false, fmt.Errorf("encode egress health block match: %w", err)
		}
		blockMatchJSON = string(encodedMatch)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO egress_audit_events (
			id, event_key, recorded_at, occurred_at, category, event_type,
			conversation_id, conversation_title, container_id, agent_id, runtime_generation,
			snapshot_id, snapshot_sha256, domain, decision, result, rule_id, reason, block_match_json,
			upstream_route_id, outcome, lifecycle_operation, lifecycle_state, message
		) VALUES (
			?, ?, ?, ?, 'lifecycle', 'health',
			?, ?, ?, 'container-agent', ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
			'health', ?, ?
		)
	`, id, eventKey, formatSQLiteUTC(recordedAt), formatSQLiteUTC(event.Timestamp.UTC()),
		record.ConversationID, sanitizeEgressAuditDisplayText(target.ConversationTitle, 512), record.ProviderID, record.RuntimeGeneration,
		event.SnapshotID, event.SnapshotSHA256, event.Domain, event.Decision, projection.result, event.RuleID, event.Reason, blockMatchJSON,
		event.UpstreamRouteID, event.Outcome, projection.status, projection.message)
	if err != nil {
		return false, fmt.Errorf("append egress health audit event: %w", err)
	}
	manual := 0
	if projection.manualRecovery {
		manual = 1
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO conversation_egress_health (
			conversation_id, runtime_generation, snapshot_id, snapshot_sha256, status, signal,
			cooldown_until, manual_recovery_required, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(conversation_id) DO UPDATE SET
			runtime_generation = excluded.runtime_generation,
			snapshot_id = excluded.snapshot_id,
			snapshot_sha256 = excluded.snapshot_sha256,
			status = excluded.status,
			signal = excluded.signal,
			cooldown_until = excluded.cooldown_until,
			manual_recovery_required = excluded.manual_recovery_required,
			updated_at = excluded.updated_at
		WHERE ? = 1
			OR excluded.runtime_generation > conversation_egress_health.runtime_generation
			OR (excluded.runtime_generation = conversation_egress_health.runtime_generation
				AND excluded.updated_at >= conversation_egress_health.updated_at)
	`, record.ConversationID, record.RuntimeGeneration, event.SnapshotID, event.SnapshotSHA256,
		projection.status, projection.signal, cooldownUntil, manual, formatSQLiteUTC(event.Timestamp.UTC()), boolToInt(projection.forceUpdate)); err != nil {
		return false, fmt.Errorf("update egress health state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	rows, _ := result.RowsAffected()
	return rows == 1, nil
}

func validateEgressHealthTarget(target EgressAuditRuntimeTarget) error {
	record := target.Record
	if !validEgressAuditText(record.ConversationID, 128, false) || !validEgressAuditText(record.ProviderID, 128, false) ||
		record.RuntimeGeneration < 0 || int64(record.RuntimeGeneration) > maxEgressAuditSafeInteger ||
		record.Spec.EgressGateway == nil || record.Spec.EgressGateway.BoundarySnapshot == nil {
		return errors.New("invalid egress health target")
	}
	return nil
}

func validateEgressHealthEvent(target EgressAuditRuntimeTarget, event egress.ActivityEvent, manual bool) (egressHealthProjection, error) {
	invalid := func() (egressHealthProjection, error) {
		return egressHealthProjection{}, errors.New("invalid egress health event")
	}
	if err := validateEgressHealthTarget(target); err != nil {
		return invalid()
	}
	record := target.Record
	if event.Event != egress.ActivityEventName || event.RequestType != egress.ActivityRequestHealth || event.Timestamp.IsZero() ||
		event.Timestamp.After(time.Now().UTC().Add(5*time.Minute)) || event.SnapshotID != record.Spec.EgressGateway.BoundarySnapshot.ID ||
		event.SnapshotSHA256 != record.Spec.EgressGateway.BoundarySnapshot.SHA256 || event.RetryAfterMS < 0 ||
		event.RetryAfterMS > int64(time.Hour/time.Millisecond) || event.Port != 0 || event.Method != "" || event.Path != "" ||
		event.HTTPStatus != 0 || event.ConnectedIP != "" || len(event.ResolvedIPs) != 0 || event.BytesUp != 0 || event.BytesDown != 0 ||
		event.LatencyMS != 0 || !validEgressAuditCode(event.Reason, false) || !validEgressAuditCode(event.Outcome, false) ||
		!validEgressAuditText(event.RuleID, 256, true) {
		return invalid()
	}
	if boundary.ValidateBlockMatch(event.BlockMatch) != nil {
		return invalid()
	}
	if event.Domain != "" {
		normalized, err := boundary.NormalizeHost(event.Domain)
		if err != nil || normalized != event.Domain {
			return invalid()
		}
	}
	expectedRouteID := ""
	if record.Spec.EgressGateway.UpstreamRoute != nil {
		expectedRouteID = record.Spec.EgressGateway.UpstreamRoute.ID
	}
	if event.UpstreamRouteID != expectedRouteID {
		return invalid()
	}
	if manual {
		if event.Decision != egress.ActivityDecisionAllowed || event.Reason != "manual_recovery" || event.Outcome != "health_recovered" || event.RetryAfterMS != 0 {
			return invalid()
		}
		return egressHealthProjection{status: EgressHealthHealthy, forceUpdate: true, result: "success", message: "egress health manually recovered"}, nil
	}
	switch event.Outcome {
	case "cooldown_started":
		if event.Decision != egress.ActivityDecisionBlocked || event.Reason != "upstream_rate_limited" || event.RetryAfterMS <= 0 {
			return invalid()
		}
		until := event.Timestamp.UTC().Add(time.Duration(event.RetryAfterMS) * time.Millisecond)
		return egressHealthProjection{status: EgressHealthCooldown, signal: event.Reason, cooldownUntil: &until, result: "failure", message: "egress cooldown started"}, nil
	case "cooldown_expired":
		if event.Decision != egress.ActivityDecisionAllowed || event.Reason != "upstream_rate_limited" || event.RetryAfterMS != 0 {
			return invalid()
		}
		return egressHealthProjection{status: EgressHealthHealthy, result: "success", message: "egress cooldown expired"}, nil
	case "health_paused":
		if event.Decision != egress.ActivityDecisionBlocked || event.RetryAfterMS != 0 ||
			(event.Reason != "consecutive_login_failures" && event.Reason != "waf_challenge" && event.Reason != "captcha_challenge") {
			return invalid()
		}
		return egressHealthProjection{status: EgressHealthPaused, signal: event.Reason, manualRecovery: true, result: "failure", message: "egress health paused"}, nil
	default:
		return invalid()
	}
}

func (db *DB) GetConversationEgressHealthState(ctx context.Context, conversationID string) (EgressHealthState, error) {
	conversationID = strings.TrimSpace(conversationID)
	if ctx == nil || conversationID == "" {
		return EgressHealthState{}, errors.New("egress health context and conversation are required")
	}
	currentGeneration := 0
	err := db.QueryRowContext(ctx, `
		SELECT runtime_generation FROM conversation_container_runtimes WHERE conversation_id = ?
	`, conversationID).Scan(&currentGeneration)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return EgressHealthState{}, err
	}
	var state EgressHealthState
	var cooldown sql.NullString
	var manual int
	var updated string
	err = db.QueryRowContext(ctx, `
		SELECT conversation_id, runtime_generation, snapshot_id, snapshot_sha256, status, signal,
			CAST(cooldown_until AS TEXT), manual_recovery_required, CAST(updated_at AS TEXT)
		FROM conversation_egress_health WHERE conversation_id = ? AND runtime_generation = ?
	`, conversationID, currentGeneration).Scan(&state.ConversationID, &state.RuntimeGeneration, &state.SnapshotID, &state.SnapshotSHA256,
		&state.Status, &state.Signal, &cooldown, &manual, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return EgressHealthState{ConversationID: conversationID, RuntimeGeneration: currentGeneration, Status: EgressHealthHealthy}, nil
	}
	if err != nil {
		return EgressHealthState{}, err
	}
	state.ManualRecoveryRequired = manual == 1
	state.CooldownUntil = parseNullableDBTime(cooldown)
	state.UpdatedAt = parseDBTime(updated)
	return state, nil
}
