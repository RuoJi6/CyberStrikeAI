package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	containerruntime "cyberstrike-ai/internal/runtime/container"
)

// ListIdleRuntimeCandidates returns only durable running runtimes whose
// per-conversation idle deadline has passed and which have no persisted
// queued/running tool executions. The scheduler still rechecks this predicate
// atomically in BeginIdleStop immediately before touching Docker.
func (db *DB) ListIdleRuntimeCandidates(ctx context.Context, now time.Time, limit int) ([]containerruntime.IdleRuntimeCandidate, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", containerruntime.ErrInvalidSpecification)
	}
	if now.IsZero() || limit < 1 || limit > 4096 {
		return nil, fmt.Errorf("%w: idle evaluation time and candidate limit are invalid", containerruntime.ErrInvalidSpecification)
	}
	rows, err := db.QueryContext(ctx, `
		SELECT r.conversation_id, c.updated_at, c.idle_action, c.idle_timeout_seconds
		FROM conversation_container_runtimes r
		JOIN conversations c ON c.id = r.conversation_id
		WHERE r.initialization_status = ?
			AND r.runtime_status = ?
			AND r.lifecycle_state = ?
			AND r.readiness_status IN (?, ?)
			AND c.idle_action IN ('delete', 'stop')
			AND c.idle_timeout_seconds BETWEEN 60 AND 2592000
			AND julianday(c.updated_at) + (CAST(c.idle_timeout_seconds AS REAL) / 86400.0) <= julianday(?)
			AND NOT EXISTS (
				SELECT 1 FROM tool_executions te
				WHERE te.conversation_id = r.conversation_id
					AND te.status IN ('queued', 'running')
			)
		ORDER BY julianday(c.updated_at), r.conversation_id
		LIMIT ?
	`, containerruntime.InitializationCreated, containerruntime.StatusRunning,
		containerruntime.LifecycleIdle, containerruntime.ReadinessReady,
		containerruntime.ReadinessNotRequired, formatSQLiteUTC(now), limit)
	if err != nil {
		return nil, fmt.Errorf("list idle conversation runtimes: %w", err)
	}
	defer rows.Close()
	candidates := make([]containerruntime.IdleRuntimeCandidate, 0)
	for rows.Next() {
		var candidate containerruntime.IdleRuntimeCandidate
		var lastActivity string
		if err := rows.Scan(&candidate.ConversationID, &lastActivity, &candidate.Action, &candidate.TimeoutSeconds); err != nil {
			return nil, err
		}
		candidate.LastActivityAt, err = ParseRFC3339Time(lastActivity)
		if err != nil {
			return nil, fmt.Errorf("parse idle conversation activity time: %w", err)
		}
		candidate.ExpiresAt = candidate.LastActivityAt.Add(time.Duration(candidate.TimeoutSeconds) * time.Second)
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return candidates, nil
}

// BeginIdleAction is the durable compare-and-swap guard for per-conversation
// automatic stop/delete operations.
func (db *DB) BeginIdleAction(ctx context.Context, candidate containerruntime.IdleRuntimeCandidate, now time.Time) (containerruntime.InitializationRecord, error) {
	conversationID := strings.TrimSpace(candidate.ConversationID)
	action := strings.TrimSpace(candidate.Action)
	if ctx == nil || conversationID == "" || now.IsZero() || (action != ConversationIdleActionStop && action != ConversationIdleActionDelete) {
		return containerruntime.InitializationRecord{}, fmt.Errorf("%w: idle action claim is invalid", containerruntime.ErrInvalidSpecification)
	}
	operation := containerruntime.LifecycleOperationStop
	if action == ConversationIdleActionDelete {
		operation = containerruntime.LifecycleOperationDelete
	}
	stamp := formatSQLiteUTC(time.Now().UTC())
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET lifecycle_operation = ?, lifecycle_state = ?, lifecycle_error = '',
			lifecycle_started_at = ?, lifecycle_completed_at = NULL,
			runtime_drift = '', updated_at = ?
		WHERE conversation_id = ?
			AND initialization_status = ?
			AND runtime_status = ?
			AND lifecycle_state = ?
			AND readiness_status IN (?, ?)
			AND EXISTS (
				SELECT 1 FROM conversations c
				WHERE c.id = conversation_container_runtimes.conversation_id
					AND c.idle_action = ?
					AND c.idle_timeout_seconds = ?
					AND julianday(c.updated_at) <= julianday(?)
					AND julianday(c.updated_at) + (CAST(c.idle_timeout_seconds AS REAL) / 86400.0) <= julianday(?)
			)
			AND NOT EXISTS (
				SELECT 1 FROM tool_executions te
				WHERE te.conversation_id = conversation_container_runtimes.conversation_id
					AND te.status IN ('queued', 'running')
			)
	`, operation, containerruntime.LifecycleInProgress, stamp, stamp, conversationID,
		containerruntime.InitializationCreated, containerruntime.StatusRunning,
		containerruntime.LifecycleIdle, containerruntime.ReadinessReady,
		containerruntime.ReadinessNotRequired, action, candidate.TimeoutSeconds,
		formatSQLiteUTC(candidate.LastActivityAt), formatSQLiteUTC(now))
	if err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("begin idle container action: %w", err)
	}
	if err := requireContainerRuntimeUpdate(result, "begin idle action"); err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	return db.GetContainerInitialization(ctx, conversationID)
}

// BeginIdleStop is the durable compare-and-swap guard for automatic stopping.
// A concurrent message, lifecycle operation, or queued/running tool causes the
// claim to fail before the Docker stop request is issued.
func (db *DB) BeginIdleStop(ctx context.Context, conversationID string, inactiveBefore time.Time) (containerruntime.InitializationRecord, error) {
	conversationID = strings.TrimSpace(conversationID)
	if ctx == nil || conversationID == "" || inactiveBefore.IsZero() {
		return containerruntime.InitializationRecord{}, fmt.Errorf("%w: context, conversation id and idle cutoff are required", containerruntime.ErrInvalidSpecification)
	}
	now := formatSQLiteUTC(time.Now())
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET lifecycle_operation = ?, lifecycle_state = ?, lifecycle_error = '',
			lifecycle_started_at = ?, lifecycle_completed_at = NULL,
			runtime_drift = '', updated_at = ?
		WHERE conversation_id = ?
			AND initialization_status = ?
			AND runtime_status = ?
			AND lifecycle_state = ?
			AND readiness_status IN (?, ?)
			AND EXISTS (
				SELECT 1 FROM conversations c
				WHERE c.id = conversation_container_runtimes.conversation_id
					AND julianday(c.updated_at) <= julianday(?)
			)
			AND NOT EXISTS (
				SELECT 1 FROM tool_executions te
				WHERE te.conversation_id = conversation_container_runtimes.conversation_id
					AND te.status IN ('queued', 'running')
			)
	`, containerruntime.LifecycleOperationStop, containerruntime.LifecycleInProgress,
		now, now, conversationID, containerruntime.InitializationCreated,
		containerruntime.StatusRunning, containerruntime.LifecycleIdle,
		containerruntime.ReadinessReady, containerruntime.ReadinessNotRequired,
		formatSQLiteUTC(inactiveBefore))
	if err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("begin idle container stop: %w", err)
	}
	if err := requireContainerRuntimeUpdate(result, "begin idle stop"); err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	return db.GetContainerInitialization(ctx, conversationID)
}

var _ containerruntime.IdleRuntimeStore = (*DB)(nil)
