package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	containerruntime "cyberstrike-ai/internal/runtime/container"
)

const createConversationContainerRuntimesTable = `
CREATE TABLE IF NOT EXISTS conversation_container_runtimes (
	conversation_id TEXT PRIMARY KEY,
	runtime_id TEXT NOT NULL UNIQUE,
	initialization_status TEXT NOT NULL,
	attempt INTEGER NOT NULL DEFAULT 0,
	provider_id TEXT NOT NULL DEFAULT '',
	runtime_status TEXT NOT NULL DEFAULT '',
	image_digest TEXT NOT NULL,
	image_platform TEXT NOT NULL,
	spec_json TEXT NOT NULL,
	last_error TEXT NOT NULL DEFAULT '',
	readiness_status TEXT NOT NULL DEFAULT 'not_required',
	readiness_error TEXT NOT NULL DEFAULT '',
	inventory_digest TEXT NOT NULL DEFAULT '',
	tool_count INTEGER NOT NULL DEFAULT 0,
	requested_at DATETIME NOT NULL,
	started_at DATETIME,
	completed_at DATETIME,
	readiness_started_at DATETIME,
	readiness_completed_at DATETIME,
	lifecycle_operation TEXT NOT NULL DEFAULT 'none',
	lifecycle_state TEXT NOT NULL DEFAULT 'idle',
	lifecycle_error TEXT NOT NULL DEFAULT '',
	runtime_generation INTEGER NOT NULL DEFAULT 0,
	runtime_observed_at DATETIME,
	lifecycle_started_at DATETIME,
	lifecycle_completed_at DATETIME,
	runtime_drift TEXT NOT NULL DEFAULT '',
	updated_at DATETIME NOT NULL,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
	CHECK (initialization_status IN ('queued', 'creating', 'created', 'failed')),
	CHECK (readiness_status IN ('not_required', 'pending', 'validating', 'ready', 'failed')),
	CHECK (lifecycle_operation IN ('none', 'start', 'stop', 'rebuild', 'delete', 'reconcile')),
	CHECK (lifecycle_state IN ('idle', 'in_progress', 'failed'))
);`

const createContainerResourceTombstonesTable = `
CREATE TABLE IF NOT EXISTS container_resource_tombstones (
	resource_kind TEXT NOT NULL,
	logical_id TEXT NOT NULL,
	provider_id TEXT NOT NULL,
	resource_name TEXT NOT NULL,
	conversation_id TEXT NOT NULL,
	resource_created_at DATETIME,
	status TEXT NOT NULL DEFAULT 'pending',
	attempt INTEGER NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT '',
	discovered_at DATETIME NOT NULL,
	last_attempt_at DATETIME,
	next_retry_at DATETIME,
	completed_at DATETIME,
	updated_at DATETIME NOT NULL,
	PRIMARY KEY (resource_kind, provider_id),
	CHECK (resource_kind IN ('agent-runtime', 'conversation-network', 'workspace-volume')),
	CHECK (status IN ('pending', 'deleting', 'failed', 'completed'))
);`

const createRetainedContainerWorkspacesTable = `
CREATE TABLE IF NOT EXISTS retained_container_workspaces (
	original_conversation_id TEXT PRIMARY KEY,
	conversation_title TEXT NOT NULL DEFAULT '',
	runtime_id TEXT NOT NULL UNIQUE,
	volume_name TEXT NOT NULL UNIQUE,
	retained_at DATETIME NOT NULL
);`

func (db *DB) initContainerRuntimeTables() error {
	if _, err := db.Exec(createConversationContainerRuntimesTable); err != nil {
		return err
	}
	if err := db.ensureContainerRuntimeColumns(); err != nil {
		return err
	}
	if _, err := db.Exec(createContainerResourceTombstonesTable); err != nil {
		return err
	}
	if _, err := db.Exec(createRetainedContainerWorkspacesTable); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_conversation_container_runtimes_status ON conversation_container_runtimes(initialization_status, updated_at)`); err != nil {
		return err
	}
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_container_resource_tombstones_retry ON container_resource_tombstones(status, next_retry_at, updated_at)`)
	return err
}

func (db *DB) ensureContainerRuntimeColumns() error {
	rows, err := db.Query(`PRAGMA table_info(conversation_container_runtimes)`)
	if err != nil {
		return err
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue interface{}
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	additions := []struct {
		name string
		sql  string
	}{
		{"readiness_status", `ALTER TABLE conversation_container_runtimes ADD COLUMN readiness_status TEXT NOT NULL DEFAULT 'not_required' CHECK (readiness_status IN ('not_required', 'pending', 'validating', 'ready', 'failed'))`},
		{"readiness_error", `ALTER TABLE conversation_container_runtimes ADD COLUMN readiness_error TEXT NOT NULL DEFAULT ''`},
		{"inventory_digest", `ALTER TABLE conversation_container_runtimes ADD COLUMN inventory_digest TEXT NOT NULL DEFAULT ''`},
		{"tool_count", `ALTER TABLE conversation_container_runtimes ADD COLUMN tool_count INTEGER NOT NULL DEFAULT 0`},
		{"readiness_started_at", `ALTER TABLE conversation_container_runtimes ADD COLUMN readiness_started_at DATETIME`},
		{"readiness_completed_at", `ALTER TABLE conversation_container_runtimes ADD COLUMN readiness_completed_at DATETIME`},
		{"lifecycle_operation", `ALTER TABLE conversation_container_runtimes ADD COLUMN lifecycle_operation TEXT NOT NULL DEFAULT 'none' CHECK (lifecycle_operation IN ('none', 'start', 'stop', 'rebuild', 'delete', 'reconcile'))`},
		{"lifecycle_state", `ALTER TABLE conversation_container_runtimes ADD COLUMN lifecycle_state TEXT NOT NULL DEFAULT 'idle' CHECK (lifecycle_state IN ('idle', 'in_progress', 'failed'))`},
		{"lifecycle_error", `ALTER TABLE conversation_container_runtimes ADD COLUMN lifecycle_error TEXT NOT NULL DEFAULT ''`},
		{"runtime_generation", `ALTER TABLE conversation_container_runtimes ADD COLUMN runtime_generation INTEGER NOT NULL DEFAULT 0`},
		{"runtime_observed_at", `ALTER TABLE conversation_container_runtimes ADD COLUMN runtime_observed_at DATETIME`},
		{"lifecycle_started_at", `ALTER TABLE conversation_container_runtimes ADD COLUMN lifecycle_started_at DATETIME`},
		{"lifecycle_completed_at", `ALTER TABLE conversation_container_runtimes ADD COLUMN lifecycle_completed_at DATETIME`},
		{"runtime_drift", `ALTER TABLE conversation_container_runtimes ADD COLUMN runtime_drift TEXT NOT NULL DEFAULT ''`},
	}
	for _, addition := range additions {
		if columns[addition.name] {
			continue
		}
		if _, err := db.Exec(addition.sql); err != nil {
			return fmt.Errorf("add container runtime column %s: %w", addition.name, err)
		}
	}
	if _, err := db.Exec(`
		UPDATE conversation_container_runtimes
		SET runtime_generation = 1
		WHERE initialization_status = 'created' AND runtime_generation = 0
	`); err != nil {
		return fmt.Errorf("backfill container runtime generation: %w", err)
	}
	return nil
}

func (db *DB) GetContainerInitialization(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return containerruntime.InitializationRecord{}, fmt.Errorf("%w: conversation id is required", containerruntime.ErrInvalidSpecification)
	}
	return scanContainerInitialization(db.QueryRowContext(ctx, containerInitializationSelect+` WHERE conversation_id = ?`, conversationID))
}

func (db *DB) Get(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
	return db.GetContainerInitialization(ctx, conversationID)
}

func (db *DB) Queue(ctx context.Context, spec containerruntime.RuntimeSpec, retryFailed bool) (containerruntime.InitializationRecord, bool, error) {
	if err := containerruntime.ValidateSpec(spec); err != nil {
		return containerruntime.InitializationRecord{}, false, err
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("encode container runtime specification: %w", err)
	}
	now := formatSQLiteUTC(time.Now())
	readinessStatus := containerruntime.ReadinessNotRequired
	if spec.Readiness.Enabled {
		readinessStatus = containerruntime.ReadinessPending
	}
	result, err := db.ExecContext(ctx, `
		INSERT OR IGNORE INTO conversation_container_runtimes (
			conversation_id, runtime_id, initialization_status, attempt,
			image_digest, image_platform, spec_json, readiness_status, requested_at, updated_at
		) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?)
	`, spec.ConversationID, spec.ID, containerruntime.InitializationQueued, spec.Image.Digest, spec.Image.Platform, string(encoded), readinessStatus, now, now)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("queue container initialization: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return containerruntime.InitializationRecord{}, false, err
	}
	record, err := db.GetContainerInitialization(ctx, spec.ConversationID)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, err
	}
	stored, err := json.Marshal(record.Spec)
	if err != nil || !bytes.Equal(stored, encoded) {
		return record, false, fmt.Errorf("%w: conversation runtime specification is immutable", containerruntime.ErrRuntimeStateConflict)
	}
	if inserted == 1 {
		return record, true, nil
	}
	if !retryFailed {
		return record, false, nil
	}
	if record.Status == containerruntime.InitializationCreated && record.ReadinessStatus == containerruntime.ReadinessFailed {
		result, err = db.ExecContext(ctx, `
			UPDATE conversation_container_runtimes
			SET readiness_status = ?, readiness_error = '', inventory_digest = '', tool_count = 0,
				readiness_started_at = NULL, readiness_completed_at = NULL, updated_at = ?
			WHERE conversation_id = ? AND initialization_status = ? AND readiness_status = ?
		`, containerruntime.ReadinessPending, now, spec.ConversationID, containerruntime.InitializationCreated, containerruntime.ReadinessFailed)
		if err != nil {
			return record, false, fmt.Errorf("retry container readiness: %w", err)
		}
		updated, _ := result.RowsAffected()
		record, err = db.GetContainerInitialization(ctx, spec.ConversationID)
		return record, updated == 1, err
	}
	if record.Status != containerruntime.InitializationFailed {
		return record, false, nil
	}

	result, err = db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET initialization_status = ?, provider_id = '', runtime_status = '', last_error = '',
			readiness_status = ?, readiness_error = '', inventory_digest = '', tool_count = 0,
			lifecycle_operation = ?, lifecycle_state = ?, lifecycle_error = '',
			runtime_generation = 0, runtime_observed_at = NULL, lifecycle_started_at = NULL,
			lifecycle_completed_at = NULL, runtime_drift = '',
			requested_at = ?, started_at = NULL, completed_at = NULL,
			readiness_started_at = NULL, readiness_completed_at = NULL, updated_at = ?
		WHERE conversation_id = ? AND initialization_status = ?
	`, containerruntime.InitializationQueued, readinessStatus, containerruntime.LifecycleOperationNone, containerruntime.LifecycleIdle, now, now, spec.ConversationID, containerruntime.InitializationFailed)
	if err != nil {
		return record, false, fmt.Errorf("retry container initialization: %w", err)
	}
	updated, _ := result.RowsAffected()
	record, err = db.GetContainerInitialization(ctx, spec.ConversationID)
	return record, updated == 1, err
}

func (db *DB) Claim(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, bool, error) {
	now := formatSQLiteUTC(time.Now())
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET initialization_status = ?, attempt = attempt + 1, started_at = ?, completed_at = NULL,
			last_error = '', updated_at = ?
		WHERE conversation_id = ? AND initialization_status = ?
	`, containerruntime.InitializationCreating, now, now, conversationID, containerruntime.InitializationQueued)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("claim container initialization: %w", err)
	}
	updated, _ := result.RowsAffected()
	record, getErr := db.GetContainerInitialization(ctx, conversationID)
	return record, updated == 1, getErr
}

// UpgradeQueuedContainerRuntimeTopology atomically upgrades only a not-yet-
// claimed runtime's trusted network/gateway topology. It exists for startup
// recovery of queued records written by earlier stage-4 deployments; created
// runtimes still require the explicit lifecycle rebuild path.
func (db *DB) UpgradeQueuedContainerRuntimeTopology(ctx context.Context, conversationID string, target containerruntime.RuntimeSpec) (containerruntime.InitializationRecord, error) {
	if err := containerruntime.ValidateSpec(target); err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	conversationID = strings.TrimSpace(conversationID)
	current, err := db.GetContainerInitialization(ctx, conversationID)
	if err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	if current.Spec.ID != target.ID || current.Spec.ConversationID != target.ConversationID || target.ConversationID != conversationID {
		return current, fmt.Errorf("%w: queued runtime identity cannot change", containerruntime.ErrRuntimeStateConflict)
	}
	baseline := target
	baseline.Security.NetworkMode = current.Spec.Security.NetworkMode
	baseline.EgressGateway = current.Spec.EgressGateway
	if containerruntime.RuntimeSpecDigest(baseline) != containerruntime.RuntimeSpecDigest(current.Spec) {
		return current, fmt.Errorf("%w: queued runtime upgrade may change only trusted topology", containerruntime.ErrRuntimeStateConflict)
	}
	if containerruntime.RuntimeSpecDigest(target) == containerruntime.RuntimeSpecDigest(current.Spec) {
		return current, nil
	}
	if current.Status != containerruntime.InitializationQueued {
		return current, fmt.Errorf("%w: only a queued runtime topology may be upgraded", containerruntime.ErrRuntimeStateConflict)
	}
	currentJSON, err := json.Marshal(current.Spec)
	if err != nil {
		return current, fmt.Errorf("encode current queued runtime specification: %w", err)
	}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		return current, fmt.Errorf("encode upgraded queued runtime specification: %w", err)
	}
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET spec_json = ?, updated_at = ?
		WHERE conversation_id = ? AND initialization_status = ? AND spec_json = ?
	`, string(targetJSON), formatSQLiteUTC(time.Now()), conversationID, containerruntime.InitializationQueued, string(currentJSON))
	if err != nil {
		return current, fmt.Errorf("upgrade queued container runtime topology: %w", err)
	}
	updated, _ := result.RowsAffected()
	record, getErr := db.GetContainerInitialization(ctx, conversationID)
	if getErr != nil {
		return containerruntime.InitializationRecord{}, getErr
	}
	if updated != 1 && containerruntime.RuntimeSpecDigest(record.Spec) != containerruntime.RuntimeSpecDigest(target) {
		return record, fmt.Errorf("%w: queued runtime topology changed concurrently", containerruntime.ErrRuntimeStateConflict)
	}
	return record, nil
}

func (db *DB) Complete(ctx context.Context, conversationID string, runtime containerruntime.Runtime) (containerruntime.InitializationRecord, error) {
	now := formatSQLiteUTC(time.Now())
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET initialization_status = ?, provider_id = ?, runtime_status = ?, last_error = '',
			lifecycle_operation = ?, lifecycle_state = ?, lifecycle_error = '',
			runtime_generation = 1, runtime_observed_at = ?, lifecycle_started_at = NULL,
			lifecycle_completed_at = ?, runtime_drift = '', completed_at = ?, updated_at = ?
		WHERE conversation_id = ? AND runtime_id = ? AND initialization_status = ?
	`, containerruntime.InitializationCreated, runtime.ProviderID, runtime.Status,
		containerruntime.LifecycleOperationNone, containerruntime.LifecycleIdle, now, now, now, now,
		conversationID, runtime.ID, containerruntime.InitializationCreating)
	if err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("complete container initialization: %w", err)
	}
	if err := requireContainerRuntimeUpdate(result, "complete"); err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	return db.GetContainerInitialization(ctx, conversationID)
}

func (db *DB) Fail(ctx context.Context, conversationID, message string) (containerruntime.InitializationRecord, error) {
	now := formatSQLiteUTC(time.Now())
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET initialization_status = ?, last_error = ?, completed_at = ?, updated_at = ?
		WHERE conversation_id = ? AND initialization_status IN (?, ?)
	`, containerruntime.InitializationFailed, strings.TrimSpace(message), now, now, conversationID, containerruntime.InitializationQueued, containerruntime.InitializationCreating)
	if err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("fail container initialization: %w", err)
	}
	if err := requireContainerRuntimeUpdate(result, "fail"); err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	return db.GetContainerInitialization(ctx, conversationID)
}

func (db *DB) ClaimReadiness(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, bool, error) {
	now := formatSQLiteUTC(time.Now())
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET readiness_status = ?, readiness_error = '', readiness_started_at = ?,
			readiness_completed_at = NULL, updated_at = ?
		WHERE conversation_id = ? AND initialization_status = ? AND readiness_status = ?
	`, containerruntime.ReadinessValidating, now, now, conversationID, containerruntime.InitializationCreated, containerruntime.ReadinessPending)
	if err != nil {
		return containerruntime.InitializationRecord{}, false, fmt.Errorf("claim container readiness: %w", err)
	}
	updated, _ := result.RowsAffected()
	record, getErr := db.GetContainerInitialization(ctx, conversationID)
	return record, updated == 1, getErr
}

func (db *DB) Ready(ctx context.Context, conversationID string, report containerruntime.ReadinessReport) (containerruntime.InitializationRecord, error) {
	now := formatSQLiteUTC(time.Now())
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET readiness_status = ?, readiness_error = '', inventory_digest = ?, tool_count = ?,
			readiness_completed_at = ?, updated_at = ?
		WHERE conversation_id = ? AND initialization_status = ? AND readiness_status = ?
	`, containerruntime.ReadinessReady, report.InventoryDigest, report.ToolCount, now, now, conversationID, containerruntime.InitializationCreated, containerruntime.ReadinessValidating)
	if err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("complete container readiness: %w", err)
	}
	if err := requireContainerRuntimeUpdate(result, "complete readiness"); err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	return db.GetContainerInitialization(ctx, conversationID)
}

func (db *DB) FailReadiness(ctx context.Context, conversationID, message string) (containerruntime.InitializationRecord, error) {
	now := formatSQLiteUTC(time.Now())
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET readiness_status = ?, readiness_error = ?, readiness_completed_at = ?, updated_at = ?
		WHERE conversation_id = ? AND initialization_status = ? AND readiness_status = ?
	`, containerruntime.ReadinessFailed, strings.TrimSpace(message), now, now, conversationID, containerruntime.InitializationCreated, containerruntime.ReadinessValidating)
	if err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("fail container readiness: %w", err)
	}
	if err := requireContainerRuntimeUpdate(result, "fail readiness"); err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	return db.GetContainerInitialization(ctx, conversationID)
}

func (db *DB) RecoverInterrupted(ctx context.Context) ([]containerruntime.InitializationRecord, error) {
	now := formatSQLiteUTC(time.Now())
	if _, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET initialization_status = ?, started_at = NULL, completed_at = NULL, updated_at = ?
		WHERE initialization_status = ?
	`, containerruntime.InitializationQueued, now, containerruntime.InitializationCreating); err != nil {
		return nil, fmt.Errorf("recover interrupted container initializations: %w", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET readiness_status = ?, readiness_started_at = NULL, readiness_completed_at = NULL, updated_at = ?
		WHERE initialization_status = ? AND readiness_status = ?
	`, containerruntime.ReadinessPending, now, containerruntime.InitializationCreated, containerruntime.ReadinessValidating); err != nil {
		return nil, fmt.Errorf("recover interrupted container readiness: %w", err)
	}
	rows, err := db.QueryContext(ctx, containerInitializationSelect+`
		WHERE initialization_status = ? OR (initialization_status = ? AND readiness_status = ?)
		ORDER BY requested_at, conversation_id`, containerruntime.InitializationQueued, containerruntime.InitializationCreated, containerruntime.ReadinessPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]containerruntime.InitializationRecord, 0)
	for rows.Next() {
		record, scanErr := scanContainerInitialization(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (db *DB) BeginLifecycle(ctx context.Context, conversationID string, operation containerruntime.LifecycleOperation) (containerruntime.InitializationRecord, error) {
	if !validLifecycleOperation(operation) || operation == containerruntime.LifecycleOperationNone {
		return containerruntime.InitializationRecord{}, fmt.Errorf("%w: lifecycle operation is invalid", containerruntime.ErrInvalidSpecification)
	}
	now := formatSQLiteUTC(time.Now())
	boundaryRebuildSnapshotID := ""
	if operation == containerruntime.LifecycleOperationRebuild {
		boundaryRebuildSnapshotID = containerruntime.BoundaryRebuildSnapshotFromContext(ctx)
	}
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET lifecycle_operation = ?, lifecycle_state = ?, lifecycle_error = '',
			lifecycle_started_at = ?, lifecycle_completed_at = NULL, runtime_drift = '',
			readiness_status = CASE WHEN ? = ? AND readiness_status != ? THEN ? ELSE readiness_status END,
			readiness_error = CASE WHEN ? = ? THEN '' ELSE readiness_error END,
			updated_at = ?
		WHERE conversation_id = ? AND initialization_status = ? AND lifecycle_state IN (?, ?)
			AND (
				? != ?
				OR (
					(? = '' AND NOT EXISTS (
						SELECT 1 FROM conversation_boundary_rebuilds br
						WHERE br.conversation_id = conversation_container_runtimes.conversation_id
					))
					OR (? != '' AND EXISTS (
						SELECT 1 FROM conversation_boundary_rebuilds br
						WHERE br.conversation_id = conversation_container_runtimes.conversation_id
							AND br.pending_snapshot_id = ?
					))
				)
			)
	`, operation, containerruntime.LifecycleInProgress, now,
		operation, containerruntime.LifecycleOperationRebuild, containerruntime.ReadinessNotRequired, containerruntime.ReadinessPending,
		operation, containerruntime.LifecycleOperationRebuild,
		now, strings.TrimSpace(conversationID),
		containerruntime.InitializationCreated, containerruntime.LifecycleIdle, containerruntime.LifecycleFailed,
		operation, containerruntime.LifecycleOperationRebuild,
		boundaryRebuildSnapshotID, boundaryRebuildSnapshotID, boundaryRebuildSnapshotID)
	if err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("begin container lifecycle %s: %w", operation, err)
	}
	if err := requireContainerRuntimeUpdate(result, "begin "+string(operation)); err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	return db.GetContainerInitialization(ctx, conversationID)
}

func (db *DB) CompleteLifecycle(ctx context.Context, conversationID string, operation containerruntime.LifecycleOperation, completion containerruntime.LifecycleCompletion) (containerruntime.InitializationRecord, error) {
	if !validLifecycleOperation(operation) || operation == containerruntime.LifecycleOperationNone {
		return containerruntime.InitializationRecord{}, fmt.Errorf("%w: lifecycle operation is invalid", containerruntime.ErrInvalidSpecification)
	}
	if strings.TrimSpace(completion.Runtime.ProviderID) == "" || completion.Runtime.ID == "" {
		return containerruntime.InitializationRecord{}, fmt.Errorf("%w: observed runtime identity is required", containerruntime.ErrInvalidSpecification)
	}
	now := formatSQLiteUTC(time.Now())
	increment := 0
	if completion.IncrementGeneration {
		increment = 1
	}
	updateReadiness := 0
	readinessDigest := ""
	readinessTools := 0
	if completion.Readiness != nil {
		updateReadiness = 1
		readinessDigest = strings.TrimSpace(completion.Readiness.InventoryDigest)
		readinessTools = completion.Readiness.ToolCount
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("begin container lifecycle completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	replaceSpec, replacementJSON, err := validateLifecycleSpecReplacement(ctx, tx, conversationID, operation, completion.Runtime, completion.ReplacementSpec)
	if err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET provider_id = ?, runtime_status = ?, last_error = ?,
			image_digest = CASE WHEN ? = 1 THEN ? ELSE image_digest END,
			image_platform = CASE WHEN ? = 1 THEN ? ELSE image_platform END,
			spec_json = CASE WHEN ? = 1 THEN ? ELSE spec_json END,
			lifecycle_state = ?, lifecycle_error = '', lifecycle_completed_at = ?,
			runtime_generation = runtime_generation + ?, runtime_observed_at = ?, runtime_drift = ?,
			readiness_status = CASE WHEN ? = 1 THEN ? ELSE readiness_status END,
			readiness_error = CASE WHEN ? = 1 THEN '' ELSE readiness_error END,
			inventory_digest = CASE WHEN ? = 1 THEN ? ELSE inventory_digest END,
			tool_count = CASE WHEN ? = 1 THEN ? ELSE tool_count END,
			readiness_completed_at = CASE WHEN ? = 1 THEN ? ELSE readiness_completed_at END,
			updated_at = ?
		WHERE conversation_id = ? AND runtime_id = ? AND initialization_status = ?
			AND lifecycle_operation = ? AND lifecycle_state = ?
	`, completion.Runtime.ProviderID, completion.Runtime.Status, strings.TrimSpace(completion.Runtime.LastError),
		replaceSpec, completion.Runtime.Image.Digest,
		replaceSpec, completion.Runtime.Image.Platform,
		replaceSpec, replacementJSON,
		containerruntime.LifecycleIdle, now, increment, now, strings.TrimSpace(completion.Drift),
		updateReadiness, containerruntime.ReadinessReady,
		updateReadiness,
		updateReadiness, readinessDigest,
		updateReadiness, readinessTools,
		updateReadiness, now,
		now, strings.TrimSpace(conversationID), completion.Runtime.ID, containerruntime.InitializationCreated,
		operation, containerruntime.LifecycleInProgress)
	if err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("complete container lifecycle %s: %w", operation, err)
	}
	if err := requireContainerRuntimeUpdate(result, "complete "+string(operation)); err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	if operation == containerruntime.LifecycleOperationRebuild {
		var previousSnapshotID, pendingSnapshotID string
		var expectedGeneration int
		pendingErr := tx.QueryRowContext(ctx, `
			SELECT previous_snapshot_id, pending_snapshot_id, expected_runtime_generation
			FROM conversation_boundary_rebuilds
			WHERE conversation_id = ?
		`, strings.TrimSpace(conversationID)).Scan(&previousSnapshotID, &pendingSnapshotID, &expectedGeneration)
		switch {
		case errors.Is(pendingErr, sql.ErrNoRows):
			// A maintenance rebuild without a boundaryPolicyId keeps the active
			// immutable snapshot unchanged, while still recording that it applies
			// to the newly created runtime generation.
			var activeSnapshotID string
			activeErr := tx.QueryRowContext(ctx, `
				SELECT snapshot_id FROM conversation_boundary_activations
				WHERE conversation_id = ? ORDER BY runtime_generation DESC LIMIT 1
			`, strings.TrimSpace(conversationID)).Scan(&activeSnapshotID)
			if activeErr != nil && !errors.Is(activeErr, sql.ErrNoRows) {
				return containerruntime.InitializationRecord{}, fmt.Errorf("load active boundary snapshot for maintenance rebuild: %w", activeErr)
			}
			if activeErr == nil {
				var runtimeGeneration int
				if err := tx.QueryRowContext(ctx, `
					SELECT runtime_generation FROM conversation_container_runtimes WHERE conversation_id = ?
				`, strings.TrimSpace(conversationID)).Scan(&runtimeGeneration); err != nil {
					return containerruntime.InitializationRecord{}, fmt.Errorf("load maintenance rebuild generation: %w", err)
				}
				activationID := fmt.Sprintf("%s:%d", activeSnapshotID, runtimeGeneration)
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO conversation_boundary_activations (
						id, conversation_id, snapshot_id, runtime_generation, activated_at
					) VALUES (?, ?, ?, ?, ?)
				`, activationID, strings.TrimSpace(conversationID), activeSnapshotID, runtimeGeneration, formatSQLiteUTC(time.Now().UTC())); err != nil {
					return containerruntime.InitializationRecord{}, fmt.Errorf("carry boundary snapshot across maintenance rebuild: %w", err)
				}
			}
		case pendingErr != nil:
			return containerruntime.InitializationRecord{}, fmt.Errorf("load pending boundary rebuild: %w", pendingErr)
		default:
			var runtimeGeneration int
			if err := tx.QueryRowContext(ctx, `
				SELECT runtime_generation FROM conversation_container_runtimes WHERE conversation_id = ?
			`, strings.TrimSpace(conversationID)).Scan(&runtimeGeneration); err != nil {
				return containerruntime.InitializationRecord{}, fmt.Errorf("load rebuilt runtime generation: %w", err)
			}
			if runtimeGeneration != expectedGeneration {
				return containerruntime.InitializationRecord{}, fmt.Errorf("%w: boundary rebuild expected runtime generation %d, got %d", containerruntime.ErrRuntimeStateConflict, expectedGeneration, runtimeGeneration)
			}
			var activeSnapshotID string
			if err := tx.QueryRowContext(ctx, `
				SELECT snapshot_id FROM conversation_boundary_activations
				WHERE conversation_id = ? ORDER BY runtime_generation DESC LIMIT 1
			`, strings.TrimSpace(conversationID)).Scan(&activeSnapshotID); err != nil {
				return containerruntime.InitializationRecord{}, fmt.Errorf("load active boundary snapshot before rebuild: %w", err)
			}
			if activeSnapshotID != previousSnapshotID {
				return containerruntime.InitializationRecord{}, fmt.Errorf("%w: active boundary snapshot changed during rebuild", containerruntime.ErrRuntimeStateConflict)
			}
			activatedAt := formatSQLiteUTC(time.Now().UTC())
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO conversation_boundary_activations (
					id, conversation_id, snapshot_id, runtime_generation, activated_at
				) VALUES (?, ?, ?, ?, ?)
			`, pendingSnapshotID, strings.TrimSpace(conversationID), pendingSnapshotID, runtimeGeneration, activatedAt); err != nil {
				return containerruntime.InitializationRecord{}, fmt.Errorf("activate rebuilt boundary snapshot: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM conversation_boundary_rebuilds
				WHERE conversation_id = ? AND pending_snapshot_id = ?
			`, strings.TrimSpace(conversationID), pendingSnapshotID); err != nil {
				return containerruntime.InitializationRecord{}, fmt.Errorf("complete pending boundary rebuild: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("commit container lifecycle %s: %w", operation, err)
	}
	return db.GetContainerInitialization(ctx, conversationID)
}

func (db *DB) FailLifecycle(ctx context.Context, conversationID string, operation containerruntime.LifecycleOperation, failure containerruntime.LifecycleFailure) (containerruntime.InitializationRecord, error) {
	if !validLifecycleOperation(operation) || operation == containerruntime.LifecycleOperationNone {
		return containerruntime.InitializationRecord{}, fmt.Errorf("%w: lifecycle operation is invalid", containerruntime.ErrInvalidSpecification)
	}
	now := formatSQLiteUTC(time.Now())
	readinessFailed := 0
	if failure.ReadinessFailed {
		readinessFailed = 1
	}
	statusPresent := 0
	if failure.RuntimeStatus != "" {
		statusPresent = 1
	}
	if (failure.AppliedRuntime == nil) != (failure.ReplacementSpec == nil) {
		return containerruntime.InitializationRecord{}, fmt.Errorf("%w: applied runtime and replacement specification must be provided together", containerruntime.ErrInvalidSpecification)
	}
	message := strings.TrimSpace(failure.Message)
	if len(message) > 1024 {
		message = message[:1024]
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("begin failed container lifecycle completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	appliedRuntime := 0
	providerID := ""
	imageDigest := ""
	imagePlatform := ""
	replacementJSON := ""
	if failure.AppliedRuntime != nil {
		appliedRuntime = 1
		providerID = strings.TrimSpace(failure.AppliedRuntime.ProviderID)
		imageDigest = failure.AppliedRuntime.Image.Digest
		imagePlatform = failure.AppliedRuntime.Image.Platform
		failure.RuntimeStatus = failure.AppliedRuntime.Status
		statusPresent = 1
		_, replacementJSON, err = validateLifecycleSpecReplacement(ctx, tx, conversationID, operation, *failure.AppliedRuntime, failure.ReplacementSpec)
		if err != nil {
			return containerruntime.InitializationRecord{}, err
		}
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET lifecycle_state = ?, lifecycle_error = ?, lifecycle_completed_at = ?,
			provider_id = CASE WHEN ? = 1 THEN ? ELSE provider_id END,
			image_digest = CASE WHEN ? = 1 THEN ? ELSE image_digest END,
			image_platform = CASE WHEN ? = 1 THEN ? ELSE image_platform END,
			spec_json = CASE WHEN ? = 1 THEN ? ELSE spec_json END,
			runtime_status = CASE WHEN ? = 1 THEN ? ELSE runtime_status END,
			runtime_observed_at = ?, runtime_drift = ?,
			readiness_status = CASE WHEN ? = 1 THEN ? ELSE readiness_status END,
			readiness_error = CASE WHEN ? = 1 THEN ? ELSE readiness_error END,
			readiness_completed_at = CASE WHEN ? = 1 THEN ? ELSE readiness_completed_at END,
			updated_at = ?
		WHERE conversation_id = ? AND initialization_status = ?
			AND lifecycle_operation = ? AND lifecycle_state = ?
	`, containerruntime.LifecycleFailed, message, now,
		appliedRuntime, providerID,
		appliedRuntime, imageDigest,
		appliedRuntime, imagePlatform,
		appliedRuntime, replacementJSON,
		statusPresent, failure.RuntimeStatus, now, strings.TrimSpace(failure.Drift),
		readinessFailed, containerruntime.ReadinessFailed,
		readinessFailed, message,
		readinessFailed, now,
		now, strings.TrimSpace(conversationID), containerruntime.InitializationCreated,
		operation, containerruntime.LifecycleInProgress)
	if err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("fail container lifecycle %s: %w", operation, err)
	}
	if err := requireContainerRuntimeUpdate(result, "fail "+string(operation)); err != nil {
		return containerruntime.InitializationRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return containerruntime.InitializationRecord{}, fmt.Errorf("commit failed container lifecycle %s: %w", operation, err)
	}
	return db.GetContainerInitialization(ctx, conversationID)
}

func validateLifecycleSpecReplacement(
	ctx context.Context,
	tx *sql.Tx,
	conversationID string,
	operation containerruntime.LifecycleOperation,
	runtime containerruntime.Runtime,
	replacement *containerruntime.RuntimeSpec,
) (int, string, error) {
	if replacement == nil {
		return 0, "", nil
	}
	if operation != containerruntime.LifecycleOperationRebuild && operation != containerruntime.LifecycleOperationReconcile {
		return 0, "", fmt.Errorf("%w: runtime specification replacement requires rebuild or reconciliation", containerruntime.ErrInvalidSpecification)
	}
	if err := containerruntime.ValidateSpec(*replacement); err != nil {
		return 0, "", err
	}
	if strings.TrimSpace(runtime.ProviderID) == "" || runtime.ID == "" || runtime.Status == "" {
		return 0, "", fmt.Errorf("%w: observed replacement runtime identity and status are required", containerruntime.ErrInvalidSpecification)
	}
	conversationID = strings.TrimSpace(conversationID)
	if replacement.ConversationID != conversationID || replacement.ID != runtime.ID ||
		replacement.Image.Digest != runtime.Image.Digest || replacement.Image.Platform != runtime.Image.Platform ||
		containerruntime.RuntimeSpecDigest(*replacement) != runtime.SpecDigest {
		return 0, "", fmt.Errorf("%w: replacement specification does not match the observed runtime", containerruntime.ErrRuntimeStateConflict)
	}
	var currentJSON string
	if err := tx.QueryRowContext(ctx, `
		SELECT spec_json FROM conversation_container_runtimes
		WHERE conversation_id = ? AND runtime_id = ? AND initialization_status = ?
			AND lifecycle_operation = ? AND lifecycle_state = ?
	`, conversationID, runtime.ID, containerruntime.InitializationCreated, operation, containerruntime.LifecycleInProgress).Scan(&currentJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, "", containerruntime.ErrRuntimeStateConflict
		}
		return 0, "", fmt.Errorf("load runtime specification for lifecycle replacement: %w", err)
	}
	var current containerruntime.RuntimeSpec
	if err := json.Unmarshal([]byte(currentJSON), &current); err != nil {
		return 0, "", fmt.Errorf("decode current runtime specification for lifecycle replacement: %w", err)
	}
	expected := current
	changed := false
	if current.Security.NetworkMode == containerruntime.NetworkNone {
		expected.Security.NetworkMode = containerruntime.NetworkInternal
		changed = true
	} else if current.Security.NetworkMode != containerruntime.NetworkInternal {
		return 0, "", fmt.Errorf("%w: current runtime network mode cannot be migrated", containerruntime.ErrRuntimeStateConflict)
	}
	if current.EgressGateway == nil && replacement.EgressGateway != nil {
		gateway := *replacement.EgressGateway
		expected.EgressGateway = &gateway
		changed = true
	}
	if current.EgressGateway != nil && current.EgressGateway.BoundarySnapshot != nil && replacement.EgressGateway != nil &&
		sameEgressBoundarySnapshot(current.EgressGateway.BoundarySnapshot, replacement.EgressGateway.BoundarySnapshot) &&
		(current.EgressGateway.Image != replacement.EgressGateway.Image || current.EgressGateway.Resources != replacement.EgressGateway.Resources) {
		// An explicit maintenance rebuild may roll out a newer trusted gateway
		// binary or resource envelope. Start from the durable gateway so the
		// immutable snapshot, route, and auth references cannot drift here.
		gateway := *current.EgressGateway
		gateway.Image = replacement.EgressGateway.Image
		gateway.Resources = replacement.EgressGateway.Resources
		expected.EgressGateway = &gateway
		changed = true
	}
	if replacement.EgressGateway != nil && replacement.EgressGateway.BoundarySnapshot != nil {
		var currentSnapshot *containerruntime.EgressBoundarySnapshotSpec
		if current.EgressGateway != nil {
			currentSnapshot = current.EgressGateway.BoundarySnapshot
		}
		requestedSnapshot := replacement.EgressGateway.BoundarySnapshot
		if !sameEgressBoundarySnapshot(currentSnapshot, requestedSnapshot) {
			if err := validateLifecycleBoundarySnapshot(ctx, tx, conversationID, operation, *requestedSnapshot); err != nil {
				return 0, "", err
			}
			if expected.EgressGateway == nil {
				return 0, "", fmt.Errorf("%w: boundary snapshot requires an egress gateway", containerruntime.ErrRuntimeStateConflict)
			}
			gateway := *expected.EgressGateway
			// The one-time item-2 to item-3 migration both introduces the
			// authorized snapshot and advances the pinned gateway image. Once a
			// snapshot is present, later policy rebuilds may only replace that
			// snapshot and must preserve every other gateway field.
			if current.EgressGateway != nil && currentSnapshot == nil {
				gateway = *replacement.EgressGateway
			}
			snapshot := *requestedSnapshot
			gateway.BoundarySnapshot = &snapshot
			expected.EgressGateway = &gateway
			changed = true
		}
	}
	if replacement.EgressGateway != nil && replacement.EgressGateway.BoundarySnapshot != nil {
		var currentAuthProfiles *containerruntime.EgressAuthProfilesSpec
		if current.EgressGateway != nil {
			currentAuthProfiles = current.EgressGateway.AuthProfiles
		}
		requestedAuthProfiles := replacement.EgressGateway.AuthProfiles
		if !sameEgressAuthProfiles(currentAuthProfiles, requestedAuthProfiles) {
			if expected.EgressGateway == nil || expected.EgressGateway.BoundarySnapshot == nil {
				return 0, "", fmt.Errorf("%w: auth profiles require an authorized boundary snapshot", containerruntime.ErrRuntimeStateConflict)
			}
			gateway := *expected.EgressGateway
			if requestedAuthProfiles == nil {
				gateway.AuthProfiles = nil
			} else {
				authProfiles := *requestedAuthProfiles
				gateway.AuthProfiles = &authProfiles
			}
			expected.EgressGateway = &gateway
			changed = true
		}
	}
	if !changed {
		return 0, "", fmt.Errorf("%w: runtime specification replacement is not a controlled topology upgrade", containerruntime.ErrRuntimeStateConflict)
	}
	if containerruntime.RuntimeSpecDigest(expected) != containerruntime.RuntimeSpecDigest(*replacement) {
		return 0, "", fmt.Errorf("%w: lifecycle replacement may only enable the internal network, refresh the pinned egress gateway, bind an authorized boundary snapshot, and update gateway-only auth profiles", containerruntime.ErrRuntimeStateConflict)
	}
	encoded, err := json.Marshal(replacement)
	if err != nil {
		return 0, "", fmt.Errorf("encode replacement runtime specification: %w", err)
	}
	return 1, string(encoded), nil
}

func sameEgressBoundarySnapshot(left, right *containerruntime.EgressBoundarySnapshotSpec) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.ID == right.ID && left.SHA256 == right.SHA256
}

func sameEgressAuthProfiles(left, right *containerruntime.EgressAuthProfilesSpec) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.ID == right.ID && left.SHA256 == right.SHA256
}

func validateLifecycleBoundarySnapshot(ctx context.Context, tx *sql.Tx, conversationID string, operation containerruntime.LifecycleOperation, requested containerruntime.EgressBoundarySnapshotSpec) error {
	var authorizedID, authorizedSHA256 string
	if operation == containerruntime.LifecycleOperationRebuild {
		err := tx.QueryRowContext(ctx, `
			SELECT s.id, s.sha256
			FROM conversation_boundary_rebuilds br
			JOIN boundary_policy_snapshots s ON s.id = br.pending_snapshot_id
			WHERE br.conversation_id = ?
		`, conversationID).Scan(&authorizedID, &authorizedSHA256)
		if err == nil {
			if requested.ID != authorizedID || requested.SHA256 != authorizedSHA256 {
				return fmt.Errorf("%w: replacement boundary snapshot does not match the authorized pending rebuild", containerruntime.ErrRuntimeStateConflict)
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("load authorized pending boundary snapshot: %w", err)
		}
	}
	err := tx.QueryRowContext(ctx, `
		SELECT s.id, s.sha256
		FROM conversation_boundary_activations a
		JOIN boundary_policy_snapshots s ON s.id = a.snapshot_id
		WHERE a.conversation_id = ?
		ORDER BY a.runtime_generation DESC
		LIMIT 1
	`, conversationID).Scan(&authorizedID, &authorizedSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: conversation has no active boundary snapshot", containerruntime.ErrRuntimeStateConflict)
	}
	if err != nil {
		return fmt.Errorf("load authorized active boundary snapshot: %w", err)
	}
	if requested.ID != authorizedID || requested.SHA256 != authorizedSHA256 {
		return fmt.Errorf("%w: replacement boundary snapshot does not match the active snapshot", containerruntime.ErrRuntimeStateConflict)
	}
	return nil
}

func (db *DB) DeleteLifecycle(ctx context.Context, conversationID string, operation containerruntime.LifecycleOperation) error {
	if operation != containerruntime.LifecycleOperationDelete {
		return fmt.Errorf("%w: delete lifecycle requires the delete operation", containerruntime.ErrInvalidSpecification)
	}
	result, err := db.ExecContext(ctx, `
		DELETE FROM conversation_container_runtimes
		WHERE conversation_id = ? AND initialization_status = ?
			AND lifecycle_operation = ? AND lifecycle_state = ?
	`, strings.TrimSpace(conversationID), containerruntime.InitializationCreated, operation, containerruntime.LifecycleInProgress)
	if err != nil {
		return fmt.Errorf("delete container lifecycle record: %w", err)
	}
	return requireContainerRuntimeUpdate(result, "delete")
}

func (db *DB) RecoverLifecycle(ctx context.Context) ([]containerruntime.InitializationRecord, error) {
	now := formatSQLiteUTC(time.Now())
	if _, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET lifecycle_state = ?, lifecycle_error = ?, lifecycle_completed_at = ?, updated_at = ?
		WHERE initialization_status = ? AND lifecycle_state = ?
	`, containerruntime.LifecycleFailed, "控制面重启中断了生命周期操作，正在对账", now, now,
		containerruntime.InitializationCreated, containerruntime.LifecycleInProgress); err != nil {
		return nil, fmt.Errorf("recover interrupted container lifecycle operations: %w", err)
	}
	rows, err := db.QueryContext(ctx, containerInitializationSelect+`
		WHERE initialization_status = ? ORDER BY requested_at, conversation_id`, containerruntime.InitializationCreated)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]containerruntime.InitializationRecord, 0)
	for rows.Next() {
		record, scanErr := scanContainerInitialization(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func validLifecycleOperation(operation containerruntime.LifecycleOperation) bool {
	switch operation {
	case containerruntime.LifecycleOperationNone,
		containerruntime.LifecycleOperationStart,
		containerruntime.LifecycleOperationStop,
		containerruntime.LifecycleOperationRebuild,
		containerruntime.LifecycleOperationDelete,
		containerruntime.LifecycleOperationReconcile:
		return true
	default:
		return false
	}
}

const containerInitializationSelect = `
	SELECT conversation_id, runtime_id, initialization_status, attempt, provider_id,
		runtime_status, image_digest, image_platform, spec_json, last_error,
		readiness_status, readiness_error, inventory_digest, tool_count,
		requested_at, started_at, completed_at, updated_at,
		readiness_started_at, readiness_completed_at,
		lifecycle_operation, lifecycle_state, lifecycle_error, runtime_generation,
		runtime_observed_at, lifecycle_started_at, lifecycle_completed_at, runtime_drift
	FROM conversation_container_runtimes`

type containerInitializationScanner interface {
	Scan(dest ...interface{}) error
}

func scanContainerInitialization(scanner containerInitializationScanner) (containerruntime.InitializationRecord, error) {
	var record containerruntime.InitializationRecord
	var runtimeID, status, runtimeStatus, specJSON, readinessStatus, lifecycleOperation, lifecycleState string
	var requestedAt, updatedAt string
	var startedAt, completedAt, readinessStartedAt, readinessCompletedAt sql.NullString
	var runtimeObservedAt, lifecycleStartedAt, lifecycleCompletedAt sql.NullString
	err := scanner.Scan(
		&record.ConversationID, &runtimeID, &status, &record.Attempt, &record.ProviderID,
		&runtimeStatus, &record.ImageDigest, &record.ImagePlatform, &specJSON, &record.LastError,
		&readinessStatus, &record.ReadinessError, &record.InventoryDigest, &record.ToolCount,
		&requestedAt, &startedAt, &completedAt, &updatedAt, &readinessStartedAt, &readinessCompletedAt,
		&lifecycleOperation, &lifecycleState, &record.LifecycleError, &record.RuntimeGeneration,
		&runtimeObservedAt, &lifecycleStartedAt, &lifecycleCompletedAt, &record.RuntimeDrift,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return record, fmt.Errorf("%w: container initialization", containerruntime.ErrNotFound)
		}
		return record, err
	}
	record.RuntimeID = containerruntime.RuntimeID(runtimeID)
	record.Status = containerruntime.InitializationStatus(status)
	record.RuntimeStatus = containerruntime.Status(runtimeStatus)
	record.ReadinessStatus = containerruntime.ReadinessStatus(readinessStatus)
	record.LifecycleOperation = containerruntime.LifecycleOperation(lifecycleOperation)
	record.LifecycleState = containerruntime.LifecycleState(lifecycleState)
	if err := json.Unmarshal([]byte(specJSON), &record.Spec); err != nil {
		return record, fmt.Errorf("decode container runtime specification: %w", err)
	}
	record.RequestedAt, err = ParseRFC3339Time(requestedAt)
	if err != nil {
		return record, err
	}
	record.UpdatedAt, err = ParseRFC3339Time(updatedAt)
	if err != nil {
		return record, err
	}
	if startedAt.Valid && strings.TrimSpace(startedAt.String) != "" {
		parsed, parseErr := ParseRFC3339Time(startedAt.String)
		if parseErr != nil {
			return record, parseErr
		}
		record.StartedAt = &parsed
	}
	if completedAt.Valid && strings.TrimSpace(completedAt.String) != "" {
		parsed, parseErr := ParseRFC3339Time(completedAt.String)
		if parseErr != nil {
			return record, parseErr
		}
		record.CompletedAt = &parsed
	}
	if readinessStartedAt.Valid && strings.TrimSpace(readinessStartedAt.String) != "" {
		parsed, parseErr := ParseRFC3339Time(readinessStartedAt.String)
		if parseErr != nil {
			return record, parseErr
		}
		record.ReadinessStartedAt = &parsed
	}
	if readinessCompletedAt.Valid && strings.TrimSpace(readinessCompletedAt.String) != "" {
		parsed, parseErr := ParseRFC3339Time(readinessCompletedAt.String)
		if parseErr != nil {
			return record, parseErr
		}
		record.ReadinessCompletedAt = &parsed
	}
	if runtimeObservedAt.Valid && strings.TrimSpace(runtimeObservedAt.String) != "" {
		parsed, parseErr := ParseRFC3339Time(runtimeObservedAt.String)
		if parseErr != nil {
			return record, parseErr
		}
		record.RuntimeObservedAt = &parsed
	}
	if lifecycleStartedAt.Valid && strings.TrimSpace(lifecycleStartedAt.String) != "" {
		parsed, parseErr := ParseRFC3339Time(lifecycleStartedAt.String)
		if parseErr != nil {
			return record, parseErr
		}
		record.LifecycleStartedAt = &parsed
	}
	if lifecycleCompletedAt.Valid && strings.TrimSpace(lifecycleCompletedAt.String) != "" {
		parsed, parseErr := ParseRFC3339Time(lifecycleCompletedAt.String)
		if parseErr != nil {
			return record, parseErr
		}
		record.LifecycleCompletedAt = &parsed
	}
	return record, nil
}

func requireContainerRuntimeUpdate(result sql.Result, action string) error {
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return fmt.Errorf("%w: cannot %s container initialization from current state", containerruntime.ErrRuntimeStateConflict, action)
	}
	return nil
}

var _ containerruntime.InitializationStore = (*DB)(nil)
var _ containerruntime.LifecycleStore = (*DB)(nil)
