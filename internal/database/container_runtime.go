package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
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
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET lifecycle_operation = ?, lifecycle_state = ?, lifecycle_error = '',
			lifecycle_started_at = ?, lifecycle_completed_at = NULL, runtime_drift = '',
			readiness_status = CASE WHEN ? = ? AND readiness_status != ? THEN ? ELSE readiness_status END,
			readiness_error = CASE WHEN ? = ? THEN '' ELSE readiness_error END,
			updated_at = ?
		WHERE conversation_id = ? AND initialization_status = ? AND lifecycle_state IN (?, ?)
	`, operation, containerruntime.LifecycleInProgress, now,
		operation, containerruntime.LifecycleOperationRebuild, containerruntime.ReadinessNotRequired, containerruntime.ReadinessPending,
		operation, containerruntime.LifecycleOperationRebuild,
		now, strings.TrimSpace(conversationID),
		containerruntime.InitializationCreated, containerruntime.LifecycleIdle, containerruntime.LifecycleFailed)
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
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET provider_id = ?, runtime_status = ?, last_error = ?,
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
	message := strings.TrimSpace(failure.Message)
	if len(message) > 1024 {
		message = message[:1024]
	}
	result, err := db.ExecContext(ctx, `
		UPDATE conversation_container_runtimes
		SET lifecycle_state = ?, lifecycle_error = ?, lifecycle_completed_at = ?,
			runtime_status = CASE WHEN ? = 1 THEN ? ELSE runtime_status END,
			runtime_observed_at = ?, runtime_drift = ?,
			readiness_status = CASE WHEN ? = 1 THEN ? ELSE readiness_status END,
			readiness_error = CASE WHEN ? = 1 THEN ? ELSE readiness_error END,
			readiness_completed_at = CASE WHEN ? = 1 THEN ? ELSE readiness_completed_at END,
			updated_at = ?
		WHERE conversation_id = ? AND initialization_status = ?
			AND lifecycle_operation = ? AND lifecycle_state = ?
	`, containerruntime.LifecycleFailed, message, now,
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
	return db.GetContainerInitialization(ctx, conversationID)
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
