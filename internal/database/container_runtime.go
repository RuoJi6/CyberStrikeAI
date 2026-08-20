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
	updated_at DATETIME NOT NULL,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
	CHECK (initialization_status IN ('queued', 'creating', 'created', 'failed')),
	CHECK (readiness_status IN ('not_required', 'pending', 'validating', 'ready', 'failed'))
);`

func (db *DB) initContainerRuntimeTables() error {
	if _, err := db.Exec(createConversationContainerRuntimesTable); err != nil {
		return err
	}
	if err := db.ensureContainerRuntimeReadinessColumns(); err != nil {
		return err
	}
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_conversation_container_runtimes_status ON conversation_container_runtimes(initialization_status, updated_at)`)
	return err
}

func (db *DB) ensureContainerRuntimeReadinessColumns() error {
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
	}
	for _, addition := range additions {
		if columns[addition.name] {
			continue
		}
		if _, err := db.Exec(addition.sql); err != nil {
			return fmt.Errorf("add container runtime column %s: %w", addition.name, err)
		}
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
			requested_at = ?, started_at = NULL, completed_at = NULL,
			readiness_started_at = NULL, readiness_completed_at = NULL, updated_at = ?
		WHERE conversation_id = ? AND initialization_status = ?
	`, containerruntime.InitializationQueued, readinessStatus, now, now, spec.ConversationID, containerruntime.InitializationFailed)
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
			completed_at = ?, updated_at = ?
		WHERE conversation_id = ? AND runtime_id = ? AND initialization_status = ?
	`, containerruntime.InitializationCreated, runtime.ProviderID, runtime.Status, now, now, conversationID, runtime.ID, containerruntime.InitializationCreating)
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

const containerInitializationSelect = `
	SELECT conversation_id, runtime_id, initialization_status, attempt, provider_id,
		runtime_status, image_digest, image_platform, spec_json, last_error,
		readiness_status, readiness_error, inventory_digest, tool_count,
		requested_at, started_at, completed_at, updated_at,
		readiness_started_at, readiness_completed_at
	FROM conversation_container_runtimes`

type containerInitializationScanner interface {
	Scan(dest ...interface{}) error
}

func scanContainerInitialization(scanner containerInitializationScanner) (containerruntime.InitializationRecord, error) {
	var record containerruntime.InitializationRecord
	var runtimeID, status, runtimeStatus, specJSON, readinessStatus string
	var requestedAt, updatedAt string
	var startedAt, completedAt, readinessStartedAt, readinessCompletedAt sql.NullString
	err := scanner.Scan(
		&record.ConversationID, &runtimeID, &status, &record.Attempt, &record.ProviderID,
		&runtimeStatus, &record.ImageDigest, &record.ImagePlatform, &specJSON, &record.LastError,
		&readinessStatus, &record.ReadinessError, &record.InventoryDigest, &record.ToolCount,
		&requestedAt, &startedAt, &completedAt, &updatedAt, &readinessStartedAt, &readinessCompletedAt,
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
