package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/traffictransform"

	"github.com/google/uuid"
)

const createTrafficTransformsTable = `
CREATE TABLE IF NOT EXISTS traffic_transforms (
	id TEXT PRIMARY KEY,
	conversation_id TEXT,
	project_id TEXT,
	current_revision_id TEXT,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	language TEXT NOT NULL CHECK (language = 'python3'),
	owner_user_id TEXT NOT NULL DEFAULT '',
	created_by_agent_id TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	deleted_at DATETIME,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE SET NULL,
	FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
);`

const createTrafficTransformRevisionsTable = `
CREATE TABLE IF NOT EXISTS traffic_transform_revisions (
	id TEXT PRIMARY KEY,
	transform_id TEXT NOT NULL,
	protocol_version TEXT NOT NULL CHECK (protocol_version = 'traffic-transform/v1'),
	language TEXT NOT NULL CHECK (language = 'python3'),
	entrypoint TEXT NOT NULL CHECK (entrypoint = 'transform.py'),
	sdk_version TEXT NOT NULL CHECK (sdk_version = '1'),
	source TEXT NOT NULL,
	source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
	hooks_json TEXT NOT NULL CHECK (json_valid(hooks_json)),
	requirements_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(requirements_json)),
	validation_status TEXT NOT NULL DEFAULT 'pending' CHECK (validation_status IN ('pending', 'passed', 'failed')),
	validation_report_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(validation_report_json)),
	created_by_agent_id TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL,
	FOREIGN KEY (transform_id) REFERENCES traffic_transforms(id) ON DELETE CASCADE,
	UNIQUE (transform_id, source_sha256)
);`

const createTrafficTransformBindingsTable = `
CREATE TABLE IF NOT EXISTS traffic_transform_bindings (
	id TEXT PRIMARY KEY,
	conversation_id TEXT NOT NULL,
	transform_id TEXT NOT NULL,
	revision_id TEXT NOT NULL,
	mode TEXT NOT NULL CHECK (mode IN ('observe', 'inline')),
	matcher_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(matcher_json)),
	config_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(config_json)),
	priority INTEGER NOT NULL DEFAULT 100 CHECK (priority >= 0 AND priority <= 10000),
	failure_policy TEXT NOT NULL CHECK (failure_policy IN ('continue', 'closed')),
	status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'disabled')),
	approved_by_user_id TEXT NOT NULL DEFAULT '',
	approved_at DATETIME,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
	FOREIGN KEY (transform_id) REFERENCES traffic_transforms(id) ON DELETE CASCADE,
	FOREIGN KEY (revision_id) REFERENCES traffic_transform_revisions(id) ON DELETE CASCADE
);`

const createTrafficTransformRunsTable = `
CREATE TABLE IF NOT EXISTS traffic_transform_runs (
	id TEXT PRIMARY KEY,
	binding_id TEXT,
	revision_id TEXT NOT NULL,
	transaction_id TEXT,
	invocation_id TEXT NOT NULL,
	kind TEXT NOT NULL CHECK (kind IN ('offline', 'online')),
	hook TEXT NOT NULL CHECK (hook IN ('decode_request', 'mutate_request', 'encode_request', 'decode_response', 'mutate_response', 'encode_response')),
	mode TEXT NOT NULL CHECK (mode IN ('observe', 'inline')),
	action TEXT NOT NULL CHECK (action IN ('pass', 'replace', 'block', 'error')),
	input_sha256 TEXT NOT NULL,
	output_sha256 TEXT NOT NULL DEFAULT '',
	duration_ms INTEGER NOT NULL DEFAULT 0 CHECK (duration_ms >= 0),
	error_code TEXT NOT NULL DEFAULT '',
	error_summary TEXT NOT NULL DEFAULT '',
	annotations_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(annotations_json)),
	runner_identity TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL,
	FOREIGN KEY (binding_id) REFERENCES traffic_transform_bindings(id) ON DELETE SET NULL,
	FOREIGN KEY (revision_id) REFERENCES traffic_transform_revisions(id) ON DELETE CASCADE,
	FOREIGN KEY (transaction_id) REFERENCES traffic_transactions(id) ON DELETE SET NULL
);`

func (db *DB) initTrafficTransformTables() error {
	for _, statement := range []string{
		createTrafficTransformsTable,
		createTrafficTransformRevisionsTable,
		createTrafficTransformBindingsTable,
		createTrafficTransformRunsTable,
		`CREATE INDEX IF NOT EXISTS idx_traffic_transforms_scope ON traffic_transforms(project_id, conversation_id, updated_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_transform_revisions_transform ON traffic_transform_revisions(transform_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_transform_bindings_active ON traffic_transform_bindings(conversation_id, status, priority, updated_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_transform_runs_transaction ON traffic_transform_runs(transaction_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_transform_runs_revision ON traffic_transform_runs(revision_id, created_at DESC)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("initialize traffic transform schema: %w", err)
		}
	}
	if err := db.addColumnIfMissing("traffic_transform_bindings", "config_json", "ALTER TABLE traffic_transform_bindings ADD COLUMN config_json TEXT NOT NULL DEFAULT '{}'"); err != nil {
		return fmt.Errorf("initialize traffic transform binding config: %w", err)
	}
	if err := db.addColumnIfMissing("traffic_transforms", "current_revision_id", "ALTER TABLE traffic_transforms ADD COLUMN current_revision_id TEXT"); err != nil {
		return fmt.Errorf("initialize traffic transform current revision: %w", err)
	}
	if err := db.addColumnIfMissing("traffic_transforms", "deleted_at", "ALTER TABLE traffic_transforms ADD COLUMN deleted_at DATETIME"); err != nil {
		return fmt.Errorf("initialize traffic transform soft deletion: %w", err)
	}
	if _, err := db.Exec(`
		UPDATE traffic_transforms
		SET current_revision_id = (
			SELECT r.id FROM traffic_transform_revisions r
			WHERE r.transform_id = traffic_transforms.id AND r.validation_status = 'passed'
			ORDER BY r.created_at DESC, r.id ASC LIMIT 1
		)
		WHERE current_revision_id IS NULL OR current_revision_id = ''
	`); err != nil {
		return fmt.Errorf("backfill traffic transform current revision: %w", err)
	}
	return nil
}

func (db *DB) CreateTrafficTransform(ctx context.Context, item *traffictransform.Transform) (*traffictransform.Transform, error) {
	if item == nil {
		return nil, errors.New("traffic transform is required")
	}
	item.Name = strings.TrimSpace(item.Name)
	item.Description = strings.TrimSpace(item.Description)
	item.ConversationID = strings.TrimSpace(item.ConversationID)
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.OwnerUserID = strings.TrimSpace(item.OwnerUserID)
	item.CreatedByAgentID = strings.TrimSpace(item.CreatedByAgentID)
	if item.Name == "" || len(item.Name) > 120 {
		return nil, errors.New("traffic transform name is required and must not exceed 120 bytes")
	}
	if len(item.Description) > 4000 {
		return nil, errors.New("traffic transform description is too large")
	}
	if item.ConversationID == "" && item.ProjectID == "" {
		return nil, errors.New("traffic transform requires a conversation or project scope")
	}
	if item.Language == "" {
		item.Language = traffictransform.LanguagePython3
	}
	if item.Language != traffictransform.LanguagePython3 {
		return nil, errors.New("traffic transform language must be python3")
	}
	if item.ID == "" {
		item.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	item.CreatedAt = now
	item.UpdatedAt = now
	_, err := db.ExecContext(ctx, `
		INSERT INTO traffic_transforms (
			id, conversation_id, project_id, current_revision_id, name, description, language,
			owner_user_id, created_by_agent_id, created_at, updated_at
		) VALUES (?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?)
	`, item.ID, item.ConversationID, item.ProjectID, item.CurrentRevisionID, item.Name, item.Description, item.Language,
		item.OwnerUserID, item.CreatedByAgentID, item.CreatedAt, item.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create traffic transform: %w", err)
	}
	copy := *item
	return &copy, nil
}

type transformScanner interface {
	Scan(...any) error
}

func scanTrafficTransform(scanner transformScanner) (*traffictransform.Transform, error) {
	var item traffictransform.Transform
	var conversationID, projectID, currentRevisionID sql.NullString
	if err := scanner.Scan(
		&item.ID, &conversationID, &projectID, &currentRevisionID, &item.Name, &item.Description,
		&item.Language, &item.OwnerUserID, &item.CreatedByAgentID, &item.CreatedAt, &item.UpdatedAt,
	); err != nil {
		return nil, err
	}
	item.ConversationID = strings.TrimSpace(conversationID.String)
	item.ProjectID = strings.TrimSpace(projectID.String)
	item.CurrentRevisionID = strings.TrimSpace(currentRevisionID.String)
	return &item, nil
}

func (db *DB) GetTrafficTransform(ctx context.Context, id string) (*traffictransform.Transform, error) {
	return scanTrafficTransform(db.QueryRowContext(ctx, `
		SELECT id, conversation_id, project_id, current_revision_id, name, description, language,
			owner_user_id, created_by_agent_id, created_at, updated_at
		FROM traffic_transforms WHERE id = ?
	`, strings.TrimSpace(id)))
}

func (db *DB) ListTrafficTransformsForConversation(ctx context.Context, conversationID string) ([]traffictransform.Transform, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return nil, errors.New("conversation id is required")
	}
	rows, err := db.QueryContext(ctx, `
		SELECT t.id, t.conversation_id, t.project_id, t.current_revision_id, t.name, t.description, t.language,
			t.owner_user_id, t.created_by_agent_id, t.created_at, t.updated_at
		FROM traffic_transforms t
		LEFT JOIN conversations c ON c.id = ?
		WHERE t.deleted_at IS NULL AND (t.conversation_id = ? OR (c.project_id IS NOT NULL AND c.project_id != '' AND t.project_id = c.project_id))
		ORDER BY t.updated_at DESC, t.id ASC
	`, conversationID, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []traffictransform.Transform
	for rows.Next() {
		item, scanErr := scanTrafficTransform(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, *item)
	}
	return result, rows.Err()
}

// ListTrafficTransforms returns recent transform metadata for management UIs.
// Callers must apply the authenticated user's project/conversation scope before
// returning these rows. Source is stored only on immutable revisions and is
// intentionally not included here.
func (db *DB) ListTrafficTransforms(ctx context.Context, limit int) ([]traffictransform.Transform, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, conversation_id, project_id, current_revision_id, name, description, language,
			owner_user_id, created_by_agent_id, created_at, updated_at
		FROM traffic_transforms
		WHERE deleted_at IS NULL
		ORDER BY updated_at DESC, id ASC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]traffictransform.Transform, 0)
	for rows.Next() {
		item, scanErr := scanTrafficTransform(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, *item)
	}
	return result, rows.Err()
}

func (db *DB) TrafficTransformBelongsToConversation(ctx context.Context, transformID, conversationID string) bool {
	var count int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM traffic_transforms t
		LEFT JOIN conversations c ON c.id = ?
		WHERE t.id = ? AND t.deleted_at IS NULL AND (t.conversation_id = ? OR (c.project_id IS NOT NULL AND c.project_id != '' AND t.project_id = c.project_id))
	`, strings.TrimSpace(conversationID), strings.TrimSpace(transformID), strings.TrimSpace(conversationID)).Scan(&count)
	return err == nil && count > 0
}

func (db *DB) CreateTrafficTransformRevision(ctx context.Context, revision *traffictransform.Revision, inventory traffictransform.RunnerInventory) (*traffictransform.Revision, traffictransform.ValidationReport, error) {
	if revision == nil {
		return nil, traffictransform.ValidationReport{}, errors.New("traffic transform revision is required")
	}
	revision.TransformID = strings.TrimSpace(revision.TransformID)
	if revision.TransformID == "" {
		return nil, traffictransform.ValidationReport{}, errors.New("traffic transform id is required")
	}
	prepared, report := traffictransform.PrepareRevision(*revision, inventory)
	if prepared.ID == "" {
		prepared.ID = uuid.NewString()
	}
	prepared.CreatedAt = time.Now().UTC()
	hooksJSON, _ := json.Marshal(prepared.Hooks)
	requirementsJSON, _ := json.Marshal(prepared.Requirements)
	reportJSON, _ := json.Marshal(report)
	_, err := db.ExecContext(ctx, `
		INSERT INTO traffic_transform_revisions (
			id, transform_id, protocol_version, language, entrypoint, sdk_version,
			source, source_sha256, hooks_json, requirements_json,
			validation_status, validation_report_json, created_by_agent_id, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, prepared.ID, prepared.TransformID, prepared.ProtocolVersion, prepared.Language, prepared.Entrypoint, prepared.SDKVersion,
		prepared.Source, prepared.SourceSHA256, string(hooksJSON), string(requirementsJSON), prepared.ValidationStatus,
		string(reportJSON), prepared.CreatedByAgentID, prepared.CreatedAt)
	if err != nil {
		return nil, report, fmt.Errorf("create traffic transform revision: %w", err)
	}
	*revision = prepared
	copy := prepared
	return &copy, report, nil
}

func scanTrafficTransformRevision(scanner transformScanner) (*traffictransform.Revision, error) {
	var item traffictransform.Revision
	var hooksJSON, requirementsJSON, reportJSON string
	if err := scanner.Scan(
		&item.ID, &item.TransformID, &item.ProtocolVersion, &item.Language, &item.Entrypoint,
		&item.SDKVersion, &item.Source, &item.SourceSHA256, &hooksJSON, &requirementsJSON,
		&item.ValidationStatus, &reportJSON, &item.CreatedByAgentID, &item.CreatedAt,
	); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(hooksJSON), &item.Hooks); err != nil {
		return nil, fmt.Errorf("decode traffic transform hooks: %w", err)
	}
	if err := json.Unmarshal([]byte(requirementsJSON), &item.Requirements); err != nil {
		return nil, fmt.Errorf("decode traffic transform requirements: %w", err)
	}
	item.ValidationReport = json.RawMessage(reportJSON)
	return &item, nil
}

func (db *DB) GetTrafficTransformRevision(ctx context.Context, id string) (*traffictransform.Revision, error) {
	return scanTrafficTransformRevision(db.QueryRowContext(ctx, `
		SELECT id, transform_id, protocol_version, language, entrypoint, sdk_version,
			source, source_sha256, hooks_json, requirements_json,
			validation_status, validation_report_json, created_by_agent_id, created_at
		FROM traffic_transform_revisions WHERE id = ?
	`, strings.TrimSpace(id)))
}

func (db *DB) ListTrafficTransformRevisions(ctx context.Context, transformID string, includeSource bool) ([]traffictransform.Revision, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, transform_id, protocol_version, language, entrypoint, sdk_version,
			source, source_sha256, hooks_json, requirements_json,
			validation_status, validation_report_json, created_by_agent_id, created_at
		FROM traffic_transform_revisions WHERE transform_id = ? ORDER BY created_at DESC, id ASC
	`, strings.TrimSpace(transformID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []traffictransform.Revision
	for rows.Next() {
		item, scanErr := scanTrafficTransformRevision(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		if !includeSource {
			item.Source = ""
		}
		result = append(result, *item)
	}
	return result, rows.Err()
}

func (db *DB) SetTrafficTransformRevisionValidation(ctx context.Context, revisionID, sourceSHA256, status string, report traffictransform.ValidationReport) error {
	if status != traffictransform.ValidationPassed && status != traffictransform.ValidationFailed {
		return errors.New("traffic transform validation status must be passed or failed")
	}
	if report.SourceSHA256 != sourceSHA256 {
		return errors.New("traffic transform validation report digest mismatch")
	}
	report.Valid = status == traffictransform.ValidationPassed
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	result, err := db.ExecContext(ctx, `
		UPDATE traffic_transform_revisions
		SET validation_status = ?, validation_report_json = ?
		WHERE id = ? AND source_sha256 = ?
	`, status, string(encoded), strings.TrimSpace(revisionID), strings.TrimSpace(sourceSHA256))
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("traffic transform revision not found or digest changed")
	}
	return nil
}

// UpdateTrafficTransformMetadata changes only the mutable display fields. The
// current immutable source revision and all bindings remain untouched.
func (db *DB) UpdateTrafficTransformMetadata(ctx context.Context, id, name, description string) (*traffictransform.Transform, error) {
	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	if name == "" || len(name) > 120 {
		return nil, errors.New("traffic transform name is required and must not exceed 120 bytes")
	}
	if len(description) > 4000 {
		return nil, errors.New("traffic transform description is too large")
	}
	result, err := db.ExecContext(ctx, `
		UPDATE traffic_transforms SET name = ?, description = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`, name, description, time.Now().UTC(), id)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, sql.ErrNoRows
	}
	return db.GetTrafficTransform(ctx, id)
}

// PromoteTrafficTransformRevision atomically makes a validated revision the
// current one and moves observe-mode bindings to it. Inline bindings are
// intentionally blocked because changing approved live-mutation code requires
// a separate approval workflow.
func (db *DB) PromoteTrafficTransformRevision(ctx context.Context, transformID, revisionID, name, description string) (*traffictransform.Transform, error) {
	transformID = strings.TrimSpace(transformID)
	revisionID = strings.TrimSpace(revisionID)
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	if name == "" || len(name) > 120 {
		return nil, errors.New("traffic transform name is required and must not exceed 120 bytes")
	}
	if len(description) > 4000 {
		return nil, errors.New("traffic transform description is too large")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var revisionTransformID, validationStatus string
	if err := tx.QueryRowContext(ctx, `SELECT transform_id, validation_status FROM traffic_transform_revisions WHERE id = ?`, revisionID).Scan(&revisionTransformID, &validationStatus); err != nil {
		return nil, err
	}
	if revisionTransformID != transformID || validationStatus != traffictransform.ValidationPassed {
		return nil, errors.New("traffic transform revision is not validated for this script")
	}
	var inlineBindings int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM traffic_transform_bindings WHERE transform_id = ? AND mode = 'inline'`, transformID).Scan(&inlineBindings); err != nil {
		return nil, err
	}
	if inlineBindings > 0 {
		return nil, errors.New("inline traffic transform bindings require a new approval before changing source")
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE traffic_transforms
		SET name = ?, description = ?, current_revision_id = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
	`, name, description, revisionID, time.Now().UTC(), transformID)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE traffic_transform_bindings SET revision_id = ?, updated_at = ?
		WHERE transform_id = ? AND mode = 'observe'
	`, revisionID, time.Now().UTC(), transformID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetTrafficTransform(ctx, transformID)
}

// DeleteTrafficTransform performs a soft deletion. Immutable revisions and
// historical runs remain available as evidence. Every binding must be removed
// first so an apparently deleted script cannot continue processing traffic.
func (db *DB) DeleteTrafficTransform(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	result, err := db.ExecContext(ctx, `
		UPDATE traffic_transforms SET deleted_at = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
			AND NOT EXISTS (SELECT 1 FROM traffic_transform_bindings b WHERE b.transform_id = traffic_transforms.id)
	`, time.Now().UTC(), time.Now().UTC(), id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 1 {
		return nil
	}
	var bindingCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM traffic_transform_bindings WHERE transform_id = ?`, id).Scan(&bindingCount); err == nil && bindingCount > 0 {
		return errors.New("remove all traffic transform scopes before deleting the script")
	}
	return sql.ErrNoRows
}

func (db *DB) CreateTrafficTransformBinding(ctx context.Context, binding *traffictransform.Binding) (*traffictransform.Binding, error) {
	if binding == nil {
		return nil, errors.New("traffic transform binding is required")
	}
	revision, err := db.GetTrafficTransformRevision(ctx, binding.RevisionID)
	if err != nil {
		return nil, err
	}
	if binding.TransformID == "" {
		binding.TransformID = revision.TransformID
	}
	if binding.Mode == traffictransform.ModeObserve && binding.FailurePolicy == "" {
		binding.FailurePolicy = traffictransform.FailurePolicyContinue
	}
	if binding.Mode == traffictransform.ModeInline && binding.FailurePolicy == "" {
		binding.FailurePolicy = traffictransform.FailurePolicyClosed
	}
	binding.Matcher = binding.Matcher.Normalize()
	if err := traffictransform.ValidateBindingDraft(*binding, *revision); err != nil {
		return nil, err
	}
	if !db.TrafficTransformBelongsToConversation(ctx, binding.TransformID, binding.ConversationID) {
		return nil, errors.New("traffic transform is outside the conversation scope")
	}
	if binding.ID == "" {
		binding.ID = uuid.NewString()
	}
	binding.Status = traffictransform.BindingDraft
	binding.ApprovedByUserID = ""
	binding.ApprovedAt = nil
	now := time.Now().UTC()
	binding.CreatedAt = now
	binding.UpdatedAt = now
	matcherJSON, _ := json.Marshal(binding.Matcher)
	configJSON, _ := json.Marshal(binding.Config)
	_, err = db.ExecContext(ctx, `
		INSERT INTO traffic_transform_bindings (
			id, conversation_id, transform_id, revision_id, mode, matcher_json, config_json,
			priority, failure_policy, status, approved_by_user_id, approved_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', NULL, ?, ?)
	`, binding.ID, binding.ConversationID, binding.TransformID, binding.RevisionID, binding.Mode, string(matcherJSON), string(configJSON),
		binding.Priority, binding.FailurePolicy, binding.Status, binding.CreatedAt, binding.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create traffic transform binding: %w", err)
	}
	copy := *binding
	return &copy, nil
}

func scanTrafficTransformBinding(scanner transformScanner) (*traffictransform.Binding, error) {
	var item traffictransform.Binding
	var matcherJSON, configJSON string
	var approvedAt sql.NullTime
	if err := scanner.Scan(
		&item.ID, &item.ConversationID, &item.TransformID, &item.RevisionID, &item.Mode,
		&matcherJSON, &configJSON, &item.Priority, &item.FailurePolicy, &item.Status,
		&item.ApprovedByUserID, &approvedAt, &item.CreatedAt, &item.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(matcherJSON), &item.Matcher); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(configJSON), &item.Config); err != nil {
		return nil, err
	}
	if approvedAt.Valid {
		approved := approvedAt.Time
		item.ApprovedAt = &approved
	}
	return &item, nil
}

func (db *DB) GetTrafficTransformBinding(ctx context.Context, id string) (*traffictransform.Binding, error) {
	return scanTrafficTransformBinding(db.QueryRowContext(ctx, `
		SELECT id, conversation_id, transform_id, revision_id, mode, matcher_json,
			config_json, priority, failure_policy, status, approved_by_user_id, approved_at, created_at, updated_at
		FROM traffic_transform_bindings WHERE id = ?
	`, strings.TrimSpace(id)))
}

// UpdateTrafficTransformBindingScope replaces only the matcher and priority.
// Binding config is intentionally left untouched because it can contain
// session-scoped codec material that must never round-trip through the UI.
func (db *DB) UpdateTrafficTransformBindingScope(ctx context.Context, id string, matcher traffictransform.Matcher, priority int) (*traffictransform.Binding, error) {
	binding, err := db.GetTrafficTransformBinding(ctx, id)
	if err != nil {
		return nil, err
	}
	revision, err := db.GetTrafficTransformRevision(ctx, binding.RevisionID)
	if err != nil {
		return nil, err
	}
	binding.Matcher = matcher.Normalize()
	binding.Priority = priority
	if binding.Status == traffictransform.BindingActive {
		err = traffictransform.ValidateBinding(*binding, *revision)
	} else {
		err = traffictransform.ValidateBindingDraft(*binding, *revision)
	}
	if err != nil {
		return nil, err
	}
	matcherJSON, err := json.Marshal(binding.Matcher)
	if err != nil {
		return nil, err
	}
	result, err := db.ExecContext(ctx, `
		UPDATE traffic_transform_bindings
		SET matcher_json = ?, priority = ?, updated_at = ?
		WHERE id = ?
	`, string(matcherJSON), binding.Priority, time.Now().UTC(), binding.ID)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, errors.New("traffic transform binding is unavailable")
	}
	return db.GetTrafficTransformBinding(ctx, binding.ID)
}

func (db *DB) ActivateTrafficTransformBinding(ctx context.Context, id, approvingUserID string) (*traffictransform.Binding, error) {
	binding, err := db.GetTrafficTransformBinding(ctx, id)
	if err != nil {
		return nil, err
	}
	revision, err := db.GetTrafficTransformRevision(ctx, binding.RevisionID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if binding.Mode == traffictransform.ModeInline {
		binding.ApprovedByUserID = strings.TrimSpace(approvingUserID)
		binding.ApprovedAt = &now
	}
	if err := traffictransform.ValidateBinding(*binding, *revision); err != nil {
		return nil, err
	}
	result, err := db.ExecContext(ctx, `
		UPDATE traffic_transform_bindings
		SET status = 'active', approved_by_user_id = ?, approved_at = ?, updated_at = ?
		WHERE id = ? AND status IN ('draft', 'disabled')
	`, binding.ApprovedByUserID, binding.ApprovedAt, now, binding.ID)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, errors.New("traffic transform binding is already active or unavailable")
	}
	return db.GetTrafficTransformBinding(ctx, binding.ID)
}

func (db *DB) DisableTrafficTransformBinding(ctx context.Context, id string) (*traffictransform.Binding, error) {
	result, err := db.ExecContext(ctx, `UPDATE traffic_transform_bindings SET status = 'disabled', updated_at = ? WHERE id = ? AND status != 'disabled'`, time.Now().UTC(), strings.TrimSpace(id))
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, errors.New("traffic transform binding is already disabled or unavailable")
	}
	return db.GetTrafficTransformBinding(ctx, id)
}

// DeleteTrafficTransformBinding removes only a disabled use-case binding.
// Historical runs keep their revision and transaction evidence because their
// optional binding foreign key is configured with ON DELETE SET NULL.
func (db *DB) DeleteTrafficTransformBinding(ctx context.Context, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM traffic_transform_bindings WHERE id = ? AND status = 'disabled'`, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("traffic transform binding must be disabled before deletion")
	}
	return nil
}

func (db *DB) ListActiveTrafficTransformBindings(ctx context.Context, conversationID string) ([]traffictransform.Binding, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, conversation_id, transform_id, revision_id, mode, matcher_json,
			config_json, priority, failure_policy, status, approved_by_user_id, approved_at, created_at, updated_at
		FROM traffic_transform_bindings
		WHERE conversation_id = ? AND status = 'active'
		ORDER BY priority ASC, created_at ASC, id ASC
	`, strings.TrimSpace(conversationID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []traffictransform.Binding
	for rows.Next() {
		item, scanErr := scanTrafficTransformBinding(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, *item)
	}
	return result, rows.Err()
}

// ListTrafficTransformBindings returns recent binding metadata for the
// transform dashboard. Config is loaded for internal callers, but handlers must
// not expose it because it can contain per-session codec material.
func (db *DB) ListTrafficTransformBindings(ctx context.Context, limit int) ([]traffictransform.Binding, error) {
	if limit <= 0 || limit > 2000 {
		limit = 1000
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, conversation_id, transform_id, revision_id, mode, matcher_json,
			config_json, priority, failure_policy, status, approved_by_user_id, approved_at, created_at, updated_at
		FROM traffic_transform_bindings
		ORDER BY updated_at DESC, id ASC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]traffictransform.Binding, 0)
	for rows.Next() {
		item, scanErr := scanTrafficTransformBinding(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, *item)
	}
	return result, rows.Err()
}

// TrafficTransformRunSummary is the safe management projection for Runner
// history. It intentionally excludes source, message bodies, hashes and
// binding config while retaining the transform identity after soft deletion.
type TrafficTransformRunSummary struct {
	ID               string                `json:"id"`
	BindingID        string                `json:"bindingId,omitempty"`
	RevisionID       string                `json:"revisionId"`
	TransformID      string                `json:"transformId"`
	TransformName    string                `json:"transformName"`
	TransformDeleted bool                  `json:"transformDeleted"`
	ConversationID   string                `json:"conversationId,omitempty"`
	ProjectID        string                `json:"projectId,omitempty"`
	TransactionID    string                `json:"transactionId,omitempty"`
	Kind             string                `json:"kind"`
	Hook             traffictransform.Hook `json:"hook"`
	Mode             string                `json:"mode"`
	Action           string                `json:"action"`
	DurationMS       int64                 `json:"durationMs"`
	ErrorCode        string                `json:"errorCode,omitempty"`
	ErrorSummary     string                `json:"errorSummary,omitempty"`
	RunnerIdentity   string                `json:"runnerIdentity,omitempty"`
	CreatedAt        time.Time             `json:"createdAt"`
}

func (db *DB) ListTrafficTransformRunSummaries(ctx context.Context, limit int) ([]TrafficTransformRunSummary, error) {
	if limit <= 0 || limit > 2000 {
		limit = 1000
	}
	rows, err := db.QueryContext(ctx, `
		SELECT run.id, run.binding_id, run.revision_id, revision.transform_id,
			transform.name, CASE WHEN transform.deleted_at IS NULL THEN 0 ELSE 1 END,
			transform.conversation_id, transform.project_id, run.transaction_id,
			run.kind, run.hook, run.mode, run.action, run.duration_ms,
			run.error_code, run.error_summary, run.runner_identity, run.created_at
		FROM traffic_transform_runs run
		JOIN traffic_transform_revisions revision ON revision.id = run.revision_id
		JOIN traffic_transforms transform ON transform.id = revision.transform_id
		ORDER BY run.created_at DESC, run.id ASC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]TrafficTransformRunSummary, 0)
	for rows.Next() {
		var item TrafficTransformRunSummary
		var bindingID, conversationID, projectID, transactionID sql.NullString
		var deleted int
		if err := rows.Scan(
			&item.ID, &bindingID, &item.RevisionID, &item.TransformID,
			&item.TransformName, &deleted, &conversationID, &projectID, &transactionID,
			&item.Kind, &item.Hook, &item.Mode, &item.Action, &item.DurationMS,
			&item.ErrorCode, &item.ErrorSummary, &item.RunnerIdentity, &item.CreatedAt,
		); err != nil {
			return nil, err
		}
		item.BindingID = strings.TrimSpace(bindingID.String)
		item.ConversationID = strings.TrimSpace(conversationID.String)
		item.ProjectID = strings.TrimSpace(projectID.String)
		item.TransactionID = strings.TrimSpace(transactionID.String)
		item.TransformDeleted = deleted != 0
		result = append(result, item)
	}
	return result, rows.Err()
}

func (db *DB) CreateTrafficTransformRun(ctx context.Context, run *traffictransform.Run) (*traffictransform.Run, error) {
	if run == nil {
		return nil, errors.New("traffic transform run is required")
	}
	if run.ID == "" {
		run.ID = uuid.NewString()
	}
	if run.CreatedAt.IsZero() {
		run.CreatedAt = time.Now().UTC()
	}
	annotationsJSON, err := json.Marshal(run.Annotations)
	if err != nil {
		return nil, err
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO traffic_transform_runs (
			id, binding_id, revision_id, transaction_id, invocation_id, kind, hook, mode,
			action, input_sha256, output_sha256, duration_ms, error_code, error_summary,
			annotations_json, runner_identity, created_at
		) VALUES (?, NULLIF(?, ''), ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, run.ID, run.BindingID, run.RevisionID, run.TransactionID, run.InvocationID, run.Kind, run.Hook, run.Mode,
		run.Action, run.InputSHA256, run.OutputSHA256, run.DurationMS, run.ErrorCode, run.ErrorSummary,
		string(annotationsJSON), run.RunnerIdentity, run.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create traffic transform run: %w", err)
	}
	copy := *run
	return &copy, nil
}
