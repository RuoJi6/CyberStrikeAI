package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"time"

	"cyberstrike-ai/internal/boundary"
	"github.com/google/uuid"
)

const (
	boundaryPolicySnapshotSchemaVersion        = 1
	boundaryPolicyTLSSnapshotSchemaVersion     = 2
	boundaryPolicyOpenSnapshotSchemaVersion    = 3
	boundaryPolicyOpenTLSSnapshotSchemaVersion = 4
)

var (
	ErrConversationBoundarySnapshotNotFound = errors.New("conversation boundary snapshot not found")
	ErrBoundarySnapshotIntegrity            = errors.New("boundary snapshot integrity check failed")
	ErrConversationBoundaryRebuildPending   = errors.New("conversation boundary rebuild is already pending")
)

// BoundaryPolicySnapshotDocument is the canonical, immutable policy input
// consumed by later egress enforcement stages. It deliberately excludes draft
// names and timestamps so equivalent rule sets produce identical hashes.
type BoundaryPolicySnapshotDocument struct {
	SchemaVersion int                                  `json:"schemaVersion"`
	PolicyID      string                               `json:"policyId"`
	Rules         []BoundaryPolicySnapshotRule         `json:"rules"`
	TLSInspection *BoundaryPolicyTLSInspectionSnapshot `json:"tlsInspection,omitempty"`
	DefaultAction string                               `json:"defaultAction,omitempty"`
}

type BoundaryPolicyTLSInspectionSnapshot struct {
	Enabled       bool     `json:"enabled"`
	BypassDomains []string `json:"bypassDomains"`
}

type BoundaryPolicySnapshotRule struct {
	ID            string            `json:"id"`
	Effect        boundary.Effect   `json:"effect"`
	Host          string            `json:"host"`
	Schemes       []string          `json:"schemes"`
	Ports         []int             `json:"ports"`
	PathPrefixes  []string          `json:"pathPrefixes"`
	Methods       []string          `json:"methods"`
	AuthProfileID *string           `json:"authProfileId"`
	RateLimit     BoundaryRateLimit `json:"rateLimit"`
	ExpiresAt     *time.Time        `json:"expiresAt"`
	Position      int               `json:"position"`
}

type ConversationBoundarySnapshot struct {
	SnapshotID        string                         `json:"snapshotId"`
	ConversationID    string                         `json:"conversationId"`
	PolicyID          string                         `json:"policyId"`
	SHA256            string                         `json:"sha256"`
	CanonicalJSON     string                         `json:"canonicalJson"`
	Document          BoundaryPolicySnapshotDocument `json:"document"`
	RuntimeGeneration int                            `json:"runtimeGeneration"`
	CreatedAt         time.Time                      `json:"createdAt"`
	BoundAt           time.Time                      `json:"boundAt"`
}

// SelectConversationBoundaryPolicy records the editable draft selected while
// a container conversation is created. The selection is consumed atomically by
// EnsureConversationBoundarySnapshot and cannot affect the bound snapshot later.
func (db *DB) SelectConversationBoundaryPolicy(ctx context.Context, conversationID, policyID string) error {
	conversationID = strings.TrimSpace(conversationID)
	policyID = strings.TrimSpace(policyID)
	if conversationID == "" || policyID == "" {
		return fmt.Errorf("conversation id and boundary policy id are required")
	}
	var runtimeMode string
	if err := db.QueryRowContext(ctx, `SELECT runtime_mode FROM conversations WHERE id = ?`, conversationID).Scan(&runtimeMode); err != nil {
		return err
	}
	if runtimeMode != ConversationRuntimeModeContainer {
		return fmt.Errorf("boundary policy can only be selected for container conversations")
	}
	var bindingCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM conversation_boundary_bindings WHERE conversation_id = ?`, conversationID).Scan(&bindingCount); err != nil {
		return fmt.Errorf("check conversation boundary binding: %w", err)
	}
	if bindingCount != 0 {
		return fmt.Errorf("conversation boundary snapshot is already bound")
	}
	if _, err := db.GetBoundaryPolicy(ctx, policyID); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO conversation_boundary_policy_selections (conversation_id, policy_id, selected_at)
		VALUES (?, ?, ?)
	`, conversationID, policyID, formatSQLiteUTC(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("select conversation boundary policy: %w", err)
	}
	return nil
}

// EnsureConversationBoundarySnapshot binds exactly one immutable snapshot before
// container creation. The no-op conversation UPDATE obtains SQLite's writer
// lock before checking the binding, making concurrent first starts idempotent.
func (db *DB) EnsureConversationBoundarySnapshot(ctx context.Context, conversationID string) (ConversationBoundarySnapshot, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return ConversationBoundarySnapshot{}, fmt.Errorf("conversation id is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("begin boundary snapshot transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, `UPDATE conversations SET id = id WHERE id = ?`, conversationID)
	if err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("lock boundary snapshot conversation: %w", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
		if affectedErr != nil {
			return ConversationBoundarySnapshot{}, affectedErr
		}
		return ConversationBoundarySnapshot{}, sql.ErrNoRows
	}

	var runtimeMode string
	if err := tx.QueryRowContext(ctx, `SELECT runtime_mode FROM conversations WHERE id = ?`, conversationID).Scan(&runtimeMode); err != nil {
		return ConversationBoundarySnapshot{}, err
	}
	if runtimeMode != ConversationRuntimeModeContainer {
		return ConversationBoundarySnapshot{}, fmt.Errorf("boundary snapshots require a container conversation")
	}
	if existing, getErr := getConversationBoundarySnapshot(ctx, tx, conversationID); getErr == nil {
		if err := tx.Commit(); err != nil {
			return ConversationBoundarySnapshot{}, fmt.Errorf("commit existing boundary snapshot: %w", err)
		}
		return existing, nil
	} else if !errors.Is(getErr, ErrConversationBoundarySnapshotNotFound) {
		return ConversationBoundarySnapshot{}, getErr
	}

	policyID := ""
	selectionErr := tx.QueryRowContext(ctx, `
		SELECT policy_id FROM conversation_boundary_policy_selections WHERE conversation_id = ?
	`, conversationID).Scan(&policyID)
	if selectionErr != nil && !errors.Is(selectionErr, sql.ErrNoRows) {
		return ConversationBoundarySnapshot{}, fmt.Errorf("load boundary policy selection: %w", selectionErr)
	}
	document, err := boundarySnapshotDocumentFromPolicy(ctx, tx, policyID)
	if err != nil {
		return ConversationBoundarySnapshot{}, err
	}
	canonicalJSON, digest, err := canonicalBoundarySnapshot(document)
	if err != nil {
		return ConversationBoundarySnapshot{}, err
	}
	now := time.Now().UTC()
	snapshotID := uuid.New().String()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO boundary_policy_snapshots (id, source_policy_id, canonical_json, sha256, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, snapshotID, document.PolicyID, canonicalJSON, digest, formatSQLiteUTC(now)); err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("insert boundary snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO conversation_boundary_bindings (conversation_id, snapshot_id, bound_at)
		VALUES (?, ?, ?)
	`, conversationID, snapshotID, formatSQLiteUTC(now)); err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("bind conversation boundary snapshot: %w", err)
	}
	runtimeGeneration := 1
	var storedRuntimeGeneration int
	runtimeErr := tx.QueryRowContext(ctx, `
		SELECT runtime_generation FROM conversation_container_runtimes WHERE conversation_id = ?
	`, conversationID).Scan(&storedRuntimeGeneration)
	if runtimeErr != nil && !errors.Is(runtimeErr, sql.ErrNoRows) {
		return ConversationBoundarySnapshot{}, fmt.Errorf("load initial boundary runtime generation: %w", runtimeErr)
	}
	if storedRuntimeGeneration > runtimeGeneration {
		runtimeGeneration = storedRuntimeGeneration
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO conversation_boundary_activations (
			id, conversation_id, snapshot_id, runtime_generation, activated_at
		) VALUES (?, ?, ?, ?, ?)
	`, snapshotID, conversationID, snapshotID, runtimeGeneration, formatSQLiteUTC(now)); err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("activate initial conversation boundary snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM conversation_boundary_policy_selections WHERE conversation_id = ?`, conversationID); err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("consume boundary policy selection: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("commit boundary snapshot: %w", err)
	}
	return ConversationBoundarySnapshot{
		SnapshotID: snapshotID, ConversationID: conversationID, PolicyID: document.PolicyID,
		SHA256: digest, CanonicalJSON: canonicalJSON, Document: document,
		RuntimeGeneration: runtimeGeneration, CreatedAt: now, BoundAt: now,
	}, nil
}

// PrepareConversationBoundaryRebuild freezes a new immutable policy snapshot
// without making it active. The corresponding container rebuild is the only
// operation allowed to activate it.
func (db *DB) PrepareConversationBoundaryRebuild(ctx context.Context, conversationID, policyID string) (ConversationBoundarySnapshot, error) {
	conversationID = strings.TrimSpace(conversationID)
	policyID = strings.TrimSpace(policyID)
	if conversationID == "" {
		return ConversationBoundarySnapshot{}, fmt.Errorf("conversation id is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("begin boundary rebuild transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, `UPDATE conversations SET id = id WHERE id = ? AND runtime_mode = ?`, conversationID, ConversationRuntimeModeContainer)
	if err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("lock boundary rebuild conversation: %w", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil || affected != 1 {
		if affectedErr != nil {
			return ConversationBoundarySnapshot{}, affectedErr
		}
		return ConversationBoundarySnapshot{}, sql.ErrNoRows
	}
	active, err := getConversationBoundarySnapshot(ctx, tx, conversationID)
	if err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("load active boundary snapshot: %w", err)
	}
	var runtimeGeneration int
	var lifecycleOperation, lifecycleState string
	if err := tx.QueryRowContext(ctx, `
		SELECT runtime_generation, lifecycle_operation, lifecycle_state
		FROM conversation_container_runtimes WHERE conversation_id = ?
	`, conversationID).Scan(&runtimeGeneration, &lifecycleOperation, &lifecycleState); err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("load boundary rebuild runtime: %w", err)
	}
	if runtimeGeneration < 1 {
		return ConversationBoundarySnapshot{}, fmt.Errorf("container runtime generation is invalid")
	}
	if active.RuntimeGeneration != runtimeGeneration {
		return ConversationBoundarySnapshot{}, fmt.Errorf("%w: boundary snapshot/runtime generation mismatch", ErrBoundarySnapshotIntegrity)
	}
	var pendingInterrupted int
	pendingErr := tx.QueryRowContext(ctx, `
		SELECT interrupted FROM conversation_boundary_rebuilds WHERE conversation_id = ?
	`, conversationID).Scan(&pendingInterrupted)
	if pendingErr != nil && !errors.Is(pendingErr, sql.ErrNoRows) {
		return ConversationBoundarySnapshot{}, fmt.Errorf("check pending boundary rebuild: %w", pendingErr)
	}
	if pendingErr == nil {
		if pendingInterrupted == 0 || (lifecycleOperation == "rebuild" && lifecycleState == "in_progress") {
			return ConversationBoundarySnapshot{}, ErrConversationBoundaryRebuildPending
		}
		// Only startup recovery can mark a request interrupted. Replacing it
		// requires this new explicit rebuild request; execution stays failed closed
		// until the replacement succeeds.
		if _, err := tx.ExecContext(ctx, `DELETE FROM conversation_boundary_rebuilds WHERE conversation_id = ?`, conversationID); err != nil {
			return ConversationBoundarySnapshot{}, fmt.Errorf("replace interrupted boundary rebuild: %w", err)
		}
	}

	document, err := boundarySnapshotDocumentFromPolicy(ctx, tx, policyID)
	if err != nil {
		return ConversationBoundarySnapshot{}, err
	}
	canonicalJSON, digest, err := canonicalBoundarySnapshot(document)
	if err != nil {
		return ConversationBoundarySnapshot{}, err
	}
	now := time.Now().UTC()
	snapshotID := uuid.New().String()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO boundary_policy_snapshots (id, source_policy_id, canonical_json, sha256, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, snapshotID, document.PolicyID, canonicalJSON, digest, formatSQLiteUTC(now)); err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("insert pending boundary snapshot: %w", err)
	}
	expectedGeneration := runtimeGeneration + 1
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO conversation_boundary_rebuilds (
			conversation_id, previous_snapshot_id, pending_snapshot_id,
			expected_runtime_generation, requested_at
		) VALUES (?, ?, ?, ?, ?)
	`, conversationID, active.SnapshotID, snapshotID, expectedGeneration, formatSQLiteUTC(now)); err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("stage boundary rebuild: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("commit pending boundary rebuild: %w", err)
	}
	return ConversationBoundarySnapshot{
		SnapshotID: snapshotID, ConversationID: conversationID, PolicyID: document.PolicyID,
		SHA256: digest, CanonicalJSON: canonicalJSON, Document: document,
		RuntimeGeneration: expectedGeneration, CreatedAt: now,
	}, nil
}

// CancelConversationBoundaryRebuild removes only the mutable pending request;
// the immutable snapshot remains as an audit artifact and can never become
// active accidentally.
func (db *DB) CancelConversationBoundaryRebuild(ctx context.Context, conversationID, snapshotID string) error {
	result, err := db.ExecContext(ctx, `
		DELETE FROM conversation_boundary_rebuilds
		WHERE conversation_id = ? AND pending_snapshot_id = ?
	`, strings.TrimSpace(conversationID), strings.TrimSpace(snapshotID))
	if err != nil {
		return fmt.Errorf("cancel pending boundary rebuild: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 1 {
		return fmt.Errorf("cancel pending boundary rebuild affected %d rows", affected)
	}
	return nil
}

func (db *DB) HasPendingConversationBoundaryRebuild(ctx context.Context, conversationID string) (bool, error) {
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM conversation_boundary_rebuilds WHERE conversation_id = ?
	`, strings.TrimSpace(conversationID)).Scan(&count); err != nil {
		return false, fmt.Errorf("check pending boundary rebuild: %w", err)
	}
	return count != 0, nil
}

func (db *DB) MarkPendingConversationBoundaryRebuildsInterrupted(ctx context.Context) (int64, error) {
	result, err := db.ExecContext(ctx, `UPDATE conversation_boundary_rebuilds SET interrupted = 1 WHERE interrupted = 0`)
	if err != nil {
		return 0, fmt.Errorf("mark pending boundary rebuilds interrupted: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (db *DB) GetConversationBoundarySnapshot(ctx context.Context, conversationID string) (ConversationBoundarySnapshot, error) {
	return getConversationBoundarySnapshot(ctx, db, strings.TrimSpace(conversationID))
}

// GetPendingConversationBoundarySnapshot returns only the exact immutable
// snapshot staged for the caller's explicit rebuild. It cannot resolve an
// arbitrary snapshot from another conversation.
func (db *DB) GetPendingConversationBoundarySnapshot(ctx context.Context, conversationID, snapshotID string) (ConversationBoundarySnapshot, error) {
	conversationID = strings.TrimSpace(conversationID)
	snapshotID = strings.TrimSpace(snapshotID)
	if conversationID == "" || snapshotID == "" {
		return ConversationBoundarySnapshot{}, fmt.Errorf("conversation id and pending snapshot id are required")
	}
	return scanConversationBoundarySnapshot(db.QueryRowContext(ctx, `
		SELECT s.id, br.conversation_id, s.source_policy_id, s.sha256, s.canonical_json,
			s.created_at, br.requested_at, br.expected_runtime_generation
		FROM conversation_boundary_rebuilds br
		JOIN boundary_policy_snapshots s ON s.id = br.pending_snapshot_id
		WHERE br.conversation_id = ? AND br.pending_snapshot_id = ?
	`, conversationID, snapshotID))
}

// EnsureContainerRuntimeBoundarySnapshots upgrades durable runtime records from
// deployments predating boundary snapshots. It intentionally touches only
// conversations that already have a runtime record; unused container-mode
// conversations keep their editable selection until their first start.
func (db *DB) EnsureContainerRuntimeBoundarySnapshots(ctx context.Context) error {
	rows, err := db.QueryContext(ctx, `
		SELECT conversation_id FROM conversation_container_runtimes ORDER BY conversation_id
	`)
	if err != nil {
		return fmt.Errorf("list container runtimes for boundary snapshot migration: %w", err)
	}
	conversationIDs := make([]string, 0)
	for rows.Next() {
		var conversationID string
		if err := rows.Scan(&conversationID); err != nil {
			_ = rows.Close()
			return err
		}
		conversationIDs = append(conversationIDs, conversationID)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var snapshotErrors []error
	for _, conversationID := range conversationIDs {
		if _, err := db.EnsureConversationBoundarySnapshot(ctx, conversationID); err != nil {
			snapshotErrors = append(snapshotErrors, fmt.Errorf("conversation %s: %w", conversationID, err))
		}
	}
	return errors.Join(snapshotErrors...)
}

type boundarySnapshotQuerier interface {
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func getConversationBoundarySnapshot(ctx context.Context, query boundarySnapshotQuerier, conversationID string) (ConversationBoundarySnapshot, error) {
	return scanConversationBoundarySnapshot(query.QueryRowContext(ctx, `
		SELECT s.id, a.conversation_id, s.source_policy_id, s.sha256, s.canonical_json,
			s.created_at, a.activated_at, a.runtime_generation
		FROM conversation_boundary_activations a
		JOIN boundary_policy_snapshots s ON s.id = a.snapshot_id
		WHERE a.conversation_id = ?
		ORDER BY a.runtime_generation DESC
		LIMIT 1
	`, conversationID))
}

type boundarySnapshotScanner interface {
	Scan(...interface{}) error
}

func scanConversationBoundarySnapshot(scanner boundarySnapshotScanner) (ConversationBoundarySnapshot, error) {
	var snapshot ConversationBoundarySnapshot
	var createdAt, boundAt string
	err := scanner.Scan(
		&snapshot.SnapshotID, &snapshot.ConversationID, &snapshot.PolicyID, &snapshot.SHA256,
		&snapshot.CanonicalJSON, &createdAt, &boundAt, &snapshot.RuntimeGeneration,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ConversationBoundarySnapshot{}, ErrConversationBoundarySnapshotNotFound
	}
	if err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("load conversation boundary snapshot: %w", err)
	}
	document, err := validateCanonicalBoundarySnapshot(snapshot.CanonicalJSON, snapshot.SHA256)
	if err != nil {
		return ConversationBoundarySnapshot{}, err
	}
	if document.PolicyID != snapshot.PolicyID {
		return ConversationBoundarySnapshot{}, fmt.Errorf("%w: source policy id mismatch", ErrBoundarySnapshotIntegrity)
	}
	snapshot.Document = document
	snapshot.CreatedAt = parseDBTime(createdAt)
	snapshot.BoundAt = parseDBTime(boundAt)
	if snapshot.CreatedAt.IsZero() || snapshot.BoundAt.IsZero() {
		return ConversationBoundarySnapshot{}, fmt.Errorf("%w: invalid snapshot timestamp", ErrBoundarySnapshotIntegrity)
	}
	return snapshot, nil
}

func boundarySnapshotDocumentFromPolicy(ctx context.Context, tx *sql.Tx, policyID string) (BoundaryPolicySnapshotDocument, error) {
	document := BoundaryPolicySnapshotDocument{
		SchemaVersion: boundaryPolicySnapshotSchemaVersion,
		PolicyID:      strings.TrimSpace(policyID),
		Rules:         []BoundaryPolicySnapshotRule{},
	}
	if document.PolicyID == "" {
		document.SchemaVersion = boundaryPolicyOpenTLSSnapshotSchemaVersion
		document.TLSInspection = &BoundaryPolicyTLSInspectionSnapshot{Enabled: true, BypassDomains: []string{}}
		document.DefaultAction = "allow"
		return document, nil
	}
	var tlsEnabled bool
	var bypassJSON string
	if err := tx.QueryRowContext(ctx, `
		SELECT tls_inspection_enabled, tls_bypass_domains_json
		FROM boundary_policies WHERE id = ?
	`, document.PolicyID).Scan(&tlsEnabled, &bypassJSON); err != nil {
		return BoundaryPolicySnapshotDocument{}, fmt.Errorf("load selected boundary policy: %w", err)
	}
	if tlsEnabled {
		var bypassDomains []string
		if err := json.Unmarshal([]byte(bypassJSON), &bypassDomains); err != nil {
			return BoundaryPolicySnapshotDocument{}, fmt.Errorf("decode selected policy TLS bypass domains: %w", err)
		}
		normalized, err := normalizeTLSBypassDomains(bypassDomains)
		if err != nil || !reflect.DeepEqual(normalized, bypassDomains) {
			return BoundaryPolicySnapshotDocument{}, fmt.Errorf("selected policy TLS bypass domains are not canonical")
		}
		document.SchemaVersion = boundaryPolicyTLSSnapshotSchemaVersion
		document.TLSInspection = &BoundaryPolicyTLSInspectionSnapshot{Enabled: true, BypassDomains: normalized}
	}
	rules, err := listBoundaryPolicyRulesForSnapshot(ctx, tx, document.PolicyID)
	if err != nil {
		return BoundaryPolicySnapshotDocument{}, err
	}
	document.Rules = rules
	return document, nil
}

type boundarySnapshotRuleQuerier interface {
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
}

func listBoundaryPolicyRulesForSnapshot(ctx context.Context, query boundarySnapshotRuleQuerier, policyID string) ([]BoundaryPolicySnapshotRule, error) {
	rows, err := query.QueryContext(ctx, `
		SELECT id, policy_id, effect, host, schemes_json, ports_json, path_prefixes_json,
			methods_json, auth_profile_id, rate_limit_json, expires_at, position, created_at, updated_at
		FROM boundary_policy_rules
		WHERE policy_id = ?
		ORDER BY position, id
	`, policyID)
	if err != nil {
		return nil, fmt.Errorf("list snapshot boundary rules: %w", err)
	}
	defer rows.Close()
	rules := make([]BoundaryPolicySnapshotRule, 0)
	for rows.Next() {
		stored, err := scanBoundaryPolicyRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, snapshotRuleFromStored(stored))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list snapshot boundary rules: %w", err)
	}
	return rules, nil
}

func snapshotRuleFromStored(rule BoundaryPolicyRule) BoundaryPolicySnapshotRule {
	return BoundaryPolicySnapshotRule{
		ID: rule.ID, Effect: rule.Effect, Host: rule.Host,
		Schemes: nonNilSlice(rule.Schemes), Ports: nonNilSlice(rule.Ports),
		PathPrefixes: nonNilSlice(rule.PathPrefixes), Methods: nonNilSlice(rule.Methods),
		AuthProfileID: rule.AuthProfileID, RateLimit: rule.RateLimit,
		ExpiresAt: rule.ExpiresAt, Position: rule.Position,
	}
}

func nonNilSlice[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

func canonicalBoundarySnapshot(document BoundaryPolicySnapshotDocument) (string, string, error) {
	if err := validateBoundarySnapshotDocument(document); err != nil {
		return "", "", err
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", "", fmt.Errorf("marshal canonical boundary snapshot: %w", err)
	}
	digestBytes := sha256.Sum256(encoded)
	return string(encoded), "sha256:" + hex.EncodeToString(digestBytes[:]), nil
}

func validateCanonicalBoundarySnapshot(canonicalJSON, digest string) (BoundaryPolicySnapshotDocument, error) {
	decoder := json.NewDecoder(strings.NewReader(canonicalJSON))
	decoder.DisallowUnknownFields()
	var document BoundaryPolicySnapshotDocument
	if err := decoder.Decode(&document); err != nil {
		return BoundaryPolicySnapshotDocument{}, fmt.Errorf("%w: decode canonical JSON: %v", ErrBoundarySnapshotIntegrity, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return BoundaryPolicySnapshotDocument{}, fmt.Errorf("%w: %v", ErrBoundarySnapshotIntegrity, err)
	}
	encoded, recomputed, err := canonicalBoundarySnapshot(document)
	if err != nil {
		return BoundaryPolicySnapshotDocument{}, fmt.Errorf("%w: %v", ErrBoundarySnapshotIntegrity, err)
	}
	if !bytes.Equal([]byte(encoded), []byte(canonicalJSON)) {
		return BoundaryPolicySnapshotDocument{}, fmt.Errorf("%w: JSON is not canonical", ErrBoundarySnapshotIntegrity)
	}
	if recomputed != digest {
		return BoundaryPolicySnapshotDocument{}, fmt.Errorf("%w: SHA-256 mismatch", ErrBoundarySnapshotIntegrity)
	}
	return document, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateBoundarySnapshotDocument(document BoundaryPolicySnapshotDocument) error {
	if document.SchemaVersion != boundaryPolicySnapshotSchemaVersion && document.SchemaVersion != boundaryPolicyTLSSnapshotSchemaVersion && document.SchemaVersion != boundaryPolicyOpenSnapshotSchemaVersion && document.SchemaVersion != boundaryPolicyOpenTLSSnapshotSchemaVersion {
		return fmt.Errorf("unsupported boundary snapshot schema version %d", document.SchemaVersion)
	}
	if document.SchemaVersion == boundaryPolicyOpenSnapshotSchemaVersion || document.SchemaVersion == boundaryPolicyOpenTLSSnapshotSchemaVersion {
		legacyOpen := document.SchemaVersion == boundaryPolicyOpenSnapshotSchemaVersion && document.TLSInspection == nil
		inspectedOpen := document.SchemaVersion == boundaryPolicyOpenTLSSnapshotSchemaVersion && document.TLSInspection != nil
		if document.PolicyID != "" || len(document.Rules) != 0 || document.DefaultAction != "allow" || (!legacyOpen && !inspectedOpen) {
			return fmt.Errorf("no-boundary snapshot settings are inconsistent")
		}
	} else if document.DefaultAction != "" {
		return fmt.Errorf("policy boundary snapshot cannot declare a default action")
	}
	if document.TLSInspection == nil && document.SchemaVersion != boundaryPolicySnapshotSchemaVersion {
		if document.SchemaVersion != boundaryPolicyOpenSnapshotSchemaVersion {
			return fmt.Errorf("TLS boundary snapshot must include TLS inspection settings")
		}
	}
	if document.TLSInspection != nil {
		if (document.SchemaVersion != boundaryPolicyTLSSnapshotSchemaVersion && document.SchemaVersion != boundaryPolicyOpenTLSSnapshotSchemaVersion) || !document.TLSInspection.Enabled {
			return fmt.Errorf("TLS inspection snapshot settings are inconsistent")
		}
		normalized, err := normalizeTLSBypassDomains(document.TLSInspection.BypassDomains)
		if err != nil || !reflect.DeepEqual(normalized, document.TLSInspection.BypassDomains) {
			return fmt.Errorf("TLS inspection bypass domains are not canonical")
		}
	}
	if document.PolicyID != strings.TrimSpace(document.PolicyID) {
		return fmt.Errorf("boundary snapshot policy id is not canonical")
	}
	if document.Rules == nil {
		return fmt.Errorf("boundary snapshot rules must be an array")
	}
	if document.PolicyID == "" && len(document.Rules) != 0 {
		return fmt.Errorf("no-boundary snapshot must not contain rules")
	}
	compiled := make([]boundary.Rule, 0, len(document.Rules))
	for index, rule := range document.Rules {
		if index > 0 {
			previous := document.Rules[index-1]
			if previous.Position > rule.Position || (previous.Position == rule.Position && previous.ID >= rule.ID) {
				return fmt.Errorf("boundary snapshot rules are not ordered by position and id")
			}
		}
		if rule.ID == "" || rule.ID != strings.TrimSpace(rule.ID) {
			return fmt.Errorf("boundary snapshot rule id is not canonical")
		}
		target := boundary.RuleTarget{
			Host: rule.Host, Schemes: rule.Schemes, Ports: rule.Ports,
			PathPrefixes: rule.PathPrefixes, Methods: rule.Methods,
		}
		normalized, err := boundary.NormalizeRuleTarget(target)
		if err != nil || !reflect.DeepEqual(normalized, target) {
			return fmt.Errorf("boundary snapshot rule %q target is not canonical", rule.ID)
		}
		limit := boundary.RateLimit{
			RequestsPerSecond: rule.RateLimit.RequestsPerSecond,
			Burst:             rule.RateLimit.Burst, MaxConcurrent: rule.RateLimit.MaxConcurrent,
		}
		if math.IsNaN(rule.RateLimit.RequestsPerSecond) || math.IsInf(rule.RateLimit.RequestsPerSecond, 0) || boundary.ValidateRateLimit(limit) != nil {
			return fmt.Errorf("boundary snapshot rule %q rate limit is invalid", rule.ID)
		}
		authProfileID := ""
		if rule.AuthProfileID != nil {
			authProfileID = *rule.AuthProfileID
			if authProfileID == "" || authProfileID != strings.TrimSpace(authProfileID) {
				return fmt.Errorf("boundary snapshot rule %q auth profile is not canonical", rule.ID)
			}
		}
		if rule.ExpiresAt != nil {
			if rule.ExpiresAt.IsZero() || rule.ExpiresAt.Location() != time.UTC {
				return fmt.Errorf("boundary snapshot rule %q expiry is not canonical UTC", rule.ID)
			}
		}
		compiled = append(compiled, boundary.Rule{
			ID: rule.ID, Effect: rule.Effect, Target: target,
			AuthProfileID: authProfileID, RateLimit: limit, ExpiresAt: rule.ExpiresAt,
		})
	}
	if _, err := boundary.NewPolicy(compiled); err != nil {
		return fmt.Errorf("compile boundary snapshot: %w", err)
	}
	return nil
}
