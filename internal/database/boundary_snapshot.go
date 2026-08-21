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

const boundaryPolicySnapshotSchemaVersion = 1

var (
	ErrConversationBoundarySnapshotNotFound = errors.New("conversation boundary snapshot not found")
	ErrBoundarySnapshotIntegrity            = errors.New("boundary snapshot integrity check failed")
)

// BoundaryPolicySnapshotDocument is the canonical, immutable policy input
// consumed by later egress enforcement stages. It deliberately excludes draft
// names and timestamps so equivalent rule sets produce identical hashes.
type BoundaryPolicySnapshotDocument struct {
	SchemaVersion int                          `json:"schemaVersion"`
	PolicyID      string                       `json:"policyId"`
	Rules         []BoundaryPolicySnapshotRule `json:"rules"`
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
	SnapshotID     string                         `json:"snapshotId"`
	ConversationID string                         `json:"conversationId"`
	PolicyID       string                         `json:"policyId"`
	SHA256         string                         `json:"sha256"`
	CanonicalJSON  string                         `json:"canonicalJson"`
	Document       BoundaryPolicySnapshotDocument `json:"document"`
	CreatedAt      time.Time                      `json:"createdAt"`
	BoundAt        time.Time                      `json:"boundAt"`
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
	document := BoundaryPolicySnapshotDocument{
		SchemaVersion: boundaryPolicySnapshotSchemaVersion,
		PolicyID:      strings.TrimSpace(policyID),
		Rules:         []BoundaryPolicySnapshotRule{},
	}
	if document.PolicyID != "" {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM boundary_policies WHERE id = ?`, document.PolicyID).Scan(&exists); err != nil {
			return ConversationBoundarySnapshot{}, fmt.Errorf("load selected boundary policy: %w", err)
		}
		rules, err := listBoundaryPolicyRulesForSnapshot(ctx, tx, document.PolicyID)
		if err != nil {
			return ConversationBoundarySnapshot{}, err
		}
		document.Rules = rules
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
	if _, err := tx.ExecContext(ctx, `DELETE FROM conversation_boundary_policy_selections WHERE conversation_id = ?`, conversationID); err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("consume boundary policy selection: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ConversationBoundarySnapshot{}, fmt.Errorf("commit boundary snapshot: %w", err)
	}
	return ConversationBoundarySnapshot{
		SnapshotID: snapshotID, ConversationID: conversationID, PolicyID: document.PolicyID,
		SHA256: digest, CanonicalJSON: canonicalJSON, Document: document,
		CreatedAt: now, BoundAt: now,
	}, nil
}

func (db *DB) GetConversationBoundarySnapshot(ctx context.Context, conversationID string) (ConversationBoundarySnapshot, error) {
	return getConversationBoundarySnapshot(ctx, db, strings.TrimSpace(conversationID))
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
	var snapshot ConversationBoundarySnapshot
	var createdAt, boundAt string
	err := query.QueryRowContext(ctx, `
		SELECT s.id, b.conversation_id, s.source_policy_id, s.sha256, s.canonical_json, s.created_at, b.bound_at
		FROM conversation_boundary_bindings b
		JOIN boundary_policy_snapshots s ON s.id = b.snapshot_id
		WHERE b.conversation_id = ?
	`, conversationID).Scan(
		&snapshot.SnapshotID, &snapshot.ConversationID, &snapshot.PolicyID, &snapshot.SHA256,
		&snapshot.CanonicalJSON, &createdAt, &boundAt,
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
	if document.SchemaVersion != boundaryPolicySnapshotSchemaVersion {
		return fmt.Errorf("unsupported boundary snapshot schema version %d", document.SchemaVersion)
	}
	if document.PolicyID != strings.TrimSpace(document.PolicyID) {
		return fmt.Errorf("boundary snapshot policy id is not canonical")
	}
	if document.Rules == nil {
		return fmt.Errorf("boundary snapshot rules must be an array")
	}
	if document.PolicyID == "" && len(document.Rules) != 0 {
		return fmt.Errorf("default-deny boundary snapshot must not contain rules")
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
		if math.IsNaN(rule.RateLimit.RequestsPerSecond) || math.IsInf(rule.RateLimit.RequestsPerSecond, 0) || rule.RateLimit.RequestsPerSecond < 0 || rule.RateLimit.Burst < 0 {
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
			AuthProfileID: authProfileID, ExpiresAt: rule.ExpiresAt,
		})
	}
	if _, err := boundary.NewPolicy(compiled); err != nil {
		return fmt.Errorf("compile boundary snapshot: %w", err)
	}
	return nil
}
