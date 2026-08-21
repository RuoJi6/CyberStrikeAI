package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/boundary"
	"github.com/google/uuid"
)

const createBoundaryPoliciesTable = `
CREATE TABLE IF NOT EXISTS boundary_policies (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	owner_user_id TEXT,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);`

const createBoundaryPolicyRulesTable = `
CREATE TABLE IF NOT EXISTS boundary_policy_rules (
	id TEXT PRIMARY KEY,
	policy_id TEXT NOT NULL,
	effect TEXT NOT NULL CHECK (effect IN ('allow-visit', 'allow-attack', 'blocked', 'auth-only')),
	host TEXT NOT NULL DEFAULT '',
	schemes_json TEXT NOT NULL DEFAULT '[]',
	ports_json TEXT NOT NULL DEFAULT '[]',
	path_prefixes_json TEXT NOT NULL DEFAULT '[]',
	methods_json TEXT NOT NULL DEFAULT '[]',
	auth_profile_id TEXT,
	rate_limit_json TEXT NOT NULL DEFAULT '{"requestsPerSecond":0,"burst":0}',
	expires_at DATETIME,
	position INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	FOREIGN KEY (policy_id) REFERENCES boundary_policies(id) ON DELETE CASCADE,
	FOREIGN KEY (auth_profile_id) REFERENCES egress_auth_profiles(id) ON DELETE RESTRICT,
	CHECK (
		(effect = 'auth-only' AND auth_profile_id IS NOT NULL AND length(trim(auth_profile_id)) > 0)
		OR (effect <> 'auth-only' AND auth_profile_id IS NULL)
	)
);`

const createConversationBoundaryPolicySelectionsTable = `
CREATE TABLE IF NOT EXISTS conversation_boundary_policy_selections (
	conversation_id TEXT PRIMARY KEY,
	policy_id TEXT NOT NULL,
	selected_at DATETIME NOT NULL,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
	FOREIGN KEY (policy_id) REFERENCES boundary_policies(id) ON DELETE RESTRICT
);`

const createBoundaryPolicySnapshotsTable = `
CREATE TABLE IF NOT EXISTS boundary_policy_snapshots (
	id TEXT PRIMARY KEY,
	source_policy_id TEXT NOT NULL DEFAULT '',
	canonical_json TEXT NOT NULL,
	sha256 TEXT NOT NULL CHECK (
		length(sha256) = 71
		AND substr(sha256, 1, 7) = 'sha256:'
		AND substr(sha256, 8) = lower(substr(sha256, 8))
		AND substr(sha256, 8) NOT GLOB '*[^0-9a-f]*'
	),
	created_at DATETIME NOT NULL,
	CHECK (json_valid(canonical_json)),
	CHECK (canonical_json = json(canonical_json))
);`

const createConversationBoundaryBindingsTable = `
CREATE TABLE IF NOT EXISTS conversation_boundary_bindings (
	conversation_id TEXT PRIMARY KEY,
	snapshot_id TEXT NOT NULL UNIQUE,
	bound_at DATETIME NOT NULL,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
	FOREIGN KEY (snapshot_id) REFERENCES boundary_policy_snapshots(id) ON DELETE RESTRICT
);`

const createConversationBoundaryActivationsTable = `
CREATE TABLE IF NOT EXISTS conversation_boundary_activations (
	id TEXT PRIMARY KEY,
	conversation_id TEXT NOT NULL,
	snapshot_id TEXT NOT NULL,
	runtime_generation INTEGER NOT NULL CHECK (runtime_generation >= 1),
	activated_at DATETIME NOT NULL,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
	FOREIGN KEY (snapshot_id) REFERENCES boundary_policy_snapshots(id) ON DELETE RESTRICT,
	UNIQUE (conversation_id, runtime_generation)
);`

const createConversationBoundaryRebuildsTable = `
CREATE TABLE IF NOT EXISTS conversation_boundary_rebuilds (
	conversation_id TEXT PRIMARY KEY,
	previous_snapshot_id TEXT NOT NULL,
	pending_snapshot_id TEXT NOT NULL UNIQUE,
	expected_runtime_generation INTEGER NOT NULL CHECK (expected_runtime_generation >= 2),
	interrupted INTEGER NOT NULL DEFAULT 0 CHECK (interrupted IN (0, 1)),
	requested_at DATETIME NOT NULL,
	FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
	FOREIGN KEY (previous_snapshot_id) REFERENCES boundary_policy_snapshots(id) ON DELETE RESTRICT,
	FOREIGN KEY (pending_snapshot_id) REFERENCES boundary_policy_snapshots(id) ON DELETE RESTRICT
);`

type BoundaryPolicy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	OwnerUserID string    `json:"owner_user_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type BoundaryRateLimit struct {
	RequestsPerSecond float64 `json:"requestsPerSecond"`
	Burst             int     `json:"burst"`
}

type BoundaryPolicyRule struct {
	ID            string            `json:"id"`
	PolicyID      string            `json:"policy_id"`
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
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

func (db *DB) initBoundaryPolicyTables() error {
	if _, err := db.Exec(createBoundaryPoliciesTable); err != nil {
		return err
	}
	if _, err := db.Exec(createBoundaryPolicyRulesTable); err != nil {
		return err
	}
	if _, err := db.Exec(createConversationBoundaryPolicySelectionsTable); err != nil {
		return err
	}
	if _, err := db.Exec(createBoundaryPolicySnapshotsTable); err != nil {
		return err
	}
	if _, err := db.Exec(createConversationBoundaryBindingsTable); err != nil {
		return err
	}
	if _, err := db.Exec(createConversationBoundaryActivationsTable); err != nil {
		return err
	}
	if _, err := db.Exec(createConversationBoundaryRebuildsTable); err != nil {
		return err
	}
	if _, err := db.Exec(`
		INSERT OR IGNORE INTO conversation_boundary_activations (
			id, conversation_id, snapshot_id, runtime_generation, activated_at
		)
		SELECT b.snapshot_id, b.conversation_id, b.snapshot_id,
			CASE WHEN COALESCE(r.runtime_generation, 0) > 0 THEN r.runtime_generation ELSE 1 END,
			b.bound_at
		FROM conversation_boundary_bindings b
		LEFT JOIN conversation_container_runtimes r ON r.conversation_id = b.conversation_id
	`); err != nil {
		return err
	}
	for _, statement := range []string{
		`CREATE TRIGGER IF NOT EXISTS boundary_policy_rules_auth_profile_insert
		 BEFORE INSERT ON boundary_policy_rules
		 WHEN NEW.auth_profile_id IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM egress_auth_profiles WHERE id = NEW.auth_profile_id)
		 BEGIN SELECT RAISE(ABORT, 'boundary auth profile does not exist'); END`,
		`CREATE TRIGGER IF NOT EXISTS boundary_policy_rules_auth_profile_update
		 BEFORE UPDATE OF auth_profile_id ON boundary_policy_rules
		 WHEN NEW.auth_profile_id IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM egress_auth_profiles WHERE id = NEW.auth_profile_id)
		 BEGIN SELECT RAISE(ABORT, 'boundary auth profile does not exist'); END`,
		`CREATE TRIGGER IF NOT EXISTS egress_auth_profiles_restrict_delete
		 BEFORE DELETE ON egress_auth_profiles
		 WHEN EXISTS (SELECT 1 FROM boundary_policy_rules WHERE auth_profile_id = OLD.id)
		 BEGIN SELECT RAISE(ABORT, 'egress auth profile is referenced by a boundary rule'); END`,
		`CREATE TRIGGER IF NOT EXISTS boundary_policy_snapshots_no_update
		 BEFORE UPDATE ON boundary_policy_snapshots
		 BEGIN SELECT RAISE(ABORT, 'boundary policy snapshots are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS boundary_policy_snapshots_no_delete
		 BEFORE DELETE ON boundary_policy_snapshots
		 BEGIN SELECT RAISE(ABORT, 'boundary policy snapshots are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS conversation_boundary_bindings_no_update
		 BEFORE UPDATE ON conversation_boundary_bindings
		 BEGIN SELECT RAISE(ABORT, 'conversation boundary bindings are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS conversation_boundary_bindings_no_live_delete
		 BEFORE DELETE ON conversation_boundary_bindings
		 WHEN EXISTS (SELECT 1 FROM conversations WHERE id = OLD.conversation_id)
		 BEGIN SELECT RAISE(ABORT, 'live conversation boundary bindings are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS conversation_boundary_activations_no_update
		 BEFORE UPDATE ON conversation_boundary_activations
		 BEGIN SELECT RAISE(ABORT, 'conversation boundary activations are immutable'); END`,
		`CREATE TRIGGER IF NOT EXISTS conversation_boundary_activations_no_live_delete
		 BEFORE DELETE ON conversation_boundary_activations
		 WHEN EXISTS (SELECT 1 FROM conversations WHERE id = OLD.conversation_id)
		 BEGIN SELECT RAISE(ABORT, 'live conversation boundary activations are immutable'); END`,
	} {
		if _, err := db.Exec(statement); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_boundary_policies_owner ON boundary_policies(owner_user_id, updated_at)`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_boundary_policy_rules_policy ON boundary_policy_rules(policy_id, position, created_at)`); err != nil {
		return err
	}
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_conversation_boundary_activations_current ON conversation_boundary_activations(conversation_id, runtime_generation DESC)`)
	return err
}

func (db *DB) CreateBoundaryPolicy(ctx context.Context, policy BoundaryPolicy) (BoundaryPolicy, error) {
	policy.ID = strings.TrimSpace(policy.ID)
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	policy.Name = strings.TrimSpace(policy.Name)
	if policy.Name == "" {
		return BoundaryPolicy{}, fmt.Errorf("boundary policy name is required")
	}
	policy.OwnerUserID = strings.TrimSpace(policy.OwnerUserID)
	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	} else {
		policy.CreatedAt = policy.CreatedAt.UTC()
	}
	policy.UpdatedAt = now

	var owner interface{}
	if policy.OwnerUserID != "" {
		owner = policy.OwnerUserID
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO boundary_policies (id, name, description, owner_user_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, policy.ID, policy.Name, policy.Description, owner, formatSQLiteUTC(policy.CreatedAt), formatSQLiteUTC(policy.UpdatedAt))
	if err != nil {
		return BoundaryPolicy{}, fmt.Errorf("create boundary policy: %w", err)
	}
	return policy, nil
}

// GetBoundaryPolicy returns one editable boundary policy draft. Callers must
// enforce the authenticated resource scope before exposing the record.
func (db *DB) GetBoundaryPolicy(ctx context.Context, policyID string) (BoundaryPolicy, error) {
	var policy BoundaryPolicy
	var owner sql.NullString
	var createdAt, updatedAt string
	err := db.QueryRowContext(ctx, `
		SELECT id, name, description, owner_user_id, created_at, updated_at
		FROM boundary_policies
		WHERE id = ?
	`, strings.TrimSpace(policyID)).Scan(
		&policy.ID, &policy.Name, &policy.Description, &owner, &createdAt, &updatedAt,
	)
	if err != nil {
		return BoundaryPolicy{}, err
	}
	policy.OwnerUserID = strings.TrimSpace(owner.String)
	policy.CreatedAt = parseDBTime(createdAt)
	policy.UpdatedAt = parseDBTime(updatedAt)
	return policy, nil
}

func (db *DB) CreateBoundaryPolicyRule(ctx context.Context, rule BoundaryPolicyRule) (BoundaryPolicyRule, error) {
	rule.PolicyID = strings.TrimSpace(rule.PolicyID)
	if rule.PolicyID == "" {
		return BoundaryPolicyRule{}, fmt.Errorf("boundary policy id is required")
	}
	effect, err := boundary.ParseEffect(string(rule.Effect))
	if err != nil {
		return BoundaryPolicyRule{}, err
	}
	rule.Effect = effect
	if err := validateBoundaryRuleAuthMarker(&rule); err != nil {
		return BoundaryPolicyRule{}, err
	}
	if rule.AuthProfileID != nil {
		if _, err := db.GetEgressAuthProfile(ctx, *rule.AuthProfileID); err != nil {
			if errors.Is(err, ErrEgressAuthProfileNotFound) {
				return BoundaryPolicyRule{}, fmt.Errorf("auth-only boundary rule references an unknown auth profile")
			}
			return BoundaryPolicyRule{}, fmt.Errorf("load auth profile for boundary rule: %w", err)
		}
	}
	normalizedTarget, err := boundary.NormalizeRuleTarget(boundary.RuleTarget{
		Host:         rule.Host,
		Schemes:      rule.Schemes,
		Ports:        rule.Ports,
		PathPrefixes: rule.PathPrefixes,
		Methods:      rule.Methods,
	})
	if err != nil {
		return BoundaryPolicyRule{}, err
	}
	rule.Host = normalizedTarget.Host
	rule.Schemes = normalizedTarget.Schemes
	rule.Ports = normalizedTarget.Ports
	rule.PathPrefixes = normalizedTarget.PathPrefixes
	rule.Methods = normalizedTarget.Methods
	if strings.Contains(rule.Host, "/") && rule.Effect != boundary.EffectBlocked {
		return BoundaryPolicyRule{}, fmt.Errorf("only blocked boundary rules may use IP prefixes")
	}
	if rule.ID = strings.TrimSpace(rule.ID); rule.ID == "" {
		rule.ID = uuid.New().String()
	}

	schemes, err := marshalBoundaryList(rule.Schemes)
	if err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("encode boundary schemes: %w", err)
	}
	ports, err := marshalBoundaryList(rule.Ports)
	if err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("encode boundary ports: %w", err)
	}
	paths, err := marshalBoundaryList(rule.PathPrefixes)
	if err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("encode boundary path prefixes: %w", err)
	}
	methods, err := marshalBoundaryList(rule.Methods)
	if err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("encode boundary methods: %w", err)
	}
	rateLimit, err := json.Marshal(rule.RateLimit)
	if err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("encode boundary rate limit: %w", err)
	}

	now := time.Now().UTC()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	} else {
		rule.CreatedAt = rule.CreatedAt.UTC()
	}
	rule.UpdatedAt = now
	var authProfile interface{}
	if rule.AuthProfileID != nil {
		authProfile = *rule.AuthProfileID
	}
	var expiresAt interface{}
	if rule.ExpiresAt != nil {
		value := rule.ExpiresAt.UTC()
		rule.ExpiresAt = &value
		expiresAt = formatSQLiteUTC(value)
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO boundary_policy_rules (
			id, policy_id, effect, host, schemes_json, ports_json, path_prefixes_json,
			methods_json, auth_profile_id, rate_limit_json, expires_at, position, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, rule.ID, rule.PolicyID, rule.Effect, rule.Host, schemes, ports, paths, methods,
		authProfile, string(rateLimit), expiresAt, rule.Position, formatSQLiteUTC(rule.CreatedAt), formatSQLiteUTC(rule.UpdatedAt))
	if err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("create boundary policy rule: %w", err)
	}
	return rule, nil
}

func validateBoundaryRuleAuthMarker(rule *BoundaryPolicyRule) error {
	if rule.AuthProfileID != nil {
		value := strings.TrimSpace(*rule.AuthProfileID)
		if value == "" {
			rule.AuthProfileID = nil
		} else {
			rule.AuthProfileID = &value
		}
	}
	if rule.Effect.RequiresAuthProfile() {
		if rule.AuthProfileID == nil {
			return fmt.Errorf("auth-only boundary rule requires an auth profile")
		}
		return nil
	}
	if rule.AuthProfileID != nil {
		return fmt.Errorf("boundary auth profile requires auth-only effect")
	}
	return nil
}

func marshalBoundaryList[T any](values []T) (string, error) {
	if values == nil {
		values = []T{}
	}
	encoded, err := json.Marshal(values)
	return string(encoded), err
}

func (db *DB) ListBoundaryPolicyRules(ctx context.Context, policyID string) ([]BoundaryPolicyRule, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, policy_id, effect, host, schemes_json, ports_json, path_prefixes_json,
			methods_json, auth_profile_id, rate_limit_json, expires_at, position, created_at, updated_at
		FROM boundary_policy_rules
		WHERE policy_id = ?
		ORDER BY position, created_at, id
	`, strings.TrimSpace(policyID))
	if err != nil {
		return nil, fmt.Errorf("list boundary policy rules: %w", err)
	}
	defer rows.Close()

	rules := make([]BoundaryPolicyRule, 0)
	for rows.Next() {
		rule, err := scanBoundaryPolicyRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list boundary policy rules: %w", err)
	}
	return rules, nil
}

type boundaryPolicyRuleScanner interface {
	Scan(dest ...interface{}) error
}

func scanBoundaryPolicyRule(scanner boundaryPolicyRuleScanner) (BoundaryPolicyRule, error) {
	var rule BoundaryPolicyRule
	var effect, schemes, ports, paths, methods, rateLimit, createdAt, updatedAt string
	var authProfile, expiresAt sql.NullString
	if err := scanner.Scan(
		&rule.ID, &rule.PolicyID, &effect, &rule.Host, &schemes, &ports, &paths,
		&methods, &authProfile, &rateLimit, &expiresAt, &rule.Position, &createdAt, &updatedAt,
	); err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("scan boundary policy rule: %w", err)
	}
	parsedEffect, err := boundary.ParseEffect(effect)
	if err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("scan boundary policy rule: %w", err)
	}
	rule.Effect = parsedEffect
	if err := json.Unmarshal([]byte(schemes), &rule.Schemes); err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("decode boundary schemes: %w", err)
	}
	if err := json.Unmarshal([]byte(ports), &rule.Ports); err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("decode boundary ports: %w", err)
	}
	if err := json.Unmarshal([]byte(paths), &rule.PathPrefixes); err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("decode boundary path prefixes: %w", err)
	}
	if err := json.Unmarshal([]byte(methods), &rule.Methods); err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("decode boundary methods: %w", err)
	}
	if err := json.Unmarshal([]byte(rateLimit), &rule.RateLimit); err != nil {
		return BoundaryPolicyRule{}, fmt.Errorf("decode boundary rate limit: %w", err)
	}
	if authProfile.Valid {
		rule.AuthProfileID = &authProfile.String
	}
	if expiresAt.Valid {
		value := parseDBTime(expiresAt.String)
		rule.ExpiresAt = &value
	}
	rule.CreatedAt = parseDBTime(createdAt)
	rule.UpdatedAt = parseDBTime(updatedAt)
	return rule, nil
}
