package database

import (
	"context"
	"database/sql"
	"encoding/json"
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
	CHECK (
		(effect = 'auth-only' AND auth_profile_id IS NOT NULL AND length(trim(auth_profile_id)) > 0)
		OR (effect <> 'auth-only' AND auth_profile_id IS NULL)
	)
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
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_boundary_policies_owner ON boundary_policies(owner_user_id, updated_at)`); err != nil {
		return err
	}
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_boundary_policy_rules_policy ON boundary_policy_rules(policy_id, position, created_at)`)
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
