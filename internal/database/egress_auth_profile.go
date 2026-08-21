package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/egress"
	"github.com/google/uuid"
)

const createEgressAuthProfilesTable = `
CREATE TABLE IF NOT EXISTS egress_auth_profiles (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	header_name TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
	credential_ciphertext TEXT NOT NULL DEFAULT '',
	credential_updated_at DATETIME,
	owner_user_id TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	CHECK (length(trim(name)) BETWEEN 1 AND 120),
	CHECK (length(trim(header_name)) BETWEEN 1 AND 128),
	CHECK (length(trim(owner_user_id)) > 0),
	CHECK (credential_ciphertext = '' OR credential_ciphertext GLOB 'v1.*.*')
);`

var (
	ErrEgressAuthProfileNotFound = errors.New("egress auth profile not found")
	ErrEgressAuthProfileInUse    = errors.New("egress auth profile is referenced by a boundary rule")
)

// EgressAuthProfile is the safe control-plane projection. The encrypted value
// is deliberately excluded from JSON and is only decrypted during gateway
// materialization.
type EgressAuthProfile struct {
	ID                    string     `json:"id"`
	Name                  string     `json:"name"`
	HeaderName            string     `json:"headerName"`
	Enabled               bool       `json:"enabled"`
	CredentialsConfigured bool       `json:"credentialsConfigured"`
	OwnerUserID           string     `json:"ownerUserId,omitempty"`
	CreatedAt             time.Time  `json:"createdAt"`
	UpdatedAt             time.Time  `json:"updatedAt"`
	CredentialUpdatedAt   *time.Time `json:"credentialUpdatedAt,omitempty"`
	CredentialCiphertext  string     `json:"-"`
}

func (db *DB) initEgressAuthProfileTables() error {
	if _, err := db.Exec(createEgressAuthProfilesTable); err != nil {
		return err
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS idx_egress_auth_profiles_owner_updated ON egress_auth_profiles(owner_user_id, updated_at DESC, id)`,
		`CREATE INDEX IF NOT EXISTS idx_egress_auth_profiles_enabled ON egress_auth_profiles(enabled, id)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

func normalizeEgressAuthProfile(profile EgressAuthProfile) (EgressAuthProfile, error) {
	if err := egress.ValidateAuthProfileID(profile.ID); err != nil {
		return EgressAuthProfile{}, err
	}
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.Name == "" || len(profile.Name) > 120 {
		return EgressAuthProfile{}, fmt.Errorf("auth profile name must be between 1 and 120 bytes")
	}
	headerName, err := egress.ValidateAuthHeaderName(profile.HeaderName)
	if err != nil {
		return EgressAuthProfile{}, err
	}
	profile.HeaderName = headerName
	profile.OwnerUserID = strings.TrimSpace(profile.OwnerUserID)
	if profile.OwnerUserID == "" {
		return EgressAuthProfile{}, fmt.Errorf("auth profile owner is required")
	}
	return profile, nil
}

func (db *DB) CreateEgressAuthProfile(ctx context.Context, profile EgressAuthProfile) (EgressAuthProfile, error) {
	profile.ID = strings.TrimSpace(profile.ID)
	if profile.ID == "" {
		profile.ID = uuid.NewString()
	}
	var err error
	profile, err = normalizeEgressAuthProfile(profile)
	if err != nil {
		return EgressAuthProfile{}, err
	}
	now := time.Now().UTC()
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = now
	} else {
		profile.CreatedAt = profile.CreatedAt.UTC()
	}
	profile.UpdatedAt = now
	profile.CredentialsConfigured = strings.TrimSpace(profile.CredentialCiphertext) != ""
	if profile.CredentialsConfigured && profile.CredentialUpdatedAt == nil {
		value := now
		profile.CredentialUpdatedAt = &value
	}
	var credentialUpdated interface{}
	if profile.CredentialUpdatedAt != nil {
		value := profile.CredentialUpdatedAt.UTC()
		profile.CredentialUpdatedAt = &value
		credentialUpdated = formatSQLiteUTC(value)
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO egress_auth_profiles (
			id, name, header_name, enabled, credential_ciphertext,
			credential_updated_at, owner_user_id, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, profile.ID, profile.Name, profile.HeaderName, boolToInt(profile.Enabled),
		profile.CredentialCiphertext, credentialUpdated, profile.OwnerUserID,
		formatSQLiteUTC(profile.CreatedAt), formatSQLiteUTC(profile.UpdatedAt))
	if err != nil {
		return EgressAuthProfile{}, fmt.Errorf("create egress auth profile: %w", err)
	}
	return profile, nil
}

func (db *DB) GetEgressAuthProfile(ctx context.Context, id string) (EgressAuthProfile, error) {
	profile, err := scanEgressAuthProfile(db.QueryRowContext(ctx, `
		SELECT id, name, header_name, enabled, credential_ciphertext,
			credential_updated_at, owner_user_id, created_at, updated_at
		FROM egress_auth_profiles WHERE id = ?
	`, strings.TrimSpace(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return EgressAuthProfile{}, ErrEgressAuthProfileNotFound
	}
	return profile, err
}

func (db *DB) ListEgressAuthProfiles(ctx context.Context, userID, scope string) ([]EgressAuthProfile, error) {
	query := `SELECT id, name, header_name, enabled, credential_ciphertext,
		credential_updated_at, owner_user_id, created_at, updated_at FROM egress_auth_profiles`
	args := make([]interface{}, 0, 2)
	if scope != RBACScopeAll {
		query += ` WHERE owner_user_id = ? OR id IN (
			SELECT resource_id FROM rbac_resource_assignments
			WHERE user_id = ? AND resource_type = 'egress_auth_profile'
		)`
		args = append(args, strings.TrimSpace(userID), strings.TrimSpace(userID))
	}
	query += ` ORDER BY updated_at DESC, id`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list egress auth profiles: %w", err)
	}
	defer rows.Close()
	profiles := make([]EgressAuthProfile, 0)
	for rows.Next() {
		profile, err := scanEgressAuthProfile(rows)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list egress auth profiles: %w", err)
	}
	return profiles, nil
}

func (db *DB) UpdateEgressAuthProfile(ctx context.Context, profile EgressAuthProfile) (EgressAuthProfile, error) {
	profile.ID = strings.TrimSpace(profile.ID)
	if profile.ID == "" {
		return EgressAuthProfile{}, fmt.Errorf("auth profile id is required")
	}
	var err error
	profile, err = normalizeEgressAuthProfile(profile)
	if err != nil {
		return EgressAuthProfile{}, err
	}
	profile.UpdatedAt = time.Now().UTC()
	var credentialUpdated interface{}
	if profile.CredentialUpdatedAt != nil {
		value := profile.CredentialUpdatedAt.UTC()
		profile.CredentialUpdatedAt = &value
		credentialUpdated = formatSQLiteUTC(value)
	}
	result, err := db.ExecContext(ctx, `
		UPDATE egress_auth_profiles SET name = ?, header_name = ?, enabled = ?,
			credential_ciphertext = ?, credential_updated_at = ?, updated_at = ? WHERE id = ?
	`, profile.Name, profile.HeaderName, boolToInt(profile.Enabled), profile.CredentialCiphertext,
		credentialUpdated, formatSQLiteUTC(profile.UpdatedAt), profile.ID)
	if err != nil {
		return EgressAuthProfile{}, fmt.Errorf("update egress auth profile: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return EgressAuthProfile{}, err
		}
		return EgressAuthProfile{}, ErrEgressAuthProfileNotFound
	}
	return db.GetEgressAuthProfile(ctx, profile.ID)
}

func (db *DB) DeleteEgressAuthProfile(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	var references int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM boundary_policy_rules WHERE auth_profile_id = ?`, id).Scan(&references); err != nil {
		return fmt.Errorf("check auth profile references: %w", err)
	}
	if references != 0 {
		return ErrEgressAuthProfileInUse
	}
	result, err := db.ExecContext(ctx, `DELETE FROM egress_auth_profiles WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete egress auth profile: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return err
		}
		return ErrEgressAuthProfileNotFound
	}
	return nil
}

type egressAuthProfileScanner interface {
	Scan(dest ...interface{}) error
}

func scanEgressAuthProfile(scanner egressAuthProfileScanner) (EgressAuthProfile, error) {
	var profile EgressAuthProfile
	var enabled int
	var credentialUpdated sql.NullString
	var createdAt, updatedAt string
	if err := scanner.Scan(&profile.ID, &profile.Name, &profile.HeaderName, &enabled,
		&profile.CredentialCiphertext, &credentialUpdated, &profile.OwnerUserID, &createdAt, &updatedAt); err != nil {
		return EgressAuthProfile{}, err
	}
	profile.Enabled = enabled != 0
	profile.CredentialsConfigured = strings.TrimSpace(profile.CredentialCiphertext) != ""
	profile.CreatedAt = parseDBTime(createdAt)
	profile.UpdatedAt = parseDBTime(updatedAt)
	if credentialUpdated.Valid {
		value := parseDBTime(credentialUpdated.String)
		profile.CredentialUpdatedAt = &value
	}
	return profile, nil
}
