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

const createEgressProxiesTable = `
CREATE TABLE IF NOT EXISTS egress_proxies (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	protocol TEXT NOT NULL CHECK (protocol IN ('http', 'https', 'socks5')),
	host TEXT NOT NULL,
	port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
	enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
	credential_ciphertext TEXT NOT NULL DEFAULT '',
	credential_updated_at DATETIME,
	owner_user_id TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	CHECK (length(trim(name)) BETWEEN 1 AND 120),
	CHECK (length(trim(host)) BETWEEN 1 AND 253),
	CHECK (length(trim(owner_user_id)) > 0),
	CHECK (credential_ciphertext = '' OR credential_ciphertext GLOB 'v1.*.*')
);`

var ErrEgressProxyNotFound = errors.New("egress proxy not found")

// EgressProxy is the safe proxy resource projection. CredentialCiphertext is
// deliberately excluded from JSON and must never be copied into an API model.
type EgressProxy struct {
	ID                    string                  `json:"id"`
	Name                  string                  `json:"name"`
	Protocol              egress.UpstreamProtocol `json:"protocol"`
	Host                  string                  `json:"host"`
	Port                  int                     `json:"port"`
	Enabled               bool                    `json:"enabled"`
	CredentialsConfigured bool                    `json:"credentialsConfigured"`
	OwnerUserID           string                  `json:"ownerUserId,omitempty"`
	CreatedAt             time.Time               `json:"createdAt"`
	UpdatedAt             time.Time               `json:"updatedAt"`
	CredentialUpdatedAt   *time.Time              `json:"credentialUpdatedAt,omitempty"`
	CredentialCiphertext  string                  `json:"-"`
}

func (db *DB) initEgressProxyTables() error {
	if _, err := db.Exec(createEgressProxiesTable); err != nil {
		return err
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS idx_egress_proxies_owner_updated ON egress_proxies(owner_user_id, updated_at DESC, id)`,
		`CREATE INDEX IF NOT EXISTS idx_egress_proxies_lookup ON egress_proxies(protocol, host, port, enabled)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			return err
		}
	}
	return db.initEgressProxyGroupTables()
}

func normalizeEgressProxy(proxy EgressProxy) (EgressProxy, error) {
	name, err := egress.ValidateUpstreamName(proxy.Name)
	if err != nil {
		return EgressProxy{}, err
	}
	protocol, err := egress.ParseUpstreamProtocol(string(proxy.Protocol))
	if err != nil {
		return EgressProxy{}, err
	}
	host, err := egress.NormalizeUpstreamHost(proxy.Host)
	if err != nil {
		return EgressProxy{}, err
	}
	if err := egress.ValidateUpstreamPort(proxy.Port); err != nil {
		return EgressProxy{}, err
	}
	proxy.Name = name
	proxy.Protocol = protocol
	proxy.Host = host
	proxy.OwnerUserID = strings.TrimSpace(proxy.OwnerUserID)
	if proxy.OwnerUserID == "" {
		return EgressProxy{}, fmt.Errorf("egress proxy owner is required")
	}
	return proxy, nil
}

func (db *DB) CreateEgressProxy(ctx context.Context, proxy EgressProxy) (EgressProxy, error) {
	proxy.ID = strings.TrimSpace(proxy.ID)
	if proxy.ID == "" {
		proxy.ID = uuid.NewString()
	}
	var err error
	proxy, err = normalizeEgressProxy(proxy)
	if err != nil {
		return EgressProxy{}, err
	}
	now := time.Now().UTC()
	if proxy.CreatedAt.IsZero() {
		proxy.CreatedAt = now
	} else {
		proxy.CreatedAt = proxy.CreatedAt.UTC()
	}
	proxy.UpdatedAt = now
	proxy.CredentialsConfigured = strings.TrimSpace(proxy.CredentialCiphertext) != ""
	if proxy.CredentialsConfigured && proxy.CredentialUpdatedAt == nil {
		value := now
		proxy.CredentialUpdatedAt = &value
	}
	var credentialUpdated interface{}
	if proxy.CredentialUpdatedAt != nil {
		value := proxy.CredentialUpdatedAt.UTC()
		proxy.CredentialUpdatedAt = &value
		credentialUpdated = formatSQLiteUTC(value)
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO egress_proxies (
			id, name, protocol, host, port, enabled, credential_ciphertext,
			credential_updated_at, owner_user_id, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, proxy.ID, proxy.Name, proxy.Protocol, proxy.Host, proxy.Port, boolToInt(proxy.Enabled),
		proxy.CredentialCiphertext, credentialUpdated, proxy.OwnerUserID,
		formatSQLiteUTC(proxy.CreatedAt), formatSQLiteUTC(proxy.UpdatedAt))
	if err != nil {
		return EgressProxy{}, fmt.Errorf("create egress proxy: %w", err)
	}
	return proxy, nil
}

func (db *DB) GetEgressProxy(ctx context.Context, id string) (EgressProxy, error) {
	proxy, err := scanEgressProxy(db.QueryRowContext(ctx, `
		SELECT id, name, protocol, host, port, enabled, credential_ciphertext,
			credential_updated_at, owner_user_id, created_at, updated_at
		FROM egress_proxies WHERE id = ?
	`, strings.TrimSpace(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return EgressProxy{}, ErrEgressProxyNotFound
	}
	return proxy, err
}

func (db *DB) ListEgressProxies(ctx context.Context, userID, scope string) ([]EgressProxy, error) {
	query := `
		SELECT id, name, protocol, host, port, enabled, credential_ciphertext,
			credential_updated_at, owner_user_id, created_at, updated_at
		FROM egress_proxies`
	args := make([]interface{}, 0, 1)
	if scope != RBACScopeAll {
		query += ` WHERE owner_user_id = ? OR id IN (
			SELECT resource_id FROM rbac_resource_assignments
			WHERE user_id = ? AND resource_type = 'egress_proxy'
		)`
		args = append(args, strings.TrimSpace(userID), strings.TrimSpace(userID))
	}
	query += ` ORDER BY updated_at DESC, id`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list egress proxies: %w", err)
	}
	defer rows.Close()
	proxies := make([]EgressProxy, 0)
	for rows.Next() {
		proxy, err := scanEgressProxy(rows)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, proxy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list egress proxies: %w", err)
	}
	return proxies, nil
}

// SearchEgressProxies provides the bounded, safe resource search used by the
// proxy-group multi-member picker. Returned rows remain the same credential-
// redacted projection as ListEgressProxies.
func (db *DB) SearchEgressProxies(ctx context.Context, userID, scope, search string, limit, offset int) ([]EgressProxy, int, error) {
	if limit < 1 || limit > 100 {
		return nil, 0, fmt.Errorf("egress proxy search limit must be between 1 and 100")
	}
	if offset < 0 {
		return nil, 0, fmt.Errorf("egress proxy search offset must be non-negative")
	}
	conditions := make([]string, 0, 2)
	args := make([]interface{}, 0, 8)
	if scope != RBACScopeAll {
		conditions = append(conditions, `(owner_user_id = ? OR id IN (
			SELECT resource_id FROM rbac_resource_assignments
			WHERE user_id = ? AND resource_type = 'egress_proxy'
		))`)
		args = append(args, strings.TrimSpace(userID), strings.TrimSpace(userID))
	}
	if search = strings.TrimSpace(search); search != "" {
		pattern := "%" + strings.ToLower(strings.NewReplacer(
			`\`, `\\`, `%`, `\%`, `_`, `\_`,
		).Replace(search)) + "%"
		conditions = append(conditions, `(LOWER(name) LIKE ? ESCAPE '\' OR LOWER(host) LIKE ? ESCAPE '\' OR LOWER(id) LIKE ? ESCAPE '\' OR LOWER(protocol) LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern, pattern, pattern)
	}
	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}
	var total int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM egress_proxies`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count egress proxy search: %w", err)
	}
	queryArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := db.QueryContext(ctx, `
		SELECT id, name, protocol, host, port, enabled, credential_ciphertext,
			credential_updated_at, owner_user_id, created_at, updated_at
		FROM egress_proxies`+where+` ORDER BY updated_at DESC, id LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("search egress proxies: %w", err)
	}
	defer rows.Close()
	proxies := make([]EgressProxy, 0)
	for rows.Next() {
		proxy, err := scanEgressProxy(rows)
		if err != nil {
			return nil, 0, err
		}
		proxies = append(proxies, proxy)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("search egress proxies: %w", err)
	}
	return proxies, total, nil
}

func (db *DB) UpdateEgressProxy(ctx context.Context, proxy EgressProxy) (EgressProxy, error) {
	proxy.ID = strings.TrimSpace(proxy.ID)
	if proxy.ID == "" {
		return EgressProxy{}, fmt.Errorf("egress proxy id is required")
	}
	var err error
	proxy, err = normalizeEgressProxy(proxy)
	if err != nil {
		return EgressProxy{}, err
	}
	proxy.UpdatedAt = time.Now().UTC()
	proxy.CredentialsConfigured = strings.TrimSpace(proxy.CredentialCiphertext) != ""
	var credentialUpdated interface{}
	if proxy.CredentialUpdatedAt != nil {
		value := proxy.CredentialUpdatedAt.UTC()
		proxy.CredentialUpdatedAt = &value
		credentialUpdated = formatSQLiteUTC(value)
	}
	result, err := db.ExecContext(ctx, `
		UPDATE egress_proxies
		SET name = ?, protocol = ?, host = ?, port = ?, enabled = ?,
			credential_ciphertext = ?, credential_updated_at = ?, updated_at = ?
		WHERE id = ?
	`, proxy.Name, proxy.Protocol, proxy.Host, proxy.Port, boolToInt(proxy.Enabled),
		proxy.CredentialCiphertext, credentialUpdated, formatSQLiteUTC(proxy.UpdatedAt), proxy.ID)
	if err != nil {
		return EgressProxy{}, fmt.Errorf("update egress proxy: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return EgressProxy{}, err
		}
		return EgressProxy{}, ErrEgressProxyNotFound
	}
	return db.GetEgressProxy(ctx, proxy.ID)
}

func (db *DB) DeleteEgressProxy(ctx context.Context, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM egress_proxies WHERE id = ?`, strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("delete egress proxy: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return err
		}
		return ErrEgressProxyNotFound
	}
	return nil
}

type egressProxyScanner interface {
	Scan(dest ...interface{}) error
}

func scanEgressProxy(scanner egressProxyScanner) (EgressProxy, error) {
	var proxy EgressProxy
	var protocol, createdAt, updatedAt string
	var enabled int
	var credentialUpdated sql.NullString
	if err := scanner.Scan(
		&proxy.ID, &proxy.Name, &protocol, &proxy.Host, &proxy.Port, &enabled,
		&proxy.CredentialCiphertext, &credentialUpdated, &proxy.OwnerUserID, &createdAt, &updatedAt,
	); err != nil {
		return EgressProxy{}, err
	}
	parsedProtocol, err := egress.ParseUpstreamProtocol(protocol)
	if err != nil {
		return EgressProxy{}, fmt.Errorf("scan egress proxy: %w", err)
	}
	proxy.Protocol = parsedProtocol
	proxy.Enabled = enabled != 0
	proxy.CredentialsConfigured = strings.TrimSpace(proxy.CredentialCiphertext) != ""
	proxy.CreatedAt = parseDBTime(createdAt)
	proxy.UpdatedAt = parseDBTime(updatedAt)
	if credentialUpdated.Valid {
		value := parseDBTime(credentialUpdated.String)
		proxy.CredentialUpdatedAt = &value
	}
	return proxy, nil
}
