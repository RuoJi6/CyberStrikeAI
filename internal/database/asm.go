package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ASMResource is a configured connection to an external attack-surface
// management platform. SecretCiphertext is never serialized to clients.
type ASMResource struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Provider         string     `json:"provider"`
	BaseURL          string     `json:"base_url"`
	Username         string     `json:"username,omitempty"`
	SecretCiphertext string     `json:"-"`
	AuthType         string     `json:"auth_type"`
	VerifyTLS        bool       `json:"verify_tls"`
	Enabled          bool       `json:"enabled"`
	Status           string     `json:"status"`
	LastError        string     `json:"last_error,omitempty"`
	LastTestAt       *time.Time `json:"last_test_at,omitempty"`
	MetadataJSON     string     `json:"metadata_json,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

func scanASMResource(scanner interface{ Scan(...interface{}) error }) (*ASMResource, error) {
	var item ASMResource
	var verifyTLS, enabled int
	var lastTestAt sql.NullString
	var createdAt, updatedAt string
	err := scanner.Scan(
		&item.ID, &item.Name, &item.Provider, &item.BaseURL, &item.Username,
		&item.SecretCiphertext, &item.AuthType, &verifyTLS, &enabled, &item.Status,
		&item.LastError, &lastTestAt, &item.MetadataJSON, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	item.VerifyTLS = verifyTLS != 0
	item.Enabled = enabled != 0
	item.CreatedAt = parseDBTime(createdAt)
	item.UpdatedAt = parseDBTime(updatedAt)
	if lastTestAt.Valid && strings.TrimSpace(lastTestAt.String) != "" {
		parsed := parseDBTime(lastTestAt.String)
		item.LastTestAt = &parsed
	}
	return &item, nil
}

const asmResourceColumns = `id, name, provider, base_url, username,
	secret_ciphertext, auth_type, verify_tls, enabled, status,
	COALESCE(last_error,''), last_test_at, COALESCE(metadata_json,'{}'), created_at, updated_at`

func (db *DB) ListASMResources(enabledOnly bool) ([]*ASMResource, error) {
	query := `SELECT ` + asmResourceColumns + ` FROM asm_resources`
	if enabledOnly {
		query += ` WHERE enabled = 1`
	}
	query += ` ORDER BY name COLLATE NOCASE, created_at`
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("查询 ASM 资源失败: %w", err)
	}
	defer rows.Close()

	items := make([]*ASMResource, 0)
	for rows.Next() {
		item, scanErr := scanASMResource(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("读取 ASM 资源失败: %w", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历 ASM 资源失败: %w", err)
	}
	return items, nil
}

func (db *DB) GetASMResource(id string) (*ASMResource, error) {
	item, err := scanASMResource(db.QueryRow(`SELECT `+asmResourceColumns+` FROM asm_resources WHERE id = ?`, strings.TrimSpace(id)))
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ASM 资源不存在")
	}
	if err != nil {
		return nil, fmt.Errorf("获取 ASM 资源失败: %w", err)
	}
	return item, nil
}

func (db *DB) CreateASMResource(item *ASMResource) error {
	if item == nil {
		return fmt.Errorf("ASM 资源不能为空")
	}
	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	_, err := db.Exec(`INSERT INTO asm_resources (
		id, name, provider, base_url, username, secret_ciphertext, auth_type,
		verify_tls, enabled, status, last_error, last_test_at, metadata_json,
		created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID, item.Name, item.Provider, item.BaseURL, item.Username,
		item.SecretCiphertext, item.AuthType, boolToInt(item.VerifyTLS), boolToInt(item.Enabled),
		item.Status, item.LastError, item.LastTestAt, item.MetadataJSON, item.CreatedAt, item.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("创建 ASM 资源失败: %w", err)
	}
	return nil
}

func (db *DB) UpdateASMResource(item *ASMResource) error {
	if item == nil {
		return fmt.Errorf("ASM 资源不能为空")
	}
	item.UpdatedAt = time.Now().UTC()
	result, err := db.Exec(`UPDATE asm_resources SET
		name = ?, provider = ?, base_url = ?, username = ?, secret_ciphertext = ?,
		auth_type = ?, verify_tls = ?, enabled = ?, status = ?, last_error = ?,
		last_test_at = ?, metadata_json = ?, updated_at = ? WHERE id = ?`,
		item.Name, item.Provider, item.BaseURL, item.Username, item.SecretCiphertext,
		item.AuthType, boolToInt(item.VerifyTLS), boolToInt(item.Enabled), item.Status,
		item.LastError, item.LastTestAt, item.MetadataJSON, item.UpdatedAt, item.ID,
	)
	if err != nil {
		return fmt.Errorf("更新 ASM 资源失败: %w", err)
	}
	rows, err := result.RowsAffected()
	if err == nil && rows == 0 {
		return fmt.Errorf("ASM 资源不存在")
	}
	return nil
}

func (db *DB) DeleteASMResource(id string) error {
	result, err := db.Exec(`DELETE FROM asm_resources WHERE id = ?`, strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("删除 ASM 资源失败: %w", err)
	}
	rows, err := result.RowsAffected()
	if err == nil && rows == 0 {
		return fmt.Errorf("ASM 资源不存在")
	}
	return nil
}
