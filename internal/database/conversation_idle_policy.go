package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ConversationIdleActionDelete = "delete"
	ConversationIdleActionStop   = "stop"
	ConversationIdleActionNone   = "none"

	ConversationIdleTimeoutMinSeconds     = 60
	ConversationIdleTimeoutMaxSeconds     = 30 * 24 * 60 * 60
	ConversationIdleTimeoutDefaultSeconds = 30 * 60
)

// ConversationIdlePolicy controls what happens after a container conversation
// has had no durable activity for TimeoutSeconds. It is stored per conversation
// so changing the platform compatibility setting does not silently change new
// conversations.
type ConversationIdlePolicy struct {
	Action         string `json:"action"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

func DefaultNewConversationIdlePolicy() ConversationIdlePolicy {
	return ConversationIdlePolicy{Action: ConversationIdleActionDelete, TimeoutSeconds: ConversationIdleTimeoutDefaultSeconds}
}

func NormalizeConversationIdlePolicy(policy ConversationIdlePolicy) (ConversationIdlePolicy, error) {
	policy.Action = strings.ToLower(strings.TrimSpace(policy.Action))
	if policy.Action != ConversationIdleActionDelete && policy.Action != ConversationIdleActionStop && policy.Action != ConversationIdleActionNone {
		return ConversationIdlePolicy{}, errors.New("idlePolicy.action 必须为 delete、stop 或 none")
	}
	if policy.TimeoutSeconds < ConversationIdleTimeoutMinSeconds || policy.TimeoutSeconds > ConversationIdleTimeoutMaxSeconds {
		return ConversationIdlePolicy{}, fmt.Errorf("idlePolicy.timeoutSeconds 必须在 %d 到 %d 之间", ConversationIdleTimeoutMinSeconds, ConversationIdleTimeoutMaxSeconds)
	}
	return policy, nil
}

func (db *DB) initConversationIdlePolicyColumns() error {
	if err := db.addColumnIfMissing("conversations", "idle_action", "ALTER TABLE conversations ADD COLUMN idle_action TEXT CHECK (idle_action IN ('delete', 'stop', 'none'))"); err != nil {
		return err
	}
	return db.addColumnIfMissing("conversations", "idle_timeout_seconds", "ALTER TABLE conversations ADD COLUMN idle_timeout_seconds INTEGER CHECK (idle_timeout_seconds BETWEEN 60 AND 2592000)")
}

// MigrateLegacyConversationIdlePolicies freezes the former global auto-stop
// behavior into rows created before per-conversation policies existed. New rows
// are inserted with a non-NULL policy and are never modified here.
func (db *DB) MigrateLegacyConversationIdlePolicies(ctx context.Context, legacyIdleStopSeconds int) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	action := ConversationIdleActionStop
	timeout := legacyIdleStopSeconds
	if legacyIdleStopSeconds < 0 {
		action = ConversationIdleActionNone
		timeout = ConversationIdleTimeoutDefaultSeconds
	}
	if timeout < ConversationIdleTimeoutMinSeconds {
		timeout = ConversationIdleTimeoutDefaultSeconds
	}
	if timeout > ConversationIdleTimeoutMaxSeconds {
		timeout = ConversationIdleTimeoutMaxSeconds
	}
	_, err := db.ExecContext(ctx, `
		UPDATE conversations
		SET idle_action = ?, idle_timeout_seconds = ?
		WHERE runtime_mode = 'container'
		  AND (idle_action IS NULL OR idle_timeout_seconds IS NULL)
	`, action, timeout)
	return err
}

func (db *DB) GetConversationIdlePolicy(ctx context.Context, conversationID string) (ConversationIdlePolicy, error) {
	if ctx == nil || strings.TrimSpace(conversationID) == "" {
		return ConversationIdlePolicy{}, errors.New("context and conversation id are required")
	}
	var action sql.NullString
	var timeout sql.NullInt64
	var runtimeMode string
	if err := db.QueryRowContext(ctx, `SELECT runtime_mode, idle_action, idle_timeout_seconds FROM conversations WHERE id = ?`, strings.TrimSpace(conversationID)).Scan(&runtimeMode, &action, &timeout); err != nil {
		return ConversationIdlePolicy{}, err
	}
	if runtimeMode != ConversationRuntimeModeContainer {
		return ConversationIdlePolicy{Action: ConversationIdleActionNone, TimeoutSeconds: ConversationIdleTimeoutDefaultSeconds}, nil
	}
	policy := DefaultNewConversationIdlePolicy()
	if action.Valid {
		policy.Action = action.String
	}
	if timeout.Valid {
		policy.TimeoutSeconds = int(timeout.Int64)
	}
	return NormalizeConversationIdlePolicy(policy)
}

func (db *DB) SetConversationIdlePolicy(ctx context.Context, conversationID string, policy ConversationIdlePolicy) (ConversationIdlePolicy, error) {
	if ctx == nil || strings.TrimSpace(conversationID) == "" {
		return ConversationIdlePolicy{}, errors.New("context and conversation id are required")
	}
	policy, err := NormalizeConversationIdlePolicy(policy)
	if err != nil {
		return ConversationIdlePolicy{}, err
	}
	result, err := db.ExecContext(ctx, `
		UPDATE conversations
		SET idle_action = ?, idle_timeout_seconds = ?
		WHERE id = ? AND runtime_mode = 'container'
	`, policy.Action, policy.TimeoutSeconds, strings.TrimSpace(conversationID))
	if err != nil {
		return ConversationIdlePolicy{}, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return ConversationIdlePolicy{}, err
	}
	if count != 1 {
		return ConversationIdlePolicy{}, sql.ErrNoRows
	}
	return policy, nil
}

func ConversationIdleExpiresAt(lastActivity time.Time, policy ConversationIdlePolicy) *time.Time {
	if policy.Action == ConversationIdleActionNone || lastActivity.IsZero() {
		return nil
	}
	value := lastActivity.UTC().Add(time.Duration(policy.TimeoutSeconds) * time.Second)
	return &value
}
