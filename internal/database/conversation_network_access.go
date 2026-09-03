package database

import (
	"context"
	"fmt"
	"strings"
)

// ConversationNetworkAccess is the conversation-scoped, high-risk network
// eligibility gate embedded into each immutable boundary snapshot.
type ConversationNetworkAccess struct {
	AllowRestrictedTargets bool `json:"allowRestrictedTargets"`
}

func (db *DB) initConversationNetworkAccessColumns() error {
	return db.addColumnIfMissing(
		"conversations",
		"allow_restricted_targets",
		"ALTER TABLE conversations ADD COLUMN allow_restricted_targets INTEGER NOT NULL DEFAULT 0 CHECK (allow_restricted_targets IN (0, 1))",
	)
}

func (db *DB) GetConversationNetworkAccess(ctx context.Context, conversationID string) (ConversationNetworkAccess, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return ConversationNetworkAccess{}, fmt.Errorf("conversation id is required")
	}
	var allow bool
	if err := db.QueryRowContext(ctx, `
		SELECT allow_restricted_targets FROM conversations
		WHERE id = ? AND runtime_mode = ?
	`, conversationID, ConversationRuntimeModeContainer).Scan(&allow); err != nil {
		return ConversationNetworkAccess{}, err
	}
	return ConversationNetworkAccess{AllowRestrictedTargets: allow}, nil
}
