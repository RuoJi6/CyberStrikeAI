package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	containerruntime "cyberstrike-ai/internal/runtime/container"
)

func (db *DB) ListManagedResourceClaims(ctx context.Context) ([]containerruntime.ManagedResourceClaim, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT runtime_id,
			CASE WHEN initialization_status IN (?, ?) OR lifecycle_state = ? THEN '' ELSE provider_id END,
			conversation_id,
			spec_json,
			lifecycle_operation,
			lifecycle_state
		FROM conversation_container_runtimes
		WHERE initialization_status IN (?, ?, ?)
		ORDER BY runtime_id
	`, containerruntime.InitializationQueued, containerruntime.InitializationCreating, containerruntime.LifecycleInProgress,
		containerruntime.InitializationQueued, containerruntime.InitializationCreating, containerruntime.InitializationCreated)
	if err != nil {
		return nil, fmt.Errorf("list container resource claims: %w", err)
	}
	claims := make([]containerruntime.ManagedResourceClaim, 0)
	workspaceClaims := make(map[string]struct{})
	for rows.Next() {
		var claim containerruntime.ManagedResourceClaim
		claim.Kind = containerruntime.ResourceKindAgent
		var specJSON string
		var lifecycleOperation containerruntime.LifecycleOperation
		var lifecycleState containerruntime.LifecycleState
		if err := rows.Scan(&claim.LogicalID, &claim.ProviderID, &claim.ConversationID, &specJSON, &lifecycleOperation, &lifecycleState); err != nil {
			_ = rows.Close()
			return nil, err
		}
		claims = append(claims, claim)
		var spec containerruntime.RuntimeSpec
		if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("decode container resource claim %s: %w", claim.LogicalID, err)
		}
		if string(spec.ID) != claim.LogicalID || spec.ConversationID != claim.ConversationID {
			_ = rows.Close()
			return nil, fmt.Errorf("%w: container resource claim identity mismatch", containerruntime.ErrRuntimeStateConflict)
		}
		migrationMayOwnNetwork := spec.Security.NetworkMode == containerruntime.NetworkNone &&
			(lifecycleOperation == containerruntime.LifecycleOperationRebuild || lifecycleOperation == containerruntime.LifecycleOperationReconcile) &&
			(lifecycleState == containerruntime.LifecycleInProgress || lifecycleState == containerruntime.LifecycleFailed)
		if spec.Security.NetworkMode == containerruntime.NetworkInternal || migrationMayOwnNetwork {
			claims = append(claims, containerruntime.ManagedResourceClaim{
				Kind: containerruntime.ResourceKindConversationNetwork, LogicalID: claim.LogicalID,
				ConversationID: claim.ConversationID,
			})
		}
		migrationMayOwnGateway := spec.EgressGateway == nil &&
			(lifecycleOperation == containerruntime.LifecycleOperationRebuild || lifecycleOperation == containerruntime.LifecycleOperationReconcile) &&
			(lifecycleState == containerruntime.LifecycleInProgress || lifecycleState == containerruntime.LifecycleFailed)
		if spec.EgressGateway != nil || migrationMayOwnGateway {
			claims = append(claims,
				containerruntime.ManagedResourceClaim{
					Kind: containerruntime.ResourceKindEgressGateway, LogicalID: claim.LogicalID,
					ConversationID: claim.ConversationID,
				},
				containerruntime.ManagedResourceClaim{
					Kind: containerruntime.ResourceKindEgressNetwork, LogicalID: claim.LogicalID,
					ConversationID: claim.ConversationID,
				},
			)
		}
		if spec.Workspace.Persistent {
			expectedName := containerruntime.WorkspaceVolumeName(containerruntime.RuntimeID(claim.LogicalID))
			if spec.Workspace.VolumeName != expectedName {
				_ = rows.Close()
				return nil, fmt.Errorf("%w: persistent workspace claim identity mismatch", containerruntime.ErrRuntimeStateConflict)
			}
			claims = append(claims, containerruntime.ManagedResourceClaim{
				Kind: containerruntime.ResourceKindWorkspaceVolume, LogicalID: claim.LogicalID,
				ProviderID: expectedName, ConversationID: claim.ConversationID,
			})
			workspaceClaims[claim.ConversationID] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	// A persistent workspace outlives its container lifecycle record. Keep a
	// control-plane claim for every persistent container conversation so the
	// orphan scanner cannot delete a deliberately retained named volume between
	// container deletion and recreation.
	persistentRows, err := db.QueryContext(ctx, `
		SELECT id
		FROM conversations
		WHERE runtime_mode = ? AND workspace_persistent = 1
		ORDER BY id
	`, ConversationRuntimeModeContainer)
	if err != nil {
		return nil, fmt.Errorf("list retained workspace claims: %w", err)
	}
	defer persistentRows.Close()
	for persistentRows.Next() {
		var conversationID string
		if err := persistentRows.Scan(&conversationID); err != nil {
			return nil, err
		}
		if _, exists := workspaceClaims[conversationID]; exists {
			continue
		}
		runtimeID := containerruntime.RuntimeID("conversation-" + conversationID)
		claims = append(claims, containerruntime.ManagedResourceClaim{
			Kind:           containerruntime.ResourceKindWorkspaceVolume,
			LogicalID:      string(runtimeID),
			ProviderID:     containerruntime.WorkspaceVolumeName(runtimeID),
			ConversationID: conversationID,
		})
		workspaceClaims[conversationID] = struct{}{}
	}
	if err := persistentRows.Err(); err != nil {
		return nil, err
	}
	if err := persistentRows.Close(); err != nil {
		return nil, err
	}

	retainedRows, err := db.QueryContext(ctx, `
		SELECT original_conversation_id, runtime_id, volume_name
		FROM retained_container_workspaces
		ORDER BY original_conversation_id
	`)
	if err != nil {
		return nil, fmt.Errorf("list retained deleted-conversation workspace claims: %w", err)
	}
	defer retainedRows.Close()
	for retainedRows.Next() {
		var conversationID, runtimeID, volumeName string
		if err := retainedRows.Scan(&conversationID, &runtimeID, &volumeName); err != nil {
			return nil, err
		}
		expectedRuntimeID := containerruntime.RuntimeID("conversation-" + conversationID)
		expectedVolumeName := containerruntime.WorkspaceVolumeName(expectedRuntimeID)
		if runtimeID != string(expectedRuntimeID) || volumeName != expectedVolumeName {
			return nil, fmt.Errorf("%w: retained workspace claim identity mismatch", containerruntime.ErrRuntimeStateConflict)
		}
		if _, exists := workspaceClaims[conversationID]; exists {
			continue
		}
		claims = append(claims, containerruntime.ManagedResourceClaim{
			Kind:           containerruntime.ResourceKindWorkspaceVolume,
			LogicalID:      runtimeID,
			ProviderID:     volumeName,
			ConversationID: conversationID,
		})
	}
	return claims, retainedRows.Err()
}

func (db *DB) DiscoverResourceTombstone(ctx context.Context, resource containerruntime.ManagedResource, now time.Time) (containerruntime.ResourceTombstone, bool, error) {
	nowText := formatSQLiteUTC(now)
	var resourceCreatedAt interface{}
	if !resource.CreatedAt.IsZero() {
		resourceCreatedAt = formatSQLiteUTC(resource.CreatedAt)
	}
	result, err := db.ExecContext(ctx, `
		INSERT OR IGNORE INTO container_resource_tombstones (
			resource_kind, logical_id, provider_id, resource_name, conversation_id,
			resource_created_at, status, attempt, last_error, discovered_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?)
	`, resource.Kind, resource.LogicalID, resource.ProviderID, resource.Name, resource.ConversationID,
		resourceCreatedAt, containerruntime.ResourceTombstonePending, nowText, nowText)
	if err != nil {
		return containerruntime.ResourceTombstone{}, false, fmt.Errorf("discover container resource tombstone: %w", err)
	}
	inserted, _ := result.RowsAffected()
	tombstone, err := db.getResourceTombstone(ctx, resource.Kind, resource.ProviderID)
	if err != nil {
		return tombstone, inserted == 1, err
	}
	if tombstone.Resource.LogicalID != resource.LogicalID || tombstone.Resource.Name != resource.Name || tombstone.Resource.ConversationID != resource.ConversationID {
		return tombstone, inserted == 1, fmt.Errorf("%w: tombstone provider identity changed", containerruntime.ErrRuntimeStateConflict)
	}
	return tombstone, inserted == 1, nil
}

func (db *DB) RecoverResourceTombstones(ctx context.Context, interruptedBefore, now time.Time) (int64, error) {
	result, err := db.ExecContext(ctx, `
		UPDATE container_resource_tombstones
		SET status = ?, last_error = ?, next_retry_at = ?, completed_at = NULL, updated_at = ?
		WHERE status = ? AND updated_at <= ?
	`, containerruntime.ResourceTombstoneFailed, "控制面重启或超时中断了孤儿资源清理，等待重试",
		formatSQLiteUTC(now), formatSQLiteUTC(now), containerruntime.ResourceTombstoneDeleting, formatSQLiteUTC(interruptedBefore))
	if err != nil {
		return 0, fmt.Errorf("recover container resource tombstones: %w", err)
	}
	updated, _ := result.RowsAffected()
	return updated, nil
}

func (db *DB) ListRetryableResourceTombstones(ctx context.Context, now time.Time, limit int) ([]containerruntime.ResourceTombstone, error) {
	if limit < 1 || limit > 4096 {
		return nil, fmt.Errorf("%w: tombstone list limit is invalid", containerruntime.ErrInvalidSpecification)
	}
	rows, err := db.QueryContext(ctx, resourceTombstoneSelect+`
		WHERE status IN (?, ?) AND (next_retry_at IS NULL OR next_retry_at <= ?)
		ORDER BY COALESCE(next_retry_at, discovered_at), resource_kind, provider_id
		LIMIT ?
	`, containerruntime.ResourceTombstonePending, containerruntime.ResourceTombstoneFailed, formatSQLiteUTC(now), limit)
	if err != nil {
		return nil, fmt.Errorf("list retryable container resource tombstones: %w", err)
	}
	defer rows.Close()
	result := make([]containerruntime.ResourceTombstone, 0)
	for rows.Next() {
		tombstone, scanErr := scanResourceTombstone(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, tombstone)
	}
	return result, rows.Err()
}

func (db *DB) ClaimResourceTombstone(ctx context.Context, resource containerruntime.ManagedResource, now time.Time) (containerruntime.ResourceTombstone, bool, error) {
	nowText := formatSQLiteUTC(now)
	result, err := db.ExecContext(ctx, `
		UPDATE container_resource_tombstones
		SET status = ?, attempt = attempt + 1, last_error = '', last_attempt_at = ?,
			next_retry_at = NULL, completed_at = NULL, updated_at = ?
		WHERE resource_kind = ? AND provider_id = ? AND logical_id = ? AND resource_name = ?
			AND conversation_id = ? AND status IN (?, ?)
			AND (next_retry_at IS NULL OR next_retry_at <= ?)
	`, containerruntime.ResourceTombstoneDeleting, nowText, nowText,
		resource.Kind, resource.ProviderID, resource.LogicalID, resource.Name, resource.ConversationID,
		containerruntime.ResourceTombstonePending, containerruntime.ResourceTombstoneFailed, nowText)
	if err != nil {
		return containerruntime.ResourceTombstone{}, false, fmt.Errorf("claim container resource tombstone: %w", err)
	}
	updated, _ := result.RowsAffected()
	tombstone, getErr := db.getResourceTombstone(ctx, resource.Kind, resource.ProviderID)
	return tombstone, updated == 1, getErr
}

func (db *DB) CompleteResourceTombstone(ctx context.Context, resource containerruntime.ManagedResource, now time.Time) error {
	nowText := formatSQLiteUTC(now)
	result, err := db.ExecContext(ctx, `
		UPDATE container_resource_tombstones
		SET status = ?, last_error = '', next_retry_at = NULL, completed_at = ?, updated_at = ?
		WHERE resource_kind = ? AND provider_id = ? AND logical_id = ? AND resource_name = ?
			AND conversation_id = ? AND status = ?
	`, containerruntime.ResourceTombstoneCompleted, nowText, nowText,
		resource.Kind, resource.ProviderID, resource.LogicalID, resource.Name, resource.ConversationID,
		containerruntime.ResourceTombstoneDeleting)
	if err != nil {
		return fmt.Errorf("complete container resource tombstone: %w", err)
	}
	return requireTombstoneUpdate(result, "complete")
}

func (db *DB) ResolveClaimedResourceTombstone(ctx context.Context, resource containerruntime.ManagedResource, now time.Time) error {
	nowText := formatSQLiteUTC(now)
	result, err := db.ExecContext(ctx, `
		UPDATE container_resource_tombstones
		SET status = ?, last_error = '', next_retry_at = NULL, completed_at = ?, updated_at = ?
		WHERE resource_kind = ? AND provider_id = ? AND logical_id = ? AND resource_name = ?
			AND conversation_id = ? AND status IN (?, ?)
	`, containerruntime.ResourceTombstoneCompleted, nowText, nowText,
		resource.Kind, resource.ProviderID, resource.LogicalID, resource.Name, resource.ConversationID,
		containerruntime.ResourceTombstonePending, containerruntime.ResourceTombstoneFailed)
	if err != nil {
		return fmt.Errorf("resolve claimed container resource tombstone: %w", err)
	}
	return requireTombstoneUpdate(result, "resolve claimed")
}

func (db *DB) FailResourceTombstone(ctx context.Context, resource containerruntime.ManagedResource, message string, nextRetryAt, now time.Time) error {
	runes := []rune(strings.TrimSpace(message))
	if len(runes) > 1024 {
		runes = runes[:1024]
	}
	result, err := db.ExecContext(ctx, `
		UPDATE container_resource_tombstones
		SET status = ?, last_error = ?, next_retry_at = ?, completed_at = NULL, updated_at = ?
		WHERE resource_kind = ? AND provider_id = ? AND logical_id = ? AND resource_name = ?
			AND conversation_id = ? AND status = ?
	`, containerruntime.ResourceTombstoneFailed, string(runes), formatSQLiteUTC(nextRetryAt), formatSQLiteUTC(now),
		resource.Kind, resource.ProviderID, resource.LogicalID, resource.Name, resource.ConversationID,
		containerruntime.ResourceTombstoneDeleting)
	if err != nil {
		return fmt.Errorf("fail container resource tombstone: %w", err)
	}
	return requireTombstoneUpdate(result, "fail")
}

func (db *DB) getResourceTombstone(ctx context.Context, kind, providerID string) (containerruntime.ResourceTombstone, error) {
	return scanResourceTombstone(db.QueryRowContext(ctx, resourceTombstoneSelect+` WHERE resource_kind = ? AND provider_id = ?`, kind, providerID))
}

const resourceTombstoneSelect = `
	SELECT resource_kind, logical_id, provider_id, resource_name, conversation_id,
		resource_created_at, status, attempt, last_error, discovered_at, last_attempt_at, next_retry_at,
		completed_at, updated_at
	FROM container_resource_tombstones`

type resourceTombstoneScanner interface {
	Scan(dest ...interface{}) error
}

func scanResourceTombstone(scanner resourceTombstoneScanner) (containerruntime.ResourceTombstone, error) {
	var tombstone containerruntime.ResourceTombstone
	var status, discoveredAt, updatedAt string
	var resourceCreatedAt, lastAttemptAt, nextRetryAt, completedAt sql.NullString
	err := scanner.Scan(
		&tombstone.Resource.Kind, &tombstone.Resource.LogicalID, &tombstone.Resource.ProviderID,
		&tombstone.Resource.Name, &tombstone.Resource.ConversationID, &resourceCreatedAt, &status, &tombstone.Attempt,
		&tombstone.LastError, &discoveredAt, &lastAttemptAt, &nextRetryAt, &completedAt, &updatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return tombstone, fmt.Errorf("%w: container resource tombstone", containerruntime.ErrNotFound)
		}
		return tombstone, err
	}
	tombstone.Status = containerruntime.ResourceTombstoneStatus(status)
	var parseErr error
	if resourceCreatedAt.Valid {
		tombstone.Resource.CreatedAt, parseErr = ParseRFC3339Time(resourceCreatedAt.String)
		if parseErr != nil {
			return tombstone, parseErr
		}
	}
	tombstone.DiscoveredAt, parseErr = ParseRFC3339Time(discoveredAt)
	if parseErr != nil {
		return tombstone, parseErr
	}
	tombstone.UpdatedAt, parseErr = ParseRFC3339Time(updatedAt)
	if parseErr != nil {
		return tombstone, parseErr
	}
	if lastAttemptAt.Valid {
		parsed, err := ParseRFC3339Time(lastAttemptAt.String)
		if err != nil {
			return tombstone, err
		}
		tombstone.LastAttemptAt = &parsed
	}
	if nextRetryAt.Valid {
		parsed, err := ParseRFC3339Time(nextRetryAt.String)
		if err != nil {
			return tombstone, err
		}
		tombstone.NextRetryAt = &parsed
	}
	if completedAt.Valid {
		parsed, err := ParseRFC3339Time(completedAt.String)
		if err != nil {
			return tombstone, err
		}
		tombstone.CompletedAt = &parsed
	}
	return tombstone, nil
}

func requireTombstoneUpdate(result sql.Result, operation string) error {
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return fmt.Errorf("%w: tombstone %s lost its compare-and-swap state", containerruntime.ErrRuntimeStateConflict, operation)
	}
	return nil
}
