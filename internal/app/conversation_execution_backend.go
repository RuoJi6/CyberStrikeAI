package app

import (
	"context"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"
)

// conversationExecutionBackendResolver binds command execution to durable
// conversation state. Container failures are returned to the tool caller and
// are never converted into a host backend.
type conversationExecutionBackendResolver struct {
	db        *database.DB
	host      security.ExecutionBackend
	container containerruntime.RuntimeExecutor
	lifecycle *containerruntime.LifecycleController
}

func newConversationExecutionBackendResolver(db *database.DB, runtime containerruntime.RuntimeExecutor, lifecycle *containerruntime.LifecycleController) security.ExecutionBackendResolver {
	return &conversationExecutionBackendResolver{
		db:        db,
		host:      security.NewHostExecutionBackend(),
		container: runtime,
		lifecycle: lifecycle,
	}
}

func (r *conversationExecutionBackendResolver) ResolveExecutionBackend(ctx context.Context) (security.ExecutionBackend, error) {
	if r == nil || r.host == nil {
		return nil, fmt.Errorf("execution backend resolver is not configured")
	}
	conversationID := strings.TrimSpace(mcp.MCPConversationIDFromContext(ctx))
	if conversationID == "" {
		return r.host, nil
	}
	if r.db == nil {
		return nil, fmt.Errorf("conversation database is not configured")
	}
	runtimeMode, err := r.db.GetConversationRuntimeMode(conversationID)
	if err != nil {
		return nil, fmt.Errorf("resolve execution conversation %s: %w", conversationID, err)
	}
	switch runtimeMode {
	case database.ConversationRuntimeModeHost:
		return r.host, nil
	case database.ConversationRuntimeModeContainer:
		return r.resolveContainer(ctx, conversationID)
	default:
		return nil, fmt.Errorf("conversation %s has invalid runtime mode %q", conversationID, runtimeMode)
	}
}

func (r *conversationExecutionBackendResolver) resolveContainer(ctx context.Context, conversationID string) (security.ExecutionBackend, error) {
	if r.container == nil || r.lifecycle == nil {
		return nil, fmt.Errorf("container execution backend is unavailable for conversation %s", conversationID)
	}
	record, err := r.db.GetContainerInitialization(ctx, conversationID)
	if err != nil {
		return nil, fmt.Errorf("load container runtime for conversation %s: %w", conversationID, err)
	}
	if record.Status != containerruntime.InitializationCreated ||
		(record.ReadinessStatus != containerruntime.ReadinessReady && record.ReadinessStatus != containerruntime.ReadinessNotRequired) {
		return nil, fmt.Errorf("container runtime for conversation %s is not ready", conversationID)
	}
	if record.RuntimeStatus == containerruntime.StatusStopped {
		started, startErr := r.lifecycle.Start(ctx, conversationID)
		if startErr != nil {
			// A concurrent tool may have won the durable lifecycle CAS. Reload once
			// and accept only an observed running runtime; otherwise fail closed.
			observed, getErr := r.db.GetContainerInitialization(ctx, conversationID)
			if getErr != nil || observed.RuntimeStatus != containerruntime.StatusRunning || observed.LifecycleState != containerruntime.LifecycleIdle {
				return nil, fmt.Errorf("start container runtime for conversation %s: %w", conversationID, startErr)
			}
			record = observed
		} else {
			record = started
		}
	}
	if record.RuntimeStatus != containerruntime.StatusRunning || record.LifecycleState != containerruntime.LifecycleIdle {
		return nil, fmt.Errorf("container runtime for conversation %s is %s/%s", conversationID, record.RuntimeStatus, record.LifecycleState)
	}
	backend, err := security.NewContainerExecutionBackendWithIdentity(r.container, record.Spec, record.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("bind container execution backend for conversation %s: %w", conversationID, err)
	}
	return backend, nil
}
