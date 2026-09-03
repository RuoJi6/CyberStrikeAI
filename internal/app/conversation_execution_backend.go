package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"
)

const (
	containerStartJoinPollInterval = 25 * time.Millisecond
	containerStartJoinMaxWait      = 30 * time.Second
)

// conversationExecutionBackendResolver binds command execution to durable
// conversation state. Container failures are returned to the tool caller and
// are never converted into a host backend.
type conversationExecutionBackendResolver struct {
	db        *database.DB
	host      security.ExecutionBackend
	hostProxy hostExecutionBackendProvider
	container containerruntime.RuntimeExecutor
	lifecycle *containerruntime.LifecycleController
}

type hostExecutionBackendProvider interface {
	ResolveHostExecutionBackend(context.Context, string) (security.ExecutionBackend, error)
}

func newConversationExecutionBackendResolver(db *database.DB, runtime containerruntime.RuntimeExecutor, lifecycle *containerruntime.LifecycleController, hostProviders ...hostExecutionBackendProvider) security.ExecutionBackendResolver {
	resolver := &conversationExecutionBackendResolver{
		db:        db,
		host:      security.NewHostExecutionBackend(),
		container: runtime,
		lifecycle: lifecycle,
	}
	if len(hostProviders) > 0 {
		resolver.hostProxy = hostProviders[0]
	}
	return resolver
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
		if r.hostProxy != nil {
			backend, resolveErr := r.hostProxy.ResolveHostExecutionBackend(ctx, conversationID)
			if resolveErr != nil {
				return nil, fmt.Errorf("configure host traffic capture for conversation %s: %w", conversationID, resolveErr)
			}
			return backend, nil
		}
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
	pendingBoundaryRebuild, err := r.db.HasPendingConversationBoundaryRebuild(ctx, conversationID)
	if err != nil {
		return nil, fmt.Errorf("check boundary rebuild for conversation %s: %w", conversationID, err)
	}
	if pendingBoundaryRebuild {
		return nil, fmt.Errorf("boundary rebuild for conversation %s is pending", conversationID)
	}
	snapshot, err := r.db.GetConversationBoundarySnapshot(ctx, conversationID)
	if err != nil {
		return nil, fmt.Errorf("load boundary snapshot for conversation %s: %w", conversationID, err)
	}
	record, err := r.db.GetContainerInitialization(ctx, conversationID)
	if err != nil {
		return nil, fmt.Errorf("load container runtime for conversation %s: %w", conversationID, err)
	}
	if record.Status != containerruntime.InitializationCreated ||
		(record.ReadinessStatus != containerruntime.ReadinessReady && record.ReadinessStatus != containerruntime.ReadinessNotRequired) {
		return nil, fmt.Errorf("container runtime for conversation %s is not ready", conversationID)
	}
	if snapshot.RuntimeGeneration != record.RuntimeGeneration {
		return nil, fmt.Errorf("boundary snapshot/runtime generation mismatch for conversation %s", conversationID)
	}
	if containerStartInProgress(record) {
		record, err = r.waitForContainerStart(ctx, conversationID)
		if err != nil {
			return nil, err
		}
	} else if record.RuntimeStatus == containerruntime.StatusStopped {
		started, startErr := r.lifecycle.Start(ctx, conversationID)
		if startErr != nil {
			observed, getErr := r.db.GetContainerInitialization(ctx, conversationID)
			if getErr != nil {
				return nil, fmt.Errorf("start container runtime for conversation %s: %w (reload lifecycle state: %v)", conversationID, startErr, getErr)
			}
			switch {
			case containerStartInProgress(observed):
				observed, err = r.waitForContainerStart(ctx, conversationID)
				if err != nil {
					return nil, err
				}
			case observed.RuntimeStatus == containerruntime.StatusRunning && observed.LifecycleState == containerruntime.LifecycleIdle:
				// A concurrent caller completed the same durable start before the reload.
			case observed.LifecycleOperation == containerruntime.LifecycleOperationStart && observed.LifecycleState == containerruntime.LifecycleFailed:
				return nil, containerStartFailedError(observed)
			default:
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

func containerStartInProgress(record containerruntime.InitializationRecord) bool {
	return record.LifecycleOperation == containerruntime.LifecycleOperationStart &&
		record.LifecycleState == containerruntime.LifecycleInProgress
}

func containerStartFailedError(record containerruntime.InitializationRecord) error {
	message := strings.TrimSpace(record.LifecycleError)
	if message == "" {
		message = strings.TrimSpace(record.LastError)
	}
	if message == "" {
		message = "unknown container engine error"
	}
	return fmt.Errorf("container runtime start for conversation %s failed: %s", record.ConversationID, message)
}

func (r *conversationExecutionBackendResolver) waitForContainerStart(ctx context.Context, conversationID string) (containerruntime.InitializationRecord, error) {
	waitCtx, cancel := context.WithTimeout(ctx, containerStartJoinMaxWait)
	defer cancel()
	ticker := time.NewTicker(containerStartJoinPollInterval)
	defer ticker.Stop()

	for {
		record, err := r.db.GetContainerInitialization(waitCtx, conversationID)
		if err != nil {
			return record, fmt.Errorf("wait for container runtime start for conversation %s: %w", conversationID, err)
		}
		switch {
		case record.RuntimeStatus == containerruntime.StatusRunning && record.LifecycleState == containerruntime.LifecycleIdle:
			return record, nil
		case record.LifecycleOperation == containerruntime.LifecycleOperationStart && record.LifecycleState == containerruntime.LifecycleFailed:
			return record, containerStartFailedError(record)
		case !containerStartInProgress(record):
			return record, fmt.Errorf("container runtime start for conversation %s changed to %s/%s before completion", conversationID, record.LifecycleOperation, record.LifecycleState)
		}

		select {
		case <-waitCtx.Done():
			return record, fmt.Errorf("wait for container runtime start for conversation %s: %w", conversationID, waitCtx.Err())
		case <-ticker.C:
		}
	}
}
