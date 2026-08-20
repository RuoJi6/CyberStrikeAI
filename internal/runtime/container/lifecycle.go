package container

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type LifecycleOperation string
type LifecycleState string

const (
	LifecycleOperationNone      LifecycleOperation = "none"
	LifecycleOperationStart     LifecycleOperation = "start"
	LifecycleOperationStop      LifecycleOperation = "stop"
	LifecycleOperationRebuild   LifecycleOperation = "rebuild"
	LifecycleOperationDelete    LifecycleOperation = "delete"
	LifecycleOperationReconcile LifecycleOperation = "reconcile"

	LifecycleIdle       LifecycleState = "idle"
	LifecycleInProgress LifecycleState = "in_progress"
	LifecycleFailed     LifecycleState = "failed"
)

type LifecycleCompletion struct {
	Runtime             Runtime
	Readiness           *ReadinessReport
	IncrementGeneration bool
	Drift               string
}

type LifecycleFailure struct {
	Message         string
	RuntimeStatus   Status
	Drift           string
	ReadinessFailed bool
}

// LifecycleStore is the durable compare-and-swap boundary for runtime
// mutations. Implementations must reject a second operation while one is in
// progress so multiple API processes cannot mutate the same container.
type LifecycleStore interface {
	Get(ctx context.Context, conversationID string) (InitializationRecord, error)
	BeginLifecycle(ctx context.Context, conversationID string, operation LifecycleOperation) (InitializationRecord, error)
	BeginIdleStop(ctx context.Context, conversationID string, inactiveBefore time.Time) (InitializationRecord, error)
	CompleteLifecycle(ctx context.Context, conversationID string, operation LifecycleOperation, completion LifecycleCompletion) (InitializationRecord, error)
	FailLifecycle(ctx context.Context, conversationID string, operation LifecycleOperation, failure LifecycleFailure) (InitializationRecord, error)
	DeleteLifecycle(ctx context.Context, conversationID string, operation LifecycleOperation) error
	RecoverLifecycle(ctx context.Context) ([]InitializationRecord, error)
}

// LifecycleController coordinates Docker mutations with durable control-plane
// state. It never accepts a provider/container ID from a handler.
type LifecycleController struct {
	manager RuntimeManager
	checker RuntimeReadinessChecker
	store   LifecycleStore
}

func NewLifecycleController(manager RuntimeManager, store LifecycleStore) (*LifecycleController, error) {
	if manager == nil || store == nil {
		return nil, invalidSpec("lifecycle controller requires a runtime manager and durable store")
	}
	checker, _ := manager.(RuntimeReadinessChecker)
	return &LifecycleController{manager: manager, checker: checker, store: store}, nil
}

func (c *LifecycleController) Start(ctx context.Context, conversationID string) (InitializationRecord, error) {
	record, err := c.prepare(ctx, conversationID, LifecycleOperationStart, true)
	if err != nil {
		return record, err
	}
	if _, err := c.verifyBeforeMutation(ctx, record, false); err != nil {
		return c.failAfterMutation(record, LifecycleOperationStart, err, LifecycleFailure{RuntimeStatus: StatusFailed, Drift: lifecycleDriftForError(err)})
	}
	runtime, err := c.manager.Start(ctx, record.RuntimeID)
	if err != nil {
		return c.failAfterMutation(record, LifecycleOperationStart, err, LifecycleFailure{RuntimeStatus: record.RuntimeStatus})
	}
	if err := validateObservedRuntime(record, runtime); err != nil {
		return c.failAfterMutation(record, LifecycleOperationStart, err, LifecycleFailure{RuntimeStatus: StatusFailed, Drift: "specification_drift"})
	}
	return c.complete(record, LifecycleOperationStart, LifecycleCompletion{Runtime: runtime})
}

func (c *LifecycleController) Stop(ctx context.Context, conversationID string) (InitializationRecord, error) {
	record, err := c.prepare(ctx, conversationID, LifecycleOperationStop, false)
	if err != nil {
		return record, err
	}
	return c.stopPrepared(ctx, record)
}

// StopIdle atomically claims an idle running runtime using the conversation's
// durable activity timestamp. It never requests workspace or runtime deletion.
func (c *LifecycleController) StopIdle(ctx context.Context, conversationID string, inactiveBefore time.Time) (InitializationRecord, error) {
	if ctx == nil {
		return InitializationRecord{}, invalidSpec("context is required")
	}
	if inactiveBefore.IsZero() {
		return InitializationRecord{}, invalidSpec("idle cutoff is required")
	}
	record, err := c.store.BeginIdleStop(ctx, strings.TrimSpace(conversationID), inactiveBefore.UTC())
	if err != nil {
		return record, err
	}
	return c.stopPrepared(ctx, record)
}

func (c *LifecycleController) stopPrepared(ctx context.Context, record InitializationRecord) (InitializationRecord, error) {
	if _, err := c.verifyBeforeMutation(ctx, record, false); err != nil {
		return c.failAfterMutation(record, LifecycleOperationStop, err, LifecycleFailure{RuntimeStatus: StatusFailed, Drift: lifecycleDriftForError(err)})
	}
	runtime, err := c.manager.Stop(ctx, record.RuntimeID, StopOptions{})
	if err != nil {
		return c.failAfterMutation(record, LifecycleOperationStop, err, LifecycleFailure{RuntimeStatus: record.RuntimeStatus})
	}
	if err := validateObservedRuntime(record, runtime); err != nil {
		return c.failAfterMutation(record, LifecycleOperationStop, err, LifecycleFailure{RuntimeStatus: StatusFailed, Drift: "specification_drift"})
	}
	return c.complete(record, LifecycleOperationStop, LifecycleCompletion{Runtime: runtime})
}

func (c *LifecycleController) Rebuild(ctx context.Context, conversationID string) (InitializationRecord, error) {
	record, err := c.prepare(ctx, conversationID, LifecycleOperationRebuild, false)
	if err != nil {
		return record, err
	}
	if _, err := c.verifyBeforeMutation(ctx, record, true); err != nil {
		return c.failAfterMutation(record, LifecycleOperationRebuild, err, LifecycleFailure{
			RuntimeStatus: StatusFailed, Drift: lifecycleDriftForError(err), ReadinessFailed: record.Spec.Readiness.Enabled,
		})
	}
	runtime, err := c.manager.Rebuild(ctx, record.RuntimeID, RebuildOptions{Spec: record.Spec})
	if err != nil {
		return c.failAfterMutation(record, LifecycleOperationRebuild, err, LifecycleFailure{
			RuntimeStatus:   StatusFailed,
			Drift:           "rebuild_incomplete",
			ReadinessFailed: record.Spec.Readiness.Enabled,
		})
	}
	if err := validateObservedRuntime(record, runtime); err != nil {
		return c.failAfterMutation(record, LifecycleOperationRebuild, err, LifecycleFailure{
			RuntimeStatus: StatusFailed, Drift: "specification_drift", ReadinessFailed: record.Spec.Readiness.Enabled,
		})
	}
	completion := LifecycleCompletion{Runtime: runtime, IncrementGeneration: true}
	if record.Spec.Readiness.Enabled {
		if c.checker == nil {
			err = fmt.Errorf("%w: runtime manager does not implement readiness validation", ErrRuntimeNotReady)
		} else {
			var report ReadinessReport
			report, err = c.checker.ValidateReadiness(ctx, runtime, record.Spec)
			if err == nil {
				completion.Readiness = &report
			}
		}
		if err != nil {
			return c.failAfterMutation(record, LifecycleOperationRebuild, err, LifecycleFailure{
				RuntimeStatus:   runtime.Status,
				Drift:           "readiness_failed",
				ReadinessFailed: true,
			})
		}
		if completion.Readiness != nil && (completion.Readiness.InventoryDigest != record.Spec.Readiness.InventoryDigest || completion.Readiness.ToolCount != len(record.Spec.Readiness.Inventory.Tools)) {
			err = fmt.Errorf("%w: readiness report does not match immutable inventory", ErrRuntimeNotReady)
			return c.failAfterMutation(record, LifecycleOperationRebuild, err, LifecycleFailure{
				RuntimeStatus: runtime.Status, Drift: "readiness_failed", ReadinessFailed: true,
			})
		}
	}
	return c.complete(record, LifecycleOperationRebuild, completion)
}

func (c *LifecycleController) Delete(ctx context.Context, conversationID string, removeWorkspace bool) error {
	record, err := c.prepare(ctx, conversationID, LifecycleOperationDelete, false)
	if err != nil {
		return err
	}
	missing, err := c.verifyBeforeMutation(ctx, record, true)
	if err != nil {
		_, failErr := c.failAfterMutation(record, LifecycleOperationDelete, err, LifecycleFailure{RuntimeStatus: StatusFailed, Drift: lifecycleDriftForError(err)})
		return errors.Join(err, failErr)
	}
	if missing {
		writeCtx, cancel := lifecycleWriteContext()
		defer cancel()
		return c.store.DeleteLifecycle(writeCtx, record.ConversationID, LifecycleOperationDelete)
	}
	err = c.manager.Delete(ctx, record.RuntimeID, DeleteOptions{RemoveWorkspace: removeWorkspace})
	if err != nil && !errors.Is(err, ErrNotFound) {
		_, failErr := c.failAfterMutation(record, LifecycleOperationDelete, err, LifecycleFailure{RuntimeStatus: record.RuntimeStatus})
		return errors.Join(err, failErr)
	}
	writeCtx, cancel := lifecycleWriteContext()
	defer cancel()
	if err := c.store.DeleteLifecycle(writeCtx, record.ConversationID, LifecycleOperationDelete); err != nil {
		return err
	}
	return nil
}

// Reconcile compares the durable desired record with the engine-observed
// container. Missing or security-drifted providers are persisted as failed
// state and returned as a successful reconciliation result for the UI.
func (c *LifecycleController) Reconcile(ctx context.Context, conversationID string) (InitializationRecord, error) {
	record, err := c.prepare(ctx, conversationID, LifecycleOperationReconcile, false)
	if err != nil {
		return record, err
	}
	runtime, inspectErr := c.manager.Inspect(ctx, record.RuntimeID)
	if inspectErr != nil {
		switch {
		case errors.Is(inspectErr, ErrNotFound):
			return c.failObserved(record, "provider_missing", "容器引擎中不存在对应运行时")
		case errors.Is(inspectErr, ErrRuntimeStateConflict):
			return c.failObserved(record, "security_baseline_drift", "容器所有权或安全基线与控制面不一致")
		default:
			return c.failAfterMutation(record, LifecycleOperationReconcile, inspectErr, LifecycleFailure{
				RuntimeStatus: record.RuntimeStatus,
				Drift:         "inspection_failed",
			})
		}
	}
	if err := validateObservedRuntime(record, runtime); err != nil {
		return c.failObserved(record, "specification_drift", "容器身份或镜像与不可变运行时规格不一致")
	}
	drifts := make([]string, 0, 2)
	if record.ProviderID != "" && record.ProviderID != runtime.ProviderID {
		drifts = append(drifts, "provider_replaced")
	}
	if record.RuntimeStatus != "" && record.RuntimeStatus != runtime.Status {
		drifts = append(drifts, "runtime_state_changed")
	}
	return c.complete(record, LifecycleOperationReconcile, LifecycleCompletion{
		Runtime: runtime,
		Drift:   strings.Join(drifts, ","),
	})
}

// Recover resolves interrupted lifecycle operations and reconciles every
// durable created runtime once during application startup.
func (c *LifecycleController) Recover(ctx context.Context) error {
	if c == nil || c.store == nil {
		return fmt.Errorf("%w: lifecycle controller is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return invalidSpec("context is required")
	}
	records, err := c.store.RecoverLifecycle(ctx)
	if err != nil {
		return err
	}
	var recoveryErrors []error
	for _, record := range records {
		if ctx.Err() != nil {
			recoveryErrors = append(recoveryErrors, ctx.Err())
			break
		}
		if record.LifecycleOperation == LifecycleOperationDelete && record.LifecycleState == LifecycleFailed {
			if deleteErr := c.Delete(ctx, record.ConversationID, false); deleteErr != nil {
				recoveryErrors = append(recoveryErrors, fmt.Errorf("recover delete %s: %w", record.ConversationID, deleteErr))
			}
			continue
		}
		if _, reconcileErr := c.Reconcile(ctx, record.ConversationID); reconcileErr != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("reconcile %s: %w", record.ConversationID, reconcileErr))
		}
	}
	return errors.Join(recoveryErrors...)
}

func (c *LifecycleController) prepare(ctx context.Context, conversationID string, operation LifecycleOperation, requireReady bool) (InitializationRecord, error) {
	if c == nil || c.manager == nil || c.store == nil {
		return InitializationRecord{}, fmt.Errorf("%w: lifecycle controller is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return InitializationRecord{}, invalidSpec("context is required")
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return InitializationRecord{}, invalidSpec("conversation id is required")
	}
	record, err := c.store.Get(ctx, conversationID)
	if err != nil {
		return record, err
	}
	if record.Status != InitializationCreated {
		return record, fmt.Errorf("%w: runtime initialization is %s", ErrRuntimeStateConflict, record.Status)
	}
	if requireReady && record.ReadinessStatus != ReadinessNotRequired && record.ReadinessStatus != ReadinessReady {
		return record, fmt.Errorf("%w: runtime readiness is %s", ErrRuntimeNotReady, record.ReadinessStatus)
	}
	if (operation == LifecycleOperationRebuild || operation == LifecycleOperationDelete) && (record.ReadinessStatus == ReadinessPending || record.ReadinessStatus == ReadinessValidating) {
		return record, fmt.Errorf("%w: runtime readiness validation is still in progress", ErrRuntimeStateConflict)
	}
	return c.store.BeginLifecycle(ctx, conversationID, operation)
}

func validateObservedRuntime(record InitializationRecord, runtime Runtime) error {
	if runtime.ID != record.RuntimeID || runtime.ConversationID != record.ConversationID ||
		runtime.Image.Digest != record.Spec.Image.Digest || runtime.Image.Platform != record.Spec.Image.Platform ||
		runtime.SpecDigest != RuntimeSpecDigest(record.Spec) {
		return fmt.Errorf("%w: engine runtime does not match the durable immutable specification", ErrRuntimeStateConflict)
	}
	return nil
}

func (c *LifecycleController) verifyBeforeMutation(ctx context.Context, record InitializationRecord, allowMissing bool) (bool, error) {
	runtime, err := c.manager.Inspect(ctx, record.RuntimeID)
	if err != nil {
		if allowMissing && errors.Is(err, ErrNotFound) {
			return true, nil
		}
		return false, err
	}
	return false, validateObservedRuntime(record, runtime)
}

func lifecycleDriftForError(err error) string {
	if errors.Is(err, ErrRuntimeStateConflict) {
		return "security_or_specification_drift"
	}
	if errors.Is(err, ErrNotFound) {
		return "provider_missing"
	}
	return "inspection_failed"
}

func (c *LifecycleController) complete(record InitializationRecord, operation LifecycleOperation, completion LifecycleCompletion) (InitializationRecord, error) {
	writeCtx, cancel := lifecycleWriteContext()
	defer cancel()
	return c.store.CompleteLifecycle(writeCtx, record.ConversationID, operation, completion)
}

func (c *LifecycleController) failAfterMutation(record InitializationRecord, operation LifecycleOperation, cause error, failure LifecycleFailure) (InitializationRecord, error) {
	failure.Message = lifecycleErrorMessage(cause)
	writeCtx, cancel := lifecycleWriteContext()
	defer cancel()
	failed, stateErr := c.store.FailLifecycle(writeCtx, record.ConversationID, operation, failure)
	return failed, errors.Join(cause, stateErr)
}

func (c *LifecycleController) failObserved(record InitializationRecord, drift, message string) (InitializationRecord, error) {
	writeCtx, cancel := lifecycleWriteContext()
	defer cancel()
	return c.store.FailLifecycle(writeCtx, record.ConversationID, LifecycleOperationReconcile, LifecycleFailure{
		Message:       message,
		RuntimeStatus: StatusFailed,
		Drift:         drift,
	})
}

func lifecycleWriteContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), initializationStateWriteTimeout)
}

func lifecycleErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > 1024 {
		message = message[:1024]
	}
	return message
}
