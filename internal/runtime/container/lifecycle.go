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
	// ReplacementSpec is set only for a controlled legacy topology upgrade
	// performed by Rebuild or recovered by Reconcile.
	ReplacementSpec *RuntimeSpec
}

type LifecycleFailure struct {
	Message         string
	RuntimeStatus   Status
	Drift           string
	ReadinessFailed bool
	// AppliedRuntime and ReplacementSpec keep the durable specification aligned
	// when Docker completed the controlled topology migration but readiness did
	// not. They must either both be nil or both describe the same runtime.
	AppliedRuntime  *Runtime
	ReplacementSpec *RuntimeSpec
}

type boundaryRebuildSnapshotContextKey struct{}

// WithBoundaryRebuildSnapshot binds one prepared immutable snapshot to the
// explicit rebuild request that is allowed to activate it.
func WithBoundaryRebuildSnapshot(ctx context.Context, snapshotID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, boundaryRebuildSnapshotContextKey{}, strings.TrimSpace(snapshotID))
}

func BoundaryRebuildSnapshotFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(boundaryRebuildSnapshotContextKey{}).(string)
	return strings.TrimSpace(value)
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

// BoundarySnapshotProvider resolves only the active snapshot, or the exact
// pending snapshot already authorized by an explicit rebuild context. The
// implementation also materializes the trusted read-only gateway file.
type BoundarySnapshotProvider interface {
	ResolveBoundarySnapshot(ctx context.Context, conversationID, snapshotID string) (EgressBoundarySnapshotSpec, error)
}

// LifecycleController coordinates Docker mutations with durable control-plane
// state. It never accepts a provider/container ID from a handler.
type LifecycleController struct {
	manager       RuntimeManager
	checker       RuntimeReadinessChecker
	store         LifecycleStore
	egressGateway *EgressGatewaySpec
	snapshots     BoundarySnapshotProvider
}

type LifecycleControllerOptions struct {
	// EgressGateway is trusted deployment policy used only to upgrade a durable
	// pre-gateway runtime during an explicit rebuild. New runtime records already
	// contain the same immutable specification.
	EgressGateway *EgressGatewaySpec
	// BoundarySnapshots is optional for legacy/unit-test controllers. Production
	// supplies it so explicit rebuilds can bind the current immutable snapshot.
	BoundarySnapshots BoundarySnapshotProvider
}

func NewLifecycleController(manager RuntimeManager, store LifecycleStore) (*LifecycleController, error) {
	return NewLifecycleControllerWithOptions(manager, store, LifecycleControllerOptions{})
}

func NewLifecycleControllerWithOptions(manager RuntimeManager, store LifecycleStore, options LifecycleControllerOptions) (*LifecycleController, error) {
	if manager == nil || store == nil {
		return nil, invalidSpec("lifecycle controller requires a runtime manager and durable store")
	}
	var gateway *EgressGatewaySpec
	if options.EgressGateway != nil {
		if err := ValidateEgressGatewaySpec(*options.EgressGateway); err != nil {
			return nil, err
		}
		copy := *options.EgressGateway
		gateway = &copy
	}
	checker, _ := manager.(RuntimeReadinessChecker)
	return &LifecycleController{
		manager: manager, checker: checker, store: store,
		egressGateway: gateway, snapshots: options.BoundarySnapshots,
	}, nil
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
	target := record
	target.Spec, err = c.upgradeRuntimeSpec(ctx, target.Spec, BoundaryRebuildSnapshotFromContext(ctx))
	if err != nil {
		return c.failAfterMutation(record, LifecycleOperationRebuild, err, LifecycleFailure{
			RuntimeStatus: record.RuntimeStatus, Drift: "boundary_snapshot_unavailable", ReadinessFailed: record.Spec.Readiness.Enabled,
		})
	}
	runtime, err := c.manager.Rebuild(ctx, record.RuntimeID, RebuildOptions{
		Spec:                          target.Spec,
		AuthorizedWorkspaceSpecDigest: RuntimeSpecDigest(record.Spec),
	})
	if err != nil {
		return c.failAfterMutation(record, LifecycleOperationRebuild, err, LifecycleFailure{
			RuntimeStatus:   StatusFailed,
			Drift:           "rebuild_incomplete",
			ReadinessFailed: record.Spec.Readiness.Enabled,
		})
	}
	if err := validateObservedRuntime(target, runtime); err != nil {
		return c.failAfterMutation(record, LifecycleOperationRebuild, err, LifecycleFailure{
			RuntimeStatus: StatusFailed, Drift: "specification_drift", ReadinessFailed: record.Spec.Readiness.Enabled,
		})
	}
	completion := LifecycleCompletion{Runtime: runtime, IncrementGeneration: true}
	if RuntimeSpecDigest(target.Spec) != RuntimeSpecDigest(record.Spec) {
		replacement := target.Spec
		completion.ReplacementSpec = &replacement
	}
	if target.Spec.Readiness.Enabled {
		if c.checker == nil {
			err = fmt.Errorf("%w: runtime manager does not implement readiness validation", ErrRuntimeNotReady)
		} else {
			var report ReadinessReport
			report, err = c.checker.ValidateReadiness(ctx, runtime, target.Spec)
			if err == nil {
				completion.Readiness = &report
			}
		}
		if err != nil {
			failure := lifecycleFailureAfterRebuild(record, target, runtime, "readiness_failed")
			return c.failAfterMutation(record, LifecycleOperationRebuild, err, failure)
		}
		if completion.Readiness != nil && (completion.Readiness.InventoryDigest != target.Spec.Readiness.InventoryDigest || completion.Readiness.ToolCount != len(target.Spec.Readiness.Inventory.Tools)) {
			err = fmt.Errorf("%w: readiness report does not match immutable inventory", ErrRuntimeNotReady)
			failure := lifecycleFailureAfterRebuild(record, target, runtime, "readiness_failed")
			return c.failAfterMutation(record, LifecycleOperationRebuild, err, failure)
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
		// The provider may have disappeared after a partial delete. Give the
		// manager one final ownership-checked chance to remove its conversation
		// network and, when requested, its named workspace volume.
		if deleteErr := c.manager.Delete(ctx, record.RuntimeID, DeleteOptions{RemoveWorkspace: removeWorkspace}); deleteErr != nil && !errors.Is(deleteErr, ErrNotFound) {
			_, failErr := c.failAfterMutation(record, LifecycleOperationDelete, deleteErr, LifecycleFailure{RuntimeStatus: StatusFailed, Drift: lifecycleDriftForError(deleteErr)})
			return errors.Join(deleteErr, failErr)
		}
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

// DeleteRetainedWorkspace removes the ownership-checked named volume after a
// container lifecycle record has already been deleted. This is the explicit
// "delete conversation and workspace" path; a missing volume is idempotent.
func (c *LifecycleController) DeleteRetainedWorkspace(ctx context.Context, conversationID string) error {
	if c == nil || c.manager == nil {
		return fmt.Errorf("%w: lifecycle controller is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return invalidSpec("context is required")
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return invalidSpec("conversation id is required")
	}
	runtimeID := RuntimeID("conversation-" + conversationID)
	if err := validateRuntimeID(runtimeID); err != nil {
		return err
	}
	err := c.manager.Delete(ctx, runtimeID, DeleteOptions{RemoveWorkspace: true})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
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
		// A process can stop after Docker created an upgraded provider but before
		// the lifecycle completion transaction committed. Adopt only the exact
		// configured topology transition; every other mismatch remains fail-closed.
		target := record
		target.Spec, err = c.upgradeRuntimeSpec(ctx, target.Spec, "")
		if err == nil && RuntimeSpecDigest(target.Spec) != RuntimeSpecDigest(record.Spec) && validateObservedRuntime(target, runtime) == nil {
			replacement := target.Spec
			return c.complete(record, LifecycleOperationReconcile, LifecycleCompletion{
				Runtime: runtime, Drift: "topology_migration_recovered", ReplacementSpec: &replacement,
			})
		}
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

func lifecycleFailureAfterRebuild(original, target InitializationRecord, runtime Runtime, drift string) LifecycleFailure {
	failure := LifecycleFailure{RuntimeStatus: runtime.Status, Drift: drift, ReadinessFailed: true}
	if RuntimeSpecDigest(original.Spec) != RuntimeSpecDigest(target.Spec) {
		applied := runtime
		replacement := target.Spec
		failure.AppliedRuntime = &applied
		failure.ReplacementSpec = &replacement
	}
	return failure
}

func (c *LifecycleController) upgradeRuntimeSpec(ctx context.Context, spec RuntimeSpec, requestedSnapshotID string) (RuntimeSpec, error) {
	if spec.Security.NetworkMode == NetworkNone {
		spec.Security.NetworkMode = NetworkInternal
	}
	if spec.EgressGateway == nil && c != nil && c.egressGateway != nil {
		gateway := *c.egressGateway
		spec.EgressGateway = &gateway
	}
	if spec.EgressGateway == nil || c == nil || c.snapshots == nil {
		return spec, nil
	}
	if strings.TrimSpace(requestedSnapshotID) == "" && spec.EgressGateway.BoundarySnapshot != nil {
		return spec, nil
	}
	if spec.EgressGateway.BoundarySnapshot == nil && c.egressGateway != nil {
		// The first snapshot adoption is also the item-3 gateway upgrade. Use
		// the currently configured pinned image/resources instead of carrying
		// the item-2 bootstrap binary into the snapshot-aware topology.
		gateway := *c.egressGateway
		spec.EgressGateway = &gateway
	}
	snapshot, err := c.snapshots.ResolveBoundarySnapshot(ctx, spec.ConversationID, requestedSnapshotID)
	if err != nil {
		return RuntimeSpec{}, fmt.Errorf("resolve gateway boundary snapshot: %w", err)
	}
	gateway := *spec.EgressGateway
	gateway.BoundarySnapshot = &snapshot
	spec.EgressGateway = &gateway
	if err := ValidateSpec(spec); err != nil {
		return RuntimeSpec{}, err
	}
	return spec, nil
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
