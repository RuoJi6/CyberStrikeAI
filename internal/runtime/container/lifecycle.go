package container

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
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
type egressRebuildRouteContextKey struct{}
type runtimeControlsContextKey struct{}

type egressRebuildRouteContext struct {
	Present bool
	Route   *EgressUpstreamRouteSpec
}

type runtimeControlsContext struct {
	Resources     ResourceLimits
	TrafficLimits *EgressTrafficLimits
}

// WithRuntimeControls authorizes an explicit rebuild to replace only the
// Agent CPU/memory values and optional gateway traffic limits. All other hard
// resource and security controls remain inherited from platform policy.
func WithRuntimeControls(ctx context.Context, resources ResourceLimits, traffic *EgressTrafficLimits) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	value := runtimeControlsContext{Resources: resources}
	if traffic != nil {
		copy := *traffic
		value.TrafficLimits = &copy
	}
	return context.WithValue(ctx, runtimeControlsContextKey{}, value)
}

func applyRuntimeControlsFromContext(ctx context.Context, spec *RuntimeSpec) {
	if ctx == nil || spec == nil {
		return
	}
	value, ok := ctx.Value(runtimeControlsContextKey{}).(runtimeControlsContext)
	if !ok {
		return
	}
	spec.Resources.NanoCPUs = value.Resources.NanoCPUs
	spec.Resources.MemoryBytes = value.Resources.MemoryBytes
	if spec.EgressGateway != nil {
		gateway := *spec.EgressGateway
		gateway.TrafficLimits = value.TrafficLimits
		spec.EgressGateway = &gateway
	}
}

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

// WithEgressRebuildRoute authorizes one staged upstream route replacement.
// A nil route is meaningful and switches the rebuilt gateway to direct egress.
func WithEgressRebuildRoute(ctx context.Context, route *EgressUpstreamRouteSpec) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	value := egressRebuildRouteContext{Present: true}
	if route != nil {
		copy := *route
		value.Route = &copy
	}
	return context.WithValue(ctx, egressRebuildRouteContextKey{}, value)
}

func EgressRebuildRouteFromContext(ctx context.Context) (*EgressUpstreamRouteSpec, bool) {
	if ctx == nil {
		return nil, false
	}
	value, ok := ctx.Value(egressRebuildRouteContextKey{}).(egressRebuildRouteContext)
	if !ok || !value.Present {
		return nil, false
	}
	if value.Route == nil {
		return nil, true
	}
	copy := *value.Route
	return &copy, true
}

// LifecycleStore is the durable compare-and-swap boundary for runtime
// mutations. Implementations must reject a second operation while one is in
// progress so multiple API processes cannot mutate the same container.
type LifecycleStore interface {
	Get(ctx context.Context, conversationID string) (InitializationRecord, error)
	BeginLifecycle(ctx context.Context, conversationID string, operation LifecycleOperation) (InitializationRecord, error)
	BeginIdleStop(ctx context.Context, conversationID string, inactiveBefore time.Time) (InitializationRecord, error)
	BeginIdleAction(ctx context.Context, candidate IdleRuntimeCandidate, now time.Time) (InitializationRecord, error)
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

type AuthProfilesProvider interface {
	ResolveAuthProfiles(ctx context.Context, conversationID, snapshotID string) (*EgressAuthProfilesSpec, error)
}

type TLSAuthorityProvider interface {
	ResolveTLSAuthority(ctx context.Context, conversationID, snapshotID string) (*EgressTLSAuthoritySpec, error)
}

// LifecycleController coordinates Docker mutations with durable control-plane
// state. It never accepts a provider/container ID from a handler.
type LifecycleController struct {
	manager        RuntimeManager
	checker        RuntimeReadinessChecker
	store          LifecycleStore
	egressGateway  *EgressGatewaySpec
	snapshots      BoundarySnapshotProvider
	authProfiles   AuthProfilesProvider
	tlsAuthorities TLSAuthorityProvider
}

type LifecycleControllerOptions struct {
	// EgressGateway is trusted deployment policy used to upgrade a durable
	// pre-gateway runtime, or refresh the pinned gateway image and resources,
	// during an explicit rebuild. The active immutable boundary/route bindings
	// remain attached to the conversation.
	EgressGateway *EgressGatewaySpec
	// BoundarySnapshots is optional for legacy/unit-test controllers. Production
	// supplies it so explicit rebuilds can bind the current immutable snapshot.
	BoundarySnapshots BoundarySnapshotProvider
	AuthProfiles      AuthProfilesProvider
	TLSAuthorities    TLSAuthorityProvider
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
		egressGateway: gateway, snapshots: options.BoundarySnapshots, authProfiles: options.AuthProfiles,
		tlsAuthorities: options.TLSAuthorities,
	}, nil
}

func (c *LifecycleController) Start(ctx context.Context, conversationID string) (InitializationRecord, error) {
	record, err := c.prepare(ctx, conversationID, LifecycleOperationStart, true)
	if err != nil {
		return record, err
	}
	operationCtx := context.WithoutCancel(ctx)
	if _, err := c.verifyBeforeMutation(operationCtx, record, false); err != nil {
		return c.failAfterMutation(record, LifecycleOperationStart, err, LifecycleFailure{RuntimeStatus: StatusFailed, Drift: lifecycleDriftForError(err)})
	}
	runtime, err := c.manager.Start(operationCtx, record.RuntimeID)
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

// ApplyIdle atomically claims and executes the per-conversation idle policy.
// Automatic deletion always retains named workspaces; an ephemeral tmpfs is
// removed together with the containers by Docker.
func (c *LifecycleController) ApplyIdle(ctx context.Context, candidate IdleRuntimeCandidate, now time.Time) (InitializationRecord, error) {
	if ctx == nil || now.IsZero() {
		return InitializationRecord{}, invalidSpec("context and idle evaluation time are required")
	}
	if candidate.Action != "stop" && candidate.Action != "delete" {
		return InitializationRecord{}, invalidSpec("idle action must be stop or delete")
	}
	record, err := c.store.BeginIdleAction(ctx, candidate, now.UTC())
	if err != nil {
		return record, err
	}
	if candidate.Action == "stop" {
		return c.stopPrepared(ctx, record)
	}
	operationCtx := context.WithoutCancel(ctx)
	_, err = c.verifyBeforeMutation(operationCtx, record, true)
	if err != nil {
		_, failErr := c.failAfterMutation(record, LifecycleOperationDelete, err, LifecycleFailure{RuntimeStatus: StatusFailed, Drift: lifecycleDriftForError(err)})
		return record, errors.Join(err, failErr)
	}
	if err = c.stopRuntimeBeforeDelete(operationCtx, record); err != nil && !errors.Is(err, ErrNotFound) {
		_, failErr := c.failAfterMutation(record, LifecycleOperationDelete, err, LifecycleFailure{RuntimeStatus: record.RuntimeStatus})
		return record, errors.Join(err, failErr)
	}
	err = c.manager.Delete(operationCtx, record.RuntimeID, DeleteOptions{RemoveWorkspace: false})
	if err != nil && !errors.Is(err, ErrNotFound) {
		_, failErr := c.failAfterMutation(record, LifecycleOperationDelete, err, LifecycleFailure{RuntimeStatus: record.RuntimeStatus})
		return record, errors.Join(err, failErr)
	}
	writeCtx, cancel := lifecycleWriteContext()
	defer cancel()
	if err := c.store.DeleteLifecycle(writeCtx, record.ConversationID, LifecycleOperationDelete); err != nil {
		return record, err
	}
	return record, nil
}

func (c *LifecycleController) stopPrepared(ctx context.Context, record InitializationRecord) (InitializationRecord, error) {
	operationCtx := context.WithoutCancel(ctx)
	if _, err := c.verifyBeforeMutation(operationCtx, record, false); err != nil {
		return c.failAfterMutation(record, LifecycleOperationStop, err, LifecycleFailure{RuntimeStatus: StatusFailed, Drift: lifecycleDriftForError(err)})
	}
	runtime, err := c.manager.Stop(operationCtx, record.RuntimeID, StopOptions{})
	if err != nil {
		failure := LifecycleFailure{RuntimeStatus: record.RuntimeStatus}
		if validateObservedRuntime(record, runtime) == nil {
			failure.RuntimeStatus = runtime.Status
		}
		return c.failAfterMutation(record, LifecycleOperationStop, err, failure)
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
	operationCtx := context.WithoutCancel(ctx)
	if _, err := c.verifyBeforeMutation(operationCtx, record, true); err != nil {
		return c.failAfterMutation(record, LifecycleOperationRebuild, err, LifecycleFailure{
			RuntimeStatus: StatusFailed, Drift: lifecycleDriftForError(err), ReadinessFailed: record.Spec.Readiness.Enabled,
		})
	}
	target := record
	target.Spec, err = c.upgradeRuntimeSpec(operationCtx, target.Spec, BoundaryRebuildSnapshotFromContext(operationCtx))
	if err != nil {
		return c.failAfterMutation(record, LifecycleOperationRebuild, err, LifecycleFailure{
			RuntimeStatus: record.RuntimeStatus, Drift: "boundary_snapshot_unavailable", ReadinessFailed: record.Spec.Readiness.Enabled,
		})
	}
	if target.Spec.EgressGateway != nil && strings.TrimSpace(target.Spec.EgressGateway.AttributionPublicKey) != "" {
		gateway := *target.Spec.EgressGateway
		gateway.AttributionRuntimeGeneration = record.RuntimeGeneration + 1
		gateway.AttributionInstanceID = uuid.NewString()
		if gateway.BoundarySnapshot != nil {
			snapshot := *gateway.BoundarySnapshot
			snapshot.RuntimeGeneration = gateway.AttributionRuntimeGeneration
			gateway.BoundarySnapshot = &snapshot
		}
		target.Spec.EgressGateway = &gateway
	}
	runtime, err := c.manager.Rebuild(operationCtx, record.RuntimeID, RebuildOptions{
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
			report, err = c.checker.ValidateReadiness(operationCtx, runtime, target.Spec)
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
	operationCtx := context.WithoutCancel(ctx)
	missing, err := c.verifyBeforeMutation(operationCtx, record, true)
	if err != nil {
		_, failErr := c.failAfterMutation(record, LifecycleOperationDelete, err, LifecycleFailure{RuntimeStatus: StatusFailed, Drift: lifecycleDriftForError(err)})
		return errors.Join(err, failErr)
	}
	if missing {
		// The provider may have disappeared after a partial delete. Give the
		// manager one final ownership-checked chance to remove its conversation
		// network and, when requested, its named workspace volume.
		if deleteErr := c.manager.Delete(operationCtx, record.RuntimeID, DeleteOptions{RemoveWorkspace: removeWorkspace}); deleteErr != nil && !errors.Is(deleteErr, ErrNotFound) {
			_, failErr := c.failAfterMutation(record, LifecycleOperationDelete, deleteErr, LifecycleFailure{RuntimeStatus: StatusFailed, Drift: lifecycleDriftForError(deleteErr)})
			return errors.Join(deleteErr, failErr)
		}
		writeCtx, cancel := lifecycleWriteContext()
		defer cancel()
		return c.store.DeleteLifecycle(writeCtx, record.ConversationID, LifecycleOperationDelete)
	}
	if err = c.stopRuntimeBeforeDelete(operationCtx, record); err != nil {
		_, failErr := c.failAfterMutation(record, LifecycleOperationDelete, err, LifecycleFailure{RuntimeStatus: record.RuntimeStatus})
		return errors.Join(err, failErr)
	}
	err = c.manager.Delete(operationCtx, record.RuntimeID, DeleteOptions{RemoveWorkspace: removeWorkspace})
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
	operationCtx := context.WithoutCancel(ctx)
	runtime, inspectErr := inspectLifecycleRuntime(c.manager, operationCtx, record.RuntimeID)
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
		target.Spec, err = c.upgradeRuntimeSpec(operationCtx, target.Spec, "")
		incrementGeneration := false
		if err == nil {
			incrementGeneration = adoptObservedAttributionBinding(&target.Spec, runtime.Spec, record.RuntimeGeneration)
		}
		if err == nil && RuntimeSpecDigest(target.Spec) != RuntimeSpecDigest(record.Spec) && validateObservedRuntime(target, runtime) == nil {
			replacement := target.Spec
			return c.complete(record, LifecycleOperationReconcile, LifecycleCompletion{
				Runtime: runtime, Drift: "topology_migration_recovered", ReplacementSpec: &replacement,
				IncrementGeneration: incrementGeneration,
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

// adoptObservedAttributionBinding recovers only the non-deterministic binding
// produced by a rebuild that reached the engine before its database commit.
// The remaining observed specification must still exactly match the trusted
// upgrade candidate and pass the database's controlled-replacement checks.
func adoptObservedAttributionBinding(target, observed *RuntimeSpec, currentGeneration int) bool {
	if target == nil || observed == nil || target.EgressGateway == nil || observed.EgressGateway == nil {
		return false
	}
	targetGateway, observedGateway := *target.EgressGateway, observed.EgressGateway
	if strings.TrimSpace(targetGateway.AttributionPublicKey) == "" ||
		targetGateway.AttributionPublicKey != observedGateway.AttributionPublicKey ||
		observedGateway.AttributionRuntimeGeneration != currentGeneration+1 ||
		strings.TrimSpace(observedGateway.AttributionInstanceID) == "" ||
		targetGateway.BoundarySnapshot == nil || observedGateway.BoundarySnapshot == nil ||
		targetGateway.BoundarySnapshot.ID != observedGateway.BoundarySnapshot.ID ||
		targetGateway.BoundarySnapshot.SHA256 != observedGateway.BoundarySnapshot.SHA256 ||
		observedGateway.BoundarySnapshot.RuntimeGeneration != observedGateway.AttributionRuntimeGeneration {
		return false
	}
	targetGateway.AttributionRuntimeGeneration = observedGateway.AttributionRuntimeGeneration
	targetGateway.AttributionInstanceID = observedGateway.AttributionInstanceID
	snapshot := *targetGateway.BoundarySnapshot
	snapshot.RuntimeGeneration = observedGateway.BoundarySnapshot.RuntimeGeneration
	targetGateway.BoundarySnapshot = &snapshot
	target.EgressGateway = &targetGateway
	return true
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
	requestedRoute, replaceRoute := EgressRebuildRouteFromContext(ctx)
	if spec.Security.NetworkMode == NetworkNone {
		spec.Security.NetworkMode = NetworkInternal
	}
	if spec.EgressGateway == nil && c != nil && c.egressGateway != nil {
		gateway := *c.egressGateway
		spec.EgressGateway = &gateway
	}
	if spec.EgressGateway == nil || c == nil || c.snapshots == nil {
		applyRuntimeControlsFromContext(ctx, &spec)
		if err := ValidateSpec(spec); err != nil {
			return RuntimeSpec{}, err
		}
		return spec, nil
	}
	if strings.TrimSpace(requestedSnapshotID) == "" && spec.EgressGateway.BoundarySnapshot != nil {
		// A maintenance rebuild is the explicit rollout boundary for a newer
		// pinned gateway image or safer resource limits. Preserve the immutable
		// policy/route/auth bindings from the durable conversation spec.
		if c.egressGateway != nil {
			current := *spec.EgressGateway
			gateway := *c.egressGateway
			gateway.BoundarySnapshot = current.BoundarySnapshot
			gateway.UpstreamRoute = current.UpstreamRoute
			gateway.AuthProfiles = current.AuthProfiles
			gateway.TLSAuthority = current.TLSAuthority
			// The configured gateway is a template and therefore has no runtime
			// attribution binding. Preserve the current binding long enough for
			// this intermediate specification to validate. Rebuild rotates it to
			// the next generation and a fresh instance ID before engine mutation.
			gateway.AttributionRuntimeGeneration = current.AttributionRuntimeGeneration
			gateway.AttributionInstanceID = current.AttributionInstanceID
			spec.EgressGateway = &gateway
		}
		if c.authProfiles != nil {
			authProfiles, err := c.authProfiles.ResolveAuthProfiles(ctx, spec.ConversationID, "")
			if err != nil {
				return RuntimeSpec{}, fmt.Errorf("resolve gateway auth profiles: %w", err)
			}
			gateway := *spec.EgressGateway
			gateway.AuthProfiles = authProfiles
			spec.EgressGateway = &gateway
		}
		if c.tlsAuthorities != nil {
			authority, err := c.tlsAuthorities.ResolveTLSAuthority(ctx, spec.ConversationID, "")
			if err != nil {
				return RuntimeSpec{}, fmt.Errorf("resolve gateway TLS authority: %w", err)
			}
			gateway := *spec.EgressGateway
			gateway.TLSAuthority = authority
			spec.EgressGateway = &gateway
		}
		if replaceRoute {
			gateway := *spec.EgressGateway
			gateway.UpstreamRoute = requestedRoute
			spec.EgressGateway = &gateway
		}
		ensureBoundGatewayAttribution(&spec)
		applyRuntimeControlsFromContext(ctx, &spec)
		if err := ValidateSpec(spec); err != nil {
			return RuntimeSpec{}, err
		}
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
	if replaceRoute {
		gateway.UpstreamRoute = requestedRoute
	}
	if c.authProfiles != nil {
		authProfiles, authErr := c.authProfiles.ResolveAuthProfiles(ctx, spec.ConversationID, requestedSnapshotID)
		if authErr != nil {
			return RuntimeSpec{}, fmt.Errorf("resolve gateway auth profiles: %w", authErr)
		}
		gateway.AuthProfiles = authProfiles
	}
	if c.tlsAuthorities != nil {
		authority, authorityErr := c.tlsAuthorities.ResolveTLSAuthority(ctx, spec.ConversationID, requestedSnapshotID)
		if authorityErr != nil {
			return RuntimeSpec{}, fmt.Errorf("resolve gateway TLS authority: %w", authorityErr)
		}
		gateway.TLSAuthority = authority
	}
	spec.EgressGateway = &gateway
	ensureBoundGatewayAttribution(&spec)
	applyRuntimeControlsFromContext(ctx, &spec)
	if err := ValidateSpec(spec); err != nil {
		return RuntimeSpec{}, err
	}
	return spec, nil
}

// ensureBoundGatewayAttribution makes an intermediate, snapshot-bound upgrade
// specification valid before Rebuild assigns the authoritative next runtime
// generation and rotates the instance ID. It also permits an explicit rebuild
// to migrate a legacy gateway to signed attribution without weakening the
// validator for specifications that reach the container engine.
func ensureBoundGatewayAttribution(spec *RuntimeSpec) {
	if spec == nil || spec.EgressGateway == nil {
		return
	}
	gateway := *spec.EgressGateway
	if strings.TrimSpace(gateway.AttributionPublicKey) == "" || gateway.BoundarySnapshot == nil {
		return
	}
	if gateway.AttributionRuntimeGeneration < 1 {
		gateway.AttributionRuntimeGeneration = gateway.BoundarySnapshot.RuntimeGeneration
		if gateway.AttributionRuntimeGeneration < 1 {
			gateway.AttributionRuntimeGeneration = 1
		}
	}
	if strings.TrimSpace(gateway.AttributionInstanceID) == "" {
		gateway.AttributionInstanceID = uuid.NewString()
	}
	spec.EgressGateway = &gateway
}

func (c *LifecycleController) verifyBeforeMutation(ctx context.Context, record InitializationRecord, allowMissing bool) (bool, error) {
	runtime, err := inspectLifecycleRuntime(c.manager, ctx, record.RuntimeID)
	if err != nil {
		if allowMissing && errors.Is(err, ErrNotFound) {
			return true, nil
		}
		return false, err
	}
	return false, validateObservedRuntime(record, runtime)
}

type lifecycleRuntimeInspector interface {
	InspectLifecycle(context.Context, RuntimeID) (Runtime, error)
}

func inspectLifecycleRuntime(manager RuntimeManager, ctx context.Context, id RuntimeID) (Runtime, error) {
	if inspector, ok := manager.(lifecycleRuntimeInspector); ok {
		return inspector.InspectLifecycle(ctx, id)
	}
	return manager.Inspect(ctx, id)
}

func (c *LifecycleController) stopRuntimeBeforeDelete(ctx context.Context, record InitializationRecord) error {
	runtime, err := inspectLifecycleRuntime(c.manager, ctx, record.RuntimeID)
	if err != nil {
		return err
	}
	if err := validateObservedRuntime(record, runtime); err != nil {
		return err
	}
	switch runtime.Status {
	case StatusStopped, StatusFailed:
		return nil
	case StatusRunning, StatusStarting:
		stopped, stopErr := c.manager.Stop(ctx, record.RuntimeID, StopOptions{})
		if stopErr != nil {
			return stopErr
		}
		if err := validateObservedRuntime(record, stopped); err != nil {
			return err
		}
		if stopped.Status != StatusStopped {
			return fmt.Errorf("%w: runtime %s did not stop before deletion", ErrRuntimeStateConflict, record.RuntimeID)
		}
		return nil
	default:
		return fmt.Errorf("%w: runtime %s cannot be deleted from %s", ErrRuntimeStateConflict, record.RuntimeID, runtime.Status)
	}
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
