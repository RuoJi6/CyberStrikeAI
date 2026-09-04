// Package containertest provides test-only collaborators for code that depends
// on the container runtime contract. It must never be wired into production.
package containertest

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"cyberstrike-ai/internal/runtime/container"
)

const (
	OperationEngineInfo         = "engine_info"
	OperationInspectManifest    = "inspect_manifest"
	OperationInspectLocalImage  = "inspect_local_image"
	OperationVerifyRuntimeImage = "verify_runtime_image"
	OperationCreate             = "create"
	OperationInspect            = "inspect"
	OperationListOwned          = "list_owned"
	OperationStart              = "start"
	OperationStop               = "stop"
	OperationRebuild            = "rebuild"
	OperationDelete             = "delete"
)

type Call struct {
	Operation string
	RuntimeID container.RuntimeID
}

// FakeManager is an in-memory, concurrency-safe implementation used by unit
// tests for future handlers, persistence and execution routing.
type FakeManager struct {
	mu       sync.Mutex
	engine   container.EngineInfo
	now      func() time.Time
	runtimes map[container.RuntimeID]container.Runtime
	calls    []Call
	failNext map[string]error
}

var _ container.RuntimeManager = (*FakeManager)(nil)

func NewFakeManager(engine container.EngineInfo) *FakeManager {
	return NewFakeManagerWithClock(engine, time.Now)
}

func NewFakeManagerWithClock(engine container.EngineInfo, now func() time.Time) *FakeManager {
	if now == nil {
		now = time.Now
	}
	return &FakeManager{
		engine:   engine,
		now:      now,
		runtimes: make(map[container.RuntimeID]container.Runtime),
		failNext: make(map[string]error),
	}
}

func (f *FakeManager) FailNext(operation string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[operation] = err
}

func (f *FakeManager) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

func (f *FakeManager) EngineInfo(ctx context.Context) (container.EngineInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return container.EngineInfo{}, err
	}
	f.record(OperationEngineInfo, "")
	if err := f.takeFailure(OperationEngineInfo); err != nil {
		return container.EngineInfo{}, err
	}
	if !f.engine.Available {
		return f.engine, container.ErrEngineUnavailable
	}
	return f.engine, nil
}

func (f *FakeManager) InspectManifest(ctx context.Context, image container.ImageReference) (container.ImageInspection, error) {
	return f.inspectImage(ctx, OperationInspectManifest, "", image, false)
}

func (f *FakeManager) InspectLocalImage(ctx context.Context, image container.ImageReference) (container.ImageInspection, error) {
	return f.inspectImage(ctx, OperationInspectLocalImage, "", image, true)
}

func (f *FakeManager) VerifyRuntimeImage(ctx context.Context, providerID string, image container.ImageReference) (container.ImageInspection, error) {
	if providerID == "" {
		return container.ImageInspection{}, fmt.Errorf("%w: provider id is required", container.ErrInvalidSpecification)
	}
	return f.inspectImage(ctx, OperationVerifyRuntimeImage, container.RuntimeID(providerID), image, true)
}

func (f *FakeManager) Create(ctx context.Context, spec container.RuntimeSpec) (container.Runtime, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return container.Runtime{}, err
	}
	f.record(OperationCreate, spec.ID)
	if err := f.takeFailure(OperationCreate); err != nil {
		return container.Runtime{}, err
	}
	if err := container.ValidateSpec(spec); err != nil {
		return container.Runtime{}, err
	}
	if _, exists := f.runtimes[spec.ID]; exists {
		return container.Runtime{}, container.ErrAlreadyExists
	}
	now := f.now().UTC()
	resolvedImage := spec.Image
	resolvedImage.ResolvedDigest = spec.Image.Digest
	runtime := container.Runtime{
		ID:             spec.ID,
		ConversationID: spec.ConversationID,
		ProviderID:     "fake-" + string(spec.ID),
		Image:          resolvedImage,
		Status:         container.StatusStopped,
		CreatedAt:      now,
		UpdatedAt:      now,
		SpecDigest:     container.RuntimeSpecDigest(spec),
		Spec:           &spec,
	}
	f.runtimes[spec.ID] = runtime
	return runtime, nil
}

func (f *FakeManager) Inspect(ctx context.Context, id container.RuntimeID) (container.Runtime, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return container.Runtime{}, err
	}
	f.record(OperationInspect, id)
	if err := f.takeFailure(OperationInspect); err != nil {
		return container.Runtime{}, err
	}
	return f.runtime(id)
}

func (f *FakeManager) ListOwned(ctx context.Context) ([]container.Runtime, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	f.record(OperationListOwned, "")
	if err := f.takeFailure(OperationListOwned); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(f.runtimes))
	for id := range f.runtimes {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	runtimes := make([]container.Runtime, 0, len(ids))
	for _, id := range ids {
		runtimes = append(runtimes, f.runtimes[container.RuntimeID(id)])
	}
	return runtimes, nil
}

func (f *FakeManager) Start(ctx context.Context, id container.RuntimeID) (container.Runtime, error) {
	return f.transition(ctx, OperationStart, id, container.StatusRunning, container.StatusStopped)
}

func (f *FakeManager) Stop(ctx context.Context, id container.RuntimeID, _ container.StopOptions) (container.Runtime, error) {
	return f.transition(ctx, OperationStop, id, container.StatusStopped, container.StatusRunning)
}

func (f *FakeManager) Rebuild(ctx context.Context, id container.RuntimeID, options container.RebuildOptions) (container.Runtime, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return container.Runtime{}, err
	}
	f.record(OperationRebuild, id)
	if err := f.takeFailure(OperationRebuild); err != nil {
		return container.Runtime{}, err
	}
	current, err := f.runtime(id)
	if err != nil {
		return container.Runtime{}, err
	}
	if options.Spec.ID != id || options.Spec.ConversationID != current.ConversationID {
		return container.Runtime{}, fmt.Errorf("%w: rebuild identity changed", container.ErrInvalidSpecification)
	}
	if err := container.ValidateSpec(options.Spec); err != nil {
		return container.Runtime{}, err
	}
	now := f.now().UTC()
	resolvedImage := options.Spec.Image
	resolvedImage.ResolvedDigest = options.Spec.Image.Digest
	rebuilt := container.Runtime{
		ID:             id,
		ConversationID: current.ConversationID,
		ProviderID:     "fake-" + string(id) + "-rebuilt",
		Image:          resolvedImage,
		Status:         container.StatusStopped,
		CreatedAt:      now,
		UpdatedAt:      now,
		SpecDigest:     container.RuntimeSpecDigest(options.Spec),
		Spec:           &options.Spec,
	}
	f.runtimes[id] = rebuilt
	return rebuilt, nil
}

func (f *FakeManager) Delete(ctx context.Context, id container.RuntimeID, _ container.DeleteOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	f.record(OperationDelete, id)
	if err := f.takeFailure(OperationDelete); err != nil {
		return err
	}
	if _, exists := f.runtimes[id]; !exists {
		return container.ErrNotFound
	}
	delete(f.runtimes, id)
	return nil
}

func (f *FakeManager) transition(ctx context.Context, operation string, id container.RuntimeID, next container.Status, allowed ...container.Status) (container.Runtime, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return container.Runtime{}, err
	}
	f.record(operation, id)
	if err := f.takeFailure(operation); err != nil {
		return container.Runtime{}, err
	}
	runtime, err := f.runtime(id)
	if err != nil {
		return container.Runtime{}, err
	}
	allowedState := false
	for _, status := range allowed {
		if runtime.Status == status {
			allowedState = true
			break
		}
	}
	if !allowedState {
		return container.Runtime{}, fmt.Errorf("%w: cannot %s runtime in %s", container.ErrRuntimeStateConflict, operation, runtime.Status)
	}
	runtime.Status = next
	runtime.UpdatedAt = f.now().UTC()
	f.runtimes[id] = runtime
	return runtime, nil
}

func (f *FakeManager) inspectImage(ctx context.Context, operation string, id container.RuntimeID, image container.ImageReference, local bool) (container.ImageInspection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return container.ImageInspection{}, err
	}
	f.record(operation, id)
	if err := f.takeFailure(operation); err != nil {
		return container.ImageInspection{}, err
	}
	if err := container.ValidateImageReference(image); err != nil {
		return container.ImageInspection{}, err
	}
	resolved := image
	resolved.ResolvedDigest = image.Digest
	inspection := container.ImageInspection{
		Reference:      resolved,
		ManifestDigest: image.Digest,
		Platforms:      []string{image.Platform},
		Local:          local,
	}
	if local {
		inspection.ImageID = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		inspection.SizeBytes = 64 << 20
	}
	return inspection, nil
}

func (f *FakeManager) runtime(id container.RuntimeID) (container.Runtime, error) {
	runtime, exists := f.runtimes[id]
	if !exists {
		return container.Runtime{}, container.ErrNotFound
	}
	return runtime, nil
}

func (f *FakeManager) record(operation string, id container.RuntimeID) {
	f.calls = append(f.calls, Call{Operation: operation, RuntimeID: id})
}

func (f *FakeManager) takeFailure(operation string) error {
	err := f.failNext[operation]
	delete(f.failNext, operation)
	return err
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
