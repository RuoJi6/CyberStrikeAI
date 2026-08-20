package container

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrInitializationQueueFull = errors.New("container initialization queue is full")

const initializationStateWriteTimeout = 10 * time.Second

type InitializationStatus string
type ReadinessStatus string

const (
	InitializationQueued   InitializationStatus = "queued"
	InitializationCreating InitializationStatus = "creating"
	InitializationCreated  InitializationStatus = "created"
	InitializationFailed   InitializationStatus = "failed"

	ReadinessNotRequired ReadinessStatus = "not_required"
	ReadinessPending     ReadinessStatus = "pending"
	ReadinessValidating  ReadinessStatus = "validating"
	ReadinessReady       ReadinessStatus = "ready"
	ReadinessFailed      ReadinessStatus = "failed"
)

// InitializationRecord is the durable control-plane state exposed to status
// APIs. Created means the stopped container exists. ReadinessReady is required
// before a readiness-enabled runtime may be exposed for Agent execution.
type InitializationRecord struct {
	ConversationID       string               `json:"conversationId"`
	RuntimeID            RuntimeID            `json:"runtimeId"`
	Status               InitializationStatus `json:"status"`
	Attempt              int                  `json:"attempt"`
	ProviderID           string               `json:"providerId,omitempty"`
	RuntimeStatus        Status               `json:"runtimeStatus,omitempty"`
	ImageDigest          string               `json:"imageDigest"`
	ImagePlatform        string               `json:"imagePlatform"`
	LastError            string               `json:"lastError,omitempty"`
	ReadinessStatus      ReadinessStatus      `json:"readinessStatus"`
	ReadinessError       string               `json:"readinessError,omitempty"`
	InventoryDigest      string               `json:"inventoryDigest,omitempty"`
	ToolCount            int                  `json:"toolCount,omitempty"`
	Spec                 RuntimeSpec          `json:"-"`
	RequestedAt          time.Time            `json:"requestedAt"`
	StartedAt            *time.Time           `json:"startedAt,omitempty"`
	CompletedAt          *time.Time           `json:"completedAt,omitempty"`
	UpdatedAt            time.Time            `json:"updatedAt"`
	ReadinessStartedAt   *time.Time           `json:"readinessStartedAt,omitempty"`
	ReadinessCompletedAt *time.Time           `json:"readinessCompletedAt,omitempty"`
}

// InitializationStore must make Queue and Claim atomic so duplicate requests
// and multiple workers cannot create more than one conversation container.
type InitializationStore interface {
	Get(ctx context.Context, conversationID string) (InitializationRecord, error)
	Queue(ctx context.Context, spec RuntimeSpec, retryFailed bool) (record InitializationRecord, shouldEnqueue bool, err error)
	Claim(ctx context.Context, conversationID string) (record InitializationRecord, claimed bool, err error)
	Complete(ctx context.Context, conversationID string, runtime Runtime) (InitializationRecord, error)
	Fail(ctx context.Context, conversationID, message string) (InitializationRecord, error)
	ClaimReadiness(ctx context.Context, conversationID string) (record InitializationRecord, claimed bool, err error)
	Ready(ctx context.Context, conversationID string, report ReadinessReport) (InitializationRecord, error)
	FailReadiness(ctx context.Context, conversationID, message string) (InitializationRecord, error)
	RecoverInterrupted(ctx context.Context) ([]InitializationRecord, error)
}

type InitializerOptions struct {
	Workers       int
	QueueCapacity int
	CreateTimeout time.Duration
}

// Initializer coordinates bounded, non-blocking container creation. EnsureAsync
// only persists and enqueues work; Docker calls run exclusively in workers.
type Initializer struct {
	creator RuntimeCreator
	checker RuntimeReadinessChecker
	store   InitializationStore
	options InitializerOptions

	ctx    context.Context
	cancel context.CancelFunc
	jobs   chan string
	wg     sync.WaitGroup

	mu       sync.Mutex
	enqueued map[string]struct{}
}

func NewInitializer(creator RuntimeCreator, store InitializationStore, options InitializerOptions) (*Initializer, error) {
	if creator == nil || store == nil {
		return nil, invalidSpec("container initializer requires a creator and durable store")
	}
	if options.Workers <= 0 || options.QueueCapacity <= 0 || options.CreateTimeout <= 0 {
		return nil, invalidSpec("initializer workers, queue capacity and create timeout must be positive")
	}
	ctx, cancel := context.WithCancel(context.Background())
	initializer := &Initializer{
		creator:  creator,
		checker:  readinessChecker(creator),
		store:    store,
		options:  options,
		ctx:      ctx,
		cancel:   cancel,
		jobs:     make(chan string, options.QueueCapacity),
		enqueued: make(map[string]struct{}),
	}
	for worker := 0; worker < options.Workers; worker++ {
		initializer.wg.Add(1)
		go initializer.runWorker()
	}
	return initializer, nil
}

func (i *Initializer) EnsureAsync(ctx context.Context, spec RuntimeSpec) (InitializationRecord, error) {
	return i.schedule(ctx, spec, false)
}

func (i *Initializer) RetryAsync(ctx context.Context, spec RuntimeSpec) (InitializationRecord, error) {
	return i.schedule(ctx, spec, true)
}

func (i *Initializer) Get(ctx context.Context, conversationID string) (InitializationRecord, error) {
	if i == nil || i.store == nil {
		return InitializationRecord{}, fmt.Errorf("%w: initializer is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return InitializationRecord{}, invalidSpec("context is required")
	}
	return i.store.Get(ctx, conversationID)
}

// Recover requeues durable queued work and turns work interrupted by a process
// restart back into queued state. It must be called once during application startup.
func (i *Initializer) Recover(ctx context.Context) error {
	if i == nil || i.store == nil {
		return fmt.Errorf("%w: initializer is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return invalidSpec("context is required")
	}
	records, err := i.store.RecoverInterrupted(ctx)
	if err != nil {
		return err
	}
	var recoveryErrors []error
	for _, record := range records {
		if enqueueErr := i.enqueue(record.ConversationID); enqueueErr != nil {
			_, _ = i.store.Fail(ctx, record.ConversationID, enqueueErr.Error())
			recoveryErrors = append(recoveryErrors, enqueueErr)
		}
	}
	return errors.Join(recoveryErrors...)
}

func (i *Initializer) Close(ctx context.Context) error {
	if i == nil {
		return nil
	}
	if ctx == nil {
		return invalidSpec("context is required")
	}
	i.cancel()
	done := make(chan struct{})
	go func() {
		i.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (i *Initializer) schedule(ctx context.Context, spec RuntimeSpec, retryFailed bool) (InitializationRecord, error) {
	if i == nil || i.store == nil {
		return InitializationRecord{}, fmt.Errorf("%w: initializer is not configured", ErrEngineUnavailable)
	}
	if err := ValidateSpec(spec); err != nil {
		return InitializationRecord{}, err
	}
	if ctx == nil {
		return InitializationRecord{}, invalidSpec("context is required")
	}
	if err := ctx.Err(); err != nil {
		return InitializationRecord{}, err
	}
	record, shouldEnqueue, err := i.store.Queue(ctx, spec, retryFailed)
	if err != nil || !shouldEnqueue {
		return record, err
	}
	if err := i.enqueue(spec.ConversationID); err != nil {
		failed, failErr := i.failWithBoundedContext(spec.ConversationID, err.Error())
		if failErr != nil {
			return record, errors.Join(err, failErr)
		}
		return failed, err
	}
	return record, nil
}

func (i *Initializer) enqueue(conversationID string) error {
	i.mu.Lock()
	if _, exists := i.enqueued[conversationID]; exists {
		i.mu.Unlock()
		return nil
	}
	i.enqueued[conversationID] = struct{}{}
	i.mu.Unlock()

	select {
	case i.jobs <- conversationID:
		return nil
	case <-i.ctx.Done():
		i.forget(conversationID)
		return i.ctx.Err()
	default:
		i.forget(conversationID)
		return fmt.Errorf("%w: capacity %d", ErrInitializationQueueFull, i.options.QueueCapacity)
	}
}

func (i *Initializer) runWorker() {
	defer i.wg.Done()
	for {
		select {
		case <-i.ctx.Done():
			return
		case conversationID := <-i.jobs:
			i.initialize(conversationID)
			i.forget(conversationID)
		}
	}
}

func (i *Initializer) initialize(conversationID string) {
	record, claimed, err := i.store.Claim(i.ctx, conversationID)
	if err != nil {
		return
	}
	var runtime Runtime
	if claimed {
		createCtx, cancel := context.WithTimeout(i.ctx, i.options.CreateTimeout)
		created, createErr := i.creator.Create(createCtx, record.Spec)
		cancel()
		if createErr != nil {
			if errors.Is(createErr, context.Canceled) && i.ctx.Err() != nil {
				return
			}
			_, _ = i.failWithBoundedContext(conversationID, createErr.Error())
			return
		}
		runtime = created
		stateCtx, stateCancel := context.WithTimeout(context.Background(), initializationStateWriteTimeout)
		record, err = i.store.Complete(stateCtx, conversationID, runtime)
		stateCancel()
		if err != nil {
			return
		}
	} else {
		record, err = i.store.Get(i.ctx, conversationID)
		if err != nil {
			return
		}
		runtime = Runtime{
			ID:             record.RuntimeID,
			ConversationID: record.ConversationID,
			ProviderID:     record.ProviderID,
			Status:         record.RuntimeStatus,
		}
	}
	if record.Status != InitializationCreated || record.ReadinessStatus != ReadinessPending {
		return
	}
	claimCtx, claimCancel := context.WithTimeout(context.Background(), initializationStateWriteTimeout)
	record, readinessClaimed, claimErr := i.store.ClaimReadiness(claimCtx, conversationID)
	claimCancel()
	if claimErr != nil || !readinessClaimed {
		return
	}
	if i.checker == nil {
		_, _ = i.failReadinessWithBoundedContext(conversationID, fmt.Errorf("%w: creator does not implement readiness validation", ErrRuntimeNotReady).Error())
		return
	}
	readinessCtx, readinessCancel := context.WithTimeout(i.ctx, i.options.CreateTimeout)
	report, readinessErr := i.checker.ValidateReadiness(readinessCtx, runtime, record.Spec)
	readinessCancel()
	if readinessErr != nil {
		if errors.Is(readinessErr, context.Canceled) && i.ctx.Err() != nil {
			return
		}
		_, _ = i.failReadinessWithBoundedContext(conversationID, readinessErr.Error())
		return
	}
	if report.InventoryDigest != record.Spec.Readiness.InventoryDigest || report.ToolCount != len(record.Spec.Readiness.Inventory.Tools) {
		message := fmt.Sprintf("%v: readiness report does not match the immutable tool inventory", ErrRuntimeNotReady)
		_, _ = i.failReadinessWithBoundedContext(conversationID, message)
		return
	}
	readyCtx, readyCancel := context.WithTimeout(context.Background(), initializationStateWriteTimeout)
	_, _ = i.store.Ready(readyCtx, conversationID, report)
	readyCancel()
}

func (i *Initializer) failWithBoundedContext(conversationID, message string) (InitializationRecord, error) {
	stateCtx, cancel := context.WithTimeout(context.Background(), initializationStateWriteTimeout)
	defer cancel()
	return i.store.Fail(stateCtx, conversationID, message)
}

func (i *Initializer) failReadinessWithBoundedContext(conversationID, message string) (InitializationRecord, error) {
	stateCtx, cancel := context.WithTimeout(context.Background(), initializationStateWriteTimeout)
	defer cancel()
	return i.store.FailReadiness(stateCtx, conversationID, message)
}

func readinessChecker(creator RuntimeCreator) RuntimeReadinessChecker {
	checker, _ := creator.(RuntimeReadinessChecker)
	return checker
}

func (i *Initializer) forget(conversationID string) {
	i.mu.Lock()
	delete(i.enqueued, conversationID)
	i.mu.Unlock()
}
