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

const (
	InitializationQueued   InitializationStatus = "queued"
	InitializationCreating InitializationStatus = "creating"
	InitializationCreated  InitializationStatus = "created"
	InitializationFailed   InitializationStatus = "failed"
)

// InitializationRecord is the durable control-plane state exposed to status
// APIs. Created means the stopped container was created and verified; it does
// not claim that tool bootstrap or execution readiness has completed.
type InitializationRecord struct {
	ConversationID string               `json:"conversationId"`
	RuntimeID      RuntimeID            `json:"runtimeId"`
	Status         InitializationStatus `json:"status"`
	Attempt        int                  `json:"attempt"`
	ProviderID     string               `json:"providerId,omitempty"`
	RuntimeStatus  Status               `json:"runtimeStatus,omitempty"`
	ImageDigest    string               `json:"imageDigest"`
	ImagePlatform  string               `json:"imagePlatform"`
	LastError      string               `json:"lastError,omitempty"`
	Spec           RuntimeSpec          `json:"-"`
	RequestedAt    time.Time            `json:"requestedAt"`
	StartedAt      *time.Time           `json:"startedAt,omitempty"`
	CompletedAt    *time.Time           `json:"completedAt,omitempty"`
	UpdatedAt      time.Time            `json:"updatedAt"`
}

// InitializationStore must make Queue and Claim atomic so duplicate requests
// and multiple workers cannot create more than one conversation container.
type InitializationStore interface {
	Get(ctx context.Context, conversationID string) (InitializationRecord, error)
	Queue(ctx context.Context, spec RuntimeSpec, retryFailed bool) (record InitializationRecord, shouldEnqueue bool, err error)
	Claim(ctx context.Context, conversationID string) (record InitializationRecord, claimed bool, err error)
	Complete(ctx context.Context, conversationID string, runtime Runtime) (InitializationRecord, error)
	Fail(ctx context.Context, conversationID, message string) (InitializationRecord, error)
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
	if err != nil || !claimed {
		return
	}
	createCtx, cancel := context.WithTimeout(i.ctx, i.options.CreateTimeout)
	runtime, createErr := i.creator.Create(createCtx, record.Spec)
	cancel()
	if createErr != nil {
		if errors.Is(createErr, context.Canceled) && i.ctx.Err() != nil {
			return
		}
		_, _ = i.failWithBoundedContext(conversationID, createErr.Error())
		return
	}
	stateCtx, stateCancel := context.WithTimeout(context.Background(), initializationStateWriteTimeout)
	_, _ = i.store.Complete(stateCtx, conversationID, runtime)
	stateCancel()
}

func (i *Initializer) failWithBoundedContext(conversationID, message string) (InitializationRecord, error) {
	stateCtx, cancel := context.WithTimeout(context.Background(), initializationStateWriteTimeout)
	defer cancel()
	return i.store.Fail(stateCtx, conversationID, message)
}

func (i *Initializer) forget(conversationID string) {
	i.mu.Lock()
	delete(i.enqueued, conversationID)
	i.mu.Unlock()
}
