package container

import (
	"context"
	"fmt"
	"sync"
)

// ExecLimiterOptions defines the process-wide safety ceiling. Runtime-specific
// limits are taken from ResourceLimits on every Acquire call.
type ExecLimiterOptions struct {
	MaxConcurrent int
	MaxQueued     int
}

// ExecLimiterSnapshot is suitable for readiness and management UI counters.
// Returned maps are copies and can be read without holding limiter locks.
type ExecLimiterSnapshot struct {
	Running          int
	Queued           int
	RunningByRuntime map[RuntimeID]int
	QueuedByRuntime  map[RuntimeID]int
}

// ExecLimiter provides bounded global and per-conversation backpressure for
// future container exec calls. It does not start processes itself.
type ExecLimiter struct {
	mu               sync.Mutex
	maxConcurrent    int
	maxQueued        int
	running          int
	runningByRuntime map[RuntimeID]int
	queuedByRuntime  map[RuntimeID]int
	waiters          []*execWaiter
}

type execWaiter struct {
	runtimeID  RuntimeID
	maxRunning int
	ready      chan struct{}
	granted    bool
}

// ExecPermit represents one active exec slot. Release is idempotent.
type ExecPermit struct {
	limiter   *ExecLimiter
	runtimeID RuntimeID
	once      sync.Once
}

func NewExecLimiter(options ExecLimiterOptions) (*ExecLimiter, error) {
	if options.MaxConcurrent <= 0 || options.MaxQueued <= 0 {
		return nil, invalidSpec("global exec concurrency and queue limits must be positive")
	}
	return &ExecLimiter{
		maxConcurrent:    options.MaxConcurrent,
		maxQueued:        options.MaxQueued,
		runningByRuntime: make(map[RuntimeID]int),
		queuedByRuntime:  make(map[RuntimeID]int),
	}, nil
}

func (l *ExecLimiter) Acquire(ctx context.Context, runtimeID RuntimeID, limits ResourceLimits) (*ExecPermit, error) {
	if l == nil {
		return nil, invalidSpec("exec limiter is required")
	}
	if ctx == nil {
		return nil, invalidSpec("exec context is required")
	}
	if !generatedNamePattern.MatchString(string(runtimeID)) {
		return nil, invalidSpec("runtime id is required and must be system-safe")
	}
	if limits.MaxConcurrentExec <= 0 || limits.MaxQueuedExec <= 0 {
		return nil, invalidSpec("runtime exec concurrency and queue limits must be positive")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l.mu.Lock()
	if len(l.waiters) == 0 && l.canRunLocked(runtimeID, limits.MaxConcurrentExec) {
		l.grantLocked(runtimeID)
		l.mu.Unlock()
		return &ExecPermit{limiter: l, runtimeID: runtimeID}, nil
	}
	if len(l.waiters) >= l.maxQueued {
		l.mu.Unlock()
		return nil, fmt.Errorf("%w: global limit %d", ErrExecQueueFull, l.maxQueued)
	}
	if l.queuedByRuntime[runtimeID] >= limits.MaxQueuedExec {
		l.mu.Unlock()
		return nil, fmt.Errorf("%w: runtime %s limit %d", ErrExecQueueFull, runtimeID, limits.MaxQueuedExec)
	}
	waiter := &execWaiter{
		runtimeID:  runtimeID,
		maxRunning: limits.MaxConcurrentExec,
		ready:      make(chan struct{}),
	}
	l.waiters = append(l.waiters, waiter)
	l.queuedByRuntime[runtimeID]++
	l.dispatchLocked()
	l.mu.Unlock()

	select {
	case <-waiter.ready:
		return &ExecPermit{limiter: l, runtimeID: runtimeID}, nil
	case <-ctx.Done():
		l.mu.Lock()
		if waiter.granted {
			l.releaseLocked(runtimeID)
		} else if l.removeWaiterLocked(waiter) {
			l.decrementQueuedLocked(runtimeID)
			l.dispatchLocked()
		}
		l.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (p *ExecPermit) Release() {
	if p == nil || p.limiter == nil {
		return
	}
	p.once.Do(func() {
		p.limiter.mu.Lock()
		p.limiter.releaseLocked(p.runtimeID)
		p.limiter.mu.Unlock()
	})
}

func (l *ExecLimiter) Snapshot() ExecLimiterSnapshot {
	if l == nil {
		return ExecLimiterSnapshot{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return ExecLimiterSnapshot{
		Running:          l.running,
		Queued:           len(l.waiters),
		RunningByRuntime: cloneRuntimeCounts(l.runningByRuntime),
		QueuedByRuntime:  cloneRuntimeCounts(l.queuedByRuntime),
	}
}

func (l *ExecLimiter) canRunLocked(runtimeID RuntimeID, maxRuntime int) bool {
	return l.running < l.maxConcurrent && l.runningByRuntime[runtimeID] < maxRuntime
}

func (l *ExecLimiter) grantLocked(runtimeID RuntimeID) {
	l.running++
	l.runningByRuntime[runtimeID]++
}

func (l *ExecLimiter) releaseLocked(runtimeID RuntimeID) {
	if l.runningByRuntime[runtimeID] <= 0 || l.running <= 0 {
		return
	}
	l.running--
	l.runningByRuntime[runtimeID]--
	if l.runningByRuntime[runtimeID] == 0 {
		delete(l.runningByRuntime, runtimeID)
	}
	l.dispatchLocked()
}

func (l *ExecLimiter) dispatchLocked() {
	for l.running < l.maxConcurrent {
		index := -1
		for candidate, waiter := range l.waiters {
			if l.canRunLocked(waiter.runtimeID, waiter.maxRunning) {
				index = candidate
				break
			}
		}
		if index < 0 {
			return
		}
		waiter := l.waiters[index]
		l.waiters = append(l.waiters[:index], l.waiters[index+1:]...)
		l.decrementQueuedLocked(waiter.runtimeID)
		l.grantLocked(waiter.runtimeID)
		waiter.granted = true
		close(waiter.ready)
	}
}

func (l *ExecLimiter) removeWaiterLocked(target *execWaiter) bool {
	for index, waiter := range l.waiters {
		if waiter == target {
			l.waiters = append(l.waiters[:index], l.waiters[index+1:]...)
			return true
		}
	}
	return false
}

func (l *ExecLimiter) decrementQueuedLocked(runtimeID RuntimeID) {
	l.queuedByRuntime[runtimeID]--
	if l.queuedByRuntime[runtimeID] <= 0 {
		delete(l.queuedByRuntime, runtimeID)
	}
}

func cloneRuntimeCounts(source map[RuntimeID]int) map[RuntimeID]int {
	cloned := make(map[RuntimeID]int, len(source))
	for runtimeID, value := range source {
		cloned[runtimeID] = value
	}
	return cloned
}
