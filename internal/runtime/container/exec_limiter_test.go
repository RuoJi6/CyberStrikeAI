package container

import (
	"context"
	"errors"
	"testing"
	"time"
)

type acquireResult struct {
	permit *ExecPermit
	err    error
}

func TestExecLimiterEnforcesPerRuntimeWithoutBlockingOthers(t *testing.T) {
	limiter := mustExecLimiter(t, ExecLimiterOptions{MaxConcurrent: 2, MaxQueued: 4})
	limits := ResourceLimits{MaxConcurrentExec: 1, MaxQueuedExec: 2}
	first, err := limiter.Acquire(context.Background(), "runtime-1", limits)
	if err != nil {
		t.Fatal(err)
	}
	waiting := acquireAsync(limiter, "runtime-1", limits)
	waitForQueued(t, limiter, 1)
	other, err := limiter.Acquire(context.Background(), "runtime-2", limits)
	if err != nil {
		t.Fatalf("unrelated runtime was blocked: %v", err)
	}
	if snapshot := limiter.Snapshot(); snapshot.Running != 2 || snapshot.Queued != 1 || snapshot.RunningByRuntime["runtime-1"] != 1 || snapshot.RunningByRuntime["runtime-2"] != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	first.Release()
	second := receiveAcquire(t, waiting)
	if second.err != nil {
		t.Fatalf("queued acquire: %v", second.err)
	}
	second.permit.Release()
	other.Release()
}

func TestExecLimiterRejectsGlobalQueueOverflow(t *testing.T) {
	limiter := mustExecLimiter(t, ExecLimiterOptions{MaxConcurrent: 1, MaxQueued: 1})
	limits := ResourceLimits{MaxConcurrentExec: 1, MaxQueuedExec: 2}
	active, err := limiter.Acquire(context.Background(), "runtime-1", limits)
	if err != nil {
		t.Fatal(err)
	}
	waiting := acquireAsync(limiter, "runtime-2", limits)
	waitForQueued(t, limiter, 1)
	_, err = limiter.Acquire(context.Background(), "runtime-3", limits)
	if !errors.Is(err, ErrExecQueueFull) {
		t.Fatalf("queue overflow error = %v", err)
	}
	active.Release()
	result := receiveAcquire(t, waiting)
	if result.err != nil {
		t.Fatal(result.err)
	}
	result.permit.Release()
}

func TestExecLimiterRejectsPerRuntimeQueueOverflow(t *testing.T) {
	limiter := mustExecLimiter(t, ExecLimiterOptions{MaxConcurrent: 4, MaxQueued: 4})
	limits := ResourceLimits{MaxConcurrentExec: 1, MaxQueuedExec: 1}
	active, err := limiter.Acquire(context.Background(), "runtime-1", limits)
	if err != nil {
		t.Fatal(err)
	}
	waiting := acquireAsync(limiter, "runtime-1", limits)
	waitForQueued(t, limiter, 1)
	_, err = limiter.Acquire(context.Background(), "runtime-1", limits)
	if !errors.Is(err, ErrExecQueueFull) {
		t.Fatalf("runtime queue overflow error = %v", err)
	}
	active.Release()
	result := receiveAcquire(t, waiting)
	if result.err != nil {
		t.Fatal(result.err)
	}
	result.permit.Release()
}

func TestExecLimiterCancellationRemovesQueuedWork(t *testing.T) {
	limiter := mustExecLimiter(t, ExecLimiterOptions{MaxConcurrent: 1, MaxQueued: 2})
	limits := ResourceLimits{MaxConcurrentExec: 1, MaxQueuedExec: 2}
	active, err := limiter.Acquire(context.Background(), "runtime-1", limits)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	waiting := acquireAsyncContext(limiter, ctx, "runtime-2", limits)
	waitForQueued(t, limiter, 1)
	cancel()
	result := receiveAcquire(t, waiting)
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("cancellation error = %v", result.err)
	}
	if snapshot := limiter.Snapshot(); snapshot.Queued != 0 || snapshot.QueuedByRuntime["runtime-2"] != 0 {
		t.Fatalf("cancelled work remained queued: %#v", snapshot)
	}
	active.Release()
	active.Release()
	if snapshot := limiter.Snapshot(); snapshot.Running != 0 {
		t.Fatalf("idempotent release snapshot = %#v", snapshot)
	}
}

func mustExecLimiter(t *testing.T, options ExecLimiterOptions) *ExecLimiter {
	t.Helper()
	limiter, err := NewExecLimiter(options)
	if err != nil {
		t.Fatal(err)
	}
	return limiter
}

func acquireAsync(limiter *ExecLimiter, runtimeID RuntimeID, limits ResourceLimits) <-chan acquireResult {
	return acquireAsyncContext(limiter, context.Background(), runtimeID, limits)
}

func acquireAsyncContext(limiter *ExecLimiter, ctx context.Context, runtimeID RuntimeID, limits ResourceLimits) <-chan acquireResult {
	result := make(chan acquireResult, 1)
	go func() {
		permit, err := limiter.Acquire(ctx, runtimeID, limits)
		result <- acquireResult{permit: permit, err: err}
	}()
	return result
}

func waitForQueued(t *testing.T, limiter *ExecLimiter, expected int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if limiter.Snapshot().Queued == expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("queue did not reach %d: %#v", expected, limiter.Snapshot())
}

func receiveAcquire(t *testing.T, result <-chan acquireResult) acquireResult {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for acquire")
		return acquireResult{}
	}
}
