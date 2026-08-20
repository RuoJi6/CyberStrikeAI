package container

import (
	"context"
	"errors"
	"testing"
	"time"
)

type idleStopTestStore struct {
	candidates []IdleRuntimeCandidate
	err        error
}

func (s idleStopTestStore) ListIdleRuntimeCandidates(context.Context, time.Time, int) ([]IdleRuntimeCandidate, error) {
	return append([]IdleRuntimeCandidate(nil), s.candidates...), s.err
}

type idleStopTestActivity map[string]bool

func (a idleStopTestActivity) ConversationTaskRuntimeState(conversationID string) (bool, time.Time) {
	return a[conversationID], time.Time{}
}

type idleStopTestLifecycle struct {
	errors map[string]error
	calls  []string
}

func (l *idleStopTestLifecycle) StopIdle(_ context.Context, conversationID string, _ time.Time) (InitializationRecord, error) {
	l.calls = append(l.calls, conversationID)
	if err := l.errors[conversationID]; err != nil {
		return InitializationRecord{}, err
	}
	return InitializationRecord{ConversationID: conversationID, RuntimeStatus: StatusStopped}, nil
}

func TestIdleStopSchedulerStopsOnlyInactiveTaskFreeCandidates(t *testing.T) {
	clock := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	store := idleStopTestStore{candidates: []IdleRuntimeCandidate{
		{ConversationID: "stopped"},
		{ConversationID: "active"},
		{ConversationID: "changed"},
		{ConversationID: "failed"},
	}}
	lifecycle := &idleStopTestLifecycle{errors: map[string]error{
		"changed": ErrRuntimeStateConflict,
		"failed":  ErrEngineUnavailable,
	}}
	scheduler, err := NewIdleStopScheduler(store, lifecycle, idleStopTestActivity{"active": true}, IdleStopSchedulerOptions{
		IdleAfter: time.Hour,
		Clock:     func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := scheduler.Reconcile(context.Background())
	if !errors.Is(err, ErrEngineUnavailable) {
		t.Fatalf("reconcile error = %v", err)
	}
	if report.Candidates != 4 || report.ActiveTasks != 1 || report.Stopped != 1 || report.Skipped != 1 || report.Failed != 1 {
		t.Fatalf("report = %#v", report)
	}
	wantCalls := []string{"stopped", "changed", "failed"}
	if len(lifecycle.calls) != len(wantCalls) {
		t.Fatalf("lifecycle calls = %#v", lifecycle.calls)
	}
	for i := range wantCalls {
		if lifecycle.calls[i] != wantCalls[i] {
			t.Fatalf("lifecycle calls = %#v", lifecycle.calls)
		}
	}
}

func TestIdleStopSchedulerPeriodicStopsOnCancellation(t *testing.T) {
	scheduler, err := NewIdleStopScheduler(idleStopTestStore{}, &idleStopTestLifecycle{}, idleStopTestActivity{}, IdleStopSchedulerOptions{IdleAfter: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := scheduler.RunPeriodic(ctx, time.Millisecond, nil); err != nil {
		t.Fatalf("periodic cancellation = %v", err)
	}
}
