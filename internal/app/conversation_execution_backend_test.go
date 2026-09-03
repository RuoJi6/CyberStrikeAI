package app

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/runtime/container/containertest"
	"cyberstrike-ai/internal/security"

	"go.uber.org/zap"
)

type appFakeRuntimeExecutor struct {
	called  int
	request containerruntime.ExecRequest
}

type credentialEchoBackend struct{ value string }

func (backend credentialEchoBackend) Execute(_ context.Context, request security.ExecutionRequest) (security.ExecutionResult, error) {
	pivot := len(backend.value) / 2
	if request.Output != nil {
		request.Output("before " + backend.value[:pivot])
		request.Output(backend.value[pivot:] + " after")
	}
	return security.ExecutionResult{Output: "before " + backend.value + " after", ExitCode: 0}, nil
}

func TestExecutionCredentialRedactionCoversSplitStreamAndResult(t *testing.T) {
	credential := "v1.header.payload.signature"
	var streamed strings.Builder
	result, err := executeWithCredentialRedaction(context.Background(), credentialEchoBackend{value: credential}, security.ExecutionRequest{
		Output: func(chunk string) { _, _ = streamed.WriteString(chunk) },
	}, []string{credential})
	if err != nil {
		t.Fatal(err)
	}
	for label, output := range map[string]string{"stream": streamed.String(), "result": result.Output} {
		if strings.Contains(output, credential) || output != "before "+redactedNetworkCredential+" after" {
			t.Fatalf("%s credential redaction = %q", label, output)
		}
	}
}

type appBlockingStartManager struct {
	*containertest.FakeManager
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
	startCall atomic.Int32
}

func (m *appBlockingStartManager) Start(ctx context.Context, id containerruntime.RuntimeID) (containerruntime.Runtime, error) {
	m.startCall.Add(1)
	m.enterOnce.Do(func() { close(m.entered) })
	select {
	case <-ctx.Done():
		return containerruntime.Runtime{}, ctx.Err()
	case <-m.release:
	}
	return m.FakeManager.Start(ctx, id)
}

func (f *appFakeRuntimeExecutor) Exec(_ context.Context, _ containerruntime.RuntimeSpec, request containerruntime.ExecRequest, sink containerruntime.ExecOutputSink) (containerruntime.ExecResult, error) {
	f.called++
	f.request = request
	if sink != nil {
		_ = sink(containerruntime.ExecStreamStdout, []byte("inside-container"))
	}
	return containerruntime.ExecResult{ExecID: "exec-1"}, nil
}

func TestConversationExecutionBackendResolverStartsAndRoutesContainer(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "execution-backend.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("container", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversation.ID); err != nil {
		t.Fatal(err)
	}
	spec := appExecutionSpec(conversation.ID)
	if _, _, err := db.Queue(context.Background(), spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(context.Background(), conversation.ID); err != nil || !claimed {
		t.Fatalf("claim: claimed=%v err=%v", claimed, err)
	}
	manager := containertest.NewFakeManager(containerruntime.EngineInfo{Available: true})
	runtime, err := manager.Create(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Complete(context.Background(), conversation.ID, runtime); err != nil {
		t.Fatal(err)
	}
	lifecycle, err := containerruntime.NewLifecycleController(manager, db)
	if err != nil {
		t.Fatal(err)
	}
	execRuntime := &appFakeRuntimeExecutor{}
	resolver := newConversationExecutionBackendResolver(db, execRuntime, lifecycle)
	ctx := mcp.WithMCPConversationID(context.Background(), conversation.ID)
	ctx = mcp.WithMCPExecutionID(ctx, "tool-execution-1")
	var audit mcp.ToolExecutionAudit
	ctx = mcp.WithToolExecutionAuditRecorder(ctx, func(_ string, observation mcp.ToolExecutionAudit) { audit = observation })
	backend, err := resolver.ResolveExecutionBackend(ctx)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	result, err := backend.Execute(ctx, security.ExecutionRequest{Command: []string{"/bin/sh", "-c", "printf marker"}})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Location != "container" || result.Output != "inside-container" || execRuntime.called != 1 || result.ContainerID != runtime.ProviderID || result.ImageDigest != spec.Image.Digest {
		t.Fatalf("result=%#v calls=%d", result, execRuntime.called)
	}
	if audit.ExecutionLocation != "container" || audit.ContainerID != runtime.ProviderID || audit.ImageDigest != spec.Image.Digest {
		t.Fatalf("execution audit = %#v runtime = %#v", audit, runtime)
	}
	record, err := db.GetContainerInitialization(context.Background(), conversation.ID)
	if err != nil || record.RuntimeStatus != containerruntime.StatusRunning {
		t.Fatalf("runtime was not durably started: %#v err=%v", record, err)
	}
	if _, err := lifecycle.Stop(context.Background(), conversation.ID); err != nil {
		t.Fatal(err)
	}
	pending, err := db.PrepareConversationBoundaryRebuild(context.Background(), conversation.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	backend, err = resolver.ResolveExecutionBackend(ctx)
	if err == nil || backend != nil || !strings.Contains(err.Error(), "boundary rebuild") {
		t.Fatalf("pending rebuild did not fail closed: backend=%T err=%v", backend, err)
	}
	if err := db.CancelConversationBoundaryRebuild(context.Background(), conversation.ID, pending.SnapshotID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE conversation_container_runtimes SET runtime_generation = 2 WHERE conversation_id = ?`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	backend, err = resolver.ResolveExecutionBackend(ctx)
	if err == nil || backend != nil || !strings.Contains(err.Error(), "generation mismatch") {
		t.Fatalf("generation mismatch did not fail closed: backend=%T err=%v", backend, err)
	}
}

func TestConversationExecutionBackendResolverJoinsConcurrentContainerStart(t *testing.T) {
	db, conversationID, manager := appStoppedContainerRuntime(t)
	defer db.Close()
	lifecycle, err := containerruntime.NewLifecycleController(manager, db)
	if err != nil {
		t.Fatal(err)
	}
	resolver := newConversationExecutionBackendResolver(db, &appFakeRuntimeExecutor{}, lifecycle)
	ctx, cancel := context.WithTimeout(mcp.WithMCPConversationID(context.Background(), conversationID), 2*time.Second)
	defer cancel()

	type result struct {
		backend security.ExecutionBackend
		err     error
	}
	first := make(chan result, 1)
	second := make(chan result, 1)
	go func() {
		backend, resolveErr := resolver.ResolveExecutionBackend(ctx)
		first <- result{backend: backend, err: resolveErr}
	}()
	select {
	case <-manager.entered:
	case <-ctx.Done():
		t.Fatalf("first start did not reach the engine: %v", ctx.Err())
	}
	go func() {
		backend, resolveErr := resolver.ResolveExecutionBackend(ctx)
		second <- result{backend: backend, err: resolveErr}
	}()
	select {
	case early := <-second:
		t.Fatalf("concurrent resolver did not join the active start: backend=%T err=%v", early.backend, early.err)
	case <-time.After(4 * containerStartJoinPollInterval):
	}
	close(manager.release)

	for index, channel := range []<-chan result{first, second} {
		select {
		case resolved := <-channel:
			if resolved.err != nil || resolved.backend == nil {
				t.Fatalf("resolver %d result: backend=%T err=%v", index+1, resolved.backend, resolved.err)
			}
		case <-ctx.Done():
			t.Fatalf("resolver %d timed out: %v", index+1, ctx.Err())
		}
	}
	if calls := manager.startCall.Load(); calls != 1 {
		t.Fatalf("engine start calls = %d, want 1", calls)
	}
	record, err := db.GetContainerInitialization(context.Background(), conversationID)
	if err != nil || record.RuntimeStatus != containerruntime.StatusRunning || record.LifecycleState != containerruntime.LifecycleIdle {
		t.Fatalf("completed runtime = %#v, err=%v", record, err)
	}
}

func TestConversationExecutionBackendResolverWaiterPropagatesPersistedStartFailure(t *testing.T) {
	db, conversationID, manager := appStoppedContainerRuntime(t)
	defer db.Close()
	if _, err := db.BeginLifecycle(context.Background(), conversationID, containerruntime.LifecycleOperationStart); err != nil {
		t.Fatal(err)
	}
	resolver := &conversationExecutionBackendResolver{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result := make(chan error, 1)
	go func() {
		_, waitErr := resolver.waitForContainerStart(ctx, conversationID)
		result <- waitErr
	}()
	time.Sleep(2 * containerStartJoinPollInterval)
	if _, err := db.FailLifecycle(context.Background(), conversationID, containerruntime.LifecycleOperationStart, containerruntime.LifecycleFailure{
		Message:       "engine start exploded",
		RuntimeStatus: containerruntime.StatusStopped,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case waitErr := <-result:
		if waitErr == nil || !strings.Contains(waitErr.Error(), "engine start exploded") {
			t.Fatalf("waiter failure = %v", waitErr)
		}
	case <-ctx.Done():
		t.Fatalf("waiter timed out: %v", ctx.Err())
	}
	if calls := manager.startCall.Load(); calls != 0 {
		t.Fatalf("waiter called the engine %d times", calls)
	}
	record, err := db.GetContainerInitialization(context.Background(), conversationID)
	if err != nil || record.LifecycleOperation != containerruntime.LifecycleOperationStart || record.LifecycleState != containerruntime.LifecycleFailed || !strings.Contains(record.LifecycleError, "engine start exploded") {
		t.Fatalf("failed runtime = %#v, err=%v", record, err)
	}
}

func TestConversationExecutionBackendResolverFailsClosedWithoutBoundarySnapshot(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "execution-backend-no-boundary.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("container", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	manager := containertest.NewFakeManager(containerruntime.EngineInfo{Available: true})
	lifecycle, err := containerruntime.NewLifecycleController(manager, db)
	if err != nil {
		t.Fatal(err)
	}
	resolver := newConversationExecutionBackendResolver(db, &appFakeRuntimeExecutor{}, lifecycle)
	ctx := mcp.WithMCPConversationID(context.Background(), conversation.ID)
	backend, err := resolver.ResolveExecutionBackend(ctx)
	if err == nil || backend != nil || !strings.Contains(err.Error(), "boundary snapshot") {
		t.Fatalf("expected missing boundary snapshot failure, backend=%T err=%v", backend, err)
	}
}

func TestConversationExecutionBackendResolverFailsClosedWithoutContainerRuntime(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "execution-backend-disabled.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("container", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	resolver := newConversationExecutionBackendResolver(db, nil, nil)
	ctx := mcp.WithMCPConversationID(context.Background(), conversation.ID)
	backend, err := resolver.ResolveExecutionBackend(ctx)
	if err == nil || backend != nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("expected fail-closed resolver error, backend=%T err=%v", backend, err)
	}
}

func TestConversationExecutionBackendResolverKeepsHostConversationOnHost(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "execution-backend-host.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conversation, err := db.CreateConversation("host", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeHost})
	if err != nil {
		t.Fatal(err)
	}
	resolver := newConversationExecutionBackendResolver(db, nil, nil)
	ctx := mcp.WithMCPConversationID(context.Background(), conversation.ID)
	backend, err := resolver.ResolveExecutionBackend(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result, err := backend.Execute(ctx, security.ExecutionRequest{Command: []string{"/bin/sh", "-c", "printf host-ok"}})
	if err != nil || result.Location != "host" || result.Output != "host-ok" {
		t.Fatalf("host result=%#v err=%v", result, err)
	}
}

func appExecutionSpec(conversationID string) containerruntime.RuntimeSpec {
	return containerruntime.RuntimeSpec{
		ID:             containerruntime.RuntimeID("conversation-" + conversationID),
		ConversationID: conversationID,
		Image: containerruntime.ImageReference{
			Repository: "ghcr.io/example/sandbox",
			Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:   "linux/arm64",
		},
		Resources: containerruntime.ResourceLimits{
			NanoCPUs: 1_000_000_000, MemoryBytes: 512 << 20, PIDs: 128,
			NoFileSoft: 1024, NoFileHard: 2048, WorkspaceBytes: 1 << 30,
			MaxConcurrentExec: 2, MaxQueuedExec: 8, LogMaxBytes: 10 << 20, LogMaxFiles: 3,
		},
		Security: containerruntime.SecurityProfile{
			ReadOnlyRootFS: true, NoNewPrivileges: true, DropAllCapabilities: true,
			NetworkMode: containerruntime.NetworkNone, SeccompProfile: "default", TmpfsBytes: 64 << 20,
		},
		Workspace: containerruntime.WorkspaceSpec{MountPath: "/workspace"},
	}
}

func appStoppedContainerRuntime(t *testing.T) (*database.DB, string, *appBlockingStartManager) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "execution-backend-concurrent.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := db.CreateConversation("container", database.ConversationCreateMeta{RuntimeMode: database.ConversationRuntimeModeContainer})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.EnsureConversationBoundarySnapshot(context.Background(), conversation.ID); err != nil {
		db.Close()
		t.Fatal(err)
	}
	spec := appExecutionSpec(conversation.ID)
	if _, _, err := db.Queue(context.Background(), spec, false); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(context.Background(), conversation.ID); err != nil || !claimed {
		db.Close()
		t.Fatalf("claim: claimed=%v err=%v", claimed, err)
	}
	fake := containertest.NewFakeManager(containerruntime.EngineInfo{Available: true})
	runtime, err := fake.Create(context.Background(), spec)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Complete(context.Background(), conversation.ID, runtime); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db, conversation.ID, &appBlockingStartManager{
		FakeManager: fake,
		entered:     make(chan struct{}),
		release:     make(chan struct{}),
	}
}
