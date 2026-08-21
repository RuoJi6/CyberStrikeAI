package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

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
