package mcp

import (
	"context"
	"testing"
	"time"
)

func TestExecutionServiceBackgroundWaitResultCompletesWaitTool(t *testing.T) {
	service := NewExecutionService(nil, nil)
	handle, err := service.Submit(context.Background(), ExecutionRequest{
		ToolName: "wait_tool_execution",
		Run: func(context.Context) (*ToolResult, error) {
			return &ToolResult{
				Content: []Content{{Type: "text", Text: `{
  "execution_id": "3eaaa391-050b-4be1-a870-48a855923cb7",
  "tool": "exec",
  "status": "running"
}

本次等待已到达 timeout_seconds，上述 execution 仍未完成。可继续等待、取消，或采用其他步骤。`}},
				IsError: true,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	snap, err := service.Wait(context.Background(), handle.ID, 0)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if snap == nil || snap.Execution == nil {
		t.Fatal("missing execution snapshot")
	}
	if snap.Execution.Status != ToolExecutionStatusCompleted {
		t.Fatalf("status = %q, want %q", snap.Execution.Status, ToolExecutionStatusCompleted)
	}
	if snap.Execution.Result == nil || !snap.Execution.Result.IsError {
		t.Fatal("model-facing result should remain IsError")
	}
}

func TestExecutionServicePersistsBackendAuditIdentity(t *testing.T) {
	service := NewExecutionService(nil, nil)
	handle, err := service.Submit(context.Background(), ExecutionRequest{
		ToolName: "exec",
		Run: func(ctx context.Context) (*ToolResult, error) {
			RecordToolExecutionAudit(ctx, ToolExecutionAudit{
				ExecutionLocation: "container",
				ContainerID:       "container-abc",
				ImageDigest:       "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			})
			return &ToolResult{Content: []Content{{Type: "text", Text: "ok"}}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	snapshot, err := service.Wait(waitCtx, handle.ID, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	exec := snapshot.Execution
	if exec.ExecutionLocation != "container" || exec.ContainerID != "container-abc" || exec.ImageDigest == "" {
		t.Fatalf("execution audit = %#v", exec)
	}
}

func TestLocalToolExecutionAuditRecorderUsesContextExecutionID(t *testing.T) {
	server := NewServer(nil)
	ctx := server.WithLocalToolExecutionAuditRecorder(context.Background())
	executionID := server.BeginToolExecution(ctx, "eino_fs::read_file", map[string]interface{}{"path": "report.txt"})
	ctx = WithMCPExecutionID(ctx, executionID)
	RecordToolExecutionAudit(ctx, ToolExecutionAudit{ExecutionLocation: "host"})
	exec, ok := server.GetExecution(executionID)
	if !ok || exec == nil || exec.ExecutionLocation != "host" {
		t.Fatalf("execution = %#v ok=%v", exec, ok)
	}
}
