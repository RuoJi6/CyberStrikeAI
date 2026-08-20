package security

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	containerruntime "cyberstrike-ai/internal/runtime/container"

	"github.com/cloudwego/eino/adk/filesystem"
	"go.uber.org/zap"
)

type fakeContainerRuntimeExecutor struct {
	request containerruntime.ExecRequest
	result  containerruntime.ExecResult
	err     error
	output  string
}

func (f *fakeContainerRuntimeExecutor) Exec(_ context.Context, _ containerruntime.RuntimeSpec, request containerruntime.ExecRequest, sink containerruntime.ExecOutputSink) (containerruntime.ExecResult, error) {
	f.request = request
	if sink != nil && f.output != "" {
		_ = sink(containerruntime.ExecStreamStdout, []byte(f.output))
	}
	return f.result, f.err
}

func TestContainerExecutionBackendStreamsAndPreservesExitCode(t *testing.T) {
	executor := &fakeContainerRuntimeExecutor{
		result: containerruntime.ExecResult{ExecID: "exec-1", ExitCode: 7},
		output: "container-output",
	}
	backend, err := NewContainerExecutionBackend(executor, executionBackendSpec())
	if err != nil {
		t.Fatal(err)
	}
	var streamed strings.Builder
	result, err := backend.Execute(context.Background(), ExecutionRequest{
		Command:    []string{"/bin/sh", "-c", "exit 7"},
		WorkingDir: "/workspace",
		Output: func(chunk string) {
			streamed.WriteString(chunk)
		},
	})
	var exitErr *CommandExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 7 {
		t.Fatalf("exit error = %T %v", err, err)
	}
	if result.Location != "container" || result.RuntimeID != "runtime-01" || result.ProviderExecID != "exec-1" || result.Output != "container-output" || streamed.String() != "container-output" {
		t.Fatalf("result=%#v streamed=%q", result, streamed.String())
	}
	if executor.request.Env[0] != "HOME=/workspace" || executor.request.WorkingDir != "/workspace" {
		t.Fatalf("container request = %#v", executor.request)
	}
	if got := FormatCommandFailureFromErr(err, result.Output); !strings.Contains(got, "exit status 7") || !strings.Contains(got, "container-output") {
		t.Fatalf("formatted failure = %q", got)
	}
}

func TestExecutionBackendResolverErrorNeverFallsBackToHost(t *testing.T) {
	resolver := ExecutionBackendResolverFunc(func(context.Context) (ExecutionBackend, error) {
		return nil, errors.New("container unavailable")
	})
	executor := NewExecutor(&testSecurityConfig, nil, testLogger())
	executor.SetExecutionBackendResolver(resolver)
	result, err := executor.ExecuteTool(context.Background(), "exec", map[string]interface{}{"command": "printf should-not-run"})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.IsError || !strings.Contains(result.Content[0].Text, "container unavailable") {
		t.Fatalf("fail-closed result = %#v", result)
	}
}

type recordingExecutionBackend struct {
	requests []ExecutionRequest
}

func (b *recordingExecutionBackend) Execute(_ context.Context, request ExecutionRequest) (ExecutionResult, error) {
	request.Command = append([]string(nil), request.Command...)
	b.requests = append(b.requests, request)
	if request.Output != nil {
		request.Output("container-route-ok")
	}
	return ExecutionResult{Output: "container-route-ok", ExitCode: 0, Location: "container", RuntimeID: "runtime-01"}, nil
}

func TestAgentCommandEntryPointsUseConfiguredExecutionBackend(t *testing.T) {
	loadTool := func(name string) config.ToolConfig {
		t.Helper()
		tool, err := config.LoadToolFromFile(filepath.Join("..", "..", "tools", name+".yaml"))
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		return *tool
	}
	position := 0
	cfg := config.SecurityConfig{Tools: []config.ToolConfig{
		{Name: "exec", Command: "sh", Enabled: true},
		loadTool("execute-python-script"),
		loadTool("install-python-package"),
		{
			Name: "yaml-command", Command: "/usr/bin/yaml-command", Args: []string{"--fixed"}, Enabled: true,
			Parameters: []config.ParameterConfig{{Name: "target", Type: "string", Required: true, Position: &position, Format: "positional"}},
		},
		{Name: "control-plane-tool", Command: "internal:unknown", Enabled: true},
	}}
	backend := &recordingExecutionBackend{}
	executor := NewExecutor(&cfg, nil, testLogger())
	executor.SetExecutionBackendResolver(NewFixedExecutionBackendResolver(backend))
	ctx := context.Background()

	result, err := executor.ExecuteTool(ctx, "exec", map[string]interface{}{
		"command": "printf exec-route", "shell": "sh", "workdir": "/workspace",
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("exec result=%#v err=%v", result, err)
	}
	assertLastBackendCommand(t, backend, "sh", "exec-route")
	if got := backend.requests[len(backend.requests)-1].WorkingDir; got != "/workspace" {
		t.Fatalf("exec workdir=%q", got)
	}

	result, err = executor.ExecuteTool(ctx, "execute-python-script", map[string]interface{}{
		"script": "print('python-route')", "env_name": "default",
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("python result=%#v err=%v", result, err)
	}
	assertLastBackendCommand(t, backend, "/bin/bash", "python-route")

	result, err = executor.ExecuteTool(ctx, "install-python-package", map[string]interface{}{
		"package": "example-package==0.0.0", "env_name": "default",
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("install result=%#v err=%v", result, err)
	}
	assertLastBackendCommand(t, backend, "/bin/bash", "example-package==0.0.0")

	result, err = executor.ExecuteTool(ctx, "yaml-command", map[string]interface{}{"target": "yaml-route"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("yaml result=%#v err=%v", result, err)
	}
	assertLastBackendCommand(t, backend, "/usr/bin/yaml-command", "--fixed", "yaml-route")

	before := len(backend.requests)
	result, err = executor.ExecuteTool(ctx, "control-plane-tool", map[string]interface{}{})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("internal result=%#v err=%v", result, err)
	}
	if len(backend.requests) != before {
		t.Fatal("internal control-plane tool unexpectedly used OS execution backend")
	}
}

func TestEinoExecuteUsesConfiguredExecutionBackend(t *testing.T) {
	backend := &recordingExecutionBackend{}
	shell := NewEinoStreamingShellWithResolver(NewFixedExecutionBackendResolver(backend))
	stream, err := shell.ExecuteStreaming(context.Background(), &filesystem.ExecuteRequest{Command: "printf eino-route"})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	for {
		_, err = stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	assertLastBackendCommand(t, backend, "/bin/sh", "eino-route")
}

func assertLastBackendCommand(t *testing.T, backend *recordingExecutionBackend, fragments ...string) {
	t.Helper()
	if backend == nil || len(backend.requests) == 0 {
		t.Fatal("execution backend was not called")
	}
	command := strings.Join(backend.requests[len(backend.requests)-1].Command, " ")
	for _, fragment := range fragments {
		if !strings.Contains(command, fragment) {
			t.Fatalf("backend command %q missing %q", command, fragment)
		}
	}
}

var testSecurityConfig = func() config.SecurityConfig {
	return config.SecurityConfig{Tools: []config.ToolConfig{{Name: "exec", Command: "sh", Enabled: true}}}
}()

func testLogger() *zap.Logger { return zap.NewNop() }

func executionBackendSpec() containerruntime.RuntimeSpec {
	return containerruntime.RuntimeSpec{
		ID:             "runtime-01",
		ConversationID: "conversation-01",
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
