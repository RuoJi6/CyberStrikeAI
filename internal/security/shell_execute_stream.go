package security

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/cloudwego/eino/adk/filesystem"
	"github.com/cloudwego/eino/schema"
)

// ConfigureShellCmdForAgentExecute 与 exec 工具一致：非交互 stdin、pager/TERM 环境、独立进程组。
func ConfigureShellCmdForAgentExecute(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	applyDefaultTerminalEnv(cmd)
	attachNonInteractiveStdin(cmd)
	_ = prepareShellCmdSession(cmd)
}

// TerminateShellCmdTree 尽力终止 shell 及其子进程组（与 exec/execute 超时取消一致）。
func TerminateShellCmdTree(cmd *exec.Cmd) {
	terminateCmdTree(cmd)
}

// TerminateShellCmdSession 使用 Start 时缓存的进程组 ID 终止（shell 已退出时仍有效）。
func TerminateShellCmdSession(session *ShellSession) {
	TerminateShellSession(session)
}

// EinoStreamingShell 为 Eino ADK execute 工具提供流式 shell，行为与 exec 对齐：
// 并发读取 stdout/stderr（定长块，非按行），避免官方 local.ExecuteStreaming 先排空 stdout
// 导致 stderr 错误（如 sudo 密码提示）长时间不可见、UI 一直显示「执行中」。
type EinoStreamingShell struct {
	resolver ExecutionBackendResolver
}

// NewEinoStreamingShell 创建 execute 流式 shell 实现。
func NewEinoStreamingShell() *EinoStreamingShell {
	return NewEinoStreamingShellWithResolver(NewFixedExecutionBackendResolver(NewHostExecutionBackend()))
}

func NewEinoStreamingShellWithResolver(resolver ExecutionBackendResolver) *EinoStreamingShell {
	if resolver == nil {
		resolver = NewFixedExecutionBackendResolver(NewHostExecutionBackend())
	}
	return &EinoStreamingShell{resolver: resolver}
}

// ExecuteStreaming 实现 filesystem.StreamingShell。
func (s *EinoStreamingShell) ExecuteStreaming(ctx context.Context, input *filesystem.ExecuteRequest) (*schema.StreamReader[*filesystem.ExecuteResponse], error) {
	if input == nil || input.Command == "" {
		return nil, fmt.Errorf("command is required")
	}
	if s == nil || s.resolver == nil {
		return nil, fmt.Errorf("execution backend resolver is not configured")
	}
	backend, err := s.resolver.ResolveExecutionBackend(ctx)
	if err != nil {
		return nil, err
	}
	if backend == nil {
		return nil, fmt.Errorf("execution backend resolver returned no backend")
	}

	sr, w := schema.Pipe[*filesystem.ExecuteResponse](100)
	if input.RunInBackendGround {
		go runShellInBackground(ctx, backend, input.Command, w)
		return sr, nil
	}
	go streamShellForeground(ctx, backend, input.Command, w)
	return sr, nil
}

func runShellInBackground(ctx context.Context, backend ExecutionBackend, command string, w *schema.StreamWriter[*filesystem.ExecuteResponse]) {
	defer w.Close()
	prepared := PrepareShellCommandForExecute(command)
	result, err := backend.Execute(ctx, ExecutionRequest{Command: []string{"/bin/sh", "-c", prepared}})
	if err != nil {
		_ = w.Send(nil, err)
		return
	}
	exitCode := result.ExitCode
	_ = w.Send(&filesystem.ExecuteResponse{Output: "command started in background\n", ExitCode: &exitCode}, nil)
}

func streamShellForeground(ctx context.Context, backend ExecutionBackend, command string, w *schema.StreamWriter[*filesystem.ExecuteResponse]) {
	defer w.Close()

	command = PrepareShellCommandForExecute(command)
	hadOutput := false
	result, err := backend.Execute(ctx, ExecutionRequest{
		Command: []string{"/bin/sh", "-c", command},
		Output: func(chunk string) {
			if chunk == "" {
				return
			}
			hadOutput = true
			_ = w.Send(&filesystem.ExecuteResponse{Output: chunk}, nil)
		},
	})
	if err == nil {
		exitCode := result.ExitCode
		_ = w.Send(&filesystem.ExecuteResponse{ExitCode: &exitCode}, nil)
		return
	}
	if exitCode, ok := commandExitCode(err); ok {
		resp := &filesystem.ExecuteResponse{ExitCode: &exitCode}
		if !hadOutput {
			resp.Output = FormatCommandFailureResult(exitCode, result.Output)
		}
		_ = w.Send(resp, nil)
		return
	}
	_ = w.Send(nil, fmt.Errorf("command failed: %w", err))
}
