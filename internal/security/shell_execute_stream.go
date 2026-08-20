package security

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/tooloutput"

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
	resolver       ExecutionBackendResolver
	maxOutputBytes int
	spillRootDir   string
}

const ptyRetryProbeDelay = 250 * time.Millisecond

// streamingOutputGate keeps only the very first short output burst speculative.
// Immediate "not a tty" failures can then be replaced by the authoritative PTY
// retry result, while longer commands still begin streaming after a small bound.
type streamingOutputGate struct {
	mu      sync.Mutex
	sendMu  sync.Mutex
	pending strings.Builder
	timer   *time.Timer
	flushed bool
	closed  bool
	emitted bool
	send    func(string)
}

func newStreamingOutputGate(send func(string)) *streamingOutputGate {
	return &streamingOutputGate{send: send}
}

func (g *streamingOutputGate) Write(chunk string) {
	if g == nil || chunk == "" {
		return
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	if g.flushed {
		g.mu.Unlock()
		g.emit(chunk)
		return
	}
	g.pending.WriteString(chunk)
	if g.timer == nil {
		g.timer = time.AfterFunc(ptyRetryProbeDelay, g.flush)
	}
	g.mu.Unlock()
}

func (g *streamingOutputGate) flush() {
	if g == nil {
		return
	}
	g.sendMu.Lock()
	defer g.sendMu.Unlock()
	g.mu.Lock()
	if g.closed || g.flushed {
		g.mu.Unlock()
		return
	}
	chunk := g.pending.String()
	g.pending.Reset()
	g.flushed = true
	if chunk != "" {
		g.emitted = true
	}
	g.mu.Unlock()
	if chunk != "" && g.send != nil {
		g.send(chunk)
	}
}

func (g *streamingOutputGate) emit(chunk string) {
	if g == nil || chunk == "" {
		return
	}
	g.sendMu.Lock()
	defer g.sendMu.Unlock()
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.emitted = true
	g.mu.Unlock()
	if g.send != nil {
		g.send(chunk)
	}
}

// Finish closes the speculative window. If it never flushed, only the
// backend's authoritative result is emitted, so a successful PTY retry does
// not retain the first non-TTY diagnostic in the tool result.
func (g *streamingOutputGate) Finish(authoritative string) bool {
	if g == nil {
		return false
	}
	g.sendMu.Lock()
	g.mu.Lock()
	g.closed = true
	if g.timer != nil {
		g.timer.Stop()
	}
	chunk := ""
	if !g.flushed {
		chunk = authoritative
		if chunk == "" {
			chunk = g.pending.String()
		}
		g.pending.Reset()
		if chunk != "" {
			g.emitted = true
		}
	}
	emitted := g.emitted
	g.mu.Unlock()
	if chunk != "" && g.send != nil {
		g.send(chunk)
	}
	g.sendMu.Unlock()
	return emitted
}

// NewEinoStreamingShell 创建 execute 流式 shell 实现。
func NewEinoStreamingShell() *EinoStreamingShell {
	return NewEinoStreamingShellWithResolver(NewFixedExecutionBackendResolver(NewHostExecutionBackend()))
}

func NewEinoStreamingShellWithResolver(resolver ExecutionBackendResolver) *EinoStreamingShell {
	return NewEinoStreamingShellWithResolverAndOutputLimit(resolver, 0, "")
}

// NewEinoStreamingShellWithResolverAndOutputLimit keeps the execute tool's
// model-facing stream bounded. The backend remains responsible for persisting
// the complete output, which means container conversations can expose only a
// /workspace/.tool-output reference while host conversations retain the
// reduction-cache behavior.
func NewEinoStreamingShellWithResolverAndOutputLimit(resolver ExecutionBackendResolver, maxOutputBytes int, spillRootDir string) *EinoStreamingShell {
	if resolver == nil {
		resolver = NewFixedExecutionBackendResolver(NewHostExecutionBackend())
	}
	return &EinoStreamingShell{
		resolver:       resolver,
		maxOutputBytes: maxOutputBytes,
		spillRootDir:   strings.TrimSpace(spillRootDir),
	}
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
	spill := tooloutput.SpillOpts{
		RootDir:        s.spillRootDir,
		ProjectID:      mcp.MCPProjectIDFromContext(ctx),
		ConversationID: mcp.MCPConversationIDFromContext(ctx),
		ExecutionID:    mcp.MCPExecutionIDFromContext(ctx),
	}
	go streamShellForeground(ctx, backend, input.Command, w, s.maxOutputBytes, spill)
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

func streamShellForeground(ctx context.Context, backend ExecutionBackend, command string, w *schema.StreamWriter[*filesystem.ExecuteResponse], maxOutputBytes int, spill tooloutput.SpillOpts) {
	defer w.Close()

	command = PrepareShellCommandForExecute(command)
	_, containerBoundedOutput := backend.(*containerExecutionBackend)
	if maxOutputBytes > 0 && containerBoundedOutput {
		streamShellForegroundBounded(ctx, backend, command, w, maxOutputBytes, spill)
		return
	}
	gate := newStreamingOutputGate(func(chunk string) {
		_ = w.Send(&filesystem.ExecuteResponse{Output: chunk}, nil)
	})
	result, err := backend.Execute(ctx, ExecutionRequest{
		Command:      []string{"/bin/sh", "-c", command},
		RetryWithPTY: true,
		Output: func(chunk string) {
			gate.Write(chunk)
		},
	})
	hadOutput := gate.Finish(result.Output)
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

// streamShellForegroundBounded deliberately withholds stdout/stderr text from
// the ADK stream until the backend has either returned the complete small
// result or replaced an oversized result with a durable reference. Empty
// responses are activity heartbeats: the outer execute wrapper can preserve
// inactivity-timeout semantics without persisting raw deltas in the database
// or exposing them to the model context.
func streamShellForegroundBounded(
	ctx context.Context,
	backend ExecutionBackend,
	command string,
	w *schema.StreamWriter[*filesystem.ExecuteResponse],
	maxOutputBytes int,
	spill tooloutput.SpillOpts,
) {
	result, err := backend.Execute(ctx, ExecutionRequest{
		Command:        []string{"/bin/sh", "-c", command},
		RetryWithPTY:   true,
		MaxOutputBytes: maxOutputBytes,
		Spill:          spill,
		Output: func(string) {
			_ = w.Send(&filesystem.ExecuteResponse{}, nil)
		},
	})
	hadOutput := result.Output != ""
	if hadOutput {
		_ = w.Send(&filesystem.ExecuteResponse{Output: result.Output}, nil)
	}
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
