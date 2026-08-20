package security

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"

	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/tooloutput"
)

// ExecutionRequest is shared by exec, Eino execute and command-backed YAML
// tools. Command is argv-based so shell interpretation only occurs when the
// caller explicitly selects a shell in argv.
type ExecutionRequest struct {
	Command            []string
	WorkingDir         string
	Env                []string
	Output             ToolOutputCallback
	NoOutputTimeoutSec int
	MaxOutputBytes     int
	Spill              tooloutput.SpillOpts
	RetryWithPTY       bool
}

type ExecutionResult struct {
	Output         string
	ExitCode       int
	Location       string
	RuntimeID      string
	ProviderExecID string
}

// ExecutionBackend is the only OS-command boundary used by Agent tools.
type ExecutionBackend interface {
	Execute(context.Context, ExecutionRequest) (ExecutionResult, error)
}

// ExecutionLocationReporter lets filesystem middleware select its host or
// container implementation from trusted backend state rather than user input.
type ExecutionLocationReporter interface {
	ExecutionLocation() string
}

// WorkspaceFileWriter exposes a normalized /workspace write without exposing
// Docker provider IDs or arbitrary host destinations.
type WorkspaceFileWriter interface {
	WriteWorkspaceFile(context.Context, string, io.Reader, int64) (string, error)
}

// ExecutionBackendResolver chooses host or container from trusted conversation
// state already carried in context. A resolver error is fail-closed.
type ExecutionBackendResolver interface {
	ResolveExecutionBackend(context.Context) (ExecutionBackend, error)
}

type ExecutionBackendResolverFunc func(context.Context) (ExecutionBackend, error)

func (f ExecutionBackendResolverFunc) ResolveExecutionBackend(ctx context.Context) (ExecutionBackend, error) {
	return f(ctx)
}

type fixedExecutionBackendResolver struct{ backend ExecutionBackend }

func (r fixedExecutionBackendResolver) ResolveExecutionBackend(context.Context) (ExecutionBackend, error) {
	if r.backend == nil {
		return nil, fmt.Errorf("execution backend is not configured")
	}
	return r.backend, nil
}

func NewHostExecutionBackend() ExecutionBackend { return hostExecutionBackend{} }

func NewFixedExecutionBackendResolver(backend ExecutionBackend) ExecutionBackendResolver {
	return fixedExecutionBackendResolver{backend: backend}
}

type hostExecutionBackend struct{}

func (hostExecutionBackend) ExecutionLocation() string { return "host" }

func (hostExecutionBackend) Execute(ctx context.Context, request ExecutionRequest) (ExecutionResult, error) {
	if len(request.Command) == 0 || strings.TrimSpace(request.Command[0]) == "" {
		return ExecutionResult{Location: "host", ExitCode: -1}, fmt.Errorf("command is required")
	}
	newCommand := func() *exec.Cmd {
		cmd := exec.CommandContext(ctx, request.Command[0], request.Command[1:]...)
		cmd.Dir = strings.TrimSpace(request.WorkingDir)
		if len(request.Env) > 0 {
			cmd.Env = append(os.Environ(), request.Env...)
		}
		ConfigureShellCmdForAgentExecute(cmd)
		return cmd
	}

	cmd := newCommand()
	var output string
	var err error
	if request.Output != nil {
		output, err = streamCommandOutput(ctx, cmd, request.Output, request.NoOutputTimeoutSec, request.MaxOutputBytes, request.Spill)
	} else {
		output, err = combinedOutputCancellableWithLimit(ctx, cmd, request.MaxOutputBytes, request.Spill)
	}
	if err != nil && request.RetryWithPTY && shouldRetryWithPTY(output) {
		cmd = newCommand()
		output, err = runCommandWithPTY(ctx, cmd, request.Output, request.MaxOutputBytes, request.Spill)
	}
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}
	return ExecutionResult{Output: output, ExitCode: exitCode, Location: "host"}, err
}

// CommandExitError preserves a container process exit code without pretending
// it is an os/exec.ExitError from a host process.
type CommandExitError struct{ Code int }

func (e *CommandExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }
func (e *CommandExitError) ExitCode() int { return e.Code }

type exitCoder interface{ ExitCode() int }

func commandExitCode(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	var coder exitCoder
	if errors.As(err, &coder) {
		return coder.ExitCode(), true
	}
	return 0, false
}

type containerExecutionBackend struct {
	executor containerruntime.RuntimeExecutor
	spec     containerruntime.RuntimeSpec
}

func (*containerExecutionBackend) ExecutionLocation() string { return "container" }

func (b *containerExecutionBackend) WriteWorkspaceFile(ctx context.Context, filePath string, content io.Reader, size int64) (string, error) {
	if b == nil || b.executor == nil {
		return "", fmt.Errorf("container execution backend is not configured")
	}
	writer, ok := b.executor.(containerruntime.RuntimeWorkspaceFileWriter)
	if !ok {
		return "", fmt.Errorf("container workspace writer is unavailable")
	}
	return writer.WriteWorkspaceFile(ctx, b.spec, containerruntime.WorkspaceFileWriteRequest{
		Path: filePath, Content: content, Size: size,
	})
}

func NewContainerExecutionBackend(executor containerruntime.RuntimeExecutor, spec containerruntime.RuntimeSpec) (ExecutionBackend, error) {
	if executor == nil {
		return nil, fmt.Errorf("container execution backend is not configured")
	}
	if err := containerruntime.ValidateSpec(spec); err != nil {
		return nil, err
	}
	return &containerExecutionBackend{executor: executor, spec: spec}, nil
}

func (b *containerExecutionBackend) Execute(ctx context.Context, request ExecutionRequest) (ExecutionResult, error) {
	if b == nil || b.executor == nil {
		return ExecutionResult{Location: "container", ExitCode: -1}, fmt.Errorf("container execution backend is not configured")
	}
	env := append([]string{
		"HOME=/workspace",
		"TMPDIR=/tmp",
		"TERM=xterm-256color",
		"COLUMNS=256",
		"LINES=40",
		"PAGER=cat",
		"GIT_PAGER=cat",
		"SYSTEMD_PAGER=cat",
		"DEBIAN_FRONTEND=noninteractive",
	}, request.Env...)
	workingDir, err := containerruntime.NormalizeWorkspacePath(b.spec.Workspace.MountPath, request.WorkingDir)
	if err != nil {
		return ExecutionResult{Location: "container", ExitCode: -1}, err
	}
	run := func(tty bool) (ExecutionResult, error) {
		var tee *tooloutput.Tee
		if request.MaxOutputBytes > 0 {
			tee = tooloutput.NewTemporaryTee()
		}
		collector := newBoundedOutputCollector(request.MaxOutputBytes, tee)

		execCtx := ctx
		cancel := func() {}
		var idleWatch *ShellInactivityWatch
		idleExpired := make(chan struct{}, 1)
		watchDone := make(chan struct{})
		if request.Output != nil {
			idleWatch = NewShellInactivityWatch(request.NoOutputTimeoutSec)
		}
		if idleWatch != nil {
			execCtx, cancel = context.WithCancel(ctx)
			go func() {
				select {
				case <-idleWatch.Expired:
					select {
					case idleExpired <- struct{}{}:
					default:
					}
					cancel()
				case <-watchDone:
				}
			}()
		}

		sink := func(_ containerruntime.ExecStream, chunk []byte) error {
			if len(chunk) > 0 && idleWatch != nil {
				idleWatch.Bump()
			}
			kept := collector.WriteStringLimited(string(chunk))
			if request.Output != nil && len(chunk) > 0 {
				// An empty callback still signals process activity after the
				// model-facing byte budget has been exhausted.
				request.Output(kept)
			}
			return nil
		}
		result, err := b.executor.Exec(execCtx, b.spec, containerruntime.ExecRequest{
			Command:    append([]string(nil), request.Command...),
			WorkingDir: workingDir,
			Env:        env,
			TTY:        tty,
		}, sink)
		if idleWatch != nil {
			idleWatch.Stop()
			close(watchDone)
			cancel()
		}
		select {
		case <-idleExpired:
			msg := ShellNoOutputTimeoutMessage(idleWatch.Sec)
			kept := collector.WriteStringLimited(msg)
			if kept != "" && request.Output != nil {
				request.Output(kept)
			}
			timeoutErr := fmt.Errorf("shell inactivity timeout (%ds)", idleWatch.Sec)
			var terminationErr *containerruntime.ExecTerminationError
			if errors.As(err, &terminationErr) {
				err = errors.Join(timeoutErr, terminationErr)
			} else {
				err = timeoutErr
			}
			result.ExitCode = -1
		default:
		}
		output, persistErr := finalizeContainerBoundedOutput(ctx, collector, request.MaxOutputBytes, tee, b.executor, b.spec, request.Spill)
		if persistErr != nil {
			err = errors.Join(err, persistErr)
		}
		executionResult := ExecutionResult{
			Output:         output,
			ExitCode:       result.ExitCode,
			Location:       "container",
			RuntimeID:      string(b.spec.ID),
			ProviderExecID: result.ExecID,
		}
		if err != nil {
			if executionResult.ExitCode == 0 {
				executionResult.ExitCode = -1
			}
			return executionResult, err
		}
		if result.ExitCode != 0 {
			return executionResult, &CommandExitError{Code: result.ExitCode}
		}
		return executionResult, nil
	}

	result, err := run(false)
	if err != nil && request.RetryWithPTY && ctx.Err() == nil && shouldRetryWithPTY(result.Output) {
		return run(true)
	}
	return result, err
}

func finalizeContainerBoundedOutput(
	ctx context.Context,
	collector *boundedOutputCollector,
	maxBytes int,
	tee *tooloutput.Tee,
	executor containerruntime.RuntimeExecutor,
	spec containerruntime.RuntimeSpec,
	spill tooloutput.SpillOpts,
) (string, error) {
	if tee != nil {
		_ = tee.Close()
	}
	if collector == nil {
		return "", nil
	}
	stagingPath := ""
	if tee != nil {
		stagingPath = tee.Path()
	}
	if stagingPath != "" {
		defer os.Remove(stagingPath)
	}
	if !collector.truncated || maxBytes <= 0 {
		return collector.String(), nil
	}
	if stagingPath == "" {
		return truncateStringBytes(collector.String(), maxBytes), fmt.Errorf("persist oversized container output: staging file unavailable")
	}
	writer, ok := executor.(containerruntime.RuntimeToolOutputWriter)
	if !ok {
		return truncateStringBytes(collector.String(), maxBytes), fmt.Errorf("persist oversized container output: runtime writer is unavailable")
	}
	file, err := os.Open(stagingPath)
	if err != nil {
		return truncateStringBytes(collector.String(), maxBytes), fmt.Errorf("open oversized container output staging file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return truncateStringBytes(collector.String(), maxBytes), fmt.Errorf("stat oversized container output staging file: %w", err)
	}
	if info.Size() != int64(collector.seenBytes) {
		return truncateStringBytes(collector.String(), maxBytes), fmt.Errorf("persist oversized container output: staged %d bytes, observed %d", info.Size(), collector.seenBytes)
	}
	expectedRef := tooloutput.WorkspaceOutputPath(spill.ExecutionID)
	ref, err := writer.WriteToolOutput(ctx, spec, containerruntime.ToolOutputWriteRequest{
		FileName: path.Base(expectedRef),
		Content:  file,
		Size:     info.Size(),
	})
	if err != nil {
		return truncateStringBytes(collector.String(), maxBytes), fmt.Errorf("persist oversized container output: %w", err)
	}
	if ref != expectedRef {
		return truncateStringBytes(collector.String(), maxBytes), fmt.Errorf("persist oversized container output: runtime returned unexpected reference %q", ref)
	}
	return tooloutput.FormatPersistedFromSourceFile(stagingPath, ref, collector.seenBytes, maxBytes), nil
}
