package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
	var tee *tooloutput.Tee
	if request.MaxOutputBytes > 0 {
		tee = tooloutput.NewTee(request.Spill)
	}
	collector := newBoundedOutputCollector(request.MaxOutputBytes, tee)
	sink := func(_ containerruntime.ExecStream, chunk []byte) error {
		kept := collector.WriteStringLimited(string(chunk))
		if kept != "" && request.Output != nil {
			request.Output(kept)
		}
		return nil
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
	result, err := b.executor.Exec(ctx, b.spec, containerruntime.ExecRequest{
		Command:    append([]string(nil), request.Command...),
		WorkingDir: strings.TrimSpace(request.WorkingDir),
		Env:        env,
	}, sink)
	output := finalizeBoundedOutput(collector, request.MaxOutputBytes, tee)
	executionResult := ExecutionResult{
		Output:         output,
		ExitCode:       result.ExitCode,
		Location:       "container",
		RuntimeID:      string(b.spec.ID),
		ProviderExecID: result.ExecID,
	}
	if err != nil {
		return executionResult, err
	}
	if result.ExitCode != 0 {
		return executionResult, &CommandExitError{Code: result.ExitCode}
	}
	return executionResult, nil
}
