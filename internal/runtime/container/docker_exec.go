package container

import (
	"context"
	"fmt"
	"path"
	"strings"

	mobystdcopy "github.com/moby/moby/api/pkg/stdcopy"
	mobyclient "github.com/moby/moby/client"
)

const maxContainerExecArgumentBytes = 1 << 20

type dockerExecAPI interface {
	ExecCreate(context.Context, string, mobyclient.ExecCreateOptions) (mobyclient.ExecCreateResult, error)
	ExecAttach(context.Context, string, mobyclient.ExecAttachOptions) (mobyclient.ExecAttachResult, error)
	ExecInspect(context.Context, string, mobyclient.ExecInspectOptions) (mobyclient.ExecInspectResult, error)
}

// Exec runs one non-interactive argv command inside the owned conversation
// runtime. It verifies the durable RuntimeSpec immediately before creating the
// engine exec and never accepts a request-provided provider/container ID.
func (m *DockerManager) Exec(ctx context.Context, spec RuntimeSpec, request ExecRequest, sink ExecOutputSink) (ExecResult, error) {
	if m == nil || m.execAPI == nil || m.execLimiter == nil {
		return ExecResult{}, fmt.Errorf("%w: container exec API is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return ExecResult{}, invalidSpec("exec context is required")
	}
	if err := ValidateSpec(spec); err != nil {
		return ExecResult{}, err
	}
	if err := validateExecRequest(spec, request); err != nil {
		return ExecResult{}, err
	}

	permit, err := m.execLimiter.Acquire(ctx, spec.ID, spec.Resources)
	if err != nil {
		return ExecResult{}, err
	}
	defer permit.Release()

	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return ExecResult{}, err
	}
	runtime, err := m.inspectOwned(operationCtx, spec.ID)
	cancel()
	if err != nil {
		return ExecResult{}, err
	}
	if runtime.ConversationID != spec.ConversationID || runtime.SpecDigest != RuntimeSpecDigest(spec) {
		return ExecResult{}, fmt.Errorf("%w: runtime specification changed before exec", ErrRuntimeStateConflict)
	}
	if runtime.Status != StatusRunning {
		return ExecResult{}, fmt.Errorf("%w: runtime %s is %s", ErrRuntimeStateConflict, spec.ID, runtime.Status)
	}

	workingDir := strings.TrimSpace(request.WorkingDir)
	if workingDir == "" {
		workingDir = spec.Workspace.MountPath
	}
	created, err := m.execAPI.ExecCreate(ctx, runtime.ProviderID, mobyclient.ExecCreateOptions{
		Privileged:   false,
		TTY:          false,
		AttachStdin:  false,
		AttachStdout: true,
		AttachStderr: true,
		Env:          append([]string(nil), request.Env...),
		WorkingDir:   workingDir,
		Cmd:          append([]string(nil), request.Command...),
	})
	if err != nil {
		return ExecResult{}, fmt.Errorf("create exec for runtime %s: %w", spec.ID, err)
	}
	if strings.TrimSpace(created.ID) == "" {
		return ExecResult{}, fmt.Errorf("%w: engine returned an empty exec id", ErrRuntimeStateConflict)
	}

	attached, err := m.execAPI.ExecAttach(ctx, created.ID, mobyclient.ExecAttachOptions{TTY: false})
	if err != nil {
		return ExecResult{ExecID: created.ID}, fmt.Errorf("attach exec %s: %w", created.ID, err)
	}
	defer attached.Close()

	copyDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			attached.Close()
		case <-copyDone:
		}
	}()
	_, copyErr := mobystdcopy.StdCopy(
		execSinkWriter{stream: ExecStreamStdout, sink: sink},
		execSinkWriter{stream: ExecStreamStderr, sink: sink},
		attached.Reader,
	)
	close(copyDone)
	if ctx.Err() != nil {
		return ExecResult{ExecID: created.ID}, ctx.Err()
	}
	if copyErr != nil {
		return ExecResult{ExecID: created.ID}, fmt.Errorf("read exec %s output: %w", created.ID, copyErr)
	}

	inspection, err := m.execAPI.ExecInspect(ctx, created.ID, mobyclient.ExecInspectOptions{})
	if err != nil {
		return ExecResult{ExecID: created.ID}, fmt.Errorf("inspect exec %s: %w", created.ID, err)
	}
	if inspection.ID != created.ID || inspection.ContainerID != runtime.ProviderID {
		return ExecResult{ExecID: created.ID}, fmt.Errorf("%w: exec identity does not match the owned runtime", ErrRuntimeStateConflict)
	}
	if inspection.Running {
		return ExecResult{ExecID: created.ID}, fmt.Errorf("%w: exec %s still running after output closed", ErrRuntimeStateConflict, created.ID)
	}
	return ExecResult{ExecID: created.ID, ExitCode: inspection.ExitCode}, nil
}

func validateExecRequest(spec RuntimeSpec, request ExecRequest) error {
	if len(request.Command) == 0 || strings.TrimSpace(request.Command[0]) == "" {
		return invalidSpec("exec command is required")
	}
	total := 0
	for _, value := range request.Command {
		if strings.IndexByte(value, 0) >= 0 {
			return invalidSpec("exec command contains NUL")
		}
		total += len(value)
	}
	if total > maxContainerExecArgumentBytes {
		return invalidSpec("exec command exceeds the maximum encoded size")
	}
	workingDir := strings.TrimSpace(request.WorkingDir)
	if workingDir != "" {
		clean := path.Clean(workingDir)
		workspace := path.Clean(spec.Workspace.MountPath)
		if !path.IsAbs(clean) || (clean != workspace && !strings.HasPrefix(clean, workspace+"/")) {
			return invalidSpec("exec working directory must stay inside the conversation workspace")
		}
	}
	if len(request.Env) > 128 {
		return invalidSpec("exec environment has too many entries")
	}
	for _, value := range request.Env {
		if strings.IndexByte(value, 0) >= 0 || !strings.Contains(value, "=") {
			return invalidSpec("exec environment entry is invalid")
		}
	}
	return nil
}

type execSinkWriter struct {
	stream ExecStream
	sink   ExecOutputSink
}

func (w execSinkWriter) Write(chunk []byte) (int, error) {
	if w.sink == nil || len(chunk) == 0 {
		return len(chunk), nil
	}
	if err := w.sink(w.stream, chunk); err != nil {
		return 0, err
	}
	return len(chunk), nil
}
