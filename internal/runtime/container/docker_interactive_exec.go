package container

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"sync"

	"github.com/google/uuid"
	mobyclient "github.com/moby/moby/client"
)

const interactiveExecWrapperScript = `pidfile=$1
printf '%s\n' "$$" > "$pidfile" || exit 70
exec /bin/sh`

type dockerInteractiveExecAPI interface {
	dockerExecAPI
	ExecResize(context.Context, string, mobyclient.ExecResizeOptions) (mobyclient.ExecResizeResult, error)
}

type dockerInteractiveExecSession struct {
	manager     *DockerManager
	api         dockerInteractiveExecAPI
	spec        RuntimeSpec
	runtime     Runtime
	execID      string
	controlFile string
	attached    mobyclient.ExecAttachResult
	permit      *ExecPermit
	closeOnce   sync.Once
	closeErr    error
}

func validateInteractiveExecSize(cols, rows uint16) error {
	if cols < 2 || cols > 512 || rows < 2 || rows > 256 {
		return invalidSpec("interactive terminal size is outside the supported range")
	}
	return nil
}

// OpenInteractiveExec creates a TTY in the verified Agent container. The
// request cannot select a provider ID, executable, user, or working directory.
func (m *DockerManager) OpenInteractiveExec(ctx context.Context, spec RuntimeSpec, request InteractiveExecRequest) (InteractiveExecSession, error) {
	if m == nil || m.execLimiter == nil || m.api == nil {
		return nil, fmt.Errorf("%w: container exec API is not configured", ErrEngineUnavailable)
	}
	api, ok := m.api.(dockerInteractiveExecAPI)
	if !ok {
		return nil, fmt.Errorf("%w: interactive container exec API is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return nil, invalidSpec("interactive exec context is required")
	}
	if err := ValidateSpec(spec); err != nil {
		return nil, err
	}
	if err := validateInteractiveExecSize(request.Cols, request.Rows); err != nil {
		return nil, err
	}

	permit, err := m.execLimiter.Acquire(ctx, spec.ID, spec.Resources)
	if err != nil {
		return nil, err
	}
	release := true
	defer func() {
		if release {
			permit.Release()
		}
	}()

	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	runtime, err := m.inspectOwned(operationCtx, spec.ID)
	cancel()
	if err != nil {
		return nil, err
	}
	if runtime.ConversationID != spec.ConversationID || runtime.SpecDigest != RuntimeSpecDigest(spec) {
		return nil, fmt.Errorf("%w: runtime specification changed before interactive exec", ErrRuntimeStateConflict)
	}
	if runtime.Status != StatusRunning {
		return nil, fmt.Errorf("%w: runtime %s is %s", ErrRuntimeStateConflict, spec.ID, runtime.Status)
	}

	controlFile := "/tmp/.cyberstrike-exec-" + uuid.NewString() + ".pid"
	created, err := api.ExecCreate(ctx, runtime.ProviderID, mobyclient.ExecCreateOptions{
		Privileged:   false,
		User:         runtimeRootExecUser,
		TTY:          true,
		ConsoleSize:  mobyclient.ConsoleSize{Height: uint(request.Rows), Width: uint(request.Cols)},
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   spec.Workspace.MountPath,
		Env: runtimeExecEnvironment([]string{
			"TERM=xterm-256color",
			"COLUMNS=" + strconv.Itoa(int(request.Cols)),
			"LINES=" + strconv.Itoa(int(request.Rows)),
		}),
		Cmd: []string{"/bin/sh", "-c", interactiveExecWrapperScript, "cyberstrike-interactive-shell", controlFile},
	})
	if err != nil {
		return nil, fmt.Errorf("create interactive exec for runtime %s: %w", spec.ID, err)
	}
	if created.ID == "" {
		return nil, fmt.Errorf("%w: engine returned an empty interactive exec id", ErrRuntimeStateConflict)
	}

	attached, err := api.ExecAttach(ctx, created.ID, mobyclient.ExecAttachOptions{
		TTY: true,
		ConsoleSize: mobyclient.ConsoleSize{
			Height: uint(request.Rows),
			Width:  uint(request.Cols),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("attach interactive exec %s: %w", created.ID, err)
	}
	failAttached := func(primary error) (InteractiveExecSession, error) {
		attached.Close()
		return nil, joinExecTermination(primary, m.terminateExecProcess(spec, runtime, controlFile))
	}
	inspection, err := api.ExecInspect(ctx, created.ID, mobyclient.ExecInspectOptions{})
	if err != nil {
		return failAttached(fmt.Errorf("inspect interactive exec %s: %w", created.ID, err))
	}
	if inspection.ID != created.ID || inspection.ContainerID != runtime.ProviderID || !inspection.Running {
		return failAttached(fmt.Errorf("%w: interactive exec identity or state does not match the owned runtime", ErrRuntimeStateConflict))
	}

	release = false
	return &dockerInteractiveExecSession{
		manager: m, api: api, spec: spec, runtime: runtime, execID: created.ID,
		controlFile: controlFile, attached: attached, permit: permit,
	}, nil
}

func (s *dockerInteractiveExecSession) Read(p []byte) (int, error) {
	if s == nil || s.attached.Reader == nil {
		return 0, io.ErrClosedPipe
	}
	return s.attached.Reader.Read(p)
}

func (s *dockerInteractiveExecSession) Write(p []byte) (int, error) {
	if s == nil || s.attached.Conn == nil {
		return 0, io.ErrClosedPipe
	}
	return s.attached.Conn.Write(p)
}

func (s *dockerInteractiveExecSession) Resize(ctx context.Context, cols, rows uint16) error {
	if s == nil || s.api == nil || s.execID == "" {
		return io.ErrClosedPipe
	}
	if err := validateInteractiveExecSize(cols, rows); err != nil {
		return err
	}
	_, err := s.api.ExecResize(ctx, s.execID, mobyclient.ExecResizeOptions{Width: uint(cols), Height: uint(rows)})
	if err != nil {
		return fmt.Errorf("resize interactive exec %s: %w", s.execID, err)
	}
	return nil
}

func (s *dockerInteractiveExecSession) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.attached.Conn != nil {
			_ = s.attached.CloseWrite()
		}
		s.attached.Close()
		if s.manager != nil {
			s.closeErr = s.manager.terminateExecProcess(s.spec, s.runtime, s.controlFile)
		}
		if s.permit != nil {
			s.permit.Release()
		}
	})
	return s.closeErr
}

var _ InteractiveExecSession = (*dockerInteractiveExecSession)(nil)
var _ RuntimeInteractiveExecutor = (*DockerManager)(nil)
