package container

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	mobystdcopy "github.com/moby/moby/api/pkg/stdcopy"
	mobyclient "github.com/moby/moby/client"
)

const workspaceFileWriteScript = `set -eu
destination=$1
expected_size=$2
workspace=$3
case "$destination" in
  "$workspace"/*) ;;
  *) exit 64 ;;
esac
directory=${destination%/*}
relative_directory=${directory#"$workspace"}
relative_directory=${relative_directory#/}
current=$workspace
set -f
old_ifs=$IFS
IFS=/
set -- $relative_directory
IFS=$old_ifs
umask 022
for segment in "$@"; do
  [ -n "$segment" ] || continue
  current="$current/$segment"
  [ ! -L "$current" ] || exit 65
  if [ ! -e "$current" ]; then
    mkdir -- "$current"
  else
    [ -d "$current" ] || exit 66
  fi
done
resolved_directory=$(CDPATH= cd -P "$directory" && pwd -P)
[ "$resolved_directory" = "$directory" ]
[ ! -L "$destination" ]
temporary="${destination}.tmp.$$"
[ ! -L "$temporary" ]
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
(umask 077; set -C; cat > "$temporary")
actual_size=$(wc -c < "$temporary" | tr -d '[:space:]')
[ "$actual_size" = "$expected_size" ]
chmod 0644 "$temporary"
mv -f -- "$temporary" "$destination"
trap - EXIT HUP INT TERM`

// WriteWorkspaceFile streams a file into the owned conversation workspace.
// The destination is canonicalized before Docker is contacted and the writer
// rejects symlinked path components inside the container.
func (m *DockerManager) WriteWorkspaceFile(ctx context.Context, spec RuntimeSpec, request WorkspaceFileWriteRequest) (string, error) {
	if err := ValidateSpec(spec); err != nil {
		return "", err
	}
	destination, err := NormalizeWorkspacePath(spec.Workspace.MountPath, request.Path)
	if err != nil {
		return "", err
	}
	if destination == spec.Workspace.MountPath {
		return "", invalidSpec("workspace file path must name a file")
	}
	if request.Content == nil || request.Size < 0 {
		return "", invalidSpec("workspace file content and size are required")
	}
	return m.writeWorkspaceFile(ctx, spec, destination, request.Content, request.Size, "workspace file")
}

func (m *DockerManager) writeWorkspaceFile(ctx context.Context, spec RuntimeSpec, destination string, content io.Reader, size int64, operation string) (string, error) {
	if m == nil || m.execAPI == nil {
		return "", fmt.Errorf("%w: container exec API is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return "", invalidSpec(operation + " context is required")
	}
	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return "", err
	}
	defer cancel()
	runtime, err := m.inspectOwned(operationCtx, spec.ID)
	if err != nil {
		return "", err
	}
	if runtime.ConversationID != spec.ConversationID || runtime.SpecDigest != RuntimeSpecDigest(spec) {
		return "", fmt.Errorf("%w: runtime specification changed before %s write", ErrRuntimeStateConflict, operation)
	}
	if runtime.Status != StatusRunning {
		return "", fmt.Errorf("%w: runtime %s is %s", ErrRuntimeStateConflict, spec.ID, runtime.Status)
	}

	created, err := m.execAPI.ExecCreate(operationCtx, runtime.ProviderID, mobyclient.ExecCreateOptions{
		Privileged:   false,
		User:         runtimeRootExecUser,
		TTY:          false,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   spec.Workspace.MountPath,
		Cmd: []string{
			"/bin/sh", "-c", workspaceFileWriteScript, "cyberstrike-workspace-file",
			destination, strconv.FormatInt(size, 10), spec.Workspace.MountPath,
		},
	})
	if err != nil {
		return "", fmt.Errorf("create %s writer for runtime %s: %w", operation, spec.ID, err)
	}
	if strings.TrimSpace(created.ID) == "" {
		return "", fmt.Errorf("%w: engine returned an empty %s writer exec id", ErrRuntimeStateConflict, operation)
	}

	attached, err := m.execAPI.ExecAttach(operationCtx, created.ID, mobyclient.ExecAttachOptions{TTY: false})
	if err != nil {
		return "", fmt.Errorf("attach %s writer %s: %w", operation, created.ID, err)
	}
	defer attached.Close()
	stopWatch := make(chan struct{})
	go func() {
		select {
		case <-operationCtx.Done():
			attached.Close()
		case <-stopWatch:
		}
	}()
	defer close(stopWatch)

	var stdout, stderr bytes.Buffer
	readDone := make(chan error, 1)
	go func() {
		_, readErr := mobystdcopy.StdCopy(&stdout, &stderr, attached.Reader)
		readDone <- readErr
	}()
	written, writeErr := io.CopyN(attached.Conn, content, size)
	if closeErr := attached.CloseWrite(); writeErr == nil {
		writeErr = closeErr
	}
	readErr := <-readDone
	if operationCtx.Err() != nil {
		return "", fmt.Errorf("stream %s into runtime %s: %w", operation, spec.ID, operationCtx.Err())
	}
	if writeErr != nil || written != size {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return "", fmt.Errorf("stream %s into runtime %s (%d/%d bytes): %w%s", operation, spec.ID, written, size, writeErr, toolOutputDiagnostic(stderr.String()))
	}
	if readErr != nil {
		return "", fmt.Errorf("read %s writer %s: %w%s", operation, created.ID, readErr, toolOutputDiagnostic(stderr.String()))
	}

	inspection, err := m.execAPI.ExecInspect(operationCtx, created.ID, mobyclient.ExecInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("inspect %s writer %s: %w", operation, created.ID, err)
	}
	if inspection.ID != created.ID || inspection.ContainerID != runtime.ProviderID || inspection.Running {
		return "", fmt.Errorf("%w: %s writer identity or state does not match the owned runtime", ErrRuntimeStateConflict, operation)
	}
	if inspection.ExitCode != 0 {
		return "", fmt.Errorf("%s writer %s exited with code %d%s", operation, created.ID, inspection.ExitCode, toolOutputDiagnostic(stderr.String()))
	}
	return destination, nil
}
