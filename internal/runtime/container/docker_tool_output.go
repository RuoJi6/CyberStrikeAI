package container

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"

	mobystdcopy "github.com/moby/moby/api/pkg/stdcopy"
	mobyclient "github.com/moby/moby/client"
)

const toolOutputDirectory = ".tool-output"

const toolOutputWriteScript = `set -eu
destination=$1
expected_size=$2
workspace=$3
case "$destination" in
  "$workspace"/.tool-output/*) ;;
  *) exit 64 ;;
esac
directory=${destination%/*}
umask 022
[ ! -L "$directory" ]
mkdir -p -- "$directory"
resolved_directory=$(CDPATH= cd -P "$directory" && pwd -P)
[ "$resolved_directory" = "$workspace/.tool-output" ]
temporary="${destination}.tmp.$$"
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
(umask 077; set -C; cat > "$temporary")
actual_size=$(wc -c < "$temporary" | tr -d '[:space:]')
[ "$actual_size" = "$expected_size" ]
chmod 0644 "$temporary"
mv -f -- "$temporary" "$destination"
trap - EXIT HUP INT TERM`

// WriteToolOutput streams one complete output file over a non-privileged exec
// stdin into the owned running conversation container. Docker archive copy is
// intentionally not used: the daemon rejects CopyToContainer for a read-only
// rootfs even when /workspace itself is a writable tmpfs. Runtime identity is
// re-verified immediately before the fixed-path exec, exactly as it is for
// normal command execution.
func (m *DockerManager) WriteToolOutput(ctx context.Context, spec RuntimeSpec, request ToolOutputWriteRequest) (string, error) {
	if m == nil || m.execAPI == nil {
		return "", fmt.Errorf("%w: container exec API is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return "", invalidSpec("tool output context is required")
	}
	if err := ValidateSpec(spec); err != nil {
		return "", err
	}
	fileName := strings.TrimSpace(request.FileName)
	if fileName == "" || fileName != path.Base(fileName) || fileName == "." || fileName == ".." || strings.ContainsAny(fileName, "/\\\x00") {
		return "", invalidSpec("tool output file name is invalid")
	}
	if request.Content == nil || request.Size < 0 {
		return "", invalidSpec("tool output content and size are required")
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
		return "", fmt.Errorf("%w: runtime specification changed before tool output write", ErrRuntimeStateConflict)
	}
	if runtime.Status != StatusRunning {
		return "", fmt.Errorf("%w: runtime %s is %s", ErrRuntimeStateConflict, spec.ID, runtime.Status)
	}

	destination := path.Join(spec.Workspace.MountPath, toolOutputDirectory, fileName)
	created, err := m.execAPI.ExecCreate(operationCtx, runtime.ProviderID, mobyclient.ExecCreateOptions{
		Privileged:   false,
		TTY:          false,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   spec.Workspace.MountPath,
		Cmd: []string{
			"/bin/sh", "-c", toolOutputWriteScript, "cyberstrike-tool-output",
			destination, strconv.FormatInt(request.Size, 10), spec.Workspace.MountPath,
		},
	})
	if err != nil {
		return "", fmt.Errorf("create tool output writer for runtime %s: %w", spec.ID, err)
	}
	if strings.TrimSpace(created.ID) == "" {
		return "", fmt.Errorf("%w: engine returned an empty tool output writer exec id", ErrRuntimeStateConflict)
	}

	attached, err := m.execAPI.ExecAttach(operationCtx, created.ID, mobyclient.ExecAttachOptions{TTY: false})
	if err != nil {
		return "", fmt.Errorf("attach tool output writer %s: %w", created.ID, err)
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
	written, writeErr := io.CopyN(attached.Conn, request.Content, request.Size)
	if closeErr := attached.CloseWrite(); writeErr == nil {
		writeErr = closeErr
	}
	readErr := <-readDone
	if operationCtx.Err() != nil {
		return "", fmt.Errorf("stream tool output into runtime %s: %w", spec.ID, operationCtx.Err())
	}
	if writeErr != nil || written != request.Size {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return "", fmt.Errorf("stream tool output into runtime %s (%d/%d bytes): %w%s", spec.ID, written, request.Size, writeErr, toolOutputDiagnostic(stderr.String()))
	}
	if readErr != nil {
		return "", fmt.Errorf("read tool output writer %s: %w%s", created.ID, readErr, toolOutputDiagnostic(stderr.String()))
	}

	inspection, err := m.execAPI.ExecInspect(operationCtx, created.ID, mobyclient.ExecInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("inspect tool output writer %s: %w", created.ID, err)
	}
	if inspection.ID != created.ID || inspection.ContainerID != runtime.ProviderID || inspection.Running {
		return "", fmt.Errorf("%w: tool output writer identity or state does not match the owned runtime", ErrRuntimeStateConflict)
	}
	if inspection.ExitCode != 0 {
		return "", fmt.Errorf("tool output writer %s exited with code %d%s", created.ID, inspection.ExitCode, toolOutputDiagnostic(stderr.String()))
	}
	return destination, nil
}

func toolOutputDiagnostic(stderr string) string {
	const maxDiagnosticBytes = 4096
	text := strings.TrimSpace(stderr)
	if text == "" {
		return ""
	}
	if len(text) > maxDiagnosticBytes {
		text = text[:maxDiagnosticBytes]
	}
	return ": " + text
}
