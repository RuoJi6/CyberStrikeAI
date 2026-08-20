package container

import (
	"context"
	"path"
	"strings"
)

const toolOutputDirectory = ".tool-output"

const toolOutputWriteScript = workspaceFileWriteScript

// WriteToolOutput streams one complete output file over a non-privileged exec
// stdin into the owned running conversation container. Docker archive copy is
// intentionally not used: the daemon rejects CopyToContainer for a read-only
// rootfs even when /workspace itself is a writable tmpfs. Runtime identity is
// re-verified immediately before the fixed-path exec, exactly as it is for
// normal command execution.
func (m *DockerManager) WriteToolOutput(ctx context.Context, spec RuntimeSpec, request ToolOutputWriteRequest) (string, error) {
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

	destination := path.Join(spec.Workspace.MountPath, toolOutputDirectory, fileName)
	return m.writeWorkspaceFile(ctx, spec, destination, request.Content, request.Size, "tool output")
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
