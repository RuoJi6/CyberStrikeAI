package container

import (
	"path"
	"strings"
)

// NormalizeWorkspacePath converts a relative or workspace-absolute Linux path
// to one canonical path below workspace. It rejects Windows separators, NULs,
// absolute host paths and parent traversal before any Docker API is reached.
func NormalizeWorkspacePath(workspace, raw string) (string, error) {
	workspace = strings.TrimSpace(workspace)
	if workspace == "" || !path.IsAbs(workspace) || path.Clean(workspace) != workspace {
		return "", invalidSpec("workspace path is invalid")
	}
	raw = strings.TrimSpace(raw)
	if strings.IndexByte(raw, 0) >= 0 || strings.Contains(raw, `\`) {
		return "", invalidSpec("workspace file path contains an invalid separator")
	}
	if raw == "" || raw == "." {
		return workspace, nil
	}
	var normalized string
	if path.IsAbs(raw) {
		normalized = path.Clean(raw)
	} else {
		normalized = path.Join(workspace, raw)
	}
	if normalized != workspace && !strings.HasPrefix(normalized, workspace+"/") {
		return "", invalidSpec("path must stay inside the conversation workspace")
	}
	return normalized, nil
}
