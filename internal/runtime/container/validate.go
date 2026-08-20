package container

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var sha256DigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var generatedNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// ValidateSpec rejects ambiguous or unsafe runtime requests before an engine
// implementation sees them.
func ValidateSpec(spec RuntimeSpec) error {
	if strings.TrimSpace(string(spec.ID)) == "" {
		return invalidSpec("runtime id is required")
	}
	if !generatedNamePattern.MatchString(string(spec.ID)) {
		return invalidSpec("runtime id contains unsupported characters")
	}
	if strings.TrimSpace(spec.ConversationID) == "" {
		return invalidSpec("conversation id is required")
	}
	if strings.TrimSpace(spec.Image.Repository) == "" {
		return invalidSpec("image repository is required")
	}
	if !sha256DigestPattern.MatchString(spec.Image.Digest) {
		return invalidSpec("image digest must be a lowercase sha256 digest")
	}
	if strings.TrimSpace(spec.Image.ResolvedDigest) != "" {
		return invalidSpec("resolved image digest is engine output and cannot be requested")
	}
	if strings.TrimSpace(spec.Image.Platform) == "" {
		return invalidSpec("image platform is required")
	}
	if spec.Resources.NanoCPUs <= 0 || spec.Resources.MemoryBytes <= 0 || spec.Resources.PIDs <= 0 {
		return invalidSpec("cpu, memory and pid limits must be positive")
	}
	if spec.Resources.NoFileSoft == 0 || spec.Resources.NoFileHard == 0 || spec.Resources.NoFileSoft > spec.Resources.NoFileHard {
		return invalidSpec("nofile limits must be positive and ordered")
	}
	if spec.Resources.WorkspaceBytes <= 0 || spec.Resources.MaxConcurrentExec <= 0 {
		return invalidSpec("workspace and exec limits must be positive")
	}
	if !spec.Security.ReadOnlyRootFS || !spec.Security.NoNewPrivileges || !spec.Security.DropAllCapabilities {
		return invalidSpec("read-only rootfs, no-new-privileges and capability drop are required")
	}
	if spec.Security.NetworkMode != NetworkNone {
		return invalidSpec("phase 1 runtimes require network mode none")
	}
	if spec.Security.TmpfsBytes <= 0 {
		return invalidSpec("tmpfs limit must be positive")
	}
	if strings.TrimSpace(spec.Security.SeccompProfile) == "" {
		return invalidSpec("seccomp profile is required")
	}
	if spec.Workspace.MountPath != "/workspace" {
		return invalidSpec("workspace mount path must be /workspace")
	}
	if spec.Workspace.Persistent && strings.TrimSpace(spec.Workspace.VolumeName) == "" {
		return invalidSpec("persistent workspace requires a named volume")
	}
	if spec.Workspace.Persistent && (!generatedNamePattern.MatchString(spec.Workspace.VolumeName) || !strings.HasPrefix(spec.Workspace.VolumeName, "cyberstrike-workspace-")) {
		return invalidSpec("persistent workspace requires a CyberStrikeAI-owned named volume")
	}
	if !spec.Workspace.Persistent && strings.TrimSpace(spec.Workspace.VolumeName) != "" {
		return invalidSpec("ephemeral workspace cannot declare a named volume")
	}
	return nil
}

func invalidSpec(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpecification, message)
}

// IsNotFound allows callers to classify provider-specific wrapped errors.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}
