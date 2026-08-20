package container_test

import (
	"errors"
	"testing"

	"cyberstrike-ai/internal/runtime/container"
)

func TestValidateSpec(t *testing.T) {
	valid := validSpec()
	if err := container.ValidateSpec(valid); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*container.RuntimeSpec)
	}{
		{name: "missing runtime id", mutate: func(spec *container.RuntimeSpec) { spec.ID = "" }},
		{name: "floating image", mutate: func(spec *container.RuntimeSpec) { spec.Image.Digest = "latest" }},
		{name: "repository includes tag", mutate: func(spec *container.RuntimeSpec) { spec.Image.Repository = "ghcr.io/example/sandbox:latest" }},
		{name: "non-linux platform", mutate: func(spec *container.RuntimeSpec) { spec.Image.Platform = "windows/amd64" }},
		{name: "non-canonical platform alias", mutate: func(spec *container.RuntimeSpec) { spec.Image.Platform = "linux/aarch64" }},
		{name: "forged resolved digest", mutate: func(spec *container.RuntimeSpec) { spec.Image.ResolvedDigest = spec.Image.Digest }},
		{name: "unlimited cpu", mutate: func(spec *container.RuntimeSpec) { spec.Resources.NanoCPUs = 0 }},
		{name: "writable rootfs", mutate: func(spec *container.RuntimeSpec) { spec.Security.ReadOnlyRootFS = false }},
		{name: "host network", mutate: func(spec *container.RuntimeSpec) { spec.Security.NetworkMode = "host" }},
		{name: "internal network before gateway phase", mutate: func(spec *container.RuntimeSpec) { spec.Security.NetworkMode = container.NetworkInternal }},
		{name: "host bind path", mutate: func(spec *container.RuntimeSpec) { spec.Workspace.MountPath = "/host" }},
		{name: "unnamed persistent volume", mutate: func(spec *container.RuntimeSpec) { spec.Workspace.VolumeName = "" }},
		{name: "arbitrary persistent volume", mutate: func(spec *container.RuntimeSpec) { spec.Workspace.VolumeName = "user-volume" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := valid
			test.mutate(&spec)
			err := container.ValidateSpec(spec)
			if !errors.Is(err, container.ErrInvalidSpecification) {
				t.Fatalf("expected invalid specification, got %v", err)
			}
		})
	}
}

func validSpec() container.RuntimeSpec {
	return container.RuntimeSpec{
		ID:             "runtime-1",
		ConversationID: "conversation-1",
		Image: container.ImageReference{
			Repository: "ghcr.io/example/sandbox",
			Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:   "linux/arm64",
		},
		Resources: container.ResourceLimits{
			NanoCPUs:          1_000_000_000,
			MemoryBytes:       512 << 20,
			PIDs:              128,
			NoFileSoft:        1024,
			NoFileHard:        2048,
			WorkspaceBytes:    1 << 30,
			MaxConcurrentExec: 2,
		},
		Security: container.SecurityProfile{
			ReadOnlyRootFS:      true,
			NoNewPrivileges:     true,
			DropAllCapabilities: true,
			NetworkMode:         container.NetworkNone,
			SeccompProfile:      "default",
			TmpfsBytes:          64 << 20,
		},
		Workspace: container.WorkspaceSpec{
			Persistent: true,
			VolumeName: "cyberstrike-workspace-1",
			MountPath:  "/workspace",
		},
	}
}
