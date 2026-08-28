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
	internal := valid
	internal.Security.NetworkMode = container.NetworkInternal
	if err := container.ValidateSpec(internal); err != nil {
		t.Fatalf("valid internal-network spec rejected: %v", err)
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

func TestValidateSpecAcceptsSharedWorkspaceAcrossConversationRuntimes(t *testing.T) {
	first := validSpec()
	first.Workspace.ID = "shared-12345678-1234-1234-1234-123456789abc"
	first.Workspace.Shared = true
	first.Workspace.VolumeName = container.WorkspaceVolumeNameForID(first.Workspace.ID)
	if err := container.ValidateSpec(first); err != nil {
		t.Fatalf("first shared workspace spec rejected: %v", err)
	}

	second := first
	second.ID = "runtime-2"
	second.ConversationID = "conversation-2"
	if err := container.ValidateSpec(second); err != nil {
		t.Fatalf("second shared workspace spec rejected: %v", err)
	}
	if first.Workspace.VolumeName != second.Workspace.VolumeName {
		t.Fatalf("shared volume names differ: %q != %q", first.Workspace.VolumeName, second.Workspace.VolumeName)
	}

	missingID := first
	missingID.Workspace.ID = ""
	missingID.Workspace.VolumeName = container.WorkspaceVolumeName(missingID.ID)
	if err := container.ValidateSpec(missingID); !errors.Is(err, container.ErrInvalidSpecification) {
		t.Fatalf("shared workspace without explicit id error = %v", err)
	}
}

func TestValidateSpecRequiresPinnedLimitedGatewayOnInternalNetwork(t *testing.T) {
	spec := validSpec()
	spec.Security.NetworkMode = container.NetworkInternal
	spec.EgressGateway = &container.EgressGatewaySpec{
		Image: container.ImageReference{
			Repository: "ghcr.io/example/cyberstrike-egress",
			Digest:     "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			Platform:   "linux/arm64",
		},
		Resources: container.EgressGatewayResources{
			NanoCPUs: 250_000_000, MemoryBytes: 128 << 20, PIDs: 64,
			NoFileSoft: 512, NoFileHard: 1024, TmpfsBytes: 16 << 20,
			LogMaxBytes: 2 << 20, LogMaxFiles: 2,
		},
	}
	if err := container.ValidateSpec(spec); err != nil {
		t.Fatalf("valid gateway spec rejected: %v", err)
	}
	withSnapshot := spec
	gatewayWithSnapshot := *spec.EgressGateway
	gatewayWithSnapshot.BoundarySnapshot = &container.EgressBoundarySnapshotSpec{
		ID:     "12345678-1234-1234-1234-123456789abc",
		SHA256: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
	withSnapshot.EgressGateway = &gatewayWithSnapshot
	if err := container.ValidateSpec(withSnapshot); err != nil {
		t.Fatalf("valid gateway snapshot rejected: %v", err)
	}
	withRoute := withSnapshot
	gatewayWithRoute := *withSnapshot.EgressGateway
	gatewayWithRoute.UpstreamRoute = &container.EgressUpstreamRouteSpec{
		ID: "conversation-1", SHA256: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	withRoute.EgressGateway = &gatewayWithRoute
	if err := container.ValidateSpec(withRoute); err != nil {
		t.Fatalf("valid gateway upstream route rejected: %v", err)
	}
	versionedRoute := withRoute
	gatewayWithVersionedRoute := *withRoute.EgressGateway
	gatewayWithVersionedRoute.UpstreamRoute = &container.EgressUpstreamRouteSpec{
		ID: "conversation-1-egress-12345678-1234-1234-1234-123456789abc", SHA256: withRoute.EgressGateway.UpstreamRoute.SHA256,
	}
	versionedRoute.EgressGateway = &gatewayWithVersionedRoute
	if err := container.ValidateSpec(versionedRoute); err != nil {
		t.Fatalf("versioned conversation upstream route rejected: %v", err)
	}
	crossConversationRoute := withRoute
	gatewayWithCrossConversationRoute := *withRoute.EgressGateway
	gatewayWithCrossConversationRoute.UpstreamRoute = &container.EgressUpstreamRouteSpec{
		ID: "conversation-2", SHA256: withRoute.EgressGateway.UpstreamRoute.SHA256,
	}
	crossConversationRoute.EgressGateway = &gatewayWithCrossConversationRoute
	if err := container.ValidateSpec(crossConversationRoute); !errors.Is(err, container.ErrInvalidSpecification) {
		t.Fatalf("cross-conversation upstream route error = %v", err)
	}
	withAuthProfiles := withSnapshot
	gatewayWithAuthProfiles := *withSnapshot.EgressGateway
	gatewayWithAuthProfiles.AuthProfiles = &container.EgressAuthProfilesSpec{
		ID:     "auth-" + gatewayWithAuthProfiles.BoundarySnapshot.ID + "-aaaaaaaaaaaaaaaa",
		SHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	withAuthProfiles.EgressGateway = &gatewayWithAuthProfiles
	if err := container.ValidateSpec(withAuthProfiles); err != nil {
		t.Fatalf("snapshot-bound auth profiles rejected: %v", err)
	}
	crossSnapshotAuthProfiles := withAuthProfiles
	gatewayWithCrossSnapshotAuthProfiles := *withAuthProfiles.EgressGateway
	gatewayWithCrossSnapshotAuthProfiles.AuthProfiles = &container.EgressAuthProfilesSpec{
		ID:     "auth-00000000-0000-4000-8000-000000000000-aaaaaaaaaaaaaaaa",
		SHA256: withAuthProfiles.EgressGateway.AuthProfiles.SHA256,
	}
	crossSnapshotAuthProfiles.EgressGateway = &gatewayWithCrossSnapshotAuthProfiles
	if err := container.ValidateSpec(crossSnapshotAuthProfiles); !errors.Is(err, container.ErrInvalidSpecification) {
		t.Fatalf("cross-snapshot auth profiles error = %v", err)
	}
	routeWithoutSnapshot := spec
	gatewayRouteWithoutSnapshot := *spec.EgressGateway
	gatewayRouteWithoutSnapshot.UpstreamRoute = withRoute.EgressGateway.UpstreamRoute
	routeWithoutSnapshot.EgressGateway = &gatewayRouteWithoutSnapshot
	if err := container.ValidateSpec(routeWithoutSnapshot); !errors.Is(err, container.ErrInvalidSpecification) {
		t.Fatalf("upstream route without boundary snapshot error = %v", err)
	}
	paddedSnapshot := withSnapshot
	gatewayWithPaddedSnapshot := *withSnapshot.EgressGateway
	snapshot := *gatewayWithPaddedSnapshot.BoundarySnapshot
	snapshot.ID += " "
	gatewayWithPaddedSnapshot.BoundarySnapshot = &snapshot
	paddedSnapshot.EgressGateway = &gatewayWithPaddedSnapshot
	if err := container.ValidateSpec(paddedSnapshot); !errors.Is(err, container.ErrInvalidSpecification) {
		t.Fatalf("padded gateway snapshot id error = %v", err)
	}
	none := spec
	none.Security.NetworkMode = container.NetworkNone
	if err := container.ValidateSpec(none); !errors.Is(err, container.ErrInvalidSpecification) {
		t.Fatalf("none-network gateway error = %v", err)
	}
	floating := spec
	gatewayWithFloatingImage := *spec.EgressGateway
	gatewayWithFloatingImage.Image.Digest = "latest"
	floating.EgressGateway = &gatewayWithFloatingImage
	if err := container.ValidateSpec(floating); !errors.Is(err, container.ErrInvalidSpecification) {
		t.Fatalf("floating gateway image error = %v", err)
	}
	unlimited := spec
	gatewayWithUnlimitedMemory := *spec.EgressGateway
	gatewayWithUnlimitedMemory.Resources.MemoryBytes = 0
	unlimited.EgressGateway = &gatewayWithUnlimitedMemory
	if err := container.ValidateSpec(unlimited); !errors.Is(err, container.ErrInvalidSpecification) {
		t.Fatalf("unlimited gateway error = %v", err)
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
			MaxQueuedExec:     8,
			LogMaxBytes:       10 << 20,
			LogMaxFiles:       3,
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
			VolumeName: "cyberstrike-workspace-runtime-1",
			MountPath:  "/workspace",
		},
	}
}
