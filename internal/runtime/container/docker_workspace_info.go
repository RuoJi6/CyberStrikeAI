package container

import (
	"context"
	"fmt"
	"strings"

	mobyclient "github.com/moby/moby/client"
)

const (
	WorkspaceStorageNamedVolume = "named_volume"
	WorkspaceStorageTmpfs       = "tmpfs"
)

// WorkspaceInfo returns only the two paths requested by the authenticated UI.
// It verifies immutable runtime ownership first and never returns other Docker
// inspect fields, mounts, labels, commands, or environment variables.
func (m *DockerManager) WorkspaceInfo(ctx context.Context, spec RuntimeSpec) (WorkspaceInfo, error) {
	if m == nil || m.api == nil {
		return WorkspaceInfo{}, fmt.Errorf("%w: container engine is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return WorkspaceInfo{}, invalidSpec("workspace inspection context is required")
	}
	if err := ValidateSpec(spec); err != nil {
		return WorkspaceInfo{}, err
	}

	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return WorkspaceInfo{}, err
	}
	defer cancel()
	runtime, err := m.inspectOwned(operationCtx, spec.ID)
	if err != nil {
		return WorkspaceInfo{}, err
	}
	if runtime.ConversationID != spec.ConversationID || runtime.SpecDigest != RuntimeSpecDigest(spec) {
		return WorkspaceInfo{}, fmt.Errorf("%w: runtime specification changed before workspace inspection", ErrRuntimeStateConflict)
	}

	info := WorkspaceInfo{
		ContainerPath: spec.Workspace.MountPath,
		Storage:       WorkspaceStorageTmpfs,
		Persistent:    spec.Workspace.Persistent,
	}
	if !spec.Workspace.Persistent {
		return info, nil
	}
	if m.volumeAPI == nil {
		return WorkspaceInfo{}, fmt.Errorf("%w: container volume API is not configured", ErrEngineUnavailable)
	}
	volume, err := m.volumeAPI.VolumeInspect(operationCtx, spec.Workspace.VolumeName, mobyclient.VolumeInspectOptions{})
	if err != nil {
		return WorkspaceInfo{}, fmt.Errorf("inspect workspace volume %s: %w", spec.Workspace.VolumeName, err)
	}
	if err := m.verifyWorkspaceVolume(spec, volume.Volume, ""); err != nil {
		return WorkspaceInfo{}, err
	}
	info.Storage = WorkspaceStorageNamedVolume
	info.HostPath = strings.TrimSpace(volume.Volume.Mountpoint)
	if info.HostPath == "" {
		return WorkspaceInfo{}, fmt.Errorf("%w: workspace volume has no host mountpoint", ErrRuntimeStateConflict)
	}
	return info, nil
}

var _ RuntimeWorkspaceInspector = (*DockerManager)(nil)
