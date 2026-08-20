package container

import (
	"context"
	"errors"
	"testing"
	"time"

	containerderrdefs "github.com/containerd/errdefs"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobyimage "github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/system"
	mobyclient "github.com/moby/moby/client"
)

type fakeDockerCreationAPI struct {
	*fakeDockerInspectionAPI
	createResult mobyclient.ContainerCreateResult
	createErr    error
	createOpts   mobyclient.ContainerCreateOptions
	removeErr    error
	removedID    string
	removeOpts   mobyclient.ContainerRemoveOptions
}

func (f *fakeDockerCreationAPI) ContainerCreate(_ context.Context, options mobyclient.ContainerCreateOptions) (mobyclient.ContainerCreateResult, error) {
	f.createOpts = options
	return f.createResult, f.createErr
}

func (f *fakeDockerCreationAPI) ContainerRemove(_ context.Context, id string, options mobyclient.ContainerRemoveOptions) (mobyclient.ContainerRemoveResult, error) {
	f.removedID = id
	f.removeOpts = options
	return mobyclient.ContainerRemoveResult{}, f.removeErr
}

func TestDockerManagerCreateUsesSystemNameAndOwnerLabels(t *testing.T) {
	spec := creationSpec()
	ownerID := "instance-01"
	pinned, err := pinnedImageReference(spec.Image)
	if err != nil {
		t.Fatal(err)
	}
	providerID := "provider-container-1"
	api := newSuccessfulCreationAPI(spec, ownerID, providerID, pinned)
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	runtime, err := manager.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if runtime.ID != spec.ID || runtime.ProviderID != providerID || runtime.Status != StatusStopped || runtime.Image.ResolvedDigest != spec.Image.Digest {
		t.Fatalf("runtime = %#v", runtime)
	}
	if api.createOpts.Name != "cyberstrike-agent-"+string(spec.ID) {
		t.Fatalf("container name = %q", api.createOpts.Name)
	}
	if api.createOpts.Image != pinned || api.createOpts.Config.Image != "" {
		t.Fatalf("image options = %q / %q", api.createOpts.Image, api.createOpts.Config.Image)
	}
	if !api.createOpts.Config.NetworkDisabled || api.createOpts.HostConfig.NetworkMode != mobycontainer.NetworkMode(NetworkNone) {
		t.Fatalf("network was not disabled: %#v / %#v", api.createOpts.Config, api.createOpts.HostConfig)
	}
	labels := api.createOpts.Config.Labels
	if labels[LabelManaged] != "true" || labels[LabelOwner] != ownerID || labels[LabelRuntimeID] != string(spec.ID) || labels[LabelConversationID] != spec.ConversationID || labels[LabelImageDigest] != spec.Image.Digest {
		t.Fatalf("labels = %#v", labels)
	}
	if len(api.createOpts.HostConfig.Binds) != 0 || len(api.createOpts.HostConfig.Mounts) != 0 {
		t.Fatalf("unexpected host mounts: %#v / %#v", api.createOpts.HostConfig.Binds, api.createOpts.HostConfig.Mounts)
	}
	if api.removedID != "" {
		t.Fatalf("successful runtime was rolled back: %s", api.removedID)
	}
}

func TestDockerManagerCreateRejectsEngineArchitecture(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.infoResult.Info.Architecture = "amd64"
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Create(context.Background(), spec)
	if !errors.Is(err, ErrArchitectureMismatch) {
		t.Fatalf("architecture error = %v", err)
	}
	if api.createOpts.Name != "" {
		t.Fatal("container create was called after architecture mismatch")
	}
}

func TestDockerManagerCreateRollsBackFailedVerification(t *testing.T) {
	spec := creationSpec()
	ownerID := "instance-01"
	pinned, err := pinnedImageReference(spec.Image)
	if err != nil {
		t.Fatal(err)
	}
	providerID := "provider-container-1"
	api := newSuccessfulCreationAPI(spec, ownerID, providerID, pinned)
	api.containerResult.Container.Config.Labels[LabelOwner] = "other-owner"
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Create(context.Background(), spec)
	if !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("verification error = %v", err)
	}
	if api.removedID != providerID || !api.removeOpts.Force || api.removeOpts.RemoveVolumes {
		t.Fatalf("rollback = id %q, options %#v", api.removedID, api.removeOpts)
	}
}

func TestDockerManagerCreateMapsNameConflict(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.createErr = containerderrdefs.ErrConflict.WithMessage("name already in use")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Create(context.Background(), spec)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestDockerManagerRequiresOwnerID(t *testing.T) {
	_, err := newDockerManager(&fakeDockerCreationAPI{fakeDockerInspectionAPI: &fakeDockerInspectionAPI{}}, DockerManagerOptions{})
	if !errors.Is(err, ErrInvalidSpecification) {
		t.Fatalf("owner error = %v", err)
	}
}

func newSuccessfulCreationAPI(spec RuntimeSpec, ownerID, providerID, pinned string) *fakeDockerCreationAPI {
	if pinned == "" {
		pinned, _ = pinnedImageReference(spec.Image)
	}
	imageID := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	created := time.Date(2026, 8, 20, 12, 45, 0, 0, time.UTC)
	inspection := &fakeDockerInspectionAPI{
		pingResult: mobyclient.PingResult{APIVersion: "1.52", OSType: "linux"},
		infoResult: mobyclient.SystemInfoResult{Info: system.Info{
			ServerVersion: "29.1.3",
			Architecture:  "arm64",
			OSType:        "linux",
		}},
		imageResult: mobyclient.ImageInspectResult{InspectResponse: mobyimage.InspectResponse{
			ID:           imageID,
			RepoDigests:  []string{"sandbox@" + spec.Image.Digest},
			Architecture: "arm64",
			Os:           "linux",
			Size:         64 << 20,
		}},
		containerResult: mobyclient.ContainerInspectResult{Container: mobycontainer.InspectResponse{
			ID:      providerID,
			Created: created.Format(time.RFC3339Nano),
			Name:    "/" + runtimeContainerName(spec.ID),
			Image:   imageID,
			State:   &mobycontainer.State{Status: mobycontainer.StateCreated},
			Config: &mobycontainer.Config{
				Image:           pinned,
				NetworkDisabled: true,
				Labels:          runtimeLabels(ownerID, spec),
			},
			HostConfig: &mobycontainer.HostConfig{NetworkMode: mobycontainer.NetworkMode(NetworkNone)},
		}},
	}
	return &fakeDockerCreationAPI{
		fakeDockerInspectionAPI: inspection,
		createResult:            mobyclient.ContainerCreateResult{ID: providerID, Warnings: []string{"test warning"}},
	}
}

func creationSpec() RuntimeSpec {
	return RuntimeSpec{
		ID:             "runtime-01",
		ConversationID: "conversation-01",
		Image: ImageReference{
			Repository: "ghcr.io/example/sandbox",
			Digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Platform:   "linux/arm64",
		},
		Resources: ResourceLimits{
			NanoCPUs:          1_000_000_000,
			MemoryBytes:       512 << 20,
			PIDs:              128,
			NoFileSoft:        1024,
			NoFileHard:        2048,
			WorkspaceBytes:    1 << 30,
			MaxConcurrentExec: 2,
		},
		Security: SecurityProfile{
			ReadOnlyRootFS:      true,
			NoNewPrivileges:     true,
			DropAllCapabilities: true,
			NetworkMode:         NetworkNone,
			SeccompProfile:      "default",
			TmpfsBytes:          64 << 20,
		},
		Workspace: WorkspaceSpec{
			MountPath: "/workspace",
		},
	}
}
