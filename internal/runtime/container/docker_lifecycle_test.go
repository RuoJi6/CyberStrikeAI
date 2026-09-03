package container

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	containerderrdefs "github.com/containerd/errdefs"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobynetwork "github.com/moby/moby/api/types/network"
	mobyvolume "github.com/moby/moby/api/types/volume"
	mobyclient "github.com/moby/moby/client"
)

func TestDockerManagerLifecycleStartStopAndDelete(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{
		Networks: map[string]*mobynetwork.EndpointSettings{"none": {}},
	}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}

	started, err := manager.Start(context.Background(), spec.ID)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if started.Status != StatusRunning || api.startedID != "provider-container-1" {
		t.Fatalf("started runtime = %#v, provider = %q", started, api.startedID)
	}

	stopped, err := manager.Stop(context.Background(), spec.ID, StopOptions{Timeout: 2500 * time.Millisecond})
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if stopped.Status != StatusStopped || api.stoppedID != "provider-container-1" {
		t.Fatalf("stopped runtime = %#v, provider = %q", stopped, api.stoppedID)
	}
	if api.stopOpts.Timeout == nil || *api.stopOpts.Timeout != 3 {
		t.Fatalf("rounded stop timeout = %#v", api.stopOpts.Timeout)
	}

	if err := manager.Delete(context.Background(), spec.ID, DeleteOptions{}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if api.removedID != "provider-container-1" || api.removeOpts.Force || api.removeOpts.RemoveVolumes {
		t.Fatalf("delete target/options = %q / %#v", api.removedID, api.removeOpts)
	}
}

func TestDockerManagerStartWaitsForWorkspaceInitialization(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{
		Networks: map[string]*mobynetwork.EndpointSettings{"none": {}},
	}
	api.execExitCode = 76
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Start(context.Background(), spec.ID); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("start readiness error = %v", err)
	}
	if api.stoppedID != "provider-container-1" {
		t.Fatalf("unready runtime rollback target = %q", api.stoppedID)
	}
	if !strings.Contains(runtimeWorkspaceInitScript, runtimeReadyFile) ||
		!strings.Contains(runtimeWorkspaceReadyWaitScript, "/proc/1/stat") ||
		!strings.Contains(runtimeWorkspaceReadyWaitScript, runtimeReadyFile) {
		t.Fatal("runtime workspace readiness scripts do not bind the marker to the current PID 1 start")
	}
}

func TestDockerManagerDeleteRemovesOwnedConversationNetwork(t *testing.T) {
	for _, missingContainer := range []bool{false, true} {
		name := "normal"
		if missingContainer {
			name = "recover partial delete"
		}
		t.Run(name, func(t *testing.T) {
			spec := creationSpec()
			spec.Security.NetworkMode = NetworkInternal
			api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
			manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Create(context.Background(), spec); err != nil {
				t.Fatalf("create: %v", err)
			}
			if missingContainer {
				api.containerErr = containerderrdefs.ErrNotFound.WithMessage("container missing")
				network := api.networks[ConversationNetworkName(spec.ID)]
				network.Containers = nil
				api.networks[ConversationNetworkName(spec.ID)] = network
			}
			if err := manager.Delete(context.Background(), spec.ID, DeleteOptions{}); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if api.networkRemoved != "provider-network-1" || len(api.networks) != 0 {
				t.Fatalf("network removal = %q / %#v", api.networkRemoved, api.networks)
			}
		})
	}
}

func TestDockerManagerInternalNetworkAttachmentFollowsLifecycle(t *testing.T) {
	spec := creationSpec()
	spec.Security.NetworkMode = NetworkInternal
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	name := ConversationNetworkName(spec.ID)
	if len(api.networks[name].Containers) != 0 {
		t.Fatal("created runtime unexpectedly appeared as an active network attachment")
	}
	if _, err := manager.Start(context.Background(), spec.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	if len(api.networks[name].Containers) != 1 {
		t.Fatalf("running network attachments = %#v", api.networks[name].Containers)
	}
	network := api.networks[name]
	attachments := network.Containers
	network.Containers = nil
	api.networks[name] = network
	if _, err := manager.Inspect(context.Background(), spec.ID); !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("running runtime without network attachment error = %v", err)
	}
	network.Containers = attachments
	api.networks[name] = network
	if _, err := manager.Stop(context.Background(), spec.ID, StopOptions{}); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if len(api.networks[name].Containers) != 0 {
		t.Fatalf("stopped network attachments = %#v", api.networks[name].Containers)
	}
	if err := manager.Delete(context.Background(), spec.ID, DeleteOptions{}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(api.networks) != 0 {
		t.Fatalf("deleted runtime network survived = %#v", api.networks)
	}
}

func TestDockerManagerDeletePersistentWorkspacePolicy(t *testing.T) {
	for _, test := range []struct {
		name            string
		removeWorkspace bool
		wantRemoved     bool
	}{
		{name: "retain by default", removeWorkspace: false, wantRemoved: false},
		{name: "remove explicitly", removeWorkspace: true, wantRemoved: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := creationSpec()
			spec.Workspace.Persistent = true
			spec.Workspace.VolumeName = WorkspaceVolumeName(spec.ID)
			api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
			api.volumes = map[string]mobyvolume.Volume{
				spec.Workspace.VolumeName: {
					Name: spec.Workspace.VolumeName, Driver: "local",
					Labels: workspaceVolumeLabels("instance-01", spec),
				},
			}
			manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Delete(context.Background(), spec.ID, DeleteOptions{RemoveWorkspace: test.removeWorkspace}); err != nil {
				t.Fatalf("delete: %v", err)
			}
			_, retained := api.volumes[spec.Workspace.VolumeName]
			if retained == test.wantRemoved {
				t.Fatalf("volume retained = %v, want removed = %v", retained, test.wantRemoved)
			}
			if api.removeOpts.RemoveVolumes {
				t.Fatal("container removal relied on Docker named-volume side effects")
			}
		})
	}
}

func TestDockerManagerDeleteCanRecoverOwnedVolumeAfterContainerDisappears(t *testing.T) {
	spec := creationSpec()
	spec.Workspace.Persistent = true
	spec.Workspace.VolumeName = WorkspaceVolumeName(spec.ID)
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerErr = containerderrdefs.ErrNotFound.WithMessage("container missing")
	api.volumes = map[string]mobyvolume.Volume{
		spec.Workspace.VolumeName: {
			Name: spec.Workspace.VolumeName, Driver: "local",
			Labels: workspaceVolumeLabels("instance-01", spec),
		},
	}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Delete(context.Background(), spec.ID, DeleteOptions{RemoveWorkspace: true}); err != nil {
		t.Fatalf("recover volume delete: %v", err)
	}
	if _, ok := api.volumes[spec.Workspace.VolumeName]; ok {
		t.Fatal("owned volume survived recovery delete")
	}
}

func TestDockerManagerLifecycleIsIdempotentAtTargetState(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Stop(context.Background(), spec.ID, StopOptions{}); err != nil {
		t.Fatalf("idempotent stop: %v", err)
	}
	if api.stoppedID != "" {
		t.Fatalf("engine stop was called for stopped runtime: %q", api.stoppedID)
	}
	api.containerResult.Container.State.Status = mobycontainer.StateRunning
	api.containerResult.Container.State.Running = true
	if _, err := manager.Start(context.Background(), spec.ID); err != nil {
		t.Fatalf("idempotent start: %v", err)
	}
	if api.startedID != "" {
		t.Fatalf("engine start was called for running runtime: %q", api.startedID)
	}
}

func TestDockerManagerLifecycleRejectsForeignOrDriftedRuntime(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeDockerCreationAPI)
	}{
		{
			name: "foreign owner",
			mutate: func(api *fakeDockerCreationAPI) {
				api.containerResult.Container.Config.Labels[LabelOwner] = "other-instance"
			},
		},
		{
			name: "network enabled",
			mutate: func(api *fakeDockerCreationAPI) {
				api.containerResult.Container.Config.NetworkDisabled = false
			},
		},
		{
			name: "extra network connected",
			mutate: func(api *fakeDockerCreationAPI) {
				api.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{
					Networks: map[string]*mobynetwork.EndpointSettings{"bridge": {}},
				}
			},
		},
		{
			name: "host bind added",
			mutate: func(api *fakeDockerCreationAPI) {
				api.containerResult.Container.HostConfig.Binds = []string{"/:/host"}
			},
		},
		{
			name: "memory limit changed",
			mutate: func(api *fakeDockerCreationAPI) {
				api.containerResult.Container.HostConfig.Memory *= 2
				api.containerResult.Container.HostConfig.MemorySwap *= 2
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := creationSpec()
			api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
			tt.mutate(api)
			manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = manager.Start(context.Background(), spec.ID)
			if !errors.Is(err, ErrRuntimeStateConflict) {
				t.Fatalf("start error = %v", err)
			}
			if api.startedID != "" {
				t.Fatalf("engine mutation reached foreign/drifted runtime: %q", api.startedID)
			}
		})
	}
}

func TestDockerManagerRebuildRequiresStoppedRuntime(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.State.Status = mobycontainer.StateRunning
	api.containerResult.Container.State.Running = true
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Rebuild(context.Background(), spec.ID, RebuildOptions{Spec: spec})
	if !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("rebuild running error = %v", err)
	}
	if api.removedID != "" || api.createOpts.Name != "" {
		t.Fatal("running runtime was mutated")
	}
}

func TestDockerManagerRebuildRemovesAndRecreatesStoppedRuntime(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := manager.Rebuild(context.Background(), spec.ID, RebuildOptions{Spec: spec})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if rebuilt.Status != StatusStopped || api.removedID != "provider-container-1" || api.createOpts.Name != runtimeContainerName(spec.ID) {
		t.Fatalf("rebuilt = %#v, remove=%q, create=%q", rebuilt, api.removedID, api.createOpts.Name)
	}
}

func TestDockerManagerDeleteRejectsRunningRuntime(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.State.Status = mobycontainer.StateRunning
	api.containerResult.Container.State.Running = true
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	err = manager.Delete(context.Background(), spec.ID, DeleteOptions{})
	if !errors.Is(err, ErrRuntimeStateConflict) || api.removedID != "" {
		t.Fatalf("delete running error=%v removed=%q", err, api.removedID)
	}
}

func TestDockerManagerListOwnedRejectsDuplicateRuntimeClaims(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.listResult = mobyclient.ContainerListResult{Items: []mobycontainer.Summary{
		{ID: "provider-1", Labels: runtimeLabels("instance-01", spec)},
		{ID: "provider-2", Labels: runtimeLabels("instance-01", spec)},
	}}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.ListOwned(context.Background())
	if !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("duplicate list error = %v", err)
	}
}

func TestDockerManagerLifecycleMapsNotFound(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerErr = containerderrdefs.ErrNotFound.WithMessage("missing")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Inspect(context.Background(), spec.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("inspect not found error = %v", err)
	}
}
