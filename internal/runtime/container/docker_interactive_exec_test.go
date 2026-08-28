package container

import (
	"context"
	"net"
	"strings"
	"testing"

	mobycontainer "github.com/moby/moby/api/types/container"
	mobynetwork "github.com/moby/moby/api/types/network"
	mobyvolume "github.com/moby/moby/api/types/volume"
	mobyclient "github.com/moby/moby/client"
)

type interactiveDockerAPI struct {
	*fakeDockerCreationAPI
	peer       net.Conn
	resizeID   string
	resizeOpts mobyclient.ExecResizeOptions
}

func (f *interactiveDockerAPI) ExecAttach(_ context.Context, _ string, options mobyclient.ExecAttachOptions) (mobyclient.ExecAttachResult, error) {
	f.execAttachOpts = options
	client, peer := net.Pipe()
	f.peer = peer
	return mobyclient.ExecAttachResult{HijackedResponse: mobyclient.NewHijackedResponse(client, "application/vnd.docker.raw-stream")}, nil
}

func (f *interactiveDockerAPI) ExecInspect(_ context.Context, execID string, _ mobyclient.ExecInspectOptions) (mobyclient.ExecInspectResult, error) {
	return mobyclient.ExecInspectResult{ID: execID, ContainerID: f.execContainerID, Running: true}, nil
}

func (f *interactiveDockerAPI) ExecResize(_ context.Context, execID string, options mobyclient.ExecResizeOptions) (mobyclient.ExecResizeResult, error) {
	f.resizeID = execID
	f.resizeOpts = options
	return mobyclient.ExecResizeResult{}, nil
}

func TestDockerManagerInteractiveExecTargetsOnlyOwnedRunningContainer(t *testing.T) {
	spec := creationSpec()
	base := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	base.containerResult.Container.State.Status = mobycontainer.StateRunning
	base.containerResult.Container.State.Running = true
	base.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{"none": {}}}
	base.execRunning = true
	api := &interactiveDockerAPI{fakeDockerCreationAPI: base}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}

	session, err := manager.OpenInteractiveExec(context.Background(), spec, InteractiveExecRequest{Cols: 120, Rows: 36})
	if err != nil {
		t.Fatalf("open interactive exec: %v", err)
	}
	if api.execContainerID != "provider-container-1" || api.execCreateOpts.Privileged || !api.execCreateOpts.TTY || !api.execCreateOpts.AttachStdin || !api.execCreateOpts.AttachStdout || !api.execCreateOpts.AttachStderr {
		t.Fatalf("unsafe interactive exec target/options: %q %#v", api.execContainerID, api.execCreateOpts)
	}
	if api.execCreateOpts.User != runtimeRootExecUser {
		t.Fatalf("interactive exec user = %q, want %q", api.execCreateOpts.User, runtimeRootExecUser)
	}
	if api.execCreateOpts.WorkingDir != "/workspace" || len(api.execCreateOpts.Cmd) != 5 || api.execCreateOpts.Cmd[0] != "/bin/sh" || api.execCreateOpts.Cmd[2] != interactiveExecWrapperScript || !strings.HasPrefix(api.execCreateOpts.Cmd[4], "/tmp/.cyberstrike-exec-") {
		t.Fatalf("interactive exec command/workdir = %#v / %q", api.execCreateOpts.Cmd, api.execCreateOpts.WorkingDir)
	}
	if !strings.Contains(interactiveExecWrapperScript, "exec /bin/bash --noprofile --norc -i") || !strings.Contains(interactiveExecWrapperScript, "exec /bin/sh -i") {
		t.Fatalf("interactive shell does not provide an interactive completion-capable shell: %q", interactiveExecWrapperScript)
	}
	if err := session.Resize(context.Background(), 132, 42); err != nil {
		t.Fatal(err)
	}
	if api.resizeID != base.execID || api.resizeOpts.Width != 132 || api.resizeOpts.Height != 42 {
		t.Fatalf("resize = %q %#v", api.resizeID, api.resizeOpts)
	}

	// A stopped runtime makes Close a no-op termination-wise; the attached TTY
	// still closes and the exec limiter permit must be released.
	base.containerResult.Container.State.Status = mobycontainer.StateExited
	base.containerResult.Container.State.Running = false
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if api.peer != nil {
		_ = api.peer.Close()
	}
	if snapshot := manager.execLimiter.Snapshot(); snapshot.Running != 0 {
		t.Fatalf("interactive exec permit leaked: %#v", snapshot)
	}
}

func TestDockerManagerInteractiveExecRejectsStoppedRuntime(t *testing.T) {
	spec := creationSpec()
	api := &interactiveDockerAPI{fakeDockerCreationAPI: newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.OpenInteractiveExec(context.Background(), spec, InteractiveExecRequest{Cols: 80, Rows: 24}); err == nil || !strings.Contains(err.Error(), string(StatusStopped)) {
		t.Fatalf("stopped interactive exec error = %v", err)
	}
	if api.execContainerID != "" {
		t.Fatalf("stopped runtime reached ExecCreate for %q", api.execContainerID)
	}
}

func TestDockerManagerWorkspaceInfoSupportsStoppedTmpfsAndNamedVolume(t *testing.T) {
	t.Run("temporary", func(t *testing.T) {
		spec := creationSpec()
		api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
		manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
		if err != nil {
			t.Fatal(err)
		}
		info, err := manager.WorkspaceInfo(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if info.ContainerPath != "/workspace" || info.HostPath != "" || info.Storage != WorkspaceStorageTmpfs || info.Persistent {
			t.Fatalf("temporary workspace info = %#v", info)
		}
	})

	t.Run("persistent", func(t *testing.T) {
		spec := creationSpec()
		spec.Workspace.Persistent = true
		spec.Workspace.VolumeName = WorkspaceVolumeName(spec.ID)
		api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
		api.volumes = map[string]mobyvolume.Volume{
			spec.Workspace.VolumeName: {
				Name: spec.Workspace.VolumeName, Driver: "local", Scope: "local",
				Labels:     workspaceVolumeLabels("instance-01", spec),
				Mountpoint: "/var/lib/docker/volumes/owned-workspace/_data",
			},
		}
		manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
		if err != nil {
			t.Fatal(err)
		}
		info, err := manager.WorkspaceInfo(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Persistent || info.Storage != WorkspaceStorageNamedVolume || info.HostPath != "/var/lib/docker/volumes/owned-workspace/_data" {
			t.Fatalf("persistent workspace info = %#v", info)
		}
	})
}
