package container

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	containerderrdefs "github.com/containerd/errdefs"
	mobystdcopy "github.com/moby/moby/api/pkg/stdcopy"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobyimage "github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/system"
	mobyclient "github.com/moby/moby/client"
)

type fakeDockerCreationAPI struct {
	*fakeDockerInspectionAPI
	createResult    mobyclient.ContainerCreateResult
	createErr       error
	createOpts      mobyclient.ContainerCreateOptions
	removeErr       error
	removedID       string
	removeOpts      mobyclient.ContainerRemoveOptions
	pathStats       map[string]mobycontainer.PathStat
	pathStatErrs    map[string]error
	listResult      mobyclient.ContainerListResult
	listErr         error
	startErr        error
	stopErr         error
	startedID       string
	stoppedID       string
	stopOpts        mobyclient.ContainerStopOptions
	execCreateOpts  mobyclient.ExecCreateOptions
	execContainerID string
	execID          string
	execStdout      string
	execStderr      string
	execExitCode    int
	execRunning     bool
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

func (f *fakeDockerCreationAPI) ContainerList(_ context.Context, _ mobyclient.ContainerListOptions) (mobyclient.ContainerListResult, error) {
	return f.listResult, f.listErr
}

func (f *fakeDockerCreationAPI) ContainerStart(_ context.Context, id string, _ mobyclient.ContainerStartOptions) (mobyclient.ContainerStartResult, error) {
	f.startedID = id
	if f.startErr == nil && f.containerResult.Container.State != nil {
		f.containerResult.Container.State.Status = mobycontainer.StateRunning
		f.containerResult.Container.State.Running = true
	}
	return mobyclient.ContainerStartResult{}, f.startErr
}

func (f *fakeDockerCreationAPI) ContainerStop(_ context.Context, id string, options mobyclient.ContainerStopOptions) (mobyclient.ContainerStopResult, error) {
	f.stoppedID = id
	f.stopOpts = options
	if f.stopErr == nil && f.containerResult.Container.State != nil {
		f.containerResult.Container.State.Status = mobycontainer.StateExited
		f.containerResult.Container.State.Running = false
	}
	return mobyclient.ContainerStopResult{}, f.stopErr
}

func (f *fakeDockerCreationAPI) ContainerStatPath(_ context.Context, _ string, options mobyclient.ContainerStatPathOptions) (mobyclient.ContainerStatPathResult, error) {
	if err := f.pathStatErrs[options.Path]; err != nil {
		return mobyclient.ContainerStatPathResult{}, err
	}
	if stat, ok := f.pathStats[options.Path]; ok {
		return mobyclient.ContainerStatPathResult{Stat: stat}, nil
	}
	return mobyclient.ContainerStatPathResult{Stat: mobycontainer.PathStat{Name: options.Path, Mode: 0o755}}, nil
}

func (f *fakeDockerCreationAPI) ExecCreate(_ context.Context, containerID string, options mobyclient.ExecCreateOptions) (mobyclient.ExecCreateResult, error) {
	f.execContainerID = containerID
	f.execCreateOpts = options
	if f.execID == "" {
		f.execID = "exec-1"
	}
	return mobyclient.ExecCreateResult{ID: f.execID}, nil
}

func (f *fakeDockerCreationAPI) ExecAttach(_ context.Context, _ string, _ mobyclient.ExecAttachOptions) (mobyclient.ExecAttachResult, error) {
	clientConn, serverConn := net.Pipe()
	go func() {
		writeFakeExecFrame(serverConn, mobystdcopy.Stdout, []byte(f.execStdout))
		writeFakeExecFrame(serverConn, mobystdcopy.Stderr, []byte(f.execStderr))
		_ = serverConn.Close()
	}()
	return mobyclient.ExecAttachResult{HijackedResponse: mobyclient.NewHijackedResponse(clientConn, "application/vnd.docker.multiplexed-stream")}, nil
}

func writeFakeExecFrame(conn net.Conn, stream mobystdcopy.StdType, payload []byte) {
	if len(payload) == 0 {
		return
	}
	header := make([]byte, 8)
	header[0] = byte(stream)
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	_, _ = conn.Write(header)
	_, _ = conn.Write(payload)
}

func (f *fakeDockerCreationAPI) ExecInspect(_ context.Context, execID string, _ mobyclient.ExecInspectOptions) (mobyclient.ExecInspectResult, error) {
	return mobyclient.ExecInspectResult{ID: execID, ContainerID: f.execContainerID, ExitCode: f.execExitCode, Running: f.execRunning}, nil
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
	if !matchesRuntimeKeepalive(api.createOpts.Config) {
		t.Fatalf("fixed keepalive process was not configured: %#v", api.createOpts.Config)
	}
	if !api.createOpts.HostConfig.ReadonlyRootfs || api.createOpts.HostConfig.Privileged || len(api.createOpts.HostConfig.CapDrop) != 1 || api.createOpts.HostConfig.CapDrop[0] != "ALL" || len(api.createOpts.HostConfig.CapAdd) != 0 {
		t.Fatalf("privilege baseline = %#v", api.createOpts.HostConfig)
	}
	if !containsString(api.createOpts.HostConfig.SecurityOpt, "no-new-privileges") || api.createOpts.HostConfig.NanoCPUs != spec.Resources.NanoCPUs || api.createOpts.HostConfig.Memory != spec.Resources.MemoryBytes || api.createOpts.HostConfig.MemorySwap != spec.Resources.MemoryBytes {
		t.Fatalf("resource/security options = %#v", api.createOpts.HostConfig)
	}
	if api.createOpts.HostConfig.PidsLimit == nil || *api.createOpts.HostConfig.PidsLimit != spec.Resources.PIDs || len(api.createOpts.HostConfig.Ulimits) != 1 || api.createOpts.HostConfig.Ulimits[0].Name != "nofile" {
		t.Fatalf("pid/nofile options = %#v", api.createOpts.HostConfig.Resources)
	}
	if api.createOpts.HostConfig.Tmpfs["/tmp"] != "rw,nosuid,nodev,mode=1777,noexec,size=67108864" || api.createOpts.HostConfig.Tmpfs["/workspace"] != "rw,nosuid,nodev,mode=1777,size=1073741824" {
		t.Fatalf("tmpfs options = %#v", api.createOpts.HostConfig.Tmpfs)
	}
	if api.createOpts.HostConfig.LogConfig.Type != "local" || api.createOpts.HostConfig.LogConfig.Config["max-size"] != "10485760" || api.createOpts.HostConfig.LogConfig.Config["max-file"] != "3" || api.createOpts.HostConfig.LogConfig.Config["compress"] != "true" {
		t.Fatalf("log rotation options = %#v", api.createOpts.HostConfig.LogConfig)
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

func TestDockerManagerCreateRejectsMissingEngineSecurityFeature(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.infoResult.Info.PidsLimit = false
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Create(context.Background(), spec)
	if !errors.Is(err, ErrEngineIncompatible) {
		t.Fatalf("engine baseline error = %v", err)
	}
	if api.createOpts.Name != "" {
		t.Fatal("container create was called for an incompatible engine")
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

func TestDockerManagerCreateRollsBackSecurityMismatch(t *testing.T) {
	spec := creationSpec()
	ownerID := "instance-01"
	providerID := "provider-container-1"
	api := newSuccessfulCreationAPI(spec, ownerID, providerID, "")
	api.containerResult.Container.HostConfig.ReadonlyRootfs = false
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: ownerID})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Create(context.Background(), spec)
	if !errors.Is(err, ErrRuntimeStateConflict) {
		t.Fatalf("security verification error = %v", err)
	}
	if api.removedID != providerID {
		t.Fatalf("unsafe runtime was not rolled back: %q", api.removedID)
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

func TestDockerManagerCreateAppliesOperationTimeout(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.blockPing = true
	manager, err := newDockerManager(api, DockerManagerOptions{
		OwnerID:          "instance-01",
		OperationTimeout: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = manager.Create(context.Background(), spec)
	if !errors.Is(err, ErrEngineUnavailable) {
		t.Fatalf("timeout error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("operation timeout was not applied: %v", elapsed)
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
			ServerVersion:   "29.1.3",
			Architecture:    "arm64",
			OSType:          "linux",
			MemoryLimit:     true,
			CPUCfsQuota:     true,
			PidsLimit:       true,
			SecurityOptions: []string{"name=seccomp,profile=builtin"},
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
				WorkingDir:      spec.Workspace.MountPath,
				Entrypoint:      append([]string(nil), runtimeKeepaliveEntrypoint...),
				Cmd:             []string{runtimeKeepaliveScript},
				Labels:          runtimeLabels(ownerID, spec),
			},
			HostConfig: runtimeHostConfig(spec),
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
			MaxQueuedExec:     8,
			LogMaxBytes:       10 << 20,
			LogMaxFiles:       3,
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
