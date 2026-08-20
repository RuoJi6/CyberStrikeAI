package container

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	mobycontainer "github.com/moby/moby/api/types/container"
	mobynetwork "github.com/moby/moby/api/types/network"
)

func TestWorkspaceFileWriteScriptCreatesNestedFileAndRejectsSymlinkTraversal(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := "workspace-input"
	destination := filepath.Join(workspace, "uploads", "2026-08-20", "input.txt")
	cmd := exec.Command("/bin/sh", "-c", workspaceFileWriteScript, "cyberstrike-workspace-file", destination, strconv.Itoa(len(content)), workspace)
	cmd.Stdin = strings.NewReader(content)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil || string(data) != content {
		t.Fatalf("workspace file = %q, %v", data, err)
	}

	outside := t.TempDir()
	symlinkParent := filepath.Join(workspace, "escape")
	if err := os.Symlink(outside, symlinkParent); err != nil {
		t.Fatal(err)
	}
	escapeDestination := filepath.Join(symlinkParent, "escaped.txt")
	escape := exec.Command("/bin/sh", "-c", workspaceFileWriteScript, "cyberstrike-workspace-file", escapeDestination, "1", workspace)
	escape.Stdin = strings.NewReader("x")
	if err := escape.Run(); err == nil {
		t.Fatal("symlinked workspace parent should be rejected")
	}
	if _, err := os.Stat(filepath.Join(outside, "escaped.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace write escaped through symlink: %v", err)
	}
}

func TestDockerManagerWritesNormalizedWorkspaceFile(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.State.Status = mobycontainer.StateRunning
	api.containerResult.Container.State.Running = true
	api.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{"none": {}}}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	content := "uploaded"
	api.execStdinBytes = len(content)
	ref, err := manager.WriteWorkspaceFile(context.Background(), spec, WorkspaceFileWriteRequest{
		Path: "uploads/./2026-08-20/input.txt", Content: strings.NewReader(content), Size: int64(len(content)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref != "/workspace/uploads/2026-08-20/input.txt" || string(api.execStdin) != content {
		t.Fatalf("workspace ref/content = %q / %q", ref, api.execStdin)
	}
	if api.execCreateOpts.Privileged || !api.execCreateOpts.AttachStdin || api.execCreateOpts.WorkingDir != "/workspace" {
		t.Fatalf("unsafe workspace writer options: %#v", api.execCreateOpts)
	}
}

func TestDockerManagerRejectsWorkspaceTraversalBeforeEngineWrite(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.WriteWorkspaceFile(context.Background(), spec, WorkspaceFileWriteRequest{
		Path: "../../etc/passwd", Content: strings.NewReader("x"), Size: 1,
	})
	if !errors.Is(err, ErrInvalidSpecification) || api.execContainerID != "" {
		t.Fatalf("traversal error/container = %v / %q", err, api.execContainerID)
	}
}
