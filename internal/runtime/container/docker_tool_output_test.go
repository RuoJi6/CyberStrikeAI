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

func TestToolOutputWriteScriptWritesExactFileAndRejectsSizeMismatch(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(workspace, toolOutputDirectory)
	destination := filepath.Join(directory, "execution-script")
	full := strings.Repeat("script-output-", 16)
	run := func(expected int) error {
		cmd := exec.Command("/bin/sh", "-c", toolOutputWriteScript, "cyberstrike-tool-output", destination, strconv.Itoa(expected), workspace)
		cmd.Stdin = strings.NewReader(full)
		return cmd.Run()
	}
	if err := run(len(full)); err != nil {
		t.Fatalf("tool output script: %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != full || info.Mode().Perm() != 0o644 {
		t.Fatalf("script output = %d bytes mode %o", len(data), info.Mode().Perm())
	}
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	if err := run(len(full) + 1); err == nil {
		t.Fatal("size mismatch should fail")
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched output should not be installed: %v", err)
	}
}

func TestToolOutputWriteScriptRejectsSymlinkedOutputDirectory(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(workspace, toolOutputDirectory)
	if err := os.Symlink(outside, directory); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "execution-symlink")
	cmd := exec.Command("/bin/sh", "-c", toolOutputWriteScript, "cyberstrike-tool-output", destination, "1", workspace)
	cmd.Stdin = strings.NewReader("x")
	if err := cmd.Run(); err == nil {
		t.Fatal("symlinked output directory should fail")
	}
	if _, err := os.Stat(filepath.Join(outside, "execution-symlink")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("output escaped through symlink: %v", err)
	}
}

func TestDockerManagerWritesToolOutputThroughOwnedWorkspaceExec(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.State.Status = mobycontainer.StateRunning
	api.containerResult.Container.State.Running = true
	api.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{"none": {}}}
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}

	full := strings.Repeat("oversized-container-output-", 32)
	api.execStdinBytes = len(full)
	ref, err := manager.WriteToolOutput(context.Background(), spec, ToolOutputWriteRequest{
		FileName: "execution-01",
		Content:  strings.NewReader(full),
		Size:     int64(len(full)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref != "/workspace/.tool-output/execution-01" || api.execContainerID != "provider-container-1" {
		t.Fatalf("reference/container = %q / %q", ref, api.execContainerID)
	}
	options := api.execCreateOpts
	if options.Privileged || options.TTY || !options.AttachStdin || !options.AttachStdout || !options.AttachStderr || options.WorkingDir != "/workspace" {
		t.Fatalf("tool output exec options = %#v", options)
	}
	if api.execAttachOpts.TTY {
		t.Fatalf("tool output attach options = %#v", api.execAttachOpts)
	}
	if len(options.Cmd) != 7 || options.Cmd[0] != "/bin/sh" || options.Cmd[1] != "-c" || options.Cmd[2] != toolOutputWriteScript || options.Cmd[4] != "/workspace/.tool-output/execution-01" || options.Cmd[5] != strconv.Itoa(len(full)) || options.Cmd[6] != "/workspace" {
		t.Fatalf("tool output command = %#v", options.Cmd)
	}
	if string(api.execStdin) != full {
		t.Fatalf("streamed output length = %d, want %d", len(api.execStdin), len(full))
	}
}

func TestDockerManagerRejectsUnsafeToolOutputNameBeforeDockerWrite(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.WriteToolOutput(context.Background(), spec, ToolOutputWriteRequest{
		FileName: "../escape",
		Content:  strings.NewReader("x"),
		Size:     1,
	})
	if !errors.Is(err, ErrInvalidSpecification) || api.execContainerID != "" {
		t.Fatalf("unsafe write error/container = %v / %q", err, api.execContainerID)
	}
}

func TestDockerManagerReportsToolOutputWriterFailure(t *testing.T) {
	spec := creationSpec()
	api := newSuccessfulCreationAPI(spec, "instance-01", "provider-container-1", "")
	api.containerResult.Container.State.Status = mobycontainer.StateRunning
	api.containerResult.Container.State.Running = true
	api.containerResult.Container.NetworkSettings = &mobycontainer.NetworkSettings{Networks: map[string]*mobynetwork.EndpointSettings{"none": {}}}
	api.execStdinBytes = 1
	api.execExitCode = 1
	api.execStderr = "workspace write denied"
	manager, err := newDockerManager(api, DockerManagerOptions{OwnerID: "instance-01"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.WriteToolOutput(context.Background(), spec, ToolOutputWriteRequest{
		FileName: "execution-failed",
		Content:  strings.NewReader("x"),
		Size:     1,
	})
	if err == nil || !strings.Contains(err.Error(), "exited with code 1") || !strings.Contains(err.Error(), "workspace write denied") {
		t.Fatalf("tool output writer error = %v", err)
	}
}
