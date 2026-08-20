package container

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	mobycontainer "github.com/moby/moby/api/types/container"
	mobynetwork "github.com/moby/moby/api/types/network"
)

func TestDockerManagerWritesToolOutputIntoOwnedWorkspace(t *testing.T) {
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
	ref, err := manager.WriteToolOutput(context.Background(), spec, ToolOutputWriteRequest{
		FileName: "execution-01",
		Content:  strings.NewReader(full),
		Size:     int64(len(full)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref != "/workspace/.tool-output/execution-01" || api.copyContainerID != "provider-container-1" {
		t.Fatalf("reference/container = %q / %q", ref, api.copyContainerID)
	}
	if api.copyOptions.DestinationPath != "/workspace" || api.copyOptions.CopyUIDGID || api.copyOptions.AllowOverwriteDirWithFile {
		t.Fatalf("copy options = %#v", api.copyOptions)
	}

	entries := map[string][]byte{}
	reader := tar.NewReader(bytes.NewReader(api.copyContent))
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		body, readErr := io.ReadAll(reader)
		if readErr != nil {
			t.Fatal(readErr)
		}
		entries[header.Name] = body
		if header.Name == ".tool-output" && header.Mode != 0o755 {
			t.Fatalf("directory mode = %o", header.Mode)
		}
		if header.Name == ".tool-output/execution-01" && header.Mode != 0o644 {
			t.Fatalf("file mode = %o", header.Mode)
		}
	}
	if string(entries[".tool-output/execution-01"]) != full {
		t.Fatalf("archived output length = %d, want %d", len(entries[".tool-output/execution-01"]), len(full))
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
	if !errors.Is(err, ErrInvalidSpecification) || api.copyContainerID != "" {
		t.Fatalf("unsafe write error/container = %v / %q", err, api.copyContainerID)
	}
}
