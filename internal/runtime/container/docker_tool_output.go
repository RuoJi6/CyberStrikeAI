package container

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	mobyclient "github.com/moby/moby/client"
)

const toolOutputDirectory = ".tool-output"

// WriteToolOutput copies one complete output file into the owned running
// conversation container. Runtime identity is re-verified immediately before
// the Docker archive write, exactly as it is for Exec.
func (m *DockerManager) WriteToolOutput(ctx context.Context, spec RuntimeSpec, request ToolOutputWriteRequest) (string, error) {
	if m == nil || m.toolOutputAPI == nil {
		return "", fmt.Errorf("%w: container archive API is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return "", invalidSpec("tool output context is required")
	}
	if err := ValidateSpec(spec); err != nil {
		return "", err
	}
	fileName := strings.TrimSpace(request.FileName)
	if fileName == "" || fileName != path.Base(fileName) || fileName == "." || fileName == ".." || strings.ContainsAny(fileName, "/\\\x00") {
		return "", invalidSpec("tool output file name is invalid")
	}
	if request.Content == nil || request.Size < 0 {
		return "", invalidSpec("tool output content and size are required")
	}

	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return "", err
	}
	defer cancel()
	runtime, err := m.inspectOwned(operationCtx, spec.ID)
	if err != nil {
		return "", err
	}
	if runtime.ConversationID != spec.ConversationID || runtime.SpecDigest != RuntimeSpecDigest(spec) {
		return "", fmt.Errorf("%w: runtime specification changed before tool output write", ErrRuntimeStateConflict)
	}
	if runtime.Status != StatusRunning {
		return "", fmt.Errorf("%w: runtime %s is %s", ErrRuntimeStateConflict, spec.ID, runtime.Status)
	}

	archiveReader, archiveErr := toolOutputArchive(request.Content, request.Size, fileName)
	_, copyErr := m.toolOutputAPI.CopyToContainer(operationCtx, runtime.ProviderID, mobyclient.CopyToContainerOptions{
		DestinationPath:           spec.Workspace.MountPath,
		Content:                   archiveReader,
		AllowOverwriteDirWithFile: false,
		CopyUIDGID:                false,
	})
	if copyErr != nil {
		_ = archiveReader.CloseWithError(copyErr)
		return "", fmt.Errorf("copy tool output into runtime %s: %w", spec.ID, copyErr)
	}
	if err := <-archiveErr; err != nil {
		return "", fmt.Errorf("archive tool output for runtime %s: %w", spec.ID, err)
	}
	return path.Join(spec.Workspace.MountPath, toolOutputDirectory, fileName), nil
}

func toolOutputArchive(content io.Reader, size int64, fileName string) (*io.PipeReader, <-chan error) {
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		tarWriter := tar.NewWriter(writer)
		modTime := time.Unix(0, 0).UTC()
		err := tarWriter.WriteHeader(&tar.Header{
			Name:     toolOutputDirectory,
			Mode:     0o755,
			Typeflag: tar.TypeDir,
			ModTime:  modTime,
		})
		if err == nil {
			err = tarWriter.WriteHeader(&tar.Header{
				Name:     path.Join(toolOutputDirectory, fileName),
				Mode:     0o644,
				Size:     size,
				Typeflag: tar.TypeReg,
				ModTime:  modTime,
			})
		}
		if err == nil {
			_, err = io.CopyN(tarWriter, content, size)
		}
		if closeErr := tarWriter.Close(); err == nil {
			err = closeErr
		}
		_ = writer.CloseWithError(err)
		done <- err
		close(done)
	}()
	return reader, done
}
