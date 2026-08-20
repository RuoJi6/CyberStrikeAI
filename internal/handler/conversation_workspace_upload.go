package handler

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"cyberstrike-ai/internal/database"
)

const conversationUploadWorkspaceDirectory = "/workspace/uploads"

// ConversationWorkspaceUploadImporter is the narrow handler-to-runtime file
// boundary. The app binds it to the trusted conversation execution backend;
// callers cannot provide a Docker provider ID or host destination.
type ConversationWorkspaceUploadImporter interface {
	ImportConversationUpload(ctx context.Context, conversationID, workspacePath string, content io.Reader, size int64) (string, error)
}

type ConversationWorkspaceUploadImporterFunc func(context.Context, string, string, io.Reader, int64) (string, error)

func (f ConversationWorkspaceUploadImporterFunc) ImportConversationUpload(ctx context.Context, conversationID, workspacePath string, content io.Reader, size int64) (string, error) {
	return f(ctx, conversationID, workspacePath, content, size)
}

type conversationUploadImport struct {
	hostPath      string
	workspacePath string
}

func safeChatUploadBaseName(raw string) string {
	normalized := strings.ReplaceAll(strings.TrimSpace(raw), `\`, "/")
	baseName := path.Base(normalized)
	if baseName == "" || baseName == "." || baseName == "/" || baseName == ".." {
		return "file"
	}
	baseName = strings.Map(func(r rune) rune {
		if r == 0 || r == '/' || r == '\\' {
			return '_'
		}
		return r
	}, baseName)
	if baseName == "" || baseName == "." || baseName == ".." {
		return "file"
	}
	return baseName
}

// conversationUploadWorkspacePath maps
// chat_uploads/<date>/<conversation>/<subpath> to
// /workspace/uploads/<date>/<subpath>. Date remains part of the destination so
// files from separate upload sessions cannot silently overwrite each other.
func conversationUploadWorkspacePath(hostPath, conversationID string) (string, error) {
	validated, err := validateChatAttachmentServerPath(hostPath)
	if err != nil {
		return "", err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	root, err := filepath.Abs(filepath.Join(cwd, chatUploadsDirName))
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, validated)
	if err != nil {
		return "", err
	}
	parts := strings.Split(filepath.ToSlash(filepath.Clean(relative)), "/")
	if len(parts) < 3 || strings.TrimSpace(parts[1]) != strings.TrimSpace(conversationID) {
		return "", fmt.Errorf("attachment does not belong to conversation %s", conversationID)
	}
	workspaceParts := append([]string{conversationUploadWorkspaceDirectory, parts[0]}, parts[2:]...)
	for _, segment := range workspaceParts[1:] {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "\\\x00") {
			return "", fmt.Errorf("attachment path contains an invalid segment")
		}
	}
	normalized := path.Clean(path.Join(workspaceParts...))
	if normalized == conversationUploadWorkspaceDirectory || !strings.HasPrefix(normalized, conversationUploadWorkspaceDirectory+"/") {
		return "", fmt.Errorf("attachment path escapes the conversation workspace")
	}
	return normalized, nil
}

func containerVisibleAttachmentPaths(savedPaths []string, conversationID string) ([]string, error) {
	visible := make([]string, 0, len(savedPaths))
	for _, hostPath := range savedPaths {
		workspacePath, err := conversationUploadWorkspacePath(hostPath, conversationID)
		if err != nil {
			return nil, err
		}
		visible = append(visible, workspacePath)
	}
	return visible, nil
}

func collectConversationUploadImports(conversationID string) ([]conversationUploadImport, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	root, err := filepath.Abs(filepath.Join(cwd, chatUploadsDirName))
	if err != nil {
		return nil, err
	}
	if st, statErr := os.Stat(root); statErr != nil {
		if os.IsNotExist(statErr) {
			return nil, nil
		}
		return nil, statErr
	} else if !st.IsDir() {
		return nil, fmt.Errorf("chat_uploads root is not a directory")
	}
	var imports []conversationUploadImport
	err = filepath.WalkDir(root, func(hostPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if hostPath == root {
			return nil
		}
		relative, relErr := filepath.Rel(root, hostPath)
		if relErr != nil {
			return relErr
		}
		parts := strings.Split(filepath.ToSlash(filepath.Clean(relative)), "/")
		belongs := len(parts) >= 2 && parts[1] == conversationID
		if entry.Type()&os.ModeSymlink != 0 {
			if belongs {
				return fmt.Errorf("conversation upload contains a symlink: %s", relative)
			}
			return nil
		}
		if entry.IsDir() || !belongs {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("conversation upload is not a regular file: %s", relative)
		}
		workspacePath, mapErr := conversationUploadWorkspacePath(hostPath, conversationID)
		if mapErr != nil {
			return mapErr
		}
		imports = append(imports, conversationUploadImport{hostPath: hostPath, workspacePath: workspacePath})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(imports, func(i, j int) bool { return imports[i].workspacePath < imports[j].workspacePath })
	return imports, nil
}

// syncConversationUploadsToWorkspace imports all durable uploads for the
// conversation before Agent execution. This also recovers attachments saved
// while the asynchronous container initializer was still pending.
func (h *AgentHandler) syncConversationUploadsToWorkspace(ctx context.Context, conversation *database.Conversation) error {
	if conversation == nil || conversation.RuntimeMode != database.ConversationRuntimeModeContainer {
		return nil
	}
	imports, err := collectConversationUploadImports(conversation.ID)
	if err != nil {
		return err
	}
	if len(imports) == 0 {
		return nil
	}
	if h.containerUploadImporter == nil {
		return fmt.Errorf("container workspace upload importer is unavailable")
	}
	for _, item := range imports {
		validated, validateErr := validateChatAttachmentServerPath(item.hostPath)
		if validateErr != nil {
			return validateErr
		}
		file, openErr := os.Open(validated)
		if openErr != nil {
			return openErr
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			_ = file.Close()
			if statErr != nil {
				return statErr
			}
			return fmt.Errorf("conversation upload is not a regular file: %s", item.hostPath)
		}
		ref, importErr := h.containerUploadImporter.ImportConversationUpload(ctx, conversation.ID, item.workspacePath, file, info.Size())
		closeErr := file.Close()
		if importErr != nil {
			return fmt.Errorf("import %s into conversation workspace: %w", item.hostPath, importErr)
		}
		if closeErr != nil {
			return closeErr
		}
		if ref != item.workspacePath {
			return fmt.Errorf("container upload importer returned unexpected path %q", ref)
		}
	}
	return nil
}
