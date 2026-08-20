package security

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	containerruntime "cyberstrike-ai/internal/runtime/container"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/cloudwego/eino/adk/filesystem"
)

const (
	conversationWorkspacePath           = "/workspace"
	maxContainerFilesystemResponseBytes = 16 << 20
)

const containerWorkspacePathGuard = `guard_workspace_path() {
  guard_workspace=$1
  guard_candidate=$2
  case "$guard_candidate" in
    "$guard_workspace"|"$guard_workspace"/*) ;;
    *) printf '%s\n' 'path outside /workspace' >&2; return 64 ;;
  esac
  guard_relative=${guard_candidate#"$guard_workspace"}
  guard_relative=${guard_relative#/}
  guard_current=$guard_workspace
  set -f
  guard_old_ifs=$IFS
  IFS=/
  set -- $guard_relative
  IFS=$guard_old_ifs
  for guard_segment in "$@"; do
    [ -n "$guard_segment" ] || continue
    guard_current="$guard_current/$guard_segment"
    if [ -L "$guard_current" ]; then
      printf '%s\n' 'symlinked workspace path rejected' >&2
      return 65
    fi
  done
  set +f
}`

const containerReadFileScript = containerWorkspacePathGuard + `
workspace=$1
file=$2
offset=$3
limit=$4
guard_workspace_path "$workspace" "$file"
[ -f "$file" ] || { printf 'file not found: %s\n' "$file" >&2; exit 66; }
awk -v start="$offset" -v max="$limit" 'NR >= start { if (seen >= max) exit; print; seen++ }' "$file"`

const containerReadWholeFileScript = containerWorkspacePathGuard + `
workspace=$1
file=$2
guard_workspace_path "$workspace" "$file"
[ -f "$file" ] || { printf 'file not found: %s\n' "$file" >&2; exit 66; }
cat -- "$file"`

const containerListDirectoryScript = containerWorkspacePathGuard + `
workspace=$1
directory=$2
guard_workspace_path "$workspace" "$directory"
if [ ! -e "$directory" ]; then exit 0; fi
[ -d "$directory" ] || { printf 'not a directory: %s\n' "$directory" >&2; exit 66; }
for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
  if [ ! -e "$entry" ] && [ ! -L "$entry" ]; then continue; fi
  name=${entry##*/}
  printf '%s\000' "$name"
done`

const containerWalkWorkspaceScript = containerWorkspacePathGuard + `
workspace=$1
directory=$2
guard_workspace_path "$workspace" "$directory"
if [ ! -e "$directory" ]; then exit 0; fi
[ -d "$directory" ] || { printf 'not a directory: %s\n' "$directory" >&2; exit 66; }
find "$directory" -mindepth 1 -print0`

const containerGrepWorkspaceScript = containerWorkspacePathGuard + `
workspace=$1
target=$2
guard_workspace_path "$workspace" "$target"
shift 2
exec rg "$@" -- "$target"`

// conversationFilesystemBackend preserves the established local filesystem
// backend for host conversations and routes container conversations through
// the trusted execution backend. Container paths are always canonicalized to
// /workspace before any command or write reaches Docker.
type conversationFilesystemBackend struct {
	host     filesystem.Backend
	resolver ExecutionBackendResolver
}

func NewConversationFilesystemBackend(host filesystem.Backend, resolver ExecutionBackendResolver) filesystem.Backend {
	return &conversationFilesystemBackend{host: host, resolver: resolver}
}

func (b *conversationFilesystemBackend) resolve(ctx context.Context) (filesystem.Backend, ExecutionBackend, error) {
	if b == nil || b.resolver == nil {
		if b != nil && b.host != nil {
			return b.host, nil, nil
		}
		return nil, nil, fmt.Errorf("filesystem backend is not configured")
	}
	backend, err := b.resolver.ResolveExecutionBackend(ctx)
	if err != nil {
		return nil, nil, err
	}
	reporter, ok := backend.(ExecutionLocationReporter)
	if !ok {
		return nil, nil, fmt.Errorf("execution backend does not report a trusted location")
	}
	switch reporter.ExecutionLocation() {
	case "host":
		if b.host == nil {
			return nil, nil, fmt.Errorf("host filesystem backend is not configured")
		}
		return b.host, nil, nil
	case "container":
		return nil, backend, nil
	default:
		return nil, nil, fmt.Errorf("unsupported execution location %q", reporter.ExecutionLocation())
	}
}

func normalizeConversationWorkspacePath(raw string) (string, error) {
	normalized, err := containerruntime.NormalizeWorkspacePath(conversationWorkspacePath, raw)
	if err != nil {
		return "", fmt.Errorf("invalid container workspace path: %w", err)
	}
	return normalized, nil
}

func runContainerFilesystemCommand(ctx context.Context, backend ExecutionBackend, command []string) (ExecutionResult, error) {
	result, err := backend.Execute(ctx, ExecutionRequest{
		Command:        command,
		WorkingDir:     conversationWorkspacePath,
		MaxOutputBytes: maxContainerFilesystemResponseBytes,
	})
	if err != nil {
		return result, err
	}
	if strings.Contains(result.Output, "<persisted-output>") {
		return result, fmt.Errorf("container filesystem response exceeded %d bytes", maxContainerFilesystemResponseBytes)
	}
	return result, nil
}

func (b *conversationFilesystemBackend) LsInfo(ctx context.Context, req *filesystem.LsInfoRequest) ([]filesystem.FileInfo, error) {
	host, backend, err := b.resolve(ctx)
	if err != nil {
		return nil, err
	}
	if host != nil {
		return host.LsInfo(ctx, req)
	}
	raw := ""
	if req != nil {
		raw = req.Path
	}
	directory, err := normalizeConversationWorkspacePath(raw)
	if err != nil {
		return nil, err
	}
	result, err := runContainerFilesystemCommand(ctx, backend, []string{
		"/bin/sh", "-c", containerListDirectoryScript, "cyberstrike-fs-ls",
		conversationWorkspacePath, directory,
	})
	if err != nil {
		return nil, fmt.Errorf("list container workspace: %w", err)
	}
	names := splitNULFields(result.Output)
	files := make([]filesystem.FileInfo, 0, len(names))
	for _, name := range names {
		files = append(files, filesystem.FileInfo{Path: name})
	}
	return files, nil
}

func (b *conversationFilesystemBackend) Read(ctx context.Context, req *filesystem.ReadRequest) (*filesystem.FileContent, error) {
	host, backend, err := b.resolve(ctx)
	if err != nil {
		return nil, err
	}
	if host != nil {
		return host.Read(ctx, req)
	}
	if req == nil {
		return nil, fmt.Errorf("read request is required")
	}
	filePath, err := normalizeConversationWorkspacePath(req.FilePath)
	if err != nil {
		return nil, err
	}
	offset := req.Offset
	if offset <= 0 {
		offset = 1
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 2000
	}
	result, err := runContainerFilesystemCommand(ctx, backend, []string{
		"/bin/sh", "-c", containerReadFileScript, "cyberstrike-fs-read",
		conversationWorkspacePath, filePath, strconv.Itoa(offset), strconv.Itoa(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("read container workspace file: %w", err)
	}
	return &filesystem.FileContent{Content: strings.TrimSuffix(result.Output, "\n")}, nil
}

func (b *conversationFilesystemBackend) GrepRaw(ctx context.Context, req *filesystem.GrepRequest) ([]filesystem.GrepMatch, error) {
	host, backend, err := b.resolve(ctx)
	if err != nil {
		return nil, err
	}
	if host != nil {
		return host.GrepRaw(ctx, req)
	}
	if req == nil || req.Pattern == "" {
		return nil, fmt.Errorf("pattern is required")
	}
	target, err := normalizeConversationWorkspacePath(req.Path)
	if err != nil {
		return nil, err
	}
	args := []string{"--json"}
	if req.CaseInsensitive {
		args = append(args, "-i")
	}
	if req.EnableMultiline {
		args = append(args, "-U", "--multiline-dotall")
	}
	if req.FileType != "" {
		args = append(args, "--type", req.FileType)
	} else if req.Glob != "" {
		args = append(args, "--glob", req.Glob)
	}
	if req.AfterLines > 0 {
		args = append(args, "-A", strconv.Itoa(req.AfterLines))
	}
	if req.BeforeLines > 0 {
		args = append(args, "-B", strconv.Itoa(req.BeforeLines))
	}
	args = append(args, "-e", req.Pattern)
	command := []string{"/bin/sh", "-c", containerGrepWorkspaceScript, "cyberstrike-fs-grep", conversationWorkspacePath, target}
	command = append(command, args...)
	result, runErr := runContainerFilesystemCommand(ctx, backend, command)
	if runErr != nil {
		if result.ExitCode == 1 {
			return []filesystem.GrepMatch{}, nil
		}
		return nil, fmt.Errorf("grep container workspace: %w", runErr)
	}
	return parseRipgrepMatches(result.Output, req.Glob, req.FileType != ""), nil
}

func (b *conversationFilesystemBackend) GlobInfo(ctx context.Context, req *filesystem.GlobInfoRequest) ([]filesystem.FileInfo, error) {
	host, backend, err := b.resolve(ctx)
	if err != nil {
		return nil, err
	}
	if host != nil {
		return host.GlobInfo(ctx, req)
	}
	if req == nil {
		return nil, fmt.Errorf("glob request is required")
	}
	directory, err := normalizeConversationWorkspacePath(req.Path)
	if err != nil {
		return nil, err
	}
	result, err := runContainerFilesystemCommand(ctx, backend, []string{
		"/bin/sh", "-c", containerWalkWorkspaceScript, "cyberstrike-fs-glob",
		conversationWorkspacePath, directory,
	})
	if err != nil {
		return nil, fmt.Errorf("walk container workspace: %w", err)
	}
	var matches []string
	for _, absolute := range splitNULFields(result.Output) {
		relative := strings.TrimPrefix(absolute, strings.TrimSuffix(directory, "/")+"/")
		if relative == absolute || relative == "" {
			continue
		}
		matched, _ := doublestar.Match(req.Pattern, relative)
		if matched {
			matches = append(matches, relative)
		}
	}
	sort.Strings(matches)
	files := make([]filesystem.FileInfo, 0, len(matches))
	for _, match := range matches {
		files = append(files, filesystem.FileInfo{Path: match})
	}
	return files, nil
}

func (b *conversationFilesystemBackend) Write(ctx context.Context, req *filesystem.WriteRequest) error {
	host, backend, err := b.resolve(ctx)
	if err != nil {
		return err
	}
	if host != nil {
		return host.Write(ctx, req)
	}
	if req == nil {
		return fmt.Errorf("write request is required")
	}
	filePath, err := normalizeConversationWorkspacePath(req.FilePath)
	if err != nil {
		return err
	}
	return writeContainerWorkspaceContent(ctx, backend, filePath, req.Content)
}

func (b *conversationFilesystemBackend) Edit(ctx context.Context, req *filesystem.EditRequest) error {
	host, backend, err := b.resolve(ctx)
	if err != nil {
		return err
	}
	if host != nil {
		return host.Edit(ctx, req)
	}
	if req == nil || req.OldString == "" {
		return fmt.Errorf("old string is required")
	}
	if req.OldString == req.NewString {
		return fmt.Errorf("new string must be different from old string")
	}
	filePath, err := normalizeConversationWorkspacePath(req.FilePath)
	if err != nil {
		return err
	}
	result, err := runContainerFilesystemCommand(ctx, backend, []string{
		"/bin/sh", "-c", containerReadWholeFileScript, "cyberstrike-fs-edit-read",
		conversationWorkspacePath, filePath,
	})
	if err != nil {
		return fmt.Errorf("read container workspace file for edit: %w", err)
	}
	count := strings.Count(result.Output, req.OldString)
	if count == 0 {
		return fmt.Errorf("old string not found in file")
	}
	if !req.ReplaceAll && count != 1 {
		return fmt.Errorf("old string appears %d times; set replace_all to replace all occurrences", count)
	}
	updated := result.Output
	if req.ReplaceAll {
		updated = strings.ReplaceAll(updated, req.OldString, req.NewString)
	} else {
		updated = strings.Replace(updated, req.OldString, req.NewString, 1)
	}
	return writeContainerWorkspaceContent(ctx, backend, filePath, updated)
}

func writeContainerWorkspaceContent(ctx context.Context, backend ExecutionBackend, filePath, content string) error {
	writer, ok := backend.(WorkspaceFileWriter)
	if !ok {
		return fmt.Errorf("container workspace writer is unavailable")
	}
	ref, err := writer.WriteWorkspaceFile(ctx, filePath, strings.NewReader(content), int64(len(content)))
	if err != nil {
		return err
	}
	if ref != filePath {
		return fmt.Errorf("container workspace writer returned unexpected path %q", ref)
	}
	return nil
}

func splitNULFields(raw string) []string {
	parts := strings.Split(raw, "\x00")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

type ripgrepJSONEvent struct {
	Type string `json:"type"`
	Data struct {
		Path struct {
			Text string `json:"text"`
		} `json:"path"`
		Lines struct {
			Text string `json:"text"`
		} `json:"lines"`
		LineNumber int `json:"line_number"`
	} `json:"data"`
}

func parseRipgrepMatches(raw, glob string, applyGlob bool) []filesystem.GrepMatch {
	var matches []filesystem.GrepMatch
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var event ripgrepJSONEvent
		if json.Unmarshal([]byte(line), &event) != nil || (event.Type != "match" && event.Type != "context") {
			continue
		}
		matchPath := event.Data.Path.Text
		if applyGlob && glob != "" {
			matched, _ := doublestar.Match(glob, matchPath)
			if !matched {
				matched, _ = doublestar.Match(glob, path.Base(matchPath))
			}
			if !matched {
				continue
			}
		}
		matches = append(matches, filesystem.GrepMatch{
			Path: matchPath, Line: event.Data.LineNumber,
			Content: strings.TrimRight(event.Data.Lines.Text, "\n"),
		})
	}
	return matches
}
