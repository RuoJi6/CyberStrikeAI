package container

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/egress"
	"github.com/google/uuid"
	mobystdcopy "github.com/moby/moby/api/pkg/stdcopy"
	mobyclient "github.com/moby/moby/client"
)

const (
	maxContainerExecArgumentBytes = 1 << 20
	containerExecCancelTimeout    = 5 * time.Second
)

// Every command is launched as a separate process group and publishes its
// container PID before waiting. Docker has no "kill exec" endpoint; the
// control file lets a second, ownership-verified exec terminate only this
// command tree without stopping the conversation container.
const containerExecWrapperScript = `guard_working_directory() {
  guard_workspace=$1
  guard_workingdir=$2
  case "$guard_workingdir" in
    "$guard_workspace"|"$guard_workspace"/*) ;;
    *) return 64 ;;
  esac
  guard_relative=${guard_workingdir#"$guard_workspace"}
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
    [ ! -L "$guard_current" ] || return 65
  done
  set +f
  [ -d "$guard_workingdir" ] || return 66
}
pidfile=$1
workspace=$2
workingdir=$3
guard_working_directory "$workspace" "$workingdir" || exit $?
shift 3
CDPATH= cd "$workingdir" || exit 66
set -m 2>/dev/null || true
"$@" &
child=$!
set +m 2>/dev/null || true
printf '%s\n' "$child" > "$pidfile"
wait "$child"
status=$?
rm -f "$pidfile"
exit "$status"`

const containerExecCancelScript = `pidfile=$1
pid=
attempt=0
while [ "$attempt" -lt 20 ]; do
  if [ -r "$pidfile" ]; then
    IFS= read -r pid < "$pidfile" || true
  fi
  case "$pid" in
    ''|*[!0-9]*) pid= ;;
    *) break ;;
  esac
  attempt=$((attempt + 1))
  sleep 0.05
done
[ -n "$pid" ] || exit 0

targets=" $pid "
groups=
remember_group() {
  group=$1
  case "$group" in
    ''|*[!0-9]*|0|1) return ;;
  esac
  case "$groups" in
    *" $group "*) ;;
    *) groups="$groups $group " ;;
  esac
}
read_process() {
  process_stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  process_tail=${process_stat##*) }
  set -- $process_tail
  [ "$#" -ge 3 ] || return 1
  process_state=$1
  process_parent=$2
  process_group=$3
}
discover_descendants() {
  round=0
  while [ "$round" -lt 32 ]; do
    changed=0
    for stat_path in /proc/[0-9]*/stat; do
      candidate=${stat_path#/proc/}
      candidate=${candidate%/stat}
      read_process "$candidate" || continue
      case "$targets" in
        *" $process_parent "*)
          case "$targets" in
            *" $candidate "*) ;;
            *)
              targets="$targets$candidate "
              changed=1
              ;;
          esac
          remember_group "$process_group"
          ;;
      esac
    done
    [ "$changed" -eq 1 ] || break
    round=$((round + 1))
  done
}
process_is_live() {
  read_process "$1" || return 1
  [ "$process_state" != Z ]
}

read_process "$pid" && remember_group "$process_group"
discover_descendants

# Freeze the discovered tree before signalling it so a child cannot fork a
# replacement between discovery and termination. Process groups cover the
# normal shell tree; explicit PIDs also cover descendants that called setsid.
for group in $groups; do
  kill -STOP -"$group" 2>/dev/null || true
done
for target in $targets; do
  kill -STOP "$target" 2>/dev/null || true
done
# Scan once more after the known parents are frozen. This closes the normal
# fork/discovery race and freezes any late child that moved to another group.
discover_descendants
for group in $groups; do
  kill -STOP -"$group" 2>/dev/null || true
done
for target in $targets; do
  kill -STOP "$target" 2>/dev/null || true
done
for group in $groups; do
  kill -TERM -"$group" 2>/dev/null || true
done
for target in $targets; do
  kill -TERM "$target" 2>/dev/null || true
done
for group in $groups; do
  kill -CONT -"$group" 2>/dev/null || true
done
for target in $targets; do
  kill -CONT "$target" 2>/dev/null || true
done

attempt=0
while [ "$attempt" -lt 20 ]; do
  alive=0
  for target in $targets; do
    if process_is_live "$target"; then
      alive=1
      break
    fi
  done
  [ "$alive" -eq 1 ] || break
  attempt=$((attempt + 1))
  sleep 0.1
done
if [ "$alive" -eq 1 ]; then
  for group in $groups; do
    kill -KILL -"$group" 2>/dev/null || true
  done
  for target in $targets; do
    kill -KILL "$target" 2>/dev/null || true
  done
fi

attempt=0
while [ "$attempt" -lt 20 ]; do
  alive=0
  for target in $targets; do
    if process_is_live "$target"; then
      alive=1
      break
    fi
  done
  [ "$alive" -eq 1 ] || break
  attempt=$((attempt + 1))
  sleep 0.05
done
rm -f "$pidfile"
[ "$alive" -eq 0 ]`

type dockerExecAPI interface {
	ExecCreate(context.Context, string, mobyclient.ExecCreateOptions) (mobyclient.ExecCreateResult, error)
	ExecAttach(context.Context, string, mobyclient.ExecAttachOptions) (mobyclient.ExecAttachResult, error)
	ExecInspect(context.Context, string, mobyclient.ExecInspectOptions) (mobyclient.ExecInspectResult, error)
}

// ExecTerminationError means the primary exec failed or was cancelled and the
// follow-up command-tree termination could not be confirmed. Callers may
// preserve this security-relevant detail while translating the primary error
// (for example, an inactivity cancellation) into a user-facing timeout.
type ExecTerminationError struct{ Err error }

func (e *ExecTerminationError) Error() string {
	if e == nil || e.Err == nil {
		return "container exec termination failed"
	}
	return "container exec termination failed: " + e.Err.Error()
}

func (e *ExecTerminationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func joinExecTermination(primary, termination error) error {
	if termination == nil {
		return primary
	}
	return errors.Join(primary, &ExecTerminationError{Err: termination})
}

// Exec runs one non-interactive argv command inside the owned conversation
// runtime. It verifies the durable RuntimeSpec immediately before creating the
// engine exec and never accepts a request-provided provider/container ID.
func (m *DockerManager) Exec(ctx context.Context, spec RuntimeSpec, request ExecRequest, sink ExecOutputSink) (ExecResult, error) {
	if m == nil || m.execAPI == nil || m.execLimiter == nil {
		return ExecResult{}, fmt.Errorf("%w: container exec API is not configured", ErrEngineUnavailable)
	}
	if ctx == nil {
		return ExecResult{}, invalidSpec("exec context is required")
	}
	if err := ValidateSpec(spec); err != nil {
		return ExecResult{}, err
	}
	if err := validateExecRequest(spec, request); err != nil {
		return ExecResult{}, err
	}

	permit, err := m.execLimiter.Acquire(ctx, spec.ID, spec.Resources)
	if err != nil {
		return ExecResult{}, err
	}
	defer permit.Release()

	operationCtx, cancel, err := m.operationContext(ctx)
	if err != nil {
		return ExecResult{}, err
	}
	runtime, err := m.inspectOwned(operationCtx, spec.ID)
	cancel()
	if err != nil {
		return ExecResult{}, err
	}
	if runtime.ConversationID != spec.ConversationID || runtime.SpecDigest != RuntimeSpecDigest(spec) {
		return ExecResult{}, fmt.Errorf("%w: runtime specification changed before exec", ErrRuntimeStateConflict)
	}
	if runtime.Status != StatusRunning {
		return ExecResult{}, fmt.Errorf("%w: runtime %s is %s", ErrRuntimeStateConflict, spec.ID, runtime.Status)
	}

	workingDir := strings.TrimSpace(request.WorkingDir)
	workingDir, err = NormalizeWorkspacePath(spec.Workspace.MountPath, workingDir)
	if err != nil {
		return ExecResult{}, err
	}
	controlFile := "/tmp/.cyberstrike-exec-" + uuid.NewString() + ".pid"
	wrappedCommand := []string{"/bin/sh", "-c", containerExecWrapperScript, "cyberstrike-exec", controlFile, spec.Workspace.MountPath, workingDir}
	wrappedCommand = append(wrappedCommand, request.Command...)
	execStartedAt := time.Now().UTC()
	created, err := m.execAPI.ExecCreate(ctx, runtime.ProviderID, mobyclient.ExecCreateOptions{
		Privileged:   false,
		User:         runtimeRootExecUser,
		TTY:          request.TTY,
		AttachStdin:  false,
		AttachStdout: true,
		AttachStderr: true,
		Env:          runtimeExecEnvironment(request.Env),
		WorkingDir:   spec.Workspace.MountPath,
		Cmd:          wrappedCommand,
	})
	if err != nil {
		return ExecResult{}, fmt.Errorf("create exec for runtime %s: %w", spec.ID, err)
	}
	if strings.TrimSpace(created.ID) == "" {
		return ExecResult{}, fmt.Errorf("%w: engine returned an empty exec id", ErrRuntimeStateConflict)
	}

	attached, err := m.execAPI.ExecAttach(ctx, created.ID, mobyclient.ExecAttachOptions{TTY: request.TTY})
	if err != nil {
		if ctx.Err() != nil {
			return ExecResult{ExecID: created.ID}, joinExecTermination(ctx.Err(), m.terminateExecProcess(spec, runtime, controlFile))
		}
		return ExecResult{ExecID: created.ID}, fmt.Errorf("attach exec %s: %w", created.ID, err)
	}
	defer attached.Close()

	copyDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			attached.Close()
		case <-copyDone:
		}
	}()
	var copyErr error
	if request.TTY {
		_, copyErr = io.Copy(execSinkWriter{stream: ExecStreamStdout, sink: sink}, attached.Reader)
	} else {
		_, copyErr = mobystdcopy.StdCopy(
			execSinkWriter{stream: ExecStreamStdout, sink: sink},
			execSinkWriter{stream: ExecStreamStderr, sink: sink},
			attached.Reader,
		)
	}
	close(copyDone)
	if ctx.Err() != nil {
		return ExecResult{ExecID: created.ID}, joinExecTermination(ctx.Err(), m.terminateExecProcess(spec, runtime, controlFile))
	}
	if copyErr != nil {
		return ExecResult{ExecID: created.ID}, joinExecTermination(
			fmt.Errorf("read exec %s output: %w", created.ID, copyErr),
			m.terminateExecProcess(spec, runtime, controlFile),
		)
	}

	inspection, err := m.execAPI.ExecInspect(ctx, created.ID, mobyclient.ExecInspectOptions{})
	if err != nil {
		return ExecResult{ExecID: created.ID}, fmt.Errorf("inspect exec %s: %w", created.ID, err)
	}
	if inspection.ID != created.ID || inspection.ContainerID != runtime.ProviderID {
		return ExecResult{ExecID: created.ID}, fmt.Errorf("%w: exec identity does not match the owned runtime", ErrRuntimeStateConflict)
	}
	if inspection.Running {
		return ExecResult{ExecID: created.ID}, joinExecTermination(
			fmt.Errorf("%w: exec %s still running after output closed", ErrRuntimeStateConflict, created.ID),
			m.terminateExecProcess(spec, runtime, controlFile),
		)
	}
	result := ExecResult{ExecID: created.ID, ExitCode: inspection.ExitCode}
	m.emitBoundaryBlockFeedback(ctx, spec, execStartedAt, time.Now().UTC(), sink)
	return result, nil
}

const maxExecBoundaryFeedbackTargets = 8

type execBoundaryFeedbackGroup struct {
	event egress.ActivityEvent
	count int
}

func (m *DockerManager) emitBoundaryBlockFeedback(ctx context.Context, spec RuntimeSpec, since, until time.Time, sink ExecOutputSink) {
	if sink == nil || ctx == nil || ctx.Err() != nil {
		return
	}
	events, ok := m.blockedEgressActivities(ctx, spec, since, until)
	if !ok {
		return
	}
	groups := make([]execBoundaryFeedbackGroup, 0, len(events))
	groupIndexes := make(map[string]int, len(events))
	for _, event := range events {
		target := boundaryFeedbackTarget(event)
		rule, reason := boundaryFeedbackRuleReason(event)
		key := strings.Join([]string{event.RequestType, target, rule, reason}, "\x00")
		if index, exists := groupIndexes[key]; exists {
			groups[index].count++
			continue
		}
		groupIndexes[key] = len(groups)
		groups = append(groups, execBoundaryFeedbackGroup{event: event, count: 1})
	}

	var message strings.Builder
	fmt.Fprintf(&message, "\n[CyberStrikeAI 网络边界] 本次工具执行触发 %d 次网络阻断，以下请求未到达目标：\n", len(events))
	visible := len(groups)
	if visible > maxExecBoundaryFeedbackTargets {
		visible = maxExecBoundaryFeedbackTargets
	}
	for _, group := range groups[:visible] {
		target := boundaryFeedbackTarget(group.event)
		rule, reason := boundaryFeedbackRuleReason(group.event)
		fmt.Fprintf(&message, "- %s %s（%d 次）：原因 %s，规则 %s\n",
			strings.ToUpper(group.event.RequestType), target, group.count, reason, rule)
	}
	if hidden := len(groups) - visible; hidden > 0 {
		fmt.Fprintf(&message, "- 其他 %d 组被阻断目标请在出站审计中查看。\n", hidden)
	}
	message.WriteString("当前边界规则中网络策略已明确禁止上述访问，请停止测试上述访问。\n")
	_ = sink(ExecStreamStderr, []byte(message.String()))
}

func boundaryFeedbackTarget(event egress.ActivityEvent) string {
	target := strings.TrimSpace(event.Domain)
	if target == "" {
		target = strings.TrimSpace(event.ConnectedIP)
	}
	if target == "" {
		target = "未知目标"
	}
	if event.Port > 0 {
		target += ":" + fmt.Sprintf("%d", event.Port)
	}
	return target
}

func boundaryFeedbackRuleReason(event egress.ActivityEvent) (string, string) {
	rule := strings.TrimSpace(event.RuleID)
	reason := strings.TrimSpace(event.Reason)
	if reason == "" {
		reason = "policy_denied"
	}
	if rule == "" {
		switch reason {
		case boundary.ReasonForbiddenAddress, boundary.ReasonForbiddenHostname, boundary.ReasonDNSRebinding:
			rule = "系统网络隔离"
		case boundary.ReasonDefaultDeny:
			rule = "边界默认拒绝"
		default:
			rule = "系统策略"
		}
	}
	return rule, reason
}

func (m *DockerManager) terminateExecProcess(spec RuntimeSpec, expected Runtime, controlFile string) error {
	if m == nil || m.execAPI == nil {
		return fmt.Errorf("%w: container exec API is not configured", ErrEngineUnavailable)
	}
	timeout := containerExecCancelTimeout
	if m.operationTimeout > 0 && m.operationTimeout < timeout {
		timeout = m.operationTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	runtime, err := m.inspectOwned(ctx, spec.ID)
	if err != nil {
		return fmt.Errorf("verify runtime before terminating exec: %w", err)
	}
	if runtime.ProviderID != expected.ProviderID || runtime.ConversationID != spec.ConversationID || runtime.SpecDigest != RuntimeSpecDigest(spec) {
		return fmt.Errorf("%w: runtime identity changed before terminating exec", ErrRuntimeStateConflict)
	}
	if runtime.Status != StatusRunning {
		return nil // stopping the container already terminated the process tree
	}
	created, err := m.execAPI.ExecCreate(ctx, runtime.ProviderID, mobyclient.ExecCreateOptions{
		Privileged:   false,
		User:         runtimeRootExecUser,
		TTY:          false,
		AttachStdin:  false,
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   spec.Workspace.MountPath,
		Cmd:          []string{"/bin/sh", "-c", containerExecCancelScript, "cyberstrike-exec-cancel", controlFile},
	})
	if err != nil {
		return fmt.Errorf("create exec cancellation helper: %w", err)
	}
	if strings.TrimSpace(created.ID) == "" {
		return fmt.Errorf("%w: engine returned an empty cancellation exec id", ErrRuntimeStateConflict)
	}
	attached, err := m.execAPI.ExecAttach(ctx, created.ID, mobyclient.ExecAttachOptions{TTY: false})
	if err != nil {
		return fmt.Errorf("attach exec cancellation helper %s: %w", created.ID, err)
	}
	defer attached.Close()
	if _, err := mobystdcopy.StdCopy(io.Discard, io.Discard, attached.Reader); err != nil && ctx.Err() == nil {
		return fmt.Errorf("read exec cancellation helper %s: %w", created.ID, err)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("wait for exec cancellation helper %s: %w", created.ID, ctx.Err())
	}
	inspection, err := m.execAPI.ExecInspect(ctx, created.ID, mobyclient.ExecInspectOptions{})
	if err != nil {
		return fmt.Errorf("inspect exec cancellation helper %s: %w", created.ID, err)
	}
	if inspection.ID != created.ID || inspection.ContainerID != runtime.ProviderID || inspection.Running || inspection.ExitCode != 0 {
		return fmt.Errorf("%w: cancellation helper did not complete cleanly", ErrRuntimeStateConflict)
	}
	return nil
}

func validateExecRequest(spec RuntimeSpec, request ExecRequest) error {
	if len(request.Command) == 0 || strings.TrimSpace(request.Command[0]) == "" {
		return invalidSpec("exec command is required")
	}
	total := 0
	for _, value := range request.Command {
		if strings.IndexByte(value, 0) >= 0 {
			return invalidSpec("exec command contains NUL")
		}
		total += len(value)
	}
	if total > maxContainerExecArgumentBytes {
		return invalidSpec("exec command exceeds the maximum encoded size")
	}
	workingDir := strings.TrimSpace(request.WorkingDir)
	if workingDir != "" {
		if _, err := NormalizeWorkspacePath(spec.Workspace.MountPath, workingDir); err != nil {
			return invalidSpec("exec working directory must stay inside the conversation workspace")
		}
	}
	if len(request.Env) > 128 {
		return invalidSpec("exec environment has too many entries")
	}
	for _, value := range request.Env {
		if strings.IndexByte(value, 0) >= 0 || !strings.Contains(value, "=") {
			return invalidSpec("exec environment entry is invalid")
		}
	}
	return nil
}

type execSinkWriter struct {
	stream ExecStream
	sink   ExecOutputSink
}

func (w execSinkWriter) Write(chunk []byte) (int, error) {
	if w.sink == nil || len(chunk) == 0 {
		return len(chunk), nil
	}
	if err := w.sink(w.stream, chunk); err != nil {
		return 0, err
	}
	return len(chunk), nil
}
