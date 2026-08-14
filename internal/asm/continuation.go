package asm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/database"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	ContinuationAuto       = "auto"
	ContinuationNotifyOnly = "notify_only"
	ContinuationNone       = "none"
)

const defaultRunningPrompt = `ASM 扫描结果已完成。
平台：{{provider}}
类型：{{task_type}}
任务 ID：{{task_id}}
任务名称：{{task_name}}
目标：{{targets}}
结果同步状态：{{sync_status}}

你收到本消息时该对话仍有任务在运行。请先完成正在进行的工作，完成之后调用 ASM MCP，使用上述任务 ID 读取已本地化的扫描结果并继续分析。`

const defaultIdlePrompt = `ASM 扫描结果已完成。
平台：{{provider}}
类型：{{task_type}}
任务 ID：{{task_id}}
任务名称：{{task_name}}
目标：{{targets}}
结果同步状态：{{sync_status}}

继续原任务。请调用 ASM MCP，使用上述任务 ID 读取已本地化的扫描结果并继续分析。`

type AgentContinuationSettings struct {
	Behavior      string `json:"behavior"`
	RunningPrompt string `json:"running_prompt"`
	IdlePrompt    string `json:"idle_prompt"`
}

func DefaultAgentContinuationSettings() AgentContinuationSettings {
	return AgentContinuationSettings{Behavior: ContinuationAuto, RunningPrompt: defaultRunningPrompt, IdlePrompt: defaultIdlePrompt}
}

func normalizeContinuationBehavior(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ContinuationAuto
	}
	switch value {
	case ContinuationAuto, ContinuationNotifyOnly, ContinuationNone:
		return value
	default:
		// Unknown API values must never turn into a billable Agent run.
		return ContinuationNone
	}
}

func truncateContinuationPrompt(value string) string {
	runes := []rune(value)
	if len(runes) > 8000 {
		return string(runes[:8000])
	}
	return value
}

func normalizeAgentContinuationSettings(input *AgentContinuationSettings) AgentContinuationSettings {
	defaults := DefaultAgentContinuationSettings()
	if input == nil {
		return defaults
	}
	result := AgentContinuationSettings{
		Behavior:      normalizeContinuationBehavior(input.Behavior),
		RunningPrompt: strings.TrimSpace(input.RunningPrompt),
		IdlePrompt:    strings.TrimSpace(input.IdlePrompt),
	}
	if result.RunningPrompt == "" {
		result.RunningPrompt = defaults.RunningPrompt
	}
	if result.IdlePrompt == "" {
		result.IdlePrompt = defaults.IdlePrompt
	}
	result.RunningPrompt = truncateContinuationPrompt(result.RunningPrompt)
	result.IdlePrompt = truncateContinuationPrompt(result.IdlePrompt)
	return result
}

func resourceAgentContinuation(item *database.ASMResource) AgentContinuationSettings {
	defaults := DefaultAgentContinuationSettings()
	if item == nil || strings.TrimSpace(item.MetadataJSON) == "" {
		return defaults
	}
	var metadata map[string]interface{}
	if json.Unmarshal([]byte(item.MetadataJSON), &metadata) != nil {
		return defaults
	}
	raw, ok := metadata["agent_continuation"]
	if !ok {
		return defaults
	}
	data, _ := json.Marshal(raw)
	var settings AgentContinuationSettings
	if json.Unmarshal(data, &settings) != nil {
		return defaults
	}
	return normalizeAgentContinuationSettings(&settings)
}

func encodeResourceAgentContinuation(input *AgentContinuationSettings, existing string) string {
	metadata := map[string]interface{}{}
	_ = json.Unmarshal([]byte(existing), &metadata)
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	metadata["agent_continuation"] = normalizeAgentContinuationSettings(input)
	data, err := json.Marshal(metadata)
	if err != nil {
		return existing
	}
	return string(data)
}

// SetAgentContinuationHooks wires the ASM worker to the Agent runtime without
// importing the handler package into asm.
func (s *Service) SetAgentContinuationHooks(running func(string) bool, runner func(context.Context, *database.ASMAgentContinuation, string) error) {
	s.continuationMu.Lock()
	defer s.continuationMu.Unlock()
	s.agentRunning = running
	s.continuationRunner = runner
}

func continuationTaskIDs(result interface{}) []string {
	object := valueMap(result)
	if object == nil {
		return nil
	}
	resultIDs := make([]string, 0)
	switch ids := object["local_task_ids"].(type) {
	case []string:
		resultIDs = append(resultIDs, ids...)
	case []interface{}:
		for _, raw := range ids {
			if id := strings.TrimSpace(fmt.Sprint(raw)); id != "" {
				resultIDs = append(resultIDs, id)
			}
		}
	}
	if len(resultIDs) == 0 {
		if id := meaningfulString(object["local_task_id"]); id != "" {
			resultIDs = append(resultIDs, id)
		}
	}
	return resultIDs
}

func (s *Service) attachAgentContinuation(conn *Connection, req TaskRequest, result interface{}) {
	object := valueMap(result)
	if object == nil || conn == nil || conn.Resource == nil {
		return
	}
	settings := resourceAgentContinuation(conn.Resource)
	behavior := settings.Behavior
	metadata := map[string]interface{}{
		"behavior": behavior,
		"status":   "disabled",
	}
	object["agent_continuation"] = metadata
	if behavior == ContinuationNone {
		metadata["wait_strategy"] = "manual_follow_up"
		metadata["message"] = "该 ASM 资源已关闭自动续跑；任务仍在后台执行，稍后可由用户主动查看"
		return
	}
	taskIDs := continuationTaskIDs(result)
	conversationID := strings.TrimSpace(req.ConversationID)
	ownerUserID := strings.TrimSpace(req.OwnerUserID)
	if len(taskIDs) == 0 || conversationID == "" || ownerUserID == "" {
		metadata["status"] = "not_linked"
		metadata["wait_strategy"] = "manual_follow_up"
		metadata["message"] = "当前任务未关联 Agent 对话；结果仍会自动本地化，但不会自动续跑对话"
		return
	}
	rawTaskIDs, _ := json.Marshal(taskIDs)
	item := &database.ASMAgentContinuation{
		ID: "asmcont_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20], TaskIDsJSON: string(rawTaskIDs),
		ConversationID: conversationID, OwnerUserID: ownerUserID, Behavior: behavior,
		RunningPrompt: settings.RunningPrompt, IdlePrompt: settings.IdlePrompt, Status: "waiting",
	}
	if err := s.db.CreateASMAgentContinuation(item); err != nil {
		metadata["status"] = "failed"
		metadata["message"] = err.Error()
		s.logger.Warn("保存 ASM Agent 联动失败", zap.Error(err))
		return
	}
	metadata["id"] = item.ID
	metadata["status"] = "waiting"
	if behavior == ContinuationNotifyOnly {
		metadata["wait_strategy"] = "record_only"
		metadata["message"] = "系统会在后台跟踪并本地化结果，但当前资源设置为仅记录完成，不自动恢复对话"
	} else {
		metadata["wait_strategy"] = "system_managed"
		metadata["message"] = "系统会在后台等待扫描及结果本地化完成，并按资源设置自动恢复当前对话"
	}
}

func continuationTasks(raw string) []string {
	var result []string
	_ = json.Unmarshal([]byte(raw), &result)
	return result
}

func (s *Service) continuationReady(item *database.ASMAgentContinuation) (bool, bool, []*database.ASMTask, string) {
	tasks := make([]*database.ASMTask, 0)
	syncStates := make([]string, 0)
	for _, taskID := range continuationTasks(item.TaskIDsJSON) {
		task, err := s.db.GetASMTask(taskID)
		if err != nil {
			return false, false, nil, ""
		}
		tasks = append(tasks, task)
		switch task.Status {
		case "failed", "stopped":
			return false, true, tasks, task.Status
		case "completed":
			status := s.resultSyncView(task).Status
			if status == "pending" || status == "waiting" || status == "syncing" {
				return false, false, nil, ""
			}
			if caching, _ := s.ScreenshotCacheState(task.ID); caching {
				return false, false, nil, ""
			}
			syncStates = append(syncStates, status)
		default:
			return false, false, nil, ""
		}
	}
	return len(tasks) > 0, false, tasks, strings.Join(syncStates, ",")
}

func continuationTaskType(task *database.ASMTask) string {
	if task == nil {
		return "asset_discovery"
	}
	var options map[string]interface{}
	_ = json.Unmarshal([]byte(task.OptionsJSON), &options)
	for _, key := range []string{"task_type", "task_mode", "port_scan_type", "required_port_scope"} {
		if value := meaningfulString(options[key]); value != "" {
			return value
		}
	}
	return normalizeProvider(task.Provider)
}

func renderContinuationPrompt(template string, tasks []*database.ASMTask, syncStatus string) string {
	if len(tasks) == 0 {
		return template
	}
	ids, targets := make([]string, 0, len(tasks)), make([]string, 0, len(tasks))
	for _, task := range tasks {
		ids = append(ids, task.ID)
		if target := strings.TrimSpace(task.Target); target != "" {
			targets = append(targets, target)
		}
	}
	first := tasks[0]
	return strings.NewReplacer(
		"{{provider}}", providerDisplayName(first.Provider),
		"{{task_type}}", continuationTaskType(first),
		"{{task_id}}", strings.Join(ids, ", "),
		"{{task_name}}", first.Name,
		"{{targets}}", strings.Join(targets, ", "),
		"{{sync_status}}", syncStatus,
	).Replace(template)
}

func (s *Service) reconcileAgentContinuations(ctx context.Context) {
	_ = s.db.RecoverStaleASMAgentContinuations(time.Now().UTC().Add(-5 * time.Hour))
	items, err := s.db.ListPendingASMAgentContinuations(50)
	if err != nil {
		s.logger.Warn("查询 ASM Agent 联动失败", zap.Error(err))
		return
	}
	for _, item := range items {
		ready, cancelled, tasks, syncStatus := s.continuationReady(item)
		if cancelled {
			now := time.Now().UTC()
			item.Status, item.CompletedAt, item.LastError = "cancelled", &now, "ASM 任务未正常完成: "+syncStatus
			_ = s.db.UpdateASMAgentContinuation(item)
			continue
		}
		if !ready {
			continue
		}
		if item.Status == "waiting" {
			now := time.Now().UTC()
			item.Status, item.ReadyAt = "ready", &now
			if s.agentRunning != nil {
				item.AgentWasRunning = s.agentRunning(item.ConversationID)
			}
			if item.Behavior == ContinuationNotifyOnly {
				item.Status, item.CompletedAt = "completed", &now
			}
			if err := s.db.UpdateASMAgentContinuation(item); err != nil || item.Status == "completed" {
				continue
			}
		}
		if s.agentRunning != nil && s.agentRunning(item.ConversationID) {
			continue
		}
		s.startAgentContinuation(item, tasks, syncStatus)
	}
}

func (s *Service) startAgentContinuation(item *database.ASMAgentContinuation, tasks []*database.ASMTask, syncStatus string) {
	s.continuationMu.Lock()
	if s.continuationJobs[item.ID] || s.continuationRunner == nil {
		s.continuationMu.Unlock()
		return
	}
	s.continuationJobs[item.ID] = true
	runner := s.continuationRunner
	s.continuationMu.Unlock()

	item.Status = "running"
	item.Attempts++
	item.LastError = ""
	if err := s.db.UpdateASMAgentContinuation(item); err != nil {
		s.continuationMu.Lock()
		delete(s.continuationJobs, item.ID)
		s.continuationMu.Unlock()
		return
	}
	template := item.IdlePrompt
	if item.AgentWasRunning {
		template = item.RunningPrompt
	}
	prompt := renderContinuationPrompt(template, tasks, syncStatus)
	go func() {
		defer func() {
			s.continuationMu.Lock()
			delete(s.continuationJobs, item.ID)
			s.continuationMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(s.workerCtx, 4*time.Hour)
		defer cancel()
		err := runner(ctx, item, prompt)
		now := time.Now().UTC()
		// The user may stop the restored or original conversation while the
		// runner is unwinding. Never overwrite that durable opt-out with retry.
		if current, readErr := s.db.GetASMAgentContinuation(item.ID); readErr == nil && current.Status == "user_stopped" {
			return
		}
		if err == nil {
			item.Status, item.CompletedAt, item.LastError = "completed", &now, ""
		} else {
			item.LastError = truncateError(err)
			if item.Attempts >= 5 {
				item.Status = "failed"
			} else {
				item.Status = "retry"
			}
		}
		if updateErr := s.db.UpdateASMAgentContinuation(item); updateErr != nil {
			s.logger.Warn("更新 ASM Agent 联动执行状态失败", zap.String("continuation_id", item.ID), zap.Error(updateErr))
		}
	}()
}
