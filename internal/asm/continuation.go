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

type AgentContinuationHistoryFilter struct {
	Statuses []string
	Query    string
	Page     int
	PageSize int
	Access   database.RBACListAccess
}

type AgentContinuationTaskView struct {
	ID           string `json:"id"`
	RemoteTaskID string `json:"remote_task_id,omitempty"`
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	Provider     string `json:"provider"`
	Name         string `json:"name"`
	Target       string `json:"target"`
	Status       string `json:"status"`
	Progress     int    `json:"progress"`
	Stage        string `json:"stage,omitempty"`
	Consumed     bool   `json:"consumed_by_agent,omitempty"`
}

type AgentContinuationHistoryItem struct {
	ID                string                      `json:"id"`
	ConversationID    string                      `json:"conversation_id"`
	ConversationTitle string                      `json:"conversation_title,omitempty"`
	Behavior          string                      `json:"behavior"`
	Status            string                      `json:"status"`
	Phase             string                      `json:"phase"`
	AgentWasRunning   bool                        `json:"agent_was_running"`
	Attempts          int                         `json:"attempts"`
	LastError         string                      `json:"last_error,omitempty"`
	ReadyAt           *time.Time                  `json:"ready_at,omitempty"`
	CompletedAt       *time.Time                  `json:"completed_at,omitempty"`
	CreatedAt         time.Time                   `json:"created_at"`
	UpdatedAt         time.Time                   `json:"updated_at"`
	ConsumedTaskIDs   []string                    `json:"consumed_task_ids,omitempty"`
	ConsumedAt        *time.Time                  `json:"consumed_at,omitempty"`
	ConsumedTool      string                      `json:"consumed_tool,omitempty"`
	Tasks             []AgentContinuationTaskView `json:"tasks"`
}

type AgentResultConsumptionView struct {
	Consumed                  bool     `json:"consumed"`
	TaskID                    string   `json:"task_id"`
	MatchedContinuationIDs    []string `json:"matched_continuation_ids,omitempty"`
	SuppressedContinuationIDs []string `json:"suppressed_continuation_ids,omitempty"`
	Message                   string   `json:"message,omitempty"`
}

type AgentContinuationHistoryPage struct {
	Items        []AgentContinuationHistoryItem `json:"items"`
	Total        int                            `json:"total"`
	Page         int                            `json:"page"`
	PageSize     int                            `json:"page_size"`
	StatusCounts map[string]int                 `json:"status_counts"`
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
func (s *Service) SetAgentContinuationHooks(runtime func(string) (bool, time.Time), runner func(context.Context, *database.ASMAgentContinuation, string) error) {
	s.continuationMu.Lock()
	defer s.continuationMu.Unlock()
	s.agentRuntime = runtime
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

func continuationTaskSet(raw string) map[string]bool {
	result := make(map[string]bool)
	for _, taskID := range continuationTasks(raw) {
		if taskID = strings.TrimSpace(taskID); taskID != "" {
			result[taskID] = true
		}
	}
	return result
}

// MarkAgentTaskResultConsumed suppresses a redundant automatic continuation
// only after the source Agent has successfully read a completed, localized
// result page for the same task. Progress-only reads never call this method.
func (s *Service) MarkAgentTaskResultConsumed(conversationID, resourceID, taskID, toolName string, result TaskResultsView) (AgentResultConsumptionView, error) {
	view := AgentResultConsumptionView{TaskID: strings.TrimSpace(taskID)}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" || view.TaskID == "" || result.Stale {
		return view, nil
	}
	_, task, err := s.resolveProviderTaskID(resourceID, view.TaskID)
	if err != nil {
		return view, err
	}
	if task == nil || task.Status != "completed" {
		return view, nil
	}
	view.TaskID = task.ID
	consumed, err := s.db.ConsumeASMAgentContinuationTask(conversationID, task.ID, toolName)
	if err != nil {
		return view, err
	}
	view.MatchedContinuationIDs = consumed.MatchedContinuationIDs
	view.SuppressedContinuationIDs = consumed.CompletedContinuationIDs
	view.Consumed = len(consumed.MatchedContinuationIDs) > 0
	if len(view.SuppressedContinuationIDs) > 0 {
		view.Message = "Agent 已主动读取全部关联扫描结果，系统不会重复插入 ASM 完成通知"
	} else if view.Consumed {
		view.Message = "Agent 已主动读取该扫描结果；多任务联动仅保留尚未读取的任务"
	}
	return view, nil
}

// PrepareAgentContinuationPrompt recomputes the prompt after the queued turn
// owns the conversation. This removes tasks consumed while the foreground
// Agent was still running, so a multi-task continuation only mentions unread
// results.
func (s *Service) PrepareAgentContinuationPrompt(item *database.ASMAgentContinuation) (string, bool, error) {
	if item == nil {
		return "", false, fmt.Errorf("ASM Agent 联动记录不能为空")
	}
	consumed := continuationTaskSet(item.ConsumedTaskIDsJSON)
	tasks := make([]*database.ASMTask, 0)
	syncStates := make([]string, 0)
	for _, taskID := range continuationTasks(item.TaskIDsJSON) {
		if consumed[taskID] {
			continue
		}
		task, err := s.db.GetASMTask(taskID)
		if err != nil {
			return "", false, err
		}
		tasks = append(tasks, task)
		syncStates = append(syncStates, s.resultSyncView(task).Status)
	}
	if len(tasks) == 0 {
		return "", false, nil
	}
	template := item.IdlePrompt
	if item.AgentWasRunning {
		template = item.RunningPrompt
	}
	return renderContinuationPrompt(template, tasks, strings.Join(syncStates, ",")), true, nil
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

func continuationHistoryPhase(item *database.ASMAgentContinuation, tasks []AgentContinuationTaskView) string {
	if item == nil {
		return "failed"
	}
	switch item.Status {
	case "ready":
		return "awaiting_agent"
	case "retry":
		return "retry_wait"
	case "queued":
		return "queued_active"
	case "running":
		return "resuming"
	case "completed":
		if item.Behavior == ContinuationNotifyOnly {
			return "recorded"
		}
		return "success"
	case "agent_consumed":
		return "agent_consumed"
	case "user_stopped":
		return "user_stopped"
	case "cancelled":
		return "scan_cancelled"
	case "failed":
		return "failed"
	case "waiting":
		if len(tasks) == 0 {
			return "waiting_scan"
		}
		allCompleted := true
		for _, task := range tasks {
			switch task.Status {
			case "completed":
				// The continuation worker still needs local result and screenshot
				// synchronization before it can advance to ready.
			case "failed", "stopped":
				return "scan_cancelled"
			default:
				allCompleted = false
			}
		}
		if allCompleted {
			return "localizing"
		}
		return "scanning"
	default:
		return "failed"
	}
}

// ListAgentContinuations exposes the durable worker state used by the Agent
// linkage diagnostics UI. Prompts and owner identifiers are intentionally not
// returned because the page only needs execution state and task context.
func (s *Service) ListAgentContinuations(filter AgentContinuationHistoryFilter) (AgentContinuationHistoryPage, error) {
	page, pageSize := filter.Page, filter.PageSize
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	rows, total, err := s.db.ListASMAgentContinuations(database.ASMAgentContinuationFilter{
		Statuses: filter.Statuses, Query: filter.Query, Page: page, PageSize: pageSize, Access: filter.Access,
	})
	if err != nil {
		return AgentContinuationHistoryPage{}, err
	}
	counts, err := s.db.CountASMAgentContinuationsByStatus(filter.Access)
	if err != nil {
		return AgentContinuationHistoryPage{}, err
	}
	result := AgentContinuationHistoryPage{
		Items: make([]AgentContinuationHistoryItem, 0, len(rows)), Total: total,
		Page: page, PageSize: pageSize, StatusCounts: counts,
	}
	for _, row := range rows {
		view := AgentContinuationHistoryItem{
			ID: row.ID, ConversationID: row.ConversationID, Behavior: row.Behavior,
			Status: row.Status, AgentWasRunning: row.AgentWasRunning, Attempts: row.Attempts,
			LastError: row.LastError, ReadyAt: row.ReadyAt, CompletedAt: row.CompletedAt,
			CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
			ConsumedTaskIDs: continuationTasks(row.ConsumedTaskIDsJSON), ConsumedAt: row.ConsumedAt, ConsumedTool: row.ConsumedTool,
			Tasks: make([]AgentContinuationTaskView, 0),
		}
		consumedTaskIDs := continuationTaskSet(row.ConsumedTaskIDsJSON)
		if conversation, readErr := s.db.GetConversation(row.ConversationID); readErr == nil {
			view.ConversationTitle = conversation.Title
		}
		for _, taskID := range continuationTasks(row.TaskIDsJSON) {
			task, readErr := s.db.GetASMTask(taskID)
			if readErr != nil {
				continue
			}
			view.Tasks = append(view.Tasks, AgentContinuationTaskView{
				ID: task.ID, RemoteTaskID: task.RemoteTaskID, ResourceID: task.ResourceID,
				ResourceName: task.ResourceName, Provider: task.Provider, Name: task.Name,
				Target: task.Target, Status: task.Status, Progress: task.Progress, Stage: task.Stage,
				Consumed: consumedTaskIDs[task.ID],
			})
		}
		view.Phase = continuationHistoryPhase(row, view.Tasks)
		result.Items = append(result.Items, view)
	}
	return result, nil
}

func (s *Service) reconcileAgentContinuations(ctx context.Context) {
	s.reconcileDeliveredAgentContinuations()
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
			if s.agentRuntime != nil {
				var startedAt time.Time
				item.AgentWasRunning, startedAt = s.agentRuntime(item.ConversationID)
				if item.AgentWasRunning && !startedAt.IsZero() {
					startedAt = startedAt.UTC()
					item.AgentStartedAt = &startedAt
				}
			}
			// A service restart clears the in-memory task registry. Fall back to
			// the durable assistant placeholder so the resumed turn still inherits
			// the original elapsed-time origin without pretending Agent is active.
			if item.Behavior == ContinuationAuto && item.AgentStartedAt == nil {
				persistedStart, persistedErr := s.db.GetPendingAssistantTurnStartedAt(item.ConversationID)
				if persistedErr != nil {
					s.logger.Warn("读取 ASM 续跑持久化起点失败", zap.String("continuation_id", item.ID), zap.Error(persistedErr))
				} else if !persistedStart.IsZero() {
					persistedStart = persistedStart.UTC()
					item.AgentStartedAt = &persistedStart
				}
			}
			if item.Behavior == ContinuationNotifyOnly {
				item.Status, item.CompletedAt = "completed", &now
			}
			if err := s.db.UpdateASMAgentContinuation(item); err != nil || item.Status == "completed" {
				continue
			}
		}
		s.startAgentContinuation(item, tasks, syncStatus)
	}
}

func (s *Service) reconcileDeliveredAgentContinuations() {
	if repaired, err := s.db.RepairMissingASMContinuationTurnTimings(500); err != nil {
		s.logger.Warn("修复 ASM 续跑累计时间失败", zap.Error(err))
	} else if repaired > 0 {
		s.logger.Info("已修复 ASM 续跑累计时间", zap.Int("count", repaired))
	}
	items, err := s.db.ListUserStoppedStartedASMAgentContinuations(200)
	if err != nil {
		s.logger.Warn("核验历史 ASM Agent 联动状态失败", zap.Error(err))
		return
	}
	for _, item := range items {
		taskIDs := continuationTasks(item.TaskIDsJSON)
		if len(taskIDs) == 0 {
			continue
		}
		messages, readErr := s.db.GetMessagesLite(item.ConversationID)
		if readErr != nil {
			continue
		}
		var deliveredAt time.Time
		for _, message := range messages {
			content := strings.TrimSpace(message.Content)
			if message.Role != "user" || !strings.HasPrefix(content, "ASM 扫描结果已完成。") {
				continue
			}
			matched := true
			for _, taskID := range taskIDs {
				if !strings.Contains(content, taskID) {
					matched = false
					break
				}
			}
			if matched {
				deliveredAt = message.CreatedAt
				break
			}
		}
		if deliveredAt.IsZero() {
			continue
		}
		if promoteErr := s.db.PromoteDeliveredASMAgentContinuation(item.ID, deliveredAt); promoteErr != nil {
			s.logger.Warn("修复已送达 ASM Agent 联动状态失败", zap.String("continuation_id", item.ID), zap.Error(promoteErr))
		}
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

	// Persist queue admission before handing the work to the process-local
	// Eino TurnLoop. Attempts are incremented only when the queued turn really
	// starts, not while it is waiting for a foreground Agent to finish.
	item.Status = "queued"
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
		if current, readErr := s.db.GetASMAgentContinuation(item.ID); readErr == nil {
			if current.Status == "user_stopped" || current.Status == "agent_consumed" {
				return
			}
		}
		err := runner(ctx, item, prompt)
		now := time.Now().UTC()
		// The user may stop the restored or original conversation while the
		// runner is unwinding. Never overwrite that durable opt-out with retry.
		if current, readErr := s.db.GetASMAgentContinuation(item.ID); readErr == nil {
			if current.Status == "user_stopped" || current.Status == "agent_consumed" || current.Status == "completed" {
				return
			}
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
