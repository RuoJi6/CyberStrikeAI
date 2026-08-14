package asm

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/database"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type TaskHistoryFilter struct {
	Provider   string
	ResourceID string
	Status     string
	Query      string
	Page       int
	PageSize   int
}

type TaskHistoryView struct {
	ID                string                    `json:"id"`
	BatchID           string                    `json:"batch_id,omitempty"`
	BatchIndex        int                       `json:"batch_index,omitempty"`
	BatchSize         int                       `json:"batch_size,omitempty"`
	ResourceID        string                    `json:"resource_id"`
	ResourceName      string                    `json:"resource_name"`
	Provider          string                    `json:"provider"`
	RemoteTaskID      string                    `json:"remote_task_id"`
	Name              string                    `json:"name"`
	Target            string                    `json:"target"`
	Options           map[string]interface{}    `json:"options"`
	ExecutionProfile  map[string]interface{}    `json:"execution_profile,omitempty"`
	Status            string                    `json:"status"`
	Progress          int                       `json:"progress"`
	Stage             string                    `json:"stage"`
	Summary           map[string]interface{}    `json:"summary"`
	Detail            interface{}               `json:"detail,omitempty"`
	LastError         string                    `json:"last_error,omitempty"`
	LastSyncedAt      *time.Time                `json:"last_synced_at,omitempty"`
	Screenshots       []*database.ASMScreenshot `json:"screenshots,omitempty"`
	ScreenshotCaching bool                      `json:"screenshot_caching,omitempty"`
	ScreenshotError   string                    `json:"screenshot_error,omitempty"`
	ResultTypes       []ResultType              `json:"result_types"`
	ResultSync        ResultSyncView            `json:"result_sync"`
	CreatedAt         time.Time                 `json:"created_at"`
	UpdatedAt         time.Time                 `json:"updated_at"`
}

type TaskHistoryPage struct {
	Tasks    []TaskHistoryView `json:"tasks"`
	Total    int               `json:"total"`
	Page     int               `json:"page"`
	PageSize int               `json:"page_size"`
}

type TaskResultsView struct {
	TaskID            string                    `json:"task_id"`
	AssetType         string                    `json:"asset_type"`
	Payload           interface{}               `json:"payload"`
	Stale             bool                      `json:"stale"`
	CachedAt          *time.Time                `json:"cached_at,omitempty"`
	Screenshots       []*database.ASMScreenshot `json:"screenshots,omitempty"`
	ScreenshotCaching bool                      `json:"screenshot_caching,omitempty"`
	ScreenshotError   string                    `json:"screenshot_error,omitempty"`
	Source            string                    `json:"source"`
	Sync              ResultSyncView            `json:"sync"`
}

func jsonObject(raw string) map[string]interface{} {
	value := make(map[string]interface{})
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &value)
	}
	return value
}

func jsonValue(raw string) interface{} {
	if strings.TrimSpace(raw) == "" {
		return map[string]interface{}{}
	}
	var value interface{}
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return map[string]interface{}{}
	}
	return value
}

func taskHistoryView(item *database.ASMTask) TaskHistoryView {
	options := jsonObject(item.OptionsJSON)
	detail := jsonValue(item.DetailJSON)
	return TaskHistoryView{
		ID: item.ID, BatchID: item.BatchID, BatchIndex: item.BatchIndex, BatchSize: item.BatchSize,
		ResourceID: item.ResourceID, ResourceName: item.ResourceName,
		Provider: item.Provider, RemoteTaskID: item.RemoteTaskID, Name: item.Name,
		Target: item.Target, Options: options, ExecutionProfile: taskExecutionProfile(item.Provider, options, detail), Status: item.Status,
		Progress: item.Progress, Stage: item.Stage, Summary: jsonObject(item.SummaryJSON),
		Detail: detail, LastError: item.LastError,
		ResultTypes:  providerResultTypes(item.Provider),
		LastSyncedAt: item.LastSyncedAt, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func valueMap(value interface{}) map[string]interface{} {
	if result, ok := value.(map[string]interface{}); ok {
		return result
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var result map[string]interface{}
	if json.Unmarshal(raw, &result) != nil {
		return nil
	}
	return result
}

func pathValue(value interface{}, path ...interface{}) interface{} {
	current := value
	for _, segment := range path {
		switch key := segment.(type) {
		case string:
			object, ok := current.(map[string]interface{})
			if !ok {
				return nil
			}
			current = object[key]
		case int:
			items, ok := current.([]interface{})
			if !ok || key < 0 || key >= len(items) {
				return nil
			}
			current = items[key]
		default:
			return nil
		}
	}
	return current
}

func meaningfulString(value interface{}) string {
	if value == nil {
		return ""
	}
	result := strings.TrimSpace(fmt.Sprint(value))
	if result == "<nil>" || result == "null" {
		return ""
	}
	return result
}

func historyStringSlice(value interface{}) []string {
	items := make([]string, 0)
	switch raw := value.(type) {
	case []string:
		items = append(items, raw...)
	case []int:
		for _, item := range raw {
			items = append(items, strconv.Itoa(item))
		}
	case []interface{}:
		for _, item := range raw {
			if text := meaningfulString(item); text != "" {
				items = append(items, text)
			}
		}
	}
	return items
}

func firstTaskHistoryValue(value interface{}, paths ...[]interface{}) interface{} {
	for _, path := range paths {
		if result := pathValue(value, path...); result != nil {
			return result
		}
	}
	return nil
}

func taskExecutionProfile(provider string, options map[string]interface{}, detail interface{}) map[string]interface{} {
	if stored := valueMap(options["_execution_profile"]); len(stored) > 0 {
		return stored
	}
	profile := map[string]interface{}{}
	switch normalizeProvider(provider) {
	case ProviderScopeSentry:
		effective := valueMap(firstTaskHistoryValue(detail,
			[]interface{}{"effective_template"},
			[]interface{}{"creation_response", "effective_template"},
			[]interface{}{"response", "effective_template"},
		))
		id := meaningfulString(options["template_id"])
		if id == "" && effective != nil {
			id = meaningfulString(effective["template_id"])
		}
		if id == "" {
			id = meaningfulString(firstTaskHistoryValue(detail,
				[]interface{}{"template_id"},
				[]interface{}{"task", "data", "template"},
				[]interface{}{"task", "template"},
			))
		}
		name := ""
		if effective != nil {
			name = meaningfulString(effective["template_name"])
			for _, key := range []string{"port_scope", "port_expression", "full_ports", "enabled_capabilities", "selected_poc_count"} {
				if value, exists := effective[key]; exists {
					profile[key] = value
				}
			}
		}
		if id == "" && name == "" {
			return nil
		}
		profile["kind"], profile["label"], profile["id"], profile["name"] = "template", "ScopeSentry 模板", id, name
	case ProviderARL:
		id := meaningfulString(options["policy_id"])
		if id == "" {
			return nil
		}
		profile["kind"], profile["label"], profile["id"] = "policy", "ARL 策略", id
		profile["name"] = meaningfulString(firstTaskHistoryValue(detail,
			[]interface{}{"policy_name"},
			[]interface{}{"response", "policy_name"},
		))
	case ProviderXingRin:
		ids := historyStringSlice(options["engine_ids"])
		if len(ids) == 0 {
			ids = historyStringSlice(firstTaskHistoryValue(detail,
				[]interface{}{"execution_profile", "ids"},
				[]interface{}{"tasks", "results", 0, "engineIds"},
				[]interface{}{"response", "scans", 0, "engineIds"},
			))
		}
		names := historyStringSlice(firstTaskHistoryValue(detail,
			[]interface{}{"execution_profile", "names"},
			[]interface{}{"tasks", "results", 0, "engineNames"},
			[]interface{}{"response", "scans", 0, "engineNames"},
		))
		if len(ids) == 0 && len(names) == 0 {
			return nil
		}
		profile["kind"], profile["label"], profile["ids"], profile["names"] = "engine", "XingRin 引擎", ids, names
	default:
		return nil
	}
	return profile
}

func taskHistoryOptions(provider string, input map[string]interface{}, result interface{}) map[string]interface{} {
	options := make(map[string]interface{}, len(input)+1)
	for key, value := range input {
		options[key] = value
	}
	if profile := taskExecutionProfile(provider, options, result); len(profile) > 0 {
		options["_execution_profile"] = profile
	}
	return options
}

func remoteTaskID(provider string, result interface{}) string {
	object := valueMap(result)
	paths := [][]interface{}{}
	switch normalizeProvider(provider) {
	case ProviderARL:
		paths = [][]interface{}{
			{"response", "data", "task_id"},
			{"response", "data", "_id"},
			{"response", "data", "id"},
			{"response", "items", 0, "task_id"},
			{"response", "items", 0, "_id"},
			{"response", "task_id"},
		}
	case ProviderXingRin:
		paths = [][]interface{}{{"response", "scans", 0, "id"}, {"response", "id"}}
	case ProviderScopeSentry:
		paths = [][]interface{}{{"task", "id"}, {"task", "_id"}}
	}
	for _, path := range paths {
		if value := meaningfulString(pathValue(object, path...)); value != "" {
			return value
		}
	}
	return ""
}

func normalizeTaskStatus(value interface{}) string {
	status := strings.ToLower(meaningfulString(value))
	switch status {
	case "done", "completed", "complete", "finished", "success", "succeeded", "3":
		return "completed"
	case "running", "processing", "started", "port_scan", "find_site", "site_identify", "site_capture", "domain_brute", "nuclei_scan", "1":
		return "running"
	case "failed", "failure", "error":
		return "failed"
	case "stop", "stopped", "cancelled", "canceled", "2":
		return "stopped"
	case "initiated", "waiting", "pending", "queued", "created", "submitted", "0", "":
		return "submitted"
	default:
		return status
	}
}

func normalizeProviderTaskStatus(provider string, value interface{}) string {
	normalized := normalizeTaskStatus(value)
	if normalizeProvider(provider) == ProviderARL {
		raw := strings.ToLower(meaningfulString(value))
		if raw != "" && normalized == raw {
			// ARL exposes the currently executing pipeline stage in status. New
			// upstream stages are still running states unless they match one of
			// the terminal values handled by normalizeTaskStatus.
			return "running"
		}
	}
	return normalized
}

func creationStatus(provider string, result interface{}) string {
	object := valueMap(result)
	paths := [][]interface{}{{"response", "status"}}
	switch normalizeProvider(provider) {
	case ProviderARL:
		paths = append([][]interface{}{{"response", "data", "status"}, {"response", "items", 0, "status"}}, paths...)
	case ProviderXingRin:
		paths = append([][]interface{}{{"response", "scans", 0, "status"}}, paths...)
	case ProviderScopeSentry:
		paths = append([][]interface{}{{"task", "status"}}, paths...)
	}
	for _, path := range paths {
		if value := pathValue(object, path...); value != nil {
			return normalizeProviderTaskStatus(provider, value)
		}
	}
	return "submitted"
}

type createdTaskEntry struct {
	RemoteID string
	Target   string
	Status   string
	Detail   interface{}
}

type recordedTaskEntry struct {
	LocalID  string
	RemoteID string
	Target   string
	Status   string
}

func requestTargetList(value string) []string {
	return strings.Fields(strings.NewReplacer(",", " ", "\r", " ", "\n", " ", "\t", " ").Replace(value))
}

func createdTaskEntries(provider string, req TaskRequest, result interface{}) []createdTaskEntry {
	provider = normalizeProvider(provider)
	object := valueMap(result)
	var rawTasks []interface{}
	switch provider {
	case ProviderXingRin:
		rawTasks, _ = pathValue(object, "response", "scans").([]interface{})
	case ProviderARL:
		rawTasks, _ = pathValue(object, "response", "items").([]interface{})
	}
	requestTargets := requestTargetList(req.Target)
	entries := make([]createdTaskEntry, 0, len(rawTasks))
	for index, rawTask := range rawTasks {
		task := valueMap(rawTask)
		if task == nil {
			continue
		}
		remoteID := meaningfulString(mapValue(task, "id", "_id", "task_id", "TaskID"))
		if remoteID == "" {
			continue
		}
		target := meaningfulString(mapValue(task, "targetName", "target", "domain", "ip"))
		if target == "" && index < len(requestTargets) {
			target = requestTargets[index]
		}
		if target == "" {
			target = strings.TrimSpace(req.Target)
		}
		status := creationStatus(provider, result)
		if rawStatus := mapValue(task, "status", "state", "taskStatus"); rawStatus != nil {
			status = normalizeProviderTaskStatus(provider, rawStatus)
		}
		entries = append(entries, createdTaskEntry{
			RemoteID: remoteID, Target: target, Status: status,
			Detail: map[string]interface{}{"creation_response": result, "remote_task": task},
		})
	}
	if len(entries) > 0 {
		return entries
	}
	remoteID := remoteTaskID(provider, result)
	if remoteID == "" {
		return nil
	}
	return []createdTaskEntry{{
		RemoteID: remoteID, Target: strings.TrimSpace(req.Target),
		Status: creationStatus(provider, result), Detail: result,
	}}
}

func withHistoryMetadata(result interface{}, batchID string, expected int, records []recordedTaskEntry, warnings []string) interface{} {
	object := valueMap(result)
	if object == nil {
		object = map[string]interface{}{"response": result}
	}
	object["history_recorded"] = len(records) > 0
	object["history_recorded_count"] = len(records)
	object["history_expected_count"] = expected
	if batchID != "" {
		object["batch_id"] = batchID
	}
	localIDs := make([]string, 0, len(records))
	remoteIDs := make([]string, 0, len(records))
	historyRecords := make([]map[string]interface{}, 0, len(records))
	for _, record := range records {
		localIDs = append(localIDs, record.LocalID)
		remoteIDs = append(remoteIDs, record.RemoteID)
		historyRecords = append(historyRecords, map[string]interface{}{
			"local_task_id": record.LocalID, "remote_task_id": record.RemoteID,
			"target": record.Target, "status": record.Status,
		})
	}
	if len(localIDs) > 0 {
		object["local_task_id"] = localIDs[0]
		object["local_task_ids"] = localIDs
		object["remote_task_ids"] = remoteIDs
		object["history_records"] = historyRecords
	}
	if len(warnings) > 0 {
		object["history_warning"] = strings.Join(warnings, "; ")
		object["history_partial"] = len(records) > 0 && len(records) < expected
	}
	return object
}

func (s *Service) recordCreatedTask(conn *Connection, req TaskRequest, result interface{}) interface{} {
	entries := createdTaskEntries(conn.Resource.Provider, req, result)
	if len(entries) == 0 {
		warning := "ASM 已接收任务，但响应中没有可识别的任务 ID"
		s.logger.Warn(warning, zap.String("resource_id", conn.Resource.ID), zap.String("provider", conn.Resource.Provider))
		return withHistoryMetadata(result, "", 0, nil, []string{warning})
	}
	batchID := "asmbatch_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	historyOptions := taskHistoryOptions(conn.Resource.Provider, req.Options, result)
	optionsJSON, _ := json.Marshal(historyOptions)
	if string(optionsJSON) == "" || string(optionsJSON) == "null" {
		optionsJSON = []byte("{}")
	}
	records := make([]recordedTaskEntry, 0, len(entries))
	warnings := make([]string, 0)
	for index, entry := range entries {
		if existing, err := s.db.FindASMTask(conn.Resource.ID, entry.RemoteID); err == nil && existing != nil {
			existing.BatchID, existing.BatchIndex, existing.BatchSize = batchID, index, len(entries)
			existing.OptionsJSON = string(optionsJSON)
			if existing.Target == "" {
				existing.Target = entry.Target
			}
			if updateErr := s.db.UpdateASMTask(existing); updateErr != nil {
				warnings = append(warnings, entry.RemoteID+": "+truncateError(updateErr))
				continue
			}
			records = append(records, recordedTaskEntry{LocalID: existing.ID, RemoteID: entry.RemoteID, Target: existing.Target, Status: existing.Status})
			continue
		}
		detailJSON, _ := json.Marshal(entry.Detail)
		localID := "asmtask_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
		item := &database.ASMTask{
			ID: localID, BatchID: batchID, BatchIndex: index, BatchSize: len(entries),
			ResourceID: conn.Resource.ID, ResourceName: conn.Resource.Name,
			Provider: normalizeProvider(conn.Resource.Provider), RemoteTaskID: entry.RemoteID,
			Name: strings.TrimSpace(req.Name), Target: entry.Target,
			OptionsJSON: string(optionsJSON), Status: entry.Status,
			SummaryJSON: "{}", DetailJSON: string(detailJSON),
		}
		if err := s.db.CreateASMTask(item); err != nil {
			warning := entry.RemoteID + ": " + truncateError(err)
			warnings = append(warnings, warning)
			s.logger.Error("保存 ASM 任务历史失败", zap.String("resource_id", conn.Resource.ID), zap.String("remote_task_id", entry.RemoteID), zap.Error(err))
			continue
		}
		records = append(records, recordedTaskEntry{LocalID: localID, RemoteID: entry.RemoteID, Target: entry.Target, Status: entry.Status})
	}
	return withHistoryMetadata(result, batchID, len(entries), records, warnings)
}

func taskCollection(provider string, payload interface{}) []interface{} {
	object := valueMap(payload)
	if normalizeProvider(provider) == ProviderScopeSentry {
		items := make([]interface{}, 0)
		for _, path := range [][]interface{}{{"tasks", "data", "list"}, {"tasks", "data", "results"}, {"tasks", "data"}} {
			if listed, ok := pathValue(object, path...).([]interface{}); ok {
				items = append(items, listed...)
				break
			}
		}
		for _, path := range [][]interface{}{{"scheduled_tasks", "data", "list"}, {"scheduled_tasks", "data", "results"}, {"scheduled_tasks", "data"}} {
			if listed, ok := pathValue(object, path...).([]interface{}); ok {
				items = append(items, listed...)
				break
			}
		}
		return items
	}
	paths := [][]interface{}{}
	switch normalizeProvider(provider) {
	case ProviderXingRin:
		paths = [][]interface{}{{"tasks", "results"}, {"tasks"}}
	case ProviderARL:
		paths = [][]interface{}{{"tasks", "items"}, {"tasks", "data", "items"}, {"tasks", "data", "results"}, {"tasks", "data", "list"}, {"tasks", "data"}}
	}
	for _, path := range paths {
		if items, ok := pathValue(object, path...).([]interface{}); ok {
			return items
		}
	}
	return nil
}

func parseRemoteTaskTime(value interface{}) time.Time {
	raw := meaningfulString(value)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func (s *Service) recordListedTasks(conn *Connection, payload interface{}) {
	for _, raw := range taskCollection(conn.Resource.Provider, payload) {
		task := valueMap(raw)
		if task == nil {
			continue
		}
		remoteID := meaningfulString(mapValue(task, "id", "_id", "task_id", "TaskID"))
		if remoteID == "" {
			continue
		}
		if existing, err := s.db.FindASMTask(conn.Resource.ID, remoteID); err == nil && existing != nil {
			s.applyRemoteTaskState(existing, task, task, true)
			if updateErr := s.db.UpdateASMTask(existing); updateErr != nil {
				s.logger.Warn("刷新 ASM 远程任务失败", zap.String("resource_id", conn.Resource.ID), zap.String("remote_task_id", remoteID), zap.Error(updateErr))
			}
			continue
		}
		detailJSON, _ := json.Marshal(task)
		summaryJSON := "{}"
		if summary := valueMap(mapValue(task, "summary", "statistic", "statistics", "stats")); summary != nil {
			rawSummary, _ := json.Marshal(summary)
			summaryJSON = string(rawSummary)
		}
		status := normalizeProviderTaskStatus(conn.Resource.Provider, mapValue(task, "status", "state", "taskStatus"))
		progress := numberInt(mapValue(task, "progress", "percent", "percentage"))
		if status == "completed" && progress < 100 {
			progress = 100
		}
		if progress < 0 {
			progress = 0
		}
		if progress > 100 {
			progress = 100
		}
		item := &database.ASMTask{
			ID:         "asmtask_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20],
			ResourceID: conn.Resource.ID, ResourceName: conn.Resource.Name,
			Provider: normalizeProvider(conn.Resource.Provider), RemoteTaskID: remoteID,
			Name:        meaningfulString(mapValue(task, "name", "taskName")),
			Target:      meaningfulString(mapValue(task, "targetName", "target", "domain", "ip")),
			OptionsJSON: "{}", Status: status, Progress: progress,
			Stage:       meaningfulString(mapValue(task, "currentStage", "current_stage", "stage")),
			SummaryJSON: summaryJSON, DetailJSON: string(detailJSON),
			LastError: meaningfulString(mapValue(task, "errorMessage", "error_message", "error")),
			CreatedAt: parseRemoteTaskTime(mapValue(task, "createdAt", "creatTime", "created_at", "start_time")),
		}
		if err := s.db.CreateASMTask(item); err != nil {
			s.logger.Warn("导入 ASM 远程任务失败", zap.String("resource_id", conn.Resource.ID), zap.String("remote_task_id", remoteID), zap.Error(err))
		}
	}
}

func (s *Service) applyRemoteTaskState(item *database.ASMTask, task map[string]interface{}, detail interface{}, synced bool) {
	if item == nil || task == nil {
		return
	}
	if raw, err := json.Marshal(detail); err == nil {
		item.DetailJSON = string(raw)
	}
	statusValue := mapValue(task, "status", "state", "taskStatus")
	if normalizeProvider(item.Provider) == ProviderScopeSentry {
		if normalized := pathValue(valueMap(detail), "normalized_status"); normalized != nil {
			statusValue = normalized
		}
	}
	item.Status = normalizeProviderTaskStatus(item.Provider, statusValue)
	if name := meaningfulString(mapValue(task, "name", "taskName")); name != "" {
		item.Name = name
	}
	if target := meaningfulString(mapValue(task, "targetName", "target", "domain", "ip")); target != "" {
		item.Target = target
	}
	item.Progress = numberInt(mapValue(task, "progress", "percent", "percentage"))
	if normalizeProvider(item.Provider) == ProviderARL {
		if stage := arlPipelineStage(task); stage != "" {
			item.Stage = stage
		}
		if item.Progress == 0 {
			item.Progress = arlPipelineProgress(task)
		}
	}
	if item.Progress < 0 {
		item.Progress = 0
	}
	if item.Progress > 100 {
		item.Progress = 100
	}
	if item.Status == "completed" && item.Progress < 100 {
		item.Progress = 100
	}
	if stage := meaningfulString(mapValue(task, "currentStage", "current_stage", "stage", "service_name")); stage != "" {
		item.Stage = stage
	}
	if summary := valueMap(mapValue(task, "summary", "statistic", "statistics", "stats")); summary != nil {
		raw, _ := json.Marshal(summary)
		item.SummaryJSON = string(raw)
	}
	item.LastError = meaningfulString(mapValue(task, "errorMessage", "error_message", "error"))
	if synced {
		now := time.Now().UTC()
		item.LastSyncedAt = &now
	}
}

func arlPipelineProgress(task map[string]interface{}) int {
	services, _ := mapValue(task, "service").([]interface{})
	completed := len(services)
	if completed == 0 {
		return 0
	}
	options := valueMap(mapValue(task, "options"))
	total := 0
	weights := map[string]int{
		"domain_brute": 1, "port_scan": 1, "service_detection": 1, "service_brute": 1,
		"os_detection": 1, "site_identify": 3, "site_capture": 1, "site_spider": 1,
		"file_leak": 1, "ssl_cert": 1, "nuclei_scan": 1, "findvhost": 1,
		"web_info_hunter": 1, "search_engines": 1, "dns_query_plugin": 1,
	}
	for key, weight := range weights {
		if enabled, ok := options[key].(bool); ok && enabled {
			total += weight
		}
	}
	if total <= completed {
		total = completed + 1
	}
	progress := int(math.Round(float64(completed) * 100 / float64(total)))
	if progress < 1 {
		return 1
	}
	if progress > 95 {
		return 95
	}
	return progress
}

func arlPipelineStage(task map[string]interface{}) string {
	status := strings.ToLower(meaningfulString(mapValue(task, "status")))
	if normalizeTaskStatus(status) == "completed" {
		return "completed"
	}
	if status != "" {
		return status
	}
	services, _ := mapValue(task, "service").([]interface{})
	if len(services) > 0 {
		last := valueMap(services[len(services)-1])
		if name := meaningfulString(mapValue(last, "name")); name != "" {
			return name
		}
	}
	return ""
}

func (s *Service) recordTaskDetail(conn *Connection, remoteTaskID string, payload interface{}) {
	item, err := s.db.FindASMTask(conn.Resource.ID, strings.TrimSpace(remoteTaskID))
	if err != nil || item == nil {
		return
	}
	s.applyRemoteTaskState(item, normalizedTaskPayload(item.Provider, payload), payload, true)
	if err := s.db.UpdateASMTask(item); err != nil {
		s.logger.Warn("刷新 ASM 任务详情失败", zap.String("resource_id", conn.Resource.ID), zap.String("remote_task_id", remoteTaskID), zap.Error(err))
	}
}

func (s *Service) recordTaskLifecycle(resourceID, remoteTaskID, status, stage string, resetProgress bool) bool {
	item, err := s.db.FindASMTask(resourceID, strings.TrimSpace(remoteTaskID))
	if err != nil || item == nil {
		return false
	}
	item.Status = status
	item.Stage = stage
	item.LastError = ""
	if resetProgress {
		item.Progress = 0
	}
	now := time.Now().UTC()
	item.LastSyncedAt = &now
	if err := s.db.UpdateASMTask(item); err != nil {
		s.logger.Warn("更新 ASM 任务生命周期失败", zap.String("resource_id", resourceID), zap.String("remote_task_id", remoteTaskID), zap.Error(err))
		return false
	}
	return true
}

func (s *Service) ListTaskHistory(filter TaskHistoryFilter) (TaskHistoryPage, error) {
	page, pageSize := normalizePagination(filter.Page, filter.PageSize)
	items, total, err := s.db.ListASMTasks(database.ASMTaskFilter{
		Provider: normalizeProvider(filter.Provider), ResourceID: strings.TrimSpace(filter.ResourceID),
		Status: strings.TrimSpace(filter.Status), Query: strings.TrimSpace(filter.Query),
		Page: page, PageSize: pageSize,
	})
	if err != nil {
		return TaskHistoryPage{}, err
	}
	views := make([]TaskHistoryView, 0, len(items))
	for _, item := range items {
		views = append(views, s.taskHistoryView(item))
	}
	return TaskHistoryPage{Tasks: views, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *Service) GetTaskHistory(id string) (TaskHistoryView, error) {
	item, err := s.db.GetASMTask(id)
	if err != nil {
		return TaskHistoryView{}, err
	}
	view := s.taskHistoryView(item)
	view.Screenshots, err = s.db.ListASMScreenshots(item.ID)
	view.Screenshots = enrichScreenshotURLs(view.Screenshots)
	view.ScreenshotCaching, view.ScreenshotError = s.ScreenshotCacheState(item.ID)
	if item.Status == "completed" && view.ResultSync.Status != "completed" {
		s.enqueueTaskResultSync(item.ID)
	}
	return view, err
}

func firstMap(value interface{}) map[string]interface{} {
	if object, ok := value.(map[string]interface{}); ok {
		return object
	}
	if items, ok := value.([]interface{}); ok && len(items) > 0 {
		return firstMap(items[0])
	}
	return nil
}

func normalizedTaskPayload(provider string, payload interface{}) map[string]interface{} {
	object := valueMap(payload)
	switch normalizeProvider(provider) {
	case ProviderXingRin:
		if task := firstMap(pathValue(object, "tasks", "results")); task != nil {
			return task
		}
	case ProviderARL:
		for _, path := range [][]interface{}{{"tasks", "items"}, {"tasks", "data", "items"}, {"tasks", "data", "results"}, {"tasks", "data"}} {
			if task := firstMap(pathValue(object, path...)); task != nil {
				return task
			}
		}
	case ProviderScopeSentry:
		if task := firstMap(pathValue(object, "task", "data")); task != nil {
			return task
		}
		if task := firstMap(pathValue(object, "task")); task != nil {
			return task
		}
	}
	return object
}

func mapValue(object map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, exists := object[key]; exists && value != nil {
			return value
		}
	}
	return nil
}

func numberInt(value interface{}) int {
	switch number := value.(type) {
	case float64:
		return int(math.Round(number))
	case float32:
		return int(math.Round(float64(number)))
	case int:
		return number
	case int64:
		return int(number)
	case json.Number:
		parsed, _ := strconv.ParseFloat(number.String(), 64)
		return int(math.Round(parsed))
	default:
		parsed, _ := strconv.ParseFloat(meaningfulString(value), 64)
		return int(math.Round(parsed))
	}
}

func (s *Service) SyncTaskHistory(ctx context.Context, id string) (TaskHistoryView, error) {
	item, err := s.db.GetASMTask(id)
	if err != nil {
		return TaskHistoryView{}, err
	}
	conn, adapter, err := s.connection(item.ResourceID, false)
	if err != nil {
		item.LastError = truncateError(err)
		return taskHistoryView(item), err
	}
	payload, syncErr := adapter.GetTask(ctx, conn, item.RemoteTaskID)
	now := time.Now().UTC()
	item.LastSyncedAt = &now
	if syncErr != nil {
		item.LastError = truncateError(syncErr)
		_ = s.db.UpdateASMTask(item)
		return taskHistoryView(item), syncErr
	}
	task := normalizedTaskPayload(item.Provider, payload)
	s.applyRemoteTaskState(item, task, payload, true)
	if err := s.db.UpdateASMTask(item); err != nil {
		return TaskHistoryView{}, err
	}
	return s.GetTaskHistory(item.ID)
}

// StopTaskHistory resolves the local history identifier to the provider-native
// task identifier. The browser never needs to know a resource credential or
// guess whether a displayed ID belongs to CyberStrikeAI or to the ASM.
func (s *Service) StopTaskHistory(ctx context.Context, id string) (TaskHistoryView, error) {
	item, err := s.db.GetASMTask(strings.TrimSpace(id))
	if err != nil {
		return TaskHistoryView{}, err
	}
	if item.Status == "completed" || item.Status == "failed" || item.Status == "stopped" {
		return s.GetTaskHistory(item.ID)
	}
	if _, err := s.StopTask(ctx, item.ResourceID, item.RemoteTaskID); err != nil {
		item.LastError = truncateError(err)
		_ = s.db.UpdateASMTask(item)
		return taskHistoryView(item), err
	}
	return s.GetTaskHistory(item.ID)
}

func normalizeAssetType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "site"
	}
	return value
}

func (s *Service) ListTaskHistoryResults(ctx context.Context, id string, filter AssetFilter) (TaskResultsView, error) {
	item, err := s.db.GetASMTask(id)
	if err != nil {
		return TaskResultsView{}, err
	}
	assetType := normalizeAssetType(filter.Type)
	if !providerSupportsResultType(item.Provider, assetType) {
		return TaskResultsView{}, fmt.Errorf("%s 不支持结果类型: %s", providerDisplayName(item.Provider), assetType)
	}
	page, pageSize := normalizePagination(filter.Page, filter.PageSize)
	syncView := s.resultSyncView(item)
	legacy, legacyAt, legacyErr := s.db.GetASMTaskResult(item.ID, assetType)
	if legacyErr != nil {
		return TaskResultsView{}, legacyErr
	}
	rawItems, total, err := s.db.ListASMResultItems(item.ID, assetType, filter.Query, page, pageSize)
	if err != nil {
		return TaskResultsView{}, err
	}
	rows := make([]interface{}, 0, len(rawItems))
	for _, raw := range rawItems {
		rows = append(rows, jsonValue(raw))
	}
	payload := interface{}(map[string]interface{}{"items": rows, "total": total, "page": page, "page_size": pageSize})
	source, stale := "local", !syncView.typeCompleted(assetType)
	var cachedAt *time.Time
	for _, state := range syncView.Types {
		if state.AssetType == assetType && state.SyncedAt != nil {
			cachedAt = state.SyncedAt
			break
		}
	}
	if total == 0 && !syncView.typeCompleted(assetType) {
		if legacy != "" {
			payload, cachedAt, source, stale = jsonValue(legacy), legacyAt, "legacy_cache", true
		}
		if item.Status == "completed" {
			s.enqueueTaskResultSync(item.ID)
		}
	}
	screenshots, _ := s.db.ListASMScreenshots(item.ID)
	screenshots = enrichScreenshotURLs(screenshots)
	caching, cacheError := s.ScreenshotCacheState(item.ID)
	return TaskResultsView{TaskID: item.ID, AssetType: assetType, Payload: payload, Stale: stale,
		CachedAt: cachedAt, Screenshots: screenshots, ScreenshotCaching: caching,
		ScreenshotError: cacheError, Source: source, Sync: syncView}, nil
}

func (s *Service) GetTaskHistoryResultDetail(ctx context.Context, id string, filter AssetDetailFilter) (interface{}, error) {
	item, err := s.db.GetASMTask(id)
	if err != nil {
		return nil, err
	}
	assetType := normalizeAssetType(filter.Type)
	if !providerSupportsResultType(item.Provider, assetType) {
		return nil, fmt.Errorf("%s 不支持结果详情类型: %s", providerDisplayName(item.Provider), assetType)
	}
	if strings.TrimSpace(filter.Key) == "" {
		return nil, fmt.Errorf("结果详情 key 不能为空")
	}
	raw, err := s.db.GetASMResultItem(item.ID, assetType, filter.Key)
	if err != nil {
		return nil, err
	}
	if raw == "" {
		if _, syncErr := s.syncTaskResultType(ctx, item, assetType); syncErr != nil {
			return nil, syncErr
		}
		raw, err = s.db.GetASMResultItem(item.ID, assetType, filter.Key)
	}
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, fmt.Errorf("ASM 本地结果详情不存在")
	}
	value := jsonValue(raw)
	if object := valueMap(value); object != nil {
		if detail, ok := object["provider_detail"]; ok {
			return detail, nil
		}
	}
	return value, nil
}
