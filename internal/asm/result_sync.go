package asm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

const asmResultSyncPageSize = 100

type ResultSyncView struct {
	Status         string                        `json:"status"`
	CurrentType    string                        `json:"current_type,omitempty"`
	CompletedTypes int                           `json:"completed_types"`
	TotalTypes     int                           `json:"total_types"`
	ItemCount      int                           `json:"item_count"`
	LastError      string                        `json:"last_error,omitempty"`
	StartedAt      *time.Time                    `json:"started_at,omitempty"`
	SyncedAt       *time.Time                    `json:"synced_at,omitempty"`
	Types          []database.ASMResultSyncState `json:"types,omitempty"`
}

func (view ResultSyncView) typeCompleted(assetType string) bool {
	for _, state := range view.Types {
		if state.AssetType == assetType && state.Status == "completed" {
			return true
		}
	}
	return false
}

func (view ResultSyncView) typeStatus(assetType string) string {
	for _, state := range view.Types {
		if state.AssetType == assetType {
			return state.Status
		}
	}
	return ""
}

func laterTime(current *time.Time, candidate *time.Time) *time.Time {
	if candidate == nil || (current != nil && !candidate.After(*current)) {
		return current
	}
	value := *candidate
	return &value
}

func (s *Service) resultSyncView(item *database.ASMTask) ResultSyncView {
	types := providerResultTypes(item.Provider)
	view := ResultSyncView{Status: "pending", TotalTypes: len(types), Types: []database.ASMResultSyncState{}}
	states, err := s.db.ListASMResultSyncStates(item.ID)
	if err != nil {
		view.Status, view.LastError = "failed", truncateError(err)
		return view
	}
	view.Types = states
	failed := 0
	for _, state := range states {
		view.ItemCount += state.ItemCount
		view.StartedAt = laterTime(view.StartedAt, state.StartedAt)
		view.SyncedAt = laterTime(view.SyncedAt, state.SyncedAt)
		switch state.Status {
		case "completed":
			view.CompletedTypes++
		case "syncing":
			view.Status, view.CurrentType = "syncing", state.AssetType
		case "failed":
			failed++
			if view.LastError == "" {
				view.LastError = state.LastError
			}
		}
	}
	if view.Status != "syncing" {
		switch {
		case view.TotalTypes > 0 && view.CompletedTypes >= view.TotalTypes:
			view.Status = "completed"
		case failed > 0 && view.CompletedTypes > 0:
			view.Status = "partial"
		case failed > 0:
			view.Status = "failed"
		case item.Status != "completed":
			view.Status = "waiting"
		default:
			view.Status = "pending"
		}
	}
	return view
}

func (s *Service) taskHistoryView(item *database.ASMTask) TaskHistoryView {
	view := taskHistoryView(item)
	view.ResultSync = s.resultSyncView(item)
	return view
}

func findResultRows(value interface{}, depth int) ([]interface{}, bool) {
	if depth > 10 || value == nil {
		return nil, false
	}
	if rows, ok := value.([]interface{}); ok {
		return rows, true
	}
	object, ok := value.(map[string]interface{})
	if !ok {
		return nil, false
	}
	for _, key := range []string{"items", "list", "results", "data", "response"} {
		if child, exists := object[key]; exists {
			if rows, found := findResultRows(child, depth+1); found {
				return rows, true
			}
		}
	}
	return nil, false
}

func findResultTotal(value interface{}, depth int) (int, bool) {
	if depth > 10 || value == nil {
		return 0, false
	}
	object, ok := value.(map[string]interface{})
	if !ok {
		return 0, false
	}
	for _, key := range []string{"total", "count", "totalCount", "total_count"} {
		if raw, exists := object[key]; exists {
			value := numberInt(raw)
			if value >= 0 {
				return value, true
			}
		}
	}
	for _, key := range []string{"results", "data", "response"} {
		if child, exists := object[key]; exists {
			if value, found := findResultTotal(child, depth+1); found {
				return value, true
			}
		}
	}
	return 0, false
}

func resultProviderKey(row map[string]interface{}) string {
	for _, key := range []string{"hash", "_id", "id", "task_id", "url", "site", "domain", "ip", "host"} {
		if value := meaningfulString(row[key]); value != "" {
			return value
		}
	}
	return ""
}

func resultSearchText(row map[string]interface{}, raw []byte) string {
	parts := make([]string, 0, 12)
	for _, key := range []string{"url", "site", "domain", "ip", "host", "title", "name", "service", "service_name", "vulnerability", "vul_name", "severity", "status"} {
		if value := meaningfulString(row[key]); value != "" {
			parts = append(parts, value)
		}
	}
	if len(raw) > 32768 {
		raw = raw[:32768]
	}
	parts = append(parts, string(raw))
	return strings.ToLower(strings.Join(parts, " "))
}

func resultItem(row map[string]interface{}, order int) (database.ASMResultItem, error) {
	raw, err := json.Marshal(row)
	if err != nil {
		return database.ASMResultItem{}, err
	}
	digest := sha256.Sum256(raw)
	return database.ASMResultItem{
		ItemKey: hex.EncodeToString(digest[:]), ProviderKey: resultProviderKey(row),
		PayloadJSON: string(raw), SearchText: resultSearchText(row, raw), SortOrder: order,
	}, nil
}

func (s *Service) markResultSync(taskID, assetType, status string, count int, startedAt, syncedAt *time.Time, syncErr error) {
	message := ""
	if syncErr != nil {
		message = truncateError(syncErr)
	}
	if err := s.db.UpsertASMResultSyncState(database.ASMResultSyncState{
		TaskID: taskID, AssetType: assetType, Status: status, ItemCount: count,
		LastError: message, StartedAt: startedAt, SyncedAt: syncedAt,
	}); err != nil {
		s.logger.Warn("保存 ASM 结果同步状态失败", zap.String("task_id", taskID), zap.String("asset_type", assetType), zap.Error(err))
	}
}

func (s *Service) syncTaskResultType(ctx context.Context, item *database.ASMTask, assetType string) (int, error) {
	assetType = normalizeAssetType(assetType)
	if !providerSupportsResultType(item.Provider, assetType) {
		return 0, fmt.Errorf("%s 不支持结果类型: %s", providerDisplayName(item.Provider), assetType)
	}
	started := time.Now().UTC()
	s.markResultSync(item.ID, assetType, "syncing", 0, &started, nil, nil)
	conn, adapter, err := s.connection(item.ResourceID, false)
	if err != nil {
		s.markResultSync(item.ID, assetType, "failed", 0, &started, nil, err)
		return 0, err
	}
	allItems := make([]database.ASMResultItem, 0)
	seen := make(map[string]struct{})
	var screenshotPayloads []interface{}
	for page := 1; page <= 10000; page++ {
		beforeCount := len(allItems)
		payload, listErr := adapter.ListAssets(ctx, conn, AssetFilter{TaskID: item.RemoteTaskID, Type: assetType, Page: page, PageSize: asmResultSyncPageSize})
		if listErr != nil {
			s.markResultSync(item.ID, assetType, "failed", len(allItems), &started, nil, listErr)
			return len(allItems), listErr
		}
		rows, _ := findResultRows(payload, 0)
		for _, rawRow := range rows {
			row := valueMap(rawRow)
			if row == nil {
				continue
			}
			if assetType == "vulnerability" {
				if detailAdapter, ok := adapter.(AssetDetailAdapter); ok {
					key := resultProviderKey(row)
					if key != "" {
						if detail, detailErr := detailAdapter.GetAssetDetail(ctx, conn, AssetDetailFilter{Type: assetType, Key: key}); detailErr == nil {
							row["provider_detail"] = detail
						} else {
							row["provider_detail_error"] = truncateError(detailErr)
						}
					}
				}
			}
			entry, itemErr := resultItem(row, len(allItems))
			if itemErr != nil {
				continue
			}
			if _, exists := seen[entry.ItemKey]; exists {
				continue
			}
			seen[entry.ItemKey] = struct{}{}
			allItems = append(allItems, entry)
		}
		if assetType == "site" || assetType == "screenshot" {
			screenshotPayloads = append(screenshotPayloads, payload)
		}
		total, hasTotal := findResultTotal(payload, 0)
		if len(rows) == 0 || len(rows) < asmResultSyncPageSize || len(allItems) == beforeCount || (hasTotal && len(allItems) >= total) {
			break
		}
	}
	if err := s.db.ReplaceASMResultItems(item.ID, assetType, allItems); err != nil {
		s.markResultSync(item.ID, assetType, "failed", len(allItems), &started, nil, err)
		return len(allItems), err
	}
	now := time.Now().UTC()
	s.markResultSync(item.ID, assetType, "completed", len(allItems), &started, &now, nil)
	if len(screenshotPayloads) > 0 {
		s.enqueueTaskScreenshotCache(item.ID, screenshotPayloads)
	}
	return len(allItems), nil
}

func (s *Service) syncTaskResults(ctx context.Context, id string) (ResultSyncView, error) {
	item, err := s.db.GetASMTask(id)
	if err != nil {
		return ResultSyncView{}, err
	}
	var errors []string
	for _, resultType := range providerResultTypes(item.Provider) {
		if _, syncErr := s.syncTaskResultType(ctx, item, resultType.ID); syncErr != nil {
			errors = append(errors, resultType.ID+": "+truncateError(syncErr))
		}
	}
	view := s.resultSyncView(item)
	if len(errors) > 0 {
		return view, fmt.Errorf("ASM 结果同步部分失败: %s", strings.Join(errors, "; "))
	}
	return view, nil
}

func (s *Service) SyncTaskResults(ctx context.Context, id string) (ResultSyncView, error) {
	select {
	case s.resultSyncSem <- struct{}{}:
		defer func() { <-s.resultSyncSem }()
	case <-ctx.Done():
		return ResultSyncView{}, ctx.Err()
	}
	return s.syncTaskResults(ctx, id)
}

func (s *Service) RequestTaskResultsSync(id string) (ResultSyncView, error) {
	item, err := s.db.GetASMTask(id)
	if err != nil {
		return ResultSyncView{}, err
	}
	s.queueTaskResultSync(item.ID, true)
	return s.resultSyncView(item), nil
}

func (s *Service) enqueueTaskResultSync(id string) {
	s.queueTaskResultSync(id, false)
}

func (s *Service) markTaskResultsPending(item *database.ASMTask) {
	existing, err := s.db.ListASMResultSyncStates(item.ID)
	if err != nil {
		s.logger.Warn("标记 ASM 结果同步排队状态失败", zap.String("task_id", item.ID), zap.Error(err))
		return
	}
	byType := make(map[string]database.ASMResultSyncState, len(existing))
	for _, state := range existing {
		byType[state.AssetType] = state
	}
	for _, resultType := range providerResultTypes(item.Provider) {
		state := byType[resultType.ID]
		state.TaskID = item.ID
		state.AssetType = resultType.ID
		state.Status = "pending"
		state.LastError = ""
		if err := s.db.UpsertASMResultSyncState(state); err != nil {
			s.logger.Warn("标记 ASM 结果同步排队状态失败", zap.String("task_id", item.ID), zap.String("asset_type", resultType.ID), zap.Error(err))
		}
	}
}

func (s *Service) queueTaskResultSync(id string, markPending bool) {
	s.resultSyncMu.Lock()
	if s.resultSyncJobs[id] {
		s.resultSyncMu.Unlock()
		return
	}
	s.resultSyncJobs[id] = true
	s.resultSyncMu.Unlock()
	if markPending {
		if item, err := s.db.GetASMTask(id); err == nil {
			s.markTaskResultsPending(item)
		}
	}
	go func() {
		defer func() { s.resultSyncMu.Lock(); delete(s.resultSyncJobs, id); s.resultSyncMu.Unlock() }()
		ctx, cancel := context.WithTimeout(s.workerCtx, 30*time.Minute)
		defer cancel()
		if _, err := s.SyncTaskResults(ctx, id); err != nil {
			s.logger.Warn("自动同步 ASM 任务结果失败", zap.String("task_id", id), zap.Error(err))
		}
	}()
}

func (s *Service) StartResultSyncWorker(ctx context.Context, interval time.Duration) {
	if interval < 10*time.Second {
		interval = 30 * time.Second
	}
	s.workerCtx = ctx
	// A process restart means no previous in-memory Agent runner can still own a
	// persisted "running" continuation; make those rows retryable immediately.
	_ = s.db.RecoverStaleASMAgentContinuations(time.Now().UTC().Add(time.Minute))
	go func() {
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				s.reconcileTaskResults(ctx)
				timer.Reset(interval)
			}
		}
	}()
}

func (s *Service) reconcileTaskResults(ctx context.Context) {
	for _, status := range []string{"submitted", "running"} {
		items, _, err := s.db.ListASMTasks(database.ASMTaskFilter{Status: status, Page: 1, PageSize: 100})
		if err != nil {
			continue
		}
		for _, item := range items {
			if ctx.Err() != nil {
				return
			}
			if _, err := s.SyncTaskHistory(ctx, item.ID); err != nil {
				s.logger.Debug("同步 ASM 任务进度失败", zap.String("task_id", item.ID), zap.Error(err))
			}
		}
	}
	items, _, err := s.db.ListASMTasks(database.ASMTaskFilter{Status: "completed", Page: 1, PageSize: 100})
	if err != nil {
		return
	}
	for _, item := range items {
		if s.resultSyncView(item).Status != "completed" {
			s.enqueueTaskResultSync(item.ID)
		}
	}
	s.reconcileAgentContinuations(ctx)
}
