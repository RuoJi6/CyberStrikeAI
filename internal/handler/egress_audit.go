package handler

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
)

const maxEgressAuditExport = 5000

type EgressAuditHandler struct {
	db    *database.DB
	audit *audit.Service
}

func (h *EgressAuditHandler) SetAudit(service *audit.Service) { h.audit = service }

type deleteEgressAuditRequest struct {
	IDs []string `json:"ids"`
}

func (h *EgressAuditHandler) Delete(c *gin.Context) {
	setEgressAuditResponseHeaders(c)
	filter, _, _, ok := egressAuditFilterFromRequest(c)
	if !ok {
		return
	}
	var request deleteEgressAuditRequest
	if err := c.ShouldBindJSON(&request); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "删除请求必须是有效 JSON"})
		return
	}
	if len(request.IDs) == 0 && filter.ConversationID == "" && filter.Query == "" &&
		filter.Category == "all" && filter.EventType == "all" && filter.Decision == "all" && filter.Since == nil && filter.Until == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "删除筛选结果时至少需要一个筛选条件"})
		return
	}
	if _, err := h.db.VerifyEgressAuditIntegrity(c.Request.Context(), database.EgressAuditFilter{
		ConversationID: filter.ConversationID, UserID: filter.UserID, Scope: filter.Scope,
	}); err != nil {
		writeEgressAuditIntegrityError(c, err)
		return
	}
	deleted, err := h.db.PurgeEgressAuditEvents(c.Request.Context(), filter, request.IDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除出站审计事件失败"})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "audit", "egress-events-delete", "删除出站审计事件", "egress_audit_event", "", map[string]interface{}{
			"deleted": deleted, "selected": len(request.IDs), "conversation_id": filter.ConversationID,
			"category": filter.Category, "event_type": filter.EventType, "decision": filter.Decision,
		})
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted})
}

func NewEgressAuditHandler(db *database.DB) *EgressAuditHandler {
	return &EgressAuditHandler{db: db}
}

func (h *EgressAuditHandler) List(c *gin.Context) {
	setEgressAuditResponseHeaders(c)
	filter, page, pageSize, ok := egressAuditFilterFromRequest(c)
	if !ok {
		return
	}
	filter.Limit = pageSize
	filter.Offset = (page - 1) * pageSize
	integrity, err := h.db.VerifyEgressAuditIntegrity(c.Request.Context(), database.EgressAuditFilter{
		ConversationID: filter.ConversationID, UserID: filter.UserID, Scope: filter.Scope,
	})
	if err != nil {
		writeEgressAuditIntegrityError(c, err)
		return
	}
	items, err := h.db.ListEgressAuditEvents(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取出站审计事件"})
		return
	}
	total, err := h.db.CountEgressAuditEvents(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法统计出站审计事件"})
		return
	}
	summary, err := h.db.SummarizeEgressAuditEvents(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法汇总出站审计事件"})
		return
	}
	totalPages := 0
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	c.JSON(http.StatusOK, gin.H{
		"items": items, "total": total, "page": page, "pageSize": pageSize,
		"totalPages": totalPages, "summary": summary, "integrity": integrity,
	})
}

func (h *EgressAuditHandler) Get(c *gin.Context) {
	setEgressAuditResponseHeaders(c)
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	event, err := h.db.GetEgressAuditEvent(c.Request.Context(), c.Param("id"), session.UserID, session.Scope)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "出站审计事件不存在"})
		return
	}
	if _, err := h.db.VerifyEgressAuditIntegrity(c.Request.Context(), database.EgressAuditFilter{ConversationID: event.ConversationID, UserID: session.UserID, Scope: session.Scope}); err != nil {
		writeEgressAuditIntegrityError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"event": event})
}

func (h *EgressAuditHandler) Integrity(c *gin.Context) {
	setEgressAuditResponseHeaders(c)
	filter, _, _, ok := egressAuditFilterFromRequest(c)
	if !ok {
		return
	}
	integrity, err := h.db.VerifyEgressAuditIntegrity(c.Request.Context(), database.EgressAuditFilter{
		ConversationID: filter.ConversationID, UserID: filter.UserID, Scope: filter.Scope,
	})
	if err != nil {
		writeEgressAuditIntegrityError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"integrity": integrity})
}

func (h *EgressAuditHandler) Export(c *gin.Context) {
	setEgressAuditResponseHeaders(c)
	filter, _, _, ok := egressAuditFilterFromRequest(c)
	if !ok {
		return
	}
	format := strings.ToLower(strings.TrimSpace(c.DefaultQuery("format", "json")))
	if format != "json" && format != "csv" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "format 必须为 json 或 csv"})
		return
	}
	filter.Limit = maxEgressAuditExport
	filter.Offset = 0
	if _, err := h.db.VerifyEgressAuditIntegrity(c.Request.Context(), database.EgressAuditFilter{
		ConversationID: filter.ConversationID, UserID: filter.UserID, Scope: filter.Scope,
	}); err != nil {
		writeEgressAuditIntegrityError(c, err)
		return
	}
	items, err := h.db.ListEgressAuditEvents(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法导出出站审计事件"})
		return
	}
	if format == "csv" {
		writeEgressAuditCSV(c, items)
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="egress-audit-%s.json"`, time.Now().UTC().Format("20060102T150405Z")))
	c.JSON(http.StatusOK, gin.H{
		"exportedAt": time.Now().UTC().Format(time.RFC3339Nano),
		"count":      len(items),
		"events":     items,
	})
}

func writeEgressAuditIntegrityError(c *gin.Context, err error) {
	if errors.Is(err, database.ErrEgressAuditIntegrity) {
		c.JSON(http.StatusConflict, gin.H{"error": "出站审计完整性校验失败"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "无法校验出站审计完整性"})
}

func setEgressAuditResponseHeaders(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("X-Content-Type-Options", "nosniff")
}

func egressAuditFilterFromRequest(c *gin.Context) (database.EgressAuditFilter, int, int, bool) {
	filter := database.EgressAuditFilter{}
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return filter, 0, 0, false
	}
	filter.UserID = session.UserID
	filter.Scope = session.Scope
	filter.ConversationID = strings.TrimSpace(c.Query("conversation_id"))
	if len(filter.ConversationID) > 128 || !utf8.ValidString(filter.ConversationID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "conversation_id 无效"})
		return filter, 0, 0, false
	}
	filter.Query = strings.TrimSpace(c.Query("q"))
	if len(filter.Query) > 200 || !utf8.ValidString(filter.Query) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "q 最多 200 个字节"})
		return filter, 0, 0, false
	}
	category, valid := database.NormalizeEgressAuditCategory(c.Query("category"))
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category 无效"})
		return filter, 0, 0, false
	}
	eventType, valid := database.NormalizeEgressAuditEventType(c.Query("event_type"))
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "event_type 无效"})
		return filter, 0, 0, false
	}
	decision, valid := database.NormalizeEgressAuditDecision(c.Query("decision"))
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decision 无效"})
		return filter, 0, 0, false
	}
	filter.Category, filter.EventType, filter.Decision = category, eventType, decision
	if raw := strings.TrimSpace(c.Query("since")); raw != "" {
		value, err := database.ParseRFC3339Time(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "since 必须为 RFC3339 时间"})
			return filter, 0, 0, false
		}
		filter.Since = &value
	}
	if raw := strings.TrimSpace(c.Query("until")); raw != "" {
		value, err := database.ParseRFC3339Time(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "until 必须为 RFC3339 时间"})
			return filter, 0, 0, false
		}
		filter.Until = &value
	}
	if filter.Since != nil && filter.Until != nil && filter.Since.After(*filter.Until) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "since 不能晚于 until"})
		return filter, 0, 0, false
	}
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "page 必须为正整数"})
		return filter, 0, 0, false
	}
	pageSize, err := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if err != nil || (pageSize != 10 && pageSize != 20 && pageSize != 50 && pageSize != 100) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "page_size 必须为 10、20、50 或 100"})
		return filter, 0, 0, false
	}
	return filter, page, pageSize, true
}

func writeEgressAuditCSV(c *gin.Context, items []database.EgressAuditEvent) {
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="egress-audit-%s.csv"`, time.Now().UTC().Format("20060102T150405Z")))
	writer := csv.NewWriter(c.Writer)
	_ = writer.Write([]string{
		"id", "chain_sequence", "previous_hash", "event_hash", "occurred_at", "recorded_at", "category", "event_type", "conversation_id", "conversation_title",
		"container_id", "agent_id", "runtime_generation", "snapshot_id", "snapshot_sha256", "domain", "resolved_ips",
		"connected_ip", "port", "decision", "result", "rule_id", "reason", "upstream_route_id", "method", "path",
		"http_status", "outcome", "latency_ms", "bytes_up", "bytes_down", "lifecycle_operation", "lifecycle_state", "message",
	})
	for _, item := range items {
		row := []string{
			item.ID, strconv.FormatInt(item.ChainSequence, 10), item.PreviousHash, item.EventHash,
			item.OccurredAt.UTC().Format(time.RFC3339Nano), item.RecordedAt.UTC().Format(time.RFC3339Nano),
			item.Category, item.EventType, item.ConversationID, item.ConversationTitle, item.ContainerID,
			item.AgentID, strconv.Itoa(item.RuntimeGeneration), item.SnapshotID, item.SnapshotSHA256, item.Domain,
			strings.Join(item.ResolvedIPs, " "), item.ConnectedIP, strconv.Itoa(item.Port), item.Decision, item.Result,
			item.RuleID, item.Reason, item.UpstreamRouteID, item.Method, item.Path, strconv.Itoa(item.HTTPStatus), item.Outcome,
			strconv.FormatInt(item.LatencyMS, 10), strconv.FormatInt(item.BytesUp, 10), strconv.FormatInt(item.BytesDown, 10),
			item.LifecycleOperation, item.LifecycleState, item.Message,
		}
		for index := range row {
			row[index] = safeAuditCSVCell(row[index])
		}
		_ = writer.Write(row)
	}
	writer.Flush()
}

func safeAuditCSVCell(value string) string {
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	trimmed := strings.TrimLeftFunc(value, unicode.IsSpace)
	if trimmed != "" && strings.ContainsRune("=+-@", []rune(trimmed)[0]) {
		return "'" + value
	}
	return value
}
