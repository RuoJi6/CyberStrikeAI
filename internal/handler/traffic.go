package handler

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffic"
	"cyberstrike-ai/internal/traffictransform"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type TrafficHandler struct {
	db              *database.DB
	logger          *zap.Logger
	replayExecutor  TrafficReplayExecutor
	transformRunner TrafficTransformRunner
}

type TrafficReplayExecutor func(context.Context, string, security.ExecutionRequest) (security.ExecutionResult, error)

type TrafficTransformRunner interface {
	traffictransform.Client
	traffictransform.RevisionLoader
}

func NewTrafficHandler(db *database.DB, logger *zap.Logger) *TrafficHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &TrafficHandler{db: db, logger: logger}
}

func (h *TrafficHandler) SetTrafficReplayExecutor(executor TrafficReplayExecutor) {
	h.replayExecutor = executor
}

func (h *TrafficHandler) SetTrafficTransformRunner(runner TrafficTransformRunner) {
	h.transformRunner = runner
}

func trafficPage(c *gin.Context) (int, int, bool) {
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "page 必须为正整数"})
		return 0, 0, false
	}
	pageSize, err := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if err != nil || pageSize < 1 || pageSize > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "page_size 必须在 1 到 100 之间"})
		return 0, 0, false
	}
	return page, pageSize, true
}

func (h *TrafficHandler) List(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	page, pageSize, ok := trafficPage(c)
	if !ok {
		return
	}
	search := strings.TrimSpace(c.Query("q"))
	if len(search) > 200 || !utf8.ValidString(search) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "q 最多 200 个字节"})
		return
	}
	filter := database.TrafficTransactionFilter{
		ID: strings.TrimSpace(c.Query("id")), ConversationID: strings.TrimSpace(c.Query("conversation_id")),
		ProjectID: strings.TrimSpace(c.Query("project_id")), ExecutionID: strings.TrimSpace(c.Query("execution_id")),
		AgentID: strings.TrimSpace(c.Query("agent")), ToolName: strings.TrimSpace(c.Query("tool")),
		AttributionStatus: strings.TrimSpace(c.Query("attribution_status")),
		RuntimeMode:       strings.TrimSpace(c.Query("runtime_mode")), Scheme: strings.TrimSpace(c.Query("scheme")),
		Host: strings.ToLower(strings.TrimSpace(c.Query("host"))), Method: strings.TrimSpace(c.Query("method")), Search: search,
		UserID: session.UserID, Scope: session.ScopeFor("traffic:read"), Limit: pageSize, Offset: (page - 1) * pageSize,
	}
	items, total, err := h.db.ListTrafficTransactions(c.Request.Context(), filter)
	if err != nil {
		h.logger.Warn("读取流量事务失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取流量事务"})
		return
	}
	for index := range items {
		decorateReplayTransformTransaction(&items[index])
	}
	totalPages := 0
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "page": page, "page_size": pageSize, "total_pages": totalPages})
}

// Conversations returns the safe, scoped options used by the traffic evidence
// conversation picker. It is separate from the paged transaction projection so
// changing filters never makes options disappear.
func (h *TrafficHandler) Conversations(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	conversations, err := h.db.ListTrafficTransactionConversations(c.Request.Context(), session.UserID, session.ScopeFor("traffic:read"))
	if err != nil {
		h.logger.Warn("读取流量证据对话失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取流量证据对话"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"conversations": conversations})
}

func decorateReplayTransformTransaction(item *traffic.Transaction) {
	if item == nil || !strings.HasPrefix(item.ExecutionID, trafficReplayTransformAttributionPrefix) {
		return
	}
	parts := strings.Split(strings.TrimPrefix(item.ExecutionID, trafficReplayTransformAttributionPrefix), ":")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return
	}
	if item.TransformBindingID == "" {
		item.TransformBindingID = parts[0]
	}
	if item.TransformRevisionID == "" {
		item.TransformRevisionID = parts[1]
	}
	if item.TransformResult == "" {
		item.TransformResult = "replay_applied"
	}
}

func (h *TrafficHandler) canAccess(session security.Session, detail *traffic.TransactionDetail, permission string) bool {
	if detail == nil {
		return false
	}
	scope := session.ScopeFor(permission)
	if scope == database.RBACScopeAll {
		return true
	}
	if detail.Transaction.ProjectID != "" && h.db.UserCanAccessResource(session.UserID, scope, "project", detail.Transaction.ProjectID) {
		return true
	}
	return detail.Transaction.ConversationID != "" && h.db.UserCanAccessResource(session.UserID, scope, "conversation", detail.Transaction.ConversationID)
}

func redactTrafficDetail(detail *traffic.TransactionDetail) {
	if detail == nil {
		return
	}
	for index := range detail.Messages {
		detail.Messages[index].Body = ""
		detail.Messages[index].BodyEncoding = ""
		detail.Messages[index].BodyView = nil
		for headerIndex := range detail.Messages[index].Headers {
			switch strings.ToLower(detail.Messages[index].Headers[headerIndex].Name) {
			case "authorization", "proxy-authorization", "cookie", "set-cookie":
				detail.Messages[index].Headers[headerIndex].Value = "[REDACTED]"
			}
		}
	}
}

func attachTrafficBodyViews(detail *traffic.TransactionDetail) {
	if detail == nil {
		return
	}
	for index := range detail.Messages {
		view, err := traffic.BuildMessageBodyView(detail.Messages[index])
		if err != nil {
			continue
		}
		detail.Messages[index].BodyView = &view
	}
}

func (h *TrafficHandler) Get(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	detail, err := h.db.GetTrafficTransaction(c.Request.Context(), c.Param("id"))
	if err != nil || !h.canAccess(session, detail, "traffic:read") {
		c.JSON(http.StatusNotFound, gin.H{"error": "流量事务不存在"})
		return
	}
	decorateReplayTransformTransaction(&detail.Transaction)
	if session.Permissions["traffic:read_sensitive"] {
		attachTrafficBodyViews(detail)
	} else {
		redactTrafficDetail(detail)
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"transaction": detail.Transaction, "messages": detail.Messages, "evidence": detail.Evidence, "untrustedContent": true})
}

type trafficTransformDashboardScript struct {
	Transform          traffictransform.Transform `json:"transform"`
	LatestRevision     *traffictransform.Revision `json:"latestRevision,omitempty"`
	BindingCount       int                        `json:"bindingCount"`
	ActiveBindingCount int                        `json:"activeBindingCount"`
}

type trafficTransformDashboardBinding struct {
	ID                string                   `json:"id"`
	ConversationID    string                   `json:"conversationId"`
	ConversationTitle string                   `json:"conversationTitle"`
	RuntimeMode       string                   `json:"runtimeMode"`
	TransformID       string                   `json:"transformId"`
	TransformName     string                   `json:"transformName"`
	RevisionID        string                   `json:"revisionId"`
	Mode              string                   `json:"mode"`
	Matcher           traffictransform.Matcher `json:"matcher"`
	Priority          int                      `json:"priority"`
	FailurePolicy     string                   `json:"failurePolicy"`
	Status            string                   `json:"status"`
	UpdatedAt         time.Time                `json:"updatedAt"`
}

type trafficTransformDashboardConversation struct {
	ID             string                     `json:"id"`
	Title          string                     `json:"title"`
	RuntimeMode    string                     `json:"runtimeMode"`
	BindingCount   int                        `json:"bindingCount"`
	ActiveCount    int                        `json:"activeCount"`
	TransformNames []string                   `json:"transformNames"`
	Matchers       []traffictransform.Matcher `json:"matchers"`
	UpdatedAt      time.Time                  `json:"updatedAt"`
}

func (h *TrafficHandler) canAccessTransform(session security.Session, item *traffictransform.Transform, permission string) bool {
	if item == nil {
		return false
	}
	scope := session.ScopeFor(permission)
	if scope == database.RBACScopeAll {
		return true
	}
	if item.ProjectID != "" && h.db.UserCanAccessResource(session.UserID, scope, "project", item.ProjectID) {
		return true
	}
	return item.ConversationID != "" && h.db.UserCanAccessResource(session.UserID, scope, "conversation", item.ConversationID)
}

// ListTrafficTransformsDashboard returns the safe management projections for
// scripts, matcher bindings, Runner history, and injected conversations.
// Source, message bodies, hashes, and binding config are deliberately omitted.
func (h *TrafficHandler) ListTrafficTransformsDashboard(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	ctx := c.Request.Context()
	transforms, err := h.db.ListTrafficTransforms(ctx, 500)
	if err != nil {
		h.logger.Warn("读取 Traffic Transform 列表失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取加解密脚本"})
		return
	}

	scripts := make([]trafficTransformDashboardScript, 0, len(transforms))
	scriptIndex := make(map[string]int, len(transforms))
	transformNames := make(map[string]string, len(transforms))
	for _, item := range transforms {
		if !h.canAccessTransform(session, &item, "traffic_transform:read") {
			continue
		}
		var latest *traffictransform.Revision
		if item.CurrentRevisionID != "" {
			current, getErr := h.db.GetTrafficTransformRevision(ctx, item.CurrentRevisionID)
			if getErr != nil {
				h.logger.Warn("读取 Traffic Transform 当前 revision 失败", zap.String("transform_id", item.ID), zap.Error(getErr))
				continue
			}
			copy := *current
			copy.Source = ""
			latest = &copy
		} else {
			revisions, listErr := h.db.ListTrafficTransformRevisions(ctx, item.ID, false)
			if listErr != nil {
				h.logger.Warn("读取 Traffic Transform revision 失败", zap.String("transform_id", item.ID), zap.Error(listErr))
				continue
			}
			if len(revisions) > 0 {
				copy := revisions[0]
				copy.Source = ""
				latest = &copy
			}
		}
		scriptIndex[item.ID] = len(scripts)
		transformNames[item.ID] = item.Name
		scripts = append(scripts, trafficTransformDashboardScript{Transform: item, LatestRevision: latest})
	}

	bindings, err := h.db.ListTrafficTransformBindings(ctx, 1000)
	if err != nil {
		h.logger.Warn("读取 Traffic Transform binding 失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取脚本使用范围"})
		return
	}
	type conversationMeta struct{ title, runtime string }
	conversationCache := map[string]conversationMeta{}
	dashboardBindings := make([]trafficTransformDashboardBinding, 0, len(bindings))
	conversationIndex := map[string]int{}
	dashboardConversations := make([]trafficTransformDashboardConversation, 0)
	conversationTransformSets := map[string]map[string]bool{}
	for _, binding := range bindings {
		if !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("traffic_transform:read"), "conversation", binding.ConversationID) {
			continue
		}
		name := transformNames[binding.TransformID]
		if name == "" {
			transform, getErr := h.db.GetTrafficTransform(ctx, binding.TransformID)
			if getErr != nil || !h.canAccessTransform(session, transform, "traffic_transform:read") {
				continue
			}
			name = transform.Name
			transformNames[binding.TransformID] = name
		}
		meta, found := conversationCache[binding.ConversationID]
		if !found {
			meta.title, _ = h.db.GetConversationTitle(binding.ConversationID)
			meta.runtime, _ = h.db.GetConversationRuntimeMode(binding.ConversationID)
			conversationCache[binding.ConversationID] = meta
		}
		dashboardBindings = append(dashboardBindings, trafficTransformDashboardBinding{
			ID: binding.ID, ConversationID: binding.ConversationID, ConversationTitle: meta.title,
			RuntimeMode: meta.runtime, TransformID: binding.TransformID, TransformName: name,
			RevisionID: binding.RevisionID, Mode: binding.Mode, Matcher: binding.Matcher,
			Priority: binding.Priority, FailurePolicy: binding.FailurePolicy, Status: binding.Status,
			UpdatedAt: binding.UpdatedAt,
		})
		if index, exists := scriptIndex[binding.TransformID]; exists {
			scripts[index].BindingCount++
			if binding.Status == traffictransform.BindingActive {
				scripts[index].ActiveBindingCount++
			}
		}
		index, exists := conversationIndex[binding.ConversationID]
		if !exists {
			index = len(dashboardConversations)
			conversationIndex[binding.ConversationID] = index
			conversationTransformSets[binding.ConversationID] = map[string]bool{}
			dashboardConversations = append(dashboardConversations, trafficTransformDashboardConversation{
				ID: binding.ConversationID, Title: meta.title, RuntimeMode: meta.runtime,
				UpdatedAt: binding.UpdatedAt,
			})
		}
		conversation := &dashboardConversations[index]
		conversation.BindingCount++
		if binding.Status == traffictransform.BindingActive {
			conversation.ActiveCount++
		}
		conversation.Matchers = append(conversation.Matchers, binding.Matcher)
		if binding.UpdatedAt.After(conversation.UpdatedAt) {
			conversation.UpdatedAt = binding.UpdatedAt
		}
		if !conversationTransformSets[binding.ConversationID][name] {
			conversationTransformSets[binding.ConversationID][name] = true
			conversation.TransformNames = append(conversation.TransformNames, name)
		}
	}
	sort.SliceStable(dashboardConversations, func(i, j int) bool {
		return dashboardConversations[i].UpdatedAt.After(dashboardConversations[j].UpdatedAt)
	})
	runSummaries, err := h.db.ListTrafficTransformRunSummaries(ctx, 1000)
	if err != nil {
		h.logger.Warn("读取 Traffic Transform Runner 记录失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取 Runner 记录"})
		return
	}
	dashboardRuns := make([]database.TrafficTransformRunSummary, 0, len(runSummaries))
	for _, run := range runSummaries {
		transform := &traffictransform.Transform{
			ID: run.TransformID, ConversationID: run.ConversationID, ProjectID: run.ProjectID,
		}
		if h.canAccessTransform(session, transform, "traffic_transform:read") {
			dashboardRuns = append(dashboardRuns, run)
		}
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"scripts": scripts, "cases": dashboardBindings, "conversations": dashboardConversations, "runs": dashboardRuns,
	})
}

// GetTrafficTransformRevisionSource is intentionally separate from the list
// endpoint so deployments can grant script-source access independently.
func (h *TrafficHandler) GetTrafficTransformRevisionSource(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	revision, err := h.db.GetTrafficTransformRevision(c.Request.Context(), strings.TrimSpace(c.Param("id")))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "脚本版本不存在"})
		return
	}
	transform, err := h.db.GetTrafficTransform(c.Request.Context(), revision.TransformID)
	if err != nil || !h.canAccessTransform(session, transform, "traffic_transform:read_source") {
		c.JSON(http.StatusNotFound, gin.H{"error": "脚本版本不存在"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"revision": revision, "transform": transform, "untrustedContent": true,
	})
}

type linkTrafficEvidenceRequest struct {
	TransactionID string `json:"traffic_transaction_id" binding:"required"`
	Role          string `json:"role"`
	Note          string `json:"note"`
}

func (h *TrafficHandler) ListVulnerabilityEvidence(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	vulnerabilityID := strings.TrimSpace(c.Param("id"))
	if !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("vulnerability:read"), "vulnerability", vulnerabilityID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "漏洞不存在"})
		return
	}
	links, err := h.db.ListTrafficEvidenceForVulnerability(c.Request.Context(), vulnerabilityID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取漏洞流量证据"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": links})
}

func (h *TrafficHandler) LinkVulnerabilityEvidence(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	vulnerabilityID := strings.TrimSpace(c.Param("id"))
	if !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("vulnerability:write"), "vulnerability", vulnerabilityID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "漏洞不存在"})
		return
	}
	var request linkTrafficEvidenceRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "流量证据请求无效"})
		return
	}
	detail, err := h.db.GetTrafficTransaction(c.Request.Context(), request.TransactionID)
	if err != nil || !h.canAccess(session, detail, "traffic:read") {
		c.JSON(http.StatusNotFound, gin.H{"error": "流量事务不存在"})
		return
	}
	if request.Role == "" {
		request.Role = traffic.EvidenceRoleSupporting
	}
	link, err := h.db.LinkVulnerabilityTrafficEvidence(c.Request.Context(), traffic.EvidenceLink{
		VulnerabilityID: vulnerabilityID, TransactionID: request.TransactionID,
		Role: request.Role, Note: request.Note,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, link)
}

func (h *TrafficHandler) UnlinkVulnerabilityEvidence(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	vulnerabilityID := strings.TrimSpace(c.Param("id"))
	if !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("vulnerability:write"), "vulnerability", vulnerabilityID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "漏洞不存在"})
		return
	}
	if err := h.db.UnlinkVulnerabilityTrafficEvidence(c.Request.Context(), vulnerabilityID, c.Param("transactionId")); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "漏洞流量证据不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}
