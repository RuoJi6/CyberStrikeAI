package handler

import (
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffic"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type TrafficHandler struct {
	db     *database.DB
	logger *zap.Logger
}

func NewTrafficHandler(db *database.DB, logger *zap.Logger) *TrafficHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &TrafficHandler{db: db, logger: logger}
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
		RuntimeMode: strings.TrimSpace(c.Query("runtime_mode")), Scheme: strings.TrimSpace(c.Query("scheme")),
		Host: strings.ToLower(strings.TrimSpace(c.Query("host"))), Method: strings.TrimSpace(c.Query("method")), Search: search,
		UserID: session.UserID, Scope: session.ScopeFor("traffic:read"), Limit: pageSize, Offset: (page - 1) * pageSize,
	}
	items, total, err := h.db.ListTrafficTransactions(c.Request.Context(), filter)
	if err != nil {
		h.logger.Warn("读取流量事务失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取流量事务"})
		return
	}
	totalPages := 0
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "page": page, "page_size": pageSize, "total_pages": totalPages})
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
		for headerIndex := range detail.Messages[index].Headers {
			switch strings.ToLower(detail.Messages[index].Headers[headerIndex].Name) {
			case "authorization", "proxy-authorization", "cookie", "set-cookie":
				detail.Messages[index].Headers[headerIndex].Value = "[REDACTED]"
			}
		}
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
	if !session.Permissions["traffic:read_sensitive"] {
		redactTrafficDetail(detail)
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"transaction": detail.Transaction, "messages": detail.Messages, "evidence": detail.Evidence, "untrustedContent": true})
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
