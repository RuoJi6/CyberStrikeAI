package handler

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/boundary"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const maxBoundarySimulationResolvedIPs = 64

// BoundaryPolicyHandler exposes the boundary policy control-plane APIs.
type BoundaryPolicyHandler struct {
	db     *database.DB
	logger *zap.Logger
}

type boundaryPolicySummary struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Description          string    `json:"description"`
	DefaultAction        string    `json:"defaultAction"`
	TLSInspectionEnabled bool      `json:"tlsInspectionEnabled"`
	RuleCount            int       `json:"ruleCount"`
	Protocols            []string  `json:"protocols"`
	UsageCount           int       `json:"usageCount"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

type boundaryPolicyDetail struct {
	ID                   string                        `json:"id"`
	Name                 string                        `json:"name"`
	Description          string                        `json:"description"`
	DefaultAction        string                        `json:"defaultAction"`
	TLSInspectionEnabled bool                          `json:"tlsInspectionEnabled"`
	TLSBypassDomains     []string                      `json:"tlsBypassDomains"`
	UpdatedAt            time.Time                     `json:"updatedAt"`
	Rules                []database.BoundaryPolicyRule `json:"rules"`
}

type boundaryPolicyWriteRequest struct {
	Name             string   `json:"name" binding:"required"`
	Description      string   `json:"description"`
	DefaultAction    string   `json:"defaultAction"`
	TLSBypassDomains []string `json:"tlsBypassDomains"`
}

type boundaryRuleWriteRequest struct {
	Effect        boundary.Effect            `json:"effect" binding:"required"`
	Host          string                     `json:"host"`
	Schemes       []string                   `json:"schemes"`
	Ports         []int                      `json:"ports"`
	PathPrefixes  []string                   `json:"pathPrefixes"`
	Methods       []string                   `json:"methods"`
	AuthProfileID *string                    `json:"authProfileId"`
	RateLimit     database.BoundaryRateLimit `json:"rateLimit"`
	ExpiresAt     *time.Time                 `json:"expiresAt"`
	Position      int                        `json:"position"`
}

func NewBoundaryPolicyHandler(db *database.DB, logger *zap.Logger) *BoundaryPolicyHandler {
	return &BoundaryPolicyHandler{db: db, logger: logger}
}

// List GET /api/boundary-policies returns the safe policy summaries available
// to the authenticated user. Rules and owner identifiers are intentionally not
// included in the conversation-creation picker response.
func (h *BoundaryPolicyHandler) List(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	if !session.Permissions["boundary:read"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "缺少 boundary:read 权限"})
		return
	}
	policies, err := h.db.ListBoundaryPolicies(c.Request.Context(), session.UserID, session.ScopeFor("boundary:read"))
	if err != nil {
		h.logger.Error("列出边界策略失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取边界策略"})
		return
	}
	search := strings.ToLower(strings.TrimSpace(c.Query("search")))
	filtered := make([]database.BoundaryPolicy, 0, len(policies))
	for _, policy := range policies {
		if search != "" && !strings.Contains(strings.ToLower(policy.Name), search) && !strings.Contains(strings.ToLower(policy.Description), search) {
			continue
		}
		filtered = append(filtered, policy)
	}
	page := 1
	if raw := strings.TrimSpace(c.Query("page")); raw != "" {
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "page 必须为正整数"})
			return
		}
		page = value
	}
	pageSize := 100
	if raw := strings.TrimSpace(c.Query("page_size")); raw != "" {
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value < 1 || value > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "page_size 必须在 1 到 100 之间"})
			return
		}
		pageSize = value
	}
	total := len(filtered)
	totalPages := 0
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	items := make([]boundaryPolicySummary, 0, end-start)
	for _, policy := range filtered[start:end] {
		rules, ruleErr := h.db.ListBoundaryPolicyRules(c.Request.Context(), policy.ID)
		if ruleErr != nil {
			h.logger.Error("统计边界策略规则失败", zap.String("policy_id", policy.ID), zap.Error(ruleErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取边界策略"})
			return
		}
		protocolSet := make(map[string]struct{})
		for _, rule := range rules {
			if len(rule.Schemes) == 0 {
				protocolSet["any"] = struct{}{}
			}
			for _, protocol := range rule.Schemes {
				protocolSet[strings.ToLower(strings.TrimSpace(protocol))] = struct{}{}
			}
		}
		protocols := make([]string, 0, len(protocolSet))
		for protocol := range protocolSet {
			if protocol != "" {
				protocols = append(protocols, protocol)
			}
		}
		sort.Strings(protocols)
		usageCount := 0
		if session.Permissions["chat:read"] {
			usage, usageErr := h.db.ListBoundaryPolicyUsage(c.Request.Context(), policy.ID, session.UserID, session.ScopeFor("chat:read"))
			if usageErr != nil {
				h.logger.Error("统计边界策略使用关系失败", zap.String("policy_id", policy.ID), zap.Error(usageErr))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取边界策略"})
				return
			}
			usageCount = len(usage)
		}
		items = append(items, boundaryPolicySummary{
			ID: policy.ID, Name: policy.Name, Description: policy.Description,
			DefaultAction:        policy.DefaultAction,
			TLSInspectionEnabled: policy.TLSInspectionEnabled, RuleCount: len(rules),
			Protocols: protocols, UsageCount: usageCount, UpdatedAt: policy.UpdatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"items": items, "page": page, "pageSize": pageSize, "total": total,
		"totalPages": totalPages, "search": strings.TrimSpace(c.Query("search")),
	})
}

// Usage returns RBAC-filtered conversations and containers currently using a
// policy. Historical snapshots are intentionally excluded.
func (h *BoundaryPolicyHandler) Usage(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	if !session.Permissions["chat:read"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "缺少 chat:read 权限"})
		return
	}
	policyID := strings.TrimSpace(c.Param("id"))
	if _, err := h.db.GetBoundaryPolicy(c.Request.Context(), policyID); errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "边界策略不存在"})
		return
	} else if err != nil {
		writeBoundaryPolicyStorageError(c, h.logger, "读取边界策略失败", err)
		return
	}
	items, err := h.db.ListBoundaryPolicyUsage(c.Request.Context(), policyID, session.UserID, session.ScopeFor("chat:read"))
	if err != nil {
		writeBoundaryPolicyStorageError(c, h.logger, "读取边界策略使用关系失败", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}

// Get returns one editable source draft with its current rules. It never
// returns immutable snapshot data or another user's policy outside RBAC scope.
func (h *BoundaryPolicyHandler) Get(c *gin.Context) {
	policy, err := h.db.GetBoundaryPolicy(c.Request.Context(), strings.TrimSpace(c.Param("id")))
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "边界策略不存在"})
		return
	}
	if err != nil {
		h.logger.Error("读取边界策略失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取边界策略"})
		return
	}
	rules, err := h.db.ListBoundaryPolicyRules(c.Request.Context(), policy.ID)
	if err != nil {
		h.logger.Error("读取边界规则失败", zap.String("policy_id", policy.ID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取边界规则"})
		return
	}
	c.JSON(http.StatusOK, boundaryPolicyDetail{
		ID: policy.ID, Name: policy.Name, Description: policy.Description,
		DefaultAction:        policy.DefaultAction,
		TLSInspectionEnabled: policy.TLSInspectionEnabled, TLSBypassDomains: policy.TLSBypassDomains,
		UpdatedAt: policy.UpdatedAt, Rules: rules,
	})
}

func (h *BoundaryPolicyHandler) Create(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	var request boundaryPolicyWriteRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "边界策略名称不能为空"})
		return
	}
	created, err := h.db.CreateBoundaryPolicy(c.Request.Context(), database.BoundaryPolicy{
		Name: request.Name, Description: request.Description, OwnerUserID: session.UserID,
		DefaultAction:        request.DefaultAction,
		TLSInspectionEnabled: true, TLSBypassDomains: request.TLSBypassDomains,
	})
	if err != nil {
		writeBoundaryPolicyStorageError(c, h.logger, "创建边界策略失败", err)
		return
	}
	c.JSON(http.StatusCreated, boundaryPolicyDetail{
		ID: created.ID, Name: created.Name, Description: created.Description,
		DefaultAction:        created.DefaultAction,
		TLSInspectionEnabled: created.TLSInspectionEnabled, TLSBypassDomains: created.TLSBypassDomains,
		UpdatedAt: created.UpdatedAt, Rules: []database.BoundaryPolicyRule{},
	})
}

func (h *BoundaryPolicyHandler) Update(c *gin.Context) {
	var request boundaryPolicyWriteRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "边界策略名称不能为空"})
		return
	}
	updated, err := h.db.UpdateBoundaryPolicy(c.Request.Context(), database.BoundaryPolicy{
		ID: strings.TrimSpace(c.Param("id")), Name: request.Name, Description: request.Description,
		DefaultAction:        request.DefaultAction,
		TLSInspectionEnabled: true, TLSBypassDomains: request.TLSBypassDomains,
	})
	if errors.Is(err, database.ErrBoundaryPolicyNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "边界策略不存在"})
		return
	}
	if err != nil {
		writeBoundaryPolicyStorageError(c, h.logger, "更新边界策略失败", err)
		return
	}
	rules, err := h.db.ListBoundaryPolicyRules(c.Request.Context(), updated.ID)
	if err != nil {
		writeBoundaryPolicyStorageError(c, h.logger, "读取更新后的边界规则失败", err)
		return
	}
	c.JSON(http.StatusOK, boundaryPolicyDetail{
		ID: updated.ID, Name: updated.Name, Description: updated.Description,
		DefaultAction:        updated.DefaultAction,
		TLSInspectionEnabled: updated.TLSInspectionEnabled, TLSBypassDomains: updated.TLSBypassDomains,
		UpdatedAt: updated.UpdatedAt, Rules: rules,
	})
}

func (h *BoundaryPolicyHandler) Delete(c *gin.Context) {
	err := h.db.DeleteBoundaryPolicy(c.Request.Context(), strings.TrimSpace(c.Param("id")))
	switch {
	case errors.Is(err, database.ErrBoundaryPolicyNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "边界策略不存在"})
	case errors.Is(err, database.ErrBoundaryPolicyInUse):
		c.JSON(http.StatusConflict, gin.H{"error": "边界策略仍被对话选择，请先切换相关对话策略"})
	case err != nil:
		writeBoundaryPolicyStorageError(c, h.logger, "删除边界策略失败", err)
	default:
		c.Status(http.StatusNoContent)
	}
}

func boundaryRuleFromRequest(policyID, ruleID string, request boundaryRuleWriteRequest) database.BoundaryPolicyRule {
	return database.BoundaryPolicyRule{
		ID: strings.TrimSpace(ruleID), PolicyID: strings.TrimSpace(policyID), Effect: request.Effect,
		Host: request.Host, Schemes: request.Schemes, Ports: request.Ports,
		PathPrefixes: request.PathPrefixes, Methods: request.Methods,
		AuthProfileID: request.AuthProfileID, RateLimit: request.RateLimit,
		ExpiresAt: request.ExpiresAt, Position: request.Position,
	}
}

func (h *BoundaryPolicyHandler) CreateRule(c *gin.Context) {
	var request boundaryRuleWriteRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "边界规则请求格式无效"})
		return
	}
	if _, err := h.db.GetBoundaryPolicy(c.Request.Context(), strings.TrimSpace(c.Param("id"))); errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "边界策略不存在"})
		return
	} else if err != nil {
		writeBoundaryPolicyStorageError(c, h.logger, "读取边界策略失败", err)
		return
	}
	created, err := h.db.CreateBoundaryPolicyRule(c.Request.Context(), boundaryRuleFromRequest(c.Param("id"), "", request))
	if err != nil {
		writeBoundaryPolicyStorageError(c, h.logger, "创建边界规则失败", err)
		return
	}
	c.JSON(http.StatusCreated, created)
}

func (h *BoundaryPolicyHandler) UpdateRule(c *gin.Context) {
	var request boundaryRuleWriteRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "边界规则请求格式无效"})
		return
	}
	updated, err := h.db.UpdateBoundaryPolicyRule(c.Request.Context(), boundaryRuleFromRequest(c.Param("id"), c.Param("ruleId"), request))
	if errors.Is(err, database.ErrBoundaryRuleNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "边界规则不存在"})
		return
	}
	if err != nil {
		writeBoundaryPolicyStorageError(c, h.logger, "更新边界规则失败", err)
		return
	}
	c.JSON(http.StatusOK, updated)
}

func (h *BoundaryPolicyHandler) DeleteRule(c *gin.Context) {
	err := h.db.DeleteBoundaryPolicyRule(c.Request.Context(), c.Param("id"), c.Param("ruleId"))
	if errors.Is(err, database.ErrBoundaryRuleNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "边界规则不存在"})
		return
	}
	if err != nil {
		writeBoundaryPolicyStorageError(c, h.logger, "删除边界规则失败", err)
		return
	}
	c.Status(http.StatusNoContent)
}

func writeBoundaryPolicyStorageError(c *gin.Context, logger *zap.Logger, message string, err error) {
	logger.Error(message, zap.Error(err))
	status := http.StatusBadRequest
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, gin.H{"error": err.Error()})
}

// GetConversationSnapshot GET /api/conversations/:id/boundary returns the
// immutable document actually bound to a conversation, never the editable
// source policy draft.
func (h *BoundaryPolicyHandler) GetConversationSnapshot(c *gin.Context) {
	conversationID := strings.TrimSpace(c.Param("id"))
	session, ok := security.CurrentSession(c)
	if !ok || !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("chat:read"), "conversation", conversationID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该对话"})
		return
	}
	if _, err := h.db.GetConversationLite(conversationID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}
	snapshot, err := h.db.GetConversationBoundarySnapshot(c.Request.Context(), conversationID)
	if errors.Is(err, database.ErrConversationBoundarySnapshotNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "该对话尚未绑定边界快照"})
		return
	}
	if err != nil {
		h.logger.Error("读取对话边界快照失败", zap.String("conversation_id", conversationID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "边界快照不可读"})
		return
	}
	c.JSON(http.StatusOK, snapshot)
}

type simulateBoundaryPolicyRequest struct {
	URL         string   `json:"url" binding:"required"`
	Method      string   `json:"method"`
	ResolvedIPs []string `json:"resolvedIps"`
}

type simulateBoundaryPolicyResponse struct {
	PolicyID      string                 `json:"policyId"`
	Allowed       bool                   `json:"allowed"`
	Effect        boundary.Effect        `json:"effect,omitempty"`
	MatchedRuleID string                 `json:"matchedRuleId,omitempty"`
	Reason        string                 `json:"reason"`
	Target        boundary.RequestTarget `json:"target"`
}

// SimulatePolicy POST /api/boundary-policies/:id/simulate evaluates a draft
// without changing it or opening container networking. resolvedIps are supplied
// explicitly so simulation never performs DNS or makes an outbound request.
func (h *BoundaryPolicyHandler) SimulatePolicy(c *gin.Context) {
	var req simulateBoundaryPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.ResolvedIPs) > maxBoundarySimulationResolvedIPs {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resolvedIps must contain at most 64 addresses"})
		return
	}
	resolvedIPs := make([]netip.Addr, 0, len(req.ResolvedIPs))
	for _, raw := range req.ResolvedIPs {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || address.Zone() != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "resolvedIps contains an invalid IP address"})
			return
		}
		resolvedIPs = append(resolvedIPs, address.Unmap())
	}

	policyID := strings.TrimSpace(c.Param("id"))
	if policyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "boundary policy id is required"})
		return
	}
	storedPolicy, err := h.db.GetBoundaryPolicy(c.Request.Context(), policyID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "boundary policy not found"})
			return
		}
		h.logger.Error("读取边界策略失败", zap.String("policy_id", policyID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load boundary policy"})
		return
	}
	dbRules, err := h.db.ListBoundaryPolicyRules(c.Request.Context(), policyID)
	if err != nil {
		h.logger.Error("读取边界规则失败", zap.String("policy_id", policyID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load boundary policy rules"})
		return
	}
	rules := make([]boundary.Rule, 0, len(dbRules))
	for _, stored := range dbRules {
		authProfileID := ""
		if stored.AuthProfileID != nil {
			authProfileID = *stored.AuthProfileID
		}
		rules = append(rules, boundary.Rule{
			ID:     stored.ID,
			Effect: stored.Effect,
			Target: boundary.RuleTarget{
				Host:         stored.Host,
				Schemes:      stored.Schemes,
				Ports:        stored.Ports,
				PathPrefixes: stored.PathPrefixes,
				Methods:      stored.Methods,
			},
			AuthProfileID: authProfileID,
			RateLimit: boundary.RateLimit{
				RequestsPerSecond: stored.RateLimit.RequestsPerSecond,
				Burst:             stored.RateLimit.Burst, MaxConcurrent: stored.RateLimit.MaxConcurrent,
			},
			ExpiresAt: stored.ExpiresAt,
		})
	}
	compiled, err := boundary.NewPolicyWithDefault(rules, storedPolicy.DefaultAction == database.BoundaryDefaultActionAllow)
	if err != nil {
		h.logger.Error("编译边界策略失败", zap.String("policy_id", policyID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "boundary policy is invalid"})
		return
	}
	decision, err := compiled.Evaluate(req.URL, req.Method, resolvedIPs, time.Now().UTC())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, simulateBoundaryPolicyResponse{
		PolicyID:      policyID,
		Allowed:       decision.Allowed,
		Effect:        decision.Effect,
		MatchedRuleID: decision.RuleID,
		Reason:        decision.Reason,
		Target:        decision.Target,
	})
}
