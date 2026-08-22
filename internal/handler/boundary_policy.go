package handler

import (
	"database/sql"
	"errors"
	"net/http"
	"net/netip"
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
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	UpdatedAt   time.Time `json:"updatedAt"`
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
	items := make([]boundaryPolicySummary, 0, len(policies))
	for _, policy := range policies {
		items = append(items, boundaryPolicySummary{
			ID: policy.ID, Name: policy.Name, Description: policy.Description, UpdatedAt: policy.UpdatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
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
	if _, err := h.db.GetBoundaryPolicy(c.Request.Context(), policyID); err != nil {
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
			ExpiresAt:     stored.ExpiresAt,
		})
	}
	compiled, err := boundary.NewPolicy(rules)
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
