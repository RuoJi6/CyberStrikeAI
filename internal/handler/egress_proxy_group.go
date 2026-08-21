package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type EgressProxyGroupHandler struct {
	db     *database.DB
	logger *zap.Logger
}

func NewEgressProxyGroupHandler(db *database.DB, logger *zap.Logger) *EgressProxyGroupHandler {
	return &EgressProxyGroupHandler{db: db, logger: logger}
}

type egressProxyGroupWriteRequest struct {
	Name             string          `json:"name"`
	Enabled          *bool           `json:"enabled,omitempty"`
	FailureThreshold *int            `json:"failureThreshold,omitempty"`
	CooldownSeconds  *int            `json:"cooldownSeconds,omitempty"`
	Members          json.RawMessage `json:"members,omitempty"`
}

type egressProxyGroupMemberWriteRequest struct {
	ProxyID  string `json:"proxyId"`
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
	Enabled  *bool  `json:"enabled,omitempty"`
}

func (h *EgressProxyGroupHandler) List(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	groups, err := h.db.ListEgressProxyGroups(c.Request.Context(), session.UserID, session.Scope)
	if err != nil {
		writeEgressProxyGroupStorageError(c, h.logger, "列出出站代理组失败", "", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": groups})
}

func (h *EgressProxyGroupHandler) Get(c *gin.Context) {
	group, err := h.db.GetEgressProxyGroup(c.Request.Context(), c.Param("id"))
	if errors.Is(err, database.ErrEgressProxyGroupNotFound) || errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "出站代理组不存在"})
		return
	}
	if err != nil {
		writeEgressProxyGroupStorageError(c, h.logger, "读取出站代理组失败", c.Param("id"), err)
		return
	}
	c.JSON(http.StatusOK, group)
}

func (h *EgressProxyGroupHandler) Create(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	var req egressProxyGroupWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "出站代理组请求格式无效"})
		return
	}
	group := database.EgressProxyGroup{
		ID: uuid.NewString(), Name: req.Name, Enabled: true,
		FailureThreshold: egress.DefaultProxyFailureCount,
		CooldownSeconds:  egress.DefaultProxyCooldownSecs,
		FailClosed:       true, OwnerUserID: session.UserID,
	}
	applyEgressProxyGroupOptions(&group, req)
	members, err := parseEgressProxyGroupMembers(req.Members, true, nil)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	group.Members = members
	if err := validateEgressProxyGroupRequest(group); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !h.membersAccessible(c.Request.Context(), session, group.Members) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "代理组成员不存在或不可访问"})
		return
	}
	created, err := h.db.CreateEgressProxyGroup(c.Request.Context(), group)
	if err != nil {
		writeEgressProxyGroupStorageError(c, h.logger, "创建出站代理组失败", "", err)
		return
	}
	c.JSON(http.StatusCreated, created)
}

func (h *EgressProxyGroupHandler) Update(c *gin.Context) {
	groupID := strings.TrimSpace(c.Param("id"))
	existing, err := h.db.GetEgressProxyGroup(c.Request.Context(), groupID)
	if errors.Is(err, database.ErrEgressProxyGroupNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "出站代理组不存在"})
		return
	}
	if err != nil {
		writeEgressProxyGroupStorageError(c, h.logger, "读取待更新出站代理组失败", groupID, err)
		return
	}
	var req egressProxyGroupWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "出站代理组请求格式无效"})
		return
	}
	existing.Name = req.Name
	applyEgressProxyGroupOptions(&existing, req)
	existing.Members, err = parseEgressProxyGroupMembers(req.Members, false, existing.Members)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateEgressProxyGroupRequest(existing); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	if !h.membersAccessible(c.Request.Context(), session, existing.Members) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "代理组成员不存在或不可访问"})
		return
	}
	updated, err := h.db.UpdateEgressProxyGroup(c.Request.Context(), existing)
	if errors.Is(err, database.ErrEgressProxyGroupNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "出站代理组不存在"})
		return
	}
	if err != nil {
		writeEgressProxyGroupStorageError(c, h.logger, "更新出站代理组失败", groupID, err)
		return
	}
	c.JSON(http.StatusOK, updated)
}

func (h *EgressProxyGroupHandler) Delete(c *gin.Context) {
	groupID := strings.TrimSpace(c.Param("id"))
	if err := h.db.DeleteEgressProxyGroup(c.Request.Context(), groupID); errors.Is(err, database.ErrEgressProxyGroupNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "出站代理组不存在"})
		return
	} else if err != nil {
		writeEgressProxyGroupStorageError(c, h.logger, "删除出站代理组失败", groupID, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func applyEgressProxyGroupOptions(group *database.EgressProxyGroup, req egressProxyGroupWriteRequest) {
	if req.Enabled != nil {
		group.Enabled = *req.Enabled
	}
	if req.FailureThreshold != nil {
		group.FailureThreshold = *req.FailureThreshold
	}
	if req.CooldownSeconds != nil {
		group.CooldownSeconds = *req.CooldownSeconds
	}
	group.FailClosed = true
}

func parseEgressProxyGroupMembers(raw json.RawMessage, required bool, existing []database.EgressProxyGroupMember) ([]database.EgressProxyGroupMember, error) {
	if len(raw) == 0 {
		if required {
			return nil, fmt.Errorf("proxy group members are required")
		}
		return existing, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("proxy group members must be an array")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input []egressProxyGroupMemberWriteRequest
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("proxy group members are invalid")
	}
	members := make([]database.EgressProxyGroupMember, 0, len(input))
	for _, item := range input {
		enabled := true
		if item.Enabled != nil {
			enabled = *item.Enabled
		}
		members = append(members, database.EgressProxyGroupMember{
			ProxyID: item.ProxyID, Priority: item.Priority, Weight: item.Weight, Enabled: enabled,
		})
	}
	return members, nil
}

func validateEgressProxyGroupRequest(group database.EgressProxyGroup) error {
	if _, err := egress.ValidateProxyGroupName(group.Name); err != nil {
		return err
	}
	if err := egress.ValidateProxyGroupFailureThreshold(group.FailureThreshold); err != nil {
		return err
	}
	if err := egress.ValidateProxyGroupCooldownSeconds(group.CooldownSeconds); err != nil {
		return err
	}
	if len(group.Members) < 1 || len(group.Members) > egress.MaxProxyGroupMembers {
		return fmt.Errorf("proxy group must contain between 1 and %d members", egress.MaxProxyGroupMembers)
	}
	seen := make(map[string]struct{}, len(group.Members))
	for _, member := range group.Members {
		proxyID := strings.TrimSpace(member.ProxyID)
		if proxyID == "" {
			return fmt.Errorf("proxy group member proxy id is required")
		}
		if _, ok := seen[proxyID]; ok {
			return fmt.Errorf("proxy group member is duplicated")
		}
		seen[proxyID] = struct{}{}
		if err := egress.ValidateProxyGroupMember(member.Priority, member.Weight); err != nil {
			return err
		}
	}
	return nil
}

func (h *EgressProxyGroupHandler) membersAccessible(ctx context.Context, session security.Session, members []database.EgressProxyGroupMember) bool {
	for _, member := range members {
		proxyID := strings.TrimSpace(member.ProxyID)
		if _, err := h.db.GetEgressProxy(ctx, proxyID); err != nil {
			return false
		}
		if session.Scope != database.RBACScopeAll && !h.db.UserCanAccessResource(session.UserID, session.Scope, "egress_proxy", proxyID) {
			return false
		}
	}
	return true
}

func writeEgressProxyGroupStorageError(c *gin.Context, logger *zap.Logger, message, groupID string, err error) {
	fields := []zap.Field{zap.Error(err)}
	if strings.TrimSpace(groupID) != "" {
		fields = append(fields, zap.String("proxy_group_id", strings.TrimSpace(groupID)))
	}
	logger.Error(message, fields...)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "出站代理组操作失败"})
}
