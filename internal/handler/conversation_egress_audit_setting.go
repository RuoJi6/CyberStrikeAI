package handler

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
)

type conversationEgressAuditSettingRequest struct {
	Enabled         *bool  `json:"enabled,omitempty"`
	Mode            string `json:"mode,omitempty"`
	AggregationMode string `json:"aggregationMode,omitempty"`
}

func (h *ConversationHandler) lockConversationAggregation(conversationID string) func() {
	h.egressAggregationMu.Lock()
	lock := h.egressAggregationLocks[conversationID]
	if lock == nil {
		lock = &sync.Mutex{}
		h.egressAggregationLocks[conversationID] = lock
	}
	h.egressAggregationMu.Unlock()
	lock.Lock()
	return lock.Unlock
}

func (h *ConversationHandler) GetConversationEgressAuditSetting(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	unlock := h.lockConversationAggregation(id)
	defer unlock()
	setting, err := h.db.GetConversationEgressAuditSetting(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取对话出站审计设置失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"conversationId": id, "enabled": setting.Enabled, "mode": setting.Mode, "aggregationMode": setting.AggregationMode})
}

func (h *ConversationHandler) UpdateConversationEgressAuditSetting(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	unlock := h.lockConversationAggregation(id)
	defer unlock()
	var request conversationEgressAuditSettingRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "出站审计设置格式无效"})
		return
	}
	if request.Enabled == nil && strings.TrimSpace(request.Mode) == "" && strings.TrimSpace(request.AggregationMode) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "至少需要 enabled、mode 或 aggregationMode"})
		return
	}
	current, err := h.db.GetConversationEgressAuditSetting(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取对话出站审计设置失败"})
		return
	}
	enabled := current.Enabled
	aggregationMode := current.AggregationMode
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	if strings.TrimSpace(request.AggregationMode) != "" {
		aggregationMode, err = database.NormalizeConversationEgressAggregationMode(request.AggregationMode)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "aggregationMode 必须为 all、tools 或 none"})
			return
		}
	}
	if strings.TrimSpace(request.Mode) != "" {
		legacyMode, modeErr := database.NormalizeConversationEgressAuditMode(request.Mode)
		if modeErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "mode 必须为 compact、full 或 off"})
			return
		}
		legacyAggregation := database.EgressAggregationModeAll
		if legacyMode == database.EgressAuditModeFull {
			legacyAggregation = database.EgressAggregationModeNone
		}
		if legacyMode == database.EgressAuditModeOff {
			if request.Enabled != nil && *request.Enabled {
				c.JSON(http.StatusBadRequest, gin.H{"error": "enabled 与旧版 mode 冲突"})
				return
			}
			enabled = false
		} else {
			if request.Enabled != nil && !*request.Enabled {
				c.JSON(http.StatusBadRequest, gin.H{"error": "enabled 与旧版 mode 冲突"})
				return
			}
			enabled = true
			if strings.TrimSpace(request.AggregationMode) != "" && aggregationMode != legacyAggregation {
				c.JSON(http.StatusBadRequest, gin.H{"error": "aggregationMode 与旧版 mode 冲突"})
				return
			}
			aggregationMode = legacyAggregation
		}
	}
	if h.egressAggregation != nil {
		if err := h.egressAggregation.ApplyConversationAggregationSetting(c.Request.Context(), id, enabled, aggregationMode); err != nil {
			_ = h.egressAggregation.ApplyConversationAggregationSetting(context.Background(), id, current.Enabled, current.AggregationMode)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "应用流量聚合策略失败，设置未变更"})
			return
		}
	}
	if err := h.db.SetConversationEgressAuditSetting(c.Request.Context(), id, enabled, aggregationMode); err != nil {
		if h.egressAggregation != nil {
			_ = h.egressAggregation.ApplyConversationAggregationSetting(context.Background(), id, current.Enabled, current.AggregationMode)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新对话出站审计设置失败"})
		return
	}
	if h.egressAggregation != nil {
		if err := h.egressAggregation.RefreshConversationAggregation(c.Request.Context()); err != nil {
			_ = h.db.SetConversationEgressAuditSetting(context.Background(), id, current.Enabled, current.AggregationMode)
			_ = h.egressAggregation.ApplyConversationAggregationSetting(context.Background(), id, current.Enabled, current.AggregationMode)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "刷新流量聚合策略失败，已恢复原设置"})
			return
		}
	}
	updated, err := h.db.GetConversationEgressAuditSetting(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取更新后的出站审计设置失败"})
		return
	}
	if h.audit != nil {
		h.audit.RecordOK(c, "conversation", "update-egress-audit", "更新对话出站审计设置", "conversation", id, map[string]interface{}{
			"enabled":          updated.Enabled,
			"mode":             updated.Mode,
			"aggregation_mode": updated.AggregationMode,
		})
	}
	c.JSON(http.StatusOK, gin.H{"conversationId": id, "enabled": updated.Enabled, "mode": updated.Mode, "aggregationMode": updated.AggregationMode})
}
