package handler

import (
	"net/http"
	"strings"

	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffictransform"

	"github.com/gin-gonic/gin"
)

type updateTrafficTransformBindingScopeRequest struct {
	Matcher  traffictransform.Matcher `json:"matcher" binding:"required"`
	Priority *int                     `json:"priority"`
}

type createTrafficTransformBindingRequest struct {
	TransformID    string                   `json:"transformId" binding:"required"`
	ConversationID string                   `json:"conversationId" binding:"required"`
	Matcher        traffictransform.Matcher `json:"matcher" binding:"required"`
	Priority       *int                     `json:"priority"`
	Activate       *bool                    `json:"activate"`
}

func (h *TrafficHandler) manageableObserveBinding(c *gin.Context) (*traffictransform.Binding, bool) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return nil, false
	}
	if !session.Permissions["traffic_transform:activate_observe"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权管理脚本使用案例"})
		return nil, false
	}
	binding, err := h.db.GetTrafficTransformBinding(c.Request.Context(), strings.TrimSpace(c.Param("id")))
	if err != nil || !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("traffic_transform:activate_observe"), "conversation", binding.ConversationID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "脚本使用案例不存在"})
		return nil, false
	}
	if binding.Mode != traffictransform.ModeObserve {
		c.JSON(http.StatusConflict, gin.H{"error": "在线中间人规则需要独立审批，不能在此处修改"})
		return nil, false
	}
	return binding, true
}

func normalizeBindingMatcher(matcher traffictransform.Matcher) traffictransform.Matcher {
	for index := range matcher.Methods {
		matcher.Methods[index] = strings.ToUpper(strings.TrimSpace(matcher.Methods[index]))
	}
	return matcher.Normalize()
}

func validBindingMatcherSize(matcher traffictransform.Matcher) bool {
	groups := [][]string{matcher.Schemes, matcher.Hosts, matcher.Methods, matcher.PathPrefixes, matcher.ContentTypes}
	for _, group := range groups {
		if len(group) > 100 {
			return false
		}
		for _, value := range group {
			if len(value) > 2048 {
				return false
			}
		}
	}
	return true
}

func bindingControlResponse(binding *traffictransform.Binding) gin.H {
	return gin.H{"binding": gin.H{
		"id": binding.ID, "conversationId": binding.ConversationID,
		"transformId": binding.TransformID, "revisionId": binding.RevisionID,
		"mode": binding.Mode, "matcher": binding.Matcher, "priority": binding.Priority,
		"failurePolicy": binding.FailurePolicy, "status": binding.Status, "updatedAt": binding.UpdatedAt,
	}}
}

// CreateTrafficTransformBinding adds an observe-only website scope to an
// existing validated script. Script source/config never round-trips through
// this endpoint, so adding a site cannot mutate an immutable revision.
func (h *TrafficHandler) CreateTrafficTransformBinding(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	if !session.Permissions["traffic_transform:activate_observe"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权管理脚本作用范围"})
		return
	}
	var request createTrafficTransformBindingRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "新增作用范围请求无效"})
		return
	}
	request.TransformID = strings.TrimSpace(request.TransformID)
	request.ConversationID = strings.TrimSpace(request.ConversationID)
	transform, err := h.db.GetTrafficTransform(c.Request.Context(), request.TransformID)
	if err != nil || !h.canAccessTransform(session, transform, "traffic_transform:activate_observe") {
		c.JSON(http.StatusNotFound, gin.H{"error": "脚本不存在"})
		return
	}
	if request.ConversationID == "" || !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("traffic_transform:activate_observe"), "conversation", request.ConversationID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在或无权访问"})
		return
	}
	if transform.CurrentRevisionID == "" {
		c.JSON(http.StatusConflict, gin.H{"error": "脚本没有可用的验证版本"})
		return
	}
	request.Matcher = normalizeBindingMatcher(request.Matcher)
	if len(request.Matcher.Hosts) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "至少指定一个目标网站"})
		return
	}
	if !validBindingMatcherSize(request.Matcher) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "作用范围条目过多或过长"})
		return
	}
	priority := 100
	if request.Priority != nil {
		priority = *request.Priority
	}
	binding, err := h.db.CreateTrafficTransformBinding(c.Request.Context(), &traffictransform.Binding{
		ConversationID: request.ConversationID,
		TransformID:    request.TransformID,
		RevisionID:     transform.CurrentRevisionID,
		Mode:           traffictransform.ModeObserve,
		Matcher:        request.Matcher,
		Priority:       priority,
		FailurePolicy:  traffictransform.FailurePolicyContinue,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	activate := true
	if request.Activate != nil {
		activate = *request.Activate
	}
	if activate {
		binding, err = h.db.ActivateTrafficTransformBinding(c.Request.Context(), binding.ID, "")
	} else {
		binding, err = h.db.DisableTrafficTransformBinding(c.Request.Context(), binding.ID)
	}
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "作用范围已创建，但状态设置失败: " + err.Error()})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, bindingControlResponse(binding))
}

// UpdateTrafficTransformBindingScope changes only the explicit website matcher
// and priority. It never accepts or returns binding Config.
func (h *TrafficHandler) UpdateTrafficTransformBindingScope(c *gin.Context) {
	binding, ok := h.manageableObserveBinding(c)
	if !ok {
		return
	}
	var request updateTrafficTransformBindingScopeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "作用范围请求无效"})
		return
	}
	request.Matcher = normalizeBindingMatcher(request.Matcher)
	if len(request.Matcher.Hosts) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "至少指定一个目标网站"})
		return
	}
	if !validBindingMatcherSize(request.Matcher) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "作用范围条目过多或过长"})
		return
	}
	priority := binding.Priority
	if request.Priority != nil {
		priority = *request.Priority
	}
	updated, err := h.db.UpdateTrafficTransformBindingScope(c.Request.Context(), binding.ID, request.Matcher, priority)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, bindingControlResponse(updated))
}

func (h *TrafficHandler) ActivateTrafficTransformBinding(c *gin.Context) {
	binding, ok := h.manageableObserveBinding(c)
	if !ok {
		return
	}
	if len(binding.Matcher.Normalize().Hosts) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请先指定目标网站后再启用"})
		return
	}
	updated, err := h.db.ActivateTrafficTransformBinding(c.Request.Context(), binding.ID, "")
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, bindingControlResponse(updated))
}

func (h *TrafficHandler) DisableTrafficTransformBinding(c *gin.Context) {
	binding, ok := h.manageableObserveBinding(c)
	if !ok {
		return
	}
	updated, err := h.db.DisableTrafficTransformBinding(c.Request.Context(), binding.ID)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, bindingControlResponse(updated))
}

func (h *TrafficHandler) DeleteTrafficTransformBinding(c *gin.Context) {
	binding, ok := h.manageableObserveBinding(c)
	if !ok {
		return
	}
	if binding.Status != traffictransform.BindingDisabled {
		c.JSON(http.StatusConflict, gin.H{"error": "请先停用使用案例后再删除"})
		return
	}
	if err := h.db.DeleteTrafficTransformBinding(c.Request.Context(), binding.ID); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}
