package handler

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/database"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
)

type createContainerWorkspaceRequest struct {
	Name      string `json:"name"`
	ProjectID string `json:"projectId,omitempty"`
}

type updateConversationWorkspaceRequest struct {
	Mode        string `json:"mode"`
	WorkspaceID string `json:"workspaceId,omitempty"`
}

func requestPage(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return page, pageSize
}

func (h *ConversationHandler) canAccessWorkspace(c *gin.Context, workspace *database.ContainerWorkspace, write bool) bool {
	if workspace == nil {
		return false
	}
	session, ok := security.CurrentSession(c)
	if !ok {
		return false
	}
	if session.Scope == database.RBACScopeAll {
		return true
	}
	if h.db.UserCanAccessResource(session.UserID, session.Scope, "container_workspace", workspace.ID) {
		return true
	}
	if strings.TrimSpace(workspace.ProjectID) == "" {
		return false
	}
	permission := "project:read"
	if write {
		permission = "project:write"
	}
	return session.Permissions[permission] && h.db.UserCanAccessResource(session.UserID, session.ScopeFor(permission), "project", workspace.ProjectID)
}

func (h *ConversationHandler) CreateContainerWorkspace(c *gin.Context) {
	var req createContainerWorkspaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	projectID := strings.TrimSpace(req.ProjectID)
	if projectID != "" && (session.Scope != database.RBACScopeAll && (!session.Permissions["project:write"] || !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("project:write"), "project", projectID))) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权在该项目创建共享工作区"})
		return
	}
	workspace, err := h.db.CreateSharedContainerWorkspace(c.Request.Context(), req.Name, projectID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.db.AssignResourceToUser(session.UserID, "container_workspace", workspace.ID); err != nil {
		_, _ = h.db.DeleteContainerWorkspaceRecord(c.Request.Context(), workspace.ID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建共享工作区授权失败"})
		return
	}
	c.JSON(http.StatusCreated, workspace)
}

func (h *ConversationHandler) ListContainerWorkspaces(c *gin.Context) {
	projectID := strings.TrimSpace(c.Query("project_id"))
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	if projectID != "" && session.Scope != database.RBACScopeAll && !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("project:read"), "project", projectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该项目"})
		return
	}
	page, pageSize := requestPage(c)
	var items []database.ContainerWorkspace
	var total int
	var err error
	if session.Scope != database.RBACScopeAll && projectID == "" {
		items, total, err = h.db.ListAssignedSharedContainerWorkspaces(c.Request.Context(), projectID, c.Query("q"), session.UserID, pageSize, (page-1)*pageSize)
	} else {
		items, total, err = h.db.ListSharedContainerWorkspaces(c.Request.Context(), projectID, c.Query("q"), pageSize, (page-1)*pageSize)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取共享工作区失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "page": page, "pageSize": pageSize})
}

func (h *ConversationHandler) GetContainerWorkspace(c *gin.Context) {
	workspace, err := h.db.GetContainerWorkspace(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "共享工作区不存在"})
		return
	}
	if !h.canAccessWorkspace(c, workspace, false) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该共享工作区"})
		return
	}
	attachments, err := h.db.ListContainerWorkspaceAttachments(c.Request.Context(), workspace.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取工作区使用关系失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"workspace": workspace, "attachments": attachments})
}

func (h *ConversationHandler) DeleteContainerWorkspace(c *gin.Context) {
	workspace, err := h.db.GetContainerWorkspace(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "共享工作区不存在"})
		return
	}
	if workspace.Kind != database.ContainerWorkspaceKindShared {
		c.JSON(http.StatusBadRequest, gin.H{"error": "专属工作区随所属对话管理"})
		return
	}
	if !h.canAccessWorkspace(c, workspace, true) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权删除该共享工作区"})
		return
	}
	if workspace.AttachedConversations != 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "工作区仍被对话使用，无法删除"})
		return
	}
	if h.sharedWorkspace == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "容器工作区服务不可用"})
		return
	}
	if err := h.sharedWorkspace.DeleteSharedWorkspace(c.Request.Context(), workspace.ID); err != nil {
		h.writeContainerWorkspaceError(c, "", err)
		return
	}
	if _, err := h.db.DeleteContainerWorkspaceRecord(c.Request.Context(), workspace.ID); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "workspaceId": workspace.ID})
}

func (h *ConversationHandler) GetConversationWorkspaceBinding(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	binding, err := h.db.GetConversationWorkspaceBinding(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取对话工作区失败"})
		return
	}
	attachments := []database.ContainerWorkspaceAttachment{}
	if binding.Workspace != nil {
		attachments, _ = h.db.ListContainerWorkspaceAttachments(c.Request.Context(), binding.Workspace.ID)
	}
	c.JSON(http.StatusOK, gin.H{"binding": binding, "attachments": attachments})
}

func (h *ConversationHandler) UpdateConversationWorkspaceBinding(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	var req updateConversationWorkspaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Mode = strings.TrimSpace(req.Mode)
	req.WorkspaceID = strings.TrimSpace(req.WorkspaceID)
	if req.Mode != database.ConversationWorkspaceModeEphemeral && req.Mode != database.ConversationWorkspaceModeDedicated && req.Mode != database.ConversationWorkspaceModeShared {
		c.JSON(http.StatusBadRequest, gin.H{"error": "工作区模式无效"})
		return
	}
	if req.Mode == database.ConversationWorkspaceModeShared {
		if req.WorkspaceID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "请选择共享工作区"})
			return
		}
		workspace, err := h.db.GetContainerWorkspace(c.Request.Context(), req.WorkspaceID)
		if err != nil || !h.canAccessWorkspace(c, workspace, false) {
			c.JSON(http.StatusForbidden, gin.H{"error": "无权使用该共享工作区"})
			return
		}
	}
	apply := func() error {
		previousBinding, err := h.db.GetConversationWorkspaceBinding(c.Request.Context(), id)
		if err != nil {
			return err
		}
		previousWorkspaceID := ""
		if previousBinding.Workspace != nil {
			previousWorkspaceID = strings.TrimSpace(previousBinding.Workspace.ID)
		}
		if previousBinding.Mode == req.Mode && (req.Mode != database.ConversationWorkspaceModeShared || previousWorkspaceID == req.WorkspaceID) {
			return nil
		}
		removePreviousWorkspace := previousBinding.Workspace != nil &&
			previousBinding.Workspace.Kind == database.ContainerWorkspaceKindDedicated &&
			strings.TrimSpace(req.Mode) != database.ConversationWorkspaceModeDedicated
		if h.containerLifecycle != nil {
			if err := h.containerLifecycle.Delete(c.Request.Context(), id, removePreviousWorkspace); err != nil && !errors.Is(err, containerruntime.ErrNotFound) {
				return err
			}
		}
		_, err = h.db.SetConversationWorkspaceBinding(c.Request.Context(), id, req.Mode, req.WorkspaceID)
		return err
	}
	var err error
	if h.taskIdle != nil {
		err = h.taskIdle.RunWhenConversationTaskIdle(id, apply)
	} else {
		err = apply()
	}
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	binding, err := h.db.GetConversationWorkspaceBinding(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取更新后的工作区失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "binding": binding, "takesEffect": "next_turn"})
}
