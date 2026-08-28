package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cyberstrike-ai/internal/database"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

const (
	conversationTerminalDefaultCols = 100
	conversationTerminalDefaultRows = 28
	conversationTerminalReadLimit   = 64 * 1024
	conversationTerminalIdleTimeout = 30 * time.Minute
)

type conversationContainerWorkspaceResponse struct {
	ConversationID       string                                  `json:"conversationId"`
	RuntimeID            containerruntime.RuntimeID              `json:"runtimeId"`
	RuntimeStatus        containerruntime.Status                 `json:"runtimeStatus"`
	ContainerPath        string                                  `json:"containerPath"`
	HostPath             string                                  `json:"hostPath,omitempty"`
	Storage              string                                  `json:"storage"`
	Persistent           bool                                    `json:"persistent"`
	WorkspaceID          string                                  `json:"workspaceId,omitempty"`
	WorkspaceName        string                                  `json:"workspaceName,omitempty"`
	WorkspaceMode        string                                  `json:"workspaceMode"`
	SharedWith           int                                     `json:"sharedWith"`
	Attachments          []database.ContainerWorkspaceAttachment `json:"attachments,omitempty"`
	InteractiveAvailable bool                                    `json:"interactiveAvailable"`
	InteractiveReason    string                                  `json:"interactiveReason,omitempty"`
}

type conversationTerminalResize struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

var conversationTerminalUpgrader = websocket.Upgrader{
	CheckOrigin: func(request *http.Request) bool {
		origin := strings.TrimSpace(request.Header.Get("Origin"))
		if origin == "" {
			return true
		}
		parsed, err := url.Parse(origin)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return false
		}
		return strings.EqualFold(parsed.Host, request.Host)
	},
}

func (h *ConversationHandler) conversationContainerRecord(c *gin.Context, id string) (containerruntime.InitializationRecord, bool) {
	if h.containerInitializations == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "对话容器状态服务不可用"})
		return containerruntime.InitializationRecord{}, false
	}
	record, err := h.containerInitializations.Get(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, containerruntime.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "对话容器尚未初始化"})
			return containerruntime.InitializationRecord{}, false
		}
		h.logger.Error("读取对话容器状态失败", zap.String("conversationId", id), zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "读取对话容器状态失败"})
		return containerruntime.InitializationRecord{}, false
	}
	return record, true
}

// GetConversationContainerWorkspace exposes only the authenticated
// conversation's workspace paths. Stopped runtimes remain inspectable.
func (h *ConversationHandler) GetConversationContainerWorkspace(c *gin.Context) {
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	record, ok := h.conversationContainerRecord(c, id)
	if !ok {
		return
	}
	if h.containerWorkspace == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "容器工作区信息服务不可用"})
		return
	}
	info, err := h.containerWorkspace.WorkspaceInfo(c.Request.Context(), record.Spec)
	if err != nil {
		h.writeContainerWorkspaceError(c, id, err)
		return
	}
	interactive := record.RuntimeStatus == containerruntime.StatusRunning
	reason := ""
	if !interactive {
		reason = "container_not_running"
	}
	binding, bindingErr := h.db.GetConversationWorkspaceBinding(c.Request.Context(), id)
	if bindingErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取对话工作区绑定失败"})
		return
	}
	attachments := []database.ContainerWorkspaceAttachment{}
	workspaceID, workspaceName, sharedWith := "", "", 0
	if binding.Workspace != nil {
		workspaceID, workspaceName = binding.Workspace.ID, binding.Workspace.Name
		attachments, _ = h.db.ListContainerWorkspaceAttachments(c.Request.Context(), binding.Workspace.ID)
		sharedWith = len(attachments)
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, conversationContainerWorkspaceResponse{
		ConversationID: id, RuntimeID: record.RuntimeID, RuntimeStatus: record.RuntimeStatus,
		ContainerPath: info.ContainerPath, HostPath: info.HostPath, Storage: info.Storage,
		Persistent: info.Persistent, WorkspaceID: workspaceID, WorkspaceName: workspaceName,
		WorkspaceMode: binding.Mode, SharedWith: sharedWith, Attachments: attachments,
		InteractiveAvailable: interactive, InteractiveReason: reason,
	})
}

func (h *ConversationHandler) writeContainerWorkspaceError(c *gin.Context, conversationID string, err error) {
	status := http.StatusServiceUnavailable
	message := "读取容器工作目录失败"
	switch {
	case errors.Is(err, containerruntime.ErrNotFound):
		status, message = http.StatusNotFound, "对话容器或工作区不存在"
	case errors.Is(err, containerruntime.ErrRuntimeStateConflict):
		status, message = http.StatusConflict, "容器当前状态与持久化记录不一致"
	case errors.Is(err, containerruntime.ErrInvalidSpecification):
		status, message = http.StatusBadRequest, "容器工作区规格无效"
	}
	h.logger.Error("读取对话容器工作区信息失败", zap.String("conversationId", conversationID), zap.Error(err))
	c.JSON(status, gin.H{"error": message})
}

// OpenConversationContainerTerminalWS bridges xterm.js to one verified Docker
// exec TTY. It never invokes the existing host terminal handler as fallback.
func (h *ConversationHandler) OpenConversationContainerTerminalWS(c *gin.Context) {
	if !security.SessionHasPermission(c, "terminal:execute") {
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足", "permission": "terminal:execute"})
		return
	}
	id, ok := h.authorizeConversationContainer(c)
	if !ok {
		return
	}
	record, ok := h.conversationContainerRecord(c, id)
	if !ok {
		return
	}
	if record.RuntimeStatus != containerruntime.StatusRunning {
		c.JSON(http.StatusConflict, gin.H{"error": "仅运行中的对话容器可打开交互式终端"})
		return
	}
	if h.containerInteractive == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "容器交互式终端服务不可用"})
		return
	}

	connection, err := conversationTerminalUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer connection.Close()

	session, err := h.containerInteractive.OpenInteractiveExec(c.Request.Context(), record.Spec, containerruntime.InteractiveExecRequest{
		Cols: conversationTerminalDefaultCols,
		Rows: conversationTerminalDefaultRows,
	})
	if err != nil {
		h.logger.Warn("打开对话容器交互式终端失败", zap.String("conversationId", id), zap.Error(err))
		_ = connection.WriteMessage(websocket.TextMessage, []byte("\r\n\x1b[31m[无法打开容器终端，请确认容器仍在运行]\x1b[0m\r\n"))
		_ = connection.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "container terminal unavailable"), time.Now().Add(time.Second))
		return
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil && !errors.Is(closeErr, context.Canceled) {
			h.logger.Warn("关闭对话容器交互式终端失败", zap.String("conversationId", id), zap.Error(closeErr))
		}
	}()

	go func() {
		buffer := make([]byte, 4096)
		for {
			count, readErr := session.Read(buffer)
			if count > 0 {
				if writeErr := connection.WriteMessage(websocket.BinaryMessage, buffer[:count]); writeErr != nil {
					return
				}
			}
			if readErr != nil {
				_ = connection.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "container shell exited"), time.Now().Add(time.Second))
				_ = connection.Close()
				return
			}
		}
	}()

	connection.SetReadLimit(conversationTerminalReadLimit)
	_ = connection.SetReadDeadline(time.Now().Add(conversationTerminalIdleTimeout))
	connection.SetPongHandler(func(string) error {
		return connection.SetReadDeadline(time.Now().Add(conversationTerminalIdleTimeout))
	})
	for {
		messageType, data, readErr := connection.ReadMessage()
		if readErr != nil {
			break
		}
		_ = connection.SetReadDeadline(time.Now().Add(conversationTerminalIdleTimeout))
		if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage || len(data) == 0 {
			continue
		}
		if messageType == websocket.TextMessage && data[0] == '{' {
			var resize conversationTerminalResize
			if json.Unmarshal(data, &resize) == nil && resize.Type == "resize" {
				resizeCtx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
				resizeErr := session.Resize(resizeCtx, resize.Cols, resize.Rows)
				cancel()
				if resizeErr != nil {
					h.logger.Debug("调整对话容器终端尺寸失败", zap.String("conversationId", id), zap.Error(resizeErr))
				}
				continue
			}
		}
		if _, writeErr := session.Write(data); writeErr != nil {
			break
		}
	}
}
