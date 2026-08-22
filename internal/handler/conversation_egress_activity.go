package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/egress"
	containerruntime "cyberstrike-ai/internal/runtime/container"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
)

const egressActivityKeepaliveInterval = 15 * time.Second

type conversationEgressActivityView struct {
	egress.ActivityEvent
	ConversationID    string `json:"conversationId"`
	ConversationTitle string `json:"conversationTitle"`
	Agent             string `json:"agent"`
	Tool              string `json:"tool"`
}

// StreamConversationEgressActivity streams a verified gateway log as SSE.
// Resource authorization is checked again here in addition to centralized
// RBAC so this handler remains safe in focused tests and alternate routers.
func (h *ConversationHandler) StreamConversationEgressActivity(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权访问"})
		return
	}
	if !h.db.UserCanAccessResource(session.UserID, session.Scope, "conversation", id) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该对话"})
		return
	}
	conversation, err := h.db.GetConversationLite(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在"})
		return
	}
	if h.containerInitializations == nil || h.egressActivityStreamer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "出站网络活动服务未配置"})
		return
	}
	record, err := h.containerInitializations.Get(c.Request.Context(), id)
	if errors.Is(err, containerruntime.ErrNotFound) {
		c.JSON(http.StatusConflict, gin.H{"error": "对话容器尚未创建", "code": "not_created"})
		return
	}
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "无法读取对话容器状态"})
		return
	}
	if record.Status != containerruntime.InitializationCreated || record.Spec.EgressGateway == nil || record.Spec.EgressGateway.BoundarySnapshot == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "对话容器网关尚未就绪", "code": "not_ready"})
		return
	}
	tail, err := strconv.Atoi(c.DefaultQuery("tail", "100"))
	if err != nil || tail < 1 || tail > 500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tail 必须为 1 到 500 的整数"})
		return
	}
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "当前响应不支持实时流"})
		return
	}
	c.Header("Content-Type", "text/event-stream; charset=utf-8")
	c.Header("Cache-Control", "no-cache, no-transform")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	if err := writeConversationActivitySSE(c.Writer, flusher, "ready", gin.H{
		"conversationId": id, "conversationTitle": conversation.Title, "agent": "container-agent", "tool": "",
	}); err != nil {
		return
	}

	activity := make(chan egress.ActivityEvent, 64)
	streamDone := make(chan error, 1)
	ctx := c.Request.Context()
	go func() {
		err := h.egressActivityStreamer.StreamEgressActivity(ctx, record.Spec, containerruntime.ActivityStreamOptions{Tail: tail}, func(event egress.ActivityEvent) error {
			select {
			case activity <- event:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		close(activity)
		streamDone <- err
	}()

	keepalive := time.NewTicker(egressActivityKeepaliveInterval)
	defer keepalive.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			if _, err := c.Writer.Write([]byte(": keepalive\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case event, open := <-activity:
			if !open {
				streamErr := <-streamDone
				if ctx.Err() == nil {
					_ = writeConversationActivitySSE(c.Writer, flusher, "stream_error", gin.H{"code": safeEgressActivityStreamError(streamErr)})
				}
				return
			}
			view := conversationEgressActivityView{
				ActivityEvent: event, ConversationID: id, ConversationTitle: conversation.Title,
				Agent: "container-agent", Tool: "",
			}
			if err := writeConversationActivitySSE(c.Writer, flusher, "activity", view); err != nil {
				return
			}
		}
	}
}

func writeConversationActivitySSE(writer http.ResponseWriter, flusher http.Flusher, event string, payload interface{}) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "event: %s\ndata: %s\n\n", event, encoded); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func safeEgressActivityStreamError(err error) string {
	switch {
	case err == nil:
		return "stream_closed"
	case errors.Is(err, containerruntime.ErrNotFound):
		return "not_found"
	case errors.Is(err, containerruntime.ErrRuntimeNotReady):
		return "not_ready"
	case errors.Is(err, containerruntime.ErrRuntimeStateConflict):
		return "runtime_drift"
	default:
		return "unavailable"
	}
}
