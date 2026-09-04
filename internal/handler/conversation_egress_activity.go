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
	"cyberstrike-ai/internal/egressactivity"
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

type conversationEgressActivityStreamItem struct {
	event          egress.ActivityEvent
	hasEvent       bool
	replayComplete bool
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
	runtimeMode := strings.ToLower(strings.TrimSpace(c.DefaultQuery("runtime_mode", "all")))
	if runtimeMode != "all" && runtimeMode != "container" && runtimeMode != "host_mitm" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "runtime_mode 必须为 all、container 或 host_mitm"})
		return
	}
	tail, err := strconv.Atoi(c.DefaultQuery("tail", "100"))
	if err != nil || tail < 1 || tail > 500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tail 必须为 1 到 500 的整数"})
		return
	}
	auditSetting, settingErr := h.db.GetConversationEgressAuditSetting(c.Request.Context(), id)
	activityMode := egressactivity.AggregationModeAll
	if settingErr == nil {
		activityMode = auditSetting.AggregationMode
	}
	if h.egressActivityIngestor != nil {
		h.streamIngestedEgressActivity(c, id, conversation.Title, runtimeMode, tail)
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

	activity := make(chan conversationEgressActivityStreamItem, 64)
	streamDone := make(chan error, 1)
	ctx := c.Request.Context()
	go func() {
		err := h.egressActivityStreamer.StreamEgressActivity(ctx, record.Spec, containerruntime.ActivityStreamOptions{
			Tail: tail,
			ReplayComplete: func() error {
				select {
				case activity <- conversationEgressActivityStreamItem{replayComplete: true}:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
		}, func(event egress.ActivityEvent) error {
			select {
			case activity <- conversationEgressActivityStreamItem{event: event, hasEvent: true}:
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
	aggregateTicker := time.NewTicker(100 * time.Millisecond)
	defer aggregateTicker.Stop()
	aggregator := egressactivity.New(egressactivity.DefaultConfig())
	writeActivities := func(events []egress.ActivityEvent) error {
		for _, event := range events {
			view := conversationEgressActivityView{
				ActivityEvent: event, ConversationID: id, ConversationTitle: conversation.Title,
				Agent: event.Provenance.AgentID, Tool: event.Provenance.ToolName,
			}
			if err := writeConversationActivitySSE(c.Writer, flusher, "activity", view); err != nil {
				return err
			}
		}
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			if _, err := c.Writer.Write([]byte(": keepalive\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case now := <-aggregateTicker.C:
			if activityMode != egressactivity.AggregationModeNone && writeActivities(aggregator.FlushExpired(now.UTC())) != nil {
				return
			}
		case item, open := <-activity:
			if !open {
				if activityMode != egressactivity.AggregationModeNone && writeActivities(aggregator.FlushAll()) != nil {
					return
				}
				streamErr := <-streamDone
				if ctx.Err() == nil {
					_ = writeConversationActivitySSE(c.Writer, flusher, "stream_error", gin.H{"code": safeEgressActivityStreamError(streamErr)})
				}
				return
			}
			if item.replayComplete {
				if activityMode != egressactivity.AggregationModeNone && writeActivities(aggregator.FlushAll()) != nil {
					return
				}
				continue
			}
			if !item.hasEvent {
				continue
			}
			event := item.event
			outgoing := []egress.ActivityEvent{event}
			if egressactivity.ShouldAggregate(activityMode, event) {
				outgoing = aggregator.ObserveAt(event, time.Now().UTC())
			}
			if err := writeActivities(outgoing); err != nil {
				return
			}
		}
	}
}

func (h *ConversationHandler) streamIngestedEgressActivity(c *gin.Context, conversationID, title, runtimeMode string, tail int) {
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
		"conversationId": conversationID, "conversationTitle": title, "runtimeMode": runtimeMode,
	}); err != nil {
		return
	}
	ctx := c.Request.Context()
	stream := h.egressActivityIngestor.Subscribe(ctx, conversationID, runtimeMode, tail)
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
		case item, open := <-stream:
			if !open {
				return
			}
			event := item.Event
			view := conversationEgressActivityView{
				ActivityEvent: event, ConversationID: conversationID, ConversationTitle: title,
				Agent: event.Provenance.AgentID, Tool: event.Provenance.ToolName,
			}
			if writeConversationActivitySSE(c.Writer, flusher, "activity", view) != nil {
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
