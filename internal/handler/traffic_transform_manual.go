package handler

import (
	"fmt"
	"net/http"
	"strings"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffic"
	"cyberstrike-ai/internal/traffictransform"

	"github.com/gin-gonic/gin"
)

type manualTrafficTransformRequest struct {
	ConversationID string                   `json:"conversationId"`
	Name           string                   `json:"name"`
	Description    string                   `json:"description"`
	Source         string                   `json:"source"`
	Hooks          []traffictransform.Hook  `json:"hooks"`
	Requirements   []string                 `json:"requirements"`
	Matcher        traffictransform.Matcher `json:"matcher"`
	TransactionID  string                   `json:"transactionId"`
	Direction      string                   `json:"direction"`
	Activate       bool                     `json:"activate"`
}

func selectManualTransformMessage(messages []traffic.Message, direction string) (traffic.Message, error) {
	wanted := []string{traffic.StageClientRequest, traffic.StageUpstreamRequest}
	if direction == traffictransform.DirectionResponse {
		wanted = []string{traffic.StageUpstreamResponse, traffic.StageClientResponse}
	} else if direction != traffictransform.DirectionRequest {
		return traffic.Message{}, fmt.Errorf("direction 必须是 request 或 response")
	}
	for _, stage := range wanted {
		for _, message := range messages {
			if message.Stage == stage {
				if !message.Complete {
					return traffic.Message{}, fmt.Errorf("%s 正文不完整，不能运行脚本", stage)
				}
				return message, nil
			}
		}
	}
	return traffic.Message{}, fmt.Errorf("事务没有可用于 %s 测试的完整消息", direction)
}

func trafficTransactionMatchesConversation(db *database.DB, detail *traffic.TransactionDetail, conversationID string) bool {
	if detail == nil {
		return false
	}
	if detail.Transaction.ConversationID == conversationID {
		return true
	}
	projectID, err := db.GetConversationProjectID(conversationID)
	return err == nil && strings.TrimSpace(projectID) != "" && detail.Transaction.ProjectID == strings.TrimSpace(projectID)
}

func (h *TrafficHandler) CreateManualTrafficTransform(c *gin.Context) {
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	if h.transformRunner == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Traffic Transform Runner 未配置"})
		return
	}
	var request manualTrafficTransformRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "脚本请求无效"})
		return
	}
	request.ConversationID = strings.TrimSpace(request.ConversationID)
	request.Direction = strings.TrimSpace(request.Direction)
	if request.Direction == "" {
		request.Direction = traffictransform.DirectionRequest
	}
	if request.ConversationID == "" || !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("traffic_transform:write"), "conversation", request.ConversationID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "对话不存在或无权编写脚本"})
		return
	}
	hooks, err := traffictransform.CanonicalHooks(request.Hooks)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	projectID, _ := h.db.GetConversationProjectID(request.ConversationID)
	transform, err := h.db.CreateTrafficTransform(c.Request.Context(), &traffictransform.Transform{
		ConversationID: request.ConversationID, ProjectID: strings.TrimSpace(projectID),
		Name: request.Name, Description: request.Description, Language: traffictransform.LanguagePython3,
		OwnerUserID: session.UserID,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	revision, staticReport, err := h.db.CreateTrafficTransformRevision(c.Request.Context(), &traffictransform.Revision{
		TransformID: transform.ID, Source: request.Source, Hooks: hooks, Requirements: request.Requirements,
	}, traffictransform.DefaultRunnerInventory())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "transform": transform})
		return
	}
	if !staticReport.Valid {
		revision.Source = ""
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "脚本静态检查未通过", "transform": transform, "revision": revision, "validation": staticReport})
		return
	}
	loaded, err := h.transformRunner.LoadRevision(c.Request.Context(), *revision)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Runner 验证失败: " + err.Error(), "transform": transform})
		return
	}
	validation := traffictransform.ValidationReport{
		Valid: true, SourceSHA256: revision.SourceSHA256,
		Hooks: append([]traffictransform.Hook(nil), loaded.Hooks...), Runner: loaded.RunnerGeneration,
	}
	if err := h.db.SetTrafficTransformRevisionValidation(c.Request.Context(), revision.ID, revision.SourceSHA256, traffictransform.ValidationPassed, validation); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "写入验证结果失败"})
		return
	}
	revision.ValidationStatus = traffictransform.ValidationPassed
	transform, err = h.db.PromoteTrafficTransformRevision(c.Request.Context(), transform.ID, revision.ID, transform.Name, transform.Description)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "启用脚本版本失败"})
		return
	}
	var dryRun *traffictransform.DryRunReport
	if strings.TrimSpace(request.TransactionID) != "" {
		if !session.Permissions["traffic:read_sensitive"] {
			c.JSON(http.StatusForbidden, gin.H{"error": "用历史正文测试脚本需要 traffic:read_sensitive 权限"})
			return
		}
		detail, getErr := h.db.GetTrafficTransaction(c.Request.Context(), strings.TrimSpace(request.TransactionID))
		if getErr != nil || !trafficTransactionMatchesConversation(h.db, detail, request.ConversationID) || !h.canAccess(session, detail, "traffic:read") {
			c.JSON(http.StatusNotFound, gin.H{"error": "测试事务不存在或不属于所选对话/项目"})
			return
		}
		message, selectErr := selectManualTransformMessage(detail.Messages, request.Direction)
		if selectErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": selectErr.Error()})
			return
		}
		report, runErr := traffictransform.NewPipeline(h.transformRunner).DryRun(c.Request.Context(), traffictransform.DryRunInput{
			Revision: *revision, Transaction: detail.Transaction, Message: message, Direction: request.Direction,
		})
		for _, hookRun := range report.HookResults {
			run := &traffictransform.Run{
				RevisionID: revision.ID, TransactionID: detail.Transaction.ID,
				InvocationID: fmt.Sprintf("manual-%s-%s", detail.Transaction.ID, hookRun.Hook),
				Kind:         "offline", Hook: hookRun.Hook, Mode: traffictransform.ModeInline,
				Action: hookRun.Action, InputSHA256: hookRun.InputSHA256, OutputSHA256: hookRun.OutputSHA256,
				DurationMS: hookRun.DurationMS, Annotations: hookRun.Annotations,
			}
			if hookRun.Error != nil {
				run.ErrorCode, run.ErrorSummary = hookRun.Error.Code, hookRun.Error.Message
			}
			_, _ = h.db.CreateTrafficTransformRun(c.Request.Context(), run)
		}
		dryRun = &report
		if runErr != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "历史包测试失败: " + runErr.Error(), "validation": validation, "dryRun": report})
			return
		}
	}
	var binding *traffictransform.Binding
	if request.Activate {
		if !session.Permissions["traffic_transform:activate_observe"] {
			c.JSON(http.StatusForbidden, gin.H{"error": "缺少 traffic_transform:activate_observe 权限"})
			return
		}
		request.Matcher = request.Matcher.Normalize()
		if len(request.Matcher.Hosts) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "启用脚本必须指定 matcher.hosts，避免影响同一对话中的其他网站"})
			return
		}
		binding, err = h.db.CreateTrafficTransformBinding(c.Request.Context(), &traffictransform.Binding{
			ConversationID: request.ConversationID, TransformID: transform.ID, RevisionID: revision.ID,
			Mode: traffictransform.ModeObserve, Matcher: request.Matcher, Priority: 100,
			FailurePolicy: traffictransform.FailurePolicyContinue,
		})
		if err == nil {
			binding, err = h.db.ActivateTrafficTransformBinding(c.Request.Context(), binding.ID, "")
		}
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "启用脚本失败: " + err.Error(), "validation": validation, "dryRun": dryRun})
			return
		}
	}
	revision.Source = ""
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, gin.H{
		"transform": transform, "revision": revision, "validation": validation, "dryRun": dryRun, "binding": binding,
	})
}
