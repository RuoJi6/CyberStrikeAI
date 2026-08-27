package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/traffic"
	"cyberstrike-ai/internal/traffictransform"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// observeImportedTraffic runs only passive decode hooks after the immutable
// wire packet has been committed. Runner failures are recorded and fail open;
// they can never delay or modify the actual Agent request.
func observeImportedTraffic(ctx context.Context, db *database.DB, runner trafficTransformRunner, detail *traffic.TransactionDetail, logger *zap.Logger) {
	if db == nil || runner == nil || detail == nil || detail.Transaction.ConversationID == "" {
		return
	}
	bindings, err := db.ListActiveTrafficTransformBindings(ctx, detail.Transaction.ConversationID)
	if err != nil {
		logger.Debug("读取 Traffic Transform observe 绑定失败", zap.Error(err))
		return
	}
	for _, binding := range bindings {
		if binding.Mode != traffictransform.ModeObserve {
			continue
		}
		revision, getErr := db.GetTrafficTransformRevision(ctx, binding.RevisionID)
		if getErr != nil || revision.ValidationStatus != traffictransform.ValidationPassed {
			continue
		}
		if _, loadErr := runner.LoadRevision(ctx, *revision); loadErr != nil {
			logger.Debug("Traffic Transform observe revision 加载失败", zap.String("revision_id", revision.ID), zap.Error(loadErr))
			continue
		}
		decoded := make([]traffic.Message, 0, 2)
		for _, direction := range []string{traffictransform.DirectionRequest, traffictransform.DirectionResponse} {
			hook := traffictransform.HookDecodeRequest
			stage := traffic.StageDecodedRequest
			if direction == traffictransform.DirectionResponse {
				hook = traffictransform.HookDecodeResponse
				stage = traffic.StageDecodedResponse
			}
			if !revisionHasHook(*revision, hook) {
				continue
			}
			wire, selectErr := selectTrafficMessage(detail.Messages, direction)
			if selectErr != nil {
				continue
			}
			invocationContext := traffictransform.InvocationContext{
				TransactionID: detail.Transaction.ID, ConversationID: detail.Transaction.ConversationID,
				Direction: direction, Scheme: detail.Transaction.Scheme, Host: detail.Transaction.Host,
				Port: detail.Transaction.Port, Method: detail.Transaction.Method, Path: detail.Transaction.Path,
				ContentType: wire.ContentType, Timestamp: time.Now().UTC(), Config: binding.Config,
			}
			if !binding.Matcher.Matches(invocationContext) {
				continue
			}
			message, convertErr := traffictransform.MessageFromTraffic(wire)
			if convertErr != nil {
				continue
			}
			invocation := traffictransform.Invocation{
				ProtocolVersion: traffictransform.ProtocolVersion,
				InvocationID:    uuid.NewString(), RevisionID: revision.ID, RevisionSHA256: revision.SourceSHA256,
				BindingID: binding.ID, Hook: hook, Mode: traffictransform.ModeObserve,
				DeadlineMS: traffictransform.DefaultDeadlineMS, Context: invocationContext,
				Message: message, TransactionState: map[string]any{},
			}
			started := time.Now()
			result, invokeErr := runner.Invoke(ctx, invocation)
			duration := time.Since(started).Milliseconds()
			run := &traffictransform.Run{
				BindingID: binding.ID, RevisionID: revision.ID, TransactionID: detail.Transaction.ID,
				InvocationID: invocation.InvocationID, Kind: "online", Hook: hook, Mode: traffictransform.ModeObserve,
				Action: result.Action, InputSHA256: message.Body.SHA256, DurationMS: max(duration, 0),
				Annotations: result.Annotations,
			}
			if invokeErr != nil {
				run.Action = traffictransform.ActionError
				run.ErrorCode, run.ErrorSummary = "runner_unavailable", summarizeTransformError(invokeErr)
			} else if result.Error != nil {
				run.ErrorCode, run.ErrorSummary = result.Error.Code, result.Error.Message
			}
			if result.Message != nil {
				run.OutputSHA256 = result.Message.Body.SHA256
			}
			_, _ = db.CreateTrafficTransformRun(ctx, run)
			if invokeErr != nil || result.Action != traffictransform.ActionReplace || result.Message == nil {
				continue
			}
			observed, convertErr := traffictransform.MessageToTraffic(detail.Transaction.ID, stage, *result.Message, time.Now().UTC())
			if convertErr == nil {
				decoded = append(decoded, observed)
			}
		}
		if len(decoded) > 0 {
			if _, applyErr := db.ApplyObservedTrafficTransform(ctx, detail.Transaction.ID, binding.ID, revision.ID, decoded); applyErr != nil {
				logger.Debug("保存 Traffic Transform observe 结果失败", zap.Error(applyErr))
			}
			return
		}
	}
}

func revisionHasHook(revision traffictransform.Revision, hook traffictransform.Hook) bool {
	for _, candidate := range revision.Hooks {
		if candidate == hook {
			return true
		}
	}
	return false
}

func summarizeTransformError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > 1000 {
		value = value[:1000]
	}
	return fmt.Sprintf("%s", value)
}
