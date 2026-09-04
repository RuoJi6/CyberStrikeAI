package app

import (
	"context"
	"errors"
	"strings"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egressaudit"
	"cyberstrike-ai/internal/trafficspool"
)

type conversationAggregationController struct {
	db        *database.DB
	spool     *trafficspool.Directory
	host      *hostTrafficProxyManager
	collector *egressaudit.Collector
}

func (controller *conversationAggregationController) ApplyConversationAggregationSetting(ctx context.Context, conversationID string, enabled bool, mode string, recordUpstreamFailures bool) error {
	if controller == nil {
		return nil
	}
	var result error
	if controller.spool != nil && controller.db != nil {
		runtimeMode, err := controller.db.GetConversationRuntimeMode(strings.TrimSpace(conversationID))
		if err != nil {
			return err
		}
		if runtimeMode == database.ConversationRuntimeModeContainer {
			result = errors.Join(result, controller.spool.WriteAggregationPolicy(strings.TrimSpace(conversationID), mode, recordUpstreamFailures))
		}
	}
	if result == nil && controller.host != nil {
		result = errors.Join(result, controller.host.ApplyConversationAggregationSetting(ctx, conversationID, enabled, mode, recordUpstreamFailures))
	}
	return result
}

func (controller *conversationAggregationController) RefreshConversationAggregation(ctx context.Context) error {
	if controller == nil || controller.collector == nil {
		return nil
	}
	return controller.collector.Reconcile(ctx)
}
