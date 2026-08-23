package egressaudit

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/egress"
	containerruntime "cyberstrike-ai/internal/runtime/container"

	"go.uber.org/zap"
)

type Store interface {
	ListRunningEgressAuditRuntimeTargets(context.Context) ([]database.EgressAuditRuntimeTarget, error)
	AppendEgressNetworkAuditEvent(context.Context, database.EgressAuditRuntimeTarget, egress.ActivityEvent) (bool, error)
	ApplyEgressHealthEvent(context.Context, database.EgressAuditRuntimeTarget, egress.ActivityEvent) (bool, error)
}

type ActivityStreamer interface {
	StreamEgressActivity(context.Context, containerruntime.RuntimeSpec, containerruntime.ActivityStreamOptions, containerruntime.RuntimeActivitySink) error
}

type streamHandle struct {
	cancel context.CancelFunc
	token  *struct{}
}

// Collector follows every running, owned conversation gateway independently
// of browser subscriptions. Replaying the gateway's complete bounded log on
// every reconnect is safe because the database applies a deterministic unique
// event key before insertion.
type Collector struct {
	store    Store
	streamer ActivityStreamer
	logger   *zap.Logger

	mu      sync.Mutex
	streams map[string]streamHandle
	wg      sync.WaitGroup
}

func NewCollector(store Store, streamer ActivityStreamer, logger *zap.Logger) (*Collector, error) {
	if store == nil || streamer == nil {
		return nil, errors.New("egress audit collector requires a store and activity streamer")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Collector{store: store, streamer: streamer, logger: logger, streams: make(map[string]streamHandle)}, nil
}

func auditStreamKey(target database.EgressAuditRuntimeTarget) string {
	record := target.Record
	return record.ConversationID + ":" + strconv.Itoa(record.RuntimeGeneration) + ":" + record.ProviderID
}

func (c *Collector) Reconcile(ctx context.Context) error {
	if ctx == nil {
		return errors.New("egress audit collector context is required")
	}
	targets, err := c.store.ListRunningEgressAuditRuntimeTargets(ctx)
	if err != nil {
		return err
	}
	desired := make(map[string]database.EgressAuditRuntimeTarget, len(targets))
	for _, target := range targets {
		record := target.Record
		if record.Status != containerruntime.InitializationCreated || record.RuntimeStatus != containerruntime.StatusRunning ||
			record.Spec.EgressGateway == nil || record.Spec.EgressGateway.BoundarySnapshot == nil {
			continue
		}
		desired[auditStreamKey(target)] = target
	}

	c.mu.Lock()
	for key, handle := range c.streams {
		if _, keep := desired[key]; keep {
			delete(desired, key)
			continue
		}
		handle.cancel()
		delete(c.streams, key)
	}
	for key, target := range desired {
		streamCtx, cancel := context.WithCancel(ctx)
		token := &struct{}{}
		c.streams[key] = streamHandle{cancel: cancel, token: token}
		c.wg.Add(1)
		go c.follow(streamCtx, key, token, target)
	}
	c.mu.Unlock()
	return nil
}

func (c *Collector) follow(ctx context.Context, key string, token *struct{}, target database.EgressAuditRuntimeTarget) {
	defer c.wg.Done()
	defer func() {
		c.mu.Lock()
		if current, ok := c.streams[key]; ok && current.token == token {
			delete(c.streams, key)
		}
		c.mu.Unlock()
	}()
	record := target.Record
	err := c.streamer.StreamEgressActivity(ctx, record.Spec, containerruntime.ActivityStreamOptions{All: true}, func(event egress.ActivityEvent) error {
		if event.RequestType == egress.ActivityRequestHealth {
			_, appendErr := c.store.ApplyEgressHealthEvent(ctx, target, event)
			return appendErr
		}
		_, appendErr := c.store.AppendEgressNetworkAuditEvent(ctx, target, event)
		return appendErr
	})
	if err != nil && ctx.Err() == nil {
		c.logger.Warn("对话出站审计流中断，将在下一轮重新连接",
			zap.String("conversationId", record.ConversationID), zap.Error(err))
	}
}

func (c *Collector) RunPeriodic(ctx context.Context, interval time.Duration, callback func(error)) error {
	if ctx == nil || interval <= 0 {
		return errors.New("egress audit collector context and positive interval are required")
	}
	reconcile := func() {
		err := c.Reconcile(ctx)
		if callback != nil {
			callback(err)
		}
	}
	reconcile()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			c.stopAll()
			c.wg.Wait()
			return nil
		case <-ticker.C:
			reconcile()
		}
	}
}

func (c *Collector) stopAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, handle := range c.streams {
		handle.cancel()
		delete(c.streams, key)
	}
}

func (c *Collector) ActiveStreams() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.streams)
}

func (c *Collector) String() string {
	return fmt.Sprintf("egress audit collector (%d active streams)", c.ActiveStreams())
}
