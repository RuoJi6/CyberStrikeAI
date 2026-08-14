package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// AgentTurnLoopManager serializes deferred system turns per conversation.
// It uses Eino v0.9 TurnLoop as the in-memory dispatcher while the database
// record that scheduled the turn remains the durable source of truth.
type AgentTurnLoopManager struct {
	ctx    context.Context
	tasks  *AgentTaskManager
	logger *zap.Logger

	mu    sync.Mutex
	loops map[string]*agentTurnLoopEntry
}

type agentTurnLoopEntry struct {
	loop *adk.TurnLoop[*agentTurnLoopItem, *schema.Message]
}

type agentTurnLoopItem struct {
	id             string
	conversationID string
	requestCtx     context.Context
	execute        func(context.Context) error

	done chan error
	once sync.Once
}

func (i *agentTurnLoopItem) complete(err error) {
	if i == nil {
		return
	}
	i.once.Do(func() {
		i.done <- err
		close(i.done)
	})
}

// NewAgentTurnLoopManager creates the process-local TurnLoop registry. The
// supplied context should live for the lifetime of the application.
func NewAgentTurnLoopManager(ctx context.Context, tasks *AgentTaskManager, logger *zap.Logger) *AgentTurnLoopManager {
	if ctx == nil {
		ctx = context.Background()
	}
	return &AgentTurnLoopManager{
		ctx: ctx, tasks: tasks, logger: logger,
		loops: make(map[string]*agentTurnLoopEntry),
	}
}

// EnqueueAndWait pushes a deferred system turn and waits for its execution.
// When a foreground Agent is active, the item stays inside the conversation's
// TurnLoop until FinishTask signals that the current turn is idle.
func (m *AgentTurnLoopManager) EnqueueAndWait(
	ctx context.Context,
	conversationID, itemID string,
	execute func(context.Context) error,
) error {
	if m == nil || m.tasks == nil {
		return fmt.Errorf("Agent TurnLoop 未初始化")
	}
	conversationID = strings.TrimSpace(conversationID)
	itemID = strings.TrimSpace(itemID)
	if conversationID == "" || itemID == "" || execute == nil {
		return fmt.Errorf("Agent TurnLoop 参数不完整")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	item := &agentTurnLoopItem{
		id: itemID, conversationID: conversationID, requestCtx: ctx,
		execute: execute, done: make(chan error, 1),
	}

	entry := m.getOrCreate(conversationID)
	if ok, _ := entry.loop.Push(item); !ok {
		m.removeIfMatch(conversationID, entry)
		entry = m.getOrCreate(conversationID)
		if ok, _ = entry.loop.Push(item); !ok {
			return fmt.Errorf("Agent TurnLoop 已停止，无法排队")
		}
	}

	select {
	case err := <-item.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *AgentTurnLoopManager) getOrCreate(conversationID string) *agentTurnLoopEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry := m.loops[conversationID]; entry != nil {
		return entry
	}
	loop := adk.NewTurnLoop(adk.TurnLoopConfig[*agentTurnLoopItem, *schema.Message]{
		GenInput: func(_ context.Context, _ *adk.TurnLoop[*agentTurnLoopItem, *schema.Message], items []*agentTurnLoopItem) (*adk.GenInputResult[*agentTurnLoopItem, *schema.Message], error) {
			if len(items) == 0 || items[0] == nil {
				return nil, fmt.Errorf("Agent TurnLoop 收到空任务")
			}
			item := items[0]
			return &adk.GenInputResult[*agentTurnLoopItem, *schema.Message]{
				Input: &adk.TypedAgentInput[*schema.Message]{
					Messages: []*schema.Message{schema.UserMessage("deferred-system-turn:" + item.id)},
				},
				Consumed:  []*agentTurnLoopItem{item},
				Remaining: append([]*agentTurnLoopItem(nil), items[1:]...),
			}, nil
		},
		PrepareAgent: func(_ context.Context, _ *adk.TurnLoop[*agentTurnLoopItem, *schema.Message], consumed []*agentTurnLoopItem) (adk.TypedAgent[*schema.Message], error) {
			if len(consumed) != 1 || consumed[0] == nil {
				return nil, fmt.Errorf("Agent TurnLoop 消费任务数量异常")
			}
			return &deferredSystemTurnAgent{manager: m, item: consumed[0]}, nil
		},
		OnAgentEvents: func(_ context.Context, _ *adk.TurnContext[*agentTurnLoopItem, *schema.Message], events *adk.AsyncIterator[*adk.TypedAgentEvent[*schema.Message]]) error {
			for {
				event, ok := events.Next()
				if !ok {
					return nil
				}
				if event != nil && event.Err != nil {
					return event.Err
				}
			}
		},
	})
	entry := &agentTurnLoopEntry{loop: loop}
	m.loops[conversationID] = entry
	loop.Run(m.ctx)
	return entry
}

func (m *AgentTurnLoopManager) removeIfMatch(conversationID string, entry *agentTurnLoopEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loops[conversationID] == entry {
		delete(m.loops, conversationID)
	}
}

type deferredSystemTurnAgent struct {
	manager *AgentTurnLoopManager
	item    *agentTurnLoopItem
}

func (a *deferredSystemTurnAgent) Name(context.Context) string { return "cyberstrike-deferred-turn" }

func (a *deferredSystemTurnAgent) Description(context.Context) string {
	return "Runs a queued system turn after the foreground conversation becomes idle."
}

func (a *deferredSystemTurnAgent) Run(
	ctx context.Context,
	_ *adk.TypedAgentInput[*schema.Message],
	_ ...adk.AgentRunOption,
) *adk.AsyncIterator[*adk.TypedAgentEvent[*schema.Message]] {
	iter, generator := adk.NewAsyncIteratorPair[*adk.TypedAgentEvent[*schema.Message]]()
	go func() {
		defer generator.Close()
		item := a.item
		if item == nil {
			return
		}
		runCtx, cancel := mergeTurnContexts(ctx, item.requestCtx)
		defer cancel()

		var runErr error
		for {
			runErr = a.manager.tasks.WaitForConversationIdle(runCtx, item.conversationID)
			if runErr != nil {
				break
			}
			runErr = item.execute(runCtx)
			if !errors.Is(runErr, ErrTaskAlreadyRunning) {
				break
			}
			// A user turn won the small race between idle notification and
			// StartTask. Wait for that turn and retry without duplicating data.
		}
		item.complete(runErr)
		if runErr != nil && a.manager.logger != nil {
			a.manager.logger.Warn("Agent TurnLoop deferred turn failed",
				zap.String("conversation_id", item.conversationID),
				zap.String("item_id", item.id), zap.Error(runErr))
		}
		generator.Send(&adk.TypedAgentEvent[*schema.Message]{
			AgentName: "cyberstrike-deferred-turn",
			Output: &adk.TypedAgentOutput[*schema.Message]{
				MessageOutput: &adk.TypedMessageVariant[*schema.Message]{
					Message: schema.AssistantMessage("deferred system turn finished", nil),
					Role:    schema.Assistant,
				},
			},
		})
	}()
	return iter
}

func mergeTurnContexts(primary, secondary context.Context) (context.Context, context.CancelFunc) {
	if primary == nil {
		primary = context.Background()
	}
	ctx, cancel := context.WithCancel(primary)
	if secondary == nil {
		return ctx, cancel
	}
	stop := context.AfterFunc(secondary, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}
