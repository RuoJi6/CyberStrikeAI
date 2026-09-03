package egressactivity

import (
	"context"
	"strings"
	"sync"

	"cyberstrike-ai/internal/egress"
	"cyberstrike-ai/internal/networkprovenance"

	"github.com/google/uuid"
)

const defaultReplayLimit = 500

// IngestedActivity is the shared envelope used by container logs, Host MITM,
// persistence, and SSE. One event ID is assigned before fan-out.
type IngestedActivity struct {
	ConversationID    string
	ConversationTitle string
	Event             egress.ActivityEvent
}

type subscription struct {
	conversationID string
	runtimeMode    string
	stream         chan IngestedActivity
}

// Ingestor is a bounded, process-local activity fan-out with event-ID dedupe.
// Durable storage remains an explicit subscriber so ingestion never weakens
// proxy enforcement when a database or browser is slow.
type Ingestor struct {
	mu          sync.Mutex
	next        uint64
	subscribers map[uint64]subscription
	recent      map[string][]IngestedActivity
	seen        map[string]struct{}
}

func NewIngestor() *Ingestor {
	return &Ingestor{subscribers: make(map[uint64]subscription), recent: make(map[string][]IngestedActivity), seen: make(map[string]struct{})}
}

func (i *Ingestor) Publish(item IngestedActivity) bool {
	if i == nil {
		return false
	}
	item.ConversationID = strings.TrimSpace(item.ConversationID)
	if item.ConversationID == "" {
		return false
	}
	if item.Event.EventID == "" {
		item.Event.EventID = uuid.NewString()
	}
	item.Event.Provenance = item.Event.Provenance.Normalized()
	key := item.ConversationID + "\x00" + item.Event.EventID
	i.mu.Lock()
	defer i.mu.Unlock()
	if _, exists := i.seen[key]; exists {
		return false
	}
	i.seen[key] = struct{}{}
	recent := append(i.recent[item.ConversationID], item)
	if len(recent) > defaultReplayLimit {
		removed := recent[:len(recent)-defaultReplayLimit]
		for _, old := range removed {
			delete(i.seen, item.ConversationID+"\x00"+old.Event.EventID)
		}
		recent = recent[len(recent)-defaultReplayLimit:]
	}
	i.recent[item.ConversationID] = recent
	for _, subscriber := range i.subscribers {
		if subscriber.conversationID != item.ConversationID || !matchesRuntimeMode(subscriber.runtimeMode, item.Event.Provenance.RuntimeMode) {
			continue
		}
		select {
		case subscriber.stream <- item:
		default:
		}
	}
	return true
}

func (i *Ingestor) Subscribe(ctx context.Context, conversationID, runtimeMode string, tail int) <-chan IngestedActivity {
	stream := make(chan IngestedActivity, defaultReplayLimit+64)
	if i == nil || ctx == nil {
		close(stream)
		return stream
	}
	conversationID = strings.TrimSpace(conversationID)
	if tail < 0 {
		tail = 0
	}
	if tail > defaultReplayLimit {
		tail = defaultReplayLimit
	}
	i.mu.Lock()
	i.next++
	id := i.next
	i.subscribers[id] = subscription{conversationID: conversationID, runtimeMode: runtimeMode, stream: stream}
	recent := i.recent[conversationID]
	if tail < len(recent) {
		recent = recent[len(recent)-tail:]
	}
	for _, item := range recent {
		if matchesRuntimeMode(runtimeMode, item.Event.Provenance.RuntimeMode) {
			stream <- item
		}
	}
	i.mu.Unlock()
	go func() {
		<-ctx.Done()
		i.mu.Lock()
		delete(i.subscribers, id)
		close(stream)
		i.mu.Unlock()
	}()
	return stream
}

func matchesRuntimeMode(filter, actual string) bool {
	filter = strings.ToLower(strings.TrimSpace(filter))
	actual = strings.ToLower(strings.TrimSpace(actual))
	return filter == "" || filter == "all" || filter == actual || (filter == networkprovenance.RuntimeModeHostMITM && actual == "host")
}
