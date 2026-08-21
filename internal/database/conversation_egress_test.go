package database

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"cyberstrike-ai/internal/egress"
)

func createConversationEgressResources(t *testing.T, db *DB) (EgressProxy, EgressProxyGroup) {
	t.Helper()
	ctx := context.Background()
	proxy, err := db.CreateEgressProxy(ctx, EgressProxy{
		ID: "conversation-proxy", Name: "Conversation proxy", Protocol: egress.UpstreamProtocolHTTPS,
		Host: "proxy.example", Port: 8443, Enabled: true, OwnerUserID: "owner-1",
		CredentialCiphertext: "v1.key.forbidden-ciphertext",
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := db.CreateEgressProxyGroup(ctx, EgressProxyGroup{
		ID: "conversation-group", Name: "Conversation group", Enabled: true,
		FailureThreshold: 3, CooldownSeconds: 60, OwnerUserID: "owner-1",
		Members: []EgressProxyGroupMember{{ProxyID: proxy.ID, Priority: 0, Weight: 1, Enabled: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return proxy, group
}

func TestConversationEgressSelectionCreateUpdateFreezeAndSafeProjection(t *testing.T) {
	db := newEgressProxyTestDB(t)
	proxy, group := createConversationEgressResources(t, db)
	ctx := context.Background()

	conversation, err := db.CreateConversation("proxy selected", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer,
		EgressMode:  ConversationEgressModeProxy, EgressProxyID: proxy.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := db.GetConversationEgress(ctx, conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pending.State != ConversationEgressStatePending || pending.Mode != ConversationEgressModeProxy || pending.Source != ConversationEgressSourceConversation || pending.Proxy == nil || pending.Proxy.ID != proxy.ID || !pending.Proxy.CredentialsConfigured || pending.ProxyGroup != nil || pending.SelectedAt == nil || pending.BoundAt != nil {
		t.Fatalf("pending proxy = %#v", pending)
	}
	encoded, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"forbidden-ciphertext", "credentialCiphertext", "currentWeight", "username", "password"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("safe projection exposed %q: %s", forbidden, encoded)
		}
	}

	pending, err = db.SetConversationEgressSelection(ctx, conversation.ID, ConversationEgressModeGroup, "", group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Mode != ConversationEgressModeGroup || pending.ProxyGroup == nil || pending.ProxyGroup.ID != group.ID || !pending.ProxyGroup.FailClosed || pending.Proxy != nil {
		t.Fatalf("pending group = %#v", pending)
	}
	active, err := db.EnsureConversationEgressBinding(ctx, conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if active.State != ConversationEgressStateActive || active.Mode != ConversationEgressModeGroup || active.Source != ConversationEgressSourceConversation || active.ProxyGroup == nil || active.ProxyGroup.ID != group.ID || active.SelectedAt != nil || active.BoundAt == nil {
		t.Fatalf("active group = %#v", active)
	}
	again, err := db.EnsureConversationEgressBinding(ctx, conversation.ID)
	if err != nil || again.BoundAt == nil || !again.BoundAt.Equal(*active.BoundAt) || again.Mode != active.Mode {
		t.Fatalf("idempotent binding = %#v / %v", again, err)
	}
	if _, err := db.SetConversationEgressSelection(ctx, conversation.ID, ConversationEgressModeNone, "", ""); !errors.Is(err, ErrConversationEgressBindingActive) {
		t.Fatalf("update active binding error = %v", err)
	}
	var selections int
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversation_egress_selections WHERE conversation_id = ?`, conversation.ID).Scan(&selections); err != nil || selections != 0 {
		t.Fatalf("selection count = %d / %v", selections, err)
	}
	if _, err := db.Exec(`UPDATE conversation_egress_bindings SET mode = 'none', proxy_group_id = NULL WHERE conversation_id = ?`, conversation.ID); err == nil {
		t.Fatal("immutable binding update succeeded")
	}
	if _, err := db.Exec(`DELETE FROM conversation_egress_bindings WHERE conversation_id = ?`, conversation.ID); err == nil {
		t.Fatal("live immutable binding delete succeeded")
	}
	if _, err := db.Exec(`DELETE FROM egress_proxy_groups WHERE id = ?`, group.ID); err == nil {
		t.Fatal("bound proxy group deletion succeeded")
	}
	if err := db.DeleteConversation(conversation.ID); err != nil {
		t.Fatalf("delete conversation with binding: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM egress_proxy_groups WHERE id = ?`, group.ID); err != nil {
		t.Fatalf("delete unbound proxy group: %v", err)
	}
}

func TestConversationEgressBindingConcurrentFirstStartIsAtomic(t *testing.T) {
	db := newEgressProxyTestDB(t)
	proxy, _ := createConversationEgressResources(t, db)
	conversation, err := db.CreateConversation("concurrent", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer,
		EgressMode:  ConversationEgressModeProxy, EgressProxyID: proxy.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	results := make(chan ConversationEgressBinding, workers)
	errs := make(chan error, workers)
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	for range workers {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			result, err := db.EnsureConversationEgressBinding(context.Background(), conversation.ID)
			results <- result
			errs <- err
		}()
	}
	start.Done()
	done.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent ensure failed: %v", err)
		}
	}
	var first *ConversationEgressBinding
	for result := range results {
		if first == nil {
			copy := result
			first = &copy
			continue
		}
		if result.Mode != first.Mode || result.Proxy == nil || first.Proxy == nil || result.Proxy.ID != first.Proxy.ID || result.BoundAt == nil || first.BoundAt == nil || !result.BoundAt.Equal(*first.BoundAt) {
			t.Fatalf("concurrent results differ: %#v / %#v", first, result)
		}
	}
	var bindings, selections int
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversation_egress_bindings WHERE conversation_id = ?`, conversation.ID).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversation_egress_selections WHERE conversation_id = ?`, conversation.ID).Scan(&selections); err != nil {
		t.Fatal(err)
	}
	if bindings != 1 || selections != 0 {
		t.Fatalf("bindings/selections = %d/%d", bindings, selections)
	}
}

func TestConversationEgressExplicitAndImplicitNoneRemainDistinct(t *testing.T) {
	db := newEgressProxyTestDB(t)
	ctx := context.Background()
	explicit, err := db.CreateConversation("explicit none", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer, EgressMode: ConversationEgressModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	implicit, err := db.CreateConversation("implicit none", ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		conversation *Conversation
		wantSource   string
	}{
		{explicit, ConversationEgressSourceConversation},
		{implicit, ConversationEgressSourceNone},
	} {
		preview, err := db.GetConversationEgress(ctx, test.conversation.ID)
		if err != nil || preview.State != ConversationEgressStatePending || preview.Mode != ConversationEgressModeNone || preview.Source != test.wantSource {
			t.Fatalf("preview %s = %#v / %v", test.conversation.ID, preview, err)
		}
		active, err := db.EnsureConversationEgressBinding(ctx, test.conversation.ID)
		if err != nil || active.State != ConversationEgressStateActive || active.Mode != ConversationEgressModeNone || active.Source != test.wantSource {
			t.Fatalf("active %s = %#v / %v", test.conversation.ID, active, err)
		}
	}
}

func TestConversationEgressValidationAndSQLConstraints(t *testing.T) {
	db := newEgressProxyTestDB(t)
	proxy, group := createConversationEgressResources(t, db)
	invalid := []ConversationCreateMeta{
		{RuntimeMode: ConversationRuntimeModeHost, EgressMode: ConversationEgressModeNone},
		{RuntimeMode: ConversationRuntimeModeContainer, EgressProxyID: proxy.ID},
		{RuntimeMode: ConversationRuntimeModeContainer, EgressMode: ConversationEgressModeNone, EgressProxyID: proxy.ID},
		{RuntimeMode: ConversationRuntimeModeContainer, EgressMode: ConversationEgressModeProxy},
		{RuntimeMode: ConversationRuntimeModeContainer, EgressMode: ConversationEgressModeProxy, EgressProxyID: proxy.ID, EgressProxyGroupID: group.ID},
		{RuntimeMode: ConversationRuntimeModeContainer, EgressMode: ConversationEgressModeGroup, EgressProxyGroupID: "missing"},
		{RuntimeMode: ConversationRuntimeModeContainer, EgressMode: "direct"},
	}
	for _, meta := range invalid {
		if _, err := db.CreateConversation("invalid", meta); err == nil {
			t.Fatalf("invalid metadata succeeded: %#v", meta)
		}
	}
	conversation, err := db.CreateConversation("constraints", ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO conversation_egress_selections (conversation_id,mode,proxy_id,selected_at) VALUES ('missing','proxy','conversation-proxy',CURRENT_TIMESTAMP)`,
		`INSERT INTO conversation_egress_selections (conversation_id,mode,proxy_id,selected_at) VALUES ('` + conversation.ID + `','none','conversation-proxy',CURRENT_TIMESTAMP)`,
		`INSERT INTO conversation_egress_bindings (conversation_id,mode,source,bound_at) VALUES ('` + conversation.ID + `','proxy','conversation',CURRENT_TIMESTAMP)`,
		`INSERT INTO conversation_egress_bindings (conversation_id,mode,source,bound_at) VALUES ('` + conversation.ID + `','proxy','none',CURRENT_TIMESTAMP)`,
	} {
		if _, err := db.Exec(statement); err == nil {
			t.Fatalf("invalid SQL succeeded: %s", statement)
		}
	}
}

func TestEnsureContainerRuntimeEgressBindingsOnlyMigratesDurableRuntimes(t *testing.T) {
	db := newEgressProxyTestDB(t)
	proxy, _ := createConversationEgressResources(t, db)
	unused, err := db.CreateConversation("unused", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer,
		EgressMode:  ConversationEgressModeProxy, EgressProxyID: proxy.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	queued, err := db.CreateConversation("queued", ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.Queue(context.Background(), databaseRuntimeSpec(queued.ID), false); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureContainerRuntimeEgressBindings(context.Background()); err != nil {
		t.Fatal(err)
	}
	active, err := db.GetConversationEgressBinding(context.Background(), queued.ID)
	if err != nil || active.Mode != ConversationEgressModeNone || active.Source != ConversationEgressSourceNone {
		t.Fatalf("queued binding = %#v / %v", active, err)
	}
	if _, err := db.GetConversationEgressBinding(context.Background(), unused.ID); !errors.Is(err, ErrConversationEgressBindingNotFound) {
		t.Fatalf("unused binding = %v", err)
	}
	pending, err := db.GetConversationEgress(context.Background(), unused.ID)
	if err != nil || pending.State != ConversationEgressStatePending || pending.Proxy == nil || pending.Proxy.ID != proxy.ID {
		t.Fatalf("unused selection = %#v / %v", pending, err)
	}
}

func TestConversationEgressDanglingBindingFailsIntegrityCheck(t *testing.T) {
	db := newEgressProxyTestDB(t)
	proxy, _ := createConversationEgressResources(t, db)
	conversation, err := db.CreateConversation("integrity", ConversationCreateMeta{
		RuntimeMode: ConversationRuntimeModeContainer,
		EgressMode:  ConversationEgressModeProxy, EgressProxyID: proxy.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.EnsureConversationEgressBinding(context.Background(), conversation.ID); err != nil {
		t.Fatal(err)
	}
	// Use one explicit SQLite connection so the connection-scoped PRAGMA can
	// simulate a damaged database that bypassed normal foreign-key enforcement.
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), `PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), `DELETE FROM egress_proxies WHERE id = ?`, proxy.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetConversationEgressBinding(context.Background(), conversation.ID); !errors.Is(err, ErrConversationEgressIntegrity) {
		t.Fatalf("dangling binding error = %v", err)
	}
}
