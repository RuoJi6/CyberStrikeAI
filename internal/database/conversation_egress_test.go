package database

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"cyberstrike-ai/internal/egress"
	containerruntime "cyberstrike-ai/internal/runtime/container"
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

func TestConversationEgressRebuildActivatesOnlyWithMatchingRuntimeGeneration(t *testing.T) {
	db := newEgressProxyTestDB(t)
	proxy, _ := createConversationEgressResources(t, db)
	ctx := context.Background()
	conversation, err := db.CreateConversation("egress rebuild", ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.EnsureConversationEgressBinding(ctx, conversation.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.EnsureConversationBoundarySnapshot(ctx, conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	spec := databaseRuntimeSpec(conversation.ID)
	spec.Security.NetworkMode = containerruntime.NetworkInternal
	spec.EgressGateway = databaseGatewaySpec()
	spec.EgressGateway.BoundarySnapshot = &containerruntime.EgressBoundarySnapshotSpec{ID: snapshot.SnapshotID, SHA256: snapshot.SHA256}
	if _, _, err := db.Queue(ctx, spec, false); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := db.Claim(ctx, conversation.ID); err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	if _, err := db.Complete(ctx, conversation.ID, containerruntime.Runtime{ID: spec.ID, ProviderID: "egress-before", Status: containerruntime.StatusStopped}); err != nil {
		t.Fatal(err)
	}

	inherited, err := db.PrepareConversationEgressRebuild(ctx, conversation.ID, "", "", "", true)
	if err != nil || inherited.Binding.Source != ConversationEgressSourceNone || inherited.Binding.Mode != ConversationEgressModeNone {
		t.Fatalf("inherited rebuild = %#v, %v", inherited, err)
	}
	if err := db.CancelConversationEgressRebuild(ctx, conversation.ID); err != nil {
		t.Fatal(err)
	}

	interrupted, err := db.PrepareConversationEgressRebuild(ctx, conversation.ID, ConversationEgressModeProxy, proxy.ID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.PrepareConversationEgressRebuild(ctx, conversation.ID, ConversationEgressModeProxy, proxy.ID, "", false); !errors.Is(err, ErrConversationEgressRebuildPending) {
		t.Fatalf("concurrent egress rebuild error = %v", err)
	}
	if count, err := db.MarkPendingConversationEgressRebuildsInterrupted(ctx); err != nil || count != 1 {
		t.Fatalf("mark interrupted = %d, %v", count, err)
	}
	activeBeforeRetry, err := db.GetConversationEgressBinding(ctx, conversation.ID)
	if err != nil || activeBeforeRetry.Mode != ConversationEgressModeNone {
		t.Fatalf("interrupted rebuild changed active binding = %#v, %v", activeBeforeRetry, err)
	}
	prepared, err := db.PrepareConversationEgressRebuild(ctx, conversation.ID, ConversationEgressModeProxy, proxy.ID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.RouteID == interrupted.RouteID {
		t.Fatalf("retry reused immutable route id %q", prepared.RouteID)
	}
	route := &containerruntime.EgressUpstreamRouteSpec{ID: prepared.RouteID, SHA256: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
	if err := db.SetConversationEgressRebuildRouteReference(ctx, conversation.ID, route.ID, route.SHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := db.BeginLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationRebuild); err != nil {
		t.Fatal(err)
	}
	replacement := spec
	replacement.EgressGateway = &containerruntime.EgressGatewaySpec{}
	*replacement.EgressGateway = *spec.EgressGateway
	replacement.EgressGateway.UpstreamRoute = route
	completed, err := db.CompleteLifecycle(ctx, conversation.ID, containerruntime.LifecycleOperationRebuild, containerruntime.LifecycleCompletion{
		Runtime: containerruntime.Runtime{
			ID: spec.ID, ProviderID: "egress-after", Status: containerruntime.StatusStopped,
			Image: replacement.Image, SpecDigest: containerruntime.RuntimeSpecDigest(replacement),
		},
		IncrementGeneration: true, ReplacementSpec: &replacement,
	})
	if err != nil {
		t.Fatal(err)
	}
	if completed.RuntimeGeneration != prepared.ExpectedRuntimeGeneration {
		t.Fatalf("generation = %d", completed.RuntimeGeneration)
	}
	active, err := db.GetConversationEgressBinding(ctx, conversation.ID)
	if err != nil || active.Mode != ConversationEgressModeProxy || active.Proxy == nil || active.Proxy.ID != proxy.ID {
		t.Fatalf("active egress = %#v, %v", active, err)
	}
	var pending int
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversation_egress_rebuilds WHERE conversation_id = ?`, conversation.ID).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("pending = %d, %v", pending, err)
	}
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

func createConversationEgressInheritanceScopes(t *testing.T, db *DB) (*RBACUser, *Project, EgressProxy, EgressProxyGroup) {
	t.Helper()
	user, err := db.CreateRBACUser("egress-default-owner", "Egress Default Owner", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	project, err := db.CreateProject(&Project{Name: "Inherited egress project"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("project", project.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	proxy, group := createConversationEgressResources(t, db)
	return user, project, proxy, group
}

func TestConversationEgressDefaultInheritancePriorityPreviewClearAndFreeze(t *testing.T) {
	db := newEgressProxyTestDB(t)
	user, project, proxy, group := createConversationEgressInheritanceScopes(t, db)
	ctx := context.Background()

	userDefault, err := db.SetUserEgressDefault(ctx, user.ID, ConversationEgressModeProxy, proxy.ID, "")
	if err != nil || !userDefault.Configured || userDefault.Source != ConversationEgressSourceUser || userDefault.Proxy == nil || userDefault.Proxy.ID != proxy.ID {
		t.Fatalf("user default = %#v / %v", userDefault, err)
	}
	projectDefault, err := db.SetProjectEgressDefault(ctx, project.ID, ConversationEgressModeGroup, "", group.ID)
	if err != nil || !projectDefault.Configured || projectDefault.Source != ConversationEgressSourceProject || projectDefault.ProxyGroup == nil || projectDefault.ProxyGroup.ID != group.ID {
		t.Fatalf("project default = %#v / %v", projectDefault, err)
	}
	preview, err := db.GetEgressInheritancePreview(ctx, user.ID, project.ID)
	if err != nil || preview.Source != ConversationEgressSourceProject || preview.ProxyGroup == nil || preview.ProxyGroup.ID != group.ID {
		t.Fatalf("project preview = %#v / %v", preview, err)
	}
	preview, err = db.GetEgressInheritancePreview(ctx, user.ID, "")
	if err != nil || preview.Source != ConversationEgressSourceUser || preview.Proxy == nil || preview.Proxy.ID != proxy.ID {
		t.Fatalf("user preview = %#v / %v", preview, err)
	}

	conversation, err := db.CreateConversation("inherits project", ConversationCreateMeta{
		ProjectID: project.ID, RuntimeMode: ConversationRuntimeModeContainer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", conversation.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	pending, err := db.GetConversationEgress(ctx, conversation.ID)
	if err != nil || pending.State != ConversationEgressStatePending || pending.Source != ConversationEgressSourceProject || pending.ProxyGroup == nil || pending.ProxyGroup.ID != group.ID || pending.SelectedAt != nil {
		t.Fatalf("inherited project pending = %#v / %v", pending, err)
	}
	explicit, err := db.SetConversationEgressSelection(ctx, conversation.ID, ConversationEgressModeNone, "", "")
	if err != nil || explicit.Source != ConversationEgressSourceConversation || explicit.Mode != ConversationEgressModeNone {
		t.Fatalf("explicit override = %#v / %v", explicit, err)
	}
	restored, err := db.ClearConversationEgressSelection(ctx, conversation.ID)
	if err != nil || restored.Source != ConversationEgressSourceProject || restored.ProxyGroup == nil || restored.ProxyGroup.ID != group.ID {
		t.Fatalf("restored inheritance = %#v / %v", restored, err)
	}
	active, err := db.EnsureConversationEgressBinding(ctx, conversation.ID)
	if err != nil || active.State != ConversationEgressStateActive || active.Source != ConversationEgressSourceProject || active.ProxyGroup == nil || active.ProxyGroup.ID != group.ID {
		t.Fatalf("project active binding = %#v / %v", active, err)
	}
	if _, err := db.SetProjectEgressDefault(ctx, project.ID, ConversationEgressModeNone, "", ""); err != nil {
		t.Fatal(err)
	}
	unchanged, err := db.GetConversationEgress(ctx, conversation.ID)
	if err != nil || unchanged.Source != ConversationEgressSourceProject || unchanged.Mode != ConversationEgressModeGroup || unchanged.ProxyGroup == nil || unchanged.ProxyGroup.ID != group.ID {
		t.Fatalf("active binding drifted with default = %#v / %v", unchanged, err)
	}
	if _, err := db.ClearConversationEgressSelection(ctx, conversation.ID); !errors.Is(err, ErrConversationEgressBindingActive) {
		t.Fatalf("cleared active binding: %v", err)
	}

	projectNoneConversation, err := db.CreateConversation("project none wins", ConversationCreateMeta{ProjectID: project.ID, RuntimeMode: ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", projectNoneConversation.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	projectNone, err := db.GetConversationEgress(ctx, projectNoneConversation.ID)
	if err != nil || projectNone.Source != ConversationEgressSourceProject || projectNone.Mode != ConversationEgressModeNone {
		t.Fatalf("explicit project none did not override user proxy = %#v / %v", projectNone, err)
	}
	if err := db.DeleteProjectEgressDefault(ctx, project.ID); err != nil {
		t.Fatal(err)
	}
	fallback, err := db.GetConversationEgress(ctx, projectNoneConversation.ID)
	if err != nil || fallback.Source != ConversationEgressSourceUser || fallback.Proxy == nil || fallback.Proxy.ID != proxy.ID {
		t.Fatalf("project delete did not fall back to user = %#v / %v", fallback, err)
	}
}

func TestEgressDefaultCRUDConstraintsCascadesAndSafeProjection(t *testing.T) {
	db := newEgressProxyTestDB(t)
	user, project, proxy, group := createConversationEgressInheritanceScopes(t, db)
	ctx := context.Background()

	empty, err := db.GetUserEgressDefault(ctx, user.ID)
	if err != nil || empty.Configured || empty.Mode != ConversationEgressModeNone || empty.Source != ConversationEgressSourceNone {
		t.Fatalf("empty user default = %#v / %v", empty, err)
	}
	explicitNone, err := db.SetUserEgressDefault(ctx, user.ID, ConversationEgressModeNone, "", "")
	if err != nil || !explicitNone.Configured || explicitNone.Mode != ConversationEgressModeNone || explicitNone.Source != ConversationEgressSourceUser || explicitNone.UpdatedAt == nil {
		t.Fatalf("explicit none = %#v / %v", explicitNone, err)
	}
	projectView, err := db.SetProjectEgressDefault(ctx, project.ID, ConversationEgressModeGroup, "", group.ID)
	if err != nil || projectView.ProxyGroup == nil || projectView.ProxyGroup.ID != group.ID {
		t.Fatalf("project group default = %#v / %v", projectView, err)
	}
	encoded, err := json.Marshal(projectView)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"forbidden-ciphertext", "credentialCiphertext", "currentWeight", "username", "password"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("default projection exposed %q: %s", forbidden, encoded)
		}
	}
	for _, invalid := range []struct{ mode, proxyID, groupID string }{
		{"", "", ""}, {"direct", "", ""}, {"none", proxy.ID, ""}, {"proxy", "", ""}, {"group", "", "missing"},
	} {
		if _, err := db.SetUserEgressDefault(ctx, user.ID, invalid.mode, invalid.proxyID, invalid.groupID); err == nil {
			t.Fatalf("invalid user default succeeded: %#v", invalid)
		}
	}
	for _, statement := range []string{
		`INSERT INTO user_egress_defaults (user_id,mode,proxy_id,updated_at) VALUES ('missing','proxy','conversation-proxy',CURRENT_TIMESTAMP)`,
		`INSERT INTO user_egress_defaults (user_id,mode,proxy_id,updated_at) VALUES ('` + user.ID + `','none','conversation-proxy',CURRENT_TIMESTAMP)`,
		`INSERT INTO project_egress_defaults (project_id,mode,proxy_group_id,updated_at) VALUES ('missing','group','conversation-group',CURRENT_TIMESTAMP)`,
	} {
		if _, err := db.Exec(statement); err == nil {
			t.Fatalf("invalid default SQL succeeded: %s", statement)
		}
	}
	if _, err := db.Exec(`DELETE FROM egress_proxy_groups WHERE id = ?`, group.ID); err == nil {
		t.Fatal("proxy group referenced by project default was deleted")
	}
	if err := db.DeleteProject(project.ID); err != nil {
		t.Fatal(err)
	}
	var projectDefaults int
	if err := db.QueryRow(`SELECT COUNT(*) FROM project_egress_defaults WHERE project_id = ?`, project.ID).Scan(&projectDefaults); err != nil || projectDefaults != 0 {
		t.Fatalf("project default cascade = %d / %v", projectDefaults, err)
	}
	if _, err := db.Exec(`DELETE FROM egress_proxy_groups WHERE id = ?`, group.ID); err != nil {
		t.Fatalf("delete group after project cascade: %v", err)
	}
	if _, err := db.SetUserEgressDefault(ctx, user.ID, ConversationEgressModeProxy, proxy.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteRBACUser(user.ID); err != nil {
		t.Fatal(err)
	}
	var userDefaults int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_egress_defaults WHERE user_id = ?`, user.ID).Scan(&userDefaults); err != nil || userDefaults != 0 {
		t.Fatalf("user default cascade = %d / %v", userDefaults, err)
	}
}

func TestConversationInheritedEgressConcurrentFirstStartIsAtomic(t *testing.T) {
	db := newEgressProxyTestDB(t)
	user, _, proxy, _ := createConversationEgressInheritanceScopes(t, db)
	if _, err := db.SetUserEgressDefault(context.Background(), user.ID, ConversationEgressModeProxy, proxy.ID, ""); err != nil {
		t.Fatal(err)
	}
	conversation, err := db.CreateConversation("concurrent inherited", ConversationCreateMeta{RuntimeMode: ConversationRuntimeModeContainer})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", conversation.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	const workers = 32
	results := make(chan ConversationEgressBinding, workers)
	errs := make(chan error, workers)
	var ready sync.WaitGroup
	ready.Add(1)
	var done sync.WaitGroup
	for range workers {
		done.Add(1)
		go func() {
			defer done.Done()
			ready.Wait()
			result, err := db.EnsureConversationEgressBinding(context.Background(), conversation.ID)
			results <- result
			errs <- err
		}()
	}
	ready.Done()
	done.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent inherited binding failed: %v", err)
		}
	}
	for result := range results {
		if result.Source != ConversationEgressSourceUser || result.Proxy == nil || result.Proxy.ID != proxy.ID || result.BoundAt == nil {
			t.Fatalf("inherited result = %#v", result)
		}
	}
	var bindings int
	if err := db.QueryRow(`SELECT COUNT(*) FROM conversation_egress_bindings WHERE conversation_id = ?`, conversation.ID).Scan(&bindings); err != nil || bindings != 1 {
		t.Fatalf("inherited bindings = %d / %v", bindings, err)
	}
}

func TestEgressDefaultDanglingTargetFailsIntegrityCheck(t *testing.T) {
	db := newEgressProxyTestDB(t)
	user, err := db.CreateRBACUser("damaged-egress-default", "Damaged Default", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := db.CreateEgressProxy(context.Background(), EgressProxy{
		ID: "damaged-default-proxy", Name: "Damaged default proxy", Protocol: egress.UpstreamProtocolHTTP,
		Host: "damaged.example", Port: 8080, Enabled: true, OwnerUserID: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetUserEgressDefault(context.Background(), user.ID, ConversationEgressModeProxy, proxy.ID, ""); err != nil {
		t.Fatal(err)
	}
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
	if _, err := db.GetUserEgressDefault(context.Background(), user.ID); !errors.Is(err, ErrConversationEgressIntegrity) {
		t.Fatalf("dangling user default error = %v", err)
	}
}
