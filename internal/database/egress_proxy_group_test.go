package database

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/egress"
)

func createProxyGroupTestProxy(t *testing.T, db *DB, id, owner string, enabled bool) EgressProxy {
	t.Helper()
	proxy, err := db.CreateEgressProxy(context.Background(), EgressProxy{
		ID: id, Name: "Proxy " + id, Protocol: egress.UpstreamProtocolHTTP,
		Host: id + ".example", Port: 8080, Enabled: enabled, OwnerUserID: owner,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proxy
}

func createProxyGroupTestGroup(t *testing.T, db *DB, id, owner string, members ...EgressProxyGroupMember) EgressProxyGroup {
	t.Helper()
	group, err := db.CreateEgressProxyGroup(context.Background(), EgressProxyGroup{
		ID: id, Name: "Primary exits", Enabled: true,
		FailureThreshold: 2, CooldownSeconds: 60, FailClosed: true,
		OwnerUserID: owner, Members: members,
	})
	if err != nil {
		t.Fatal(err)
	}
	return group
}

func TestEgressProxyGroupCRUDWeightedPriorityCircuitAndFailClosed(t *testing.T) {
	db := newEgressProxyTestDB(t)
	for _, id := range []string{"proxy-a", "proxy-b", "proxy-c"} {
		createProxyGroupTestProxy(t, db, id, "owner-1", true)
	}
	group := createProxyGroupTestGroup(t, db, "group-1", "owner-1",
		EgressProxyGroupMember{ProxyID: "proxy-a", Priority: 10, Weight: 3, Enabled: true},
		EgressProxyGroupMember{ProxyID: "proxy-b", Priority: 10, Weight: 1, Enabled: true},
		EgressProxyGroupMember{ProxyID: "proxy-c", Priority: 20, Weight: 100, Enabled: true},
	)
	if !group.FailClosed || len(group.Members) != 3 || group.Members[0].Status != "available" {
		t.Fatalf("created group = %#v", group)
	}
	encoded, err := json.Marshal(group)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"currentWeight", "current_weight", "credentialCiphertext", "credential_ciphertext"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("group JSON exposed %q: %s", forbidden, encoded)
		}
	}

	base := time.Now().UTC().Truncate(time.Second)
	counts := map[string]int{}
	for i := range 8 {
		selection, err := db.SelectEgressProxyGroupMember(context.Background(), group.ID, base.Add(time.Duration(i)*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		counts[selection.ProxyID]++
		if selection.Priority != 10 || selection.ProxyID == "proxy-c" || selection.Proxy.ID != selection.ProxyID {
			t.Fatalf("selection = %#v", selection)
		}
	}
	if counts["proxy-a"] != 6 || counts["proxy-b"] != 2 || counts["proxy-c"] != 0 {
		t.Fatalf("weighted counts = %#v", counts)
	}

	first, err := db.RecordEgressProxyGroupMemberResult(context.Background(), group.ID, "proxy-a", false, base.Add(time.Second))
	if err != nil || first.ConsecutiveFailures != 1 || first.CircuitOpenUntil != nil {
		t.Fatalf("first failure = %#v / %v", first, err)
	}
	opened, err := db.RecordEgressProxyGroupMemberResult(context.Background(), group.ID, "proxy-a", false, base.Add(2*time.Second))
	if err != nil || opened.CircuitOpenUntil == nil || opened.ConsecutiveFailures != 2 {
		t.Fatalf("opened circuit = %#v / %v", opened, err)
	}
	late, err := db.RecordEgressProxyGroupMemberResult(context.Background(), group.ID, "proxy-a", false, base.Add(3*time.Second))
	if err != nil || late.CircuitOpenUntil == nil || !late.CircuitOpenUntil.Equal(*opened.CircuitOpenUntil) || late.ConsecutiveFailures != 2 {
		t.Fatalf("late failure extended circuit = %#v / %v", late, err)
	}
	selection, err := db.SelectEgressProxyGroupMember(context.Background(), group.ID, base.Add(4*time.Second))
	if err != nil || selection.ProxyID != "proxy-b" {
		t.Fatalf("same-priority fallback = %#v / %v", selection, err)
	}
	for i := 0; i < 2; i++ {
		if _, err := db.RecordEgressProxyGroupMemberResult(context.Background(), group.ID, "proxy-b", false, base.Add(time.Duration(5+i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	selection, err = db.SelectEgressProxyGroupMember(context.Background(), group.ID, base.Add(8*time.Second))
	if err != nil || selection.ProxyID != "proxy-c" || selection.Priority != 20 {
		t.Fatalf("lower-priority fallback = %#v / %v", selection, err)
	}
	for i := 0; i < 2; i++ {
		if _, err := db.RecordEgressProxyGroupMemberResult(context.Background(), group.ID, "proxy-c", false, base.Add(time.Duration(9+i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.SelectEgressProxyGroupMember(context.Background(), group.ID, base.Add(11*time.Second)); !errors.Is(err, ErrNoAvailableEgressProxy) {
		t.Fatalf("all-open selection error = %v", err)
	}
	afterCooldown, err := db.SelectEgressProxyGroupMember(context.Background(), group.ID, base.Add(2*time.Minute))
	if err != nil || afterCooldown.Priority != 10 || (afterCooldown.ProxyID != "proxy-a" && afterCooldown.ProxyID != "proxy-b") {
		t.Fatalf("after cooldown selection = %#v / %v", afterCooldown, err)
	}
	reset, err := db.RecordEgressProxyGroupMemberResult(context.Background(), group.ID, "proxy-a", true, base.Add(3*time.Minute))
	if err != nil || reset.ConsecutiveFailures != 0 || reset.CircuitOpenUntil != nil || reset.LastSuccessAt == nil {
		t.Fatalf("success reset = %#v / %v", reset, err)
	}
}

func TestEgressProxyGroupUpdatePreservesHealthAndCascadeIsSafe(t *testing.T) {
	db := newEgressProxyTestDB(t)
	createProxyGroupTestProxy(t, db, "proxy-a", "owner-1", true)
	createProxyGroupTestProxy(t, db, "proxy-b", "owner-1", false)
	group := createProxyGroupTestGroup(t, db, "group-update", "owner-1",
		EgressProxyGroupMember{ProxyID: "proxy-a", Priority: 0, Weight: 1, Enabled: true},
		EgressProxyGroupMember{ProxyID: "proxy-b", Priority: 1, Weight: 1, Enabled: true},
	)
	base := time.Now().UTC().Truncate(time.Second)
	for range 2 {
		if _, err := db.RecordEgressProxyGroupMemberResult(context.Background(), group.ID, "proxy-a", false, base); err != nil {
			t.Fatal(err)
		}
	}
	group.Name = " Updated "
	updated, err := db.UpdateEgressProxyGroup(context.Background(), group)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Updated" || updated.Members[0].CircuitOpenUntil == nil || updated.Members[0].ConsecutiveFailures != 2 {
		t.Fatalf("updated group lost health = %#v", updated)
	}
	if _, err := db.SelectEgressProxyGroupMember(context.Background(), group.ID, base.Add(time.Second)); !errors.Is(err, ErrNoAvailableEgressProxy) {
		t.Fatalf("open primary plus disabled proxy should fail closed: %v", err)
	}
	if err := db.DeleteEgressProxy(context.Background(), "proxy-a"); err != nil {
		t.Fatal(err)
	}
	afterDelete, err := db.GetEgressProxyGroup(context.Background(), group.ID)
	if err != nil || len(afterDelete.Members) != 1 || afterDelete.Members[0].ProxyID != "proxy-b" {
		t.Fatalf("proxy cascade = %#v / %v", afterDelete, err)
	}
	if err := db.DeleteEgressProxyGroup(context.Background(), group.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetEgressProxyGroup(context.Background(), group.ID); !errors.Is(err, ErrEgressProxyGroupNotFound) {
		t.Fatalf("deleted group error = %v", err)
	}
	var members int
	if err := db.QueryRow(`SELECT COUNT(*) FROM egress_proxy_group_members WHERE group_id = ?`, group.ID).Scan(&members); err != nil || members != 0 {
		t.Fatalf("member cascade count = %d / %v", members, err)
	}
}

func TestEgressProxyGroupConcurrentSelectionKeepsExactWeightRatio(t *testing.T) {
	db := newEgressProxyTestDB(t)
	createProxyGroupTestProxy(t, db, "proxy-a", "owner-1", true)
	createProxyGroupTestProxy(t, db, "proxy-b", "owner-1", true)
	group := createProxyGroupTestGroup(t, db, "group-concurrent", "owner-1",
		EgressProxyGroupMember{ProxyID: "proxy-a", Priority: 0, Weight: 3, Enabled: true},
		EgressProxyGroupMember{ProxyID: "proxy-b", Priority: 0, Weight: 1, Enabled: true},
	)
	const requests = 40
	start := make(chan struct{})
	results := make(chan string, requests)
	errs := make(chan error, requests)
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			selection, err := db.SelectEgressProxyGroupMember(context.Background(), group.ID, time.Unix(int64(1_800_000_000+i), 0))
			if err != nil {
				errs <- err
				return
			}
			results <- selection.ProxyID
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent selection: %v", err)
	}
	counts := map[string]int{}
	for id := range results {
		counts[id]++
	}
	if counts["proxy-a"] != 30 || counts["proxy-b"] != 10 {
		t.Fatalf("concurrent counts = %#v", counts)
	}
}

func TestEgressProxyGroupSelectionRejectsDisabledGroupAndMembers(t *testing.T) {
	db := newEgressProxyTestDB(t)
	createProxyGroupTestProxy(t, db, "proxy-a", "owner-1", true)
	createProxyGroupTestProxy(t, db, "proxy-b", "owner-1", true)
	group := createProxyGroupTestGroup(t, db, "group-disabled", "owner-1",
		EgressProxyGroupMember{ProxyID: "proxy-a", Priority: 0, Weight: 1, Enabled: false},
		EgressProxyGroupMember{ProxyID: "proxy-b", Priority: 1, Weight: 1, Enabled: true},
	)
	selection, err := db.SelectEgressProxyGroupMember(context.Background(), group.ID, time.Now())
	if err != nil || selection.ProxyID != "proxy-b" {
		t.Fatalf("disabled member selection = %#v / %v", selection, err)
	}
	group.Enabled = false
	group, err = db.UpdateEgressProxyGroup(context.Background(), group)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SelectEgressProxyGroupMember(context.Background(), group.ID, time.Now()); !errors.Is(err, ErrNoAvailableEgressProxy) {
		t.Fatalf("disabled group selection error = %v", err)
	}
	group.Enabled = true
	for i := range group.Members {
		group.Members[i].Enabled = false
	}
	if _, err := db.UpdateEgressProxyGroup(context.Background(), group); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SelectEgressProxyGroupMember(context.Background(), group.ID, time.Now()); !errors.Is(err, ErrNoAvailableEgressProxy) {
		t.Fatalf("all-disabled members selection error = %v", err)
	}
}

func TestEgressProxyGroupOwnerAssignmentsPickerAndProxySearch(t *testing.T) {
	db := newEgressProxyTestDB(t)
	for _, proxy := range []struct{ id, owner string }{{"owned", "user-1"}, {"assigned", "user-2"}, {"hidden", "user-3"}, {"literal-percent", "user-1"}} {
		createProxyGroupTestProxy(t, db, proxy.id, proxy.owner, true)
	}
	if _, err := db.Exec(`UPDATE egress_proxies SET name = 'Literal % proxy' WHERE id = 'literal-percent'`); err != nil {
		t.Fatal(err)
	}
	ownedGroup := createProxyGroupTestGroup(t, db, "owned-group", "user-1", EgressProxyGroupMember{ProxyID: "owned", Priority: 0, Weight: 1, Enabled: true})
	assignedGroup := createProxyGroupTestGroup(t, db, "assigned-group", "user-2", EgressProxyGroupMember{ProxyID: "assigned", Priority: 0, Weight: 1, Enabled: true})
	createProxyGroupTestGroup(t, db, "hidden-group", "user-3", EgressProxyGroupMember{ProxyID: "hidden", Priority: 0, Weight: 1, Enabled: true})
	if _, err := db.Exec(`INSERT INTO rbac_users (id, username, display_name, password_hash, enabled, is_builtin, created_at, updated_at) VALUES ('user-1', 'user-1', 'User 1', 'unused', 1, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if created, err := db.AssignResourcesToUser("user-1", "egress_proxy_group", []string{assignedGroup.ID}); err != nil || created != 1 {
		t.Fatalf("assign group = %d / %v", created, err)
	}
	groups, err := db.ListEgressProxyGroups(context.Background(), "user-1", RBACScopeOwn)
	if err != nil || len(groups) != 2 {
		t.Fatalf("visible groups = %#v / %v", groups, err)
	}
	if !db.UserCanAccessResource("user-1", RBACScopeOwn, "egress_proxy_group", ownedGroup.ID) || !db.UserCanAccessResource("user-1", RBACScopeOwn, "egress_proxy_group", assignedGroup.ID) {
		t.Fatalf("group ownership/assignment access failed")
	}
	options, err := db.ListAssignableRBACResources("egress_proxy_group", "assigned", 10)
	if err != nil || len(options) != 1 || options[0].ID != assignedGroup.ID || strings.Contains(strings.ToLower(options[0].Detail), "credential") {
		t.Fatalf("group picker = %#v / %v", options, err)
	}
	if total, err := db.CountAssignableRBACResources("egress_proxy_group", "group"); err != nil || total != 3 {
		t.Fatalf("group picker count = %d / %v", total, err)
	}

	items, total, err := db.SearchEgressProxies(context.Background(), "user-1", RBACScopeOwn, "owned", 10, 0)
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != "owned" {
		t.Fatalf("scoped proxy search = %#v / %d / %v", items, total, err)
	}
	items, total, err = db.SearchEgressProxies(context.Background(), "admin", RBACScopeAll, "%", 10, 0)
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != "literal-percent" {
		t.Fatalf("literal wildcard search = %#v / %d / %v", items, total, err)
	}
	if _, _, err := db.SearchEgressProxies(context.Background(), "admin", RBACScopeAll, "", 101, 0); err == nil {
		t.Fatal("invalid search limit accepted")
	}
}

func TestEgressProxyGroupValidationAndSchemaConstraints(t *testing.T) {
	db := newEgressProxyTestDB(t)
	createProxyGroupTestProxy(t, db, "proxy-a", "owner-1", true)
	for _, group := range []EgressProxyGroup{
		{ID: "bad-name", Name: "", Enabled: true, FailureThreshold: 2, CooldownSeconds: 60, OwnerUserID: "owner", Members: []EgressProxyGroupMember{{ProxyID: "proxy-a", Weight: 1, Enabled: true}}},
		{ID: "bad-threshold", Name: "Bad", Enabled: true, FailureThreshold: 0, CooldownSeconds: 60, OwnerUserID: "owner", Members: []EgressProxyGroupMember{{ProxyID: "proxy-a", Weight: 1, Enabled: true}}},
		{ID: "bad-cooldown", Name: "Bad", Enabled: true, FailureThreshold: 2, CooldownSeconds: 0, OwnerUserID: "owner", Members: []EgressProxyGroupMember{{ProxyID: "proxy-a", Weight: 1, Enabled: true}}},
		{ID: "bad-empty", Name: "Bad", Enabled: true, FailureThreshold: 2, CooldownSeconds: 60, OwnerUserID: "owner", Members: nil},
		{ID: "bad-missing", Name: "Bad", Enabled: true, FailureThreshold: 2, CooldownSeconds: 60, OwnerUserID: "owner", Members: []EgressProxyGroupMember{{ProxyID: "missing", Weight: 1, Enabled: true}}},
		{ID: "bad-duplicate", Name: "Bad", Enabled: true, FailureThreshold: 2, CooldownSeconds: 60, OwnerUserID: "owner", Members: []EgressProxyGroupMember{{ProxyID: "proxy-a", Weight: 1, Enabled: true}, {ProxyID: "proxy-a", Weight: 1, Enabled: true}}},
	} {
		if _, err := db.CreateEgressProxyGroup(context.Background(), group); err == nil {
			t.Fatalf("invalid group %#v succeeded", group)
		}
	}
	if _, err := db.Exec(`INSERT INTO egress_proxy_groups (id,name,enabled,failure_threshold,cooldown_seconds,fail_closed,owner_user_id,created_at,updated_at) VALUES ('unsafe','Unsafe',1,3,60,0,'owner',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err == nil {
		t.Fatal("fail_closed=0 bypassed database constraint")
	}
}
