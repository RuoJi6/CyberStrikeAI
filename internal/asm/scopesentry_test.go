package asm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"cyberstrike-ai/internal/database"
)

func TestScopeSentryAdapterProtocol(t *testing.T) {
	const (
		taskID        = "64b000000000000000000001"
		defaultID     = "64b000000000000000000002"
		profileID     = "64b000000000000000000003"
		token         = "test-jwt-token"
		secret        = "scope-password"
		name          = "Cloud ScopeSentry E2E"
		portHash      = "port-plugin-hash"
		handleHash    = "asset-handle-hash"
		mapHash       = "asset-map-hash"
		fingerHash    = "finger-hash"
		scheduledID   = "64b000000000000000000004"
		scheduledName = "Cloud ScopeSentry Scheduled"
	)

	var mu sync.Mutex
	profileCreated, taskCreated, scheduledCreated := false, false, false
	profileName := scopeSentryLowLoadTemplateName("22", 2, true, false, false, false)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/user/login" {
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode login: %v", err)
			}
			if body["username"] != "admin" || body["password"] != secret {
				t.Errorf("unexpected login body: %#v", body)
			}
			_, _ = fmt.Fprintf(w, `{"code":200,"data":{"access_token":%q}}`, token)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("missing bearer token on %s", r.URL.Path)
			http.Error(w, `{"code":401}`, http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/api/node/online":
			_, _ = w.Write([]byte(`{"code":200,"data":{"list":["node-test","node-backup"]}}`))
		case "/api/task/template":
			mu.Lock()
			created := profileCreated
			mu.Unlock()
			items := []map[string]interface{}{{"id": defaultID, "name": "default"}}
			if created {
				items = append(items, map[string]interface{}{"id": profileID, "name": profileName})
			}
			writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": map[string]interface{}{"list": items, "total": len(items)}})
		case "/api/task/template/detail":
			writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": scopeSentryTestDefaultTemplate(defaultID, portHash, handleHash, mapHash, fingerHash)})
		case "/api/task/template/save":
			var body struct {
				ID     string                 `json:"id"`
				Result map[string]interface{} `json:"result"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode template save: %v", err)
			}
			if body.Result["name"] != profileName {
				t.Errorf("unexpected template name: %#v", body.Result["name"])
			}
			if got := fmt.Sprint(scopeSentryMap(scopeSentryMap(body.Result["Parameters"])["PortScan"])[portHash]); !strings.Contains(got, "-port 22") || !strings.Contains(got, "-b 2") {
				t.Errorf("unexpected port profile: %q", got)
			}
			if got, _ := body.Result["SubdomainScan"].([]interface{}); len(got) != 0 {
				t.Errorf("subdomain scan was not pruned: %#v", got)
			}
			if got, _ := body.Result["AssetMapping"].([]interface{}); len(got) != 0 {
				t.Errorf("asset mapping was not disabled: %#v", got)
			}
			if got, _ := body.Result["PortFingerprint"].([]interface{}); len(got) == 0 {
				t.Errorf("port fingerprint was disabled, so open ports cannot reach asset handling")
			}
			mu.Lock()
			profileCreated = true
			mu.Unlock()
			_, _ = w.Write([]byte(`{"code":200}`))
		case "/api/task/add":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode task add: %v", err)
			}
			if body["name"] != name || body["target"] != "192.0.2.10" || body["template"] != profileID {
				t.Errorf("unexpected task body: %#v", body)
			}
			mu.Lock()
			taskCreated = true
			mu.Unlock()
			_, _ = w.Write([]byte(`{"code":200}`))
		case "/api/task/scheduled/add":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode scheduled task add: %v", err)
			}
			if body["name"] != scheduledName || body["target"] != "192.0.2.20" || body["template"] != profileID || body["scheduledTasks"] != true {
				t.Errorf("unexpected scheduled task body: %#v", body)
			}
			mu.Lock()
			scheduledCreated = true
			mu.Unlock()
			_, _ = w.Write([]byte(`{"code":200}`))
		case "/api/task/":
			mu.Lock()
			created := taskCreated
			mu.Unlock()
			items := []map[string]interface{}{}
			if created {
				items = append(items, map[string]interface{}{"id": taskID, "name": name, "status": 1, "progress": 10})
			}
			writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": map[string]interface{}{"list": items, "total": len(items)}})
		case "/api/task/scheduled":
			mu.Lock()
			created := scheduledCreated
			mu.Unlock()
			items := []map[string]interface{}{}
			if created {
				items = append(items, map[string]interface{}{"id": scheduledID, "name": scheduledName, "scheduledTasks": true, "cycleType": "daily"})
			}
			writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": map[string]interface{}{"list": items, "total": len(items)}})
		case "/api/task/detail":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode task detail: %v", err)
			}
			if body["id"] == scheduledID {
				http.Error(w, `{"code":500,"data":"task not found"}`, http.StatusInternalServerError)
				return
			}
			writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": map[string]interface{}{"id": taskID, "name": name, "status": 3, "progress": 100}})
		case "/api/task/scheduled/detail":
			writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": map[string]interface{}{"id": scheduledID, "name": scheduledName, "scheduledTasks": true, "cycleType": "daily"}})
		case "/api/assets/ip":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode asset list: %v", err)
			}
			if got := fmt.Sprint(body["search"]); got != `task="`+name+`"` {
				t.Errorf("unexpected task asset filter: %q", got)
			}
			writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": map[string]interface{}{"list": []interface{}{map[string]interface{}{"ip": "192.0.2.10", "port": "22"}}, "total": 1}})
		case "/api/assets/common/total":
			writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": map[string]interface{}{"total": 1}})
		case "/api/task/stop":
			_, _ = w.Write([]byte(`{"code":200}`))
		case "/api/task/start":
			_, _ = w.Write([]byte(`{"code":200}`))
		case "/api/task/retest":
			_, _ = w.Write([]byte(`{"code":200}`))
		case "/api/task/delete":
			_, _ = w.Write([]byte(`{"code":200}`))
		case "/api/task/scheduled/delete":
			_, _ = w.Write([]byte(`{"code":200}`))
		case "/api/dictionary/port/data":
			_, _ = w.Write([]byte(`{"code":200,"data":{"list":[{"id":"top100","name":"TOP100","value":"1-65535"}]}}`))
		case "/api/poc":
			_, _ = w.Write([]byte(`{"code":200,"data":{"list":[{"id":"64b000000000000000000009","name":"Safe POC","content":"very large yaml","tags":["safe"]}],"total":1}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	adapter := NewScopeSentryAdapter()
	resource := &database.ASMResource{
		ID: "asm_scope_test", Provider: ProviderScopeSentry, BaseURL: server.URL,
		Username: "admin", AuthType: "password", VerifyTLS: false, Enabled: true,
	}
	connection := &Connection{Resource: resource, Secret: secret}
	ctx := context.Background()
	if result, err := adapter.Test(ctx, connection); err != nil || !strings.Contains(fmt.Sprint(result), "connected") {
		t.Fatalf("Test result=%#v err=%v", result, err)
	}
	if result, err := adapter.GetTaskProfile(ctx, connection); err != nil || !strings.Contains(fmt.Sprint(result), "template_id") {
		t.Fatalf("GetTaskProfile result=%#v err=%v", result, err)
	}
	if result, err := adapter.ListTaskOptions(ctx, connection, TaskOptionFilter{Kind: "port_dictionaries"}); err != nil || !strings.Contains(fmt.Sprint(result), "TOP100") {
		t.Fatalf("ListTaskOptions result=%#v err=%v", result, err)
	}
	if result, err := adapter.ListTaskOptions(ctx, connection, TaskOptionFilter{Kind: "port_dictionaries"}); err != nil || strings.Contains(fmt.Sprint(result), "1-65535") {
		t.Fatalf("port dictionary list must not include full values: result=%#v err=%v", result, err)
	}
	if result, err := adapter.ListTaskOptions(ctx, connection, TaskOptionFilter{Kind: "pocs", Query: "Safe", Page: 1, PageSize: 10}); err != nil || !strings.Contains(fmt.Sprint(result), "Safe POC") || strings.Contains(fmt.Sprint(result), "very large yaml") {
		t.Fatalf("POC list must be compact and searchable: result=%#v err=%v", result, err)
	}
	created, err := adapter.CreateTask(ctx, connection, TaskRequest{
		Name: name, Target: "192.0.2.10",
		Options: map[string]interface{}{"ports": "22", "port_scan": true, "site_identify": false, "concurrency": 2},
	})
	if err != nil || !strings.Contains(fmt.Sprint(created), taskID) {
		t.Fatalf("CreateTask result=%#v err=%v", created, err)
	}
	if result, err := adapter.ListTasks(ctx, connection, TaskFilter{Page: 1, PageSize: 10}); err != nil || !strings.Contains(fmt.Sprint(result), taskID) {
		t.Fatalf("ListTasks result=%#v err=%v", result, err)
	}
	if result, err := adapter.GetTask(ctx, connection, taskID); err != nil || !strings.Contains(fmt.Sprint(result), "completed") {
		t.Fatalf("GetTask result=%#v err=%v", result, err)
	}
	if result, err := adapter.ListAssets(ctx, connection, AssetFilter{TaskID: taskID, Type: "ip", Page: 1, PageSize: 20}); err != nil || !strings.Contains(fmt.Sprint(result), "192.0.2.10") {
		t.Fatalf("ListAssets result=%#v err=%v", result, err)
	}
	if result, err := adapter.StopTask(ctx, connection, taskID); err != nil || !strings.Contains(fmt.Sprint(result), ProviderScopeSentry) {
		t.Fatalf("StopTask result=%#v err=%v", result, err)
	}
	if result, err := adapter.ManageTask(ctx, connection, TaskManageRequest{Action: "resume", TaskID: taskID}); err != nil || !strings.Contains(fmt.Sprint(result), "resume") {
		t.Fatalf("ManageTask result=%#v err=%v", result, err)
	}
	scheduledTask, err := adapter.CreateTask(ctx, connection, TaskRequest{
		Name: scheduledName, Target: "192.0.2.20",
		Options: map[string]interface{}{"template_id": profileID, "scheduled": true, "cycle_type": "daily", "hour": 3, "minute": 15},
	})
	if err != nil || !strings.Contains(fmt.Sprint(scheduledTask), scheduledID) {
		t.Fatalf("CreateTask scheduled result=%#v err=%v", scheduledTask, err)
	}
	if result, err := adapter.ListTasks(ctx, connection, TaskFilter{Name: scheduledName, Page: 1, PageSize: 10}); err != nil || !strings.Contains(fmt.Sprint(result), scheduledID) {
		t.Fatalf("ListTasks scheduled result=%#v err=%v", result, err)
	}
	if result, err := adapter.GetTask(ctx, connection, scheduledID); err != nil || !strings.Contains(fmt.Sprint(result), "scheduled") {
		t.Fatalf("GetTask scheduled result=%#v err=%v", result, err)
	}
	if _, err := adapter.StopTask(ctx, connection, scheduledID); err == nil || !strings.Contains(err.Error(), "不支持 stop") {
		t.Fatalf("scheduled stop must be rejected, err=%v", err)
	}
	if result, err := adapter.ManageTask(ctx, connection, TaskManageRequest{Action: "delete", TaskID: scheduledID}); err != nil || !strings.Contains(fmt.Sprint(result), "delete") {
		t.Fatalf("ManageTask scheduled delete result=%#v err=%v", result, err)
	}
	if _, err := adapter.GetTask(ctx, connection, "invalid"); err == nil {
		t.Fatal("invalid task id was accepted")
	}
}

func scopeSentryTestDefaultTemplate(id, portHash, handleHash, mapHash, fingerHash string) map[string]interface{} {
	return map[string]interface{}{
		"id": id, "name": "default",
		"SubdomainScan": []interface{}{"sub-hash"}, "PortScan": []interface{}{portHash},
		"PortFingerprint": []interface{}{fingerHash}, "AssetMapping": []interface{}{mapHash},
		"AssetHandle": []interface{}{handleHash}, "URLScan": []interface{}{"url-hash"},
		"Parameters": map[string]interface{}{
			"SubdomainScan":   map[string]interface{}{"sub-hash": "-t 10"},
			"PortScan":        map[string]interface{}{portHash: "-port {port.top1000} -b 500 -t 5000"},
			"PortFingerprint": map[string]interface{}{fingerHash: ""},
			"AssetMapping":    map[string]interface{}{mapHash: "-screenshot true"},
			"AssetHandle":     map[string]interface{}{handleHash: ""},
		},
		"ParameterLists": map[string]interface{}{
			"PortScan":     map[string]interface{}{portHash: "-port {port.top1000} -b 500 -t 5000"},
			"AssetMapping": map[string]interface{}{mapHash: "-screenshot true"},
		},
	}
}

func writeScopeSentryTestJSON(t *testing.T, w http.ResponseWriter, value interface{}) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}
