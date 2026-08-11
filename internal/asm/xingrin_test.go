package asm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
)

func TestBuildXingRinConfigurationUsesLowLoadDefaults(t *testing.T) {
	configuration, err := buildXingRinConfiguration(map[string]interface{}{
		"ports": "443,8083", "rate_limit": 12, "concurrency": 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`ports: "443,8083"`, "rate: 12", "threads: 3", "naabu_passive:", "enabled: false", "site_scan:",
	} {
		if !strings.Contains(configuration, expected) {
			t.Fatalf("configuration missing %q:\n%s", expected, configuration)
		}
	}
	if _, err := buildXingRinConfiguration(map[string]interface{}{"ports": "0,70000"}); err == nil {
		t.Fatal("expected invalid ports to fail")
	}
	if _, err := buildXingRinConfiguration(map[string]interface{}{"port_scan": false, "site_identify": false}); err == nil {
		t.Fatal("expected empty scan configuration to fail")
	}
}

func TestXingRinAdapterProtocol(t *testing.T) {
	const sessionCookie = "xingrin-test-session"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/auth/login/" {
			var login map[string]string
			if err := json.NewDecoder(r.Body).Decode(&login); err != nil {
				t.Errorf("decode login: %v", err)
			}
			if login["username"] != "admin" || login["password"] != "secret" {
				t.Errorf("unexpected login: %#v", login)
			}
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: sessionCookie, Path: "/"})
			_, _ = w.Write([]byte(`{"user":{"id":1,"username":"admin"}}`))
			return
		}
		cookie, err := r.Cookie("sessionid")
		if err != nil || cookie.Value != sessionCookie {
			http.Error(w, `{"error":{"code":"UNAUTHORIZED"}}`, http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/auth/me/":
			_, _ = w.Write([]byte(`{"authenticated":true,"user":{"id":1,"username":"admin"}}`))
		case r.URL.Path == "/api/engines/":
			_, _ = w.Write([]byte(`[{"id":1,"name":"full scan","configuration":""}]`))
		case r.URL.Path == "/api/scans/quick/":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode task: %v", err)
			}
			if !strings.Contains(body["configuration"].(string), `ports: "8083"`) {
				t.Errorf("unexpected configuration: %v", body["configuration"])
			}
			_, _ = w.Write([]byte(`{"count":1,"scans":[{"id":7,"status":"initiated"}]}`))
		case r.URL.Path == "/api/scans/7/" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"id":7,"targetName":"example.test","status":"completed"}`))
		case r.URL.Path == "/api/scans/":
			_, _ = w.Write([]byte(`{"results":[{"id":7,"status":"completed"}],"total":1,"page":1,"pageSize":20,"totalPages":1}`))
		case r.URL.Path == "/api/scans/7/websites/":
			_, _ = w.Write([]byte(`{"results":[{"id":2,"url":"https://example.test"}],"total":1,"page":1,"pageSize":20,"totalPages":1}`))
		case r.URL.Path == "/api/scans/7/stop/" && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"revokedTaskCount":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	adapter := NewXingRinAdapter()
	conn := &Connection{Resource: &database.ASMResource{
		ID: "asm_xingrin", Provider: ProviderXingRin, BaseURL: server.URL,
		Username: "admin", AuthType: "password", VerifyTLS: false, Enabled: true,
	}, Secret: "secret"}
	ctx := context.Background()

	if _, err := adapter.Test(ctx, conn); err != nil {
		t.Fatalf("test connection: %v", err)
	}
	if _, err := adapter.CreateTask(ctx, conn, TaskRequest{Target: "example.test", Options: map[string]interface{}{"ports": "8083"}}); err != nil {
		t.Fatalf("create task: %v", err)
	}
	if _, err := adapter.ListTasks(ctx, conn, TaskFilter{Page: 1, PageSize: 20}); err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	if _, err := adapter.GetTask(ctx, conn, "7"); err != nil {
		t.Fatalf("get task: %v", err)
	}
	if _, err := adapter.ListAssets(ctx, conn, AssetFilter{TaskID: "7", Type: "site", Page: 1, PageSize: 20}); err != nil {
		t.Fatalf("list assets: %v", err)
	}
	if _, err := adapter.StopTask(ctx, conn, "7"); err != nil {
		t.Fatalf("stop task: %v", err)
	}
}
