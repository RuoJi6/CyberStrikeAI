package asm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
)

func TestBuildARLTaskRequestModes(t *testing.T) {
	endpoint, body, err := buildARLTaskRequest(TaskRequest{
		Name: "direct", Target: "192.0.2.10",
		Options: map[string]interface{}{"task_mode": "direct", "port_scan": true, "port_scan_type": "top100", "site_capture": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "/api/task/" || body["port_scan_type"] != "top100" || body["site_capture"] != true {
		t.Fatalf("unexpected direct request: endpoint=%s body=%#v", endpoint, body)
	}
	const policyID = "64b000000000000000000001"
	endpoint, body, err = buildARLTaskRequest(TaskRequest{
		Name: "policy", Target: "192.0.2.11",
		Options: map[string]interface{}{"task_mode": "policy", "policy_id": policyID, "task_tag": "risk_cruising"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "/api/task/policy/" || body["policy_id"] != policyID || body["task_tag"] != "risk_cruising" {
		t.Fatalf("unexpected policy request: endpoint=%s body=%#v", endpoint, body)
	}
	for name, request := range map[string]TaskRequest{
		"direct rejects custom ports": {Target: "192.0.2.10", Options: map[string]interface{}{"port_custom": "80,443"}},
		"policy requires id":          {Target: "192.0.2.10", Options: map[string]interface{}{"task_mode": "policy"}},
		"direct rejects custom enum":  {Target: "192.0.2.10", Options: map[string]interface{}{"port_scan_type": "custom"}},
		"strict boolean":              {Target: "192.0.2.10", Options: map[string]interface{}{"port_scan": "yes"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := buildARLTaskRequest(request); err == nil {
				t.Fatal("expected invalid ARL request to fail")
			}
		})
	}
}

func TestARLTaskProfileMarksPolicyOnlyFields(t *testing.T) {
	profileValue, err := NewARLAdapter().GetTaskProfile(context.Background(), &Connection{Resource: &database.ASMResource{ID: "arl-profile"}})
	if err != nil {
		t.Fatal(err)
	}
	profile := profileValue.(map[string]interface{})
	options := profile["create_options"].(map[string]interface{})
	for _, field := range []string{"policy_id", "task_tag", "result_set_id"} {
		definition := options[field].(map[string]interface{})
		if definition["mode"] != "policy" {
			t.Fatalf("%s should be marked policy-only: %#v", field, definition)
		}
	}
	if definition := options["port_scan"].(map[string]interface{}); definition["mode"] == "policy" {
		t.Fatalf("direct option port_scan must not be marked policy-only: %#v", definition)
	}
	templateOptions := profile["template_create_options"].(map[string]interface{})
	for _, field := range []string{"port_scan_type", "port_custom", "port_parallelism", "poc_selection", "brute_selection"} {
		if _, exists := templateOptions[field]; !exists {
			t.Fatalf("ARL profile omits template field %q: %#v", field, templateOptions)
		}
	}
	if _, exists := templateOptions["ports"]; exists {
		t.Fatal("ARL profile must not advertise ScopeSentry's ports alias")
	}
}

func TestARLPolicyTaskReturnsPolicyNameExecutionProfile(t *testing.T) {
	const policyID = "64b000000000000000000001"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/user/login":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"token": "test-token"}})
		case "/api/task/policy/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"task_id": "64b000000000000000000099"}})
		case "/api/policy/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "items": []interface{}{
				map[string]interface{}{"_id": policyID, "name": "CyberStrikeAI · 外网全量策略", "policy": map[string]interface{}{}},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := NewARLAdapter().CreateTask(context.Background(), &Connection{
		Resource: &database.ASMResource{ID: "asm-arl-policy", Provider: ProviderARL, BaseURL: server.URL, Username: "admin", AuthType: "password", VerifyTLS: true},
		Secret:   "password",
	}, TaskRequest{Name: "policy task", Target: "192.0.2.20", Options: map[string]interface{}{
		"task_mode": "policy", "policy_id": policyID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	profile := valueMap(valueMap(result)["execution_profile"])
	if meaningfulString(profile["id"]) != policyID || meaningfulString(profile["name"]) != "CyberStrikeAI · 外网全量策略" {
		t.Fatalf("ARL policy execution profile missing: %#v", profile)
	}
}

func TestARLCreateTaskResolvesMissingIDFromTaskList(t *testing.T) {
	const taskID = "64b000000000000000000099"
	listCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/user/login":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"token": "test-token"}})
		case "/api/task/":
			if r.Method == http.MethodPost {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "message": "success"})
				return
			}
			listCalls++
			if r.URL.Query().Get("name") != "resolve missing id" || r.URL.Query().Get("target") != "192.0.2.25" {
				t.Errorf("unexpected task lookup query: %s", r.URL.RawQuery)
			}
			if listCalls == 1 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "items": []interface{}{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "items": []interface{}{
				map[string]interface{}{"_id": taskID, "name": "resolve missing id", "target": "192.0.2.25", "status": "waiting"},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := NewARLAdapter().CreateTask(context.Background(), &Connection{
		Resource: &database.ASMResource{ID: "asm-arl-resolve", Provider: ProviderARL, BaseURL: server.URL, Username: "admin", AuthType: "password", VerifyTLS: true},
		Secret:   "password",
	}, TaskRequest{Name: "resolve missing id", Target: "192.0.2.25"})
	if err != nil {
		t.Fatal(err)
	}
	if listCalls != 2 {
		t.Fatalf("expected eventual-consistency retry, got %d task-list lookups", listCalls)
	}
	object := valueMap(result)
	if meaningfulString(object["task_id_resolution"]) != "task_list" || remoteTaskID(ProviderARL, result) != taskID {
		t.Fatalf("ARL task ID was not resolved from the task list: %#v", result)
	}
	entries := createdTaskEntries(ProviderARL, TaskRequest{Name: "resolve missing id", Target: "192.0.2.25"}, result)
	if len(entries) != 1 || entries[0].RemoteID != taskID {
		t.Fatalf("resolved ARL task was not recordable: %#v", entries)
	}
}

func TestARLFetchScreenshotUsesAPINamespace(t *testing.T) {
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F'}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/user/login":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"token": "test-token"}})
		case "/api/image/task-one/site.jpg":
			if r.Header.Get("Token") != "test-token" {
				t.Errorf("missing ARL token: %q", r.Header.Get("Token"))
			}
			w.Header().Set("Content-Type", "image/jpg")
			_, _ = w.Write(jpeg)
		default:
			t.Errorf("unexpected screenshot path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	data, contentType, err := NewARLAdapter().FetchScreenshot(context.Background(), &Connection{
		Resource: &database.ASMResource{ID: "asm_arl_screenshot", Provider: ProviderARL, BaseURL: server.URL, Username: "admin", AuthType: "password", VerifyTLS: true},
		Secret:   "password",
	}, "/image/task-one/site.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "image/jpeg" || !reflect.DeepEqual(data, jpeg) {
		t.Fatalf("unexpected screenshot: type=%q data=%x", contentType, data)
	}
}

func TestARLReusesTokenAcrossAuthenticatedRequests(t *testing.T) {
	loginCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/user/login":
			loginCalls++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"token": "stable-token"}})
		case "/api/console/info":
			if r.Header.Get("Token") != "stable-token" {
				t.Errorf("unexpected console token: %q", r.Header.Get("Token"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"version": "2.6.3"}})
		case "/api/task/":
			if r.Header.Get("Token") != "stable-token" {
				t.Errorf("unexpected task token: %q", r.Header.Get("Token"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "items": []interface{}{}, "total": 0})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connection := &Connection{
		Resource: &database.ASMResource{ID: "asm_arl_token", Provider: ProviderARL, BaseURL: server.URL, Username: "admin", AuthType: "password", VerifyTLS: true},
		Secret:   "password",
	}
	adapter := NewARLAdapter()
	if _, err := adapter.Test(context.Background(), connection); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ListTasks(context.Background(), connection, TaskFilter{}); err != nil {
		t.Fatal(err)
	}
	if loginCalls != 1 {
		t.Fatalf("expected one shared ARL login, got %d", loginCalls)
	}
}

func TestARLRefreshesRejectedCachedTokenOnce(t *testing.T) {
	loginCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/user/login":
			loginCalls++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"token": fmt.Sprintf("token-%d", loginCalls)}})
		case "/api/task/":
			if r.Header.Get("Token") == "token-1" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 401, "message": "not login"})
				return
			}
			if r.Header.Get("Token") != "token-2" {
				t.Errorf("unexpected refreshed token: %q", r.Header.Get("Token"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "items": []interface{}{}, "total": 0})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connection := &Connection{
		Resource: &database.ASMResource{ID: "asm_arl_retry", Provider: ProviderARL, BaseURL: server.URL, Username: "admin", AuthType: "password", VerifyTLS: true},
		Secret:   "password",
	}
	if _, err := NewARLAdapter().ListTasks(context.Background(), connection, TaskFilter{}); err != nil {
		t.Fatal(err)
	}
	if loginCalls != 2 {
		t.Fatalf("expected one token refresh after 401, got %d logins", loginCalls)
	}
}

func TestARLAlreadyFinishedStopErrorIsTyped(t *testing.T) {
	err := arlResponseError(map[string]interface{}{"code": 105, "message": "任务已经完成"})
	var apiErr *arlAPIError
	if !errors.As(err, &apiErr) || apiErr.Code != "105" || apiErr.Message != "任务已经完成" {
		t.Fatalf("unexpected typed ARL error: %#v", err)
	}
}

func TestBuildARLPolicyRequestUsesNativePolicyShape(t *testing.T) {
	body, err := buildARLPolicyRequest(TemplateRequest{
		Name: "CyberStrikeAI · 全量扫描",
		Options: map[string]interface{}{
			"domain_brute": true, "domain_brute_type": "big", "port_scan": true,
			"port_scan_type": "all", "service_detection": true, "os_detection": true,
			"site_identify": true, "site_capture": true, "nuclei_scan": true,
			"host_timeout_type": "custom", "host_timeout": 1800, "port_parallelism": 32, "port_min_rate": 80,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, ok := body["policy"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing native policy body: %#v", body)
	}
	domain := policy["domain_config"].(map[string]interface{})
	ip := policy["ip_config"].(map[string]interface{})
	site := policy["site_config"].(map[string]interface{})
	if domain["domain_brute_type"] != "big" || ip["port_scan_type"] != "all" || ip["host_timeout"] != 1800 {
		t.Fatalf("unexpected full scan policy: %#v", policy)
	}
	if site["site_capture"] != true || site["nuclei_scan"] != true {
		t.Fatalf("unexpected site policy: %#v", site)
	}
	if _, exists := policy["poc_config"]; !exists {
		t.Fatal("ARL add policy request must include poc_config")
	}
}

func TestBuildARLPolicyRequestRejectsUnsafeOrUnknownOptions(t *testing.T) {
	for name, options := range map[string]map[string]interface{}{
		"unknown":       {"command_line": "nmap -p-"},
		"invalid ports": {"port_scan_type": "custom", "port_custom": "80;whoami"},
		"invalid bool":  {"site_capture": "yes"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildARLPolicyRequest(TemplateRequest{Name: "invalid", Options: options}); err == nil {
				t.Fatal("expected invalid ARL policy request to fail")
			}
		})
	}
}

func TestARLCreateBuiltInPolicyIsUpstreamAndIdempotent(t *testing.T) {
	const policyID = "64b000000000000000000009"
	created := false
	addCalls := 0
	editCalls := 0
	var storedPolicy map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/user/login":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"token": "test-token"}})
		case "/api/policy/":
			if r.Header.Get("Token") != "test-token" {
				t.Errorf("unexpected policy query: header=%q query=%s", r.Header.Get("Token"), r.URL.RawQuery)
			}
			if r.URL.Query().Get("_id") == policyID {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "items": []interface{}{map[string]interface{}{"_id": policyID, "name": "CyberStrikeAI · 快速探测", "policy": storedPolicy}}, "total": 1})
				return
			}
			if r.URL.Query().Get("name") != "CyberStrikeAI · 快速探测" {
				t.Errorf("unexpected policy name query: %s", r.URL.RawQuery)
			}
			items := []interface{}{}
			if created {
				items = append(items, map[string]interface{}{"_id": policyID, "name": "CyberStrikeAI · 快速探测"})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "items": items, "total": len(items)})
		case "/api/policy/add/":
			addCalls++
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			policy := body["policy"].(map[string]interface{})
			ip := policy["ip_config"].(map[string]interface{})
			if ip["port_scan_type"] != "top100" {
				t.Errorf("unexpected policy body: %#v", body)
			}
			storedPolicy = policy
			created = true
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"policy_id": policyID}})
		case "/api/policy/edit/":
			editCalls++
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body["policy_id"] != policyID {
				t.Errorf("unexpected edit body: %#v", body)
			}
			storedPolicy = valueMap(valueMap(body["policy_data"])["policy"])
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": body["policy_data"]})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	connection := &Connection{
		Resource: &database.ASMResource{ID: "asm_arl_test", Provider: ProviderARL, BaseURL: server.URL, Username: "admin", AuthType: "password", VerifyTLS: true},
		Secret:   "password",
	}
	request, err := applyTemplatePreset(ProviderARL, TemplateRequest{PresetID: "quick_discovery"})
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewARLAdapter()
	first, err := adapter.CreateTemplate(context.Background(), connection, request)
	if err != nil {
		t.Fatal(err)
	}
	if valueMap(first)["reused"] != false {
		t.Fatalf("first create should not reuse: %#v", first)
	}
	if valueMap(first)["template_verified"] != true || valueMap(valueMap(first)["effective_policy"])["ip_config"] == nil {
		t.Fatalf("first create must return verified upstream policy: %#v", first)
	}
	second, err := adapter.CreateTemplate(context.Background(), connection, request)
	if err != nil {
		t.Fatal(err)
	}
	if valueMap(second)["reused"] != true || valueMap(second)["updated"] != true || valueMap(second)["template_verified"] != true || addCalls != 1 || editCalls != 1 {
		t.Fatalf("second create should reuse and calibrate upstream policy: result=%#v add_calls=%d edit_calls=%d", second, addCalls, editCalls)
	}
}

func TestARLCreateCustomPolicyReturnsVerifiedEffectiveConfiguration(t *testing.T) {
	const policyID = "64b00000000000000000000b"
	var storedPolicy map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/user/login":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"token": "test-token"}})
		case "/api/policy/":
			if r.URL.Query().Get("_id") == policyID {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "items": []interface{}{map[string]interface{}{"_id": policyID, "name": "CyberStrike 自定义端口", "policy": storedPolicy}}, "total": 1})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "items": []interface{}{}, "total": 0})
		case "/api/policy/add/":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			storedPolicy = valueMap(body["policy"])
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"policy_id": policyID}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := NewARLAdapter().CreateTemplate(context.Background(), &Connection{
		Resource: &database.ASMResource{ID: "asm_arl_custom", Provider: ProviderARL, BaseURL: server.URL, Username: "admin", AuthType: "password", VerifyTLS: true},
		Secret:   "password",
	}, TemplateRequest{
		Name: "CyberStrike 自定义端口",
		Options: map[string]interface{}{
			"port_scan_type": "custom", "port_custom": "80,443,7001,8080-8090",
			"port_parallelism": 50, "site_capture": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	effective := valueMap(valueMap(result)["effective_policy"])
	ipConfig := valueMap(effective["ip_config"])
	siteConfig := valueMap(effective["site_config"])
	if valueMap(result)["template_verified"] != true || ipConfig["port_scan_type"] != "custom" || ipConfig["port_custom"] != "80,443,7001,8080-8090" || fmt.Sprint(ipConfig["port_parallelism"]) != "50" || siteConfig["site_capture"] != true {
		t.Fatalf("custom ARL policy was truncated or not verified: %#v", result)
	}
}

func TestARLFullScanPresetSelectsAllPOCAndBrutePlugins(t *testing.T) {
	const policyID = "64b00000000000000000000a"
	var createdPolicy map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/user/login":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"token": "test-token"}})
		case "/api/poc/":
			var items []interface{}
			switch r.URL.Query().Get("plugin_type") {
			case "poc":
				items = []interface{}{
					map[string]interface{}{"plugin_name": "poc-one", "vul_name": "POC One"},
					map[string]interface{}{"plugin_name": "poc-two", "vul_name": "POC Two"},
				}
			case "brute":
				items = []interface{}{map[string]interface{}{"plugin_name": "ssh-brute", "vul_name": "SSH 弱口令"}}
			default:
				t.Errorf("unexpected plugin query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "items": items, "total": len(items)})
		case "/api/policy/":
			if r.URL.Query().Get("_id") == policyID {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "items": []interface{}{map[string]interface{}{"_id": policyID, "name": "CyberStrikeAI · 全量扫描", "policy": createdPolicy}}, "total": 1})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "items": []interface{}{}, "total": 0})
		case "/api/policy/add/":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			createdPolicy = valueMap(body["policy"])
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"policy_id": policyID}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	request, err := applyTemplatePreset(ProviderARL, TemplateRequest{PresetID: "full_scan"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewARLAdapter().CreateTemplate(context.Background(), &Connection{
		Resource: &database.ASMResource{ID: "asm_arl_full", Provider: ProviderARL, BaseURL: server.URL, Username: "admin", AuthType: "password", VerifyTLS: true},
		Secret:   "password",
	}, request)
	if err != nil {
		t.Fatal(err)
	}
	if createdPolicy == nil {
		t.Fatal("full scan policy was not created")
	}
	pocConfig, _ := createdPolicy["poc_config"].([]interface{})
	bruteConfig, _ := createdPolicy["brute_config"].([]interface{})
	if len(pocConfig) != 2 || len(bruteConfig) != 1 {
		t.Fatalf("full scan must select every live POC and brute plugin: policy=%#v", createdPolicy)
	}
	for _, raw := range append(pocConfig, bruteConfig...) {
		item := valueMap(raw)
		if item["enable"] != true || strings.TrimSpace(fmt.Sprint(item["plugin_name"])) == "" {
			t.Fatalf("invalid policy plugin selection: %#v", item)
		}
	}
	summary := valueMap(valueMap(result)["plugin_summary"])
	if summary["poc_count"] != 2 || summary["brute_count"] != 1 {
		t.Fatalf("unexpected plugin summary: %#v", summary)
	}
	if valueMap(result)["template_verified"] != true || valueMap(valueMap(result)["effective_policy"])["poc_config"] == nil {
		t.Fatalf("full scan policy must be verified from upstream: %#v", result)
	}
}

func TestARLResultTypesMatchUpstreamTaskDetailCollections(t *testing.T) {
	want := []string{"site", "domain", "ip", "cert", "service", "fileleak", "url", "vulnerability", "npoc_service", "cip", "nuclei_result", "stat_finger", "wih"}
	got := make([]string, 0, len(want))
	for _, item := range providerResultTypes(ProviderARL) {
		got = append(got, item.ID)
		if _, ok := arlAssetEndpoints[item.ID]; !ok {
			t.Fatalf("ARL result type %q has no endpoint", item.ID)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ARL result types=%v want=%v", got, want)
	}
}

func TestARLPipelineProgressUsesCompletedStages(t *testing.T) {
	task := map[string]interface{}{
		"service": []interface{}{map[string]interface{}{"name": "port_scan"}, map[string]interface{}{"name": "ssl_cert"}},
		"options": map[string]interface{}{"port_scan": true, "ssl_cert": true, "site_identify": true, "file_leak": true},
	}
	progress := arlPipelineProgress(task)
	if progress <= 0 || progress >= 100 {
		t.Fatalf("unexpected running progress: %d", progress)
	}
	if stage := arlPipelineStage(map[string]interface{}{"status": "file_leak"}); stage != "file_leak" {
		t.Fatalf("unexpected ARL stage: %s", stage)
	}
}

func TestProviderResultTypeValidationIsProviderSpecific(t *testing.T) {
	if !providerSupportsResultType(ProviderARL, "nuclei_result") {
		t.Fatal("ARL should expose nuclei_result")
	}
	if providerSupportsResultType(ProviderXingRin, "nuclei_result") || providerSupportsResultType(ProviderScopeSentry, "cert") {
		t.Fatal("provider-specific ARL result collections leaked to other adapters")
	}
}
