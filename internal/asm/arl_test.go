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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/user/login":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"token": "test-token"}})
		case "/api/policy/":
			if r.Header.Get("Token") != "test-token" || r.URL.Query().Get("name") != "CyberStrikeAI · 快速探测" {
				t.Errorf("unexpected policy query: header=%q query=%s", r.Header.Get("Token"), r.URL.RawQuery)
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
	second, err := adapter.CreateTemplate(context.Background(), connection, request)
	if err != nil {
		t.Fatal(err)
	}
	if valueMap(second)["reused"] != true || valueMap(second)["updated"] != true || addCalls != 1 || editCalls != 1 {
		t.Fatalf("second create should reuse and calibrate upstream policy: result=%#v add_calls=%d edit_calls=%d", second, addCalls, editCalls)
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
