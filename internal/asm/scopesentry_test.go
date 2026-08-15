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
		customID      = "64b000000000000000000005"
		customName    = "CyberStrikeAI controlled full ports"
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
	var profileTemplate, customTemplate map[string]interface{}
	profileCreated, customCreated, taskCreated, scheduledCreated := false, false, false, false
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
			created, explicitCreated := profileCreated, customCreated
			mu.Unlock()
			items := []map[string]interface{}{{"id": defaultID, "name": "default"}}
			if created {
				items = append(items, map[string]interface{}{"id": profileID, "name": profileName})
			}
			if explicitCreated {
				items = append(items, map[string]interface{}{"id": customID, "name": customName})
			}
			writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": map[string]interface{}{"list": items, "total": len(items)}})
		case "/api/task/template/detail":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode template detail: %v", err)
			}
			mu.Lock()
			profile, explicitProfile := profileTemplate, customTemplate
			mu.Unlock()
			if fmt.Sprint(body["id"]) == profileID && profile != nil {
				writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": profile})
				return
			}
			if fmt.Sprint(body["id"]) == customID && explicitProfile != nil {
				writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": explicitProfile})
				return
			}
			writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": scopeSentryTestDefaultTemplate(defaultID, portHash, handleHash, mapHash, fingerHash)})
		case "/api/task/template/save":
			var body struct {
				ID     string                 `json:"id"`
				Result map[string]interface{} `json:"result"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode template save: %v", err)
			}
			if body.Result["name"] == customName {
				if got := fmt.Sprint(scopeSentryMap(scopeSentryMap(body.Result["Parameters"])["PortScan"])[portHash]); !strings.Contains(got, "-port 1-65535") || !strings.Contains(got, "-b 5") {
					t.Errorf("unexpected controlled template port profile: %q", got)
				}
				if got, _ := body.Result["SubdomainScan"].([]interface{}); len(got) != 0 {
					t.Errorf("controlled template retained disabled subdomain scan: %#v", got)
				}
				mu.Lock()
				body.Result["id"] = customID
				customTemplate = body.Result
				customCreated = true
				mu.Unlock()
				_, _ = w.Write([]byte(`{"code":200}`))
				return
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
			body.Result["id"] = profileID
			profileTemplate = body.Result
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
				items = append(items, map[string]interface{}{"id": taskID, "name": name, "status": 1, "progress": 10, "template": profileID})
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
			writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": map[string]interface{}{"id": taskID, "name": name, "status": 3, "progress": 100, "template": profileID}})
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
		case "/api/plugin":
			plugins := []map[string]interface{}{
				{"name": "subfinder", "module": "SubdomainScan", "hash": "sub-hash", "isSystem": true},
				{"name": "SubdomainTakeover", "module": "SubdomainSecurity", "hash": "takeover-hash", "isSystem": true},
				{"name": "RustScan", "module": "PortScan", "hash": portHash, "parameter": "-port {port.top1000} -b 500", "isSystem": true},
				{"name": "fingerprintx", "module": "PortFingerprint", "hash": fingerHash, "isSystem": true},
				{"name": "httpx", "module": "AssetMapping", "hash": mapHash, "parameter": "-screenshot true", "isSystem": true},
				{"name": "katana", "module": "URLScan", "hash": "url-hash", "isSystem": true},
				{"name": "rad", "module": "WebCrawler", "hash": "crawler-hash", "isSystem": true},
				{"name": "sensitive", "module": "URLSecurity", "hash": "sensitive-hash", "isSystem": true},
				{"name": "trufflehog", "module": "URLSecurity", "hash": "trufflehog-hash", "isSystem": true},
				{"name": "SentryDir", "module": "DirScan", "hash": "dir-hash", "isSystem": true},
				{"name": "nuclei", "module": "VulnerabilityScan", "hash": "vuln-hash", "isSystem": true},
				{"name": "AssetHandle", "module": "AssetHandle", "hash": handleHash, "isSystem": true},
			}
			writeScopeSentryTestJSON(t, w, map[string]interface{}{"code": 200, "data": map[string]interface{}{"list": plugins, "total": len(plugins)}})
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
	defaultInspection, err := adapter.ListTaskOptions(ctx, connection, TaskOptionFilter{Kind: "template_detail", ID: defaultID})
	if err != nil {
		t.Fatalf("template detail: %v", err)
	}
	defaultOptions := scopeSentryMap(scopeSentryMap(defaultInspection)["options"])
	defaultSummary := scopeSentryMap(defaultOptions["capability_summary"])
	defaultToken := strings.TrimSpace(fmt.Sprint(defaultOptions["verification_token"]))
	if defaultToken == "" || defaultSummary["port_scope"] != "top1000" || defaultSummary["full_ports"] != false {
		t.Fatalf("unexpected default template inspection: %#v", defaultOptions)
	}
	createdTemplate, err := adapter.CreateTemplate(ctx, connection, TemplateRequest{
		Name: customName, BaseTemplateID: defaultID,
		Options: map[string]interface{}{
			"enabled_capabilities": []interface{}{"port_scan", "service_fingerprint", "asset_handle"},
			"ports":                "1-65535", "concurrency": 5,
		},
	})
	createdTemplateMap := scopeSentryMap(createdTemplate)
	createdSummary := scopeSentryMap(createdTemplateMap["capability_summary"])
	if err != nil || createdTemplateMap["template_id"] != customID || createdSummary["full_ports"] != true {
		t.Fatalf("CreateTemplate result=%#v err=%v", createdTemplate, err)
	}
	reusedTemplate, err := adapter.CreateTemplate(ctx, connection, TemplateRequest{Name: customName, PresetID: "full_scan"})
	if err != nil || scopeSentryMap(reusedTemplate)["reused"] != true || scopeSentryMap(reusedTemplate)["template_id"] != customID {
		t.Fatalf("built-in template should reuse an exact upstream name: result=%#v err=%v", reusedTemplate, err)
	}
	if _, err := adapter.CreateTask(ctx, connection, TaskRequest{
		Name: "must inspect", Target: "192.0.2.11", Options: map[string]interface{}{"template_id": defaultID},
	}); err == nil || !strings.Contains(err.Error(), "template_detail") {
		t.Fatalf("template creation without verification token must fail, err=%v", err)
	}
	if _, err := adapter.CreateTask(ctx, connection, TaskRequest{
		Name: "must be full ports", Target: "192.0.2.11", Options: map[string]interface{}{
			"template_id": defaultID, "template_verification_token": defaultToken, "required_port_scope": "all",
		},
	}); err == nil || !strings.Contains(err.Error(), "实际 top1000") {
		t.Fatalf("template with top1000 must fail full-port assertion, err=%v", err)
	}
	if _, err := adapter.CreateTask(ctx, connection, TaskRequest{
		Name: "must scan vulnerabilities", Target: "192.0.2.11", Options: map[string]interface{}{
			"template_id": defaultID, "template_verification_token": defaultToken,
			"required_capabilities": []interface{}{"vulnerability_scan", "directory_scan"},
		},
	}); err == nil || !strings.Contains(err.Error(), "vulnerability_scan, directory_scan") {
		t.Fatalf("template with disabled required capabilities must fail, err=%v", err)
	}
	created, err := adapter.CreateTask(ctx, connection, TaskRequest{
		Name: name, Target: "192.0.2.10",
		Options: map[string]interface{}{"ports": "22", "port_scan": true, "site_identify": false, "concurrency": 2},
	})
	if err != nil || !strings.Contains(fmt.Sprint(created), taskID) {
		t.Fatalf("CreateTask result=%#v err=%v", created, err)
	}
	if !strings.Contains(fmt.Sprint(created), "effective_template") || !strings.Contains(fmt.Sprint(created), "custom") {
		t.Fatalf("CreateTask must return the effective template summary: %#v", created)
	}
	if result, err := adapter.ListTasks(ctx, connection, TaskFilter{Page: 1, PageSize: 10}); err != nil || !strings.Contains(fmt.Sprint(result), taskID) || !strings.Contains(fmt.Sprint(result), profileName) {
		t.Fatalf("ListTasks result=%#v err=%v", result, err)
	}
	if result, err := adapter.GetTask(ctx, connection, taskID); err != nil || !strings.Contains(fmt.Sprint(result), "completed") || !strings.Contains(fmt.Sprint(result), profileName) {
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
	profileInspection, err := adapter.ListTaskOptions(ctx, connection, TaskOptionFilter{Kind: "template_detail", ID: profileID})
	if err != nil {
		t.Fatalf("profile template detail: %v", err)
	}
	profileOptions := scopeSentryMap(scopeSentryMap(profileInspection)["options"])
	profileToken := strings.TrimSpace(fmt.Sprint(profileOptions["verification_token"]))
	scheduledTask, err := adapter.CreateTask(ctx, connection, TaskRequest{
		Name: scheduledName, Target: "192.0.2.20",
		Options: map[string]interface{}{"template_id": profileID, "template_verification_token": profileToken, "scheduled": true, "cycle_type": "daily", "hour": 3, "minute": 15},
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

func TestScopeSentryEnableInstalledPlugins(t *testing.T) {
	template := map[string]interface{}{
		"WebCrawler":        []interface{}{},
		"VulnerabilityScan": []interface{}{},
		"Parameters":        map[string]interface{}{},
		"ParameterLists":    map[string]interface{}{},
	}
	options := map[string]interface{}{
		"enabled_capabilities": []interface{}{"web_crawler", "vulnerability_scan"},
	}
	plugins := map[string]interface{}{"data": map[string]interface{}{"list": []interface{}{
		map[string]interface{}{
			"name": "katana", "module": "WebCrawler", "hash": "crawler-system", "parameter": "-depth 3",
			"parameterList": `[{"name":"depth","type":"string","defaultValue":"3"}]`, "isSystem": true,
		},
		map[string]interface{}{
			"name": "custom crawler", "module": "WebCrawler", "hash": "crawler-custom", "parameter": "-depth 9", "isSystem": false,
		},
		map[string]interface{}{
			"name": "nuclei", "module": "VulnerabilityScan", "hash": "nuclei-system", "parameter": "-rl 150", "isSystem": true,
		},
	}}}

	autoEnabled, err := scopeSentryEnableInstalledPlugins(template, options, plugins)
	if err != nil {
		t.Fatal(err)
	}
	if len(autoEnabled) != 2 {
		t.Fatalf("auto enabled=%#v", autoEnabled)
	}
	if got := fmt.Sprint(template["WebCrawler"]); !strings.Contains(got, "crawler-system") || strings.Contains(got, "crawler-custom") {
		t.Fatalf("built-in plugin preference failed: %s", got)
	}
	if got := fmt.Sprint(scopeSentryMap(scopeSentryMap(template["Parameters"])["VulnerabilityScan"])["nuclei-system"]); got != "-rl 150" {
		t.Fatalf("nuclei default parameter=%q", got)
	}
	if got := fmt.Sprint(scopeSentryMap(scopeSentryMap(template["ParameterLists"])["WebCrawler"])["crawler-system"]); !strings.Contains(got, "defaultValue") {
		t.Fatalf("crawler parameter list=%q", got)
	}
}

func TestScopeSentryEnableInstalledPluginsReportsMissingModule(t *testing.T) {
	template := map[string]interface{}{"PassiveScan": []interface{}{}}
	_, err := scopeSentryEnableInstalledPlugins(template, map[string]interface{}{
		"enabled_capabilities": []interface{}{"passive_scan"},
	}, map[string]interface{}{"data": map[string]interface{}{"list": []interface{}{}}})
	if err == nil || !strings.Contains(err.Error(), "passive_scan (PassiveScan)") {
		t.Fatalf("missing plugin error=%v", err)
	}
}

func TestScopeSentrySensitiveCapabilityRequiresSensitivePlugin(t *testing.T) {
	template := map[string]interface{}{
		"URLSecurity": []interface{}{"trufflehog-hash"},
		"Parameters": map[string]interface{}{"URLSecurity": map[string]interface{}{
			"trufflehog-hash": "-pdf false -verify false",
		}},
		"ParameterLists": map[string]interface{}{"URLSecurity": map[string]interface{}{}},
	}
	plugins := map[string]interface{}{"data": map[string]interface{}{"list": []interface{}{
		map[string]interface{}{"name": "sensitive", "module": "URLSecurity", "hash": "sensitive-hash", "parameter": "-t 10", "isSystem": true},
		map[string]interface{}{"name": "trufflehog", "module": "URLSecurity", "hash": "trufflehog-hash", "parameter": "-pdf false -verify false", "isSystem": true},
	}}}

	before := scopeSentryTemplateCapabilitySummary(template, plugins)
	if capabilities, _ := before["capabilities"].(map[string]bool); capabilities["sensitive_scan"] != false {
		t.Fatalf("trufflehog alone must not satisfy sensitive_scan: %#v", before)
	}
	autoEnabled, err := scopeSentryEnableInstalledPlugins(template, map[string]interface{}{
		"enabled_capabilities": []interface{}{"sensitive_scan"},
	}, plugins)
	if err != nil {
		t.Fatal(err)
	}
	if len(autoEnabled) != 1 || autoEnabled[0]["plugin"] != "sensitive" {
		t.Fatalf("auto enabled=%#v", autoEnabled)
	}
	selected := fmt.Sprint(template["URLSecurity"])
	if !strings.Contains(selected, "sensitive-hash") || !strings.Contains(selected, "trufflehog-hash") {
		t.Fatalf("URLSecurity selection must merge sensitive with existing plugins: %s", selected)
	}
	after := scopeSentryTemplateCapabilitySummary(template, plugins)
	if capabilities, _ := after["capabilities"].(map[string]bool); capabilities["sensitive_scan"] != true {
		t.Fatalf("sensitive plugin was not recognized: %#v", after)
	}
	if available := fmt.Sprint(after["available_capabilities"]); !strings.Contains(available, "sensitive_scan") {
		t.Fatalf("available capabilities=%s", available)
	}
}

func writeScopeSentryTestJSON(t *testing.T, w http.ResponseWriter, value interface{}) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}
