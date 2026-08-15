package asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const arlMaxResponseBytes = 4 * 1024 * 1024

var arlTaskIDPattern = regexp.MustCompile(`^[a-fA-F0-9]{24}$`)

var arlPolicyPortPattern = regexp.MustCompile(`^[0-9,\-\s]*$`)

type arlTokenEntry struct {
	token       string
	fingerprint [32]byte
}

type ARLAdapter struct {
	tokenMu    sync.Mutex
	tokenCache map[string]arlTokenEntry
}

type arlAPIError struct {
	Code    string
	Message string
}

func (e *arlAPIError) Error() string { return fmt.Sprintf("%s (code=%s)", e.Message, e.Code) }

func NewARLAdapter() *ARLAdapter { return &ARLAdapter{tokenCache: make(map[string]arlTokenEntry)} }

func (a *ARLAdapter) Provider() string { return ProviderARL }

func (a *ARLAdapter) Capabilities() []string {
	return []string{"test_connection", "get_task_profile", "list_task_options", "create_template", "create_task", "list_tasks", "get_task", "list_assets", "stop_task", "manage_task"}
}

func arlHTTPClient(verifyTLS bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !verifyTLS} // #nosec G402 -- operator-controlled compatibility option for lab ASM deployments.
	return &http.Client{
		Timeout:   45 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func arlCodeOK(value interface{}) bool {
	switch code := value.(type) {
	case float64:
		return int(code) == 200
	case int:
		return code == 200
	case json.Number:
		return code.String() == "200"
	case string:
		return strings.TrimSpace(code) == "200"
	default:
		return false
	}
}

func arlResponseError(payload map[string]interface{}) error {
	if code, exists := payload["code"]; exists && !arlCodeOK(code) {
		message := strings.TrimSpace(fmt.Sprint(payload["message"]))
		if message == "" || message == "<nil>" {
			message = "ARL API 返回失败"
		}
		return &arlAPIError{Code: strings.TrimSpace(fmt.Sprint(code)), Message: message}
	}
	return nil
}

func (a *ARLAdapter) request(ctx context.Context, conn *Connection, method, apiPath string, query url.Values, body interface{}, token string) (map[string]interface{}, error) {
	endpoint := strings.TrimRight(conn.Resource.BaseURL, "/") + apiPath
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("编码 ARL 请求失败: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, fmt.Errorf("创建 ARL 请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CyberStrikeAI-ASM/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Token", token)
	}
	resp, err := arlHTTPClient(conn.Resource.VerifyTLS).Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 ARL 失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, arlMaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取 ARL 响应失败: %w", err)
	}
	if len(raw) > arlMaxResponseBytes {
		return nil, fmt.Errorf("ARL 响应超过 %d 字节限制", arlMaxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := strings.TrimSpace(string(raw))
		if len(detail) > 500 {
			detail = detail[:500]
		}
		return nil, fmt.Errorf("ARL HTTP %d: %s", resp.StatusCode, detail)
	}
	payload := make(map[string]interface{})
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("解析 ARL 响应失败: %w", err)
	}
	if err := arlResponseError(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (a *ARLAdapter) token(ctx context.Context, conn *Connection) (string, error) {
	if conn.Resource.AuthType == "api_key" {
		if strings.TrimSpace(conn.Secret) == "" {
			return "", fmt.Errorf("ARL API Key 为空")
		}
		return conn.Secret, nil
	}
	if strings.TrimSpace(conn.Resource.Username) == "" || conn.Secret == "" {
		return "", fmt.Errorf("ARL 用户名或密码为空")
	}
	key := strings.TrimSpace(conn.Resource.ID)
	if key == "" {
		key = strings.TrimSpace(conn.Resource.BaseURL)
	}
	fingerprint := sha256.Sum256([]byte(strings.Join([]string{
		conn.Resource.BaseURL, conn.Resource.Username, conn.Resource.AuthType, conn.Secret,
	}, "\x00")))
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()
	if cached, ok := a.tokenCache[key]; ok && cached.fingerprint == fingerprint && cached.token != "" {
		return cached.token, nil
	}
	payload, err := a.request(ctx, conn, http.MethodPost, "/api/user/login", nil, map[string]string{
		"username": conn.Resource.Username,
		"password": conn.Secret,
	}, "")
	if err != nil {
		return "", err
	}
	data, _ := payload["data"].(map[string]interface{})
	token := strings.TrimSpace(fmt.Sprint(data["token"]))
	if token == "" || token == "<nil>" {
		return "", fmt.Errorf("ARL 登录成功但未返回 Token")
	}
	if a.tokenCache == nil {
		a.tokenCache = make(map[string]arlTokenEntry)
	}
	a.tokenCache[key] = arlTokenEntry{token: token, fingerprint: fingerprint}
	return token, nil
}

func (a *ARLAdapter) invalidateToken(conn *Connection, token string) {
	if conn == nil || conn.Resource == nil || conn.Resource.AuthType == "api_key" {
		return
	}
	key := strings.TrimSpace(conn.Resource.ID)
	if key == "" {
		key = strings.TrimSpace(conn.Resource.BaseURL)
	}
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()
	if cached, ok := a.tokenCache[key]; ok && cached.token == token {
		delete(a.tokenCache, key)
	}
}

func arlUnauthorized(err error) bool {
	var apiErr *arlAPIError
	return (errors.As(err, &apiErr) && apiErr.Code == "401") || strings.Contains(fmt.Sprint(err), "ARL HTTP 401")
}

func (a *ARLAdapter) authenticatedRequest(ctx context.Context, conn *Connection, method, apiPath string, query url.Values, body interface{}) (map[string]interface{}, error) {
	token, err := a.token(ctx, conn)
	if err != nil {
		return nil, err
	}
	payload, err := a.request(ctx, conn, method, apiPath, query, body, token)
	if err == nil || !arlUnauthorized(err) || conn.Resource.AuthType == "api_key" {
		return payload, err
	}
	a.invalidateToken(conn, token)
	token, err = a.token(ctx, conn)
	if err != nil {
		return nil, err
	}
	return a.request(ctx, conn, method, apiPath, query, body, token)
}

func (a *ARLAdapter) Test(ctx context.Context, conn *Connection) (interface{}, error) {
	payload, err := a.authenticatedRequest(ctx, conn, http.MethodGet, "/api/console/info", nil, nil)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderARL,
		"connected": true,
		"console":   payload["data"],
	}, nil
}

var arlTaskOptionDefaults = map[string]interface{}{
	"domain_brute": false, "domain_brute_type": "test", "port_scan_type": "test",
	"port_scan": false, "service_detection": false, "service_brute": false,
	"os_detection": false, "site_identify": true, "site_capture": false,
	"file_leak": false, "search_engines": false, "site_spider": false,
	"arl_search": false, "alt_dns": false, "ssl_cert": false,
	"dns_query_plugin": false, "skip_scan_cdn_ip": true, "nuclei_scan": false,
	"findvhost": false, "web_info_hunter": false,
}

var arlDirectTaskOptions = taskOptionAllowed(
	"task_mode", "domain_brute", "domain_brute_type", "port_scan_type", "port_scan",
	"service_detection", "service_brute", "os_detection", "site_identify", "site_capture",
	"file_leak", "search_engines", "site_spider", "arl_search", "alt_dns", "ssl_cert",
	"dns_query_plugin", "skip_scan_cdn_ip", "nuclei_scan", "findvhost", "web_info_hunter",
)

var arlPolicyTaskOptions = taskOptionAllowed("task_mode", "policy_id", "task_tag", "result_set_id")

func buildARLTaskRequest(req TaskRequest) (string, map[string]interface{}, error) {
	name, target := strings.TrimSpace(req.Name), strings.TrimSpace(req.Target)
	if target == "" || len(target) > 10000 {
		return "", nil, fmt.Errorf("任务目标不能为空且不能超过 10000 字符")
	}
	if name == "" {
		name = "CyberStrikeAI ASM task"
	}
	if len(name) > 200 {
		return "", nil, fmt.Errorf("任务名称不能超过 200 字符")
	}
	mode, err := taskOptionEnum("ARL", req.Options, "task_mode", "direct", "direct", "policy")
	if err != nil {
		return "", nil, err
	}
	if mode == "policy" {
		if err := rejectUnknownTaskOptions("ARL policy 模式", req.Options, arlPolicyTaskOptions); err != nil {
			return "", nil, err
		}
		policyID, err := taskOptionString("ARL", req.Options, "policy_id", "", 64)
		if err != nil || !arlTaskIDPattern.MatchString(policyID) {
			return "", nil, fmt.Errorf("ARL policy 模式需要有效的 policy_id")
		}
		taskTag, err := taskOptionEnum("ARL", req.Options, "task_tag", "task", "task", "risk_cruising")
		if err != nil {
			return "", nil, err
		}
		body := map[string]interface{}{"name": name, "target": target, "policy_id": policyID, "task_tag": taskTag}
		resultSetID, err := taskOptionString("ARL", req.Options, "result_set_id", "", 64)
		if err != nil {
			return "", nil, err
		}
		if resultSetID != "" {
			if !arlTaskIDPattern.MatchString(resultSetID) {
				return "", nil, fmt.Errorf("ARL result_set_id 格式无效")
			}
			body["result_set_id"] = resultSetID
		}
		return "/api/task/policy/", body, nil
	}
	if err := rejectUnknownTaskOptions("ARL direct 模式", req.Options, arlDirectTaskOptions); err != nil {
		return "", nil, err
	}
	body := map[string]interface{}{"name": name, "target": target}
	for key, value := range arlTaskOptionDefaults {
		body[key] = value
	}
	for key := range req.Options {
		if key == "task_mode" {
			continue
		}
		fallback := arlTaskOptionDefaults[key]
		switch fallback.(type) {
		case bool:
			parsed, err := taskOptionBool("ARL", req.Options, key, fallback.(bool))
			if err != nil {
				return "", nil, err
			}
			body[key] = parsed
		case string:
			var parsed string
			var err error
			if key == "domain_brute_type" {
				parsed, err = taskOptionEnum("ARL", req.Options, key, fallback.(string), "test", "big")
			} else {
				parsed, err = taskOptionEnum("ARL", req.Options, key, fallback.(string), "test", "top100", "top1000", "all")
			}
			if err != nil {
				return "", nil, err
			}
			body[key] = parsed
		}
	}
	return "/api/task/", body, nil
}

func (a *ARLAdapter) CreateTask(ctx context.Context, conn *Connection, req TaskRequest) (interface{}, error) {
	endpoint, body, err := buildARLTaskRequest(req)
	if err != nil {
		return nil, err
	}
	payload, err := a.authenticatedRequest(ctx, conn, http.MethodPost, endpoint, nil, body)
	if err != nil {
		return nil, err
	}
	result := map[string]interface{}{"provider": ProviderARL, "resource_id": conn.Resource.ID, "response": payload}
	if remoteTaskID(ProviderARL, result) == "" {
		resolved, lookupErr := a.resolveCreatedTasks(ctx, conn, meaningfulString(body["name"]), meaningfulString(body["target"]))
		if len(resolved) > 0 {
			result["resolved_tasks"] = resolved
			result["task_id_resolution"] = "task_list"
		} else if lookupErr != nil {
			result["task_id_resolution_warning"] = "ARL 任务已创建，但任务 ID 回查失败: " + lookupErr.Error()
		}
	}
	if endpoint == "/api/task/policy/" {
		policyID := meaningfulString(body["policy_id"])
		profile := map[string]interface{}{"kind": "policy", "label": "ARL 策略", "id": policyID}
		if detail, detailErr := a.readPolicyDetail(ctx, conn, policyID); detailErr == nil {
			name := meaningfulString(detail["name"])
			if name == "" {
				name = meaningfulString(detail["policy_name"])
			}
			if name == "" {
				policy := valueMap(detail["policy"])
				name = meaningfulString(mapValue(policy, "name", "policy_name"))
			}
			profile["name"] = name
			result["policy_name"] = name
		} else {
			result["profile_lookup_warning"] = "ARL 任务已创建，但策略名称回读失败: " + detailErr.Error()
		}
		result["execution_profile"] = profile
	}
	return result, nil
}

func (a *ARLAdapter) resolveCreatedTasks(ctx context.Context, conn *Connection, name, target string) ([]interface{}, error) {
	requestedTargets := requestTargetList(target)
	expected := len(requestedTargets)
	if expected < 1 {
		expected = 1
	}
	var best []interface{}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return best, ctx.Err()
			case <-timer.C:
			}
		}
		listed, err := a.ListTasks(ctx, conn, TaskFilter{Name: name, Target: target, Page: 1, PageSize: 100})
		if err != nil {
			lastErr = err
			continue
		}
		matches := matchARLCreatedTasks(listed, name, target, expected)
		if len(matches) > len(best) {
			best = matches
		}
		if len(best) >= expected {
			return best, nil
		}
	}
	if len(best) > 0 {
		return best, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("未在 ARL 任务列表中找到刚创建的任务")
}

func matchARLCreatedTasks(payload interface{}, name, target string, limit int) []interface{} {
	name = strings.TrimSpace(name)
	target = strings.TrimSpace(target)
	requestedTargets := requestTargetList(target)
	targetSet := make(map[string]bool, len(requestedTargets)+1)
	for _, item := range requestedTargets {
		targetSet[item] = true
	}
	if target != "" {
		targetSet[target] = true
	}
	if limit < 1 {
		limit = 1
	}
	result := make([]interface{}, 0, limit)
	for _, raw := range taskCollection(ProviderARL, payload) {
		task := valueMap(raw)
		if task == nil {
			continue
		}
		remoteID := meaningfulString(mapValue(task, "id", "_id", "task_id", "TaskID"))
		if !arlTaskIDPattern.MatchString(remoteID) {
			continue
		}
		if actualName := meaningfulString(mapValue(task, "name", "task_name")); name != "" && actualName != name {
			continue
		}
		if actualTarget := meaningfulString(mapValue(task, "target", "targetName", "domain", "ip")); len(targetSet) > 0 && !targetSet[actualTarget] {
			continue
		}
		result = append(result, raw)
		if len(result) >= limit {
			break
		}
	}
	return result
}

func normalizePagination(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return page, size
}

func (a *ARLAdapter) ListTasks(ctx context.Context, conn *Connection, filter TaskFilter) (interface{}, error) {
	page, size := normalizePagination(filter.Page, filter.PageSize)
	query := url.Values{"page": {strconv.Itoa(page)}, "size": {strconv.Itoa(size)}, "order": {"-_id"}}
	if value := strings.TrimSpace(filter.TaskID); value != "" {
		query.Set("_id", value)
	}
	if value := strings.TrimSpace(filter.Name); value != "" {
		query.Set("name", value)
	}
	if value := strings.TrimSpace(filter.Target); value != "" {
		query.Set("target", value)
	}
	if value := strings.TrimSpace(filter.Status); value != "" {
		query.Set("status", value)
	}
	payload, err := a.authenticatedRequest(ctx, conn, http.MethodGet, "/api/task/", query, nil)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderARL, "resource_id": conn.Resource.ID, "tasks": payload}, nil
}

func (a *ARLAdapter) GetTask(ctx context.Context, conn *Connection, taskID string) (interface{}, error) {
	if !arlTaskIDPattern.MatchString(taskID) {
		return nil, fmt.Errorf("ARL 任务 ID 格式无效")
	}
	result, err := a.ListTasks(ctx, conn, TaskFilter{TaskID: taskID, Page: 1, PageSize: 1})
	if err != nil {
		return nil, err
	}
	return result, nil
}

var arlAssetEndpoints = map[string]struct{ path, queryField string }{
	"site": {"/api/site/", "site"}, "domain": {"/api/domain/", "domain"},
	"ip": {"/api/ip/", "ip"}, "url": {"/api/url/", "url"},
	"service": {"/api/service/", "service_name"}, "vulnerability": {"/api/vuln/", "vul_name"},
	"cert": {"/api/cert/", "ip"}, "fileleak": {"/api/fileleak/", "url"},
	"npoc_service": {"/api/npoc_service/", "host"}, "cip": {"/api/cip/", "cidr_ip"},
	"nuclei_result": {"/api/nuclei_result/", "vuln_url"}, "stat_finger": {"/api/stat_finger/", "name"},
	"wih": {"/api/wih/", "content"},
}

func (a *ARLAdapter) ListAssets(ctx context.Context, conn *Connection, filter AssetFilter) (interface{}, error) {
	assetType := strings.ToLower(strings.TrimSpace(filter.Type))
	if assetType == "" {
		assetType = "site"
	}
	endpoint, ok := arlAssetEndpoints[assetType]
	if !ok {
		return nil, fmt.Errorf("ARL 结果类型不支持: %s", assetType)
	}
	page, size := normalizePagination(filter.Page, filter.PageSize)
	query := url.Values{"page": {strconv.Itoa(page)}, "size": {strconv.Itoa(size)}, "order": {"-_id"}}
	if taskID := strings.TrimSpace(filter.TaskID); taskID != "" {
		if !arlTaskIDPattern.MatchString(taskID) {
			return nil, fmt.Errorf("ARL 任务 ID 格式无效")
		}
		query.Set("task_id", taskID)
	}
	if value := strings.TrimSpace(filter.Query); value != "" && endpoint.queryField != "" {
		query.Set(endpoint.queryField, value)
	}
	payload, err := a.authenticatedRequest(ctx, conn, http.MethodGet, endpoint.path, query, nil)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderARL, "resource_id": conn.Resource.ID, "asset_type": assetType, "results": payload}, nil
}

func (a *ARLAdapter) StopTask(ctx context.Context, conn *Connection, taskID string) (interface{}, error) {
	if !arlTaskIDPattern.MatchString(taskID) {
		return nil, fmt.Errorf("ARL 任务 ID 格式无效")
	}
	payload, err := a.authenticatedRequest(ctx, conn, http.MethodGet, "/api/task/stop/"+taskID, nil, nil)
	if err != nil {
		var apiErr *arlAPIError
		if errors.As(err, &apiErr) && apiErr.Code == "105" {
			return map[string]interface{}{
				"provider": ProviderARL, "resource_id": conn.Resource.ID,
				"already_finished": true, "message": apiErr.Message,
			}, nil
		}
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderARL, "resource_id": conn.Resource.ID, "response": payload}, nil
}

func (a *ARLAdapter) GetTaskProfile(_ context.Context, conn *Connection) (interface{}, error) {
	return map[string]interface{}{
		"provider": ProviderARL, "resource_id": conn.Resource.ID, "upstream_version": "2.6.3",
		"task_modes":           []string{"direct", "policy"},
		"dynamic_option_kinds": []string{"policies", "policy_detail", "pocs", "brute_plugins", "scopes"},
		"manage_actions":       []string{"restart", "delete", "sync_results"},
		"result_types":         providerResultTypes(ProviderARL),
		"notes": []string{
			"direct 模式对应 /api/task/，仅支持 ARL 直接任务字段",
			"policy 模式对应 /api/task/policy/，自定义端口、排除端口、速率、POC 和弱口令插件由 policy_id 指向的上游策略决定，不支持任务级覆盖",
			"自定义策略使用 template_create_options 中的 ARL 原生字段；不要传 ScopeSentry 的 ports、concurrency、enabled_capabilities 或 poc_ids",
			"内置漏洞巡检会实时选择全部已安装 POC；内置全量扫描还会实时选择全部已安装弱口令插件，并在复用旧策略时校准配置",
		},
		"create_options": map[string]interface{}{
			"task_mode":         map[string]interface{}{"type": "string", "enum": []string{"direct", "policy"}, "default": "direct"},
			"policy_id":         map[string]interface{}{"type": "string", "description": "policy 模式使用的 ARL 策略 ID", "mode": "policy"},
			"task_tag":          map[string]interface{}{"type": "string", "enum": []string{"task", "risk_cruising"}, "default": "task", "mode": "policy"},
			"result_set_id":     map[string]interface{}{"type": "string", "description": "风险巡航可选结果集 ID", "mode": "policy"},
			"domain_brute":      map[string]interface{}{"type": "boolean", "default": false},
			"domain_brute_type": map[string]interface{}{"type": "string", "enum": []string{"big", "test"}, "default": "test"},
			"port_scan":         map[string]interface{}{"type": "boolean", "default": false},
			"port_scan_type":    map[string]interface{}{"type": "string", "enum": []string{"test", "top100", "top1000", "all"}, "default": "test", "mode": "direct"},
			"service_detection": map[string]interface{}{"type": "boolean"}, "service_brute": map[string]interface{}{"type": "boolean"},
			"os_detection": map[string]interface{}{"type": "boolean"}, "site_identify": map[string]interface{}{"type": "boolean"},
			"site_capture": map[string]interface{}{"type": "boolean"}, "file_leak": map[string]interface{}{"type": "boolean"},
			"search_engines": map[string]interface{}{"type": "boolean"}, "site_spider": map[string]interface{}{"type": "boolean"},
			"arl_search": map[string]interface{}{"type": "boolean"}, "alt_dns": map[string]interface{}{"type": "boolean"},
			"ssl_cert": map[string]interface{}{"type": "boolean"}, "dns_query_plugin": map[string]interface{}{"type": "boolean"},
			"skip_scan_cdn_ip": map[string]interface{}{"type": "boolean"}, "nuclei_scan": map[string]interface{}{"type": "boolean"},
			"findvhost": map[string]interface{}{"type": "boolean"}, "web_info_hunter": map[string]interface{}{"type": "boolean"},
		},
		"template_create_options": map[string]interface{}{
			"domain_brute":           map[string]interface{}{"type": "boolean", "default": false},
			"domain_brute_type":      map[string]interface{}{"type": "string", "enum": []string{"test", "big"}, "default": "test"},
			"alt_dns":                map[string]interface{}{"type": "boolean", "default": false},
			"arl_search":             map[string]interface{}{"type": "boolean", "default": false},
			"dns_query_plugin":       map[string]interface{}{"type": "boolean", "default": false},
			"port_scan":              map[string]interface{}{"type": "boolean", "default": true},
			"port_scan_type":         map[string]interface{}{"type": "string", "enum": []string{"test", "top100", "top1000", "all", "custom"}, "default": "top100"},
			"port_custom":            map[string]interface{}{"type": "string", "default": "80,443", "requires": map[string]interface{}{"port_scan_type": "custom"}},
			"exclude_ports":          map[string]interface{}{"type": "string", "default": ""},
			"host_timeout_type":      map[string]interface{}{"type": "string", "enum": []string{"default", "custom"}, "default": "default"},
			"host_timeout":           map[string]interface{}{"type": "integer", "minimum": 60, "maximum": 7200, "default": 900},
			"port_parallelism":       map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 512, "default": 32},
			"port_min_rate":          map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 10000, "default": 60},
			"service_detection":      map[string]interface{}{"type": "boolean", "default": true},
			"os_detection":           map[string]interface{}{"type": "boolean", "default": false},
			"ssl_cert":               map[string]interface{}{"type": "boolean", "default": true},
			"skip_scan_cdn_ip":       map[string]interface{}{"type": "boolean", "default": true},
			"site_identify":          map[string]interface{}{"type": "boolean", "default": true},
			"site_capture":           map[string]interface{}{"type": "boolean", "default": false},
			"search_engines":         map[string]interface{}{"type": "boolean", "default": false},
			"site_spider":            map[string]interface{}{"type": "boolean", "default": false},
			"nuclei_scan":            map[string]interface{}{"type": "boolean", "default": false},
			"web_info_hunter":        map[string]interface{}{"type": "boolean", "default": false},
			"file_leak":              map[string]interface{}{"type": "boolean", "default": false},
			"npoc_service_detection": map[string]interface{}{"type": "boolean", "default": false},
			"scope_id":               map[string]interface{}{"type": "string", "dynamic_kind": "scopes"},
			"poc_selection":          map[string]interface{}{"type": "string", "enum": []string{"none", "all"}, "default": "none", "dynamic_kind": "pocs"},
			"brute_selection":        map[string]interface{}{"type": "string", "enum": []string{"none", "all"}, "default": "none", "dynamic_kind": "brute_plugins"},
		},
		"policy_fields": map[string]interface{}{
			"port_scan_type": []string{"test", "top100", "top1000", "all", "custom"},
			"advanced":       []string{"port_custom", "exclude_ports", "host_timeout_type", "host_timeout", "port_parallelism", "port_min_rate", "poc_selection", "brute_selection", "poc_config", "brute_config", "scope_config"},
		},
	}, nil
}

func (a *ARLAdapter) ListTaskOptions(ctx context.Context, conn *Connection, filter TaskOptionFilter) (interface{}, error) {
	page, size := normalizePagination(filter.Page, filter.PageSize)
	query := url.Values{"page": {strconv.Itoa(page)}, "size": {strconv.Itoa(size)}, "order": {"-_id"}}
	if filter.Query != "" {
		query.Set("name", filter.Query)
	}
	var endpoint string
	switch filter.Kind {
	case "policies":
		endpoint = "/api/policy/"
	case "policy_detail":
		if !arlTaskIDPattern.MatchString(filter.ID) {
			return nil, fmt.Errorf("ARL 策略 ID 格式无效")
		}
		endpoint = "/api/policy/"
		query.Set("_id", filter.ID)
	case "pocs":
		endpoint = "/api/poc/"
		query.Set("plugin_type", "poc")
	case "brute_plugins":
		endpoint = "/api/poc/"
		query.Set("plugin_type", "brute")
	case "scopes":
		endpoint = "/api/asset_scope/"
	default:
		return nil, fmt.Errorf("ARL 不支持的动态选项类别: %s", filter.Kind)
	}
	payload, err := a.authenticatedRequest(ctx, conn, http.MethodGet, endpoint, query, nil)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderARL, "resource_id": conn.Resource.ID, "kind": filter.Kind, "options": payload}, nil
}

var arlTemplateOptions = taskOptionAllowed(
	"domain_brute", "domain_brute_type", "alt_dns", "arl_search", "dns_query_plugin",
	"port_scan", "port_scan_type", "service_detection", "os_detection", "ssl_cert", "skip_scan_cdn_ip",
	"port_custom", "host_timeout_type", "host_timeout", "port_parallelism", "port_min_rate", "exclude_ports",
	"site_identify", "site_capture", "search_engines", "site_spider", "nuclei_scan", "web_info_hunter",
	"file_leak", "npoc_service_detection", "scope_id", "poc_selection", "brute_selection",
)

func buildARLPolicyRequest(req TemplateRequest) (map[string]interface{}, error) {
	if err := rejectUnknownTaskOptions("ARL 策略", req.Options, arlTemplateOptions); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 150 || strings.ContainsAny(name, "\r\n") {
		return nil, fmt.Errorf("ARL 策略名称必填、不能换行且不能超过 150 字符")
	}

	boolDefaults := map[string]bool{
		"domain_brute": false, "alt_dns": false, "arl_search": false, "dns_query_plugin": false,
		"port_scan": true, "service_detection": true, "os_detection": false, "ssl_cert": true, "skip_scan_cdn_ip": true,
		"site_identify": true, "site_capture": false, "search_engines": false, "site_spider": false,
		"nuclei_scan": false, "web_info_hunter": false, "file_leak": false, "npoc_service_detection": false,
	}
	flags := make(map[string]bool, len(boolDefaults))
	for key, fallback := range boolDefaults {
		value, err := taskOptionBool("ARL 策略", req.Options, key, fallback)
		if err != nil {
			return nil, err
		}
		flags[key] = value
	}
	domainBruteType, err := taskOptionEnum("ARL 策略", req.Options, "domain_brute_type", "test", "test", "big")
	if err != nil {
		return nil, err
	}
	portScanType, err := taskOptionEnum("ARL 策略", req.Options, "port_scan_type", "top100", "test", "top100", "top1000", "all", "custom")
	if err != nil {
		return nil, err
	}
	hostTimeoutType, err := taskOptionEnum("ARL 策略", req.Options, "host_timeout_type", "default", "default", "custom")
	if err != nil {
		return nil, err
	}
	hostTimeout, err := taskOptionInt("ARL 策略", req.Options, "host_timeout", 900, 60, 7200)
	if err != nil {
		return nil, err
	}
	parallelism, err := taskOptionInt("ARL 策略", req.Options, "port_parallelism", 32, 1, 512)
	if err != nil {
		return nil, err
	}
	minRate, err := taskOptionInt("ARL 策略", req.Options, "port_min_rate", 60, 1, 10000)
	if err != nil {
		return nil, err
	}
	portCustom, err := taskOptionString("ARL 策略", req.Options, "port_custom", "80,443", 500)
	if err != nil {
		return nil, err
	}
	excludePorts, err := taskOptionString("ARL 策略", req.Options, "exclude_ports", "", 500)
	if err != nil {
		return nil, err
	}
	if !arlPolicyPortPattern.MatchString(portCustom) || !arlPolicyPortPattern.MatchString(excludePorts) {
		return nil, fmt.Errorf("ARL 策略端口表达式只能包含数字、逗号和连字符")
	}
	scopeID, err := taskOptionString("ARL 策略", req.Options, "scope_id", "", 64)
	if err != nil {
		return nil, err
	}
	if scopeID != "" && !arlTaskIDPattern.MatchString(scopeID) {
		return nil, fmt.Errorf("ARL 策略 scope_id 格式无效")
	}
	if _, err := taskOptionEnum("ARL 策略", req.Options, "poc_selection", "none", "none", "all"); err != nil {
		return nil, err
	}
	if _, err := taskOptionEnum("ARL 策略", req.Options, "brute_selection", "none", "none", "all"); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"name": name,
		"desc": "由 CyberStrikeAI 创建的受控扫描策略",
		"policy": map[string]interface{}{
			"domain_config": map[string]interface{}{
				"domain_brute": flags["domain_brute"], "domain_brute_type": domainBruteType,
				"alt_dns": flags["alt_dns"], "arl_search": flags["arl_search"], "dns_query_plugin": flags["dns_query_plugin"],
			},
			"ip_config": map[string]interface{}{
				"port_scan": flags["port_scan"], "port_scan_type": portScanType,
				"service_detection": flags["service_detection"], "os_detection": flags["os_detection"],
				"ssl_cert": flags["ssl_cert"], "skip_scan_cdn_ip": flags["skip_scan_cdn_ip"],
				"port_custom": portCustom, "host_timeout_type": hostTimeoutType, "host_timeout": hostTimeout,
				"port_parallelism": parallelism, "port_min_rate": minRate, "exclude_ports": excludePorts,
			},
			"site_config": map[string]interface{}{
				"site_identify": flags["site_identify"], "site_capture": flags["site_capture"],
				"search_engines": flags["search_engines"], "site_spider": flags["site_spider"],
				"nuclei_scan": flags["nuclei_scan"], "web_info_hunter": flags["web_info_hunter"],
			},
			"file_leak": flags["file_leak"], "npoc_service_detection": flags["npoc_service_detection"],
			"poc_config": []interface{}{}, "brute_config": []interface{}{}, "scope_config": map[string]interface{}{"scope_id": scopeID},
		},
	}, nil
}

func (a *ARLAdapter) policyPluginConfig(ctx context.Context, conn *Connection, pluginType string) ([]interface{}, error) {
	if pluginType != "poc" && pluginType != "brute" {
		return nil, fmt.Errorf("ARL 不支持的策略插件类型: %s", pluginType)
	}
	const pageSize = 1000
	seen := make(map[string]struct{})
	plugins := make([]interface{}, 0)
	for page := 1; page <= 100; page++ {
		query := url.Values{
			"page":        {strconv.Itoa(page)},
			"size":        {strconv.Itoa(pageSize)},
			"order":       {"-_id"},
			"plugin_type": {pluginType},
		}
		payload, err := a.authenticatedRequest(ctx, conn, http.MethodGet, "/api/poc/", query, nil)
		if err != nil {
			return nil, err
		}
		items, _ := payload["items"].([]interface{})
		for _, raw := range items {
			item := valueMap(raw)
			pluginName := strings.TrimSpace(fmt.Sprint(item["plugin_name"]))
			if pluginName == "" || pluginName == "<nil>" {
				continue
			}
			if _, exists := seen[pluginName]; exists {
				continue
			}
			seen[pluginName] = struct{}{}
			plugins = append(plugins, map[string]interface{}{"plugin_name": pluginName, "enable": true})
		}
		if len(items) < pageSize {
			break
		}
		if page == 100 {
			return nil, fmt.Errorf("ARL %s 插件超过可安全读取的分页上限", pluginType)
		}
	}
	if len(plugins) == 0 {
		label := "POC"
		if pluginType == "brute" {
			label = "弱口令"
		}
		return nil, fmt.Errorf("ARL 上游未返回可用的%s插件，无法创建声明该能力的策略", label)
	}
	return plugins, nil
}

func (a *ARLAdapter) resolvePolicyPlugins(ctx context.Context, conn *Connection, req TemplateRequest, body map[string]interface{}) (map[string]interface{}, error) {
	pocSelection, err := taskOptionEnum("ARL 策略", req.Options, "poc_selection", "none", "none", "all")
	if err != nil {
		return nil, err
	}
	bruteSelection, err := taskOptionEnum("ARL 策略", req.Options, "brute_selection", "none", "none", "all")
	if err != nil {
		return nil, err
	}
	policy := valueMap(body["policy"])
	if policy == nil {
		return nil, fmt.Errorf("ARL 策略请求缺少 policy")
	}
	pocConfig := []interface{}{}
	if pocSelection == "all" {
		pocConfig, err = a.policyPluginConfig(ctx, conn, "poc")
		if err != nil {
			return nil, err
		}
	}
	bruteConfig := []interface{}{}
	if bruteSelection == "all" {
		bruteConfig, err = a.policyPluginConfig(ctx, conn, "brute")
		if err != nil {
			return nil, err
		}
	}
	policy["poc_config"] = pocConfig
	policy["brute_config"] = bruteConfig
	return map[string]interface{}{
		"poc_selection": pocSelection, "poc_count": len(pocConfig),
		"brute_selection": bruteSelection, "brute_count": len(bruteConfig),
	}, nil
}

func arlPolicySubsetEqual(expected, actual interface{}) bool {
	switch value := expected.(type) {
	case map[string]interface{}:
		actualMap := valueMap(actual)
		if actualMap == nil {
			return false
		}
		for key, expectedValue := range value {
			actualValue, exists := actualMap[key]
			if !exists || !arlPolicySubsetEqual(expectedValue, actualValue) {
				return false
			}
		}
		return true
	case []interface{}:
		actualValues, ok := actual.([]interface{})
		if !ok || len(actualValues) != len(value) {
			return false
		}
		for index := range value {
			if !arlPolicySubsetEqual(value[index], actualValues[index]) {
				return false
			}
		}
		return true
	default:
		expectedJSON, expectedErr := json.Marshal(expected)
		actualJSON, actualErr := json.Marshal(actual)
		return expectedErr == nil && actualErr == nil && bytes.Equal(expectedJSON, actualJSON)
	}
}

func (a *ARLAdapter) readPolicyDetail(ctx context.Context, conn *Connection, policyID string) (map[string]interface{}, error) {
	query := url.Values{
		"page": {"1"}, "size": {"1"}, "order": {"-_id"}, "_id": {policyID},
	}
	payload, err := a.authenticatedRequest(ctx, conn, http.MethodGet, "/api/policy/", query, nil)
	if err != nil {
		return nil, err
	}
	items, _ := payload["items"].([]interface{})
	for _, raw := range items {
		item := valueMap(raw)
		if item != nil && strings.EqualFold(strings.TrimSpace(fmt.Sprint(item["_id"])), policyID) {
			return item, nil
		}
	}
	if data := valueMap(payload["data"]); data != nil && strings.EqualFold(strings.TrimSpace(fmt.Sprint(data["_id"])), policyID) {
		return data, nil
	}
	return nil, fmt.Errorf("ARL 未返回新建策略 %s 的详情", policyID)
}

func (a *ARLAdapter) attachPolicyVerification(ctx context.Context, conn *Connection, policyID string, requested map[string]interface{}, result map[string]interface{}) {
	detail, err := a.readPolicyDetail(ctx, conn, policyID)
	if err != nil {
		result["template_verified"] = false
		result["verification_warning"] = fmt.Sprintf("策略已创建，但上游详情回读失败: %v", err)
		return
	}
	effectivePolicy := valueMap(detail["policy"])
	if effectivePolicy == nil {
		result["template_verified"] = false
		result["verification_warning"] = "策略已创建，但上游详情未返回 policy 字段"
		return
	}
	result["effective_policy"] = effectivePolicy
	result["template_verified"] = arlPolicySubsetEqual(valueMap(requested["policy"]), effectivePolicy)
	if result["template_verified"] != true {
		result["verification_warning"] = "上游实际策略与请求配置不一致；请以 effective_policy 为准，不得宣称全部请求字段已生效"
	}
}

func (a *ARLAdapter) CreateTemplate(ctx context.Context, conn *Connection, req TemplateRequest) (interface{}, error) {
	body, err := buildARLPolicyRequest(req)
	if err != nil {
		return nil, err
	}
	pluginSummary, err := a.resolvePolicyPlugins(ctx, conn, req, body)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	query := url.Values{"page": {"1"}, "size": {"100"}, "order": {"-_id"}, "name": {name}}
	existing, err := a.authenticatedRequest(ctx, conn, http.MethodGet, "/api/policy/", query, nil)
	if err != nil {
		return nil, err
	}
	if items, ok := existing["items"].([]interface{}); ok {
		for _, raw := range items {
			item := valueMap(raw)
			if item == nil || !strings.EqualFold(strings.TrimSpace(fmt.Sprint(item["name"])), name) {
				continue
			}
			policyID := strings.TrimSpace(fmt.Sprint(item["_id"]))
			if req.PresetID == "" {
				return nil, fmt.Errorf("ARL 策略名称已存在: %s", name)
			}
			updated, err := a.authenticatedRequest(ctx, conn, http.MethodPost, "/api/policy/edit/", nil, map[string]interface{}{
				"policy_id": policyID, "policy_data": body,
			})
			if err != nil {
				return nil, fmt.Errorf("校准已有 ARL 内置策略失败: %w", err)
			}
			result := map[string]interface{}{
				"provider": ProviderARL, "resource_id": conn.Resource.ID, "template_kind": "policy",
				"template_id": policyID, "policy_id": policyID, "template_name": name,
				"preset_id": req.PresetID, "reused": true, "updated": true, "policy": updated,
				"plugin_summary": pluginSummary,
			}
			a.attachPolicyVerification(ctx, conn, policyID, body, result)
			return result, nil
		}
	}
	created, err := a.authenticatedRequest(ctx, conn, http.MethodPost, "/api/policy/add/", nil, body)
	if err != nil {
		return nil, err
	}
	data := valueMap(created["data"])
	policyID := strings.TrimSpace(fmt.Sprint(data["policy_id"]))
	if !arlTaskIDPattern.MatchString(policyID) {
		return nil, fmt.Errorf("ARL 策略已创建但未返回有效 policy_id")
	}
	result := map[string]interface{}{
		"provider": ProviderARL, "resource_id": conn.Resource.ID, "template_kind": "policy",
		"template_id": policyID, "policy_id": policyID, "template_name": name,
		"preset_id": req.PresetID, "reused": false, "updated": false, "response": created,
		"plugin_summary": pluginSummary,
	}
	a.attachPolicyVerification(ctx, conn, policyID, body, result)
	return result, nil
}

func (a *ARLAdapter) ManageTask(ctx context.Context, conn *Connection, req TaskManageRequest) (interface{}, error) {
	if !arlTaskIDPattern.MatchString(req.TaskID) {
		return nil, fmt.Errorf("ARL 任务 ID 格式无效")
	}
	var method, endpoint string
	var body interface{}
	switch req.Action {
	case "restart":
		method, endpoint, body = http.MethodPost, "/api/task/restart/", map[string]interface{}{"task_id": []string{req.TaskID}}
	case "delete":
		deleteResults, _ := req.Options["delete_results"].(bool)
		method, endpoint, body = http.MethodPost, "/api/task/delete/", map[string]interface{}{"task_id": []string{req.TaskID}, "del_task_data": deleteResults}
	case "sync_results":
		scopeID := strings.TrimSpace(fmt.Sprint(req.Options["scope_id"]))
		if !arlTaskIDPattern.MatchString(scopeID) {
			return nil, fmt.Errorf("ARL 结果同步需要有效的 scope_id")
		}
		method, endpoint, body = http.MethodPost, "/api/task/sync/", map[string]interface{}{"task_id": req.TaskID, "scope_id": scopeID}
	default:
		return nil, fmt.Errorf("ARL 不支持的任务管理动作: %s", req.Action)
	}
	payload, err := a.authenticatedRequest(ctx, conn, method, endpoint, nil, body)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderARL, "resource_id": conn.Resource.ID, "action": req.Action, "response": payload}, nil
}
