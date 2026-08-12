package asm

import (
	"bytes"
	"context"
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
	"time"
)

const arlMaxResponseBytes = 4 * 1024 * 1024

var arlTaskIDPattern = regexp.MustCompile(`^[a-fA-F0-9]{24}$`)

type ARLAdapter struct{}

type arlAPIError struct {
	Code    string
	Message string
}

func (e *arlAPIError) Error() string { return fmt.Sprintf("%s (code=%s)", e.Message, e.Code) }

func NewARLAdapter() *ARLAdapter { return &ARLAdapter{} }

func (a *ARLAdapter) Provider() string { return ProviderARL }

func (a *ARLAdapter) Capabilities() []string {
	return []string{"test_connection", "get_task_profile", "list_task_options", "create_task", "list_tasks", "get_task", "list_assets", "stop_task", "manage_task"}
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
	return token, nil
}

func (a *ARLAdapter) authenticatedRequest(ctx context.Context, conn *Connection, method, apiPath string, query url.Values, body interface{}) (map[string]interface{}, error) {
	token, err := a.token(ctx, conn)
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
	return map[string]interface{}{"provider": ProviderARL, "resource_id": conn.Resource.ID, "response": payload}, nil
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
		"dynamic_option_kinds": []string{"policies", "policy_detail", "pocs", "scopes"},
		"manage_actions":       []string{"restart", "delete", "sync_results"},
		"notes": []string{
			"direct 模式对应 /api/task/，仅支持 ARL 直接任务字段",
			"policy 模式对应 /api/task/policy/，自定义端口、排除端口、速率、POC 和字典由 policy_id 指向的上游策略决定，不支持任务级覆盖",
		},
		"create_options": map[string]interface{}{
			"task_mode":         map[string]interface{}{"type": "string", "enum": []string{"direct", "policy"}, "default": "direct"},
			"policy_id":         map[string]interface{}{"type": "string", "description": "policy 模式使用的 ARL 策略 ID"},
			"task_tag":          map[string]interface{}{"type": "string", "enum": []string{"task", "risk_cruising"}, "default": "task"},
			"result_set_id":     map[string]interface{}{"type": "string", "description": "风险巡航可选结果集 ID"},
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
		"policy_fields": map[string]interface{}{
			"port_scan_type": []string{"test", "top100", "top1000", "all", "custom"},
			"advanced":       []string{"port_custom", "exclude_ports", "host_timeout_type", "host_timeout", "port_parallelism", "port_min_rate", "poc_config", "brute_config", "scope_config"},
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
