package asm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
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

func NewARLAdapter() *ARLAdapter { return &ARLAdapter{} }

func (a *ARLAdapter) Provider() string { return ProviderARL }

func (a *ARLAdapter) Capabilities() []string {
	return []string{"test_connection", "create_task", "list_tasks", "get_task", "list_assets", "stop_task"}
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
		return fmt.Errorf("%s (code=%v)", message, code)
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

func buildARLTaskBody(req TaskRequest) (map[string]interface{}, error) {
	name, target := strings.TrimSpace(req.Name), strings.TrimSpace(req.Target)
	if target == "" || len(target) > 10000 {
		return nil, fmt.Errorf("任务目标不能为空且不能超过 10000 字符")
	}
	if name == "" {
		name = "CyberStrikeAI ASM task"
	}
	if len(name) > 200 {
		return nil, fmt.Errorf("任务名称不能超过 200 字符")
	}
	body := map[string]interface{}{"name": name, "target": target}
	for key, value := range arlTaskOptionDefaults {
		body[key] = value
	}
	for key, value := range req.Options {
		if _, allowed := arlTaskOptionDefaults[key]; !allowed {
			return nil, fmt.Errorf("ARL 不支持的任务选项: %s", key)
		}
		body[key] = value
	}
	return body, nil
}

func (a *ARLAdapter) CreateTask(ctx context.Context, conn *Connection, req TaskRequest) (interface{}, error) {
	body, err := buildARLTaskBody(req)
	if err != nil {
		return nil, err
	}
	payload, err := a.authenticatedRequest(ctx, conn, http.MethodPost, "/api/task/", nil, body)
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
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderARL, "resource_id": conn.Resource.ID, "response": payload}, nil
}
