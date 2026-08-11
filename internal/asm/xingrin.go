package asm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const xingrinMaxResponseBytes = 4 * 1024 * 1024

var (
	xingrinTaskIDPattern = regexp.MustCompile(`^[1-9][0-9]*$`)
	xingrinPortsPattern  = regexp.MustCompile(`^[0-9,-]+$`)
)

type XingRinAdapter struct{}

func NewXingRinAdapter() *XingRinAdapter { return &XingRinAdapter{} }

func (a *XingRinAdapter) Provider() string { return ProviderXingRin }

func (a *XingRinAdapter) Capabilities() []string {
	return []string{"test_connection", "create_task", "list_tasks", "get_task", "list_assets", "stop_task"}
}

func xingrinHTTPClient(verifyTLS bool) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("初始化 XingRin Cookie 会话失败: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !verifyTLS} // #nosec G402 -- operator-controlled compatibility option for lab ASM deployments.
	return &http.Client{
		Timeout:   45 * time.Second,
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func xingrinRequest(ctx context.Context, client *http.Client, conn *Connection, method, apiPath string, query url.Values, body interface{}) (interface{}, error) {
	endpoint := strings.TrimRight(conn.Resource.BaseURL, "/") + apiPath
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("编码 XingRin 请求失败: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, fmt.Errorf("创建 XingRin 请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CyberStrikeAI-ASM/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 XingRin 失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, xingrinMaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取 XingRin 响应失败: %w", err)
	}
	if len(raw) > xingrinMaxResponseBytes {
		return nil, fmt.Errorf("XingRin 响应超过 %d 字节限制", xingrinMaxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := strings.TrimSpace(string(raw))
		if len(detail) > 500 {
			detail = detail[:500]
		}
		return nil, fmt.Errorf("XingRin HTTP %d: %s", resp.StatusCode, detail)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]interface{}{}, nil
	}
	var payload interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("解析 XingRin 响应失败: %w", err)
	}
	return payload, nil
}

func (a *XingRinAdapter) session(ctx context.Context, conn *Connection) (*http.Client, interface{}, error) {
	if conn.Resource.AuthType != "password" {
		return nil, nil, fmt.Errorf("XingRin 当前仅支持用户名和密码认证")
	}
	if strings.TrimSpace(conn.Resource.Username) == "" || conn.Secret == "" {
		return nil, nil, fmt.Errorf("XingRin 用户名或密码为空")
	}
	client, err := xingrinHTTPClient(conn.Resource.VerifyTLS)
	if err != nil {
		return nil, nil, err
	}
	login, err := xingrinRequest(ctx, client, conn, http.MethodPost, "/api/auth/login/", nil, map[string]string{
		"username": conn.Resource.Username,
		"password": conn.Secret,
	})
	if err != nil {
		return nil, nil, err
	}
	return client, login, nil
}

func (a *XingRinAdapter) Test(ctx context.Context, conn *Connection) (interface{}, error) {
	client, login, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	me, err := xingrinRequest(ctx, client, conn, http.MethodGet, "/api/auth/me/", nil, nil)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider": ProviderXingRin, "connected": true, "login": login, "session": me,
	}, nil
}

func xingrinCollection(payload interface{}) []interface{} {
	if items, ok := payload.([]interface{}); ok {
		return items
	}
	if object, ok := payload.(map[string]interface{}); ok {
		if items, ok := object["results"].([]interface{}); ok {
			return items
		}
	}
	return nil
}

func xingrinEngine(payload interface{}) (interface{}, string, error) {
	items := xingrinCollection(payload)
	if len(items) == 0 {
		return nil, "", fmt.Errorf("XingRin 未返回可用扫描引擎")
	}
	var fallback map[string]interface{}
	for _, raw := range items {
		item, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if fallback == nil {
			fallback = item
		}
		if strings.EqualFold(strings.TrimSpace(fmt.Sprint(item["name"])), "full scan") {
			fallback = item
			break
		}
	}
	if fallback == nil || fallback["id"] == nil {
		return nil, "", fmt.Errorf("XingRin 扫描引擎数据无效")
	}
	name := strings.TrimSpace(fmt.Sprint(fallback["name"]))
	if name == "" || name == "<nil>" {
		return nil, "", fmt.Errorf("XingRin 扫描引擎名称无效")
	}
	return fallback["id"], name, nil
}

func xingrinBoolOption(options map[string]interface{}, key string, fallback bool) (bool, error) {
	value, exists := options[key]
	if !exists || value == nil {
		return fallback, nil
	}
	result, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("XingRin 任务选项 %s 必须是布尔值", key)
	}
	return result, nil
}

func xingrinIntOption(options map[string]interface{}, key string, fallback, minimum, maximum int) (int, error) {
	value, exists := options[key]
	if !exists || value == nil {
		return fallback, nil
	}
	var result int
	switch number := value.(type) {
	case int:
		result = number
	case int64:
		result = int(number)
	case float64:
		result = int(number)
	case json.Number:
		parsed, err := strconv.Atoi(number.String())
		if err != nil {
			return 0, fmt.Errorf("XingRin 任务选项 %s 必须是整数", key)
		}
		result = parsed
	default:
		return 0, fmt.Errorf("XingRin 任务选项 %s 必须是整数", key)
	}
	if result < minimum || result > maximum {
		return 0, fmt.Errorf("XingRin 任务选项 %s 必须在 %d 到 %d 之间", key, minimum, maximum)
	}
	return result, nil
}

func validateXingRinPorts(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "80,443,8080,8083", nil
	}
	if len(value) > 200 || !xingrinPortsPattern.MatchString(value) {
		return "", fmt.Errorf("XingRin ports 仅支持逗号分隔的端口或端口范围")
	}
	for _, part := range strings.Split(value, ",") {
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return "", fmt.Errorf("XingRin ports 格式无效")
		}
		previous := 0
		for _, bound := range bounds {
			port, err := strconv.Atoi(bound)
			if err != nil || port < 1 || port > 65535 || (previous > 0 && port < previous) {
				return "", fmt.Errorf("XingRin ports 包含无效端口")
			}
			previous = port
		}
	}
	return value, nil
}

func buildXingRinConfiguration(options map[string]interface{}) (string, error) {
	portScan, err := xingrinBoolOption(options, "port_scan", true)
	if err != nil {
		return "", err
	}
	siteScan, err := xingrinBoolOption(options, "site_identify", true)
	if err != nil {
		return "", err
	}
	siteCapture, err := xingrinBoolOption(options, "site_capture", false)
	if err != nil {
		return "", err
	}
	nucleiScan, err := xingrinBoolOption(options, "nuclei_scan", false)
	if err != nil {
		return "", err
	}
	if !portScan && !siteScan && !siteCapture && !nucleiScan {
		return "", fmt.Errorf("XingRin 至少需要启用一个扫描阶段")
	}
	if siteCapture || nucleiScan {
		// 截图和漏洞扫描都依赖站点发现结果。
		siteScan = true
	}
	ports, err := validateXingRinPorts(strings.TrimSpace(fmt.Sprint(options["ports"])))
	if options["ports"] == nil {
		ports, err = validateXingRinPorts("")
	}
	if err != nil {
		return "", err
	}
	rate, err := xingrinIntOption(options, "rate_limit", 20, 1, 1000)
	if err != nil {
		return "", err
	}
	concurrency, err := xingrinIntOption(options, "concurrency", 5, 1, 200)
	if err != nil {
		return "", err
	}

	var config strings.Builder
	if portScan {
		fmt.Fprintf(&config, "port_scan:\n  tools:\n    naabu_active:\n      enabled: true\n      ports: \"%s\"\n      threads: %d\n      rate: %d\n    naabu_passive:\n      enabled: false\n", ports, concurrency, rate)
	}
	if siteScan {
		fmt.Fprintf(&config, "site_scan:\n  tools:\n    httpx:\n      enabled: true\n      threads: %d\n      rate-limit: %d\n      request-timeout: 8\n      retries: 1\n", concurrency, rate)
		config.WriteString("fingerprint_detect:\n  tools:\n    xingfinger:\n      enabled: true\n      fingerprint-libs: [ehole, goby, wappalyzer, fingers, fingerprinthub, arl]\n")
	}
	if siteCapture {
		fmt.Fprintf(&config, "screenshot:\n  tools:\n    playwright:\n      enabled: true\n      concurrency: %d\n      url_sources: [websites]\n", concurrency)
	}
	if nucleiScan {
		fmt.Fprintf(&config, "vuln_scan:\n  tools:\n    dalfox_xss:\n      enabled: false\n    nuclei:\n      enabled: true\n      template-repo-names:\n        - nuclei-templates\n      concurrency: %d\n      rate-limit: %d\n      request-timeout: 8\n      severity: medium,high,critical\n      tags: cve\n", concurrency, rate)
	}
	return config.String(), nil
}

func (a *XingRinAdapter) CreateTask(ctx context.Context, conn *Connection, req TaskRequest) (interface{}, error) {
	target := strings.TrimSpace(req.Target)
	if target == "" || len(target) > 10000 {
		return nil, fmt.Errorf("任务目标不能为空且不能超过 10000 字符")
	}
	configuration, err := buildXingRinConfiguration(req.Options)
	if err != nil {
		return nil, err
	}
	client, _, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	engines, err := xingrinRequest(ctx, client, conn, http.MethodGet, "/api/engines/", nil, nil)
	if err != nil {
		return nil, err
	}
	engineID, engineName, err := xingrinEngine(engines)
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"targets":       []map[string]string{{"name": target}},
		"configuration": configuration,
		"engineIds":     []interface{}{engineID},
		"engineNames":   []string{engineName},
	}
	payload, err := xingrinRequest(ctx, client, conn, http.MethodPost, "/api/scans/quick/", nil, body)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderXingRin, "resource_id": conn.Resource.ID, "response": payload}, nil
}

func normalizeXingRinTaskID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !xingrinTaskIDPattern.MatchString(value) {
		return "", fmt.Errorf("XingRin 任务 ID 格式无效")
	}
	return value, nil
}

func (a *XingRinAdapter) ListTasks(ctx context.Context, conn *Connection, filter TaskFilter) (interface{}, error) {
	client, _, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(filter.TaskID) != "" {
		taskID, err := normalizeXingRinTaskID(filter.TaskID)
		if err != nil {
			return nil, err
		}
		payload, err := xingrinRequest(ctx, client, conn, http.MethodGet, "/api/scans/"+taskID+"/", nil, nil)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"provider": ProviderXingRin, "resource_id": conn.Resource.ID,
			"tasks": map[string]interface{}{"results": []interface{}{payload}, "total": 1, "page": 1, "pageSize": 1, "totalPages": 1},
		}, nil
	}
	page, size := normalizePagination(filter.Page, filter.PageSize)
	query := url.Values{"page": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	search := strings.TrimSpace(filter.Target)
	if search == "" {
		search = strings.TrimSpace(filter.Name)
	}
	if search != "" {
		query.Set("search", search)
	}
	if status := strings.TrimSpace(filter.Status); status != "" {
		query.Set("status", status)
	}
	payload, err := xingrinRequest(ctx, client, conn, http.MethodGet, "/api/scans/", query, nil)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderXingRin, "resource_id": conn.Resource.ID, "tasks": payload}, nil
}

func (a *XingRinAdapter) GetTask(ctx context.Context, conn *Connection, taskID string) (interface{}, error) {
	return a.ListTasks(ctx, conn, TaskFilter{TaskID: taskID, Page: 1, PageSize: 1})
}

var xingrinAssetEndpoints = map[string]struct{ segment, queryField string }{
	"site":          {"websites", "url"},
	"domain":        {"subdomains", "name"},
	"ip":            {"ip-addresses", "ip"},
	"url":           {"endpoints", "url"},
	"service":       {"ip-addresses", "ip"},
	"vulnerability": {"vulnerabilities", "url"},
}

func xingrinFilterExpression(field, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if len(value) > 500 {
		return "", fmt.Errorf("XingRin 资产查询内容过长")
	}
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return field + `="` + value + `"`, nil
}

func (a *XingRinAdapter) ListAssets(ctx context.Context, conn *Connection, filter AssetFilter) (interface{}, error) {
	assetType := strings.ToLower(strings.TrimSpace(filter.Type))
	if assetType == "" {
		assetType = "site"
	}
	endpoint, ok := xingrinAssetEndpoints[assetType]
	if !ok {
		return nil, fmt.Errorf("XingRin 结果类型不支持: %s", assetType)
	}
	page, size := normalizePagination(filter.Page, filter.PageSize)
	query := url.Values{"page": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	expression, err := xingrinFilterExpression(endpoint.queryField, filter.Query)
	if err != nil {
		return nil, err
	}
	if expression != "" {
		query.Set("filter", expression)
	}
	apiPath := "/api/assets/" + endpoint.segment + "/"
	if strings.TrimSpace(filter.TaskID) != "" {
		taskID, err := normalizeXingRinTaskID(filter.TaskID)
		if err != nil {
			return nil, err
		}
		apiPath = "/api/scans/" + taskID + "/" + endpoint.segment + "/"
	}
	client, _, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	payload, err := xingrinRequest(ctx, client, conn, http.MethodGet, apiPath, query, nil)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider": ProviderXingRin, "resource_id": conn.Resource.ID,
		"asset_type": assetType, "results": payload,
	}, nil
}

func (a *XingRinAdapter) StopTask(ctx context.Context, conn *Connection, taskID string) (interface{}, error) {
	taskID, err := normalizeXingRinTaskID(taskID)
	if err != nil {
		return nil, err
	}
	client, _, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	payload, err := xingrinRequest(ctx, client, conn, http.MethodPost, "/api/scans/"+taskID+"/stop/", nil, map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderXingRin, "resource_id": conn.Resource.ID, "response": payload}, nil
}
