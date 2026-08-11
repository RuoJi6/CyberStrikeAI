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

const (
	scopeSentryMaxResponseBytes = 4 * 1024 * 1024
	scopeSentryTemplateName     = "CyberStrikeAI low-load"
)

var scopeSentryTaskIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)

type ScopeSentryAdapter struct{}

func NewScopeSentryAdapter() *ScopeSentryAdapter { return &ScopeSentryAdapter{} }

func (a *ScopeSentryAdapter) Provider() string { return ProviderScopeSentry }

func (a *ScopeSentryAdapter) Capabilities() []string {
	return []string{"test_connection", "create_task", "list_tasks", "get_task", "list_assets", "stop_task"}
}

func scopeSentryHTTPClient(verifyTLS bool) *http.Client {
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

func scopeSentryRequest(ctx context.Context, client *http.Client, conn *Connection, token, method, apiPath string, query url.Values, body interface{}) (interface{}, error) {
	endpoint := strings.TrimRight(conn.Resource.BaseURL, "/") + apiPath
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("编码 ScopeSentry 请求失败: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, fmt.Errorf("创建 ScopeSentry 请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "zh-CN")
	req.Header.Set("User-Agent", "CyberStrikeAI-ASM/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 ScopeSentry 失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, scopeSentryMaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取 ScopeSentry 响应失败: %w", err)
	}
	if len(raw) > scopeSentryMaxResponseBytes {
		return nil, fmt.Errorf("ScopeSentry 响应超过 %d 字节限制", scopeSentryMaxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := strings.TrimSpace(string(raw))
		if len(detail) > 500 {
			detail = detail[:500]
		}
		return nil, fmt.Errorf("ScopeSentry HTTP %d: %s", resp.StatusCode, detail)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]interface{}{}, nil
	}
	var payload interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("解析 ScopeSentry 响应失败: %w", err)
	}
	return payload, nil
}

func scopeSentryMap(value interface{}) map[string]interface{} {
	result, _ := value.(map[string]interface{})
	return result
}

func scopeSentryData(value interface{}) interface{} {
	object := scopeSentryMap(value)
	if data, exists := object["data"]; exists {
		return data
	}
	return value
}

func scopeSentryList(value interface{}) []interface{} {
	data := scopeSentryData(value)
	if list, ok := data.([]interface{}); ok {
		return list
	}
	object := scopeSentryMap(data)
	for _, key := range []string{"list", "results"} {
		if list, ok := object[key].([]interface{}); ok {
			return list
		}
	}
	return nil
}

func (a *ScopeSentryAdapter) session(ctx context.Context, conn *Connection) (*http.Client, string, error) {
	if conn.Resource.AuthType != "password" {
		return nil, "", fmt.Errorf("ScopeSentry 当前仅支持用户名和密码认证")
	}
	if strings.TrimSpace(conn.Resource.Username) == "" || conn.Secret == "" {
		return nil, "", fmt.Errorf("ScopeSentry 用户名或密码为空")
	}
	client := scopeSentryHTTPClient(conn.Resource.VerifyTLS)
	login, err := scopeSentryRequest(ctx, client, conn, "", http.MethodPost, "/api/user/login", nil, map[string]string{
		"username": conn.Resource.Username,
		"password": conn.Secret,
	})
	if err != nil {
		return nil, "", err
	}
	data := scopeSentryMap(scopeSentryData(login))
	token := strings.TrimSpace(fmt.Sprint(data["access_token"]))
	if token == "" || token == "<nil>" {
		token = strings.TrimSpace(fmt.Sprint(data["accessToken"]))
	}
	if token == "" || token == "<nil>" {
		return nil, "", fmt.Errorf("ScopeSentry 登录响应未包含 access_token")
	}
	return client, token, nil
}

func (a *ScopeSentryAdapter) Test(ctx context.Context, conn *Connection) (interface{}, error) {
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	nodes, err := scopeSentryRequest(ctx, client, conn, token, http.MethodGet, "/api/node/online", nil, nil)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider": ProviderScopeSentry, "connected": true, "nodes": scopeSentryData(nodes),
	}, nil
}

func scopeSentryOnlineNode(value interface{}) (string, error) {
	items := scopeSentryList(value)
	for _, item := range items {
		name := strings.TrimSpace(fmt.Sprint(item))
		if object, ok := item.(map[string]interface{}); ok {
			name = strings.TrimSpace(fmt.Sprint(object["name"]))
		}
		if name != "" && name != "<nil>" {
			return name, nil
		}
	}
	return "", fmt.Errorf("ScopeSentry 未返回在线扫描节点")
}

func scopeSentryTemplateByName(value interface{}, name string) (string, map[string]interface{}) {
	for _, item := range scopeSentryList(value) {
		object := scopeSentryMap(item)
		if !strings.EqualFold(strings.TrimSpace(fmt.Sprint(object["name"])), name) {
			continue
		}
		id := strings.TrimSpace(fmt.Sprint(object["id"]))
		if id != "" && id != "<nil>" {
			return id, object
		}
	}
	return "", nil
}

func scopeSentryPorts(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "80,443,8080,8082", nil
	}
	if len(value) > 200 {
		return "", fmt.Errorf("ScopeSentry ports 过长")
	}
	for _, part := range strings.Split(value, ",") {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) < 1 || len(bounds) > 2 {
			return "", fmt.Errorf("ScopeSentry ports 格式无效")
		}
		previous := 0
		for _, bound := range bounds {
			port, err := strconv.Atoi(bound)
			if err != nil || port < 1 || port > 65535 || (previous > 0 && port < previous) {
				return "", fmt.Errorf("ScopeSentry ports 包含无效端口")
			}
			previous = port
		}
	}
	return value, nil
}

func scopeSentryLowLoadOptions(options map[string]interface{}) (string, int, bool, bool, error) {
	portScan, err := xingrinBoolOption(options, "port_scan", true)
	if err != nil {
		return "", 0, false, false, fmt.Errorf("%s", strings.ReplaceAll(err.Error(), "XingRin", "ScopeSentry"))
	}
	siteIdentify, err := xingrinBoolOption(options, "site_identify", true)
	if err != nil {
		return "", 0, false, false, fmt.Errorf("%s", strings.ReplaceAll(err.Error(), "XingRin", "ScopeSentry"))
	}
	if !portScan && !siteIdentify {
		return "", 0, false, false, fmt.Errorf("ScopeSentry 至少需要启用 port_scan 或 site_identify")
	}
	ports, err := scopeSentryPorts(strings.TrimSpace(fmt.Sprint(options["ports"])))
	if options["ports"] == nil {
		ports, err = scopeSentryPorts("")
	}
	if err != nil {
		return "", 0, false, false, err
	}
	concurrency, err := xingrinIntOption(options, "concurrency", 20, 1, 200)
	if err != nil {
		return "", 0, false, false, fmt.Errorf("%s", strings.ReplaceAll(err.Error(), "XingRin", "ScopeSentry"))
	}
	return ports, concurrency, portScan, siteIdentify, nil
}

func scopeSentryPruneTemplate(source map[string]interface{}, ports string, concurrency int, portScan, siteIdentify bool) map[string]interface{} {
	result := make(map[string]interface{}, len(source))
	for key, value := range source {
		result[key] = value
	}
	delete(result, "id")
	result["name"] = scopeSentryTemplateName
	result["TaskName"] = ""
	result["VulList"] = []interface{}{}
	result["vullist"] = []interface{}{}

	keep := map[string]bool{
		"PortScan":        portScan,
		"PortFingerprint": portScan,
		"AssetMapping":    siteIdentify,
		"AssetHandle":     true,
	}
	modules := []string{
		"TargetHandler", "SubdomainScan", "SubdomainSecurity", "PortScanPreparation",
		"PortScan", "PortFingerprint", "AssetMapping", "AssetHandle", "URLScan",
		"WebCrawler", "URLSecurity", "DirScan", "VulnerabilityScan", "PassiveScan",
	}
	for _, module := range modules {
		if !keep[module] {
			result[module] = []interface{}{}
		}
	}
	for _, parameterKey := range []string{"Parameters", "ParameterLists"} {
		parameters := scopeSentryMap(result[parameterKey])
		if parameters == nil {
			parameters = make(map[string]interface{})
		}
		for _, module := range modules {
			if !keep[module] {
				parameters[module] = map[string]interface{}{}
			}
		}
		if portScan {
			pluginParameters := scopeSentryMap(parameters["PortScan"])
			for hash := range pluginParameters {
				pluginParameters[hash] = fmt.Sprintf("-port %s -b %d -t 5000", ports, concurrency)
			}
			parameters["PortScan"] = pluginParameters
		}
		if siteIdentify {
			mappingParameters := scopeSentryMap(parameters["AssetMapping"])
			for hash := range mappingParameters {
				mappingParameters[hash] = "-cdncheck true -screenshot false -tlsprobe false"
			}
			parameters["AssetMapping"] = mappingParameters
		}
		result[parameterKey] = parameters
	}
	return result
}

func (a *ScopeSentryAdapter) ensureTemplate(ctx context.Context, client *http.Client, conn *Connection, token string, options map[string]interface{}) (string, error) {
	ports, concurrency, portScan, siteIdentify, err := scopeSentryLowLoadOptions(options)
	if err != nil {
		return "", err
	}
	listBody := map[string]interface{}{"pageIndex": 1, "pageSize": 100, "query": ""}
	templates, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template", nil, listBody)
	if err != nil {
		return "", err
	}
	existingID, _ := scopeSentryTemplateByName(templates, scopeSentryTemplateName)
	defaultID, _ := scopeSentryTemplateByName(templates, "default")
	if defaultID == "" {
		return "", fmt.Errorf("ScopeSentry 未找到 default 扫描模板")
	}
	detail, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template/detail", nil, map[string]string{"id": defaultID})
	if err != nil {
		return "", err
	}
	source := scopeSentryMap(scopeSentryData(detail))
	if source == nil {
		return "", fmt.Errorf("ScopeSentry default 模板详情无效")
	}
	profile := scopeSentryPruneTemplate(source, ports, concurrency, portScan, siteIdentify)
	_, err = scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template/save", nil, map[string]interface{}{
		"id": existingID, "result": profile,
	})
	if err != nil {
		return "", err
	}
	if existingID != "" {
		return existingID, nil
	}
	for attempt := 0; attempt < 10; attempt++ {
		templates, err = scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template", nil, map[string]interface{}{
			"pageIndex": 1, "pageSize": 20, "query": scopeSentryTemplateName,
		})
		if err == nil {
			if id, _ := scopeSentryTemplateByName(templates, scopeSentryTemplateName); id != "" {
				return id, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return "", fmt.Errorf("ScopeSentry 专用低负载模板创建后不可见")
}

func (a *ScopeSentryAdapter) CreateTask(ctx context.Context, conn *Connection, req TaskRequest) (interface{}, error) {
	target := strings.TrimSpace(req.Target)
	if target == "" || len(target) > 10000 {
		return nil, fmt.Errorf("任务目标不能为空且不能超过 10000 字符")
	}
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	nodes, err := scopeSentryRequest(ctx, client, conn, token, http.MethodGet, "/api/node/online", nil, nil)
	if err != nil {
		return nil, err
	}
	node, err := scopeSentryOnlineNode(nodes)
	if err != nil {
		return nil, err
	}
	templateID, err := a.ensureTemplate(ctx, client, conn, token, req.Options)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "CyberStrikeAI ASM " + time.Now().Format("20060102-150405.000")
	}
	if len(name) > 150 {
		return nil, fmt.Errorf("ScopeSentry 任务名称不能超过 150 字符")
	}
	_, err = scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/add", nil, map[string]interface{}{
		"name": name, "node": []string{node}, "allNode": false, "scheduledTasks": false,
		"target": target, "ignore": "", "template": templateID, "project": []string{},
		"search": "", "duplicates": "true", "targetSource": "general", "targetNumber": 1,
	})
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 15; attempt++ {
		listed, listErr := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/", nil, map[string]interface{}{
			"pageIndex": 1, "pageSize": 20, "search": name,
		})
		if listErr == nil {
			for _, item := range scopeSentryList(listed) {
				task := scopeSentryMap(item)
				if strings.TrimSpace(fmt.Sprint(task["name"])) != name {
					continue
				}
				id := strings.TrimSpace(fmt.Sprint(task["id"]))
				if scopeSentryTaskIDPattern.MatchString(id) {
					return map[string]interface{}{
						"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID,
						"task": task, "template_id": templateID, "node": node,
					}, nil
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("ScopeSentry 任务已提交但无法读取任务 ID")
}

func normalizeScopeSentryTaskID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !scopeSentryTaskIDPattern.MatchString(value) {
		return "", fmt.Errorf("ScopeSentry 任务 ID 格式无效")
	}
	return strings.ToLower(value), nil
}

func (a *ScopeSentryAdapter) ListTasks(ctx context.Context, conn *Connection, filter TaskFilter) (interface{}, error) {
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(filter.TaskID) != "" {
		return a.getTaskWithSession(ctx, client, conn, token, filter.TaskID)
	}
	page, size := normalizePagination(filter.Page, filter.PageSize)
	search := strings.TrimSpace(filter.Name)
	if search == "" {
		search = strings.TrimSpace(filter.Target)
	}
	payload, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/", nil, map[string]interface{}{
		"pageIndex": page, "pageSize": size, "search": search,
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID, "tasks": payload}, nil
}

func scopeSentryStatus(value interface{}) string {
	switch strings.TrimSpace(fmt.Sprint(value)) {
	case "1":
		return "running"
	case "2":
		return "stopped"
	case "3":
		return "completed"
	default:
		return "unknown"
	}
}

func (a *ScopeSentryAdapter) getTaskWithSession(ctx context.Context, client *http.Client, conn *Connection, token, taskID string) (interface{}, error) {
	taskID, err := normalizeScopeSentryTaskID(taskID)
	if err != nil {
		return nil, err
	}
	payload, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/detail", nil, map[string]string{"id": taskID})
	if err != nil {
		return nil, err
	}
	task := scopeSentryMap(scopeSentryData(payload))
	status := task["status"]
	name := strings.TrimSpace(fmt.Sprint(task["name"]))
	if name != "" {
		listed, listErr := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/", nil, map[string]interface{}{
			"pageIndex": 1, "pageSize": 20, "search": name,
		})
		if listErr == nil {
			for _, item := range scopeSentryList(listed) {
				summary := scopeSentryMap(item)
				if strings.EqualFold(strings.TrimSpace(fmt.Sprint(summary["id"])), taskID) {
					listedStatus := scopeSentryStatus(summary["status"])
					if scopeSentryStatus(status) == "unknown" || listedStatus == "completed" || listedStatus == "stopped" {
						status = summary["status"]
					}
					break
				}
			}
		}
	}
	return map[string]interface{}{
		"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID,
		"task": payload, "normalized_status": scopeSentryStatus(status),
	}, nil
}

func (a *ScopeSentryAdapter) GetTask(ctx context.Context, conn *Connection, taskID string) (interface{}, error) {
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	return a.getTaskWithSession(ctx, client, conn, token, taskID)
}

var scopeSentryAssetEndpoints = map[string]struct{ path, field string }{
	"site":          {"/api/assets/asset", "domain"},
	"domain":        {"/api/assets/subdomain", "domain"},
	"ip":            {"/api/assets/ip", "ip"},
	"url":           {"/api/assets/url", "url"},
	"service":       {"/api/assets/ip", "service"},
	"vulnerability": {"/api/assets/vulnerability", "url"},
}

func scopeSentrySearchValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > 500 {
		return "", fmt.Errorf("ScopeSentry 资产查询内容过长")
	}
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value, nil
}

func (a *ScopeSentryAdapter) ListAssets(ctx context.Context, conn *Connection, filter AssetFilter) (interface{}, error) {
	assetType := strings.ToLower(strings.TrimSpace(filter.Type))
	if assetType == "" {
		assetType = "site"
	}
	endpoint, ok := scopeSentryAssetEndpoints[assetType]
	if !ok {
		return nil, fmt.Errorf("ScopeSentry 结果类型不支持: %s", assetType)
	}
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	expressions := make([]string, 0, 2)
	if strings.TrimSpace(filter.TaskID) != "" {
		taskID, err := normalizeScopeSentryTaskID(filter.TaskID)
		if err != nil {
			return nil, err
		}
		detail, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/detail", nil, map[string]string{"id": taskID})
		if err != nil {
			return nil, err
		}
		name, err := scopeSentrySearchValue(strings.TrimSpace(fmt.Sprint(scopeSentryMap(scopeSentryData(detail))["name"])))
		if err != nil {
			return nil, err
		}
		if name != "" && name != "<nil>" {
			expressions = append(expressions, `task="`+name+`"`)
		}
	}
	if strings.TrimSpace(filter.Query) != "" {
		queryValue, err := scopeSentrySearchValue(filter.Query)
		if err != nil {
			return nil, err
		}
		expressions = append(expressions, endpoint.field+`="`+queryValue+`"`)
	}
	page, size := normalizePagination(filter.Page, filter.PageSize)
	payload, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, endpoint.path, nil, map[string]interface{}{
		"pageIndex": page, "pageSize": size, "search": strings.Join(expressions, "&&"),
		"filter": map[string]interface{}{}, "sort": map[string]interface{}{},
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID,
		"asset_type": assetType, "results": payload,
	}, nil
}

func (a *ScopeSentryAdapter) StopTask(ctx context.Context, conn *Connection, taskID string) (interface{}, error) {
	taskID, err := normalizeScopeSentryTaskID(taskID)
	if err != nil {
		return nil, err
	}
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	payload, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/stop", nil, map[string]interface{}{"ids": []string{taskID}})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID, "response": payload}, nil
}
