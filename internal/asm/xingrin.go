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
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
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
	return []string{"test_connection", "get_task_profile", "list_task_options", "create_task", "list_tasks", "get_task", "list_assets", "stop_task"}
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

func xingrinEngineOptions(payload interface{}, detailID string) (interface{}, error) {
	detailID = strings.TrimSpace(detailID)
	if detailID != "" {
		if !xingrinTaskIDPattern.MatchString(detailID) {
			return nil, fmt.Errorf("XingRin 引擎 ID 格式无效")
		}
		for _, raw := range xingrinCollection(payload) {
			item := valueMap(raw)
			if item != nil && meaningfulString(item["id"]) == detailID {
				return map[string]interface{}{"item": item}, nil
			}
		}
		return nil, fmt.Errorf("XingRin 引擎 ID 不存在: %s", detailID)
	}

	items := make([]interface{}, 0, len(xingrinCollection(payload)))
	for _, raw := range xingrinCollection(payload) {
		item := valueMap(raw)
		if item == nil {
			continue
		}
		delete(item, "configuration")
		items = append(items, item)
	}
	if object := valueMap(payload); object != nil {
		object["results"] = items
		return object, nil
	}
	return items, nil
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

func xingrinSelectedEngines(payload interface{}, selected []int) ([]interface{}, []string, error) {
	if len(selected) == 0 {
		id, name, err := xingrinEngine(payload)
		if err != nil {
			return nil, nil, err
		}
		return []interface{}{id}, []string{name}, nil
	}
	wanted := make(map[int]struct{}, len(selected))
	for _, id := range selected {
		wanted[id] = struct{}{}
	}
	ids := make([]interface{}, 0, len(selected))
	names := make([]string, 0, len(selected))
	for _, raw := range xingrinCollection(payload) {
		item, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		id, err := taskOptionInt("XingRin", map[string]interface{}{"id": item["id"]}, "id", 0, 1, 1<<31-1)
		if err != nil {
			continue
		}
		if _, exists := wanted[id]; !exists {
			continue
		}
		name := strings.TrimSpace(fmt.Sprint(item["name"]))
		if name == "" || name == "<nil>" {
			return nil, nil, fmt.Errorf("XingRin 引擎 %d 名称无效", id)
		}
		ids, names = append(ids, item["id"]), append(names, name)
		delete(wanted, id)
	}
	if len(wanted) > 0 {
		missing := make([]string, 0, len(wanted))
		for id := range wanted {
			missing = append(missing, strconv.Itoa(id))
		}
		sort.Strings(missing)
		return nil, nil, fmt.Errorf("XingRin 引擎 ID 不存在: %s", strings.Join(missing, ", "))
	}
	return ids, names, nil
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
	allowed := taskOptionAllowed(
		"engine_ids", "subdomain_discovery", "subdomain_bruteforce", "subdomain_permutation", "subdomain_resolve", "subdomain_wordlist",
		"port_scan", "port_scan_passive", "ports", "top_ports", "site_identify", "fingerprint_libraries",
		"directory_scan", "directory_wordlist", "site_capture", "screenshot_sources", "url_fetch", "crawl_depth",
		"nuclei_scan", "nuclei_template_repos", "nuclei_severity", "nuclei_tags", "dalfox_scan",
		"rate_limit", "concurrency", "directory_concurrency", "request_timeout",
	)
	if err := rejectUnknownTaskOptions("XingRin", options, allowed); err != nil {
		return "", err
	}
	subdomainDiscovery, err := taskOptionBool("XingRin", options, "subdomain_discovery", false)
	if err != nil {
		return "", err
	}
	subdomainBruteforce, err := taskOptionBool("XingRin", options, "subdomain_bruteforce", false)
	if err != nil {
		return "", err
	}
	subdomainPermutation, err := taskOptionBool("XingRin", options, "subdomain_permutation", true)
	if err != nil {
		return "", err
	}
	subdomainResolve, err := taskOptionBool("XingRin", options, "subdomain_resolve", true)
	if err != nil {
		return "", err
	}
	portScan, err := taskOptionBool("XingRin", options, "port_scan", true)
	if err != nil {
		return "", err
	}
	portScanPassive, err := taskOptionBool("XingRin", options, "port_scan_passive", false)
	if err != nil {
		return "", err
	}
	siteScan, err := taskOptionBool("XingRin", options, "site_identify", true)
	if err != nil {
		return "", err
	}
	directoryScan, err := taskOptionBool("XingRin", options, "directory_scan", false)
	if err != nil {
		return "", err
	}
	siteCapture, err := taskOptionBool("XingRin", options, "site_capture", false)
	if err != nil {
		return "", err
	}
	urlFetch, err := taskOptionBool("XingRin", options, "url_fetch", false)
	if err != nil {
		return "", err
	}
	nucleiScan, err := taskOptionBool("XingRin", options, "nuclei_scan", false)
	if err != nil {
		return "", err
	}
	dalfoxScan, err := taskOptionBool("XingRin", options, "dalfox_scan", false)
	if err != nil {
		return "", err
	}
	if !subdomainDiscovery && !portScan && !siteScan && !directoryScan && !siteCapture && !urlFetch && !nucleiScan && !dalfoxScan {
		return "", fmt.Errorf("XingRin 至少需要启用一个扫描阶段")
	}
	if directoryScan || siteCapture || urlFetch || nucleiScan || dalfoxScan {
		siteScan = true
	}
	ports, err := validateXingRinPorts(strings.TrimSpace(fmt.Sprint(options["ports"])))
	if options["ports"] == nil {
		ports, err = validateXingRinPorts("")
	}
	if err != nil {
		return "", err
	}
	topPorts, err := taskOptionInt("XingRin", options, "top_ports", 0, 0, 65535)
	if err != nil {
		return "", err
	}
	if _, hasPorts := options["ports"]; hasPorts && topPorts > 0 {
		return "", fmt.Errorf("XingRin ports 与 top_ports 不能同时使用")
	}
	rate, err := taskOptionInt("XingRin", options, "rate_limit", 20, 1, 1000)
	if err != nil {
		return "", err
	}
	concurrency, err := taskOptionInt("XingRin", options, "concurrency", 5, 1, 200)
	if err != nil {
		return "", err
	}
	directoryConcurrency, err := taskOptionInt("XingRin", options, "directory_concurrency", 3, 1, 50)
	if err != nil {
		return "", err
	}
	requestTimeout, err := taskOptionInt("XingRin", options, "request_timeout", 8, 1, 120)
	if err != nil {
		return "", err
	}
	crawlDepth, err := taskOptionInt("XingRin", options, "crawl_depth", 3, 1, 20)
	if err != nil {
		return "", err
	}
	config := make(map[string]interface{})
	if subdomainDiscovery {
		wordlist, err := taskOptionString("XingRin", options, "subdomain_wordlist", "subdomains-top1million-110000.txt", 200)
		if err != nil {
			return "", err
		}
		config["subdomain_discovery"] = map[string]interface{}{
			"passive_tools": map[string]interface{}{
				"subfinder":   map[string]interface{}{"enabled": true, "timeout": 3600},
				"sublist3r":   map[string]interface{}{"enabled": true, "timeout": 3600},
				"assetfinder": map[string]interface{}{"enabled": true, "timeout": 3600},
			},
			"bruteforce":  map[string]interface{}{"enabled": subdomainBruteforce, "subdomain_bruteforce": map[string]interface{}{"wordlist-name": wordlist}},
			"permutation": map[string]interface{}{"enabled": subdomainPermutation, "subdomain_permutation_resolve": map[string]interface{}{"timeout": 7200}},
			"resolve":     map[string]interface{}{"enabled": subdomainResolve, "subdomain_resolve": map[string]interface{}{"timeout": "auto"}},
		}
	}
	if portScan {
		active := map[string]interface{}{"enabled": true, "threads": concurrency, "rate": rate}
		if topPorts > 0 {
			active["top-ports"] = topPorts
		} else {
			active["ports"] = ports
		}
		config["port_scan"] = map[string]interface{}{"tools": map[string]interface{}{
			"naabu_active": active, "naabu_passive": map[string]interface{}{"enabled": portScanPassive},
		}}
	}
	if siteScan {
		libs, err := taskOptionStringSlice("XingRin", options, "fingerprint_libraries", []string{"ehole", "goby", "wappalyzer", "fingers", "fingerprinthub", "arl"}, 6, 32)
		if err != nil {
			return "", err
		}
		for _, lib := range libs {
			if !optionStringIn(lib, "ehole", "goby", "wappalyzer", "fingers", "fingerprinthub", "arl") {
				return "", fmt.Errorf("XingRin 不支持的指纹库: %s", lib)
			}
		}
		config["site_scan"] = map[string]interface{}{"tools": map[string]interface{}{"httpx": map[string]interface{}{
			"enabled": true, "threads": concurrency, "rate-limit": rate, "request-timeout": requestTimeout, "retries": 1,
		}}}
		config["fingerprint_detect"] = map[string]interface{}{"tools": map[string]interface{}{"xingfinger": map[string]interface{}{"enabled": true, "fingerprint-libs": libs}}}
	}
	if directoryScan {
		wordlist, err := taskOptionString("XingRin", options, "directory_wordlist", "dir_default.txt", 200)
		if err != nil {
			return "", err
		}
		config["directory_scan"] = map[string]interface{}{"tools": map[string]interface{}{"ffuf": map[string]interface{}{
			"enabled": true, "max-workers": directoryConcurrency, "wordlist-name": wordlist, "delay": "0.1-2.0",
			"threads": concurrency, "request-timeout": requestTimeout, "match-codes": "200,201,301,302,401,403", "rate": rate,
		}}}
	}
	if siteCapture {
		sources, err := taskOptionStringSlice("XingRin", options, "screenshot_sources", []string{"websites"}, 2, 16)
		if err != nil {
			return "", err
		}
		for _, source := range sources {
			if !optionStringIn(source, "websites", "endpoints") {
				return "", fmt.Errorf("XingRin 截图来源仅支持 websites 或 endpoints")
			}
		}
		config["screenshot"] = map[string]interface{}{"tools": map[string]interface{}{"playwright": map[string]interface{}{"enabled": true, "concurrency": concurrency, "url_sources": sources}}}
	}
	if urlFetch {
		config["url_fetch"] = map[string]interface{}{"tools": map[string]interface{}{
			"waymore": map[string]interface{}{"enabled": true, "timeout": 3600},
			"katana":  map[string]interface{}{"enabled": true, "depth": crawlDepth, "threads": concurrency, "rate-limit": rate, "random-delay": 1, "retry": 2, "request-timeout": requestTimeout},
			"uro":     map[string]interface{}{"enabled": true},
			"httpx":   map[string]interface{}{"enabled": true, "threads": concurrency, "rate-limit": rate, "request-timeout": requestTimeout, "retries": 1},
		}}
	}
	if nucleiScan || dalfoxScan {
		repositories, err := taskOptionStringSlice("XingRin", options, "nuclei_template_repos", []string{"nuclei-templates"}, 20, 200)
		if err != nil {
			return "", err
		}
		severity, err := taskOptionString("XingRin", options, "nuclei_severity", "medium,high,critical", 100)
		if err != nil {
			return "", err
		}
		for _, item := range strings.Split(severity, ",") {
			if !optionStringIn(strings.TrimSpace(item), "info", "low", "medium", "high", "critical", "unknown") {
				return "", fmt.Errorf("XingRin nuclei_severity 包含无效等级: %s", item)
			}
		}
		tags, err := taskOptionString("XingRin", options, "nuclei_tags", "cve", 200)
		if err != nil || (tags != "" && !regexp.MustCompile(`^[A-Za-z0-9_,.-]+$`).MatchString(tags)) {
			return "", fmt.Errorf("XingRin nuclei_tags 格式无效")
		}
		config["vuln_scan"] = map[string]interface{}{"tools": map[string]interface{}{
			"dalfox_xss": map[string]interface{}{"enabled": dalfoxScan, "request-timeout": requestTimeout, "only-poc": "r", "ignore-return": "302,404,403", "delay": 50, "worker": concurrency},
			"nuclei":     map[string]interface{}{"enabled": nucleiScan, "template-repo-names": repositories, "concurrency": concurrency, "rate-limit": rate, "request-timeout": requestTimeout, "severity": severity, "tags": tags},
		}}
	}
	raw, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("生成 XingRin 引擎配置失败: %w", err)
	}
	return string(raw), nil
}

func splitXingRinTargets(value string) ([]map[string]string, error) {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(parts) == 0 || len(parts) > 5000 {
		return nil, fmt.Errorf("XingRin 目标数必须在 1 到 5000 之间")
	}
	result := make([]map[string]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, target := range parts {
		target = strings.TrimSpace(target)
		if target == "" || len(target) > 2048 {
			return nil, fmt.Errorf("XingRin 目标为空或过长")
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		result = append(result, map[string]string{"name": target})
	}
	return result, nil
}

func (a *XingRinAdapter) GetTaskProfile(_ context.Context, conn *Connection) (interface{}, error) {
	return map[string]interface{}{
		"provider": ProviderXingRin, "resource_id": conn.Resource.ID, "upstream_version": "v1.5.8",
		"task_modes": []string{"quick_scan"}, "dynamic_option_kinds": []string{"engines", "workers", "wordlists", "nuclei_repositories"},
		"manage_actions": []string{},
		"result_types":   providerResultTypes(ProviderXingRin),
		"notes": []string{
			"quick_scan 最多接受 5000 个目标；多个目标使用换行、逗号或空白分隔",
			"任务名称由 XingRin 上游生成，CyberStrikeAI 不伪造不存在的 name 字段",
			"字典名称和 Nuclei 模板仓库名需从 asm_list_task_options 实时查询",
			"engines 列表默认仅返回轻量摘要；传入 id 可查询单个引擎的完整 YAML 配置",
		},
		"create_options": map[string]interface{}{
			"engine_ids":            map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "integer"}, "description": "可选引擎 ID；省略时优先 full scan"},
			"subdomain_discovery":   map[string]interface{}{"type": "boolean", "default": false},
			"subdomain_bruteforce":  map[string]interface{}{"type": "boolean", "default": false, "requires": "subdomain_discovery"},
			"subdomain_permutation": map[string]interface{}{"type": "boolean", "default": true, "requires": "subdomain_discovery"},
			"subdomain_resolve":     map[string]interface{}{"type": "boolean", "default": true, "requires": "subdomain_discovery"},
			"subdomain_wordlist":    map[string]interface{}{"type": "string", "dynamic_kind": "wordlists", "requires": "subdomain_bruteforce"},
			"port_scan":             map[string]interface{}{"type": "boolean", "default": true},
			"port_scan_passive":     map[string]interface{}{"type": "boolean", "default": false, "requires": "port_scan"},
			"ports":                 map[string]interface{}{"type": "string", "default": "80,443,8080,8083", "conflicts": "top_ports"},
			"top_ports":             map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 65535, "conflicts": "ports"},
			"site_identify":         map[string]interface{}{"type": "boolean", "default": true},
			"fingerprint_libraries": map[string]interface{}{"type": "array", "items": map[string]interface{}{"enum": []string{"ehole", "goby", "wappalyzer", "fingers", "fingerprinthub", "arl"}}},
			"directory_scan":        map[string]interface{}{"type": "boolean", "default": false},
			"directory_wordlist":    map[string]interface{}{"type": "string", "dynamic_kind": "wordlists", "requires": "directory_scan"},
			"directory_concurrency": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 50, "default": 3},
			"site_capture":          map[string]interface{}{"type": "boolean", "default": false},
			"screenshot_sources":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"enum": []string{"websites", "endpoints"}}},
			"url_fetch":             map[string]interface{}{"type": "boolean", "default": false},
			"crawl_depth":           map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 20, "default": 3},
			"nuclei_scan":           map[string]interface{}{"type": "boolean", "default": false},
			"nuclei_template_repos": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "dynamic_kind": "nuclei_repositories"},
			"nuclei_severity":       map[string]interface{}{"type": "string", "default": "medium,high,critical"},
			"nuclei_tags":           map[string]interface{}{"type": "string", "default": "cve"},
			"dalfox_scan":           map[string]interface{}{"type": "boolean", "default": false},
			"rate_limit":            map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 1000, "default": 20},
			"concurrency":           map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 200, "default": 5},
			"request_timeout":       map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 120, "default": 8},
		},
	}, nil
}

func (a *XingRinAdapter) ListTaskOptions(ctx context.Context, conn *Connection, filter TaskOptionFilter) (interface{}, error) {
	var endpoint string
	kind := strings.ToLower(strings.TrimSpace(filter.Kind))
	switch kind {
	case "engines":
		endpoint = "/api/engines/"
	case "workers":
		endpoint = "/api/workers/"
	case "wordlists":
		endpoint = "/api/wordlists/"
	case "nuclei_repositories":
		endpoint = "/api/nuclei/repos/"
	default:
		return nil, fmt.Errorf("XingRin 不支持的动态选项类别: %s", filter.Kind)
	}
	page, size := normalizePagination(filter.Page, filter.PageSize)
	query := url.Values{"page": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	if filter.Query != "" {
		query.Set("search", filter.Query)
	}
	client, _, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	payload, err := xingrinRequest(ctx, client, conn, http.MethodGet, endpoint, query, nil)
	if err != nil {
		return nil, err
	}
	if kind == "engines" {
		payload, err = xingrinEngineOptions(payload, filter.ID)
		if err != nil {
			return nil, err
		}
	}
	return map[string]interface{}{"provider": ProviderXingRin, "resource_id": conn.Resource.ID, "kind": filter.Kind, "options": payload}, nil
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
	selectedEngineIDs, err := taskOptionIntSlice("XingRin", req.Options, "engine_ids", 20)
	if err != nil {
		return nil, err
	}
	engineIDs, engineNames, err := xingrinSelectedEngines(engines, selectedEngineIDs)
	if err != nil {
		return nil, err
	}
	targets, err := splitXingRinTargets(target)
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"targets":       targets,
		"configuration": configuration,
		"engine_ids":    engineIDs,
		"engine_names":  engineNames,
	}
	payload, err := xingrinRequest(ctx, client, conn, http.MethodPost, "/api/scans/quick/", nil, body)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider": ProviderXingRin, "resource_id": conn.Resource.ID, "response": payload,
		"execution_profile": map[string]interface{}{
			"kind": "engine", "label": "XingRin 引擎", "ids": engineIDs, "names": engineNames,
		},
	}, nil
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
	"directory":     {"directories", "url"},
	"vulnerability": {"vulnerabilities", "url"},
	"screenshot":    {"screenshots", "url"},
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
	// XingRin deliberately omits image bytes from screenshot list responses.
	// Add a same-origin image reference so CyberStrikeAI's authenticated fetcher
	// can cache each screenshot without exposing upstream credentials to the UI.
	if assetType == "screenshot" {
		for _, raw := range xingrinCollection(payload) {
			item := valueMap(raw)
			if item == nil {
				continue
			}
			id := meaningfulString(item["id"])
			if id == "" {
				continue
			}
			if strings.TrimSpace(filter.TaskID) != "" {
				item["screenshot_path"] = "/api/scans/" + strings.TrimSpace(filter.TaskID) + "/screenshots/" + id + "/image/"
			} else {
				item["screenshot_path"] = "/api/assets/screenshots/" + id + "/image/"
			}
		}
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
