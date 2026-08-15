package asm

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	scopeSentryTemplatePrefix   = "CyberStrikeAI low-load"
)

var scopeSentryTaskIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)

var scopeSentryPortArgumentPattern = regexp.MustCompile(`(?:^|\s)-port(?:\s+|=)([^\s]+)`)

type scopeSentryCapabilityModule struct {
	Capability  string
	Module      string
	PluginNames []string
}

var scopeSentryCapabilityModules = []scopeSentryCapabilityModule{
	{Capability: "subdomain_discovery", Module: "SubdomainScan"},
	{Capability: "subdomain_takeover", Module: "SubdomainSecurity"},
	{Capability: "port_scan", Module: "PortScan"},
	{Capability: "service_fingerprint", Module: "PortFingerprint"},
	{Capability: "site_identify", Module: "AssetMapping"},
	{Capability: "url_scan", Module: "URLScan"},
	{Capability: "web_crawler", Module: "WebCrawler"},
	// URLSecurity also contains PageMonitoring and trufflehog. Requiring the
	// concrete sensitive plugin avoids reporting the whole module as
	// sensitive_scan merely because a different URLSecurity plugin is enabled.
	{Capability: "sensitive_scan", Module: "URLSecurity", PluginNames: []string{"sensitive"}},
	{Capability: "directory_scan", Module: "DirScan"},
	{Capability: "vulnerability_scan", Module: "VulnerabilityScan"},
	{Capability: "passive_scan", Module: "PassiveScan"},
	{Capability: "asset_handle", Module: "AssetHandle"},
}

var scopeSentryRequiredCapabilities = []string{
	"subdomain_discovery", "subdomain_takeover", "port_scan", "service_fingerprint",
	"site_identify", "site_capture", "tls_probe", "url_scan", "web_crawler",
	"sensitive_scan", "directory_scan", "vulnerability_scan", "passive_scan", "asset_handle",
}

type ScopeSentryAdapter struct{}

func NewScopeSentryAdapter() *ScopeSentryAdapter { return &ScopeSentryAdapter{} }

func (a *ScopeSentryAdapter) Provider() string { return ProviderScopeSentry }

func (a *ScopeSentryAdapter) Capabilities() []string {
	return []string{"test_connection", "get_task_profile", "list_task_options", "create_template", "create_task", "list_tasks", "get_task", "list_assets", "stop_task", "manage_task"}
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

func scopeSentryCompactOptionPayload(kind string, payload interface{}) interface{} {
	fields := map[string][]string{
		"templates":         {"id", "name"},
		"port_dictionaries": {"id", "name"},
		"dictionaries":      {"id", "name", "category", "size"},
		"plugins":           {"id", "name", "module", "introduction", "version", "help", "isSystem", "status"},
		"pocs":              {"id", "name", "Template ID", "level", "tags", "time"},
		"projects":          {"id", "name", "description"},
	}
	selected, compact := fields[kind]
	if !compact {
		return payload
	}
	items := make([]interface{}, 0, len(scopeSentryList(payload)))
	for _, raw := range scopeSentryList(payload) {
		item := scopeSentryMap(raw)
		if item == nil {
			continue
		}
		summary := make(map[string]interface{}, len(selected))
		for _, key := range selected {
			if value, exists := item[key]; exists {
				summary[key] = value
			}
		}
		items = append(items, summary)
	}
	result := map[string]interface{}{"list": items}
	if data := scopeSentryMap(scopeSentryData(payload)); data != nil {
		for _, key := range []string{"total", "pageIndex", "pageSize"} {
			if value, exists := data[key]; exists {
				result[key] = value
			}
		}
	}
	return result
}

func scopeSentrySelectionEnabled(value interface{}) bool {
	switch typed := value.(type) {
	case []interface{}:
		return len(typed) > 0
	case []string:
		return len(typed) > 0
	case nil:
		return false
	default:
		text := strings.TrimSpace(fmt.Sprint(typed))
		return text != "" && text != "<nil>" && text != "[]"
	}
}

func scopeSentryTemplateParameters(template map[string]interface{}, module string) []string {
	result := make([]string, 0)
	seen := make(map[string]struct{})
	for _, containerName := range []string{"Parameters", "ParameterLists"} {
		container := scopeSentryMap(template[containerName])
		values := scopeSentryMap(container[module])
		for _, raw := range values {
			value := strings.TrimSpace(fmt.Sprint(raw))
			if value == "" || value == "<nil>" {
				continue
			}
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

func scopeSentryParameterFlag(parameters []string, name string) bool {
	for _, parameter := range parameters {
		fields := strings.Fields(strings.ToLower(parameter))
		for index, field := range fields {
			if field == "-"+name && index+1 < len(fields) && fields[index+1] == "true" {
				return true
			}
			if field == "-"+name+"=true" {
				return true
			}
		}
	}
	return false
}

func scopeSentryPortSummary(template map[string]interface{}, enabled bool) (string, string) {
	if !enabled {
		return "disabled", ""
	}
	for _, parameter := range scopeSentryTemplateParameters(template, "PortScan") {
		match := scopeSentryPortArgumentPattern.FindStringSubmatch(parameter)
		if len(match) != 2 {
			continue
		}
		expression := strings.Trim(strings.TrimSpace(match[1]), `"'`)
		normalized := strings.ToLower(expression)
		switch {
		case normalized == "1-65535", normalized == "{port.all}", normalized == "all":
			return "all", expression
		case strings.Contains(normalized, "top1000"):
			return "top1000", expression
		case strings.Contains(normalized, "top100"):
			return "top100", expression
		default:
			return "custom", expression
		}
	}
	return "unknown", ""
}

func scopeSentrySelectedPluginHashes(template map[string]interface{}, module string) map[string]struct{} {
	selected := make(map[string]struct{})
	for _, raw := range scopeSentryList(template[module]) {
		hash := strings.TrimSpace(fmt.Sprint(raw))
		if hash != "" && hash != "<nil>" {
			selected[hash] = struct{}{}
		}
	}
	return selected
}

func scopeSentryPluginNameMatches(plugin map[string]interface{}, names []string) bool {
	if len(names) == 0 {
		return true
	}
	name := strings.TrimSpace(fmt.Sprint(plugin["name"]))
	for _, expected := range names {
		if strings.EqualFold(name, strings.TrimSpace(expected)) {
			return true
		}
	}
	return false
}

func scopeSentryCapabilityPluginCandidates(mapping scopeSentryCapabilityModule, payload interface{}) []map[string]interface{} {
	candidates := make([]map[string]interface{}, 0)
	for _, raw := range scopeSentryList(payload) {
		plugin := scopeSentryMap(raw)
		if !strings.EqualFold(strings.TrimSpace(fmt.Sprint(plugin["module"])), mapping.Module) || !scopeSentryPluginNameMatches(plugin, mapping.PluginNames) {
			continue
		}
		hash := strings.TrimSpace(fmt.Sprint(plugin["hash"]))
		if hash == "" || hash == "<nil>" {
			continue
		}
		candidates = append(candidates, plugin)
	}
	return candidates
}

func scopeSentryCapabilityAvailable(mapping scopeSentryCapabilityModule, plugins interface{}) bool {
	return len(scopeSentryCapabilityPluginCandidates(mapping, plugins)) > 0
}

func scopeSentryCapabilityEnabled(template map[string]interface{}, mapping scopeSentryCapabilityModule, plugins interface{}) bool {
	if len(mapping.PluginNames) == 0 {
		return scopeSentrySelectionEnabled(template[mapping.Module])
	}
	selected := scopeSentrySelectedPluginHashes(template, mapping.Module)
	if len(selected) == 0 {
		return false
	}
	matchedNames := make(map[string]bool, len(mapping.PluginNames))
	for _, plugin := range scopeSentryCapabilityPluginCandidates(mapping, plugins) {
		hash := strings.TrimSpace(fmt.Sprint(plugin["hash"]))
		if _, ok := selected[hash]; !ok {
			continue
		}
		name := strings.TrimSpace(fmt.Sprint(plugin["name"]))
		for _, expected := range mapping.PluginNames {
			if strings.EqualFold(name, strings.TrimSpace(expected)) {
				matchedNames[strings.ToLower(strings.TrimSpace(expected))] = true
			}
		}
	}
	for _, expected := range mapping.PluginNames {
		if !matchedNames[strings.ToLower(strings.TrimSpace(expected))] {
			return false
		}
	}
	return true
}

func scopeSentryAvailableCapabilities(plugins interface{}) ([]string, []string) {
	availableSet := make(map[string]bool, len(scopeSentryRequiredCapabilities))
	for _, mapping := range scopeSentryCapabilityModules {
		availableSet[mapping.Capability] = scopeSentryCapabilityAvailable(mapping, plugins)
	}
	availableSet["site_capture"] = availableSet["site_identify"]
	availableSet["tls_probe"] = availableSet["site_identify"]
	available := make([]string, 0, len(scopeSentryRequiredCapabilities))
	unavailable := make([]string, 0, len(scopeSentryRequiredCapabilities))
	for _, capability := range scopeSentryRequiredCapabilities {
		if availableSet[capability] {
			available = append(available, capability)
		} else {
			unavailable = append(unavailable, capability)
		}
	}
	return available, unavailable
}

func scopeSentryTemplateCapabilitySummary(template map[string]interface{}, plugins interface{}) map[string]interface{} {
	capabilities := make(map[string]bool, len(scopeSentryRequiredCapabilities))
	enabled := make([]string, 0, len(scopeSentryRequiredCapabilities))
	disabled := make([]string, 0, len(scopeSentryRequiredCapabilities))
	for _, mapping := range scopeSentryCapabilityModules {
		capabilities[mapping.Capability] = scopeSentryCapabilityEnabled(template, mapping, plugins)
	}
	assetMappingParameters := scopeSentryTemplateParameters(template, "AssetMapping")
	capabilities["site_capture"] = capabilities["site_identify"] && scopeSentryParameterFlag(assetMappingParameters, "screenshot")
	capabilities["tls_probe"] = capabilities["site_identify"] && scopeSentryParameterFlag(assetMappingParameters, "tlsprobe")
	for _, capability := range scopeSentryRequiredCapabilities {
		if capabilities[capability] {
			enabled = append(enabled, capability)
		} else {
			disabled = append(disabled, capability)
		}
	}
	portScope, portExpression := scopeSentryPortSummary(template, capabilities["port_scan"])
	availableCapabilities, unavailableCapabilities := scopeSentryAvailableCapabilities(plugins)
	pocSelection := "disabled"
	pocCount := 0
	if capabilities["vulnerability_scan"] {
		pocSelection = "template_default"
		for _, key := range []string{"vullist", "VulList"} {
			if values, ok := template[key].([]interface{}); ok && len(values) > 0 {
				pocSelection = "selected"
				pocCount = len(values)
				break
			}
		}
	}
	return map[string]interface{}{
		"template_id":              strings.TrimSpace(fmt.Sprint(template["id"])),
		"template_name":            strings.TrimSpace(fmt.Sprint(template["name"])),
		"port_scope":               portScope,
		"port_expression":          portExpression,
		"full_ports":               portScope == "all",
		"capabilities":             capabilities,
		"enabled_capabilities":     enabled,
		"disabled_capabilities":    disabled,
		"available_capabilities":   availableCapabilities,
		"unavailable_capabilities": unavailableCapabilities,
		"all_capabilities":         len(disabled) == 0,
		"poc_selection":            pocSelection,
		"selected_poc_count":       pocCount,
	}
}

func scopeSentryTemplateVerificationToken(template map[string]interface{}) (string, error) {
	raw, err := json.Marshal(template)
	if err != nil {
		return "", fmt.Errorf("ScopeSentry 生成模板校验令牌失败: %w", err)
	}
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", digest[:]), nil
}

func scopeSentryTemplateInspection(payload, plugins interface{}) (map[string]interface{}, string, error) {
	template := scopeSentryMap(scopeSentryData(payload))
	if template == nil {
		return nil, "", fmt.Errorf("ScopeSentry 模板详情响应无效")
	}
	token, err := scopeSentryTemplateVerificationToken(template)
	if err != nil {
		return nil, "", err
	}
	return scopeSentryTemplateCapabilitySummary(template, plugins), token, nil
}

func scopeSentryValidateTemplateExpectations(options map[string]interface{}, summary map[string]interface{}) error {
	requiredPortScope, err := taskOptionEnum("ScopeSentry", options, "required_port_scope", "", "", "all", "top1000", "top100", "custom")
	if err != nil {
		return err
	}
	actualPortScope := strings.TrimSpace(fmt.Sprint(summary["port_scope"]))
	if requiredPortScope != "" && requiredPortScope != actualPortScope {
		return fmt.Errorf("ScopeSentry 模板端口范围不符合要求: 要求 %s，实际 %s（%s）", requiredPortScope, actualPortScope, strings.TrimSpace(fmt.Sprint(summary["port_expression"])))
	}
	required, err := taskOptionStringSlice("ScopeSentry", options, "required_capabilities", nil, len(scopeSentryRequiredCapabilities), 64)
	if err != nil {
		return err
	}
	known := make(map[string]struct{}, len(scopeSentryRequiredCapabilities))
	for _, capability := range scopeSentryRequiredCapabilities {
		known[capability] = struct{}{}
	}
	capabilities, _ := summary["capabilities"].(map[string]bool)
	missing := make([]string, 0)
	for _, capability := range required {
		capability = strings.ToLower(strings.TrimSpace(capability))
		if _, exists := known[capability]; !exists {
			return fmt.Errorf("ScopeSentry 不支持的能力断言: %s", capability)
		}
		if !capabilities[capability] {
			missing = append(missing, capability)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("ScopeSentry 模板未开启用户要求的能力: %s", strings.Join(missing, ", "))
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

func scopeSentryOnlineNodes(value interface{}) []string {
	items := scopeSentryList(value)
	result := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		name := strings.TrimSpace(fmt.Sprint(item))
		if object, ok := item.(map[string]interface{}); ok {
			name = strings.TrimSpace(fmt.Sprint(object["name"]))
		}
		if name != "" && name != "<nil>" {
			if _, exists := seen[name]; !exists {
				seen[name] = struct{}{}
				result = append(result, name)
			}
		}
	}
	return result
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

func scopeSentryLowLoadOptions(options map[string]interface{}) (string, int, bool, bool, bool, bool, error) {
	portScan, err := taskOptionBool("ScopeSentry", options, "port_scan", true)
	if err != nil {
		return "", 0, false, false, false, false, err
	}
	siteIdentify, err := taskOptionBool("ScopeSentry", options, "site_identify", true)
	if err != nil {
		return "", 0, false, false, false, false, err
	}
	if !portScan && !siteIdentify {
		return "", 0, false, false, false, false, fmt.Errorf("ScopeSentry 至少需要启用 port_scan 或 site_identify")
	}
	ports, err := scopeSentryPorts(strings.TrimSpace(fmt.Sprint(options["ports"])))
	if options["ports"] == nil {
		ports, err = scopeSentryPorts("")
	}
	if err != nil {
		return "", 0, false, false, false, false, err
	}
	concurrency, err := taskOptionInt("ScopeSentry", options, "concurrency", 20, 1, 200)
	if err != nil {
		return "", 0, false, false, false, false, err
	}
	siteCapture, err := taskOptionBool("ScopeSentry", options, "site_capture", false)
	if err != nil {
		return "", 0, false, false, false, false, err
	}
	tlsProbe, err := taskOptionBool("ScopeSentry", options, "tls_probe", false)
	if err != nil {
		return "", 0, false, false, false, false, err
	}
	return ports, concurrency, portScan, siteIdentify, siteCapture, tlsProbe, nil
}

func scopeSentryLowLoadTemplateName(ports string, concurrency int, portScan, siteIdentify, siteCapture, tlsProbe bool) string {
	profile := fmt.Sprintf("ports=%s;concurrency=%d;port_scan=%t;site_identify=%t;site_capture=%t;tls_probe=%t", ports, concurrency, portScan, siteIdentify, siteCapture, tlsProbe)
	digest := sha256.Sum256([]byte(profile))
	return fmt.Sprintf("%s %x", scopeSentryTemplatePrefix, digest[:6])
}

func scopeSentryPruneTemplate(source map[string]interface{}, name, ports string, concurrency int, portScan, siteIdentify, siteCapture, tlsProbe bool) map[string]interface{} {
	result := make(map[string]interface{}, len(source))
	for key, value := range source {
		result[key] = value
	}
	delete(result, "id")
	result["name"] = name
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
				mappingParameters[hash] = fmt.Sprintf("-cdncheck true -screenshot %t -tlsprobe %t", siteCapture, tlsProbe)
			}
			parameters["AssetMapping"] = mappingParameters
		}
		result[parameterKey] = parameters
	}
	return result
}

var scopeSentryTemplateOptions = taskOptionAllowed(
	"enabled_capabilities", "ports", "concurrency", "site_capture", "tls_probe", "poc_ids",
)

func scopeSentryCloneTemplate(source map[string]interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(source)
	if err != nil {
		return nil, fmt.Errorf("ScopeSentry 复制基模板失败: %w", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("ScopeSentry 复制基模板失败: %w", err)
	}
	return result, nil
}

func scopeSentrySetParameter(command, name, value string) string {
	pattern := regexp.MustCompile(`(^|\s)-` + regexp.QuoteMeta(name) + `(?:\s+|=)[^\s]+`)
	replacement := `${1}-` + name + ` ` + value
	if pattern.MatchString(command) {
		return strings.TrimSpace(pattern.ReplaceAllString(command, replacement))
	}
	return strings.TrimSpace(command + " -" + name + " " + value)
}

func scopeSentryUpdateModuleParameters(template map[string]interface{}, module string, update func(string) string) {
	for _, parameterKey := range []string{"Parameters", "ParameterLists"} {
		parameters := scopeSentryMap(template[parameterKey])
		if parameters == nil {
			continue
		}
		pluginParameters := scopeSentryMap(parameters[module])
		for hash, raw := range pluginParameters {
			pluginParameters[hash] = update(strings.TrimSpace(fmt.Sprint(raw)))
		}
		parameters[module] = pluginParameters
		template[parameterKey] = parameters
	}
}

func scopeSentryCapabilitySet(options map[string]interface{}) (map[string]bool, bool, error) {
	_, configured := options["enabled_capabilities"]
	values, err := taskOptionStringSlice("ScopeSentry", options, "enabled_capabilities", nil, len(scopeSentryRequiredCapabilities), 64)
	if err != nil {
		return nil, false, err
	}
	if configured && len(values) == 0 {
		return nil, false, fmt.Errorf("ScopeSentry enabled_capabilities 至少需要一项能力")
	}
	known := make(map[string]struct{}, len(scopeSentryRequiredCapabilities))
	for _, capability := range scopeSentryRequiredCapabilities {
		known[capability] = struct{}{}
	}
	result := make(map[string]bool, len(values))
	for _, value := range values {
		capability := strings.ToLower(strings.TrimSpace(value))
		if _, exists := known[capability]; !exists {
			return nil, false, fmt.Errorf("ScopeSentry 不支持的模板能力: %s", capability)
		}
		result[capability] = true
	}
	if configured && result["service_fingerprint"] && !result["port_scan"] {
		return nil, false, fmt.Errorf("ScopeSentry service_fingerprint 需要同时启用 port_scan")
	}
	if configured && (result["site_capture"] || result["tls_probe"]) && !result["site_identify"] {
		return nil, false, fmt.Errorf("ScopeSentry site_capture/tls_probe 需要同时启用 site_identify")
	}
	return result, configured, nil
}

func scopeSentryMissingCapabilityModules(template map[string]interface{}, options map[string]interface{}, plugins interface{}) ([]int, error) {
	capabilities, configured, err := scopeSentryCapabilitySet(options)
	if err != nil || !configured {
		return nil, err
	}
	missing := make([]int, 0)
	for index, mapping := range scopeSentryCapabilityModules {
		if capabilities[mapping.Capability] && !scopeSentryCapabilityEnabled(template, mapping, plugins) {
			missing = append(missing, index)
		}
	}
	return missing, nil
}

func scopeSentryPluginBool(value interface{}) bool {
	if typed, ok := value.(bool); ok {
		return typed
	}
	parsed, _ := strconv.ParseBool(strings.TrimSpace(fmt.Sprint(value)))
	return parsed
}

// scopeSentryEnableInstalledPlugins fills capabilities that are disabled in a
// base template with upstream-installed scan plugins. It only copies the
// plugin hash and the upstream-owned default parameters; callers still cannot
// inject or rewrite arbitrary plugin commands.
func scopeSentryEnableInstalledPlugins(template map[string]interface{}, options map[string]interface{}, payload interface{}) ([]map[string]interface{}, error) {
	missingIndexes, err := scopeSentryMissingCapabilityModules(template, options, payload)
	if err != nil || len(missingIndexes) == 0 {
		return nil, err
	}

	parameters := scopeSentryMap(template["Parameters"])
	if parameters == nil {
		parameters = make(map[string]interface{})
	}
	parameterLists := scopeSentryMap(template["ParameterLists"])
	if parameterLists == nil {
		parameterLists = make(map[string]interface{})
	}
	autoEnabled := make([]map[string]interface{}, 0)
	missingCapabilities := make([]string, 0)
	for _, index := range missingIndexes {
		mapping := scopeSentryCapabilityModules[index]
		candidates := scopeSentryCapabilityPluginCandidates(mapping, payload)
		systemPlugins := make([]map[string]interface{}, 0, len(candidates))
		for _, plugin := range candidates {
			if scopeSentryPluginBool(plugin["isSystem"]) {
				systemPlugins = append(systemPlugins, plugin)
			}
		}
		if len(systemPlugins) > 0 {
			candidates = systemPlugins
		}
		if len(candidates) == 0 {
			missingCapabilities = append(missingCapabilities, fmt.Sprintf("%s (%s)", mapping.Capability, mapping.Module))
			continue
		}

		selection := make([]interface{}, 0, len(candidates)+len(scopeSentrySelectedPluginHashes(template, mapping.Module)))
		selected := scopeSentrySelectedPluginHashes(template, mapping.Module)
		for hash := range selected {
			selection = append(selection, hash)
		}
		moduleParameters := scopeSentryMap(parameters[mapping.Module])
		if moduleParameters == nil {
			moduleParameters = make(map[string]interface{}, len(candidates))
		}
		moduleParameterLists := scopeSentryMap(parameterLists[mapping.Module])
		if moduleParameterLists == nil {
			moduleParameterLists = make(map[string]interface{}, len(candidates))
		}
		for _, plugin := range candidates {
			hash := strings.TrimSpace(fmt.Sprint(plugin["hash"]))
			if _, exists := selected[hash]; !exists {
				selection = append(selection, hash)
				selected[hash] = struct{}{}
			}
			parameter := strings.TrimSpace(fmt.Sprint(plugin["parameter"]))
			if parameter == "<nil>" {
				parameter = ""
			}
			moduleParameters[hash] = parameter
			parameterList := strings.TrimSpace(fmt.Sprint(plugin["parameterList"]))
			if parameterList != "" && parameterList != "<nil>" {
				moduleParameterLists[hash] = parameterList
			}
			autoEnabled = append(autoEnabled, map[string]interface{}{
				"capability": mapping.Capability, "module": mapping.Module,
				"plugin": strings.TrimSpace(fmt.Sprint(plugin["name"])), "hash": hash,
			})
		}
		template[mapping.Module] = selection
		parameters[mapping.Module] = moduleParameters
		parameterLists[mapping.Module] = moduleParameterLists
	}
	if len(missingCapabilities) > 0 {
		return nil, fmt.Errorf("ScopeSentry 上游未安装请求能力对应的插件: %s", strings.Join(missingCapabilities, ", "))
	}
	template["Parameters"] = parameters
	template["ParameterLists"] = parameterLists
	return autoEnabled, nil
}

func scopeSentryTemplateEquivalent(left, right map[string]interface{}) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func scopeSentryCustomizeTemplate(source map[string]interface{}, name string, options map[string]interface{}, plugins interface{}) (map[string]interface{}, error) {
	result, err := scopeSentryCloneTemplate(source)
	if err != nil {
		return nil, err
	}
	delete(result, "id")
	result["name"] = name
	result["TaskName"] = ""

	capabilities, configured, err := scopeSentryCapabilitySet(options)
	if err != nil {
		return nil, err
	}
	if configured {
		for _, mapping := range scopeSentryCapabilityModules {
			if !capabilities[mapping.Capability] {
				result[mapping.Module] = []interface{}{}
				for _, parameterKey := range []string{"Parameters", "ParameterLists"} {
					parameters := scopeSentryMap(result[parameterKey])
					if parameters != nil {
						parameters[mapping.Module] = map[string]interface{}{}
					}
				}
			}
		}
	}

	if raw, exists := options["ports"]; exists {
		ports, portsErr := scopeSentryPorts(strings.TrimSpace(fmt.Sprint(raw)))
		if portsErr != nil {
			return nil, portsErr
		}
		if !scopeSentrySelectionEnabled(result["PortScan"]) {
			return nil, fmt.Errorf("ScopeSentry 设置 ports 前需要启用 port_scan")
		}
		scopeSentryUpdateModuleParameters(result, "PortScan", func(command string) string {
			return scopeSentrySetParameter(command, "port", ports)
		})
	}
	if _, exists := options["concurrency"]; exists {
		concurrency, concurrencyErr := taskOptionInt("ScopeSentry", options, "concurrency", 20, 1, 200)
		if concurrencyErr != nil {
			return nil, concurrencyErr
		}
		if !scopeSentrySelectionEnabled(result["PortScan"]) {
			return nil, fmt.Errorf("ScopeSentry 设置 concurrency 前需要启用 port_scan")
		}
		scopeSentryUpdateModuleParameters(result, "PortScan", func(command string) string {
			return scopeSentrySetParameter(command, "b", strconv.Itoa(concurrency))
		})
	}

	siteEnabled := scopeSentrySelectionEnabled(result["AssetMapping"])
	for _, field := range []string{"site_capture", "tls_probe"} {
		if _, exists := options[field]; !exists && !configured {
			continue
		}
		value := capabilities[field]
		if _, exists := options[field]; exists {
			value, err = taskOptionBool("ScopeSentry", options, field, value)
			if err != nil {
				return nil, err
			}
		}
		if value && !siteEnabled {
			return nil, fmt.Errorf("ScopeSentry 启用 %s 前需要启用 site_identify", field)
		}
		if siteEnabled {
			flag := map[string]string{"site_capture": "screenshot", "tls_probe": "tlsprobe"}[field]
			scopeSentryUpdateModuleParameters(result, "AssetMapping", func(command string) string {
				return scopeSentrySetParameter(command, flag, strconv.FormatBool(value))
			})
		}
	}

	if _, exists := options["poc_ids"]; exists {
		pocIDs, pocErr := taskOptionStringSlice("ScopeSentry", options, "poc_ids", nil, 500, 200)
		if pocErr != nil {
			return nil, pocErr
		}
		if len(pocIDs) > 0 && !scopeSentrySelectionEnabled(result["VulnerabilityScan"]) {
			return nil, fmt.Errorf("ScopeSentry 选择 POC 前需要启用 vulnerability_scan")
		}
		selected := make([]interface{}, len(pocIDs))
		for index, value := range pocIDs {
			selected[index] = value
		}
		result["VulList"] = selected
		result["vullist"] = selected
	}

	summary := scopeSentryTemplateCapabilitySummary(result, plugins)
	if configured {
		actual, _ := summary["capabilities"].(map[string]bool)
		missing := make([]string, 0)
		for capability := range capabilities {
			if !actual[capability] {
				missing = append(missing, capability)
			}
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("ScopeSentry 基模板不包含请求的插件能力: %s", strings.Join(missing, ", "))
		}
	}
	return result, nil
}

func (a *ScopeSentryAdapter) CreateTemplate(ctx context.Context, conn *Connection, req TemplateRequest) (interface{}, error) {
	if err := rejectUnknownTaskOptions("ScopeSentry 模板", req.Options, scopeSentryTemplateOptions); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 150 || strings.ContainsAny(name, "\r\n") {
		return nil, fmt.Errorf("ScopeSentry 模板名称必填、不能换行且不能超过 150 字符")
	}
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	templates, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template", nil, map[string]interface{}{
		"pageIndex": 1, "pageSize": 100, "query": "", "search": "",
	})
	if err != nil {
		return nil, err
	}
	existingID, _ := scopeSentryTemplateByName(templates, name)
	if existingID != "" && req.PresetID == "" {
		return nil, fmt.Errorf("ScopeSentry 模板名称已存在: %s", name)
	}
	baseID := strings.TrimSpace(req.BaseTemplateID)
	saveID := ""
	if existingID != "" {
		baseID = existingID
		saveID = existingID
	} else if baseID == "" {
		baseID, _ = scopeSentryTemplateByName(templates, "default")
		if baseID == "" {
			return nil, fmt.Errorf("ScopeSentry 未找到 default 基模板")
		}
	} else {
		baseID, err = scopeSentryValidateObjectID(baseID, "base_template_id", false)
		if err != nil {
			return nil, err
		}
	}
	detail, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template/detail", nil, map[string]string{"id": baseID})
	if err != nil {
		return nil, err
	}
	source := scopeSentryMap(scopeSentryData(detail))
	if source == nil {
		return nil, fmt.Errorf("ScopeSentry 基模板详情无效")
	}
	baseline, err := scopeSentryCloneTemplate(source)
	if err != nil {
		return nil, err
	}
	delete(baseline, "id")
	baseline["name"] = name
	baseline["TaskName"] = ""

	plugins, pluginErr := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/plugin", nil, map[string]interface{}{
		"pageIndex": 1, "pageSize": 200, "search": "",
	})
	if pluginErr != nil {
		return nil, fmt.Errorf("读取 ScopeSentry 已安装插件失败: %w", pluginErr)
	}
	var autoEnabled []map[string]interface{}
	missingModules, missingErr := scopeSentryMissingCapabilityModules(source, req.Options, plugins)
	if missingErr != nil {
		return nil, missingErr
	}
	if len(missingModules) > 0 {
		autoEnabled, err = scopeSentryEnableInstalledPlugins(source, req.Options, plugins)
		if err != nil {
			return nil, err
		}
	}
	profile, err := scopeSentryCustomizeTemplate(source, name, req.Options, plugins)
	if err != nil {
		return nil, err
	}
	if saveID != "" && scopeSentryTemplateEquivalent(baseline, profile) {
		summary, verificationToken, inspectErr := scopeSentryTemplateInspection(detail, plugins)
		if inspectErr != nil {
			return nil, inspectErr
		}
		return map[string]interface{}{
			"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID, "template_kind": "task_template",
			"template_id": saveID, "template_name": name, "preset_id": req.PresetID, "reused": true, "repaired": false,
			"capability_summary": summary, "verification_token": verificationToken,
		}, nil
	}
	if _, err = scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template/save", nil, map[string]interface{}{
		"id": saveID, "result": profile,
	}); err != nil {
		return nil, err
	}
	if saveID != "" {
		updatedDetail, detailErr := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template/detail", nil, map[string]string{"id": saveID})
		if detailErr != nil {
			return nil, detailErr
		}
		summary, verificationToken, inspectErr := scopeSentryTemplateInspection(updatedDetail, plugins)
		if inspectErr != nil {
			return nil, inspectErr
		}
		return map[string]interface{}{
			"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID, "template_kind": "task_template",
			"template_id": saveID, "template_name": name, "base_template_id": baseID,
			"preset_id": req.PresetID, "reused": true, "repaired": true, "auto_enabled_plugins": autoEnabled,
			"capability_summary": summary, "verification_token": verificationToken,
		}, nil
	}
	for attempt := 0; attempt < 10; attempt++ {
		listed, listErr := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template", nil, map[string]interface{}{
			"pageIndex": 1, "pageSize": 20, "query": name, "search": name,
		})
		if listErr == nil {
			if templateID, _ := scopeSentryTemplateByName(listed, name); templateID != "" {
				createdDetail, detailErr := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template/detail", nil, map[string]string{"id": templateID})
				if detailErr != nil {
					return nil, detailErr
				}
				summary, verificationToken, inspectErr := scopeSentryTemplateInspection(createdDetail, plugins)
				if inspectErr != nil {
					return nil, inspectErr
				}
				return map[string]interface{}{
					"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID, "template_kind": "task_template",
					"template_id": templateID, "template_name": name, "base_template_id": baseID,
					"preset_id": req.PresetID, "reused": false, "repaired": false, "auto_enabled_plugins": autoEnabled,
					"capability_summary": summary, "verification_token": verificationToken,
				}, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("ScopeSentry 模板已保存但回查不到: %s", name)
}

func (a *ScopeSentryAdapter) ensureTemplate(ctx context.Context, client *http.Client, conn *Connection, token string, options map[string]interface{}) (string, error) {
	ports, concurrency, portScan, siteIdentify, siteCapture, tlsProbe, err := scopeSentryLowLoadOptions(options)
	if err != nil {
		return "", err
	}
	templateName := scopeSentryLowLoadTemplateName(ports, concurrency, portScan, siteIdentify, siteCapture, tlsProbe)
	listBody := map[string]interface{}{"pageIndex": 1, "pageSize": 100, "query": ""}
	templates, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template", nil, listBody)
	if err != nil {
		return "", err
	}
	existingID, _ := scopeSentryTemplateByName(templates, templateName)
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
	profile := scopeSentryPruneTemplate(source, templateName, ports, concurrency, portScan, siteIdentify, siteCapture, tlsProbe)
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
			"pageIndex": 1, "pageSize": 20, "query": templateName,
		})
		if err == nil {
			if id, _ := scopeSentryTemplateByName(templates, templateName); id != "" {
				return id, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return "", fmt.Errorf("ScopeSentry 专用低负载模板创建后不可见")
}

var scopeSentryTaskOptions = taskOptionAllowed(
	"template_id", "node_names", "all_nodes", "ignore", "duplicates", "target_source", "project_ids",
	"source_search", "source_limit", "source_filter",
	"scheduled", "cycle_type", "hour", "minute", "day", "week",
	"port_scan", "site_identify", "ports", "concurrency", "site_capture", "tls_probe",
	"template_verification_token", "required_port_scope", "required_capabilities",
)

func scopeSentryValidateObjectID(value, field string, optional bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" && optional {
		return "", nil
	}
	if !scopeSentryTaskIDPattern.MatchString(value) {
		return "", fmt.Errorf("ScopeSentry %s 格式无效", field)
	}
	return strings.ToLower(value), nil
}

func scopeSentrySelectNodes(upstream interface{}, requested []string, allNodes bool) ([]string, error) {
	available := scopeSentryOnlineNodes(upstream)
	if len(available) == 0 {
		return nil, fmt.Errorf("ScopeSentry 未返回在线扫描节点")
	}
	if allNodes {
		return available, nil
	}
	if len(requested) == 0 {
		return []string{available[0]}, nil
	}
	lookup := make(map[string]struct{}, len(available))
	for _, name := range available {
		lookup[name] = struct{}{}
	}
	for _, name := range requested {
		if _, ok := lookup[name]; !ok {
			return nil, fmt.Errorf("ScopeSentry 节点不在线: %s", name)
		}
	}
	return requested, nil
}

func scopeSentrySourceFilter(options map[string]interface{}) (map[string][]interface{}, error) {
	value, exists := options["source_filter"]
	if !exists || value == nil {
		return map[string][]interface{}{}, nil
	}
	object, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("ScopeSentry 任务选项 source_filter 必须是对象")
	}
	if len(object) > 50 {
		return nil, fmt.Errorf("ScopeSentry source_filter 字段过多")
	}
	result := make(map[string][]interface{}, len(object))
	keyPattern := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,99}$`)
	for key, raw := range object {
		if !keyPattern.MatchString(key) || strings.Contains(key, "..") {
			return nil, fmt.Errorf("ScopeSentry source_filter 字段名无效: %s", key)
		}
		items, ok := raw.([]interface{})
		if !ok || len(items) > 1000 {
			return nil, fmt.Errorf("ScopeSentry source_filter.%s 必须是不超过 1000 项的数组", key)
		}
		for _, item := range items {
			switch item.(type) {
			case string, bool, float64, json.Number:
			default:
				return nil, fmt.Errorf("ScopeSentry source_filter.%s 包含不支持的值类型", key)
			}
		}
		result[key] = items
	}
	return result, nil
}

func (a *ScopeSentryAdapter) CreateTask(ctx context.Context, conn *Connection, req TaskRequest) (interface{}, error) {
	target := strings.TrimSpace(req.Target)
	if err := rejectUnknownTaskOptions("ScopeSentry", req.Options, scopeSentryTaskOptions); err != nil {
		return nil, err
	}
	targetSource, err := taskOptionEnum("ScopeSentry", req.Options, "target_source", "general", "general", "project", "asset", "RootDomain", "subdomain")
	if err != nil {
		return nil, err
	}
	if len(target) > 10000 || (targetSource == "general" && target == "") {
		return nil, fmt.Errorf("ScopeSentry general 模式目标不能为空，且任务目标不能超过 10000 字符")
	}
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	nodes, err := scopeSentryRequest(ctx, client, conn, token, http.MethodGet, "/api/node/online", nil, nil)
	if err != nil {
		return nil, err
	}
	plugins, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/plugin", nil, map[string]interface{}{
		"pageIndex": 1, "pageSize": 200, "search": "",
	})
	if err != nil {
		return nil, fmt.Errorf("读取 ScopeSentry 已安装插件失败: %w", err)
	}
	allNodes, err := taskOptionBool("ScopeSentry", req.Options, "all_nodes", false)
	if err != nil {
		return nil, err
	}
	requestedNodes, err := taskOptionStringSlice("ScopeSentry", req.Options, "node_names", nil, 100, 200)
	if err != nil {
		return nil, err
	}
	selectedNodes, err := scopeSentrySelectNodes(nodes, requestedNodes, allNodes)
	if err != nil {
		return nil, err
	}
	templateID, err := taskOptionString("ScopeSentry", req.Options, "template_id", "", 64)
	if err != nil {
		return nil, err
	}
	var templateSummary map[string]interface{}
	if templateID != "" {
		templateID, err = scopeSentryValidateObjectID(templateID, "template_id", false)
		if err != nil {
			return nil, err
		}
		for _, field := range []string{"port_scan", "site_identify", "ports", "concurrency", "site_capture", "tls_probe"} {
			if _, exists := req.Options[field]; exists {
				return nil, fmt.Errorf("ScopeSentry 选择 template_id 时不能使用低负载模板覆盖字段 %s，请在上游模板中配置", field)
			}
		}
		verificationToken, tokenErr := taskOptionString("ScopeSentry", req.Options, "template_verification_token", "", 100)
		if tokenErr != nil {
			return nil, tokenErr
		}
		if verificationToken == "" {
			return nil, fmt.Errorf("ScopeSentry 使用 template_id 前必须先调用 asm_list_task_options(kind=template_detail,id=%s)，并传入返回的 template_verification_token", templateID)
		}
		detail, detailErr := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template/detail", nil, map[string]string{"id": templateID})
		if detailErr != nil {
			return nil, detailErr
		}
		actualToken := ""
		templateSummary, actualToken, detailErr = scopeSentryTemplateInspection(detail, plugins)
		if detailErr != nil {
			return nil, detailErr
		}
		if verificationToken != actualToken {
			return nil, fmt.Errorf("ScopeSentry 模板已在详情查询后发生变化，请重新调用 asm_list_task_options(kind=template_detail,id=%s) 确认实际配置", templateID)
		}
		if err := scopeSentryValidateTemplateExpectations(req.Options, templateSummary); err != nil {
			return nil, err
		}
	} else {
		templateID, err = a.ensureTemplate(ctx, client, conn, token, req.Options)
		if err != nil {
			return nil, err
		}
		detail, detailErr := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template/detail", nil, map[string]string{"id": templateID})
		if detailErr != nil {
			return nil, detailErr
		}
		templateSummary, _, detailErr = scopeSentryTemplateInspection(detail, plugins)
		if detailErr != nil {
			return nil, detailErr
		}
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "CyberStrikeAI ASM " + time.Now().Format("20060102-150405.000")
	}
	if len(name) > 150 {
		return nil, fmt.Errorf("ScopeSentry 任务名称不能超过 150 字符")
	}
	ignore, err := taskOptionString("ScopeSentry", req.Options, "ignore", "", 10000)
	if err != nil {
		return nil, err
	}
	duplicates, err := taskOptionEnum("ScopeSentry", req.Options, "duplicates", "None", "None", "subdomain")
	if err != nil {
		return nil, err
	}
	projectIDs, err := taskOptionStringSlice("ScopeSentry", req.Options, "project_ids", nil, 100, 64)
	if err != nil {
		return nil, err
	}
	for i, id := range projectIDs {
		projectIDs[i], err = scopeSentryValidateObjectID(id, "project_ids", false)
		if err != nil {
			return nil, err
		}
	}
	if targetSource == "project" && len(projectIDs) == 0 {
		return nil, fmt.Errorf("ScopeSentry project 目标来源需要 project_ids")
	}
	sourceSearch, err := taskOptionString("ScopeSentry", req.Options, "source_search", "", 1000)
	if err != nil {
		return nil, err
	}
	sourceLimit, err := taskOptionInt("ScopeSentry", req.Options, "source_limit", 1000, 1, 100000)
	if err != nil {
		return nil, err
	}
	sourceFilter, err := scopeSentrySourceFilter(req.Options)
	if err != nil {
		return nil, err
	}
	scheduled, err := taskOptionBool("ScopeSentry", req.Options, "scheduled", false)
	if err != nil {
		return nil, err
	}
	cycleType, err := taskOptionEnum("ScopeSentry", req.Options, "cycle_type", "daily", "daily", "ndays", "nhours", "weekly", "monthly")
	if err != nil {
		return nil, err
	}
	hour, err := taskOptionInt("ScopeSentry", req.Options, "hour", 0, 0, 23)
	if err != nil {
		return nil, err
	}
	minute, err := taskOptionInt("ScopeSentry", req.Options, "minute", 0, 0, 59)
	if err != nil {
		return nil, err
	}
	day, err := taskOptionInt("ScopeSentry", req.Options, "day", 1, 1, 31)
	if err != nil {
		return nil, err
	}
	week, err := taskOptionInt("ScopeSentry", req.Options, "week", 1, 0, 6)
	if err != nil {
		return nil, err
	}
	endpoint := "/api/task/add"
	if scheduled {
		endpoint = "/api/task/scheduled/add"
	}
	requestBody := map[string]interface{}{
		"name": name, "node": selectedNodes, "allNode": allNodes, "scheduledTasks": scheduled,
		"target": target, "ignore": ignore, "template": templateID, "project": projectIDs,
		"search": sourceSearch, "filter": sourceFilter, "duplicates": duplicates, "targetSource": targetSource,
		"targetNumber": sourceLimit, "targetIds": []string{}, "bindProject": nil, "cycleType": cycleType,
		"hour": hour, "minute": minute, "day": day, "week": week,
	}
	_, err = scopeSentryRequest(ctx, client, conn, token, http.MethodPost, endpoint, nil, requestBody)
	if err != nil {
		return nil, err
	}
	if scheduled {
		for attempt := 0; attempt < 15; attempt++ {
			listed, listErr := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/scheduled", nil, map[string]interface{}{
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
						task["status"] = "submitted"
						task["stage"] = "scheduled"
						task["task_kind"] = "scheduled"
						return map[string]interface{}{
							"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID, "scheduled": true,
							"task": task, "template_id": templateID, "nodes": selectedNodes,
							"template_verified": true, "effective_template": templateSummary,
						}, nil
					}
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		return nil, fmt.Errorf("ScopeSentry 定时任务已提交但无法读取任务 ID")
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
						"task": task, "template_id": templateID, "nodes": selectedNodes,
						"template_verified": true, "effective_template": templateSummary,
					}, nil
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("ScopeSentry 任务已提交但无法读取任务 ID")
}

func (a *ScopeSentryAdapter) GetTaskProfile(ctx context.Context, conn *Connection) (interface{}, error) {
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	plugins, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/plugin", nil, map[string]interface{}{
		"pageIndex": 1, "pageSize": 200, "search": "",
	})
	if err != nil {
		return nil, fmt.Errorf("读取 ScopeSentry 已安装插件失败: %w", err)
	}
	availableCapabilities, unavailableCapabilities := scopeSentryAvailableCapabilities(plugins)
	return map[string]interface{}{
		"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID, "upstream_version": "v1.9.3",
		"available_template_capabilities":   availableCapabilities,
		"unavailable_template_capabilities": unavailableCapabilities,
		"task_modes":                        []string{"immediate", "scheduled"},
		"dynamic_option_kinds":              []string{"nodes", "templates", "template_detail", "port_dictionaries", "dictionaries", "plugins", "pocs", "projects"},
		"manage_actions":                    []string{"resume", "restart", "delete"},
		"result_types":                      providerResultTypes(ProviderScopeSentry),
		"notes": []string{
			"提供 template_id 时完整复用 ScopeSentry 上游模板，端口字典、文件字典、插件参数和 POC 均由该模板决定",
			"Agent 和 ASM 任务中心可以克隆已有模板，通过受控字段选择能力、端口、并发、截图、TLS 和 POC，并立即用新模板下发任务",
			"使用 template_id 前必须单独调用 template_detail，并在创建时传回 template_verification_token；模板列表或名称不能证明实际能力",
			"用户要求全端口或指定能力时，必须分别传 required_port_scope 和 required_capabilities；模板不满足时会在上游创建前拒绝",
			"未提供 template_id 时按受控端口、并发、截图与 TLS 配置指纹生成独立低负载模板，任务之间不会相互覆盖",
			"不允许 Agent 直接传入任意插件命令行；模板创建仅能修改适配器已声明的结构化字段",
			"模板、端口字典和 POC 列表仅返回选择所需的轻量摘要，避免大型上游响应挤占 Agent 上下文",
			"定时任务会回查上游 ID 并记录到 ASM 任务中心；定时定义不支持 stop/resume/restart，仅支持显式 delete",
		},
		"template_create_options": map[string]interface{}{
			"base_template_id":     map[string]interface{}{"type": "string", "dynamic_kind": "templates", "description": "要克隆的上游模板；留空使用 default"},
			"enabled_capabilities": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string", "enum": availableCapabilities}, "description": "新模板启用的能力；已安装但基模板未启用的插件会自动补齐"},
			"ports":                map[string]interface{}{"type": "string", "description": "结构化端口表达式，例如 1-65535 或 80,443"},
			"concurrency":          map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 200, "description": "端口扫描并发"},
			"site_capture":         map[string]interface{}{"type": "boolean", "description": "是否截图"},
			"tls_probe":            map[string]interface{}{"type": "boolean", "description": "是否执行 TLS 探测"},
			"poc_ids":              map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "dynamic_kind": "pocs", "description": "漏洞扫描选用的 POC"},
		},
		"create_options": map[string]interface{}{
			"template_id":                 map[string]interface{}{"type": "string", "dynamic_kind": "templates", "description": "选择已在上游配置好的完整模板；选择后必须查询 template_detail"},
			"template_verification_token": map[string]interface{}{"type": "string", "requires": "template_id", "dynamic_kind": "template_detail", "description": "template_detail 返回的校验令牌，用于证明已核对实际模板配置"},
			"required_port_scope":         map[string]interface{}{"type": "string", "enum": []string{"all", "top1000", "top100", "custom"}, "requires": "template_id", "description": "用户要求的端口范围断言；要求全端口时必须传 all"},
			"required_capabilities":       map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string", "enum": availableCapabilities}, "requires": "template_id", "description": "用户明确要求的已安装能力断言；MCP 在创建上游任务前逐项校验"},
			"node_names":                  map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "dynamic_kind": "nodes"},
			"all_nodes":                   map[string]interface{}{"type": "boolean", "default": false},
			"ignore":                      map[string]interface{}{"type": "string", "description": "排除目标，按上游格式分行"},
			"duplicates":                  map[string]interface{}{"type": "string", "enum": []string{"None", "subdomain"}, "default": "None"},
			"target_source":               map[string]interface{}{"type": "string", "enum": []string{"general", "project", "asset", "RootDomain", "subdomain"}, "default": "general"},
			"project_ids":                 map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "dynamic_kind": "projects"},
			"source_search":               map[string]interface{}{"type": "string", "description": "非 general/project 目标来源的上游查询表达式"},
			"source_limit":                map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 100000, "default": 1000},
			"source_filter":               map[string]interface{}{"type": "object", "description": "非 general/project 目标来源的结构化过滤条件"},
			"scheduled":                   map[string]interface{}{"type": "boolean", "default": false},
			"cycle_type":                  map[string]interface{}{"type": "string", "enum": []string{"daily", "ndays", "nhours", "weekly", "monthly"}, "default": "daily", "requires": "scheduled"},
			"hour":                        map[string]interface{}{"type": "integer", "minimum": 0, "maximum": 23, "default": 0, "requires": "scheduled"},
			"minute":                      map[string]interface{}{"type": "integer", "minimum": 0, "maximum": 59, "default": 0, "requires": "scheduled"},
			"day":                         map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 31, "default": 1, "requires": "scheduled"},
			"week":                        map[string]interface{}{"type": "integer", "minimum": 0, "maximum": 6, "default": 1, "requires": "scheduled"},
			"port_scan":                   map[string]interface{}{"type": "boolean", "default": true, "mode": "generated_low_load_template"},
			"site_identify":               map[string]interface{}{"type": "boolean", "default": true, "mode": "generated_low_load_template"},
			"ports":                       map[string]interface{}{"type": "string", "default": "80,443,8080,8082", "mode": "generated_low_load_template"},
			"concurrency":                 map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 200, "default": 20, "mode": "generated_low_load_template"},
			"site_capture":                map[string]interface{}{"type": "boolean", "default": false, "mode": "generated_low_load_template"},
			"tls_probe":                   map[string]interface{}{"type": "boolean", "default": false, "mode": "generated_low_load_template"},
		},
	}, nil
}

func (a *ScopeSentryAdapter) ListTaskOptions(ctx context.Context, conn *Connection, filter TaskOptionFilter) (interface{}, error) {
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	page, size := normalizePagination(filter.Page, filter.PageSize)
	kind := strings.ToLower(strings.TrimSpace(filter.Kind))
	var method, endpoint string
	var query url.Values
	var body interface{}
	switch kind {
	case "nodes":
		method, endpoint = http.MethodGet, "/api/node/online"
	case "templates":
		method, endpoint = http.MethodPost, "/api/task/template"
		body = map[string]interface{}{"pageIndex": page, "pageSize": size, "search": filter.Query, "query": filter.Query}
	case "template_detail":
		id, idErr := scopeSentryValidateObjectID(filter.ID, "template id", false)
		if idErr != nil {
			return nil, idErr
		}
		method, endpoint, body = http.MethodPost, "/api/task/template/detail", map[string]string{"id": id}
	case "port_dictionaries":
		method, endpoint = http.MethodPost, "/api/dictionary/port/data"
		body = map[string]interface{}{"pageIndex": page, "pageSize": size, "search": filter.Query}
	case "dictionaries":
		method, endpoint = http.MethodGet, "/api/dictionary/manage/list"
		query = url.Values{"pageIndex": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}, "search": {filter.Query}}
	case "plugins":
		method, endpoint = http.MethodPost, "/api/plugin"
		body = map[string]interface{}{"pageIndex": page, "pageSize": size, "search": filter.Query}
	case "pocs":
		method, endpoint = http.MethodPost, "/api/poc"
		body = map[string]interface{}{
			"pageIndex": page, "pageSize": size, "search": filter.Query,
			"filter": map[string]interface{}{"level": []interface{}{}},
		}
	case "projects":
		method, endpoint = http.MethodGet, "/api/project/all"
	default:
		return nil, fmt.Errorf("ScopeSentry 不支持的动态选项类别: %s", filter.Kind)
	}
	payload, err := scopeSentryRequest(ctx, client, conn, token, method, endpoint, query, body)
	if err != nil {
		return nil, err
	}
	if kind == "template_detail" {
		plugins, pluginErr := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/plugin", nil, map[string]interface{}{
			"pageIndex": 1, "pageSize": 200, "search": "",
		})
		if pluginErr != nil {
			return nil, fmt.Errorf("读取 ScopeSentry 已安装插件失败: %w", pluginErr)
		}
		summary, verificationToken, inspectionErr := scopeSentryTemplateInspection(payload, plugins)
		if inspectionErr != nil {
			return nil, inspectionErr
		}
		return map[string]interface{}{
			"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID, "kind": kind,
			"options": map[string]interface{}{
				"detail": payload, "capability_summary": summary, "verification_token": verificationToken,
			},
		}, nil
	}
	payload = scopeSentryCompactOptionPayload(kind, payload)
	return map[string]interface{}{"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID, "kind": kind, "options": payload}, nil
}

func normalizeScopeSentryTaskID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !scopeSentryTaskIDPattern.MatchString(value) {
		return "", fmt.Errorf("ScopeSentry 任务 ID 格式无效")
	}
	return strings.ToLower(value), nil
}

func scopeSentryTaskTemplateID(task map[string]interface{}) string {
	if task == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(mapValue(task, "template", "template_id", "templateId")))
}

func (a *ScopeSentryAdapter) enrichTaskTemplateProfile(ctx context.Context, client *http.Client, conn *Connection, token string, task map[string]interface{}, cache map[string]map[string]interface{}) {
	templateID := scopeSentryTaskTemplateID(task)
	if !scopeSentryTaskIDPattern.MatchString(templateID) {
		return
	}
	profile, exists := cache[templateID]
	if !exists {
		payload, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/template/detail", nil, map[string]string{"id": templateID})
		if err != nil {
			cache[templateID] = nil
			return
		}
		template := scopeSentryMap(scopeSentryData(payload))
		name := strings.TrimSpace(fmt.Sprint(template["name"]))
		if name == "" || name == "<nil>" {
			cache[templateID] = nil
			return
		}
		profile = map[string]interface{}{
			"kind": "template", "label": "ScopeSentry 模板", "id": templateID, "name": name,
		}
		cache[templateID] = profile
	}
	if len(profile) == 0 {
		return
	}
	task["template_name"] = profile["name"]
	task["execution_profile"] = profile
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
	scheduled, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/scheduled", nil, map[string]interface{}{
		"pageIndex": page, "pageSize": size, "search": search,
	})
	if err != nil {
		return nil, err
	}
	templateProfiles := make(map[string]map[string]interface{})
	for _, item := range scopeSentryList(payload) {
		a.enrichTaskTemplateProfile(ctx, client, conn, token, scopeSentryMap(item), templateProfiles)
	}
	for _, item := range scopeSentryList(scheduled) {
		task := scopeSentryMap(item)
		a.enrichTaskTemplateProfile(ctx, client, conn, token, task, templateProfiles)
		task["status"] = "submitted"
		task["stage"] = "scheduled"
		task["task_kind"] = "scheduled"
	}
	return map[string]interface{}{
		"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID,
		"tasks": payload, "scheduled_tasks": scheduled,
	}, nil
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

func (a *ScopeSentryAdapter) getImmediateTaskWithSession(ctx context.Context, client *http.Client, conn *Connection, token, taskID string) (interface{}, error) {
	payload, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/detail", nil, map[string]string{"id": taskID})
	if err != nil {
		return nil, err
	}
	task := scopeSentryMap(scopeSentryData(payload))
	if task == nil || !strings.EqualFold(strings.TrimSpace(fmt.Sprint(task["id"])), taskID) {
		return nil, fmt.Errorf("ScopeSentry 即时任务详情响应无效")
	}
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
		"task": payload, "normalized_status": scopeSentryStatus(status), "task_kind": "immediate",
	}, nil
}

func (a *ScopeSentryAdapter) getScheduledTaskWithSession(ctx context.Context, client *http.Client, conn *Connection, token, taskID string) (interface{}, error) {
	payload, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/scheduled/detail", nil, map[string]string{"id": taskID})
	if err != nil {
		return nil, err
	}
	task := scopeSentryMap(scopeSentryData(payload))
	if task == nil || !strings.EqualFold(strings.TrimSpace(fmt.Sprint(task["id"])), taskID) {
		return nil, fmt.Errorf("ScopeSentry 定时任务详情响应无效")
	}
	task["status"] = "submitted"
	task["stage"] = "scheduled"
	task["task_kind"] = "scheduled"
	return map[string]interface{}{
		"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID,
		"task": payload, "normalized_status": "submitted", "task_kind": "scheduled",
	}, nil
}

func (a *ScopeSentryAdapter) getTaskWithSession(ctx context.Context, client *http.Client, conn *Connection, token, taskID string) (interface{}, error) {
	taskID, err := normalizeScopeSentryTaskID(taskID)
	if err != nil {
		return nil, err
	}
	immediate, immediateErr := a.getImmediateTaskWithSession(ctx, client, conn, token, taskID)
	if immediateErr == nil {
		result := valueMap(immediate)
		task := scopeSentryMap(scopeSentryData(result["task"]))
		a.enrichTaskTemplateProfile(ctx, client, conn, token, task, make(map[string]map[string]interface{}))
		if profile := valueMap(task["execution_profile"]); len(profile) > 0 {
			result["execution_profile"] = profile
			result["template_id"] = profile["id"]
			result["template_name"] = profile["name"]
		}
		return immediate, nil
	}
	scheduled, scheduledErr := a.getScheduledTaskWithSession(ctx, client, conn, token, taskID)
	if scheduledErr == nil {
		result := valueMap(scheduled)
		task := scopeSentryMap(scopeSentryData(result["task"]))
		a.enrichTaskTemplateProfile(ctx, client, conn, token, task, make(map[string]map[string]interface{}))
		if profile := valueMap(task["execution_profile"]); len(profile) > 0 {
			result["execution_profile"] = profile
			result["template_id"] = profile["id"]
			result["template_name"] = profile["name"]
		}
		return scheduled, nil
	}
	return nil, fmt.Errorf("ScopeSentry 既未找到即时任务也未找到定时任务: %w", immediateErr)
}

func (a *ScopeSentryAdapter) GetTask(ctx context.Context, conn *Connection, taskID string) (interface{}, error) {
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	return a.getTaskWithSession(ctx, client, conn, token, taskID)
}

var scopeSentryAssetEndpoints = map[string]struct{ path, field, index string }{
	"site":          {"/api/assets/asset", "domain", "asset"},
	"domain":        {"/api/assets/subdomain", "domain", "subdomain"},
	"ip":            {"/api/assets/ip", "ip", "IPAsset"},
	"url":           {"/api/assets/url", "url", "UrlScan"},
	"service":       {"/api/assets/ip", "service", "IPAsset"},
	"crawler":       {"/api/assets/crawler", "url", "crawler"},
	"sensitive":     {"/api/assets/sensitive", "url", "SensitiveResult"},
	"directory":     {"/api/assets/dirscan", "url", "DirScanResult"},
	"takeover":      {"/api/assets/subdomain/taker", "domain", "SubdomainTakerResult"},
	"vulnerability": {"/api/assets/vulnerability", "url", "vulnerability"},
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
	body := map[string]interface{}{
		"pageIndex": page, "pageSize": size, "search": strings.Join(expressions, "&&"),
		"filter": map[string]interface{}{}, "sort": map[string]interface{}{},
	}
	payload, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, endpoint.path, nil, body)
	if err != nil {
		return nil, err
	}
	total := pathValue(payload, "data", "total")
	if total == nil {
		totalPayload, totalErr := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/assets/common/total", nil, map[string]interface{}{
			"pageIndex": page, "pageSize": size, "search": body["search"], "filter": body["filter"], "index": endpoint.index,
		})
		if totalErr == nil {
			total = pathValue(totalPayload, "data", "total")
		}
	}
	return map[string]interface{}{
		"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID,
		"asset_type": assetType, "results": payload, "total": total,
	}, nil
}

func (a *ScopeSentryAdapter) GetAssetDetail(ctx context.Context, conn *Connection, filter AssetDetailFilter) (interface{}, error) {
	if strings.ToLower(strings.TrimSpace(filter.Type)) != "vulnerability" {
		return nil, fmt.Errorf("ScopeSentry 结果详情类型不支持: %s", filter.Type)
	}
	hash := strings.TrimSpace(filter.Key)
	if hash == "" || len(hash) > 256 {
		return nil, fmt.Errorf("ScopeSentry 漏洞 hash 无效")
	}
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	payload, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/assets/vulnerability/detail", nil, map[string]string{"hash": hash})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider": ProviderScopeSentry, "asset_type": "vulnerability", "key": hash, "detail": payload,
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
	detail, err := a.getTaskWithSession(ctx, client, conn, token, taskID)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(meaningfulString(pathValue(detail, "task_kind")), "scheduled") {
		return nil, fmt.Errorf("ScopeSentry 定时任务是调度定义，不支持 stop；如需移除请显式使用 manage_task action=delete")
	}
	payload, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, "/api/task/stop", nil, map[string]interface{}{"ids": []string{taskID}})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID, "response": payload}, nil
}

func (a *ScopeSentryAdapter) ManageTask(ctx context.Context, conn *Connection, req TaskManageRequest) (interface{}, error) {
	taskID, err := normalizeScopeSentryTaskID(req.TaskID)
	if err != nil {
		return nil, err
	}
	client, token, err := a.session(ctx, conn)
	if err != nil {
		return nil, err
	}
	detail, err := a.getTaskWithSession(ctx, client, conn, token, taskID)
	if err != nil {
		return nil, err
	}
	scheduled := strings.EqualFold(meaningfulString(pathValue(detail, "task_kind")), "scheduled")
	var endpoint string
	var body interface{}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if scheduled && action != "delete" {
		return nil, fmt.Errorf("ScopeSentry 定时任务不支持 %s，仅支持显式 delete", req.Action)
	}
	switch action {
	case "resume":
		endpoint, body = "/api/task/start", map[string]interface{}{"ids": []string{taskID}}
	case "restart":
		endpoint, body = "/api/task/retest", map[string]interface{}{"id": taskID}
	case "delete":
		if scheduled {
			if len(req.Options) > 0 {
				return nil, fmt.Errorf("ScopeSentry 删除定时任务不支持额外选项")
			}
			endpoint, body = "/api/task/scheduled/delete", map[string]interface{}{"ids": []string{taskID}}
			break
		}
		deleteResults, err := taskOptionBool("ScopeSentry", req.Options, "delete_results", false)
		if err != nil {
			return nil, err
		}
		endpoint, body = "/api/task/delete", map[string]interface{}{"ids": []string{taskID}, "delA": deleteResults}
	default:
		return nil, fmt.Errorf("ScopeSentry 不支持的任务管理动作: %s", req.Action)
	}
	payload, err := scopeSentryRequest(ctx, client, conn, token, http.MethodPost, endpoint, nil, body)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"provider": ProviderScopeSentry, "resource_id": conn.Resource.ID, "action": req.Action, "response": payload}, nil
}
