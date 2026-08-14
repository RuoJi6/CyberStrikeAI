package asm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// TemplatePreset is a provider-neutral, audited scan profile. The public
// metadata is shared by the ASM resource page and MCP. ProviderOptions stays
// server-side so callers cannot accidentally drift from the built-in profile.
type TemplatePreset struct {
	ID                 string                            `json:"id"`
	Name               string                            `json:"name"`
	Description        string                            `json:"description"`
	Level              string                            `json:"level"`
	EstimatedDuration  string                            `json:"estimated_duration"`
	PortScope          string                            `json:"port_scope"`
	Capabilities       []string                          `json:"capabilities"`
	Warning            string                            `json:"warning,omitempty"`
	SupportedProviders []string                          `json:"supported_providers"`
	Provider           string                            `json:"provider,omitempty"`
	ProviderKind       string                            `json:"provider_kind,omitempty"`
	ProviderConfig     map[string]interface{}            `json:"provider_config,omitempty"`
	MCPUsage           map[string]interface{}            `json:"mcp_usage,omitempty"`
	ProviderOptions    map[string]map[string]interface{} `json:"-"`
}

var builtInTemplatePresets = []TemplatePreset{
	{
		ID: "quick_discovery", Name: "快速探测", Level: "低", EstimatedDuration: "数分钟",
		Description: "快速确认常见端口、服务与 Web 站点，适合首轮存活性排查。",
		PortScope:   "ARL TOP100 / 常见服务端口", Capabilities: []string{"常见端口", "服务指纹", "站点识别", "TLS 探测"},
		SupportedProviders: []string{ProviderARL, ProviderScopeSentry},
		ProviderOptions: map[string]map[string]interface{}{
			ProviderARL: {
				"domain_brute": false, "domain_brute_type": "test", "alt_dns": false, "arl_search": false, "dns_query_plugin": false,
				"port_scan": true, "port_scan_type": "top100", "service_detection": true, "os_detection": false, "ssl_cert": true,
				"skip_scan_cdn_ip": true, "site_identify": true, "site_capture": false, "search_engines": false, "site_spider": false,
				"nuclei_scan": false, "web_info_hunter": false, "file_leak": false, "npoc_service_detection": false,
				"host_timeout_type": "default", "host_timeout": 600, "port_parallelism": 16, "port_min_rate": 40,
				"poc_selection": "none", "brute_selection": "none",
			},
			ProviderScopeSentry: {
				"enabled_capabilities": []string{"port_scan", "service_fingerprint", "site_identify", "tls_probe", "asset_handle"},
				"ports":                "21,22,23,25,53,80,81,110,135,139,143,443,445,587,993,995,1433,1521,2375,2379,3000,3306,3389,5432,5601,5672,5900,6379,7001,8000,8009,8080,8081,8082,8083,8443,9000,9090,9200,11211,27017",
				"concurrency":          10, "site_capture": false, "tls_probe": true,
			},
		},
	},
	{
		ID: "information_collection", Name: "信息收集", Level: "中", EstimatedDuration: "10–30 分钟",
		Description: "扩展子域、端口、服务、站点、截图与爬虫信息，不主动执行漏洞 POC。",
		PortScope:   "ARL TOP1000 / Scope 1-10000", Capabilities: []string{"子域发现", "扩展端口", "服务指纹", "站点截图", "URL/爬虫"},
		SupportedProviders: []string{ProviderARL, ProviderScopeSentry},
		ProviderOptions: map[string]map[string]interface{}{
			ProviderARL: {
				"domain_brute": true, "domain_brute_type": "test", "alt_dns": true, "arl_search": true, "dns_query_plugin": true,
				"port_scan": true, "port_scan_type": "top1000", "service_detection": true, "os_detection": false, "ssl_cert": true,
				"skip_scan_cdn_ip": true, "site_identify": true, "site_capture": true, "search_engines": true, "site_spider": true,
				"nuclei_scan": false, "web_info_hunter": true, "file_leak": false, "npoc_service_detection": false,
				"host_timeout_type": "default", "host_timeout": 900, "port_parallelism": 24, "port_min_rate": 60,
				"poc_selection": "none", "brute_selection": "none",
			},
			ProviderScopeSentry: {
				"enabled_capabilities": []string{"subdomain_discovery", "port_scan", "service_fingerprint", "site_identify", "site_capture", "tls_probe", "url_scan", "web_crawler", "asset_handle"},
				"ports":                "1-10000", "concurrency": 20, "site_capture": true, "tls_probe": true,
			},
		},
	},
	{
		ID: "vulnerability_assessment", Name: "漏洞巡检", Level: "中高", EstimatedDuration: "20–60 分钟",
		Description: "在资产与服务识别基础上执行平台默认漏洞检测，适合已授权的周期巡检。",
		PortScope:   "ARL TOP1000 / Scope 1-10000", Capabilities: []string{"扩展端口", "服务指纹", "站点识别", "文件泄露", "漏洞 POC"},
		Warning: "会发送漏洞检测请求，仅用于明确授权目标。", SupportedProviders: []string{ProviderARL, ProviderScopeSentry},
		ProviderOptions: map[string]map[string]interface{}{
			ProviderARL: {
				"domain_brute": false, "domain_brute_type": "test", "alt_dns": false, "arl_search": true, "dns_query_plugin": false,
				"port_scan": true, "port_scan_type": "top1000", "service_detection": true, "os_detection": false, "ssl_cert": true,
				"skip_scan_cdn_ip": true, "site_identify": true, "site_capture": true, "search_engines": false, "site_spider": true,
				"nuclei_scan": true, "web_info_hunter": false, "file_leak": true, "npoc_service_detection": true,
				"host_timeout_type": "default", "host_timeout": 1200, "port_parallelism": 24, "port_min_rate": 60,
				"poc_selection": "all", "brute_selection": "none",
			},
			ProviderScopeSentry: {
				"enabled_capabilities": []string{"port_scan", "service_fingerprint", "site_identify", "site_capture", "tls_probe", "url_scan", "sensitive_scan", "vulnerability_scan", "asset_handle"},
				"ports":                "1-10000", "concurrency": 20, "site_capture": true, "tls_probe": true,
			},
		},
	},
	{
		ID: "full_scan", Name: "全量扫描", Level: "高", EstimatedDuration: "1 小时以上",
		Description: "启用当前平台可用的完整扫描链路并扫描 1–65535 端口，用于完整攻击面复核。",
		PortScope:   "all", Capabilities: []string{"大字典子域", "全端口", "服务/操作系统", "站点与截图", "爬虫/敏感信息", "漏洞 POC", "弱口令爆破"},
		Warning: "资源消耗和扫描流量最高，请确认授权窗口与上游节点容量。", SupportedProviders: []string{ProviderARL, ProviderScopeSentry},
		ProviderOptions: map[string]map[string]interface{}{
			ProviderARL: {
				"domain_brute": true, "domain_brute_type": "big", "alt_dns": true, "arl_search": true, "dns_query_plugin": true,
				"port_scan": true, "port_scan_type": "all", "service_detection": true, "os_detection": true, "ssl_cert": true,
				"skip_scan_cdn_ip": false, "site_identify": true, "site_capture": true, "search_engines": true, "site_spider": true,
				"nuclei_scan": true, "web_info_hunter": true, "file_leak": true, "npoc_service_detection": true,
				"host_timeout_type": "custom", "host_timeout": 1800, "port_parallelism": 32, "port_min_rate": 80,
				"poc_selection": "all", "brute_selection": "all",
			},
			ProviderScopeSentry: {
				"enabled_capabilities": []string{
					"subdomain_discovery", "subdomain_takeover", "port_scan", "service_fingerprint", "site_identify", "site_capture", "tls_probe",
					"url_scan", "web_crawler", "sensitive_scan", "directory_scan", "vulnerability_scan", "asset_handle",
				},
				"ports": "1-65535", "concurrency": 30, "site_capture": true, "tls_probe": true,
			},
		},
	},
}

func templatePresetsForProvider(provider string) []TemplatePreset {
	provider = normalizeProvider(provider)
	result := make([]TemplatePreset, 0, len(builtInTemplatePresets))
	for _, preset := range builtInTemplatePresets {
		options, ok := cloneTemplatePresetOptions(preset.ProviderOptions[provider])
		if !ok {
			continue
		}
		copyPreset := preset
		copyPreset.Capabilities = append([]string(nil), preset.Capabilities...)
		copyPreset.SupportedProviders = append([]string(nil), preset.SupportedProviders...)
		copyPreset.Provider = provider
		copyPreset.ProviderConfig = options
		if provider == ProviderARL {
			copyPreset.ProviderKind = "policy"
			copyPreset.MCPUsage = map[string]interface{}{
				"create":             map[string]interface{}{"tool": "asm_create_template", "arguments": map[string]interface{}{"preset_id": preset.ID}},
				"scan":               map[string]interface{}{"tool": "asm_create_task", "options": map[string]interface{}{"task_mode": "policy", "policy_id": "<template_id returned by asm_create_template>"}},
				"dynamic_resolution": "poc_selection/brute_selection=all 会在创建或校准策略时解析为上游全部已安装插件",
			}
		} else {
			copyPreset.ProviderKind = "task_template"
			copyPreset.MCPUsage = map[string]interface{}{
				"create":     map[string]interface{}{"tool": "asm_create_template", "arguments": map[string]interface{}{"preset_id": preset.ID}},
				"scan":       map[string]interface{}{"tool": "asm_create_task", "options": map[string]interface{}{"template_id": "<template_id returned by asm_create_template>", "template_verification_token": "<verification_token returned by asm_create_template>"}},
				"validation": "enabled_capabilities 会与 ScopeSentry 上游已安装插件核对，缺少必需插件时拒绝创建",
			}
		}
		copyPreset.ProviderOptions = nil
		result = append(result, copyPreset)
	}
	return result
}

func cloneTemplatePresetOptions(options map[string]interface{}) (map[string]interface{}, bool) {
	if options == nil {
		return nil, false
	}
	raw, err := json.Marshal(options)
	if err != nil {
		return nil, false
	}
	var cloned map[string]interface{}
	if json.Unmarshal(raw, &cloned) != nil {
		return nil, false
	}
	return cloned, true
}

func templatePresetByID(provider, presetID string) (TemplatePreset, map[string]interface{}, bool) {
	provider = normalizeProvider(provider)
	presetID = strings.ToLower(strings.TrimSpace(presetID))
	for _, preset := range builtInTemplatePresets {
		if preset.ID != presetID {
			continue
		}
		options, ok := preset.ProviderOptions[provider]
		if !ok {
			return TemplatePreset{}, nil, false
		}
		cloned, ok := cloneTemplatePresetOptions(options)
		if !ok {
			return TemplatePreset{}, nil, false
		}
		return preset, cloned, true
	}
	return TemplatePreset{}, nil, false
}

func applyTemplatePreset(provider string, req TemplateRequest) (TemplateRequest, error) {
	req.PresetID = strings.ToLower(strings.TrimSpace(req.PresetID))
	if req.PresetID == "" {
		return req, nil
	}
	if len(req.Options) > 0 {
		return TemplateRequest{}, fmt.Errorf("使用内置模板时不允许覆盖 options，请使用自定义模板或只传 preset_id")
	}
	preset, options, ok := templatePresetByID(provider, req.PresetID)
	if !ok {
		return TemplateRequest{}, fmt.Errorf("%s 不支持内置模板: %s", providerDisplayName(provider), req.PresetID)
	}
	if strings.TrimSpace(req.BaseTemplateID) != "" {
		return TemplateRequest{}, fmt.Errorf("内置模板不允许指定 base_template_id")
	}
	canonicalName := "CyberStrikeAI · " + preset.Name
	if name := strings.TrimSpace(req.Name); name != "" && name != canonicalName {
		return TemplateRequest{}, fmt.Errorf("内置模板名称固定为 %s，请省略 name", canonicalName)
	}
	req.Name = canonicalName
	req.Options = options
	return req, nil
}
