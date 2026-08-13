package app

import (
	"context"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/asm"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

func registerASMTools(server *mcp.Server, service *asm.Service, logger *zap.Logger) {
	if server == nil || service == nil {
		return
	}

	register := func(tool mcp.Tool, run func(context.Context, map[string]interface{}) (interface{}, error)) {
		server.RegisterTool(tool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
			value, err := run(ctx, args)
			if err != nil {
				logger.Warn("ASM MCP 工具调用失败", zap.String("tool", tool.Name), zap.Error(err))
				return textResult("错误: "+err.Error(), true), nil
			}
			return textResult(asm.MarshalResult(value), false), nil
		})
	}

	register(mcp.Tool{
		Name: builtin.ToolASMListResources, ShortDescription: "列出可用 ASM 连接",
		Description: "列出当前已启用、凭据已脱敏的 ASM 资源及其类型、连接状态和能力。下发 ASM 任务前先调用本工具选择 resource_id。",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
	}, func(_ context.Context, _ map[string]interface{}) (interface{}, error) {
		return service.ListResources(true)
	})

	resourceSchema := func(extra map[string]interface{}, required ...string) map[string]interface{} {
		properties := map[string]interface{}{"resource_id": map[string]interface{}{"type": "string", "description": "由 asm_list_resources 返回的 ASM 资源 ID"}}
		for key, value := range extra {
			properties[key] = value
		}
		allRequired := append([]string{"resource_id"}, required...)
		return map[string]interface{}{"type": "object", "properties": properties, "required": allRequired}
	}

	register(mcp.Tool{
		Name: builtin.ToolASMTestConnection, ShortDescription: "测试 ASM 连接",
		Description: "验证指定 ASM 的地址与凭据是否可用，并更新资源连接状态。不会创建扫描任务。",
		InputSchema: resourceSchema(nil),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return service.TestConnection(ctx, asmStringArg(args, "resource_id"))
	})

	register(mcp.Tool{
		Name: builtin.ToolASMGetTaskProfile, ShortDescription: "读取 ASM 创建任务配置",
		Description: "读取指定 ASM 的固定版本、任务模式、可用字段、枚举、默认值、依赖关系和动态选项类别。创建任务前应先调用本工具，避免向错误的平台传入无效字段。",
		InputSchema: resourceSchema(nil),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return service.GetTaskProfile(ctx, asmStringArg(args, "resource_id"))
	})

	register(mcp.Tool{
		Name: builtin.ToolASMListTaskOptions, ShortDescription: "查询 ASM 动态任务选项",
		Description: "按类别查询平台实时的策略、引擎、字典、端口字典、节点、模板、插件或 POC。kind 可传 all，按当前分页批量查询全部列表型类别；*_detail 需传 id 单独查询。ScopeSentry 选择模板后必须再查询 template_detail；返回的 capability_summary 是实际端口/能力依据，verification_token 必须传给 asm_create_task。禁止仅根据模板名称推断“全功能”或“全端口”。",
		InputSchema: resourceSchema(map[string]interface{}{
			"kind":      map[string]interface{}{"type": "string", "description": "动态选项类别；传 all 会按 page/page_size 为每个列表型类别各查询一页"},
			"query":     map[string]interface{}{"type": "string", "description": "名称或关键字筛选"},
			"id":        map[string]interface{}{"type": "string", "description": "查询详情时使用的上游 ID"},
			"page":      map[string]interface{}{"type": "integer", "minimum": 1},
			"page_size": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 100},
		}, "kind"),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return service.ListTaskOptions(ctx, asmStringArg(args, "resource_id"), asm.TaskOptionFilter{
			Kind: asmStringArg(args, "kind"), Query: asmStringArg(args, "query"), ID: asmStringArg(args, "id"),
			Page: asmIntArg(args, "page"), PageSize: asmIntArg(args, "page_size"),
		})
	})

	register(mcp.Tool{
		Name: builtin.ToolASMCreateTemplate, ShortDescription: "创建 ScopeSentry 扫描模板",
		Description: "在 ScopeSentry 上游创建可审计的扫描模板。先用 asm_list_task_options(kind=templates) 选择基模板，再通过结构化字段设置能力、端口、并发、截图、TLS 和 POC。不接受任意插件命令行。成功后返回 template_id、capability_summary 和 verification_token，可直接传给 asm_create_task。当 enabled_capabilities 留空时完整继承基模板。",
		InputSchema: resourceSchema(map[string]interface{}{
			"name":             map[string]interface{}{"type": "string", "minLength": 1, "maxLength": 150, "description": "新模板的唯一名称"},
			"base_template_id": map[string]interface{}{"type": "string", "description": "由 templates 返回的基模板 ID；留空克隆 default"},
			"options": map[string]interface{}{
				"type": "object", "additionalProperties": false,
				"properties": map[string]interface{}{
					"enabled_capabilities": map[string]interface{}{
						"type": "array", "description": "仅保留指定能力；省略时完整继承基模板",
						"items": map[string]interface{}{"type": "string", "enum": []string{
							"subdomain_discovery", "subdomain_takeover", "port_scan", "service_fingerprint", "site_identify",
							"site_capture", "tls_probe", "url_scan", "web_crawler", "sensitive_scan", "directory_scan",
							"vulnerability_scan", "passive_scan", "asset_handle",
						}}, "uniqueItems": true,
					},
					"ports":        map[string]interface{}{"type": "string", "description": "端口表达式，例如 1-65535 或 80,443,8080-8090"},
					"concurrency":  map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 200},
					"site_capture": map[string]interface{}{"type": "boolean"},
					"tls_probe":    map[string]interface{}{"type": "boolean"},
					"poc_ids":      map[string]interface{}{"type": "array", "maxItems": 500, "items": map[string]interface{}{"type": "string", "maxLength": 200}},
				},
			},
		}, "name"),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		options, _ := args["options"].(map[string]interface{})
		return service.CreateTemplate(ctx, asmStringArg(args, "resource_id"), asm.TemplateRequest{
			Name: asmStringArg(args, "name"), BaseTemplateID: asmStringArg(args, "base_template_id"), Options: options,
		})
	})

	optionProperties := map[string]interface{}{}
	for _, name := range []string{"domain_brute", "port_scan", "service_detection", "service_brute", "os_detection", "site_identify", "site_capture", "file_leak", "search_engines", "site_spider", "arl_search", "alt_dns", "ssl_cert", "dns_query_plugin", "skip_scan_cdn_ip", "nuclei_scan", "findvhost", "web_info_hunter"} {
		optionProperties[name] = map[string]interface{}{"type": "boolean"}
	}
	for _, name := range []string{
		"subdomain_discovery", "subdomain_bruteforce", "subdomain_permutation", "subdomain_resolve", "port_scan_passive",
		"directory_scan", "url_fetch", "dalfox_scan", "all_nodes", "scheduled", "tls_probe",
	} {
		optionProperties[name] = map[string]interface{}{"type": "boolean"}
	}
	optionProperties["task_mode"] = map[string]interface{}{"type": "string", "enum": []string{"direct", "policy"}, "description": "ARL 任务模式"}
	optionProperties["policy_id"] = map[string]interface{}{"type": "string", "description": "ARL policy 模式策略 ID"}
	optionProperties["task_tag"] = map[string]interface{}{"type": "string", "enum": []string{"task", "risk_cruising"}}
	optionProperties["result_set_id"] = map[string]interface{}{"type": "string"}
	optionProperties["domain_brute_type"] = map[string]interface{}{"type": "string", "enum": []string{"test", "big"}}
	optionProperties["port_scan_type"] = map[string]interface{}{"type": "string", "enum": []string{"test", "top100", "top1000", "all"}}
	optionProperties["engine_ids"] = map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "integer"}, "maxItems": 20}
	for _, name := range []string{"subdomain_wordlist", "directory_wordlist", "nuclei_severity", "nuclei_tags", "template_id", "ignore", "duplicates", "target_source", "cycle_type", "source_search"} {
		optionProperties[name] = map[string]interface{}{"type": "string"}
	}
	optionProperties["duplicates"] = map[string]interface{}{"type": "string", "enum": []string{"None", "subdomain"}}
	optionProperties["target_source"] = map[string]interface{}{"type": "string", "enum": []string{"general", "project", "asset", "RootDomain", "subdomain"}}
	optionProperties["cycle_type"] = map[string]interface{}{"type": "string", "enum": []string{"daily", "ndays", "nhours", "weekly", "monthly"}}
	for _, name := range []string{"fingerprint_libraries", "screenshot_sources", "nuclei_template_repos", "node_names", "project_ids"} {
		optionProperties[name] = map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}
	}
	optionProperties["template_verification_token"] = map[string]interface{}{"type": "string", "description": "ScopeSentry template_detail 返回的 verification_token；使用 template_id 时必填"}
	optionProperties["required_port_scope"] = map[string]interface{}{"type": "string", "enum": []string{"all", "top1000", "top100", "custom"}, "description": "ScopeSentry 模板端口范围断言；用户要求全端口时必须传 all"}
	optionProperties["required_capabilities"] = map[string]interface{}{
		"type": "array", "description": "ScopeSentry 用户明确要求的能力；创建前会根据上游模板详情逐项校验",
		"items": map[string]interface{}{"type": "string", "enum": []string{
			"subdomain_discovery", "subdomain_takeover", "port_scan", "service_fingerprint", "site_identify",
			"site_capture", "tls_probe", "url_scan", "web_crawler", "sensitive_scan", "directory_scan",
			"vulnerability_scan", "passive_scan", "asset_handle",
		}},
	}
	optionProperties["ports"] = map[string]interface{}{"type": "string", "description": "适配器支持时使用的逗号分隔端口或端口范围"}
	for _, name := range []string{"top_ports", "directory_concurrency", "request_timeout", "crawl_depth", "hour", "minute", "day", "week"} {
		optionProperties[name] = map[string]interface{}{"type": "integer"}
	}
	optionProperties["hour"] = map[string]interface{}{"type": "integer", "minimum": 0, "maximum": 23}
	optionProperties["minute"] = map[string]interface{}{"type": "integer", "minimum": 0, "maximum": 59}
	optionProperties["day"] = map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 31}
	optionProperties["week"] = map[string]interface{}{"type": "integer", "minimum": 0, "maximum": 6}
	optionProperties["source_limit"] = map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 100000}
	optionProperties["source_filter"] = map[string]interface{}{"type": "object", "additionalProperties": map[string]interface{}{"type": "array"}}
	optionProperties["rate_limit"] = map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 1000}
	optionProperties["concurrency"] = map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 200}

	register(mcp.Tool{
		Name: builtin.ToolASMCreateTask, ShortDescription: "向 ASM 下发资产发现任务",
		Description: "向指定 ASM 创建资产发现任务。仅当用户明确授权目标并要求扫描时调用；先调用 asm_get_task_profile，再查询所需实时选项。XingRin 多目标会返回多个远程子任务，成功响应的 history_records、local_task_ids 和 remote_task_ids 是完整落库清单，local_task_id 仅保留为旧调用兼容字段。ScopeSentry 使用 template_id 时，必须先单独查询 template_detail 并传回 template_verification_token；用户要求全端口时传 required_port_scope=all，要求的功能逐项写入 required_capabilities。MCP 会在上游创建前校验，成功响应中的 effective_template 才是最终配置依据；不得仅根据任务名或模板名宣称“全功能”。",
		InputSchema: resourceSchema(map[string]interface{}{
			"name":    map[string]interface{}{"type": "string", "description": "任务名称"},
			"target":  map[string]interface{}{"type": "string", "description": "已获授权的域名、IP 或 CIDR；多个目标按 ASM 支持的空格/换行格式传递"},
			"options": map[string]interface{}{"type": "object", "properties": optionProperties, "additionalProperties": false},
		}, "target"),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		options, _ := args["options"].(map[string]interface{})
		return service.CreateTask(ctx, asmStringArg(args, "resource_id"), asm.TaskRequest{Name: asmStringArg(args, "name"), Target: asmStringArg(args, "target"), Options: options})
	})

	register(mcp.Tool{
		Name: builtin.ToolASMListTasks, ShortDescription: "分页查询 ASM 任务",
		Description: "分页查询指定 ASM 上的扫描任务，可按任务 ID、名称、目标和状态筛选。",
		InputSchema: resourceSchema(map[string]interface{}{
			"task_id": map[string]interface{}{"type": "string"}, "name": map[string]interface{}{"type": "string"},
			"target": map[string]interface{}{"type": "string"}, "status": map[string]interface{}{"type": "string"},
			"page": map[string]interface{}{"type": "integer", "minimum": 1}, "page_size": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 100},
		}),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return service.ListTasks(ctx, asmStringArg(args, "resource_id"), asm.TaskFilter{
			TaskID: asmStringArg(args, "task_id"), Name: asmStringArg(args, "name"), Target: asmStringArg(args, "target"), Status: asmStringArg(args, "status"),
			Page: asmIntArg(args, "page"), PageSize: asmIntArg(args, "page_size"),
		})
	})

	register(mcp.Tool{
		Name: builtin.ToolASMGetTask, ShortDescription: "读取 ASM 任务详情",
		Description: "按 provider 的任务 ID 读取扫描状态、统计与任务选项。",
		InputSchema: resourceSchema(map[string]interface{}{"task_id": map[string]interface{}{"type": "string"}}, "task_id"),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return service.GetTask(ctx, asmStringArg(args, "resource_id"), asmStringArg(args, "task_id"))
	})

	register(mcp.Tool{
		Name: builtin.ToolASMListAssets, ShortDescription: "分页读取 ASM 发现结果",
		Description: "按结果类型分页读取 CyberStrikeAI 本地数据库中的 ASM 发现结果。任务完成后会自动从上游全量同步；本地缺少所请类型时，首次调用会先同步该类型。必须传 task_id；先调用 asm_get_task_profile 读取 provider-specific result_types。",
		InputSchema: resourceSchema(map[string]interface{}{
			"task_id":    map[string]interface{}{"type": "string"},
			"asset_type": map[string]interface{}{"type": "string", "enum": []string{"site", "domain", "ip", "cert", "service", "fileleak", "url", "vulnerability", "npoc_service", "cip", "nuclei_result", "stat_finger", "wih", "directory", "screenshot", "crawler", "sensitive", "takeover"}, "description": "必须使用 asm_get_task_profile.result_types 中当前平台支持的 ID"},
			"query":      map[string]interface{}{"type": "string"},
			"page":       map[string]interface{}{"type": "integer", "minimum": 1}, "page_size": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 100},
		}, "task_id"),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return service.ListAssets(ctx, asmStringArg(args, "resource_id"), asm.AssetFilter{
			TaskID: asmStringArg(args, "task_id"), Type: asmStringArg(args, "asset_type"), Query: asmStringArg(args, "query"),
			Page: asmIntArg(args, "page"), PageSize: asmIntArg(args, "page_size"),
		})
	})

	register(mcp.Tool{
		Name: builtin.ToolASMStopTask, ShortDescription: "停止 ASM 扫描任务",
		Description: "停止指定 ASM 扫描任务。该操作会改变远端任务状态，仅在用户明确要求停止时调用。",
		InputSchema: resourceSchema(map[string]interface{}{"task_id": map[string]interface{}{"type": "string"}}, "task_id"),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return service.StopTask(ctx, asmStringArg(args, "resource_id"), asmStringArg(args, "task_id"))
	})

	register(mcp.Tool{
		Name: builtin.ToolASMManageTask, ShortDescription: "执行 ASM 扩展任务动作",
		Description: "执行平台支持的重跑、恢复、删除或结果同步动作。sync_results 会从上游全量拉取所有支持的结果类型并替换 CyberStrikeAI 本地快照；其他动作会改变远端任务状态。",
		InputSchema: resourceSchema(map[string]interface{}{
			"action":  map[string]interface{}{"type": "string", "enum": []string{"restart", "resume", "delete", "sync_results"}},
			"task_id": map[string]interface{}{"type": "string"},
			"options": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"delete_results": map[string]interface{}{"type": "boolean"},
					"scope_id":       map[string]interface{}{"type": "string"},
				},
				"additionalProperties": false,
			},
		}, "action", "task_id"),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		options, _ := args["options"].(map[string]interface{})
		return service.ManageTask(ctx, asmStringArg(args, "resource_id"), asm.TaskManageRequest{
			Action: asmStringArg(args, "action"), TaskID: asmStringArg(args, "task_id"), Options: options,
		})
	})
}

func asmStringArg(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	value, exists := args[key]
	if !exists || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func asmIntArg(args map[string]interface{}, key string) int {
	value, exists := args[key]
	if !exists {
		return 0
	}
	switch number := value.(type) {
	case int:
		return number
	case int64:
		return int(number)
	case float64:
		return int(number)
	default:
		var parsed int
		_, _ = fmt.Sscanf(fmt.Sprint(value), "%d", &parsed)
		return parsed
	}
}
