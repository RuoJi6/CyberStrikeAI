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
		Description: "按类别查询平台实时的策略、引擎、字典、端口字典、节点、模板、插件或 POC。kind 可传 all，按当前分页批量查询全部列表型类别；否则必须使用 asm_get_task_profile.dynamic_option_kinds 中的单个值。*_detail 需传 id 单独查询。",
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
		Description: "向指定 ASM 创建资产发现任务。仅当用户明确授权目标并要求扫描时调用；先调用 asm_get_task_profile，必要时通过 asm_list_task_options 获取引擎、字典、策略、模板和节点等实时选项。options 必须严格匹配所选平台 profile；未提供时使用安全的低负载默认值。",
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
