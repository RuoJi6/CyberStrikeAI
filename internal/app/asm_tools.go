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

	optionProperties := map[string]interface{}{}
	for _, name := range []string{"domain_brute", "port_scan", "service_detection", "service_brute", "os_detection", "site_identify", "site_capture", "file_leak", "search_engines", "site_spider", "arl_search", "alt_dns", "ssl_cert", "dns_query_plugin", "skip_scan_cdn_ip", "nuclei_scan", "findvhost", "web_info_hunter"} {
		optionProperties[name] = map[string]interface{}{"type": "boolean"}
	}
	optionProperties["domain_brute_type"] = map[string]interface{}{"type": "string"}
	optionProperties["port_scan_type"] = map[string]interface{}{"type": "string"}
	optionProperties["ports"] = map[string]interface{}{"type": "string", "description": "适配器支持时使用的逗号分隔端口或端口范围"}
	optionProperties["rate_limit"] = map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 1000}
	optionProperties["concurrency"] = map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 200}

	register(mcp.Tool{
		Name: builtin.ToolASMCreateTask, ShortDescription: "向 ASM 下发资产发现任务",
		Description: "向指定 ASM 创建资产发现任务。仅当用户明确授权目标并要求扫描时调用；先用 asm_list_resources 选择资源。options 由不同 ASM 适配器映射，未提供时使用低负载默认值。",
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
		Description: "分页读取 ASM 的资产发现结果。ARL、XingRin 与 ScopeSentry 支持 site、domain、ip、url、service、vulnerability；可用 task_id 限定某次扫描。",
		InputSchema: resourceSchema(map[string]interface{}{
			"task_id":    map[string]interface{}{"type": "string"},
			"asset_type": map[string]interface{}{"type": "string", "enum": []string{"site", "domain", "ip", "url", "service", "vulnerability"}},
			"query":      map[string]interface{}{"type": "string"},
			"page":       map[string]interface{}{"type": "integer", "minimum": 1}, "page_size": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 100},
		}),
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
