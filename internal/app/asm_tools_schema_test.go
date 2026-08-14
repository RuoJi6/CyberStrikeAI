package app

import (
	"reflect"
	"strings"
	"testing"

	"cyberstrike-ai/internal/asm"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

func TestASMCreateTemplateMCPExposesBuiltInPresets(t *testing.T) {
	server := mcp.NewServer(zap.NewNop())
	registerASMTools(server, &asm.Service{}, zap.NewNop())
	var schema map[string]interface{}
	for _, tool := range server.GetAllTools() {
		if tool.Name == builtin.ToolASMCreateTemplate {
			schema = tool.InputSchema
			break
		}
	}
	if schema == nil {
		t.Fatal("asm_create_template is not registered")
	}
	properties, _ := schema["properties"].(map[string]interface{})
	preset, _ := properties["preset_id"].(map[string]interface{})
	if !reflect.DeepEqual(preset["enum"], []string{"quick_discovery", "information_collection", "vulnerability_assessment", "full_scan"}) {
		t.Fatalf("unexpected preset enum: %#v", preset["enum"])
	}
	required, _ := schema["required"].([]string)
	if !reflect.DeepEqual(required, []string{"resource_id"}) {
		t.Fatalf("preset mode should only require resource_id: %#v", required)
	}
}

func TestASMCreateTaskMCPExposesARLDirectAndPolicyModes(t *testing.T) {
	server := mcp.NewServer(zap.NewNop())
	registerASMTools(server, &asm.Service{}, zap.NewNop())
	var schema map[string]interface{}
	for _, tool := range server.GetAllTools() {
		if tool.Name == builtin.ToolASMCreateTask {
			schema = tool.InputSchema
			break
		}
	}
	if schema == nil {
		t.Fatal("asm_create_task is not registered")
	}
	properties, _ := schema["properties"].(map[string]interface{})
	if _, exists := properties["completion_behavior"]; exists {
		t.Fatal("Agent continuation is a user-managed ASM setting, not a task argument")
	}
	options, _ := properties["options"].(map[string]interface{})
	optionProperties, _ := options["properties"].(map[string]interface{})
	taskMode, _ := optionProperties["task_mode"].(map[string]interface{})
	if !reflect.DeepEqual(taskMode["enum"], []string{"direct", "policy"}) {
		t.Fatalf("unexpected ARL task modes: %#v", taskMode["enum"])
	}
	policyID, _ := optionProperties["policy_id"].(map[string]interface{})
	if policyID["type"] != "string" {
		t.Fatalf("ARL policy mode must expose policy_id: %#v", policyID)
	}
}

func TestASMCreateTaskMCPExplainsSystemManagedContinuation(t *testing.T) {
	server := mcp.NewServer(zap.NewNop())
	registerASMTools(server, &asm.Service{}, zap.NewNop())
	for _, tool := range server.GetAllTools() {
		if tool.Name != builtin.ToolASMCreateTask {
			continue
		}
		for _, expected := range []string{"资源联动设置", "后台等待", "禁止 sleep", "循环轮询"} {
			if !strings.Contains(tool.ShortDescription, expected) {
				t.Fatalf("asm_create_task short description does not contain %q: %s", expected, tool.ShortDescription)
			}
		}
		for _, expected := range []string{"Agent 联动", "用户主动停止来源对话", "不得重新启动 Agent", "不要调用 sleep", "不要为了等待完成而循环轮询", "agent_continuation"} {
			if !strings.Contains(tool.Description, expected) {
				t.Fatalf("asm_create_task description does not contain %q: %s", expected, tool.Description)
			}
		}
		return
	}
	t.Fatal("asm_create_task is not registered")
}

func TestASMResourceAndManageToolsExplainContinuation(t *testing.T) {
	server := mcp.NewServer(zap.NewNop())
	registerASMTools(server, &asm.Service{}, zap.NewNop())
	seen := map[string]bool{}
	for _, tool := range server.GetAllTools() {
		switch tool.Name {
		case builtin.ToolASMListResources:
			seen[tool.Name] = true
			if !strings.Contains(tool.ShortDescription, "Agent 联动设置") {
				t.Fatalf("asm_list_resources short description omits continuation settings: %s", tool.ShortDescription)
			}
		case builtin.ToolASMManageTask:
			seen[tool.Name] = true
			for _, expected := range []string{"重跑/恢复", "后台等待", "禁止 sleep", "循环轮询"} {
				if !strings.Contains(tool.ShortDescription, expected) {
					t.Fatalf("asm_manage_task short description does not contain %q: %s", expected, tool.ShortDescription)
				}
			}
			for _, expected := range []string{"restart/resume", "当前 MCP 对话", "Agent 联动设置"} {
				if !strings.Contains(tool.Description, expected) {
					t.Fatalf("asm_manage_task description does not contain %q: %s", expected, tool.Description)
				}
			}
		}
	}
	for _, name := range []string{builtin.ToolASMListResources, builtin.ToolASMManageTask} {
		if !seen[name] {
			t.Fatalf("%s is not registered", name)
		}
	}
}
