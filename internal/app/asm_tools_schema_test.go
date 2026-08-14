package app

import (
	"reflect"
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
