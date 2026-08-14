package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/asm"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

// TestASMRealMCPFlow is an opt-in live integration test. It intentionally uses
// the same MCP registrations, authorization policy, resource database and
// encrypted credentials as the application. The test is skipped unless all
// required CYBERSTRIKE_ASM_REAL_* variables are set.
func TestASMRealMCPFlow(t *testing.T) {
	if os.Getenv("CYBERSTRIKE_ASM_REAL_TEST") != "1" {
		t.Skip("set CYBERSTRIKE_ASM_REAL_TEST=1 to run live ASM MCP integration")
	}
	databasePath := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_DB"))
	resourceID := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_RESOURCE_ID"))
	if databasePath == "" || resourceID == "" {
		t.Fatal("CYBERSTRIKE_ASM_REAL_DB and CYBERSTRIKE_ASM_REAL_RESOURCE_ID are required")
	}
	db, err := database.NewDB(databasePath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service, err := asm.NewService(db, databasePath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerASMTools(server, service, zap.NewNop())
	principal := authctx.NewPrincipal("asm-live-integration", "asm-live-integration", database.RBACScopeAll, map[string]bool{"mcp:external:execute": true})
	ctx := authctx.WithPrincipal(context.Background(), principal)

	call := func(tool string, arguments map[string]interface{}) map[string]interface{} {
		t.Helper()
		result, executionID, callErr := server.CallTool(ctx, tool, arguments)
		if callErr != nil {
			t.Fatalf("%s execution=%s: %v", tool, executionID, callErr)
		}
		plain := mcp.ToolResultPlainText(result)
		t.Logf("MCP %s execution=%s\n%s", tool, executionID, plain)
		if result != nil && result.IsError {
			t.Fatalf("%s returned error result", tool)
		}
		if strings.HasPrefix(strings.TrimSpace(plain), "<persisted-output>") {
			return map[string]interface{}{"persisted": true}
		}
		var decoded interface{}
		if err := json.Unmarshal([]byte(plain), &decoded); err != nil {
			t.Fatalf("%s returned non-JSON content: %v", tool, err)
		}
		object, ok := decoded.(map[string]interface{})
		if !ok {
			return map[string]interface{}{"value": decoded}
		}
		return object
	}

	call(builtin.ToolASMListResources, map[string]interface{}{})
	call(builtin.ToolASMTestConnection, map[string]interface{}{"resource_id": resourceID})
	profile := call(builtin.ToolASMGetTaskProfile, map[string]interface{}{"resource_id": resourceID})
	optionPage := 1
	optionPageSize := 10
	if value, parseErr := strconv.Atoi(strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_OPTION_PAGE"))); parseErr == nil && value > 0 {
		optionPage = value
	}
	if value, parseErr := strconv.Atoi(strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_OPTION_PAGE_SIZE"))); parseErr == nil && value > 0 {
		optionPageSize = value
	}
	for _, kind := range asmRealOptionKinds(profile) {
		arguments := map[string]interface{}{
			"resource_id": resourceID, "kind": kind, "page": optionPage, "page_size": optionPageSize,
		}
		if value := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_OPTION_ID")); value != "" {
			arguments["id"] = value
		}
		if value := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_OPTION_QUERY")); value != "" {
			arguments["query"] = value
		}
		call(builtin.ToolASMListTaskOptions, arguments)
	}
	if listName := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_LIST_NAME")); listName != "" {
		listed := call(builtin.ToolASMListTasks, map[string]interface{}{
			"resource_id": resourceID, "name": listName, "page": 1, "page_size": 20,
		})
		if absentID := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_EXPECT_ABSENT_TASK_ID")); absentID != "" {
			raw, _ := json.Marshal(listed)
			if strings.Contains(string(raw), absentID) {
				t.Fatalf("deleted task %s is still present in the remote task list", absentID)
			}
		}
	}
	var createdTemplate map[string]interface{}
	if presetID := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_TEMPLATE_PRESET_ID")); presetID != "" {
		createdTemplate = call(builtin.ToolASMCreateTemplate, map[string]interface{}{
			"resource_id": resourceID,
			"preset_id":   presetID,
		})
	} else if templateName := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_TEMPLATE_NAME")); templateName != "" {
		templateOptions := map[string]interface{}{}
		if raw := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_TEMPLATE_OPTIONS")); raw != "" {
			if err := json.Unmarshal([]byte(raw), &templateOptions); err != nil {
				t.Fatalf("invalid CYBERSTRIKE_ASM_REAL_TEMPLATE_OPTIONS: %v", err)
			}
		}
		createdTemplate = call(builtin.ToolASMCreateTemplate, map[string]interface{}{
			"resource_id": resourceID,
			"name":        templateName,
			"base_template_id": strings.TrimSpace(
				os.Getenv("CYBERSTRIKE_ASM_REAL_BASE_TEMPLATE_ID"),
			),
			"options": templateOptions,
		})
	}

	target := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_TARGET"))
	remoteTaskID := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_EXISTING_TASK_ID"))
	if target == "" && remoteTaskID == "" {
		return
	}
	name := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_NAME"))
	if target != "" {
		options := map[string]interface{}{}
		if raw := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_OPTIONS")); raw != "" {
			if err := json.Unmarshal([]byte(raw), &options); err != nil {
				t.Fatalf("invalid CYBERSTRIKE_ASM_REAL_OPTIONS: %v", err)
			}
		}
		if createdTemplate != nil {
			options["template_id"] = createdTemplate["template_id"]
			options["template_verification_token"] = createdTemplate["verification_token"]
			if summary, ok := createdTemplate["capability_summary"].(map[string]interface{}); ok {
				options["required_port_scope"] = summary["port_scope"]
				options["required_capabilities"] = summary["enabled_capabilities"]
			}
		}
		if name == "" {
			name = "CyberStrikeAI MCP live " + time.Now().Format("20060102-150405")
		}
		created := call(builtin.ToolASMCreateTask, map[string]interface{}{
			"resource_id": resourceID, "name": name, "target": target, "options": options,
		})
		call(builtin.ToolASMListTasks, map[string]interface{}{
			"resource_id": resourceID, "name": name, "target": target, "page": 1, "page_size": 10,
		})
		remoteTaskID = asmRealRemoteTaskID(created)
		if remoteTaskID == "" {
			if tasks, _, lookupErr := db.ListASMTasks(database.ASMTaskFilter{ResourceID: resourceID, Query: name, Page: 1, PageSize: 1}); lookupErr == nil && len(tasks) > 0 {
				remoteTaskID = strings.TrimSpace(tasks[0].RemoteTaskID)
			}
		}
	}
	if remoteTaskID == "" {
		t.Fatal("created task response did not contain a remote task id")
	}
	t.Logf("remote task id: %s", remoteTaskID)
	time.Sleep(time.Second)
	call(builtin.ToolASMGetTask, map[string]interface{}{"resource_id": resourceID, "task_id": remoteTaskID})
	if os.Getenv("CYBERSTRIKE_ASM_REAL_SKIP_ASSETS") != "1" {
		for _, assetType := range []string{"site", "ip"} {
			arguments := map[string]interface{}{
				"resource_id": resourceID, "task_id": remoteTaskID, "asset_type": assetType,
				"page": 1, "page_size": 10,
			}
			if target != "" {
				arguments["query"] = target
			}
			call(builtin.ToolASMListAssets, arguments)
		}
	}
	manageAction := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_MANAGE_ACTION"))
	if manageAction != "" {
		manageOptions := map[string]interface{}{}
		if raw := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_MANAGE_OPTIONS")); raw != "" {
			if err := json.Unmarshal([]byte(raw), &manageOptions); err != nil {
				t.Fatalf("invalid CYBERSTRIKE_ASM_REAL_MANAGE_OPTIONS: %v", err)
			}
		}
		call(builtin.ToolASMManageTask, map[string]interface{}{
			"resource_id": resourceID, "task_id": remoteTaskID, "action": manageAction, "options": manageOptions,
		})
	}
	if os.Getenv("CYBERSTRIKE_ASM_REAL_STOP") == "1" || manageAction == "restart" || manageAction == "resume" {
		if manageAction != "" {
			time.Sleep(time.Second)
		}
		call(builtin.ToolASMStopTask, map[string]interface{}{"resource_id": resourceID, "task_id": remoteTaskID})
	}
}

func asmRealOptionKinds(profile map[string]interface{}) []string {
	if configured := strings.TrimSpace(os.Getenv("CYBERSTRIKE_ASM_REAL_OPTION_KINDS")); configured != "" {
		parts := strings.Split(configured, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			if part = strings.TrimSpace(part); part != "" {
				result = append(result, part)
			}
		}
		return result
	}
	items, _ := profile["dynamic_option_kinds"].([]interface{})
	result := make([]string, 0, len(items))
	for _, item := range items {
		if value := strings.TrimSpace(fmt.Sprint(item)); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func asmRealRemoteTaskID(created map[string]interface{}) string {
	provider := strings.TrimSpace(fmt.Sprint(created["provider"]))
	if task, ok := created["task"].(map[string]interface{}); ok {
		if value := asmRealIDString(task["id"]); value != "" {
			return value
		}
	}
	response, _ := created["response"].(map[string]interface{})
	if provider == asm.ProviderXingRin {
		if scans, ok := response["scans"].([]interface{}); ok && len(scans) > 0 {
			if scan, ok := scans[0].(map[string]interface{}); ok {
				return asmRealIDString(scan["id"])
			}
		}
	}
	if provider == asm.ProviderARL {
		if data, ok := response["data"].(map[string]interface{}); ok {
			for _, key := range []string{"_id", "id", "task_id"} {
				if value := asmRealIDString(data[key]); value != "" {
					return value
				}
			}
		}
		if items, ok := response["items"].([]interface{}); ok && len(items) > 0 {
			if item, ok := items[0].(map[string]interface{}); ok {
				for _, key := range []string{"_id", "id", "task_id"} {
					if value := asmRealIDString(item[key]); value != "" {
						return value
					}
				}
			}
		}
		for _, key := range []string{"_id", "id", "task_id"} {
			if value := asmRealIDString(response[key]); value != "" {
				return value
			}
		}
	}
	return ""
}

func asmRealIDString(value interface{}) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case float64:
		if typed > 0 && typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
	case json.Number:
		return typed.String()
	case string:
		return strings.TrimSpace(typed)
	}
	return ""
}
