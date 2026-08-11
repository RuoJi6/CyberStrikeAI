/**
 * 内置工具名称常量
 * 所有前端代码中使用内置工具名称的地方都应该使用这些常量，而不是硬编码字符串
 * 
 * 注意：这些常量必须与后端的 internal/mcp/builtin/constants.go 中的常量保持一致
 */

// 内置工具名称常量
const BuiltinTools = {
    // 漏洞管理工具
    RECORD_VULNERABILITY: 'record_vulnerability',

    // ASM 统一适配工具（ARL / XingRin / ScopeSentry）
    ASM_LIST_RESOURCES: 'asm_list_resources',
    ASM_TEST_CONNECTION: 'asm_test_connection',
    ASM_CREATE_TASK: 'asm_create_task',
    ASM_LIST_TASKS: 'asm_list_tasks',
    ASM_GET_TASK: 'asm_get_task',
    ASM_LIST_ASSETS: 'asm_list_assets',
    ASM_STOP_TASK: 'asm_stop_task',
    
    // 知识库工具
    LIST_KNOWLEDGE_RISK_TYPES: 'list_knowledge_risk_types',
    SEARCH_KNOWLEDGE_BASE: 'search_knowledge_base'
};

// 内置 MCP 工具组，用于在管理页明确展示工具来源。
const BuiltinMCPGroups = {
    ASM: {
        id: 'asm',
        label: 'ASM MCP',
        tools: [
            BuiltinTools.ASM_LIST_RESOURCES,
            BuiltinTools.ASM_TEST_CONNECTION,
            BuiltinTools.ASM_CREATE_TASK,
            BuiltinTools.ASM_LIST_TASKS,
            BuiltinTools.ASM_GET_TASK,
            BuiltinTools.ASM_LIST_ASSETS,
            BuiltinTools.ASM_STOP_TASK
        ]
    }
};

// 检查是否是内置工具
function isBuiltinTool(toolName) {
    return Object.values(BuiltinTools).includes(toolName);
}

// 获取所有内置工具名称列表
function getAllBuiltinTools() {
    return Object.values(BuiltinTools);
}

// 获取工具所属的内置 MCP 工具组。
function getBuiltinMCPGroup(toolName) {
    return Object.values(BuiltinMCPGroups).find(group => group.tools.includes(toolName)) || null;
}
