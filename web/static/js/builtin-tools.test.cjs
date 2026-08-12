const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

const source = fs.readFileSync('web/static/js/builtin-tools.js', 'utf8');

function loadBuiltinTools() {
    const context = {};
    vm.runInNewContext(`${source}\nthis.api = { BuiltinTools, getAllBuiltinTools, getBuiltinMCPGroup };`, context);
    return context.api;
}

test('ASM 的 10 个内置工具都标记为 ASM MCP', () => {
    const api = loadBuiltinTools();
    const asmTools = [
        api.BuiltinTools.ASM_LIST_RESOURCES,
        api.BuiltinTools.ASM_TEST_CONNECTION,
        api.BuiltinTools.ASM_GET_TASK_PROFILE,
        api.BuiltinTools.ASM_LIST_TASK_OPTIONS,
        api.BuiltinTools.ASM_CREATE_TASK,
        api.BuiltinTools.ASM_LIST_TASKS,
        api.BuiltinTools.ASM_GET_TASK,
        api.BuiltinTools.ASM_LIST_ASSETS,
        api.BuiltinTools.ASM_STOP_TASK,
        api.BuiltinTools.ASM_MANAGE_TASK
    ];

    assert.equal(new Set(asmTools).size, 10);
    asmTools.forEach(toolName => {
        assert.equal(api.getBuiltinMCPGroup(toolName)?.label, 'ASM MCP');
        assert.equal(api.getAllBuiltinTools().includes(toolName), true);
    });
});

test('普通内置工具不会被误标为 ASM MCP', () => {
    const api = loadBuiltinTools();
    assert.equal(api.getBuiltinMCPGroup(api.BuiltinTools.RECORD_VULNERABILITY), null);
});
