const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');

const source = fs.readFileSync('web/static/js/asm.js', 'utf8');
const template = fs.readFileSync('web/templates/index.html', 'utf8');
const css = fs.readFileSync('web/static/css/asm.css', 'utf8');

test('ASM resource cards expose native template library only by capability', () => {
    assert.match(source, /item\.capabilities\.includes\('create_template'\)/);
    assert.match(source, /data-asm-action="templates"/);
    assert.match(source, /action === 'templates'\) openASMTemplateLibrary\(id\)/);
});

test('template library shares preset and upstream option endpoints', () => {
    assert.match(source, /task-options\?kind=template_presets/);
    assert.match(source, /resource\.provider === 'arl' \? 'policies' : 'templates'/);
    assert.match(source, /JSON\.stringify\(\{ preset_id: presetID \}\)/);
    assert.match(source, /createAllASMTemplatePresets/);
});

test('template decisions render provider-specific exact settings for UI and MCP', () => {
    assert.match(source, /preset\?\.provider_config/);
    assert.match(source, /resource\.provider === 'arl'/);
    assert.match(source, /查看配置/);
    assert.match(source, /asm-template-preset-detail-button/);
    assert.match(source, /asm-template-preset-create-button/);
    assert.match(source, /MCP 可读取的结构化配置/);
    assert.match(source, /provider_config: config, mcp_usage: preset\.mcp_usage/);
    assert.match(source, /policy_detail/);
    assert.match(source, /template_detail/);
    assert.match(template, /id="asm-template-preset-detail"/);
    assert.match(template, /id="asm-template-upstream-detail"/);
});

test('built-in template creation starts directly without risk confirmation popups', () => {
    assert.doesNotMatch(source, /preset\.warning\s*&&\s*!window\.confirm/);
    assert.doesNotMatch(source, /createAllASMTemplatePresets[\s\S]*createAllConfirm[\s\S]*window\.confirm/);
});

test('existing built-in templates remain actionable so drift can be reconciled', () => {
    assert.match(source, /allCreated \? asmT\('asm\.syncAllTemplates'/);
    assert.match(source, /exists \? asmEscape\(asmT\('asm\.syncTemplate'/);
    assert.match(source, /result\.updated \? asmT\('asm\.templateSynced'/);
    assert.doesNotMatch(source, /busy \|\| exists \? 'disabled'/);
});

test('template modal includes preset cards, upstream list and responsive layout', () => {
    assert.match(template, /id="asm-template-library-modal"/);
    assert.match(template, /id="asm-template-preset-grid"/);
    assert.match(template, /id="asm-template-upstream-list"/);
    assert.match(css, /\.asm-template-preset-grid[\s\S]*repeat\(4/);
    assert.match(css, /@media \(max-width: 720px\)[\s\S]*\.asm-template-preset-grid/);
});

test('ScopeSentry template builder separates enabled and upstream-available capabilities', () => {
    assert.match(source, /available_template_capabilities/);
    assert.match(source, /node\.checked = Boolean\(capabilities\[capability\]\)/);
    assert.match(source, /node\.disabled = !available/);
    assert.match(source, /启用的扫描能力/);
});

test('ARL task center exposes MCP-compatible direct and policy modes', () => {
    assert.match(source, /直接自定义扫描/);
    assert.match(source, /使用策略模板/);
    assert.match(source, /setASMCreateTaskMode/);
    assert.match(source, /mode === 'policy' && !result\.policy_id/);
    assert.match(source, /\['task_mode', 'policy_id', 'task_tag', 'result_set_id'\]/);
});

test('ASM task center exposes standalone durable Agent continuation settings', () => {
    assert.match(template, /onclick="openASMAgentContinuationModal\(\)"/);
    assert.match(template, /id="asm-agent-continuation-modal"/);
    assert.match(template, /id="asm-agent-continuation-resource"/);
    assert.match(template, /id="asm-agent-continuation-behavior"/);
    assert.match(template, /id="asm-agent-continuation-running-prompt"/);
    assert.match(template, /id="asm-agent-continuation-idle-prompt"/);
    assert.doesNotMatch(template, /id="asm-create-continuation"/);
    assert.match(source, /agent_continuation:/);
    assert.doesNotMatch(source, /completion_behavior: completionBehavior/);
    assert.doesNotMatch(source, /conversation_id: conversationId/);
    assert.match(css, /\.asm-continuation-config/);
    assert.match(css, /\.asm-agent-continuation-content/);
    assert.match(template, /用户主动停止对话/);
    assert.match(template, /不会自动重新启动 Agent/);
    assert.match(source, /renderASMTaskExecutionChip\(task\)/);
    assert.match(source, /renderASMTaskExecutionPanel\(task\)/);
    assert.match(css, /\.asm-task-profile-chip/);
    assert.match(css, /\.asm-task-execution-panel/);
    assert.match(template, /id="asm-continuation-summary"/);
    assert.match(template, /id="asm-continuation-list"/);
    assert.match(template, /id="asm-continuation-pagination"/);
    assert.match(source, /\/api\/asm\/agent-continuations/);
    assert.match(source, /user_stopped/);
    assert.match(source, /等待发起/);
    assert.match(source, /changeASMContinuationPageSize/);
    assert.match(source, /page_size: String\(asmPageState\.continuationPageSize\)/);
    assert.match(css, /\.asm-continuation-summary-card/);
    assert.match(css, /\.asm-continuation-item/);
    assert.match(css, /\.asm-continuation-pagination/);
});

test('ASM task center keeps task groups in newest-first creation order', () => {
    assert.match(source, /function asmTaskTimestamp\(task\)/);
    assert.match(source, /asmTaskTimestamp\(right\) - asmTaskTimestamp\(left\)/);
    assert.match(source, /right\.createdAt - left\.createdAt/);
    assert.match(source, /创建时间（最新优先）/);
});
