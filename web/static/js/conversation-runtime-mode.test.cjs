const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');

const chat = fs.readFileSync('web/static/js/chat.js', 'utf8');
const template = fs.readFileSync('web/templates/index.html', 'utf8');
const styles = fs.readFileSync('web/static/css/style.css', 'utf8');
const zh = JSON.parse(fs.readFileSync('web/static/i18n/zh-CN.json', 'utf8'));
const en = JSON.parse(fs.readFileSync('web/static/i18n/en-US.json', 'utf8'));

test('新对话使用自定义 host/container 选择器', () => {
    assert.match(template, /id="runtime-mode-wrapper"/);
    assert.match(template, /class="role-selection-item-main runtime-mode-option selected" data-value="host"/);
    assert.match(template, /class="role-selection-item-main runtime-mode-option" data-value="container"/);
    assert.doesNotMatch(template, /<select[^>]+id="runtime-mode-select"/);
    assert.match(styles, /\.runtime-mode-option\.selected \.runtime-mode-check/);
});

test('仅首条消息携带创建时执行位置', () => {
    assert.match(chat, /const creatingNewConversation = !requestConversationId;[\s\S]{0,520}body\.runtimeMode = normalizeConversationRuntimeModeForUI/);
    assert.match(chat, /applyConversationRuntimeMode\(conversationId, conversation\)/);
    assert.match(chat, /button\.disabled = !!locked/);
    assert.match(chat, /syncRuntimeModeFromValue\(CHAT_RUNTIME_MODE_HOST\);[\s\S]{0,100}setChatRuntimeModeLocked\(false\)/);
});

test('中英文文案明确区分执行位置与 Agent 编排', () => {
    for (const locale of [zh, en]) {
        assert.equal(typeof locale.chat.runtimeModeHost, 'string');
        assert.equal(typeof locale.chat.runtimeModeContainer, 'string');
        assert.equal(typeof locale.chat.runtimeModeLockedHint, 'string');
        assert.equal(typeof locale.chat.agentModePanelTitle, 'string');
    }
    assert.notEqual(zh.chat.runtimeModePanelTitle, zh.chat.agentModePanelTitle);
    assert.notEqual(en.chat.runtimeModePanelTitle, en.chat.agentModePanelTitle);
});
