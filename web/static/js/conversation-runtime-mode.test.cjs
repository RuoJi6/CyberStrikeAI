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
    assert.match(template, /id="workspace-persistence-toggle"/);
    assert.match(template, /id="workspace-persistence-hint"/);
    assert.match(styles, /\.workspace-persistence-toggle input:checked \+ \.workspace-persistence-switch/);
});

test('仅首条消息携带创建时执行位置', () => {
    assert.match(chat, /const creatingNewConversation = !requestConversationId;[\s\S]{0,520}body\.runtimeMode = normalizeConversationRuntimeModeForUI/);
    assert.match(chat, /body\.workspacePersistent = body\.runtimeMode === CHAT_RUNTIME_MODE_CONTAINER/);
    assert.match(chat, /workspacePersistenceEnabledFromConversation\(conversation\)/);
    assert.match(chat, /applyConversationRuntimeMode\(conversationId, conversation\)/);
    assert.match(chat, /button\.disabled = !!locked/);
    assert.match(chat, /syncRuntimeModeFromValue\(CHAT_RUNTIME_MODE_HOST\);[\s\S]{0,320}resetNewConversationContainerControls[\s\S]{0,160}setChatRuntimeModeLocked\(false\)/);
});

test('容器执行选择先通过服务端灰度授权并在异常时失败关闭', () => {
    assert.match(chat, /apiFetch\(`\/api\/container-runtime-rollout\$\{query\}`\)/);
    assert.match(chat, /rollout\.allowed !== true[\s\S]{0,500}syncRuntimeModeFromValue\(CHAT_RUNTIME_MODE_HOST\)/);
    assert.match(chat, /containerRuntimeRolloutUnavailable/);
    assert.match(chat, /option\.disabled = true/);
    for (const locale of [zh, en]) {
        assert.equal(typeof locale.chat.containerRuntimeDisabled, 'string');
        assert.equal(typeof locale.chat.containerRuntimeRolloutDenied, 'string');
        assert.equal(typeof locale.chat.containerRuntimeRolloutUnavailable, 'string');
    }
});

test('中英文文案明确区分执行位置与 Agent 编排', () => {
    for (const locale of [zh, en]) {
        assert.equal(typeof locale.chat.runtimeModeHost, 'string');
        assert.equal(typeof locale.chat.runtimeModeContainer, 'string');
        assert.equal(typeof locale.chat.runtimeModeLockedHint, 'string');
        assert.equal(typeof locale.chat.workspacePersistenceLabel, 'string');
        assert.equal(typeof locale.chat.workspacePersistenceHintEphemeral, 'string');
        assert.equal(typeof locale.chat.workspacePersistenceHintPersistent, 'string');
        assert.equal(typeof locale.chat.agentModePanelTitle, 'string');
    }
    assert.notEqual(zh.chat.runtimeModePanelTitle, zh.chat.agentModePanelTitle);
    assert.notEqual(en.chat.runtimeModePanelTitle, en.chat.agentModePanelTitle);
    assert.equal(zh.chat.runtimeModeContainer, '容器执行');
    assert.match(zh.chat.runtimeModeContainerHint, /每对话隔离容器/);
    assert.match(zh.chat.runtimeModeContainerHint, /失败关闭/);
    assert.doesNotMatch(zh.chat.runtimeModeContainer + zh.chat.runtimeModeContainerHint, /待接入|后端未接入/);
    assert.doesNotMatch(en.chat.runtimeModeContainer + en.chat.runtimeModeContainerHint, /pending|not wired/i);
    assert.match(zh.chat.workspacePersistenceHintEphemeral, /删除容器会永久删除/);
    assert.match(zh.chat.workspacePersistenceHintPersistent, /每对话|该对话专属/);
    assert.match(en.chat.workspacePersistenceHintEphemeral, /deleting the container permanently deletes/i);
    assert.match(en.chat.workspacePersistenceHintPersistent, /dedicated Docker named volume/i);
});
