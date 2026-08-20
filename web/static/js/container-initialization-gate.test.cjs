const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '..', '..', '..');
const monitor = fs.readFileSync(path.join(root, 'web/static/js/monitor.js'), 'utf8');
const chat = fs.readFileSync(path.join(root, 'web/static/js/chat.js'), 'utf8');
const zh = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/zh-CN.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/en-US.json'), 'utf8'));

test('容器初始化保持运行态、实时计时并在就绪后续跑', () => {
    assert.match(monitor, /case 'container_initialization':/);
    assert.match(monitor, /initializationIsActive = initializationState === 'initializing' \|\| initializationState === 'ready'/);
    assert.match(monitor, /progressNode\.dataset\.containerInitializationState = initializationState/);
    assert.match(monitor, /startProgressElapsedClock\(progressId\)/);
    assert.match(monitor, /if \(!initializationIsActive\) \{[\s\S]*upsertTerminalAssistantMessage\(event\.message, preferredMessageId\)/);
    assert.match(monitor, /t\.status === 'running' \|\| t\.status === 'initializing' \|\| t\.status === 'cancelling'/);
    assert.match(monitor, /window\.getConversationExecutionStatus/);
    assert.match(chat, /turnPhase === 'container_initializing'/);
    assert.match(chat, /conversationTaskStatus === 'initializing'/);
    assert.match(chat, /containerStartingElapsed/);
    assert.match(monitor, /setChatRuntimeModeLocked\(true\)/);
    assert.match(monitor, /loadConversationsWithGroups\(\)/);
    assert.match(monitor, /containerExecutionBlockedTitle/);
});

test('容器初始化与失败关闭状态具备中英文文案', () => {
    for (const key of ['containerInitializingTitle', 'containerStartingElapsed', 'containerReadyContinuingTitle', 'containerInitializationFailedTitle', 'containerExecutionBlockedTitle']) {
        assert.equal(typeof zh.chat[key], 'string');
        assert.equal(typeof en.chat[key], 'string');
        assert.ok(zh.chat[key].length > 0);
        assert.ok(en.chat[key].length > 0);
    }
    assert.match(zh.chat.runtimeModeContainerHint, /绝不回退宿主机/);
    assert.match(en.chat.runtimeModeContainerHint, /never fall back to the host/i);
    assert.equal(typeof zh.tasks.statusInitializing, 'string');
    assert.equal(typeof en.tasks.statusInitializing, 'string');
});
