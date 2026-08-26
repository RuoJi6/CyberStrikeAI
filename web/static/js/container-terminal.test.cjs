const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '../../..');
const read = (...parts) => fs.readFileSync(path.join(root, ...parts), 'utf8');
const template = read('web', 'templates', 'index.html');
const terminal = read('web', 'static', 'js', 'terminal.js');
const containerTerminal = read('web', 'static', 'js', 'container-terminal.js');
const management = read('web', 'static', 'js', 'container-management.js');
const chat = read('web', 'static', 'js', 'chat.js');
const styles = read('web', 'static', 'css', 'style.css');
const zh = JSON.parse(read('web', 'static', 'i18n', 'zh-CN.json'));
const en = JSON.parse(read('web', 'static', 'i18n', 'en-US.json'));

test('对话执行栏提供工作区入口并在右侧抽屉承载共享终端', () => {
    assert.match(template, /id="runtime-mode-wrapper"[\s\S]*?id="chat-container-workspace-btn"/);
    assert.match(template, /id="chat-container-workspace-panel"/);
    assert.match(template, /id="chat-container-runtime-state"[\s\S]*?id="chat-container-runtime-state-label"[\s\S]*?chat\.containerWorkspaceShort/);
    assert.match(template, /id="chat-container-path"/);
    assert.match(template, /id="chat-container-host-path"/);
    assert.match(template, /id="chat-container-terminal-root"/);
    assert.match(chat, /syncChatContainerWorkspaceButton/);
    assert.match(containerTerminal, /toggleChatContainerWorkspacePanel/);
    assert.match(containerTerminal, /openChatContainerShell/);
    assert.match(template, /id="chat-container-workspace-panel" class="container-terminal-drawer chat-container-terminal-drawer"/);
    assert.match(template, /id="chat-container-terminal-root" class="container-terminal-root is-drawer"/);
    assert.match(styles, /\.container-terminal-drawer\s*\{[\s\S]*?position: fixed;[\s\S]*?right: 0;/);
    assert.match(styles, /\.container-terminal-root \.terminal-panes/);
});

test('新建容器对话无需刷新即可显示工作区入口和实时容器状态', () => {
    assert.match(containerTerminal, /const visible = mode === 'container'/);
    assert.match(containerTerminal, /button\.disabled = !actionable/);
    assert.match(containerTerminal, /renderChatContainerState\('idle'\)/);
    assert.match(containerTerminal, /window\.addEventListener\('conversation-changed', syncChatContainerWorkspaceButton\)/);
    assert.match(containerTerminal, /\/container-initialization/);
    assert.match(containerTerminal, /conversation-container-state-changed/);
    assert.match(containerTerminal, /containerStateStarting/);
    assert.match(containerTerminal, /containerStateRunning/);
    assert.match(styles, /\.chat-container-runtime-state\.is-starting/);
    assert.match(styles, /\.chat-container-runtime-state\.is-running/);
});

test('系统设置终端与容器终端复用同一 xterm 会话和多标签代码', () => {
    assert.match(terminal, /function createTerminalInContainer\(container, tab\)/);
    assert.match(terminal, /function createEmbeddedTerminal\(root, options\)/);
    assert.match(terminal, /createTerminalInContainer\(container, tab\)/);
    assert.match(terminal, /window\.CyberStrikeTerminal/);
    assert.match(containerTerminal, /CyberStrikeTerminal\.createEmbeddedTerminal/);
    assert.match(template, /terminal\.js\?v=20260824-1/);
    assert.match(template, /container-terminal\.js\?v=20260824-7/);
});

test('容器终端只连接会话容器端点且不会回退宿主机终端', () => {
    assert.match(containerTerminal, /\/api\/conversations\/\$\{encodeURIComponent\(conversationId\)\}\/container\/terminal\/ws/);
    assert.match(containerTerminal, /\/container\/workspace/);
    assert.doesNotMatch(containerTerminal, /\/api\/terminal\/ws/);
    assert.doesNotMatch(containerTerminal, /terminal\/run/);
    assert.match(containerTerminal, /info\.interactiveAvailable/);
    assert.match(containerTerminal, /button\.disabled = !available/);
});

test('对话容器详情使用右侧栏并保留已停止容器的只读路径入口', () => {
    assert.match(template, /id="conversation-container-terminal-drawer"/);
    assert.match(template, /id="conversation-container-terminal-root"/);
    assert.match(management, /workspaceTerminalStoppedHint/);
    assert.match(management, /openConversationContainerTerminalDrawer\(record\.conversationId\)/);
    assert.match(styles, /\.container-terminal-drawer\s*\{[\s\S]*?position: fixed;[\s\S]*?right: 0;/);
    assert.match(styles, /@media \(max-width: 760px\)[\s\S]*?\.container-terminal-drawer/);
});

test('宿主机长路径完整换行，已停止容器明确禁用终端按钮', () => {
    assert.match(styles, /\.container-terminal-workspace-grid code\s*\{[\s\S]*?overflow-wrap: anywhere;[\s\S]*?user-select: text;[\s\S]*?white-space: normal;/);
    assert.doesNotMatch(styles, /\.container-terminal-workspace-grid code\s*\{[\s\S]*?text-overflow: ellipsis;[\s\S]*?\}/);
    assert.match(styles, /\.container-terminal-actions \.btn-primary:disabled\s*\{[\s\S]*?cursor: not-allowed;/);
    assert.match(containerTerminal, /button\.setAttribute\('aria-disabled', available \? 'false' : 'true'\)/);
    assert.match(containerTerminal, /chat\.containerShellUnavailableButton/);
    assert.match(containerTerminal, /chat\.focusContainerShell/);
    assert.match(containerTerminal, /chat\.reconnectContainerShell/);
    assert.match(containerTerminal, /state === 'closed' && views\[viewName\]\.terminal && !views\[viewName\]\.connectionFailed/);
});

test('对话与管理页共用互斥的右侧终端抽屉', () => {
    assert.match(styles, /\.chat-container-terminal-drawer\s*\{[\s\S]*?width: min\(720px, calc\(100vw - 48px\)\);/);
    assert.match(styles, /\.container-terminal-root \.embedded-terminal-wrapper\s*\{[\s\S]*?display: flex;[\s\S]*?height: 100%;/);
    assert.match(containerTerminal, /syncDrawerBodyState/);
    assert.match(containerTerminal, /if \(conversationDrawer && !conversationDrawer\.hidden\) closeConversationContainerTerminalDrawer\(\)/);
    assert.match(containerTerminal, /if \(chatDrawer && !chatDrawer\.hidden\) closeChatContainerWorkspacePanel\(\)/);
});

test('聊天页和对话容器页终端都可用鼠标调整侧栏宽度与终端高度', () => {
    assert.equal((template.match(/data-container-terminal-resize="width"/g) || []).length, 2);
    assert.equal((template.match(/data-container-terminal-resize="height"/g) || []).length, 2);
    assert.match(styles, /\.container-terminal-drawer-width-handle\s*\{[\s\S]*?cursor: ew-resize;[\s\S]*?touch-action: none;/);
    assert.match(styles, /\.container-terminal-height-handle\s*\{[\s\S]*?cursor: ns-resize;[\s\S]*?touch-action: none;/);
    assert.match(containerTerminal, /function beginResize\(event\)/);
    assert.match(containerTerminal, /function continueResize\(event\)/);
    assert.match(containerTerminal, /activeResize\.drawer\.style\.width = `\$\{size\}px`/);
    assert.match(containerTerminal, /activeResize\.root\.style\.height = `\$\{size\}px`/);
    assert.match(containerTerminal, /bodyRect\.bottom - event\.clientY/);
    assert.equal((template.match(/class="container-terminal-info-pane"/g) || []).length, 2);
    assert.match(styles, /\.container-terminal-info-pane\s*\{[\s\S]*?flex: 1 1 auto;[\s\S]*?overflow-y: auto;/);
    assert.match(containerTerminal, /scheduleTerminalFit\(activeResize\.viewName\)/);
});

test('容器终端中英文文案和缓存版本完整', () => {
    const chatKeys = [
        'containerWorkspaceButton', 'containerWorkspacePath', 'hostWorkspacePath', 'hostWorkspaceTmpfs',
        'containerWorkspaceLoading', 'openContainerShell', 'containerShellUnavailableButton', 'focusContainerShell', 'reconnectContainerShell', 'containerShellReady', 'containerShellStopped',
        'containerTerminalWelcome', 'containerTerminalConnected', 'containerTerminalConnectionFailed',
        'containerStateStarting', 'containerStateRunning', 'containerStateStopped', 'containerStateFailed', 'containerStateNotStarted',
    ];
    const managementKeys = [
        'workspaceAndTerminal', 'workspaceTerminalReadyHint', 'workspaceTerminalStoppedHint', 'openWorkspaceTerminal',
    ];
    for (const locale of [zh, en]) {
        for (const key of chatKeys) assert.equal(typeof locale.chat[key], 'string', key);
        for (const key of managementKeys) assert.equal(typeof locale.containerManagement[key], 'string', key);
    }
    assert.match(template, /style\.css\?v=20260826-4/);
    assert.match(template, /chat\.js\?v=20260826-1/);
    assert.match(template, /container-management\.js\?v=20260826-1/);
});
