const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

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

function containerStatusHarness(apiFetch, conversationId = 'conversation-a', executionStatus = '') {
    const listeners = new Map();
    const timers = [];
    const statefulElement = (extra = {}) => Object.assign({
        hidden: false,
        disabled: false,
        dataset: {},
        className: '',
        textContent: '',
        title: '',
        setAttribute() {},
        replaceChildren() {},
        appendChild() {},
        querySelector() { return null; },
    }, extra);
    const elements = {
        'runtime-mode-select': { value: 'container' },
        'chat-container-workspace-btn': statefulElement(),
        'chat-container-workspace-panel': statefulElement({ hidden: true }),
        'chat-container-terminal-open': statefulElement(),
        'chat-container-terminal-status': statefulElement(),
        'chat-container-runtime-state': statefulElement(),
        'chat-container-runtime-state-label': statefulElement(),
    };
    const classList = { add() {}, remove() {}, toggle() {} };
    const document = {
        body: { classList },
        getElementById(id) { return elements[id] || null; },
        querySelectorAll() { return []; },
        addEventListener(type, fn) { listeners.set(`document:${type}`, fn); },
        createElement() { return { appendChild() {}, replaceChildren() {}, setAttribute() {}, classList }; },
    };
    const window = {
        currentConversationId: conversationId,
        apiFetch,
        getConversationExecutionStatus() { return executionStatus; },
        addEventListener(type, fn) { listeners.set(type, fn); },
        setTimeout(fn, delay) { timers.push({ fn, delay }); return timers.length; },
        clearTimeout() {},
        requestAnimationFrame(fn) { fn(); },
        innerWidth: 1280,
        innerHeight: 800,
    };
    vm.runInNewContext(containerTerminal, {
        window,
        document,
        Promise,
        Object,
        String,
        Array,
        Error,
        Math,
        Number,
        encodeURIComponent,
        requestAnimationFrame: window.requestAnimationFrame,
    });
    return { window, elements, listeners, timers };
}

async function flushStatusPromises() {
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
}

test('对话执行栏提供工作区入口并在右侧抽屉承载共享终端', () => {
    assert.match(template, /id="runtime-mode-wrapper"[\s\S]*?id="chat-container-workspace-btn"/);
    assert.match(template, /id="chat-container-workspace-panel"/);
    assert.match(template, /id="chat-container-runtime-state"[\s\S]*?id="chat-container-runtime-state-label"/);
    assert.doesNotMatch(template.match(/id="chat-container-workspace-btn"[\s\S]*?<\/button>/)?.[0] || '', /chat\.containerWorkspaceShort|>\s*工作区\s*</);
    assert.doesNotMatch(template.match(/id="chat-container-workspace-btn"[\s\S]*?<\/button>/)?.[0] || '', /role-selector-text|role-selector-icon/);
    assert.match(template, /id="chat-container-path"/);
    assert.match(template, /id="chat-container-host-path"/);
    assert.match(template, /id="chat-container-terminal-root"/);
    assert.match(template, /id="chat-container-workspace-mode"/);
    assert.match(template, /id="chat-container-workspace-name"/);
    assert.match(template, /id="chat-container-workspace-shared-count"/);
    assert.match(template, /id="chat-container-workspace-attachments"/);
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
    assert.match(containerTerminal, /\?observe=1/);
    assert.match(containerTerminal, /chatStatusPollAttempts === 0/);
    assert.match(containerTerminal, /lifecycleState === 'in_progress'/);
    assert.match(containerTerminal, /observedAgentStatus === 'running'/);
    assert.match(containerTerminal, /taskStatus === 'running'[\s\S]*?readiness === 'ready'/);
    assert.match(containerTerminal, /runtimeStatus === 'running'[\s\S]*?\? 'running'/);
    assert.match(containerTerminal, /conversation-container-state-changed/);
    assert.match(containerTerminal, /containerStateStarting/);
    assert.match(containerTerminal, /containerStateRunning/);
    assert.match(styles, /\.chat-container-runtime-state\.is-starting/);
    assert.match(styles, /\.chat-container-runtime-state\.is-running/);
});

test('未知状态不会显示为启动中，首次状态失败可自动恢复', async () => {
    let calls = 0;
    const harness = containerStatusHarness(async (url) => {
        calls += 1;
        assert.match(url, /\?observe=1$/);
        if (calls === 1) throw new Error('temporary failure');
        return { ok: true, async json() { return { status: 'created', runtimeStatus: 'running' }; } };
    });
    harness.window.renderChatContainerState('unexpected-state');
    assert.equal(harness.elements['chat-container-runtime-state'].dataset.state, 'unavailable');
    assert.doesNotMatch(harness.elements['chat-container-runtime-state-label'].textContent, /启动中/);

    await flushStatusPromises();
    assert.equal(harness.elements['chat-container-runtime-state'].dataset.state, 'checking');
    assert.equal(harness.timers.length, 1);
    await harness.timers.shift().fn();
    await flushStatusPromises();
    assert.equal(harness.elements['chat-container-runtime-state'].dataset.state, 'running');
});

test('活动任务初始化时短暂的 stopped 状态不会终止轮询且无需刷新即可转为运行中', async () => {
    let calls = 0;
    const harness = containerStatusHarness(async () => {
        calls += 1;
        if (calls === 1) {
            return {
                ok: true,
                async json() {
                    return {
                        status: 'created',
                        readinessStatus: 'ready',
                        runtimeStatus: 'stopped',
                        lifecycleOperation: 'start',
                        lifecycleState: 'in_progress',
                        observationError: 'runtime_drift',
                        observation: { agent: { status: 'stopped' } },
                    };
                },
            };
        }
        return {
            ok: true,
            async json() {
                return {
                    status: 'created',
                    readinessStatus: 'ready',
                    runtimeStatus: 'running',
                    lifecycleOperation: 'start',
                    lifecycleState: 'idle',
                    observation: { agent: { status: 'running' } },
                };
            },
        };
    }, 'conversation-a', 'initializing');

    await flushStatusPromises();
    assert.equal(harness.elements['chat-container-runtime-state'].dataset.state, 'starting');
    assert.equal(harness.timers.length, 1);

    await harness.timers.shift().fn();
    await flushStatusPromises();
    assert.equal(harness.elements['chat-container-runtime-state'].dataset.state, 'running');
    assert.equal(calls, 2);
});

test('容器就绪事件在运行状态落库前保持启动中并继续自动同步', async () => {
    let calls = 0;
    const harness = containerStatusHarness(() => {
        calls += 1;
        return new Promise(() => {});
    }, 'conversation-a', 'running');
    harness.listeners.get('conversation-container-state-changed')({
        detail: { conversationId: 'conversation-a', state: 'ready', runtimeStatus: 'stopped' },
    });
    assert.equal(harness.elements['chat-container-runtime-state'].dataset.state, 'starting');
    assert.equal(calls, 2);
});

test('工作区抽屉打开时会随运行状态刷新 Shell 可用性', async () => {
    let workspaceCalls = 0;
    const harness = containerStatusHarness(async (url) => {
        if (url.includes('/container/workspace')) {
            workspaceCalls += 1;
            const running = workspaceCalls > 1;
            return {
                ok: true,
                async json() {
                    return {
                        runtimeStatus: running ? 'running' : 'stopped',
                        interactiveAvailable: running,
                    };
                },
            };
        }
        return { ok: true, async json() { return { status: 'created', runtimeStatus: 'stopped' }; } };
    }, 'conversation-a', 'running');

    await flushStatusPromises();
    await harness.window.toggleChatContainerWorkspacePanel();
    assert.equal(workspaceCalls, 1);
    assert.equal(harness.elements['chat-container-terminal-open'].disabled, true);

    harness.listeners.get('conversation-container-state-changed')({
        detail: { conversationId: 'conversation-a', state: 'ready', runtimeStatus: 'running' },
    });
    await flushStatusPromises();
    assert.equal(workspaceCalls, 2);
    assert.equal(harness.elements['chat-container-terminal-open'].disabled, false);
    assert.equal(harness.elements['chat-container-terminal-status'].dataset.tone, 'success');
});

test('快速切换对话时旧状态响应不能覆盖当前对话', async () => {
    const pending = new Map();
    const harness = containerStatusHarness((url) => new Promise((resolve) => {
        pending.set(url.includes('conversation-a') ? 'a' : 'b', resolve);
    }));
    harness.window.currentConversationId = 'conversation-b';
    harness.listeners.get('conversation-changed')();
    pending.get('b')({ ok: true, async json() { return { status: 'created', runtimeStatus: 'stopped' }; } });
    await flushStatusPromises();
    assert.equal(harness.elements['chat-container-runtime-state'].dataset.state, 'stopped');
    pending.get('a')({ ok: true, async json() { return { status: 'created', runtimeStatus: 'running' }; } });
    await flushStatusPromises();
    assert.equal(harness.elements['chat-container-runtime-state'].dataset.state, 'stopped');
});

test('系统设置终端与容器终端复用同一 xterm 会话和多标签代码', () => {
    assert.match(terminal, /function createTerminalInContainer\(container, tab\)/);
    assert.match(terminal, /function createEmbeddedTerminal\(root, options\)/);
    assert.match(terminal, /createTerminalInContainer\(container, tab\)/);
    assert.match(terminal, /window\.CyberStrikeTerminal/);
    assert.match(containerTerminal, /CyberStrikeTerminal\.createEmbeddedTerminal/);
    assert.match(terminal, /attachCustomKeyEventHandler/);
    assert.match(terminal, /event\.key !== 'Tab'/);
    assert.match(terminal, /sendToWS\(event\.shiftKey \? '\\x1b\[Z' : '\\t'\)/);
    assert.match(template, /terminal\.js\?v=20260828-3/);
    assert.match(template, /container-terminal\.js\?v=20260903-1/);
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
    const pathRule = styles.match(/\.container-terminal-workspace-grid code\s*\{([^}]*)\}/)?.[1] || '';
    assert.doesNotMatch(pathRule, /text-overflow:\s*ellipsis/);
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
        'containerStateChecking', 'containerStateRetrying', 'containerStateUnavailable', 'containerStateStopping', 'containerStateDeleting',
    ];
    const managementKeys = [
        'workspaceAndTerminal', 'workspaceTerminalReadyHint', 'workspaceTerminalStoppedHint', 'openWorkspaceTerminal',
    ];
    for (const locale of [zh, en]) {
        for (const key of chatKeys) assert.equal(typeof locale.chat[key], 'string', key);
        for (const key of managementKeys) assert.equal(typeof locale.containerManagement[key], 'string', key);
    }
	assert.match(template, /style\.css\?v=20260905-2/);
	assert.match(template, /chat\.js\?v=20260902-1/);
	assert.match(template, /container-terminal\.js\?v=20260903-1/);
	assert.match(template, /container-management\.js\?v=20260905-1/);
});
