const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

const chat = fs.readFileSync('web/static/js/chat.js', 'utf8');

function timingSource(source) {
    const start = source.indexOf('function formatAssistantTurnDuration(');
    const end = source.indexOf('window.setAssistantTurnTiming = setAssistantTurnTiming;', start);
    assert.notEqual(start, -1, 'formatAssistantTurnDuration should exist');
    assert.notEqual(end, -1, 'timing exports should exist');
    return source.slice(start, end);
}

function processDetailFilterSource(source) {
    const start = source.indexOf('function isEinoAgentHeartbeatProgress(');
    const end = source.indexOf('function dedupeConsecutiveProcessDetailRows(', start);
    assert.notEqual(start, -1, 'process detail filter should exist');
    assert.notEqual(end, -1, 'dedupe boundary should exist');
    return source.slice(start, end);
}

function createClassList() {
    return {
        toggle() {},
    };
}

function createMessage() {
    const label = {
        innerHTML: '',
        classList: createClassList(),
        setAttribute() {},
    };
    return {
        dataset: {},
        querySelector(selector) {
            if (selector === '.mcp-call-label.turn-process-summary') return label;
            return null;
        },
        label,
    };
}

function createHarness(nowMs) {
    const RealDate = Date;
    class TestDate extends RealDate {
        static now() {
            return nowMs;
        }
    }
    const context = {
        Date: TestDate,
        Number,
        Math,
        String,
        document: {
            querySelector() { return null; },
            querySelectorAll() { return []; },
            getElementById() { return null; },
        },
        window: {},
        escapeHtml(value) { return String(value); },
        setInterval() { return 1; },
        clearInterval() {},
    };
    vm.runInNewContext(
        `${timingSource(chat)}; this.setAssistantTurnTiming = setAssistantTurnTiming;`,
        context
    );
    return context;
}

test('刷新运行中任务时使用服务端耗时快照而不受客户端时钟漂移影响', () => {
    const startedAt = '2026-08-12T02:00:00.000Z';
    const startedMs = Date.parse(startedAt);
    const context = createHarness(startedMs + (43 * 60_000) + 65_000);
    const message = createMessage();

    context.setAssistantTurnTiming(message, {
        startedAt,
        durationMs: 0,
        elapsedMs: 65_000,
        status: 'running',
    });

    assert.equal(message.dataset.turnDurationMs, undefined);
    assert.match(message.label.innerHTML, /已处理 1 分钟 5 秒/);
    assert.doesNotMatch(message.label.innerHTML, /43 分钟/);
});

test('运行中占位在耗时快照返回前从本地零秒起跑', () => {
    const context = createHarness(Date.parse('2026-08-12T02:43:00.000Z'));
    const message = createMessage();

    context.setAssistantTurnTiming(message, {
        startedAt: '2026-08-12T02:00:00.000Z',
        status: 'running',
    });

    assert.match(message.label.innerHTML, /已处理 0 秒/);
    assert.doesNotMatch(message.label.innerHTML, /43 分钟/);
});

test('已完成任务仍优先使用持久化耗时', () => {
    const context = createHarness(Date.parse('2026-08-12T02:05:00.000Z'));
    const message = createMessage();

    context.setAssistantTurnTiming(message, {
        startedAt: '2026-08-12T02:00:00.000Z',
        completedAt: '2026-08-12T02:01:05.000Z',
        durationMs: 65_000,
        status: 'completed',
    });

    assert.equal(message.dataset.turnDurationMs, '65000');
    assert.match(message.label.innerHTML, /耗时 1 分钟 5 秒/);
});

test('容器启动只占用顶部计时摘要且就绪后恢复普通对话耗时', () => {
    const startedAt = '2026-08-12T02:00:00.000Z';
    const context = createHarness(Date.parse(startedAt) + 31_000);
    const message = createMessage();
    message.dataset.turnPhase = 'container_initializing';

    context.setAssistantTurnTiming(message, {
        startedAt,
        elapsedMs: 31_000,
        status: 'running',
    });
    assert.match(message.label.innerHTML, /容器正在启动中 · 31 秒/);

    delete message.dataset.turnPhase;
    context.syncAssistantTurnSummary(message);
    assert.match(message.label.innerHTML, /已处理 31 秒/);
    assert.doesNotMatch(message.label.innerHTML, /容器正在启动中/);
});

test('已中断任务使用固定终态耗时且不再按当前时间增长', () => {
    const context = createHarness(Date.parse('2026-08-13T12:00:00.000Z'));
    const message = createMessage();

    context.setAssistantTurnTiming(message, {
        startedAt: '2026-08-11T09:47:14.000Z',
        completedAt: '2026-08-11T09:51:39.000Z',
        durationMs: 265_000,
        status: 'cancelled',
    });

    assert.equal(message.dataset.turnDurationMs, '265000');
    assert.match(message.label.innerHTML, /已中断 · 耗时 4 分钟 25 秒/);
    assert.doesNotMatch(message.label.innerHTML, /已处理/);
});

test('历史占位消息存在取消事件时不会再判定为运行中', () => {
    assert.match(chat, /function assistantTurnTerminalState\(processDetails\)/);
    assert.match(chat, /const isRunning = isAssistantPlaceholder && !terminalState/);
    assert.match(chat, /status: status/);
});

test('过程详情隐藏容器启动过程与 Eino 内部诊断但保留真实工具调用', () => {
    const context = {};
    vm.runInNewContext(
        `${processDetailFilterSource(chat)}; this.filterNoiseProcessDetails = filterNoiseProcessDetails;`,
        context
    );

    const filtered = context.filterNoiseProcessDetails([
        {
            eventType: 'container_initialization',
            message: '对话容器正在启动；容器就绪后将自动继续当前请求。',
            data: { state: 'initializing' },
        },
        {
            eventType: 'container_initialization',
            message: '对话容器已就绪，正在继续执行原请求。',
            data: { state: 'ready' },
        },
        {
            eventType: 'tool_call',
            data: {
                toolName: 'task',
                argumentsObj: {
                    _cyberstrike_model_output_recovery: {
                        reason: 'invalid_tool_arguments_json',
                        repair_attempt: 1,
                    },
                },
            },
        },
        {
            eventType: 'model_output_rejected',
            message: '模型工具调用不完整或参数不安全，已阻止执行并要求重写。',
            data: { reason: 'invalid_tool_arguments_json' },
        },
        {
            eventType: 'progress',
            message: 'Eino TurnLoop 常驻多轮 runtime 已接管本轮会话。',
            data: { kind: 'turn_loop_takeover' },
        },
        {
            eventType: 'tool_call',
            data: {
                toolName: 'task',
                argumentsObj: { _raw: 'command' },
                arguments: 'command',
            },
        },
        {
            eventType: 'tool_call',
            data: {
                toolName: 'task',
                argumentsObj: { _raw: '"' },
                arguments: '"',
            },
        },
        {
            eventType: 'tool_call',
            data: {
                toolName: 'exec',
                arguments: '{"command":"ls"}',
            },
        },
    ]);

    assert.equal(filtered.length, 1);
    assert.equal(filtered[0].data.toolName, 'exec');
});
