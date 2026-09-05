const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const lifecycle = require('./container-lifecycle.js');
const audit = require('./egress-audit.js');
const source = fs.readFileSync(`${__dirname}/container-lifecycle.js`, 'utf8');
const event = (id = 'a', overrides = {}) => ({ id: `event-${id}`, conversationId: id, category: 'lifecycle', eventType: 'stop', result: 'success',
    occurredAt: '2026-09-05T01:00:00Z', chainSequence: 1, previousHash: '0'.repeat(64), eventHash: 'a'.repeat(64), runtimeGeneration: 2, ...overrides });
const payload = id => ({ items: [event(id)], total: 1, totalPages: 1 });

test('lifecycle filters are conversation-scoped, paged and category-locked', () => {
    const params = lifecycle.filterParams('a&category=network', { page: 2, type: 'rebuild', result: 'failure' });
    assert.deepEqual(Object.fromEntries(params), { conversation_id: 'a&category=network', category: 'lifecycle', defer_integrity: 'true', page: '2', page_size: '10', event_type: 'rebuild', decision: 'failure' });
    const invalid = lifecycle.filterParams('a', { type: 'http', result: 'allowed' });
    assert.equal(invalid.has('event_type'), false); assert.equal(invalid.has('decision'), false);
});

test('lifecycle data fails closed for other conversations, categories or unsafe fields', () => {
    assert.equal(lifecycle.acceptEvents(payload('a'), 'a', audit.isSafeAuditEvent).length, 1);
    for (const item of [event('b'), event('a', { category: 'network' }), event('a', { eventType: 'http' }), event('a', { authorization: 'secret' }), event('a', { eventHash: 'invalid' })]) {
        assert.throws(() => lifecycle.acceptEvents({ items: [item], total: 1, totalPages: 1 }, 'a', audit.isSafeAuditEvent));
    }
    assert.throws(() => lifecycle.acceptEvents({ items: [], total: -1, totalPages: 0 }, 'a', audit.isSafeAuditEvent));
});

test('historical failures never become a claim about current failure or recovery', () => {
    const failure = event('a', { result: 'failure' });
    assert.match(lifecycle.failureContext(failure, { runtimeStatus: 'running', status: 'created', lifecycleState: 'idle' }), /历史失败.*当前容器运行中/);
    assert.doesNotMatch(lifecycle.failureContext(failure, { runtimeStatus: 'running', lifecycleState: 'failed' }), /当前容器运行中/);
    assert.equal(lifecycle.failureContext(event(), {}), '');
});

class Node {
    constructor(tag = 'div') { this.tag = tag; this.children = []; this.dataset = {}; this.isConnected = true; this.events = {}; this.textContent = ''; }
    append(...items) { this.children.push(...items); }
    replaceChildren(...items) { this.children = items; }
    setAttribute() {}
    addEventListener(name, fn) { this.events[name] = fn; }
    get text() { return this.textContent + this.children.map(n => n.text).join(' '); }
}
function setup(permission = true) {
    const pending = []; const summary = new Node(); summary.dataset.containerLifecycleLatest = 'b';
    const window = { document: { createElement: tag => new Node(tag), querySelectorAll: () => [summary] }, setTimeout, clearTimeout,
        hasPermission: () => permission, CyberStrikeEgressAudit: audit,
        apiFetch: url => new Promise(resolve => pending.push({ url, resolve })) };
    vm.runInNewContext(source, { window, URLSearchParams, AbortController });
    return { api: window.ContainerLifecycle, pending, summary };
}
const settle = () => new Promise(resolve => setImmediate(resolve));
test('late responses cannot replace the selected conversation history', async () => {
    const { api, pending, summary } = setup(); const a = new Node(), b = new Node();
    api.mount(a, { conversationId: 'a' }, true); api.mount(b, { conversationId: 'b' }, true);
    pending[1].resolve({ ok: true, json: async () => payload('b') }); await settle();
    pending[0].resolve({ ok: true, json: async () => payload('a') }); await settle();
    assert.match(b.text, /event-b/); assert.doesNotMatch(b.text, /event-a/);
    assert.match(summary.text, /停止.*成功/);
});

test('permission denied does not call the audit API', () => {
    const { api, pending } = setup(false); const host = new Node();
    api.mount(host, { conversationId: 'a' }, true);
    assert.equal(pending.length, 0); assert.match(host.text, /审计读取权限/);
});

test('network audit entry no longer exposes lifecycle filters, including legacy URLs', () => {
    const template = fs.readFileSync(`${__dirname}/../../templates/index.html`, 'utf8');
    assert.doesNotMatch(template, /id="egress-audit-category"/);
    assert.match(template, /id="egress-audit-open-lifecycle"/);
    assert.ok(template.indexOf('container-lifecycle.js?v=') < template.indexOf('container-management.js?v='));
    const state = audit.readURLStateForTest('?audit_category=lifecycle&audit_type=rebuild');
    assert.equal(state.category, 'network'); assert.equal(state.type, 'all');
    const management = fs.readFileSync(`${__dirname}/container-management.js`, 'utf8');
    assert.match(management, /panels\.settings\.append/);
    assert.match(management, /panels\.overview\.append/);
    assert.doesNotMatch(source, /\.innerHTML\s*=/);
});

test('both languages cover every new lifecycle label', () => {
    const zh = JSON.parse(fs.readFileSync(`${__dirname}/../i18n/zh-CN.json`)).containerManagement;
    const en = JSON.parse(fs.readFileSync(`${__dirname}/../i18n/en-US.json`)).containerManagement;
    for (const key of Object.keys(zh).filter(k => k.startsWith('lifecycle') || k.startsWith('detail') || k === 'auditLifecycleMoved' || k === 'auditOpenLifecycle')) assert.ok(en[key], key);
});
