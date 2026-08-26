const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '..', '..', '..');
const audit = require('./egress-audit.js');
const source = fs.readFileSync(path.join(root, 'web/static/js/egress-audit.js'), 'utf8');
const template = fs.readFileSync(path.join(root, 'web/templates/index.html'), 'utf8');
const management = fs.readFileSync(path.join(root, 'web/static/js/container-management.js'), 'utf8');
const router = fs.readFileSync(path.join(root, 'web/static/js/router.js'), 'utf8');
const styles = fs.readFileSync(path.join(root, 'web/static/css/style.css'), 'utf8');
const zh = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/zh-CN.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/en-US.json'), 'utf8'));

test('egress audit validates the closed safe projection without requiring omitted IP arrays', () => {
    const network = {
        id: 'ea-1', chainSequence: 1, previousHash: '0'.repeat(64), eventHash: 'a'.repeat(64),
        occurredAt: '2026-08-22T12:00:00Z', category: 'network', eventType: 'http',
        conversationId: 'conversation-a', conversationTitle: 'audit target', domain: 'allowed.example',
        decision: 'allowed', method: 'GET', path: '/safe', resolvedIps: ['93.184.216.34'],
        bytesUp: 1536, bytesDown: 4096,
    };
    const lifecycle = {
        id: 'ea-2', chainSequence: 2, previousHash: 'a'.repeat(64), eventHash: 'b'.repeat(64),
        occurredAt: '2026-08-22T12:00:01Z', category: 'lifecycle', eventType: 'stop',
        conversationId: 'conversation-a', conversationTitle: 'audit target', result: 'success',
    };
	const health = {
		id: 'eh-3', chainSequence: 3, previousHash: 'b'.repeat(64), eventHash: 'c'.repeat(64),
		occurredAt: '2026-08-22T12:00:02Z', category: 'lifecycle', eventType: 'health',
		conversationId: 'conversation-a', conversationTitle: 'audit target', result: 'failure',
		decision: 'blocked', reason: 'waf_challenge', outcome: 'health_paused', lifecycleOperation: 'health', lifecycleState: 'paused',
	};
    assert.equal(audit.isSafeAuditEvent(network), true);
    assert.equal(audit.isSafeAuditEvent({ ...network, resolvedIps: undefined }), true);
    assert.equal(audit.isSafeAuditEvent({ ...network, aggregateCount: 25, aggregateKind: 'web-fuzz', aggregateFirstAt: '2026-08-22T12:00:00Z', aggregateLastAt: '2026-08-22T12:00:01Z', aggregateDistinctVariants: 25 }), true);
    assert.equal(audit.isSafeAuditEvent({ ...network, aggregateCount: 25, aggregateKind: 'web-fuzz' }), false);
    assert.equal(audit.isSafeAuditEvent(lifecycle), true);
	assert.equal(audit.isSafeAuditEvent(health), true);
    assert.equal(audit.isSafeAuditEvent({ ...network, eventType: 'raw_socket' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, category: 'lifecycle', result: 'success' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, decision: '<script>' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, conversationTitle: 'line\nheader' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, message: 'line\nheader' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, authorization: 'Bearer private-token' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, requestBody: 'private-body' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, responseHeaders: { cookie: 'private-cookie' } }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, httpPacket: {
        requestLine: 'GET /safe?token=plain HTTP/1.1', requestHeaders: { Authorization: ['Bearer plain-token'] },
        responseLine: 'HTTP/1.1 200 OK', responseHeaders: { 'Content-Type': ['text/plain'] },
        responseBody: 'complete response', responseBodyEncoding: 'utf8', sensitiveDataRedacted: false,
    } }), true);
    assert.equal(audit.isSafeAuditEvent({ ...network, httpPacket: { requestLine: 'GET / HTTP/1.1', requestHeaders: {}, extra: 'unsafe' } }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, chainSequence: 0 }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, previousHash: 'not-a-hash' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, eventHash: 'A'.repeat(64) }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, latencyMs: -1 }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, port: 70000 }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, resolvedIps: new Array(65).fill('1.1.1.1') }), false);
    const dns = { ...network, eventType: 'dns', method: '', path: '', dnsQueryType: 'mx', dnsAnswers: ['allowed.example MX 10 mail.allowed.example'] };
    const icmp = { ...network, eventType: 'icmp', method: '', path: '', port: 0, bytesUp: 0, bytesDown: 0 };
    assert.equal(audit.isSafeAuditEvent(dns), true);
    assert.equal(audit.isSafeAuditEvent(icmp), true);
    assert.equal(audit.isSafeAuditEvent({ ...dns, dnsAnswers: new Array(129).fill('A') }), false);
    assert.deepEqual(audit.packetSummaryForTest(dns), { primary: 'DNS MX allowed.example', secondary: 'allowed.example MX 10 mail.allowed.example' });
    assert.deepEqual(audit.packetSummaryForTest(icmp), { primary: 'ICMP allowed.example', secondary: '↑0 B · ↓0 B' });
    assert.deepEqual(audit.packetSummaryForTest(network), { primary: 'GET /safe', secondary: '↑1.5 KiB · ↓4.0 KiB' });
    assert.deepEqual(audit.packetSummaryForTest(lifecycle), { primary: '—', secondary: '' });
});

test('egress audit validates a closed integrity proof', () => {
    const proof = { status: 'verified', conversations: 2, events: 7, verifiedAt: '2026-08-23T00:00:00Z' };
    assert.equal(audit.isSafeIntegrity(proof), true);
    assert.equal(audit.isSafeIntegrity({ ...proof, status: 'unknown' }), false);
    assert.equal(audit.isSafeIntegrity({ ...proof, events: -1 }), false);
    assert.equal(audit.isSafeIntegrity({ ...proof, extra: 'unsafe' }), false);
});

test('egress audit URL state accepts only closed filters and supported page sizes', () => {
    assert.deepEqual(audit.readURLStateForTest('?audit_page=3&audit_page_size=50&audit_q=needle&audit_conversation=conversation-a&audit_category=network&audit_type=dns&audit_decision=blocked'), {
        page: 3, pageSize: 50, query: 'needle', conversation: 'conversation-a', category: 'network', type: 'dns', decision: 'blocked',
    });
	assert.equal(audit.readURLStateForTest('?audit_type=health').type, 'health');
    assert.deepEqual(audit.readURLStateForTest('?audit_page=-2&audit_page_size=25&audit_category=secret&audit_type=socket&audit_decision=maybe'), {
        page: 1, pageSize: 20, query: '', conversation: '', category: 'all', type: 'all', decision: 'all',
    });
});

test('egress audit accepts only a closed conversation option projection', () => {
    assert.equal(audit.isSafeAuditConversation({ conversationId: 'conversation-a', conversationTitle: 'Title' }), true);
    assert.equal(audit.isSafeAuditConversation({ conversationId: 'conversation-a', conversationTitle: 'line\nTitle' }), false);
    assert.equal(audit.isSafeAuditConversation({ conversationId: 'conversation-a', conversationTitle: 'Title', owner: 'secret' }), false);
});

test('egress audit page is authenticated, searchable, pageable, exportable, and permission gated', () => {
    for (const id of [
        'egress-audit-search', 'egress-audit-conversation', 'egress-audit-category', 'egress-audit-type', 'egress-audit-decision',
        'egress-audit-page-size', 'egress-audit-refresh', 'egress-audit-export-json',
        'egress-audit-export-csv', 'egress-audit-summary', 'egress-audit-rows',
        'egress-audit-prev', 'egress-audit-next', 'egress-audit-pagination-meta', 'egress-audit-integrity',
        'egress-audit-select-page', 'egress-audit-delete-selected', 'egress-audit-delete-filtered',
        'egress-audit-packet-modal', 'egress-audit-packet-request', 'egress-audit-packet-response',
    ]) assert.match(template, new RegExp(`id="${id}"`));
    assert.match(template, /data-page="egress-audit" data-require-permission="audit:read"/);
    assert.match(template, /id="page-egress-audit"[^>]+data-require-permission="audit:read"/);
    assert.match(template, /egress-audit\.js\?v=20260826-3/);
    assert.equal(zh.containerManagement.auditReconcile, '状态校准');
    assert.equal(zh.containerManagement.auditRuntimeReconciled, '容器运行时状态已校准');
    assert.match(template, /data-i18n="containerManagement\.auditPacket"/);
    assert.match(source, /params\.set\('defer_integrity', 'true'\)/);
    assert.match(source, /\/api\/egress-audit-events\/conversations/);
    assert.match(source, /\/api\/egress-audit-events\/integrity/);
    assert.match(source, /\/api\/egress-audit-events\/export\?\$\{params\.toString\(\)\}/);
    assert.match(source, /method: 'DELETE'/);
    assert.match(source, /\/api\/egress-audit-events\/.*encodeURIComponent\(event\.id\)/);
    assert.match(source, /root\.apiFetch/);
    assert.match(source, /createObjectURL\(blob\)/);
    assert.match(source, /URL_KEYS = Object\.freeze/);
    assert.match(source, /setTimeout\(applyFilters, 300\)/);
    assert.match(source, /params\.set\('conversation_id', state\.conversation\)/);
    assert.match(source, /payload\.conversations\) \? payload\.conversations\.filter\(isSafeAuditConversation\)/);
    assert.match(source, /root\.AbortController/);
    assert.match(source, /textContent/);
    assert.match(source, /isSafeIntegrity\(payload\.integrity\)/);
    assert.doesNotMatch(source, /\.innerHTML\s*=/);
    assert.match(management, /pageId === 'egress-audit'[\s\S]*?initEgressAuditPage\(\)/);
    assert.match(router, /currentPage === 'egress-audit'[\s\S]*?stopEgressAuditPage\(\)/);
});

test('egress audit translations and responsive table/card layout are complete', () => {
    const keys = [
        'auditPersistent', 'auditSearch', 'auditSearchPlaceholder', 'auditConversationFilter', 'auditAllConversations', 'auditCategory', 'auditCategoryNetwork',
        'auditCategoryLifecycle', 'auditEventType', 'auditDecisionFilter', 'auditSuccess', 'auditFailure',
        'auditExportJSON', 'auditExportCSV', 'auditResults', 'auditLoading', 'auditLoaded', 'auditLoadFailed',
        'auditTrace', 'auditEmpty', 'auditTotal', 'auditNetwork', 'auditLifecycle', 'auditBlocked',
        'auditFailures', 'auditPageMeta', 'auditPageMetaEmpty',
        'auditIntegrityChecking', 'auditIntegrityVerified', 'auditIntegrityFailed',
		'auditPacket', 'auditPacketView', 'auditDeleteSelected', 'auditDeleteFiltered', 'auditDeleted',
		'auditHealth', 'auditHealthCooldownStarted', 'auditHealthCooldownExpired', 'auditHealthPaused', 'auditHealthRecovered',
    ];
    for (const locale of [zh, en]) {
        for (const key of keys) assert.equal(typeof locale.containerManagement[key], 'string', key);
        assert.equal(typeof locale.containerManagement.activityValues.rate_limited, 'string');
        assert.equal(typeof locale.containerManagement.activityValues.rate_limit_exceeded, 'string');
    }
    assert.match(styles, /\.egress-audit-filter-grid\s*\{/);
    assert.match(styles, /\.egress-audit-summary\s*\{/);
    assert.match(styles, /\.egress-audit-table-wrap\s*\{[\s\S]*?overflow-x: auto/);
    assert.match(styles, /@media \(max-width: 760px\)[\s\S]*?\.egress-audit-table tr\s*\{[\s\S]*?display: grid/);
    assert.match(styles, /\.egress-audit-table td::before[\s\S]*?content: attr\(data-label\)/);
    assert.match(styles, /\.egress-audit-packet-modal\s*\{/);
    assert.match(styles, /\.egress-audit-packet-grid\s*\{/);
    assert.match(styles, /\.container-management-phase\.is-ready\s*\{/);
    assert.match(styles, /\.container-management-phase\.is-error\s*\{/);
    assert.match(template, /style\.css\?v=20260826-7/);
    assert.match(template, /router\.js\?v=20260822-5/);
    assert.match(template, /container-management\.js\?v=20260826-1/);
});
