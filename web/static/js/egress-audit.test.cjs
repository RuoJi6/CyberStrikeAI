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
        id: 'ea-1', occurredAt: '2026-08-22T12:00:00Z', category: 'network', eventType: 'http',
        conversationId: 'conversation-a', conversationTitle: 'audit target', domain: 'allowed.example',
        decision: 'allowed', path: '/safe', resolvedIps: ['93.184.216.34'],
    };
    const lifecycle = {
        id: 'ea-2', occurredAt: '2026-08-22T12:00:01Z', category: 'lifecycle', eventType: 'stop',
        conversationId: 'conversation-a', conversationTitle: 'audit target', result: 'success',
    };
    assert.equal(audit.isSafeAuditEvent(network), true);
    assert.equal(audit.isSafeAuditEvent({ ...network, resolvedIps: undefined }), true);
    assert.equal(audit.isSafeAuditEvent(lifecycle), true);
    assert.equal(audit.isSafeAuditEvent({ ...network, eventType: 'raw_socket' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, category: 'lifecycle', result: 'success' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, decision: '<script>' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, conversationTitle: 'line\nheader' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, message: 'line\nheader' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, authorization: 'Bearer private-token' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, requestBody: 'private-body' }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, responseHeaders: { cookie: 'private-cookie' } }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, latencyMs: -1 }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, port: 70000 }), false);
    assert.equal(audit.isSafeAuditEvent({ ...network, resolvedIps: new Array(65).fill('1.1.1.1') }), false);
});

test('egress audit URL state accepts only closed filters and supported page sizes', () => {
    assert.deepEqual(audit.readURLStateForTest('?audit_page=3&audit_page_size=50&audit_q=needle&audit_category=network&audit_type=dns&audit_decision=blocked'), {
        page: 3, pageSize: 50, query: 'needle', category: 'network', type: 'dns', decision: 'blocked',
    });
    assert.deepEqual(audit.readURLStateForTest('?audit_page=-2&audit_page_size=25&audit_category=secret&audit_type=socket&audit_decision=maybe'), {
        page: 1, pageSize: 20, query: '', category: 'all', type: 'all', decision: 'all',
    });
});

test('egress audit page is authenticated, searchable, pageable, exportable, and permission gated', () => {
    for (const id of [
        'egress-audit-search', 'egress-audit-category', 'egress-audit-type', 'egress-audit-decision',
        'egress-audit-page-size', 'egress-audit-refresh', 'egress-audit-export-json',
        'egress-audit-export-csv', 'egress-audit-summary', 'egress-audit-rows',
        'egress-audit-prev', 'egress-audit-next', 'egress-audit-pagination-meta',
    ]) assert.match(template, new RegExp(`id="${id}"`));
    assert.match(template, /data-page="egress-audit" data-require-permission="audit:read"/);
    assert.match(template, /id="page-egress-audit"[^>]+data-require-permission="audit:read"/);
    assert.match(template, /egress-audit\.js\?v=20260822-3/);
    assert.match(source, /\/api\/egress-audit-events\?\$\{queryParams\(true\)\.toString\(\)\}/);
    assert.match(source, /\/api\/egress-audit-events\/export\?\$\{params\.toString\(\)\}/);
    assert.match(source, /root\.apiFetch/);
    assert.match(source, /createObjectURL\(blob\)/);
    assert.match(source, /URL_KEYS = Object\.freeze/);
    assert.match(source, /setTimeout\(applyFilters, 300\)/);
    assert.match(source, /textContent/);
    assert.doesNotMatch(source, /\.innerHTML\s*=/);
    assert.match(management, /pageId === 'egress-audit'[\s\S]*?initEgressAuditPage\(\)/);
    assert.match(router, /currentPage === 'egress-audit'[\s\S]*?stopEgressAuditPage\(\)/);
});

test('egress audit translations and responsive table/card layout are complete', () => {
    const keys = [
        'auditPersistent', 'auditSearch', 'auditSearchPlaceholder', 'auditCategory', 'auditCategoryNetwork',
        'auditCategoryLifecycle', 'auditEventType', 'auditDecisionFilter', 'auditSuccess', 'auditFailure',
        'auditExportJSON', 'auditExportCSV', 'auditResults', 'auditLoading', 'auditLoaded', 'auditLoadFailed',
        'auditTrace', 'auditEmpty', 'auditTotal', 'auditNetwork', 'auditLifecycle', 'auditBlocked',
        'auditFailures', 'auditPageMeta', 'auditPageMetaEmpty',
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
    assert.match(template, /style\.css\?v=20260822-13/);
    assert.match(template, /router\.js\?v=20260822-5/);
    assert.match(template, /container-management\.js\?v=20260822-7/);
});
