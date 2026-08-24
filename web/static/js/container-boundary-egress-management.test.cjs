const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '..', '..', '..');
const read = (...parts) => fs.readFileSync(path.join(root, ...parts), 'utf8');
const template = read('web', 'templates', 'index.html');
const boundary = read('web', 'static', 'js', 'boundary-rules.js');
const management = read('web', 'static', 'js', 'container-management.js');
const egress = read('web', 'static', 'js', 'egress-management.js');
const styles = read('web', 'static', 'css', 'style.css');
const zh = JSON.parse(read('web', 'static', 'i18n', 'zh-CN.json'));
const en = JSON.parse(read('web', 'static', 'i18n', 'en-US.json'));

test('边界规则页提供可检索分页的策略列表、使用关系和完整 CRUD', () => {
    for (const id of [
        'boundary-rules-phase',
        'boundary-policy-search',
        'boundary-policy-page-size',
        'boundary-policy-list',
        'boundary-policy-pagination',
        'boundary-policy-detail-drawer',
        'boundary-policy-detail-body',
        'boundary-policy-editor-modal',
        'boundary-policy-form',
        'boundary-policy-name',
        'boundary-policy-description',
		'boundary-policy-tls-enabled',
		'boundary-policy-tls-bypass',
        'boundary-policy-rule-list',
        'boundary-rule-form',
        'boundary-rule-form-title',
        'boundary-rule-close',
        'boundary-rule-effect',
        'boundary-rule-host',
        'boundary-rule-schemes',
        'boundary-rule-ports',
        'boundary-rule-paths',
        'boundary-rule-methods',
        'boundary-rules-refresh',
        'boundary-rules-load-state',
    ]) assert.match(template, new RegExp(`id="${id}"`));

    assert.doesNotMatch(template, /id="boundary-rules-focus-title"/);
    assert.match(template, /class="boundary-policy-editor-body"/);
    assert.match(boundary, /\/api\/boundary-policies\?' \+ query\.toString\(\)/);
    assert.match(boundary, /\/usage/);
    assert.match(boundary, /\/rules['"]? \+ \(ruleID/);
    assert.match(boundary, /jsonOptions\(id \? 'PUT' : 'POST', payload\)/);
    assert.match(boundary, /\{ method: 'DELETE' \}/);
	assert.match(boundary, /boundary_page/);
	assert.match(boundary, /boundary_page_size/);
	assert.match(boundary, /boundary_q/);
	assert.match(boundary, /tlsInspectionEnabled/);
	assert.match(boundary, /tlsBypassDomains/);
    assert.match(boundary, /state\.selectedUsage/);
    assert.match(boundary, /window\.initBoundaryRulesPage = init/);
});

test('出站管理页提供代理、代理组和凭据档案的完整 CRUD', () => {
    for (const id of [
        'egress-management-summary',
        'egress-management-refresh',
        'egress-view-proxies',
        'egress-proxy-form',
        'egress-proxy-list',
        'egress-view-groups',
        'egress-group-form',
        'egress-group-list',
        'egress-group-members',
        'egress-view-auth',
        'egress-auth-form',
        'egress-auth-list',
    ]) assert.match(template, new RegExp(`id="${id}"`));

    for (const endpoint of ['egress-proxies', 'egress-proxy-groups', 'egress-auth-profiles']) {
        assert.match(egress, new RegExp(`/api/${endpoint.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    }
    assert.match(egress, /jsonOptions\(id \? 'PUT' : 'POST', payload\)/);
    assert.match(egress, /\{ method: 'DELETE' \}/);
    assert.match(egress, /payload\.credentials = null/);
    assert.match(egress, /payload\.credential = null/);
    assert.match(egress, /credentialsConfigured/);
    assert.match(egress, /selectableProxyIds\.has\(member\.proxyId\)/);
    assert.match(egress, /egress_view/);
    assert.match(egress, /window\.initEgressManagementPage = init/);
});

test('新管理页不注入非受信 HTML，也不把凭据写入浏览器存储', () => {
    for (const source of [boundary, egress]) {
        assert.doesNotMatch(source, /\.innerHTML\s*=/);
        assert.doesNotMatch(source, /\b(?:localStorage|sessionStorage)\b/);
        assert.doesNotMatch(source, /credentialCiphertext/);
        assert.match(source, /\.textContent\s*=/);
    }
    assert.match(template, /id="egress-proxy-password" type="password"/);
    assert.match(template, /id="egress-auth-credential" type="password"/);
    assert.match(template, /id="egress-proxy-password"[^>]+autocomplete="new-password"/);
    assert.match(template, /id="egress-auth-credential"[^>]+autocomplete="new-password"/);
});

test('中英文文案与宽窄屏布局覆盖新管理功能', () => {
    const keys = [
        'boundaryConversation', 'boundaryLoading', 'boundaryReady', 'boundarySnapshotHash',
        'boundaryRulesTitle', 'boundaryRate', 'boundaryNoConversations', 'boundaryTLSEnabled',
        'boundaryAnyMethod', 'boundaryDefaultAllow',
        'boundaryTLSBypassDomains', 'boundaryTLSBypassHint', 'activityHTTPS',
        'egressLoading', 'egressReady', 'egressProxiesTab', 'egressGroupsTab', 'egressAuthTab',
        'createProxy', 'createGroup', 'createAuth', 'credentialsConfigured', 'clearCredentials',
        'groupMembers', 'priority', 'weight', 'proxyDeleteConfirm', 'groupDeleteConfirm', 'authDeleteConfirm',
    ];
    for (const locale of [zh, en]) {
        for (const key of keys) assert.equal(typeof locale.containerManagement[key], 'string', key);
    }
    assert.match(boundary, /boundaryAnyMethod/);
    assert.match(boundary, /usageCount/);
    assert.match(boundary, /protocolLabel/);
    assert.match(styles, /\.boundary-policy-row\s*\{/);
    assert.match(styles, /\.boundary-policy-detail-drawer\s*\{/);
    assert.match(styles, /\.boundary-policy-editor-modal\s*\{/);
    assert.match(styles, /\.boundary-policy-editor-dialog\s*\{[\s\S]*?grid-template-rows: auto minmax\(0, 1fr\);[\s\S]*?max-height:[\s\S]*?overflow: hidden;/);
    assert.match(styles, /\.boundary-policy-editor-body\s*\{[\s\S]*?overflow: auto;/);
    assert.match(styles, /\.boundary-rule-form:not\(\[hidden\]\)\s*\{[\s\S]*?position: fixed;[\s\S]*?transform: translate\(-50%, -50%\)/);
    assert.match(styles, /\.container-policy-detail\s*\{/);
    assert.match(styles, /\.container-policy-rule-grid\s*\{/);
    assert.match(styles, /\.egress-management-view\s*\{/);
    assert.match(styles, /\.egress-form-grid\s*\{/);
    assert.match(styles, /\.egress-form-toggle\[hidden\]\s*\{\s*display: none !important;/);
    assert.match(styles, /\.container-environment-card\s*\{[\s\S]*?grid-template-columns: minmax\(0, 1fr\);[\s\S]*?min-width: 0;/);
    assert.match(styles, /\.container-environment-heading,[\s\S]*?\.container-environment-details\s*\{[\s\S]*?min-width: 0;/);
    assert.match(styles, /@media \(max-width: 760px\)[\s\S]*?\.container-environment-details\s*\{\s*grid-template-columns: 1fr;/);
    assert.match(styles, /@media \(max-width: 760px\)[\s\S]*?\.egress-management-view/);
    assert.match(styles, /@media \(max-width: 480px\)[\s\S]*?\.container-policy-rule-grid/);
    assert.match(styles, /@media \(max-width: 480px\)[\s\S]*?\.container-policy-snapshot-heading,[\s\S]*?flex-direction: column/);
});

test('空方法对所有边界效果都显示为任意方法', () => {
    const source = boundary.match(/function ruleMethodsLabel\(rule\) \{[\s\S]*?\n    \}/);
    assert.ok(source, '应找到实际 ruleMethodsLabel 实现');
    const makeLabel = new Function('t', `${source[0]}; return ruleMethodsLabel;`);
    const label = makeLabel((key, fallback) => key === 'boundaryAnyMethod'
        ? '任意方法'
        : fallback);

    assert.equal(label({ effect: 'allow-visit', methods: [] }), '任意方法');
    assert.equal(label({ effect: 'allow-visit', methods: ['POST'] }), 'POST');
    assert.equal(label({ effect: 'allow-attack', methods: [] }), '任意方法');
});

test('对话容器详情可以切换边界策略并显式重建', () => {
    assert.match(management, /container-boundary-policy-switch/);
    assert.match(management, /\/api\/boundary-policies\?page=1&page_size=100/);
    assert.match(management, /\/container\/rebuild/);
    assert.match(management, /JSON\.stringify\(\{ boundaryPolicyId: policyId \}\)/);
    assert.match(management, /record\.boundaryPolicyId/);
    assert.match(styles, /\.container-boundary-policy-switch\s*\{/);
});
