const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../../..');
const template = fs.readFileSync(path.join(root, 'web/templates/index.html'), 'utf8');
const chat = fs.readFileSync(path.join(root, 'web/static/js/chat.js'), 'utf8');
const settings = fs.readFileSync(path.join(root, 'web/static/js/conversation-container-settings.js'), 'utf8');
const styles = fs.readFileSync(path.join(root, 'web/static/css/style.css'), 'utf8');
const zh = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/zh-CN.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/en-US.json'), 'utf8'));

test('new conversation panel shows workspace, boundary, inherited egress, and safe targets', () => {
    assert.match(template, /id="runtime-mode-panel"[\s\S]*?role="dialog"/);
    assert.match(template, /id="workspace-persistence-option"/);
    assert.match(template, /id="conversation-workspace-mode"[\s\S]*?value="ephemeral"[\s\S]*?value="dedicated"[\s\S]*?value="shared"/);
    assert.match(template, /id="conversation-shared-workspace-select"/);
    assert.match(template, /id="conversation-shared-workspace-name"/);
    assert.match(template, /id="conversation-shared-workspace-create"/);
    assert.match(template, /id="container-conversation-options"/);
    assert.match(template, /id="boundary-policy-select"/);
    assert.match(template, /id="conversation-egress-mode-select"/);
    assert.match(template, /value=""[^>]*data-i18n="chat\.egressModeInherit"/);
    assert.match(template, /value="none"[^>]*data-i18n="chat\.egressModeNone"/);
    assert.match(template, /value="proxy"[^>]*disabled/);
    assert.match(template, /value="group"[^>]*disabled/);
    assert.match(template, /id="conversation-egress-target-select"/);
	assert.match(template, /type="checkbox"[^>]*id="conversation-scan-rate-toggle"/);
	assert.match(template, /type="checkbox"[^>]*id="conversation-resource-limit-toggle"/);
	assert.match(template, /id="conversation-http-rate"[^>]*value="20"/);
	assert.match(template, /id="conversation-cpu-limit"[^>]*value="1"/);
    assert.match(template, /id="conversation-egress-audit-toggle"[^>]*checked/);
    assert.match(template, /id="conversation-egress-audit-mode"[^>]*data-unified-select="single"/);
    assert.doesNotMatch(template, /conversation-network-settings-apply|applyConversationContainerNetworkSettings/);
    assert.match(template, /class="container-conversation-field is-runtime-editable"[\s\S]{0,1400}id="conversation-egress-audit-toggle"/);
    assert.match(template, /id="conversation-egress-preview"[^>]*aria-live|id="container-conversation-options-status"[^>]*aria-live/);
    assert.match(styles, /\.runtime-mode-panel \{[\s\S]*?overflow-y: auto/);
    assert.match(styles, /\.runtime-mode-panel > \.runtime-mode-options,[\s\S]*?\.runtime-mode-panel > \.workspace-persistence-option,[\s\S]*?flex: 0 0 auto/);
    assert.match(styles, /@media \(max-width: 768px\)[\s\S]*?\.runtime-mode-wrapper \.runtime-mode-panel \{[\s\S]*?position: fixed/);
    assert.match(styles, /\.runtime-mode-wrapper \.runtime-mode-panel \{[\s\S]*?inset: auto 8px 76px 8px/);
    assert.ok((template.match(/data-unified-select="single"/g) || []).length >= 15);
    for (const id of ['egress-audit-category', 'egress-audit-type', 'egress-audit-decision', 'egress-audit-page-size']) {
        assert.match(template, new RegExp(`id="${id}"[^>]+data-unified-select="single"`));
    }
    assert.match(styles, /\.unified-select-trigger:focus-visible/);
    assert.match(styles, /html\[data-theme="dark"\] \.unified-select-trigger/);
});

test('settings client loads only safe control-plane projections', () => {
    for (const endpoint of [
        '/api/boundary-policies',
        '/api/egress-proxies?limit=100&offset=0',
        '/api/egress-proxy-groups',
        '/api/egress-defaults/preview',
        '/api/container-workspaces?project_id=',
        '/container/network-settings',
    ]) {
        assert.ok(settings.includes(endpoint), endpoint);
    }
    assert.doesNotMatch(settings, /credentials|credentialCiphertext|password|authorization/i);
    assert.match(settings, /option\.textContent = text/);
    assert.doesNotMatch(settings, /sessionStorage|localStorage/, 'selection code must not persist server resource payloads');
});

test('shared workspace selection is included in container conversation creation', () => {
    const elements = {
        'conversation-workspace-mode': { value: 'shared' },
        'conversation-shared-workspace-select': { value: 'workspace-shared-1' },
        'boundary-policy-select': { value: '' },
        'conversation-egress-mode-select': { value: '' },
        'conversation-egress-audit-toggle': { checked: true },
        'conversation-egress-audit-mode': { value: 'compact' },
        'conversation-scan-rate-toggle': { checked: false },
        'conversation-resource-limit-toggle': { checked: false },
    };
    const document = {
        getElementById(id) { return elements[id] || null; },
        addEventListener() {},
        createElement() { return {}; },
    };
    const window = { currentConversationId: '', t(key) { return key; } };
    vm.runInNewContext(settings, { window, document, Promise, Object, String, Array, Error, encodeURIComponent });

    assert.deepEqual(
        JSON.parse(JSON.stringify(window.readNewConversationContainerControls('container'))),
        {
            workspaceMode: 'shared',
            workspacePersistent: true,
            workspaceId: 'workspace-shared-1',
            idlePolicy: { action: 'delete', timeoutSeconds: 1800 },
            egressAuditEnabled: true,
            egressAuditMode: 'compact',
            runtimeControls: {
                scanRateEnabled: false,
                httpRequestsPerSecond: 0,
                tcpConnectionsPerSecond: 0,
                udpDatagramsPerSecond: 0,
                customResourcesEnabled: false,
                nanoCpus: 0,
                memoryBytes: 0,
            },
        },
    );
});

test('new conversation request sends exact immutable selection fields only for container mode', () => {
    const elements = {
        'conversation-workspace-mode': { value: 'dedicated' },
        'boundary-policy-select': { value: 'policy-1' },
        'conversation-egress-mode-select': { value: 'proxy' },
        'conversation-egress-target-select': { value: 'proxy-1' },
        'conversation-egress-audit-toggle': { checked: true },
        'conversation-egress-audit-mode': { value: 'full' },
		'conversation-scan-rate-toggle': { checked: false },
		'conversation-resource-limit-toggle': { checked: false },
    };
    const document = {
        getElementById(id) { return elements[id] || null; },
        addEventListener() {},
        createElement() { return {}; },
    };
    const window = { currentConversationId: '', t(key) { return key; } };
    vm.runInNewContext(settings, { window, document, Promise, Object, String, Array, Error, encodeURIComponent });

    assert.deepEqual(
        JSON.parse(JSON.stringify(window.readNewConversationContainerControls('container'))),
		{ workspaceMode: 'dedicated', workspacePersistent: true, idlePolicy: { action: 'delete', timeoutSeconds: 1800 }, egressAuditEnabled: true, egressAuditMode: 'full', boundaryPolicyId: 'policy-1', egressMode: 'proxy', egressProxyId: 'proxy-1', runtimeControls: {
			scanRateEnabled: false, httpRequestsPerSecond: 0, tcpConnectionsPerSecond: 0, udpDatagramsPerSecond: 0,
			customResourcesEnabled: false, nanoCpus: 0, memoryBytes: 0,
		} },
    );
    elements['conversation-egress-mode-select'].value = 'group';
    elements['conversation-egress-target-select'].value = 'group-1';
    assert.deepEqual(
        JSON.parse(JSON.stringify(window.readNewConversationContainerControls('container'))),
		{ workspaceMode: 'dedicated', workspacePersistent: true, idlePolicy: { action: 'delete', timeoutSeconds: 1800 }, egressAuditEnabled: true, egressAuditMode: 'full', boundaryPolicyId: 'policy-1', egressMode: 'group', egressProxyGroupId: 'group-1', runtimeControls: {
			scanRateEnabled: false, httpRequestsPerSecond: 0, tcpConnectionsPerSecond: 0, udpDatagramsPerSecond: 0,
			customResourcesEnabled: false, nanoCpus: 0, memoryBytes: 0,
		} },
    );
    elements['conversation-egress-mode-select'].value = '';
    assert.deepEqual(
        JSON.parse(JSON.stringify(window.readNewConversationContainerControls('container'))),
		{ workspaceMode: 'dedicated', workspacePersistent: true, idlePolicy: { action: 'delete', timeoutSeconds: 1800 }, egressAuditEnabled: true, egressAuditMode: 'full', boundaryPolicyId: 'policy-1', runtimeControls: {
			scanRateEnabled: false, httpRequestsPerSecond: 0, tcpConnectionsPerSecond: 0, udpDatagramsPerSecond: 0,
			customResourcesEnabled: false, nanoCpus: 0, memoryBytes: 0,
		} },
    );
    assert.deepEqual(JSON.parse(JSON.stringify(window.readNewConversationContainerControls('host'))), {});
    assert.match(chat, /Object\.assign\(body, window\.readNewConversationContainerControls\(body\.runtimeMode\)\)/);
});

test('container creation copy is bilingual and cache-busted', () => {
    for (const locale of [zh, en]) {
        for (const key of [
            'containerSecurityOptionsTitle', 'boundaryPolicyLabel', 'boundaryPolicyDefaultAllow', 'boundaryPolicyDefaultAllowHint',
            'egressModeLabel', 'egressModeInherit', 'egressPreviewUnavailable',
            'egressInheritedPreview', 'egressExplicitPreview', 'egressTargetHint',
            'egressAuditLabel', 'egressAuditHint', 'egressAuditDisabledHint', 'egressAuditFullHint',
            'egressAuditModeLabel', 'egressAuditModeCompact', 'egressAuditModeFull', 'egressAuditModeHint',
            'containerNetworkAutoApplying', 'containerNetworkAutoApplied', 'containerNetworkAutoApplyFailed',
			'scanRateLimitLabel', 'scanRateLimitHint', 'httpRateLabel', 'tcpRateLabel', 'udpRateLabel',
			'customResourcesLabel', 'customResourcesHint', 'cpuLimitLabel', 'memoryLimitLabel',
			'containerIdleActionLabel', 'containerIdleDelete', 'containerIdleStop', 'containerIdleNone',
			'containerIdleTimeoutLabel', 'containerIdleDeleteHint', 'containerIdleStopHint', 'containerIdleNoneHint',
        ]) {
            assert.equal(typeof locale.chat[key], 'string', key);
            assert.ok(locale.chat[key].trim(), key);
        }
    }
    assert.match(zh.chat.boundaryPolicyDefaultAllowHint, /不限制/);
	assert.match(zh.chat.boundaryPolicyDefaultAllowHint, /HTTPS 默认解密并完整审计/);
	assert.match(en.chat.boundaryPolicyDefaultAllowHint, /HTTPS is decrypted and fully audited by default/);
    assert.match(zh.chat.egressTargetHint, /脱敏/);
    assert.match(en.chat.egressTargetHint, /credential-redacted/i);
    assert.match(template, /style\.css\?v=20260901-2/);
	assert.match(template, /chat\.js\?v=20260901-1/);
    assert.match(template, /unified-select\.js\?v=20260822-3/);
	assert.match(template, /conversation-container-settings\.js\?v=20260901-1/);
});

test('completed container conversations apply changed boundary and upstream settings on the next send', () => {
    assert.match(chat, /setConversationContainerControlsLocked\(taskLocked\)/);
    assert.match(settings, /currentNetworkSelection/);
    assert.match(settings, /boundaryPolicyId:\s*selection\.boundaryPolicyId/);
    assert.match(settings, /egressMode:\s*selection\.egressMode/);
    assert.match(settings, /\/container\/rebuild/);
    assert.match(settings, /state\.taskLocked/);
    assert.match(settings, /window\.ensureConversationContainerNetworkSettings\s*=\s*ensureConversationContainerNetworkSettings/);
    assert.doesNotMatch(settings, /window\.confirm/);
    assert.doesNotMatch(styles, /\.container-conversation-network-actions/);
    const send = chat.slice(chat.indexOf('async function sendMessage()'));
    assert.ok(send.indexOf('await window.ensureConversationContainerNetworkSettings()') >= 0);
    assert.ok(send.indexOf('await window.ensureConversationContainerNetworkSettings()') < send.indexOf("addMessage('user'"));
});

test('next-send network preparation rebuilds and verifies the active generation before sending', async () => {
    function select(value) {
        return {
            value, disabled: false, options: [],
            replaceChildren(...options) { this.options = options; if (!options.some((option) => option.value === this.value)) this.value = options[0]?.value || ''; },
            set selectedIndex(index) { this.value = this.options[index]?.value || ''; },
            get selectedOptions() { return this.options.filter((option) => option.value === this.value); },
            querySelector() { return null; },
        };
    }
    const boundary = select('');
    const mode = select('none');
    const target = select('');
    const elements = {
        'runtime-mode-select': { value: 'container' },
        'boundary-policy-select': boundary,
        'boundary-policy-hint': { textContent: '' },
        'conversation-egress-mode-select': mode,
        'conversation-egress-target-select': target,
    };
    const document = {
        getElementById(id) { return elements[id] || null; },
        addEventListener() {},
        createElement() { return { value: '', textContent: '', disabled: false, dataset: {} }; },
    };
    let activeBoundary = 'policy-a';
    let generation = 3;
    let rebuilds = 0;
    let failRebuild = false;
    const notifications = [];
    const window = {
        currentConversationId: 'conversation-1',
        t(key) { return key; },
        showNotification(message, type) { notifications.push({ message, type }); },
        async apiFetch(path, options) {
            if (path.endsWith('/container/network-settings')) {
                return {
                    ok: true,
                    async json() {
                        return {
                            boundaryPolicyId: activeBoundary,
                            boundaryDefaultAction: activeBoundary ? '' : 'allow',
                            egressMode: 'none', egressSource: 'conversation', runtimeGeneration: generation,
                            runtimeControls: {
                                scanRateEnabled: false, httpRequestsPerSecond: 0, tcpConnectionsPerSecond: 0, udpDatagramsPerSecond: 0,
                                customResourcesEnabled: false, nanoCpus: 0, memoryBytes: 0,
                            },
                        };
                    },
                };
            }
            if (path.endsWith('/container/rebuild')) {
                rebuilds++;
                if (failRebuild) return { ok: false, status: 409, async json() { return { error: 'conflict' }; } };
                activeBoundary = JSON.parse(options.body).boundaryPolicyId;
                generation++;
                return { ok: true, async json() { return {}; } };
            }
            throw new Error(`unexpected request: ${path}`);
        },
    };
    vm.runInNewContext(settings, { window, document, Promise, Object, String, Array, Error, encodeURIComponent });

    await window.loadActiveConversationNetworkSettings();
    boundary.value = 'policy-b';
    assert.equal(await window.ensureConversationContainerNetworkSettings(), true);
    assert.equal(rebuilds, 1);
    assert.equal(activeBoundary, 'policy-b');
    assert.equal(await window.ensureConversationContainerNetworkSettings(), true);
    assert.equal(rebuilds, 1, 'unchanged settings must not rebuild again');

    boundary.value = 'policy-c';
    failRebuild = true;
    assert.equal(await window.ensureConversationContainerNetworkSettings(), false);
    assert.equal(rebuilds, 2);
    assert.ok(notifications.some((item) => item.type === 'error'));
});

test('clearing a stale boundary requires an allow snapshot and a new runtime generation', async () => {
    assert.match(settings, /boundaryPolicyId:\s*selection\.boundaryPolicyId/);
    assert.match(settings, /active && active\.boundaryDefaultAction[\s\S]{0,180}!== 'allow'/);
    assert.match(settings, /Number\(active && active\.runtimeGeneration \|\| 0\)/);
    assert.match(settings, /activeGeneration <= previousGeneration/);
    assert.match(settings, /if \(!loaded \|\| !state\.activeNetworkSignature\)[\s\S]{0,180}return false/);
});
