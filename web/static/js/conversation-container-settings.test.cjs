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
    assert.match(template, /id="container-conversation-options"/);
    assert.match(template, /id="boundary-policy-select"/);
    assert.match(template, /id="conversation-egress-mode-select"/);
    assert.match(template, /value=""[^>]*data-i18n="chat\.egressModeInherit"/);
    assert.match(template, /value="none"[^>]*data-i18n="chat\.egressModeNone"/);
    assert.match(template, /value="proxy"[^>]*disabled/);
    assert.match(template, /value="group"[^>]*disabled/);
    assert.match(template, /id="conversation-egress-target-select"/);
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
    ]) {
        assert.ok(settings.includes(endpoint), endpoint);
    }
    assert.doesNotMatch(settings, /credentials|credentialCiphertext|password|authorization/i);
    assert.match(settings, /option\.textContent = text/);
    assert.doesNotMatch(settings, /sessionStorage|localStorage/, 'selection code must not persist server resource payloads');
});

test('new conversation request sends exact immutable selection fields only for container mode', () => {
    const elements = {
        'boundary-policy-select': { value: 'policy-1' },
        'conversation-egress-mode-select': { value: 'proxy' },
        'conversation-egress-target-select': { value: 'proxy-1' },
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
        { boundaryPolicyId: 'policy-1', egressMode: 'proxy', egressProxyId: 'proxy-1' },
    );
    elements['conversation-egress-mode-select'].value = 'group';
    elements['conversation-egress-target-select'].value = 'group-1';
    assert.deepEqual(
        JSON.parse(JSON.stringify(window.readNewConversationContainerControls('container'))),
        { boundaryPolicyId: 'policy-1', egressMode: 'group', egressProxyGroupId: 'group-1' },
    );
    elements['conversation-egress-mode-select'].value = '';
    assert.deepEqual(
        JSON.parse(JSON.stringify(window.readNewConversationContainerControls('container'))),
        { boundaryPolicyId: 'policy-1' },
    );
    assert.deepEqual(JSON.parse(JSON.stringify(window.readNewConversationContainerControls('host'))), {});
    assert.match(chat, /Object\.assign\(body, window\.readNewConversationContainerControls\(body\.runtimeMode\)\)/);
});

test('container creation copy is bilingual and cache-busted', () => {
    for (const locale of [zh, en]) {
        for (const key of [
            'containerSecurityOptionsTitle', 'boundaryPolicyLabel', 'boundaryPolicyDefaultDenyHint',
            'egressModeLabel', 'egressModeInherit', 'egressPreviewUnavailable',
            'egressInheritedPreview', 'egressExplicitPreview', 'egressTargetHint',
        ]) {
            assert.equal(typeof locale.chat[key], 'string', key);
            assert.ok(locale.chat[key].trim(), key);
        }
    }
    assert.match(zh.chat.boundaryPolicyDefaultDenyHint, /默认拒绝/);
    assert.match(zh.chat.egressTargetHint, /脱敏/);
    assert.match(en.chat.egressTargetHint, /credential-redacted/i);
    assert.match(template, /style\.css\?v=20260824-1/);
    assert.match(template, /chat\.js\?v=20260824-1/);
    assert.match(template, /unified-select\.js\?v=20260822-3/);
    assert.match(template, /conversation-container-settings\.js\?v=20260822-2/);
});
