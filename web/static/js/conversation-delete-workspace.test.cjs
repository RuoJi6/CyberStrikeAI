const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..', '..', '..');
const chat = fs.readFileSync(path.join(root, 'web/static/js/chat.js'), 'utf8');
const modal = fs.readFileSync(path.join(root, 'web/static/js/modal.js'), 'utf8');
const webshell = fs.readFileSync(path.join(root, 'web/static/js/webshell.js'), 'utf8');
const template = fs.readFileSync(path.join(root, 'web/templates/index.html'), 'utf8');
const styles = fs.readFileSync(path.join(root, 'web/static/css/style.css'), 'utf8');
const zh = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/zh-CN.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/en-US.json'), 'utf8'));

test('删除对话弹窗为持久工作区提供两个明确选项', () => {
    assert.match(template, /id="conversation-delete-workspace-modal" class="modal-overlay projects-modal-overlay conversation-delete-workspace-modal"/);
    assert.match(styles, /\.modal-overlay\.projects-modal-overlay\s*\{[\s\S]{0,240}position:\s*fixed;[\s\S]{0,240}align-items:\s*center;[\s\S]{0,120}justify-content:\s*center;/);
    assert.match(styles, /\.modal-overlay\.projects-modal-overlay\.conversation-delete-workspace-modal\s*\{[\s\S]{0,280}width:\s*100vw\s*!important;[\s\S]{0,180}height:\s*100dvh;/);
    assert.match(styles, /\.conversation-delete-workspace-dialog\s*\{[\s\S]{0,320}position:\s*fixed;[\s\S]{0,160}top:\s*50vh;[\s\S]{0,120}left:\s*50vw;[\s\S]{0,180}translate\(-50%,\s*-50%\);/);
    assert.match(template, /style\.css\?v=20260828-01/);
    assert.match(template, /modal\.js\?v=20260821-1/);
    assert.match(template, /id="conversation-delete-retain-btn"[^>]+onclick="resolveConversationDeleteWorkspaceChoice\('retain'\)"/);
    assert.match(template, /id="conversation-delete-workspace-btn"[^>]+onclick="resolveConversationDeleteWorkspaceChoice\('delete'\)"/);
    assert.match(styles, /\.conversation-delete-workspace-dialog/);
    assert.match(styles, /\.conversation-delete-retain-btn/);
    assert.match(styles, /html\[data-theme="dark"\][\s\S]{0,600}\.conversation-delete-workspace-notice/);
});

test('删除对话弹窗脱离布局容器并按真实视口中心固定定位', () => {
    assert.match(modal, /VIEWPORT_CENTERED_MODAL_IDS[\s\S]{0,160}'conversation-delete-workspace-modal'/);
    assert.match(modal, /el\.parentElement !== document\.body[\s\S]{0,80}document\.body\.appendChild\(el\)/);
    assert.match(modal, /Number\(viewport\.scale\) > 1/);
    assert.match(modal, /setImportantStyle\(dialog\.style, 'left', `\$\{metrics\.centerX\}px`\)/);
    assert.match(modal, /setImportantStyle\(dialog\.style, 'top', `\$\{metrics\.centerY\}px`\)/);
    assert.match(modal, /setImportantStyle\(dialog\.style, 'transform', 'translate\(-50%, -50%\)'\)/);
    assert.match(modal, /visualViewport\.addEventListener\('resize', syncViewportModals/);
    assert.match(modal, /visualViewport\.addEventListener\('scroll', syncViewportModals/);
});

test('视口定位器在 Retina 与缩放视口下都重新计算可见中心', () => {
    const listeners = new Map();
    const makeStyle = (initial = {}) => ({
        ...initial,
        setProperty(name, value) {
            this[name] = value;
            this[name.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
        },
    });
    const makeClassList = (classes) => ({
        contains(name) { return classes.includes(name); },
        toggle() {},
    });
    const dialog = { style: makeStyle() };
    const oldParent = {};
    const overlay = {
        id: 'conversation-delete-workspace-modal',
        parentElement: oldParent,
        style: makeStyle({ display: 'none' }),
        classList: makeClassList(['modal-overlay', 'projects-modal-overlay', 'conversation-delete-workspace-modal']),
        querySelector(selector) {
            return selector === '.conversation-delete-workspace-dialog' ? dialog : null;
        },
    };
    const body = {
        classList: makeClassList([]),
        appendChild(element) { element.parentElement = this; },
    };
    const visualViewport = {
        scale: 1,
        width: 902,
        height: 484,
        offsetLeft: 0,
        offsetTop: 0,
        addEventListener(type, handler) { listeners.set(`visual:${type}`, handler); },
    };
    const context = {
        document: {
            body,
            documentElement: { clientWidth: 902, clientHeight: 484 },
            getElementById(id) { return id === overlay.id ? overlay : null; },
            querySelectorAll() { return [overlay]; },
        },
        window: {
            innerWidth: 902,
            innerHeight: 484,
            visualViewport,
            getComputedStyle(element) {
                return { display: element.style.display || 'none', visibility: 'visible' };
            },
            addEventListener(type, handler) { listeners.set(`window:${type}`, handler); },
        },
        requestAnimationFrame(handler) { handler(); },
    };
    vm.runInNewContext(modal, context);

    context.window.openAppModal(overlay.id, { focus: false });
    assert.equal(overlay.parentElement, body);
    assert.equal(overlay.style.display, 'flex');
    assert.equal(overlay.style.width, '902px');
    assert.equal(overlay.style.height, '484px');
    assert.equal(dialog.style.left, '451px');
    assert.equal(dialog.style.top, '242px');
    assert.equal(dialog.style.width, '560px');
    assert.equal(dialog.style.maxHeight, '460px');
    assert.equal(dialog.style.transform, 'translate(-50%, -50%)');

    visualViewport.scale = 2;
    visualViewport.width = 450;
    visualViewport.height = 242;
    visualViewport.offsetLeft = 100;
    visualViewport.offsetTop = 20;
    listeners.get('visual:resize')();
    assert.equal(dialog.style.left, '325px');
    assert.equal(dialog.style.top, '141px');
    assert.equal(dialog.style.width, '426px');
    assert.equal(dialog.style.maxHeight, '218px');
});

test('聊天页所有删除入口均通过工作区选择弹窗', () => {
    assert.match(chat, /window\.requestConversationDeleteWorkspaceChoice = requestConversationDeleteWorkspaceChoice/);
    assert.match(chat, /workspace_action=\$\{encodeURIComponent\(workspaceAction\)\}/);
    assert.match(chat, /function deleteConversationFromContext\(\)[\s\S]{0,500}window\.setTimeout\(\(\) => \{[\s\S]{0,120}void deleteConversation\(convId\);[\s\S]{0,80}\}, 0\)/);
    assert.match(chat, /async function deleteSelectedConversations\(\)[\s\S]{0,1800}requestConversationDeleteWorkspaceChoice\('', \{/);
    assert.match(chat, /persistentConversationIDs\.has\(id\)[\s\S]{0,180}'retain'[\s\S]{0,80}'delete'/);
    assert.match(chat, /ephemeralEl\.hidden = !hasEphemeralWorkspace/);
});

test('WebShell 对话删除复用相同选择并传递 API 参数', () => {
    assert.match(webshell, /window\.requestConversationDeleteWorkspaceChoice\(deletedId\)/);
    assert.match(webshell, /\?workspace_action=' \+ encodeURIComponent\(workspaceAction\)/);
});

test('中英文文案明确区分保留与删除工作区', () => {
    for (const locale of [zh, en]) {
        for (const key of [
            'deleteConversationWorkspaceDecision',
            'deleteConversationRetainWorkspace',
            'deleteConversationWithWorkspace',
            'deleteConversationOnly',
            'deleteConversationLoadFailed',
            'deleteConversationBatchName'
        ]) {
            assert.equal(typeof locale.chat[key], 'string');
            assert.ok(locale.chat[key].length > 0);
        }
    }
    assert.notEqual(zh.chat.deleteConversationRetainWorkspace, zh.chat.deleteConversationWithWorkspace);
    assert.notEqual(en.chat.deleteConversationRetainWorkspace, en.chat.deleteConversationWithWorkspace);
});
