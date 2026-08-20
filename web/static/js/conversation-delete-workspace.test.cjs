const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '..', '..', '..');
const chat = fs.readFileSync(path.join(root, 'web/static/js/chat.js'), 'utf8');
const webshell = fs.readFileSync(path.join(root, 'web/static/js/webshell.js'), 'utf8');
const template = fs.readFileSync(path.join(root, 'web/templates/index.html'), 'utf8');
const styles = fs.readFileSync(path.join(root, 'web/static/css/style.css'), 'utf8');
const zh = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/zh-CN.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/en-US.json'), 'utf8'));

test('删除对话弹窗为持久工作区提供两个明确选项', () => {
    assert.match(template, /id="conversation-delete-workspace-modal"/);
    assert.match(template, /id="conversation-delete-retain-btn"[^>]+onclick="resolveConversationDeleteWorkspaceChoice\('retain'\)"/);
    assert.match(template, /id="conversation-delete-workspace-btn"[^>]+onclick="resolveConversationDeleteWorkspaceChoice\('delete'\)"/);
    assert.match(styles, /\.conversation-delete-workspace-dialog/);
    assert.match(styles, /\.conversation-delete-retain-btn/);
    assert.match(styles, /html\[data-theme="dark"\][\s\S]{0,600}\.conversation-delete-workspace-notice/);
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
