const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '..', '..', '..');
const chat = fs.readFileSync(path.join(root, 'web/static/js/chat.js'), 'utf8');
const template = fs.readFileSync(path.join(root, 'web/templates/index.html'), 'utf8');
const zh = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/zh-CN.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/en-US.json'), 'utf8'));

test('工具执行详情展示受信执行位置和容器身份', () => {
    for (const id of ['detail-execution-location', 'detail-container-id', 'detail-image-digest']) {
        assert.match(template, new RegExp(`id="${id}"`));
        assert.match(chat, new RegExp(`getElementById\\('${id}'\\)`));
    }
    assert.match(chat, /exec\.executionLocation/);
    assert.match(chat, /exec\.containerId/);
    assert.match(chat, /exec\.imageDigest/);
});

test('执行审计字段具备中英文文案', () => {
    for (const locale of [zh, en]) {
        for (const key of ['executionLocation', 'executionLocationHost', 'executionLocationContainer', 'containerId', 'imageDigest']) {
            assert.equal(typeof locale.mcpDetailModal[key], 'string');
            assert.ok(locale.mcpDetailModal[key].length > 0);
        }
    }
});
