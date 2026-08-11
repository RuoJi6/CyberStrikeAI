const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

const settings = fs.readFileSync('web/static/js/settings.js', 'utf8');

function functionSource(source, name, nextName) {
    const start = source.indexOf(`async function ${name}(`);
    const end = source.indexOf(`function ${nextName}(`, start);
    assert.notEqual(start, -1, `${name} should exist`);
    assert.notEqual(end, -1, `${nextName} should follow ${name}`);
    return source.slice(start, end);
}

test('MCP 页刷新会同时重载工具列表和外部 MCP 状态', async () => {
    const calls = [];
    const context = {
        toolsPagination: { page: 3 },
        toolsSearchKeyword: 'asm',
        loadToolsList(page, keyword, options) {
            calls.push(['tools', page, keyword, options]);
            return Promise.resolve();
        },
        loadExternalMCPs(options) {
            calls.push(['external', options]);
            return Promise.resolve();
        }
    };
    vm.runInNewContext(
        `${functionSource(settings, 'refreshMCPManagement', 'clearSearch')}; this.refreshMCPManagement = refreshMCPManagement;`,
        context
    );

    const attributes = new Map();
    const button = {
        disabled: false,
        setAttribute(name, value) { attributes.set(name, value); },
        removeAttribute(name) { attributes.delete(name); }
    };

    await context.refreshMCPManagement(button);

    assert.equal(calls[0][0], 'tools');
    assert.equal(calls[0][1], 3);
    assert.equal(calls[0][2], 'asm');
    assert.equal(calls[0][3].refreshExternal, true);
    assert.equal(calls[1][0], 'external');
    assert.equal(calls[1][1].forceRender, true);
    assert.equal(button.disabled, false);
    assert.equal(attributes.has('aria-busy'), false);
});
