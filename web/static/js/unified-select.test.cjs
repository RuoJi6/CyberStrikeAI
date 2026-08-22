const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '../../..');
const componentPath = path.join(root, 'web/static/js/unified-select.js');
const component = require(componentPath);
const source = fs.readFileSync(componentPath, 'utf8');
const template = fs.readFileSync(path.join(root, 'web/templates/index.html'), 'utf8');
const styles = fs.readFileSync(path.join(root, 'web/static/css/style.css'), 'utf8');
const zh = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/zh-CN.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/en-US.json'), 'utf8'));

test('search normalization and matching are deterministic', () => {
    assert.equal(component.normalizeSearchText('  Ａgent  '), 'agent');
    const records = [
        { index: 0, label: 'Default deny', searchText: 'Default deny empty policy' },
        { index: 1, label: 'Proxy Alpha', searchText: 'Proxy Alpha HTTPS' },
        { index: 2, label: '代理乙', searchText: '代理乙 SOCKS5' },
    ];
    assert.deepEqual(component.filterOptionRecords(records, ''), [0, 1, 2]);
    assert.deepEqual(component.filterOptionRecords(records, 'https'), [1]);
    assert.deepEqual(component.filterOptionRecords(records, '代理'), [2]);
    assert.deepEqual(component.filterOptionRecords(records, 'missing'), []);
});

test('keyboard navigation skips disabled and filtered options', () => {
    const records = [
        { index: 0, disabled: false },
        { index: 1, disabled: true },
        { index: 2, disabled: false },
        { index: 3, disabled: false },
    ];
    assert.equal(component.nextEnabledIndex(records, [0, 1, 2, 3], 0, 1), 2);
    assert.equal(component.nextEnabledIndex(records, [0, 1, 2, 3], 2, -1), 0);
    assert.equal(component.nextEnabledIndex(records, [1, 3], -1, 1), 3);
    assert.equal(component.nextEnabledIndex(records, [0, 2, 3], 2, 'first'), 0);
    assert.equal(component.nextEnabledIndex(records, [0, 2, 3], 2, 'last'), 3);
    assert.equal(component.nextEnabledIndex(records, [1], -1, 1), -1);
});

test('floating menu clamps width and flips above near the viewport bottom', () => {
    const below = component.calculateMenuGeometry(
        { left: 30, top: 80, bottom: 118, width: 260 },
        { width: 390, height: 844 },
        360,
    );
    assert.equal(below.placement, 'bottom');
    assert.equal(below.left, 30);
    assert.equal(below.width, 260);
    assert.ok(below.top >= 124);

    const above = component.calculateMenuGeometry(
        { left: 310, top: 780, bottom: 818, width: 240 },
        { width: 390, height: 844 },
        360,
    );
    assert.equal(above.placement, 'top');
    assert.equal(above.left, 142);
    assert.equal(above.width, 240);
    assert.ok(above.top >= 8);

    const narrow = component.calculateMenuGeometry(
        { left: -30, top: 100, bottom: 138, width: 900 },
        { width: 320, height: 600 },
        360,
    );
    assert.equal(narrow.left, 8);
    assert.equal(narrow.width, 304);
});

test('component implements searchable single and multi-select accessibility', () => {
    assert.match(source, /document\.body\.appendChild\(menu\)/);
    assert.match(source, /menu\.style\.position|className = 'unified-select-menu'/);
    assert.match(source, /setAttribute\('role', 'listbox'\)/);
    assert.match(source, /setAttribute\('aria-multiselectable'/);
    assert.match(source, /setAttribute\('aria-activedescendant'/);
    assert.match(source, /event\.key === 'ArrowDown'/);
    assert.match(source, /event\.key === 'Escape'/);
    assert.match(source, /event\.stopPropagation\(\)/);
    assert.match(source, /if \(instance\.multiple\) option\.selected = !option\.selected/);
    assert.match(source, /translate\('common\.noMatchingOptions'/);
    assert.doesNotMatch(source, /\.innerHTML\s*=/);
    assert.match(styles, /\.unified-select-menu\s*\{[\s\S]*?position: fixed;[\s\S]*?z-index: 6200/);
    assert.match(styles, /\.unified-select-empty/);
});

test('container creation uses the unified component with bilingual empty states', () => {
    for (const id of ['boundary-policy-select', 'conversation-egress-mode-select', 'conversation-egress-target-select']) {
        assert.match(template, new RegExp(`id="${id}"[^>]*data-unified-select="single"`));
    }
    assert.match(template, /unified-select\.js\?v=20260822-3/);
    for (const locale of [zh, en]) {
        for (const key of ['searchOptions', 'noMatchingOptions', 'selectedOptions', 'openOptions']) {
            assert.equal(typeof locale.common[key], 'string', key);
            assert.ok(locale.common[key].trim(), key);
        }
    }
});
