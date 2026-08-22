const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..', '..', '..');
const template = fs.readFileSync(path.join(root, 'web/templates/index.html'), 'utf8');
const router = fs.readFileSync(path.join(root, 'web/static/js/router.js'), 'utf8');
const management = fs.readFileSync(path.join(root, 'web/static/js/container-management.js'), 'utf8');
const styles = fs.readFileSync(path.join(root, 'web/static/css/style.css'), 'utf8');
const zh = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/zh-CN.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/en-US.json'), 'utf8'));

const pageIDs = [
    'container-overview',
    'conversation-containers',
    'runtime-environments',
    'boundary-rules',
    'egress-proxies',
    'network-activity',
    'egress-audit',
];

test('容器管理侧栏包含 7 个独立子页且每页有自己的页头', () => {
    assert.match(template, /data-page="container-management"/);
    assert.match(template, /toggleSubmenu\('container-management'\)/);
    assert.equal((template.match(/data-page="(?:container-overview|conversation-containers|runtime-environments|boundary-rules|egress-proxies|network-activity|egress-audit)"/g) || []).length, 7);

    const titles = new Set();
    for (const pageID of pageIDs) {
        assert.match(template, new RegExp(`id="page-${pageID}"[^>]+data-container-management-page="${pageID}"`));
        const pageStart = template.indexOf(`id="page-${pageID}"`);
        const nextPage = template.indexOf('<div id="page-', pageStart + 1);
        const pageMarkup = template.slice(pageStart, nextPage < 0 ? undefined : nextPage);
        const title = pageMarkup.match(/class="container-management-page-title"[^>]*>([^<]+)<\/h2>/);
        assert.ok(title, `${pageID} 缺少独立页头`);
        titles.add(title[1]);
    }
    assert.equal(titles.size, 7);
    assert.match(template, /container-management\.js\?v=20260822-5/);
});

test('hash 路由把 7 个子页归入容器管理并初始化目标页', () => {
    assert.match(router, /\.\.\.\(window\.CONTAINER_MANAGEMENT_PAGES \|\| \[\]\)/);
    assert.match(router, /nav-item\[data-page="container-management"\]/);
    assert.match(router, /initContainerManagementPage\(pageId\)/);
    for (const pageID of pageIDs) {
        assert.match(router, new RegExp(`case '${pageID.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'`));
    }
});

test('容器管理初始化只标记当前独立页面', () => {
    const pages = new Map(pageIDs.map((id) => [id, {
        id: `page-${id}`,
        dataset: {},
        attributes: new Map(),
        setAttribute(name, value) { this.attributes.set(name, value); },
        removeAttribute(name) { this.attributes.delete(name); },
    }]));
    const context = {
        window: {},
        document: {
            getElementById(id) { return pages.get(String(id).replace(/^page-/, '')) || null; },
            querySelectorAll(selector) { return selector === '[data-container-management-page]' ? [...pages.values()] : []; },
        },
    };
    vm.runInNewContext(management, context);
    context.window.initContainerManagementPage('network-activity');
    assert.equal(context.window.currentContainerManagementPage, 'network-activity');
    assert.equal(pages.get('network-activity').attributes.get('aria-current'), 'page');
    assert.equal(pages.get('network-activity').dataset.initialized, 'true');
    for (const id of pageIDs.filter((item) => item !== 'network-activity')) {
        assert.equal(pages.get(id).attributes.has('aria-current'), false);
    }
});

test('中英文导航与页面文案完整且窄屏布局有明确规则', () => {
    const navKeys = ['containerManagement', 'containerOverview', 'conversationContainers', 'runtimeEnvironments', 'boundaryRules', 'egressProxies', 'networkActivity', 'egressAudit'];
    const contentKeys = ['overviewTitle', 'conversationsTitle', 'runtimesTitle', 'boundaryTitle', 'proxiesTitle', 'activityTitle', 'auditTitle', 'connectingData'];
    for (const locale of [zh, en]) {
        for (const key of navKeys) assert.equal(typeof locale.nav[key], 'string');
        for (const key of contentKeys) assert.equal(typeof locale.containerManagement[key], 'string');
    }
    assert.match(styles, /\.container-management-page\s*\{/);
    assert.match(styles, /\.container-management-page\s*\{[\s\S]*?overflow-y: auto/);
    assert.match(styles, /@media \(max-width: 760px\)[\s\S]*?\.container-management-surface\s*\{/);
    assert.match(styles, /body:has\(\.container-management-page\.active\) \.main-sidebar:not\(\.collapsed\)/);
    assert.match(router, /function syncContainerManagementSidebar\(pageId\)/);
    assert.match(router, /window\.matchMedia\('\(max-width: 760px\)'\)\.matches/);
    assert.match(router, /sidebar\.classList\.add\('collapsed'\)/);
    assert.match(router, /syncContainerManagementSidebar\(pageId\)/);
    assert.match(template, /style\.css\?v=20260822-9/);
    assert.match(template, /router\.js\?v=20260822-3/);
    assert.match(router, /popup\.style\.maxHeight = 'calc\(100vh - 16px\)'/);
    assert.match(router, /window\.innerHeight - popupRect\.height - viewportMargin/);
    assert.match(router, /popupItem\.setAttribute\('role', 'menuitem'\)/);
});

test('容器管理视图使用安全观测端点和服务端分页筛选', () => {
    for (const id of [
        'container-overview-summary', 'container-overview-runtime-list', 'conversation-containers-list',
        'conversation-container-detail', 'runtime-environments-list',
    ]) {
        assert.match(template, new RegExp(`id="${id}"`));
    }
    assert.match(management, /container-initialization\?observe=1/);
    assert.match(management, /\/api\/container-runtimes\?\$\{params\.toString\(\)\}/);
    assert.doesNotMatch(management, /\/api\/conversations\?limit=1000/);
    assert.doesNotMatch(management, /containerRuntimeMapConcurrent/);
    assert.match(management, /CONTAINER_RUNTIME_PAGE_SIZES = Object\.freeze\(\[10, 20, 50, 100\]\)/);
    assert.match(management, /document\.addEventListener\('languagechange',[\s\S]*?containerRuntimeLoadedMessage\(\)/);
    for (const key of ['container_page', 'container_page_size', 'container_search', 'container_status']) {
        assert.match(management, new RegExp(key));
    }
    for (const id of ['container-overview', 'conversation-containers', 'runtime-environments']) {
        assert.match(template, new RegExp(`id="${id}-search"[^>]+data-container-runtime-search`));
        assert.match(template, new RegExp(`id="${id}-status"[^>]+data-container-runtime-status`));
        assert.match(template, new RegExp(`id="${id}-page-size"[^>]+data-container-runtime-page-size`));
        assert.match(template, new RegExp(`id="${id}-pagination"`));
    }
    for (const size of [10, 20, 50, 100]) {
        assert.ok((template.match(new RegExp(`<option value="${size}"`, 'g')) || []).length >= 3);
    }
    assert.match(management, /policyDnsStatus/);
    assert.match(management, /workspaceStatus/);
    assert.match(management, /memoryUsageBytes/);
    assert.match(management, /boundarySnapshotSha256/);
    assert.match(management, /containerRuntimeLatestError/);
    assert.match(management, /interpolation: \{ escapeValue: false \}/);
    assert.doesNotMatch(management, /\.innerHTML\s*=/);
    for (const locale of [zh, en]) {
        for (const key of [
            'summaryContainers', 'agentContainer', 'egressGateway', 'policyDNS', 'workspace', 'latestError',
            'loadedRange', 'emptyFiltered', 'searchPlaceholder', 'statusFilter', 'rowsPerPage',
            'filterAll', 'filterNotRequested', 'filterPending', 'filterRunning', 'filterStopped',
            'filterFailed', 'paginationSummary', 'paginationPrevious', 'paginationNext',
        ]) {
            assert.equal(typeof locale.containerManagement[key], 'string');
        }
        assert.equal(typeof locale.containerManagement.status.running, 'string');
        assert.equal(typeof locale.containerManagement.status.failed, 'string');
    }
    assert.match(styles, /\.container-runtime-status-grid\s*\{/);
    assert.match(styles, /\.container-runtime-filter-bar\s*\{/);
    assert.match(styles, /\.container-runtime-pagination\s*\{/);
    assert.match(styles, /@media \(max-width: 760px\)[\s\S]*?\.container-runtime-status-grid/);
});
