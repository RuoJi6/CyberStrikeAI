(function () {
    'use strict';

    const views = ['proxies', 'groups'];
    const PAGE_SIZES = new Set([10, 20, 50]);
    const VIEW_META = Object.freeze({
        proxies: { title: '上游代理', description: '凭据仅以已配置状态显示，不返回原文。', resource: '代理名称', config: '出口地址', status: '凭据 / 状态', newLabel: '+  新建代理', editorTitle: '新建代理', editorDescription: '凭据原文保存后不会通过管理 API 或页面回显。' },
        groups: { title: '代理组', description: '按优先级和权重选择；全部成员不可用时失败关闭。', resource: '代理组名称', config: '成员 / 路由', status: '熔断 / 状态', newLabel: '+  新建代理组', editorTitle: '新建代理组', editorDescription: '至少选择一个代理成员，并设置优先级与权重。' },
    });
    const state = {
        bound: false, loading: false, loadRequestId: 0, detailRequestId: 0, searchTimer: null,
        view: 'proxies', page: 1, pageSize: 10, query: '', total: 0, totalPages: 0,
        proxies: [], proxyChoices: [], groups: [],
        selected: null, selectedView: '', error: '',
    };

    function t(key, fallback, values) {
        const fullKey = 'containerManagement.' + key;
        const params = values || {};
        let value = typeof window.t === 'function' ? window.t(fullKey, params) : fallback;
        if (!value || value === fullKey) value = fallback;
        return Object.keys(params).reduce(function (current, name) { return String(current).replaceAll('{{' + name + '}}', String(params[name])); }, String(value));
    }

    function node(tag, className, text) {
        const element = document.createElement(tag);
        if (className) element.className = className;
        if (text !== undefined && text !== null) element.textContent = String(text);
        return element;
    }

    function byId(id) { return document.getElementById(id); }

    function notify(message, type) {
        if (typeof window.showNotification === 'function') window.showNotification(message, type || 'info');
        else if (typeof window.showToast === 'function') window.showToast(message, type || 'info');
    }

    function formatDate(raw) {
        if (!raw) return '—';
        const date = new Date(raw);
        return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
    }

    async function requestJSON(path, options) {
        const response = typeof window.apiFetch === 'function' ? await window.apiFetch(path, options || {}) : await fetch(path, options || {});
        if (response.status === 204) return {};
        let payload = null;
        try { payload = await response.json(); } catch (_) { payload = null; }
        if (!response.ok) throw new Error(payload && payload.error ? payload.error : 'HTTP ' + response.status);
        return payload || {};
    }

    function jsonOptions(method, payload) { return { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }; }

    function readURL() {
        if (!window.location || typeof URLSearchParams === 'undefined') return;
        const params = new URLSearchParams(window.location.search || '');
        const view = String(params.get('egress_view') || 'proxies').trim();
        const page = Number.parseInt(params.get('egress_page'), 10);
        const pageSize = Number.parseInt(params.get('egress_page_size'), 10);
        state.view = views.includes(view) ? view : 'proxies';
        state.page = Number.isInteger(page) && page > 0 ? page : 1;
        state.pageSize = PAGE_SIZES.has(pageSize) ? pageSize : 10;
        state.query = Array.from(String(params.get('egress_q') || '')).slice(0, 200).join('');
    }

    function writeURL() {
        if (!window.location || !window.history || typeof URL === 'undefined') return;
        const url = new URL(window.location.href);
        const setOrDelete = function (key, value, fallback) { if (!value || value === fallback) url.searchParams.delete(key); else url.searchParams.set(key, String(value)); };
        setOrDelete('egress_view', state.view, 'proxies');
        setOrDelete('egress_page', state.page, 1);
        setOrDelete('egress_page_size', state.pageSize, 10);
        setOrDelete('egress_q', state.query, '');
        window.history.replaceState(window.history.state, '', url.toString());
    }

    function syncUnified(select) {
        if (!select || !window.CyberStrikeSelect) return;
        window.CyberStrikeSelect.enhance(select);
        window.CyberStrikeSelect.refresh(select);
    }

    function syncControls() {
        const search = byId('egress-resource-search');
        const pageSize = byId('egress-resource-page-size');
        if (search) search.value = state.query;
        if (pageSize) { pageSize.value = String(state.pageSize); syncUnified(pageSize); }
    }

    function setPhase(message, mode) {
        const status = byId('egress-management-load-state');
        if (status) { status.textContent = message || ''; status.classList.toggle('is-error', mode === 'error'); }
        const phase = byId('egress-management-phase');
        if (phase) {
            phase.textContent = mode === 'error' ? t('egressLoadFailed', '出口配置加载失败') : mode === 'ready' ? t('egressReady', '出口配置已加载') : t('egressLoading', '正在加载出口配置…');
            phase.classList.toggle('is-error', mode === 'error');
            phase.classList.toggle('is-ready', mode === 'ready');
        }
    }

    function badge(enabled, configured) {
        const label = enabled === false ? t('disabled', '已停用') : t('enabled', '已启用');
        const value = node('span', 'container-runtime-badge is-' + (enabled === false ? 'neutral' : 'success'), label);
        if (configured === true) value.title = t('credentialsConfigured', '凭据已配置且原文不可见');
        return value;
    }

    function actionButton(label, className, handler) {
        const button = node('button', className || 'btn-secondary', label);
        button.type = 'button';
        button.addEventListener('click', function (event) { event.stopPropagation(); handler(); });
        return button;
    }

    function empty(title, description) {
        const root = node('div', 'container-policy-empty');
        root.append(node('strong', '', title), node('p', '', description || ''));
        return root;
    }

    function currentSource() {
        if (state.view === 'groups') return state.groups;
        return state.proxies;
    }

    function matches(item) {
        const query = state.query.trim().toLocaleLowerCase();
        if (!query) return true;
        let fields = [];
        if (state.view === 'proxies') fields = [item.name, item.protocol, item.host, item.port];
        else fields = [item.name, item.failureThreshold, item.cooldownSeconds].concat((item.members || []).flatMap(function (member) { return [member.proxyId, member.proxy && member.proxy.name, member.proxy && member.proxy.host]; }));
        return fields.some(function (value) { return String(value || '').toLocaleLowerCase().includes(query); });
    }

    function currentItems() {
        if (state.view === 'proxies') return state.proxies;
        const filtered = currentSource().filter(matches);
        return filtered.slice((state.page - 1) * state.pageSize, state.page * state.pageSize);
    }

    function localTotal() { return state.view === 'proxies' ? state.total : currentSource().filter(matches).length; }

    function rowShell(item, identityTitle, identityDescription, configTitle, configDescription, statusDescription) {
        const row = node('article', 'egress-resource-row');
        row.setAttribute('role', 'listitem'); row.tabIndex = 0;
        const identity = node('div', 'egress-resource-row-identity');
        identity.append(node('strong', '', identityTitle), node('p', '', identityDescription));
        const config = node('div', 'egress-resource-row-value');
        config.append(node('strong', '', configTitle), node('small', '', configDescription));
        const status = node('div', 'egress-resource-row-value');
        status.append(badge(item.enabled, item.credentialsConfigured), node('small', '', statusDescription));
        const updated = node('time', 'egress-resource-row-time', formatDate(item.updatedAt));
        const actions = node('div', 'egress-resource-row-actions');
        actions.append(
            actionButton('查看', 'btn-secondary btn-small', function () { openDetail(state.view, item.id); }),
            actionButton('修改', 'btn-secondary btn-small', function () { openEditor(state.view, item); }),
            actionButton('删除', 'btn-danger btn-small', function () { deleteResource(state.view, item); }),
        );
        row.addEventListener('click', function () { openDetail(state.view, item.id); });
        row.addEventListener('keydown', function (event) { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openDetail(state.view, item.id); } });
        row.append(identity, config, status, updated, actions);
        return row;
    }

    function renderList() {
        const roots = { proxies: byId('egress-proxy-list'), groups: byId('egress-group-list') };
        Object.values(roots).forEach(function (root) { if (root) root.replaceChildren(); });
        const root = roots[state.view];
        if (!root) return;
        const items = currentItems();
        if (!items.length) { root.append(empty(state.query ? '没有符合检索条件的配置' : '暂无' + VIEW_META[state.view].title, state.query ? '请调整检索条件。' : '点击右上角的新建按钮开始配置。')); return; }
        const selectable = new Set(state.proxyChoices.filter(function (proxy) { return proxy.enabled !== false; }).map(function (proxy) { return proxy.id; }));
        items.forEach(function (item) {
            if (state.view === 'proxies') {
                root.append(rowShell(item, item.name || item.id, item.credentialsConfigured ? '凭据已安全保存' : '未配置凭据', String(item.protocol || '').toUpperCase() + ' · ' + String(item.host || '') + ':' + String(item.port || ''), '连接由独立出站网关转发', item.credentialsConfigured ? '凭据已配置' : '无凭据'));
            } else if (state.view === 'groups') {
                const members = Array.isArray(item.members) ? item.members : [];
                const healthy = members.filter(function (member) { return member.enabled !== false && member.status !== 'cooldown' && selectable.has(member.proxyId); }).length;
                root.append(rowShell(item, item.name || item.id, '全部成员不可用时失败关闭', members.length + ' 个成员 · ' + healthy + ' 个可选', '阈值 ' + item.failureThreshold + ' · 冷却 ' + item.cooldownSeconds + ' 秒', healthy ? '路由可用' : '无可选成员'));
            }
        });
    }

    function renderPagination() {
        const root = byId('egress-resource-pagination');
        if (!root) return;
        root.replaceChildren();
        const total = localTotal();
        const pages = Math.max(1, Math.ceil(total / state.pageSize));
        state.totalPages = total ? pages : 0;
        const previous = actionButton('上一页', 'btn-secondary', function () { setPage(state.page - 1); });
        previous.disabled = state.loading || state.page <= 1 || total === 0;
        const label = node('span', 'container-runtime-page-summary', '第 ' + state.page + ' / ' + pages + ' 页，共 ' + total + ' 个' + VIEW_META[state.view].title);
        const next = actionButton('下一页', 'btn-secondary', function () { setPage(state.page + 1); });
        next.disabled = state.loading || state.page >= pages || total === 0;
        root.append(previous, label, next);
    }

    function renderChrome() {
        const meta = VIEW_META[state.view];
        byId('egress-catalog-title').textContent = meta.title;
        byId('egress-catalog-description').textContent = meta.description;
        byId('egress-column-resource').textContent = meta.resource;
        byId('egress-column-config').textContent = meta.config;
        byId('egress-column-status').textContent = meta.status;
        byId('egress-resource-new').textContent = meta.newLabel;
        document.querySelectorAll('[data-egress-view]').forEach(function (button) { const selected = button.dataset.egressView === state.view; button.classList.toggle('is-active', selected); button.setAttribute('aria-selected', selected ? 'true' : 'false'); });
        document.querySelectorAll('[data-egress-panel]').forEach(function (panel) { const selected = panel.dataset.egressPanel === state.view; panel.hidden = !selected; panel.classList.toggle('is-active', selected); });
    }

    function renderAll() { renderChrome(); renderList(); renderPagination(); }

    function setPage(page) {
        const pages = Math.max(1, state.totalPages || 1);
        state.page = Math.min(Math.max(1, Number.parseInt(page, 10) || 1), pages);
        writeURL();
        if (state.view === 'proxies') refresh(false); else renderAll();
    }

    function selectView(view, reload) {
        const next = views.includes(view) ? view : 'proxies';
        const changed = state.view !== next;
        state.view = next;
        if (changed) { state.page = 1; state.query = ''; syncControls(); }
        writeURL(); renderAll();
        if (reload) refresh(false);
    }

    function detailPair(label, value) {
        const wrapper = node('div', 'container-runtime-detail-item');
        wrapper.append(node('dt', '', label), node('dd', '', value === undefined || value === null || value === '' ? '—' : value));
        return wrapper;
    }

    function renderDetail() {
        const item = state.selected;
        const body = byId('egress-resource-detail-body');
        if (!body || !item) return;
        body.replaceChildren();
        byId('egress-resource-detail-title').textContent = item.name || item.id;
        byId('egress-resource-detail-kicker').textContent = VIEW_META[state.selectedView].title + '详情';
        const section = node('section', 'boundary-policy-detail-section');
        const grid = node('dl', 'boundary-policy-detail-metadata egress-resource-detail-grid');
        if (state.selectedView === 'proxies') {
            grid.append(detailPair('协议', String(item.protocol || '').toUpperCase()), detailPair('地址', String(item.host || '') + ':' + String(item.port || '')), detailPair('状态', item.enabled === false ? '已停用' : '已启用'), detailPair('凭据', item.credentialsConfigured ? '已配置' : '无凭据'), detailPair('凭据更新时间', formatDate(item.credentialUpdatedAt)), detailPair('配置 ID', item.id));
        } else if (state.selectedView === 'groups') {
            grid.append(detailPair('状态', item.enabled === false ? '已停用' : '已启用'), detailPair('失败策略', item.failClosed === false ? '允许回退' : '失败关闭'), detailPair('失败阈值', item.failureThreshold), detailPair('冷却时间', item.cooldownSeconds + ' 秒'), detailPair('成员数量', Array.isArray(item.members) ? item.members.length : 0), detailPair('配置 ID', item.id));
        }
        section.append(grid); body.append(section);
        if (state.selectedView === 'groups' && Array.isArray(item.members) && item.members.length) {
            const members = node('section', 'boundary-policy-detail-section');
            const heading = node('div', 'boundary-policy-detail-section-heading');
            heading.append(node('h4', '', '代理成员'), node('span', '', item.members.length + ' 个'));
            const list = node('div', 'boundary-policy-usage-list');
            item.members.forEach(function (member) { const card = node('article', 'boundary-policy-usage-card'); const name = member.proxy && member.proxy.name ? member.proxy.name : member.proxyId; card.append(node('strong', '', name), node('p', 'boundary-policy-detail-description', '优先级 ' + member.priority + ' · 权重 ' + member.weight + ' · ' + (member.status || 'unknown'))); list.append(card); });
            members.append(heading, list); body.append(members);
        }
    }

    function showDrawer() {
        const drawer = byId('egress-resource-detail-drawer'); const backdrop = byId('egress-resource-detail-backdrop');
        if (drawer) { drawer.hidden = false; drawer.setAttribute('aria-hidden', 'false'); }
        if (backdrop) backdrop.hidden = false;
        document.body.classList.add('boundary-policy-overlay-open');
    }

    function closeDrawer() {
        const drawer = byId('egress-resource-detail-drawer'); const backdrop = byId('egress-resource-detail-backdrop');
        if (drawer) { drawer.hidden = true; drawer.setAttribute('aria-hidden', 'true'); }
        if (backdrop) backdrop.hidden = true;
        if (byId('egress-resource-editor-modal')?.hidden !== false) document.body.classList.remove('boundary-policy-overlay-open');
    }

    function endpointFor(view) { return view === 'groups' ? '/api/egress-proxy-groups' : '/api/egress-proxies'; }

    async function openDetail(view, id) {
        state.selectedView = views.includes(view) ? view : 'proxies'; state.selected = null; showDrawer();
        const body = byId('egress-resource-detail-body'); if (body) body.replaceChildren(empty('正在读取配置详情…', ''));
        const requestId = ++state.detailRequestId;
        try { const item = await requestJSON(endpointFor(state.selectedView) + '/' + encodeURIComponent(id)); if (requestId !== state.detailRequestId) return; state.selected = item; renderDetail(); }
        catch (error) { if (body) body.replaceChildren(empty('读取配置详情失败', error.message || '')); }
    }

    function showEditor(view, editing) {
        state.selectedView = view;
        const modal = byId('egress-resource-editor-modal'); if (modal) modal.hidden = false;
        ['proxies', 'groups'].forEach(function (name) { const form = byId(name === 'proxies' ? 'egress-proxy-form' : 'egress-group-form'); if (form) form.hidden = name !== view; });
        const meta = VIEW_META[view];
        byId('egress-resource-editor-title').textContent = editing ? '修改' + meta.title.replace('上游', '') : meta.editorTitle;
        byId('egress-resource-editor-description').textContent = meta.editorDescription;
        document.body.classList.add('boundary-policy-overlay-open');
    }

    function closeEditor() {
        const modal = byId('egress-resource-editor-modal'); if (modal) modal.hidden = true;
        if (byId('egress-resource-detail-drawer')?.hidden !== false) document.body.classList.remove('boundary-policy-overlay-open');
    }

    function resetProxyForm() {
        byId('egress-proxy-form').reset(); byId('egress-proxy-id').value = ''; byId('egress-proxy-port').value = '8080'; byId('egress-proxy-enabled').checked = true;
        byId('egress-proxy-clear-field').hidden = true; byId('egress-proxy-clear-credentials').checked = false;
    }

    function editProxy(proxy) {
        resetProxyForm();
        byId('egress-proxy-id').value = proxy.id || ''; byId('egress-proxy-name').value = proxy.name || ''; byId('egress-proxy-protocol').value = proxy.protocol || 'http';
        byId('egress-proxy-host').value = proxy.host || ''; byId('egress-proxy-port').value = String(proxy.port || 8080); byId('egress-proxy-enabled').checked = proxy.enabled !== false;
        byId('egress-proxy-clear-field').hidden = !proxy.credentialsConfigured; showEditor('proxies', true); byId('egress-proxy-name').focus();
    }

    async function saveProxy(event) {
        event.preventDefault();
        const id = String(byId('egress-proxy-id').value || '').trim();
        const payload = { name: byId('egress-proxy-name').value, protocol: byId('egress-proxy-protocol').value, host: byId('egress-proxy-host').value, port: Number(byId('egress-proxy-port').value), enabled: byId('egress-proxy-enabled').checked };
        const clear = byId('egress-proxy-clear-credentials').checked; const username = byId('egress-proxy-username').value.trim(); const password = byId('egress-proxy-password').value;
        if (clear) payload.credentials = null; else if (username) payload.credentials = { username: username, password: password }; else if (password) { notify(t('proxyUsernameRequired', '填写密码时必须同时填写用户名'), 'error'); return; }
        try { await requestJSON('/api/egress-proxies' + (id ? '/' + encodeURIComponent(id) : ''), jsonOptions(id ? 'PUT' : 'POST', payload)); notify(id ? t('proxyUpdated', '代理已更新') : t('proxyCreated', '代理已创建'), 'success'); closeEditor(); closeDrawer(); await refresh(true); }
        catch (error) { notify(error.message, 'error'); }
    }

    function memberValues() {
        const values = new Map();
        document.querySelectorAll('#egress-group-members [data-proxy-id]').forEach(function (row) { values.set(row.dataset.proxyId, { checked: row.querySelector('[data-member-enabled]').checked, priority: Number(row.querySelector('[data-member-priority]').value || 0), weight: Number(row.querySelector('[data-member-weight]').value || 1) }); });
        return values;
    }

    function renderGroupMembers(preferred) {
        const root = byId('egress-group-members'); if (!root) return;
        const existing = preferred instanceof Map ? preferred : memberValues(); const proxies = state.proxyChoices.length ? state.proxyChoices : state.proxies;
        root.replaceChildren();
        if (!proxies.length) { root.append(empty(t('groupNeedsProxy', '请先创建至少一个代理'), '')); return; }
        proxies.forEach(function (proxy) {
            const current = existing.get(proxy.id) || { checked: false, priority: 0, weight: 1 }; const row = node('div', 'egress-group-member'); row.dataset.proxyId = proxy.id;
            const choice = node('label', 'egress-group-member-choice'); const checkbox = node('input'); checkbox.type = 'checkbox'; checkbox.dataset.memberEnabled = '1'; checkbox.checked = !!current.checked;
            choice.append(checkbox, node('span', '', proxy.name || proxy.id), node('small', '', String(proxy.protocol || '').toUpperCase() + ' · ' + proxy.host + ':' + proxy.port));
            const priorityLabel = node('label'); priorityLabel.append(node('span', '', t('priority', '优先级'))); const priority = node('input'); priority.type = 'number'; priority.min = '0'; priority.max = '1000000'; priority.value = String(current.priority); priority.dataset.memberPriority = '1'; priority.disabled = !checkbox.checked; priorityLabel.append(priority);
            const weightLabel = node('label'); weightLabel.append(node('span', '', t('weight', '权重'))); const weight = node('input'); weight.type = 'number'; weight.min = '1'; weight.max = '1000'; weight.value = String(current.weight || 1); weight.dataset.memberWeight = '1'; weight.disabled = !checkbox.checked; weightLabel.append(weight);
            checkbox.addEventListener('change', function () { priority.disabled = !checkbox.checked; weight.disabled = !checkbox.checked; }); row.append(choice, priorityLabel, weightLabel); root.append(row);
        });
    }

    function resetGroupForm() { byId('egress-group-form').reset(); byId('egress-group-id').value = ''; byId('egress-group-threshold').value = '3'; byId('egress-group-cooldown').value = '60'; byId('egress-group-enabled').checked = true; renderGroupMembers(new Map()); }

    function editGroup(group) {
        resetGroupForm(); byId('egress-group-id').value = group.id || ''; byId('egress-group-name').value = group.name || ''; byId('egress-group-threshold').value = String(group.failureThreshold || 3); byId('egress-group-cooldown').value = String(group.cooldownSeconds || 60); byId('egress-group-enabled').checked = group.enabled !== false;
        const preferred = new Map(); (Array.isArray(group.members) ? group.members : []).forEach(function (member) { preferred.set(member.proxyId, { checked: member.enabled !== false, priority: member.priority || 0, weight: member.weight || 1 }); });
        renderGroupMembers(preferred); showEditor('groups', true); byId('egress-group-name').focus();
    }

    async function saveGroup(event) {
        event.preventDefault(); const id = String(byId('egress-group-id').value || '').trim(); const members = [];
        document.querySelectorAll('#egress-group-members [data-proxy-id]').forEach(function (row) { if (row.querySelector('[data-member-enabled]').checked) members.push({ proxyId: row.dataset.proxyId, priority: Number(row.querySelector('[data-member-priority]').value), weight: Number(row.querySelector('[data-member-weight]').value), enabled: true }); });
        if (!members.length) { notify(t('groupMemberRequired', '代理组至少需要一个成员'), 'error'); return; }
        const payload = { name: byId('egress-group-name').value, enabled: byId('egress-group-enabled').checked, failureThreshold: Number(byId('egress-group-threshold').value), cooldownSeconds: Number(byId('egress-group-cooldown').value), members: members };
        try { await requestJSON('/api/egress-proxy-groups' + (id ? '/' + encodeURIComponent(id) : ''), jsonOptions(id ? 'PUT' : 'POST', payload)); notify(id ? t('groupUpdated', '代理组已更新') : t('groupCreated', '代理组已创建'), 'success'); closeEditor(); closeDrawer(); await refresh(true); }
        catch (error) { notify(error.message, 'error'); }
    }

    function openEditor(view, item) {
        if (view === 'groups') { if (item) editGroup(item); else { resetGroupForm(); showEditor('groups', false); byId('egress-group-name').focus(); } return; }
        if (item) editProxy(item); else { resetProxyForm(); showEditor('proxies', false); byId('egress-proxy-name').focus(); }
    }

    async function deleteResource(view, item) {
        if (!window.confirm('确定删除“' + String(item.name || item.id) + '”吗？')) return;
        try { await requestJSON(endpointFor(view) + '/' + encodeURIComponent(item.id), { method: 'DELETE' }); notify('配置已删除', 'success'); closeDrawer(); await refresh(true); }
        catch (error) { notify(error.message, 'error'); }
    }

    async function refresh(forceConversationChoices) {
        state.loading = true; const requestId = ++state.loadRequestId; setPhase(t('egressLoading', '正在加载出口配置…'), 'loading');
        const refreshButton = byId('egress-management-refresh'); if (refreshButton) refreshButton.disabled = true;
        try {
            const proxyParams = new URLSearchParams();
            if (state.view === 'proxies' && state.query) proxyParams.set('search', state.query);
            proxyParams.set('limit', String(state.view === 'proxies' ? state.pageSize : 100));
            proxyParams.set('offset', String(state.view === 'proxies' ? (state.page - 1) * state.pageSize : 0));
            const results = await Promise.all([requestJSON('/api/egress-proxies?' + proxyParams.toString()), requestJSON('/api/egress-proxy-groups')]);
            if (requestId !== state.loadRequestId) return;
            const proxyItems = Array.isArray(results[0].items) ? results[0].items : [];
            if (state.view === 'proxies') { state.proxies = proxyItems; state.total = Math.max(0, Number(results[0].total || 0)); } else state.proxyChoices = proxyItems;
            state.groups = Array.isArray(results[1].items) ? results[1].items : [];
            if (state.view !== 'proxies') state.total = localTotal();
            const pages = Math.max(1, Math.ceil(state.total / state.pageSize));
            if (state.total > 0 && state.page > pages) { state.page = pages; writeURL(); state.loading = false; return refresh(forceConversationChoices); }
            state.error = ''; renderAll(); setPhase('已加载 ' + state.total + ' 个' + VIEW_META[state.view].title, 'ready');
            if (forceConversationChoices && typeof window.loadConversationContainerChoices === 'function') window.loadConversationContainerChoices(true);
        } catch (error) {
            if (requestId !== state.loadRequestId) return;
            state.error = error && error.message ? error.message : t('egressLoadFailed', '出口配置加载失败'); setPhase(state.error, 'error'); renderAll();
        } finally {
            if (requestId === state.loadRequestId) state.loading = false;
            if (refreshButton) refreshButton.disabled = false;
        }
    }

    function bind() {
        if (state.bound) return; state.bound = true;
        document.querySelectorAll('[data-egress-view]').forEach(function (button) { button.addEventListener('click', function () { selectView(button.dataset.egressView, true); }); });
        byId('egress-management-refresh').addEventListener('click', function () { refresh(false); });
        byId('egress-resource-new').addEventListener('click', function () { openEditor(state.view, null); });
        byId('egress-resource-search').addEventListener('input', function (event) { if (state.searchTimer) window.clearTimeout(state.searchTimer); state.searchTimer = window.setTimeout(function () { state.query = Array.from(event.target.value || '').slice(0, 200).join(''); state.page = 1; writeURL(); refresh(false); }, 250); });
        byId('egress-resource-page-size').addEventListener('change', function (event) { const value = Number.parseInt(event.target.value, 10); state.pageSize = PAGE_SIZES.has(value) ? value : 10; state.page = 1; writeURL(); refresh(false); });
        byId('egress-resource-detail-close').addEventListener('click', closeDrawer); byId('egress-resource-detail-backdrop').addEventListener('click', closeDrawer);
        byId('egress-resource-detail-edit').addEventListener('click', function () { if (state.selected) openEditor(state.selectedView, state.selected); });
        byId('egress-resource-detail-delete').addEventListener('click', function () { if (state.selected) deleteResource(state.selectedView, state.selected); });
        byId('egress-resource-editor-close').addEventListener('click', closeEditor);
        byId('egress-proxy-cancel').addEventListener('click', closeEditor); byId('egress-proxy-form').addEventListener('submit', saveProxy);
        byId('egress-group-cancel').addEventListener('click', closeEditor); byId('egress-group-form').addEventListener('submit', saveGroup);
        document.addEventListener('keydown', function (event) { if (event.key !== 'Escape') return; if (byId('egress-resource-editor-modal')?.hidden === false) closeEditor(); else if (byId('egress-resource-detail-drawer')?.hidden === false) closeDrawer(); });
        document.addEventListener('languagechange', function () { renderAll(); });
    }

    function init() { readURL(); bind(); syncControls(); renderAll(); writeURL(); refresh(false); }

    window.initEgressManagementPage = init;
    window.refreshEgressManagementPage = function () { return refresh(false); };
}());
