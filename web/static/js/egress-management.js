(function () {
    'use strict';

    const views = ['proxies', 'groups', 'auth'];
    const state = {
        bound: false,
        loading: false,
        requestId: 0,
        view: 'proxies',
        proxies: [],
        groups: [],
        authProfiles: [],
        proxySearch: '',
        error: '',
    };

    function t(key, fallback, values) {
        const fullKey = 'containerManagement.' + key;
        const params = values || {};
        let value = typeof window.t === 'function' ? window.t(fullKey, params) : fallback;
        if (!value || value === fullKey) value = fallback;
        return Object.keys(params).reduce(function (current, name) {
            return String(current).replaceAll('{{' + name + '}}', String(params[name]));
        }, String(value));
    }

    function node(tag, className, text) {
        const element = document.createElement(tag);
        if (className) element.className = className;
        if (text !== undefined && text !== null) element.textContent = String(text);
        return element;
    }

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
        const response = typeof window.apiFetch === 'function'
            ? await window.apiFetch(path, options || {})
            : await fetch(path, options || {});
        if (response.status === 204) return {};
        let payload = null;
        try { payload = await response.json(); } catch (_) { payload = null; }
        if (!response.ok) throw new Error(payload && payload.error ? payload.error : 'HTTP ' + response.status);
        return payload || {};
    }

    function jsonOptions(method, payload) {
        return { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) };
    }

    function readView() {
        if (!window.location || typeof URLSearchParams === 'undefined') return 'proxies';
        const value = String(new URLSearchParams(window.location.search || '').get('egress_view') || '').trim();
        return views.includes(value) ? value : 'proxies';
    }

    function writeView() {
        if (!window.location || !window.history || typeof URL === 'undefined') return;
        const url = new URL(window.location.href);
        url.searchParams.set('egress_view', state.view);
        window.history.replaceState(window.history.state, '', url.toString());
    }

    function setPhase(message, mode) {
        const status = document.getElementById('egress-management-load-state');
        if (status) {
            status.textContent = message || '';
            status.classList.toggle('is-error', mode === 'error');
        }
        const phase = document.getElementById('egress-management-phase');
        if (phase) {
            phase.textContent = mode === 'error'
                ? t('egressLoadFailed', '出口配置加载失败')
                : mode === 'ready'
                    ? t('egressReady', '出口配置已加载')
                    : t('egressLoading', '正在加载出口配置…');
            phase.classList.toggle('is-error', mode === 'error');
            phase.classList.toggle('is-ready', mode === 'ready');
        }
    }

    function summaryCard(label, value, tone) {
        const card = node('article', 'container-runtime-summary-card is-' + (tone || 'neutral'));
        card.append(node('span', 'container-runtime-summary-label', label), node('strong', 'container-runtime-summary-value', value));
        return card;
    }

    function renderSummary() {
        const root = document.getElementById('egress-management-summary');
        if (!root) return;
        const enabledProxies = state.proxies.filter(function (item) { return item.enabled !== false; }).length;
        const enabledGroups = state.groups.filter(function (item) { return item.enabled !== false; }).length;
        const enabledAuth = state.authProfiles.filter(function (item) { return item.enabled !== false; }).length;
        const openCircuits = state.groups.reduce(function (count, group) {
            return count + (Array.isArray(group.members) ? group.members.filter(function (member) { return member.status === 'cooldown'; }).length : 0);
        }, 0);
        root.replaceChildren(
            summaryCard(t('egressProxyCount', '代理'), state.proxies.length + ' / ' + enabledProxies + ' ' + t('enabledShort', '启用'), enabledProxies ? 'success' : 'neutral'),
            summaryCard(t('egressGroupCount', '代理组'), state.groups.length + ' / ' + enabledGroups + ' ' + t('enabledShort', '启用'), enabledGroups ? 'success' : 'neutral'),
            summaryCard(t('egressAuthCount', '凭据档案'), state.authProfiles.length + ' / ' + enabledAuth + ' ' + t('enabledShort', '启用'), enabledAuth ? 'success' : 'neutral'),
            summaryCard(t('egressCircuitCount', '冷却成员'), openCircuits, openCircuits ? 'danger' : 'success'),
        );
    }

    function empty(message) {
        const root = node('div', 'egress-resource-empty');
        root.append(node('span', '', '⇄'), node('p', '', message));
        return root;
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
        button.addEventListener('click', handler);
        return button;
    }

    function resourceCard(title, subtitle, enabled, configured, editHandler, deleteHandler) {
        const card = node('article', 'egress-resource-card');
        const main = node('div', 'egress-resource-card-main');
        const heading = node('div', 'egress-resource-card-heading');
        heading.append(node('strong', '', title), badge(enabled, configured));
        main.append(heading, node('p', '', subtitle));
        const actions = node('div', 'egress-resource-actions');
        actions.append(
            actionButton(t('edit', '编辑'), 'btn-secondary btn-small', editHandler),
            actionButton(t('delete', '删除'), 'btn-danger btn-small', deleteHandler),
        );
        card.append(main, actions);
        return card;
    }

    function filteredProxies() {
        const query = state.proxySearch.trim().toLocaleLowerCase();
        if (!query) return state.proxies;
        return state.proxies.filter(function (item) {
            return [item.name, item.protocol, item.host, item.port].some(function (value) {
                return String(value || '').toLocaleLowerCase().includes(query);
            });
        });
    }

    function renderProxyList() {
        const root = document.getElementById('egress-proxy-list');
        if (!root) return;
        root.replaceChildren();
        const proxies = filteredProxies();
        if (!proxies.length) {
            root.append(empty(state.proxySearch ? t('proxySearchEmpty', '没有符合搜索条件的代理') : t('proxyEmpty', '暂无上游代理')));
            return;
        }
        proxies.forEach(function (proxy) {
            const endpoint = String(proxy.protocol || '').toUpperCase() + ' · ' + String(proxy.host || '') + ':' + String(proxy.port || '');
            const credential = proxy.credentialsConfigured ? ' · ' + t('credentialsConfigured', '凭据已配置') : ' · ' + t('credentialsNone', '无凭据');
            root.append(resourceCard(proxy.name || proxy.id, endpoint + credential + ' · ' + formatDate(proxy.updatedAt), proxy.enabled, proxy.credentialsConfigured,
                function () { editProxy(proxy); }, function () { deleteProxy(proxy); }));
        });
    }

    function renderGroupList() {
        const root = document.getElementById('egress-group-list');
        if (!root) return;
        root.replaceChildren();
        if (!state.groups.length) {
            root.append(empty(t('groupEmpty', '暂无代理组')));
            return;
        }
        const selectableProxyIds = new Set(state.proxies.filter(function (proxy) { return proxy.enabled !== false; }).map(function (proxy) { return proxy.id; }));
        state.groups.forEach(function (group) {
            const members = Array.isArray(group.members) ? group.members : [];
            const healthy = members.filter(function (member) {
                return member.enabled !== false && member.status !== 'cooldown' && selectableProxyIds.has(member.proxyId);
            }).length;
            const subtitle = t('groupSummary', '{{members}} 个成员 · {{healthy}} 个可选 · 阈值 {{threshold}} · 冷却 {{cooldown}} 秒', {
                members: members.length, healthy: healthy, threshold: group.failureThreshold, cooldown: group.cooldownSeconds,
            });
            root.append(resourceCard(group.name || group.id, subtitle, group.enabled, false,
                function () { editGroup(group); }, function () { deleteGroup(group); }));
        });
    }

    function renderAuthList() {
        const root = document.getElementById('egress-auth-list');
        if (!root) return;
        root.replaceChildren();
        if (!state.authProfiles.length) {
            root.append(empty(t('authEmpty', '暂无凭据档案')));
            return;
        }
        state.authProfiles.forEach(function (profile) {
            const subtitle = String(profile.headerName || '—') + ' · ' + (profile.credentialsConfigured ? t('credentialsConfigured', '凭据已配置') : t('credentialsNone', '无凭据')) + ' · ' + formatDate(profile.updatedAt);
            root.append(resourceCard(profile.name || profile.id, subtitle, profile.enabled, profile.credentialsConfigured,
                function () { editAuth(profile); }, function () { deleteAuth(profile); }));
        });
    }

    function renderAll() {
        renderSummary();
        renderProxyList();
        renderGroupList();
        renderAuthList();
        renderGroupMembers();
    }

    function selectView(view) {
        state.view = views.includes(view) ? view : 'proxies';
        document.querySelectorAll('[data-egress-view]').forEach(function (button) {
            const selected = button.dataset.egressView === state.view;
            button.classList.toggle('is-active', selected);
            button.setAttribute('aria-selected', selected ? 'true' : 'false');
        });
        document.querySelectorAll('[data-egress-panel]').forEach(function (panel) {
            const selected = panel.dataset.egressPanel === state.view;
            panel.hidden = !selected;
            panel.classList.toggle('is-active', selected);
        });
        writeView();
    }

    function resetProxyForm() {
        document.getElementById('egress-proxy-form').reset();
        document.getElementById('egress-proxy-id').value = '';
        document.getElementById('egress-proxy-port').value = '8080';
        document.getElementById('egress-proxy-enabled').checked = true;
        document.getElementById('egress-proxy-clear-field').hidden = true;
        document.getElementById('egress-proxy-clear-credentials').checked = false;
        document.getElementById('egress-proxy-form-title').textContent = t('createProxy', '新建代理');
    }

    function editProxy(proxy) {
        selectView('proxies');
        document.getElementById('egress-proxy-id').value = proxy.id || '';
        document.getElementById('egress-proxy-name').value = proxy.name || '';
        document.getElementById('egress-proxy-protocol').value = proxy.protocol || 'http';
        document.getElementById('egress-proxy-host').value = proxy.host || '';
        document.getElementById('egress-proxy-port').value = String(proxy.port || 8080);
        document.getElementById('egress-proxy-enabled').checked = proxy.enabled !== false;
        document.getElementById('egress-proxy-username').value = '';
        document.getElementById('egress-proxy-password').value = '';
        document.getElementById('egress-proxy-clear-field').hidden = !proxy.credentialsConfigured;
        document.getElementById('egress-proxy-clear-credentials').checked = false;
        document.getElementById('egress-proxy-form-title').textContent = t('editProxy', '编辑代理');
        document.getElementById('egress-proxy-name').focus();
    }

    async function saveProxy(event) {
        event.preventDefault();
        const id = String(document.getElementById('egress-proxy-id').value || '').trim();
        const payload = {
            name: document.getElementById('egress-proxy-name').value,
            protocol: document.getElementById('egress-proxy-protocol').value,
            host: document.getElementById('egress-proxy-host').value,
            port: Number(document.getElementById('egress-proxy-port').value),
            enabled: document.getElementById('egress-proxy-enabled').checked,
        };
        const clear = document.getElementById('egress-proxy-clear-credentials').checked;
        const username = document.getElementById('egress-proxy-username').value.trim();
        const password = document.getElementById('egress-proxy-password').value;
        if (clear) payload.credentials = null;
        else if (username) payload.credentials = { username: username, password: password };
        else if (password) {
            notify(t('proxyUsernameRequired', '填写密码时必须同时填写用户名'), 'error');
            return;
        }
        try {
            await requestJSON('/api/egress-proxies' + (id ? '/' + encodeURIComponent(id) : ''), jsonOptions(id ? 'PUT' : 'POST', payload));
            notify(id ? t('proxyUpdated', '代理已更新') : t('proxyCreated', '代理已创建'), 'success');
            resetProxyForm();
            await refresh(true);
        } catch (error) { notify(error.message, 'error'); }
    }

    async function deleteProxy(proxy) {
        if (!window.confirm(t('proxyDeleteConfirm', '确定删除代理“{{name}}”吗？', { name: proxy.name || proxy.id }))) return;
        try {
            await requestJSON('/api/egress-proxies/' + encodeURIComponent(proxy.id), { method: 'DELETE' });
            notify(t('proxyDeleted', '代理已删除'), 'success');
            resetProxyForm();
            await refresh(true);
        } catch (error) { notify(error.message, 'error'); }
    }

    function memberValues() {
        const values = new Map();
        document.querySelectorAll('#egress-group-members [data-proxy-id]').forEach(function (row) {
            values.set(row.dataset.proxyId, {
                checked: row.querySelector('[data-member-enabled]').checked,
                priority: Number(row.querySelector('[data-member-priority]').value || 0),
                weight: Number(row.querySelector('[data-member-weight]').value || 1),
            });
        });
        return values;
    }

    function renderGroupMembers(preferred) {
        const root = document.getElementById('egress-group-members');
        if (!root) return;
        const existing = preferred instanceof Map ? preferred : memberValues();
        root.replaceChildren();
        if (!state.proxies.length) {
            root.append(empty(t('groupNeedsProxy', '请先创建至少一个代理')));
            return;
        }
        state.proxies.forEach(function (proxy) {
            const current = existing.get(proxy.id) || { checked: false, priority: 0, weight: 1 };
            const row = node('div', 'egress-group-member');
            row.dataset.proxyId = proxy.id;
            const enabledLabel = node('label', 'egress-group-member-choice');
            const checkbox = node('input');
            checkbox.type = 'checkbox';
            checkbox.dataset.memberEnabled = '1';
            checkbox.checked = !!current.checked;
            enabledLabel.append(checkbox, node('span', '', proxy.name || proxy.id), node('small', '', String(proxy.protocol || '').toUpperCase() + ' · ' + proxy.host + ':' + proxy.port));
            const priorityLabel = node('label');
            priorityLabel.append(node('span', '', t('priority', '优先级')));
            const priority = node('input');
            priority.type = 'number'; priority.min = '0'; priority.max = '1000000'; priority.value = String(current.priority); priority.dataset.memberPriority = '1';
            priority.disabled = !checkbox.checked;
            priorityLabel.append(priority);
            const weightLabel = node('label');
            weightLabel.append(node('span', '', t('weight', '权重')));
            const weight = node('input');
            weight.type = 'number'; weight.min = '1'; weight.max = '1000'; weight.value = String(current.weight || 1); weight.dataset.memberWeight = '1';
            weight.disabled = !checkbox.checked;
            weightLabel.append(weight);
            checkbox.addEventListener('change', function () { priority.disabled = !checkbox.checked; weight.disabled = !checkbox.checked; });
            row.append(enabledLabel, priorityLabel, weightLabel);
            root.append(row);
        });
    }

    function resetGroupForm() {
        document.getElementById('egress-group-form').reset();
        document.getElementById('egress-group-id').value = '';
        document.getElementById('egress-group-threshold').value = '3';
        document.getElementById('egress-group-cooldown').value = '60';
        document.getElementById('egress-group-enabled').checked = true;
        document.getElementById('egress-group-form-title').textContent = t('createGroup', '新建代理组');
        renderGroupMembers(new Map());
    }

    function editGroup(group) {
        selectView('groups');
        document.getElementById('egress-group-id').value = group.id || '';
        document.getElementById('egress-group-name').value = group.name || '';
        document.getElementById('egress-group-threshold').value = String(group.failureThreshold || 3);
        document.getElementById('egress-group-cooldown').value = String(group.cooldownSeconds || 60);
        document.getElementById('egress-group-enabled').checked = group.enabled !== false;
        const preferred = new Map();
        (Array.isArray(group.members) ? group.members : []).forEach(function (member) {
            preferred.set(member.proxyId, { checked: member.enabled !== false, priority: member.priority || 0, weight: member.weight || 1 });
        });
        renderGroupMembers(preferred);
        document.getElementById('egress-group-form-title').textContent = t('editGroup', '编辑代理组');
        document.getElementById('egress-group-name').focus();
    }

    async function saveGroup(event) {
        event.preventDefault();
        const id = String(document.getElementById('egress-group-id').value || '').trim();
        const members = [];
        document.querySelectorAll('#egress-group-members [data-proxy-id]').forEach(function (row) {
            if (!row.querySelector('[data-member-enabled]').checked) return;
            members.push({ proxyId: row.dataset.proxyId, priority: Number(row.querySelector('[data-member-priority]').value), weight: Number(row.querySelector('[data-member-weight]').value), enabled: true });
        });
        if (!members.length) { notify(t('groupMemberRequired', '代理组至少需要一个成员'), 'error'); return; }
        const payload = {
            name: document.getElementById('egress-group-name').value,
            enabled: document.getElementById('egress-group-enabled').checked,
            failureThreshold: Number(document.getElementById('egress-group-threshold').value),
            cooldownSeconds: Number(document.getElementById('egress-group-cooldown').value),
            members: members,
        };
        try {
            await requestJSON('/api/egress-proxy-groups' + (id ? '/' + encodeURIComponent(id) : ''), jsonOptions(id ? 'PUT' : 'POST', payload));
            notify(id ? t('groupUpdated', '代理组已更新') : t('groupCreated', '代理组已创建'), 'success');
            resetGroupForm();
            await refresh(true);
        } catch (error) { notify(error.message, 'error'); }
    }

    async function deleteGroup(group) {
        if (!window.confirm(t('groupDeleteConfirm', '确定删除代理组“{{name}}”吗？', { name: group.name || group.id }))) return;
        try {
            await requestJSON('/api/egress-proxy-groups/' + encodeURIComponent(group.id), { method: 'DELETE' });
            notify(t('groupDeleted', '代理组已删除'), 'success');
            resetGroupForm();
            await refresh(true);
        } catch (error) { notify(error.message, 'error'); }
    }

    function resetAuthForm() {
        document.getElementById('egress-auth-form').reset();
        document.getElementById('egress-auth-id').value = '';
        document.getElementById('egress-auth-enabled').checked = true;
        document.getElementById('egress-auth-clear-field').hidden = true;
        document.getElementById('egress-auth-clear-credential').checked = false;
        document.getElementById('egress-auth-form-title').textContent = t('createAuth', '新建凭据档案');
    }

    function editAuth(profile) {
        selectView('auth');
        document.getElementById('egress-auth-id').value = profile.id || '';
        document.getElementById('egress-auth-name').value = profile.name || '';
        document.getElementById('egress-auth-header').value = profile.headerName || '';
        document.getElementById('egress-auth-enabled').checked = profile.enabled !== false;
        document.getElementById('egress-auth-credential').value = '';
        document.getElementById('egress-auth-clear-field').hidden = !profile.credentialsConfigured;
        document.getElementById('egress-auth-clear-credential').checked = false;
        document.getElementById('egress-auth-form-title').textContent = t('editAuth', '编辑凭据档案');
        document.getElementById('egress-auth-name').focus();
    }

    async function saveAuth(event) {
        event.preventDefault();
        const id = String(document.getElementById('egress-auth-id').value || '').trim();
        const credential = document.getElementById('egress-auth-credential').value;
        const clear = document.getElementById('egress-auth-clear-credential').checked;
        if (!id && !credential) { notify(t('authCredentialRequired', '创建凭据档案时必须填写凭据值'), 'error'); return; }
        const payload = {
            name: document.getElementById('egress-auth-name').value,
            headerName: document.getElementById('egress-auth-header').value,
            enabled: document.getElementById('egress-auth-enabled').checked,
        };
        if (clear) payload.credential = null;
        else if (credential) payload.credential = credential;
        try {
            await requestJSON('/api/egress-auth-profiles' + (id ? '/' + encodeURIComponent(id) : ''), jsonOptions(id ? 'PUT' : 'POST', payload));
            notify(id ? t('authUpdated', '凭据档案已更新') : t('authCreated', '凭据档案已创建'), 'success');
            resetAuthForm();
            await refresh(true);
        } catch (error) { notify(error.message, 'error'); }
    }

    async function deleteAuth(profile) {
        if (!window.confirm(t('authDeleteConfirm', '确定删除凭据档案“{{name}}”吗？', { name: profile.name || profile.id }))) return;
        try {
            await requestJSON('/api/egress-auth-profiles/' + encodeURIComponent(profile.id), { method: 'DELETE' });
            notify(t('authDeleted', '凭据档案已删除'), 'success');
            resetAuthForm();
            await refresh(true);
        } catch (error) { notify(error.message, 'error'); }
    }

    async function refresh(forceConversationChoices) {
        if (state.loading) return;
        state.loading = true;
        const requestId = ++state.requestId;
        setPhase(t('egressLoading', '正在加载出口配置…'), 'loading');
        const refreshButton = document.getElementById('egress-management-refresh');
        if (refreshButton) refreshButton.disabled = true;
        try {
            const results = await Promise.all([
                requestJSON('/api/egress-proxies?limit=100&offset=0'),
                requestJSON('/api/egress-proxy-groups'),
                requestJSON('/api/egress-auth-profiles'),
            ]);
            if (requestId !== state.requestId) return;
            state.proxies = Array.isArray(results[0].items) ? results[0].items : [];
            state.groups = Array.isArray(results[1].items) ? results[1].items : [];
            state.authProfiles = Array.isArray(results[2].items) ? results[2].items : [];
            state.error = '';
            renderAll();
            setPhase(t('egressLoaded', '已加载 {{proxies}} 个代理、{{groups}} 个代理组和 {{profiles}} 个凭据档案', {
                proxies: state.proxies.length, groups: state.groups.length, profiles: state.authProfiles.length,
            }), 'ready');
            if (forceConversationChoices && typeof window.loadConversationContainerChoices === 'function') {
                window.loadConversationContainerChoices(true);
            }
        } catch (error) {
            if (requestId !== state.requestId) return;
            state.error = error && error.message ? error.message : t('egressLoadFailed', '出口配置加载失败');
            setPhase(state.error, 'error');
        } finally {
            if (requestId === state.requestId) state.loading = false;
            if (refreshButton) refreshButton.disabled = false;
        }
    }

    function bind() {
        if (state.bound) return;
        state.bound = true;
        document.querySelectorAll('[data-egress-view]').forEach(function (button) {
            button.addEventListener('click', function () { selectView(button.dataset.egressView); });
        });
        document.getElementById('egress-management-refresh').addEventListener('click', function () { refresh(false); });
        document.getElementById('egress-proxy-search').addEventListener('input', function (event) { state.proxySearch = event.target.value || ''; renderProxyList(); });
        document.getElementById('egress-proxy-new').addEventListener('click', resetProxyForm);
        document.getElementById('egress-proxy-cancel').addEventListener('click', resetProxyForm);
        document.getElementById('egress-proxy-form').addEventListener('submit', saveProxy);
        document.getElementById('egress-group-new').addEventListener('click', resetGroupForm);
        document.getElementById('egress-group-cancel').addEventListener('click', resetGroupForm);
        document.getElementById('egress-group-form').addEventListener('submit', saveGroup);
        document.getElementById('egress-auth-new').addEventListener('click', resetAuthForm);
        document.getElementById('egress-auth-cancel').addEventListener('click', resetAuthForm);
        document.getElementById('egress-auth-form').addEventListener('submit', saveAuth);
        document.addEventListener('languagechange', function () {
            renderAll();
            if (state.error) {
                setPhase(state.error, 'error');
            } else if (state.loading) {
                setPhase(t('egressLoading', '正在加载出口配置…'), 'loading');
            } else {
                setPhase(t('egressLoaded', '已加载 {{proxies}} 个代理、{{groups}} 个代理组和 {{profiles}} 个凭据档案', {
                    proxies: state.proxies.length, groups: state.groups.length, profiles: state.authProfiles.length,
                }), 'ready');
            }
        });
    }

    function init() {
        bind();
        state.view = readView();
        selectView(state.view);
        if (!state.loading) refresh(false);
    }

    window.initEgressManagementPage = init;
    window.refreshEgressManagementPage = function () { return refresh(false); };
}());
