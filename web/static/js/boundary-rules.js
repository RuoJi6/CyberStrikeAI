(function () {
    'use strict';

    const PAGE_SIZES = [10, 20, 50];
    const params = typeof URLSearchParams === 'undefined' ? null : new URLSearchParams(window.location.search || '');
    const initialPage = Number.parseInt(params && params.get('boundary_page'), 10);
    const initialPageSize = Number.parseInt(params && params.get('boundary_page_size'), 10);
    const state = {
        bound: false,
        loading: false,
        requestId: 0,
        policies: [],
        page: Number.isInteger(initialPage) && initialPage > 0 ? initialPage : 1,
        pageSize: PAGE_SIZES.includes(initialPageSize) ? initialPageSize : 10,
        search: String(params && params.get('boundary_q') || '').slice(0, 200),
        total: 0,
        totalPages: 0,
        selectedPolicyId: String(params && params.get('boundary_policy') || '').trim(),
        selectedPolicy: null,
        selectedUsage: [],
        editingRuleId: '',
        searchTimer: null,
    };

    function t(key, fallback, values) {
        const fullKey = 'containerManagement.' + key;
        const replacements = values || {};
        let value = typeof window.t === 'function' ? window.t(fullKey, replacements) : fallback;
        if (!value || value === fullKey) value = fallback;
        return Object.keys(replacements).reduce(function (current, name) {
            return String(current).replaceAll('{{' + name + '}}', String(replacements[name]));
        }, String(value));
    }

    function element(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
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

    function dateTimeLocal(raw) {
        if (!raw) return '';
        const date = new Date(raw);
        if (Number.isNaN(date.getTime())) return '';
        const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
        return local.toISOString().slice(0, 16);
    }

    function shortHash(raw) {
        const value = String(raw || '').trim();
        return value.length > 26 ? value.slice(0, 15) + '…' + value.slice(-8) : (value || '—');
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

    function refreshUnified(select) {
        if (select && window.CyberStrikeSelect && typeof window.CyberStrikeSelect.refresh === 'function') {
            window.CyberStrikeSelect.refresh(select);
        }
    }

    function writeURL() {
        if (!window.location || !window.history || typeof URL === 'undefined') return;
        const url = new URL(window.location.href);
        url.searchParams.set('boundary_page', String(state.page));
        url.searchParams.set('boundary_page_size', String(state.pageSize));
        if (state.search) url.searchParams.set('boundary_q', state.search);
        else url.searchParams.delete('boundary_q');
        if (state.selectedPolicyId) url.searchParams.set('boundary_policy', state.selectedPolicyId);
        else url.searchParams.delete('boundary_policy');
        window.history.replaceState(window.history.state, '', url.toString());
    }

    function setStatus(message, mode) {
        const load = document.getElementById('boundary-rules-load-state');
        if (load) {
            load.textContent = message || '';
            load.classList.toggle('is-error', mode === 'error');
        }
        const phase = document.getElementById('boundary-rules-phase');
        if (phase) {
            phase.textContent = mode === 'error' ? '加载失败' : mode === 'ready' ? '策略列表已更新' : '正在加载边界策略…';
            phase.classList.toggle('is-error', mode === 'error');
            phase.classList.toggle('is-ready', mode === 'ready');
        }
    }

    function actionButton(label, className, handler) {
        const button = element('button', className, label);
        button.type = 'button';
        button.addEventListener('click', handler);
        return button;
    }

    function effectLabel(effect) {
        return ({
            blocked: t('boundaryEffectBlocked', '显式阻断'),
            'allow-visit': t('boundaryEffectVisit', '允许访问'),
            'allow-attack': t('boundaryEffectAttack', '允许测试'),
        })[String(effect || '')] || String(effect || '—');
    }

    function defaultActionLabel(action) {
        return String(action || 'deny').toLowerCase() === 'allow'
            ? '放行（黑名单模式）'
            : '阻断（白名单模式）';
    }

    function ruleEffectLabel(rule) {
        if (rule && rule.effect === 'blocked' && Array.isArray(rule.pathPrefixes) && rule.pathPrefixes.length) {
            return '路径阻断';
        }
        return effectLabel(rule && rule.effect);
    }

    function ruleMethodsLabel(rule) {
        if (Array.isArray(rule.methods) && rule.methods.length) return rule.methods.join(', ');
        return t('boundaryAnyMethod', '任意方法');
    }

    function rulePathsLabel(rule) {
        const patterns = Array.isArray(rule.pathPrefixes) ? rule.pathPrefixes : [];
        if (!patterns.length) return '*';
        return patterns.map(function (pattern) {
            const value = String(pattern || '');
            if (value.startsWith('=')) return '精确 ' + value.slice(1);
            if (value === '/') return '子树 /*';
            if (value.endsWith('/')) return '前缀 ' + value + '…';
            return '子树 ' + value + '/*';
        }).join(', ');
    }

    function detailField(label, value, full) {
        const field = element('div', 'container-policy-field');
        field.append(element('dt', '', label));
        const content = element('dd', '', value || '—');
        if (full) content.title = String(full);
        field.append(content);
        return field;
    }

    function renderRule(rule, index, editable) {
        const card = element('article', 'container-policy-rule' + (editable && state.editingRuleId === rule.id ? ' is-editing' : ''));
        const heading = element('div', 'container-policy-rule-heading');
        heading.append(
            element('span', 'container-policy-position', String(Number(rule.position || index + 1))),
            element('strong', '', ruleEffectLabel(rule)),
            element('code', '', String(rule.id || '—')),
        );
        if (editable) {
            const actions = element('div', 'boundary-rule-card-actions');
            actions.append(
                actionButton('编辑', 'btn-secondary btn-small', function () { editRule(rule); }),
                actionButton('删除', 'btn-danger btn-small', function () { deleteRule(rule); }),
            );
            heading.append(actions);
        }
        const grid = element('dl', 'container-policy-rule-grid');
        grid.append(
            detailField(t('host', '主机'), rule.host === '*' ? '所有主机' : (rule.host || '—')),
            detailField(t('protocol', '协议'), Array.isArray(rule.schemes) && rule.schemes.length ? rule.schemes.join(', ') : '任意协议'),
            detailField(t('port', '端口'), Array.isArray(rule.ports) && rule.ports.length ? rule.ports.join(', ') : '*'),
            detailField(t('boundaryMethods', '方法'), ruleMethodsLabel(rule)),
            detailField(t('boundaryPaths', '路径规则'), rulePathsLabel(rule)),
            detailField(t('boundaryExpires', '过期时间'), rule.expiresAt ? formatDate(rule.expiresAt) : t('boundaryNeverExpires', '永不过期')),
        );
        const rate = rule.rateLimit || {};
        const footer = element('div', 'container-policy-rule-footer');
        footer.append(
            element('span', '', t('boundaryRate', '速率 {{rate}}/秒 · 突发 {{burst}} · 并发 {{concurrent}}', {
                rate: Number(rate.requestsPerSecond || 0), burst: Number(rate.burst || 0), concurrent: Number(rate.maxConcurrent || 0),
            })),
        );
        card.append(heading, grid, footer);
        return card;
    }

    function renderEmpty(root, title, description) {
        if (!root) return;
        const empty = element('div', 'container-policy-empty');
        empty.append(element('span', '', '⌁'), element('strong', '', title));
        if (description) empty.append(element('p', '', description));
        root.replaceChildren(empty);
    }

    function protocolLabel(policy) {
        const protocols = Array.isArray(policy.protocols) ? policy.protocols : [];
        if (!protocols.length) return '暂无规则';
        if (protocols.includes('any')) return '任意协议';
        return protocols.map(function (item) { return String(item).toUpperCase(); }).join(' · ');
    }

    function renderPolicyList() {
        const root = document.getElementById('boundary-policy-list');
        if (!root) return;
        root.replaceChildren();
        if (!state.policies.length) {
            renderEmpty(root, state.search ? '没有匹配的边界策略' : '还没有边界策略', state.search ? '请调整检索条件。' : '新建策略后，可以在对话容器中切换使用。');
            return;
        }
        state.policies.forEach(function (policy) {
            const row = element('article', 'boundary-policy-row');
            row.setAttribute('role', 'listitem');
            const identity = element('div', 'boundary-policy-row-identity');
            identity.append(element('strong', '', policy.name || policy.id), element('p', '', policy.description || '未填写说明'));
            const rules = element('div', 'boundary-policy-row-value');
            rules.append(element('strong', '', String(Number(policy.ruleCount || 0)) + ' 条规则'), element('small', '', protocolLabel(policy)));
            const usage = element('div', 'boundary-policy-row-value');
            usage.append(element('strong', policy.usageCount ? 'is-used' : '', String(Number(policy.usageCount || 0)) + ' 个对话'), element('small', '', policy.usageCount ? '删除前需先切换' : '可安全删除'));
            const updated = element('time', 'boundary-policy-row-time', formatDate(policy.updatedAt));
            const actions = element('div', 'boundary-policy-row-actions');
            actions.append(
                actionButton('查看', 'btn-secondary btn-small', function () { openDetail(policy.id); }),
                actionButton('修改', 'btn-secondary btn-small', function () { openEditor(policy.id); }),
                actionButton('删除', 'btn-danger btn-small', function () { deletePolicy(policy); }),
            );
            row.append(identity, rules, usage, updated, actions);
            root.append(row);
        });
    }

    function renderPagination() {
        const root = document.getElementById('boundary-policy-pagination');
        if (!root) return;
        root.replaceChildren();
        const pageCount = Math.max(1, state.totalPages || 0);
        const previous = actionButton('上一页', 'btn-secondary', function () { setPage(state.page - 1); });
        previous.disabled = state.loading || state.page <= 1 || state.total === 0;
        const label = element('span', 'container-runtime-page-summary', '第 ' + state.page + ' / ' + pageCount + ' 页，共 ' + state.total + ' 个策略');
        const next = actionButton('下一页', 'btn-secondary', function () { setPage(state.page + 1); });
        next.disabled = state.loading || state.page >= pageCount || state.total === 0;
        root.append(previous, label, next);
    }

    function setPage(page) {
        const pageCount = Math.max(1, state.totalPages || 0);
        state.page = Math.min(Math.max(1, Number.parseInt(page, 10) || 1), pageCount);
        writeURL();
        refresh();
    }

    function showDrawer() {
        const drawer = document.getElementById('boundary-policy-detail-drawer');
        const backdrop = document.getElementById('boundary-policy-detail-backdrop');
        if (drawer) { drawer.hidden = false; drawer.setAttribute('aria-hidden', 'false'); }
        if (backdrop) backdrop.hidden = false;
        document.body.classList.add('boundary-policy-overlay-open');
    }

    function closeDrawer() {
        const drawer = document.getElementById('boundary-policy-detail-drawer');
        const backdrop = document.getElementById('boundary-policy-detail-backdrop');
        if (drawer) { drawer.hidden = true; drawer.setAttribute('aria-hidden', 'true'); }
        if (backdrop) backdrop.hidden = true;
        if (document.getElementById('boundary-policy-editor-modal')?.hidden !== false) document.body.classList.remove('boundary-policy-overlay-open');
    }

    function renderUsageItem(item) {
        const card = element('article', 'boundary-policy-usage-card');
        const heading = element('div', 'boundary-policy-usage-heading');
        heading.append(element('strong', '', item.conversationTitle || item.conversationId), element('span', 'container-runtime-badge is-' + (item.runtimeStatus === 'running' ? 'success' : 'neutral'), item.runtimeStatus || 'not_requested'));
        const metadata = element('dl', 'boundary-policy-usage-grid');
        metadata.append(
            detailField('对话 ID', shortHash(item.conversationId), item.conversationId),
            detailField('工作区', item.workspacePersistent ? '持久' : '临时'),
            detailField('激活代次', item.runtimeGeneration ? String(item.runtimeGeneration) : '首次启动前'),
            detailField('快照 Hash', shortHash(item.snapshotSha256), item.snapshotSha256),
        );
        card.append(heading, metadata);
        return card;
    }

    function renderDetail() {
        const root = document.getElementById('boundary-policy-detail-body');
        const title = document.getElementById('boundary-policy-detail-title');
        const remove = document.getElementById('boundary-policy-detail-delete');
        if (!root || !state.selectedPolicy) return;
        const policy = state.selectedPolicy;
        if (title) title.textContent = policy.name || '策略详情';
        root.replaceChildren();
        const summary = element('section', 'boundary-policy-detail-section');
        summary.append(element('p', 'boundary-policy-detail-description', policy.description || '未填写说明'));
        const metadata = element('dl', 'boundary-policy-detail-metadata');
        metadata.append(
            detailField('规则数量', String(Array.isArray(policy.rules) ? policy.rules.length : 0)),
            detailField('更新时间', formatDate(policy.updatedAt)),
        );
        summary.append(metadata);
        root.append(summary);
        const ruleSection = element('section', 'boundary-policy-detail-section');
        const ruleHeading = element('div', 'boundary-policy-detail-section-heading');
        ruleHeading.append(element('h4', '', '策略规则'), element('span', '', '未命中默认' + defaultActionLabel(policy.defaultAction)));
        ruleSection.append(ruleHeading);
        const rules = element('div', 'container-policy-rule-list');
        if (Array.isArray(policy.rules) && policy.rules.length) policy.rules.forEach(function (rule, index) { rules.append(renderRule(rule, index, false)); });
        else renderEmpty(rules, '当前为空策略', String(policy.defaultAction || 'deny') === 'allow' ? '没有显式阻断规则，其他目标默认放行。' : '所有网络目标默认拒绝。');
        ruleSection.append(rules);
        root.append(ruleSection);
        const usageSection = element('section', 'boundary-policy-detail-section');
        const usageHeading = element('div', 'boundary-policy-detail-section-heading');
        usageHeading.append(element('h4', '', '正在使用此策略'), element('span', '', state.selectedUsage.length + ' 个对话容器'));
        usageSection.append(usageHeading);
        const usageList = element('div', 'boundary-policy-usage-list');
        if (state.selectedUsage.length) state.selectedUsage.forEach(function (item) { usageList.append(renderUsageItem(item)); });
        else renderEmpty(usageList, '当前没有对话使用此策略', '此策略可以直接删除。');
        usageSection.append(usageList);
        root.append(usageSection);
        if (remove) {
            remove.disabled = state.selectedUsage.length > 0;
            remove.title = state.selectedUsage.length ? '请先在对话容器中切换策略' : '';
        }
    }

    async function openDetail(policyId) {
        state.selectedPolicyId = String(policyId || '');
        writeURL();
        showDrawer();
        renderEmpty(document.getElementById('boundary-policy-detail-body'), '正在读取策略详情…');
        const requestId = ++state.requestId;
        try {
            const results = await Promise.all([
                requestJSON('/api/boundary-policies/' + encodeURIComponent(state.selectedPolicyId)),
                requestJSON('/api/boundary-policies/' + encodeURIComponent(state.selectedPolicyId) + '/usage'),
            ]);
            if (requestId !== state.requestId) return;
            state.selectedPolicy = results[0];
            state.selectedUsage = Array.isArray(results[1].items) ? results[1].items : [];
            renderDetail();
        } catch (error) {
            renderEmpty(document.getElementById('boundary-policy-detail-body'), '读取策略详情失败', error.message || '');
        }
    }

    function populatePolicyForm() {
        const policy = state.selectedPolicy;
        document.getElementById('boundary-policy-id').value = policy ? policy.id : '';
        document.getElementById('boundary-policy-name').value = policy ? policy.name || '' : '';
        document.getElementById('boundary-policy-description').value = policy ? policy.description || '' : '';
        document.getElementById('boundary-policy-default-action').value = policy ? policy.defaultAction || 'deny' : 'deny';
        refreshUnified(document.getElementById('boundary-policy-default-action'));
        document.getElementById('boundary-policy-editor').hidden = !policy;
        document.getElementById('boundary-policy-editor-title').textContent = policy ? '修改边界策略' : '新建边界策略';
        resetRuleForm();
        renderDraftRules();
    }

    function showEditor() {
        const modal = document.getElementById('boundary-policy-editor-modal');
        if (modal) modal.hidden = false;
        document.body.classList.add('boundary-policy-overlay-open');
    }

    function closeEditor() {
        resetRuleForm();
        const modal = document.getElementById('boundary-policy-editor-modal');
        if (modal) modal.hidden = true;
        if (document.getElementById('boundary-policy-detail-drawer')?.hidden !== false) document.body.classList.remove('boundary-policy-overlay-open');
    }

    async function openEditor(policyId) {
        state.selectedPolicyId = String(policyId || '');
        state.selectedPolicy = null;
        showEditor();
        if (state.selectedPolicyId) {
            try { state.selectedPolicy = await requestJSON('/api/boundary-policies/' + encodeURIComponent(state.selectedPolicyId)); }
            catch (error) { notify(error.message || '读取边界策略失败', 'error'); closeEditor(); return; }
        }
        populatePolicyForm();
        writeURL();
        document.getElementById('boundary-policy-name').focus();
    }

    function renderDraftRules() {
        const root = document.getElementById('boundary-policy-rule-list');
        if (!root) return;
        root.replaceChildren();
        const rules = state.selectedPolicy && Array.isArray(state.selectedPolicy.rules) ? state.selectedPolicy.rules : [];
        if (!rules.length) {
            renderEmpty(root, '当前为空策略', '点击“新增规则”填写 HTTP、HTTPS、TCP 或 UDP 访问边界。');
            return;
        }
        rules.forEach(function (rule, index) { root.append(renderRule(rule, index, true)); });
    }

    function splitValues(value, transform) {
        const values = String(value || '').split(',').map(function (item) { return item.trim(); }).filter(Boolean);
        return transform ? values.map(transform) : values;
    }

    function rulePayload() {
        const effect = document.getElementById('boundary-rule-effect').value;
        const rate = Number(document.getElementById('boundary-rule-rate').value || 0);
        const burst = Number(document.getElementById('boundary-rule-burst').value || 0);
        const concurrent = Number(document.getElementById('boundary-rule-concurrent').value || 0);
        if (!Number.isFinite(rate) || !Number.isInteger(burst) || !Number.isInteger(concurrent)) throw new Error('限速参数必须是有效数字');
        if ((rate === 0) !== (burst === 0)) throw new Error('每秒请求数和突发请求数必须同时为 0 或同时大于 0');
        const ports = splitValues(document.getElementById('boundary-rule-ports').value, function (raw) {
            const port = Number(raw);
            if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('端口必须在 1 到 65535 之间');
            return port;
        });
        const expires = document.getElementById('boundary-rule-expires').value;
        const subtreePaths = splitValues(document.getElementById('boundary-rule-paths').value);
        const exactPaths = splitValues(document.getElementById('boundary-rule-exact-paths').value, function (raw) {
            const value = raw.replace(/^=+/, '').trim();
            if (!value) throw new Error('精确接口不能为空');
            return '=' + value;
        });
        let host = document.getElementById('boundary-rule-host').value.trim();
        if (!host && effect === 'blocked' && subtreePaths.concat(exactPaths).length) host = '*';
        return {
            effect: effect,
            host: host,
            schemes: splitValues(document.getElementById('boundary-rule-schemes').value),
            ports: ports,
            pathPrefixes: subtreePaths.concat(exactPaths),
            methods: splitValues(document.getElementById('boundary-rule-methods').value),
            rateLimit: { requestsPerSecond: rate, burst: burst, maxConcurrent: concurrent },
            expiresAt: expires ? new Date(expires).toISOString() : null,
            position: Number(document.getElementById('boundary-rule-position').value || 0),
        };
    }

    function resetRuleForm() {
        state.editingRuleId = '';
        const form = document.getElementById('boundary-rule-form');
        if (!form) return;
        form.reset();
        form.hidden = true;
        document.getElementById('boundary-rule-id').value = '';
        document.getElementById('boundary-rule-effect').value = 'allow-visit';
        document.getElementById('boundary-rule-position').value = '0';
        document.getElementById('boundary-rule-rate').value = '0';
        document.getElementById('boundary-rule-burst').value = '0';
        document.getElementById('boundary-rule-concurrent').value = '0';
    }

    function openNewRule() {
        resetRuleForm();
        const form = document.getElementById('boundary-rule-form');
        form.hidden = false;
        document.getElementById('boundary-rule-form-title').textContent = '新增边界规则';
        const rules = state.selectedPolicy && Array.isArray(state.selectedPolicy.rules) ? state.selectedPolicy.rules : [];
        document.getElementById('boundary-rule-position').value = String(rules.length + 1);
        document.getElementById('boundary-rule-host').focus();
    }

    function editRule(rule) {
        state.editingRuleId = String(rule.id || '');
        const form = document.getElementById('boundary-rule-form');
        form.hidden = false;
        document.getElementById('boundary-rule-form-title').textContent = '修改边界规则';
        document.getElementById('boundary-rule-id').value = state.editingRuleId;
        document.getElementById('boundary-rule-effect').value = rule.effect || 'allow-visit';
        document.getElementById('boundary-rule-host').value = rule.host === '*' && Array.isArray(rule.pathPrefixes) && rule.pathPrefixes.length ? '' : (rule.host || '');
        document.getElementById('boundary-rule-schemes').value = Array.isArray(rule.schemes) ? rule.schemes.join(', ') : '';
        document.getElementById('boundary-rule-ports').value = Array.isArray(rule.ports) ? rule.ports.join(', ') : '';
        const pathPatterns = Array.isArray(rule.pathPrefixes) ? rule.pathPrefixes : [];
        document.getElementById('boundary-rule-paths').value = pathPatterns.filter(function (pattern) { return !String(pattern).startsWith('='); }).join(', ');
        document.getElementById('boundary-rule-exact-paths').value = pathPatterns.filter(function (pattern) { return String(pattern).startsWith('='); }).map(function (pattern) { return String(pattern).slice(1); }).join(', ');
        document.getElementById('boundary-rule-methods').value = Array.isArray(rule.methods) ? rule.methods.join(', ') : '';
        const rate = rule.rateLimit || {};
        document.getElementById('boundary-rule-rate').value = String(rate.requestsPerSecond || 0);
        document.getElementById('boundary-rule-burst').value = String(rate.burst || 0);
        document.getElementById('boundary-rule-concurrent').value = String(rate.maxConcurrent || 0);
        document.getElementById('boundary-rule-position').value = String(rule.position || 0);
        document.getElementById('boundary-rule-expires').value = dateTimeLocal(rule.expiresAt);
        renderDraftRules();
        document.getElementById('boundary-rule-host').focus();
    }

    async function reloadSelectedPolicy() {
        if (!state.selectedPolicyId) return;
        state.selectedPolicy = await requestJSON('/api/boundary-policies/' + encodeURIComponent(state.selectedPolicyId));
        populatePolicyForm();
    }

    async function savePolicy(event) {
        event.preventDefault();
        const id = document.getElementById('boundary-policy-id').value.trim();
        const payload = {
            name: document.getElementById('boundary-policy-name').value.trim(),
            description: document.getElementById('boundary-policy-description').value.trim(),
            defaultAction: document.getElementById('boundary-policy-default-action').value || 'deny',
        };
        if (!payload.name) { notify('请输入策略名称', 'error'); return; }
        try {
            const saved = await requestJSON('/api/boundary-policies' + (id ? '/' + encodeURIComponent(id) : ''), jsonOptions(id ? 'PUT' : 'POST', payload));
            state.selectedPolicyId = saved.id;
            state.selectedPolicy = saved;
            populatePolicyForm();
            writeURL();
            notify(id ? '边界策略已更新；运行中容器仍使用原快照' : '边界策略已创建，现在可以添加规则', 'success');
            await refresh(false);
        } catch (error) { notify(error.message || '保存边界策略失败', 'error'); }
    }

    async function deletePolicy(policy) {
        const target = policy || state.selectedPolicy;
        if (!target) return;
        const usageCount = Number(target.usageCount || (target.id === state.selectedPolicyId ? state.selectedUsage.length : 0));
        if (usageCount > 0) { notify('此策略仍被对话容器使用，请先切换策略', 'error'); return; }
        if (!window.confirm('删除边界策略“' + target.name + '”？此操作无法撤销。')) return;
        try {
            await requestJSON('/api/boundary-policies/' + encodeURIComponent(target.id), { method: 'DELETE' });
            if (target.id === state.selectedPolicyId) { state.selectedPolicyId = ''; state.selectedPolicy = null; state.selectedUsage = []; closeDrawer(); closeEditor(); }
            notify('边界策略已删除', 'success');
            await refresh();
        } catch (error) { notify(error.message || '删除边界策略失败', 'error'); }
    }

    async function saveRule(event) {
        event.preventDefault();
        if (!state.selectedPolicyId) return;
        const ruleID = document.getElementById('boundary-rule-id').value.trim();
        try {
            const path = '/api/boundary-policies/' + encodeURIComponent(state.selectedPolicyId) + '/rules' + (ruleID ? '/' + encodeURIComponent(ruleID) : '');
            await requestJSON(path, jsonOptions(ruleID ? 'PUT' : 'POST', rulePayload()));
            notify(ruleID ? '边界规则已更新' : '边界规则已创建', 'success');
            await reloadSelectedPolicy();
            await refresh(false);
        } catch (error) { notify(error.message || '保存边界规则失败', 'error'); }
    }

    async function deleteRule(rule) {
        if (!state.selectedPolicyId || !window.confirm('删除当前规则？')) return;
        try {
            await requestJSON('/api/boundary-policies/' + encodeURIComponent(state.selectedPolicyId) + '/rules/' + encodeURIComponent(rule.id), { method: 'DELETE' });
            notify('边界规则已删除', 'success');
            await reloadSelectedPolicy();
            await refresh(false);
        } catch (error) { notify(error.message || '删除边界规则失败', 'error'); }
    }

    async function refresh(resetSelection) {
        if (state.loading) return;
        state.loading = true;
        const requestId = ++state.requestId;
        setStatus('正在加载边界策略…', 'loading');
        renderPagination();
        try {
            const query = new URLSearchParams({ page: String(state.page), page_size: String(state.pageSize) });
            if (state.search) query.set('search', state.search);
            const results = await Promise.all([
                requestJSON('/api/boundary-policies?' + query.toString()),
            ]);
            if (requestId !== state.requestId) return;
            const payload = results[0];
            state.policies = Array.isArray(payload.items) ? payload.items : [];
            state.total = Number(payload.total || 0);
            state.totalPages = Number(payload.totalPages || 0);
            if (state.totalPages > 0 && state.page > state.totalPages) { state.page = state.totalPages; state.loading = false; writeURL(); await refresh(resetSelection); return; }
            if (resetSelection !== false && state.selectedPolicyId && !state.policies.some(function (item) { return item.id === state.selectedPolicyId; })) state.selectedPolicyId = '';
            renderPolicyList();
            renderPagination();
            writeURL();
            setStatus('当前显示 ' + state.policies.length + ' 个，共 ' + state.total + ' 个边界策略', 'ready');
        } catch (error) {
            if (requestId !== state.requestId) return;
            state.policies = [];
            state.total = 0;
            state.totalPages = 0;
            renderPolicyList();
            setStatus(error.message || '加载边界策略失败', 'error');
        } finally {
            if (requestId === state.requestId) state.loading = false;
            renderPagination();
        }
    }

    function bind() {
        if (state.bound) return;
        state.bound = true;
        const search = document.getElementById('boundary-policy-search');
        if (search) {
            search.value = state.search;
            search.addEventListener('input', function () {
                state.search = String(search.value || '').slice(0, 200);
                state.page = 1;
                writeURL();
                if (state.searchTimer) clearTimeout(state.searchTimer);
                state.searchTimer = setTimeout(function () { state.searchTimer = null; refresh(); }, 300);
            });
        }
        const pageSize = document.getElementById('boundary-policy-page-size');
        if (pageSize) {
            pageSize.value = String(state.pageSize);
            refreshUnified(pageSize);
            pageSize.addEventListener('change', function () {
                const value = Number.parseInt(pageSize.value, 10);
                state.pageSize = PAGE_SIZES.includes(value) ? value : 10;
                state.page = 1;
                writeURL();
                refresh();
            });
        }
        document.getElementById('boundary-rules-refresh')?.addEventListener('click', function () { refresh(false); });
        document.getElementById('boundary-policy-new')?.addEventListener('click', function () { openEditor(''); });
        document.getElementById('boundary-policy-detail-close')?.addEventListener('click', closeDrawer);
        document.getElementById('boundary-policy-detail-backdrop')?.addEventListener('click', closeDrawer);
        document.getElementById('boundary-policy-detail-edit')?.addEventListener('click', function () { openEditor(state.selectedPolicyId); });
        document.getElementById('boundary-policy-detail-delete')?.addEventListener('click', function () { deletePolicy(state.selectedPolicy); });
        document.getElementById('boundary-policy-editor-close')?.addEventListener('click', closeEditor);
        document.getElementById('boundary-policy-reset')?.addEventListener('click', closeEditor);
        document.getElementById('boundary-policy-form')?.addEventListener('submit', savePolicy);
        document.getElementById('boundary-rule-new')?.addEventListener('click', openNewRule);
        document.getElementById('boundary-rule-close')?.addEventListener('click', resetRuleForm);
        document.getElementById('boundary-rule-cancel')?.addEventListener('click', resetRuleForm);
        document.getElementById('boundary-rule-form')?.addEventListener('submit', saveRule);
        document.addEventListener('keydown', function (event) {
            if (event.key !== 'Escape') return;
            if (document.getElementById('boundary-rule-form')?.hidden === false) resetRuleForm();
            else if (document.getElementById('boundary-policy-editor-modal')?.hidden === false) closeEditor();
            else closeDrawer();
        });
        document.addEventListener('languagechange', function () { renderPolicyList(); renderDetail(); renderDraftRules(); });
    }

    function init() {
        bind();
        if (!state.loading) refresh(false);
    }

    window.initBoundaryRulesPage = init;
    window.refreshBoundaryRulesPage = refresh;
}());
