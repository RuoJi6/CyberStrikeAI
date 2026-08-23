(function () {
    'use strict';

    const state = {
        bound: false,
        loading: false,
        requestId: 0,
        conversations: [],
        selectedConversationId: '',
        snapshot: null,
        policies: [],
        selectedPolicyId: '',
        selectedPolicy: null,
        authProfiles: [],
        editingRuleId: '',
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
        return value.length > 30 ? value.slice(0, 18) + '…' + value.slice(-10) : (value || '—');
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

    function selectedFromURL(key) {
        if (!window.location || typeof URLSearchParams === 'undefined') return '';
        return String(new URLSearchParams(window.location.search || '').get(key) || '').trim();
    }

    function writeURL() {
        if (!window.location || !window.history || typeof URL === 'undefined') return;
        const url = new URL(window.location.href);
        if (state.selectedConversationId) url.searchParams.set('boundary_conversation', state.selectedConversationId);
        else url.searchParams.delete('boundary_conversation');
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
            phase.textContent = mode === 'error'
                ? t('boundaryLoadFailed', '边界配置加载失败')
                : mode === 'ready'
                    ? t('boundaryReady', '策略草案与快照已加载')
                    : t('boundaryLoading', '正在加载边界配置…');
            phase.classList.toggle('is-error', mode === 'error');
            phase.classList.toggle('is-ready', mode === 'ready');
        }
    }

    function renderConversationOptions() {
        const select = document.getElementById('boundary-rules-conversation');
        if (!select) return;
        const previous = state.selectedConversationId || selectedFromURL('boundary_conversation');
        const placeholder = element('option', '', t('boundarySelectConversation', '选择已绑定快照的对话'));
        placeholder.value = '';
        const options = [placeholder];
        state.conversations.forEach(function (record) {
            const option = element('option', '', String(record.conversationTitle || record.conversationId));
            option.value = String(record.conversationId || '');
            options.push(option);
        });
        select.replaceChildren.apply(select, options);
        if (previous && state.conversations.some(function (item) { return item.conversationId === previous; })) {
            select.value = previous;
        } else if (state.conversations.length) {
            select.value = state.conversations[0].conversationId;
        }
        state.selectedConversationId = select.value;
        refreshUnified(select);
        writeURL();
    }

    function renderPolicyOptions() {
        const select = document.getElementById('boundary-policy-select');
        if (!select) return;
        const previous = state.selectedPolicyId || selectedFromURL('boundary_policy');
        const placeholder = element('option', '', '选择或新建边界策略');
        placeholder.value = '';
        const options = [placeholder];
        state.policies.forEach(function (policy) {
            const option = element('option', '', String(policy.name || policy.id));
            option.value = String(policy.id || '');
            options.push(option);
        });
        select.replaceChildren.apply(select, options);
        if (previous && state.policies.some(function (item) { return item.id === previous; })) {
            select.value = previous;
        } else if (state.policies.length) {
            select.value = state.policies[0].id;
        }
        state.selectedPolicyId = select.value;
        refreshUnified(select);
        writeURL();
    }

    function renderAuthProfileOptions() {
        const select = document.getElementById('boundary-rule-auth-profile');
        if (!select) return;
        const previous = select.value;
        const placeholder = element('option', '', '不注入凭据');
        placeholder.value = '';
        const options = [placeholder];
        state.authProfiles.filter(function (profile) { return profile.enabled !== false; }).forEach(function (profile) {
            const option = element('option', '', String(profile.name || profile.id));
            option.value = String(profile.id || '');
            options.push(option);
        });
        select.replaceChildren.apply(select, options);
        if (state.authProfiles.some(function (profile) { return profile.id === previous; })) select.value = previous;
        refreshUnified(select);
    }

    function detailField(label, value, full) {
        const wrapper = element('div', 'container-policy-field');
        wrapper.append(element('dt', '', label));
        const content = element('dd', '', value || '—');
        if (full) content.title = String(full);
        wrapper.append(content);
        return wrapper;
    }

    function effectLabel(effect) {
        const labels = {
            'blocked': t('boundaryEffectBlocked', '显式阻断'),
            'allow-visit': t('boundaryEffectVisit', '允许访问'),
            'allow-attack': t('boundaryEffectAttack', '允许测试'),
            'auth-only': t('boundaryEffectAuth', '仅凭据访问'),
        };
        return labels[String(effect || '')] || String(effect || '—');
    }

    function actionButton(label, className, handler) {
        const button = element('button', className, label);
        button.type = 'button';
        button.addEventListener('click', handler);
        return button;
    }

    function renderRule(rule, index, editable) {
        const card = element('article', 'container-policy-rule' + (editable && state.editingRuleId === rule.id ? ' is-editing' : ''));
        const heading = element('div', 'container-policy-rule-heading');
        heading.append(
            element('span', 'container-policy-position', String(Number(rule.position || index + 1))),
            element('strong', '', effectLabel(rule.effect)),
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
        const target = element('dl', 'container-policy-rule-grid');
        target.append(
            detailField(t('host', '主机'), rule.host || '*'),
            detailField(t('protocol', '协议'), Array.isArray(rule.schemes) && rule.schemes.length ? rule.schemes.join(', ') : '*'),
            detailField(t('port', '端口'), Array.isArray(rule.ports) && rule.ports.length ? rule.ports.join(', ') : '*'),
            detailField(t('boundaryMethods', '方法'), Array.isArray(rule.methods) && rule.methods.length ? rule.methods.join(', ') : '*'),
            detailField(t('boundaryPaths', '路径前缀'), Array.isArray(rule.pathPrefixes) && rule.pathPrefixes.length ? rule.pathPrefixes.join(', ') : '*'),
            detailField(t('boundaryExpires', '过期时间'), rule.expiresAt ? formatDate(rule.expiresAt) : t('boundaryNeverExpires', '永不过期')),
        );
        const rate = rule.rateLimit || {};
        const footer = element('div', 'container-policy-rule-footer');
        footer.append(
            element('span', '', t('boundaryRate', '速率 {{rate}}/秒 · 突发 {{burst}} · 并发 {{concurrent}}', {
                rate: Number(rate.requestsPerSecond || 0),
                burst: Number(rate.burst || 0),
                concurrent: Number(rate.maxConcurrent || 0),
            })),
            element('span', '', rule.authProfileId
                ? t('boundaryAuthProfile', '凭据档案 {{id}}', { id: rule.authProfileId })
                : t('boundaryNoAuthProfile', '无凭据注入')),
        );
        card.append(heading, target, footer);
        return card;
    }

    function renderEmpty(root, message, detail) {
        if (!root) return;
        const empty = element('div', 'container-policy-empty');
        empty.append(element('span', '', '⌁'), element('strong', '', message));
        if (detail) empty.append(element('p', '', detail));
        root.replaceChildren(empty);
    }

    function renderSnapshot() {
        const root = document.getElementById('boundary-rules-detail');
        if (!root) return;
        if (!state.selectedConversationId) {
            renderEmpty(root, t('boundaryNoConversations', '暂无已绑定边界快照的对话'), t('boundaryNoConversationsHint', '创建并首次启动容器对话后，不可变快照会显示在这里。'));
            return;
        }
        if (!state.snapshot) {
            renderEmpty(root, t('boundarySnapshotMissing', '该对话尚未绑定不可变快照'));
            return;
        }
        const snapshot = state.snapshot;
        const summary = element('section', 'container-policy-snapshot');
        const heading = element('div', 'container-policy-snapshot-heading');
        const headingText = element('div');
        headingText.append(element('span', 'container-runtime-kicker', t('boundarySnapshot', '不可变策略快照')), element('h3', '', String(snapshot.document && snapshot.document.policyId || snapshot.policyId || '—')));
        heading.append(headingText, element('span', 'container-management-phase is-ready', t('boundaryVerified', 'SHA-256 已验证')));
        const metadata = element('dl', 'container-policy-metadata');
        metadata.append(
            detailField(t('boundarySnapshotId', '快照 ID'), shortHash(snapshot.snapshotId), snapshot.snapshotId),
            detailField(t('boundarySnapshotHash', '快照 Hash'), shortHash(snapshot.sha256), snapshot.sha256),
            detailField(t('boundaryGeneration', '激活代次'), String(snapshot.runtimeGeneration || 0)),
            detailField(t('boundaryBoundAt', '绑定时间'), formatDate(snapshot.boundAt)),
            detailField(t('boundarySchemaVersion', '文档版本'), String(snapshot.document && snapshot.document.schemaVersion || 1)),
            detailField(t('boundaryRuleCount', '规则数量'), String(snapshot.document && Array.isArray(snapshot.document.rules) ? snapshot.document.rules.length : 0)),
        );
        summary.append(heading, metadata);
        const rulesSection = element('section', 'container-policy-rules');
        const rulesHeading = element('div', 'container-policy-rules-heading');
        rulesHeading.append(element('h3', '', t('boundaryRulesTitle', '按固定优先级执行的规则')), element('p', '', t('boundaryRulesHint', '显式阻断优先；未命中任何规则时默认拒绝。')));
        rulesSection.append(rulesHeading);
        const rules = snapshot.document && Array.isArray(snapshot.document.rules) ? snapshot.document.rules : [];
        const list = element('div', 'container-policy-rule-list');
        if (rules.length) rules.forEach(function (rule, index) { list.append(renderRule(rule, index, false)); });
        else list.append(element('div', 'container-policy-empty is-compact', t('boundaryDefaultDeny', '空快照：所有目标均默认拒绝')));
        rulesSection.append(list);
        root.replaceChildren(summary, rulesSection);
    }

    function populatePolicyForm() {
        const policy = state.selectedPolicy;
        document.getElementById('boundary-policy-id').value = policy ? policy.id : '';
        document.getElementById('boundary-policy-name').value = policy ? policy.name || '' : '';
        document.getElementById('boundary-policy-description').value = policy ? policy.description || '' : '';
		const tlsEnabled = Boolean(policy && policy.tlsInspectionEnabled);
		document.getElementById('boundary-policy-tls-enabled').checked = tlsEnabled;
		document.getElementById('boundary-policy-tls-bypass').value = policy && Array.isArray(policy.tlsBypassDomains) ? policy.tlsBypassDomains.join(', ') : '';
		syncPolicyTLS();
        const editor = document.getElementById('boundary-policy-editor');
        if (editor) editor.hidden = !policy;
        const deleteButton = document.getElementById('boundary-policy-delete');
        if (deleteButton) deleteButton.disabled = !policy;
        resetRuleForm();
        renderDraftRules();
    }

    function renderDraftRules() {
        const root = document.getElementById('boundary-policy-rule-list');
        if (!root) return;
        root.replaceChildren();
        const rules = state.selectedPolicy && Array.isArray(state.selectedPolicy.rules) ? state.selectedPolicy.rules : [];
        if (!rules.length) {
            const empty = element('div', 'container-policy-empty is-compact');
            empty.append(element('span', '', '⌁'), element('p', '', '当前为空策略：所有网络目标默认拒绝。点击“新增规则”填写允许或阻断目标。'));
            root.append(empty);
            return;
        }
        rules.forEach(function (rule, index) { root.append(renderRule(rule, index, true)); });
    }

    async function loadPolicy(requestId) {
        state.selectedPolicy = null;
        populatePolicyForm();
        if (!state.selectedPolicyId) return;
        const payload = await requestJSON('/api/boundary-policies/' + encodeURIComponent(state.selectedPolicyId));
        if (requestId !== state.requestId) return;
        state.selectedPolicy = payload;
        populatePolicyForm();
    }

    async function loadSnapshot(requestId) {
        state.snapshot = null;
        renderSnapshot();
        if (!state.selectedConversationId) return;
        try {
            const payload = await requestJSON('/api/conversations/' + encodeURIComponent(state.selectedConversationId) + '/boundary');
            if (requestId !== state.requestId) return;
            state.snapshot = payload;
            renderSnapshot();
        } catch (error) {
            if (requestId !== state.requestId) return;
            const root = document.getElementById('boundary-rules-detail');
            renderEmpty(root, t('boundaryLoadFailed', '快照加载失败'), error && error.message ? error.message : '');
        }
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
        const authProfileId = document.getElementById('boundary-rule-auth-profile').value || null;
        if (effect === 'auth-only' && !authProfileId) throw new Error('仅凭据访问规则必须选择凭据档案');
        const expires = document.getElementById('boundary-rule-expires').value;
        return {
            effect: effect,
            host: document.getElementById('boundary-rule-host').value.trim(),
            schemes: splitValues(document.getElementById('boundary-rule-schemes').value),
            ports: ports,
            pathPrefixes: splitValues(document.getElementById('boundary-rule-paths').value),
            methods: splitValues(document.getElementById('boundary-rule-methods').value),
            authProfileId: effect === 'auth-only' ? authProfileId : null,
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
        syncRuleAuth();
        renderDraftRules();
    }

    function openNewRule() {
        resetRuleForm();
        const form = document.getElementById('boundary-rule-form');
        form.hidden = false;
        const rules = state.selectedPolicy && Array.isArray(state.selectedPolicy.rules) ? state.selectedPolicy.rules : [];
        document.getElementById('boundary-rule-position').value = String(rules.length + 1);
        document.getElementById('boundary-rule-host').focus();
    }

    function editRule(rule) {
        state.editingRuleId = String(rule.id || '');
        const form = document.getElementById('boundary-rule-form');
        form.hidden = false;
        document.getElementById('boundary-rule-id').value = state.editingRuleId;
        document.getElementById('boundary-rule-effect').value = rule.effect || 'allow-visit';
        document.getElementById('boundary-rule-host').value = rule.host || '';
        document.getElementById('boundary-rule-schemes').value = Array.isArray(rule.schemes) ? rule.schemes.join(', ') : '';
        document.getElementById('boundary-rule-ports').value = Array.isArray(rule.ports) ? rule.ports.join(', ') : '';
        document.getElementById('boundary-rule-paths').value = Array.isArray(rule.pathPrefixes) ? rule.pathPrefixes.join(', ') : '';
        document.getElementById('boundary-rule-methods').value = Array.isArray(rule.methods) ? rule.methods.join(', ') : '';
        document.getElementById('boundary-rule-auth-profile').value = rule.authProfileId || '';
        const rate = rule.rateLimit || {};
        document.getElementById('boundary-rule-rate').value = String(rate.requestsPerSecond || 0);
        document.getElementById('boundary-rule-burst').value = String(rate.burst || 0);
        document.getElementById('boundary-rule-concurrent').value = String(rate.maxConcurrent || 0);
        document.getElementById('boundary-rule-position').value = String(rule.position || 0);
        document.getElementById('boundary-rule-expires').value = dateTimeLocal(rule.expiresAt);
        syncRuleAuth();
        renderDraftRules();
        form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function syncRuleAuth() {
        const effect = document.getElementById('boundary-rule-effect');
        const select = document.getElementById('boundary-rule-auth-profile');
        if (!effect || !select) return;
        const enabled = effect.value === 'auth-only';
        select.disabled = !enabled;
        select.required = enabled;
        if (!enabled) select.value = '';
        refreshUnified(select);
    }

	function syncPolicyTLS() {
		const enabled = document.getElementById('boundary-policy-tls-enabled');
		const field = document.getElementById('boundary-policy-tls-bypass-field');
		const input = document.getElementById('boundary-policy-tls-bypass');
		if (!enabled || !field || !input) return;
		field.hidden = !enabled.checked;
		input.disabled = !enabled.checked;
		if (!enabled.checked) input.value = '';
	}

    async function savePolicy(event) {
        event.preventDefault();
        const id = document.getElementById('boundary-policy-id').value.trim();
        const payload = {
            name: document.getElementById('boundary-policy-name').value.trim(),
            description: document.getElementById('boundary-policy-description').value.trim(),
			tlsInspectionEnabled: document.getElementById('boundary-policy-tls-enabled').checked,
			tlsBypassDomains: splitValues(document.getElementById('boundary-policy-tls-bypass').value),
        };
        if (!payload.name) {
            notify('请输入策略名称', 'error');
            return;
        }
        try {
            const saved = await requestJSON('/api/boundary-policies' + (id ? '/' + encodeURIComponent(id) : ''), jsonOptions(id ? 'PUT' : 'POST', payload));
            state.selectedPolicyId = saved.id;
            notify(id ? '边界策略已更新；已运行对话仍使用原不可变快照' : '边界策略已创建', 'success');
            await refresh();
        } catch (error) {
            notify(error.message || '保存边界策略失败', 'error');
        }
    }

    async function deletePolicy() {
        if (!state.selectedPolicy) return;
        if (!window.confirm('删除策略草案“' + state.selectedPolicy.name + '”？已绑定快照不会被修改；仍被对话选择的策略无法删除。')) return;
        try {
            await requestJSON('/api/boundary-policies/' + encodeURIComponent(state.selectedPolicy.id), { method: 'DELETE' });
            state.selectedPolicyId = '';
            notify('边界策略草案已删除', 'success');
            await refresh();
        } catch (error) {
            notify(error.message || '删除边界策略失败', 'error');
        }
    }

    async function saveRule(event) {
        event.preventDefault();
        if (!state.selectedPolicyId) return;
        const ruleID = document.getElementById('boundary-rule-id').value.trim();
        try {
            const payload = rulePayload();
            const path = '/api/boundary-policies/' + encodeURIComponent(state.selectedPolicyId) + '/rules' + (ruleID ? '/' + encodeURIComponent(ruleID) : '');
            await requestJSON(path, jsonOptions(ruleID ? 'PUT' : 'POST', payload));
            notify(ruleID ? '边界规则已更新' : '边界规则已创建', 'success');
            const requestId = ++state.requestId;
            await loadPolicy(requestId);
            writeURL();
        } catch (error) {
            notify(error.message || '保存边界规则失败', 'error');
        }
    }

    async function deleteRule(rule) {
        if (!state.selectedPolicyId || !window.confirm('删除规则“' + String(rule.id || '') + '”？')) return;
        try {
            await requestJSON('/api/boundary-policies/' + encodeURIComponent(state.selectedPolicyId) + '/rules/' + encodeURIComponent(rule.id), { method: 'DELETE' });
            notify('边界规则已删除', 'success');
            const requestId = ++state.requestId;
            await loadPolicy(requestId);
            writeURL();
        } catch (error) {
            notify(error.message || '删除边界规则失败', 'error');
        }
    }

    async function refresh() {
        if (state.loading) return;
        state.loading = true;
        const requestId = ++state.requestId;
        setStatus(t('boundaryLoading', '正在加载边界配置…'), 'loading');
        const refreshButton = document.getElementById('boundary-rules-refresh');
        if (refreshButton) refreshButton.disabled = true;
        try {
            const results = await Promise.all([
                requestJSON('/api/container-runtimes?page=1&page_size=100&status=all'),
                requestJSON('/api/boundary-policies'),
                // Credential profiles have their own egress:read permission.
                // A boundary editor without that permission must still be able
                // to manage non-auth rules instead of losing the whole page.
                requestJSON('/api/egress-auth-profiles').catch(function () { return { items: [] }; }),
            ]);
            if (requestId !== state.requestId) return;
            const runtimes = Array.isArray(results[0].items) ? results[0].items : [];
            state.conversations = runtimes.filter(function (record) {
                return record && record.conversationId && record.desired && record.desired.boundarySnapshotSha256;
            });
            state.policies = Array.isArray(results[1].items) ? results[1].items : [];
            state.authProfiles = Array.isArray(results[2].items) ? results[2].items : [];
            renderConversationOptions();
            renderPolicyOptions();
            renderAuthProfileOptions();
            await Promise.all([loadPolicy(requestId), loadSnapshot(requestId)]);
            if (requestId !== state.requestId) return;
            state.error = '';
            setStatus('已加载 ' + state.policies.length + ' 个策略草案和 ' + state.conversations.length + ' 个运行时快照', 'ready');
        } catch (error) {
            if (requestId !== state.requestId) return;
            state.error = error && error.message ? error.message : t('boundaryLoadFailed', '边界配置加载失败');
            setStatus(state.error, 'error');
        } finally {
            if (requestId === state.requestId) state.loading = false;
            if (refreshButton) refreshButton.disabled = false;
        }
    }

    function bind() {
        if (state.bound) return;
        state.bound = true;
        const conversationSelect = document.getElementById('boundary-rules-conversation');
        if (conversationSelect) conversationSelect.addEventListener('change', function () {
            state.selectedConversationId = String(conversationSelect.value || '').trim();
            writeURL();
            loadSnapshot(++state.requestId);
        });
        const policySelect = document.getElementById('boundary-policy-select');
        if (policySelect) policySelect.addEventListener('change', function () {
            state.selectedPolicyId = String(policySelect.value || '').trim();
            writeURL();
            loadPolicy(++state.requestId).catch(function (error) { notify(error.message || '读取边界策略失败', 'error'); });
        });
        document.getElementById('boundary-rules-refresh')?.addEventListener('click', refresh);
        document.getElementById('boundary-policy-new')?.addEventListener('click', function () {
            state.selectedPolicyId = '';
            state.selectedPolicy = null;
            const select = document.getElementById('boundary-policy-select');
            if (select) { select.value = ''; refreshUnified(select); }
            populatePolicyForm();
            document.getElementById('boundary-policy-name').focus();
            writeURL();
        });
        document.getElementById('boundary-policy-delete')?.addEventListener('click', deletePolicy);
        document.getElementById('boundary-policy-reset')?.addEventListener('click', populatePolicyForm);
        document.getElementById('boundary-policy-form')?.addEventListener('submit', savePolicy);
        document.getElementById('boundary-rule-new')?.addEventListener('click', openNewRule);
        document.getElementById('boundary-rule-cancel')?.addEventListener('click', resetRuleForm);
        document.getElementById('boundary-rule-form')?.addEventListener('submit', saveRule);
        document.getElementById('boundary-rule-effect')?.addEventListener('change', syncRuleAuth);
		document.getElementById('boundary-policy-tls-enabled')?.addEventListener('change', syncPolicyTLS);
        document.addEventListener('languagechange', function () {
            renderConversationOptions();
            renderPolicyOptions();
            renderSnapshot();
            renderDraftRules();
        });
    }

    function init() {
        bind();
        if (!state.loading) refresh();
    }

    window.initBoundaryRulesPage = init;
    window.refreshBoundaryRulesPage = refresh;
}());
