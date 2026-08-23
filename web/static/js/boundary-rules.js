(function () {
    'use strict';

    const state = {
        bound: false,
        loading: false,
        requestId: 0,
        conversations: [],
        selectedConversationId: '',
        snapshot: null,
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

    function formatDate(raw) {
        if (!raw) return '—';
        const date = new Date(raw);
        return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
    }

    function shortHash(raw) {
        const value = String(raw || '').trim();
        return value.length > 30 ? value.slice(0, 18) + '…' + value.slice(-10) : (value || '—');
    }

    async function requestJSON(path) {
        const response = typeof window.apiFetch === 'function' ? await window.apiFetch(path) : await fetch(path);
        let payload = null;
        try { payload = await response.json(); } catch (_) { payload = null; }
        if (!response.ok) throw new Error(payload && payload.error ? payload.error : 'HTTP ' + response.status);
        return payload || {};
    }

    function refreshUnified(select) {
        if (select && window.CyberStrikeSelect && typeof window.CyberStrikeSelect.refresh === 'function') {
            window.CyberStrikeSelect.refresh(select);
        }
    }

    function selectedFromURL() {
        if (!window.location || typeof URLSearchParams === 'undefined') return '';
        return String(new URLSearchParams(window.location.search || '').get('boundary_conversation') || '').trim();
    }

    function writeURL() {
        if (!window.location || !window.history || typeof URL === 'undefined') return;
        const url = new URL(window.location.href);
        if (state.selectedConversationId) url.searchParams.set('boundary_conversation', state.selectedConversationId);
        else url.searchParams.delete('boundary_conversation');
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
                ? t('boundaryLoadFailed', '快照加载失败')
                : mode === 'ready'
                    ? t('boundaryReady', '不可变快照已验证')
                    : t('boundaryLoading', '正在加载快照…');
            phase.classList.toggle('is-error', mode === 'error');
            phase.classList.toggle('is-ready', mode === 'ready');
        }
    }

    function renderConversationOptions() {
        const select = document.getElementById('boundary-rules-conversation');
        if (!select) return;
        const previous = state.selectedConversationId || selectedFromURL();
        const placeholder = element('option', '', t('boundarySelectConversation', '选择已绑定快照的对话'));
        placeholder.value = '';
        const options = [placeholder];
        state.conversations.forEach(function (record) {
            const option = element('option', '', String(record.conversationTitle || record.conversationId));
            option.value = String(record.conversationId || '');
            option.dataset.hash = String(record.desired && record.desired.boundarySnapshotSha256 || '');
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

    function detailField(label, value, full) {
        const wrapper = element('div', 'container-policy-field');
        wrapper.append(element('dt', '', label));
        const content = element('dd', '', value || '—');
        if (full) content.title = String(full);
        wrapper.append(content);
        return wrapper;
    }

    function renderEmpty(message, detail) {
        const root = document.getElementById('boundary-rules-detail');
        if (!root) return;
        const empty = element('div', 'container-policy-empty');
        empty.append(element('span', '', '⌁'), element('strong', '', message));
        if (detail) empty.append(element('p', '', detail));
        root.replaceChildren(empty);
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

    function renderRule(rule, index) {
        const card = element('article', 'container-policy-rule');
        const heading = element('div', 'container-policy-rule-heading');
        heading.append(
            element('span', 'container-policy-position', String(Number(rule.position || index + 1))),
            element('strong', '', effectLabel(rule.effect)),
            element('code', '', String(rule.id || '—')),
        );
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

    function renderSnapshot() {
        const root = document.getElementById('boundary-rules-detail');
        if (!root) return;
        if (!state.selectedConversationId) {
            renderEmpty(t('boundaryNoConversations', '暂无已绑定边界快照的对话'), t('boundaryNoConversationsHint', '创建并首次启动容器对话后，不可变快照会显示在这里。'));
            return;
        }
        if (!state.snapshot) {
            renderEmpty(t('boundarySnapshotMissing', '该对话尚未绑定不可变快照'));
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
        if (rules.length) rules.forEach(function (rule, index) { list.append(renderRule(rule, index)); });
        else list.append(element('div', 'container-policy-empty is-compact', t('boundaryDefaultDeny', '空快照：所有目标均默认拒绝')));
        rulesSection.append(list);
        root.replaceChildren(summary, rulesSection);
    }

    async function loadSnapshot(requestId) {
        state.snapshot = null;
        renderSnapshot();
        if (!state.selectedConversationId) return;
        setStatus(t('boundaryLoadingSnapshot', '正在读取不可变快照…'), 'loading');
        try {
            const payload = await requestJSON('/api/conversations/' + encodeURIComponent(state.selectedConversationId) + '/boundary');
            if (requestId !== state.requestId) return;
            state.snapshot = payload;
            state.error = '';
            renderSnapshot();
            setStatus(t('boundaryLoaded', '已加载 {{count}} 条边界规则', { count: payload.document && Array.isArray(payload.document.rules) ? payload.document.rules.length : 0 }), 'ready');
        } catch (error) {
            if (requestId !== state.requestId) return;
            state.error = error && error.message ? error.message : t('boundaryLoadFailed', '快照加载失败');
            renderEmpty(t('boundaryLoadFailed', '快照加载失败'), state.error);
            setStatus(state.error, 'error');
        }
    }

    async function refresh() {
        if (state.loading) return;
        state.loading = true;
        const requestId = ++state.requestId;
        setStatus(t('boundaryLoading', '正在加载快照…'), 'loading');
        const refreshButton = document.getElementById('boundary-rules-refresh');
        if (refreshButton) refreshButton.disabled = true;
        try {
            const payload = await requestJSON('/api/container-runtimes?page=1&page_size=100&status=all');
            if (requestId !== state.requestId) return;
            const items = Array.isArray(payload.items) ? payload.items : [];
            state.conversations = items.filter(function (record) {
                return record && record.conversationId && record.desired && record.desired.boundarySnapshotSha256;
            });
            renderConversationOptions();
            await loadSnapshot(requestId);
            if (!state.selectedConversationId) setStatus(t('boundaryNoConversations', '暂无已绑定边界快照的对话'), 'ready');
        } catch (error) {
            if (requestId !== state.requestId) return;
            state.conversations = [];
            state.snapshot = null;
            renderConversationOptions();
            state.error = error && error.message ? error.message : t('boundaryLoadFailed', '快照加载失败');
            renderEmpty(t('boundaryLoadFailed', '快照加载失败'), state.error);
            setStatus(state.error, 'error');
        } finally {
            if (requestId === state.requestId) state.loading = false;
            if (refreshButton) refreshButton.disabled = false;
        }
    }

    function bind() {
        if (state.bound) return;
        state.bound = true;
        const select = document.getElementById('boundary-rules-conversation');
        if (select) select.addEventListener('change', function () {
            state.selectedConversationId = String(select.value || '').trim();
            writeURL();
            const requestId = ++state.requestId;
            loadSnapshot(requestId);
        });
        const refreshButton = document.getElementById('boundary-rules-refresh');
        if (refreshButton) refreshButton.addEventListener('click', refresh);
        document.addEventListener('languagechange', function () {
            renderConversationOptions();
            renderSnapshot();
            if (state.error) {
                setStatus(state.error, 'error');
            } else if (state.loading) {
                setStatus(t('boundaryLoading', '正在加载快照…'), 'loading');
            } else if (state.snapshot) {
                const count = state.snapshot.document && Array.isArray(state.snapshot.document.rules) ? state.snapshot.document.rules.length : 0;
                setStatus(t('boundaryLoaded', '已加载 {{count}} 条边界规则', { count: count }), 'ready');
            } else {
                setStatus(t('boundaryNoConversations', '暂无已绑定边界快照的对话'), 'ready');
            }
        });
    }

    function init() {
        bind();
        if (!state.loading) refresh();
    }

    window.initBoundaryRulesPage = init;
    window.refreshBoundaryRulesPage = refresh;
}());
