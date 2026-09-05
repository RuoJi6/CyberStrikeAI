(function (root, factory) {
    'use strict';
    const api = factory(root || {});
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.ContainerLifecycle = api;
}(typeof window !== 'undefined' ? window : globalThis, function (root) {
    'use strict';
    const OPERATIONS = ['create', 'start', 'stop', 'rebuild', 'delete', 'reconcile', 'health'];
    const PAGE_SIZE = 10;
    const state = { id: '', revision: '', record: null, host: null, page: 1, type: 'all', result: 'all',
        items: [], total: 0, pages: 0, latest: null, loading: false, loaded: false, error: '',
        generation: 0, controller: null, integrity: '', verifying: false, verification: 0 };

    function t(key, fallback, values = {}) {
        if (typeof root.containerManagementT === 'function') return root.containerManagementT(key, fallback, values);
        return Object.entries(values).reduce((text, [key, value]) => text.replaceAll(`{{${key}}}`, String(value)), fallback);
    }
    function el(tag, className, text) {
        const node = root.document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = String(text);
        return node;
    }
    function operationLabel(value) {
        const labels = { create: ['auditCreate', '创建'], start: ['auditStart', '启动'], stop: ['auditStop', '停止'],
            rebuild: ['auditRebuild', '重建'], delete: ['lifecycleDestroy', '销毁'], reconcile: ['auditReconcile', '状态校准'], health: ['auditHealth', '出站健康'] };
        const pair = labels[value];
        return pair ? t(...pair) : value;
    }
    function resultLabel(event) {
        return event.result === 'failure' ? t('auditFailure', '失败') : event.result === 'success' ? t('auditSuccess', '成功') : t('lifecycleUnknownResult', '结果未记录');
    }
    function date(value) {
        const result = new Date(value);
        return Number.isNaN(result.getTime()) ? '—' : result.toLocaleString();
    }
    function eventTitle(event) { return `${operationLabel(event.eventType)} · ${resultLabel(event)}`; }
    function filterParams(id, options = {}) {
        const params = new URLSearchParams({ conversation_id: id, category: 'lifecycle', defer_integrity: 'true', page: String(options.page || 1), page_size: String(PAGE_SIZE) });
        if (OPERATIONS.includes(options.type)) params.set('event_type', options.type);
        if (['success', 'failure'].includes(options.result)) params.set('decision', options.result);
        return params;
    }
    function acceptEvents(payload, id, validator) {
        if (!payload || !Array.isArray(payload.items) || !Number.isSafeInteger(payload.total) || payload.total < 0 || !Number.isSafeInteger(payload.totalPages) || payload.totalPages < 0) throw new Error(t('lifecycleInvalidData', '生命周期记录格式无效'));
        if (payload.items.some(event => event.category !== 'lifecycle' || event.conversationId !== id || !OPERATIONS.includes(event.eventType) || !validator(event))) throw new Error(t('lifecycleInvalidData', '生命周期记录格式无效'));
        return payload.items;
    }
    function failureContext(event, record) {
        if (event.result !== 'failure') return '';
        const running = record.runtimeStatus === 'running' && record.lifecycleState !== 'failed' && record.status !== 'failed';
        return running ? t('lifecyclePastFailureRunning', '历史失败记录 · 当前容器运行中') : t('lifecyclePastFailure', '历史操作结果，不代表当前实时状态');
    }
    async function request(url, signal) {
        const response = await root.apiFetch(url, signal ? { signal } : {});
        const payload = await response.json();
        if (!response.ok) throw new Error(response.status === 403 ? t('lifecyclePermission', '查看生命周期记录需要审计读取权限。') : (payload.error || t('lifecycleLoadFailed', '加载生命周期记录失败')));
        return payload;
    }
    function summary() {
        root.document.querySelectorAll('[data-container-lifecycle-latest]').forEach(node => {
            if (node.dataset.containerLifecycleLatest !== state.id) return;
            node.replaceChildren();
            node.append(el('strong', '', t('lifecycleLatest', '最近生命周期变更')));
            node.append(el('span', '', state.latest ? `${date(state.latest.occurredAt)} · ${eventTitle(state.latest)}` : state.error || (state.loading ? t('lifecycleLoading', '正在加载生命周期记录…') : t('lifecycleNoHistory', '尚无持久化生命周期记录'))));
            if (state.latest && state.latest.eventType === 'delete' && state.latest.result === 'success' && state.record.status === 'not_requested') {
                node.append(el('span', '', t('lifecycleDestroyedHistory', '最近运行时已销毁；历史记录保留。工作区状态请单独核实。')));
            }
        });
    }
    async function load() {
        const generation = ++state.generation;
        if (state.controller) state.controller.abort();
        state.integrity = ''; state.verification++; state.verifying = false;
        if (typeof root.hasPermission === 'function' && !root.hasPermission('audit:read')) {
            state.items = []; state.latest = null; state.total = 0; state.pages = 0; state.loading = false;
            state.error = t('lifecyclePermission', '查看生命周期记录需要审计读取权限。'); render(); summary(); return;
        }
        const controller = new AbortController(); state.controller = controller;
        const id = state.id;
        state.loading = true; state.error = ''; render(); summary();
        const timeout = root.setTimeout(() => controller.abort(), 15000);
        try {
            const needsLatest = state.page !== 1 || state.type !== 'all' || state.result !== 'all';
            const [payload, latestPayload] = await Promise.all([
                request(`/api/egress-audit-events?${filterParams(id, state)}`, controller.signal),
                needsLatest ? request(`/api/egress-audit-events?${filterParams(id)}`, controller.signal) : null,
            ]);
            if (generation !== state.generation || id !== state.id) return;
            const items = acceptEvents(payload, id, event => root.CyberStrikeEgressAudit.isSafeAuditEvent(event));
            state.items = items; state.total = payload.total; state.pages = payload.totalPages; state.loaded = true;
            state.latest = (latestPayload ? acceptEvents(latestPayload, id, event => root.CyberStrikeEgressAudit.isSafeAuditEvent(event)) : items)[0] || null;
        } catch (error) {
            if (generation !== state.generation || id !== state.id) return;
            state.items = []; state.total = 0; state.pages = 0;
            state.error = error.name === 'AbortError' ? t('lifecycleTimeout', '加载超时，请重试。') : error.message;
        } finally {
            root.clearTimeout(timeout);
            if (generation === state.generation) { state.loading = false; render(); summary(); }
        }
    }
    function field(dl, name, value) {
        const field = el('div', 'container-runtime-field');
        field.append(el('dt', '', name), el('dd', '', value || '—')); dl.append(field);
    }
    function renderEvent(event) {
        const article = el('article', `container-lifecycle-event is-${event.result === 'failure' ? 'failure' : 'success'}`);
        const heading = el('div', 'container-lifecycle-event-heading');
        const time = el('time', '', date(event.occurredAt)); time.dateTime = event.occurredAt;
        heading.append(el('strong', '', eventTitle(event)), time); article.append(heading);
        article.append(el('p', 'container-lifecycle-event-context', `${t('lifecycleGeneration', '第 {{generation}} 代', { generation: event.runtimeGeneration })} · ${t('lifecycleSequence', '审计序号 {{sequence}}', { sequence: event.chainSequence })}`));
        const context = failureContext(event, state.record);
        if (context) article.append(el('p', 'container-lifecycle-event-context', context));
        const details = el('details', 'container-lifecycle-event-details');
        details.append(el('summary', '', t('lifecycleEventDetails', '事件详情')));
        const dl = el('dl', 'container-lifecycle-event-fields');
        field(dl, t('lifecycleEventId', '事件 ID'), event.id);
        field(dl, t('lifecycleOperation', '生命周期操作'), operationLabel(event.lifecycleOperation || event.eventType));
        field(dl, t('lifecycleHistoricalState', '当时操作状态'), event.lifecycleState ? t(`status.${event.lifecycleState}`, event.lifecycleState) : '—');
        field(dl, t('lifecycleReason', '触发原因'), event.reason || t('lifecycleNotCaptured', '历史记录未采集此信息'));
        field(dl, t('lifecycleOriginalMessage', '原始记录'), event.message);
        field(dl, t('lifecycleContainerId', '当时容器 ID'), event.containerId);
        field(dl, t('lifecycleSnapshotId', '当时边界快照 ID'), event.snapshotId);
        field(dl, t('snapshotHash', '边界快照 Hash'), event.snapshotSha256);
        field(dl, t('lifecycleEventHash', '审计事件 Hash'), event.eventHash);
        details.append(dl); article.append(details); return article;
    }
    async function verify() {
        if (typeof root.hasPermission === 'function' && !root.hasPermission('audit:read')) return;
        const id = state.id, generation = ++state.verification;
        state.verifying = true; state.integrity = ''; render();
        const controller = new AbortController(), timeout = root.setTimeout(() => controller.abort(), 30000);
        try {
            const payload = await request(`/api/egress-audit-events/integrity?conversation_id=${encodeURIComponent(id)}`, controller.signal);
            if (id !== state.id || generation !== state.verification) return;
            if (!root.CyberStrikeEgressAudit.isSafeIntegrity(payload.integrity)) throw new Error(t('auditIntegrityFailed', '审计链校验失败'));
            state.integrity = t('lifecycleIntegrityOK', '此对话完整审计链校验通过（包含网络与生命周期事件）。');
        } catch (error) {
            if (id === state.id && generation === state.verification) state.integrity = error.name === 'AbortError' ? t('lifecycleTimeout', '加载超时，请重试。') : error.message;
        } finally { root.clearTimeout(timeout); if (id === state.id && generation === state.verification) { state.verifying = false; render(); } }
    }
    function button(label, action, disabled = false) {
        const node = el('button', 'btn-secondary', label); node.type = 'button'; node.disabled = disabled; node.addEventListener('click', action); return node;
    }
    function selectFilter(label, entries, value, update) {
        const wrapper = el('label', 'container-lifecycle-filter'); wrapper.append(el('span', '', label));
        const select = el('select'); entries.forEach(([value, label]) => { const option = el('option', '', label); option.value = value; select.append(option); });
        select.value = value; select.disabled = state.loading;
        select.addEventListener('change', () => { update(select.value); state.page = 1; load(); }); wrapper.append(select); return wrapper;
    }
    function render() {
        if (!state.host || !state.host.isConnected) return;
        state.host.replaceChildren();
        const filters = el('div', 'container-lifecycle-toolbar');
        filters.append(selectFilter(t('lifecycleOperation', '生命周期操作'), [['all', t('filterAll', '全部')], ...OPERATIONS.map(value => [value, operationLabel(value)])], state.type, value => { state.type = value; }));
        filters.append(selectFilter(t('lifecycleResult', '操作结果'), [['all', t('filterAll', '全部')], ['success', t('auditSuccess', '成功')], ['failure', t('auditFailure', '失败')]], state.result, value => { state.result = value; }));
        filters.append(button(t('refresh', '刷新'), load, state.loading));
        state.host.append(filters, el('p', 'container-lifecycle-history-hint', t('lifecycleHistoryHint', '按已记录的操作结果展示，最新在前。旧记录未采集的原因、操作者及子步骤不作推断。')));
        const status = el('p', `container-lifecycle-load-state${state.error ? ' is-error' : ''}`, state.loading ? t('lifecycleLoading', '正在加载生命周期记录…') : state.error);
        status.setAttribute('role', 'status'); state.host.append(status);
        if (!state.loading && !state.error && !state.items.length) state.host.append(el('p', 'container-runtime-empty', t('lifecycleEmpty', '暂无符合条件的生命周期记录。')));
        if (!state.loading && !state.error) state.host.append(...state.items.map(renderEvent));
        const pagination = el('div', 'container-runtime-pagination');
        pagination.append(button(t('paginationPrevious', '上一页'), () => { state.page--; load(); }, state.loading || state.page <= 1),
            el('span', 'container-runtime-page-summary', t('paginationSummary', '第 {{page}} / {{totalPages}} 页，共 {{total}} 条', { page: state.page, totalPages: Math.max(1, state.pages), total: state.total })),
            button(t('paginationNext', '下一页'), () => { state.page++; load(); }, state.loading || state.page >= state.pages));
        state.host.append(pagination);
        const integrity = el('div', 'container-lifecycle-integrity');
        integrity.append(button(state.verifying ? t('auditIntegrityChecking', '正在校验审计链…') : t('lifecycleVerify', '校验此对话审计链'), verify, state.verifying || state.loading || Boolean(state.error)));
        const message = el('p', '', state.integrity || t('lifecycleIntegrityHint', '原始事件及其审计链保持不变；此处仅调整展示入口。')); message.setAttribute('role', 'status'); integrity.append(message); state.host.append(integrity);
    }
    function mount(host, record, active) {
        const revision = [record.conversationId, record.runtimeGeneration, record.status, record.lifecycleState, record.lifecycleCompletedAt, record.updatedAt].join('|');
        const changed = state.id !== record.conversationId;
        if (changed) {
            if (state.controller) state.controller.abort(); state.generation++; state.verification++;
            Object.assign(state, { id: record.conversationId, page: 1, type: 'all', result: 'all', items: [], total: 0, pages: 0, latest: null, error: '', loaded: false, loading: false, integrity: '', verifying: false, revision: '' });
        }
        const stale = state.revision !== revision;
        state.host = host; state.record = record; state.revision = revision;
        render(); summary();
        if (!state.loading && (changed || stale || (!state.loaded && !state.error && active))) load();
    }
    function refresh() { if (state.id) load(); }
    return { mount, refresh, filterParams, acceptEvents, failureContext, eventTitle };
}));
