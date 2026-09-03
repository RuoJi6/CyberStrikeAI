(function (root, factory) {
    'use strict';
    const api = factory(root || {});
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) {
        root.initNetworkActivityPage = api.init;
        root.stopNetworkActivityPage = api.stop;
        root.refreshNetworkActivityConversations = api.refreshConversations;
    }
}(typeof window !== 'undefined' ? window : globalThis, function (root) {
    'use strict';

    const MAX_EVENTS = 500;
    const MAX_PAUSED_EVENTS = 500;
    const MAX_SEEN_EVENTS = 1000;
    const MAX_RENDERED_EVENTS = 100;
    const RENDER_THROTTLE_MS = 250;
    const READY_STABILITY_MS = 150;
    const URL_PARAMS = Object.freeze({
        conversation: 'activity_conversation',
        domain: 'activity_domain',
        requestType: 'activity_type',
        decision: 'activity_decision',
        agent: 'activity_agent',
        tool: 'activity_tool',
        route: 'activity_route',
    });
    const REQUEST_TYPES = new Set(['all', 'dns', 'http', 'https', 'connect', 'tcp', 'udp', 'icmp']);
    const DECISIONS = new Set(['all', 'allowed', 'blocked']);
    const AGENTS = new Set(['all', 'container-agent']);
    const TOOLS = new Set(['all', 'unknown']);
    const state = {
        active: false,
        bound: false,
        conversations: [],
        selectedConversationId: '',
        events: [],
        pausedEvents: [],
        seenEventKeys: new Set(),
        seenEventOrder: [],
        paused: false,
        follow: true,
        domain: '',
        requestType: 'all',
        decision: 'all',
        agent: 'all',
        tool: 'all',
        route: 'all',
        availableRoutes: new Set(['direct']),
        controller: null,
        generation: 0,
        reconnectAttempt: 0,
        reconnectTimer: null,
        connectionStatus: 'idle',
        connectionDetail: '',
        statusBeforePause: 'live',
        loadGeneration: 0,
        renderTimer: null,
    };

    function t(key, fallback, values) {
        const fullKey = `containerManagement.${key}`;
        const replacements = values || {};
        let translated = typeof root.t === 'function'
            ? root.t(fullKey, { ...replacements, interpolation: { escapeValue: false } })
            : fallback;
        if (!translated || translated === fullKey) translated = fallback;
        return Object.entries(replacements).reduce((value, entry) => (
            String(value).replaceAll(`{{${entry[0]}}}`, String(entry[1]))
        ), String(translated));
    }

    function element(id) {
        return root.document && root.document.getElementById ? root.document.getElementById(id) : null;
    }

    function create(tag, className, text) {
        const node = root.document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    function readURLState() {
        if (!root.location || typeof URLSearchParams === 'undefined') return;
        const params = new URLSearchParams(root.location.search || '');
        state.selectedConversationId = String(params.get(URL_PARAMS.conversation) || '').trim();
        state.domain = Array.from(String(params.get(URL_PARAMS.domain) || '')).slice(0, 253).join('');
        const requestType = String(params.get(URL_PARAMS.requestType) || 'all').toLowerCase();
        const decision = String(params.get(URL_PARAMS.decision) || 'all').toLowerCase();
        const agent = String(params.get(URL_PARAMS.agent) || 'all').toLowerCase();
        const tool = String(params.get(URL_PARAMS.tool) || 'all').toLowerCase();
        const route = String(params.get(URL_PARAMS.route) || 'all').trim();
        state.requestType = REQUEST_TYPES.has(requestType) ? requestType : 'all';
        state.decision = DECISIONS.has(decision) ? decision : 'all';
        state.agent = AGENTS.has(agent) ? agent : 'all';
        state.tool = TOOLS.has(tool) ? tool : 'all';
        state.route = /^(all|direct|[a-z0-9][a-z0-9._:-]{0,127})$/.test(route) ? route : 'all';
        if (state.route !== 'all') state.availableRoutes.add(state.route);
    }

    function writeURLState() {
        if (!root.location || !root.history || typeof URL === 'undefined') return;
        const url = new URL(root.location.href);
        const setOrDelete = function (key, value, fallback) {
            if (!value || value === fallback) url.searchParams.delete(key);
            else url.searchParams.set(key, value);
        };
        setOrDelete(URL_PARAMS.conversation, state.selectedConversationId, '');
        setOrDelete(URL_PARAMS.domain, state.domain, '');
        setOrDelete(URL_PARAMS.requestType, state.requestType, 'all');
        setOrDelete(URL_PARAMS.decision, state.decision, 'all');
        setOrDelete(URL_PARAMS.agent, state.agent, 'all');
        setOrDelete(URL_PARAMS.tool, state.tool, 'all');
        setOrDelete(URL_PARAMS.route, state.route, 'all');
        root.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
    }

    function parseSSEText(previous, incoming) {
        const combined = String(previous || '') + String(incoming || '');
        if (combined.length > (1 << 20)) throw new Error('SSE frame exceeded client limit');
        const blocks = combined.split(/\r?\n\r?\n/);
        const remainder = blocks.pop() || '';
        const events = [];
        blocks.forEach(function (block) {
            let event = 'message';
            const data = [];
            block.split(/\r?\n/).forEach(function (line) {
                if (!line || line[0] === ':') return;
                const separator = line.indexOf(':');
                const field = separator < 0 ? line : line.slice(0, separator);
                let value = separator < 0 ? '' : line.slice(separator + 1);
                if (value[0] === ' ') value = value.slice(1);
                if (field === 'event') event = value || 'message';
                if (field === 'data') data.push(value);
            });
            if (data.length) events.push({ event, data: data.join('\n') });
        });
        return { remainder, events };
    }

    function isSafeActivityEvent(value) {
        if (!value || typeof value !== 'object') return false;
        if (!['dns', 'http', 'https', 'connect', 'tcp', 'udp', 'icmp'].includes(value.requestType)) return false;
        if (!['allowed', 'blocked'].includes(value.decision)) return false;
        if (typeof value.domain !== 'string' || value.domain.length < 1 || value.domain.length > 253) return false;
        if (typeof value.timestamp !== 'string' || Number.isNaN(new Date(value.timestamp).getTime())) return false;
        if (value.agent !== undefined && (typeof value.agent !== 'string' || value.agent.length > 128)) return false;
        if (value.tool !== undefined && (typeof value.tool !== 'string' || value.tool.length > 256)) return false;
        if (value.upstreamRouteId !== undefined && (typeof value.upstreamRouteId !== 'string' || !/^$|^[a-z0-9][a-z0-9._:-]{0,127}$/.test(value.upstreamRouteId))) return false;
        if (value.dnsQueryType !== undefined && (typeof value.dnsQueryType !== 'string' || value.dnsQueryType.length > 128)) return false;
        if (value.dnsAnswers !== undefined && (!Array.isArray(value.dnsAnswers) || value.dnsAnswers.length > 128 || value.dnsAnswers.some((answer) => typeof answer !== 'string' || answer.length > 1024))) return false;
        const aggregateCount = Number(value.aggregateCount || 0);
        if (!Number.isSafeInteger(aggregateCount) || aggregateCount < 0 || aggregateCount === 1) return false;
        if (aggregateCount > 1) {
            if (typeof value.aggregateKind !== 'string' || !/^[a-z0-9][a-z0-9._:-]{0,127}$/.test(value.aggregateKind)) return false;
            if (Number.isNaN(Date.parse(value.aggregateFirstAt)) || Number.isNaN(Date.parse(value.aggregateLastAt))) return false;
        }
        for (const field of ['aggregateDistinctTargets', 'aggregateDistinctPorts', 'aggregateDistinctVariants']) {
            const number = Number(value[field] || 0);
            if (!Number.isSafeInteger(number) || number < 0) return false;
        }
        return true;
    }

    function activityEventKey(event) {
        return JSON.stringify([
            event.timestamp, event.requestType, event.domain, event.port || 0,
            event.dnsQueryType || '', Array.isArray(event.dnsAnswers) ? event.dnsAnswers : [],
            Array.isArray(event.resolvedIps) ? event.resolvedIps : [], event.connectedIp || '',
            event.decision, event.ruleId || '', event.reason || '', event.upstreamRouteId || '',
            event.method || '', event.path || '', event.httpStatus || 0, event.outcome || '',
            event.latencyMs || 0, event.bytesUp || 0, event.bytesDown || 0,
            event.snapshotId || '', event.snapshotSha256 || '', event.agent || '', event.tool || '',
            event.aggregateCount || 0, event.aggregateKind || '', event.aggregateLastAt || '',
        ]);
    }

    function rememberActivity(event) {
        const key = activityEventKey(event);
        if (state.seenEventKeys.has(key)) return false;
        state.seenEventKeys.add(key);
        state.seenEventOrder.push(key);
        if (state.seenEventOrder.length > MAX_SEEN_EVENTS) {
            const expired = state.seenEventOrder.splice(0, state.seenEventOrder.length - MAX_SEEN_EVENTS);
            expired.forEach((value) => state.seenEventKeys.delete(value));
        }
        return true;
    }

    function resetEventHistory() {
        state.events = [];
        state.pausedEvents = [];
        state.seenEventKeys = new Set();
        state.seenEventOrder = [];
    }

    function connectionLabel(status, detail) {
        const labels = {
            idle: t('activityStatusIdle', '尚未连接'),
            loading: t('activityStatusLoading', '正在加载对话…'),
            connecting: t('activityStatusConnecting', '正在连接实时流…'),
            live: t('activityStatusLive', '实时连接'),
            paused: t('activityStatusPaused', '已暂停显示'),
            waiting: t('activityStatusWaiting', '等待网关就绪…'),
            error: t('activityStatusError', '连接失败'),
        };
        return detail ? `${labels[status] || labels.idle} · ${activityText(detail, detail)}` : (labels[status] || labels.idle);
    }

    function connectionStatusNeedsUpdate(currentStatus, currentDetail, nextStatus, nextDetail) {
        return String(currentStatus || '') !== String(nextStatus || '') || String(currentDetail || '') !== String(nextDetail || '');
    }

    function setConnectionStatus(status, detail) {
        const nextDetail = String(detail || '');
        if (!connectionStatusNeedsUpdate(state.connectionStatus, state.connectionDetail, status, nextDetail)) return;
        state.connectionStatus = status;
        state.connectionDetail = nextDetail;
        const badge = element('network-activity-connection');
        if (!badge) return;
        badge.className = `network-activity-connection is-${status}`;
        let label = badge.querySelector('b');
        if (!label) {
            label = create('b');
            badge.appendChild(label);
        }
        label.textContent = connectionLabel(status, state.connectionDetail);
    }

    function statusLabel(value) {
        const key = `status.${String(value || 'unknown')}`;
        return t(key, String(value || 'unknown'));
    }

    function renderConversationOptions() {
        const select = element('network-activity-conversation');
        if (!select) return;
        const placeholder = create('option', '', t('activitySelectConversation', '选择一个已创建的对话容器'));
        placeholder.value = '';
        select.replaceChildren(placeholder);
        state.conversations.forEach(function (record) {
            const option = create('option');
            option.value = String(record.conversationId || '');
            option.textContent = `${record.conversationTitle || record.conversationId || t('untitled', '未命名对话')} · ${statusLabel(record.runtimeStatus || record.status)}`;
            select.appendChild(option);
        });
        select.value = state.selectedConversationId;
        if (root.CyberStrikeSelect) {
            root.CyberStrikeSelect.enhance(select);
            root.CyberStrikeSelect.refresh(select);
        }
    }

    function renderRouteOptions() {
        const select = element('network-activity-route');
        if (!select) return;
        const all = create('option', '', t('filterAll', '全部'));
        all.value = 'all';
        const direct = create('option', '', t('activityDirectRoute', '直接出口'));
        direct.value = 'direct';
        const routes = Array.from(state.availableRoutes)
            .filter((route) => route && route !== 'direct' && route !== 'all')
            .sort((left, right) => left.localeCompare(right));
        select.replaceChildren(all, direct, ...routes.map(function (route) {
            const option = create('option', '', route);
            option.value = route;
            return option;
        }));
        select.value = state.route;
        if (root.CyberStrikeSelect) {
            root.CyberStrikeSelect.enhance(select);
            root.CyberStrikeSelect.refresh(select);
        }
    }

    function syncControls() {
        const conversation = element('network-activity-conversation');
        const domain = element('network-activity-domain');
        const requestType = element('network-activity-type');
        const decision = element('network-activity-decision');
        const agent = element('network-activity-agent');
        const tool = element('network-activity-tool');
        const route = element('network-activity-route');
        if (conversation) conversation.value = state.selectedConversationId;
        if (domain) domain.value = state.domain;
        if (requestType) requestType.value = state.requestType;
        if (decision) decision.value = state.decision;
        if (agent) agent.value = state.agent;
        if (tool) tool.value = state.tool;
        renderRouteOptions();
        if (route) route.value = state.route;
        [conversation, requestType, decision, agent, tool, route].forEach(function (select) {
            if (select && root.CyberStrikeSelect) root.CyberStrikeSelect.refresh(select);
        });
        updateActionControls();
    }

    function updateActionControls() {
        const pause = element('network-activity-pause');
        if (pause) {
            pause.disabled = !state.selectedConversationId;
            pause.textContent = state.paused ? t('activityResume', '继续显示') : t('activityPause', '暂停显示');
        }
        const follow = element('network-activity-follow');
        if (follow) {
            follow.classList.toggle('is-active', state.follow);
            follow.setAttribute('aria-pressed', state.follow ? 'true' : 'false');
            follow.textContent = t('activityFollow', '跟随最新');
        }
    }

    function formatTime(value) {
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? '—' : date.toLocaleTimeString([], { hour12: false });
    }

    function formatBytes(value) {
        const bytes = Number(value || 0);
        if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
        const units = ['B', 'KiB', 'MiB', 'GiB'];
        const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
        const amount = bytes / (1024 ** index);
        return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
    }

    function activityText(key, fallback) {
        return t(`activityValues.${key}`, fallback || key);
    }

    function policySource(event) {
        if (event.ruleId) return `${t('activityRule', '规则')} ${event.ruleId}`;
        if (['forbidden-address', 'forbidden-hostname', 'dns-rebinding'].includes(event.reason)) {
            return t('activitySystemNetworkIsolation', '系统网络隔离');
        }
        if (event.reason === 'default-deny') return t('activityBoundaryDefaultDeny', '边界默认拒绝');
        return activityText(event.reason || 'unknown', event.reason || 'unknown');
    }

    function cell(label, primary, secondary, className) {
        const td = create('td', className || '');
        td.dataset.label = label;
        td.appendChild(create('strong', '', primary || '—'));
        if (secondary) td.appendChild(create('small', '', secondary));
        return td;
    }

    function activityRow(event) {
        const row = create('tr', `is-${event.decision}`);
        const requestType = event.requestType === 'dns' && event.dnsQueryType
            ? `DNS ${String(event.dnsQueryType).toUpperCase()}`
            : String(event.requestType || '').toUpperCase();
        let requestDetail = event.requestType === 'http' || event.requestType === 'https'
            ? [event.method, event.path].filter(Boolean).join(' ')
            : (['connect', 'tcp', 'udp'].includes(event.requestType) ? `:${event.port || 0}` : '');
        if (Number(event.aggregateCount || 0) > 1) requestDetail = `${requestDetail}${requestDetail ? ' · ' : ''}批次 ×${event.aggregateCount}`;
        const target = event.port ? `${event.domain}:${event.port}` : event.domain;
        const resolved = Array.isArray(event.resolvedIps) && event.resolvedIps.length
            ? event.resolvedIps.join(', ')
            : (Array.isArray(event.dnsAnswers) && event.dnsAnswers.length ? event.dnsAnswers.join(' · ') : '—');
        const connected = event.connectedIp ? `${t('activityConnected', '连接')} ${event.connectedIp}` : '';
        const decision = activityText(event.decision, event.decision);
        const rule = policySource(event);
        const agent = event.agent || 'container-agent';
        const tool = event.tool ? `${t('activityTool', '工具')} ${event.tool}` : t('activityToolUnknown', '工具未知');
        const route = event.upstreamRouteId ? `${t('activityRoute', '路由')} ${event.upstreamRouteId}` : t('activityDirectRoute', '直接出口');
        const result = activityText(event.outcome || 'unknown', event.outcome || 'unknown');
        const performance = `${Number(event.latencyMs || 0)} ms · ↑${formatBytes(event.bytesUp)} ↓${formatBytes(event.bytesDown)}`;
        const aggregate = Number(event.aggregateCount || 0) > 1 ? `${activityText(event.aggregateKind, event.aggregateKind)} · ${event.aggregateCount} 次 · ` : '';
        const status = `${aggregate}${(event.requestType === 'http' || event.requestType === 'https') && event.httpStatus ? `HTTP ${event.httpStatus} · ` : ''}${performance}`;
        row.append(
            cell(t('activityTime', '时间'), formatTime(event.timestamp), new Date(event.timestamp).toLocaleDateString()),
            cell(t('activityRequest', '请求'), requestType, requestDetail, 'is-request'),
            cell(t('activityTarget', '目标'), target, event.requestType === 'http' || event.requestType === 'https' ? event.path : '', 'is-target'),
            cell(t('activityResolution', '解析 / 连接'), resolved, connected, 'is-resolution'),
            cell(t('activityDecision', '策略判定'), decision, rule, `is-decision is-${event.decision}`),
            cell(t('activityContext', '上下文'), agent, `${tool} · ${route}`, 'is-context'),
            cell(t('activityResult', '结果'), result, status, 'is-result'),
        );
        return row;
    }

    function filteredEvents() {
        const query = String(state.domain || '').normalize('NFKC').trim().toLocaleLowerCase();
        return state.events.filter(function (event) {
            if (state.requestType !== 'all' && event.requestType !== state.requestType) return false;
            if (state.decision !== 'all' && event.decision !== state.decision) return false;
            if (state.agent !== 'all' && (event.agent || 'container-agent') !== state.agent) return false;
            if (state.tool !== 'all' && (event.tool || 'unknown') !== state.tool) return false;
            if (state.route !== 'all' && (event.upstreamRouteId || 'direct') !== state.route) return false;
            if (!query) return true;
            const haystack = [event.domain, event.connectedIp, event.dnsQueryType, ...(Array.isArray(event.resolvedIps) ? event.resolvedIps : []), ...(Array.isArray(event.dnsAnswers) ? event.dnsAnswers : [])]
                .join(' ').normalize('NFKC').toLocaleLowerCase();
            return haystack.includes(query);
        });
    }

    function renderCounts(visible) {
        const rootNode = element('network-activity-counts');
        if (!rootNode) return;
        const eventWeight = (event) => Number(event.aggregateCount || 0) > 1 ? Number(event.aggregateCount) : 1;
        const allowed = state.events.filter((event) => event.decision === 'allowed').reduce((total, event) => total + eventWeight(event), 0);
        const blocked = state.events.filter((event) => event.decision === 'blocked').reduce((total, event) => total + eventWeight(event), 0);
        const visibleCount = visible.reduce((total, event) => total + eventWeight(event), 0);
        const values = [
            [t('activityVisibleCount', '可见 {{count}}', { count: visibleCount }), 'neutral'],
            [t('activityAllowedCount', '允许 {{count}}', { count: allowed }), 'success'],
            [t('activityBlockedCount', '阻断 {{count}}', { count: blocked }), 'danger'],
        ];
        if (state.pausedEvents.length) values.push([t('activityBufferedCount', '待显示 {{count}}', { count: state.pausedEvents.length }), 'warning']);
        rootNode.replaceChildren(...values.map(function (value) { return create('span', `is-${value[1]}`, value[0]); }));
    }

    function renderEvents() {
        const body = element('network-activity-rows');
        const empty = element('network-activity-empty');
        const table = body && body.closest ? body.closest('table') : null;
        const summary = element('network-activity-summary');
        if (!body || !empty || !table) return;
        const visible = filteredEvents();
        const rendered = visible.length > MAX_RENDERED_EVENTS
            ? visible.slice(visible.length - MAX_RENDERED_EVENTS)
            : visible;
        body.replaceChildren(...rendered.map(activityRow));
        const hasEvents = rendered.length > 0;
        table.hidden = !hasEvents;
        empty.hidden = hasEvents;
        if (summary) {
            const receivedCount = state.events.reduce((total, event) => total + (Number(event.aggregateCount || 0) > 1 ? Number(event.aggregateCount) : 1), 0);
            const renderedCount = rendered.reduce((total, event) => total + (Number(event.aggregateCount || 0) > 1 ? Number(event.aggregateCount) : 1), 0);
            summary.textContent = state.events.length
                ? t('activitySummary', '已接收 {{total}} 条，当前显示 {{visible}} 条', { total: receivedCount, visible: renderedCount })
                : t('activityEmptySummary', '尚未收到网络活动');
        }
        renderCounts(rendered);
        updateActionControls();
        if (hasEvents && state.follow) {
            const wrap = element('network-activity-table-wrap');
            const schedule = typeof root.requestAnimationFrame === 'function' ? root.requestAnimationFrame.bind(root) : root.setTimeout;
            if (wrap) schedule(function () { wrap.scrollTop = wrap.scrollHeight; }, 0);
        }
    }

    function scheduleEventRender() {
        if (state.renderTimer !== null) return;
        state.renderTimer = root.setTimeout(function () {
            state.renderTimer = null;
            renderEvents();
        }, RENDER_THROTTLE_MS);
    }

    function yieldToMainThread() {
        return new Promise(function (resolve) { root.setTimeout(resolve, 0); });
    }

    function addActivity(event) {
        if (!isSafeActivityEvent(event) || event.conversationId !== state.selectedConversationId) return;
        if (!rememberActivity(event)) return;
        const route = String(event.upstreamRouteId || 'direct');
        if (!state.availableRoutes.has(route)) {
            state.availableRoutes.add(route);
            renderRouteOptions();
        }
        if (state.paused) {
            state.pausedEvents.push(event);
            if (state.pausedEvents.length > MAX_PAUSED_EVENTS) state.pausedEvents.splice(0, state.pausedEvents.length - MAX_PAUSED_EVENTS);
            renderCounts(filteredEvents());
            return;
        }
        state.events.push(event);
        if (state.events.length > MAX_EVENTS) state.events.splice(0, state.events.length - MAX_EVENTS);
        scheduleEventRender();
    }

    function cancelStream() {
        state.generation += 1;
        if (state.controller) {
            try { state.controller.abort(); } catch (_) { /* noop */ }
            state.controller = null;
        }
        if (state.reconnectTimer) {
            root.clearTimeout(state.reconnectTimer);
            state.reconnectTimer = null;
        }
    }

    function responseError(status, code) {
        const error = new Error(code || `http_${status}`);
        error.status = status;
        error.code = code || '';
        return error;
    }

    function shouldShowConnecting(retrying, currentStatus) {
        return !retrying || !['waiting', 'error'].includes(String(currentStatus || ''));
    }

    async function connectStream(options) {
        const retrying = Boolean(options && options.retrying);
        cancelStream();
        if (!state.active || !state.selectedConversationId) {
            setConnectionStatus('idle');
            return;
        }
        const generation = state.generation;
        const controller = new AbortController();
        state.controller = controller;
        if (shouldShowConnecting(retrying, state.connectionStatus)) setConnectionStatus('connecting');
        let terminalCode = '';
        let readyTimer = null;
        const cancelReadyAnnouncement = function () {
            if (!readyTimer) return;
            root.clearTimeout(readyTimer);
            readyTimer = null;
        };
        const scheduleReadyAnnouncement = function () {
            cancelReadyAnnouncement();
            readyTimer = root.setTimeout(function () {
                readyTimer = null;
                if (state.active && generation === state.generation && state.controller === controller) {
                    setConnectionStatus(state.paused ? 'paused' : 'live');
                }
            }, READY_STABILITY_MS);
        };
        try {
            const url = `/api/conversations/${encodeURIComponent(state.selectedConversationId)}/egress-activity/stream?tail=100`;
            const response = await root.apiFetch(url, { method: 'GET', headers: { Accept: 'text/event-stream' }, signal: controller.signal });
            if (!response.ok) {
                const payload = await response.json().catch(function () { return {}; });
                throw responseError(response.status, payload.code || '');
            }
            if (!response.body || typeof response.body.getReader !== 'function') throw responseError(503, 'stream_unavailable');
            state.reconnectAttempt = 0;
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let remainder = '';
            while (true) {
                const chunk = await reader.read();
                if (chunk.done) break;
                const parsed = parseSSEText(remainder, decoder.decode(chunk.value, { stream: true }));
                remainder = parsed.remainder;
                parsed.events.forEach(function (frame) {
                    let payload = null;
                    try { payload = JSON.parse(frame.data); } catch (_) { return; }
                    if (frame.event === 'ready') scheduleReadyAnnouncement();
                    if (frame.event === 'activity') {
                        cancelReadyAnnouncement();
                        setConnectionStatus(state.paused ? 'paused' : 'live');
                        addActivity(payload);
                    }
                    if (frame.event === 'stream_error') {
                        cancelReadyAnnouncement();
                        terminalCode = String(payload && payload.code || 'stream_closed');
                    }
                });
                await yieldToMainThread();
            }
            if (!controller.signal.aborted) throw responseError(503, terminalCode || 'stream_closed');
        } catch (error) {
            if (controller.signal.aborted || generation !== state.generation || !state.active) return;
            const nonRetryable = error && (error.status === 400 || error.status === 403 || error.status === 404);
            if (nonRetryable) {
                setConnectionStatus('error', error.code || 'unavailable');
                return;
            }
            const waiting = error && (error.status === 409 || error.code === 'not_ready');
            setConnectionStatus(waiting ? 'waiting' : 'error', error && error.code || 'unavailable');
            scheduleReconnect(generation);
        } finally {
            cancelReadyAnnouncement();
            if (state.controller === controller) state.controller = null;
        }
    }

    function scheduleReconnect(generation) {
        if (!state.active || generation !== state.generation) return;
        state.reconnectAttempt += 1;
        const delay = Math.min(15000, 1000 * (2 ** Math.min(4, state.reconnectAttempt - 1)));
        state.reconnectTimer = root.setTimeout(function () {
            state.reconnectTimer = null;
            if (state.active && generation === state.generation) connectStream({ retrying: true });
        }, delay);
    }

    async function requestJSON(url) {
        const response = await root.apiFetch(url);
        const payload = await response.json().catch(function () { return {}; });
        if (!response.ok) throw responseError(response.status, payload.code || 'load_failed');
        return payload;
    }

    async function refreshConversations() {
        const generation = ++state.loadGeneration;
        const button = element('network-activity-refresh');
        if (button) button.disabled = true;
        setConnectionStatus('loading');
        try {
            const records = [];
            let page = 1;
            let totalPages = 1;
            do {
                const payload = await requestJSON(`/api/container-runtimes?page=${page}&page_size=100&status=all`);
                if (generation !== state.loadGeneration || !state.active) return;
                records.push(...(Array.isArray(payload.items) ? payload.items : []));
                totalPages = Math.min(100, Math.max(1, Number(payload.totalPages || 1)));
                page += 1;
            } while (page <= totalPages);
            state.conversations = records.filter(function (record) {
                return record && record.status === 'created' && record.desired && record.desired.gatewayImageDigest;
            });
            if (!state.conversations.some((record) => record.conversationId === state.selectedConversationId)) {
                const preferred = state.conversations.find((record) => record.runtimeStatus === 'running') || state.conversations[0];
                state.selectedConversationId = preferred ? String(preferred.conversationId) : '';
                resetEventHistory();
                state.availableRoutes = new Set(['direct', state.route]);
            }
            renderConversationOptions();
            syncControls();
            writeURLState();
            if (state.selectedConversationId) connectStream();
            else setConnectionStatus('idle', 'no_containers');
            renderEvents();
        } catch (error) {
            if (generation !== state.loadGeneration || !state.active) return;
            state.conversations = [];
            renderConversationOptions();
            setConnectionStatus('error', 'load_failed');
        } finally {
            if (button && generation === state.loadGeneration) button.disabled = false;
        }
    }

    function bindControls() {
        if (state.bound || !root.document) return;
        state.bound = true;
        const conversation = element('network-activity-conversation');
        const domain = element('network-activity-domain');
        const requestType = element('network-activity-type');
        const decision = element('network-activity-decision');
        const agent = element('network-activity-agent');
        const tool = element('network-activity-tool');
        const route = element('network-activity-route');
        const pause = element('network-activity-pause');
        const follow = element('network-activity-follow');
        const clear = element('network-activity-clear');
        const refresh = element('network-activity-refresh');
        const wrap = element('network-activity-table-wrap');
        if (conversation) conversation.addEventListener('change', function () {
            state.selectedConversationId = String(conversation.value || '');
            resetEventHistory();
            state.availableRoutes = new Set(['direct', state.route]);
            state.paused = false;
            writeURLState();
            renderEvents();
            connectStream();
        });
        if (domain) domain.addEventListener('input', function () {
            state.domain = Array.from(domain.value || '').slice(0, 253).join('');
            writeURLState();
            renderEvents();
        });
        if (requestType) requestType.addEventListener('change', function () {
            state.requestType = REQUEST_TYPES.has(requestType.value) ? requestType.value : 'all';
            writeURLState();
            renderEvents();
        });
        if (decision) decision.addEventListener('change', function () {
            state.decision = DECISIONS.has(decision.value) ? decision.value : 'all';
            writeURLState();
            renderEvents();
        });
        if (agent) agent.addEventListener('change', function () {
            state.agent = AGENTS.has(agent.value) ? agent.value : 'all';
            writeURLState();
            renderEvents();
        });
        if (tool) tool.addEventListener('change', function () {
            state.tool = TOOLS.has(tool.value) ? tool.value : 'all';
            writeURLState();
            renderEvents();
        });
        if (route) route.addEventListener('change', function () {
            state.route = String(route.value || 'all');
            writeURLState();
            renderEvents();
        });
        if (pause) pause.addEventListener('click', function () {
            state.paused = !state.paused;
            if (state.paused) state.statusBeforePause = state.connectionStatus === 'paused' ? 'live' : state.connectionStatus;
            if (!state.paused && state.pausedEvents.length) {
                state.events.push(...state.pausedEvents);
                state.pausedEvents = [];
                if (state.events.length > MAX_EVENTS) state.events.splice(0, state.events.length - MAX_EVENTS);
            }
            setConnectionStatus(state.paused ? 'paused' : (state.statusBeforePause || 'live'));
            renderEvents();
        });
        if (follow) follow.addEventListener('click', function () {
            state.follow = !state.follow;
            renderEvents();
        });
        if (clear) clear.addEventListener('click', function () {
            state.events = [];
            state.pausedEvents = [];
            renderEvents();
        });
        if (refresh) refresh.addEventListener('click', refreshConversations);
        if (wrap) wrap.addEventListener('scroll', function () {
            if (wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight > 48 && state.follow) {
                state.follow = false;
                updateActionControls();
            }
        });
    }

    function init() {
        if (!root.document || !element('page-network-activity')) return;
        state.active = true;
        readURLState();
        bindControls();
        syncControls();
        renderEvents();
        refreshConversations();
    }

    function stop() {
        state.active = false;
        state.loadGeneration += 1;
        cancelStream();
        if (state.renderTimer !== null) {
            root.clearTimeout(state.renderTimer);
            state.renderTimer = null;
        }
        setConnectionStatus('idle');
    }

    if (root.document && typeof root.document.addEventListener === 'function') {
        root.document.addEventListener('languagechange', function () {
            if (!state.active) return;
            renderConversationOptions();
            syncControls();
            setConnectionStatus(state.connectionStatus, state.connectionDetail);
            renderEvents();
        });
    }

    return {
        init,
        stop,
        refreshConversations,
        parseSSEText,
        isSafeActivityEvent,
        activityEventKey,
        shouldShowConnectingForTest: shouldShowConnecting,
        connectionStatusNeedsUpdateForTest: connectionStatusNeedsUpdate,
        readyStabilityMsForTest: READY_STABILITY_MS,
        maxRenderedEventsForTest: MAX_RENDERED_EVENTS,
        renderThrottleMsForTest: RENDER_THROTTLE_MS,
        filteredEventsForTest: function (events, filters) {
            const previous = { events: state.events, domain: state.domain, requestType: state.requestType, decision: state.decision, agent: state.agent, tool: state.tool, route: state.route };
            state.events = events;
            state.domain = filters.domain || '';
            state.requestType = filters.requestType || 'all';
            state.decision = filters.decision || 'all';
            state.agent = filters.agent || 'all';
            state.tool = filters.tool || 'all';
            state.route = filters.route || 'all';
            const result = filteredEvents();
            Object.assign(state, previous);
            return result;
        },
    };
}));
