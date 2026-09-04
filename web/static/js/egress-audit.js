(function (root, factory) {
    'use strict';
    const api = factory(root || {});
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) {
        root.initEgressAuditPage = api.init;
        root.stopEgressAuditPage = api.stop;
        root.refreshEgressAuditPage = api.refresh;
    }
}(typeof window !== 'undefined' ? window : globalThis, function (root) {
    'use strict';

    const PAGE_SIZES = new Set([10, 20, 50, 100]);
    const CATEGORIES = new Set(['all', 'network', 'lifecycle']);
    const NETWORK_TYPES = new Set(['dns', 'http', 'https', 'connect', 'tcp', 'udp', 'icmp']);
    const LIFECYCLE_TYPES = new Set(['create', 'start', 'stop', 'rebuild', 'delete', 'reconcile', 'health']);
    const TYPES = new Set(['all', ...NETWORK_TYPES, ...LIFECYCLE_TYPES]);
    const DECISIONS = new Set(['all', 'allowed', 'blocked', 'success', 'failure']);
    const AUDIT_EVENT_FIELDS = new Set([
        'id', 'chainSequence', 'previousHash', 'eventHash', 'recordedAt', 'occurredAt', 'category', 'eventType', 'conversationId', 'conversationTitle',
        'containerId', 'agentId', 'runtimeGeneration', 'snapshotId', 'snapshotSha256', 'domain', 'dnsQueryType', 'dnsAnswers', 'resolvedIps',
        'eventId', 'runtimeMode', 'runtimeInstanceId', 'toolName', 'executionId', 'toolCallId', 'activityScopeId',
        'attributionStatus', 'declaredActivityKind', 'observedActivityKind', 'hashVersion',
        'connectedIp', 'port', 'decision', 'result', 'ruleId', 'reason', 'upstreamRouteId', 'method', 'path',
        'httpStatus', 'outcome', 'latencyMs', 'bytesUp', 'bytesDown', 'lifecycleOperation', 'lifecycleState', 'message', 'httpPacket',
        'aggregateCount', 'aggregateKind', 'aggregateFirstAt', 'aggregateLastAt', 'aggregateDistinctTargets', 'aggregateDistinctPorts', 'aggregateDistinctVariants',
    ]);
    const URL_KEYS = Object.freeze({
        page: 'audit_page', pageSize: 'audit_page_size', query: 'audit_q',
        conversation: 'audit_conversation', category: 'audit_category', type: 'audit_type', decision: 'audit_decision',
    });
    const state = {
        active: false, bound: false, loading: false, integrityLoading: false, conversationsLoading: false,
        generation: 0, searchTimer: null, listController: null, integrityController: null,
        page: 1, pageSize: 20, query: '', conversation: '', category: 'all', type: 'all', decision: 'all',
        total: 0, totalPages: 0, items: [], summary: { total: 0, network: 0, lifecycle: 0, blocked: 0, failures: 0 },
        conversations: [], integrity: null, integrityError: '', error: '', selected: new Set(),
    };

    function t(key, fallback, values) {
        const fullKey = `containerManagement.${key}`;
        const replacements = values || {};
        let value = typeof root.t === 'function'
            ? root.t(fullKey, { ...replacements, interpolation: { escapeValue: false } })
            : fallback;
        if (!value || value === fullKey) value = fallback;
        return Object.entries(replacements).reduce((result, entry) => (
            String(result).replaceAll(`{{${entry[0]}}}`, String(entry[1]))
        ), String(value));
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

    function closedValue(raw, allowed, fallback) {
        const value = String(raw || fallback).toLowerCase();
        return allowed.has(value) ? value : fallback;
    }

    function readURLState(searchOverride) {
        if ((searchOverride === undefined && !root.location) || typeof URLSearchParams === 'undefined') return;
        const params = new URLSearchParams(searchOverride === undefined ? (root.location.search || '') : searchOverride);
        const page = Number.parseInt(params.get(URL_KEYS.page), 10);
        const pageSize = Number.parseInt(params.get(URL_KEYS.pageSize), 10);
        state.page = Number.isInteger(page) && page > 0 ? page : 1;
        state.pageSize = PAGE_SIZES.has(pageSize) ? pageSize : 20;
        state.query = Array.from(String(params.get(URL_KEYS.query) || '')).slice(0, 200).join('');
        state.conversation = Array.from(String(params.get(URL_KEYS.conversation) || '')).slice(0, 128).join('');
        state.category = closedValue(params.get(URL_KEYS.category), CATEGORIES, 'all');
        state.type = closedValue(params.get(URL_KEYS.type), TYPES, 'all');
        state.decision = closedValue(params.get(URL_KEYS.decision), DECISIONS, 'all');
    }

    function writeURLState() {
        if (!root.location || !root.history || typeof URL === 'undefined') return;
        const url = new URL(root.location.href);
        const setOrDelete = function (key, value, fallback) {
            if (!value || value === fallback) url.searchParams.delete(key);
            else url.searchParams.set(key, String(value));
        };
        setOrDelete(URL_KEYS.page, state.page, 1);
        setOrDelete(URL_KEYS.pageSize, state.pageSize, 20);
        setOrDelete(URL_KEYS.query, state.query, '');
        setOrDelete(URL_KEYS.conversation, state.conversation, '');
        setOrDelete(URL_KEYS.category, state.category, 'all');
        setOrDelete(URL_KEYS.type, state.type, 'all');
        setOrDelete(URL_KEYS.decision, state.decision, 'all');
        root.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
    }

    function syncControls() {
        const values = {
            'egress-audit-search': state.query,
            'egress-audit-conversation': state.conversation,
            'egress-audit-category': state.category,
            'egress-audit-type': state.type,
            'egress-audit-decision': state.decision,
            'egress-audit-page-size': String(state.pageSize),
        };
        Object.entries(values).forEach(([id, value]) => {
            const control = element(id);
            if (!control) return;
            control.value = value;
            if (control.tagName === 'SELECT' && root.CyberStrikeSelect) {
                root.CyberStrikeSelect.enhance(control);
                root.CyberStrikeSelect.refresh(control);
            }
        });
    }

    function queryParams(includePage) {
        const params = new URLSearchParams();
        if (includePage) {
            params.set('page', String(state.page));
            params.set('page_size', String(state.pageSize));
        }
        if (state.query) params.set('q', state.query);
        if (state.conversation) params.set('conversation_id', state.conversation);
        if (state.category !== 'all') params.set('category', state.category);
        if (state.type !== 'all') params.set('event_type', state.type);
        if (state.decision !== 'all') params.set('decision', state.decision);
        return params;
    }

    async function requestJSON(url, options) {
        const response = typeof root.apiFetch === 'function' ? await root.apiFetch(url, options || {}) : await root.fetch(url, options || {});
        const payload = await response.json().catch(function () { return {}; });
        if (!response.ok) throw new Error(payload.error || t('auditLoadFailed', '加载出站审计失败'));
        return payload;
    }

    function notify(message, type) {
        if (typeof root.showNotification === 'function') root.showNotification(message, type || 'info');
    }

    function safeString(value, maximum) {
        const text = String(value || '');
        if (text.length > maximum) return null;
        for (const character of text) {
            const code = character.codePointAt(0);
            if (code < 0x20 || code === 0x7f) return null;
        }
        return text;
    }

    function isSafeAuditEvent(event) {
        if (!event || typeof event !== 'object') return false;
        if (Object.keys(event).some((key) => !AUDIT_EVENT_FIELDS.has(key))) return false;
        if (!['network', 'lifecycle'].includes(event.category)) return false;
        if (!TYPES.has(String(event.eventType || ''))) return false;
        if (event.category === 'network' && !NETWORK_TYPES.has(event.eventType)) return false;
        if (event.category === 'lifecycle' && !LIFECYCLE_TYPES.has(event.eventType)) return false;
        if (!safeString(event.id, 128) || !safeString(event.conversationId, 128)) return false;
        if (!Number.isSafeInteger(Number(event.chainSequence)) || Number(event.chainSequence) < 1) return false;
        if (!/^[0-9a-f]{64}$/.test(String(event.previousHash || '')) || !/^[0-9a-f]{64}$/.test(String(event.eventHash || ''))) return false;
        if (Number.isNaN(Date.parse(event.occurredAt))) return false;
        const safeFields = [
            [event.conversationTitle, 512], [event.containerId, 128], [event.agentId, 128],
            [event.eventId, 128], [event.runtimeMode, 32], [event.runtimeInstanceId, 128], [event.toolName, 256],
            [event.executionId, 128], [event.toolCallId, 128], [event.activityScopeId, 128], [event.attributionStatus, 32],
            [event.declaredActivityKind, 32], [event.observedActivityKind, 32],
            [event.snapshotId, 128], [event.snapshotSha256, 128], [event.domain, 253], [event.dnsQueryType, 128],
            [event.connectedIp, 64], [event.ruleId, 256], [event.reason, 128],
            [event.upstreamRouteId, 128], [event.method, 32], [event.path, 1024],
            [event.outcome, 128], [event.lifecycleOperation, 128], [event.lifecycleState, 128], [event.message, 1024],
        ];
        if (safeFields.some(([value, maximum]) => safeString(value, maximum) === null)) return false;
        if (event.category === 'network' && !safeString(event.domain, 253)) return false;
        if (event.category === 'network' && event.eventType === 'http' && !safeString(event.path, 1024)) return false;
        const resolvedIps = event.resolvedIps === undefined ? [] : event.resolvedIps;
        if (!Array.isArray(resolvedIps) || resolvedIps.length > 64 || resolvedIps.some((value) => !safeString(value, 64))) return false;
        const dnsAnswers = event.dnsAnswers === undefined ? [] : event.dnsAnswers;
        if (!Array.isArray(dnsAnswers) || dnsAnswers.length > 128 || dnsAnswers.some((value) => !safeString(value, 1024))) return false;
        for (const [value, maximum] of [[event.runtimeGeneration, Number.MAX_SAFE_INTEGER], [event.port, 65535], [event.httpStatus, 999], [event.latencyMs, Number.MAX_SAFE_INTEGER], [event.bytesUp, Number.MAX_SAFE_INTEGER], [event.bytesDown, Number.MAX_SAFE_INTEGER]]) {
            const numeric = Number(value || 0);
            if (!Number.isSafeInteger(numeric) || numeric < 0 || numeric > maximum) return false;
        }
        if (![0, 1, 2, 3, 4].includes(Number(event.hashVersion || 0))) return false;
        if (event.runtimeMode && !['container', 'host_mitm'].includes(event.runtimeMode)) return false;
        if (event.attributionStatus && !['verified', 'legacy_unattributed', 'unattributed', 'invalid'].includes(event.attributionStatus)) return false;
        if (event.category === 'network' && !['allowed', 'blocked'].includes(event.decision)) return false;
        if (event.category === 'lifecycle' && !['success', 'failure'].includes(event.result)) return false;
        if (event.httpPacket !== undefined && !isSafeHTTPPacket(event.httpPacket)) return false;
        const aggregateCount = Number(event.aggregateCount || 0);
        if (!Number.isSafeInteger(aggregateCount) || aggregateCount < 0 || aggregateCount === 1) return false;
        if (aggregateCount > 1 && (typeof event.aggregateKind !== 'string' || Number.isNaN(Date.parse(event.aggregateFirstAt)) || Number.isNaN(Date.parse(event.aggregateLastAt)))) return false;
        for (const field of ['aggregateDistinctTargets', 'aggregateDistinctPorts', 'aggregateDistinctVariants']) {
            const number = Number(event[field] || 0);
            if (!Number.isSafeInteger(number) || number < 0) return false;
        }
        return true;
    }

    function isSafeHTTPPacket(packet) {
        if (!packet || typeof packet !== 'object') return false;
        const fields = new Set(['requestLine', 'requestHeaders', 'requestBody', 'requestBodyEncoding', 'requestBodyTruncated', 'requestContentEncoding', 'requestBodyDecoded', 'responseLine', 'responseHeaders', 'responseBody', 'responseBodyEncoding', 'responseBodyTruncated', 'responseContentEncoding', 'responseBodyDecoded', 'sensitiveDataRedacted']);
        if (Object.keys(packet).some((key) => !fields.has(key))) return false;
        if (typeof packet.requestLine !== 'string' || packet.requestLine.length > 65536) return false;
        if (typeof packet.responseLine !== 'string' || packet.responseLine.length > 65536) return false;
        for (const headers of [packet.requestHeaders || {}, packet.responseHeaders || {}]) {
            if (!headers || typeof headers !== 'object' || Array.isArray(headers) || Object.keys(headers).length > 128) return false;
            for (const [name, values] of Object.entries(headers)) {
                if (!name || name.length > 256 || !Array.isArray(values) || values.length > 128) return false;
                if (values.some((value) => typeof value !== 'string' || value.length > 65536)) return false;
            }
        }
        for (const direction of ['request', 'response']) {
            const body = packet[direction + 'Body'] || '';
            const encoding = packet[direction + 'BodyEncoding'] || '';
            const contentEncoding = packet[direction + 'ContentEncoding'] || '';
            if (typeof body !== 'string' || body.length > 70000 || !['', 'utf8', 'base64', 'hex'].includes(encoding)) return false;
            if (typeof contentEncoding !== 'string' || contentEncoding.length > 256 || /[\r\n\0]/.test(contentEncoding)) return false;
            if (packet[direction + 'BodyDecoded'] !== undefined && typeof packet[direction + 'BodyDecoded'] !== 'boolean') return false;
        }
        return true;
    }

    function isSafeIntegrity(integrity) {
        if (!integrity || typeof integrity !== 'object' || integrity.status !== 'verified') return false;
        if (Object.keys(integrity).some((key) => !['status', 'conversations', 'events', 'verifiedAt'].includes(key))) return false;
        if (!Number.isSafeInteger(Number(integrity.conversations)) || Number(integrity.conversations) < 0) return false;
        if (!Number.isSafeInteger(Number(integrity.events)) || Number(integrity.events) < 0) return false;
        return !Number.isNaN(Date.parse(integrity.verifiedAt));
    }

    function isSafeAuditConversation(item) {
        if (!item || typeof item !== 'object') return false;
        if (Object.keys(item).some((key) => !['conversationId', 'conversationTitle'].includes(key))) return false;
        return Boolean(safeString(item.conversationId, 128)) && safeString(item.conversationTitle, 512) !== null;
    }

    function syncConversationOptions() {
        const select = element('egress-audit-conversation');
        if (!select) return;
        const current = state.conversation;
        const options = [create('option', '', t('auditAllConversations', '全部对话'))];
        options[0].value = '';
        state.conversations.forEach((item) => {
            const option = create('option', '', item.conversationTitle || item.conversationId);
            option.value = item.conversationId;
            option.title = item.conversationId;
            options.push(option);
        });
        if (current && !state.conversations.some((item) => item.conversationId === current)) {
            const option = create('option', '', current);
            option.value = current;
            options.push(option);
        }
        select.replaceChildren(...options);
        select.value = current;
        if (root.CyberStrikeSelect) {
            root.CyberStrikeSelect.enhance(select);
            root.CyberStrikeSelect.refresh(select);
        }
    }

    function shortHash(value) {
        const text = String(value || '');
        return text.length > 24 ? `${text.slice(0, 14)}…${text.slice(-8)}` : (text || '—');
    }

    function formatDate(value) {
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
    }

    function formatBytes(value) {
        const bytes = Number(value || 0);
        if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
        const units = ['B', 'KiB', 'MiB', 'GiB'];
        const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
        const amount = bytes / (1024 ** index);
        return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
    }

    function packetSummary(event) {
        if (!event || event.category !== 'network') return { primary: '—', secondary: '' };
        let primary = eventTypeLabel(event.eventType);
        if (event.eventType === 'http' || event.eventType === 'https') {
            primary = [event.method || eventTypeLabel(event.eventType), event.path || '/'].filter(Boolean).join(' ');
        } else if (event.eventType === 'connect' || event.eventType === 'tcp' || event.eventType === 'udp') {
            primary = `${eventTypeLabel(event.eventType)} ${event.domain || '—'}${event.port ? `:${event.port}` : ''}`;
        } else if (event.eventType === 'icmp') {
            primary = `ICMP ${event.domain || '—'}`;
        } else if (event.eventType === 'dns') {
            primary = `DNS ${(event.dnsQueryType || '').toUpperCase()} ${event.domain || '—'}`.replace('DNS  ', 'DNS ');
        }
        const aggregate = Number(event.aggregateCount || 0) > 1 ? ` · 批次 ${event.aggregateCount} 次` : '';
        return {
            primary,
            secondary: event.eventType === 'dns' && Array.isArray(event.dnsAnswers) && event.dnsAnswers.length
                ? event.dnsAnswers.join(' · ') + aggregate
                : `↑${formatBytes(event.bytesUp)} · ↓${formatBytes(event.bytesDown)}${aggregate}`,
        };
    }

    function eventTypeLabel(value) {
        const labels = {
            dns: 'DNS', http: 'HTTP', https: 'HTTPS（已解密）', connect: 'CONNECT', tcp: 'TCP', udp: 'UDP', icmp: 'ICMP',
            create: t('auditCreate', '创建'), start: t('auditStart', '启动'), stop: t('auditStop', '停止'),
			rebuild: t('auditRebuild', '重建'), delete: t('auditDelete', '删除'), reconcile: t('auditReconcile', '状态校准'),
			health: t('auditHealth', '出站健康'),
        };
        return labels[value] || String(value || '').toUpperCase();
    }

    function verdictLabel(value) {
        const labels = {
            allowed: t('activityAllowed', '允许'), blocked: t('activityBlocked', '阻断'),
            success: t('auditSuccess', '成功'), failure: t('auditFailure', '失败'),
        };
        return labels[value] || value;
    }

    function lifecycleMessage(event) {
		if (event.eventType === 'health') {
			const messages = {
				cooldown_started: t('auditHealthCooldownStarted', '出站网关已进入冷却'),
				cooldown_expired: t('auditHealthCooldownExpired', '出站网关冷却已结束'),
				health_paused: t('auditHealthPaused', '出站网关已暂停，需要手动恢复'),
				health_recovered: t('auditHealthRecovered', '出站网关已手动恢复'),
			};
			return messages[event.outcome] || t('auditHealthChanged', '出站健康状态已变更');
		}
        if (event.result === 'failure') return t('auditLifecycleFailed', '容器生命周期操作失败');
        if (event.eventType === 'create') return t('auditRuntimeCreated', '容器运行时已创建');
        if (event.eventType === 'delete') return t('auditRuntimeDeleted', '容器运行时已删除');
        if (event.eventType === 'reconcile') return t('auditRuntimeReconciled', '容器运行时状态已校准');
        return t('auditLifecycleCompleted', '容器生命周期操作已完成');
    }

    function outcomeLabel(event) {
        if (event.category === 'lifecycle') return lifecycleMessage(event);
        return t(`activityValues.${event.outcome}`, event.outcome || event.decision);
    }

    function cell(label, primary, secondary, className) {
        const td = create('td', className || '');
        td.dataset.label = label;
        td.append(create('strong', '', primary || '—'));
        if (secondary) td.append(create('span', '', secondary));
        return td;
    }

    function selectionCell(event) {
        const td = create('td', 'is-select');
        td.dataset.label = t('auditSelect', '选择');
        const checkbox = create('input', 'egress-audit-row-select');
        checkbox.type = 'checkbox';
        checkbox.checked = state.selected.has(event.id);
        checkbox.setAttribute('aria-label', t('auditSelectEvent', '选择审计事件'));
        checkbox.addEventListener('change', function () {
            if (checkbox.checked) state.selected.add(event.id);
            else state.selected.delete(event.id);
            renderSelectionControls();
        });
        td.append(checkbox);
        return td;
    }

    function packetCell(event, packet) {
        const td = cell(t('auditPacket', '报文摘要'), packet.primary, packet.secondary, 'is-packet');
        if (event.category === 'network' && (event.eventType === 'http' || event.eventType === 'https')) {
            const button = create('button', 'egress-audit-packet-open', t('auditPacketView', '查看完整报文'));
            button.type = 'button';
            button.addEventListener('click', function () { openPacket(event); });
            td.append(button);
        }
        return td;
    }

    function eventRow(event) {
        const row = create('tr', `is-${event.category}`);
        const target = event.category === 'network'
            ? `${event.domain || '—'}${event.port ? `:${event.port}` : ''}`
            : eventTypeLabel(event.lifecycleOperation || event.eventType);
        const resolution = event.connectedIp || (event.resolvedIps || []).join(', ') || (event.dnsAnswers || []).join(' · ');
        const verdict = event.decision || event.result;
		const reason = event.eventType === 'health'
			? t(`healthSignal.${event.reason || 'unknown'}`, event.reason || '')
			: (event.reason ? t(`activityValues.${event.reason}`, event.reason) : '');
		let rule = event.ruleId || reason || event.lifecycleState;
		if (!event.ruleId && ['forbidden-address', 'forbidden-hostname', 'dns-rebinding'].includes(event.reason)) {
			rule = t('activitySystemNetworkIsolation', '系统网络隔离');
		} else if (!event.ruleId && event.reason === 'default-deny') {
			rule = t('activityBoundaryDefaultDeny', '边界默认拒绝');
		}
        const runtimeLabel = event.runtimeMode === 'host_mitm' ? t('activityRuntimeHostMITM', 'Host MITM') : t('activityRuntimeContainer', '容器');
        const attributionLabels = {
            verified: t('activityAttributionVerified', '已验证'), legacy_unattributed: t('activityAttributionLegacy', '旧版运行时'),
            unattributed: t('activityAttributionUnattributed', '未归因'), invalid: t('activityAttributionInvalid', '归因无效'),
        };
        const tracePrimary = event.category === 'network'
            ? `${runtimeLabel} · ${event.agentId || 'Agent 未归因'} · ${event.toolName || '工具未知'}`
            : (event.snapshotSha256 ? shortHash(event.snapshotSha256) : t('auditGeneration', '代次 {{generation}}', { generation: event.runtimeGeneration }));
        const traceSecondary = event.category === 'network'
            ? [attributionLabels[event.attributionStatus] || t('activityAttributionUnattributed', '未归因'), event.executionId, event.toolCallId, event.activityScopeId].filter(Boolean).join(' · ')
            : [`#${event.chainSequence}`, shortHash(event.eventHash), shortHash(event.containerId), event.upstreamRouteId].filter((value) => value && value !== '—').join(' · ');
        const outcome = outcomeLabel(event);
        const packet = packetSummary(event);
        const resultDetail = event.category === 'network'
            ? `${Number(event.aggregateCount || 0) > 1 ? `${event.aggregateKind} · ${event.aggregateCount} 次 · ` : ''}${event.httpStatus ? `HTTP ${event.httpStatus} · ` : ''}${Number(event.latencyMs || 0)} ms`
            : t(`status.${event.lifecycleState}`, event.lifecycleState);
        row.append(
            selectionCell(event),
            cell(t('activityTime', '时间'), formatDate(event.occurredAt), '', 'is-time'),
            cell(t('auditEventType', '事件'), eventTypeLabel(event.eventType), event.category === 'network' ? t('auditCategoryNetwork', '网络') : t('auditCategoryLifecycle', '生命周期'), 'is-event'),
            cell(t('activityConversation', '对话'), event.conversationTitle || event.conversationId, event.conversationId, 'is-conversation'),
            cell(t('activityTarget', '目标'), target, resolution, 'is-target'),
            packetCell(event, packet),
            cell(t('activityDecision', '策略判定'), verdictLabel(verdict), rule, `is-decision is-${verdict}`),
            cell(t('auditTrace', '追溯'), tracePrimary, traceSecondary, 'is-trace'),
            cell(t('activityResult', '结果'), outcome, resultDetail, 'is-result'),
        );
        if (event.category === 'network') {
            row.title = [`event: ${event.eventId || '—'}`, `execution: ${event.executionId || '—'}`, `tool-call: ${event.toolCallId || '—'}`, `scope: ${event.activityScopeId || '—'}`, `generation: ${event.runtimeGeneration || 0}`, `declared: ${event.declaredActivityKind || 'unknown'}`, `observed: ${event.observedActivityKind || 'single'}`, `hash v${event.hashVersion || 1}`].join('\n');
        }
        return row;
    }

    function packetHeadersText(headers) {
        return Object.keys(headers || {}).sort().flatMap(function (name) {
            return (headers[name] || []).map(function (value) { return name + ': ' + value; });
        }).join('\n');
    }

    function formatPacketHex(value) {
        const hex = String(value || '').replace(/\s+/g, '').toLowerCase();
        if (!hex || hex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(hex)) return '[二进制正文无法解析]';
        const lines = [];
        for (let offset = 0; offset < hex.length; offset += 32) {
            const bytes = hex.slice(offset, offset + 32).match(/.{2}/g) || [];
            const byteColumn = `${bytes.slice(0, 8).join(' ').padEnd(23, ' ')}  ${bytes.slice(8).join(' ').padEnd(23, ' ')}`;
            const ascii = bytes.map(function (byte) {
                const number = Number.parseInt(byte, 16);
                return number >= 0x20 && number <= 0x7e ? String.fromCharCode(number) : '.';
            }).join('');
            lines.push(`${(offset / 2).toString(16).padStart(8, '0')}  ${byteColumn}  |${ascii}|`);
        }
        return lines.join('\n');
    }

    function packetBase64AsHex(value) {
        try {
            const binary = typeof root.atob === 'function' ? root.atob(String(value || '')) : '';
            let hex = '';
            for (let index = 0; index < binary.length; index += 1) hex += binary.charCodeAt(index).toString(16).padStart(2, '0');
            return formatPacketHex(hex);
        } catch (_) {
            return '[二进制正文无法解析]';
        }
    }

    function packetDirectionText(packet, direction) {
        const line = packet[direction + 'Line'] || '';
        const headers = packetHeadersText(packet[direction + 'Headers']);
        const body = packet[direction + 'Body'] || '';
        const encoding = packet[direction + 'BodyEncoding'] || '';
        const truncated = packet[direction + 'BodyTruncated'] === true;
        const contentEncoding = packet[direction + 'ContentEncoding'] || '';
        const decoded = packet[direction + 'BodyDecoded'] === true;
        let bodyText = body;
        if (encoding === 'hex') bodyText = formatPacketHex(body);
        else if (encoding === 'base64') bodyText = packetBase64AsHex(body);
        const notices = [];
        if (!decoded && contentEncoding) notices.push(`[正文未能按 Content-Encoding 解压：${contentEncoding}；以下为原始捕获正文]`);
        if (encoding === 'hex' || encoding === 'base64') notices.push('[二进制正文 · Hex]');
        if (bodyText) notices.push(bodyText);
        if (truncated) notices.push('[正文已在 32 KiB 显示上限处截断，完整原始证据请在流量证据中查看]');
        const head = [line, headers].filter(Boolean).join('\n');
        return [head, notices.join('\n')].filter(Boolean).join('\n\n');
    }

    async function openPacket(event) {
        const modal = element('egress-audit-packet-modal');
        const request = element('egress-audit-packet-request');
        const response = element('egress-audit-packet-response');
        const meta = element('egress-audit-packet-meta');
        if (!modal || !request || !response || !meta) return;
        modal.hidden = false;
        request.textContent = t('auditPacketLoading', '正在读取报文…');
        response.textContent = '';
        meta.textContent = `${event.eventType.toUpperCase()} · ${event.domain || '—'} · ${formatDate(event.occurredAt)}`;
        try {
            const payload = await requestJSON('/api/egress-audit-events/' + encodeURIComponent(event.id));
            if (!payload.event || !isSafeAuditEvent(payload.event) || !isSafeHTTPPacket(payload.event.httpPacket)) throw new Error(t('auditPacketInvalid', '报文内容无效'));
            request.textContent = packetDirectionText(payload.event.httpPacket, 'request') || '—';
            response.textContent = packetDirectionText(payload.event.httpPacket, 'response') || '—';
        } catch (error) {
            request.textContent = error && error.message ? error.message : t('auditPacketLoadFailed', '读取完整报文失败');
            response.textContent = '';
        }
    }

    function closePacket() {
        const modal = element('egress-audit-packet-modal');
        if (modal) modal.hidden = true;
    }

    function hasActiveFilter() {
        return Boolean(state.query || state.conversation || state.category !== 'all' || state.type !== 'all' || state.decision !== 'all');
    }

    function renderSelectionControls() {
        const currentIDs = state.items.map((item) => item.id);
        const selectedCurrent = currentIDs.filter((id) => state.selected.has(id)).length;
        const selectPage = element('egress-audit-select-page');
        if (selectPage) {
            selectPage.checked = currentIDs.length > 0 && selectedCurrent === currentIDs.length;
            selectPage.indeterminate = selectedCurrent > 0 && selectedCurrent < currentIDs.length;
            selectPage.disabled = state.loading || currentIDs.length === 0;
        }
        const selectedButton = element('egress-audit-delete-selected');
        if (selectedButton) {
            selectedButton.textContent = t('auditDeleteSelected', '删除已选 ({{count}})', { count: state.selected.size });
            selectedButton.disabled = state.loading || state.selected.size === 0;
        }
        const filteredButton = element('egress-audit-delete-filtered');
        if (filteredButton) {
            filteredButton.textContent = t('auditDeleteFiltered', '删除筛选结果 ({{count}})', { count: state.total });
            filteredButton.disabled = state.loading || state.total === 0 || !hasActiveFilter();
        }
    }

    function summaryCard(label, value, tone) {
        const card = create('article', `egress-audit-summary-card is-${tone || 'neutral'}`);
        card.append(create('span', '', label), create('strong', '', Number(value || 0)));
        return card;
    }

    function render() {
        const summary = element('egress-audit-summary');
        if (summary) {
            summary.replaceChildren(
                summaryCard(t('auditTotal', '总事件'), state.summary.total),
                summaryCard(t('auditNetwork', '网络'), state.summary.network),
                summaryCard(t('auditLifecycle', '生命周期'), state.summary.lifecycle),
                summaryCard(t('auditBlocked', '阻断'), state.summary.blocked, state.summary.blocked ? 'danger' : 'neutral'),
                summaryCard(t('auditFailures', '失败'), state.summary.failures, state.summary.failures ? 'danger' : 'success'),
            );
        }
        const body = element('egress-audit-rows');
        const empty = element('egress-audit-empty');
        const table = body && body.closest ? body.closest('table') : null;
        if (body) body.replaceChildren(...state.items.map(eventRow));
        if (table) table.hidden = state.items.length === 0;
        if (empty) empty.hidden = state.items.length > 0;
        const meta = element('egress-audit-pagination-meta');
        if (meta) meta.textContent = state.total
            ? t('auditPageMeta', '第 {{page}} / {{pages}} 页 · 共 {{total}} 条', { page: state.page, pages: state.totalPages, total: state.total })
            : t('auditPageMetaEmpty', '共 0 条');
        const previous = element('egress-audit-prev');
        const next = element('egress-audit-next');
        if (previous) previous.disabled = state.loading || state.page <= 1;
        if (next) next.disabled = state.loading || state.totalPages === 0 || state.page >= state.totalPages;
        const load = element('egress-audit-load-state');
        if (load) {
            load.textContent = state.loading
                ? t('auditLoading', '正在加载审计事件…')
                : (state.error || t('auditLoaded', '已加载 {{count}} 条当前页事件', { count: state.items.length }));
            load.classList.toggle('is-error', Boolean(state.error));
        }
        const refresh = element('egress-audit-refresh');
        if (refresh) refresh.disabled = state.loading;
        const integrity = element('egress-audit-integrity');
        if (integrity) {
            integrity.textContent = state.integrityLoading
                ? t('auditIntegrityChecking', '正在校验审计链…')
                : (state.integrity
                    ? t('auditIntegrityVerified', '链已验证 · {{events}} 条', { events: state.integrity.events })
                    : (state.integrityError || t('auditIntegrityChecking', '等待校验审计链…')));
            integrity.classList.toggle('is-ready', Boolean(state.integrity) && !state.integrityLoading);
            integrity.classList.toggle('is-error', Boolean(state.integrityError) && !state.integrityLoading);
        }
        renderSelectionControls();
    }

    async function deleteEvents(selectedOnly) {
        const ids = selectedOnly ? Array.from(state.selected) : [];
        const count = selectedOnly ? ids.length : state.total;
        if (!count || (!selectedOnly && !hasActiveFilter())) return;
        const message = selectedOnly
            ? t('auditDeleteSelectedConfirm', '永久删除已选的 {{count}} 条出站审计事件？删除后将重建并校验受影响的审计链。', { count })
            : t('auditDeleteFilteredConfirm', '永久删除当前筛选命中的 {{count}} 条出站审计事件？删除后将重建并校验受影响的审计链。', { count });
        if (!root.confirm(message)) return;
        state.loading = true;
        render();
        try {
            const params = selectedOnly ? new URLSearchParams() : queryParams(false);
            const payload = await requestJSON('/api/egress-audit-events?' + params.toString(), {
                method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }),
            });
            state.selected.clear();
            notify(t('auditDeleted', '已删除 {{count}} 条出站审计事件', { count: Number(payload.deleted || 0) }), 'success');
        } catch (error) {
            notify(error && error.message ? error.message : t('auditDeleteFailed', '删除出站审计事件失败'), 'error');
        } finally {
            state.loading = false;
        }
        await refresh();
    }

    async function loadConversations(generation) {
        if (state.conversationsLoading) return;
        state.conversationsLoading = true;
        try {
            const payload = await requestJSON('/api/egress-audit-events/conversations');
            if (!state.active) return;
            state.conversations = Array.isArray(payload.conversations) ? payload.conversations.filter(isSafeAuditConversation) : [];
            syncConversationOptions();
        } catch (error) {
            if (state.active && generation === state.generation && !state.error) {
                state.error = error && error.message ? error.message : t('auditLoadFailed', '加载出站审计失败');
            }
        } finally {
            state.conversationsLoading = false;
            if (state.active) render();
        }
    }

    async function verifyIntegrity(generation) {
        if (state.integrityController && typeof state.integrityController.abort === 'function') state.integrityController.abort();
        const controller = typeof root.AbortController === 'function' ? new root.AbortController() : null;
        state.integrityController = controller;
        state.integrityLoading = true;
        state.integrityError = '';
        state.integrity = null;
        render();
        try {
            const params = new URLSearchParams();
            if (state.conversation) params.set('conversation_id', state.conversation);
            const suffix = params.toString();
            const payload = await requestJSON('/api/egress-audit-events/integrity' + (suffix ? '?' + suffix : ''), controller ? { signal: controller.signal } : undefined);
            if (!state.active || generation !== state.generation) return;
            if (!isSafeIntegrity(payload.integrity)) throw new Error(t('auditIntegrityFailed', '审计链校验失败'));
            state.integrity = payload.integrity;
        } catch (error) {
            if (error && error.name === 'AbortError') return;
            if (!state.active || generation !== state.generation) return;
            state.items = [];
            state.total = 0;
            state.totalPages = 0;
            state.summary = { total: 0, network: 0, lifecycle: 0, blocked: 0, failures: 0 };
            state.integrity = null;
            state.integrityError = error && error.message ? error.message : t('auditIntegrityFailed', '审计链校验失败');
            state.error = state.integrityError;
        } finally {
            if (generation === state.generation) {
                state.integrityLoading = false;
                render();
            }
        }
    }

    async function refresh(options) {
        if (!state.active) return;
        const settings = options && typeof options === 'object' ? options : {};
        if (state.listController && typeof state.listController.abort === 'function') state.listController.abort();
        const controller = typeof root.AbortController === 'function' ? new root.AbortController() : null;
        state.listController = controller;
        state.loading = true;
        state.error = '';
        const generation = ++state.generation;
        render();
        if (settings.conversations || state.conversations.length === 0) void loadConversations(generation);
        try {
            const params = queryParams(true);
            params.set('defer_integrity', 'true');
            const payload = await requestJSON(`/api/egress-audit-events?${params.toString()}`, controller ? { signal: controller.signal } : undefined);
            if (!state.active || generation !== state.generation) return;
            const items = Array.isArray(payload.items) ? payload.items.filter(isSafeAuditEvent) : [];
            state.items = items;
            state.total = Math.max(0, Number(payload.total || 0));
            state.totalPages = Math.max(0, Number(payload.totalPages || 0));
            state.summary = payload.summary || { total: 0, network: 0, lifecycle: 0, blocked: 0, failures: 0 };
            if (state.totalPages > 0 && state.page > state.totalPages) {
                state.page = state.totalPages;
                writeURLState();
                state.loading = false;
                return refresh(settings);
            }
            state.loading = false;
            render();
            if (settings.verify || !state.integrity) void verifyIntegrity(generation);
        } catch (error) {
            if (error && error.name === 'AbortError') return;
            if (!state.active || generation !== state.generation) return;
            state.items = [];
            state.total = 0;
            state.totalPages = 0;
            state.summary = { total: 0, network: 0, lifecycle: 0, blocked: 0, failures: 0 };
            state.error = error && error.message ? error.message : t('auditLoadFailed', '加载出站审计失败');
        } finally {
            if (generation === state.generation) {
                state.loading = false;
                render();
            }
        }
    }

    async function exportEvents(format) {
        const button = element(`egress-audit-export-${format}`);
        if (button) button.disabled = true;
        try {
            const params = queryParams(false);
            params.set('format', format);
            const response = typeof root.apiFetch === 'function'
                ? await root.apiFetch(`/api/egress-audit-events/export?${params.toString()}`)
                : await root.fetch(`/api/egress-audit-events/export?${params.toString()}`);
            if (!response.ok) throw new Error(t('auditExportFailed', '导出失败'));
            const blob = await response.blob();
            const disposition = response.headers.get('Content-Disposition') || '';
            const match = disposition.match(/filename="([^"]+)"/);
            const name = match ? match[1] : `egress-audit.${format}`;
            const url = root.URL.createObjectURL(blob);
            const anchor = root.document.createElement('a');
            anchor.href = url;
            anchor.download = name;
            anchor.hidden = true;
            root.document.body.append(anchor);
            anchor.click();
            anchor.remove();
            root.URL.revokeObjectURL(url);
        } catch (error) {
            const load = element('egress-audit-load-state');
            if (load) {
                load.textContent = error && error.message ? error.message : t('auditExportFailed', '导出失败');
                load.classList.add('is-error');
            }
        } finally {
            if (button) button.disabled = false;
        }
    }

    function applyFilters() {
        const previousConversation = state.conversation;
        state.query = Array.from(element('egress-audit-search')?.value || '').slice(0, 200).join('');
        state.conversation = Array.from(element('egress-audit-conversation')?.value || '').slice(0, 128).join('');
        state.category = closedValue(element('egress-audit-category')?.value, CATEGORIES, 'all');
        state.type = closedValue(element('egress-audit-type')?.value, TYPES, 'all');
        state.decision = closedValue(element('egress-audit-decision')?.value, DECISIONS, 'all');
        const pageSize = Number.parseInt(element('egress-audit-page-size')?.value, 10);
        state.pageSize = PAGE_SIZES.has(pageSize) ? pageSize : 20;
        state.page = 1;
        writeURLState();
        refresh({ verify: state.conversation !== previousConversation });
    }

    function bind() {
        if (state.bound) return;
        state.bound = true;
        const search = element('egress-audit-search');
        if (search) search.addEventListener('input', function () {
            if (state.searchTimer) root.clearTimeout(state.searchTimer);
            state.searchTimer = root.setTimeout(applyFilters, 300);
        });
        ['egress-audit-conversation', 'egress-audit-category', 'egress-audit-type', 'egress-audit-decision', 'egress-audit-page-size'].forEach((id) => {
            const control = element(id);
            if (control) control.addEventListener('change', applyFilters);
        });
        element('egress-audit-refresh')?.addEventListener('click', function () { refresh({ verify: true, conversations: true }); });
        element('egress-audit-prev')?.addEventListener('click', function () {
            if (state.page <= 1) return;
            state.page -= 1;
            writeURLState();
            refresh();
        });
        element('egress-audit-next')?.addEventListener('click', function () {
            if (state.totalPages === 0 || state.page >= state.totalPages) return;
            state.page += 1;
            writeURLState();
            refresh();
        });
        element('egress-audit-export-json')?.addEventListener('click', function () { exportEvents('json'); });
        element('egress-audit-export-csv')?.addEventListener('click', function () { exportEvents('csv'); });
        element('egress-audit-select-page')?.addEventListener('change', function (event) {
            state.items.forEach(function (item) {
                if (event.target.checked) state.selected.add(item.id);
                else state.selected.delete(item.id);
            });
            render();
        });
        element('egress-audit-delete-selected')?.addEventListener('click', function () { deleteEvents(true); });
        element('egress-audit-delete-filtered')?.addEventListener('click', function () { deleteEvents(false); });
        element('egress-audit-packet-close')?.addEventListener('click', closePacket);
        element('egress-audit-packet-modal')?.addEventListener('click', function (event) { if (event.target === event.currentTarget) closePacket(); });
        if (root.document && typeof root.document.addEventListener === 'function') {
            root.document.addEventListener('languagechange', function () { if (state.active) render(); });
        }
    }

    function init() {
        if (!root.document || !element('page-egress-audit')) return;
        state.active = true;
        readURLState();
        bind();
        syncControls();
        writeURLState();
        refresh({ verify: true, conversations: true });
    }

    function stop() {
        state.active = false;
        state.generation += 1;
        state.loading = false;
        state.integrityLoading = false;
        state.conversationsLoading = false;
        if (state.listController && typeof state.listController.abort === 'function') state.listController.abort();
        if (state.integrityController && typeof state.integrityController.abort === 'function') state.integrityController.abort();
        if (state.searchTimer) {
            root.clearTimeout(state.searchTimer);
            state.searchTimer = null;
        }
    }

    return {
        init, stop, refresh, isSafeAuditEvent, isSafeIntegrity, isSafeAuditConversation,
        packetSummaryForTest: packetSummary,
		packetDirectionTextForTest: packetDirectionText,
        readURLStateForTest: function (search) {
            readURLState(search || '');
            return { page: state.page, pageSize: state.pageSize, query: state.query, conversation: state.conversation, category: state.category, type: state.type, decision: state.decision };
        },
    };
}));
