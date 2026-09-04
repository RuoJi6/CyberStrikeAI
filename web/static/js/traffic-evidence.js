(function (root) {
    'use strict';

    const REQUEST_TIMEOUT_MS = 15000;

    const state = {
        active: false,
        bound: false,
        loading: false,
        page: 1,
        pageSize: 20,
        totalPages: 0,
        query: '',
        conversation: '',
        runtime: '',
        timer: null,
        listController: null,
        listRequestID: 0,
        detailController: null,
        detailRequestID: 0,
        detailTransactionID: '',
    };

    function byId(id) {
        return root.document ? root.document.getElementById(id) : null;
    }

    function value(id) {
        const node = byId(id);
        return node ? String(node.value || '').trim() : '';
    }

    function formatTime(raw) {
        const date = new Date(raw || '');
        return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString();
    }

    function setText(node, text) {
        if (node) node.textContent = String(text == null ? '' : text);
    }

    function create(tag, className, text) {
        const node = root.document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) setText(node, text);
        return node;
    }

    function queryString() {
        const params = new URLSearchParams({ page: String(state.page), page_size: String(state.pageSize) });
        if (state.query) params.set('q', state.query);
        if (state.conversation) params.set('conversation_id', state.conversation);
        if (state.runtime) params.set('runtime_mode', state.runtime);
        return params.toString();
    }

    async function requestWithTimeout(url, controllerKey) {
        if (state[controllerKey]) state[controllerKey].abort();
        const controller = new root.AbortController();
        state[controllerKey] = controller;
        let timedOut = false;
        const timeout = root.setTimeout(() => {
            timedOut = true;
            controller.abort();
        }, REQUEST_TIMEOUT_MS);
        try {
            return await root.apiFetch(url, { signal: controller.signal });
        } catch (error) {
            if (timedOut) throw new Error('请求超过 15 秒，请检查网络后重试');
            throw error;
        } finally {
            root.clearTimeout(timeout);
            if (state[controllerKey] === controller) state[controllerKey] = null;
        }
    }

    function runtimeModeLabel(mode) {
        if (mode === 'container') return '容器';
        if (mode === 'host') return '本机';
        return '未标注';
    }

    function transformResultLabel(result) {
		if (result === 'observe_passed') return '脚本已解码';
		if (result === 'replay_applied') return '脚本已处理';
		return result ? '脚本已处理' : '';
	}

    function renderRows(items) {
        const body = byId('traffic-evidence-rows');
        const empty = byId('traffic-evidence-empty');
        if (!body || !empty) return;
        body.replaceChildren();
        empty.hidden = items.length !== 0;
        items.forEach((item) => {
            const row = create('tr');
            row.tabIndex = 0;
            row.setAttribute('role', 'button');
            row.setAttribute('aria-label', `查看流量事务 ${item.id || ''}`);

            row.appendChild(create('td', '', formatTime(item.started_at)));
            const requestCell = create('td');
            requestCell.appendChild(create('span', 'traffic-evidence-method', item.method || '-'));
            row.appendChild(requestCell);

            const target = `${item.scheme || 'http'}://${item.host || '-'}${item.path || '/'}`;
            const targetCell = create('td', 'traffic-evidence-target', target);
            targetCell.title = target;
            row.appendChild(targetCell);

            const statusCell = create('td');
            const status = Number(item.http_status || 0);
			const failed = Boolean(item.error_code);
			statusCell.appendChild(create('span', `traffic-evidence-status-code${status >= 400 || failed ? ' is-error' : ''}`, status || '-'));
            row.appendChild(statusCell);

			const transformCell = create('td');
			const transformLabel = transformResultLabel(item.transform_result)
				|| (item.transform_binding_id || item.transform_revision_id ? '脚本已处理' : '');
			if (transformLabel) {
				row.classList.add('is-transformed');
				const badge = create('span', 'traffic-evidence-transform-badge', transformLabel);
				badge.title = `规则 ${item.transform_binding_id || '-'} · 版本 ${item.transform_revision_id || '-'}`;
				transformCell.appendChild(badge);
			} else {
				transformCell.appendChild(create('span', 'traffic-evidence-transform-empty', '—'));
			}
			row.appendChild(transformCell);

            const runtimeMode = String(item.runtime_mode || 'unknown').toLowerCase();
            const runtimeCell = create('td');
            runtimeCell.appendChild(create('span', `traffic-evidence-runtime-badge is-${runtimeMode}`, runtimeModeLabel(runtimeMode)));
            row.appendChild(runtimeCell);

			const replayTransform = String(item.execution_id || '').startsWith('replay-transform:');
			const attributionLabels = { verified: '已验证', legacy_unattributed: '旧版运行时', unattributed: '未归因', invalid: '归因无效' };
			const source = replayTransform ? '重发包 · 脚本' : ([item.agent_id || 'Agent 未归因', item.tool_name || '工具未知', attributionLabels[item.attribution_status] || '未归因'].join(' · '));
			const sourceCell = create('td', '', source);
			sourceCell.title = [source, `event: ${item.event_id || '—'}`, `execution: ${item.execution_id || '—'}`, `tool-call: ${item.tool_call_id || '—'}`, `scope: ${item.activity_scope_id || '—'}`, `generation: ${item.runtime_generation || 0}`, `declared: ${item.declared_activity_kind || 'unknown'}`, `observed: ${item.observed_activity_kind || 'single'}`].join('\n');
            row.appendChild(sourceCell);

            const storageCell = create('td');
            const aggregateCount = Number(item.aggregate_count || 0);
			if (item.error_code) {
				const failure = create('span', 'traffic-evidence-failure', item.error_code);
				failure.title = item.error_summary || item.outcome || '上游响应未建立';
				storageCell.appendChild(failure);
			} else if (aggregateCount > 1) {
				const aggregateLabels = { 'web-fuzz': 'Fuzz（已声明）', 'path-sweep': '疑似路径扫描', 'unattributed-path-sweep': '未归因路径扫描', 'request-burst': '高频请求' };
				const aggregateKind = aggregateLabels[item.aggregate_kind] || '高频请求';
                const aggregate = create('span', 'traffic-evidence-aggregate', `${aggregateKind} × ${aggregateCount}`);
                aggregate.title = '仅首个事务保存完整代表包；其余请求只计数并保留关键摘要';
                storageCell.appendChild(aggregate);
            } else {
                storageCell.appendChild(create('span', 'traffic-evidence-full', '完整事务'));
            }
            row.appendChild(storageCell);

            const captureCell = create('td');
            const coverage = item.capture_coverage || 'unknown';
            captureCell.appendChild(create('span', `traffic-evidence-capture${coverage === 'enforced' ? ' is-enforced' : ''}`, coverage === 'enforced' ? '强制' : '尽力'));
            row.appendChild(captureCell);

            const open = () => void openDetail(item.id);
            row.addEventListener('click', open);
            row.addEventListener('keydown', (event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    open();
                }
            });
            body.appendChild(row);
        });
    }

    async function load(resetPage) {
        if (typeof root.apiFetch !== 'function') return;
        if (resetPage) state.page = 1;
        state.query = value('traffic-evidence-search').slice(0, 200);
        state.conversation = value('traffic-evidence-conversation').slice(0, 128);
        state.runtime = value('traffic-evidence-runtime');
        state.pageSize = Number.parseInt(value('traffic-evidence-page-size'), 10) || 20;
        state.loading = true;
        const requestID = ++state.listRequestID;
        setText(byId('traffic-evidence-status'), '正在加载流量事务…');
        try {
            const response = await requestWithTimeout(`/api/traffic-transactions?${queryString()}`, 'listController');
            if (requestID !== state.listRequestID) return;
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const payload = await response.json();
            if (requestID !== state.listRequestID) return;
            const items = Array.isArray(payload.items) ? payload.items : [];
            state.totalPages = Number(payload.total_pages || 0);
            renderRows(items);
            setText(byId('traffic-evidence-status'), `共 ${Number(payload.total || 0)} 条；点击一行查看完整请求与响应`);
            setText(byId('traffic-evidence-page-meta'), `第 ${state.page} / ${Math.max(state.totalPages, 1)} 页`);
            const prev = byId('traffic-evidence-prev');
            const next = byId('traffic-evidence-next');
            if (prev) prev.disabled = state.page <= 1;
            if (next) next.disabled = state.totalPages === 0 || state.page >= state.totalPages;
        } catch (error) {
            if (requestID !== state.listRequestID || error?.name === 'AbortError') return;
            renderRows([]);
            setText(byId('traffic-evidence-status'), `加载失败：${error.message || error}`);
        } finally {
            if (requestID === state.listRequestID) state.loading = false;
        }
    }

    function formatHexBody(value) {
        const hex = String(value || '').replace(/\s+/g, '').toLowerCase();
        if (!hex || hex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(hex)) return '[二进制正文无法解析]';
        const lines = [];
        for (let offset = 0; offset < hex.length; offset += 32) {
            const chunk = hex.slice(offset, offset + 32);
            const bytes = chunk.match(/.{2}/g) || [];
            const left = bytes.slice(0, 8).join(' ');
            const right = bytes.slice(8).join(' ');
            const byteColumn = `${left.padEnd(23, ' ')}  ${right.padEnd(23, ' ')}`;
            const ascii = bytes.map((byte) => {
                const number = Number.parseInt(byte, 16);
                return number >= 0x20 && number <= 0x7e ? String.fromCharCode(number) : '.';
            }).join('');
            lines.push(`${(offset / 2).toString(16).padStart(8, '0')}  ${byteColumn}  |${ascii}|`);
        }
        return lines.join('\n');
    }

    function base64AsHex(value) {
        try {
            const binary = typeof root.atob === 'function' ? root.atob(String(value || '')) : '';
            if (!binary) return '[二进制正文无法解析]';
            let hex = '';
            for (let index = 0; index < binary.length; index += 1) hex += binary.charCodeAt(index).toString(16).padStart(2, '0');
            return formatHexBody(hex);
        } catch (_) {
            return '[二进制正文无法解析]';
        }
    }

    function packetBodyText(message) {
        const view = message.body_view && typeof message.body_view === 'object' ? message.body_view : null;
        if (view) {
            const content = view.format === 'hex' ? formatHexBody(view.content) : String(view.content || '');
            const notices = [];
            if (view.format === 'hex') notices.push('[二进制正文 · Hex]');
            const fallbackLabel = view.format === 'hex' ? '原始字节 Hex' : '未解压的原始正文';
            if (view.error === 'unsupported_content_encoding') notices.push(`[不支持该 Content-Encoding，以下为${fallbackLabel}]`);
            else if (view.error) notices.push(`[正文解压失败，以下为${fallbackLabel}]`);
            notices.push(content);
            return notices.filter(Boolean).join('\n');
        }
        if (message.body_encoding === 'base64') return `[二进制正文 · Hex]\n${base64AsHex(message.body)}`;
        return String(message.body || '');
    }

    function packetText(message) {
        const headers = Array.isArray(message.headers) ? message.headers : [];
        let start = '';
        if (message.kind === 'request') {
            start = `${message.method || 'GET'} ${message.path || '/'} ${message.protocol || 'HTTP/1.1'}`;
        } else {
            start = `${message.protocol || 'HTTP/1.1'} ${message.status || 0}`;
        }
        const lines = [start, ...headers.map((header) => `${header.name || ''}: ${header.value || ''}`), ''];
        lines.push(packetBodyText(message));
        return lines.join('\n');
    }

    function renderDetail(payload) {
        const transaction = payload.transaction || {};
        const stages = byId('traffic-evidence-detail-stages');
        if (!stages) return;
        stages.replaceChildren();
        const aggregateCount = Number(transaction.aggregate_count || 0);
        const aggregateMeta = aggregateCount > 1 ? ` · ${transaction.aggregate_kind || 'aggregate'} × ${aggregateCount}（当前为完整代表包）` : '';
		setText(byId('traffic-evidence-detail-meta'), `${transaction.id || '-'} · event ${transaction.event_id || '—'} · ${transaction.scheme || ''}://${transaction.host || ''}${transaction.path || ''}${aggregateMeta}`);
		const transformed = Boolean(transaction.transform_result || transaction.transform_binding_id || transaction.transform_revision_id);
		const messages = Array.isArray(payload.messages) ? payload.messages : [];
		if (transaction.error_code) {
			const failureCard = create('section', 'traffic-evidence-failure-summary');
			failureCard.appendChild(create('strong', '', messages.some((message) => message.stage === 'upstream_response') ? '上游响应未完整结束' : '上游响应未建立'));
			failureCard.appendChild(create('span', '', transaction.error_code));
			if (transaction.error_summary) failureCard.appendChild(create('p', '', transaction.error_summary));
			stages.appendChild(failureCard);
		}
		if (transformed) {
			const transformCard = create('section', 'traffic-evidence-transform-summary');
			const heading = create('div', 'traffic-evidence-transform-summary-head');
			heading.appendChild(create('strong', '', transformResultLabel(transaction.transform_result) || '脚本已处理'));
			heading.appendChild(create('span', '', 'Traffic Transform'));
			transformCard.appendChild(heading);
			transformCard.appendChild(create('p', '', `该事务已命中加解密规则；规则 ${transaction.transform_binding_id || '-'} · 脚本版本 ${transaction.transform_revision_id || '-'}`));
			stages.appendChild(transformCard);
		}
        if (aggregateCount > 1) {
            let summary = {};
            try { summary = JSON.parse(transaction.aggregate_summary_json || '{}'); } catch (error) { summary = {}; }
            const summaryCard = create('section', 'traffic-evidence-aggregate-summary');
            summaryCard.appendChild(create('strong', '', '高流量聚合摘要'));
            const statusCounts = summary.status_counts && typeof summary.status_counts === 'object'
                ? Object.entries(summary.status_counts).map(([status, count]) => `${status}: ${count}`).join('，')
                : '无';
            summaryCard.appendChild(create('p', '', `请求数 ${aggregateCount}；不同路径 ${Number(summary.distinct_paths || 0)}；状态码 ${statusCounts}`));
            const paths = Array.isArray(summary.representative_paths) ? summary.representative_paths : [];
            if (paths.length) summaryCard.appendChild(create('code', '', paths.join('\n')));
            stages.appendChild(summaryCard);
        }
		messages.forEach((message) => {
			const decodedStage = message.stage === 'decoded_request' || message.stage === 'decoded_response';
            const card = create('section', `traffic-evidence-packet${decodedStage ? ' is-transform-output' : ''}`);
            const head = create('div', 'traffic-evidence-packet-head');
			const bodyView = message.body_view && typeof message.body_view === 'object' ? message.body_view : null;
			const contentDecoded = Boolean(bodyView?.decoded && bodyView?.content_encoding);
			const stageLabel = decodedStage ? `${message.stage} · 脚本输出` : `${message.stage || message.kind || 'packet'}${contentDecoded ? ` · 已解压 ${bodyView.content_encoding}` : ''}`;
            head.appendChild(create('span', '', stageLabel));
            const complete = message.complete !== false;
            head.appendChild(create('span', '', `${message.body_length || 0} bytes`));
            card.appendChild(head);
            const pre = create('pre');
            pre.textContent = packetText(message);
            card.appendChild(pre);
            if (!complete) {
                const storedBytes = Number(message.body_stored_bytes || 0);
                const totalBytes = Number(message.body_length || 0);
                const truncation = create('div', 'traffic-evidence-packet-truncation');
                truncation.setAttribute('role', 'status');
                truncation.appendChild(create('strong', '', '正文已截断'));
                truncation.appendChild(create('span', '', `当前显示 ${storedBytes}/${totalBytes} bytes`));
                card.appendChild(truncation);
            }
			if (bodyView && bodyView.complete === false && complete) {
				const truncation = create('div', 'traffic-evidence-packet-truncation');
				truncation.setAttribute('role', 'status');
				truncation.appendChild(create('strong', '', '可读正文已达到显示上限'));
				truncation.appendChild(create('span', '', `当前显示 ${Number(bodyView.stored_bytes || 0)} bytes；原始证据仍保持不变`));
				card.appendChild(truncation);
			}
            stages.appendChild(card);
        });
        if (!stages.childNodes.length) stages.appendChild(create('div', 'traffic-evidence-empty', '该事务没有可显示的数据包阶段'));
    }

    async function openDetail(transactionId) {
        if (!transactionId || typeof root.apiFetch !== 'function') return;
        const modal = byId('traffic-evidence-detail');
        const stages = byId('traffic-evidence-detail-stages');
        if (!modal || !stages) return;
        modal.hidden = false;
        state.detailTransactionID = transactionId;
        const requestID = ++state.detailRequestID;
        stages.replaceChildren(create('div', 'traffic-evidence-empty', '正在读取完整数据包…'));
        try {
            const response = await requestWithTimeout(`/api/traffic-transactions/${encodeURIComponent(transactionId)}`, 'detailController');
            if (requestID !== state.detailRequestID) return;
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const payload = await response.json();
            if (requestID === state.detailRequestID) renderDetail(payload);
        } catch (error) {
            if (requestID !== state.detailRequestID || error?.name === 'AbortError') return;
            stages.replaceChildren(create('div', 'traffic-evidence-empty', `读取失败：${error.message || error}`));
        }
    }

    function closeDetail() {
        const modal = byId('traffic-evidence-detail');
        if (modal) modal.hidden = true;
        state.detailRequestID++;
        if (state.detailController) state.detailController.abort();
        state.detailController = null;
    }

    function sendDetailToReplay() {
        if (!state.detailTransactionID) return;
        if (typeof root.openTrafficReplayTransaction === 'function') {
            root.openTrafficReplayTransaction(state.detailTransactionID);
        } else {
            root.pendingTrafficReplayTransaction = state.detailTransactionID;
            if (typeof root.switchPage === 'function') root.switchPage('traffic-replay');
        }
        closeDetail();
    }

    function bind() {
        if (state.bound) return;
        state.bound = true;
        byId('traffic-evidence-refresh')?.addEventListener('click', () => void load(false));
        byId('traffic-evidence-prev')?.addEventListener('click', () => { if (state.page > 1) { state.page--; void load(false); } });
        byId('traffic-evidence-next')?.addEventListener('click', () => { if (state.page < state.totalPages) { state.page++; void load(false); } });
        ['traffic-evidence-conversation', 'traffic-evidence-runtime', 'traffic-evidence-page-size'].forEach((id) => {
            byId(id)?.addEventListener('change', () => void load(true));
        });
        byId('traffic-evidence-search')?.addEventListener('input', () => {
            root.clearTimeout(state.timer);
            state.timer = root.setTimeout(() => void load(true), 250);
        });
        byId('traffic-evidence-detail-close')?.addEventListener('click', closeDetail);
        byId('traffic-evidence-send-replay')?.addEventListener('click', sendDetailToReplay);
        byId('traffic-evidence-detail')?.addEventListener('click', (event) => { if (event.target === byId('traffic-evidence-detail')) closeDetail(); });
        root.document?.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeDetail(); });
    }

    function init() {
        state.active = true;
        bind();
        void load(false);
    }

    root.initTrafficEvidencePage = init;
    root.refreshTrafficEvidencePage = () => load(false);
    root.openTrafficEvidenceTransaction = openDetail;
}(typeof window !== 'undefined' ? window : globalThis));
