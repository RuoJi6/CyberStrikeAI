(function (root) {
    'use strict';

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
            statusCell.appendChild(create('span', `traffic-evidence-status-code${status >= 400 ? ' is-error' : ''}`, status || '-'));
            row.appendChild(statusCell);

            const source = [item.agent_id, item.execution_id, item.tool_call_id].filter(Boolean).join(' · ') || '未标注';
            const sourceCell = create('td', '', source);
            sourceCell.title = source;
            row.appendChild(sourceCell);

            const storageCell = create('td');
            const aggregateCount = Number(item.aggregate_count || 0);
            if (aggregateCount > 1) {
                const aggregateKind = item.aggregate_kind === 'web-fuzz' ? 'Web fuzz' : '高频请求';
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
        if (state.loading || typeof root.apiFetch !== 'function') return;
        if (resetPage) state.page = 1;
        state.query = value('traffic-evidence-search').slice(0, 200);
        state.conversation = value('traffic-evidence-conversation').slice(0, 128);
        state.runtime = value('traffic-evidence-runtime');
        state.pageSize = Number.parseInt(value('traffic-evidence-page-size'), 10) || 20;
        state.loading = true;
        setText(byId('traffic-evidence-status'), '正在加载流量事务…');
        try {
            const response = await root.apiFetch(`/api/traffic-transactions?${queryString()}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const payload = await response.json();
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
            renderRows([]);
            setText(byId('traffic-evidence-status'), `加载失败：${error.message || error}`);
        } finally {
            state.loading = false;
        }
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
        if (message.body_encoding === 'base64') lines.push('[base64 encoded body]', message.body || '');
        else lines.push(message.body || '');
        return lines.join('\n');
    }

    function renderDetail(payload) {
        const transaction = payload.transaction || {};
        const stages = byId('traffic-evidence-detail-stages');
        if (!stages) return;
        stages.replaceChildren();
        const aggregateCount = Number(transaction.aggregate_count || 0);
        const aggregateMeta = aggregateCount > 1 ? ` · ${transaction.aggregate_kind || 'aggregate'} × ${aggregateCount}（当前为完整代表包）` : '';
        setText(byId('traffic-evidence-detail-meta'), `${transaction.id || '-'} · ${transaction.scheme || ''}://${transaction.host || ''}${transaction.path || ''}${aggregateMeta}`);
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
        (Array.isArray(payload.messages) ? payload.messages : []).forEach((message) => {
            const card = create('section', 'traffic-evidence-packet');
            const head = create('div', 'traffic-evidence-packet-head');
            head.appendChild(create('span', '', message.stage || message.kind || 'packet'));
            const complete = message.complete !== false;
            head.appendChild(create('span', complete ? '' : 'traffic-evidence-packet-note', complete ? `${message.body_length || 0} bytes` : `已截断 ${message.body_stored_bytes || 0}/${message.body_length || 0} bytes`));
            card.appendChild(head);
            const pre = create('pre');
            pre.textContent = packetText(message);
            card.appendChild(pre);
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
        stages.replaceChildren(create('div', 'traffic-evidence-empty', '正在读取完整数据包…'));
        try {
            const response = await root.apiFetch(`/api/traffic-transactions/${encodeURIComponent(transactionId)}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            renderDetail(await response.json());
        } catch (error) {
            stages.replaceChildren(create('div', 'traffic-evidence-empty', `读取失败：${error.message || error}`));
        }
    }

    function closeDetail() {
        const modal = byId('traffic-evidence-detail');
        if (modal) modal.hidden = true;
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
