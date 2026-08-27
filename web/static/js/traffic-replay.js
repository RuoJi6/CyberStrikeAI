(function (root) {
    'use strict';

    const MANAGED_HEADERS = new Set(['host', 'content-length']);
    const FORBIDDEN_HEADERS = new Set(['transfer-encoding', 'connection', 'proxy-connection', 'proxy-authorization']);
    const state = {
        bound: false,
        transactionID: '',
        controller: null,
        origin: '',
        authority: '',
        originalRequest: '',
        lastResponse: '',
        responseView: 'raw',
        history: [],
    };

    function byId(id) { return root.document ? root.document.getElementById(id) : null; }
    function setText(node, value) { if (node) node.textContent = String(value == null ? '' : value); }
    function setDisabled(id, disabled) { const node = byId(id); if (node) node.disabled = Boolean(disabled); }
    function requestMessage(messages) {
        const list = Array.isArray(messages) ? messages : [];
        for (const stage of ['client_request', 'upstream_request']) {
            const message = list.find((item) => item.stage === stage);
            if (message) return message;
        }
        return null;
    }
    function editableHeaders(headers) {
        return (Array.isArray(headers) ? headers : []).filter((header) => {
            const name = String(header.name || '').toLowerCase();
            return !MANAGED_HEADERS.has(name) && !FORBIDDEN_HEADERS.has(name);
        });
    }
    function normalizeAuthority(host, scheme, port) {
        const rawHost = String(host || '').trim();
        const displayHost = rawHost.includes(':') && !rawHost.startsWith('[') ? `[${rawHost}]` : rawHost;
        const numericPort = Number(port || 0);
        const defaultPort = scheme === 'https' ? 443 : 80;
        return numericPort && numericPort !== defaultPort ? `${displayHost}:${numericPort}` : displayHost;
    }
    function buildRawRequest(method, target, authority, headers, body) {
        const lines = [`${String(method || 'GET').toUpperCase()} ${target || '/'} HTTP/1.1`, `Host: ${authority}`];
        editableHeaders(headers).forEach((header) => lines.push(`${header.name || ''}: ${header.value || ''}`));
        return `${lines.join('\n')}\n\n${body || ''}`;
    }
    function splitRawMessage(raw) {
        const value = String(raw || '');
        const match = /\r?\n\r?\n/.exec(value);
        if (!match) return { head: value, body: '', separator: '\n\n' };
        return { head: value.slice(0, match.index), body: value.slice(match.index + match[0].length), separator: match[0] };
    }
    function parseRawRequest(raw) {
        if (!state.origin || !state.authority) throw new Error('请先载入一个流量事务');
        const parts = splitRawMessage(raw);
        const lines = parts.head.split(/\r?\n/);
        const requestLine = String(lines.shift() || '').trim();
        const match = /^([A-Za-z]+)\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/.exec(requestLine);
        if (!match) throw new Error('请求首行格式应为 METHOD /path HTTP/1.1');

        const method = match[1].toUpperCase();
        const target = match[2];
        let url;
        try {
            url = new root.URL(target, `${state.origin}/`);
        } catch (_) {
            throw new Error('请求路径或 URL 无效');
        }
        if (url.origin !== state.origin) throw new Error('只能重发到原事务的协议、主机和端口');

        const headers = [];
        let hostCount = 0;
        lines.forEach((line, index) => {
            if (!line.trim()) return;
            if (/^[ \t]/.test(line)) throw new Error(`第 ${index + 2} 行不支持折叠请求头`);
            const separator = line.indexOf(':');
            if (separator <= 0) throw new Error(`第 ${index + 2} 行请求头缺少冒号`);
            const name = line.slice(0, separator).trim();
            const value = line.slice(separator + 1).trim();
            const lowerName = name.toLowerCase();
            if (lowerName === 'host') {
                hostCount += 1;
                if (value.toLowerCase() !== state.authority.toLowerCase()) throw new Error('Host 由原事务锁定，不能修改');
                return;
            }
            if (lowerName === 'content-length') return;
            if (FORBIDDEN_HEADERS.has(lowerName)) throw new Error(`请求头 ${name} 由重发器管理，不能覆盖`);
            headers.push({ name, value });
        });
        if (hostCount !== 1) throw new Error('原始请求必须保留且只能包含一个 Host 请求头');
        return { method, url: url.href, headers, body: parts.body };
    }
    function lineNumbers(value) {
        const count = Math.max(1, String(value || '').split(/\r?\n/).length);
        return Array.from({ length: count }, (_, index) => index + 1).join('\n');
    }
    function updateRequestLines() {
        const editor = byId('traffic-replay-request');
        setText(byId('traffic-replay-request-lines'), lineNumbers(editor?.value));
        const firstLine = String(editor?.value || '').split(/\r?\n/, 1)[0];
        const match = /^([A-Za-z]+)\s+(\S+)/.exec(firstLine);
        setText(byId('traffic-replay-request-summary'), match ? `${match[1].toUpperCase()} ${match[2]}` : '请求首行待完善');
    }
    function responseBody(raw) {
        let remaining = String(raw || '');
        // curl --include reports an HTTPS proxy CONNECT response before the
        // actual origin response. Skip only interim/CONNECT header blocks so
        // the body tab never mistakes the origin status line for body text.
        for (let index = 0; index < 8; index += 1) {
            const parts = splitRawMessage(remaining);
            const statusLine = String(parts.head || '').split(/\r?\n/, 1)[0];
            const status = Number((/^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(statusLine) || [])[1] || 0);
            const interim = status >= 100 && status < 200;
            const connected = /\bConnection Established\b/i.test(statusLine);
            if ((interim || connected) && parts.body) {
                remaining = parts.body;
                continue;
            }
            return parts.body || '(空正文)';
        }
        return '(空正文)';
    }
    function renderResponseView() {
        const value = state.lastResponse || '选择数据包后即可编辑并重发。';
        const shown = state.responseView === 'body' && state.lastResponse ? responseBody(value) : value;
        setText(byId('traffic-replay-response'), shown);
        setText(byId('traffic-replay-response-lines'), lineNumbers(shown));
        root.document?.querySelectorAll('[data-replay-response-view]').forEach((button) => {
            const active = button.dataset.replayResponseView === state.responseView;
            button.classList.toggle('is-active', active);
            button.setAttribute('aria-selected', active ? 'true' : 'false');
        });
        const response = byId('traffic-replay-response');
        if (response) response.scrollTop = 0;
        const lines = byId('traffic-replay-response-lines');
        if (lines) lines.scrollTop = 0;
    }
    function byteLength(value) {
        if (typeof root.TextEncoder === 'function') return new root.TextEncoder().encode(String(value || '')).length;
        return String(value || '').length;
    }
    function formatBytes(bytes) {
        const value = Number(bytes || 0);
        if (value < 1024) return `${value} B`;
        if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
        return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
    }
    function runtimeLabel(mode) {
        if (mode === 'container') return '容器执行';
        if (mode === 'host') return '本机执行';
        return '运行位置未标注';
    }
    function setRuntimeBadge(mode) {
        const badge = byId('traffic-replay-runtime');
        if (!badge) return;
        badge.classList.remove('is-container', 'is-host');
        if (mode === 'container' || mode === 'host') badge.classList.add(`is-${mode}`);
        setText(badge, runtimeLabel(mode));
    }
    function setResponseStatus(status) {
        const node = byId('traffic-replay-response-status');
        if (!node) return;
        node.classList.remove('is-success', 'is-error');
        if (Number(status) >= 200 && Number(status) < 400) node.classList.add('is-success');
        else if (Number(status) >= 400) node.classList.add('is-error');
        setText(node, status ? `HTTP ${status}` : '未发送');
    }
    function renderHistory() {
        setText(byId('traffic-replay-history-count'), state.history.length);
        const list = byId('traffic-replay-history');
        if (!list || !root.document) return;
        list.replaceChildren();
        if (!state.history.length) {
            const empty = root.document.createElement('p');
            empty.textContent = '本次页面尚无重发记录';
            list.appendChild(empty);
            return;
        }
        state.history.forEach((entry, index) => {
            const button = root.document.createElement('button');
            button.type = 'button';
            button.dataset.historyIndex = String(index);
            const title = root.document.createElement('strong');
            title.textContent = `${entry.method} ${entry.target}`;
            const meta = root.document.createElement('span');
            meta.textContent = `HTTP ${entry.status || '-'} · ${entry.elapsed}ms · ${entry.time}`;
            button.append(title, meta);
            list.appendChild(button);
        });
    }
    function restoreHistory(index) {
        const entry = state.history[Number(index)];
        if (!entry) return;
        const editor = byId('traffic-replay-request');
        if (editor) editor.value = entry.request;
        state.lastResponse = entry.response;
        state.responseView = 'raw';
        updateRequestLines();
        renderResponseView();
        setText(byId('traffic-replay-response-meta'), entry.meta);
        setResponseStatus(entry.status);
        setText(byId('traffic-replay-status'), `已恢复 ${entry.time} 的本次页面重发记录。`);
        const menu = byId('traffic-replay-history-menu');
        if (menu) menu.open = false;
    }
    function clearResponse() {
        state.lastResponse = '';
        state.responseView = 'raw';
        renderResponseView();
        setText(byId('traffic-replay-response-meta'), '等待重发');
        setResponseStatus(0);
    }
    async function load(transactionID) {
        const id = String(transactionID || byId('traffic-replay-transaction-id')?.value || '').trim();
        if (!id || typeof root.apiFetch !== 'function') return;
        if (state.controller) state.controller.abort();
        const controller = new root.AbortController();
        state.controller = controller;
        setText(byId('traffic-replay-status'), '正在载入完整请求…');
        setDisabled('traffic-replay-send', true);
        try {
            const response = await root.apiFetch(`/api/traffic-transactions/${encodeURIComponent(id)}`, { signal: controller.signal });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const payload = await response.json();
            const transaction = payload.transaction || {};
            const message = requestMessage(payload.messages);
            if (!message) throw new Error('事务没有可重发的请求');
            if (message.complete === false) throw new Error('原始请求被截断，不能安全重发');
            if (message.body_encoding === 'base64') throw new Error('当前重发包仅支持 UTF-8 文本正文');

            const scheme = String(transaction.scheme || 'http').toLowerCase();
            const authority = normalizeAuthority(transaction.host, scheme, transaction.port);
            if (!authority) throw new Error('事务缺少目标主机');
            state.transactionID = id;
            state.authority = authority;
            state.origin = `${scheme}://${authority}`;
            const target = message.path || transaction.path || '/';
            state.originalRequest = buildRawRequest(message.method || transaction.method, target, authority, message.headers, message.body);

            const input = byId('traffic-replay-transaction-id');
            const editor = byId('traffic-replay-request');
            if (input) input.value = id;
            if (editor) { editor.value = state.originalRequest; editor.disabled = false; editor.scrollTop = 0; editor.scrollLeft = 0; }
            setText(byId('traffic-replay-scheme'), scheme.toUpperCase());
            setRuntimeBadge(transaction.runtime_mode);
            setText(byId('traffic-replay-origin-lock'), `🔒 ${state.origin}`);
            setText(byId('traffic-replay-meta'), `${runtimeLabel(transaction.runtime_mode)} · 对话 ${transaction.conversation_id || '-'} · 原事务 ${id}`);
            setText(byId('traffic-replay-status'), '请求已载入；可修改方法、路径、请求头和正文，目标站点保持锁定。');
            updateRequestLines();
            clearResponse();
            for (const control of ['traffic-replay-send', 'traffic-replay-format', 'traffic-replay-reset']) setDisabled(control, false);
        } catch (error) {
            if (error?.name !== 'AbortError') setText(byId('traffic-replay-status'), `载入失败：${error.message || error}`);
        } finally {
            if (state.controller === controller) state.controller = null;
        }
    }
    async function send() {
        if (!state.transactionID || typeof root.apiFetch !== 'function') return;
        const button = byId('traffic-replay-send');
        if (button) button.disabled = true;
        setText(byId('traffic-replay-status'), '正在原执行位置重发…');
        const started = root.performance?.now ? root.performance.now() : Date.now();
        try {
            const request = String(byId('traffic-replay-request')?.value || '');
            const payload = parseRawRequest(request);
            const response = await root.apiFetch(`/api/traffic-transactions/${encodeURIComponent(state.transactionID)}/replay`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
            });
            const responseText = await response.text();
            let result = {};
            try { result = JSON.parse(responseText); } catch (_) { result = {}; }
            if (!response.ok) throw new Error(result.error || responseText || `HTTP ${response.status}`);
            const elapsed = Math.max(0, Math.round((root.performance?.now ? root.performance.now() : Date.now()) - started));
            const rawResponse = result.rawResponse || '(空响应)';
			const status = Number(result.httpStatus || 0);
			const execution = runtimeLabel(result.executionLocation);
			const transform = result.transform || {};
			const transformFeedback = replayTransformFeedback(transform);
			const meta = `HTTP ${status || '-'} · ${formatBytes(byteLength(rawResponse))} · ${elapsed}ms · ${execution}${transformFeedback.meta}`;
            state.lastResponse = rawResponse;
            state.responseView = 'raw';
            renderResponseView();
            setText(byId('traffic-replay-response-meta'), meta);
            setResponseStatus(status);
			setText(byId('traffic-replay-status'), transformFeedback.status);
            const replayURL = new root.URL(payload.url);
            state.history.unshift({
                request,
                response: rawResponse,
                status,
                elapsed,
                method: payload.method,
                target: replayURL.pathname + replayURL.search,
                meta,
                time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            });
            state.history = state.history.slice(0, 20);
            renderHistory();
        } catch (error) {
            setText(byId('traffic-replay-status'), `重发失败：${error.message || error}`);
            setText(byId('traffic-replay-response-meta'), '请求未发出或服务端拒绝');
            setResponseStatus(400);
        } finally {
            if (button) button.disabled = false;
        }
    }
    function formatJSONBody() {
        const editor = byId('traffic-replay-request');
        if (!editor) return;
        try {
            parseRawRequest(editor.value);
            const parts = splitRawMessage(editor.value);
            if (!parts.body.trim()) throw new Error('当前请求没有正文');
            const formatted = JSON.stringify(JSON.parse(parts.body), null, 2);
            editor.value = `${parts.head}${parts.separator}${formatted}`;
            updateRequestLines();
            setText(byId('traffic-replay-status'), 'JSON 正文已美化。');
        } catch (error) {
            setText(byId('traffic-replay-status'), `无法美化：${error.message || error}`);
        }
    }
    function resetRequest() {
        const editor = byId('traffic-replay-request');
        if (!editor || !state.originalRequest) return;
        editor.value = state.originalRequest;
        editor.scrollTop = 0;
        editor.scrollLeft = 0;
        updateRequestLines();
        setText(byId('traffic-replay-status'), '已还原为捕获时的原始请求。');
    }
	function replayTransformFeedback(transform) {
		const item = transform && typeof transform === 'object' ? transform : {};
		const name = item.transformName || item.revisionId || '已匹配';
		if (item.applied && item.strategy === 'observe') {
			return {
				meta: ` · 脚本 ${name} · 旁路解密`,
				status: '重发完成；解密 Hook 已旁路执行，编辑器中的原始密文已原样发送，新流量证据会显示脚本标记。',
			};
		}
		if (item.applied) {
			return {
				meta: ` · 脚本 ${name} · 完整重编码`,
				status: '重发完成；匹配的加解密脚本已在发送前完成解密、修改与重编码，新流量证据会显示脚本标记。',
			};
		}
		if (item.matched && item.strategy === 'observe') {
			return {
				meta: ` · 脚本 ${name} · 旁路失败后原样发送`,
				status: '重发完成；规则已匹配，但旁路解密 Hook 执行失败，已按继续策略原样发送原始密文。',
			};
		}
		if (item.matched) {
			return {
				meta: ` · 规则 ${name} · 原样发送`,
				status: '重发完成；规则已匹配但没有请求 Hook，原始数据包已原样发送。',
			};
		}
		return { meta: ' · 未匹配脚本', status: '重发完成；当前请求未匹配启用的加解密规则。' };
	}
    function setWorkbenchWidth(value) {
        const workbench = byId('traffic-replay-workbench');
        const splitter = byId('traffic-replay-splitter');
        if (!workbench || !splitter) return;
        const rect = workbench.getBoundingClientRect();
        if (rect.width < 720) return;
        const clamped = Math.max(280, Math.min(Number(value), rect.width - 288));
        workbench.style.setProperty('--replay-request-width', `${clamped}px`);
        splitter.setAttribute('aria-valuenow', String(Math.round((clamped / rect.width) * 100)));
    }
    function bindSplitter() {
        const splitter = byId('traffic-replay-splitter');
        const workbench = byId('traffic-replay-workbench');
        if (!splitter || !workbench || !root.document) return;
        splitter.addEventListener('pointerdown', (event) => {
            event.preventDefault();
            splitter.classList.add('is-dragging');
            splitter.setPointerCapture?.(event.pointerId);
            const rect = workbench.getBoundingClientRect();
            const move = (moveEvent) => setWorkbenchWidth(moveEvent.clientX - rect.left);
            const up = () => {
                splitter.classList.remove('is-dragging');
                root.document.removeEventListener('pointermove', move);
                root.document.removeEventListener('pointerup', up);
            };
            root.document.addEventListener('pointermove', move);
            root.document.addEventListener('pointerup', up);
        });
        splitter.addEventListener('keydown', (event) => {
            if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
            event.preventDefault();
            const requestPane = root.document.querySelector('.traffic-replay-request-pane');
            setWorkbenchWidth((requestPane?.getBoundingClientRect().width || workbench.clientWidth / 2) + (event.key === 'ArrowLeft' ? -24 : 24));
        });
    }
    function bind() {
        if (state.bound) return;
        state.bound = true;
        byId('traffic-replay-load')?.addEventListener('click', () => void load());
        byId('traffic-replay-send')?.addEventListener('click', () => void send());
        byId('traffic-replay-format')?.addEventListener('click', formatJSONBody);
        byId('traffic-replay-reset')?.addEventListener('click', resetRequest);
        byId('traffic-replay-transaction-id')?.addEventListener('keydown', (event) => { if (event.key === 'Enter') void load(); });
        byId('traffic-replay-request')?.addEventListener('input', updateRequestLines);
        byId('traffic-replay-request')?.addEventListener('scroll', (event) => {
            const lines = byId('traffic-replay-request-lines');
            if (lines) lines.scrollTop = event.currentTarget.scrollTop;
        });
        byId('traffic-replay-request')?.addEventListener('keydown', (event) => {
            if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') { event.preventDefault(); void send(); }
        });
        byId('traffic-replay-response')?.addEventListener('scroll', (event) => {
            const lines = byId('traffic-replay-response-lines');
            if (lines) lines.scrollTop = event.currentTarget.scrollTop;
        });
        root.document?.querySelectorAll('[data-replay-response-view]').forEach((button) => {
            button.addEventListener('click', () => { state.responseView = button.dataset.replayResponseView || 'raw'; renderResponseView(); });
        });
        byId('traffic-replay-history')?.addEventListener('click', (event) => {
            const button = event.target.closest('button[data-history-index]');
            if (button) restoreHistory(button.dataset.historyIndex);
        });
        bindSplitter();
        renderHistory();
    }
    function init() {
        bind();
        const pending = String(root.pendingTrafficReplayTransaction || '').trim();
        if (pending) {
            root.pendingTrafficReplayTransaction = '';
            void load(pending);
        }
    }
    root.openTrafficReplayTransaction = (transactionID) => {
        root.pendingTrafficReplayTransaction = String(transactionID || '');
        if (typeof root.switchPage === 'function') root.switchPage('traffic-replay');
    };
    root.initTrafficReplayPage = init;
}(typeof window !== 'undefined' ? window : globalThis));
