(function (root) {
    'use strict';

    const REQUEST_TIMEOUT_MS = 15000;
    const state = {
        bound: false,
        loading: false,
        view: 'scripts',
        query: '',
        selectedTransformID: '',
        scripts: [],
        cases: [],
        runs: [],
        conversations: [],
        controller: null,
        sourceController: null,
        manualController: null,
        editorController: null,
        scopeController: null,
        editTransformID: '',
        editRevisionID: '',
        scopeBindingID: '',
        scopeTransformID: '',
        scopeCreate: false,
        pendingBindings: new Set(),
        pendingTransforms: new Set(),
        confirmDeleteBindingID: '',
        confirmDeleteTransformID: '',
        requestID: 0,
        sourceRequestID: 0,
    };

    function byId(id) {
        return root.document ? root.document.getElementById(id) : null;
    }

    function setText(node, value) {
        if (node) node.textContent = String(value == null ? '' : value);
    }

    function create(tag, className, text) {
        const node = root.document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) setText(node, text);
        return node;
    }

    function list(value) {
        return Array.isArray(value) ? value.filter((item) => String(item || '').trim()) : [];
    }

    function splitValues(value, transform) {
        const seen = new Set();
        return String(value || '').split(/[\n,]+/).map((item) => {
            const trimmed = item.trim();
            return trimmed && typeof transform === 'function' ? transform(trimmed) : trimmed;
        }).filter((item) => {
            if (!item || seen.has(item)) return false;
            seen.add(item);
            return true;
        });
    }

    function canManageBindings() {
        return typeof root.hasPermission === 'function' && root.hasPermission('traffic_transform:activate_observe');
    }

    function canWriteScripts() {
        return typeof root.hasPermission === 'function' && root.hasPermission('traffic_transform:write');
    }

    function canEditScripts() {
        return canWriteScripts() && typeof root.hasPermission === 'function' && root.hasPermission('traffic_transform:read_source');
    }

    async function responseError(response, fallback) {
        try {
            const payload = await response.json();
            return new Error(payload.error || fallback || `HTTP ${response.status}`);
        } catch (_error) {
            return new Error(fallback || `HTTP ${response.status}`);
        }
    }

    function formatTime(raw) {
        const date = new Date(raw || '');
        return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString();
    }

    function shortID(value) {
        const text = String(value || '');
        return text.length > 14 ? `${text.slice(0, 12)}…` : (text || '-');
    }

    function runtimeLabel(mode) {
        if (mode === 'container') return '容器执行';
        if (mode === 'host') return '本机执行';
        return '运行位置未标注';
    }

    function badge(text, kind) {
        return create('span', `traffic-transform-badge${kind ? ` is-${kind}` : ''}`, text);
    }

    function appendMeta(container, label, value, code) {
        const item = create('span');
        item.appendChild(create('span', '', `${label} `));
        item.appendChild(create(code ? 'code' : 'strong', '', value));
        container.appendChild(item);
    }

    function appendMatcher(container, matcher) {
        const normalized = matcher && typeof matcher === 'object' ? matcher : {};
        const groups = [
            ['站点', list(normalized.hosts)],
            ['协议', list(normalized.schemes)],
            ['方法', list(normalized.methods)],
            ['路径', list(normalized.pathPrefixes)],
            ['类型', list(normalized.contentTypes)],
        ];
        groups.forEach(([label, values]) => {
            values.forEach((value) => container.appendChild(create('code', '', `${label} · ${value}`)));
        });
    }

    function emptyState(title, description) {
        const empty = create('div', 'traffic-transform-empty');
        const body = create('div');
        body.appendChild(create('strong', '', title));
        body.appendChild(create('p', '', description));
        empty.appendChild(body);
        return empty;
    }

    function matchesQuery(value) {
        if (!state.query) return true;
        return JSON.stringify(value || {}).toLocaleLowerCase().includes(state.query);
    }

    function validationBadge(revision) {
        if (!revision) return badge('暂无版本', 'pending');
        if (revision.validationStatus === 'passed') return badge('验证通过', 'passed');
        if (revision.validationStatus === 'failed') return badge('验证失败', 'failed');
        return badge('待验证', 'pending');
    }

    function validationLabel(status) {
        if (status === 'passed') return '验证通过';
        if (status === 'failed') return '验证失败';
        return '待验证';
    }

    function scriptStatus(item) {
        if (Number(item.activeBindingCount || 0) > 0) return ['已启用', 'active'];
        if (Number(item.bindingCount || 0) > 0) return ['已停用', 'disabled'];
        return ['未配置', 'pending'];
    }

    function requestScopeText(matcher) {
        const method = list(matcher?.methods).join(', ') || '全部方法';
        const paths = list(matcher?.pathPrefixes).join(', ') || '全部路径';
        const schemes = list(matcher?.schemes).join(', ').toUpperCase();
        return [schemes, method, paths].filter(Boolean).join(' · ');
    }

    function appendHookChain(container, label, hooks) {
        if (!hooks.length) return;
        const row = create('div', 'traffic-transform-hook-row');
        row.appendChild(create('span', 'traffic-transform-hook-label', label));
        const chain = create('div', 'traffic-transform-hook-chain');
        hooks.forEach((hook, index) => {
            if (index) chain.appendChild(create('span', 'traffic-transform-hook-arrow', '→'));
            chain.appendChild(create('code', '', hook));
        });
        row.appendChild(chain);
        container.appendChild(row);
    }

    function appendScopeActions(container, item) {
        if (!canManageBindings() || item.mode !== 'observe') return;
        const pending = state.pendingBindings.has(item.id);
        const edit = create('button', 'traffic-transform-row-action', '编辑');
        edit.type = 'button';
        edit.disabled = pending;
        edit.addEventListener('click', () => openScope(item));
        container.appendChild(edit);
        if (item.status === 'disabled') {
            const confirming = state.confirmDeleteBindingID === item.id;
            const remove = create('button', `traffic-transform-row-action is-danger${confirming ? ' is-confirming' : ''}`, confirming ? '确认删除' : '删除');
            remove.type = 'button';
            remove.disabled = pending;
            remove.setAttribute('aria-pressed', confirming ? 'true' : 'false');
            remove.addEventListener('click', () => {
                if (!confirming) {
                    state.confirmDeleteBindingID = item.id;
                    state.confirmDeleteTransformID = '';
                    render();
                    setText(byId('traffic-transform-status'), '请再次点击“确认删除”移除该作用范围；脚本源码和历史运行记录会保留。');
                    return;
                }
                state.confirmDeleteBindingID = '';
                void deleteBinding(item);
            });
            container.appendChild(remove);
        }
    }

    function createScopeToggle(item) {
        const enabled = item.status === 'active';
        const hosts = list(item.matcher?.hosts);
        const pending = state.pendingBindings.has(item.id);
        const toggle = create('button', `traffic-transform-toggle${enabled ? ' is-active' : ''}`);
        toggle.type = 'button';
        toggle.setAttribute('role', 'switch');
        toggle.setAttribute('aria-checked', enabled ? 'true' : 'false');
        toggle.setAttribute('aria-label', `${enabled ? '停用' : '启用'} ${item.transformName || '脚本'} 的作用范围`);
        toggle.disabled = pending || (!enabled && !hosts.length);
        toggle.title = !enabled && !hosts.length ? '请先编辑并指定目标网站' : '';
        toggle.appendChild(create('span'));
        toggle.addEventListener('click', () => void setBindingEnabled(item, !enabled));
        return toggle;
    }

    function renderScopeRows(container, transformID) {
        const items = state.cases.filter((item) => item.transformId === transformID && item.mode === 'observe');
        if (!items.length) {
            container.appendChild(emptyState('尚未配置作用范围', '让 Agent 为脚本指定目标网站，或在手写脚本时填写站点后启用。'));
            return;
        }
        const table = create('div', 'traffic-transform-scope-table');
        const header = create('div', 'traffic-transform-scope-row is-header');
        ['启用', '站点', '请求范围', '运行位置', '注入的对话', '操作'].forEach((text) => header.appendChild(create('span', '', text)));
        table.appendChild(header);
        items.forEach((item) => {
            const matcher = item.matcher || {};
            const row = create('div', 'traffic-transform-scope-row');
            const toggleCell = create('div', 'traffic-transform-scope-toggle');
            toggleCell.appendChild(createScopeToggle(item));
            row.appendChild(toggleCell);
            const hostCell = create('div', 'traffic-transform-scope-primary', list(matcher.hosts).join(', ') || '未限定网站');
            if (!list(matcher.hosts).length) hostCell.classList.add('is-warning');
            row.appendChild(hostCell);
            row.appendChild(create('div', 'traffic-transform-scope-request', requestScopeText(matcher)));
            row.appendChild(create('div', 'traffic-transform-scope-runtime', runtimeLabel(item.runtimeMode)));
            const conversation = create('div', 'traffic-transform-scope-conversation');
            conversation.appendChild(create('strong', '', item.conversationTitle || '未命名对话'));
            conversation.appendChild(create('span', '', shortID(item.conversationId)));
            row.appendChild(conversation);
            const actions = create('div', 'traffic-transform-row-actions');
            appendScopeActions(actions, item);
            row.appendChild(actions);
            table.appendChild(row);
        });
        container.appendChild(table);
    }

    function renderScriptDetail(item) {
        const container = byId('traffic-transform-script-detail');
        if (!container) return;
        container.replaceChildren();
        if (!item) {
            container.appendChild(emptyState('选择一个脚本', '从左侧选择脚本后，可查看代码、Hook 链和网站作用范围。'));
            return;
        }
        const transform = item.transform || {};
        const revision = item.latestRevision || null;
        const head = create('section', 'traffic-transform-detail-head');
        head.appendChild(create('div', 'traffic-transform-code-mark', '</>'));
        const summary = create('div', 'traffic-transform-detail-summary');
        const titleLine = create('div', 'traffic-transform-detail-title');
        titleLine.appendChild(create('h3', '', transform.name || '未命名脚本'));
        titleLine.appendChild(validationBadge(revision));
        summary.appendChild(titleLine);
        summary.appendChild(create('p', '', transform.description || 'Agent 未填写脚本说明。'));
        const meta = create('div', 'traffic-transform-detail-meta');
        appendMeta(meta, '', transform.createdByAgentId ? 'AI 生成' : '用户编写');
        appendMeta(meta, '', String(transform.language || 'python3').replace(/^python3$/i, 'Python 3'));
        appendMeta(meta, '', `${list(revision?.hooks).length} 个 Hook`);
        appendMeta(meta, '', `更新于 ${formatTime(transform.updatedAt)}`);
        summary.appendChild(meta);
        head.appendChild(summary);
        const canReadSource = typeof root.hasPermission === 'function' && root.hasPermission('traffic_transform:read_source');
        const actions = create('div', 'traffic-transform-detail-actions');
        if (revision && canReadSource) {
            const read = create('button', 'btn-secondary traffic-transform-view-code', '查看代码');
            read.type = 'button';
            read.addEventListener('click', () => void openSource(revision.id));
            actions.appendChild(read);
        }
        if (revision && canEditScripts()) {
            const edit = create('button', 'btn-secondary', '编辑脚本');
            edit.type = 'button';
            edit.disabled = state.pendingTransforms.has(transform.id);
            edit.addEventListener('click', () => void openEditor(item));
            actions.appendChild(edit);
        }
        if (canWriteScripts()) {
            const confirming = state.confirmDeleteTransformID === transform.id;
            const remove = create('button', `btn-secondary is-danger${confirming ? ' is-confirming' : ''}`, confirming ? '确认删除脚本' : '删除脚本');
            remove.type = 'button';
            const hasBindings = Number(item.bindingCount || 0) > 0;
            remove.disabled = hasBindings || state.pendingTransforms.has(transform.id);
            remove.setAttribute('aria-pressed', confirming ? 'true' : 'false');
            remove.title = hasBindings ? '请先停用并删除该脚本的全部作用范围' : '删除脚本；历史版本与运行证据仍会保留';
            remove.addEventListener('click', () => {
                if (!confirming) {
                    state.confirmDeleteTransformID = transform.id;
                    state.confirmDeleteBindingID = '';
                    render();
                    setText(byId('traffic-transform-status'), '请再次点击“确认删除脚本”；历史版本、流量和 Runner 证据会保留。');
                    return;
                }
                state.confirmDeleteTransformID = '';
                void deleteScript(item);
            });
            actions.appendChild(remove);
        }
        if (actions.childNodes.length) head.appendChild(actions);
        container.appendChild(head);

        const scopes = create('section', 'traffic-transform-detail-section');
        const scopeHead = create('div', 'traffic-transform-section-head');
        scopeHead.appendChild(create('h4', '', '作用范围'));
        const count = state.cases.filter((binding) => binding.transformId === transform.id && binding.mode === 'observe').length;
        const scopeActions = create('div', 'traffic-transform-section-actions');
        scopeActions.appendChild(create('span', '', `${count} 条`));
        if (revision && canManageBindings()) {
            const add = create('button', 'traffic-transform-add-scope', '新增作用范围');
            add.type = 'button';
            add.addEventListener('click', () => openNewScope(item));
            scopeActions.appendChild(add);
        }
        scopeHead.appendChild(scopeActions);
        scopes.appendChild(scopeHead);
        renderScopeRows(scopes, transform.id);
        container.appendChild(scopes);

        const hooks = list(revision?.hooks);
        const hookSection = create('section', 'traffic-transform-detail-section traffic-transform-hooks');
        const hookHead = create('div', 'traffic-transform-section-head');
        hookHead.appendChild(create('h4', '', 'Hook 链'));
        hookSection.appendChild(hookHead);
        if (hooks.length) {
            appendHookChain(hookSection, '请求', hooks.filter((hook) => hook.includes('request')));
            appendHookChain(hookSection, '响应', hooks.filter((hook) => hook.includes('response')));
        } else {
            hookSection.appendChild(create('p', 'traffic-transform-inline-empty', '当前版本没有声明 Hook。'));
        }
        container.appendChild(hookSection);
    }

    function renderScripts() {
        const rail = byId('traffic-transform-script-list');
        if (!rail) return;
        rail.replaceChildren();
        const items = state.scripts.filter(matchesQuery);
        if (!items.some((item) => item.transform?.id === state.selectedTransformID)) {
            state.selectedTransformID = items[0]?.transform?.id || '';
        }
        if (!items.length) {
            rail.appendChild(emptyState('没有匹配的脚本', state.query ? '请尝试其他搜索词。' : '让 Agent 生成或手写一个脚本。'));
            renderScriptDetail(null);
            setText(byId('traffic-transform-script-total'), `共 ${state.scripts.length} 个脚本`);
            return;
        }
        items.forEach((item) => {
            const transform = item.transform || {};
            const row = create('button', `traffic-transform-script-item${transform.id === state.selectedTransformID ? ' is-active' : ''}`);
            row.type = 'button';
            row.setAttribute('aria-pressed', transform.id === state.selectedTransformID ? 'true' : 'false');
            row.appendChild(create('span', 'traffic-transform-script-icon', '</>'));
            const body = create('span', 'traffic-transform-script-copy');
            body.appendChild(create('strong', '', transform.name || '未命名脚本'));
            body.appendChild(create('span', '', transform.description || '暂无说明'));
            body.appendChild(create('small', '', `更新于 ${formatTime(transform.updatedAt)}`));
            row.appendChild(body);
            const [label, kind] = scriptStatus(item);
            row.appendChild(badge(label, kind));
            row.addEventListener('click', () => {
                state.selectedTransformID = transform.id;
                state.confirmDeleteTransformID = '';
                state.confirmDeleteBindingID = '';
                renderScripts();
            });
            rail.appendChild(row);
        });
        const selected = state.scripts.find((item) => item.transform?.id === state.selectedTransformID) || items[0];
        renderScriptDetail(selected);
        setText(byId('traffic-transform-script-total'), `共 ${state.scripts.length} 个脚本`);
    }

    function renderConversations() {
        const container = byId('traffic-transform-conversations');
        if (!container) return;
        container.replaceChildren();
        const items = state.conversations.filter(matchesQuery);
        if (!items.length) {
            container.appendChild(emptyState('暂无注入脚本的对话', state.query ? '没有对话匹配当前搜索。' : '脚本绑定到对话后，会在这里显示对话、运行位置和被限定的网站。'));
            return;
        }
        const table = create('div', 'traffic-transform-conversation-table');
        const header = create('div', 'traffic-transform-conversation-row is-header');
        ['对话', '脚本', '目标网站', '运行位置', '状态'].forEach((text) => header.appendChild(create('span', '', text)));
        table.appendChild(header);
        items.forEach((item) => {
            const row = create('article', 'traffic-transform-conversation-row');
            const title = create('div', 'traffic-transform-conversation-title');
            title.appendChild(create('strong', '', item.title || '未命名对话'));
            title.appendChild(create('span', '', shortID(item.id)));
            row.appendChild(title);
            row.appendChild(create('div', '', list(item.transformNames).join(', ') || '-'));
            const hosts = list(item.matchers).flatMap((matcher) => list(matcher?.hosts));
            row.appendChild(create('div', 'traffic-transform-conversation-hosts', hosts.join(', ') || '未限定网站'));
            row.appendChild(create('div', '', runtimeLabel(item.runtimeMode)));
            const activeCount = Number(item.activeCount || 0);
            const bindingCount = Number(item.bindingCount || 0);
            const statusText = activeCount === 0 ? '已停用' : (activeCount === bindingCount ? '已启用' : `${activeCount}/${bindingCount} 已启用`);
            row.appendChild(badge(statusText, activeCount > 0 ? 'active' : 'disabled'));
            table.appendChild(row);
        });
        container.appendChild(table);
    }

    function runnerAction(item) {
        if (item.action === 'pass') return ['通过', 'passed'];
        if (item.action === 'replace') return ['已转换', 'active'];
        if (item.action === 'block') return ['已阻断', 'warning'];
        return ['执行错误', 'failed'];
    }

    function renderRunner() {
        const container = byId('traffic-transform-runner');
        if (!container) return;
        container.replaceChildren();
        const items = state.runs.filter(matchesQuery);
        if (!items.length) {
            container.appendChild(emptyState('暂无 Runner 执行记录', state.query ? '没有执行记录匹配当前搜索。' : '脚本完成离线测试或处理流量后，会在这里显示安全的执行元数据。'));
            return;
        }
        const table = create('div', 'traffic-transform-runner-table');
        const header = create('div', 'traffic-transform-runner-row is-header');
        ['时间', '脚本', '执行', 'Hook', '结果', '耗时', '事务 / Runner'].forEach((text) => header.appendChild(create('span', '', text)));
        table.appendChild(header);
        items.forEach((item) => {
            const row = create('article', 'traffic-transform-runner-row');
            row.appendChild(create('time', '', formatTime(item.createdAt)));
            const script = create('div', 'traffic-transform-runner-script');
            script.appendChild(create('strong', '', item.transformName || '未命名脚本'));
            if (item.transformDeleted) script.appendChild(badge('脚本已删除', 'deleted'));
            script.appendChild(create('span', '', shortID(item.revisionId)));
            row.appendChild(script);
            row.appendChild(create('div', '', `${item.kind === 'offline' ? '离线测试' : '在线执行'} · ${item.mode === 'inline' ? '中间人' : '旁路'}`));
            row.appendChild(create('code', '', item.hook || '-'));
            const [actionText, actionKind] = runnerAction(item);
            const result = create('div', 'traffic-transform-runner-result');
            result.appendChild(badge(actionText, actionKind));
            if (item.errorSummary) result.appendChild(create('small', '', item.errorSummary));
            row.appendChild(result);
            row.appendChild(create('div', '', `${Number(item.durationMs || 0)} ms`));
            const identity = create('div', 'traffic-transform-runner-identity');
            identity.appendChild(create('span', '', item.transactionId ? `事务 ${shortID(item.transactionId)}` : '无关联事务'));
            identity.appendChild(create('small', '', item.runnerIdentity || 'Runner 未标注'));
            row.appendChild(identity);
            table.appendChild(row);
        });
        container.appendChild(table);
    }

    function render() {
        setText(byId('traffic-transform-count-scripts'), state.scripts.length);
        setText(byId('traffic-transform-count-runner'), state.runs.length);
        setText(byId('traffic-transform-count-conversations'), state.conversations.length);
        renderScripts();
        renderRunner();
        renderConversations();
    }

    function selectView(view) {
        if (!['scripts', 'runner', 'conversations'].includes(view)) return;
        state.view = view;
        root.document.querySelectorAll('[data-transform-view]').forEach((button) => {
            const active = button.dataset.transformView === view;
            button.classList.toggle('is-active', active);
            button.setAttribute('aria-selected', active ? 'true' : 'false');
        });
        ['scripts', 'runner', 'conversations'].forEach((candidate) => {
            const panel = byId(`traffic-transform-panel-${candidate}`);
            if (panel) panel.hidden = candidate !== view;
        });
    }

    async function load() {
        if (typeof root.apiFetch !== 'function') return;
        if (state.controller) state.controller.abort();
        const controller = new root.AbortController();
        state.controller = controller;
        state.loading = true;
        const requestID = ++state.requestID;
        let timedOut = false;
        const timeout = root.setTimeout(() => { timedOut = true; controller.abort(); }, REQUEST_TIMEOUT_MS);
        setText(byId('traffic-transform-status'), '正在加载脚本和注入对话…');
        try {
            const response = await root.apiFetch('/api/traffic-transforms', { signal: controller.signal });
            if (requestID !== state.requestID) return;
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const payload = await response.json();
            if (requestID !== state.requestID) return;
            state.scripts = list(payload.scripts);
            state.cases = list(payload.cases);
            state.runs = list(payload.runs);
            state.conversations = list(payload.conversations);
            render();
            setText(byId('traffic-transform-status'), `${state.scripts.length} 个脚本 · ${state.runs.length} 条 Runner 记录 · ${state.conversations.length} 个注入对话`);
        } catch (error) {
            if (requestID !== state.requestID || (!timedOut && error?.name === 'AbortError')) return;
            state.scripts = [];
            state.cases = [];
            state.runs = [];
            state.conversations = [];
            render();
            setText(byId('traffic-transform-status'), timedOut ? '加载超过 15 秒，请检查网络后重试' : `加载失败：${error.message || error}`);
        } finally {
            root.clearTimeout(timeout);
            if (state.controller === controller) state.controller = null;
            if (requestID === state.requestID) state.loading = false;
        }
    }

    async function openSource(revisionID) {
        if (!revisionID || typeof root.apiFetch !== 'function') return;
        if (state.sourceController) state.sourceController.abort();
        const controller = new root.AbortController();
        state.sourceController = controller;
        const requestID = ++state.sourceRequestID;
        const modal = byId('traffic-transform-source-detail');
        if (!modal) return;
        modal.hidden = false;
        renderSourceCode('正在读取脚本…');
        try {
            const response = await root.apiFetch(`/api/traffic-transform-revisions/${encodeURIComponent(revisionID)}/source`, { signal: controller.signal });
            if (requestID !== state.sourceRequestID) return;
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const payload = await response.json();
            const revision = payload.revision || {};
            const transform = payload.transform || {};
            const source = revision.source || '该版本没有可显示的源码';
            const lineCount = source.split('\n').length;
            setText(byId('traffic-transform-source-title'), transform.name || 'AI 生成的脚本');
            setText(byId('traffic-transform-source-meta'), `${shortID(revision.id)} · ${lineCount} 行 · SHA-256 ${revision.sourceSha256 || '-'} · ${validationLabel(revision.validationStatus)}`);
            renderSourceCode(source);
        } catch (error) {
            if (requestID !== state.sourceRequestID || error?.name === 'AbortError') return;
            renderSourceCode(`读取失败：${error.message || error}`);
        }
    }

    function renderSourceCode(source) {
        const container = byId('traffic-transform-source-code');
        if (!container) return;
        container.replaceChildren();
        String(source == null ? '' : source).split('\n').forEach((line, index) => {
            const row = create('div', 'traffic-transform-source-line');
            row.appendChild(create('span', 'traffic-transform-source-line-number', index + 1));
            row.appendChild(create('code', '', line || ' '));
            container.appendChild(row);
        });
    }

    function closeSource() {
        const modal = byId('traffic-transform-source-detail');
        if (modal) modal.hidden = true;
        state.sourceRequestID++;
        if (state.sourceController) state.sourceController.abort();
        state.sourceController = null;
    }

    async function openEditor(item) {
        const transform = item?.transform || {};
        const revision = item?.latestRevision || {};
        const modal = byId('traffic-transform-editor');
        if (!modal || !transform.id || !revision.id || typeof root.apiFetch !== 'function') return;
        if (state.editorController) state.editorController.abort();
        const controller = new root.AbortController();
        state.editorController = controller;
        state.editTransformID = transform.id;
        state.editRevisionID = revision.id;
        modal.hidden = false;
        const submit = byId('traffic-transform-editor-submit');
        if (submit) submit.disabled = true;
        byId('traffic-transform-editor-name').value = transform.name || '';
        byId('traffic-transform-editor-description').value = transform.description || '';
        byId('traffic-transform-editor-source').value = '';
        setText(byId('traffic-transform-editor-status'), '正在读取当前不可变版本…');
        try {
            const response = await root.apiFetch(`/api/traffic-transform-revisions/${encodeURIComponent(revision.id)}/source`, { signal: controller.signal });
            if (!response.ok) throw await responseError(response, '读取脚本失败');
            const payload = await response.json();
            if (state.editTransformID !== transform.id || state.editRevisionID !== revision.id) return;
            byId('traffic-transform-editor-source').value = payload.revision?.source || '';
            setText(byId('traffic-transform-editor-status'), '修改源码后保存会创建新版本；只修改名称或说明不会重复创建版本。');
            if (submit) submit.disabled = false;
        } catch (error) {
            if (error?.name !== 'AbortError') setText(byId('traffic-transform-editor-status'), `读取失败：${error.message || error}`);
        } finally {
            if (state.editorController === controller) state.editorController = null;
        }
    }

    function closeEditor() {
        const modal = byId('traffic-transform-editor');
        if (modal) modal.hidden = true;
        state.editTransformID = '';
        state.editRevisionID = '';
        if (state.editorController) state.editorController.abort();
        state.editorController = null;
    }

    async function submitEditor(event) {
        event?.preventDefault();
        const transformID = state.editTransformID;
        const revisionID = state.editRevisionID;
        if (!transformID || !revisionID || typeof root.apiFetch !== 'function') return;
        if (state.editorController) state.editorController.abort();
        const controller = new root.AbortController();
        state.editorController = controller;
        const submit = byId('traffic-transform-editor-submit');
        if (submit) submit.disabled = true;
        setText(byId('traffic-transform-editor-status'), '正在静态检查并在隔离 Runner 中验证…');
        try {
            const response = await root.apiFetch(`/api/traffic-transforms/${encodeURIComponent(transformID)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    baseRevisionId: revisionID,
                    name: String(byId('traffic-transform-editor-name')?.value || '').trim(),
                    description: String(byId('traffic-transform-editor-description')?.value || '').trim(),
                    source: byId('traffic-transform-editor-source')?.value || '',
                }),
                signal: controller.signal,
            });
            if (!response.ok) throw await responseError(response, '保存失败');
            closeEditor();
            await load();
            setText(byId('traffic-transform-status'), '脚本已更新；新源码已生成不可变版本并通过验证。');
        } catch (error) {
            if (error?.name !== 'AbortError') setText(byId('traffic-transform-editor-status'), `保存失败：${error.message || error}`);
        } finally {
            if (submit) submit.disabled = false;
            if (state.editorController === controller) state.editorController = null;
        }
    }

    async function deleteScript(item) {
        const transform = item?.transform || {};
        if (!transform.id || Number(item.bindingCount || 0) > 0 || state.pendingTransforms.has(transform.id) || typeof root.apiFetch !== 'function') return;
        state.pendingTransforms.add(transform.id);
        render();
        setText(byId('traffic-transform-status'), '正在删除脚本…');
        try {
            const response = await root.apiFetch(`/api/traffic-transforms/${encodeURIComponent(transform.id)}`, { method: 'DELETE' });
            if (!response.ok) throw await responseError(response, '删除失败');
            if (state.selectedTransformID === transform.id) state.selectedTransformID = '';
            await load();
            setText(byId('traffic-transform-status'), '脚本已删除；历史版本、流量和运行证据已保留。');
        } catch (error) {
            setText(byId('traffic-transform-status'), `删除失败：${error.message || error}`);
        } finally {
            state.pendingTransforms.delete(transform.id);
            render();
        }
    }

    function minimalSource(direction) {
        const hook = direction === 'response' ? 'decode_response' : 'decode_request';
        return `from cyberstrike_transform import Message\n\ndef ${hook}(ctx, wire: Message) -> Message:\n    return wire.set_header("X-Traffic-Decoded", "true")`;
    }

    function openManual() {
        const modal = byId('traffic-transform-manual');
        if (!modal) return;
        modal.hidden = false;
        setText(byId('traffic-transform-manual-status'), '填写脚本与一个历史事务，可直接完成隔离验证和离线测试。');
        const output = byId('traffic-transform-manual-output');
        if (output) output.hidden = true;
    }

    function closeManual() {
        const modal = byId('traffic-transform-manual');
        if (modal) modal.hidden = true;
        if (state.manualController) state.manualController.abort();
        state.manualController = null;
    }

    function openScope(item) {
        const modal = byId('traffic-transform-scope-editor');
        if (!modal || !item?.id) return;
        const matcher = item.matcher && typeof item.matcher === 'object' ? item.matcher : {};
        state.scopeBindingID = item.id;
        state.scopeTransformID = item.transformId || '';
        state.scopeCreate = false;
        modal.hidden = false;
        setText(byId('traffic-transform-scope-title'), `编辑作用范围 · ${item.transformName || '未命名脚本'}`);
        setText(byId('traffic-transform-scope-meta'), `${item.conversationTitle || item.conversationId || '未命名对话'} · ${runtimeLabel(item.runtimeMode)}`);
        const conversationField = byId('traffic-transform-scope-conversation-field');
        if (conversationField) conversationField.hidden = true;
        const conversation = byId('traffic-transform-scope-conversation-id');
        if (conversation) {
            conversation.value = item.conversationId || '';
            conversation.disabled = true;
        }
        const activateField = byId('traffic-transform-scope-activate-field');
        if (activateField) activateField.hidden = true;
        byId('traffic-transform-scope-hosts').value = list(matcher.hosts).join('\n');
        byId('traffic-transform-scope-schemes').value = list(matcher.schemes).join(', ');
        byId('traffic-transform-scope-methods').value = list(matcher.methods).join(', ');
        byId('traffic-transform-scope-paths').value = list(matcher.pathPrefixes).join('\n');
        byId('traffic-transform-scope-types').value = list(matcher.contentTypes).join(', ');
        byId('traffic-transform-scope-priority').value = Number(item.priority || 0);
        setText(byId('traffic-transform-scope-submit'), '保存作用范围');
        setText(byId('traffic-transform-scope-status'), '保存后立即按新范围筛选该对话的流量；未匹配的网站不会进入脚本 Runner。');
    }

    function openNewScope(item) {
        const modal = byId('traffic-transform-scope-editor');
        const transform = item?.transform || {};
        if (!modal || !transform.id) return;
        state.scopeBindingID = '';
        state.scopeTransformID = transform.id;
        state.scopeCreate = true;
        modal.hidden = false;
        setText(byId('traffic-transform-scope-title'), `新增作用范围 · ${transform.name || '未命名脚本'}`);
        setText(byId('traffic-transform-scope-meta'), '为脚本选择对话和目标网站；同一对话中的其他网站不会进入 Runner。');
        const conversationField = byId('traffic-transform-scope-conversation-field');
        if (conversationField) conversationField.hidden = false;
        const conversation = byId('traffic-transform-scope-conversation-id');
        if (conversation) {
            conversation.disabled = false;
            conversation.value = transform.conversationId || '';
        }
        const activateField = byId('traffic-transform-scope-activate-field');
        if (activateField) activateField.hidden = false;
        const activate = byId('traffic-transform-scope-activate');
        if (activate) activate.checked = true;
        byId('traffic-transform-scope-hosts').value = '';
        byId('traffic-transform-scope-schemes').value = 'https';
        byId('traffic-transform-scope-methods').value = '';
        byId('traffic-transform-scope-paths').value = '';
        byId('traffic-transform-scope-types').value = '';
        byId('traffic-transform-scope-priority').value = 100;
        setText(byId('traffic-transform-scope-submit'), '创建作用范围');
        setText(byId('traffic-transform-scope-status'), '填写目标网站后即可创建；需要时可进一步限定协议、方法、路径和内容类型。');
        conversation?.focus();
    }

    function closeScope() {
        const modal = byId('traffic-transform-scope-editor');
        if (modal) modal.hidden = true;
        state.scopeBindingID = '';
        state.scopeTransformID = '';
        state.scopeCreate = false;
        if (state.scopeController) state.scopeController.abort();
        state.scopeController = null;
    }

    async function submitScope(event) {
        event?.preventDefault();
        if ((!state.scopeCreate && !state.scopeBindingID) || (state.scopeCreate && !state.scopeTransformID) || typeof root.apiFetch !== 'function') return;
        const conversationID = String(byId('traffic-transform-scope-conversation-id')?.value || '').trim();
        if (state.scopeCreate && !conversationID) {
            setText(byId('traffic-transform-scope-status'), '请填写要注入脚本的对话 ID。');
            byId('traffic-transform-scope-conversation-id')?.focus();
            return;
        }
        const hosts = splitValues(byId('traffic-transform-scope-hosts')?.value, (value) => value.toLocaleLowerCase());
        if (!hosts.length) {
            setText(byId('traffic-transform-scope-status'), '至少填写一个目标网站。');
            byId('traffic-transform-scope-hosts')?.focus();
            return;
        }
        if (state.scopeController) state.scopeController.abort();
        const controller = new root.AbortController();
        state.scopeController = controller;
        const bindingID = state.scopeBindingID;
        const creating = state.scopeCreate;
        const payload = {
            matcher: {
                hosts,
                schemes: splitValues(byId('traffic-transform-scope-schemes')?.value, (value) => value.toLocaleLowerCase()),
                methods: splitValues(byId('traffic-transform-scope-methods')?.value, (value) => value.toUpperCase()),
                pathPrefixes: splitValues(byId('traffic-transform-scope-paths')?.value),
                contentTypes: splitValues(byId('traffic-transform-scope-types')?.value, (value) => value.toLocaleLowerCase()),
            },
            priority: Number(byId('traffic-transform-scope-priority')?.value || 0),
        };
        if (creating) {
            payload.transformId = state.scopeTransformID;
            payload.conversationId = conversationID;
            payload.activate = Boolean(byId('traffic-transform-scope-activate')?.checked);
        }
        const submit = byId('traffic-transform-scope-submit');
        if (submit) submit.disabled = true;
        setText(byId('traffic-transform-scope-status'), creating ? '正在创建作用范围…' : '正在保存作用范围…');
        try {
            const url = creating ? '/api/traffic-transform-bindings' : `/api/traffic-transform-bindings/${encodeURIComponent(bindingID)}/scope`;
            const response = await root.apiFetch(url, {
                method: creating ? 'POST' : 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: controller.signal,
            });
            if (!response.ok) throw await responseError(response, creating ? '创建失败' : '保存失败');
            closeScope();
            await load();
            setText(byId('traffic-transform-status'), creating ? '作用范围已创建。' : '作用范围已更新。');
        } catch (error) {
            if (error?.name !== 'AbortError') setText(byId('traffic-transform-scope-status'), `${creating ? '创建' : '保存'}失败：${error.message || error}`);
        } finally {
            if (submit) submit.disabled = false;
            if (state.scopeController === controller) state.scopeController = null;
        }
    }

    async function setBindingEnabled(item, enabled) {
        if (!item?.id || state.pendingBindings.has(item.id) || typeof root.apiFetch !== 'function') return;
        state.pendingBindings.add(item.id);
        render();
        setText(byId('traffic-transform-status'), enabled ? '正在启用作用范围…' : '正在停用作用范围…');
        try {
            const action = enabled ? 'activate' : 'disable';
            const response = await root.apiFetch(`/api/traffic-transform-bindings/${encodeURIComponent(item.id)}/${action}`, { method: 'POST' });
            if (!response.ok) throw await responseError(response, enabled ? '启用失败' : '停用失败');
            await load();
            setText(byId('traffic-transform-status'), enabled ? '作用范围已启用。' : '作用范围已停用。');
        } catch (error) {
            setText(byId('traffic-transform-status'), `${enabled ? '启用' : '停用'}失败：${error.message || error}`);
        } finally {
            state.pendingBindings.delete(item.id);
            render();
        }
    }

    async function deleteBinding(item) {
        if (!item?.id || item.status !== 'disabled' || state.pendingBindings.has(item.id) || typeof root.apiFetch !== 'function') return;
        state.pendingBindings.add(item.id);
        render();
        setText(byId('traffic-transform-status'), '正在删除已停用的作用范围…');
        try {
            const response = await root.apiFetch(`/api/traffic-transform-bindings/${encodeURIComponent(item.id)}`, { method: 'DELETE' });
            if (!response.ok) throw await responseError(response, '删除失败');
            await load();
            setText(byId('traffic-transform-status'), '作用范围已删除；脚本源码和历史运行记录已保留。');
        } catch (error) {
            setText(byId('traffic-transform-status'), `删除失败：${error.message || error}`);
        } finally {
            state.pendingBindings.delete(item.id);
            render();
        }
    }

    function summarizeManualResult(result) {
        const hooks = Array.isArray(result.dryRun?.hookResults) ? result.dryRun.hookResults.map((item) => ({
            hook: item.hook,
            action: item.action,
            outputHeaders: Array.isArray(item.outputMessage?.headers) ? item.outputMessage.headers : [],
            annotations: item.annotations || [],
        })) : [];
        return {
            validation: result.validation,
            dryRun: result.dryRun ? { roundTripMatched: result.dryRun.roundTripMatched, hookResults: hooks } : null,
            binding: result.binding ? { id: result.binding.id, status: result.binding.status, matcher: result.binding.matcher } : null,
        };
    }

    async function submitManual(event) {
        event?.preventDefault();
        if (typeof root.apiFetch !== 'function') return;
        if (state.manualController) state.manualController.abort();
        const controller = new root.AbortController();
        state.manualController = controller;
        const direction = byId('traffic-transform-manual-direction')?.value || 'request';
        const pathPrefix = String(byId('traffic-transform-manual-path')?.value || '').trim();
        const payload = {
            conversationId: String(byId('traffic-transform-manual-conversation')?.value || '').trim(),
            name: String(byId('traffic-transform-manual-name')?.value || '').trim(),
            description: String(byId('traffic-transform-manual-description')?.value || '').trim(),
            transactionId: String(byId('traffic-transform-manual-transaction')?.value || '').trim(),
            direction,
            source: byId('traffic-transform-manual-source')?.value || '',
            hooks: [direction === 'response' ? 'decode_response' : 'decode_request'],
            matcher: {
                hosts: [String(byId('traffic-transform-manual-host')?.value || '').trim()],
                pathPrefixes: pathPrefix ? [pathPrefix] : [],
            },
            activate: Boolean(byId('traffic-transform-manual-activate')?.checked),
        };
        const submit = byId('traffic-transform-manual-submit');
        if (submit) submit.disabled = true;
        setText(byId('traffic-transform-manual-status'), '正在静态检查、隔离加载并测试历史数据包…');
        const output = byId('traffic-transform-manual-output');
        if (output) output.hidden = true;
        try {
            const response = await root.apiFetch('/api/traffic-transforms/manual', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: controller.signal,
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
            setText(byId('traffic-transform-manual-status'), result.dryRun
                ? '脚本验证与历史包测试通过；下方输出可确认 Hook 是否修改了消息。'
                : '脚本验证通过；未填写历史事务，因此没有执行离线数据包测试。');
            if (output) {
                output.hidden = false;
                setText(output, JSON.stringify(summarizeManualResult(result), null, 2));
            }
            void load();
        } catch (error) {
            if (error?.name !== 'AbortError') setText(byId('traffic-transform-manual-status'), `处理失败：${error.message || error}`);
        } finally {
            if (submit) submit.disabled = false;
            if (state.manualController === controller) state.manualController = null;
        }
    }

    function bind() {
        if (state.bound) return;
        state.bound = true;
        root.document.querySelectorAll('[data-transform-view]').forEach((button) => {
            button.addEventListener('click', () => selectView(button.dataset.transformView));
        });
        byId('traffic-transform-refresh')?.addEventListener('click', () => void load());
        byId('traffic-transform-search')?.addEventListener('input', (event) => {
            state.query = String(event.target?.value || '').trim().toLocaleLowerCase().slice(0, 200);
            render();
        });
        byId('traffic-transform-source-close')?.addEventListener('click', closeSource);
        byId('traffic-transform-editor-close')?.addEventListener('click', closeEditor);
        byId('traffic-transform-editor-cancel')?.addEventListener('click', closeEditor);
        byId('traffic-transform-editor-form')?.addEventListener('submit', (event) => void submitEditor(event));
        byId('traffic-transform-manual-open')?.addEventListener('click', openManual);
        byId('traffic-transform-manual-close')?.addEventListener('click', closeManual);
        byId('traffic-transform-manual-cancel')?.addEventListener('click', closeManual);
        byId('traffic-transform-manual-form')?.addEventListener('submit', (event) => void submitManual(event));
        byId('traffic-transform-scope-close')?.addEventListener('click', closeScope);
        byId('traffic-transform-scope-cancel')?.addEventListener('click', closeScope);
        byId('traffic-transform-scope-form')?.addEventListener('submit', (event) => void submitScope(event));
        byId('traffic-transform-manual-direction')?.addEventListener('change', (event) => {
            const source = byId('traffic-transform-manual-source');
            if (!source) return;
            const oldDirection = event.target?.value === 'response' ? 'request' : 'response';
            if (source.value.trim() === minimalSource(oldDirection).trim()) source.value = minimalSource(event.target?.value || 'request');
        });
        byId('traffic-transform-source-detail')?.addEventListener('click', (event) => {
            if (event.target === byId('traffic-transform-source-detail')) closeSource();
        });
        byId('traffic-transform-editor')?.addEventListener('click', (event) => { if (event.target === byId('traffic-transform-editor')) closeEditor(); });
        byId('traffic-transform-manual')?.addEventListener('click', (event) => { if (event.target === byId('traffic-transform-manual')) closeManual(); });
        byId('traffic-transform-scope-editor')?.addEventListener('click', (event) => { if (event.target === byId('traffic-transform-scope-editor')) closeScope(); });
        root.document.addEventListener('keydown', (event) => { if (event.key === 'Escape') { closeSource(); closeEditor(); closeManual(); closeScope(); } });
    }

    function init() {
        bind();
        selectView(state.view);
        void load();
    }

    root.initTrafficTransformsPage = init;
    root.refreshTrafficTransformsPage = load;
}(typeof window !== 'undefined' ? window : globalThis));
