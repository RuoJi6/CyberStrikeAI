const asmPageState = {
    resources: [],
    providers: [],
    editId: '',
    loading: false,
    busyIds: new Set(),
    tasks: [],
    taskPage: 1,
    taskPageSize: 20,
    taskTotal: 0,
    loadingTasks: false,
    selectedTask: null,
    selectedAssetType: 'site',
    imageObjectUrls: [],
};

function asmT(key, fallback, options) {
    if (window.i18next && typeof window.i18next.t === 'function') {
        const value = window.i18next.t(key, options || {});
        if (value && value !== key) return value;
    }
    return fallback;
}

function asmEscape(value) {
    return String(value == null ? '' : value)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

async function asmApi(url, options) {
    const response = await apiFetch(url, options || {});
    let payload = {};
    try { payload = await response.json(); } catch (_) { payload = {}; }
    if (!response.ok) {
        throw new Error(payload.error || payload.message || `${asmT('asm.requestFailed', '请求失败')} (${response.status})`);
    }
    return payload;
}

function asmProviderById(id) {
    return asmPageState.providers.find(provider => provider.id === id) || null;
}

function asmProviderLabel(id) {
    const provider = asmProviderById(id);
    if (provider && provider.name) return provider.name;
    return { arl: 'ARL / 灯塔', xingrin: 'XingRin / 星环', scopesentry: 'ScopeSentry' }[id] || id;
}

function asmProviderMark(id) {
    return { arl: 'ARL', xingrin: 'XR', scopesentry: 'SS' }[id] || 'ASM';
}

function renderASMProviders() {
    const root = document.getElementById('asm-provider-strip');
    if (!root) return;
    const providers = asmPageState.providers.length ? asmPageState.providers : [
        { id: 'arl', name: 'ARL / 灯塔', implemented: false, capabilities: [] },
        { id: 'xingrin', name: 'XingRin / 星环', implemented: false, capabilities: [] },
        { id: 'scopesentry', name: 'ScopeSentry', implemented: false, capabilities: [] },
    ];
    root.innerHTML = providers.map(provider => {
        const ready = Boolean(provider.implemented);
        const state = ready ? asmT('asm.ready', '已接入') : asmT('asm.pending', '待接入');
        const capabilityCount = Array.isArray(provider.capabilities) ? provider.capabilities.length : 0;
        return `<div class="asm-provider-pill">
            <div class="asm-provider-pill-head"><strong>${asmEscape(provider.name)}</strong><span class="asm-provider-state${ready ? '' : ' pending'}">${asmEscape(state)}</span></div>
            <small>${ready ? asmEscape(asmT('asm.capabilityCount', `${capabilityCount} 项 MCP 能力`, { count: capabilityCount })) : asmEscape(asmT('asm.adapterPending', '适配器串行实现中'))}</small>
        </div>`;
    }).join('');
}

function formatASMTime(value) {
    if (!value) return asmT('asm.neverTested', '尚未测试');
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString();
}

function asmStatusLabel(status) {
    return {
        connected: asmT('asm.connected', '连接正常'),
        error: asmT('asm.connectionError', '连接失败'),
        testing: asmT('asm.testing', '测试中'),
        unknown: asmT('asm.unknown', '等待测试'),
    }[status] || status || asmT('asm.unknown', '等待测试');
}

function renderASMResources() {
    const grid = document.getElementById('asm-resource-grid');
    const summary = document.getElementById('asm-resource-summary');
    if (!grid) return;
    const items = asmPageState.resources;
    const connected = items.filter(item => item.status === 'connected').length;
    if (summary) {
        summary.textContent = asmT('asm.resourceSummary', `${items.length} 个连接 · ${connected} 个正常`, { total: items.length, connected });
    }
    if (!items.length) {
        grid.innerHTML = `<div class="asm-empty-state"><div class="asm-empty-state-content">
            <strong>${asmEscape(asmT('asm.emptyTitle', '还没有 ASM 连接'))}</strong>
            <span>${asmEscape(asmT('asm.emptyDesc', '添加第一个资源后，Agent 即可通过统一 MCP 使用它。'))}</span>
        </div></div>`;
        return;
    }
    grid.innerHTML = items.map(item => {
        const busy = asmPageState.busyIds.has(item.id);
        const status = busy ? 'testing' : (item.status || 'unknown');
        const enabledLabel = item.enabled ? asmT('asm.enabledShort', 'Agent 已启用') : asmT('asm.disabledShort', 'Agent 已停用');
        const testText = busy ? asmT('asm.testing', '测试中') : asmT('asm.test', '测试连接');
        const toggleText = item.enabled ? asmT('asm.disable', '停用') : asmT('asm.enable', '启用');
        return `<article class="asm-resource-card" data-asm-resource-id="${asmEscape(item.id)}">
            <div class="asm-card-head">
                <div class="asm-card-title-row">
                    <span class="asm-provider-mark">${asmEscape(asmProviderMark(item.provider))}</span>
                    <div class="asm-card-title"><strong title="${asmEscape(item.name)}">${asmEscape(item.name)}</strong><small>${asmEscape(asmProviderLabel(item.provider))}</small></div>
                </div>
                <span class="asm-enabled-badge${item.enabled ? '' : ' disabled'}">${asmEscape(enabledLabel)}</span>
            </div>
            <div class="asm-card-url" title="${asmEscape(item.base_url)}">${asmEscape(item.base_url)}</div>
            <div class="asm-card-status-row"><span class="asm-status-dot ${asmEscape(status)}"></span><strong>${asmEscape(asmStatusLabel(status))}</strong><span>·</span><span>${asmEscape(formatASMTime(item.last_test_at))}</span></div>
            ${item.last_error ? `<div class="asm-card-error" title="${asmEscape(item.last_error)}">${asmEscape(item.last_error)}</div>` : ''}
            <div class="asm-card-actions">
                <button type="button" class="btn-secondary" data-require-permission="mcp:write" data-asm-action="test" ${busy ? 'disabled' : ''}>${asmEscape(testText)}</button>
                <button type="button" class="btn-secondary" data-require-permission="mcp:write" data-asm-action="edit">${asmEscape(asmT('common.edit', '编辑'))}</button>
                <button type="button" class="btn-secondary" data-require-permission="mcp:write" data-asm-action="toggle">${asmEscape(toggleText)}</button>
                <button type="button" class="btn-secondary asm-delete-button" data-require-permission="mcp:write" data-asm-action="delete">${asmEscape(asmT('common.delete', '删除'))}</button>
            </div>
        </article>`;
    }).join('');
    if (typeof applyRBACToUI === 'function') applyRBACToUI(grid);
}

async function loadASMResources() {
    if (asmPageState.loading) return;
    asmPageState.loading = true;
    const grid = document.getElementById('asm-resource-grid');
    if (grid && !asmPageState.resources.length) {
        grid.innerHTML = `<div class="asm-empty-state"><span class="asm-spinner" aria-hidden="true"></span><span>${asmEscape(asmT('asm.loading', '正在加载连接…'))}</span></div>`;
    }
    try {
        const payload = await asmApi('/api/asm/resources');
        asmPageState.resources = Array.isArray(payload.resources) ? payload.resources : [];
        asmPageState.providers = Array.isArray(payload.providers) ? payload.providers : [];
        renderASMProviders();
        renderASMResources();
        syncASMProviderOptions();
        syncASMTaskProviderOptions();
    } catch (error) {
        if (grid) grid.innerHTML = `<div class="asm-empty-state"><div class="asm-empty-state-content"><strong>${asmEscape(asmT('asm.loadFailed', '加载失败'))}</strong><span>${asmEscape(error.message)}</span></div></div>`;
    } finally {
        asmPageState.loading = false;
    }
}

function syncASMProviderOptions() {
    const select = document.getElementById('asm-resource-provider');
    if (!select) return;
    Array.from(select.options).forEach(option => {
        const provider = asmProviderById(option.value);
        option.disabled = Boolean(provider && !provider.implemented);
        option.textContent = `${asmProviderLabel(option.value)}${provider && !provider.implemented ? ` · ${asmT('asm.pending', '待接入')}` : ''}`;
    });
    syncASMProviderForm();
}

function openASMResourceModal(id) {
    const item = id ? asmPageState.resources.find(resource => resource.id === id) : null;
    asmPageState.editId = item ? item.id : '';
    const title = document.getElementById('asm-resource-modal-title');
    const error = document.getElementById('asm-form-error');
    if (error) { error.hidden = true; error.textContent = ''; }
    document.getElementById('asm-resource-name').value = item ? item.name : '';
    document.getElementById('asm-resource-provider').value = item ? item.provider : 'arl';
    document.getElementById('asm-resource-url').value = item ? item.base_url : '';
    document.getElementById('asm-resource-auth-type').value = item ? item.auth_type : 'password';
    document.getElementById('asm-resource-username').value = item ? (item.username || '') : '';
    document.getElementById('asm-resource-credential').value = '';
    document.getElementById('asm-resource-verify-tls').checked = item ? Boolean(item.verify_tls) : true;
    document.getElementById('asm-resource-enabled').checked = item ? Boolean(item.enabled) : true;
    if (title) title.textContent = item ? asmT('asm.editResource', '编辑资源') : asmT('asm.addResource', '添加资源');
    const hint = document.getElementById('asm-credential-hint');
    if (hint) hint.textContent = item && item.has_credential
        ? asmT('asm.credentialEditHint', '留空将保留现有凭据；输入新值则安全替换。')
        : asmT('asm.credentialCreateHint', '凭据将使用 AES-GCM 加密保存，之后不会再次显示明文。');
    syncASMProviderOptions();
    syncASMAuthForm();
    if (typeof openAppModal === 'function') openAppModal('asm-resource-modal', { focusEl: document.getElementById('asm-resource-name') });
    else document.getElementById('asm-resource-modal').style.display = 'flex';
}

function closeASMResourceModal() {
    if (typeof closeAppModal === 'function') closeAppModal('asm-resource-modal');
    else document.getElementById('asm-resource-modal').style.display = 'none';
    asmPageState.editId = '';
}

function syncASMProviderForm() {
    const providerId = document.getElementById('asm-resource-provider')?.value || 'arl';
    const provider = asmProviderById(providerId);
    const hint = document.getElementById('asm-provider-form-hint');
    if (hint) hint.textContent = provider && !provider.implemented
        ? asmT('asm.providerNotReady', '该适配器尚未完成，当前不能保存。')
        : asmT('asm.providerReadyHint', '保存后可先测试连接，再由角色工具白名单授权给 Agent。');
}

function syncASMAuthForm() {
    const apiKey = document.getElementById('asm-resource-auth-type')?.value === 'api_key';
    const usernameGroup = document.getElementById('asm-username-group');
    const label = document.getElementById('asm-credential-label');
    if (usernameGroup) usernameGroup.hidden = apiKey;
    if (label) label.textContent = apiKey ? 'API Key' : asmT('asm.password', '密码');
}

function setASMFormError(message) {
    const node = document.getElementById('asm-form-error');
    if (!node) return;
    node.textContent = message || '';
    node.hidden = !message;
}

async function saveASMResource(event) {
    if (event) event.preventDefault();
    const button = document.getElementById('asm-save-button');
    const credential = document.getElementById('asm-resource-credential').value;
    const isEdit = Boolean(asmPageState.editId);
    if (!isEdit && !credential) {
        setASMFormError(asmT('asm.credentialRequired', '首次创建时必须填写凭据。'));
        return;
    }
    const payload = {
        name: document.getElementById('asm-resource-name').value.trim(),
        provider: document.getElementById('asm-resource-provider').value,
        base_url: document.getElementById('asm-resource-url').value.trim(),
        username: document.getElementById('asm-resource-username').value.trim(),
        auth_type: document.getElementById('asm-resource-auth-type').value,
        verify_tls: document.getElementById('asm-resource-verify-tls').checked,
        enabled: document.getElementById('asm-resource-enabled').checked,
    };
    if (credential) payload.credential = credential;
    setASMFormError('');
    if (button) button.disabled = true;
    try {
        const url = isEdit ? `/api/asm/resources/${encodeURIComponent(asmPageState.editId)}` : '/api/asm/resources';
        await asmApi(url, { method: isEdit ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        closeASMResourceModal();
        if (typeof showNotification === 'function') showNotification(asmT('asm.saved', 'ASM 资源已保存'), 'success');
        await loadASMResources();
    } catch (error) {
        setASMFormError(error.message);
    } finally {
        if (button) button.disabled = false;
    }
}

async function testASMResource(id) {
    if (asmPageState.busyIds.has(id)) return;
    asmPageState.busyIds.add(id);
    renderASMResources();
    try {
        await asmApi(`/api/asm/resources/${encodeURIComponent(id)}/test`, { method: 'POST' });
        if (typeof showNotification === 'function') showNotification(asmT('asm.testSuccess', 'ASM 连接成功'), 'success');
    } catch (error) {
        if (typeof showNotification === 'function') showNotification(error.message, 'error');
    } finally {
        asmPageState.busyIds.delete(id);
        await loadASMResources();
    }
}

async function toggleASMResource(id) {
    const item = asmPageState.resources.find(resource => resource.id === id);
    if (!item) return;
    try {
        await asmApi(`/api/asm/resources/${encodeURIComponent(id)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !item.enabled }) });
        await loadASMResources();
    } catch (error) {
        if (typeof showNotification === 'function') showNotification(error.message, 'error');
    }
}

async function deleteASMResource(id) {
    const item = asmPageState.resources.find(resource => resource.id === id);
    if (!item) return;
    const message = asmT('asm.deleteConfirm', `确认删除 ASM 资源“${item.name}”？加密凭据也会一并删除。`, { name: item.name });
    if (!window.confirm(message)) return;
    try {
        await asmApi(`/api/asm/resources/${encodeURIComponent(id)}`, { method: 'DELETE' });
        if (typeof showNotification === 'function') showNotification(asmT('asm.deleted', 'ASM 资源已删除'), 'success');
        await loadASMResources();
    } catch (error) {
        if (typeof showNotification === 'function') showNotification(error.message, 'error');
    }
}

function syncASMTaskProviderOptions() {
    const select = document.getElementById('asm-task-provider');
    if (!select) return;
    const selected = select.value;
    const providers = asmPageState.providers.length ? asmPageState.providers : [
        { id: 'arl', name: 'ARL / 灯塔' }, { id: 'xingrin', name: 'XingRin / 星环' }, { id: 'scopesentry', name: 'ScopeSentry' },
    ];
    select.innerHTML = `<option value="">全部 ASM</option>${providers.map(item => `<option value="${asmEscape(item.id)}">${asmEscape(item.name)}</option>`).join('')}`;
    select.value = selected;
}

function asmTaskStatusLabel(status) {
    return {
        submitted: '已提交', running: '运行中', completed: '已完成',
        failed: '失败', stopped: '已停止', unknown: '未知',
    }[status] || status || '未知';
}

function asmTaskStatusClass(status) {
    return ['submitted', 'running', 'completed', 'failed', 'stopped'].includes(status) ? status : 'unknown';
}

function asmTaskProgress(value) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return 0;
    return Math.max(0, Math.min(100, Math.round(parsed)));
}

function renderASMTasks() {
    const root = document.getElementById('asm-task-list');
    const summary = document.getElementById('asm-task-summary');
    const pagination = document.getElementById('asm-task-pagination');
    if (!root) return;
    if (summary) summary.textContent = `${asmPageState.taskTotal} 条历史任务 · MCP 下发后自动记录`;
    if (!asmPageState.tasks.length) {
        root.innerHTML = `<div class="asm-task-empty"><strong>暂无任务记录</strong><span>Agent 或 MCP 创建任务后会自动出现在这里。</span></div>`;
    } else {
        root.innerHTML = `<div class="asm-task-table-head"><span>任务 / 目标</span><span>ASM 资源</span><span>进度</span><span>创建时间</span><span></span></div>${asmPageState.tasks.map(task => {
            const progress = asmTaskProgress(task.progress);
            const status = asmTaskStatusClass(task.status);
            return `<article class="asm-task-row" onclick="openASMTaskModal('${asmEscape(task.id)}')">
                <div class="asm-task-primary"><strong>${asmEscape(task.name || `远程任务 ${task.remote_task_id}`)}</strong><span title="${asmEscape(task.target)}">${asmEscape(task.target || '未记录目标')}</span></div>
                <div class="asm-task-provider"><span class="asm-provider-mark small">${asmEscape(asmProviderMark(task.provider))}</span><span><strong>${asmEscape(task.resource_name)}</strong><small>${asmEscape(task.remote_task_id)}</small></span></div>
                <div class="asm-task-progress-cell"><div><span class="asm-task-status ${status}">${asmEscape(asmTaskStatusLabel(task.status))}</span><small>${asmEscape(task.stage || '')}</small></div><div class="asm-progress-track"><span style="width:${progress}%"></span></div><b>${progress}%</b></div>
                <time>${asmEscape(formatASMTime(task.created_at))}</time>
                <button type="button" class="btn-secondary btn-small" onclick="event.stopPropagation();openASMTaskModal('${asmEscape(task.id)}')">查看</button>
            </article>`;
        }).join('')}`;
    }
    const pages = Math.max(1, Math.ceil(asmPageState.taskTotal / asmPageState.taskPageSize));
    if (pagination) pagination.innerHTML = asmPageState.taskTotal > asmPageState.taskPageSize
        ? `<button type="button" class="btn-secondary btn-small" ${asmPageState.taskPage <= 1 ? 'disabled' : ''} onclick="changeASMTaskPage(-1)">上一页</button><span>${asmPageState.taskPage} / ${pages}</span><button type="button" class="btn-secondary btn-small" ${asmPageState.taskPage >= pages ? 'disabled' : ''} onclick="changeASMTaskPage(1)">下一页</button>` : '';
    if (typeof applyRBACToUI === 'function') applyRBACToUI(root);
}

async function loadASMTasks(resetPage) {
    if (asmPageState.loadingTasks) return;
    if (resetPage) asmPageState.taskPage = 1;
    asmPageState.loadingTasks = true;
    const root = document.getElementById('asm-task-list');
    if (root && !asmPageState.tasks.length) root.innerHTML = `<div class="asm-task-loading"><span class="asm-spinner"></span><span>正在加载任务…</span></div>`;
    const params = new URLSearchParams({ page: String(asmPageState.taskPage), page_size: String(asmPageState.taskPageSize) });
    const query = document.getElementById('asm-task-query')?.value.trim();
    const provider = document.getElementById('asm-task-provider')?.value;
    const status = document.getElementById('asm-task-status')?.value;
    if (query) params.set('query', query);
    if (provider) params.set('provider', provider);
    if (status) params.set('status', status);
    try {
        const payload = await asmApi(`/api/asm/tasks?${params.toString()}`);
        asmPageState.tasks = Array.isArray(payload.tasks) ? payload.tasks : [];
        asmPageState.taskTotal = Number(payload.total) || 0;
        asmPageState.taskPage = Number(payload.page) || 1;
        renderASMTasks();
    } catch (error) {
        if (root) root.innerHTML = `<div class="asm-task-empty error"><strong>任务加载失败</strong><span>${asmEscape(error.message)}</span></div>`;
    } finally {
        asmPageState.loadingTasks = false;
    }
}

function changeASMTaskPage(delta) {
    const pages = Math.max(1, Math.ceil(asmPageState.taskTotal / asmPageState.taskPageSize));
    asmPageState.taskPage = Math.max(1, Math.min(pages, asmPageState.taskPage + delta));
    void loadASMTasks(false);
}

function asmSummaryEntries(summary) {
    if (!summary || typeof summary !== 'object') return [];
    const result = [];
    Object.entries(summary).forEach(([key, value]) => {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            if (Number.isFinite(Number(value.total))) result.push([key, value.total]);
        } else if (['string', 'number', 'boolean'].includes(typeof value)) result.push([key, value]);
    });
    return result.slice(0, 6);
}

function renderASMTaskDetail() {
    const root = document.getElementById('asm-task-detail');
    const task = asmPageState.selectedTask;
    if (!root || !task) return;
    const progress = asmTaskProgress(task.progress);
    const summaries = asmSummaryEntries(task.summary);
    root.innerHTML = `<div class="asm-task-detail-hero">
        <div class="asm-task-detail-main"><div class="asm-task-detail-badges"><span class="asm-task-status ${asmTaskStatusClass(task.status)}">${asmEscape(asmTaskStatusLabel(task.status))}</span><span>${asmEscape(asmProviderLabel(task.provider))}</span><span>${asmEscape(task.resource_name)}</span></div><h4>${asmEscape(task.name || `远程任务 ${task.remote_task_id}`)}</h4><code>${asmEscape(task.target || '')}</code></div>
        <div class="asm-task-detail-progress"><strong>${progress}%</strong><span>${asmEscape(task.stage || '等待同步')}</span></div>
    </div>
    <div class="asm-detail-progress-track"><span style="width:${progress}%"></span></div>
    <div class="asm-task-meta-grid"><div><span>远程任务 ID</span><strong>${asmEscape(task.remote_task_id)}</strong></div><div><span>创建时间</span><strong>${asmEscape(formatASMTime(task.created_at))}</strong></div><div><span>最后同步</span><strong>${asmEscape(formatASMTime(task.last_synced_at))}</strong></div><div><span>本地记录 ID</span><strong>${asmEscape(task.id)}</strong></div></div>
    ${summaries.length ? `<div class="asm-summary-grid">${summaries.map(([key, value]) => `<div><strong>${asmEscape(value)}</strong><span>${asmEscape(key)}</span></div>`).join('')}</div>` : ''}
    ${task.last_error ? `<div class="asm-task-detail-error">${asmEscape(task.last_error)}</div>` : ''}`;
    const title = document.getElementById('asm-task-modal-title');
    if (title) title.textContent = task.name || 'ASM 任务详情';
}

function renderASMResultTabs() {
    const root = document.getElementById('asm-result-tabs');
    if (!root) return;
    const labels = { site: '站点', domain: '域名', ip: 'IP', url: 'URL', service: '服务', vulnerability: '漏洞' };
    root.innerHTML = Object.entries(labels).map(([id, label]) => `<button type="button" class="${asmPageState.selectedAssetType === id ? 'active' : ''}" onclick="selectASMResultType('${id}')">${label}</button>`).join('');
}

function asmFindResultRows(value, depth) {
    if (depth > 7 || value == null) return [];
    if (Array.isArray(value)) return value;
    if (typeof value !== 'object') return [];
    for (const key of ['items', 'results', 'list', 'assets', 'data']) {
        if (Object.prototype.hasOwnProperty.call(value, key)) {
            const rows = asmFindResultRows(value[key], depth + 1);
            if (rows.length) return rows;
        }
    }
    for (const child of Object.values(value)) {
        const rows = asmFindResultRows(child, depth + 1);
        if (rows.length) return rows;
    }
    return [];
}

function asmResultCell(value) {
    if (value == null) return '';
    if (typeof value === 'object') {
        const raw = JSON.stringify(value);
        return raw.length > 180 ? `${raw.slice(0, 177)}…` : raw;
    }
    const raw = String(value);
    return raw.length > 180 ? `${raw.slice(0, 177)}…` : raw;
}

function clearASMImageObjectURLs() {
    asmPageState.imageObjectUrls.forEach(value => URL.revokeObjectURL(value));
    asmPageState.imageObjectUrls = [];
}

async function hydrateASMScreenshotImages() {
    const nodes = Array.from(document.querySelectorAll('[data-asm-screenshot-url]'));
    await Promise.all(nodes.map(async node => {
        try {
            const response = await apiFetch(node.dataset.asmScreenshotUrl);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const blob = await response.blob();
            const objectURL = URL.createObjectURL(blob);
            asmPageState.imageObjectUrls.push(objectURL);
            const image = node.querySelector('img');
            if (image) image.src = objectURL;
            node.classList.add('loaded');
        } catch (_) {
            node.classList.add('failed');
            const label = node.querySelector('.asm-screenshot-loading');
            if (label) label.textContent = '图片加载失败';
        }
    }));
}

function renderASMScreenshots(screenshots) {
    if (!Array.isArray(screenshots) || !screenshots.length) return '';
    return `<section class="asm-screenshot-section"><div class="asm-result-section-title"><strong>本地截图</strong><span>${screenshots.length} 张 · 已存储在 CyberStrikeAI</span></div><div class="asm-screenshot-grid">${screenshots.map(item => `<figure data-asm-screenshot-url="${asmEscape(item.url)}"><div class="asm-screenshot-loading">正在安全加载…</div><img alt="${asmEscape(item.label || 'ASM 站点截图')}" loading="lazy"><figcaption><strong>${asmEscape(item.label || 'ASM 站点截图')}</strong><span>${asmEscape(item.content_type)} · ${Math.max(1, Math.round((Number(item.size_bytes) || 0) / 1024))} KiB</span></figcaption></figure>`).join('')}</div></section>`;
}

function asmFilterResultRows(rows, query) {
    const keyword = String(query || '').trim().toLocaleLowerCase();
    if (!keyword) return rows;
    return rows.filter(item => {
        try {
            return JSON.stringify(item).toLocaleLowerCase().includes(keyword);
        } catch (_) {
            return String(item).toLocaleLowerCase().includes(keyword);
        }
    });
}

function renderASMResults(payload, query) {
    const root = document.getElementById('asm-task-results');
    if (!root) return;
    clearASMImageObjectURLs();
    const allRows = asmFindResultRows(payload?.payload, 0).filter(item => item && typeof item === 'object');
    const rows = asmFilterResultRows(allRows, query);
    let body = '';
    if (rows.length) {
        const preferred = ['url', 'site', 'domain', 'ip', 'port', 'service', 'title', 'status', 'severity', 'name', 'fingerprints', 'technologies'];
        const available = Array.from(new Set(rows.slice(0, 5).flatMap(item => Object.keys(item))));
        const columns = [...preferred.filter(key => available.includes(key)), ...available.filter(key => !preferred.includes(key))].slice(0, 7);
        body = `<div class="asm-result-section-title"><strong>${asmEscape(asmPageState.selectedAssetType.toUpperCase())} 结果</strong><span>${rows.length} 条当前页记录${payload.stale ? ' · 离线快照' : ''}</span></div><div class="asm-result-table-wrap"><table><thead><tr>${columns.map(key => `<th>${asmEscape(key)}</th>`).join('')}</tr></thead><tbody>${rows.map(item => `<tr>${columns.map(key => `<td title="${asmEscape(asmResultCell(item[key]))}">${asmEscape(asmResultCell(item[key]))}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
    } else {
        const raw = JSON.stringify(payload?.payload || {}, null, 2);
        const emptyMessage = query ? `当前结果中没有匹配“${asmEscape(query)}”的记录。` : '任务可能仍在运行，或 ASM 未返回该类型资产。';
        body = `<div class="asm-result-empty"><strong>${query ? '未找到匹配结果' : '当前类型暂无结果'}</strong><span>${emptyMessage}</span>${!query && raw !== '{}' ? `<details><summary>查看原始响应</summary><pre>${asmEscape(raw)}</pre></details>` : ''}</div>`;
    }
    root.innerHTML = `${payload?.stale ? '<div class="asm-stale-banner">远程 ASM 当前不可用，正在显示 CyberStrikeAI 缓存的最后一次结果。</div>' : ''}${renderASMScreenshots(payload?.screenshots)}${body}`;
    void hydrateASMScreenshotImages();
}

async function loadSelectedASMResults() {
    const task = asmPageState.selectedTask;
    const root = document.getElementById('asm-task-results');
    if (!task || !root) return;
    root.innerHTML = `<div class="asm-task-loading"><span class="asm-spinner"></span><span>正在从 ${asmEscape(asmProviderLabel(task.provider))} 读取结果…</span></div>`;
    const params = new URLSearchParams({ asset_type: asmPageState.selectedAssetType, page: '1', page_size: '100' });
    const query = document.getElementById('asm-result-query')?.value.trim();
    try {
        renderASMResults(await asmApi(`/api/asm/tasks/${encodeURIComponent(task.id)}/results?${params.toString()}`), query);
    } catch (error) {
        root.innerHTML = `<div class="asm-result-empty error"><strong>结果读取失败</strong><span>${asmEscape(error.message)}</span></div>`;
    }
}

function selectASMResultType(type) {
    asmPageState.selectedAssetType = type;
    renderASMResultTabs();
    void loadSelectedASMResults();
}

async function openASMTaskModal(id) {
    const root = document.getElementById('asm-task-detail');
    asmPageState.selectedAssetType = 'site';
    if (root) root.innerHTML = `<div class="asm-task-loading"><span class="asm-spinner"></span><span>正在加载任务详情…</span></div>`;
    renderASMResultTabs();
    if (typeof openAppModal === 'function') openAppModal('asm-task-modal');
    else document.getElementById('asm-task-modal').style.display = 'flex';
    try {
        asmPageState.selectedTask = await asmApi(`/api/asm/tasks/${encodeURIComponent(id)}`);
        renderASMTaskDetail();
        await loadSelectedASMResults();
    } catch (error) {
        if (root) root.innerHTML = `<div class="asm-task-detail-error">${asmEscape(error.message)}</div>`;
    }
}

function closeASMTaskModal() {
    clearASMImageObjectURLs();
    asmPageState.selectedTask = null;
    if (typeof closeAppModal === 'function') closeAppModal('asm-task-modal');
    else document.getElementById('asm-task-modal').style.display = 'none';
}

async function syncSelectedASMTask() {
    const task = asmPageState.selectedTask;
    if (!task) return;
    try {
        asmPageState.selectedTask = await asmApi(`/api/asm/tasks/${encodeURIComponent(task.id)}/sync`, { method: 'POST' });
        renderASMTaskDetail();
        await Promise.all([loadASMTasks(false), loadSelectedASMResults()]);
        if (typeof showNotification === 'function') showNotification('ASM 任务进度已同步', 'success');
    } catch (error) {
        if (typeof showNotification === 'function') showNotification(error.message, 'error');
    }
}

async function syncSelectedASMScreenshots() {
    const task = asmPageState.selectedTask;
    if (!task) return;
    try {
        const result = await asmApi(`/api/asm/tasks/${encodeURIComponent(task.id)}/screenshots/sync`, { method: 'POST' });
        asmPageState.selectedTask = await asmApi(`/api/asm/tasks/${encodeURIComponent(task.id)}`);
        renderASMTaskDetail();
        await loadSelectedASMResults();
        const message = `截图同步完成：新增 ${result.downloaded || 0} 张，已缓存 ${result.screenshots?.length || 0} 张`;
        if (typeof showNotification === 'function') showNotification(message, result.errors?.length ? 'warning' : 'success');
    } catch (error) {
        if (typeof showNotification === 'function') showNotification(error.message, 'error');
    }
}

function handleASMGridClick(event) {
    const button = event.target.closest('[data-asm-action]');
    if (!button) return;
    const card = button.closest('[data-asm-resource-id]');
    const id = card?.dataset.asmResourceId;
    if (!id) return;
    const action = button.dataset.asmAction;
    if (action === 'test') void testASMResource(id);
    if (action === 'edit') openASMResourceModal(id);
    if (action === 'toggle') void toggleASMResource(id);
    if (action === 'delete') void deleteASMResource(id);
}

function initASMResourcesPage() {
    const grid = document.getElementById('asm-resource-grid');
    if (grid && !grid.dataset.bound) {
        grid.dataset.bound = 'true';
        grid.addEventListener('click', handleASMGridClick);
    }
    void Promise.all([loadASMResources(), loadASMTasks(true)]);
}

window.initASMResourcesPage = initASMResourcesPage;
window.loadASMResources = loadASMResources;
window.openASMResourceModal = openASMResourceModal;
window.closeASMResourceModal = closeASMResourceModal;
window.syncASMProviderForm = syncASMProviderForm;
window.syncASMAuthForm = syncASMAuthForm;
window.saveASMResource = saveASMResource;
window.loadASMTasks = loadASMTasks;
window.changeASMTaskPage = changeASMTaskPage;
window.openASMTaskModal = openASMTaskModal;
window.closeASMTaskModal = closeASMTaskModal;
window.syncSelectedASMTask = syncSelectedASMTask;
window.selectASMResultType = selectASMResultType;
window.loadSelectedASMResults = loadSelectedASMResults;
window.syncSelectedASMScreenshots = syncSelectedASMScreenshots;
