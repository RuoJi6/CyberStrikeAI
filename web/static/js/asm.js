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
    expandedBatches: new Set(),
    selectedTask: null,
    selectedAssetType: 'site',
    resultPage: 1,
    resultPageSize: 20,
    resultTotal: 0,
    imageObjectUrls: [],
    screenshotSyncing: false,
    screenshotMessage: '',
    resultRequestSeq: 0,
    lastResultPayload: null,
    lastResultQuery: '',
    resultSyncPolling: false,
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

const asmProviderLogoPaths = Object.freeze({
    arl: '/static/images/asm/arl.png',
    xingrin: '/static/images/asm/xingrin.png',
    scopesentry: '/static/images/asm/scopesentry.png',
});

function renderASMProviderMark(id, small) {
    const provider = String(id || '').toLowerCase();
    const logo = asmProviderLogoPaths[provider];
    const sizeClass = small ? ' small' : '';
    if (!logo) {
        return `<span class="asm-provider-mark${sizeClass}">${asmEscape(asmProviderMark(provider))}</span>`;
    }
    return `<span class="asm-provider-mark has-logo asm-provider-${asmEscape(provider)}${sizeClass}" aria-hidden="true"><img src="${logo}" alt="" decoding="async"></span>`;
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
                    ${renderASMProviderMark(item.provider, false)}
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
    refreshASMFormSelects();
}

function decorateASMFormSelect(select, kind) {
    if (!select) return;
    const wrapper = select.closest('.settings-custom-select');
    if (!wrapper) return;
    wrapper.classList.add('asm-form-select', `asm-form-select-${kind}`);
    const menu = wrapper.querySelector('.settings-custom-select-menu');
    if (menu) menu.classList.add('asm-form-select-menu', `asm-form-select-menu-${kind}`);
    if (kind === 'provider') wrapper.dataset.provider = select.value || 'arl';
}

function refreshASMFormSelects() {
    const form = document.getElementById('asm-resource-form');
    if (!form || typeof window.initSettingsCustomSelects !== 'function') return;
    window.initSettingsCustomSelects(form);
    if (typeof window.refreshSettingsCustomSelects === 'function') window.refreshSettingsCustomSelects();
    decorateASMFormSelect(document.getElementById('asm-resource-provider'), 'provider');
    decorateASMFormSelect(document.getElementById('asm-resource-auth-type'), 'auth');
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
    refreshASMFormSelects();
    if (typeof openAppModal === 'function') openAppModal('asm-resource-modal', { focusEl: document.getElementById('asm-resource-name') });
    else document.getElementById('asm-resource-modal').style.display = 'flex';
}

function closeASMResourceModal() {
    if (typeof window.closeAllSettingsCustomSelects === 'function') window.closeAllSettingsCustomSelects();
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
    const wrapper = document.getElementById('asm-resource-provider')?.closest('.settings-custom-select');
    if (wrapper) wrapper.dataset.provider = providerId;
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
    select.innerHTML = `<option value="">${asmEscape(asmT('asm.allProviders', '全部 ASM'))}</option>${providers.map(item => `<option value="${asmEscape(item.id)}">${asmEscape(item.name)}</option>`).join('')}`;
    select.value = selected;
}

function asmTaskStatusLabel(status) {
    return {
        submitted: asmT('asm.statusSubmitted', '已提交'),
        running: asmT('asm.statusRunning', '运行中'),
        completed: asmT('asm.statusCompleted', '已完成'),
        failed: asmT('asm.statusFailed', '失败'),
        stopped: asmT('asm.statusStopped', '已停止'),
        unknown: asmT('asm.statusUnknown', '未知'),
    }[status] || status || asmT('asm.statusUnknown', '未知');
}

function asmTaskStatusClass(status) {
    return ['submitted', 'running', 'completed', 'failed', 'stopped'].includes(status) ? status : 'unknown';
}

function asmResultSyncLabel(sync) {
    const status = sync?.status || 'pending';
    return {
        waiting: '等待扫描完成', pending: '等待同步结果', syncing: '同步结果中',
        completed: '结果已本地化', partial: '结果部分同步', failed: '结果同步失败',
    }[status] || status;
}

function asmResultSyncClass(sync) {
    const status = sync?.status || 'pending';
    return ['waiting', 'pending', 'syncing', 'completed', 'partial', 'failed'].includes(status) ? status : 'pending';
}

function asmResultSyncProgress(sync) {
    const total = Number(sync?.total_types) || 0;
    const completed = Number(sync?.completed_types) || 0;
    return total ? Math.max(0, Math.min(100, Math.round(completed * 100 / total))) : 0;
}

function asmTaskProgress(value) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return 0;
    return Math.max(0, Math.min(100, Math.round(parsed)));
}

function asmTaskGroups(tasks) {
    const groups = [];
    const byKey = new Map();
    (Array.isArray(tasks) ? tasks : []).forEach(task => {
        const batchSize = Math.max(1, Number(task.batch_size) || 1);
        const batchID = String(task.batch_id || '');
        const grouped = Boolean(batchID) && batchSize > 1;
        const key = grouped ? `batch:${batchID}` : `task:${task.id}`;
        let group = byKey.get(key);
        if (!group) {
            group = { key, batchID, grouped, expected: batchSize, tasks: [] };
            byKey.set(key, group);
            groups.push(group);
        }
        group.expected = Math.max(group.expected, batchSize);
        group.tasks.push(task);
    });
    groups.forEach(group => group.tasks.sort((left, right) => (Number(left.batch_index) || 0) - (Number(right.batch_index) || 0)));
    return groups;
}

function asmBatchState(group) {
    const expected = Math.max(group.expected, group.tasks.length);
    const completed = group.tasks.filter(task => task.status === 'completed').length;
    const stopped = group.tasks.filter(task => task.status === 'stopped').length;
    const failed = group.tasks.filter(task => task.status === 'failed').length;
    const progress = Math.round(group.tasks.reduce((total, task) => total + asmTaskProgress(task.progress), 0) / expected);
    let status = 'submitted';
    if (completed >= expected) status = 'completed';
    else if (failed > 0) status = 'failed';
    else if (group.tasks.some(task => task.status === 'running') || completed > 0) status = 'running';
    else if (stopped >= expected) status = 'stopped';
    return { expected, completed, progress, status };
}

function renderASMTaskRow(task, child) {
    const progress = asmTaskProgress(task.progress);
    const status = asmTaskStatusClass(task.status);
    return `<article class="asm-task-row${child ? ' asm-task-child' : ''}" onclick="openASMTaskModal('${asmEscape(task.id)}')">
        <div class="asm-task-primary"><strong>${asmEscape(task.name || `远程任务 ${task.remote_task_id}`)}</strong><span title="${asmEscape(task.target)}">${asmEscape(task.target || '未记录目标')}</span></div>
        <div class="asm-task-provider">${renderASMProviderMark(task.provider, true)}<span><strong>${asmEscape(task.resource_name)}</strong><small>${asmEscape(task.remote_task_id)}</small><em class="asm-result-sync-badge ${asmResultSyncClass(task.result_sync)}">${asmEscape(asmResultSyncLabel(task.result_sync))}</em></span></div>
        <div class="asm-task-progress-cell"><div><span class="asm-task-status ${status}">${asmEscape(asmTaskStatusLabel(task.status))}</span><small>${asmEscape(task.stage || '')}</small></div><div class="asm-progress-track"><span style="width:${progress}%"></span></div><b>${progress}%</b></div>
        <time>${asmEscape(formatASMTime(task.created_at))}</time>
        <button type="button" class="btn-secondary btn-small" onclick="event.stopPropagation();openASMTaskModal('${asmEscape(task.id)}')">查看</button>
    </article>`;
}

function renderASMBatch(group) {
    const first = group.tasks[0];
    const state = asmBatchState(group);
    const expanded = asmPageState.expandedBatches.has(group.batchID);
    const targets = [...new Set(group.tasks.map(task => String(task.target || '').trim()).filter(Boolean))];
    const targetLabel = targets.join(' · ') || `${state.expected} 个目标`;
    const status = asmTaskStatusClass(state.status);
    const children = expanded ? group.tasks.map(task => renderASMTaskRow(task, true)).join('') : '';
    return `<section class="asm-task-batch${expanded ? ' expanded' : ''}" data-batch-id="${asmEscape(group.batchID)}">
        <article class="asm-task-row asm-task-batch-row" onclick="toggleASMBatch('${asmEscape(group.batchID)}')">
            <div class="asm-task-primary"><strong>${asmEscape(first.name || '批量扫描')}</strong><span title="${asmEscape(targetLabel)}">${state.expected} 个目标 · ${asmEscape(targetLabel)}</span></div>
            <div class="asm-task-provider">${renderASMProviderMark(first.provider, true)}<span><strong>${asmEscape(first.resource_name)}</strong><small>${asmEscape(group.batchID)}</small><em class="asm-result-sync-badge completed">同次 MCP 下发</em></span></div>
            <div class="asm-task-progress-cell"><div><span class="asm-task-status ${status}">${asmEscape(asmTaskStatusLabel(state.status))}</span><small>${state.completed}/${state.expected} 个子任务完成</small></div><div class="asm-progress-track"><span style="width:${state.progress}%"></span></div><b>${state.progress}%</b></div>
            <time>${asmEscape(formatASMTime(first.created_at))}</time>
            <button type="button" class="btn-secondary btn-small" aria-expanded="${expanded}" onclick="event.stopPropagation();toggleASMBatch('${asmEscape(group.batchID)}')">${expanded ? '收起' : '展开'} ${expanded ? '↑' : '↓'}</button>
        </article>${children}
    </section>`;
}

function toggleASMBatch(batchID) {
    if (asmPageState.expandedBatches.has(batchID)) asmPageState.expandedBatches.delete(batchID);
    else asmPageState.expandedBatches.add(batchID);
    renderASMTasks();
}

function renderASMTasks() {
    const root = document.getElementById('asm-task-list');
    const summary = document.getElementById('asm-task-summary');
    const pagination = document.getElementById('asm-task-pagination');
    if (!root) return;
    if (summary) summary.textContent = `${asmPageState.taskTotal} 条历史子任务 · MCP 下发后自动记录`;
    if (!asmPageState.tasks.length) {
        root.innerHTML = `<div class="asm-task-empty"><strong>暂无任务记录</strong><span>Agent 或 MCP 创建任务后会自动出现在这里。</span></div>`;
    } else {
        const groups = asmTaskGroups(asmPageState.tasks);
        root.innerHTML = `<div class="asm-task-table-head"><span>任务 / 目标</span><span>ASM 资源</span><span>进度</span><span>创建时间</span><span></span></div>${groups.map(group => group.grouped ? renderASMBatch(group) : renderASMTaskRow(group.tasks[0], false)).join('')}`;
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
    const resultSync = task.result_sync || {};
    const syncProgress = asmResultSyncProgress(resultSync);
    root.innerHTML = `<div class="asm-task-detail-hero">
        <div class="asm-task-detail-main"><div class="asm-task-detail-badges"><span class="asm-task-status ${asmTaskStatusClass(task.status)}">${asmEscape(asmTaskStatusLabel(task.status))}</span><span>${asmEscape(asmProviderLabel(task.provider))}</span><span>${asmEscape(task.resource_name)}</span></div><h4>${asmEscape(task.name || `远程任务 ${task.remote_task_id}`)}</h4><code>${asmEscape(task.target || '')}</code></div>
        <div class="asm-task-detail-progress"><strong>${progress}%</strong><span>${asmEscape(task.stage || '等待同步')}</span></div>
    </div>
    <div class="asm-detail-progress-track"><span style="width:${progress}%"></span></div>
    <div class="asm-task-meta-grid"><div><span>远程任务 ID</span><strong>${asmEscape(task.remote_task_id)}</strong></div><div><span>创建时间</span><strong>${asmEscape(formatASMTime(task.created_at))}</strong></div><div><span>最后同步</span><strong>${asmEscape(formatASMTime(task.last_synced_at))}</strong></div><div><span>本地记录 ID</span><strong>${asmEscape(task.id)}</strong></div></div>
    <section class="asm-result-sync-panel ${asmResultSyncClass(resultSync)}"><div><span class="asm-result-sync-badge ${asmResultSyncClass(resultSync)}">${asmEscape(asmResultSyncLabel(resultSync))}</span><strong>${Number(resultSync.completed_types) || 0} / ${Number(resultSync.total_types) || 0} 类型</strong><small>${Number(resultSync.item_count) || 0} 条本地结果${resultSync.current_type ? ` · 正在同步 ${asmEscape(resultSync.current_type)}` : ''}${resultSync.synced_at ? ` · ${asmEscape(formatASMTime(resultSync.synced_at))}` : ''}</small></div><div class="asm-result-sync-track"><span style="width:${syncProgress}%"></span></div>${resultSync.last_error ? `<p>${asmEscape(resultSync.last_error)}</p>` : ''}</section>
    ${summaries.length ? `<div class="asm-summary-grid">${summaries.map(([key, value]) => `<div><strong>${asmEscape(value)}</strong><span>${asmEscape(key)}</span></div>`).join('')}</div>` : ''}
    ${task.last_error ? `<div class="asm-task-detail-error">${asmEscape(task.last_error)}</div>` : ''}`;
    const title = document.getElementById('asm-task-modal-title');
    if (title) title.textContent = task.name || 'ASM 任务详情';
}

function renderASMResultTabs() {
    const root = document.getElementById('asm-result-tabs');
    if (!root) return;
    const screenshotCount = asmPageState.selectedTask?.screenshots?.length || 0;
    root.innerHTML = asmTaskResultTypes().map(item => `<button type="button" class="${asmPageState.selectedAssetType === item.id ? 'active' : ''}" onclick="selectASMResultType('${asmEscape(item.id)}')">${asmEscape(item.label)}${item.local && screenshotCount ? `<b>${screenshotCount}</b>` : ''}</button>`).join('');
}

function asmTaskResultTypes() {
    const values = Array.isArray(asmPageState.selectedTask?.result_types) ? asmPageState.selectedTask.result_types : [];
    const result = values.filter(item => item && /^[a-z0-9_]+$/.test(String(item.id || '')) && item.label);
    const fallback = [
        { id: 'site', label: '站点', default: true }, { id: 'domain', label: '域名' },
        { id: 'ip', label: 'IP' }, { id: 'url', label: 'URL' },
        { id: 'service', label: '服务' }, { id: 'vulnerability', label: '漏洞' },
    ];
    const items = result.length ? result.slice() : fallback;
    items.push({ id: 'screenshots', label: '已缓存截图', local: true });
    return items;
}

function asmSelectedResultType() {
    return asmTaskResultTypes().find(item => item.id === asmPageState.selectedAssetType) || { id: asmPageState.selectedAssetType, label: asmPageState.selectedAssetType };
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

const asmResultLabels = Object.freeze({
    site: '站点', url: 'URL', domain: '域名', host: '主机', ip: 'IP', port: '端口',
    service: '服务', service_name: '服务', title: '标题', status: '状态', status_code: '状态码',
    statusCode: '状态码', content_length: '内容长度', contentLength: '内容长度', content_type: '内容类型',
    webserver: 'Web Server', webServer: 'Web Server', products: '产品 / 指纹', tech: '技术栈', finger: '指纹',
    vulnerability: '漏洞名称', vul_name: '漏洞名称', vuln_name: '漏洞名称', vulName: '漏洞名称',
    vuln_type: '漏洞类型', vulnType: '漏洞类型', severity: '严重级别', level: '严重级别',
    target: '目标', matched: '匹配位置', source: '来源', template_id: '模板 ID', 'template-id': '模板 ID',
    cvss_score: 'CVSS', cvssScore: 'CVSS', request: '请求', response: '响应', req: '请求', res: '响应',
    raw_output: '扫描器原始结果', rawOutput: '扫描器原始结果', description: '描述', tags: '标签',
    time: '发现时间', created_at: '创建时间', createdAt: '创建时间', save_date: '保存时间',
    screenshot: '上游截图', screenshot_path: '上游截图', headers: '响应头', responseHeaders: '响应头',
    banner: 'Banner', metadata: '元数据', record: '记录值', type: '类型', name: '名称', value: '值',
    ports: '端口', hosts: '关联主机', os_info: '操作系统', geo_asn: 'ASN', geo_city: '地理位置',
    subject: '证书主题', issuer: '签发者', not_before: '生效时间', not_after: '过期时间',
    input: '输入', output: '输出', method: '方法', length: '长度', match: '匹配内容', color: '规则颜色',
    content: '内容', record_type: '记录类型', cidr_ip: 'C 段', ip_count: 'IP 数', domain_count: '域名数',
    cnt: '数量', project: '项目', taskName: '任务', rootDomain: '根域名', gfPatterns: 'GF 模式',
});

function asmPathValue(value, path) {
    return String(path || '').split('.').reduce((current, key) => current && typeof current === 'object' ? current[key] : undefined, value);
}

function asmFirstValue(row, keys) {
    for (const key of keys || []) {
        const value = asmPathValue(row, key);
        if (value !== undefined && value !== null && value !== '' && !(Array.isArray(value) && !value.length)) return value;
    }
    return '';
}

function asmTextValue(value) {
    if (value == null) return '';
    if (Array.isArray(value)) return value.map(asmTextValue).filter(Boolean).join(', ');
    if (typeof value === 'object') {
        for (const key of ['name', 'title', 'value', 'url', 'host', 'ip']) {
            if (value[key] != null && value[key] !== '') return String(value[key]);
        }
        return JSON.stringify(value);
    }
    return String(value);
}

function asmLooksLikeURL(value) {
    return /^https?:\/\//i.test(String(value || ''));
}

function asmValueHTML(value) {
    const text = asmTextValue(value);
    if (asmLooksLikeURL(text)) return `<a href="${asmEscape(text)}" target="_blank" rel="noopener noreferrer">${asmEscape(text)}</a>`;
    return asmEscape(text);
}

function asmSeverity(value) {
    const level = String(value || '').toLowerCase();
    if (['critical', '严重', '危急'].includes(level)) return { key: 'critical', label: '严重' };
    if (['high', '高危', 'high-risk'].includes(level)) return { key: 'high', label: '高危' };
    if (['medium', '中危', 'moderate'].includes(level)) return { key: 'medium', label: '中危' };
    if (['low', '低危'].includes(level)) return { key: 'low', label: '低危' };
    if (['info', 'informational', '信息'].includes(level)) return { key: 'info', label: '信息' };
    return value ? { key: 'unknown', label: String(value) } : null;
}

function asmResultSchema(provider, type) {
    const common = {
        site: { title: ['url', 'site', 'domain'], subtitle: ['title'], facts: [['状态码', 'status', 'status_code', 'statusCode'], ['IP', 'ip'], ['端口', 'port'], ['服务', 'service', 'webserver', 'webServer'], ['技术 / 指纹', 'products', 'tech', 'finger']] },
        domain: { title: ['domain', 'host', 'name'], subtitle: ['rootDomain'], facts: [['类型', 'type'], ['记录值', 'record', 'value'], ['IP', 'ips', 'ip'], ['时间', 'time', 'created_at', 'createdAt']] },
        ip: { title: ['ip', 'host'], subtitle: ['domain'], facts: [['端口', 'port', 'ports'], ['服务', 'service'], ['关联主机', 'hosts', 'domain'], ['产品 / 指纹', 'products'], ['时间', 'time', 'created_at', 'createdAt']] },
        service: { title: ['service_name', 'service', 'ip'], subtitle: ['ip', 'domain'], facts: [['端口', 'port', 'ports'], ['产品', 'product', 'products'], ['版本', 'version'], ['Web Server', 'webServer', 'webserver']] },
        url: { title: ['url', 'output', 'site'], subtitle: ['title', 'source'], facts: [['状态码', 'status', 'status_code', 'statusCode'], ['类型', 'type', 'content_type', 'contentType'], ['长度', 'length', 'content_length', 'contentLength'], ['来源', 'source'], ['时间', 'time', 'created_at', 'createdAt']] },
        directory: { title: ['url'], subtitle: ['msg'], facts: [['状态码', 'status', 'status_code'], ['长度', 'length', 'content_length'], ['类型', 'content_type'], ['单词 / 行', 'words', 'lines'], ['耗时', 'duration']] },
        crawler: { title: ['url'], subtitle: ['method'], facts: [['方法', 'method'], ['请求体', 'body'], ['时间', 'time'], ['标签', 'tags']] },
        sensitive: { title: ['url'], subtitle: ['name'], facts: [['规则', 'name'], ['匹配内容', 'match'], ['状态', 'status'], ['时间', 'time'], ['标签', 'tags']] },
        takeover: { title: ['host', 'input', 'domain'], subtitle: ['value'], facts: [['CNAME', 'type', 'cname'], ['记录值', 'value'], ['响应', 'response'], ['标签', 'tags']] },
        screenshot: { title: ['url'], subtitle: ['status_code'], facts: [['状态码', 'status_code'], ['创建时间', 'created_at'], ['更新时间', 'updated_at']] },
        vulnerability: { title: ['vulnerability', 'vul_name', 'vuln_name', 'vulName', 'vuln_type', 'vulnType', 'raw_output.info.name', 'rawOutput.info.name', 'template_id'], subtitle: ['url', 'target', 'matched'], facts: [['严重级别', 'severity', 'level', 'vuln_severity'], ['来源', 'source', 'plg_type'], ['模板 / 插件', 'template_id', 'vulnid', 'app_name'], ['CVSS', 'cvss_score', 'cvssScore'], ['发现时间', 'time', 'save_date', 'created_at', 'createdAt']] },
        nuclei_result: { title: ['vuln_name', 'template_id'], subtitle: ['vuln_url', 'target'], facts: [['严重级别', 'vuln_severity'], ['模板 ID', 'template_id'], ['时间', 'save_date']] },
        cert: { title: ['subject', 'cert.subject', 'ip'], subtitle: ['issuer', 'cert.issuer'], facts: [['IP', 'ip'], ['端口', 'port'], ['生效时间', 'not_before', 'cert.not_before'], ['过期时间', 'not_after', 'cert.not_after'], ['DNS 名称', 'dns_names', 'cert.dns_names']] },
        fileleak: { title: ['url'], subtitle: ['title'], facts: [['状态码', 'status_code'], ['内容长度', 'content_length'], ['时间', 'save_date']] },
        npoc_service: { title: ['target', 'host'], subtitle: ['scheme'], facts: [['协议', 'scheme'], ['主机', 'host'], ['端口', 'port'], ['时间', 'save_date']] },
        cip: { title: ['cidr_ip'], subtitle: ['domain'], facts: [['IP 数', 'ip_count'], ['域名数', 'domain_count'], ['时间', 'save_date']] },
        stat_finger: { title: ['name'], subtitle: ['type'], facts: [['数量', 'cnt', 'count']] },
        wih: { title: ['site', 'content'], subtitle: ['source'], facts: [['记录类型', 'record_type'], ['内容', 'content'], ['来源', 'source']] },
    };
    const schema = common[type] || { title: ['name', 'title', 'url', 'site', 'domain', 'ip', 'id'], subtitle: ['description'], facts: [] };
    if (provider === 'arl' && type === 'ip') schema.facts = [['端口信息', 'port_info'], ['操作系统', 'os_info'], ['ASN', 'geo_asn'], ['地理位置', 'geo_city']];
    if (provider === 'xingrin' && ['ip', 'service'].includes(type)) schema.facts = [['端口', 'ports'], ['关联主机', 'hosts'], ['时间', 'created_at', 'createdAt']];
    return schema;
}

function asmResultTitle(row, schema, index) {
    return asmFirstValue(row, schema.title) || `结果 ${index + 1}`;
}

const asmHeavyResultFields = new Set([
    'headers', 'responseHeaders', 'banner', 'metadata', 'body', 'response_body', 'responseBody',
    'request', 'response', 'req', 'res', 'raw_output', 'rawOutput', 'verify_data', 'verifyData',
]);

const asmSecondaryResultFields = new Set([
    '_id', 'id', 'task_id', 'taskId', 'hash', 'favicon', 'screenshot', 'screenshot_path',
    'created_at', 'createdAt', 'updated_at', 'updatedAt',
]);

function asmPrettyValue(value) {
    if (value == null) return '';
    return typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
}

function asmTagValues(value) {
    const result = [];
    const append = item => {
        if (item == null || item === '') return;
        if (Array.isArray(item)) {
            item.forEach(append);
            return;
        }
        if (typeof item === 'object') {
            const label = asmFirstValue(item, ['name', 'title', 'product', 'value', 'finger', 'tech', 'service']);
            if (label !== '') result.push(asmTextValue(label));
            else Object.values(item).forEach(append);
            return;
        }
        result.push(String(item));
    };
    append(value);
    return [...new Set(result.filter(Boolean))];
}

function asmRenderResultChips(values) {
    const items = asmTagValues(values);
    if (!items.length) return '';
    return `<div class="asm-result-chips">${items.map(item => `<span>${asmEscape(item)}</span>`).join('')}</div>`;
}

function asmRenderDirectFields(row, excluded) {
    const hidden = new Set([...(excluded || []), ...asmHeavyResultFields, ...asmSecondaryResultFields]);
    const fields = Object.entries(row).filter(([key, value]) => {
        if (hidden.has(key) || value == null || value === '') return false;
        if (Array.isArray(value) && !value.length) return false;
        if (typeof value === 'object' && !Array.isArray(value) && !Object.keys(value).length) return false;
        return true;
    });
    if (!fields.length) return '';
    return `<div class="asm-result-all-fields">${fields.map(([key, value]) => `<div><span>${asmEscape(asmResultLabels[key] || key)}</span><strong>${asmValueHTML(value)}</strong></div>`).join('')}</div>`;
}

function asmRenderEvidence(row, keys) {
    const sections = (keys || []).filter(key => row[key] != null && row[key] !== '').map(key => {
        const value = asmPrettyValue(row[key]);
        if (!value || value === '{}' || value === '[]') return '';
        return `<section class="asm-result-evidence"><h6>${asmEscape(asmResultLabels[key] || key)}</h6><pre>${asmEscape(value)}</pre></section>`;
    }).filter(Boolean);
    return sections.length ? `<div class="asm-result-evidence-grid">${sections.join('')}</div>` : '';
}

function asmNormalizedAssetKey(value) {
    const text = String(value || '').trim();
    if (!text) return '';
    try {
        const parsed = new URL(text);
        parsed.hash = '';
        const path = parsed.pathname === '/' ? '' : parsed.pathname.replace(/\/$/, '');
        return `${parsed.protocol.toLowerCase()}//${parsed.host.toLowerCase()}${path}${parsed.search}`;
    } catch (_) {
        return text.toLocaleLowerCase().replace(/\/$/, '');
    }
}

function asmScreenshotsForRow(row, screenshots) {
    if (!Array.isArray(screenshots) || !screenshots.length) return [];
    const candidates = ['url', 'site', 'output', 'target', 'host', 'domain', 'ip']
        .map(key => asmNormalizedAssetKey(row[key])).filter(Boolean);
    if (!candidates.length) return [];
    return screenshots.filter(item => {
        const label = asmNormalizedAssetKey(item?.label);
        if (!label) return false;
        return candidates.some(candidate => candidate === label);
    });
}

function asmRenderScreenshotFigure(item, compact) {
    const label = item?.label || 'ASM 站点截图';
    return `<figure class="${compact ? 'asm-record-screenshot' : ''}" data-asm-screenshot-url="${asmEscape(item.url)}"><div class="asm-screenshot-loading">正在安全加载…</div><img alt="${asmEscape(label)}" loading="lazy"><figcaption><strong>${asmEscape(label)}</strong><span>${asmEscape(item.content_type)} · ${Math.max(1, Math.round((Number(item.size_bytes) || 0) / 1024))} KiB</span></figcaption></figure>`;
}

function asmArrayValue(value) {
    if (Array.isArray(value)) return value;
    if (value && typeof value === 'object') {
        if (['port_id', 'port', 'number'].some(key => value[key] !== undefined && value[key] !== null)) {
            return [value];
        }
        return Object.values(value);
    }
    if (typeof value === 'string') {
        try {
            const parsed = JSON.parse(value);
            return asmArrayValue(parsed);
        } catch (_) {
            return [];
        }
    }
    return [];
}

function asmRenderARLPorts(value) {
    const ports = asmArrayValue(value).filter(item => item && typeof item === 'object');
    if (!ports.length) return '<div class="asm-arl-port-empty">上游未返回端口信息</div>';
    return `<section class="asm-record-section asm-arl-port-section"><div class="asm-record-section-head"><h6>端口与服务</h6><span>${ports.length} 个开放端口</span></div><div class="asm-arl-port-grid">${ports.map(item => {
        const port = asmFirstValue(item, ['port_id', 'port', 'number']);
        const protocol = asmFirstValue(item, ['protocol', 'proto']) || 'tcp';
        const service = asmFirstValue(item, ['service_name', 'service']);
        const product = asmFirstValue(item, ['product']);
        const version = asmFirstValue(item, ['version']);
        const productLine = [asmTextValue(product), asmTextValue(version)].filter(Boolean).join(' ');
        return `<div class="asm-arl-port-item"><div class="asm-arl-port-number"><strong>${asmEscape(port || '未知')}</strong><span>/${asmEscape(protocol)}</span></div><div class="asm-arl-port-service">${service ? `<b>${asmEscape(service)}</b>` : '<b>未识别服务</b>'}${productLine ? `<span>${asmEscape(productLine)}</span>` : '<span>暂无产品与版本信息</span>'}</div></div>`;
    }).join('')}</div></section>`;
}

function asmRenderARLIPRecord(row, index) {
    const ip = asmFirstValue(row, ['ip', 'host']) || `IP 结果 ${index + 1}`;
    const os = asmTextValue(asmFirstValue(row, ['os_info']));
    const asn = row.geo_asn && typeof row.geo_asn === 'object' ? row.geo_asn : {};
    const asnNumber = asmFirstValue(asn, ['number', 'asn']);
    const asnOrganization = asmFirstValue(asn, ['organization', 'org', 'name']);
    const asnPrimary = asnNumber !== '' ? `AS${String(asnNumber).replace(/^AS/i, '')}` : '';
    const geo = row.geo_city && typeof row.geo_city === 'object' ? row.geo_city : {};
    const geoParts = [asmFirstValue(geo, ['city']), asmFirstValue(geo, ['region_name', 'region']), asmFirstValue(geo, ['country_name', 'country'])].map(asmTextValue).filter(Boolean);
    const countryCode = asmTextValue(asmFirstValue(geo, ['country_code']));
    const coordinates = [asmFirstValue(geo, ['latitude']), asmFirstValue(geo, ['longitude'])].filter(value => value !== '').map(asmTextValue).join(', ');
    const overview = [
        ['操作系统', os, ''],
        ['ASN', asnPrimary || asmTextValue(asnOrganization), asnPrimary && asnOrganization ? asmTextValue(asnOrganization) : ''],
        ['地理位置', geoParts.join(' · ') || countryCode, countryCode && geoParts.length ? countryCode : ''],
        ['经纬度', coordinates, ''],
    ].filter(([, primary]) => primary);
    const used = ['ip', 'host', 'port_info', 'os_info', 'geo_asn', 'geo_city'];
    return `<article class="asm-result-card asm-arl-ip-record">
        <header><div class="asm-result-index">${index + 1}</div><div class="asm-result-card-title"><h5>${asmEscape(ip)}</h5><p>ARL IP 资产详情</p></div><div class="asm-result-card-badges"><span class="asm-result-status">${asmArrayValue(row.port_info).length} 端口</span></div></header>
        ${overview.length ? `<div class="asm-arl-ip-overview">${overview.map(([label, primary, secondary]) => `<div><span>${asmEscape(label)}</span><strong>${asmEscape(primary)}</strong>${secondary ? `<small>${asmEscape(secondary)}</small>` : ''}</div>`).join('')}</div>` : ''}
        ${asmRenderARLPorts(row.port_info)}
        ${asmRenderDirectFields(row, used)}
        <details class="asm-result-detail"><summary>查看上游原始字段</summary><dl>${asmRenderResultDetails(row)}</dl></details>
    </article>`;
}

function asmRenderSiteRecord(row, index, screenshots) {
    const schema = asmResultSchema(asmPageState.selectedTask?.provider || '', 'site');
    const title = asmResultTitle(row, schema, index);
    const subtitle = asmFirstValue(row, ['title']);
    const status = asmFirstValue(row, ['status_code', 'statusCode', 'status']);
    const facts = [
        ['IP', asmFirstValue(row, ['ip', 'host'])], ['端口', asmFirstValue(row, ['port'])],
        ['服务 / Web Server', asmFirstValue(row, ['service', 'webserver', 'webServer'])],
        ['内容类型', asmFirstValue(row, ['content_type', 'contentType'])],
        ['内容长度', asmFirstValue(row, ['content_length', 'contentLength', 'body_length'])],
        ['发现时间', asmFirstValue(row, ['time', 'save_date', 'created_at', 'createdAt'])],
    ].filter(([, value]) => value !== '');
    const finger = asmFirstValue(row, ['finger', 'products', 'tech', 'fingerprints']);
    const matchedScreenshots = asmScreenshotsForRow(row, screenshots);
    const media = matchedScreenshots.length
        ? matchedScreenshots.map(item => asmRenderScreenshotFigure(item, true)).join('')
        : `<div class="asm-record-screenshot-placeholder"><span>站点截图</span><strong>${asmPageState.screenshotSyncing ? '正在自动缓存…' : '上游未返回可关联截图'}</strong></div>`;
    const used = ['url', 'site', 'domain', 'title', 'status', 'status_code', 'statusCode', 'ip', 'host', 'port', 'service', 'webserver', 'webServer', 'content_type', 'contentType', 'content_length', 'contentLength', 'body_length', 'time', 'save_date', 'finger', 'products', 'tech', 'fingerprints'];
    return `<article class="asm-result-card asm-site-record">
        <header><div class="asm-result-index">${index + 1}</div><div class="asm-result-card-title"><h5>${asmValueHTML(title)}</h5>${subtitle ? `<p>${asmValueHTML(subtitle)}</p>` : ''}</div><div class="asm-result-card-badges">${status !== '' ? `<span class="asm-result-status">HTTP ${asmEscape(status)}</span>` : ''}</div></header>
        <div class="asm-site-record-layout"><div class="asm-site-record-data">
            ${facts.length ? `<div class="asm-result-facts">${facts.map(([label, value]) => `<div><span>${asmEscape(label)}</span><strong>${asmValueHTML(value)}</strong></div>`).join('')}</div>` : ''}
            ${finger !== '' ? `<section class="asm-record-section"><h6>指纹 / 技术栈</h6>${asmRenderResultChips(finger)}</section>` : ''}
            ${asmRenderDirectFields(row, used)}
            ${asmRenderEvidence(row, ['headers', 'responseHeaders', 'banner', 'metadata', 'body', 'response_body', 'responseBody'])}
        </div><aside class="asm-site-record-media">${media}</aside></div>
        <details class="asm-result-detail"><summary>查看上游原始字段</summary><dl>${asmRenderResultDetails(row)}</dl></details>
    </article>`;
}

function asmRenderResultDetails(row) {
    return Object.entries(row).map(([key, value]) => {
        const label = asmResultLabels[key] || key;
        const raw = asmTextValue(value);
        const complex = value && typeof value === 'object' || raw.length > 240 || ['request', 'response', 'req', 'res', 'raw_output', 'rawOutput', 'headers', 'responseHeaders', 'body', 'banner', 'metadata'].includes(key);
        return `<div class="asm-result-detail-field ${complex ? 'wide' : ''}"><dt>${asmEscape(label)}</dt><dd>${complex ? `<pre>${asmEscape(typeof value === 'object' ? JSON.stringify(value, null, 2) : raw)}</pre>` : asmValueHTML(value)}</dd></div>`;
    }).join('');
}

function asmResultDetailKey(row) {
    return asmFirstValue(row, ['hash']);
}

function asmRenderResultCard(row, index, screenshots) {
    const type = asmPageState.selectedAssetType;
    const provider = asmPageState.selectedTask?.provider || '';
    if (type === 'site') return asmRenderSiteRecord(row, index, screenshots);
    if (provider === 'arl' && type === 'ip') return asmRenderARLIPRecord(row, index);
    const schema = asmResultSchema(provider, type);
    const title = asmResultTitle(row, schema, index);
    const subtitle = asmFirstValue(row, schema.subtitle);
    const severity = asmSeverity(asmFirstValue(row, ['severity', 'level', 'vuln_severity', 'raw_output.info.severity', 'rawOutput.info.severity']));
    const status = asmFirstValue(row, ['status_code', 'statusCode', 'status']);
    const tags = asmFirstValue(row, ['tags', 'tech', 'products', 'finger']);
    const detailKey = provider === 'scopesentry' && type === 'vulnerability' ? asmResultDetailKey(row) : '';
    const facts = schema.facts.map(([label, ...keys]) => {
        const value = asmFirstValue(row, keys);
        if (value === '') return '';
        return `<div><span>${asmEscape(label)}</span><strong>${asmValueHTML(value)}</strong></div>`;
    }).filter(Boolean).join('');
    const used = [...schema.title, ...schema.subtitle, ...schema.facts.flatMap(([, ...keys]) => keys), 'severity', 'level', 'vuln_severity', 'status_code', 'statusCode', 'status', 'tags', 'tech', 'products', 'finger'];
    return `<article class="asm-result-card ${type === 'vulnerability' || type === 'nuclei_result' ? 'is-risk' : ''}">
        <header><div class="asm-result-index">${index + 1}</div><div class="asm-result-card-title"><h5>${asmValueHTML(title)}</h5>${subtitle ? `<p>${asmValueHTML(subtitle)}</p>` : ''}</div><div class="asm-result-card-badges">${severity ? `<span class="asm-severity ${severity.key}">${asmEscape(severity.label)}</span>` : ''}${status !== '' ? `<span class="asm-result-status">${asmEscape(status)}</span>` : ''}</div></header>
        ${facts ? `<div class="asm-result-facts">${facts}</div>` : ''}
        ${asmRenderResultChips(tags)}
        ${asmRenderDirectFields(row, used)}
        ${asmRenderEvidence(row, ['headers', 'responseHeaders', 'banner', 'metadata', 'request', 'response', 'req', 'res', 'verify_data', 'verifyData', 'body', 'raw_output', 'rawOutput'])}
        ${detailKey ? `<section class="asm-provider-detail" data-asm-provider-detail-key="${asmEscape(detailKey)}"><span><span class="asm-spinner"></span> 正在自动读取上游漏洞请求与响应…</span></section>` : ''}
        <details class="asm-result-detail"><summary>查看上游原始字段</summary><dl>${asmRenderResultDetails(row)}</dl></details>
    </article>`;
}

function asmFindResultTotal(value, depth) {
    if (depth > 8 || value == null || typeof value !== 'object') return null;
    if (!Array.isArray(value)) {
        for (const key of ['total', 'count', 'totalCount', 'total_count']) {
            const parsed = Number(value[key]);
            if (Number.isFinite(parsed) && parsed >= 0) return parsed;
        }
        for (const key of ['results', 'data', 'response']) {
            if (Object.prototype.hasOwnProperty.call(value, key)) {
                const nested = asmFindResultTotal(value[key], depth + 1);
                if (nested != null) return nested;
            }
        }
    }
    return null;
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
            if (image) {
                image.src = objectURL;
                image.onclick = () => window.open(objectURL, '_blank', 'noopener,noreferrer');
            }
            node.classList.add('loaded');
        } catch (_) {
            node.classList.add('failed');
            const label = node.querySelector('.asm-screenshot-loading');
            if (label) label.textContent = '图片加载失败';
        }
    }));
}

function renderASMScreenshots(screenshots) {
    if (!Array.isArray(screenshots) || !screenshots.length) return `<div class="asm-result-empty"><strong>${asmPageState.screenshotSyncing ? '正在自动缓存截图' : '暂无已缓存截图'}</strong><span>${asmPageState.screenshotMessage || '系统会自动从 ASM 获取截图并保存到 CyberStrikeAI，无需手动点击。'}</span></div>`;
    return `<section class="asm-screenshot-section"><div class="asm-result-section-title"><strong>CyberStrikeAI 本地截图</strong><span>${screenshots.length} 张 · 已自动缓存${asmPageState.screenshotSyncing ? ' · 正在检查新增截图' : ''}</span></div><div class="asm-screenshot-grid">${screenshots.map(item => `<figure data-asm-screenshot-url="${asmEscape(item.url)}"><div class="asm-screenshot-loading">正在安全加载…</div><img alt="${asmEscape(item.label || 'ASM 站点截图')}" loading="lazy"><figcaption><strong>${asmEscape(item.label || 'ASM 站点截图')}</strong><span>${asmEscape(item.content_type)} · ${Math.max(1, Math.round((Number(item.size_bytes) || 0) / 1024))} KiB · ${asmEscape(formatASMTime(item.created_at))}</span></figcaption></figure>`).join('')}</div></section>`;
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
    asmPageState.lastResultPayload = payload;
    asmPageState.lastResultQuery = query || '';
    clearASMImageObjectURLs();
    const allRows = asmFindResultRows(payload?.payload, 0).filter(item => item && typeof item === 'object');
    const rows = asmFilterResultRows(allRows, query);
    const remoteTotal = asmFindResultTotal(payload?.payload, 0);
    asmPageState.resultTotal = remoteTotal == null ? allRows.length : remoteTotal;
    let body = '';
    if (rows.length) {
        const pageCount = Math.max(1, Math.ceil(asmPageState.resultTotal / asmPageState.resultPageSize));
        const firstNumber = (asmPageState.resultPage - 1) * asmPageState.resultPageSize + 1;
        const lastNumber = firstNumber + rows.length - 1;
        const screenshots = Array.isArray(payload?.screenshots) ? payload.screenshots : (asmPageState.selectedTask?.screenshots || []);
        body = `<div class="asm-result-section-title"><strong>${asmEscape(asmSelectedResultType().label)}结果</strong><span>显示 ${firstNumber}–${lastNumber} · 共 ${asmPageState.resultTotal} 条${payload.stale ? ' · 离线快照' : ''}</span></div><div class="asm-result-card-list">${rows.map((item, index) => asmRenderResultCard(item, firstNumber + index - 1, screenshots)).join('')}</div><div class="asm-result-pagination"><span>第 ${asmPageState.resultPage} / ${pageCount} 页 · 每页 ${asmPageState.resultPageSize} 条</span><div><button type="button" class="btn-secondary btn-small" onclick="changeASMResultPage(-1)" ${asmPageState.resultPage <= 1 ? 'disabled' : ''}>上一页</button><button type="button" class="btn-secondary btn-small" onclick="changeASMResultPage(1)" ${asmPageState.resultPage >= pageCount ? 'disabled' : ''}>下一页</button></div></div>`;
    } else {
        const raw = JSON.stringify(payload?.payload || {}, null, 2);
        const emptyMessage = query ? `当前结果中没有匹配“${asmEscape(query)}”的记录。` : '该结果类型当前为空；打开任务时系统会自动寻找首个已有数据的类型。';
        body = `<div class="asm-result-empty"><strong>${query ? '未找到匹配结果' : '当前类型暂无结果'}</strong><span>${emptyMessage}</span>${!query && raw !== '{}' ? `<details><summary>查看原始响应</summary><pre>${asmEscape(raw)}</pre></details>` : ''}</div>`;
    }
    const pending = payload?.sync && payload.sync.status !== 'completed';
    const banner = pending ? `<div class="asm-stale-banner">${asmEscape(asmResultSyncLabel(payload.sync))}：当前显示 CyberStrikeAI 已保存的本地结果，同步完成后将自动更新。</div>` : '';
    root.innerHTML = `${banner}${body}`;
    void hydrateASMScreenshotImages();
    void hydrateASMProviderResultDetails();
}

async function fetchASMTaskResults(type, page, query) {
    const task = asmPageState.selectedTask;
    const params = new URLSearchParams({ asset_type: type, page: String(page), page_size: String(asmPageState.resultPageSize) });
    if (query) params.set('query', query);
    return asmApi(`/api/asm/tasks/${encodeURIComponent(task.id)}/results?${params.toString()}`);
}

async function loadSelectedASMResults(options) {
    const task = asmPageState.selectedTask;
    const root = document.getElementById('asm-task-results');
    if (!task || !root) return;
    if (asmPageState.selectedAssetType === 'screenshots') {
        renderASMScreenshotPanel();
        return;
    }
    const requestSeq = ++asmPageState.resultRequestSeq;
    root.innerHTML = `<div class="asm-task-loading"><span class="asm-spinner"></span><span>正在读取 CyberStrikeAI 本地结果…</span></div>`;
    const query = document.getElementById('asm-result-query')?.value.trim();
    try {
        let payload = await fetchASMTaskResults(asmPageState.selectedAssetType, asmPageState.resultPage, query);
        if (options?.autoSelect && !query && !asmFindResultRows(payload?.payload, 0).length) {
            for (const candidate of asmTaskResultTypes().filter(item => !item.local)) {
                if (candidate.id === asmPageState.selectedAssetType) continue;
                const candidatePayload = await fetchASMTaskResults(candidate.id, 1, '');
                if (asmFindResultRows(candidatePayload?.payload, 0).length) {
                    asmPageState.selectedAssetType = candidate.id;
                    asmPageState.resultPage = 1;
                    payload = candidatePayload;
                    renderASMResultTabs();
                    break;
                }
            }
        }
        if (requestSeq !== asmPageState.resultRequestSeq) return;
        if (Array.isArray(payload?.screenshots)) asmPageState.selectedTask.screenshots = payload.screenshots;
        if (payload?.screenshot_caching) {
            asmPageState.screenshotSyncing = true;
            renderASMScreenshotCacheStatus();
            void refreshASMTaskScreenshots(task.id, payload.screenshots?.length || 0);
        }
        renderASMResultTabs();
        renderASMResults(payload, query);
    } catch (error) {
        root.innerHTML = `<div class="asm-result-empty error"><strong>结果读取失败</strong><span>${asmEscape(error.message)}</span></div>`;
    }
}

function selectASMResultType(type) {
    asmPageState.selectedAssetType = type;
    asmPageState.resultPage = 1;
    renderASMResultTabs();
    void loadSelectedASMResults();
}

function changeASMResultPageSize(value) {
    const size = Number(value);
    if (![10, 20, 50, 100].includes(size)) return;
    asmPageState.resultPageSize = size;
    asmPageState.resultPage = 1;
    void loadSelectedASMResults();
}

function renderASMScreenshotPanel() {
    const root = document.getElementById('asm-task-results');
    if (!root) return;
    clearASMImageObjectURLs();
    root.innerHTML = renderASMScreenshots(asmPageState.selectedTask?.screenshots || []);
    void hydrateASMScreenshotImages();
}

function renderASMScreenshotCacheStatus() {
    const root = document.getElementById('asm-screenshot-cache-status');
    if (!root) return;
    const count = asmPageState.selectedTask?.screenshots?.length || 0;
    if (asmPageState.screenshotSyncing) root.innerHTML = '<span class="asm-spinner"></span> 自动缓存截图中';
    else if (asmPageState.screenshotMessage) root.textContent = asmPageState.screenshotMessage;
    else root.textContent = count ? `已自动缓存 ${count} 张` : '截图将自动缓存';
}

async function autoSyncSelectedASMScreenshots() {
    const task = asmPageState.selectedTask;
    if (!task || asmPageState.screenshotSyncing) return;
    asmPageState.screenshotSyncing = true;
    asmPageState.screenshotMessage = '';
    renderASMScreenshotCacheStatus();
    if (asmPageState.selectedAssetType === 'screenshots') renderASMScreenshotPanel();
    try {
        const result = await asmApi(`/api/asm/tasks/${encodeURIComponent(task.id)}/screenshots/sync`, { method: 'POST' });
        if (asmPageState.selectedTask?.id !== task.id) return;
        asmPageState.selectedTask.screenshots = Array.isArray(result.screenshots) ? result.screenshots : [];
        asmPageState.screenshotMessage = result.errors?.length ? `已缓存 ${result.screenshots?.length || 0} 张，${result.errors.length} 张失败` : `已自动缓存 ${result.screenshots?.length || 0} 张`;
    } catch (error) {
        if (asmPageState.selectedTask?.id !== task.id) return;
        asmPageState.screenshotMessage = `自动缓存暂不可用：${error.message}`;
    } finally {
        if (asmPageState.selectedTask?.id === task.id) {
            asmPageState.screenshotSyncing = false;
            renderASMScreenshotCacheStatus();
            renderASMResultTabs();
            if (asmPageState.selectedAssetType === 'screenshots') renderASMScreenshotPanel();
            else if (asmPageState.lastResultPayload) {
                asmPageState.lastResultPayload.screenshots = asmPageState.selectedTask.screenshots;
                renderASMResults(asmPageState.lastResultPayload, asmPageState.lastResultQuery);
            }
        }
    }
}

async function refreshASMTaskScreenshots(taskId, previousCount) {
    for (let attempt = 0; attempt < 5; attempt++) {
        await new Promise(resolve => setTimeout(resolve, 900));
        if (asmPageState.selectedTask?.id !== taskId) return;
        try {
            const latest = await asmApi(`/api/asm/tasks/${encodeURIComponent(taskId)}`);
            if (asmPageState.selectedTask?.id !== taskId) return;
            asmPageState.selectedTask.screenshots = latest.screenshots || [];
            asmPageState.screenshotSyncing = Boolean(latest.screenshot_caching);
            asmPageState.screenshotMessage = latest.screenshot_error ? `自动缓存暂不可用：${latest.screenshot_error}` : (latest.screenshots?.length ? `已自动缓存 ${latest.screenshots.length} 张` : '正在等待上游生成截图');
            renderASMScreenshotCacheStatus();
            renderASMResultTabs();
            if (asmPageState.selectedAssetType === 'screenshots') renderASMScreenshotPanel();
            if (!latest.screenshot_caching && (latest.screenshots?.length || 0) >= previousCount) {
                if (asmPageState.selectedAssetType !== 'screenshots' && asmPageState.lastResultPayload) {
                    asmPageState.lastResultPayload.screenshots = asmPageState.selectedTask.screenshots;
                    renderASMResults(asmPageState.lastResultPayload, asmPageState.lastResultQuery);
                }
                return;
            }
        } catch (_) {
            return;
        }
    }
}

async function onASMResultDetailToggle(details) {
    if (!details?.open || details.dataset.loaded === 'true' || details.dataset.loading === 'true') return;
    const task = asmPageState.selectedTask;
    const key = details.dataset.asmDetailKey;
    const root = details.querySelector('.asm-provider-detail');
    if (!task || !key || !root) return;
    details.dataset.loading = 'true';
    root.innerHTML = '<span><span class="asm-spinner"></span> 正在读取上游漏洞详情…</span>';
    try {
        const params = new URLSearchParams({ asset_type: asmPageState.selectedAssetType, key });
        const payload = await asmApi(`/api/asm/tasks/${encodeURIComponent(task.id)}/results/detail?${params.toString()}`);
        const detail = payload?.detail?.data ?? payload?.detail ?? payload;
        root.innerHTML = `<div class="asm-provider-detail-grid">${asmRenderResultDetails(detail && typeof detail === 'object' ? detail : { detail })}</div>`;
        details.dataset.loaded = 'true';
    } catch (error) {
        root.innerHTML = `<span class="error">详情读取失败：${asmEscape(error.message)}</span>`;
    } finally {
        delete details.dataset.loading;
    }
}

async function hydrateASMProviderResultDetails() {
    const nodes = Array.from(document.querySelectorAll('[data-asm-provider-detail-key]'));
    for (const node of nodes) {
        if (node.dataset.loaded === 'true' || node.dataset.loading === 'true') continue;
        const task = asmPageState.selectedTask;
        const key = node.dataset.asmProviderDetailKey;
        if (!task || !key) continue;
        node.dataset.loading = 'true';
        try {
            const params = new URLSearchParams({ asset_type: asmPageState.selectedAssetType, key });
            const payload = await asmApi(`/api/asm/tasks/${encodeURIComponent(task.id)}/results/detail?${params.toString()}`);
            if (asmPageState.selectedTask?.id !== task.id || !node.isConnected) continue;
            const detail = payload?.detail?.data ?? payload?.detail ?? payload;
            node.innerHTML = `<div class="asm-provider-detail-grid">${asmRenderResultDetails(detail && typeof detail === 'object' ? detail : { detail })}</div>`;
            node.dataset.loaded = 'true';
        } catch (error) {
            if (node.isConnected) node.innerHTML = `<span class="error">详情读取失败：${asmEscape(error.message)}</span>`;
        } finally {
            delete node.dataset.loading;
        }
    }
}

function changeASMResultPage(delta) {
    const next = Math.max(1, asmPageState.resultPage + Number(delta || 0));
    if (next === asmPageState.resultPage) return;
    asmPageState.resultPage = next;
    void loadSelectedASMResults();
}

async function openASMTaskModal(id) {
    const root = document.getElementById('asm-task-detail');
    asmPageState.selectedAssetType = 'site';
    asmPageState.resultPage = 1;
    asmPageState.screenshotSyncing = false;
    asmPageState.screenshotMessage = '';
    asmPageState.lastResultPayload = null;
    asmPageState.lastResultQuery = '';
    if (root) root.innerHTML = `<div class="asm-task-loading"><span class="asm-spinner"></span><span>正在加载任务详情…</span></div>`;
    renderASMResultTabs();
    if (typeof openAppModal === 'function') openAppModal('asm-task-modal');
    else document.getElementById('asm-task-modal').style.display = 'flex';
    try {
        asmPageState.selectedTask = await asmApi(`/api/asm/tasks/${encodeURIComponent(id)}`);
        const defaultType = asmTaskResultTypes().find(item => item.default) || asmTaskResultTypes()[0];
        asmPageState.selectedAssetType = defaultType?.id || 'site';
        renderASMTaskDetail();
        renderASMResultTabs();
        renderASMScreenshotCacheStatus();
        await loadSelectedASMResults({ autoSelect: true });
        if (asmPageState.selectedTask.result_sync?.status !== 'completed') void pollASMResultSync(id);
    } catch (error) {
        if (root) root.innerHTML = `<div class="asm-task-detail-error">${asmEscape(error.message)}</div>`;
    }
}

function closeASMTaskModal() {
    asmPageState.resultRequestSeq++;
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

async function syncSelectedASMTaskResults() {
    const task = asmPageState.selectedTask;
    if (!task) return;
    try {
        task.result_sync = await asmApi(`/api/asm/tasks/${encodeURIComponent(task.id)}/results/sync`, { method: 'POST' });
        renderASMTaskDetail();
        void pollASMResultSync(task.id, true);
        if (typeof showNotification === 'function') showNotification('ASM 结果全量同步已启动', 'success');
    } catch (error) {
        if (typeof showNotification === 'function') showNotification(error.message, 'error');
    }
}

async function pollASMResultSync(taskId, reloadResults) {
    if (asmPageState.resultSyncPolling) return;
    asmPageState.resultSyncPolling = true;
    try {
        for (let attempt = 0; attempt < 120; attempt++) {
            await new Promise(resolve => setTimeout(resolve, 1200));
            if (asmPageState.selectedTask?.id !== taskId) return;
            const latest = await asmApi(`/api/asm/tasks/${encodeURIComponent(taskId)}`);
            if (asmPageState.selectedTask?.id !== taskId) return;
            asmPageState.selectedTask = latest;
            const listTask = asmPageState.tasks.find(item => item.id === taskId);
            if (listTask) listTask.result_sync = latest.result_sync;
            renderASMTaskDetail();
            renderASMTasks();
            renderASMScreenshotCacheStatus();
            if (latest.result_sync?.status === 'completed' || latest.result_sync?.status === 'partial' || latest.result_sync?.status === 'failed') {
                if (reloadResults || asmPageState.lastResultPayload?.sync?.status !== 'completed') await loadSelectedASMResults();
                return;
            }
        }
    } catch (_) {
        // 保留最后一次本地状态，下次打开时继续轮询。
    } finally {
        asmPageState.resultSyncPolling = false;
    }
}

async function syncSelectedASMScreenshots() {
    return autoSyncSelectedASMScreenshots();
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
    void loadASMResources();
}

async function initASMTaskCenterPage() {
    await loadASMResources();
    syncASMTaskProviderOptions();
    await loadASMTasks(true);
}

window.initASMResourcesPage = initASMResourcesPage;
window.initASMTaskCenterPage = initASMTaskCenterPage;
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
window.syncSelectedASMTaskResults = syncSelectedASMTaskResults;
window.selectASMResultType = selectASMResultType;
window.loadSelectedASMResults = loadSelectedASMResults;
window.changeASMResultPage = changeASMResultPage;
window.changeASMResultPageSize = changeASMResultPageSize;
window.onASMResultDetailToggle = onASMResultDetailToggle;
window.syncSelectedASMScreenshots = syncSelectedASMScreenshots;
