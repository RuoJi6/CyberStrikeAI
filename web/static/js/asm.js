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
    createProfile: null,
    createOptionSets: {},
    createTemplateToken: '',
    createTemplateBaseSummary: null,
    createLoading: false,
    templateResource: null,
    templatePresets: [],
    upstreamTemplates: [],
    templateLoading: false,
    templateBusyPreset: '',
    templateBulkCreating: false,
    templateError: '',
    templateSelectedPreset: '',
    templateUpstreamDetailID: '',
    templateUpstreamDetail: null,
    templateUpstreamDetailLoading: false,
    templateUpstreamDetailError: '',
    continuations: [],
    continuationStatusCounts: {},
    continuationTotal: 0,
    continuationFilter: 'all',
    continuationPage: 1,
    continuationPageSize: 10,
    continuationLoading: false,
    continuationRequestSeq: 0,
    continuationPollTimer: null,
};

const asmDefaultRunningPrompt = `ASM 扫描结果已完成。
平台：{{provider}}
类型：{{task_type}}
任务 ID：{{task_id}}
任务名称：{{task_name}}
目标：{{targets}}
结果同步状态：{{sync_status}}

你收到本消息时该对话仍有任务在运行。请先完成正在进行的工作，完成之后调用 ASM MCP，使用上述任务 ID 读取已本地化的扫描结果并继续分析。`;

const asmDefaultIdlePrompt = `ASM 扫描结果已完成。
平台：{{provider}}
类型：{{task_type}}
任务 ID：{{task_id}}
任务名称：{{task_name}}
目标：{{targets}}
结果同步状态：{{sync_status}}

继续原任务。请调用 ASM MCP，使用上述任务 ID 读取已本地化的扫描结果并继续分析。`;

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
        const canCreateTemplate = Array.isArray(item.capabilities) && item.capabilities.includes('create_template');
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
                ${canCreateTemplate ? `<button type="button" class="btn-secondary asm-template-button" data-require-permission="mcp:write" data-asm-action="templates">${asmEscape(asmT('asm.scanTemplates', '扫描模板'))}</button>` : ''}
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

function selectedASMAgentContinuationResource() {
    const id = document.getElementById('asm-agent-continuation-resource')?.value || '';
    return asmPageState.resources.find(resource => resource.id === id) || null;
}

function setASMAgentContinuationError(message) {
    const node = document.getElementById('asm-agent-continuation-error');
    if (!node) return;
    node.textContent = message || '';
    node.hidden = !message;
}

function resetASMAgentContinuationPrompts() {
    const running = document.getElementById('asm-agent-continuation-running-prompt');
    const idle = document.getElementById('asm-agent-continuation-idle-prompt');
    if (running) running.value = asmDefaultRunningPrompt;
    if (idle) idle.value = asmDefaultIdlePrompt;
}

function syncASMAgentContinuationForm() {
    const behavior = document.getElementById('asm-agent-continuation-behavior')?.value || 'auto';
    const prompts = document.getElementById('asm-agent-continuation-prompts');
    if (prompts) prompts.hidden = behavior !== 'auto';
}

function loadASMAgentContinuationSettings() {
    const resource = selectedASMAgentContinuationResource();
    const settings = resource?.agent_continuation || {};
    const behavior = document.getElementById('asm-agent-continuation-behavior');
    const running = document.getElementById('asm-agent-continuation-running-prompt');
    const idle = document.getElementById('asm-agent-continuation-idle-prompt');
    if (behavior) behavior.value = settings.behavior || 'auto';
    if (running) running.value = settings.running_prompt || asmDefaultRunningPrompt;
    if (idle) idle.value = settings.idle_prompt || asmDefaultIdlePrompt;
    syncASMAgentContinuationForm();
    if (typeof window.refreshSettingsCustomSelects === 'function') window.refreshSettingsCustomSelects();
}

const asmContinuationPhaseMeta = Object.freeze({
    waiting_scan: { label: '等待扫描', group: 'scanning', tone: 'pending', description: '任务已绑定，等待 ASM 开始扫描' },
    scanning: { label: '正在扫描', group: 'scanning', tone: 'running', description: 'ASM 扫描尚未完成' },
    localizing: { label: '结果本地化中', group: 'scanning', tone: 'syncing', description: '扫描已完成，正在同步结果或缓存截图' },
    awaiting_agent: { label: '等待发起', group: 'waiting', tone: 'ready', description: '结果已就绪，等待来源 Agent 空闲' },
    retry_wait: { label: '等待重试', group: 'waiting', tone: 'warning', description: '上次恢复失败，系统将自动重试' },
    queued_active: { label: '已排队', group: 'waiting', tone: 'ready', description: '来源 Agent 仍在运行；已进入 Eino TurnLoop，将在当前任务结束后自动续跑' },
    resuming: { label: '正在恢复', group: 'running', tone: 'running', description: '系统正在向来源对话发起 Agent 续跑' },
    success: { label: '成功', group: 'success', tone: 'success', description: '联动消息已送达，并已成功启动一次 Agent 续跑' },
    agent_consumed: { label: 'Agent 已读取', group: 'success', tone: 'success', description: '来源 Agent 已主动读取全部关联扫描结果，系统已取消重复插入' },
    recorded: { label: '仅记录完成', group: 'success', tone: 'neutral', description: '扫描结果已就绪，策略配置为不自动续跑' },
    user_stopped: { label: '用户停止', group: 'stopped', tone: 'stopped', description: '用户主动停止来源对话，系统不会重新启动 Agent' },
    scan_cancelled: { label: '扫描未完成', group: 'failed', tone: 'failed', description: '关联 ASM 任务失败或被停止，联动已取消' },
    failed: { label: '联动失败', group: 'failed', tone: 'failed', description: '达到重试上限或联动记录异常' },
});

function asmContinuationMeta(item) {
    return asmContinuationPhaseMeta[item?.phase] || asmContinuationPhaseMeta.failed;
}

function asmContinuationSummaryCounts() {
    const counts = asmPageState.continuationStatusCounts || {};
    const value = key => Number(counts[key]) || 0;
    return {
        all: Object.values(counts).reduce((total, count) => total + (Number(count) || 0), 0),
        scanning: value('waiting'),
        waiting: value('ready') + value('retry') + value('queued'),
        running: value('running'),
        success: value('completed') + value('agent_consumed'),
        stopped: value('user_stopped'),
        failed: value('failed') + value('cancelled'),
    };
}

function setASMContinuationFilter(filter) {
    asmPageState.continuationFilter = filter || 'all';
    asmPageState.continuationPage = 1;
    void loadASMAgentContinuations();
}

function asmContinuationFilterStatuses() {
    return {
        scanning: 'waiting',
        waiting: 'ready,retry,queued',
        running: 'running',
        success: 'completed,agent_consumed',
        stopped: 'user_stopped',
        failed: 'failed,cancelled',
    }[asmPageState.continuationFilter] || '';
}

function changeASMContinuationPage(delta) {
    const pages = Math.max(1, Math.ceil(asmPageState.continuationTotal / asmPageState.continuationPageSize));
    asmPageState.continuationPage = Math.max(1, Math.min(pages, asmPageState.continuationPage + Number(delta || 0)));
    void loadASMAgentContinuations();
}

function changeASMContinuationPageSize(value) {
    const size = Number(value);
    if (![5, 10, 20, 50].includes(size)) return;
    asmPageState.continuationPageSize = size;
    asmPageState.continuationPage = 1;
    void loadASMAgentContinuations();
}

function renderASMAgentContinuations() {
    const summary = document.getElementById('asm-continuation-summary');
    const root = document.getElementById('asm-continuation-list');
    const pagination = document.getElementById('asm-continuation-pagination');
    if (!summary || !root || !pagination) return;
    const counts = asmContinuationSummaryCounts();
    const cards = [
        ['all', '全部'], ['scanning', '扫描中'], ['waiting', '等待发起'], ['running', '恢复中'],
        ['success', '成功'], ['stopped', '用户停止'], ['failed', '异常'],
    ];
    summary.innerHTML = cards.map(([key, label]) => `<button type="button" class="asm-continuation-summary-card ${key}${asmPageState.continuationFilter === key ? ' active' : ''}" aria-pressed="${asmPageState.continuationFilter === key}" onclick="setASMContinuationFilter('${key}')"><strong>${counts[key] || 0}</strong><span>${label}</span></button>`).join('');
    const items = asmPageState.continuations;
    if (!items.length) {
        root.innerHTML = `<div class="asm-continuation-empty"><strong>当前分类暂无联动记录</strong><span>Agent/MCP 下发并成功绑定来源对话后，会在这里持续更新状态。</span></div>`;
    } else root.innerHTML = items.map(item => {
        const meta = asmContinuationMeta(item);
        const tasks = Array.isArray(item.tasks) ? item.tasks : [];
        const first = tasks[0] || {};
        const title = first.name || (tasks.length > 1 ? `${tasks.length} 个 ASM 子任务` : item.id);
        const provider = first.provider ? asmProviderLabel(first.provider) : 'ASM';
        const resource = first.resource_name || '资源已删除或不可用';
        const targets = [...new Set(tasks.map(task => task.target).filter(Boolean))];
        const progress = tasks.length ? Math.round(tasks.reduce((total, task) => total + (Number(task.progress) || 0), 0) / tasks.length) : 0;
        const taskStatus = tasks.length ? [...new Set(tasks.map(task => asmTaskStatusLabel(task.status)).filter(Boolean))].join('、') : '等待任务记录';
        const taskIDs = tasks.map(task => task.id).filter(Boolean);
        const consumedCount = tasks.filter(task => task.consumed_by_agent).length;
        const error = item.last_error ? `<p class="asm-continuation-error">${asmEscape(item.last_error)}</p>` : '';
        const action = taskIDs.length ? `<button type="button" class="btn-secondary btn-small" onclick="openASMContinuationTask('${asmEscape(taskIDs[0])}')">查看扫描任务</button>` : '';
        const footerStatus = item.phase === 'agent_consumed'
            ? `Agent 已主动读取 ${consumedCount}/${tasks.length} 个关联任务结果`
            : (item.agent_was_running ? '扫描完成时 Agent 正在运行' : '扫描完成时 Agent 已停止或空闲');
        return `<article class="asm-continuation-item ${meta.tone}">
            <header><span class="asm-continuation-status ${meta.tone}"><i aria-hidden="true"></i>${asmEscape(meta.label)}</span><strong>${asmEscape(title)}</strong><time>${asmEscape(formatASMTime(item.updated_at))}</time></header>
            <p class="asm-continuation-description">${asmEscape(meta.description)}</p>
            <div class="asm-continuation-task-line"><span>${asmEscape(provider)} · ${asmEscape(resource)}</span><span>${asmEscape(taskStatus)} · ${progress}%</span></div>
            <div class="asm-continuation-progress"><span style="width:${Math.max(0, Math.min(100, progress))}%"></span></div>
            <dl><div><dt>扫描目标</dt><dd>${asmEscape(targets.join('、') || '—')}</dd></div><div><dt>来源对话</dt><dd title="${asmEscape(item.conversation_id)}">${asmEscape(item.conversation_title || item.conversation_id || '—')}</dd></div><div><dt>联动 ID</dt><dd>${asmEscape(item.id)}</dd></div><div><dt>尝试次数</dt><dd>${Number(item.attempts) || 0}</dd></div></dl>
            ${error}<footer><span>${asmEscape(footerStatus)}</span>${action}</footer>
        </article>`;
    }).join('');
    const pages = Math.max(1, Math.ceil(asmPageState.continuationTotal / asmPageState.continuationPageSize));
    const start = asmPageState.continuationTotal ? (asmPageState.continuationPage - 1) * asmPageState.continuationPageSize + 1 : 0;
    const end = Math.min(asmPageState.continuationTotal, asmPageState.continuationPage * asmPageState.continuationPageSize);
    pagination.innerHTML = `<span>显示 ${start}-${end} · 共 ${asmPageState.continuationTotal} 条</span>
        <label><span>每页</span><select aria-label="每页联动记录数" onchange="changeASMContinuationPageSize(this.value)">
            ${[5, 10, 20, 50].map(size => `<option value="${size}"${asmPageState.continuationPageSize === size ? ' selected' : ''}>${size} 条</option>`).join('')}
        </select></label>
        <button type="button" class="btn-secondary btn-small" ${asmPageState.continuationPage <= 1 ? 'disabled' : ''} onclick="changeASMContinuationPage(-1)">上一页</button>
        <b>${asmPageState.continuationPage} / ${pages}</b>
        <button type="button" class="btn-secondary btn-small" ${asmPageState.continuationPage >= pages ? 'disabled' : ''} onclick="changeASMContinuationPage(1)">下一页</button>`;
}

async function loadASMAgentContinuations(silent) {
    if (asmPageState.continuationLoading) return;
    asmPageState.continuationLoading = true;
    const requestSeq = ++asmPageState.continuationRequestSeq;
    const root = document.getElementById('asm-continuation-list');
    if (!silent && root && !asmPageState.continuations.length) root.innerHTML = `<div class="asm-task-loading"><span class="asm-spinner" aria-hidden="true"></span><span>正在读取联动状态…</span></div>`;
    try {
        const params = new URLSearchParams({
            page: String(asmPageState.continuationPage),
            page_size: String(asmPageState.continuationPageSize),
        });
        const statuses = asmContinuationFilterStatuses();
        if (statuses) params.set('status', statuses);
        const payload = await asmApi(`/api/asm/agent-continuations?${params.toString()}`);
        if (requestSeq !== asmPageState.continuationRequestSeq) return;
        asmPageState.continuations = Array.isArray(payload.items) ? payload.items : [];
        asmPageState.continuationStatusCounts = payload.status_counts || {};
        asmPageState.continuationTotal = Number(payload.total) || 0;
        asmPageState.continuationPage = Number(payload.page) || asmPageState.continuationPage;
        renderASMAgentContinuations();
    } catch (error) {
        if (root) root.innerHTML = `<div class="asm-continuation-empty error"><strong>联动状态读取失败</strong><span>${asmEscape(error.message)}</span></div>`;
    } finally {
        asmPageState.continuationLoading = false;
    }
}

function openASMContinuationTask(taskID) {
    closeASMAgentContinuationModal();
    void openASMTaskModal(taskID);
}

async function openASMAgentContinuationModal() {
    if (!asmPageState.resources.length) await loadASMResources();
    if (!asmPageState.resources.length) {
        if (typeof showNotification === 'function') showNotification('请先添加 ASM 资源', 'warning');
        return;
    }
    const select = document.getElementById('asm-agent-continuation-resource');
    const previous = select?.value || '';
    if (select) {
        select.innerHTML = asmPageState.resources.map(resource => `<option value="${asmEscape(resource.id)}">${asmEscape(resource.name)} · ${asmEscape(asmProviderLabel(resource.provider))}</option>`).join('');
        select.value = asmPageState.resources.some(resource => resource.id === previous) ? previous : asmPageState.resources[0].id;
    }
    setASMAgentContinuationError('');
    loadASMAgentContinuationSettings();
    const form = document.getElementById('asm-agent-continuation-form');
    if (form && typeof window.initSettingsCustomSelects === 'function') window.initSettingsCustomSelects(form);
    if (typeof openAppModal === 'function') openAppModal('asm-agent-continuation-modal');
    else document.getElementById('asm-agent-continuation-modal').style.display = 'flex';
    void loadASMAgentContinuations();
    if (asmPageState.continuationPollTimer) window.clearInterval(asmPageState.continuationPollTimer);
    asmPageState.continuationPollTimer = window.setInterval(() => void loadASMAgentContinuations(true), 5000);
}

function closeASMAgentContinuationModal() {
    if (asmPageState.continuationPollTimer) {
        window.clearInterval(asmPageState.continuationPollTimer);
        asmPageState.continuationPollTimer = null;
    }
    if (typeof window.closeAllSettingsCustomSelects === 'function') window.closeAllSettingsCustomSelects();
    if (typeof closeAppModal === 'function') closeAppModal('asm-agent-continuation-modal');
    else document.getElementById('asm-agent-continuation-modal').style.display = 'none';
}

async function saveASMAgentContinuation(event) {
    if (event) event.preventDefault();
    const resource = selectedASMAgentContinuationResource();
    if (!resource) {
        setASMAgentContinuationError('请选择 ASM 资源');
        return;
    }
    const button = document.getElementById('asm-agent-continuation-save');
    const payload = {
        agent_continuation: {
            behavior: document.getElementById('asm-agent-continuation-behavior')?.value || 'auto',
            running_prompt: document.getElementById('asm-agent-continuation-running-prompt')?.value.trim() || asmDefaultRunningPrompt,
            idle_prompt: document.getElementById('asm-agent-continuation-idle-prompt')?.value.trim() || asmDefaultIdlePrompt,
        },
    };
    setASMAgentContinuationError('');
    if (button) button.disabled = true;
    try {
        const updated = await asmApi(`/api/asm/resources/${encodeURIComponent(resource.id)}`, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
        });
        const index = asmPageState.resources.findIndex(item => item.id === resource.id);
        if (index >= 0) asmPageState.resources[index] = updated;
        closeASMAgentContinuationModal();
        if (typeof showNotification === 'function') showNotification('Agent 联动设置已保存', 'success');
    } catch (error) {
        setASMAgentContinuationError(error.message);
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

function asmTemplateItems(payload) {
    const root = payload?.options ?? payload ?? {};
    if (Array.isArray(root)) return root;
    const candidates = [root.items, root.list, root.results, root.data?.items, root.data?.list, root.data?.results, root.data];
    return candidates.find(Array.isArray) || [];
}

function asmUpstreamTemplateID(item) {
    return String(item?._id || item?.id || item?.policy_id || item?.template_id || '').trim();
}

function asmUpstreamTemplateName(item) {
    return String(item?.name || item?.template_name || item?.policy_name || '').trim();
}

function asmTemplateProviderKind(provider) {
    return provider === 'arl' ? asmT('asm.policyKind', 'ARL 策略') : asmT('asm.templateKind', 'ScopeSentry 模板');
}

const asmTemplateConfigLabels = Object.freeze({
    domain_brute: '子域名爆破', domain_brute_type: '域名字典', alt_dns: 'DNS 智能字典', arl_search: 'ARL 历史查询', dns_query_plugin: 'DNS 查询插件',
    port_scan: '端口扫描', port_scan_type: '端口范围', service_detection: '服务识别', os_detection: '操作系统识别', ssl_cert: 'SSL 证书', skip_scan_cdn_ip: '跳过 CDN IP',
    site_identify: '站点识别', site_capture: '站点截图', search_engines: '搜索引擎', site_spider: '站点爬虫', nuclei_scan: 'Nuclei 扫描', web_info_hunter: 'WIH 调用',
    file_leak: '文件泄露', npoc_service_detection: 'NPoC 服务检测', host_timeout_type: '主机超时方式', host_timeout: '主机超时（秒）', port_parallelism: '端口并发', port_min_rate: '端口最小速率',
    poc_selection: '漏洞 POC', brute_selection: '弱口令插件', enabled_capabilities: '启用能力', ports: '端口表达式', concurrency: '扫描并发', tls_probe: 'TLS 探测',
});

const asmTemplateCapabilityLabels = Object.freeze({
    subdomain_discovery: '子域名发现', subdomain_takeover: '子域接管', port_scan: '端口扫描', service_fingerprint: '服务指纹', site_identify: '站点识别',
    site_capture: '站点截图', tls_probe: 'TLS 探测', url_scan: 'URL 扫描', web_crawler: 'Web 爬虫', sensitive_scan: '敏感信息', directory_scan: '目录扫描',
    vulnerability_scan: '漏洞扫描', passive_scan: '被动扫描', asset_handle: '资产处理',
});

function asmTemplateConfigValue(value) {
    if (typeof value === 'boolean') return value ? '开启' : '关闭';
    if (Array.isArray(value)) {
        if (!value.length) return '无';
        if (value.every(item => item == null || ['string', 'number', 'boolean'].includes(typeof item))) return value.map(item => asmTemplateCapabilityLabels[item] || item).join('、');
        return `${value.length} 项`;
    }
    if (typeof value === 'object' && value) return `${Object.keys(value).length} 个配置字段`;
    if (value === 'all') return '全部';
    if (value === 'none') return '不启用';
    if (value == null || value === '') return '未设置';
    return String(value);
}

function asmTemplatePresetCardSummary(preset, provider) {
    const config = preset?.provider_config || {};
    if (provider === 'arl') {
        const port = String(config.port_scan_type || 'test').toUpperCase();
        return {
            meta: [`ARL ${port}`, preset.estimated_duration || ''],
            chips: [
                config.domain_brute ? `子域字典：${config.domain_brute_type === 'big' ? '大字典' : '测试'}` : '子域爆破：关闭',
                config.site_capture ? '站点截图：开启' : '站点截图：关闭',
                `漏洞 POC：${asmTemplateConfigValue(config.poc_selection)}`,
                `弱口令：${asmTemplateConfigValue(config.brute_selection)}`,
            ],
        };
    }
    const capabilities = Array.isArray(config.enabled_capabilities) ? config.enabled_capabilities : [];
    const ports = String(config.ports || '');
    const portSummary = ports.includes(',') ? `${ports.split(',').filter(Boolean).length} 个常用端口` : (ports || '默认端口');
    return {
        meta: [`Scope ${portSummary}`, `并发 ${config.concurrency || '默认'}`],
        chips: capabilities.slice(0, 5).map(item => asmTemplateCapabilityLabels[item] || item).concat(capabilities.length > 5 ? [`另 ${capabilities.length - 5} 项能力`] : []),
    };
}

function asmTemplateConfigRows(config) {
    return Object.entries(config || {}).map(([key, value]) => `<div><span>${asmEscape(asmTemplateConfigLabels[key] || key)}</span><strong>${asmEscape(asmTemplateConfigValue(value))}</strong><code>${asmEscape(key)}</code></div>`).join('');
}

function renderASMTemplatePresetDetail() {
    const root = document.getElementById('asm-template-preset-detail');
    const resource = asmPageState.templateResource;
    const preset = asmPageState.templatePresets.find(item => item.id === asmPageState.templateSelectedPreset);
    if (!root || !resource || !preset) {
        if (root) { root.hidden = true; root.innerHTML = ''; }
        return;
    }
    const config = preset.provider_config || {};
    const providerKind = resource.provider === 'arl' ? 'ARL 策略参数' : 'ScopeSentry 模板参数';
    const capabilities = Array.isArray(config.enabled_capabilities) ? config.enabled_capabilities : [];
    const configWithoutCapabilities = Object.fromEntries(Object.entries(config).filter(([key]) => key !== 'enabled_capabilities'));
    root.hidden = false;
    root.innerHTML = `<div class="asm-template-detail-head">
        <div><span>${asmEscape(resource.provider === 'arl' ? 'ARL POLICY' : 'SCOPESENTRY TEMPLATE')}</span><h5>${asmEscape(preset.name)} · ${asmEscape(providerKind)}</h5><p>${asmEscape(preset.description || '')}</p></div>
        <button type="button" class="modal-close" onclick="closeASMTemplatePresetDetail()" aria-label="关闭模板详情">&times;</button>
    </div>
    ${capabilities.length ? `<section class="asm-template-detail-capabilities"><strong>启用的 ScopeSentry 插件能力（${capabilities.length}）</strong><div>${capabilities.map(item => `<span><b>${asmEscape(asmTemplateCapabilityLabels[item] || item)}</b><code>${asmEscape(item)}</code></span>`).join('')}</div></section>` : ''}
    <section class="asm-template-detail-settings"><strong>${asmEscape(providerKind)}</strong><div class="asm-template-detail-grid">${asmTemplateConfigRows(configWithoutCapabilities)}</div></section>
    <details class="asm-template-detail-json"><summary>MCP 可读取的结构化配置</summary><pre>${asmEscape(JSON.stringify({ provider: preset.provider, provider_kind: preset.provider_kind, provider_config: config, mcp_usage: preset.mcp_usage }, null, 2))}</pre></details>`;
}

function showASMTemplatePresetDetail(presetID) {
    asmPageState.templateSelectedPreset = presetID;
    renderASMTemplateLibrary();
    document.getElementById('asm-template-preset-detail')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function closeASMTemplatePresetDetail() {
    asmPageState.templateSelectedPreset = '';
    renderASMTemplateLibrary();
}

function renderASMUpstreamTemplateDetail() {
    const root = document.getElementById('asm-template-upstream-detail');
    const resource = asmPageState.templateResource;
    if (!root || !resource || !asmPageState.templateUpstreamDetailID) {
        if (root) { root.hidden = true; root.innerHTML = ''; }
        return;
    }
    root.hidden = false;
    if (asmPageState.templateUpstreamDetailLoading) {
        root.innerHTML = '<div class="asm-template-loading"><span class="asm-spinner"></span><span>正在读取上游具体设置…</span></div>';
        return;
    }
    if (asmPageState.templateUpstreamDetailError) {
        root.innerHTML = `<div class="asm-template-detail-head"><div><h5>上游设置读取失败</h5><p>${asmEscape(asmPageState.templateUpstreamDetailError)}</p></div><button type="button" class="modal-close" onclick="closeASMUpstreamTemplateDetail()" aria-label="关闭详情">&times;</button></div>`;
        return;
    }
    const item = asmPageState.upstreamTemplates.find(entry => asmUpstreamTemplateID(entry) === asmPageState.templateUpstreamDetailID);
    const payload = asmPageState.templateUpstreamDetail?.options ?? asmPageState.templateUpstreamDetail ?? {};
    const summary = payload.capability_summary || {};
    const arlItem = resource.provider === 'arl' ? (payload.items?.[0] || payload.results?.[0] || payload.data?.items?.[0] || payload.data?.results?.[0] || payload) : null;
    const readable = resource.provider === 'arl' ? (arlItem?.policy || arlItem || {}) : (Object.keys(summary).length ? summary : payload);
    root.innerHTML = `<div class="asm-template-detail-head">
        <div><span>UPSTREAM DETAIL</span><h5>${asmEscape(asmUpstreamTemplateName(item) || asmTemplateProviderKind(resource.provider))}</h5><p>${asmEscape(resource.provider === 'arl' ? 'ARL policy_detail 实时返回' : 'ScopeSentry template_detail 实时回读并校验')}</p></div>
        <button type="button" class="modal-close" onclick="closeASMUpstreamTemplateDetail()" aria-label="关闭详情">&times;</button>
    </div>
    <section class="asm-template-detail-settings"><strong>具体设置摘要</strong><div class="asm-template-detail-grid">${asmTemplateConfigRows(readable)}</div></section>
    <details class="asm-template-detail-json" open><summary>上游原始结构化响应</summary><pre>${asmEscape(JSON.stringify(payload, null, 2))}</pre></details>`;
}

async function showASMUpstreamTemplateDetail(templateID) {
    const resource = asmPageState.templateResource;
    if (!resource || !templateID || asmPageState.templateUpstreamDetailLoading) return;
    asmPageState.templateUpstreamDetailID = templateID;
    asmPageState.templateUpstreamDetail = null;
    asmPageState.templateUpstreamDetailError = '';
    asmPageState.templateUpstreamDetailLoading = true;
    renderASMUpstreamTemplateDetail();
    document.getElementById('asm-template-upstream-detail')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    try {
        const kind = resource.provider === 'arl' ? 'policy_detail' : 'template_detail';
        asmPageState.templateUpstreamDetail = await asmApi(`/api/asm/resources/${encodeURIComponent(resource.id)}/task-options?kind=${encodeURIComponent(kind)}&option_id=${encodeURIComponent(templateID)}&page=1&page_size=1`);
    } catch (error) {
        asmPageState.templateUpstreamDetailError = error.message;
    } finally {
        asmPageState.templateUpstreamDetailLoading = false;
        renderASMUpstreamTemplateDetail();
    }
}

function closeASMUpstreamTemplateDetail() {
    asmPageState.templateUpstreamDetailID = '';
    asmPageState.templateUpstreamDetail = null;
    asmPageState.templateUpstreamDetailError = '';
    renderASMUpstreamTemplateDetail();
}

function renderASMTemplateLibrary() {
    const resource = asmPageState.templateResource;
    const subtitle = document.getElementById('asm-template-library-subtitle');
    const error = document.getElementById('asm-template-library-error');
    const presetRoot = document.getElementById('asm-template-preset-grid');
    const listRoot = document.getElementById('asm-template-upstream-list');
    const countRoot = document.getElementById('asm-template-upstream-count');
    const createAll = document.getElementById('asm-template-create-all');
    if (!resource || !presetRoot || !listRoot) return;

    if (subtitle) subtitle.textContent = `${resource.name} · ${asmTemplateProviderKind(resource.provider)}`;
    if (error) {
        error.hidden = !asmPageState.templateError;
        error.textContent = asmPageState.templateError;
    }
    const existingNames = new Set(asmPageState.upstreamTemplates.map(asmUpstreamTemplateName).filter(Boolean));
    const loading = asmPageState.templateLoading;
    if (createAll) {
        const allCreated = asmPageState.templatePresets.length > 0 && asmPageState.templatePresets.every(item => existingNames.has(`CyberStrikeAI · ${item.name}`));
        createAll.disabled = loading || asmPageState.templateBulkCreating;
        createAll.textContent = asmPageState.templateBulkCreating
            ? asmT('asm.creatingTemplates', '正在创建…')
            : (allCreated ? asmT('asm.syncAllTemplates', '校准全部配置') : asmT('asm.createAllTemplates', '一键创建全部'));
    }
    if (loading && !asmPageState.templatePresets.length) {
        presetRoot.innerHTML = `<div class="asm-template-loading"><span class="asm-spinner" aria-hidden="true"></span>${asmEscape(asmT('asm.loadingTemplates', '正在读取模板…'))}</div>`;
    } else {
        presetRoot.innerHTML = asmPageState.templatePresets.map((preset, index) => {
            const expectedName = `CyberStrikeAI · ${preset.name}`;
            const exists = existingNames.has(expectedName);
            const busy = asmPageState.templateBusyPreset === preset.id || asmPageState.templateBulkCreating;
            const providerSummary = asmTemplatePresetCardSummary(preset, resource.provider);
            const selected = asmPageState.templateSelectedPreset === preset.id;
            return `<article class="asm-template-preset-card level-${asmEscape(preset.id)}${selected ? ' is-selected' : ''}">
                <div class="asm-template-preset-head">
                    <span class="asm-template-index">0${index + 1}</span>
                    <span class="asm-template-level">${asmEscape(asmT('asm.scanLevel', '等级'))} · ${asmEscape(preset.level || '')}</span>
                </div>
                <h4>${asmEscape(preset.name)}</h4>
                <p>${asmEscape(preset.description || '')}</p>
                <div class="asm-template-meta">${providerSummary.meta.filter(Boolean).map(item => `<span>${asmEscape(item)}</span>`).join('')}</div>
                <div class="asm-template-capabilities">${providerSummary.chips.map(item => `<span>${asmEscape(item)}</span>`).join('')}</div>
                ${preset.warning ? `<div class="asm-template-warning">${asmEscape(preset.warning)}</div>` : ''}
                <div class="asm-template-preset-actions">
                    <button type="button" class="btn-secondary asm-template-preset-detail-button" onclick="showASMTemplatePresetDetail('${asmEscape(preset.id)}')" aria-expanded="${selected}">
                        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h10M18 7h2M10 17H4m10 0h6M8 4v6m8 4v6"/></svg>
                        <span>查看配置</span>
                    </button>
                    <button type="button" class="${exists ? 'btn-secondary' : 'btn-primary'} asm-template-preset-create-button${exists ? ' is-calibrate' : ''}" data-require-permission="mcp:write" onclick="createASMTemplatePreset('${asmEscape(preset.id)}')" ${busy ? 'disabled' : ''}>
                        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="${exists ? 'M20 12a8 8 0 0 1-14.9 4M4 12A8 8 0 0 1 18.9 8M5 16H2v3M19 8h3V5' : 'M12 5v14M5 12h14'}"/></svg>
                        ${busy && !asmPageState.templateBulkCreating ? asmEscape(asmT('asm.creatingTemplate', '创建中…')) : (exists ? asmEscape(asmT('asm.syncTemplate', '校准配置')) : asmEscape(asmT('asm.createTemplate', '一键创建')))}
                    </button>
                </div>
            </article>`;
        }).join('') || `<div class="asm-template-loading">${asmEscape(asmT('asm.noTemplatePresets', '该平台暂无内置模板预设'))}</div>`;
    }
    renderASMTemplatePresetDetail();

    if (countRoot) countRoot.textContent = asmT('asm.upstreamTemplateCount', `${asmPageState.upstreamTemplates.length} 个上游模板`, { count: asmPageState.upstreamTemplates.length });
    if (loading && !asmPageState.upstreamTemplates.length) {
        listRoot.innerHTML = `<div class="asm-template-list-empty">${asmEscape(asmT('asm.loadingUpstreamTemplates', '正在读取上游模板…'))}</div>`;
    } else {
        listRoot.innerHTML = asmPageState.upstreamTemplates.map(item => {
            const name = asmUpstreamTemplateName(item) || asmT('asm.unnamedTemplate', '未命名模板');
            const id = asmUpstreamTemplateID(item);
            const managed = name.startsWith('CyberStrikeAI ·');
            const description = String(item?.desc || item?.description || '').trim();
            return `<div class="asm-template-upstream-item">
                <div class="asm-template-upstream-icon">${managed ? 'CS' : (resource.provider === 'arl' ? 'P' : 'T')}</div>
                <div class="asm-template-upstream-copy"><strong>${asmEscape(name)}</strong>${description ? `<p>${asmEscape(description)}</p>` : ''}<code>${asmEscape(id || '—')}</code></div>
                <div class="asm-template-upstream-actions"><span class="asm-template-origin${managed ? ' managed' : ''}">${asmEscape(managed ? asmT('asm.builtInTemplate', '内置') : asmT('asm.upstreamTemplate', '上游'))}</span>${id ? `<button type="button" class="btn-secondary btn-small" onclick="showASMUpstreamTemplateDetail('${asmEscape(id)}')">查看设置</button>` : ''}</div>
            </div>`;
        }).join('') || `<div class="asm-template-list-empty">${asmEscape(asmT('asm.noUpstreamTemplates', '上游暂无可见模板'))}</div>`;
    }
    renderASMUpstreamTemplateDetail();
    if (typeof applyRBACToUI === 'function') applyRBACToUI(document.getElementById('asm-template-library-modal'));
}

async function loadASMTemplateLibrary() {
    const resource = asmPageState.templateResource;
    if (!resource || asmPageState.templateLoading) return;
    asmPageState.templateLoading = true;
    asmPageState.templateError = '';
    renderASMTemplateLibrary();
    const upstreamKind = resource.provider === 'arl' ? 'policies' : 'templates';
    try {
        const [presets, upstream] = await Promise.all([
            asmApi(`/api/asm/resources/${encodeURIComponent(resource.id)}/task-options?kind=template_presets&page=1&page_size=100`),
            asmApi(`/api/asm/resources/${encodeURIComponent(resource.id)}/task-options?kind=${encodeURIComponent(upstreamKind)}&page=1&page_size=100`),
        ]);
        asmPageState.templatePresets = asmTemplateItems(presets);
        asmPageState.upstreamTemplates = asmTemplateItems(upstream);
    } catch (error) {
        asmPageState.templateError = error.message;
    } finally {
        asmPageState.templateLoading = false;
        renderASMTemplateLibrary();
    }
}

function openASMTemplateLibrary(id) {
    const resource = asmPageState.resources.find(item => item.id === id);
    if (!resource || !Array.isArray(resource.capabilities) || !resource.capabilities.includes('create_template')) return;
    asmPageState.templateResource = resource;
    asmPageState.templatePresets = [];
    asmPageState.upstreamTemplates = [];
    asmPageState.templateError = '';
    asmPageState.templateSelectedPreset = '';
    asmPageState.templateUpstreamDetailID = '';
    asmPageState.templateUpstreamDetail = null;
    asmPageState.templateUpstreamDetailError = '';
    renderASMTemplateLibrary();
    if (typeof openAppModal === 'function') openAppModal('asm-template-library-modal', { focusEl: document.getElementById('asm-template-create-all') });
    else document.getElementById('asm-template-library-modal').style.display = 'flex';
    void loadASMTemplateLibrary();
}

function closeASMTemplateLibrary() {
    if (asmPageState.templateLoading || asmPageState.templateBusyPreset || asmPageState.templateBulkCreating) return;
    if (typeof closeAppModal === 'function') closeAppModal('asm-template-library-modal');
    else document.getElementById('asm-template-library-modal').style.display = 'none';
    asmPageState.templateResource = null;
    asmPageState.templateSelectedPreset = '';
    asmPageState.templateUpstreamDetailID = '';
    asmPageState.templateUpstreamDetail = null;
}

async function createASMTemplatePreset(presetID, quiet) {
    const resource = asmPageState.templateResource;
    const preset = asmPageState.templatePresets.find(item => item.id === presetID);
    if (!resource || !preset || asmPageState.templateBusyPreset) return false;
    asmPageState.templateBusyPreset = presetID;
    asmPageState.templateError = '';
    renderASMTemplateLibrary();
    try {
        const result = await asmApi(`/api/asm/resources/${encodeURIComponent(resource.id)}/templates`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ preset_id: presetID }),
        });
        if (!quiet && typeof showNotification === 'function') {
            showNotification(result.updated ? asmT('asm.templateSynced', '扫描模板已按内置预设校准') : asmT('asm.templateCreateSuccess', '扫描模板创建成功'), 'success');
        }
        return true;
    } catch (error) {
        asmPageState.templateError = error.message;
        if (!quiet && typeof showNotification === 'function') showNotification(error.message, 'error');
        return false;
    } finally {
        asmPageState.templateBusyPreset = '';
        if (!quiet) await loadASMTemplateLibrary();
        else renderASMTemplateLibrary();
    }
}

async function createAllASMTemplatePresets() {
    if (asmPageState.templateBulkCreating) return;
    const pending = asmPageState.templatePresets.slice();
    if (!pending.length) return;
    asmPageState.templateBulkCreating = true;
    renderASMTemplateLibrary();
    let created = 0;
    try {
        for (const preset of pending) {
            if (await createASMTemplatePreset(preset.id, true)) created += 1;
        }
        await loadASMTemplateLibrary();
        if (typeof showNotification === 'function') showNotification(asmT('asm.templatesCreateSummary', `已处理 ${created} 个内置模板`, { count: created }), 'success');
    } finally {
        asmPageState.templateBulkCreating = false;
        renderASMTemplateLibrary();
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

function asmTaskTimestamp(task) {
    const timestamp = Date.parse(task?.created_at || '');
    return Number.isFinite(timestamp) ? timestamp : 0;
}

function asmTaskGroups(tasks) {
    const groups = [];
    const byKey = new Map();
    const orderedTasks = (Array.isArray(tasks) ? tasks.slice() : []).sort((left, right) => {
        const difference = asmTaskTimestamp(right) - asmTaskTimestamp(left);
        return difference || String(right.id || '').localeCompare(String(left.id || ''));
    });
    orderedTasks.forEach(task => {
        const batchSize = Math.max(1, Number(task.batch_size) || 1);
        const batchID = String(task.batch_id || '');
        const grouped = Boolean(batchID) && batchSize > 1;
        const key = grouped ? `batch:${batchID}` : `task:${task.id}`;
        let group = byKey.get(key);
        if (!group) {
            group = { key, batchID, grouped, expected: batchSize, tasks: [], createdAt: 0, createdAtValue: '' };
            byKey.set(key, group);
            groups.push(group);
        }
        group.expected = Math.max(group.expected, batchSize);
        group.tasks.push(task);
        const createdAt = asmTaskTimestamp(task);
        if (createdAt >= group.createdAt) {
            group.createdAt = createdAt;
            group.createdAtValue = task.created_at;
        }
    });
    groups.forEach(group => group.tasks.sort((left, right) => (Number(left.batch_index) || 0) - (Number(right.batch_index) || 0)));
    return groups.sort((left, right) => (right.createdAt - left.createdAt) || right.key.localeCompare(left.key));
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

function asmTaskExecutionProfile(task) {
    const profile = task?.execution_profile;
    return profile && typeof profile === 'object' ? profile : null;
}

function asmTaskExecutionName(profile) {
    if (!profile) return '';
    const names = Array.isArray(profile.names) ? profile.names.map(String).filter(Boolean) : [];
    return String(profile.name || names.join('、') || profile.id || (Array.isArray(profile.ids) ? profile.ids.join(', ') : '') || '').trim();
}

function renderASMTaskExecutionChip(task) {
    const profile = asmTaskExecutionProfile(task);
    const name = asmTaskExecutionName(profile);
    if (!profile || !name) return '';
    const label = String(profile.label || '扫描配置');
    return `<em class="asm-task-profile-chip" title="${asmEscape(`${label}：${name}`)}">${asmEscape(label)} · ${asmEscape(name)}</em>`;
}

function renderASMTaskExecutionPanel(task) {
    const profile = asmTaskExecutionProfile(task);
    const name = asmTaskExecutionName(profile);
    if (!profile || !name) return '';
    const ids = String(profile.id || (Array.isArray(profile.ids) ? profile.ids.join(', ') : '') || '').trim();
    const port = String(profile.port_expression || profile.port_scope || '').trim();
    const capabilities = Array.isArray(profile.enabled_capabilities) ? profile.enabled_capabilities.map(String).filter(Boolean) : [];
    return `<section class="asm-task-execution-panel" aria-label="任务扫描配置">
        <div><span>${asmEscape(profile.label || '扫描配置')}</span><strong>${asmEscape(name)}</strong></div>
        <div><span>上游配置 ID</span><strong>${asmEscape(ids || '上游未返回')}</strong></div>
        <div><span>端口范围</span><strong>${asmEscape(port || '由该配置决定')}</strong></div>
        ${capabilities.length ? `<div class="asm-task-execution-capabilities"><span>已启用能力</span><p>${capabilities.map(asmEscape).join(' · ')}</p></div>` : ''}
    </section>`;
}

function renderASMTaskRow(task, child) {
    const progress = asmTaskProgress(task.progress);
    const status = asmTaskStatusClass(task.status);
    return `<article class="asm-task-row${child ? ' asm-task-child' : ''}" onclick="openASMTaskModal('${asmEscape(task.id)}')">
        <div class="asm-task-primary"><strong>${asmEscape(task.name || `远程任务 ${task.remote_task_id}`)}</strong><span title="${asmEscape(task.target)}">${asmEscape(task.target || '未记录目标')}</span>${renderASMTaskExecutionChip(task)}</div>
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
            <div class="asm-task-primary"><strong>${asmEscape(first.name || '批量扫描')}</strong><span title="${asmEscape(targetLabel)}">${state.expected} 个目标 · ${asmEscape(targetLabel)}</span>${renderASMTaskExecutionChip(first)}</div>
            <div class="asm-task-provider">${renderASMProviderMark(first.provider, true)}<span><strong>${asmEscape(first.resource_name)}</strong><small>${asmEscape(group.batchID)}</small><em class="asm-result-sync-badge completed">同次 MCP 下发</em></span></div>
            <div class="asm-task-progress-cell"><div><span class="asm-task-status ${status}">${asmEscape(asmTaskStatusLabel(state.status))}</span><small>${state.completed}/${state.expected} 个子任务完成</small></div><div class="asm-progress-track"><span style="width:${state.progress}%"></span></div><b>${state.progress}%</b></div>
            <time>${asmEscape(formatASMTime(group.createdAtValue || first.created_at))}</time>
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
        root.innerHTML = `<div class="asm-task-table-head"><span>任务 / 目标</span><span>ASM 资源</span><span>进度</span><span>创建时间（最新优先）</span><span></span></div>${groups.map(group => group.grouped ? renderASMBatch(group) : renderASMTaskRow(group.tasks[0], false)).join('')}`;
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
    ${renderASMTaskExecutionPanel(task)}
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
        syncASMTaskStopButton();
        renderASMResultTabs();
        renderASMScreenshotCacheStatus();
        await loadSelectedASMResults({ autoSelect: true });
        const screenshotState = (asmPageState.selectedTask.result_sync?.types || []).find(item => item.asset_type === 'screenshot');
        if (asmPageState.selectedTask.provider === 'xingrin' && !asmPageState.selectedTask.screenshots?.length && Number(screenshotState?.item_count) > 0) {
            void autoSyncSelectedASMScreenshots();
        }
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
        syncASMTaskStopButton();
        await Promise.all([loadASMTasks(false), loadSelectedASMResults()]);
        if (typeof showNotification === 'function') showNotification('ASM 任务进度已同步', 'success');
    } catch (error) {
        if (typeof showNotification === 'function') showNotification(error.message, 'error');
    }
}

function asmTaskCanStop(task) {
    return task && !['completed', 'failed', 'stopped'].includes(String(task.status || '').toLowerCase());
}

function syncASMTaskStopButton() {
    const button = document.getElementById('asm-task-stop-button');
    const task = asmPageState.selectedTask;
    if (!button) return;
    button.style.display = asmTaskCanStop(task) ? '' : 'none';
    button.textContent = task?.provider === 'scopesentry' ? '暂停任务' : '停止任务';
    button.disabled = false;
}

async function stopSelectedASMTask() {
    const task = asmPageState.selectedTask;
    if (!asmTaskCanStop(task)) return;
    const action = task.provider === 'scopesentry' ? '暂停' : '停止';
    const note = task.provider === 'xingrin' ? '（XingRin 不支持原任务续传，停止后需新建任务）' : '';
    if (!window.confirm(`确定要${action}该任务吗？${note}`)) return;
    const button = document.getElementById('asm-task-stop-button');
    if (button) { button.disabled = true; button.textContent = `${action}中…`; }
    try {
        asmPageState.selectedTask = await asmApi(`/api/asm/tasks/${encodeURIComponent(task.id)}/stop`, { method: 'POST' });
        renderASMTaskDetail();
        syncASMTaskStopButton();
        await loadASMTasks(false);
        if (typeof showNotification === 'function') showNotification(`ASM 任务已${action}`, 'success');
    } catch (error) {
        if (typeof showNotification === 'function') showNotification(error.message, 'error');
        syncASMTaskStopButton();
    }
}

const asmCreateFieldLabels = Object.freeze({
    task_mode: '任务模式', policy_id: 'ARL 策略', task_tag: '任务类型', result_set_id: '结果集 ID',
    domain_brute: '子域名爆破', domain_brute_type: '域名字典级别', port_scan: '端口扫描', port_scan_type: '端口范围',
    service_detection: '服务识别', service_brute: '弱口令爆破', os_detection: '操作系统识别', site_identify: '站点识别', site_capture: '站点截图',
    file_leak: '文件泄露', search_engines: '搜索引擎', site_spider: '站点爬虫', arl_search: 'ARL 历史查询', alt_dns: 'DNS 字典生成',
    ssl_cert: 'SSL 证书', dns_query_plugin: '域名查询插件', skip_scan_cdn_ip: '跳过 CDN IP', nuclei_scan: 'Nuclei 漏洞扫描', findvhost: 'Host 碰撞', web_info_hunter: 'WIH 调用',
    engine_ids: '扫描引擎', subdomain_discovery: '子域名发现', subdomain_bruteforce: '子域名字典爆破', subdomain_permutation: '子域名变异', subdomain_resolve: 'DNS 解析',
    subdomain_wordlist: '子域名字典', port_scan_passive: '被动端口发现', ports: '自定义端口', top_ports: 'Top 端口数', fingerprint_libraries: '指纹库',
    directory_scan: '目录扫描', directory_wordlist: '目录字典', directory_concurrency: '目录扫描并发', screenshot_sources: '截图来源', url_fetch: 'URL 抓取', crawl_depth: '爬虫深度',
    nuclei_template_repos: 'Nuclei 模板仓库', nuclei_severity: 'Nuclei 严重程度', nuclei_tags: 'Nuclei 标签', dalfox_scan: 'Dalfox XSS', rate_limit: '请求速率', concurrency: '并发数', request_timeout: '请求超时（秒）',
    template_id: '上游任务模板', required_port_scope: '必须满足的端口范围', required_capabilities: '必须满足的扫描能力', node_names: '扫描节点', all_nodes: '使用全部在线节点', ignore: '忽略目标',
    duplicates: '去重方式', target_source: '目标来源', project_ids: '项目', source_search: '来源搜索表达式', source_limit: '来源结果上限', source_filter: '来源结构化过滤',
    scheduled: '定时任务', cycle_type: '执行周期', hour: '小时', minute: '分钟', day: '日期', week: '星期', tls_probe: 'TLS 探测',
});

const asmCreateEnumLabels = Object.freeze({
    task_tag: { task: '普通扫描任务', risk_cruising: '风险巡航' },
    domain_brute_type: { test: '测试字典', big: '大字典' },
    port_scan_type: { test: '测试端口', top100: 'TOP 100', top1000: 'TOP 1000', all: '全端口（1-65535）' },
});

const asmCreateOrders = Object.freeze({
    arl: ['task_mode', 'policy_id', 'task_tag', 'result_set_id', 'domain_brute', 'domain_brute_type', 'port_scan', 'port_scan_type', 'service_detection', 'service_brute', 'os_detection', 'site_identify', 'site_capture', 'file_leak', 'search_engines', 'site_spider', 'arl_search', 'alt_dns', 'ssl_cert', 'dns_query_plugin', 'skip_scan_cdn_ip', 'nuclei_scan', 'findvhost', 'web_info_hunter'],
    xingrin: ['engine_ids', 'port_scan', 'ports', 'top_ports', 'port_scan_passive', 'site_identify', 'fingerprint_libraries', 'site_capture', 'screenshot_sources', 'subdomain_discovery', 'subdomain_bruteforce', 'subdomain_permutation', 'subdomain_resolve', 'subdomain_wordlist', 'directory_scan', 'directory_wordlist', 'directory_concurrency', 'url_fetch', 'crawl_depth', 'nuclei_scan', 'nuclei_template_repos', 'nuclei_severity', 'nuclei_tags', 'dalfox_scan', 'rate_limit', 'concurrency', 'request_timeout'],
    scopesentry: ['template_id', 'required_port_scope', 'required_capabilities', 'node_names', 'all_nodes', 'target_source', 'project_ids', 'source_search', 'source_limit', 'source_filter', 'ignore', 'duplicates', 'scheduled', 'cycle_type', 'hour', 'minute', 'day', 'week', 'port_scan', 'ports', 'site_identify', 'site_capture', 'tls_probe', 'concurrency'],
});

const asmScopeTemplateCapabilities = Object.freeze([
    ['subdomain_discovery', '子域名发现'], ['subdomain_takeover', '子域接管'], ['port_scan', '端口扫描'], ['service_fingerprint', '服务指纹'],
    ['site_identify', '站点识别'], ['site_capture', '站点截图'], ['tls_probe', 'TLS 探测'], ['url_scan', 'URL 扫描'],
    ['web_crawler', 'Web 爬虫'], ['sensitive_scan', '敏感信息'], ['directory_scan', '目录扫描'], ['vulnerability_scan', '漏洞扫描'],
    ['passive_scan', '被动扫描'], ['asset_handle', '资产处理'],
]);

function asmCreateResource() {
    const id = document.getElementById('asm-create-resource')?.value;
    return asmPageState.resources.find(item => item.id === id) || null;
}

function asmOptionRows(value, depth) {
    if (depth > 7 || value == null) return [];
    if (Array.isArray(value)) return value;
    if (typeof value !== 'object') return [value];
    for (const key of ['results', 'list', 'items', 'data', 'options', 'response']) {
        if (Object.prototype.hasOwnProperty.call(value, key)) {
            const rows = asmOptionRows(value[key], depth + 1);
            if (rows.length) return rows;
        }
    }
    return [];
}

function asmOptionValue(field, item) {
    if (item == null || typeof item !== 'object') return String(item ?? '');
    if (['node_names', 'subdomain_wordlist', 'directory_wordlist', 'nuclei_template_repos'].includes(field)) return String(item.name ?? item.label ?? item.id ?? '');
    return String(item.id ?? item._id ?? item.value ?? item.name ?? '');
}

function asmOptionLabel(item) {
    if (item == null || typeof item !== 'object') return String(item ?? '');
    const name = item.name ?? item.title ?? item.label ?? item.id ?? item._id ?? item.value;
    const extra = item.description ?? item.introduction ?? item.status;
    return `${name ?? ''}${extra && String(extra) !== String(name) ? ` · ${extra}` : ''}`;
}

function asmCreateChoiceLabel(field, value) {
    return asmCreateEnumLabels[field]?.[String(value)] || String(value);
}

function asmDynamicKind(field, schema) {
    return schema.dynamic_kind || ({ policy_id: 'policies', engine_ids: 'engines' }[field] || '');
}

function asmCreateInputValue(node) {
    if (!node) return null;
    if (node.type === 'checkbox') return node.checked;
    if (node.multiple) return Array.from(node.selectedOptions).map(option => option.value);
    return String(node.value || '').trim();
}

function asmCreateFieldValue(key) {
    return asmCreateInputValue(document.getElementById(`asm-create-option-${key}`));
}

function asmCreateHasValue(value) {
    return Array.isArray(value) ? value.length > 0 : (typeof value === 'boolean' ? value : String(value ?? '').trim() !== '');
}

function closeASMCreateDropdowns(except) {
    document.querySelectorAll('.asm-create-select.is-open').forEach(wrapper => {
        if (wrapper === except) return;
        wrapper.classList.remove('is-open');
        wrapper._asmCreateSelectMenu?.classList.remove('is-open');
        wrapper.querySelector('.asm-create-select-trigger')?.setAttribute('aria-expanded', 'false');
    });
}

function positionASMCreateDropdown(wrapper) {
    const trigger = wrapper?.querySelector('.asm-create-select-trigger');
    const menu = wrapper?._asmCreateSelectMenu;
    if (!trigger || !menu || !wrapper.classList.contains('is-open')) return;
    const rect = trigger.getBoundingClientRect();
    const gap = 6;
    const maxHeight = Math.min(280, Math.max(120, window.innerHeight - 32));
    const below = window.innerHeight - rect.bottom - gap - 12;
    const above = rect.top - gap - 12;
    const openUp = below < Math.min(220, maxHeight) && above > below;
    const height = Math.max(96, Math.min(maxHeight, openUp ? above : below));
    menu.style.left = `${Math.round(rect.left)}px`;
    menu.style.width = `${Math.round(rect.width)}px`;
    menu.style.maxHeight = `${Math.round(height)}px`;
    menu.style.top = openUp ? 'auto' : `${Math.round(rect.bottom + gap)}px`;
    menu.style.bottom = openUp ? `${Math.round(window.innerHeight - rect.top + gap)}px` : 'auto';
}

function syncASMCreateSelect(select) {
    if (!select || select.multiple) return;
    const wrapper = select.closest('.asm-create-select');
    if (!wrapper) return;
    const trigger = wrapper.querySelector('.asm-create-select-trigger');
    const valueNode = wrapper.querySelector('.asm-create-select-value');
    const menu = wrapper._asmCreateSelectMenu;
    const options = Array.from(select.options || []);
    const selected = options.find(option => option.value === select.value) || options[0];
    if (valueNode) valueNode.textContent = selected?.textContent || '请选择';
    if (trigger) {
        trigger.disabled = select.disabled;
        trigger.classList.toggle('is-placeholder', !selected?.value);
    }
    menu?.querySelectorAll('.asm-create-select-option').forEach((button, index) => {
        const active = options[index]?.value === select.value;
        button.classList.toggle('is-selected', active);
        button.setAttribute('aria-selected', String(active));
    });
    if (select.disabled) closeASMCreateDropdowns();
}

function enhanceASMCreateSelect(select) {
    if (!select || select.multiple || select.dataset.asmCustomSelect === 'true') return;
    select.dataset.asmCustomSelect = 'true';
    const wrapper = document.createElement('div');
    wrapper.className = 'asm-create-select';
    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'asm-create-select-trigger';
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    const fieldLabel = select.closest('label')?.querySelector(':scope > span')?.textContent?.trim() || select.getAttribute('aria-label') || '选择选项';
    trigger.setAttribute('aria-label', fieldLabel);
    trigger.innerHTML = '<span class="asm-create-select-value"></span><span class="asm-create-select-chevron" aria-hidden="true"></span>';
    const menu = document.createElement('div');
    menu.className = 'asm-create-select-menu';
    menu.setAttribute('role', 'listbox');
    Array.from(select.options || []).forEach(option => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'asm-create-select-option';
        button.setAttribute('role', 'option');
        button.dataset.value = option.value;
        button.textContent = option.textContent;
        button.addEventListener('click', () => {
            select.value = option.value;
            syncASMCreateSelect(select);
            closeASMCreateDropdowns();
            trigger.focus();
            select.dispatchEvent(new Event('change', { bubbles: true }));
        });
        button.addEventListener('keydown', event => {
            const optionButtons = Array.from(menu.querySelectorAll('.asm-create-select-option'));
            const index = optionButtons.indexOf(button);
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                event.preventDefault();
                const offset = event.key === 'ArrowDown' ? 1 : -1;
                optionButtons[(index + offset + optionButtons.length) % optionButtons.length]?.focus();
            } else if (event.key === 'Escape') {
                event.preventDefault();
                closeASMCreateDropdowns();
                trigger.focus();
            }
        });
        menu.appendChild(button);
    });
    select.parentNode.insertBefore(wrapper, select);
    wrapper.append(select, trigger);
    wrapper._asmCreateSelectMenu = menu;
    menu._asmCreateSelectWrapper = wrapper;
    document.body.appendChild(menu);
    select.classList.add('asm-create-select-native');
    select.setAttribute('aria-hidden', 'true');
    select.tabIndex = -1;
    trigger.addEventListener('click', () => {
        const willOpen = !wrapper.classList.contains('is-open');
        closeASMCreateDropdowns(wrapper);
        wrapper.classList.toggle('is-open', willOpen);
        menu.classList.toggle('is-open', willOpen);
        trigger.setAttribute('aria-expanded', String(willOpen));
        if (willOpen) {
            positionASMCreateDropdown(wrapper);
            const selectedButton = menu.querySelector('.asm-create-select-option.is-selected') || menu.querySelector('.asm-create-select-option');
            if (selectedButton) menu.scrollTop = Math.max(0, selectedButton.offsetTop - ((menu.clientHeight - selectedButton.offsetHeight) / 2));
        }
    });
    trigger.addEventListener('keydown', event => {
        if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
        event.preventDefault();
        if (!wrapper.classList.contains('is-open')) trigger.click();
        const selectedButton = menu.querySelector('.asm-create-select-option.is-selected') || menu.querySelector('.asm-create-select-option');
        selectedButton?.focus();
    });
    syncASMCreateSelect(select);
}

function enhanceASMCreateSelects(root) {
    const scope = root || document.getElementById('asm-task-create-modal');
    if (!scope) return;
    if (scope.matches?.('select:not([multiple])')) enhanceASMCreateSelect(scope);
    scope.querySelectorAll('select:not([multiple])').forEach(enhanceASMCreateSelect);
}

function destroyASMCreateSelects(root) {
    root?.querySelectorAll('.asm-create-select').forEach(wrapper => {
        wrapper._asmCreateSelectMenu?.remove();
        wrapper._asmCreateSelectMenu = null;
    });
}

document.addEventListener('click', event => {
    if (!event.target.closest('.asm-create-select, .asm-create-select-menu')) closeASMCreateDropdowns();
});
document.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeASMCreateDropdowns();
});
window.addEventListener('resize', () => closeASMCreateDropdowns());
document.addEventListener('scroll', event => {
    if (event.target?.classList?.contains('asm-create-select-menu')) return;
    document.querySelectorAll('.asm-create-select.is-open').forEach(positionASMCreateDropdown);
}, true);

function asmCreateSchemaEntries() {
    const options = asmPageState.createProfile?.create_options || {};
    const provider = asmPageState.createProfile?.provider || '';
    const order = asmCreateOrders[provider] || [];
    return Object.keys(options).filter(key => key !== 'template_verification_token').sort((a, b) => {
        const ai = order.indexOf(a), bi = order.indexOf(b);
        return (ai < 0 ? 999 : ai) - (bi < 0 ? 999 : bi) || a.localeCompare(b);
    }).map(key => [key, options[key] || {}]);
}

function asmRenderCreateField(key, schema) {
    const id = `asm-create-option-${key}`;
    const label = asmCreateFieldLabels[key] || key;
    const dynamicKind = asmDynamicKind(key, schema);
    const rows = dynamicKind ? asmOptionRows(asmPageState.createOptionSets[dynamicKind], 0) : [];
    const defaultValue = schema.default;
    const description = schema.description ? `<small>${asmEscape(schema.description)}</small>` : '';
    let control = '';
    if (key === 'task_mode') {
        const selectedMode = defaultValue === 'policy' ? 'policy' : 'direct';
        return `<section class="asm-create-field asm-create-mode-field" data-asm-create-field="task_mode">
            <div class="asm-create-mode-head"><strong>ARL 下发方式</strong><span>与 MCP 的 <code>task_mode</code> 参数完全一致</span></div>
            <div class="asm-create-mode-options" role="radiogroup" aria-label="ARL 下发方式">
                <label class="asm-create-mode-option ${selectedMode === 'direct' ? 'is-selected' : ''}" data-asm-create-mode="direct">
                    <input type="radio" name="asm-create-task-mode" value="direct" ${selectedMode === 'direct' ? 'checked' : ''} onchange="setASMCreateTaskMode(this.value)">
                    <span><strong>直接自定义扫描</strong><small>逐项设置端口、域名、服务、Web、POC 等 ARL 原生开关。</small></span>
                    <code>direct</code>
                </label>
                <label class="asm-create-mode-option ${selectedMode === 'policy' ? 'is-selected' : ''}" data-asm-create-mode="policy">
                    <input type="radio" name="asm-create-task-mode" value="policy" ${selectedMode === 'policy' ? 'checked' : ''} onchange="setASMCreateTaskMode(this.value)">
                    <span><strong>使用策略模板</strong><small>选择已在 ARL 创建的策略；端口、POC 和弱口令配置均由该策略决定。</small></span>
                    <code>policy</code>
                </label>
            </div>
            <input id="${id}" data-asm-create-option="task_mode" type="hidden" value="${selectedMode}">
        </section>`;
    }
    if (schema.type === 'boolean') {
        control = `<label class="asm-create-switch"><input id="${id}" data-asm-create-option="${asmEscape(key)}" type="checkbox" ${defaultValue ? 'checked' : ''} onchange="onASMCreateOptionChange('${asmEscape(key)}')"><span>${asmEscape(label)}</span></label>`;
        return `<div class="asm-create-field asm-create-boolean" data-asm-create-field="${asmEscape(key)}" data-requires="${asmEscape(schema.requires || '')}">${control}${description}</div>`;
    }
    const enums = Array.isArray(schema.enum) ? schema.enum : (Array.isArray(schema.items?.enum) ? schema.items.enum : []);
    if (schema.type === 'array' && (rows.length || enums.length)) {
        const choices = rows.length ? rows.map(item => [asmOptionValue(key, item), asmOptionLabel(item)]) : enums.map(value => [String(value), asmCreateChoiceLabel(key, value)]);
        control = `<select id="${id}" data-asm-create-option="${asmEscape(key)}" multiple size="${Math.min(6, Math.max(3, choices.length))}" onchange="onASMCreateOptionChange('${asmEscape(key)}')">${choices.map(([value, text]) => `<option value="${asmEscape(value)}">${asmEscape(text)}</option>`).join('')}</select><small>可按 Ctrl / Command 多选</small>`;
    } else if (schema.type === 'array') {
        control = `<textarea id="${id}" data-asm-create-option="${asmEscape(key)}" rows="3" placeholder="每行一项" onchange="onASMCreateOptionChange('${asmEscape(key)}')"></textarea>`;
    } else if (rows.length || enums.length) {
        const choices = rows.length ? rows.map(item => [asmOptionValue(key, item), asmOptionLabel(item)]) : enums.map(value => [String(value), asmCreateChoiceLabel(key, value)]);
        control = `<select id="${id}" data-asm-create-option="${asmEscape(key)}" onchange="onASMCreateOptionChange('${asmEscape(key)}')"><option value="">请选择</option>${choices.map(([value, text]) => `<option value="${asmEscape(value)}" ${String(defaultValue ?? '') === value ? 'selected' : ''}>${asmEscape(text)}</option>`).join('')}</select>`;
    } else if (schema.type === 'integer') {
        control = `<input id="${id}" data-asm-create-option="${asmEscape(key)}" type="number" ${schema.minimum != null ? `min="${asmEscape(schema.minimum)}"` : ''} ${schema.maximum != null ? `max="${asmEscape(schema.maximum)}"` : ''} value="${asmEscape(defaultValue ?? '')}" onchange="onASMCreateOptionChange('${asmEscape(key)}')">`;
    } else if (schema.type === 'object') {
        control = `<textarea id="${id}" data-asm-create-option="${asmEscape(key)}" rows="4" placeholder='{"field":["value"]}' onchange="onASMCreateOptionChange('${asmEscape(key)}')"></textarea>`;
    } else {
        control = `<input id="${id}" data-asm-create-option="${asmEscape(key)}" type="text" value="${asmEscape(defaultValue ?? '')}" onchange="onASMCreateOptionChange('${asmEscape(key)}')">`;
    }
    return `<label class="asm-create-field" data-asm-create-field="${asmEscape(key)}" data-requires="${asmEscape(schema.requires || '')}"><span>${asmEscape(label)}</span>${control}${description}</label>`;
}

function setASMCreateTaskMode(mode) {
    const selectedMode = mode === 'policy' ? 'policy' : 'direct';
    const value = document.getElementById('asm-create-option-task_mode');
    if (value) value.value = selectedMode;
    document.querySelectorAll('[data-asm-create-mode]').forEach(card => {
        const selected = card.dataset.asmCreateMode === selectedMode;
        card.classList.toggle('is-selected', selected);
        const radio = card.querySelector('input[type="radio"]');
        if (radio) radio.checked = selected;
    });
    onASMCreateOptionChange('task_mode');
}

function renderASMTaskCreateProfile() {
    const root = document.getElementById('asm-create-options');
    const summary = document.getElementById('asm-create-profile-summary');
    const profile = asmPageState.createProfile;
    if (!root || !profile) return;
    const notes = Array.isArray(profile.notes) ? profile.notes : [];
    if (summary) summary.innerHTML = `<div><strong>${asmEscape(asmProviderLabel(profile.provider))}</strong><span>上游版本 ${asmEscape(profile.upstream_version || '未识别')} · ${asmCreateSchemaEntries().length} 项可配置字段</span></div>${notes.length ? `<details><summary>查看平台差异说明</summary><ul>${notes.map(note => `<li>${asmEscape(note)}</li>`).join('')}</ul></details>` : ''}`;
    renderASMTemplateBuilder();
    destroyASMCreateSelects(root);
    root.innerHTML = asmCreateSchemaEntries().map(([key, schema]) => asmRenderCreateField(key, schema)).join('');
    enhanceASMCreateSelects(root);
    syncASMCreateDependencies();
}

function asmTemplateBuilderEnabled() {
    return Boolean(document.getElementById('asm-template-create-enabled')?.checked);
}

function renderASMTemplateBuilder() {
    const root = document.getElementById('asm-create-template-builder');
    const profile = asmPageState.createProfile;
    if (!root) return;
    asmPageState.createTemplateBaseSummary = null;
    if (profile?.provider !== 'scopesentry' || !profile.template_create_options) {
        root.hidden = true;
        root.innerHTML = '';
        return;
    }
    const templates = asmOptionRows(asmPageState.createOptionSets.templates, 0);
    const pocs = asmOptionRows(asmPageState.createOptionSets.pocs, 0);
    const defaultTemplate = templates.find(item => String(item?.name || '').toLowerCase() === 'default') || templates[0];
    const baseOptions = templates.map(item => {
        const value = String(item?.id || item?._id || '');
        const label = asmOptionLabel(item);
        return `<option value="${asmEscape(value)}" ${value && value === String(defaultTemplate?.id || defaultTemplate?._id || '') ? 'selected' : ''}>${asmEscape(label)}</option>`;
    }).join('');
    const pocOptions = pocs.map(item => {
        const value = String(item?.id || item?._id || item?.['Template ID'] || '');
        return value ? `<option value="${asmEscape(value)}">${asmEscape(asmOptionLabel(item))}</option>` : '';
    }).join('');
    root.hidden = false;
    root.innerHTML = `
        <div class="asm-template-builder-head">
            <div><strong>新建 ScopeSentry 模板</strong><span>克隆上游已审核模板，仅修改结构化扫描参数，并用新模板下发本次任务。</span></div>
            <label class="asm-create-switch asm-template-builder-toggle"><input id="asm-template-create-enabled" type="checkbox" onchange="toggleASMTemplateBuilder()"><span>创建并使用</span></label>
        </div>
        <div id="asm-template-builder-fields" class="asm-template-builder-fields" hidden>
            <div class="asm-template-builder-grid">
                <label><span>模板名称 *</span><input id="asm-template-create-name" maxlength="150" placeholder="例如：CyberStrikeAI 外网复核模板"></label>
                <label><span>基模板 *</span><select id="asm-template-create-base" onchange="inspectASMTemplateBase()">${baseOptions}</select></label>
                <label><span>端口范围</span><input id="asm-template-create-ports" maxlength="200" placeholder="留空继承，例如 1-65535"></label>
                <label><span>端口扫描并发</span><input id="asm-template-create-concurrency" type="number" min="1" max="200" placeholder="留空继承"></label>
            </div>
            <fieldset class="asm-template-capability-picker"><legend>启用的扫描能力</legend>${asmScopeTemplateCapabilities.map(([key, label]) => `<label><input type="checkbox" data-asm-template-capability="${asmEscape(key)}"><span>${asmEscape(label)}</span><code>${asmEscape(key)}</code></label>`).join('')}</fieldset>
            ${pocOptions ? `<label class="asm-template-poc-picker"><span>POC 选择（可选）</span><select id="asm-template-create-pocs" multiple size="5">${pocOptions}</select><small>留空时继承基模板的 POC 选择。</small></label>` : ''}
            <div id="asm-template-base-status" class="asm-template-base-status">开启后将实时核对基模板能力。</div>
        </div>`;
    enhanceASMCreateSelects(root);
}

async function toggleASMTemplateBuilder() {
    const fields = document.getElementById('asm-template-builder-fields');
    const enabled = asmTemplateBuilderEnabled();
    if (fields) fields.hidden = !enabled;
    syncASMCreateDependencies();
    if (enabled) await inspectASMTemplateBase();
}

async function inspectASMTemplateBase() {
    const resource = asmCreateResource();
    const templateID = document.getElementById('asm-template-create-base')?.value || '';
    const status = document.getElementById('asm-template-base-status');
    asmPageState.createTemplateBaseSummary = null;
    if (!resource || !templateID) return;
    if (status) status.innerHTML = '<span class="asm-spinner"></span><span>正在核对基模板…</span>';
    try {
        const payload = await asmApi(`/api/asm/resources/${encodeURIComponent(resource.id)}/task-options?kind=template_detail&option_id=${encodeURIComponent(templateID)}&page=1&page_size=1`);
        const summary = payload.options?.capability_summary || {};
        asmPageState.createTemplateBaseSummary = summary;
        const capabilities = summary.capabilities || {};
        const profileAvailable = Array.isArray(asmPageState.createProfile?.available_template_capabilities) ? asmPageState.createProfile.available_template_capabilities : [];
        const availableCapabilities = new Set(Array.isArray(summary.available_capabilities) ? summary.available_capabilities : profileAvailable);
        document.querySelectorAll('[data-asm-template-capability]').forEach(node => {
            const capability = node.dataset.asmTemplateCapability;
            const available = availableCapabilities.has(capability);
            node.checked = Boolean(capabilities[capability]);
            node.disabled = !available;
            const card = node.closest('label');
            if (card) {
                card.classList.toggle('is-unavailable', !available);
                card.title = available ? '' : '当前 ScopeSentry 上游未安装该能力对应的插件';
            }
        });
        const ports = document.getElementById('asm-template-create-ports');
        if (ports && !ports.value) ports.value = String(summary.port_expression || '');
        if (status) status.textContent = `已核对：基模板启用 ${(summary.enabled_capabilities || []).length} 项 · 上游可用 ${availableCapabilities.size} 项 · 端口 ${summary.port_scope || 'unknown'}${summary.selected_poc_count ? ` · ${summary.selected_poc_count} 个 POC` : ''}`;
    } catch (error) {
        if (status) status.textContent = error.message;
    }
}

function collectASMTemplateCreateRequest(taskName) {
    if (!asmTemplateBuilderEnabled()) return null;
    if (!asmPageState.createTemplateBaseSummary) throw new Error('请等待 ScopeSentry 基模板能力核对完成');
    const name = document.getElementById('asm-template-create-name')?.value.trim() || `${taskName || 'CyberStrikeAI'} 模板 ${new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14)}`;
    const baseTemplateID = document.getElementById('asm-template-create-base')?.value || '';
    const enabledCapabilities = Array.from(document.querySelectorAll('[data-asm-template-capability]:checked')).map(node => node.dataset.asmTemplateCapability);
    if (!enabledCapabilities.length) throw new Error('请至少保留一项 ScopeSentry 扫描能力');
    const options = { enabled_capabilities: enabledCapabilities };
    const ports = document.getElementById('asm-template-create-ports')?.value.trim();
    const concurrency = document.getElementById('asm-template-create-concurrency')?.value;
    const pocs = document.getElementById('asm-template-create-pocs');
    if (ports) options.ports = ports;
    if (concurrency) options.concurrency = Number(concurrency);
    if (pocs && pocs.selectedOptions.length) options.poc_ids = Array.from(pocs.selectedOptions).map(option => option.value);
    return { name, base_template_id: baseTemplateID, options };
}

function syncASMCreateDependencies() {
    const profile = asmPageState.createProfile;
    if (!profile) return;
    const templateSelected = asmCreateHasValue(asmCreateFieldValue('template_id'));
    const templateBuilder = asmTemplateBuilderEnabled();
    const mode = asmCreateFieldValue('task_mode') || 'direct';
    asmCreateSchemaEntries().forEach(([key, schema]) => {
        const field = document.querySelector(`[data-asm-create-field="${CSS.escape(key)}"]`);
        if (!field) return;
        let visible = !schema.requires || asmCreateHasValue(asmCreateFieldValue(schema.requires));
        if (profile.provider === 'scopesentry' && schema.mode === 'generated_low_load_template' && templateSelected) visible = false;
        if (profile.provider === 'scopesentry' && templateBuilder && ['template_id', 'required_port_scope', 'required_capabilities', 'port_scan', 'ports', 'site_identify', 'site_capture', 'tls_probe', 'concurrency'].includes(key)) visible = false;
        if (profile.provider === 'arl') {
            const policyFields = ['policy_id', 'task_tag', 'result_set_id'];
            if (mode === 'policy') visible = key === 'task_mode' || policyFields.includes(key);
            else if (policyFields.includes(key)) visible = false;
            if (key === 'result_set_id' && mode === 'policy' && asmCreateFieldValue('task_tag') !== 'risk_cruising') visible = false;
        }
        field.hidden = !visible;
        field.querySelectorAll('input,select,textarea').forEach(node => { node.disabled = !visible; });
        field.querySelectorAll('select:not([multiple])').forEach(syncASMCreateSelect);
    });
}

async function inspectASMCreateTemplate(templateID) {
    const resource = asmCreateResource();
    asmPageState.createTemplateToken = '';
    if (!resource || !templateID) return;
    const summary = document.getElementById('asm-create-profile-summary');
    try {
        const payload = await asmApi(`/api/asm/resources/${encodeURIComponent(resource.id)}/task-options?kind=template_detail&option_id=${encodeURIComponent(templateID)}&page=1&page_size=1`);
        const detail = payload.options || {};
        asmPageState.createTemplateToken = String(detail.verification_token || '');
        if (summary && detail.capability_summary) summary.insertAdjacentHTML('beforeend', `<div class="asm-template-capabilities"><strong>已核对模板实际能力</strong><code>${asmEscape(JSON.stringify(detail.capability_summary, null, 2))}</code></div>`);
    } catch (error) {
        const errorRoot = document.getElementById('asm-create-error');
        if (errorRoot) { errorRoot.style.display = ''; errorRoot.textContent = error.message; }
    }
}

function onASMCreateOptionChange(key) {
    const profile = asmPageState.createProfile;
    const schema = profile?.create_options?.[key] || {};
    if (schema.conflicts && asmCreateHasValue(asmCreateFieldValue(key))) {
        const other = document.getElementById(`asm-create-option-${schema.conflicts}`);
        if (other) {
            if (other.type === 'checkbox') other.checked = false;
            else other.value = '';
            syncASMCreateSelect(other);
        }
    }
    syncASMCreateDependencies();
    if (key === 'template_id') void inspectASMCreateTemplate(String(asmCreateFieldValue(key) || ''));
}

async function loadASMTaskCreateProfile() {
    const resource = asmCreateResource();
    const root = document.getElementById('asm-create-options');
    const errorRoot = document.getElementById('asm-create-error');
    asmPageState.createProfile = null;
    asmPageState.createOptionSets = {};
    asmPageState.createTemplateToken = '';
    asmPageState.createTemplateBaseSummary = null;
    if (errorRoot) { errorRoot.style.display = 'none'; errorRoot.textContent = ''; }
    if (!resource) { if (root) root.innerHTML = '<div class="asm-result-empty"><strong>请选择 ASM 资源</strong></div>'; return; }
    if (root) root.innerHTML = '<div class="asm-task-loading"><span class="asm-spinner"></span><span>正在读取平台能力和实时选项…</span></div>';
    try {
        const profile = await asmApi(`/api/asm/resources/${encodeURIComponent(resource.id)}/task-profile`);
        const supportedKinds = new Set(Array.isArray(profile.dynamic_option_kinds) ? profile.dynamic_option_kinds : []);
        const dynamicSchemas = { ...(profile.create_options || {}), ...(profile.template_create_options || {}) };
        const kinds = [...new Set(Object.entries(dynamicSchemas).map(([key, schema]) => asmDynamicKind(key, schema || {})).filter(kind => kind && supportedKinds.has(kind) && !String(kind).endsWith('_detail')))];
        const optionPayload = { options: {}, errors: {}, partial: false };
        await Promise.all(kinds.map(async kind => {
            try {
                const value = await asmApi(`/api/asm/resources/${encodeURIComponent(resource.id)}/task-options?kind=${encodeURIComponent(kind)}&page=1&page_size=100`);
                optionPayload.options[kind] = value.options;
            } catch (error) {
                optionPayload.partial = true;
                optionPayload.errors[kind] = error.message;
            }
        }));
        asmPageState.createProfile = profile;
        asmPageState.createOptionSets = optionPayload.options || {};
        renderASMTaskCreateProfile();
        if (optionPayload.partial && errorRoot) { errorRoot.style.display = ''; errorRoot.textContent = `部分实时选项未能读取：${Object.values(optionPayload.errors || {}).join('；')}`; }
    } catch (error) {
        if (root) root.innerHTML = `<div class="asm-result-empty error"><strong>平台能力读取失败</strong><span>${asmEscape(error.message)}</span></div>`;
    }
}

async function openASMTaskCreateModal() {
    await loadASMResources();
    const select = document.getElementById('asm-create-resource');
    const enabled = asmPageState.resources.filter(item => item.enabled);
    if (select) select.innerHTML = enabled.map(item => `<option value="${asmEscape(item.id)}">${asmEscape(item.name)} · ${asmEscape(asmProviderLabel(item.provider))}</option>`).join('');
    enhanceASMCreateSelects(select);
    syncASMCreateSelect(select);
    document.getElementById('asm-create-name').value = '';
    document.getElementById('asm-create-target').value = '';
    if (typeof openAppModal === 'function') openAppModal('asm-task-create-modal');
    else document.getElementById('asm-task-create-modal').style.display = 'flex';
    await loadASMTaskCreateProfile();
}

function closeASMTaskCreateModal() {
    closeASMCreateDropdowns();
    if (typeof closeAppModal === 'function') closeAppModal('asm-task-create-modal');
    else document.getElementById('asm-task-create-modal').style.display = 'none';
}

function collectASMTaskCreateOptions() {
    const profile = asmPageState.createProfile;
    const result = {};
    const templateSelected = !asmTemplateBuilderEnabled() && asmCreateHasValue(asmCreateFieldValue('template_id'));
    const mode = asmCreateFieldValue('task_mode') || 'direct';
    asmCreateSchemaEntries().forEach(([key, schema]) => {
        const field = document.querySelector(`[data-asm-create-field="${CSS.escape(key)}"]`);
        if (!field || field.hidden) return;
        if (profile.provider === 'scopesentry' && schema.mode === 'generated_low_load_template' && templateSelected) return;
        if (profile.provider === 'arl' && mode === 'policy' && !['task_mode', 'policy_id', 'task_tag', 'result_set_id'].includes(key)) return;
        const node = document.getElementById(`asm-create-option-${key}`);
        let value = asmCreateInputValue(node);
        if (schema.type === 'boolean') { result[key] = Boolean(value); return; }
        if (!asmCreateHasValue(value)) return;
        if (schema.type === 'integer') value = Number(value);
        if (schema.type === 'array' && !node.multiple) value = String(value).split(/[\n,]+/).map(item => item.trim()).filter(Boolean);
        if (schema.type === 'array' && schema.items?.type === 'integer') value = value.map(item => Number(item));
        if (schema.type === 'object') value = JSON.parse(String(value));
        result[key] = value;
    });
    if (profile.provider === 'arl' && mode === 'policy' && !result.policy_id) throw new Error('请选择要使用的 ARL 策略模板');
    if (templateSelected) {
        if (!asmPageState.createTemplateToken) throw new Error('请等待 ScopeSentry 模板详情核对完成');
        result.template_verification_token = asmPageState.createTemplateToken;
    }
    return result;
}

async function submitASMTaskCreate() {
    if (asmPageState.createLoading) return;
    const resource = asmCreateResource();
    const target = document.getElementById('asm-create-target')?.value.trim();
    const name = document.getElementById('asm-create-name')?.value.trim();
    const errorRoot = document.getElementById('asm-create-error');
    const submit = document.getElementById('asm-create-submit');
    if (!resource || !target) return;
    try {
        const templateRequest = collectASMTemplateCreateRequest(name);
        const options = collectASMTaskCreateOptions();
        asmPageState.createLoading = true;
        if (submit) { submit.disabled = true; submit.textContent = templateRequest ? '正在创建模板…' : '正在下发…'; }
        if (errorRoot) { errorRoot.style.display = 'none'; errorRoot.textContent = ''; }
        if (templateRequest) {
            const template = await asmApi(`/api/asm/resources/${encodeURIComponent(resource.id)}/templates`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(templateRequest) });
            options.template_id = template.template_id;
            options.template_verification_token = template.verification_token;
            if (template.capability_summary?.port_scope) options.required_port_scope = template.capability_summary.port_scope;
            options.required_capabilities = templateRequest.options.enabled_capabilities;
            if (submit) submit.textContent = '模板已创建，正在下发…';
        }
        const result = await asmApi(`/api/asm/resources/${encodeURIComponent(resource.id)}/tasks`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, target, options }) });
        closeASMTaskCreateModal();
        await loadASMTasks(true);
        const count = Number(result.history_recorded_count) || 1;
        if (typeof showNotification === 'function') showNotification(`ASM 任务已下发，记录 ${count} 个扫描子任务`, 'success');
    } catch (error) {
        if (errorRoot) { errorRoot.style.display = ''; errorRoot.textContent = error.message; }
    } finally {
        asmPageState.createLoading = false;
        if (submit) { submit.disabled = false; submit.textContent = '确认下发'; }
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
    if (action === 'templates') openASMTemplateLibrary(id);
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
window.openASMAgentContinuationModal = openASMAgentContinuationModal;
window.closeASMAgentContinuationModal = closeASMAgentContinuationModal;
window.loadASMAgentContinuationSettings = loadASMAgentContinuationSettings;
window.syncASMAgentContinuationForm = syncASMAgentContinuationForm;
window.resetASMAgentContinuationPrompts = resetASMAgentContinuationPrompts;
window.saveASMAgentContinuation = saveASMAgentContinuation;
window.openASMTemplateLibrary = openASMTemplateLibrary;
window.closeASMTemplateLibrary = closeASMTemplateLibrary;
window.loadASMTemplateLibrary = loadASMTemplateLibrary;
window.createASMTemplatePreset = createASMTemplatePreset;
window.createAllASMTemplatePresets = createAllASMTemplatePresets;
window.syncASMProviderForm = syncASMProviderForm;
window.syncASMAuthForm = syncASMAuthForm;
window.saveASMResource = saveASMResource;
window.loadASMTasks = loadASMTasks;
window.changeASMTaskPage = changeASMTaskPage;
window.openASMTaskModal = openASMTaskModal;
window.closeASMTaskModal = closeASMTaskModal;
window.syncSelectedASMTask = syncSelectedASMTask;
window.stopSelectedASMTask = stopSelectedASMTask;
window.syncSelectedASMTaskResults = syncSelectedASMTaskResults;
window.selectASMResultType = selectASMResultType;
window.loadSelectedASMResults = loadSelectedASMResults;
window.changeASMResultPage = changeASMResultPage;
window.changeASMResultPageSize = changeASMResultPageSize;
window.onASMResultDetailToggle = onASMResultDetailToggle;
window.syncSelectedASMScreenshots = syncSelectedASMScreenshots;
window.openASMTaskCreateModal = openASMTaskCreateModal;
window.closeASMTaskCreateModal = closeASMTaskCreateModal;
window.loadASMTaskCreateProfile = loadASMTaskCreateProfile;
window.onASMCreateOptionChange = onASMCreateOptionChange;
window.toggleASMTemplateBuilder = toggleASMTemplateBuilder;
window.inspectASMTemplateBase = inspectASMTemplateBase;
window.submitASMTaskCreate = submitASMTaskCreate;
