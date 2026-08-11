const asmPageState = {
    resources: [],
    providers: [],
    editId: '',
    loading: false,
    busyIds: new Set(),
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

window.initASMResourcesPage = initASMResourcesPage;
window.loadASMResources = loadASMResources;
window.openASMResourceModal = openASMResourceModal;
window.closeASMResourceModal = closeASMResourceModal;
window.syncASMProviderForm = syncASMProviderForm;
window.syncASMAuthForm = syncASMAuthForm;
window.saveASMResource = saveASMResource;
