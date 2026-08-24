const CONTAINER_MANAGEMENT_PAGES = Object.freeze([
    'container-overview',
    'conversation-containers',
    'runtime-environments',
    'boundary-rules',
    'egress-proxies',
    'network-activity',
    'egress-audit',
]);

const CONTAINER_RUNTIME_DATA_PAGES = new Set([
    'container-overview',
    'conversation-containers',
    'runtime-environments',
]);

const CONTAINER_RUNTIME_PAGE_SIZES = Object.freeze([10, 20, 50, 100]);
const CONTAINER_RUNTIME_FILTER_STATUSES = Object.freeze([
    'all',
    'not_requested',
    'pending',
    'running',
    'stopped',
    'failed',
]);
const CONTAINER_RUNTIME_URL_PARAMS = Object.freeze({
    page: 'container_page',
    pageSize: 'container_page_size',
    search: 'container_search',
    status: 'container_status',
});

function readContainerRuntimeURLState() {
    const fallback = { page: 1, pageSize: 20, search: '', status: 'all' };
    if (!window.location || typeof URLSearchParams === 'undefined') return fallback;
    const params = new URLSearchParams(window.location.search || '');
    const page = Number.parseInt(params.get(CONTAINER_RUNTIME_URL_PARAMS.page), 10);
    const pageSize = Number.parseInt(params.get(CONTAINER_RUNTIME_URL_PARAMS.pageSize), 10);
    const status = String(params.get(CONTAINER_RUNTIME_URL_PARAMS.status) || 'all').toLowerCase();
    return {
        page: Number.isInteger(page) && page > 0 ? page : fallback.page,
        pageSize: CONTAINER_RUNTIME_PAGE_SIZES.includes(pageSize) ? pageSize : fallback.pageSize,
        search: Array.from(String(params.get(CONTAINER_RUNTIME_URL_PARAMS.search) || '')).slice(0, 200).join(''),
        status: CONTAINER_RUNTIME_FILTER_STATUSES.includes(status) ? status : fallback.status,
    };
}

const initialContainerRuntimeURLState = readContainerRuntimeURLState();

const containerManagementState = {
    rows: [],
    boundaryPolicies: [],
    summary: { total: 0, running: 0, gateways: 0, persistent: 0, attention: 0 },
    selectedConversationId: '',
    requestGeneration: 0,
    loading: false,
    page: initialContainerRuntimeURLState.page,
    pageSize: initialContainerRuntimeURLState.pageSize,
    search: initialContainerRuntimeURLState.search,
    status: initialContainerRuntimeURLState.status,
    total: 0,
    totalPages: 0,
    controlsBound: false,
    searchTimer: null,
    loadError: '',
};

function containerManagementT(key, fallback, values = {}) {
    const fullKey = `containerManagement.${key}`;
    const translationOptions = { ...values, interpolation: { escapeValue: false } };
    let value = typeof window.t === 'function' ? window.t(fullKey, translationOptions) : fallback;
    if (!value || value === fullKey) value = fallback;
    return Object.entries(values).reduce((current, [name, replacement]) => (
        String(current).replaceAll(`{{${name}}}`, String(replacement))
    ), String(value));
}

function isContainerManagementPage(pageId) {
    return CONTAINER_MANAGEMENT_PAGES.includes(String(pageId || ''));
}

function containerRuntimeElement(tagName, className = '', value = '') {
    const element = document.createElement(tagName);
    if (className) element.className = className;
    if (value !== '') element.textContent = String(value);
    return element;
}

function containerRuntimeStatusTone(status) {
    const value = String(status || '').toLowerCase();
    if (['running', 'ready', 'created', 'healthy'].includes(value)) return 'success';
    if (['failed', 'error', 'unavailable', 'runtime_drift', 'provider_missing', 'paused'].includes(value)) return 'danger';
    if (['queued', 'creating', 'pending', 'validating', 'in_progress', 'cooldown'].includes(value)) return 'warning';
    return 'neutral';
}

function containerRuntimeStatusLabel(status) {
    const value = String(status || 'unknown');
    return containerManagementT(`status.${value}`, value);
}

function containerRuntimeBadge(status) {
    const badge = containerRuntimeElement('span', `container-runtime-badge is-${containerRuntimeStatusTone(status)}`);
    const dot = containerRuntimeElement('span', 'container-runtime-badge-dot');
    dot.setAttribute('aria-hidden', 'true');
    badge.append(dot, document.createTextNode(containerRuntimeStatusLabel(status)));
    return badge;
}

function containerRuntimeFormatBytes(raw) {
    const bytes = Number(raw || 0);
    if (!Number.isFinite(bytes) || bytes <= 0) return '—';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / (1024 ** index);
    return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

function containerRuntimeFormatDate(raw) {
    if (!raw) return '—';
    const date = new Date(raw);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleString();
}

function containerRuntimeShortHash(raw) {
    const value = String(raw || '').trim();
    if (!value) return '—';
    return value.length > 24 ? `${value.slice(0, 15)}…${value.slice(-8)}` : value;
}

async function containerRuntimeRequestJSON(url, options = {}) {
    const response = typeof window.apiFetch === 'function' ? await window.apiFetch(url, options) : await fetch(url, options);
    let payload = null;
    try {
        payload = await response.json();
    } catch (_) {
        payload = null;
    }
    if (!response.ok) {
        const message = payload && payload.error ? payload.error : containerManagementT('loadFailed', '加载容器管理数据失败');
        throw new Error(message);
    }
    return payload || {};
}

function setContainerRuntimeLoadState(message, error = false) {
    ['container-overview-load-state', 'conversation-containers-load-state', 'runtime-environments-load-state'].forEach((id) => {
        const element = document.getElementById(id);
        if (!element) return;
        element.textContent = message;
        element.classList.toggle('is-error', error);
    });
    document.querySelectorAll('.container-runtime-refresh').forEach((button) => {
        button.disabled = containerManagementState.loading;
    });
}

function containerRuntimeLoadedMessage() {
    const start = containerManagementState.total === 0 ? 0 : ((containerManagementState.page - 1) * containerManagementState.pageSize) + 1;
    const end = containerManagementState.rows.length
        ? Math.min(containerManagementState.total, start + containerManagementState.rows.length - 1)
        : 0;
    return containerManagementT('loadedRange', '显示 {{start}}–{{end}}，共 {{total}} 个对话容器', {
        start,
        end,
        total: containerManagementState.total,
    });
}

function containerRuntimeHasAttention(record) {
    return record.status === 'failed' || record.lifecycleState === 'failed' || ['cooldown', 'paused'].includes(record.egressHealth?.status)
        || Boolean(record.lastError || record.lifecycleError || record.readinessError || record.observationError);
}

function containerRuntimeRowTitle(record) {
    return record.conversationTitle || record.title || record.conversationId || containerManagementT('untitled', '未命名对话');
}

function containerRuntimeAgentStatus(record) {
    return record.observation?.agent?.status || record.runtimeStatus || record.status || 'unknown';
}

function containerRuntimePrimaryStatus(record) {
    const egressHealthStatus = String(record.egressHealth?.status || '').toLowerCase();
    if (egressHealthStatus === 'paused' || egressHealthStatus === 'cooldown') {
        return egressHealthStatus;
    }
    return containerRuntimeAgentStatus(record);
}

function containerRuntimeSummaryCard(label, value, tone = 'neutral') {
    const card = containerRuntimeElement('article', `container-runtime-summary-card is-${tone}`);
    card.append(
        containerRuntimeElement('span', 'container-runtime-summary-label', label),
        containerRuntimeElement('strong', 'container-runtime-summary-value', value),
    );
    return card;
}

function renderContainerRuntimeSummary() {
    const root = document.getElementById('container-overview-summary');
    if (!root) return;
    root.replaceChildren();
    const summary = containerManagementState.summary;
    const running = Number(summary.running || 0);
    const gateways = Number(summary.gateways || 0);
    const persistent = Number(summary.persistent || 0);
    const attention = Number(summary.attention || 0);
    root.append(
        containerRuntimeSummaryCard(containerManagementT('summaryContainers', '对话容器'), Number(summary.total || 0)),
        containerRuntimeSummaryCard(containerManagementT('summaryRunning', '运行中'), running, running ? 'success' : 'neutral'),
        containerRuntimeSummaryCard(containerManagementT('summaryGateways', '独立网关'), gateways),
        containerRuntimeSummaryCard(containerManagementT('summaryPersistent', '持久工作区'), persistent),
        containerRuntimeSummaryCard(containerManagementT('summaryAttention', '需要处理'), attention, attention ? 'danger' : 'success'),
    );
}

function containerRuntimeEmpty(value) {
    const empty = containerRuntimeElement('div', 'container-runtime-empty');
    empty.append(containerRuntimeElement('span', 'container-runtime-empty-icon', '◎'), containerRuntimeElement('p', '', value));
    return empty;
}

function containerRuntimeEmptyMessage() {
    if (containerManagementState.search || containerManagementState.status !== 'all') {
        return containerManagementT('emptyFiltered', '没有符合当前筛选条件的对话容器');
    }
    return containerManagementT('empty', '暂无容器对话');
}

function renderContainerRuntimeCompactList() {
    const root = document.getElementById('container-overview-runtime-list');
    if (!root) return;
    root.replaceChildren();
    const rows = containerManagementState.rows;
    if (!rows.length) {
        root.append(containerRuntimeEmpty(containerRuntimeEmptyMessage()));
        return;
    }
    rows.forEach((record) => {
        const row = containerRuntimeElement('button', 'container-runtime-compact-row');
        row.type = 'button';
        row.addEventListener('click', () => {
            containerManagementState.selectedConversationId = record.conversationId;
            if (typeof window.switchPage === 'function') window.switchPage('conversation-containers');
        });
        const title = containerRuntimeElement('span', 'container-runtime-row-title', containerRuntimeRowTitle(record));
        const meta = containerRuntimeElement('span', 'container-runtime-row-meta');
        meta.append(
            containerRuntimeBadge(containerRuntimePrimaryStatus(record)),
            containerRuntimeElement('span', '', record.workspacePersistent ? containerManagementT('persistent', '持久') : containerManagementT('temporary', '临时')),
            containerRuntimeElement('time', '', containerRuntimeFormatDate(record.updatedAt)),
        );
        row.append(title, meta);
        root.append(row);
    });
}

function renderConversationContainerList() {
    const root = document.getElementById('conversation-containers-list');
    if (!root) return;
    root.replaceChildren();
    if (!containerManagementState.rows.length) {
        root.append(containerRuntimeEmpty(containerRuntimeEmptyMessage()));
        return;
    }
    containerManagementState.rows.forEach((record) => {
        const selected = record.conversationId === containerManagementState.selectedConversationId;
        const button = containerRuntimeElement('button', `container-runtime-list-item${selected ? ' is-selected' : ''}`);
        button.type = 'button';
        button.setAttribute('role', 'option');
        button.setAttribute('aria-selected', selected ? 'true' : 'false');
        button.addEventListener('click', () => selectContainerRuntimeConversation(record.conversationId));
        const heading = containerRuntimeElement('span', 'container-runtime-list-heading');
        heading.append(containerRuntimeElement('strong', '', containerRuntimeRowTitle(record)), containerRuntimeBadge(containerRuntimePrimaryStatus(record)));
        const meta = containerRuntimeElement('span', 'container-runtime-list-meta');
        meta.append(
            containerRuntimeElement('span', '', record.desired?.imagePlatform || '—'),
            containerRuntimeElement('span', '', record.workspacePersistent ? containerManagementT('persistentWorkspace', '持久工作区') : containerManagementT('temporaryWorkspace', '临时工作区')),
        );
        button.append(heading, meta);
        root.append(button);
    });
}

function containerRuntimeDetailField(label, value, options = {}) {
    const field = containerRuntimeElement('div', `container-runtime-field${options.wide ? ' is-wide' : ''}`);
    field.append(containerRuntimeElement('dt', '', label));
    const content = containerRuntimeElement('dd');
    if (typeof Node !== 'undefined' && value instanceof Node) content.append(value);
    else content.textContent = String(value || '—');
    if (options.title) content.title = String(options.title);
    if (options.mono) content.classList.add('is-mono');
    field.append(content);
    return field;
}

function containerRuntimeResourceBlock(label, component, desired) {
    const block = containerRuntimeElement('article', 'container-runtime-resource-block');
    const heading = containerRuntimeElement('div', 'container-runtime-resource-heading');
    heading.append(containerRuntimeElement('h4', '', label), containerRuntimeBadge(component?.status || 'unknown'));
    const usage = component?.resources || {};
    const memory = usage.available
        ? `${containerRuntimeFormatBytes(usage.memoryUsageBytes)} / ${containerRuntimeFormatBytes(usage.memoryLimitBytes || desired?.memoryBytes)}`
        : containerManagementT('statsUnavailable', '统计暂不可用');
    const grid = containerRuntimeElement('dl', 'container-runtime-resource-grid');
    grid.append(
        containerRuntimeDetailField('CPU', usage.available ? `${Number(usage.cpuPercent || 0).toFixed(1)}%` : '—'),
        containerRuntimeDetailField(containerManagementT('memory', '内存'), memory),
        containerRuntimeDetailField('PIDs', usage.available ? usage.pids : '—'),
        containerRuntimeDetailField(containerManagementT('networkIO', '网络 I/O'), usage.available ? `↓ ${containerRuntimeFormatBytes(usage.networkRxBytes)}  ↑ ${containerRuntimeFormatBytes(usage.networkTxBytes)}` : '—'),
        containerRuntimeDetailField(containerManagementT('blockIO', '块 I/O'), usage.available ? `R ${containerRuntimeFormatBytes(usage.blockReadBytes)}  W ${containerRuntimeFormatBytes(usage.blockWriteBytes)}` : '—'),
        containerRuntimeDetailField(containerManagementT('limit', '限额'), desired ? `${containerRuntimeFormatBytes(desired.memoryBytes)} · ${desired.pids || '—'} PIDs` : '—'),
    );
    block.append(heading, grid);
    return block;
}

function selectedContainerRuntimeRecord() {
    return containerManagementState.rows.find((record) => record.conversationId === containerManagementState.selectedConversationId) || null;
}

function containerRuntimeLatestError(record) {
    return record.observation?.agent?.lastError || record.observation?.gateway?.lastError || record.lifecycleError || record.readinessError || record.lastError || record.observationError || '';
}

function renderConversationContainerDetail() {
    const root = document.getElementById('conversation-container-detail');
    if (!root) return;
    root.replaceChildren();
    const record = selectedContainerRuntimeRecord();
    if (!record) {
        root.append(containerRuntimeEmpty(containerManagementT('selectConversation', '选择一个对话查看运行时详情')));
        return;
    }
    const heading = containerRuntimeElement('div', 'container-runtime-detail-heading');
    const headingText = containerRuntimeElement('div');
    headingText.append(
        containerRuntimeElement('span', 'container-runtime-kicker', containerManagementT('liveObservation', '实时引擎观测')),
        containerRuntimeElement('h3', '', containerRuntimeRowTitle(record)),
        containerRuntimeElement('p', '', record.observation
            ? containerManagementT('observedAt', '观测于 {{time}}', { time: containerRuntimeFormatDate(record.observation.observedAt) })
            : containerManagementT('persistedState', '当前显示持久化状态')),
    );
    heading.append(headingText, containerRuntimeBadge(containerRuntimePrimaryStatus(record)));
    root.append(heading);

    const statusGrid = containerRuntimeElement('dl', 'container-runtime-status-grid');
    const gatewayConfigured = Boolean(record.desired?.gatewayImageDigest);
	const egressHealthStatus = record.egressHealth?.status || (gatewayConfigured ? 'healthy' : 'not_required');
    statusGrid.append(
        containerRuntimeDetailField(containerManagementT('agentContainer', 'Agent 容器'), containerRuntimeBadge(containerRuntimeAgentStatus(record))),
        containerRuntimeDetailField(containerManagementT('egressGateway', '出站网关'), gatewayConfigured ? containerRuntimeBadge(record.observation?.gateway?.status || 'pending') : containerManagementT('notConfigured', '未配置')),
        containerRuntimeDetailField(containerManagementT('policyDNS', '策略 DNS'), containerRuntimeBadge(record.observation?.policyDnsStatus || (gatewayConfigured ? 'pending' : 'not_required'))),
        containerRuntimeDetailField(containerManagementT('workspace', '工作区'), containerRuntimeBadge(record.observation?.workspaceStatus || (record.status === 'created' ? 'ready' : 'pending'))),
		containerRuntimeDetailField(containerManagementT('egressHealth', '出站健康'), containerRuntimeBadge(egressHealthStatus)),
    );
    root.append(statusGrid);

	if (gatewayConfigured && record.egressHealth && record.egressHealth.status !== 'healthy') {
		const health = containerRuntimeElement('section', `container-egress-health is-${containerRuntimeStatusTone(record.egressHealth.status)}`);
		const healthText = containerRuntimeElement('div');
		healthText.append(
			containerRuntimeElement('strong', '', containerManagementT('egressHealthAttention', '出站保护已触发')),
			containerRuntimeElement('p', '', containerManagementT(`healthSignal.${record.egressHealth.signal || 'unknown'}`, record.egressHealth.signal || '未知信号')),
		);
		if (record.egressHealth.cooldownUntil) {
			healthText.append(containerRuntimeElement('small', '', containerManagementT('cooldownUntil', '冷却至 {{time}}', {
				time: containerRuntimeFormatDate(record.egressHealth.cooldownUntil),
			})));
		}
		health.append(healthText);
		if (record.egressHealth.manualRecoveryRequired) {
			const recover = containerRuntimeElement('button', 'btn-secondary container-egress-health-recover', containerManagementT('recoverEgressHealth', '手动恢复'));
			recover.type = 'button';
			recover.addEventListener('click', () => recoverContainerEgressHealth(record.conversationId, recover));
			health.append(recover);
		}
		root.append(health);
	}

    if (record.observation) {
        const resources = containerRuntimeElement('div', 'container-runtime-resources');
        resources.append(containerRuntimeResourceBlock('Agent', record.observation.agent, record.desired?.resources));
        if (record.observation.gateway) resources.append(containerRuntimeResourceBlock(containerManagementT('gateway', '网关'), record.observation.gateway, record.desired?.gatewayResources));
        root.append(resources);
    }

    const metadata = containerRuntimeElement('dl', 'container-runtime-metadata');
    const agentDigest = record.observation?.agent?.imageDigest || record.desired?.imageDigest || record.imageDigest;
    const gatewayDigest = record.observation?.gateway?.imageDigest || record.desired?.gatewayImageDigest;
    metadata.append(
        containerRuntimeDetailField(containerManagementT('agentImage', 'Agent 镜像'), containerRuntimeShortHash(agentDigest), { mono: true, title: agentDigest }),
        containerRuntimeDetailField(containerManagementT('gatewayImage', '网关镜像'), containerRuntimeShortHash(gatewayDigest), { mono: true, title: gatewayDigest }),
        containerRuntimeDetailField(containerManagementT('platform', '平台'), record.desired?.imagePlatform || record.imagePlatform),
        containerRuntimeDetailField(containerManagementT('workspaceType', '工作区类型'), record.workspacePersistent ? containerManagementT('persistent', '持久') : containerManagementT('temporary', '临时')),
        containerRuntimeDetailField(containerManagementT('specDigest', '运行时规格 Hash'), containerRuntimeShortHash(record.desired?.specDigest), { mono: true, title: record.desired?.specDigest }),
        containerRuntimeDetailField(containerManagementT('snapshotHash', '边界快照 Hash'), containerRuntimeShortHash(record.desired?.boundarySnapshotSha256), { mono: true, title: record.desired?.boundarySnapshotSha256 }),
        containerRuntimeDetailField(containerManagementT('policyDNSAddress', '策略 DNS 地址'), record.observation?.policyDnsAddress || '—', { mono: true }),
        containerRuntimeDetailField(containerManagementT('readiness', '工具就绪'), containerRuntimeStatusLabel(record.readinessStatus || 'unknown')),
    );
    root.append(metadata);

    const policySwitch = containerRuntimeElement('section', 'container-boundary-policy-switch');
    const policyCopy = containerRuntimeElement('div', 'container-boundary-policy-switch-copy');
    policyCopy.append(
        containerRuntimeElement('strong', '', containerManagementT('activeBoundaryPolicy', '边界策略')),
        containerRuntimeElement('p', '', containerManagementT('boundaryPolicySwitchHint', '切换会重建当前容器、中断运行中任务，并为所选策略生成新的不可变快照。')),
    );
    const policyControls = containerRuntimeElement('div', 'container-boundary-policy-switch-controls');
    const policySelect = containerRuntimeElement('select', 'container-boundary-policy-select');
    policySelect.setAttribute('aria-label', containerManagementT('activeBoundaryPolicy', '边界策略'));
    policySelect.dataset.unifiedSelect = 'single';
    policySelect.dataset.unifiedSearch = 'true';
    const defaultOption = containerRuntimeElement('option', '', containerManagementT('noBoundaryPolicy', '不设置边界（允许全部外部访问）'));
    defaultOption.value = '';
    policySelect.append(defaultOption);
    containerManagementState.boundaryPolicies.forEach((policy) => {
        const option = containerRuntimeElement('option', '', policy.name || policy.id);
        option.value = String(policy.id || '');
        policySelect.append(option);
    });
    if (record.boundaryPolicyId && !containerManagementState.boundaryPolicies.some((policy) => policy.id === record.boundaryPolicyId)) {
        const currentOption = containerRuntimeElement('option', '', record.boundaryPolicyName || record.boundaryPolicyId);
        currentOption.value = String(record.boundaryPolicyId);
        policySelect.append(currentOption);
    }
    policySelect.value = String(record.boundaryPolicyId || '');
    const policyButton = containerRuntimeElement('button', 'btn-primary', containerManagementT('switchBoundaryPolicy', '切换策略并重建'));
    policyButton.type = 'button';
    policyButton.disabled = policySelect.value === String(record.boundaryPolicyId || '') || record.lifecycleState === 'in_progress';
    policySelect.addEventListener('change', () => {
        policyButton.disabled = policySelect.value === String(record.boundaryPolicyId || '') || record.lifecycleState === 'in_progress';
    });
    policyButton.addEventListener('click', () => switchConversationBoundaryPolicy(record, policySelect, policyButton));
    policyControls.append(policySelect, policyButton);
    policySwitch.append(policyCopy, policyControls);
    root.append(policySwitch);
    if (window.CyberStrikeSelect && typeof window.CyberStrikeSelect.refresh === 'function') window.CyberStrikeSelect.refresh(policySelect);

    if (record.status === 'created') {
        const workspaceActions = containerRuntimeElement('div', 'container-runtime-workspace-actions');
        const workspaceCopy = containerRuntimeElement('div');
        workspaceCopy.append(
            containerRuntimeElement('strong', '', containerManagementT('workspaceAndTerminal', '工作目录与交互式终端')),
            containerRuntimeElement('p', '', record.runtimeStatus === 'running'
                ? containerManagementT('workspaceTerminalReadyHint', '查看容器与宿主机工作目录，并进入当前容器执行交互式命令。')
                : containerManagementT('workspaceTerminalStoppedHint', '已停止的容器仍可查看工作目录，但不能打开交互式终端。')),
        );
        const workspaceButton = containerRuntimeElement('button', 'btn-secondary', containerManagementT('openWorkspaceTerminal', '查看工作区'));
        workspaceButton.type = 'button';
        workspaceButton.addEventListener('click', () => {
            if (typeof window.openConversationContainerTerminalDrawer === 'function') {
                window.openConversationContainerTerminalDrawer(record.conversationId);
            }
        });
        workspaceActions.append(workspaceCopy, workspaceButton);
        root.append(workspaceActions);
    }

    const latestError = containerRuntimeLatestError(record);
    if (latestError) {
        const error = containerRuntimeElement('div', 'container-runtime-error');
        error.append(containerRuntimeElement('strong', '', containerManagementT('latestError', '最后错误')), containerRuntimeElement('p', '', latestError));
        root.append(error);
    }
}

async function switchConversationBoundaryPolicy(record, select, button) {
    if (!record || !select || !button || button.disabled) return;
    const policyId = String(select.value || '');
    const selectedPolicy = containerManagementState.boundaryPolicies.find((policy) => policy.id === policyId);
    const policyName = selectedPolicy ? selectedPolicy.name : containerManagementT('noBoundaryPolicy', '不设置边界（允许全部外部访问）');
    if (!window.confirm(containerManagementT('boundaryPolicySwitchConfirm', '将对话“{{conversation}}”切换为“{{policy}}”？容器会重建，当前运行任务将被中断。', {
        conversation: containerRuntimeRowTitle(record), policy: policyName,
    }))) return;
    button.disabled = true;
    button.textContent = containerManagementT('switchingBoundaryPolicy', '正在切换…');
    try {
        await containerRuntimeRequestJSON(`/api/conversations/${encodeURIComponent(record.conversationId)}/container/rebuild`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ boundaryPolicyId: policyId }),
        });
        if (typeof window.showNotification === 'function') window.showNotification(containerManagementT('boundaryPolicySwitched', '边界策略已切换，容器已重建'), 'success');
        await refreshContainerManagementData();
    } catch (error) {
        button.disabled = false;
        button.textContent = containerManagementT('switchBoundaryPolicy', '切换策略并重建');
        if (typeof window.showNotification === 'function') window.showNotification(error.message || '切换边界策略失败', 'error');
    }
}

async function recoverContainerEgressHealth(conversationId, button) {
	if (!conversationId || !button || button.disabled) return;
	button.disabled = true;
	button.textContent = containerManagementT('recoveringEgressHealth', '正在恢复…');
	try {
		const state = await containerRuntimeRequestJSON(`/api/conversations/${encodeURIComponent(conversationId)}/egress-health/recover`, { method: 'POST' });
		const record = containerManagementState.rows.find((item) => item.conversationId === conversationId);
		if (record) {
			record.egressHealth = state;
			record.observationError = '';
		}
		renderContainerManagementData();
	} catch (error) {
		button.disabled = false;
		button.textContent = containerManagementT('recoverEgressHealth', '手动恢复');
		const record = containerManagementState.rows.find((item) => item.conversationId === conversationId);
		if (record) record.observationError = error && error.message ? error.message : 'recovery_failed';
		renderContainerManagementData();
	}
}

function renderRuntimeEnvironments() {
    const root = document.getElementById('runtime-environments-list');
    if (!root) return;
    root.replaceChildren();
    if (!containerManagementState.rows.length) {
        root.append(containerRuntimeEmpty(containerRuntimeEmptyMessage()));
        return;
    }
    containerManagementState.rows.forEach((record) => {
        const selected = record.conversationId === containerManagementState.selectedConversationId;
        const card = containerRuntimeElement('button', `container-environment-card${selected ? ' is-selected' : ''}`);
        card.type = 'button';
        card.addEventListener('click', () => selectContainerRuntimeConversation(record.conversationId));
        const heading = containerRuntimeElement('span', 'container-environment-heading');
        heading.append(containerRuntimeElement('strong', '', containerRuntimeRowTitle(record)), containerRuntimeBadge(containerRuntimePrimaryStatus(record)));
        const details = containerRuntimeElement('dl', 'container-environment-details');
        details.append(
            containerRuntimeDetailField(containerManagementT('platform', '平台'), record.desired?.imagePlatform || record.imagePlatform),
            containerRuntimeDetailField(containerManagementT('agentImage', 'Agent 镜像'), containerRuntimeShortHash(record.desired?.imageDigest || record.imageDigest), { mono: true }),
            containerRuntimeDetailField(containerManagementT('memoryLimit', '内存限额'), containerRuntimeFormatBytes(record.desired?.resources?.memoryBytes)),
            containerRuntimeDetailField(containerManagementT('workspaceLimit', '工作区限额'), containerRuntimeFormatBytes(record.desired?.workspace?.limitBytes)),
            containerRuntimeDetailField(containerManagementT('toolCount', '工具数'), record.toolCount || '—'),
            containerRuntimeDetailField(containerManagementT('readiness', '工具就绪'), containerRuntimeStatusLabel(record.readinessStatus || 'unknown')),
        );
        card.append(heading, details);
        root.append(card);
    });
}

function writeContainerRuntimeURLState() {
    if (!window.location || !window.history || typeof window.history.replaceState !== 'function' || typeof URLSearchParams === 'undefined') return;
    const params = new URLSearchParams(window.location.search || '');
    params.set(CONTAINER_RUNTIME_URL_PARAMS.page, String(containerManagementState.page));
    params.set(CONTAINER_RUNTIME_URL_PARAMS.pageSize, String(containerManagementState.pageSize));
    params.set(CONTAINER_RUNTIME_URL_PARAMS.status, containerManagementState.status);
    if (containerManagementState.search) params.set(CONTAINER_RUNTIME_URL_PARAMS.search, containerManagementState.search);
    else params.delete(CONTAINER_RUNTIME_URL_PARAMS.search);
    const search = params.toString();
    window.history.replaceState(window.history.state, '', `${window.location.pathname || ''}${search ? `?${search}` : ''}${window.location.hash || ''}`);
}

function syncContainerRuntimeControls() {
    document.querySelectorAll('[data-container-runtime-search]').forEach((input) => {
        if (input.value !== containerManagementState.search) input.value = containerManagementState.search;
    });
    document.querySelectorAll('[data-container-runtime-status]').forEach((select) => {
        if (select.value !== containerManagementState.status) select.value = containerManagementState.status;
        if (window.CyberStrikeSelect && typeof window.CyberStrikeSelect.refresh === 'function') window.CyberStrikeSelect.refresh(select);
    });
    document.querySelectorAll('[data-container-runtime-page-size]').forEach((select) => {
        const value = String(containerManagementState.pageSize);
        if (select.value !== value) select.value = value;
        if (window.CyberStrikeSelect && typeof window.CyberStrikeSelect.refresh === 'function') window.CyberStrikeSelect.refresh(select);
    });
}

function renderContainerRuntimePagination() {
    const totalPages = Math.max(1, Number(containerManagementState.totalPages || 0));
    const currentPage = Math.min(Math.max(1, containerManagementState.page), totalPages);
    const summary = containerManagementT('paginationSummary', '第 {{page}} / {{totalPages}} 页，共 {{total}} 条', {
        page: currentPage,
        totalPages,
        total: containerManagementState.total,
    });
    ['container-overview-pagination', 'conversation-containers-pagination', 'runtime-environments-pagination'].forEach((id) => {
        const root = document.getElementById(id);
        if (!root) return;
        root.replaceChildren();
        const previous = containerRuntimeElement('button', 'btn-secondary container-runtime-page-button', containerManagementT('paginationPrevious', '上一页'));
        previous.type = 'button';
        previous.disabled = containerManagementState.loading || currentPage <= 1 || containerManagementState.total === 0;
        previous.addEventListener('click', () => setContainerRuntimePage(currentPage - 1));
        const label = containerRuntimeElement('span', 'container-runtime-page-summary', summary);
        label.setAttribute('aria-live', 'polite');
        const next = containerRuntimeElement('button', 'btn-secondary container-runtime-page-button', containerManagementT('paginationNext', '下一页'));
        next.type = 'button';
        next.disabled = containerManagementState.loading || currentPage >= totalPages || containerManagementState.total === 0;
        next.addEventListener('click', () => setContainerRuntimePage(currentPage + 1));
        root.append(previous, label, next);
    });
}

function bindContainerRuntimeControls() {
    if (containerManagementState.controlsBound) return;
    containerManagementState.controlsBound = true;
    document.querySelectorAll('[data-container-runtime-search]').forEach((input) => {
        input.addEventListener('input', (event) => {
            const value = Array.from(String(event.target.value || '')).slice(0, 200).join('');
            containerManagementState.search = value;
            containerManagementState.page = 1;
            syncContainerRuntimeControls();
            writeContainerRuntimeURLState();
            if (containerManagementState.searchTimer) clearTimeout(containerManagementState.searchTimer);
            containerManagementState.searchTimer = setTimeout(() => {
                containerManagementState.searchTimer = null;
                refreshContainerManagementData();
            }, 300);
        });
    });
    document.querySelectorAll('[data-container-runtime-status]').forEach((select) => {
        select.addEventListener('change', (event) => {
            const value = String(event.target.value || 'all').toLowerCase();
            containerManagementState.status = CONTAINER_RUNTIME_FILTER_STATUSES.includes(value) ? value : 'all';
            containerManagementState.page = 1;
            syncContainerRuntimeControls();
            writeContainerRuntimeURLState();
            refreshContainerManagementData();
        });
    });
    document.querySelectorAll('[data-container-runtime-page-size]').forEach((select) => {
        select.addEventListener('change', (event) => {
            const value = Number.parseInt(event.target.value, 10);
            containerManagementState.pageSize = CONTAINER_RUNTIME_PAGE_SIZES.includes(value) ? value : 20;
            containerManagementState.page = 1;
            syncContainerRuntimeControls();
            writeContainerRuntimeURLState();
            refreshContainerManagementData();
        });
    });
    syncContainerRuntimeControls();
}

function setContainerRuntimePage(page) {
    const totalPages = Math.max(1, Number(containerManagementState.totalPages || 0));
    const nextPage = Math.min(Math.max(1, Number.parseInt(page, 10) || 1), totalPages);
    if (nextPage === containerManagementState.page && containerManagementState.rows.length) return;
    containerManagementState.page = nextPage;
    writeContainerRuntimeURLState();
    refreshContainerManagementData();
}

function renderContainerManagementData() {
    syncContainerRuntimeControls();
    renderContainerRuntimeSummary();
    renderContainerRuntimeCompactList();
    renderConversationContainerList();
    renderConversationContainerDetail();
    renderRuntimeEnvironments();
    renderContainerRuntimePagination();
}

async function observeSelectedContainerRuntime(generation, conversationId) {
    const record = containerManagementState.rows.find((item) => item.conversationId === conversationId);
    if (!record || record.status !== 'created') return;
    try {
        const observed = await containerRuntimeRequestJSON(`/api/conversations/${encodeURIComponent(conversationId)}/container-initialization?observe=1`);
        if (generation !== containerManagementState.requestGeneration || conversationId !== containerManagementState.selectedConversationId) return;
        Object.assign(record, observed);
    } catch (error) {
        if (generation !== containerManagementState.requestGeneration) return;
        record.observationError = error && error.message ? error.message : 'observation_failed';
    }
    renderContainerManagementData();
}

async function selectContainerRuntimeConversation(conversationId) {
    containerManagementState.selectedConversationId = String(conversationId || '');
    renderContainerManagementData();
    await observeSelectedContainerRuntime(containerManagementState.requestGeneration, containerManagementState.selectedConversationId);
}

async function refreshContainerManagementData() {
    const generation = containerManagementState.requestGeneration + 1;
    containerManagementState.requestGeneration = generation;
    containerManagementState.loading = true;
    containerManagementState.loadError = '';
    setContainerRuntimeLoadState(containerManagementT('loading', '正在加载容器状态…'));
    renderContainerRuntimePagination();
    try {
        const params = new URLSearchParams({
            page: String(containerManagementState.page),
            page_size: String(containerManagementState.pageSize),
            status: containerManagementState.status,
        });
        if (containerManagementState.search) params.set('search', containerManagementState.search);
        const results = await Promise.all([
            containerRuntimeRequestJSON(`/api/container-runtimes?${params.toString()}`),
            containerRuntimeRequestJSON('/api/boundary-policies?page=1&page_size=100').catch(() => ({ items: [] })),
        ]);
        const payload = results[0];
        if (generation !== containerManagementState.requestGeneration) return;
        const totalPages = Math.max(0, Number(payload.totalPages || 0));
        if (totalPages > 0 && containerManagementState.page > totalPages) {
            containerManagementState.page = totalPages;
            writeContainerRuntimeURLState();
            await refreshContainerManagementData();
            return;
        }
        const rows = Array.isArray(payload.items) ? payload.items : [];
        containerManagementState.rows = rows;
        containerManagementState.boundaryPolicies = Array.isArray(results[1].items) ? results[1].items : [];
        containerManagementState.summary = payload.summary || { total: 0, running: 0, gateways: 0, persistent: 0, attention: 0 };
        containerManagementState.total = Math.max(0, Number(payload.total || 0));
        containerManagementState.totalPages = totalPages;
        if (!rows.some((record) => record.conversationId === containerManagementState.selectedConversationId)) {
            containerManagementState.selectedConversationId = rows.find((record) => record.status === 'created')?.conversationId || rows[0]?.conversationId || '';
        }
        renderContainerManagementData();
        setContainerRuntimeLoadState(containerRuntimeLoadedMessage());
        await observeSelectedContainerRuntime(generation, containerManagementState.selectedConversationId);
    } catch (error) {
        if (generation !== containerManagementState.requestGeneration) return;
        containerManagementState.rows = [];
        containerManagementState.summary = { total: 0, running: 0, gateways: 0, persistent: 0, attention: 0 };
        containerManagementState.total = 0;
        containerManagementState.totalPages = 0;
        containerManagementState.loadError = error && error.message ? error.message : containerManagementT('loadFailed', '加载容器管理数据失败');
        renderContainerManagementData();
        setContainerRuntimeLoadState(containerManagementState.loadError, true);
    } finally {
        if (generation === containerManagementState.requestGeneration) {
            containerManagementState.loading = false;
            document.querySelectorAll('.container-runtime-refresh').forEach((button) => { button.disabled = false; });
            renderContainerRuntimePagination();
        }
    }
}

function initContainerManagementPage(pageId) {
    if (!isContainerManagementPage(pageId)) return;
    const page = document.getElementById(`page-${pageId}`);
    if (!page) return;

    document.querySelectorAll('[data-container-management-page]').forEach((candidate) => {
        candidate.removeAttribute('aria-current');
    });
    page.setAttribute('aria-current', 'page');
    page.dataset.initialized = 'true';
    window.currentContainerManagementPage = pageId;
    if (CONTAINER_RUNTIME_DATA_PAGES.has(pageId)) {
        bindContainerRuntimeControls();
        if (!containerManagementState.loading) refreshContainerManagementData();
    } else if (pageId === 'boundary-rules' && typeof window.initBoundaryRulesPage === 'function') {
        window.initBoundaryRulesPage();
    } else if (pageId === 'egress-proxies' && typeof window.initEgressManagementPage === 'function') {
        window.initEgressManagementPage();
    } else if (pageId === 'network-activity' && typeof window.initNetworkActivityPage === 'function') {
        window.initNetworkActivityPage();
    } else if (pageId === 'egress-audit' && typeof window.initEgressAuditPage === 'function') {
        window.initEgressAuditPage();
    }
}

window.CONTAINER_MANAGEMENT_PAGES = CONTAINER_MANAGEMENT_PAGES;
window.isContainerManagementPage = isContainerManagementPage;
window.initContainerManagementPage = initContainerManagementPage;
window.refreshContainerManagementData = refreshContainerManagementData;
window.selectContainerRuntimeConversation = selectContainerRuntimeConversation;
window.setContainerRuntimePage = setContainerRuntimePage;
window.recoverContainerEgressHealth = recoverContainerEgressHealth;

if (typeof document.addEventListener === 'function') {
    document.addEventListener('languagechange', () => {
        renderContainerManagementData();
        if (containerManagementState.loading) {
            setContainerRuntimeLoadState(containerManagementT('loading', '正在加载容器状态…'));
        } else if (containerManagementState.loadError) {
            setContainerRuntimeLoadState(containerManagementState.loadError, true);
        } else {
            setContainerRuntimeLoadState(containerRuntimeLoadedMessage());
        }
    });
}
