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

const containerManagementState = {
    rows: [],
    selectedConversationId: '',
    requestGeneration: 0,
    loading: false,
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
    if (['failed', 'error', 'unavailable', 'runtime_drift', 'provider_missing'].includes(value)) return 'danger';
    if (['queued', 'creating', 'pending', 'validating', 'in_progress'].includes(value)) return 'warning';
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

async function containerRuntimeRequestJSON(url) {
    const response = typeof window.apiFetch === 'function' ? await window.apiFetch(url) : await fetch(url);
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

async function containerRuntimeMapConcurrent(items, limit, mapper) {
    const results = new Array(items.length);
    let nextIndex = 0;
    async function worker() {
        while (nextIndex < items.length) {
            const index = nextIndex;
            nextIndex += 1;
            results[index] = await mapper(items[index], index);
        }
    }
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
    return results;
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

function containerRuntimeHasAttention(record) {
    return record.status === 'failed' || record.lifecycleState === 'failed' || Boolean(record.lastError || record.lifecycleError || record.readinessError || record.observationError);
}

function containerRuntimeRowTitle(record) {
    return record.conversationTitle || record.title || record.conversationId || containerManagementT('untitled', '未命名对话');
}

function containerRuntimePrimaryStatus(record) {
    return record.observation?.agent?.status || record.runtimeStatus || record.status || 'unknown';
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
    const rows = containerManagementState.rows;
    const running = rows.filter((record) => containerRuntimePrimaryStatus(record) === 'running').length;
    const gateways = rows.filter((record) => record.desired?.gatewayImageDigest).length;
    const persistent = rows.filter((record) => record.workspacePersistent || record.desired?.workspace?.persistent).length;
    const attention = rows.filter(containerRuntimeHasAttention).length;
    root.append(
        containerRuntimeSummaryCard(containerManagementT('summaryContainers', '对话容器'), rows.length),
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

function renderContainerRuntimeCompactList() {
    const root = document.getElementById('container-overview-runtime-list');
    if (!root) return;
    root.replaceChildren();
    const rows = containerManagementState.rows.slice(0, 8);
    if (!rows.length) {
        root.append(containerRuntimeEmpty(containerManagementT('empty', '暂无容器对话')));
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
        root.append(containerRuntimeEmpty(containerManagementT('empty', '暂无容器对话')));
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
    statusGrid.append(
        containerRuntimeDetailField(containerManagementT('agentContainer', 'Agent 容器'), containerRuntimeBadge(containerRuntimePrimaryStatus(record))),
        containerRuntimeDetailField(containerManagementT('egressGateway', '出站网关'), gatewayConfigured ? containerRuntimeBadge(record.observation?.gateway?.status || 'pending') : containerManagementT('notConfigured', '未配置')),
        containerRuntimeDetailField(containerManagementT('policyDNS', '策略 DNS'), containerRuntimeBadge(record.observation?.policyDnsStatus || (gatewayConfigured ? 'pending' : 'not_required'))),
        containerRuntimeDetailField(containerManagementT('workspace', '工作区'), containerRuntimeBadge(record.observation?.workspaceStatus || (record.status === 'created' ? 'ready' : 'pending'))),
    );
    root.append(statusGrid);

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

    const latestError = containerRuntimeLatestError(record);
    if (latestError) {
        const error = containerRuntimeElement('div', 'container-runtime-error');
        error.append(containerRuntimeElement('strong', '', containerManagementT('latestError', '最后错误')), containerRuntimeElement('p', '', latestError));
        root.append(error);
    }
}

function renderRuntimeEnvironments() {
    const root = document.getElementById('runtime-environments-list');
    if (!root) return;
    root.replaceChildren();
    if (!containerManagementState.rows.length) {
        root.append(containerRuntimeEmpty(containerManagementT('empty', '暂无容器对话')));
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

function renderContainerManagementData() {
    renderContainerRuntimeSummary();
    renderContainerRuntimeCompactList();
    renderConversationContainerList();
    renderConversationContainerDetail();
    renderRuntimeEnvironments();
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
    setContainerRuntimeLoadState(containerManagementT('loading', '正在加载容器状态…'));
    try {
        const list = await containerRuntimeRequestJSON('/api/conversations?limit=1000');
        const conversations = (Array.isArray(list) ? list : (list.conversations || list.items || []))
            .filter((conversation) => conversation && conversation.runtimeMode === 'container');
        const rows = await containerRuntimeMapConcurrent(conversations, 6, async (conversation) => {
            try {
                const status = await containerRuntimeRequestJSON(`/api/conversations/${encodeURIComponent(conversation.id)}/container-initialization`);
                return { ...conversation, ...status, conversationId: conversation.id, conversationTitle: status.conversationTitle || conversation.title };
            } catch (error) {
                return { ...conversation, conversationId: conversation.id, conversationTitle: conversation.title, status: 'unavailable', observationError: error && error.message ? error.message : 'load_failed' };
            }
        });
        if (generation !== containerManagementState.requestGeneration) return;
        containerManagementState.rows = rows;
        if (!rows.some((record) => record.conversationId === containerManagementState.selectedConversationId)) {
            containerManagementState.selectedConversationId = rows.find((record) => record.status === 'created')?.conversationId || rows[0]?.conversationId || '';
        }
        renderContainerManagementData();
        setContainerRuntimeLoadState(containerManagementT('loadedCount', '已加载 {{count}} 个对话容器', { count: rows.length }));
        await observeSelectedContainerRuntime(generation, containerManagementState.selectedConversationId);
    } catch (error) {
        if (generation !== containerManagementState.requestGeneration) return;
        containerManagementState.rows = [];
        renderContainerManagementData();
        setContainerRuntimeLoadState(error && error.message ? error.message : containerManagementT('loadFailed', '加载容器管理数据失败'), true);
    } finally {
        if (generation === containerManagementState.requestGeneration) {
            containerManagementState.loading = false;
            document.querySelectorAll('.container-runtime-refresh').forEach((button) => { button.disabled = false; });
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
    if (CONTAINER_RUNTIME_DATA_PAGES.has(pageId) && !containerManagementState.loading) refreshContainerManagementData();
}

window.CONTAINER_MANAGEMENT_PAGES = CONTAINER_MANAGEMENT_PAGES;
window.isContainerManagementPage = isContainerManagementPage;
window.initContainerManagementPage = initContainerManagementPage;
window.refreshContainerManagementData = refreshContainerManagementData;
window.selectContainerRuntimeConversation = selectContainerRuntimeConversation;
