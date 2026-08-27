(function () {
    'use strict';

    const views = {
        chat: { conversationId: '', info: null, terminal: null, connectionFailed: false },
        conversation: { conversationId: '', info: null, terminal: null, connectionFailed: false },
    };
    let chatStatusGeneration = 0;
    let chatStatusTimer = null;
    let chatStatusPollAttempts = 0;

    function translate(key, fallback, values) {
        let value = typeof window.t === 'function' ? window.t(key, values || {}) : fallback;
        if (!value || value === key) value = fallback;
        Object.entries(values || {}).forEach(([name, replacement]) => {
            value = String(value).replaceAll(`{{${name}}}`, String(replacement));
        });
        return String(value);
    }

    function element(id) {
        return document.getElementById(id);
    }

    function terminalRoot(viewName) {
        return element(viewName === 'chat' ? 'chat-container-terminal-root' : 'conversation-container-terminal-root');
    }

    function terminalHeightHandle(viewName) {
        return element(viewName === 'chat' ? 'chat-container-terminal-height-handle' : 'conversation-container-terminal-height-handle');
    }

    function terminalDrawer(viewName) {
        return element(viewName === 'chat' ? 'chat-container-workspace-panel' : 'conversation-container-terminal-drawer');
    }

    function terminalDrawerBody(viewName) {
        const drawer = terminalDrawer(viewName);
        return drawer ? drawer.querySelector('.container-terminal-drawer-body') : null;
    }

    function fitTerminal(viewName) {
        const view = views[viewName];
        if (!view || !view.terminal || typeof view.terminal.fit !== 'function') return;
        try { view.terminal.fit(); } catch (error) {}
    }

    function scheduleTerminalFit(viewName) {
        requestAnimationFrame(() => fitTerminal(viewName));
    }

    function disposeTerminal(viewName) {
        const view = views[viewName];
        if (view && view.terminal) {
            view.terminal.dispose();
            view.terminal = null;
        }
        if (view) view.connectionFailed = false;
        const root = terminalRoot(viewName);
        const heightHandle = terminalHeightHandle(viewName);
        if (heightHandle) heightHandle.hidden = true;
        const drawerBody = terminalDrawerBody(viewName);
        if (drawerBody) drawerBody.classList.remove('has-terminal');
        if (root) {
            root.hidden = true;
            root.replaceChildren();
        }
    }

    function setStatus(viewName, message, tone) {
        const status = element(viewName === 'chat' ? 'chat-container-terminal-status' : 'conversation-container-terminal-status');
        if (!status) return;
        status.textContent = message;
        status.dataset.tone = tone || 'neutral';
    }

    function hostWorkspaceLabel(info) {
        if (info && info.hostPath) return String(info.hostPath);
        if (info && info.storage === 'tmpfs') {
            return translate('chat.hostWorkspaceTmpfs', 'Docker tmpfs（内存挂载，无宿主机目录）');
        }
        return '—';
    }

    function renderShellButton(viewName, available) {
        const prefix = viewName === 'chat' ? 'chat-container' : 'conversation-container';
        const button = element(`${prefix}-terminal-open`);
        const view = views[viewName];
        if (!button) return;
        let label;
        let title;
        if (!available) {
            label = translate('chat.containerShellUnavailableButton', '容器未运行，Shell 不可用');
            title = translate('chat.containerShellStopped', '容器未运行；仍可查看工作目录，但不能打开交互式 Shell。');
        } else if (view && view.terminal && view.connectionFailed) {
            label = translate('chat.reconnectContainerShell', '重新连接 Shell');
            title = label;
        } else if (view && view.terminal) {
            label = translate('chat.focusContainerShell', '聚焦终端');
            title = label;
        } else {
            label = translate('chat.openContainerShell', '打开交互式 Shell');
            title = label;
        }
        button.disabled = !available;
        button.setAttribute('aria-disabled', available ? 'false' : 'true');
        button.textContent = label;
        button.title = title;
    }

    function renderWorkspaceInfo(viewName, info) {
        const prefix = viewName === 'chat' ? 'chat-container' : 'conversation-container';
        const containerPath = element(`${prefix}-path`);
        const hostPath = element(`${prefix}-host-path`);
        if (containerPath) {
            containerPath.textContent = info && info.containerPath ? String(info.containerPath) : '—';
            containerPath.title = containerPath.textContent;
        }
        if (hostPath) {
            hostPath.textContent = hostWorkspaceLabel(info);
            hostPath.title = hostPath.textContent;
        }
        const available = !!(info && info.interactiveAvailable);
        if (viewName === 'chat' && info && info.runtimeStatus) {
            renderChatContainerState(String(info.runtimeStatus));
        }
        renderShellButton(viewName, available);
        setStatus(viewName, available
            ? translate('chat.containerShellReady', '容器运行中，可以打开交互式 Shell。')
            : translate('chat.containerShellStopped', '容器未运行；仍可查看工作目录，但不能打开交互式 Shell。'),
        available ? 'success' : 'neutral');
    }

    function chatContainerStatePresentation(rawState) {
        const state = String(rawState || '').trim().toLowerCase();
        if (state === 'running' || state === 'ready') {
            return { state: 'running', key: 'chat.containerStateRunning', fallback: '运行中' };
        }
        if (state === 'failed' || state === 'unavailable' || state === 'error') {
            return { state: 'failed', key: 'chat.containerStateFailed', fallback: '启动失败' };
        }
        if (state === 'stopped' || state === 'exited') {
            return { state: 'stopped', key: 'chat.containerStateStopped', fallback: '已停止' };
        }
        if (state === 'not_requested' || state === 'idle') {
            return { state: 'idle', key: 'chat.containerStateNotStarted', fallback: '未启动' };
        }
        return { state: 'starting', key: 'chat.containerStateStarting', fallback: '启动中' };
    }

    function renderChatContainerState(rawState) {
        const badge = element('chat-container-runtime-state');
        const label = element('chat-container-runtime-state-label');
        if (!badge || !label) return;
        const presentation = chatContainerStatePresentation(rawState);
        badge.className = `chat-container-runtime-state is-${presentation.state}`;
        badge.dataset.state = presentation.state;
        label.textContent = translate(presentation.key, presentation.fallback);
    }

    function clearChatContainerStatusPoll() {
        if (chatStatusTimer) window.clearTimeout(chatStatusTimer);
        chatStatusTimer = null;
    }

    function initializationState(payload, conversationId) {
        const initStatus = String(payload && payload.status || '').trim().toLowerCase();
        const readiness = String(payload && payload.readinessStatus || '').trim().toLowerCase();
        const runtimeStatus = String(payload && payload.runtimeStatus || '').trim().toLowerCase();
        const observedAgentStatus = String(payload && payload.observation && payload.observation.agent && payload.observation.agent.status || '').trim().toLowerCase();
        const taskStatus = typeof window.getConversationExecutionStatus === 'function'
            ? String(window.getConversationExecutionStatus(conversationId) || '').trim().toLowerCase()
            : '';
        if (initStatus === 'failed' || readiness === 'failed' || runtimeStatus === 'failed' || observedAgentStatus === 'failed') return 'failed';
        if (runtimeStatus === 'running' || observedAgentStatus === 'running') return 'running';
        // A ready runtime is necessarily usable by an already-running turn. This
        // closes the short persistence/event ordering window where chat output is
        // visible while the lightweight runtimeStatus field is still stale.
        if (taskStatus === 'running' && initStatus === 'created' && (readiness === 'ready' || readiness === 'not_required')) return 'running';
        if (initStatus === 'queued' || initStatus === 'creating' || readiness === 'pending' || readiness === 'validating' || taskStatus === 'initializing') return 'starting';
        if (runtimeStatus === 'stopped') return taskStatus === 'running' ? 'starting' : 'stopped';
        return 'starting';
    }

    async function refreshChatContainerState(conversationId, generation) {
        const id = String(conversationId || '').trim();
        if (!id || generation !== chatStatusGeneration) return;
        try {
            const taskStatus = typeof window.getConversationExecutionStatus === 'function'
                ? String(window.getConversationExecutionStatus(id) || '').trim().toLowerCase()
                : '';
            // While a turn is active, request one authoritative Docker observation.
            // The loop ends immediately once running is confirmed, so this does not
            // turn the normal 1-second lightweight poll into continuous Docker work.
            const observe = taskStatus === 'running' || taskStatus === 'initializing';
            const suffix = observe ? '?observe=1' : '';
            const response = await window.apiFetch(`/api/conversations/${encodeURIComponent(id)}/container-initialization${suffix}`);
            const payload = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(payload && payload.error ? String(payload.error) : `HTTP ${response.status}`);
            if (generation !== chatStatusGeneration || id !== String(window.currentConversationId || '').trim()) return;
            const nextState = initializationState(payload, id);
            renderChatContainerState(nextState);
            if (nextState === 'starting' && chatStatusPollAttempts < 120) {
                chatStatusPollAttempts += 1;
                clearChatContainerStatusPoll();
                chatStatusTimer = window.setTimeout(() => refreshChatContainerState(id, generation), 1000);
            }
        } catch (error) {
            // Keep the last known state. A transient status request must not
            // make a running/stopped badge flash back to "starting".
        }
    }

    function startChatContainerStatusSync(conversationId, showStarting) {
        clearChatContainerStatusPoll();
        chatStatusGeneration += 1;
        chatStatusPollAttempts = 0;
        const generation = chatStatusGeneration;
        if (showStarting !== false) renderChatContainerState('starting');
        refreshChatContainerState(conversationId, generation);
    }

    async function fetchWorkspaceInfo(conversationId) {
        const response = await window.apiFetch(`/api/conversations/${encodeURIComponent(conversationId)}/container/workspace`);
        let payload = null;
        try { payload = await response.json(); } catch (error) { payload = null; }
        if (!response.ok) throw new Error(payload && payload.error ? String(payload.error) : `HTTP ${response.status}`);
        return payload || {};
    }

    async function loadWorkspaceInfo(viewName, conversationId) {
        const view = views[viewName];
        const expected = String(conversationId || '').trim();
        if (!view || !expected) return null;
        view.conversationId = expected;
        view.info = null;
        disposeTerminal(viewName);
        const button = element(viewName === 'chat' ? 'chat-container-terminal-open' : 'conversation-container-terminal-open');
        if (button) {
            button.disabled = true;
            button.setAttribute('aria-disabled', 'true');
        }
        setStatus(viewName, translate('chat.containerWorkspaceLoading', '正在读取容器工作目录…'));
        try {
            const info = await fetchWorkspaceInfo(expected);
            if (view.conversationId !== expected) return null;
            view.info = info;
            renderWorkspaceInfo(viewName, info);
            return info;
        } catch (error) {
            if (view.conversationId !== expected) return null;
            renderWorkspaceInfo(viewName, null);
            setStatus(viewName, error && error.message
                ? error.message
                : translate('chat.containerWorkspaceLoadFailed', '读取容器工作目录失败。'), 'danger');
            return null;
        }
    }

    function terminalURL(conversationId) {
        const path = `/api/conversations/${encodeURIComponent(conversationId)}/container/terminal/ws`;
        if (!window.CyberStrikeTerminal || typeof window.CyberStrikeTerminal.buildAuthenticatedWSURL !== 'function') return '';
        return window.CyberStrikeTerminal.buildAuthenticatedWSURL(path);
    }

    function openShell(viewName) {
        const view = views[viewName];
        if (!view || !view.conversationId) return;
        if (!view.info || !view.info.interactiveAvailable) {
            setStatus(viewName,
                translate('chat.containerShellStopped', '容器未运行；仍可查看工作目录，但不能打开交互式 Shell。'),
                'neutral');
            return;
        }
        if (view.terminal && view.connectionFailed) {
            disposeTerminal(viewName);
        } else if (view.terminal) {
            renderShellButton(viewName, true);
            view.terminal.focus();
            return;
        }
        if (!window.CyberStrikeTerminal || typeof window.CyberStrikeTerminal.createEmbeddedTerminal !== 'function') {
            setStatus(viewName, translate('chat.containerTerminalUnavailable', '终端组件未加载，请刷新页面。'), 'danger');
            return;
        }
        const root = terminalRoot(viewName);
        if (!root) return;
        const heightHandle = terminalHeightHandle(viewName);
        if (heightHandle) heightHandle.hidden = false;
        const drawerBody = terminalDrawerBody(viewName);
        if (drawerBody) drawerBody.classList.add('has-terminal');
        root.hidden = false;
        const conversationId = view.conversationId;
        view.connectionFailed = false;
        view.terminal = window.CyberStrikeTerminal.createEmbeddedTerminal(root, {
            buildWSURL() { return terminalURL(conversationId); },
            tabLabel() { return translate('chat.containerTerminalTab', 'CyberStrikeAI'); },
            newTabTitle: translate('chat.newContainerTerminal', '新建容器终端'),
            welcomeLine: translate('chat.containerTerminalWelcome', 'CyberStrikeAI 容器终端 · 命令仅在当前对话容器中执行'),
            onConnectionState(state) {
                if (views[viewName].conversationId !== conversationId) return;
                if (state === 'open') {
                    views[viewName].connectionFailed = false;
                    renderShellButton(viewName, true);
                    setStatus(viewName, translate('chat.containerTerminalConnected', '已进入对话容器。'), 'success');
                } else if (state === 'error') {
                    views[viewName].connectionFailed = true;
                    renderShellButton(viewName, true);
                    setStatus(viewName, translate('chat.containerTerminalConnectionFailed', '容器终端连接失败。'), 'danger');
                } else if (state === 'closed' && views[viewName].terminal && !views[viewName].connectionFailed) {
                    views[viewName].connectionFailed = true;
                    renderShellButton(viewName, true);
                    setStatus(viewName, translate('chat.containerTerminalClosed', '容器终端会话已关闭。'), 'neutral');
                }
            },
        });
        renderShellButton(viewName, true);
        requestAnimationFrame(() => {
            if (view.terminal) {
                view.terminal.fit();
                view.terminal.focus();
            }
        });
    }

    let activeResize = null;

    function resizeBounds(axis, drawer, root) {
        if (axis === 'width') {
            return {
                min: Math.min(420, Math.max(300, window.innerWidth - 24)),
                max: Math.max(300, window.innerWidth - 24),
            };
        }
        const body = drawer ? drawer.querySelector('.container-terminal-drawer-body') : null;
        const bodyHeight = body ? body.getBoundingClientRect().height : window.innerHeight;
        return {
            min: Math.min(240, Math.max(180, bodyHeight - 126)),
            max: Math.max(180, bodyHeight - 126),
        };
    }

    function beginResize(event) {
        if (event.pointerType === 'mouse' && event.button !== 0) return;
        const handle = event.currentTarget;
        const viewName = String(handle.dataset.terminalView || '');
        const axis = String(handle.dataset.containerTerminalResize || '');
        const drawer = terminalDrawer(viewName);
        const root = terminalRoot(viewName);
        if (!drawer || (axis === 'height' && (!root || root.hidden))) return;
        if (axis === 'width' && window.matchMedia && window.matchMedia('(max-width: 760px)').matches) return;
        const rect = (axis === 'width' ? drawer : root).getBoundingClientRect();
        activeResize = {
            axis,
            drawer,
            handle,
            root,
            viewName,
            startX: event.clientX,
            startY: event.clientY,
            startSize: axis === 'width' ? rect.width : rect.height,
        };
        handle.classList.add('is-active');
        document.body.classList.add('is-resizing-container-terminal', `is-resizing-container-terminal-${axis}`);
        if (handle.setPointerCapture) {
            try { handle.setPointerCapture(event.pointerId); } catch (error) {}
        }
        event.preventDefault();
    }

    function continueResize(event) {
        if (!activeResize) return;
        const bounds = resizeBounds(activeResize.axis, activeResize.drawer, activeResize.root);
        const body = terminalDrawerBody(activeResize.viewName);
        const bodyRect = body ? body.getBoundingClientRect() : null;
        const rawSize = activeResize.axis === 'width'
            ? activeResize.startSize + activeResize.startX - event.clientX
            : (bodyRect ? bodyRect.bottom - event.clientY : activeResize.startSize + activeResize.startY - event.clientY);
        const size = Math.round(Math.min(bounds.max, Math.max(bounds.min, rawSize)));
        if (activeResize.axis === 'width') {
            activeResize.drawer.style.width = `${size}px`;
        } else {
            activeResize.root.style.flex = `0 0 ${size}px`;
            activeResize.root.style.height = `${size}px`;
        }
        activeResize.handle.setAttribute('aria-valuenow', String(size));
        scheduleTerminalFit(activeResize.viewName);
        event.preventDefault();
    }

    function endResize(event) {
        if (!activeResize) return;
        const { axis, handle, viewName } = activeResize;
        handle.classList.remove('is-active');
        if (handle.releasePointerCapture && event && event.pointerId !== undefined) {
            try { handle.releasePointerCapture(event.pointerId); } catch (error) {}
        }
        document.body.classList.remove('is-resizing-container-terminal', `is-resizing-container-terminal-${axis}`);
        activeResize = null;
        scheduleTerminalFit(viewName);
    }

    function resetResize(event) {
        const handle = event.currentTarget;
        const viewName = String(handle.dataset.terminalView || '');
        const axis = String(handle.dataset.containerTerminalResize || '');
        if (axis === 'width') {
            const drawer = terminalDrawer(viewName);
            if (drawer) drawer.style.removeProperty('width');
        } else {
            const root = terminalRoot(viewName);
            if (root) {
                root.style.removeProperty('flex');
                root.style.removeProperty('height');
            }
        }
        scheduleTerminalFit(viewName);
    }

    function initializeResizeHandles() {
        document.querySelectorAll('[data-container-terminal-resize]').forEach((handle) => {
            handle.addEventListener('pointerdown', beginResize);
            handle.addEventListener('dblclick', resetResize);
        });
        document.addEventListener('pointermove', continueResize, { passive: false });
        document.addEventListener('pointerup', endResize);
        document.addEventListener('pointercancel', endResize);
        window.addEventListener('resize', () => {
            scheduleTerminalFit('chat');
            scheduleTerminalFit('conversation');
        });
    }

    function closeChatContainerWorkspacePanel() {
        const panel = element('chat-container-workspace-panel');
        const button = element('chat-container-workspace-btn');
        if (panel) panel.hidden = true;
        if (button) button.setAttribute('aria-expanded', 'false');
        syncDrawerBodyState();
        disposeTerminal('chat');
    }

    function syncDrawerBodyState() {
        const chatDrawer = element('chat-container-workspace-panel');
        const conversationDrawer = element('conversation-container-terminal-drawer');
        const open = !!((chatDrawer && !chatDrawer.hidden) || (conversationDrawer && !conversationDrawer.hidden));
        document.body.classList.toggle('container-terminal-drawer-open', open);
    }

    async function toggleChatContainerWorkspacePanel() {
        const panel = element('chat-container-workspace-panel');
        const button = element('chat-container-workspace-btn');
        const conversationId = String(window.currentConversationId || '').trim();
        if (!panel || !button || !conversationId) return;
        if (!panel.hidden) {
            closeChatContainerWorkspacePanel();
            return;
        }
        const conversationDrawer = element('conversation-container-terminal-drawer');
        if (conversationDrawer && !conversationDrawer.hidden) closeConversationContainerTerminalDrawer();
        panel.hidden = false;
        button.setAttribute('aria-expanded', 'true');
        syncDrawerBodyState();
        await loadWorkspaceInfo('chat', conversationId);
    }

    function syncChatContainerWorkspaceButton() {
        const button = element('chat-container-workspace-btn');
        if (!button) return;
        const conversationId = String(window.currentConversationId || '').trim();
        const mode = String((element('runtime-mode-select') || {}).value || '').trim().toLowerCase();
        const visible = mode === 'container';
        const actionable = visible && !!conversationId;
        const conversationChanged = views.chat.conversationId !== conversationId;
        button.hidden = !visible;
        button.disabled = !actionable;
        button.setAttribute('aria-disabled', actionable ? 'false' : 'true');
        if (!visible || !actionable || (views.chat.conversationId && conversationChanged)) {
            closeChatContainerWorkspacePanel();
            views.chat.conversationId = conversationId;
            views.chat.info = null;
        }
        if (!visible) {
            clearChatContainerStatusPoll();
            chatStatusGeneration += 1;
        } else if (!actionable) {
            clearChatContainerStatusPoll();
            chatStatusGeneration += 1;
            renderChatContainerState('idle');
        } else if (conversationChanged || !views.chat.conversationId) {
            views.chat.conversationId = conversationId;
            startChatContainerStatusSync(conversationId, true);
        }
    }

    async function openConversationContainerTerminalDrawer(conversationId) {
        const id = String(conversationId || '').trim();
        const drawer = element('conversation-container-terminal-drawer');
        if (!id || !drawer) return;
        const chatDrawer = element('chat-container-workspace-panel');
        if (chatDrawer && !chatDrawer.hidden) closeChatContainerWorkspacePanel();
        drawer.hidden = false;
        syncDrawerBodyState();
        await loadWorkspaceInfo('conversation', id);
    }

    function closeConversationContainerTerminalDrawer() {
        const drawer = element('conversation-container-terminal-drawer');
        if (drawer) drawer.hidden = true;
        syncDrawerBodyState();
        disposeTerminal('conversation');
        views.conversation.conversationId = '';
        views.conversation.info = null;
    }

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            const chatDrawer = element('chat-container-workspace-panel');
            if (chatDrawer && !chatDrawer.hidden) closeChatContainerWorkspacePanel();
            const drawer = element('conversation-container-terminal-drawer');
            if (drawer && !drawer.hidden) closeConversationContainerTerminalDrawer();
        }
    });
    document.addEventListener('languagechange', () => {
        if (views.chat.info) renderWorkspaceInfo('chat', views.chat.info);
        if (views.conversation.info) renderWorkspaceInfo('conversation', views.conversation.info);
        const badge = element('chat-container-runtime-state');
        if (badge) renderChatContainerState(badge.dataset.state || 'starting');
    });
    window.addEventListener('conversation-changed', syncChatContainerWorkspaceButton);
    window.addEventListener('conversation-task-state-changed', () => {
        const id = String(window.currentConversationId || '').trim();
        if (id && String((element('runtime-mode-select') || {}).value || '').trim().toLowerCase() === 'container') {
            startChatContainerStatusSync(id, false);
        }
    });
    window.addEventListener('conversation-container-state-changed', (event) => {
        const detail = event && event.detail || {};
        const id = String(detail.conversationId || '').trim();
        if (!id || id !== String(window.currentConversationId || '').trim()) return;
        const runtimeStatus = String(detail.runtimeStatus || '').trim().toLowerCase();
        const state = runtimeStatus === 'running'
            ? 'running'
            : String(detail.state || runtimeStatus || '').trim().toLowerCase();
        renderChatContainerState(state === 'ready' ? 'running' : state);
        if (state === 'ready' || state === 'running' || state === 'failed' || state === 'unavailable') {
            clearChatContainerStatusPoll();
            chatStatusGeneration += 1;
        }
    });

    window.syncChatContainerWorkspaceButton = syncChatContainerWorkspaceButton;
    window.renderChatContainerState = renderChatContainerState;
    window.toggleChatContainerWorkspacePanel = toggleChatContainerWorkspacePanel;
    window.closeChatContainerWorkspacePanel = closeChatContainerWorkspacePanel;
    window.openChatContainerShell = function () { openShell('chat'); };
    window.openConversationContainerTerminalDrawer = openConversationContainerTerminalDrawer;
    window.closeConversationContainerTerminalDrawer = closeConversationContainerTerminalDrawer;
    window.openConversationContainerShell = function () { openShell('conversation'); };
    initializeResizeHandles();
    syncChatContainerWorkspaceButton();
})();
