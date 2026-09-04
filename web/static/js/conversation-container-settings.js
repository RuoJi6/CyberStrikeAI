(function () {
    'use strict';

    const state = {
        loadKey: '',
        requestId: 0,
        loaded: false,
        policies: [],
        proxies: [],
        groups: [],
        workspaces: [],
        preview: null,
        errors: Object.create(null),
        auditSettingRequestId: 0,
        networkSettingRequestId: 0,
        activeNetworkSignature: '',
        activeNetworkPayload: null,
        loadingActiveNetwork: false,
        applyingNetwork: false,
        workspaceBindingRequestId: 0,
        loadingWorkspaceBinding: false,
        applyingWorkspace: false,
        idlePolicyRequestId: 0,
        loadingIdlePolicy: false,
        applyingIdlePolicy: false,
        taskLocked: false,
    };

    function translate(key, fallback, params) {
        if (typeof window.t === 'function') {
            const value = window.t(key, params || {});
            if (value && value !== key) return value;
        }
        return fallback;
    }

    function activeProjectId() {
        if (typeof window.getActiveProjectId === 'function') {
            return String(window.getActiveProjectId() || '').trim();
        }
        return '';
    }

    function selectElement(id) {
        return document.getElementById(id);
    }

    function refreshEnhancedSelect(select) {
        if (select && window.CyberStrikeSelect && typeof window.CyberStrikeSelect.refresh === 'function') {
            window.CyberStrikeSelect.refresh(select);
        }
    }

    function createOption(value, text, disabled) {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = text;
        option.disabled = !!disabled;
        return option;
    }

    function replaceOptions(select, options, preferredValue) {
        if (!select) return '';
        select.replaceChildren.apply(select, options);
        const preferred = String(preferredValue || '').trim();
        if (preferred && Array.prototype.some.call(select.options, function (option) {
            return option.value === preferred && !option.disabled;
        })) {
            select.value = preferred;
        } else {
            select.selectedIndex = 0;
        }
        refreshEnhancedSelect(select);
        return select.value;
    }

    function workspaceModeHint(mode) {
        if (mode === 'shared') {
            return translate('chat.workspacePersistenceHintShared', '共享工作区：多个容器对话共同读写同一个 Docker named volume');
        }
        if (mode === 'dedicated') {
            return translate('chat.workspacePersistenceHintPersistent', '持久工作区：使用该对话专属 Docker named volume');
        }
        return translate('chat.workspacePersistenceHintEphemeral', '临时工作区：/workspace 使用 Docker tmpfs 并占用容器内存；销毁容器后文件永久丢失');
    }

    function renderWorkspaceOptions(preferredValue) {
        const select = selectElement('conversation-shared-workspace-select');
        if (!select) return;
        const selected = preferredValue !== undefined ? preferredValue : select.value;
        const options = [];
        state.workspaces.forEach(function (workspace) {
            if (!workspace || !workspace.id) return;
            const count = Number(workspace.attachedConversations || 0);
            const suffix = count > 0
                ? translate('chat.sharedWorkspaceUseCountSuffix', ' · {{count}} 个对话', { count: count })
                : '';
            options.push(createOption(String(workspace.id), String(workspace.name || workspace.id) + suffix));
        });
        if (!options.length) {
            options.push(createOption('', state.errors.workspaces
                ? translate('chat.sharedWorkspacesUnavailable', '共享工作区不可用或无读取权限')
                : translate('chat.sharedWorkspaceEmpty', '暂无共享工作区，请先创建'), true));
        }
        replaceOptions(select, options, selected);
    }

    function applyWorkspaceModeToControls(mode, workspaceID) {
        const normalized = mode === 'shared' || mode === 'dedicated' ? mode : 'ephemeral';
        const modeSelect = selectElement('conversation-workspace-mode');
        const sharedField = selectElement('conversation-shared-workspace-field');
        const sharedSelect = selectElement('conversation-shared-workspace-select');
        const legacyToggle = selectElement('workspace-persistence-toggle');
        const hint = selectElement('workspace-persistence-hint');
        if (modeSelect) modeSelect.value = normalized;
        if (sharedField) sharedField.hidden = normalized !== 'shared';
        if (legacyToggle) legacyToggle.checked = normalized !== 'ephemeral';
        if (hint) hint.textContent = workspaceModeHint(normalized);
        if (sharedSelect && workspaceID) sharedSelect.value = String(workspaceID);
        refreshEnhancedSelect(modeSelect);
        refreshEnhancedSelect(sharedSelect);
    }

    function selectedWorkspaceBinding() {
        const modeSelect = selectElement('conversation-workspace-mode');
        const sharedSelect = selectElement('conversation-shared-workspace-select');
        const mode = String(modeSelect && modeSelect.value || 'dedicated').trim().toLowerCase();
        const normalized = mode === 'shared' || mode === 'dedicated' ? mode : 'ephemeral';
        const workspaceId = normalized === 'shared' ? String(sharedSelect && sharedSelect.value || '').trim() : '';
        if (normalized === 'shared' && !workspaceId) {
            throw new Error(translate('chat.sharedWorkspaceRequired', '请选择或创建一个共享工作区。'));
        }
        return { mode: normalized, workspaceId: workspaceId };
    }

    async function loadConversationWorkspaceBinding() {
        const conversationId = String(window.currentConversationId || '').trim();
        if (!conversationId) {
            applyWorkspaceModeToControls('dedicated', '');
            return;
        }
        const requestId = ++state.workspaceBindingRequestId;
        state.loadingWorkspaceBinding = true;
        try {
            const payload = await fetchJSON('/api/conversations/' + encodeURIComponent(conversationId) + '/workspace-binding');
            if (requestId !== state.workspaceBindingRequestId || conversationId !== String(window.currentConversationId || '').trim()) return;
            const binding = payload && payload.binding || {};
            const workspace = binding.workspace || {};
            if (workspace.id && !state.workspaces.some(function (item) { return item && item.id === workspace.id; }) && workspace.kind === 'shared') {
                state.workspaces.unshift(workspace);
                renderWorkspaceOptions(workspace.id);
            }
            applyWorkspaceModeToControls(binding.mode, workspace.id || '');
        } catch (error) {
            if (requestId === state.workspaceBindingRequestId) {
                notify(translate('chat.workspaceBindingLoadFailed', '读取当前工作区配置失败。'), 'error');
            }
        } finally {
            if (requestId === state.workspaceBindingRequestId) state.loadingWorkspaceBinding = false;
        }
    }

    async function applyConversationWorkspaceBinding() {
        const conversationId = String(window.currentConversationId || '').trim();
        if (!conversationId || state.loadingWorkspaceBinding) return true;
        if (state.taskLocked || state.applyingWorkspace) return false;
        let binding;
        try {
            binding = selectedWorkspaceBinding();
        } catch (error) {
            notify(error.message, 'error');
            return false;
        }
        state.applyingWorkspace = true;
        setConversationContainerControlsLocked(state.taskLocked);
        try {
            const response = await window.apiFetch('/api/conversations/' + encodeURIComponent(conversationId) + '/workspace-binding', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(binding),
            });
            const payload = await response.json().catch(function () { return {}; });
            if (!response.ok) throw new Error(payload && payload.error ? String(payload.error) : 'HTTP ' + response.status);
            await loadConversationWorkspaceBinding();
            window.dispatchEvent(new CustomEvent('conversation-container-state-changed', { detail: { conversationId: conversationId, state: 'stopped' } }));
            notify(translate('chat.workspaceBindingSaved', '工作区已切换，将在下次对话时自动生效。'), 'success');
            return true;
        } catch (error) {
            notify(translate('chat.workspaceBindingSaveFailed', '切换工作区失败：{{message}}', { message: error && error.message ? error.message : '' }), 'error');
            await loadConversationWorkspaceBinding();
            return false;
        } finally {
            state.applyingWorkspace = false;
            setConversationContainerControlsLocked(state.taskLocked);
        }
    }

    async function syncConversationWorkspaceMode(mode) {
        applyWorkspaceModeToControls(mode, '');
        if (String(window.currentConversationId || '').trim()) await applyConversationWorkspaceBinding();
    }

    async function syncConversationSharedWorkspace(value) {
        const select = selectElement('conversation-shared-workspace-select');
        if (select) select.value = String(value || '');
        if (String(window.currentConversationId || '').trim()) await applyConversationWorkspaceBinding();
    }

    async function createConversationSharedWorkspace() {
        if (state.taskLocked || state.applyingWorkspace) return;
        const input = selectElement('conversation-shared-workspace-name');
        const name = String(input && input.value || '').trim();
        if (!name) {
            notify(translate('chat.sharedWorkspaceNameRequired', '请输入共享工作区名称。'), 'error');
            return;
        }
        try {
            const response = await window.apiFetch('/api/container-workspaces', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: name, projectId: activeProjectId() }),
            });
            const workspace = await response.json().catch(function () { return {}; });
            if (!response.ok) throw new Error(workspace && workspace.error ? String(workspace.error) : 'HTTP ' + response.status);
            state.workspaces.unshift(workspace);
            renderWorkspaceOptions(workspace.id);
            applyWorkspaceModeToControls('shared', workspace.id);
            if (input) input.value = '';
            if (String(window.currentConversationId || '').trim()) await applyConversationWorkspaceBinding();
            else notify(translate('chat.sharedWorkspaceCreated', '共享工作区已创建。'), 'success');
        } catch (error) {
            notify(translate('chat.sharedWorkspaceCreateFailed', '创建共享工作区失败：{{message}}', { message: error && error.message ? error.message : '' }), 'error');
        }
    }

    function setLoadStatus() {
        const status = selectElement('container-conversation-options-status');
        if (!status) return;
        if (!state.loaded) {
            status.textContent = translate('chat.containerOptionsLoading', '正在加载…');
            status.dataset.state = 'loading';
            return;
        }
        const partial = Object.keys(state.errors).length > 0;
        status.textContent = partial
            ? translate('chat.containerOptionsPartial', '部分选项不可用')
            : translate('chat.containerOptionsReady', '已加载');
        status.dataset.state = partial ? 'partial' : 'ready';
    }

    function renderBoundaryOptions() {
        const select = selectElement('boundary-policy-select');
        if (!select) return;
        const selected = select.value;
        const options = [createOption('', translate('chat.boundaryPolicyDefaultAllow', '不设置边界（允许公网访问）'))];
        state.policies.forEach(function (policy) {
            if (!policy || !policy.id) return;
            const option = createOption(String(policy.id), String(policy.name || policy.id));
            option.dataset.description = String(policy.description || '');
            options.push(option);
        });
        if (state.errors.policies && !state.policies.length) {
            options.push(createOption('__unavailable__', translate('chat.boundaryPoliciesUnavailable', '边界策略不可用或无读取权限'), true));
        }
        const activePolicyId = String(state.activeNetworkPayload && state.activeNetworkPayload.boundaryPolicyId || '').trim();
        if (activePolicyId && !state.policies.some(function (policy) { return policy && String(policy.id) === activePolicyId; })) {
            const unavailable = createOption(activePolicyId, translate('chat.activeBoundaryPolicyUnavailable', '当前已激活策略（不可见）') + ' · ' + activePolicyId, true);
            unavailable.dataset.activeUnavailable = 'true';
            options.push(unavailable);
        }
        replaceOptions(select, options, selected);
        syncConversationBoundarySelection();
    }

    function enabledResources(items) {
        return (items || []).filter(function (item) {
            return item && item.id && item.enabled !== false;
        });
    }

    function renderEgressModeAvailability() {
        const select = selectElement('conversation-egress-mode-select');
        if (!select) return;
        const proxyOption = select.querySelector('option[value="proxy"]');
        const groupOption = select.querySelector('option[value="group"]');
        const proxiesAvailable = enabledResources(state.proxies).length > 0;
        const groupsAvailable = enabledResources(state.groups).length > 0;
        if (proxyOption) proxyOption.disabled = !proxiesAvailable;
        if (groupOption) groupOption.disabled = !groupsAvailable;
        if ((select.value === 'proxy' && !proxiesAvailable) || (select.value === 'group' && !groupsAvailable)) {
            select.value = '';
        }
        refreshEnhancedSelect(select);
        syncConversationEgressMode();
    }

    function sourceLabel(source) {
        if (source === 'project') return translate('chat.egressSourceProject', '项目默认值');
        if (source === 'user') return translate('chat.egressSourceUser', '用户默认值');
        return translate('chat.egressSourceNone', '无默认值');
    }

    function egressChoiceLabel(mode, proxy, group) {
        if (mode === 'proxy' && proxy) return String(proxy.name || proxy.id || '');
        if (mode === 'group' && group) return String(group.name || group.id || '');
        return translate('chat.egressModeNoneShort', '无上游代理');
    }

    function updateEgressPreview() {
        const preview = selectElement('conversation-egress-preview');
        const modeSelect = selectElement('conversation-egress-mode-select');
        if (!preview || !modeSelect) return;
        const mode = String(modeSelect.value || '').trim();
        if (mode) {
            const targetSelect = selectElement('conversation-egress-target-select');
            const targetText = targetSelect && targetSelect.selectedOptions[0]
                ? targetSelect.selectedOptions[0].textContent
                : '';
            const choice = mode === 'none'
                ? translate('chat.egressModeNoneShort', '无上游代理')
                : targetText;
            preview.textContent = translate('chat.egressExplicitPreview', '当前对话将显式使用：{{choice}}', { choice: choice });
            return;
        }
        if (state.errors.preview) {
            preview.textContent = translate('chat.egressPreviewUnavailable', '继承预览不可用；创建时仍由服务端安全解析默认值。');
            return;
        }
        if (!state.loaded || !state.preview) {
            preview.textContent = translate('chat.egressPreviewLoading', '正在读取当前继承结果…');
            return;
        }
        const choice = egressChoiceLabel(state.preview.mode, state.preview.proxy, state.preview.proxyGroup);
        preview.textContent = translate('chat.egressInheritedPreview', '当前继承：{{source}} · {{choice}}', {
            source: sourceLabel(state.preview.source),
            choice: choice,
        });
    }

    function syncConversationBoundarySelection() {
        const select = selectElement('boundary-policy-select');
        const hint = selectElement('boundary-policy-hint');
        if (!select || !hint) return;
        const selected = select.selectedOptions[0];
        if (!select.value) {
            hint.textContent = translate('chat.boundaryPolicyDefaultAllowHint', '不选择草案时不限制外部网络目标、协议、端口或 HTTP 方法；HTTPS 默认解密并完整审计，Docker、宿主机与保留地址仍保持隔离。');
            return;
        }
        const description = selected ? String(selected.dataset.description || '').trim() : '';
        hint.textContent = description || translate('chat.boundaryPolicySelectedHint', '首次启动时生成不可变策略快照，之后编辑草案不会改变本对话。');
    }

    function renderEgressTargets() {
        const modeSelect = selectElement('conversation-egress-mode-select');
        const targetSelect = selectElement('conversation-egress-target-select');
        const targetField = selectElement('conversation-egress-target-field');
        const targetLabel = selectElement('conversation-egress-target-label');
        if (!modeSelect || !targetSelect || !targetField || !targetLabel) return;
        const mode = String(modeSelect.value || '').trim();
        if (mode !== 'proxy' && mode !== 'group') {
            targetField.hidden = true;
            targetSelect.replaceChildren();
            refreshEnhancedSelect(targetSelect);
            updateEgressPreview();
            return;
        }
        const previous = targetSelect.value;
        const resources = enabledResources(mode === 'proxy' ? state.proxies : state.groups);
        const options = resources.map(function (resource) {
            let details = '';
            if (mode === 'proxy') {
                details = [resource.protocol, resource.host && resource.port ? resource.host + ':' + resource.port : resource.host]
                    .filter(Boolean).join(' · ');
            }
            const label = String(resource.name || resource.id) + (details ? ' — ' + details : '');
            return createOption(String(resource.id), label);
        });
        if (!options.length) {
            options.push(createOption('', mode === 'proxy'
                ? translate('chat.egressProxyEmpty', '没有可用代理')
                : translate('chat.egressGroupEmpty', '没有可用代理组'), true));
        }
        replaceOptions(targetSelect, options, previous);
        targetLabel.textContent = mode === 'proxy'
            ? translate('chat.egressProxyLabel', '选择代理')
            : translate('chat.egressGroupLabel', '选择代理组');
        targetLabel.setAttribute('data-i18n', mode === 'proxy' ? 'chat.egressProxyLabel' : 'chat.egressGroupLabel');
        targetField.hidden = false;
        updateEgressPreview();
    }

    function syncConversationEgressMode() {
        renderEgressTargets();
    }

    function syncConversationEgressTarget() {
        updateEgressPreview();
    }

    function currentNetworkSelection() {
        const boundary = selectElement('boundary-policy-select');
        const modeSelect = selectElement('conversation-egress-mode-select');
        const target = selectElement('conversation-egress-target-select');
        const mode = modeSelect ? String(modeSelect.value || '').trim() : '';
        return {
            boundaryPolicyId: boundary ? String(boundary.value || '').trim() : '',
            egressMode: mode,
            egressProxyId: mode === 'proxy' && target ? String(target.value || '').trim() : '',
            egressProxyGroupId: mode === 'group' && target ? String(target.value || '').trim() : '',
            runtimeControls: currentRuntimeControls(),
			networkAccess: currentNetworkAccess(),
        };
    }

	function currentNetworkAccess() {
		const toggle = selectElement('conversation-restricted-targets-toggle');
		return { allowRestrictedTargets: !!(toggle && toggle.checked) };
	}

    function numericValue(id, fallback) {
        const element = selectElement(id);
        const value = Number(element && element.value);
        return Number.isFinite(value) ? value : fallback;
    }

    function currentRuntimeControls() {
        const rateToggle = selectElement('conversation-scan-rate-toggle');
        const resourceToggle = selectElement('conversation-resource-limit-toggle');
        const scanRateEnabled = !!(rateToggle && rateToggle.checked);
        const customResourcesEnabled = !!(resourceToggle && resourceToggle.checked);
        return {
            scanRateEnabled: scanRateEnabled,
            httpRequestsPerSecond: scanRateEnabled ? Math.round(numericValue('conversation-http-rate', 0)) : 0,
            tcpConnectionsPerSecond: scanRateEnabled ? Math.round(numericValue('conversation-tcp-rate', 0)) : 0,
            udpDatagramsPerSecond: scanRateEnabled ? Math.round(numericValue('conversation-udp-rate', 0)) : 0,
            customResourcesEnabled: customResourcesEnabled,
            nanoCpus: customResourcesEnabled ? Math.round(numericValue('conversation-cpu-limit', 1) * 1000000000) : 0,
            memoryBytes: customResourcesEnabled ? Math.round(numericValue('conversation-memory-limit', 512) * 1048576) : 0,
        };
    }

    function validateRuntimeControls(value) {
        if (value.scanRateEnabled) {
            const rates = [value.httpRequestsPerSecond, value.tcpConnectionsPerSecond, value.udpDatagramsPerSecond];
            if (rates.some(function (rate) { return !Number.isInteger(rate) || rate < 0 || rate > 100000; }) || rates.every(function (rate) { return rate === 0; })) {
                throw new Error(translate('chat.scanRateInvalid', '启用速率限制后，请将至少一项设置为 1–100000。'));
            }
        }
        if (value.customResourcesEnabled && (value.nanoCpus < 250000000 || value.nanoCpus > 8000000000 || value.memoryBytes < 268435456 || value.memoryBytes > 17179869184)) {
            throw new Error(translate('chat.customResourcesInvalid', 'CPU 必须为 0.25–8 核，内存必须为 256–16384 MiB。'));
        }
        return value;
    }

    function syncConversationRuntimeControls() {
        const rateToggle = selectElement('conversation-scan-rate-toggle');
        const resourceToggle = selectElement('conversation-resource-limit-toggle');
        const rateFields = selectElement('conversation-scan-rate-fields');
        const resourceFields = selectElement('conversation-resource-limit-fields');
        if (rateFields) rateFields.hidden = !(rateToggle && rateToggle.checked);
        if (resourceFields) resourceFields.hidden = !(resourceToggle && resourceToggle.checked);
    }

    function networkSelectionSignature(selection) {
        const value = selection || currentNetworkSelection();
		return [value.boundaryPolicyId, value.egressMode, value.egressProxyId, value.egressProxyGroupId,
			JSON.stringify(value.runtimeControls || {}), JSON.stringify(value.networkAccess || {})].join('\u0000');
    }

    function activeNetworkSelection(payload) {
        const value = payload || {};
        const inherited = value.egressSource && value.egressSource !== 'conversation';
        const mode = inherited ? '' : String(value.egressMode || 'none').trim();
        return {
            boundaryPolicyId: String(value.boundaryPolicyId || '').trim(),
            egressMode: mode,
            egressProxyId: mode === 'proxy' ? String(value.egressProxyId || '').trim() : '',
            egressProxyGroupId: mode === 'group' ? String(value.egressProxyGroupId || '').trim() : '',
            runtimeControls: value.runtimeControls || {},
			networkAccess: value.networkAccess || { allowRestrictedTargets: false },
        };
    }

    function applyActiveNetworkSettings(payload) {
        const boundary = selectElement('boundary-policy-select');
        const modeSelect = selectElement('conversation-egress-mode-select');
        const targetSelect = selectElement('conversation-egress-target-select');
        if (!boundary || !modeSelect) return;
        state.loadingActiveNetwork = true;
        state.activeNetworkPayload = payload || {};
        renderBoundaryOptions();
        boundary.value = String(payload.boundaryPolicyId || '');
        const inherited = payload.egressSource && payload.egressSource !== 'conversation';
        modeSelect.value = inherited ? '' : String(payload.egressMode || 'none');
        refreshEnhancedSelect(boundary);
        refreshEnhancedSelect(modeSelect);
        renderEgressTargets();
        if (targetSelect && modeSelect.value === 'proxy') targetSelect.value = String(payload.egressProxyId || '');
        if (targetSelect && modeSelect.value === 'group') targetSelect.value = String(payload.egressProxyGroupId || '');
        refreshEnhancedSelect(targetSelect);
        syncConversationBoundarySelection();
        updateEgressPreview();
        const controls = payload.runtimeControls || {};
        const rateToggle = selectElement('conversation-scan-rate-toggle');
        const resourceToggle = selectElement('conversation-resource-limit-toggle');
        if (rateToggle) rateToggle.checked = controls.scanRateEnabled === true;
        if (resourceToggle) resourceToggle.checked = controls.customResourcesEnabled === true;
		const restrictedTargetsToggle = selectElement('conversation-restricted-targets-toggle');
		if (restrictedTargetsToggle) restrictedTargetsToggle.checked = !!(payload.networkAccess && payload.networkAccess.allowRestrictedTargets === true);
        const values = {
            'conversation-http-rate': controls.httpRequestsPerSecond || 20,
            'conversation-tcp-rate': controls.tcpConnectionsPerSecond || 20,
            'conversation-udp-rate': controls.udpDatagramsPerSecond || 20,
            'conversation-cpu-limit': controls.nanoCpus ? controls.nanoCpus / 1000000000 : ((payload.effectiveNanoCpus || 1000000000) / 1000000000),
            'conversation-memory-limit': controls.memoryBytes ? controls.memoryBytes / 1048576 : ((payload.effectiveMemoryBytes || 536870912) / 1048576),
        };
        Object.keys(values).forEach(function (id) { const element = selectElement(id); if (element) element.value = String(values[id]); });
        syncConversationRuntimeControls();
        state.activeNetworkSignature = networkSelectionSignature(activeNetworkSelection(payload));
        state.loadingActiveNetwork = false;
    }

    async function loadActiveConversationNetworkSettings() {
        const conversationId = String(window.currentConversationId || '').trim();
        if (!conversationId) {
            state.activeNetworkSignature = '';
            state.activeNetworkPayload = null;
            return;
        }
        const requestId = ++state.networkSettingRequestId;
        state.loadingActiveNetwork = true;
        try {
            const payload = await fetchJSON('/api/conversations/' + encodeURIComponent(conversationId) + '/container/network-settings');
            if (requestId !== state.networkSettingRequestId || conversationId !== String(window.currentConversationId || '').trim()) return;
            applyActiveNetworkSettings(payload || {});
            return payload || {};
        } catch (error) {
            if (requestId === state.networkSettingRequestId) notify(translate('chat.containerNetworkLoadFailed', '读取当前容器网络配置失败。'), 'error');
        } finally {
            if (requestId === state.networkSettingRequestId) {
                state.loadingActiveNetwork = false;
            }
        }
    }

    async function ensureConversationContainerNetworkSettings() {
        const conversationId = String(window.currentConversationId || '').trim();
        const runtimeMode = selectElement('runtime-mode-select');
        if (!conversationId || String(runtimeMode && runtimeMode.value || '').trim().toLowerCase() !== 'container') return true;
        if (state.taskLocked || state.applyingNetwork || state.loadingActiveNetwork) return false;
        if (!state.activeNetworkSignature) {
            const loaded = await loadActiveConversationNetworkSettings();
            if (!loaded || !state.activeNetworkSignature) {
                notify(translate('chat.containerNetworkLoadFailed', '读取当前容器网络配置失败，本次消息未发送。'), 'error');
                return false;
            }
        }
        const selection = currentNetworkSelection();
        try { validateRuntimeControls(selection.runtimeControls); } catch (error) { notify(error.message, 'error'); return false; }
        if (networkSelectionSignature(selection) === state.activeNetworkSignature) return true;
        if ((selection.egressMode === 'proxy' && !selection.egressProxyId) || (selection.egressMode === 'group' && !selection.egressProxyGroupId)) {
            notify(selection.egressMode === 'proxy'
                ? translate('chat.egressProxyRequired', '请选择可用代理。')
                : translate('chat.egressGroupRequired', '请选择可用代理组。'), 'error');
            return false;
        }
        state.applyingNetwork = true;
        setConversationContainerControlsLocked(state.taskLocked);
        notify(translate('chat.containerNetworkAutoApplying', '正在应用新的边界策略和上游出口…'), 'info');
        const body = {
            boundaryPolicyId: selection.boundaryPolicyId,
            egressMode: selection.egressMode,
            runtimeControls: selection.runtimeControls,
			networkAccess: selection.networkAccess,
        };
        const previousGeneration = Number(state.activeNetworkPayload && state.activeNetworkPayload.runtimeGeneration || 0);
        if (selection.egressProxyId) body.egressProxyId = selection.egressProxyId;
        if (selection.egressProxyGroupId) body.egressProxyGroupId = selection.egressProxyGroupId;
        try {
            const response = await window.apiFetch('/api/conversations/' + encodeURIComponent(conversationId) + '/container/rebuild', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
            });
            const payload = await response.json().catch(function () { return {}; });
            if (!response.ok) throw new Error(payload && payload.error ? String(payload.error) : 'HTTP ' + response.status);
            const active = await loadActiveConversationNetworkSettings();
            const activeSelection = activeNetworkSelection(active || {});
            const expectedPolicy = String(selection.boundaryPolicyId || '').trim();
            const activeGeneration = Number(active && active.runtimeGeneration || 0);
			if (activeSelection.boundaryPolicyId !== expectedPolicy ||
				!!activeSelection.networkAccess.allowRestrictedTargets !== !!selection.networkAccess.allowRestrictedTargets ||
                (!expectedPolicy && String(active && active.boundaryDefaultAction || '').trim().toLowerCase() !== 'allow') ||
                activeGeneration <= previousGeneration) {
                throw new Error(translate('chat.containerNetworkVerificationFailed', '容器已重建，但激活的边界快照未通过确认。'));
            }
            notify(translate('chat.containerNetworkAutoApplied', '新的边界策略和上游出口已应用。'), 'success');
            return true;
        } catch (error) {
            const fallback = translate('chat.containerNetworkAutoApplyFailed', '无法应用容器网络配置，本次消息未发送。');
            notify(error && error.message ? fallback + ' ' + error.message : fallback, 'error');
            return false;
        } finally {
            state.applyingNetwork = false;
            setConversationContainerControlsLocked(state.taskLocked);
        }
    }

    async function fetchJSON(path) {
        const response = await window.apiFetch(path);
        if (!response.ok) {
            const error = new Error('HTTP ' + response.status);
            error.status = response.status;
            throw error;
        }
        return response.json();
    }

    function notify(message, type) {
        if (typeof window.showNotification === 'function') window.showNotification(message, type || 'info');
    }

    function updateAuditHint(enabled, saving, mode) {
        const hint = selectElement('conversation-egress-audit-hint');
        const modeSelect = selectElement('conversation-egress-audit-mode');
        if (modeSelect) {
            modeSelect.disabled = !!saving;
            refreshEnhancedSelect(modeSelect);
        }
        if (!hint) return;
        if (saving) {
            hint.textContent = translate('chat.egressAuditSaving', '正在保存出站网络审计设置…');
            return;
        }
        hint.textContent = enabled
            ? translate('chat.egressAuditHint', '正在记录实时网络活动与持久审计；流量证据始终捕获。')
            : translate('chat.egressAuditDisabledHint', '已停止实时网络活动与持久审计；流量证据仍会捕获并使用所选聚合方式。');
    }

    async function loadConversationEgressAuditSetting() {
        const toggle = selectElement('conversation-egress-audit-toggle');
        const modeSelect = selectElement('conversation-egress-audit-mode');
        const conversationId = String(window.currentConversationId || '').trim();
        if (!toggle || !conversationId) return;
        const requestId = ++state.auditSettingRequestId;
        toggle.disabled = true;
        updateAuditHint(toggle.checked, true, modeSelect ? modeSelect.value : 'tools');
        try {
            const payload = await fetchJSON('/api/conversations/' + encodeURIComponent(conversationId) + '/egress-audit');
            if (requestId !== state.auditSettingRequestId || conversationId !== String(window.currentConversationId || '').trim()) return;
            toggle.checked = payload.enabled !== false;
            if (modeSelect) {
                modeSelect.value = ['all', 'tools', 'none'].includes(payload.aggregationMode) ? payload.aggregationMode : (payload.mode === 'full' ? 'none' : 'all');
                modeSelect.dataset.appliedValue = modeSelect.value;
            }
            refreshEnhancedSelect(modeSelect);
            updateAuditHint(toggle.checked, false, modeSelect ? modeSelect.value : 'tools');
        } catch (error) {
            if (requestId === state.auditSettingRequestId) {
                updateAuditHint(toggle.checked, false, modeSelect ? modeSelect.value : 'tools');
                notify(translate('chat.egressAuditLoadFailed', '读取出站网络审计设置失败。'), 'error');
            }
        } finally {
            if (requestId === state.auditSettingRequestId) toggle.disabled = false;
        }
    }

    async function syncConversationEgressAudit(enabled) {
        const toggle = selectElement('conversation-egress-audit-toggle');
        const modeSelect = selectElement('conversation-egress-audit-mode');
        const conversationId = String(window.currentConversationId || '').trim();
        if (!toggle) return;
        toggle.checked = !!enabled;
        if (!conversationId) {
            updateAuditHint(toggle.checked, false, modeSelect ? modeSelect.value : 'tools');
            return;
        }
        const requestId = ++state.auditSettingRequestId;
        toggle.disabled = true;
        const requestedMode = modeSelect && ['all', 'tools', 'none'].includes(modeSelect.value) ? modeSelect.value : 'tools';
        const previousEnabled = !toggle.checked;
        updateAuditHint(toggle.checked, true, requestedMode);
        try {
            const response = await window.apiFetch('/api/conversations/' + encodeURIComponent(conversationId) + '/egress-audit', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: toggle.checked, aggregationMode: requestedMode }),
            });
            if (!response.ok) throw new Error('HTTP ' + response.status);
            const payload = await response.json();
            if (requestId !== state.auditSettingRequestId) return;
            toggle.checked = payload.enabled !== false;
            if (modeSelect && ['all', 'tools', 'none'].includes(payload.aggregationMode)) modeSelect.value = payload.aggregationMode;
            refreshEnhancedSelect(modeSelect);
            updateAuditHint(toggle.checked, false, modeSelect ? modeSelect.value : 'tools');
            notify(toggle.checked
                ? translate('chat.egressAuditEnabled', '已开启出站网络审计。')
                : translate('chat.egressAuditDisabled', '已关闭出站网络审计。'), 'success');
        } catch (error) {
            if (requestId === state.auditSettingRequestId) {
                toggle.checked = previousEnabled;
                updateAuditHint(toggle.checked, false, modeSelect ? modeSelect.value : 'tools');
                notify(translate('chat.egressAuditSaveFailed', '保存出站网络审计设置失败。'), 'error');
            }
        } finally {
            if (requestId === state.auditSettingRequestId) toggle.disabled = false;
        }
    }

    async function syncConversationEgressAuditMode(mode) {
        const select = selectElement('conversation-egress-audit-mode');
        const toggle = selectElement('conversation-egress-audit-toggle');
        if (!select || !toggle) return;
        const previousMode = select.dataset.appliedValue || 'tools';
        select.value = ['all', 'tools', 'none'].includes(mode) ? mode : 'tools';
        refreshEnhancedSelect(select);
        const conversationId = String(window.currentConversationId || '').trim();
        if (!conversationId) {
            select.dataset.appliedValue = select.value;
            updateAuditHint(toggle.checked, false, select.value);
            return;
        }
        select.disabled = true;
        toggle.disabled = true;
        updateAuditHint(toggle.checked, true, select.value);
        try {
            const response = await window.apiFetch('/api/conversations/' + encodeURIComponent(conversationId) + '/egress-audit', {
                method: 'PUT', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: toggle.checked, aggregationMode: select.value }),
            });
            if (!response.ok) throw new Error('HTTP ' + response.status);
            const payload = await response.json();
            select.value = payload.aggregationMode;
            select.dataset.appliedValue = select.value;
            notify(translate('chat.egressAggregationApplied', '已立即应用于后续流量。'), 'success');
        } catch (error) {
            select.value = previousMode;
            notify(translate('chat.egressAggregationApplyFailed', '应用流量聚合方式失败，已恢复原选择。'), 'error');
        } finally {
            select.disabled = false;
            toggle.disabled = false;
            refreshEnhancedSelect(select);
            updateAuditHint(toggle.checked, false, select.value);
        }
    }

    function idlePolicyFromControls() {
        const actionSelect = selectElement('conversation-idle-action');
        const timeoutInput = selectElement('conversation-idle-timeout-minutes');
        const action = String(actionSelect && actionSelect.value || 'delete').trim().toLowerCase();
        const minutes = Math.round(Number(timeoutInput && timeoutInput.value || 30));
        if (!['delete', 'stop', 'none'].includes(action)) throw new Error(translate('chat.containerIdleActionInvalid', '空闲动作无效。'));
        if (!Number.isFinite(minutes) || minutes < 1 || minutes > 43200) throw new Error(translate('chat.containerIdleTimeoutInvalid', '空闲时间必须在 1 分钟到 30 天之间。'));
        return { action: action, timeoutSeconds: minutes * 60 };
    }

    function applyIdlePolicyToControls(policy) {
        const value = policy || { action: 'delete', timeoutSeconds: 1800 };
        const action = ['delete', 'stop', 'none'].includes(String(value.action)) ? String(value.action) : 'delete';
        const seconds = Math.max(60, Math.min(2592000, Number(value.timeoutSeconds || 1800)));
        const actionSelect = selectElement('conversation-idle-action');
        const timeoutInput = selectElement('conversation-idle-timeout-minutes');
        const timeoutField = selectElement('conversation-idle-timeout-field');
        const hint = selectElement('conversation-idle-policy-hint');
        if (actionSelect) actionSelect.value = action;
        if (timeoutInput) timeoutInput.value = String(Math.max(1, Math.round(seconds / 60)));
        if (timeoutField) timeoutField.hidden = action === 'none';
        if (hint) {
            hint.textContent = action === 'delete'
                ? translate('chat.containerIdleDeleteHint', '到期后销毁 Agent、网关和网络；专属/共享工作区仍保留，临时工作区会丢失。')
                : (action === 'stop'
                    ? translate('chat.containerIdleStopHint', '到期后停止容器；容器和工作区都会保留，可稍后手动启动。')
                    : translate('chat.containerIdleNoneHint', '该对话的容器不会因空闲而自动停止或销毁。'));
        }
        refreshEnhancedSelect(actionSelect);
    }

    async function loadConversationIdlePolicy() {
        const conversationId = String(window.currentConversationId || '').trim();
        if (!conversationId) {
            applyIdlePolicyToControls({ action: 'delete', timeoutSeconds: 1800 });
            return;
        }
        const requestId = ++state.idlePolicyRequestId;
        state.loadingIdlePolicy = true;
        try {
            const payload = await fetchJSON('/api/conversations/' + encodeURIComponent(conversationId) + '/container/idle-policy');
            if (requestId !== state.idlePolicyRequestId || conversationId !== String(window.currentConversationId || '').trim()) return;
            applyIdlePolicyToControls(payload && payload.idlePolicy);
        } catch (error) {
            if (requestId === state.idlePolicyRequestId) notify(translate('chat.containerIdleLoadFailed', '读取容器空闲策略失败。'), 'error');
        } finally {
            if (requestId === state.idlePolicyRequestId) state.loadingIdlePolicy = false;
        }
    }

    async function syncConversationIdlePolicy() {
        let policy;
        try {
            policy = idlePolicyFromControls();
        } catch (error) {
            notify(error.message, 'error');
            return false;
        }
        applyIdlePolicyToControls(policy);
        const conversationId = String(window.currentConversationId || '').trim();
        if (!conversationId || state.loadingIdlePolicy || state.applyingIdlePolicy) return true;
        state.applyingIdlePolicy = true;
        setConversationContainerControlsLocked(state.taskLocked);
        try {
            const response = await window.apiFetch('/api/conversations/' + encodeURIComponent(conversationId) + '/container/idle-policy', {
                method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(policy),
            });
            const payload = await response.json().catch(function () { return {}; });
            if (!response.ok) throw new Error(payload && payload.error ? String(payload.error) : 'HTTP ' + response.status);
            applyIdlePolicyToControls(payload.idlePolicy || policy);
            notify(translate('chat.containerIdleSaved', '容器空闲策略已更新。'), 'success');
            return true;
        } catch (error) {
            notify(translate('chat.containerIdleSaveFailed', '保存容器空闲策略失败：{{message}}', { message: error && error.message ? error.message : '' }), 'error');
            await loadConversationIdlePolicy();
            return false;
        } finally {
            state.applyingIdlePolicy = false;
            setConversationContainerControlsLocked(state.taskLocked);
        }
    }

    async function loadConversationContainerChoices(force) {
        const projectId = activeProjectId();
        const key = projectId || '__none__';
        if (!force && state.loaded && state.loadKey === key) {
            renderBoundaryOptions();
            renderEgressModeAvailability();
            renderWorkspaceOptions();
            setLoadStatus();
            if (String(window.currentConversationId || '').trim()) {
                await loadActiveConversationNetworkSettings();
                loadConversationWorkspaceBinding();
                loadConversationIdlePolicy();
            }
            return;
        }
        const requestId = ++state.requestId;
        state.loadKey = key;
        state.loaded = false;
        state.errors = Object.create(null);
        setLoadStatus();
        updateEgressPreview();
        const previewPath = '/api/egress-defaults/preview' + (projectId ? '?projectId=' + encodeURIComponent(projectId) : '');
        const results = await Promise.allSettled([
            fetchJSON('/api/boundary-policies'),
            fetchJSON('/api/egress-proxies?limit=100&offset=0'),
            fetchJSON('/api/egress-proxy-groups'),
            fetchJSON(previewPath),
            fetchJSON('/api/container-workspaces?project_id=' + encodeURIComponent(projectId) + '&page_size=100'),
        ]);
        if (requestId !== state.requestId) return;
        const names = ['policies', 'proxies', 'groups', 'preview', 'workspaces'];
        results.forEach(function (result, index) {
            const name = names[index];
            if (result.status === 'fulfilled') {
                if (name === 'preview') state.preview = result.value || null;
                else state[name] = Array.isArray(result.value && result.value.items) ? result.value.items : [];
            } else {
                state.errors[name] = result.reason || true;
                if (name === 'preview') state.preview = null;
                else state[name] = [];
            }
        });
        state.loaded = true;
        renderBoundaryOptions();
        renderEgressModeAvailability();
        renderWorkspaceOptions();
        setLoadStatus();
        if (String(window.currentConversationId || '').trim()) {
            await loadActiveConversationNetworkSettings();
            loadConversationWorkspaceBinding();
            loadConversationIdlePolicy();
        }
    }

    function syncConversationContainerControlsVisibility(runtimeMode) {
        const container = selectElement('container-conversation-options');
        if (!container) return;
        const visible = String(runtimeMode || '').trim().toLowerCase() === 'container';
        container.hidden = !visible;
        if (visible) {
            loadConversationContainerChoices(false);
        }
        if (String(window.currentConversationId || '').trim()) loadConversationEgressAuditSetting();
    }

    function setConversationContainerControlsLocked(locked) {
        state.taskLocked = !!locked;
        const container = selectElement('container-conversation-options');
        if (container) container.classList.toggle('locked', !!locked);
        const networkLocked = !!locked || state.applyingNetwork;
        ['boundary-policy-select', 'conversation-egress-mode-select', 'conversation-egress-target-select',
            'conversation-restricted-targets-toggle',
            'conversation-scan-rate-toggle', 'conversation-http-rate', 'conversation-tcp-rate', 'conversation-udp-rate',
            'conversation-resource-limit-toggle', 'conversation-cpu-limit', 'conversation-memory-limit'].forEach(function (id) {
            const control = selectElement(id);
            if (control) {
                control.disabled = networkLocked;
                refreshEnhancedSelect(control);
            }
        });
        const workspaceLocked = !!locked || state.applyingWorkspace;
        ['conversation-workspace-mode', 'conversation-shared-workspace-select', 'conversation-shared-workspace-name'].forEach(function (id) {
            const control = selectElement(id);
            if (control) {
                control.disabled = workspaceLocked;
                refreshEnhancedSelect(control);
            }
        });
        const workspaceCreate = selectElement('conversation-shared-workspace-create');
        if (workspaceCreate) workspaceCreate.disabled = workspaceLocked;
        ['conversation-idle-action', 'conversation-idle-timeout-minutes'].forEach(function (id) {
            const control = selectElement(id);
            if (control) control.disabled = state.applyingIdlePolicy;
            refreshEnhancedSelect(control);
        });
        if (locked && String(window.currentConversationId || '').trim()) loadConversationEgressAuditSetting();
    }

    function resetNewConversationContainerControls() {
        const boundary = selectElement('boundary-policy-select');
        const mode = selectElement('conversation-egress-mode-select');
        const auditToggle = selectElement('conversation-egress-audit-toggle');
        const auditMode = selectElement('conversation-egress-audit-mode');
        if (boundary) boundary.value = '';
        if (mode) mode.value = '';
        if (auditToggle) auditToggle.checked = true;
        if (auditMode) {
            auditMode.value = 'tools';
            auditMode.dataset.appliedValue = 'tools';
        }
        const rateToggle = selectElement('conversation-scan-rate-toggle');
        const resourceToggle = selectElement('conversation-resource-limit-toggle');
        if (rateToggle) rateToggle.checked = false;
        if (resourceToggle) resourceToggle.checked = false;
		const restrictedTargetsToggle = selectElement('conversation-restricted-targets-toggle');
		if (restrictedTargetsToggle) restrictedTargetsToggle.checked = false;
        applyWorkspaceModeToControls('dedicated', '');
        applyIdlePolicyToControls({ action: 'delete', timeoutSeconds: 1800 });
        refreshEnhancedSelect(boundary);
        refreshEnhancedSelect(mode);
        syncConversationBoundarySelection();
        syncConversationEgressMode();
        refreshEnhancedSelect(auditMode);
        updateAuditHint(true, false, 'tools');
        syncConversationRuntimeControls();
    }

    function readNewConversationContainerControls(runtimeMode) {
        const result = {};
        const auditToggle = selectElement('conversation-egress-audit-toggle');
        const auditMode = selectElement('conversation-egress-audit-mode');
        result.egressAuditEnabled = !auditToggle || auditToggle.checked;
        result.egressAggregationMode = auditMode && ['all', 'tools', 'none'].includes(auditMode.value) ? auditMode.value : 'tools';
        if (String(runtimeMode || '').trim().toLowerCase() !== 'container') return result;
        const workspace = selectedWorkspaceBinding();
        result.workspaceMode = workspace.mode;
        result.workspacePersistent = workspace.mode !== 'ephemeral';
        if (workspace.mode === 'shared') result.workspaceId = workspace.workspaceId;
        result.idlePolicy = idlePolicyFromControls();
        result.runtimeControls = validateRuntimeControls(currentRuntimeControls());
        result.networkAccess = currentNetworkAccess();
        const boundary = selectElement('boundary-policy-select');
        const boundaryPolicyId = boundary ? String(boundary.value || '').trim() : '';
        if (boundaryPolicyId) result.boundaryPolicyId = boundaryPolicyId;

        const modeSelect = selectElement('conversation-egress-mode-select');
        const mode = modeSelect ? String(modeSelect.value || '').trim() : '';
        if (!mode) return result;
        result.egressMode = mode;
        if (mode === 'proxy' || mode === 'group') {
            const target = selectElement('conversation-egress-target-select');
            const targetId = target ? String(target.value || '').trim() : '';
            if (!targetId) {
                throw new Error(mode === 'proxy'
                    ? translate('chat.egressProxyRequired', '请选择可用代理。')
                    : translate('chat.egressGroupRequired', '请选择可用代理组。'));
            }
            if (mode === 'proxy') result.egressProxyId = targetId;
            else result.egressProxyGroupId = targetId;
        }
        return result;
    }

    window.syncConversationBoundarySelection = syncConversationBoundarySelection;
    window.syncConversationEgressMode = syncConversationEgressMode;
    window.syncConversationEgressTarget = syncConversationEgressTarget;
    window.syncConversationEgressAudit = syncConversationEgressAudit;
    window.syncConversationEgressAuditMode = syncConversationEgressAuditMode;
    window.syncConversationRuntimeControls = syncConversationRuntimeControls;
    window.syncConversationIdlePolicy = syncConversationIdlePolicy;
    window.syncConversationWorkspaceMode = syncConversationWorkspaceMode;
    window.syncConversationSharedWorkspace = syncConversationSharedWorkspace;
    window.createConversationSharedWorkspace = createConversationSharedWorkspace;
    window.loadConversationWorkspaceBinding = loadConversationWorkspaceBinding;
    window.loadConversationContainerChoices = loadConversationContainerChoices;
    window.syncConversationContainerControlsVisibility = syncConversationContainerControlsVisibility;
    window.setConversationContainerControlsLocked = setConversationContainerControlsLocked;
    window.resetNewConversationContainerControls = resetNewConversationContainerControls;
    window.readNewConversationContainerControls = readNewConversationContainerControls;
    window.loadActiveConversationNetworkSettings = loadActiveConversationNetworkSettings;
    window.ensureConversationContainerNetworkSettings = ensureConversationContainerNetworkSettings;

    document.addEventListener('DOMContentLoaded', function () {
        syncConversationContainerControlsVisibility('host');
        applyWorkspaceModeToControls('dedicated', '');
        applyIdlePolicyToControls({ action: 'delete', timeoutSeconds: 1800 });
        setConversationContainerControlsLocked(false);
        setLoadStatus();
    });

    document.addEventListener('languagechange', function () {
        renderBoundaryOptions();
        renderEgressModeAvailability();
        setLoadStatus();
    });
}());
