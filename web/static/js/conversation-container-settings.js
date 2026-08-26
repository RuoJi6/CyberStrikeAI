(function () {
    'use strict';

    const state = {
        loadKey: '',
        requestId: 0,
        loaded: false,
        policies: [],
        proxies: [],
        groups: [],
        preview: null,
        errors: Object.create(null),
        auditSettingRequestId: 0,
        networkSettingRequestId: 0,
        activeNetworkSignature: '',
        loadingActiveNetwork: false,
        applyingNetwork: false,
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
        const options = [createOption('', translate('chat.boundaryPolicyDefaultAllow', '不设置边界（允许全部外部访问）'))];
        state.policies.forEach(function (policy) {
            if (!policy || !policy.id) return;
            const option = createOption(String(policy.id), String(policy.name || policy.id));
            option.dataset.description = String(policy.description || '');
            options.push(option);
        });
        if (state.errors.policies && !state.policies.length) {
            options.push(createOption('__unavailable__', translate('chat.boundaryPoliciesUnavailable', '边界策略不可用或无读取权限'), true));
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
            hint.textContent = translate('chat.boundaryPolicyDefaultAllowHint', '不选择草案时不限制外部网络目标、协议、端口或 HTTP 方法；Docker、宿主机与保留地址仍保持隔离。');
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
        };
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
        return [value.boundaryPolicyId, value.egressMode, value.egressProxyId, value.egressProxyGroupId, JSON.stringify(value.runtimeControls || {})].join('\u0000');
    }

    function applyActiveNetworkSettings(payload) {
        const boundary = selectElement('boundary-policy-select');
        const modeSelect = selectElement('conversation-egress-mode-select');
        const targetSelect = selectElement('conversation-egress-target-select');
        if (!boundary || !modeSelect) return;
        state.loadingActiveNetwork = true;
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
        const values = {
            'conversation-http-rate': controls.httpRequestsPerSecond || 20,
            'conversation-tcp-rate': controls.tcpConnectionsPerSecond || 20,
            'conversation-udp-rate': controls.udpDatagramsPerSecond || 20,
            'conversation-cpu-limit': controls.nanoCpus ? controls.nanoCpus / 1000000000 : ((payload.effectiveNanoCpus || 1000000000) / 1000000000),
            'conversation-memory-limit': controls.memoryBytes ? controls.memoryBytes / 1048576 : ((payload.effectiveMemoryBytes || 536870912) / 1048576),
        };
        Object.keys(values).forEach(function (id) { const element = selectElement(id); if (element) element.value = String(values[id]); });
        syncConversationRuntimeControls();
        state.activeNetworkSignature = networkSelectionSignature();
        state.loadingActiveNetwork = false;
    }

    async function loadActiveConversationNetworkSettings() {
        const conversationId = String(window.currentConversationId || '').trim();
        if (!conversationId) {
            state.activeNetworkSignature = '';
            return;
        }
        const requestId = ++state.networkSettingRequestId;
        state.loadingActiveNetwork = true;
        try {
            const payload = await fetchJSON('/api/conversations/' + encodeURIComponent(conversationId) + '/container/network-settings');
            if (requestId !== state.networkSettingRequestId || conversationId !== String(window.currentConversationId || '').trim()) return;
            applyActiveNetworkSettings(payload || {});
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
        const selection = currentNetworkSelection();
        try { validateRuntimeControls(selection.runtimeControls); } catch (error) { notify(error.message, 'error'); return false; }
        if (!state.activeNetworkSignature || networkSelectionSignature(selection) === state.activeNetworkSignature) return true;
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
        };
        if (selection.egressProxyId) body.egressProxyId = selection.egressProxyId;
        if (selection.egressProxyGroupId) body.egressProxyGroupId = selection.egressProxyGroupId;
        try {
            const response = await window.apiFetch('/api/conversations/' + encodeURIComponent(conversationId) + '/container/rebuild', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
            });
            const payload = await response.json().catch(function () { return {}; });
            if (!response.ok) throw new Error(payload && payload.error ? String(payload.error) : 'HTTP ' + response.status);
            await loadActiveConversationNetworkSettings();
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
            modeSelect.disabled = !enabled || !!saving;
            refreshEnhancedSelect(modeSelect);
        }
        if (!hint) return;
        if (saving) {
            hint.textContent = translate('chat.egressAuditSaving', '正在保存出站网络审计设置…');
            return;
        }
        hint.textContent = enabled
            ? (mode === 'full'
                ? translate('chat.egressAuditFullHint', '正在全量记录每条网络请求；高流量测试会产生较多审计数据。')
                : translate('chat.egressAuditHint', '默认聚合高频流量：保留首条完整记录并累计请求数量。'))
            : translate('chat.egressAuditDisabledHint', '已停止记录网络事件；容器生命周期事件仍会保留。');
    }

    async function loadConversationEgressAuditSetting() {
        const toggle = selectElement('conversation-egress-audit-toggle');
        const modeSelect = selectElement('conversation-egress-audit-mode');
        const conversationId = String(window.currentConversationId || '').trim();
        if (!toggle || !conversationId) return;
        const requestId = ++state.auditSettingRequestId;
        toggle.disabled = true;
        updateAuditHint(toggle.checked, true, modeSelect ? modeSelect.value : 'compact');
        try {
            const payload = await fetchJSON('/api/conversations/' + encodeURIComponent(conversationId) + '/egress-audit');
            if (requestId !== state.auditSettingRequestId || conversationId !== String(window.currentConversationId || '').trim()) return;
            toggle.checked = payload.enabled !== false;
            if (modeSelect) modeSelect.value = payload.mode === 'full' ? 'full' : 'compact';
            refreshEnhancedSelect(modeSelect);
            updateAuditHint(toggle.checked, false, modeSelect ? modeSelect.value : 'compact');
        } catch (error) {
            if (requestId === state.auditSettingRequestId) {
                updateAuditHint(toggle.checked, false, modeSelect ? modeSelect.value : 'compact');
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
            updateAuditHint(toggle.checked, false, modeSelect ? modeSelect.value : 'compact');
            return;
        }
        const requestId = ++state.auditSettingRequestId;
        toggle.disabled = true;
        const requestedMode = toggle.checked && modeSelect && modeSelect.value === 'full' ? 'full' : (toggle.checked ? 'compact' : 'off');
        updateAuditHint(toggle.checked, true, requestedMode);
        try {
            const response = await window.apiFetch('/api/conversations/' + encodeURIComponent(conversationId) + '/egress-audit', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: requestedMode }),
            });
            if (!response.ok) throw new Error('HTTP ' + response.status);
            const payload = await response.json();
            if (requestId !== state.auditSettingRequestId) return;
            toggle.checked = payload.enabled !== false;
            if (modeSelect && payload.mode !== 'off') modeSelect.value = payload.mode === 'full' ? 'full' : 'compact';
            refreshEnhancedSelect(modeSelect);
            updateAuditHint(toggle.checked, false, modeSelect ? modeSelect.value : 'compact');
            notify(toggle.checked
                ? translate('chat.egressAuditEnabled', '已开启出站网络审计。')
                : translate('chat.egressAuditDisabled', '已关闭出站网络审计。'), 'success');
        } catch (error) {
            if (requestId === state.auditSettingRequestId) {
                toggle.checked = !toggle.checked;
                updateAuditHint(toggle.checked, false, modeSelect ? modeSelect.value : 'compact');
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
        select.value = mode === 'full' ? 'full' : 'compact';
        toggle.checked = true;
        refreshEnhancedSelect(select);
        await syncConversationEgressAudit(true);
    }

    async function loadConversationContainerChoices(force) {
        const projectId = activeProjectId();
        const key = projectId || '__none__';
        if (!force && state.loaded && state.loadKey === key) {
            renderBoundaryOptions();
            renderEgressModeAvailability();
            setLoadStatus();
            if (String(window.currentConversationId || '').trim()) loadActiveConversationNetworkSettings();
            return;
        }
        const requestId = ++state.requestId;
        state.loadKey = key;
        state.loaded = false;
        state.errors = Object.create(null);
        setLoadStatus();
        if (String(window.currentConversationId || '').trim()) loadActiveConversationNetworkSettings();
        updateEgressPreview();
        const previewPath = '/api/egress-defaults/preview' + (projectId ? '?projectId=' + encodeURIComponent(projectId) : '');
        const results = await Promise.allSettled([
            fetchJSON('/api/boundary-policies'),
            fetchJSON('/api/egress-proxies?limit=100&offset=0'),
            fetchJSON('/api/egress-proxy-groups'),
            fetchJSON(previewPath),
        ]);
        if (requestId !== state.requestId) return;
        const names = ['policies', 'proxies', 'groups', 'preview'];
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
        setLoadStatus();
    }

    function syncConversationContainerControlsVisibility(runtimeMode) {
        const container = selectElement('container-conversation-options');
        if (!container) return;
        const visible = String(runtimeMode || '').trim().toLowerCase() === 'container';
        container.hidden = !visible;
        if (visible) {
            loadConversationContainerChoices(false);
            if (String(window.currentConversationId || '').trim()) loadConversationEgressAuditSetting();
        }
    }

    function setConversationContainerControlsLocked(locked) {
        state.taskLocked = !!locked;
        const container = selectElement('container-conversation-options');
        if (container) container.classList.toggle('locked', !!locked);
        const networkLocked = !!locked || state.applyingNetwork;
        ['boundary-policy-select', 'conversation-egress-mode-select', 'conversation-egress-target-select',
            'conversation-scan-rate-toggle', 'conversation-http-rate', 'conversation-tcp-rate', 'conversation-udp-rate',
            'conversation-resource-limit-toggle', 'conversation-cpu-limit', 'conversation-memory-limit'].forEach(function (id) {
            const control = selectElement(id);
            if (control) {
                control.disabled = networkLocked;
                refreshEnhancedSelect(control);
            }
        });
        if (locked && container && !container.hidden) loadConversationEgressAuditSetting();
    }

    function resetNewConversationContainerControls() {
        const boundary = selectElement('boundary-policy-select');
        const mode = selectElement('conversation-egress-mode-select');
        const auditToggle = selectElement('conversation-egress-audit-toggle');
        const auditMode = selectElement('conversation-egress-audit-mode');
        if (boundary) boundary.value = '';
        if (mode) mode.value = '';
        if (auditToggle) auditToggle.checked = true;
        if (auditMode) auditMode.value = 'compact';
        const rateToggle = selectElement('conversation-scan-rate-toggle');
        const resourceToggle = selectElement('conversation-resource-limit-toggle');
        if (rateToggle) rateToggle.checked = false;
        if (resourceToggle) resourceToggle.checked = false;
        refreshEnhancedSelect(boundary);
        refreshEnhancedSelect(mode);
        syncConversationBoundarySelection();
        syncConversationEgressMode();
        refreshEnhancedSelect(auditMode);
        updateAuditHint(true, false, 'compact');
        syncConversationRuntimeControls();
    }

    function readNewConversationContainerControls(runtimeMode) {
        if (String(runtimeMode || '').trim().toLowerCase() !== 'container') return {};
        const result = {};
        const auditToggle = selectElement('conversation-egress-audit-toggle');
        const auditMode = selectElement('conversation-egress-audit-mode');
        result.egressAuditEnabled = !auditToggle || auditToggle.checked;
        result.egressAuditMode = result.egressAuditEnabled && auditMode && auditMode.value === 'full' ? 'full' : (result.egressAuditEnabled ? 'compact' : 'off');
        result.runtimeControls = validateRuntimeControls(currentRuntimeControls());
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
    window.loadConversationContainerChoices = loadConversationContainerChoices;
    window.syncConversationContainerControlsVisibility = syncConversationContainerControlsVisibility;
    window.setConversationContainerControlsLocked = setConversationContainerControlsLocked;
    window.resetNewConversationContainerControls = resetNewConversationContainerControls;
    window.readNewConversationContainerControls = readNewConversationContainerControls;
    window.loadActiveConversationNetworkSettings = loadActiveConversationNetworkSettings;
    window.ensureConversationContainerNetworkSettings = ensureConversationContainerNetworkSettings;

    document.addEventListener('DOMContentLoaded', function () {
        syncConversationContainerControlsVisibility('host');
        setConversationContainerControlsLocked(!!window.currentConversationId);
        setLoadStatus();
    });

    document.addEventListener('languagechange', function () {
        renderBoundaryOptions();
        renderEgressModeAvailability();
        setLoadStatus();
    });
}());
