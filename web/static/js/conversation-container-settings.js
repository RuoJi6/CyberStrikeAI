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
        const options = [createOption('', translate('chat.boundaryPolicyDefaultDeny', '默认拒绝（空策略）'))];
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
            hint.textContent = translate('chat.boundaryPolicyDefaultDenyHint', '不选择草案时生成默认拒绝快照；容器无法访问任何目标。');
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

    async function fetchJSON(path) {
        const response = await window.apiFetch(path);
        if (!response.ok) {
            const error = new Error('HTTP ' + response.status);
            error.status = response.status;
            throw error;
        }
        return response.json();
    }

    async function loadConversationContainerChoices(force) {
        const projectId = activeProjectId();
        const key = projectId || '__none__';
        if (!force && state.loaded && state.loadKey === key) {
            renderBoundaryOptions();
            renderEgressModeAvailability();
            setLoadStatus();
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
        if (visible) loadConversationContainerChoices(false);
    }

    function setConversationContainerControlsLocked(locked) {
        const container = selectElement('container-conversation-options');
        if (container) container.classList.toggle('locked', !!locked);
        ['boundary-policy-select', 'conversation-egress-mode-select', 'conversation-egress-target-select'].forEach(function (id) {
            const control = selectElement(id);
            if (control) {
                control.disabled = !!locked;
                refreshEnhancedSelect(control);
            }
        });
    }

    function resetNewConversationContainerControls() {
        const boundary = selectElement('boundary-policy-select');
        const mode = selectElement('conversation-egress-mode-select');
        if (boundary) boundary.value = '';
        if (mode) mode.value = '';
        refreshEnhancedSelect(boundary);
        refreshEnhancedSelect(mode);
        syncConversationBoundarySelection();
        syncConversationEgressMode();
    }

    function readNewConversationContainerControls(runtimeMode) {
        if (String(runtimeMode || '').trim().toLowerCase() !== 'container') return {};
        const result = {};
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
    window.loadConversationContainerChoices = loadConversationContainerChoices;
    window.syncConversationContainerControlsVisibility = syncConversationContainerControlsVisibility;
    window.setConversationContainerControlsLocked = setConversationContainerControlsLocked;
    window.resetNewConversationContainerControls = resetNewConversationContainerControls;
    window.readNewConversationContainerControls = readNewConversationContainerControls;

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
