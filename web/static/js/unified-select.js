(function (root, factory) {
    'use strict';

    const api = factory(root || {});
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.CyberStrikeSelect = api;
}(typeof window !== 'undefined' ? window : globalThis, function (root) {
    'use strict';

    const instances = new Map();
    let documentEventsBound = false;
    let instanceSequence = 0;

    function normalizeSearchText(value) {
        return String(value == null ? '' : value).normalize('NFKC').trim().toLocaleLowerCase();
    }

    function filterOptionRecords(records, query) {
        const normalized = normalizeSearchText(query);
        if (!normalized) return records.map(function (record) { return record.index; });
        return records.filter(function (record) {
            return normalizeSearchText(record.searchText || record.label).includes(normalized);
        }).map(function (record) { return record.index; });
    }

    function enabledVisibleIndexes(records, visibleIndexes) {
        const visible = new Set(visibleIndexes);
        return records.filter(function (record) {
            return visible.has(record.index) && !record.disabled;
        }).map(function (record) { return record.index; });
    }

    function nextEnabledIndex(records, visibleIndexes, currentIndex, direction) {
        const enabled = enabledVisibleIndexes(records, visibleIndexes);
        if (!enabled.length) return -1;
        const currentPosition = enabled.indexOf(currentIndex);
        if (direction === 'first') return enabled[0];
        if (direction === 'last') return enabled[enabled.length - 1];
        if (currentPosition < 0) return direction < 0 ? enabled[enabled.length - 1] : enabled[0];
        const nextPosition = Math.max(0, Math.min(enabled.length - 1, currentPosition + (direction < 0 ? -1 : 1)));
        return enabled[nextPosition];
    }

    function calculateMenuGeometry(rect, viewport, desiredHeight) {
        const edge = 8;
        const gap = 6;
        const viewportWidth = Math.max(0, Number(viewport && viewport.width) || 0);
        const viewportHeight = Math.max(0, Number(viewport && viewport.height) || 0);
        const availableWidth = Math.max(0, viewportWidth - edge * 2);
        const desiredWidth = Math.max(Number(rect && rect.width) || 0, 220);
        const width = Math.min(desiredWidth, availableWidth);
        const leftLimit = Math.max(edge, viewportWidth - width - edge);
        const left = Math.min(Math.max(edge, Number(rect && rect.left) || 0), leftLimit);
        const rectTop = Number(rect && rect.top) || 0;
        const rectBottom = Number(rect && rect.bottom) || rectTop;
        const below = Math.max(0, viewportHeight - rectBottom - gap - edge);
        const above = Math.max(0, rectTop - gap - edge);
        const heightWanted = Math.max(160, Math.min(Number(desiredHeight) || 360, 420));
        const placement = below < Math.min(220, heightWanted) && above > below ? 'top' : 'bottom';
        const availableHeight = placement === 'top' ? above : below;
        const maxHeight = Math.max(120, Math.min(heightWanted, availableHeight || 120));
        const top = placement === 'top'
            ? Math.max(edge, rectTop - gap - maxHeight)
            : Math.min(viewportHeight - edge - maxHeight, rectBottom + gap);
        return { left: left, top: Math.max(edge, top), width: width, maxHeight: maxHeight, placement: placement };
    }

    function translate(key, fallback, params) {
        if (typeof root.t === 'function') {
            const value = root.t(key, params || {});
            if (value && value !== key) return value;
        }
        return fallback;
    }

    function optionRecords(select) {
        return Array.prototype.map.call(select.options || [], function (option, index) {
            return {
                index: index,
                label: String(option.textContent || ''),
                searchText: [option.textContent, option.dataset && option.dataset.searchText].filter(Boolean).join(' '),
                disabled: !!option.disabled,
                selected: !!option.selected,
            };
        });
    }

    function setElementText(element, value) {
        if (element) element.textContent = String(value == null ? '' : value);
    }

    function selectedSummary(instance) {
        const selected = Array.prototype.filter.call(instance.select.options || [], function (option) {
            return option.selected;
        });
        if (!selected.length) {
            return instance.options.placeholder || instance.select.dataset.placeholder || translate('common.noData', '暂无选择');
        }
        if (!instance.multiple || selected.length === 1) return String(selected[0].textContent || '');
        return translate('common.selectedOptions', '已选择 {{count}} 项', { count: selected.length })
            .replace('{{count}}', String(selected.length));
    }

    function ensureOptionId(instance, index) {
        return instance.id + '-option-' + index;
    }

    function setActiveIndex(instance, index, scroll) {
        const enabled = enabledVisibleIndexes(instance.records, instance.visibleIndexes);
        instance.activeIndex = enabled.includes(index) ? index : (enabled[0] == null ? -1 : enabled[0]);
        const activeId = instance.activeIndex >= 0 ? ensureOptionId(instance, instance.activeIndex) : '';
        [instance.trigger, instance.search].forEach(function (control) {
            if (!control) return;
            if (activeId) control.setAttribute('aria-activedescendant', activeId);
            else control.removeAttribute('aria-activedescendant');
        });
        instance.optionButtons.forEach(function (button, optionIndex) {
            button.classList.toggle('is-active', optionIndex === instance.activeIndex);
        });
        if (scroll && instance.activeIndex >= 0) {
            const active = instance.optionButtons.get(instance.activeIndex);
            if (active && typeof active.scrollIntoView === 'function') active.scrollIntoView({ block: 'nearest' });
        }
    }

    function renderOptions(instance) {
        instance.records = optionRecords(instance.select);
        instance.visibleIndexes = filterOptionRecords(instance.records, instance.search ? instance.search.value : '');
        instance.optionButtons = new Map();
        instance.list.replaceChildren();

        const visible = new Set(instance.visibleIndexes);
        instance.records.forEach(function (record) {
            if (!visible.has(record.index)) return;
            const option = instance.select.options[record.index];
            const button = document.createElement('button');
            button.type = 'button';
            button.id = ensureOptionId(instance, record.index);
            button.className = 'unified-select-option';
            button.dataset.optionIndex = String(record.index);
            button.setAttribute('role', 'option');
            button.setAttribute('aria-selected', option.selected ? 'true' : 'false');
            button.disabled = !!option.disabled;
            button.classList.toggle('is-selected', !!option.selected);
            button.classList.toggle('is-disabled', !!option.disabled);

            const check = document.createElement('span');
            check.className = 'unified-select-check';
            check.setAttribute('aria-hidden', 'true');
            check.textContent = instance.multiple ? '✓' : '●';
            const label = document.createElement('span');
            label.className = 'unified-select-option-label';
            label.textContent = record.label;
            button.append(check, label);
            instance.list.appendChild(button);
            instance.optionButtons.set(record.index, button);
        });

        instance.empty.hidden = instance.visibleIndexes.length > 0;
        if (!instance.visibleIndexes.length) {
            const fallback = instance.search && instance.search.value
                ? translate('common.noMatchingOptions', '没有匹配选项')
                : translate('common.noData', '暂无数据');
            setElementText(instance.empty, fallback);
        }
        setActiveIndex(instance, instance.activeIndex, false);
    }

    function sync(instance) {
        if (!instance || instance.destroyed) return;
        instance.multiple = !!instance.select.multiple;
        instance.trigger.disabled = !!instance.select.disabled;
        instance.wrapper.classList.toggle('is-disabled', !!instance.select.disabled);
        instance.wrapper.classList.toggle('is-multiple', instance.multiple);
        instance.list.setAttribute('aria-multiselectable', instance.multiple ? 'true' : 'false');
        if (instance.search) {
            instance.search.placeholder = translate('common.searchOptions', '搜索选项…');
            instance.search.setAttribute('aria-label', translate('common.searchOptions', '搜索选项'));
        }
        setElementText(instance.value, selectedSummary(instance));
        renderOptions(instance);
        if (instance.open) position(instance);
    }

    function position(instance) {
        if (!instance || !instance.open) return;
        const rect = instance.trigger.getBoundingClientRect();
        const geometry = calculateMenuGeometry(rect, {
            width: root.innerWidth || document.documentElement.clientWidth,
            height: root.innerHeight || document.documentElement.clientHeight,
        }, instance.options.maxHeight || 360);
        instance.menu.style.left = Math.round(geometry.left) + 'px';
        instance.menu.style.width = Math.round(geometry.width) + 'px';
        instance.menu.style.maxHeight = Math.round(geometry.maxHeight) + 'px';
        instance.menu.dataset.placement = geometry.placement;
        const renderedHeight = Math.min(instance.menu.scrollHeight || geometry.maxHeight, geometry.maxHeight);
        const top = geometry.placement === 'top'
            ? Math.max(8, rect.top - 6 - renderedHeight)
            : geometry.top;
        instance.menu.style.top = Math.round(top) + 'px';
    }

    function close(instance, options) {
        if (!instance || !instance.open) return;
        instance.open = false;
        instance.wrapper.classList.remove('open');
        instance.trigger.setAttribute('aria-expanded', 'false');
        instance.menu.hidden = true;
        if (instance.search) instance.search.value = '';
        renderOptions(instance);
        if (options && options.focusTrigger) instance.trigger.focus();
    }

    function closeAll(except) {
        instances.forEach(function (instance) {
            if (instance !== except) close(instance);
        });
    }

    function initialActiveIndex(instance, preferLast) {
        const selected = instance.records.find(function (record) {
            return record.selected && !record.disabled && instance.visibleIndexes.includes(record.index);
        });
        if (selected) return selected.index;
        return nextEnabledIndex(instance.records, instance.visibleIndexes, -1, preferLast ? -1 : 1);
    }

    function open(instance, options) {
        if (!instance || instance.open || instance.select.disabled) return;
        closeAll(instance);
        instance.open = true;
        instance.wrapper.classList.add('open');
        instance.trigger.setAttribute('aria-expanded', 'true');
        instance.menu.hidden = false;
        renderOptions(instance);
        setActiveIndex(instance, initialActiveIndex(instance, options && options.last), true);
        position(instance);
        if (instance.search && instance.searchEnabled) {
            instance.search.focus();
            if (options && options.seed) {
                instance.search.value = options.seed;
                renderOptions(instance);
                setActiveIndex(instance, nextEnabledIndex(instance.records, instance.visibleIndexes, -1, 1), true);
            }
        } else {
            instance.trigger.focus();
        }
    }

    function selectOption(instance, index) {
        const option = instance.select.options[index];
        if (!option || option.disabled) return;
        if (instance.multiple) option.selected = !option.selected;
        else instance.select.value = option.value;
        instance.select.dispatchEvent(new Event('input', { bubbles: true }));
        instance.select.dispatchEvent(new Event('change', { bubbles: true }));
        sync(instance);
        if (instance.multiple) {
            setActiveIndex(instance, index, true);
            if (instance.search) instance.search.focus();
        } else {
            close(instance, { focusTrigger: true });
        }
    }

    function handleNavigation(instance, event) {
        let next = instance.activeIndex;
        if (event.key === 'ArrowDown') next = nextEnabledIndex(instance.records, instance.visibleIndexes, instance.activeIndex, 1);
        else if (event.key === 'ArrowUp') next = nextEnabledIndex(instance.records, instance.visibleIndexes, instance.activeIndex, -1);
        else if (event.key === 'Home') next = nextEnabledIndex(instance.records, instance.visibleIndexes, instance.activeIndex, 'first');
        else if (event.key === 'End') next = nextEnabledIndex(instance.records, instance.visibleIndexes, instance.activeIndex, 'last');
        else if (event.key === 'Enter' || (event.key === ' ' && (!instance.search || event.target !== instance.search))) {
            event.preventDefault();
            event.stopPropagation();
            if (instance.activeIndex >= 0) selectOption(instance, instance.activeIndex);
            return true;
        } else if (event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            close(instance, { focusTrigger: true });
            return true;
        } else if (event.key === 'Tab') {
            close(instance);
            return false;
        } else {
            return false;
        }
        event.preventDefault();
        event.stopPropagation();
        setActiveIndex(instance, next, true);
        return true;
    }

    function bindGlobalEvents() {
        if (documentEventsBound || typeof document === 'undefined') return;
        document.addEventListener('pointerdown', function (event) {
            instances.forEach(function (instance) {
                if (!instance.open || instance.wrapper.contains(event.target) || instance.menu.contains(event.target)) return;
                close(instance);
            });
        });
        document.addEventListener('scroll', function () {
            instances.forEach(position);
        }, true);
        root.addEventListener('resize', function () {
            instances.forEach(position);
        });
        document.addEventListener('languagechange', function () {
            instances.forEach(sync);
        });
        documentEventsBound = true;
    }

    function enhance(select, options) {
        if (!select || String(select.tagName || '').toLowerCase() !== 'select') return null;
        if (instances.has(select)) {
            const existing = instances.get(select);
            sync(existing);
            return existing;
        }
        if (typeof document === 'undefined') return null;

        const config = Object.assign({
            searchable: select.dataset.unifiedSearch !== 'false',
            maxHeight: Number(select.dataset.unifiedMaxHeight) || 360,
            placeholder: select.dataset.unifiedPlaceholder || '',
        }, options || {});
        const id = 'unified-select-' + (++instanceSequence);
        const wrapper = document.createElement('div');
        wrapper.className = 'unified-select';
        const trigger = document.createElement('button');
        trigger.type = 'button';
        trigger.id = id + '-trigger';
        trigger.className = 'unified-select-trigger';
        trigger.setAttribute('aria-haspopup', 'listbox');
        trigger.setAttribute('aria-expanded', 'false');
        trigger.setAttribute('aria-controls', id + '-list');
        const value = document.createElement('span');
        value.className = 'unified-select-value';
        const caret = document.createElement('span');
        caret.className = 'unified-select-caret';
        caret.setAttribute('aria-hidden', 'true');
        trigger.append(value, caret);

        const menu = document.createElement('div');
        menu.id = id + '-menu';
        menu.className = 'unified-select-menu';
        menu.hidden = true;
        const searchWrap = document.createElement('div');
        searchWrap.className = 'unified-select-search-wrap';
        const search = document.createElement('input');
        search.type = 'search';
        search.className = 'unified-select-search';
        search.autocomplete = 'off';
        search.spellcheck = false;
        search.placeholder = translate('common.searchOptions', '搜索选项…');
        search.setAttribute('aria-label', translate('common.searchOptions', '搜索选项'));
        search.setAttribute('aria-controls', id + '-list');
        searchWrap.appendChild(search);
        const list = document.createElement('div');
        list.id = id + '-list';
        list.className = 'unified-select-options';
        list.setAttribute('role', 'listbox');
        list.setAttribute('aria-labelledby', trigger.id);
        const empty = document.createElement('div');
        empty.className = 'unified-select-empty';
        empty.setAttribute('role', 'status');
        empty.hidden = true;
        if (config.searchable) menu.appendChild(searchWrap);
        menu.append(list, empty);

        const parent = select.parentNode;
        parent.insertBefore(wrapper, select);
        wrapper.append(trigger, select);
        document.body.appendChild(menu);
        select.classList.add('unified-select-native');
        select.dataset.unifiedSelectReady = '1';
        select.tabIndex = -1;
        select.setAttribute('aria-hidden', 'true');

        const label = select.id ? document.querySelector('label[for="' + select.id.replace(/"/g, '\\"') + '"]') : null;
        if (label) {
            if (!label.id) label.id = id + '-label';
            trigger.setAttribute('aria-labelledby', label.id);
            select.setAttribute('aria-labelledby', label.id);
            label.htmlFor = trigger.id;
        } else {
            trigger.setAttribute('aria-label', select.getAttribute('aria-label') || translate('common.openOptions', '选择选项'));
        }

        const instance = {
            id: id, select: select, wrapper: wrapper, trigger: trigger, value: value,
            menu: menu, search: search, searchEnabled: !!config.searchable, list: list, empty: empty,
            label: label, originalLabelFor: select.id, options: config, records: [], visibleIndexes: [],
            optionButtons: new Map(), activeIndex: -1, multiple: !!select.multiple, open: false,
            destroyed: false, observer: null,
        };
        instances.set(select, instance);

        trigger.addEventListener('click', function () {
            if (instance.open) close(instance);
            else open(instance);
        });
        trigger.addEventListener('keydown', function (event) {
            if (instance.open && handleNavigation(instance, event)) return;
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp' || event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                event.stopPropagation();
                open(instance, { last: event.key === 'ArrowUp' });
            } else if (event.key.length === 1 && !event.metaKey && !event.ctrlKey && !event.altKey) {
                event.preventDefault();
                event.stopPropagation();
                open(instance, { seed: event.key });
            }
        });
        search.addEventListener('input', function () {
            renderOptions(instance);
            setActiveIndex(instance, nextEnabledIndex(instance.records, instance.visibleIndexes, -1, 1), false);
        });
        search.addEventListener('keydown', function (event) {
            handleNavigation(instance, event);
        });
        menu.addEventListener('click', function (event) {
            event.stopPropagation();
        });
        list.addEventListener('click', function (event) {
            const optionButton = event.target.closest('.unified-select-option');
            if (!optionButton || optionButton.disabled) return;
            selectOption(instance, Number(optionButton.dataset.optionIndex));
        });
        select.addEventListener('change', function () { sync(instance); });

        if (typeof MutationObserver !== 'undefined') {
            instance.observer = new MutationObserver(function () { sync(instance); });
            instance.observer.observe(select, { attributes: true, childList: true, subtree: true, characterData: true });
        }
        bindGlobalEvents();
        sync(instance);
        return instance;
    }

    function refresh(select) {
        const instance = instances.get(select);
        if (instance) sync(instance);
        return instance || null;
    }

    function enhanceAll(scope) {
        if (!scope || typeof scope.querySelectorAll !== 'function') return [];
        return Array.prototype.map.call(scope.querySelectorAll('select[data-unified-select]'), function (select) {
            return enhance(select);
        }).filter(Boolean);
    }

    function destroy(select) {
        const instance = instances.get(select);
        if (!instance) return;
        close(instance);
        instance.destroyed = true;
        if (instance.observer) instance.observer.disconnect();
        if (instance.label) instance.label.htmlFor = instance.originalLabelFor;
        select.classList.remove('unified-select-native');
        delete select.dataset.unifiedSelectReady;
        select.removeAttribute('aria-hidden');
        select.removeAttribute('aria-labelledby');
        select.tabIndex = 0;
        instance.wrapper.parentNode.insertBefore(select, instance.wrapper);
        instance.wrapper.remove();
        instance.menu.remove();
        instances.delete(select);
    }

    if (typeof document !== 'undefined') {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function () { enhanceAll(document); });
        } else {
            enhanceAll(document);
        }
    }

    return {
        enhance: enhance,
        enhanceAll: enhanceAll,
        refresh: refresh,
        open: function (select) { open(instances.get(select)); },
        close: function (select) { close(instances.get(select)); },
        closeAll: closeAll,
        destroy: destroy,
        get: function (select) { return instances.get(select) || null; },
        normalizeSearchText: normalizeSearchText,
        filterOptionRecords: filterOptionRecords,
        nextEnabledIndex: nextEnabledIndex,
        calculateMenuGeometry: calculateMenuGeometry,
    };
}));
