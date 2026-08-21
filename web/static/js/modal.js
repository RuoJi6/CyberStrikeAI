/**
 * 统一弹窗：先显示遮罩、下一帧再填大段内容，避免与 backdrop 绘制抢主线程。
 */
(function () {
    const BODY_LOCK = 'app-modal-open';
    const LEGACY_BODY_LOCK = 'projects-modal-open';
    const OVERLAY_SELECTOR =
        '.projects-modal-overlay, .c2-modal-overlay, .modal, .info-collect-cell-modal, #login-overlay';

    const FLEX_MODAL_IDS = new Set([
        'role-modal',
        'skill-modal',
        'agent-md-modal',
        'batch-manage-modal',
        'create-group-modal',
        'workflow-meta-modal',
        'workflow-dry-run-modal',
        'login-overlay',
    ]);
    const VIEWPORT_CENTERED_MODAL_IDS = new Set([
        'conversation-delete-workspace-modal',
    ]);
    let viewportModalListenersBound = false;

    function resolveEl(idOrEl) {
        if (!idOrEl) return null;
        return typeof idOrEl === 'string' ? document.getElementById(idOrEl) : idOrEl;
    }

    function isElVisible(el) {
        if (!el) return false;
        const s = window.getComputedStyle(el);
        return s.display !== 'none' && s.visibility !== 'hidden';
    }

    function defaultDisplay(el) {
        if (el.classList.contains('projects-modal-overlay') || el.classList.contains('c2-modal-overlay')) {
            return 'flex';
        }
        if (el.classList.contains('info-collect-cell-modal')) {
            return 'flex';
        }
        if (el.classList.contains('chat-files-form-modal')) {
            return 'flex';
        }
        if (FLEX_MODAL_IDS.has(el.id)) {
            return 'flex';
        }
        return 'block';
    }

    function viewportModalMetrics() {
        const root = document.documentElement;
        const layoutWidth = Math.max(1, Number(root && root.clientWidth) || 0, Number(window.innerWidth) || 0);
        const layoutHeight = Math.max(1, Number(root && root.clientHeight) || 0, Number(window.innerHeight) || 0);
        const viewport = window.visualViewport;
        const useVisualViewport = !!(viewport && Number(viewport.scale) > 1);
        const visibleWidth = useVisualViewport ? Number(viewport.width) || layoutWidth : layoutWidth;
        const visibleHeight = useVisualViewport ? Number(viewport.height) || layoutHeight : layoutHeight;
        const offsetLeft = useVisualViewport ? Number(viewport.offsetLeft) || 0 : 0;
        const offsetTop = useVisualViewport ? Number(viewport.offsetTop) || 0 : 0;
        return {
            layoutWidth,
            layoutHeight,
            visibleWidth,
            visibleHeight,
            centerX: offsetLeft + visibleWidth / 2,
            centerY: offsetTop + visibleHeight / 2,
        };
    }

    function setImportantStyle(style, property, value) {
        if (style && typeof style.setProperty === 'function') {
            style.setProperty(property, value, 'important');
            return;
        }
        if (style) style[property] = value;
    }

    function positionViewportModal(el) {
        if (!el || !VIEWPORT_CENTERED_MODAL_IDS.has(el.id)) return;
        if (el.parentElement !== document.body) document.body.appendChild(el);
        const metrics = viewportModalMetrics();
        setImportantStyle(el.style, 'position', 'fixed');
        setImportantStyle(el.style, 'inset', '0 auto auto 0');
        setImportantStyle(el.style, 'width', `${metrics.layoutWidth}px`);
        setImportantStyle(el.style, 'height', `${metrics.layoutHeight}px`);
        setImportantStyle(el.style, 'margin', '0');
        el.style.alignItems = 'center';
        el.style.justifyContent = 'center';

        const dialog = el.querySelector('.conversation-delete-workspace-dialog');
        if (!dialog) return;
        const horizontalRoom = Math.max(0, metrics.visibleWidth - 24);
        const verticalRoom = Math.max(0, metrics.visibleHeight - 24);
        setImportantStyle(dialog.style, 'position', 'fixed');
        setImportantStyle(dialog.style, 'left', `${metrics.centerX}px`);
        setImportantStyle(dialog.style, 'top', `${metrics.centerY}px`);
        setImportantStyle(dialog.style, 'right', 'auto');
        setImportantStyle(dialog.style, 'bottom', 'auto');
        setImportantStyle(dialog.style, 'width', `${Math.min(560, horizontalRoom)}px`);
        setImportantStyle(dialog.style, 'max-height', `${verticalRoom}px`);
        setImportantStyle(dialog.style, 'margin', '0');
        setImportantStyle(dialog.style, 'transform', 'translate(-50%, -50%)');
        setImportantStyle(dialog.style, 'animation', 'none');
    }

    function syncViewportModals() {
        VIEWPORT_CENTERED_MODAL_IDS.forEach(function (id) {
            const el = document.getElementById(id);
            if (isElVisible(el)) positionViewportModal(el);
        });
    }

    function bindViewportModalListeners() {
        if (viewportModalListenersBound) return;
        viewportModalListenersBound = true;
        window.addEventListener('resize', syncViewportModals, { passive: true });
        if (window.visualViewport) {
            window.visualViewport.addEventListener('resize', syncViewportModals, { passive: true });
            window.visualViewport.addEventListener('scroll', syncViewportModals, { passive: true });
        }
    }

    function syncBodyLock() {
        const anyOpen = Array.from(document.querySelectorAll(OVERLAY_SELECTOR)).some(isElVisible);
        document.body.classList.toggle(BODY_LOCK, anyOpen);
        const projectsOpen = Array.from(document.querySelectorAll('.projects-modal-overlay')).some(isElVisible);
        document.body.classList.toggle(LEGACY_BODY_LOCK, projectsOpen);
    }

    function openAppModal(idOrEl, opts) {
        opts = opts || {};
        const el = resolveEl(idOrEl);
        if (!el) return null;
        if (VIEWPORT_CENTERED_MODAL_IDS.has(el.id)) {
            bindViewportModalListeners();
            positionViewportModal(el);
        }
        el.style.display = opts.display || defaultDisplay(el);
        syncBodyLock();
        if (opts.focus === false) return el;
        const sel =
            opts.focusSelector ||
            'input.form-input, textarea.form-input, select.form-input, input:not([type="hidden"]):not([disabled]), textarea:not([disabled]), select:not([disabled])';
        const focusTarget = opts.focusEl || el.querySelector(sel);
        if (focusTarget) {
            requestAnimationFrame(function () {
                focusTarget.focus();
            });
        }
        return el;
    }

    function closeAppModal(idOrEl) {
        const el = resolveEl(idOrEl);
        if (el) el.style.display = 'none';
        syncBodyLock();
        return el;
    }

    function isAppModalOpen(idOrEl) {
        return isElVisible(resolveEl(idOrEl));
    }

    /** 双 rAF：等遮罩绘制完成后再写入大段 DOM / 表单 */
    function deferModalContent(fn) {
        requestAnimationFrame(function () {
            requestAnimationFrame(fn);
        });
    }

    window.openAppModal = openAppModal;
    window.closeAppModal = closeAppModal;
    window.isAppModalOpen = isAppModalOpen;
    window.deferModalContent = deferModalContent;
    window.syncAppModalBodyLock = syncBodyLock;
})();
