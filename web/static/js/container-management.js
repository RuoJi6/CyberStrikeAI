const CONTAINER_MANAGEMENT_PAGES = Object.freeze([
    'container-overview',
    'conversation-containers',
    'runtime-environments',
    'boundary-rules',
    'egress-proxies',
    'network-activity',
    'egress-audit',
]);

function isContainerManagementPage(pageId) {
    return CONTAINER_MANAGEMENT_PAGES.includes(String(pageId || ''));
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
}

window.CONTAINER_MANAGEMENT_PAGES = CONTAINER_MANAGEMENT_PAGES;
window.isContainerManagementPage = isContainerManagementPage;
window.initContainerManagementPage = initContainerManagementPage;
