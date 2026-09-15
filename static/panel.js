/* Shared progressive enhancement for forms and modal navigation. */
let lastFocusedElement = null;
const mobileNavigation = window.matchMedia('(max-width: 768px)');
const inertLayers = new Set();

function syncLayers() {
    inertLayers.forEach(element => { element.inert = false; });
    inertLayers.clear();
    const disable = element => {
        element.inert = true;
        inertLayers.add(element);
    };
    const modal = document.querySelector('.modal-overlay.show');
    const sidebar = document.getElementById('sidebar');
    const drawerOpen = mobileNavigation.matches && sidebar.classList.contains('open');
    if (mobileNavigation.matches && !drawerOpen) disable(sidebar);
    // Some dialogs live inside main: disable siblings along their ancestor
    // path, never the ancestor containing the active dialog.
    let active = modal || (drawerOpen ? sidebar : null);
    while (active && active !== document.body) {
        Array.from(active.parentElement.children).forEach(sibling => {
            if (sibling !== active && (modal || sibling.id !== 'sidebarOverlay')) disable(sibling);
        });
        active = active.parentElement;
    }
    document.body.style.overflow = modal || drawerOpen ? 'hidden' : '';
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const toggle = document.querySelector('.mobile-header button');
    const open = sidebar.classList.toggle('open');
    document.getElementById('sidebarOverlay').classList.toggle('show', open);
    toggle.setAttribute('aria-expanded', String(open));
    syncLayers();
    if (open) sidebar.querySelector('.sidebar-close').focus();
    else toggle.focus();
}

function openModal(id) {
    const modal = document.getElementById(id);
    if (!modal) return;
    if (document.getElementById('sidebar').classList.contains('open')) toggleSidebar();
    lastFocusedElement = document.activeElement === document.body
        ? Array.from(document.querySelectorAll('[data-action="open-modal"]')).find(button => button.dataset.modal === id)
        : document.activeElement;
    modal.classList.add('show');
    modal.setAttribute('aria-hidden', 'false');
    syncLayers();
    const first = modal.querySelector('[data-initial-focus]') ||
        modal.querySelector('input:not([type="hidden"]), textarea, select') ||
        modal.querySelector('button');
    if (first) first.focus();
}

function closeModal(id) {
    const modal = document.getElementById(id);
    if (!modal) return;
    if (modal.querySelector('form[aria-busy="true"]')) return;
    modal.classList.remove('show');
    modal.setAttribute('aria-hidden', 'true');
    syncLayers();
    if (lastFocusedElement && lastFocusedElement.isConnected &&
        !lastFocusedElement.closest('[inert]')) lastFocusedElement.focus();
}

function trapLayerFocus(event) {
    if (event.key !== 'Tab') return;
    const layer = document.querySelector('.modal-overlay.show') ||
        (mobileNavigation.matches ? document.querySelector('.sidebar.open') : null);
    if (!layer) return;
    const items = Array.from(layer.querySelectorAll(
        'a[href],button,input:not([type="hidden"]),select,textarea,[tabindex]'
    )).filter(el => !el.disabled && el.tabIndex >= 0 && el.getClientRects().length);
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (event.shiftKey && (document.activeElement === first || !layer.contains(document.activeElement))) {
        event.preventDefault(); last.focus();
    } else if (!event.shiftKey && (document.activeElement === last || !layer.contains(document.activeElement))) {
        event.preventDefault(); first.focus();
    }
}

async function readPanelResponse(response) {
    if (response.redirected) throw new Error('登录已过期，请在新标签页重新登录后再操作。');
    const json = (response.headers.get('Content-Type') || '').includes('application/json');
    const data = json ? await response.json() : null;
    if (!response.ok) {
        const error = new Error(data?.error || data?.msg ||
            (response.status === 400 ? '页面已过期，请先保留输入，再刷新页面重试。' : '请求失败，请稍后重试。'));
        error.field = data?.field;
        throw error;
    }
    if (!data || typeof data !== 'object') throw new Error('响应格式异常，请先确认操作结果。');
    return data;
}

document.addEventListener('DOMContentLoaded', () => {
    syncLayers();
    mobileNavigation.addEventListener('change', () => {
        const sidebar = document.getElementById('sidebar');
        sidebar.classList.remove('open');
        document.getElementById('sidebarOverlay').classList.remove('show');
        document.querySelector('.mobile-header button').setAttribute('aria-expanded', 'false');
        syncLayers();
        if (sidebar.contains(document.activeElement) && mobileNavigation.matches) {
            document.querySelector('.mobile-header button').focus();
        }
    });

    document.querySelectorAll('form[data-preserve-form]').forEach(form => {
        const feedback = document.createElement('p');
        feedback.className = 'form-feedback';
        feedback.id = 'form-feedback-' + Array.from(document.forms).indexOf(form);
        feedback.setAttribute('role', 'status');
        feedback.tabIndex = -1;
        const actions = form.querySelector('.modal-actions');
        if (actions) actions.before(feedback);
        else form.appendChild(feedback);
        form.addEventListener('submit', async event => {
            event.preventDefault();
            if (form.getAttribute('aria-busy') === 'true') return;
            const body = new FormData(form);
            const modal = form.closest('.modal-overlay');
            const buttons = Array.from(new Set([
                ...form.querySelectorAll('button'),
                ...(modal ? modal.querySelectorAll('[data-action="close-modal"]') : [])
            ])).filter(button => !button.disabled);
            form.setAttribute('aria-busy', 'true');
            buttons.forEach(button => { button.disabled = true; });
            form.querySelectorAll('[aria-invalid]').forEach(field => {
                field.removeAttribute('aria-invalid');
                field.removeAttribute('aria-describedby');
            });
            feedback.classList.remove('is-error');
            feedback.textContent = '正在提交，请稍候…';
            const controller = new AbortController();
            const timeout = window.setTimeout(() => controller.abort(), 120000);
            try {
                const response = await fetch(form.action, {
                    method: 'POST', body, signal: controller.signal,
                    headers: {'X-Panel-Form': '1', 'Accept': 'application/json'}
                });
                const data = await readPanelResponse(response);
                if (typeof data.redirect !== 'string' || !data.redirect.startsWith('/') || data.redirect.startsWith('//')) {
                    throw new Error('响应格式异常，请先确认操作结果。');
                }
                feedback.textContent = '已保存，正在返回…';
                window.location.assign(data.redirect);
            } catch (error) {
                feedback.classList.add('is-error');
                feedback.textContent = error.name === 'AbortError' || error instanceof TypeError
                    ? '连接中断或等待超时，结果尚未确认。输入已保留，请先在列表中核对，避免重复提交。'
                    : error.message;
                const field = error.field ? form.elements.namedItem(error.field) : null;
                if (field && field.focus) {
                    field.setAttribute('aria-invalid', 'true');
                    field.setAttribute('aria-describedby', feedback.id);
                    field.insertAdjacentElement('afterend', feedback);
                    field.focus();
                } else feedback.focus();
            } finally {
                window.clearTimeout(timeout);
                form.removeAttribute('aria-busy');
                buttons.forEach(button => { button.disabled = false; });
            }
        });
        const start = form.elements.namedItem('started_on');
        const end = form.elements.namedItem('expires_on');
        if (start && end) {
            const update = () => { end.min = start.value; };
            start.addEventListener('input', update);
            update();
        }
    });

    document.querySelectorAll('.attention-list').forEach((list, index) => {
        if (list.children.length <= 2) return;
        list.id = 'attention-list-' + index;
        const extra = Array.from(list.children).slice(2);
        extra.forEach(item => { item.hidden = true; });
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-ghost attention-more';
        button.setAttribute('aria-controls', list.id);
        button.setAttribute('aria-expanded', 'false');
        button.textContent = '展开其余 ' + extra.length + ' 项';
        button.addEventListener('click', () => {
            const expanded = button.getAttribute('aria-expanded') !== 'true';
            extra.forEach(item => { item.hidden = !expanded; });
            button.setAttribute('aria-expanded', String(expanded));
            button.textContent = expanded ? '收起更多项目' : '展开其余 ' + extra.length + ' 项';
        });
        list.after(button);
    });

    const search = document.getElementById('service-search');
    const filter = document.getElementById('service-filter');
    if (search && filter) {
        const rows = Array.from(document.querySelectorAll('[data-service-state]'));
        const applyFilter = () => {
            const query = search.value.trim().toLocaleLowerCase();
            let count = 0;
            rows.forEach(row => {
                const matches = row.dataset.search.toLocaleLowerCase().includes(query) &&
                    (!filter.value || (filter.value === 'due' ? row.dataset.due === 'true' : row.dataset.serviceState === filter.value));
                row.hidden = !matches;
                if (matches) count += 1;
            });
            document.getElementById('service-filter-count').textContent = '显示 ' + count + ' / ' + rows.length + ' 位用户';
            document.getElementById('service-no-match').hidden = count > 0;
        };
        search.addEventListener('input', applyFilter);
        filter.addEventListener('change', applyFilter);
        applyFilter();
    }
    const autoOpen = document.querySelector('[data-auto-open]');
    if (autoOpen) openModal(autoOpen.id);
});
