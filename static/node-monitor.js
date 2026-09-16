/* Shared monitor/account UI: persisted evidence is separate from request state. */
(() => {
    const running = new Map();
    let batchRunning = false;
    const cells = () => Array.from(document.querySelectorAll('.node-health'));
    function effective(h) {
        if (['entry', 'verified', 'failed', 'tls_error', 'unsupported'].includes(h.status) &&
            h.expires_at && Date.now() / 1000 >= h.expires_at) {
            return {...h, status: 'expired', label: '结果已过期，需要复测', tone: 'orange', previous: h.label};
        }
        return h;
    }
    function text(tag, value, className = '') {
        const el = document.createElement(tag);
        el.textContent = value;
        el.className = className;
        return el;
    }
    function render(cell, health) {
        cell.dataset.health = JSON.stringify(health);
        const h = effective(health);
        const open = cell.querySelector('details')?.open || false;
        const detail = document.createElement('details');
        detail.open = open;
        detail.append(text('summary', '检测详情'));
        detail.append(text('p', '来源：面板服务器 · 有效期 15 分钟', 'cell-subtitle'));
        detail.append(text('p', '证书验证模式：' + (h.tls_mode === 'strict' ? '严格验证' : h.tls_mode === 'insecure_configured' ? '节点配置跳过验证（不证明证书有效）' : '未执行或未记录'), 'cell-subtitle'));
        if (['expired', 'error', 'checking'].includes(h.status)) detail.append(text('p', '上次：' + h.previous));
        for (const stage of h.stages) {
            const p = text('p', '', 'probe-stage');
            p.append(text('strong', stage.label + '：' + stage.outcome), text('span', stage.detail, 'cell-subtitle'));
            detail.append(p);
        }
        detail.append(text('p', 'TCP 建连耗时：' + (Number.isFinite(h.latency) && h.latency >= 0 ? h.latency + ' ms' : '未记录') + '；不代表代理访问延迟。', 'cell-subtitle'));
        if (h.attempt_at) detail.append(text('p', '最近尝试：' + h.attempt_at + ' UTC', 'cell-subtitle'));
        const age = h.expires_at ? Math.max(0, Math.floor((Date.now()/1000 - h.expires_at + h.ttl_seconds)/60)) : null;
        cell.replaceChildren(text('span', h.label, 'badge badge-' + h.tone),
            text('span', h.msg, 'cell-subtitle'),
            text('span', h.checked_at ? h.checked_at + ' · ' + age + ' 分钟前' : '尚无检测时间', 'cell-subtitle probe-time'), detail);
    }
    function stats() {
        const values = cells().map(cell => effective(JSON.parse(cell.dataset.health)));
        const verified = values.filter(h => h.status === 'verified').length;
        const entry = values.filter(h => h.status === 'entry').length;
        for (const [id, value] of [['stat-verified', verified], ['stat-entry', entry], ['stat-other', values.length - verified - entry]]) {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        }
    }
    async function perform(id, deadline) {
        const cell = document.getElementById('status-' + id);
        if (!cell) return false;
        const previous = JSON.parse(cell.dataset.health);
        const button = cell.closest('tr').querySelector('[data-action="check-node"]');
        render(cell, {...previous, status: 'checking', label: '检测中', tone: 'neutral', previous: effective(previous).label});
        stats();
        button.disabled = true;
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), Math.max(1, Math.min(15000, deadline - Date.now())));
        try {
            const response = await fetch('/api/nodes/' + id + '/check', {method: 'POST', headers: csrfHeaders(), signal: controller.signal});
            // Expected probe-task errors also contain persisted health evidence.
            if (response.status === 503 && response.headers.get('Content-Type')?.includes('application/json')) {
                const data = await response.json();
                if (!data.health) throw new Error('检测未完成');
                render(cell, data.health);
                return false;
            }
            const data = await readPanelResponse(response);
            if (!data.health || !Array.isArray(data.health.stages)) throw new Error('检测响应异常');
            render(cell, data.health);
            return !['error', 'checking'].includes(data.health.status);
        } catch (error) {
            // A lost HTTP response is not evidence about a node. Keep saved state
            // and statistics; request outcome lives in a separate message.
            render(cell, previous);
            cell.append(text('span', '本次请求未完成；保留上次结果，请刷新确认。' +
                (error.name === 'AbortError' ? '等待超时。' : error.message), 'cell-subtitle'));
            return false;
        } finally {
            window.clearTimeout(timeout);
            button.disabled = false;
            stats();
        }
    }
    window.checkNode = function(id, deadline = Date.now() + 15000) {
        if (running.has(String(id))) return running.get(String(id));
        const task = perform(id, deadline).finally(() => running.delete(String(id)));
        running.set(String(id), task);
        return task;
    };
    window.checkAll = async function() {
        if (batchRunning) return;
        batchRunning = true;
        const button = document.getElementById('checkAllBtn');
        const feedback = document.getElementById('check-status');
        const ids = cells().map(cell => cell.id.slice('status-'.length));
        const deadline = Date.now() + 120000;
        let next = 0, finished = 0, completed = 0;
        button.disabled = true;
        feedback.textContent = '检测中：0 / ' + ids.length;
        async function worker() {
            while (next < ids.length && Date.now() < deadline) {
                const id = ids[next++];
                if (await window.checkNode(id, deadline)) completed++;
                finished++;
                feedback.textContent = '已处理 ' + finished + ' / ' + ids.length + '，取得结果 ' + completed;
            }
        }
        try {
            await Promise.all(Array.from({length: Math.min(4, ids.length)}, worker));
            feedback.textContent = '已取得 ' + completed + ' / ' + ids.length + ' 项结果；' +
                (ids.length - completed) + ' 项未完成。检测失败结果不代表所有网络均不可达。';
        } finally { batchRunning = false; button.disabled = false; }
    };
    function refreshDashboard() {
        const note = document.getElementById('dashboard-probe-note');
        if (!note) return;
        const states = JSON.parse(note.dataset.states).map(effective);
        const verified = states.filter(h => h.status === 'verified').length;
        const failed = states.filter(h => ['failed', 'tls_error'].includes(h.status)).length;
        document.getElementById('dashboard-verified').textContent = verified;
        document.getElementById('dashboard-failed').textContent = failed;
        document.getElementById('dashboard-pending').textContent = '入口检测失败 ' + failed + ' · 待确认 ' + (states.length - verified - failed);
        document.querySelectorAll('[data-probe-expires]').forEach(badge => {
            if (effective({status: badge.dataset.probeStatus, expires_at: Number(badge.dataset.probeExpires)}).status === 'expired') {
                badge.textContent = '结果已过期，需要复测';
                badge.className = 'badge badge-orange';
            }
        });
    }
    function refreshTime() {
        refreshDashboard();
        cells().forEach(cell => {
            const saved = JSON.parse(cell.dataset.health);
            const id = cell.id.slice('status-'.length);
            if (saved.status === 'checking' && !running.has(id)) {
                fetch('/api/nodes/' + id + '/health').then(readPanelResponse).then(data => {
                    if (!running.has(id) && data.health) { render(cell, data.health); stats(); }
                }).catch(() => {}); // Retain prior evidence if the status request fails.
            }
            const h = effective(saved);
            if (h.status !== saved.status) render(cell, h);
            else if (h.checked_at) {
                const age = Math.max(0, Math.floor((Date.now()/1000 - h.expires_at + h.ttl_seconds)/60));
                cell.querySelector('.probe-time').textContent = h.checked_at + ' · ' + age + ' 分钟前';
            }
        });
        stats();
    }
    refreshTime();
    window.setInterval(refreshTime, 30000);
})();
