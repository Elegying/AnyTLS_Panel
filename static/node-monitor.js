/* Shared monitor/account UI: persisted evidence is separate from request state. */
(() => {
    const running = new Map();
    let batchRunning = false;
    let pendingIds = [];
    let nextRequestAt = 0;
    let retryAt = 0;
    const cells = () => Array.from(document.querySelectorAll('.node-health'));
    // Server-calculated age plus monotonic elapsed time: device clock/timezone
    // must never turn a fresh server result into expired evidence.
    const stamp = h => ({...h, receivedAt: h.receivedAt ?? performance.now()});
    const ageSeconds = h => Number.isFinite(h.age_seconds)
        ? h.age_seconds + Math.max(0, (performance.now() - (h.receivedAt ?? performance.now())) / 1000)
        : null;
    function effective(h) {
        if (['entry', 'verified', 'failed', 'tls_error', 'unsupported'].includes(h.status) &&
            ageSeconds(h) !== null && ageSeconds(h) >= h.ttl_seconds) {
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
        health = stamp(health);
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
        const age = ageSeconds(h) === null ? null : Math.floor(ageSeconds(h) / 60);
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
        const timeout = window.setTimeout(() => controller.abort(), Math.max(1, Math.min(15000, deadline - performance.now())));
        try {
            if (performance.now() < retryAt) throw new Error('请求频繁，请等待 ' + Math.ceil((retryAt - performance.now()) / 1000) + ' 秒后继续。');
            const response = await fetch('/api/nodes/' + id + '/check', {method: 'POST', headers: csrfHeaders(), signal: controller.signal});
            if (response.status === 429) {
                const seconds = Number(response.headers.get('Retry-After'));
                retryAt = performance.now() + (Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds, 60) : 60) * 1000;
                throw new Error('请求频繁，请稍后继续检测；已取得的结果会保留。');
            }
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
    window.checkNode = function(id, deadline = performance.now() + 15000) {
        if (running.has(String(id))) return running.get(String(id));
        const task = perform(id, deadline).finally(() => running.delete(String(id)));
        running.set(String(id), task);
        return task;
    };
    window.checkAll = async function() {
        if (batchRunning) return;
        if (performance.now() < retryAt) {
            document.getElementById('check-status').textContent = '请求频繁，请等待 ' + Math.ceil((retryAt - performance.now()) / 1000) + ' 秒后继续检测。';
            return;
        }
        batchRunning = true;
        const button = document.getElementById('checkAllBtn');
        const feedback = document.getElementById('check-status');
        const all = cells();
        const available = new Set(all.map(cell => cell.id.slice('status-'.length)));
        pendingIds = pendingIds.filter(id => available.has(id));
        // On reload, stale/unknown rows come first; oldest attempts win so large
        // lists do not repeatedly spend the whole budget on their first rows.
        const ids = pendingIds.length ? pendingIds : all.map(cell => ({
            id: cell.id.slice('status-'.length), h: effective(JSON.parse(cell.dataset.health))
        })).sort((a, b) => {
            const pending = h => ['unknown', 'expired', 'error'].includes(h.status) ? 0 : 1;
            return pending(a.h) - pending(b.h) || (a.h.attempt_at || '').localeCompare(b.h.attempt_at || '');
        }).map(item => item.id);
        const retry = [];
        const deadline = performance.now() + 120000;
        let next = 0, finished = 0, completed = 0;
        button.disabled = true;
        feedback.textContent = '检测中：0 / ' + ids.length;
        async function worker() {
            while (next < ids.length && performance.now() < deadline && performance.now() >= retryAt) {
                // At most 150 starts/minute leaves room under the shared 200/min
                // limit for page/status requests. Concurrency remains at four.
                const slot = Math.max(performance.now(), nextRequestAt);
                if (slot >= deadline) break;
                nextRequestAt = slot + 400;
                if (slot > performance.now()) await new Promise(resolve => window.setTimeout(resolve, slot - performance.now()));
                if (performance.now() >= deadline || performance.now() < retryAt || next >= ids.length) break;
                const id = ids[next++];
                if (await window.checkNode(id, deadline)) completed++;
                else retry.push(id);
                finished++;
                feedback.textContent = '已处理 ' + finished + ' / ' + ids.length + '，取得结果 ' + completed;
            }
        }
        try {
            await Promise.all(Array.from({length: Math.min(4, ids.length)}, worker));
            pendingIds = ids.slice(next).concat(retry);
            feedback.textContent = '本轮已取得 ' + completed + ' / ' + ids.length + ' 项结果；' +
                pendingIds.length + ' 项未完成。' + (pendingIds.length ? '点击继续检测，接着处理剩余节点。' : '') +
                '检测失败结果不代表所有网络均不可达。';
        } finally {
            batchRunning = false; button.disabled = false;
            button.textContent = pendingIds.length ? '继续检测（剩余 ' + pendingIds.length + ' 项）' : '检测全部';
        }
    };
    function refreshDashboard() {
        const note = document.getElementById('dashboard-probe-note');
        if (!note) return;
        const states = JSON.parse(note.dataset.states).map(effective);
        const verified = states.filter(h => h.status === 'verified').length;
        const failed = states.filter(h => ['failed', 'tls_error'].includes(h.status)).length;
        document.getElementById('dashboard-verified').textContent = verified;
        document.getElementById('dashboard-failed').textContent = failed;
        document.getElementById('dashboard-pending').textContent = '入口检测失败 ' + failed + ' · 待确认 ' + (Number(note.dataset.total ?? states.length) - verified - failed);
        const pending = document.getElementById('dashboard-attention-nodes');
        if (pending) pending.textContent = Number(note.dataset.total ?? states.length) - verified;
        document.querySelectorAll('[data-probe-health]').forEach(badge => {
            if (effective(JSON.parse(badge.dataset.probeHealth)).status === 'expired') {
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
                const age = Math.floor(ageSeconds(h) / 60);
                cell.querySelector('.probe-time').textContent = h.checked_at + ' · ' + age + ' 分钟前';
            }
        });
        stats();
    }
    cells().forEach(cell => { cell.dataset.health = JSON.stringify(stamp(JSON.parse(cell.dataset.health))); });
    const dashboard = document.getElementById('dashboard-probe-note');
    if (dashboard) {
        dashboard.dataset.states = JSON.stringify(JSON.parse(dashboard.dataset.states).map(stamp));
        document.querySelectorAll('[data-probe-health]').forEach(badge => {
            badge.dataset.probeHealth = JSON.stringify(stamp(JSON.parse(badge.dataset.probeHealth)));
        });
    }
    refreshTime();
    window.setInterval(refreshTime, 30000);
})();
