const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.resolve(__dirname, '..');

function element() {
    const classes = new Set();
    return {
        textContent: '', innerHTML: '', hidden: false, disabled: false,
        dataset: {}, children: [],
        classList: {
            add: name => classes.add(name), remove: name => classes.delete(name),
            contains: name => classes.has(name),
            toggle(name, on) { if (on) classes.add(name); else classes.delete(name); },
        },
        setAttribute() {}, removeAttribute() {},
        appendChild(child) { this.children.push(child); },
        append(...children) { this.children.push(...children); },
        replaceChildren() { this.children = []; this.textContent = ''; },
    };
}

function setup(template) {
    const elements = new Map();
    const get = id => {
        if (!elements.has(id)) elements.set(id, element());
        return elements.get(id);
    };
    const requests = [];
    const document = {
        addEventListener() {},
        getElementById: get,
        createElement: element,
        createTextNode: text => ({textContent: text}),
        querySelectorAll: () => [],
    };
    const context = vm.createContext({
        document, AbortController, Map, Set, URL,
        window: {matchMedia: () => ({}), setTimeout: () => 1, clearTimeout() {}},
        csrfHeaders: extra => ({'X-CSRFToken': 'test-csrf', ...extra}),
        fetch: async (url, options) => {
            requests.push({url, options});
            return context.response;
        },
    });
    vm.runInContext(fs.readFileSync(path.join(root, 'static/panel.js'), 'utf8'), context);
    const source = fs.readFileSync(path.join(root, 'templates', template), 'utf8');
    vm.runInContext(source.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1], context);
    return {context, get, requests, document};
}

function response(body, status = 200) {
    return {ok: status < 400, status, redirected: false,
        headers: {get: () => 'application/json'}, json: async () => body};
}

test('sync distinguishes successful, partial, failed, empty and invalid responses', async () => {
    for (const [body, status, text, error] of [
        [{results: [{id: 1, status: 'ok'}]}, 200, '同步成功：1', false],
        [{results: [{id: 1, status: 'ok'}, {id: 2, status: 'error', name: '<script>'}]}, 200, '1 个成功，1 个未完成', true],
        [{results: [{id: 1, status: 'error'}]}, 200, '0 个成功，1 个未完成', true],
        [{error: '账号上限'}, 413, '账号上限', true],
        [{results: []}, 200, '没有需要同步', false],
        [{results: [null]}, 200, '响应异常', true],
    ]) {
        const {context, get, requests} = setup('dashboard.html');
        context.response = response(body, status);
        const button = element();
        await context.syncAll(button);
        assert.ok(get('syncMessage').textContent.includes(text));
        assert.equal(get('syncFeedback').classList.contains('is-error'), error);
        assert.equal(button.disabled, false);
        assert.equal(requests[0].options.headers['X-CSRFToken'], 'test-csrf');
        if (body.results?.[1]?.name) {
            assert.equal(get('syncFailures').children[0].children[0].textContent, '<script>');
        }
    }
});

test('sync restores controls after session expiry and transport failure', async () => {
    const {context, get} = setup('dashboard.html');
    context.response = {...response({}), redirected: true};
    const button = element();
    await context.syncAll(button);
    assert.match(get('syncMessage').textContent, /登录已过期/);
    context.fetch = async () => { throw new Error('connection lost'); };
    await context.syncAll(button);
    assert.equal(button.disabled, false);
    assert.equal(get('syncFeedback').classList.contains('is-error'), true);
});


function monitorSetup(count = 1) {
    let elapsed = 0;
    const nodes = new Map();
    const get = id => { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); };
    const makeHealth = status => ({status, label: status === 'entry' ? '入口可达，代理未验证' : '检测失败',
        tone: status === 'entry' ? 'orange' : 'red', msg: '测试', previous: '入口可达',
        checked_at: '2026-01-01 00:00:00 UTC', expires_at: Date.now()/1000+900, ttl_seconds: 900, age_seconds: 0,
        latency: 12, stages: []});
    const cell = get('status-1'), button = element();
    cell.dataset.health = JSON.stringify(makeHealth('entry'));
    cell.id = 'status-1';
    cell.querySelector = () => element();
    cell.closest = () => ({querySelector: () => button});
    const monitorCells = [cell];
    for (let i = 2; i <= count; i++) {
        const extra = get('status-' + i);
        Object.assign(extra, {id: 'status-' + i, querySelector: cell.querySelector, closest: cell.closest});
        extra.dataset.health = JSON.stringify(makeHealth('unknown'));
        monitorCells.push(extra);
    }
    let callback;
    const requests = [];
    const context = vm.createContext({Date, Map, Set, Promise, AbortController, performance: {now: () => elapsed},
        document: {getElementById: id => id.startsWith('dashboard-') ? null : get(id), querySelectorAll: () => monitorCells,
            createElement: tag => ({...element(), tag})},
        window: {setTimeout(fn, ms) { if (ms <= 1200) { elapsed += ms; fn(); } return 1; }, clearTimeout() {}, setInterval(fn) {callback = fn;}},
        csrfHeaders: () => ({'X-CSRFToken': 'fake'}),
        readPanelResponse: async response => {if (!response.ok) throw new Error('request failed'); return response.json();},
        fetch: async (url, options) => {requests.push({url, options}); return context.response;},
    });
    vm.runInContext(fs.readFileSync(path.join(root, 'static/node-monitor.js'), 'utf8'), context);
    return {context, cell, button, get, requests, makeHealth, monitorCells, advance: ms => {elapsed += ms;}, tick: () => callback()};
}

test('node request errors preserve saved evidence and statistics; valid failure persists', async () => {
    const {context, cell, button, get, requests, makeHealth} = monitorSetup();
    context.response = response({error:'unavailable'}, 500);
    await context.window.checkNode(1);
    assert.equal(JSON.parse(cell.dataset.health).status, 'entry');
    assert.equal(get('stat-entry').textContent, 1);
    assert.equal(get('stat-verified').textContent, 0);
    assert.equal(button.disabled, false);
    context.response = response({health: makeHealth('failed')});
    await context.window.checkNode(1);
    assert.equal(JSON.parse(cell.dataset.health).status, 'failed');
    assert.equal(get('stat-entry').textContent, 0);
    assert.equal(get('stat-other').textContent, 1);
    assert.equal(requests[0].options.headers['X-CSRFToken'], 'fake');
});

test('node repeats share one request; persisted task error stays unknown after response', async () => {
    const {context, cell, requests, makeHealth} = monitorSetup();
    context.response = response({health: {...makeHealth('error'),label:'检测未完成'}}, 503);
    const first = context.window.checkNode(1), second = context.window.checkNode(1);
    assert.equal(first, second);
    await first;
    assert.equal(requests.length, 1);
    assert.equal(JSON.parse(cell.dataset.health).status, 'error');
});

test('expired evidence leaves current entry counts without claiming proxy success', () => {
    const {cell, get, makeHealth, tick} = monitorSetup();
    cell.dataset.health = JSON.stringify({...makeHealth('entry'), age_seconds: 901});
    tick();
    assert.equal(JSON.parse(cell.dataset.health).status, 'expired');
    assert.equal(get('stat-entry').textContent, 0);
    assert.equal(get('stat-verified').textContent, 0);
});


test('server age survives skewed device clocks and expires only after elapsed TTL', async () => {
    const {context, cell, get, makeHealth, advance, tick} = monitorSetup();
    context.Date = class extends Date { static now() { return 0; } };
    context.response = response({health: {...makeHealth('entry'), expires_at: 1, age_seconds: 10}});
    await context.window.checkNode(1);
    tick();
    assert.equal(get('stat-entry').textContent, 1);
    context.Date = class extends Date { static now() { return 9999999999999; } };
    advance(889000);
    tick();
    assert.equal(get('stat-entry').textContent, 1);
    advance(1000);
    tick();
    assert.equal(JSON.parse(cell.dataset.health).status, 'expired');
    assert.equal(get('stat-entry').textContent, 0);
});

test('bulk starts with pending rows and resumes untouched rows after deadline', async () => {
    const {context, requests, makeHealth, advance, get} = monitorSetup(8);
    context.fetch = async (url, options) => {
        requests.push({url, options});
        advance(61000);
        return response({health: makeHealth('entry')});
    };
    await context.window.checkAll();
    const first = requests.map(r => r.url);
    assert.ok(first.length < 8);
    assert.equal(first[0], '/api/nodes/2/check');
    assert.match(get('checkAllBtn').textContent, /继续检测/);
    await context.window.checkAll();
    const next = requests.slice(first.length).map(r => r.url);
    assert.ok(next.length > 0);
    assert.ok(next.every(url => !first.includes(url)));
});

test('bulk respects Retry-After and resumes without discarding saved evidence', async () => {
    const {context, requests, makeHealth, advance, get, cell} = monitorSetup(8);
    context.response = {...response({}, 429), headers: {get: key => key === 'Retry-After' ? '30' : 'application/json'}};
    await context.window.checkAll();
    const limited = requests.length;
    assert.ok(limited <= 4);
    assert.equal(JSON.parse(cell.dataset.health).status, 'entry');
    await context.window.checkAll();
    assert.equal(requests.length, limited);
    assert.match(get('check-status').textContent, /等待/);
    advance(30000);
    context.response = response({health: makeHealth('entry')});
    await context.window.checkAll();
    assert.equal(get('checkAllBtn').textContent, '检测全部');
    assert.equal(get('stat-entry').textContent, 8);
});


test('fast bulk responses are paced below the global request limit', async () => {
    const {context, makeHealth} = monitorSetup(4);
    context.performance = performance;
    context.window.setTimeout = setTimeout;
    context.window.clearTimeout = clearTimeout;
    const starts = [];
    context.fetch = async () => {
        starts.push(performance.now());
        return response({health: makeHealth('entry')});
    };
    await context.window.checkAll();
    assert.equal(starts.length, 4);
    for (let i = 1; i < starts.length; i++) assert.ok(starts[i] - starts[i - 1] >= 370);
});
