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

test('monitor keeps last result on failure, counts unknown, and recovers', async () => {
    const {context, get, document} = setup('monitor.html');
    const row = element(), button = element();
    row.dataset.state = 'online';
    row.querySelector = () => button;
    const status = get('status-example.invalid-443');
    status.textContent = '在线';
    status.closest = () => row;
    document.querySelectorAll = () => [row];
    get('latency-example.invalid-443').textContent = '12 ms';
    get('checked-example.invalid-443').textContent = 'last check';
    context.response = response({error: '检测服务暂时不可用'}, 500);
    assert.equal(await context.checkOne('example.invalid', 443), false);
    assert.equal(get('stat-offline').textContent, 0);
    assert.equal(get('stat-unknown').textContent, 1);
    assert.equal(get('latency-example.invalid-443').textContent, '12 ms');
    assert.equal(get('checked-example.invalid-443').textContent, 'last check');
    assert.match(status.children[1].textContent, /上次：在线/);
    context.response = response({online: false, latency: -1, checked_at: 'new check'});
    assert.equal(await context.checkOne('example.invalid', 443), true);
    assert.equal(get('stat-offline').textContent, 1);
    assert.equal(get('stat-unknown').textContent, 0);
    assert.equal(get('checked-example.invalid-443').textContent, 'new check');
    assert.equal(button.disabled, false);
});
