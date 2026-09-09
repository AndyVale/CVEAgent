// Run with: node --test tests/gui/*.test.cjs
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

function element(tag = 'div') {
  const classes = new Set();
  return {
    tag, children: [], value: '', textContent: '', disabled: false,
    classList: {
      add(value) { classes.add(value); },
      remove(value) { classes.delete(value); },
      toggle(value, force) {
        if (force === undefined ? !classes.has(value) : force) classes.add(value);
        else classes.delete(value);
      },
      contains(value) { return classes.has(value); },
    },
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
  };
}

function deferred() {
  let resolvePromise;
  const promise = new Promise(resolve => { resolvePromise = resolve; });
  return {promise, resolve: resolvePromise};
}

function fixture(request = async () => ({analyses: [], next_cursor: null})) {
  const context = vm.createContext({
    document: {createElement: element}, URLSearchParams,
    CVEAgent: {},
  });
  vm.runInContext(
    readFileSync(resolve(__dirname, '../../src/cve_agent/gui/static/history.js'), 'utf8'),
    context,
  );
  const searchInput = element('input');
  const list = element();
  const moreButton = element('button');
  const timers = [];
  const Controller = context.CVEAgent.history.HistoryController;
  const controller = new Controller({
    request,
    searchInput,
    list,
    moreButton,
    renderRow: item => ({tag: 'button', item}),
    setTimer: callback => { timers.push(callback); return callback; },
    clearTimer: () => {},
  });
  return {controller, searchInput, list, moreButton, timers};
}

const rows = ['CVE-2021-26855', 'CVE-2020-11022', 'CVE-2020-2889'].map((cve_id, i) => ({
  id: String(i), cve_id, updated_at: '2026-09-09', taxonomy_name: 'Fixture', labels: [], status: 'classified',
}));

test('search immediately hides unrelated rows while fragments and clearing still work', () => {
  const {controller, searchInput, list} = fixture();
  controller.setInitial({analyses: rows, next_cursor: null});
  const visible = query => {
    searchInput.value = query;
    controller.render();
    return list.children.filter(child => child.tag === 'button').map(button => button.item.cve_id);
  };

  assert.deepEqual(visible('CVE-2021-26855'), ['CVE-2021-26855']);
  assert.deepEqual(visible('2889'), ['CVE-2020-2889']);
  assert.deepEqual(visible('2020'), ['CVE-2020-11022', 'CVE-2020-2889']);
  assert.deepEqual(visible('missing'), []);
  assert.equal(visible('').length, 3);
});

test('a stale search response cannot replace a newer query', async () => {
  const requests = [];
  const request = path => {
    const pending = deferred();
    requests.push({path, pending});
    return pending.promise;
  };
  const {controller, searchInput} = fixture(request);

  searchInput.value = '2020';
  const oldRequest = controller.refresh();
  searchInput.value = '26855';
  controller.query = '26855';
  const newRequest = controller.refresh();
  requests[1].pending.resolve({analyses: [rows[0]], next_cursor: null});
  await newRequest;
  requests[0].pending.resolve({analyses: rows.slice(1), next_cursor: null});
  await oldRequest;

  assert.equal(controller.items.map(item => item.cve_id).join(','), 'CVE-2021-26855');
});

test('pagination sends the opaque cursor and avoids duplicate rows', async () => {
  const paths = [];
  const {controller, moreButton} = fixture(async path => {
    paths.push(path);
    return {analyses: [rows[1], rows[2]], next_cursor: null};
  });
  controller.setInitial({analyses: [rows[0], rows[1]], next_cursor: 'opaque-next'});

  await controller.refresh({append: true});

  assert.match(paths[0], /cursor=opaque-next/);
  assert.equal(controller.items.map(item => item.id).join(','), '0,1,2');
  assert.equal(controller.cursor, null);
  assert.equal(moreButton.disabled, false);
});
