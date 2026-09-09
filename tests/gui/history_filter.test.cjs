// Run with: node --test tests/gui/history_filter.test.cjs
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

function element(tag = 'div') {
  return {
    tag, children: [], value: '', classList: {toggle() {}},
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    addEventListener() {},
  };
}

function fixture() {
  const context = vm.createContext({document: {addEventListener() {}, createElement: element}});
  vm.runInContext(readFileSync(resolve(__dirname, '../../src/cve_agent/gui/static/app.js'), 'utf8'), context);
  const list = element();
  const search = element('input');
  context.list = list;
  context.search = search;
  context.more = element('button');
  vm.runInContext(`
    elements.historyList = list;
    elements.historySearch = search;
    elements.historyMore = more;
    state.history = ['CVE-2021-26855', 'CVE-2020-11022', 'CVE-2020-2889'].map((cve_id, i) => ({
      id: String(i), cve_id, updated_at: '2026-09-09', taxonomy_name: 'Fixture', labels: [], status: 'classified'
    }));
  `, context);
  const filter = query => {
    search.value = query;
    vm.runInContext('renderHistory()', context);
    return list.children.filter(child => child.tag === 'button').map(button => button.children[0].children[0].textContent);
  };
  return {filter, context};
}

test('unfiltered server rows cannot show unrelated CVEs for an exact search', () => {
  const {filter} = fixture();
  assert.deepEqual(filter('CVE-2021-26855'), ['CVE-2021-26855']);
});

test('fragments, case, no matches and clearing immediately update visible rows', () => {
  const {filter} = fixture();
  assert.deepEqual(filter('2889'), ['CVE-2020-2889']);
  assert.deepEqual(filter('2020'), ['CVE-2020-11022', 'CVE-2020-2889']);
  assert.deepEqual(filter(' cve-2021-26855 '), ['CVE-2021-26855']);
  assert.deepEqual(filter('missing'), []);
  assert.equal(filter('').length, 3);
});

test('current input wins over stale query state during any rerender', () => {
  const {filter, context} = fixture();
  vm.runInContext('state.historyQuery = "2020"', context);
  assert.deepEqual(filter('CVE-2021-26855'), ['CVE-2021-26855']);
});
