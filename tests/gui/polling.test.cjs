// Run with: node --test tests/gui/*.test.cjs
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

function deferred() {
  let resolvePromise;
  const promise = new Promise(resolve => { resolvePromise = resolve; });
  return {promise, resolve: resolvePromise};
}

function load() {
  const context = vm.createContext({CVEAgent: {}, encodeURIComponent});
  vm.runInContext(
    readFileSync(resolve(__dirname, '../../src/cve_agent/gui/static/polling.js'), 'utf8'),
    context,
  );
  return context.CVEAgent.polling;
}

function fixture(request, retryDelays = [10, 20]) {
  const {AnalysisPoller} = load();
  const timers = [];
  const cleared = [];
  const poller = new AnalysisPoller(request, {
    pollInterval: 5,
    retryDelays,
    setTimer: (callback, delay) => {
      const timer = {callback, delay};
      timers.push(timer);
      return timer;
    },
    clearTimer: timer => { cleared.push(timer); },
  });
  return {poller, timers, cleared};
}

test('transient polling failures back off, exhaust, and reconnect without submitting', async () => {
  const paths = [];
  let connected = false;
  const request = async path => {
    paths.push(path);
    if (!connected) throw Object.assign(new Error('offline'), {transient: true});
    return {id: 'pending-one', lifecycle: 'running'};
  };
  const {poller, timers} = fixture(request);
  const interrupted = [];
  let exhausted = 0;
  let reconnecting = 0;

  await poller.start('pending-one', {
    onInterrupted: state => interrupted.push(state),
    onExhausted: () => { exhausted += 1; },
    onReconnecting: () => { reconnecting += 1; },
  });
  assert.equal(timers[0].delay, 10);
  await timers[0].callback();
  assert.equal(timers[1].delay, 20);
  await timers[1].callback();
  assert.equal(exhausted, 1);
  assert.equal(poller.isTracking(), true);

  connected = true;
  const retry = poller.retry();
  assert.ok(retry);
  await retry;
  assert.equal(reconnecting, 1);
  assert.equal(timers.at(-1).delay, 5);
  assert.ok(paths.every(path => path === '/api/analyses/pending-one'));
  assert.equal(paths.some(path => path === '/api/analyses'), false);
  assert.deepEqual(interrupted.map(state => state.delay), [10, 20]);
  poller.stop();
});

test('stale responses and cleared timers cannot override a newer selection', async () => {
  const old = deferred();
  const calls = [];
  const request = path => {
    calls.push(path);
    if (path.endsWith('old')) return old.promise;
    return Promise.resolve({id: 'new', lifecycle: 'completed'});
  };
  const {poller, timers} = fixture(request);
  const seen = [];
  const oldRun = poller.start('old', {onData: analysis => seen.push(analysis.id)});
  await poller.start('new', {onData: analysis => seen.push(analysis.id)});
  old.resolve({id: 'old', lifecycle: 'running'});
  await oldRun;

  assert.deepEqual(seen, ['new']);
  assert.equal(timers.length, 0);

  let first = true;
  const scheduled = fixture(async () => {
    if (first) { first = false; return {id: 'timer-old', lifecycle: 'running'}; }
    return {id: 'timer-new', lifecycle: 'completed'};
  });
  const timerSeen = [];
  await scheduled.poller.start('timer-old', {onData: item => timerSeen.push(item.id)});
  const staleTimer = scheduled.timers[0];
  await scheduled.poller.start('timer-new', {onData: item => timerSeen.push(item.id)});
  await staleTimer.callback();
  assert.deepEqual(timerSeen, ['timer-old', 'timer-new']);
});

test('a failed analysis is terminal analysis data, not a connection interruption', async () => {
  const {poller} = fixture(async () => ({id: 'one', lifecycle: 'failed', error: 'classification failed'}));
  const events = [];
  await poller.start('one', {
    onData: analysis => events.push(`data:${analysis.lifecycle}`),
    onTerminal: analysis => events.push(`terminal:${analysis.lifecycle}`),
    onInterrupted: () => events.push('interrupted'),
    onExhausted: () => events.push('exhausted'),
  });
  assert.deepEqual(events, ['data:failed', 'terminal:failed']);
  assert.equal(poller.isTracking(), false);
});

test('submission guards remain closed while posting, polling, or reconnecting', () => {
  const {canStartAnalysis, hasActiveAnalysis} = load();
  const idlePoller = {isTracking: () => false};
  const activePoller = {isTracking: () => true};
  const session = {submitting: false, activeRunId: null, analysis: null};

  assert.equal(canStartAnalysis(session, idlePoller), true);
  assert.equal(canStartAnalysis({...session, submitting: true}, idlePoller), false);
  assert.equal(canStartAnalysis({...session, activeRunId: 'pending'}, idlePoller), false);
  assert.equal(canStartAnalysis(session, activePoller), false);
  assert.equal(hasActiveAnalysis({...session, analysis: {lifecycle: 'running'}}, idlePoller), true);
  assert.equal(canStartAnalysis({...session, analysis: {lifecycle: 'failed'}}, idlePoller), true);
});
