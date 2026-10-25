// Offline only: no imports of a live checker, browser, Docker, HTTP or database.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFunctionalCoverage, finalizeFunctionalRun, functionalCaseSourceMatches, functionalManifest, isFunctionalProfile } from './management_functional.mjs';
import { browserLaunchOptions } from './management_browser.mjs';

const root = await mkdtemp(join(tmpdir(), 'idp-n2-functional-offline-'));
const env = { IDP_UI_PROFILE: 'ci-functional' };
let checks = 0;
function check(name, action) { action(); checks++; console.log(`PASS ${name}`); }
async function asyncCheck(name, action) { await action(); checks++; console.log(`PASS ${name}`); }
const readCoverage = directory => readFile(join(directory, 'functional-coverage.json'), 'utf8').then(JSON.parse);
const smallManifest = { schemaVersion: 1, profile: 'ci-functional', suites: { mock: { cases: [
  { id: 'mock-selected', case: 'selected', source: { path: 'mock.mjs', line: 1 }, selection: 'selected' },
  { id: 'mock-excluded', case: 'excluded', source: { path: 'mock.mjs', line: 2 }, selection: 'excluded', reason: 'visual' },
] } } };
function mock(name, manifest = smallManifest) {
  const directory = join(root, name);
  return [createFunctionalCoverage('mock', directory, { env, manifest }), directory];
}

// Extract the exact guarded blocks from the real checkers and execute them with
// the CI flag. All browser variables are deliberately absent: any branch entry
// would fail before it could touch a service. This is a branch test, not UI proof.
function closingBrace(source, start) {
  let depth = 0, quote = null, comment = null;
  for (let i = start; i < source.length; i++) {
    const c = source[i], next = source[i + 1];
    if (comment === '//') { if (c === '\n') comment = null; continue; }
    if (comment === '/*') { if (c === '*' && next === '/') { comment = null; i++; } continue; }
    if (quote) { if (c === '\\') i++; else if (c === quote) quote = null; continue; }
    if (c === '/' && next === '/') { comment = '//'; i++; continue; }
    if (c === '/' && next === '*') { comment = '/*'; i++; continue; }
    if (['"', "'", '`'].includes(c)) { quote = c; continue; }
    if (c === '{') depth++;
    if (c === '}' && --depth === 0) return i;
  }
  throw new Error('Unbalanced visual block');
}
try {
  check('CI uses the paired full headless Chromium channel', () => {
    assert.deepEqual(browserLaunchOptions(env), { channel: 'chromium', headless: true });
  });
  check('CI refuses headed and layout conflicts', () => {
    assert.throws(() => browserLaunchOptions({ ...env, IDP_UI_HEADED: '1' }), /forbids/);
    assert.throws(() => browserLaunchOptions({ ...env, IDP_UI_N2_LAYOUT: '1' }), /forbids/);
  });
  check('default browser options preserve the existing executable and headed flag', () => {
    assert.deepEqual(browserLaunchOptions({ IDP_UI_HEADED: '1', IDP_UI_BROWSER_EXECUTABLE: '/mock/chrome' }),
      { headless: false, executablePath: '/mock/chrome' });
  });
  check('only the exact explicit profile enables CI selection', () => {
    assert.equal(isFunctionalProfile({}), false);
    assert.equal(isFunctionalProfile({ IDP_UI_PROFILE: 'functional-only' }), false);
    assert.equal(isFunctionalProfile(env), true);
  });
  await asyncCheck('default desktop reporter does not write or reject legacy cases', async () => {
    const directory = join(root, 'legacy');
    const reporter = createFunctionalCoverage('not-a-suite', directory, { env: {} });
    reporter.pass('legacy'); reporter.complete();
    await assert.rejects(readCoverage(directory), { code: 'ENOENT' });
  });
  await asyncCheck('initial and incremental coverage cannot claim completion', async () => {
    const [reporter, directory] = mock('incremental');
    assert.equal((await readCoverage(directory)).status, 'running');
    assert.equal((await readCoverage(directory)).missing.length, 1);
    reporter.pass('selected');
    assert.equal((await readCoverage(directory)).status, 'running');
    assert.deepEqual((await readCoverage(directory)).missing, []);
    reporter.complete(); assert.equal((await readCoverage(directory)).status, 'passed');
  });
  for (const [name, action, reason] of [
    ['unknown', r => r.pass('unrecorded'), 'unknown-case'],
    ['excluded', r => r.pass('excluded'), 'excluded-case-executed'],
    ['duplicate', r => { r.pass('selected'); r.pass('selected'); }, 'duplicate-case'],
    ['missing', r => r.complete(), 'missing-selected-cases'],
    ['late', r => { r.pass('selected'); r.complete(); r.pass('selected'); }, 'case-after-finalization'],
  ]) await asyncCheck(`reject and persist ${name} cases`, async () => {
    const [reporter, directory] = mock(name);
    assert.throws(() => action(reporter), new RegExp(reason));
    const result = await readCoverage(directory);
    assert.equal(result.status, 'failed'); assert.equal(result.rejection, reason);
  });
  check('reject unknown suite and malformed duplicate manifest', () => {
    assert.throws(() => createFunctionalCoverage('absent', root, { env, manifest: smallManifest }), /Unknown/);
    const manifest = structuredClone(smallManifest);
    manifest.suites.mock.cases.push(manifest.suites.mock.cases[0]);
    assert.throws(() => mock('bad', manifest), /Duplicate/);
  });
  const allIds = new Set();
  for (const [suite, definition] of Object.entries(functionalManifest.suites)) {
    await asyncCheck(`${suite}: every selected concrete case completes; exclusions remain explicit`, async () => {
      const directory = join(root, suite);
      const reporter = createFunctionalCoverage(suite, directory, { env });
      for (const item of definition.cases) {
        assert.ok(!allIds.has(item.id), 'Global semantic IDs are unique'); allIds.add(item.id);
        assert.ok(item.id.startsWith('N2-' + suite.toUpperCase() + '-'));
        const source = await readFile(new URL('../' + item.source.path, import.meta.url), 'utf8');
        assert.ok(functionalCaseSourceMatches(item.case, source.split('\n')[item.source.line - 1]),
          'Mapped case name must match the literal, fixed template text, or explicit branch of its source PASS');
        if (item.selection === 'selected') reporter.pass(item.case);
        else assert.ok(item.reason);
      }
      reporter.complete();
      const result = await readCoverage(directory);
      assert.equal(result.status, 'passed'); assert.deepEqual(result.missing, []);
      assert.equal(result.executed.length, definition.cases.filter(c => c.selection === 'selected').length);
      assert.equal(result.excluded.length, definition.cases.filter(c => c.selection === 'excluded').length);
    });
  }
  check('case mapping rejects a name that only points at a PASS line', () => {
    const item = functionalManifest.suites.navigation.cases.find(c => c.selection === 'selected');
    assert.ok(item);
    const source = readFileSync(new URL('../' + item.source.path, import.meta.url), 'utf8').split('\n')[item.source.line - 1];
    assert.equal(functionalCaseSourceMatches('unrelated semantic case name', source), false);
    assert.equal(functionalCaseSourceMatches('tenant synthetic test', 'pass(`tenant ${id} test`)'), true);
  });
  await asyncCheck('all cases plus a business or page error remain failed after cleanup', async () => {
    const [reporter, directory] = mock('business-error'); reporter.pass('selected');
    const failure = Object.assign(new Error('details omitted'), { name: 'AssertionError' });
    let contextClosed = false, browserClosed = false;
    const simulateChecker = async () => {
      let caught;
      try { throw failure; }
      catch (error) { caught = error; throw error; }
      finally {
        await finalizeFunctionalRun({ coverage: reporter, contexts: [{ close: async () => { contextClosed = true; } }],
          browser: { close: async () => { browserClosed = true; } }, resultPath: join(directory, 'results.json'),
          result: { cases: ['selected'], pageErrors: ['TypeError'] }, failure: caught });
      }
    };
    await assert.rejects(simulateChecker(), error => error === failure);
    const proof = await readFile(join(directory, 'results.json'), 'utf8').then(JSON.parse);
    assert.equal(proof.complete, false); assert.equal(proof.failure.name, 'AssertionError');
    assert.deepEqual(proof.pageErrors, ['TypeError']); assert.equal(contextClosed && browserClosed, true);
    assert.equal((await readCoverage(directory)).status, 'failed');
  });
  await asyncCheck('context-close failure does not skip other contexts or browser close and fails the run', async () => {
    const [reporter, directory] = mock('context-cleanup'); reporter.pass('selected');
    let remainingClosed = false, browserClosed = false;
    await assert.rejects(finalizeFunctionalRun({ coverage: reporter,
      contexts: [{ close: async () => { throw Object.assign(new Error('private details'), { name: 'ContextCloseError' }); } },
        { close: async () => { remainingClosed = true; } }],
      browser: { close: async () => { browserClosed = true; } }, resultPath: join(directory, 'results.json'), result: { cases: ['selected'] } }), /Browser cleanup failed/);
    const proof = await readFile(join(directory, 'results.json'), 'utf8').then(JSON.parse);
    assert.equal(remainingClosed && browserClosed, true); assert.equal(proof.complete, false);
    assert.equal(proof.cleanupErrors[0].error, 'ContextCloseError'); assert.equal(proof.failure.name, 'Error');
    assert.equal((await readCoverage(directory)).status, 'failed');
  });
  await asyncCheck('browser-close failure fails coverage and preserves result evidence', async () => {
    const [reporter, directory] = mock('browser-cleanup'); reporter.pass('selected');
    await assert.rejects(finalizeFunctionalRun({ coverage: reporter, contexts: [],
      browser: { close: async () => { throw Object.assign(new Error('browser detail'), { name: 'BrowserCloseError' }); } },
      resultPath: join(directory, 'results.json'), result: { cases: ['selected'] } }), /Browser cleanup failed/);
    const proof = await readFile(join(directory, 'results.json'), 'utf8').then(JSON.parse);
    assert.equal(proof.complete, false); assert.equal(proof.cleanupErrors[0].error, 'BrowserCloseError');
    assert.equal((await readCoverage(directory)).status, 'failed');
  });
  await asyncCheck('page errors delivered during cleanup cannot finalize passed coverage', async () => {
    const [reporter, directory] = mock('late-page-error'); reporter.pass('selected');
    const pageErrors = [];
    await assert.rejects(finalizeFunctionalRun({ coverage: reporter,
      contexts: [{ close: async () => { pageErrors.push('TypeError'); } }], browser: { close: async () => {} },
      resultPath: join(directory, 'results.json'), result: { cases: ['selected'], pageErrors } }), /Browser page errors/);
    const proof = await readFile(join(directory, 'results.json'), 'utf8').then(JSON.parse);
    assert.equal(proof.complete, false); assert.deepEqual(proof.pageErrors, ['TypeError']);
    assert.equal((await readCoverage(directory)).status, 'failed');
  });
  await asyncCheck('only successful assertions and all cleanup produce passed coverage', async () => {
    const [reporter, directory] = mock('clean-success'); reporter.pass('selected');
    await finalizeFunctionalRun({ coverage: reporter, contexts: [{ close: async () => {} }], browser: { close: async () => {} },
      resultPath: join(directory, 'results.json'), result: { cases: ['selected'], pageErrors: [] } });
    const proof = await readFile(join(directory, 'results.json'), 'utf8').then(JSON.parse);
    assert.equal(proof.complete, true); assert.deepEqual(proof.cleanupErrors, []); assert.equal(proof.failure, null);
    assert.equal((await readCoverage(directory)).status, 'passed');
  });
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  for (const suite of Object.keys(functionalManifest.suites)) {
    await asyncCheck(`${suite}: exact visual blocks are unreachable in CI`, async () => {
      const source = await readFile(new URL(`./check_management_${suite}.mjs`, import.meta.url), 'utf8');
      assert.match(source, /chromium\.launch\(browserLaunchOptions\(\)\)/);
      assert.match(source, /finalizeFunctionalRun\(/);
      for (const match of source.matchAll(/if \(!functionalOnly(?: && process\.env\.IDP_UI_N2_LAYOUT === '1')?\) \{/g)) {
        const start = source.indexOf('{', match.index), end = closingBrace(source, start);
        const guarded = source.slice(match.index, end + 1);
        await new AsyncFunction('functionalOnly', 'process', guarded)(true, { env: { IDP_UI_N2_LAYOUT: '1' } });
      }
    });
  }
  await asyncCheck('F keeps desktop keyboard main flow plus all four functional modules', async () => {
    const source = await readFile(new URL('./check_management_console.mjs', import.meta.url), 'utf8');
    for (const name of ['runTenantChecks', 'runPermissionFocusChecks', 'runPaginationChecks', 'runStateChecks']) assert.match(source, new RegExp(`await ${name}\\(`));
    assert.match(source, /functionalOnly \? '#\/platform\/clients' : '#\/platform\/home'/);
    for (const name of ['read-only current-session drawer', 'keyboard client filter lookup validation', 'permission editor and nested SafeConfirm']) {
      assert.ok(functionalManifest.suites.console.cases.some(c => c.selection === 'selected' && c.case.startsWith(name)));
    }
  });
  await asyncCheck('security transmitted modules mask visual calls and retain functional cancellation', async () => {
    const devices = await readFile(new URL('./management_security_devices.mjs', import.meta.url), 'utf8');
    const sessions = await readFile(new URL('./management_security_sessions.mjs', import.meta.url), 'utf8');
    assert.match(devices, /if \(!functionalOnly\) await p\.setViewportSize\(\{ width: 320/);
    assert.match(devices, /if \(!functionalOnly\) await review\.screenshot\([^\n]+; await accepting\(p,/);
    assert.match(sessions, /await detail\.getByLabel\('审计变更内容'\)\.waitFor\(\); if \(!functionalOnly\) await detail\.screenshot/);
    for (const source of [devices, sessions]) for (const line of source.split('\n').filter(l => l.includes('.screenshot('))) assert.match(line, /if \(!functionalOnly\) await [^;]*\.screenshot/);
  });
  await asyncCheck('two-tab refresh probe waits for both real reload completions', async () => {
    const source = await readFile(new URL('./check_management_n2_mac.mjs', import.meta.url), 'utf8');
    const start = source.indexOf('  await Promise.all([first, second].map(', source.indexOf('Date.now = () => originalNow() + 280000'));
    const end = source.indexOf('  for (const t of [first, second]) assert.equal', start);
    assert.ok(start >= 0 && end > start);
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    await new AsyncFunction('assert', `
      let rotations = 0, maximum = 1; const refreshResponses = [], timers = [];
      function tab(delay) {
        const page = { delay, listeners: [], waitForFunction: async () => true };
        page.waitForResponse = predicate => new Promise(resolve => {
          page.listeners.push(response => { if (predicate(response)) resolve(response); });
        });
        return { page, host: { mount: '/identity' } };
      }
      const first = tab(10), second = tab(30);
      const button = page => ({ click: async (options = {}) => {
        if (options.trial) return;
        timers.push(setTimeout(() => {
          rotations++; refreshResponses.push(200);
          const response = path => ({ request: () => ({ method: () => 'GET' }),
            url: () => 'http://127.0.0.1' + path, status: () => 200 });
          for (const listener of page.listeners) {
            listener(response('/unrelated'));
            listener(response('/identity/admin/clients?limit=20'));
          }
        }, page.delay));
      } });
      try { ${source.slice(start, end)} }
      finally { timers.forEach(clearTimeout); }
    `)(assert);
  });
  console.log(JSON.stringify({ mode: 'offline-mocks-and-source-branches', checks, suites: Object.keys(functionalManifest.suites), actualBrowserRuns: 0 }));
} finally { await rm(root, { recursive: true, force: true }); }
