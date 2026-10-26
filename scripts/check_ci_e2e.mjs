// Fixed upstream browser regression groups. N2's full-suite contract is separate.
// Credentials stay in memory; only fixed identifiers/statuses enter the result.
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile, realpath } from 'node:fs/promises';
import { dirname, basename, join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';

const groups = ['E01', 'E02', 'E03', 'E04', 'E05', 'E06'];
const results = groups.map(id => ({ id, status: 'not_run' }));
const contexts = [], pageErrors = [];
const acceptedDialogs = new WeakSet();
async function accepting(page, action) {
  acceptedDialogs.add(page);
  try { return await action(); } finally { acceptedDialogs.delete(page); }
}
let failureDiagnostic;
let browser, browserVersion, playwrightVersion, current, stage = 'fixture', failed = false, browserClosed = false;
const output = process.env.IDP_UI_OUTPUT_DIR;
assert.ok(output, 'IDP_UI_OUTPUT_DIR is required');
await mkdir(output, { recursive: true });
const button = (p, name) => p.getByRole('button', { name: new RegExp('^' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/([\u3400-\u9fff])(?=[\u3400-\u9fff])/g, '$1\\s*') + '$') });
const dialog = (p, name) => p.getByRole('dialog', { name, exact: true });
const drawer = p => dialog(p, '客户端配置');
const confirmation = p => dialog(p, '确认保存客户端配置');
const settle = p => p.waitForFunction(() => !document.querySelector('.management-client-loading, .ant-spin-spinning, .ant-spin-blur'));
const checked = async (name, fn) => { stage = name; await fn(); };
async function group(id, fn) {
  current = results.find(result => result.id === id);
  current.status = 'running'; const start = Date.now();
  await fn(); assert.equal(pageErrors.length, 0);
  current.duration_ms = Date.now() - start; current.status = 'passed';
  console.log(`PASS ${id}`); current = undefined;
}
try {
  const statePath = await realpath(process.env.IDP_UI_TEST_FIXTURE);
  const fixture = JSON.parse(await readFile(statePath, 'utf8'));
  assert.equal(dirname(statePath), await realpath(fixture.dir));
  assert.equal(dirname(dirname(statePath)), await realpath(tmpdir()));
  assert.match(basename(fixture.dir), /^idp-ui-b-[a-zA-Z0-9_-]+$/);
  assert.match(fixture.container, /^idp-ui-b-[a-f0-9]+$/);
  assert.equal(execFileSync('docker', ['inspect', '--format', '{{index .Config.Labels "idp.ui-b.fixture"}}', fixture.container], { encoding: 'utf8', timeout: 15000 }).trim(), fixture.dir);
  assert.deepEqual(Object.keys(fixture.schemas).sort(), ['disabled', 'enabled']);
  for (const [mode, schema] of Object.entries(fixture.schemas)) assert.match(schema, new RegExp(`^uib_${mode}_[a-f0-9]+$`));
  for (const key of ['enabled', 'disabled', 'fixed']) {
    const host = fixture.hosts[key], url = new URL(host.origin);
    assert.equal(url.protocol, 'http:'); assert.equal(url.hostname, '127.0.0.1');
    assert.ok(host.mount.startsWith('/') && host.ui.startsWith('/'));
  }
  playwrightVersion = JSON.parse(await readFile(join(dirname(process.env.IDP_UI_PLAYWRIGHT_PATH), 'package.json'), 'utf8')).version;
  const pinned = JSON.parse(await readFile(new URL('./n2-ci/package.json', import.meta.url), 'utf8')).dependencies.playwright;
  assert.equal(playwrightVersion, pinned, 'paired Playwright package version');
  const { chromium } = await import(pathToFileURL(process.env.IDP_UI_PLAYWRIGHT_PATH).href);
  stage = 'launch'; browser = await chromium.launch({ channel: 'chromium', headless: true });
  browserVersion = browser.version();
  async function context() {
    const c = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
    contexts.push(c); return c;
  }
  async function open(c, key = 'enabled', login = true) {
    const host = fixture.hosts[key], page = await c.newPage(); let bearer;
    page.setDefaultTimeout(15000); page.setDefaultNavigationTimeout(30000);
    page.on('pageerror', () => pageErrors.push('pageerror'));
    page.on('dialog', d => acceptedDialogs.has(page) ? d.accept() : d.dismiss());
    page.on('request', r => { if (new URL(r.url()).pathname.startsWith(host.mount + '/admin/')) bearer = r.headers().authorization ?? bearer; });
    const hash = key === 'disabled' ? '#/system/clients' : key === 'fixed' ? '#/tenants/tenant-a/home' : '#/platform/clients';
    await page.goto(host.origin + host.ui + '/' + hash);
    const t = { page, host, bearer: () => bearer };
    if (login) await signIn(t, key === 'fixed' ? 'tenant-a@example.test' : 'admin@example.test', fixture.password);
    return t;
  }
  async function signIn(t, email, password) {
    await t.page.getByLabel('邮箱', { exact: true }).fill(email);
    await t.page.getByLabel('密码', { exact: true }).fill(password);
    await button(t.page, '登录').click(); await t.page.locator('.management-shell').waitFor(); await settle(t.page);
  }
  async function request(t, path, headers = {}) {
    assert.ok(t.bearer()?.startsWith('Bearer '));
    return t.page.request.get(t.host.origin + t.host.mount + '/admin' + path, { headers: { authorization: t.bearer(), ...headers } });
  }
  async function read(t, path, headers) { const response = await request(t, path, headers); assert.equal(response.status(), 200); return response.json(); }
  async function session(t) {
    await button(t.page, '当前会话').click(); await dialog(t.page, '当前管理会话').waitFor();
    const value = await read(t, '/auth/session');
    await t.page.keyboard.press('Escape'); await dialog(t.page, '当前管理会话').waitFor({ state: 'hidden' }); return value;
  }
  async function locate(p, id) {
    await button(p, '按 ID 登记 / 编辑').click(); const modal = dialog(p, '按 ID 登记 / 编辑');
    await modal.getByLabel('客户端 ID', { exact: true }).fill(id);
    await button(modal, '读取配置').click(); await modal.waitFor({ state: 'hidden' });
    await drawer(p).waitFor(); await button(drawer(p), '重新读取配置').waitFor(); await settle(p);
  }
  async function review(p) { await button(drawer(p), '核对并保存').click(); await confirmation(p).waitFor(); }
  async function close(p) { await accepting(p, () => button(drawer(p), '关闭配置').click()); await drawer(p).waitFor({ state: 'hidden' }); }
  async function reread(p) {
    const response = p.waitForResponse(r => new URL(r.url()).pathname.endsWith('/clients/-/lookup'));
    await accepting(p, () => button(drawer(p), '重新读取配置').click()); assert.equal((await response).status(), 200); await settle(p);
  }
  let operator;
  const clientId = 'ci-e2e-' + randomBytes(6).toString('hex');
  await group('E01', async () => {
    const t = await open(await context(), 'enabled', false);
    await checked('E01.invalid_credentials', async () => {
      await t.page.getByLabel('邮箱', { exact: true }).fill('admin@example.test');
      await t.page.getByLabel('密码', { exact: true }).fill('synthetic-wrong-password');
      const response = t.page.waitForResponse(r => r.url().endsWith('/admin/auth/browser/login'));
      await button(t.page, '登录').click(); assert.equal((await response).status(), 401);
      await t.page.getByRole('alert').waitFor(); assert.equal(await t.page.locator('.management-shell').count(), 0);
    });
    await checked('E01.login_restore_logout', async () => {
      await signIn(t, 'admin@example.test', fixture.password); const before = await session(t);
      await t.page.reload(); await t.page.locator('.management-shell').waitFor(); assert.equal((await session(t)).session_id, before.session_id);
      const old = t.bearer(); await button(t.page, '退出登录').click(); await t.page.getByLabel('邮箱', { exact: true }).waitFor();
      const response = await t.page.request.get(t.host.origin + t.host.mount + '/admin/auth/session', { headers: { authorization: old } });
      assert.equal(response.status(), 401);
    });
  });
  await group('E02', async () => {
    await checked('E02.modes_and_scope', async () => {
      operator = await open(await context());
      for (const t of [operator, await open(await context(), 'disabled')]) {
        await t.page.getByRole('heading', { name: '客户端管理', exact: true }).waitFor();
        await locate(t.page, 'management-ui-b'); await drawer(t.page).getByText('正在编辑已有配置', { exact: false }).waitFor(); await close(t.page);
      }
      const fixed = await open(await context(), 'fixed'); let calls = 0;
      fixed.page.on('request', r => { if (new URL(r.url()).pathname.includes('/admin/clients')) calls++; });
      await fixed.page.evaluate(() => { location.hash = '#/platform/clients'; });
      await fixed.page.getByRole('heading', { name: '无权访问', exact: true }).waitFor(); assert.equal(calls, 0);
      assert.equal((await request(fixed, '/clients?limit=1', { 'x-embedded-idp-tenant-id': '0', 'x-embedded-idp-subject': 'synthetic-admin' })).status(), 403);
      const forged = await operator.page.request.get(operator.host.origin + operator.host.mount + '/admin/tenants', { headers: { 'x-embedded-idp-subject': 'synthetic-admin' } }); assert.equal(forged.status(), 401);
    });
  });
  await group('E03', async () => {
    await checked('E03.create_and_readback', async () => {
      const p = operator.page; await locate(p, clientId); await drawer(p).getByText('此 ID 尚未登记', { exact: false }).waitFor();
      await drawer(p).getByLabel('名称', { exact: true }).fill('CI synthetic client');
      await drawer(p).getByLabel('允许的回调地址（每行一个）', { exact: true }).fill('http://127.0.0.1/callback');
      await review(p); const posted = p.waitForResponse(r => r.url().endsWith('/clients/upsert') && r.request().method() === 'POST');
      await button(confirmation(p), '确认保存').click(); assert.equal((await posted).status(), 200);
      await p.getByText(/配置已保存/).first().waitFor(); await settle(p); await close(p);
      await locate(p, clientId); assert.equal(await drawer(p).getByLabel('名称', { exact: true }).inputValue(), 'CI synthetic client');
      assert.equal((await read(operator, '/clients/-/lookup?client_id=' + clientId)).client.client_name, 'CI synthetic client'); await close(p);
    });
  });
  await group('E04', async () => {
    await checked('E04.revoke_cancel_confirm', async () => {
      stage = 'E04.open_first'; const first = await open(await context(), 'fixed');
      stage = 'E04.open_second'; const second = await open(await context(), 'fixed');
      stage = 'E04.read_sessions'; const a = await session(first), b = await session(second), p = operator.page;
      assert.notEqual(a.session_id, b.session_id);
      stage = 'E04.navigate';
      await accepting(p, async () => {
        await p.evaluate(() => { location.hash = '#/tenants/tenant-a/sessions'; });
        await p.getByRole('heading', { name: '会话管理', exact: true }).waitFor(); await settle(p);
      });
      stage = 'E04.query';
      await p.getByLabel('用户 ID', { exact: true }).fill(a.account_id); await button(p, '查询').click();
      stage = 'E04.open_detail';
      await button(p, `查看会话 ${a.session_id}`).click(); const detail = dialog(p, '会话详情');
      const endpoint = `/sessions/${a.session_id}/revoke`; let writes = 0;
      p.on('request', r => { if (r.method() === 'POST' && new URL(r.url()).pathname.endsWith(endpoint)) writes++; });
      stage = 'E04.cancel';
      await button(detail, '撤销会话').click(); await button(dialog(p, '确认撤销会话'), '取消').click();
      stage = 'E04.verify_cancel';
      assert.equal(writes, 0); assert.equal((await read(operator, `/sessions/${a.session_id}`, { 'x-embedded-idp-tenant-id': 'tenant-a' })).status, 'active');
      stage = 'E04.confirm';
      await button(detail, '撤销会话').click(); const response = p.waitForResponse(r => new URL(r.url()).pathname.endsWith(endpoint));
      await button(dialog(p, '确认撤销会话'), '确认撤销').click(); assert.ok((await response).ok()); assert.equal(writes, 1);
      stage = 'E04.verify_revoke';
      assert.equal((await read(operator, `/sessions/${a.session_id}`, { 'x-embedded-idp-tenant-id': 'tenant-a' })).status, 'revoked');
      assert.equal((await request(first, '/auth/session')).status(), 401); assert.equal((await read(second, '/auth/session')).session_id, b.session_id);
    });
  });
  await group('E05', async () => {
    const t = await open(await context()), p = t.page, base = t.host.origin + t.host.mount + '/admin/clients';
    await checked('E05.injected_read_errors', async () => {
      for (const status of [403, 500]) {
        const pattern = url => url.pathname.endsWith('/clients/-/lookup') && url.searchParams.get('client_id') === clientId;
        await p.route(pattern, route => route.fulfill({ status, json: {} })); await locate(p, clientId);
        assert.equal(await drawer(p).getByLabel('名称', { exact: true }).count(), 0); assert.equal(await button(drawer(p), '核对并保存').count(), 0);
        await close(p); await p.unroute(pattern);
      }
      const pattern = url => url.href.split('?')[0] === base;
      await p.route(pattern, route => route.fulfill({ status: 500, json: {} })); await button(p, '刷新客户端').click();
      await p.getByText('读取客户端配置失败', { exact: true }).waitFor(); assert.equal(await p.getByText('尚无客户端配置，可按 ID 登记接入应用。', { exact: true }).count(), 0);
      await p.unroute(pattern); await button(p, '刷新客户端').click(); await settle(p);
    });
    await checked('E05.real_write_lost_response', async () => {
      await locate(p, clientId); await drawer(p).getByLabel('名称', { exact: true }).fill('CI uncertain response');
      let writes = 0, verified = false, routeFailure = false;
      await p.route(base + '/upsert', async route => {
        try {
          writes++; const response = await route.fetch(); assert.ok(response.ok());
          assert.equal((await read(t, '/clients/-/lookup?client_id=' + clientId)).client.client_name, 'CI uncertain response'); verified = true;
        } catch { routeFailure = true; }
        await route.abort('failed');
      });
      await review(p); await button(confirmation(p), '确认保存').click();
      await drawer(p).getByText('保存结果未确认，请勿重复提交', { exact: true }).waitFor();
      assert.equal(routeFailure, false); assert.equal(verified, true); assert.equal(writes, 1); assert.equal(await button(drawer(p), '核对并保存').isDisabled(), true);
      await p.unroute(base + '/upsert'); await reread(p);
      assert.equal(await button(drawer(p), '核对并保存').isDisabled(), false);
      assert.equal(await drawer(p).getByLabel('名称', { exact: true }).inputValue(), 'CI uncertain response'); assert.equal(writes, 1); await close(p);
    });
    await checked('E05.injected_401_exits_session', async () => {
      await p.route(url => url.href.split('?')[0] === base, route => route.fulfill({ status: 401, json: {} }));
      await button(p, '刷新客户端').click(); await p.getByLabel('邮箱', { exact: true }).waitFor(); assert.equal(await p.locator('.management-shell').count(), 0);
    });
  });
  await group('E06', async () => {
    await checked('E06.real_two_tab_refresh', async () => {
      const c = await context(), host = fixture.hosts.enabled;
      for (const action of ['login', 'restore']) await c.route(host.origin + host.mount + '/admin/auth/browser/' + action, async route => {
        const response = await route.fetch(); if (response.status() !== 200) return route.fulfill({ response });
        const body = await response.json(); body.tokens.access_expires_at_unix_secs = Math.floor(Date.now() / 1000) + 300; await route.fulfill({ response, json: body });
      });
      const first = await open(c), second = await open(c, 'enabled', false); await second.page.locator('.management-shell').waitFor();
      const original = await session(first); assert.equal((await session(second)).session_id, original.session_id);
      let active = 0, maximum = 0; const statuses = [];
      await c.route(host.origin + host.mount + '/admin/auth/browser/refresh', async route => {
        active++; maximum = Math.max(maximum, active);
        try { await new Promise(resolve => setTimeout(resolve, 150)); const response = await route.fetch(); statuses.push(response.status()); await route.fulfill({ response }); } finally { active--; }
      });
      for (const t of [first, second]) await t.page.evaluate(() => { const now = Date.now.bind(Date); Date.now = () => now() + 280000; });
      await Promise.all([first, second].map(async t => {
        const response = t.page.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname === host.mount + '/admin/clients');
        await button(t.page, '刷新客户端').click(); assert.equal((await response).status(), 200);
      }));
      assert.equal(maximum, 1); assert.deepEqual(statuses, [200, 200]);
      for (const t of [first, second]) assert.equal((await session(t)).session_id, original.session_id);
      const other = await open(c, 'disabled'), otherSession = await session(other);
      await button(first.page, '退出登录').click(); await first.page.getByLabel('邮箱', { exact: true }).waitFor(); await second.page.getByLabel('邮箱', { exact: true }).waitFor();
      await other.page.reload(); await other.page.locator('.management-shell').waitFor(); assert.equal((await session(other)).session_id, otherSession.session_id);
    });
  });
} catch (error) {
  const allowed = ['AssertionError', 'TimeoutError', 'TypeError', 'SyntaxError', 'Error'];
  const line = String(error.stack ?? '').match(/check_ci_e2e\.mjs:(\d+):\d+/)?.[1];
  failureDiagnostic = { type: allowed.includes(error.name) ? error.name : 'Error', checker_line: line ? Number(line) : null };
  failed = true;
  if (current) { current.status = 'failed'; current.failed_stage = stage; }
  console.error(`FAIL ${stage}`); // Never print Playwright errors, URLs, response bodies or tokens.
} finally {
  const cleanupErrors = [];
  for (const c of contexts) { try { await c.close(); } catch { cleanupErrors.push('context_close'); } }
  if (browser) { try { await browser.close(); browserClosed = true; } catch { cleanupErrors.push('browser_close'); } }
  const complete = !failed && cleanupErrors.length === 0 && results.every(r => r.status === 'passed') && pageErrors.length === 0;
  await writeFile(join(output, 'ci-e2e-results.json'), JSON.stringify({ schema_version: 1, suite: 'critical-e2e', status: complete ? 'passed' : 'failed', browser_version: browserVersion ?? null, playwright_version: playwrightVersion ?? null, groups: results,
    complete, failure_stage: failed ? stage : null, failure_diagnostic: failureDiagnostic ?? null, page_error_count: pageErrors.length, browser_closed: browserClosed, cleanup_errors: cleanupErrors,
    viewport: { width: 1440, height: 1000 }, injections: ['E05: HTTP errors and lost response after real write/readback', 'E06: client expiry/clock and refresh response delay; real server rotations'],
  }, null, 2) + '\n');
  if (!complete) process.exitCode = 1;
}
