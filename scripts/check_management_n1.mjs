// N1 browser checks: real disposable UI-B fixture, with explicitly injected responses.
import { browserLaunchOptions } from './management_browser.mjs';
import { createFunctionalCoverage, finalizeFunctionalRun } from './management_functional.mjs';
import assert from 'node:assert/strict';
import { readFile, mkdir } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';

const fixture = JSON.parse(await readFile(process.env.IDP_UI_TEST_FIXTURE, 'utf8'));
assert.match(fixture.container, /^idp-ui-b-[a-f0-9]+$/);
for (const schema of Object.values(fixture.schemas)) assert.match(schema, /^uib_(enabled|disabled)_[a-f0-9]+$/);
for (const host of Object.values(fixture.hosts)) assert.equal(new URL(host.origin).hostname, '127.0.0.1');
const { chromium } = await import(process.env.IDP_UI_PLAYWRIGHT_PATH ? pathToFileURL(process.env.IDP_UI_PLAYWRIGHT_PATH).href : 'playwright');
const browser = await chromium.launch(browserLaunchOptions());
const output = process.env.IDP_UI_OUTPUT_DIR ?? fixture.dir;
await mkdir(output, { recursive: true });
const coverage = createFunctionalCoverage('n1', output);
const cases = [], errors = [], contexts = [];
const heldResponses = new Set();
let failure;
const pass = name => { coverage.pass(name); cases.push(name); console.log(`PASS ${name}`); };
const button = (parent, name) => parent.getByRole('button', { name: new RegExp('^' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/([\u3400-\u9fff])(?=[\u3400-\u9fff])/g, '$1\\s*') + '$') });
const drawer = page => page.getByRole('dialog', { name: '客户端配置', exact: true });
const confirm = page => page.getByRole('dialog', { name: '确认保存客户端配置', exact: true });
const suffix = randomBytes(6).toString('hex');
async function open(key = 'enabled', hash = '#/platform/clients') {
  const host = fixture.hosts[key]; const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } }); contexts.push(context);
  const page = await context.newPage(); page.setDefaultTimeout(15000); page.on('pageerror', e => errors.push(e.name)); page.on('dialog', d => d.accept());
  let bearer; page.on('request', r => { if (new URL(r.url()).pathname.startsWith(`${host.mount}/admin/`)) bearer = r.headers().authorization ?? bearer; });
  await page.goto(`${host.origin}${host.ui}/${hash}`); await page.getByLabel('邮箱', { exact: true }).fill('admin@example.test');
  await page.getByLabel('密码', { exact: true }).fill(fixture.password); await page.getByRole('button', { name: /^登\s*录$/ }).click(); await page.locator('.management-shell').waitFor();
  return { page, host, context, bearer: () => bearer };
}
async function locate(page, id) {
  await button(page, '按 ID 登记 / 编辑').click(); const modal = page.getByRole('dialog', { name: '按 ID 登记 / 编辑', exact: true });
  await modal.getByLabel('客户端 ID', { exact: true }).fill(id); await button(modal, '读取配置').click(); await drawer(page).waitFor();
  await page.waitForFunction(() => !document.querySelector('.management-client-editor .management-client-loading'));
}
async function close(page) { await button(drawer(page), '关闭配置').click(); await drawer(page).waitFor({ state: 'hidden' }); }
async function review(page) { await button(drawer(page), '核对并保存').click(); await confirm(page).waitFor(); }
async function reload(page) {
  const response = page.waitForResponse(r => new URL(r.url()).pathname.endsWith('/clients/-/lookup') && r.request().method() === 'GET');
  await button(drawer(page), '重新读取配置').click(); await response;
  await page.waitForFunction(() => !document.querySelector('.management-client-editor .management-client-loading'));
}
const settings = page => page.getByRole('dialog', { name: '租户设置', exact: true });
const tenantConfirm = page => page.getByRole('dialog', { name: '确认租户变更', exact: true });
const tenantUrl = t => `${t.host.origin}${t.host.mount}/admin/tenants`;
const tenantRead = (t, id) => `${tenantUrl(t)}?tenant_id=${encodeURIComponent(id)}&limit=2`;
async function readTenant(t, id) {
  const response = await t.page.request.get(tenantRead(t, id), { headers: { authorization: t.bearer() } });
  assert.equal(response.status(), 200); const data = await response.json();
  assert.equal(data.has_more, false); assert.equal(data.items.length, 1); assert.equal(data.items[0].tenant_id, id);
  return data.items[0];
}
async function openTenant(t, id, wait = true) {
  const before = await readTenant(t, id);
  await t.page.getByLabel('租户 ID', { exact: true }).fill(id); await button(t.page, '查询').click();
  await button(t.page, `设置租户 ${before.name}`).click(); await settings(t.page).waitFor();
  if (wait) await t.page.waitForFunction(() => !document.querySelector('.management-workflow-editor .management-workflow-loading'));
  return before;
}
async function answerDialog(page, action, accept) {
  page.removeAllListeners('dialog'); const observed = page.waitForEvent('dialog');
  page.once('dialog', d => accept ? d.accept() : d.dismiss());
  await action(); const dialog = await observed; assert.equal(dialog.type(), 'confirm');
  page.on('dialog', d => d.accept()); return dialog.message();
}
function gate() {
  let release; const promise = new Promise(resolve => { release = resolve; }); heldResponses.add(release);
  return { promise, release };
}
const bounded = (promise, label) => Promise.race([promise, new Promise((_, reject) => {
  const timer = setTimeout(() => reject(new Error(`Timed out: ${label}`)), 15000); timer.unref();
})]);
try {
  const t = await open(); const { page, host } = t; const base = `${host.origin}${host.mount}/admin/clients`;
  await page.getByRole('heading', { name: '客户端管理', exact: true }).waitFor();
  let posts = 0; const requests = [];
  page.on('request', r => { const u = new URL(r.url()); if (!u.pathname.startsWith(`${host.mount}/admin/clients`)) return; requests.push({ path: u.pathname, query: u.searchParams.get('client_id'), method: r.method() });
    assert.ok(!r.headers()['x-embedded-idp-tenant-id'] && !r.headers()['x-embedded-idp-business-id']); if (u.pathname.endsWith('/upsert') && r.method() === 'POST') posts++; });
  for (const id of ['.', '..']) {
    const seed = await page.request.post(`${base}/upsert`, { headers: { authorization: t.bearer() }, data: { client_id: id, client_name: `N1 ${id}`, client_type: 'public_desktop', pkce_required: true, redirect_uris: ['http://127.0.0.1/callback'] } }); assert.ok(seed.ok());
    await locate(page, id); await drawer(page).getByText('正在编辑已有配置', { exact: false }).waitFor();
    assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), `N1 ${id}`);
    await drawer(page).getByLabel('名称', { exact: true }).fill(`N1 edited ${id}`); await review(page);
    const response = page.waitForResponse(r => new URL(r.url()).pathname.endsWith('/clients/-/lookup') && new URL(r.url()).searchParams.get('client_id') === id);
    await button(confirm(page), '确认保存').click(); assert.equal((await response).status(), 200);
    await drawer(page).getByText(/配置已保存/).first().waitFor(); assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), `N1 edited ${id}`); await close(page);
    assert.ok(requests.some(r => r.method === 'GET' && r.path === `${host.mount}/admin/clients/-/lookup` && r.query === id));
  }
  pass('real dot-only client seed, lookup, edit and readback use query and do not carry target headers');
  await button(page, '刷新客户端').click();
  await button(page, '配置客户端 .').click();
  await drawer(page).getByText('正在编辑已有配置', { exact: false }).waitFor();
  assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), 'N1 edited .');
  await close(page); pass('dot-only client opens from the real list');
  const missing = `n1-missing-${suffix}`; await locate(page, missing); await drawer(page).getByText('此 ID 尚未登记', { exact: false }).waitFor(); await close(page);
  pass('real authorized lookup 200/null permits initial registration');
  const lookup = u => u.pathname === `${host.mount}/admin/clients/-/lookup`;
  const injections = [
    ['404', { status: 404, json: {} }], ['405', { status: 405, json: {} }],
    ['204', { status: 204, body: '' }], ['201 valid envelope', { status: 201, json: { client_id: missing, client: null } }],
    ['202 valid envelope', { status: 202, json: { client_id: missing, client: null } }],
    ['206 valid envelope', { status: 206, json: { client_id: missing, client: null } }],
    ['HTML', { status: 200, contentType: 'text/html', body: '<html>not an API</html>' }],
    ['invalid JSON', { status: 200, contentType: 'application/json', body: '{' }],
    ['missing field', { status: 200, json: { client_id: missing } }], ['wrong ID', { status: 200, json: { client_id: 'other', client: null } }],
  ];
  for (const [name, result] of injections) {
    await page.route(lookup, route => route.fulfill(result)); const before = posts;
    await locate(page, missing); await drawer(page).getByText('读取客户端配置失败', { exact: true }).waitFor();
    assert.equal(await drawer(page).getByText('此 ID 尚未登记', { exact: false }).count(), 0, name);
    assert.equal(await button(drawer(page), '核对并保存').count(), 0, name); assert.equal(posts, before); await close(page); await page.unroute(lookup);
  }
  pass('injected 404/405/204/201/202/206/HTML/invalid JSON/missing fields/wrong ID never opens registration or POST');
  for (const phase of ['saved', 'unknown', 'rejected']) {
    const id = '.'; await locate(page, id); await drawer(page).getByLabel('名称', { exact: true }).fill(`N1 ${phase} ${suffix}`);
    let wrote = 0; let committed = false;
    const writePath = `${base}/upsert`;
    await page.route(writePath, async route => { wrote++; if (phase === 'rejected') return route.fulfill({ status: 400, json: {} });
      const response = await route.fetch(); assert.ok(response.ok()); committed = true;
      if (phase === 'unknown') {
        const read = await page.request.get(`${base}/-/lookup?client_id=${encodeURIComponent(id)}`, { headers: { authorization: t.bearer() } });
        assert.equal(read.status(), 200); const body = await read.json();
        assert.equal(body.client_id, id); assert.equal(body.client.client_name, `N1 ${phase} ${suffix}`);
        return route.abort('failed');
      }
      return route.fulfill({ response }); });
    await page.route(lookup, route => route.fulfill({ status: 200, json: { client_id: id, client: null } }));
    await review(page); await button(confirm(page), '确认保存').click();
    if (phase === 'saved') await drawer(page).getByText('配置已保存，重新读取失败', { exact: true }).waitFor();
    else {
      await drawer(page).getByText(phase === 'unknown' ? '保存结果未确认，请勿重复提交' : '服务端未接受本次保存，请重新读取当前配置后核对。', { exact: true }).waitFor();
      await reload(page); await drawer(page).getByText('读取客户端配置失败', { exact: true }).waitFor();
    }
    assert.equal(wrote, 1); assert.equal(committed, phase !== 'rejected');
    assert.equal(await drawer(page).getByText('此 ID 尚未登记', { exact: false }).count(), 0);
    assert.equal(await button(drawer(page), '核对并保存').count(), 0);
    await page.unroute(lookup); await page.route(lookup, route => route.fulfill({ status: 404, json: {} }));
    await reload(page); assert.equal(await drawer(page).getByText('此 ID 尚未登记', { exact: false }).count(), 0);
    assert.equal(await button(drawer(page), '核对并保存').count(), 0); assert.equal(wrote, 1);
    await page.unroute(lookup); await page.unroute(writePath); await reload(page);
    await drawer(page).getByText('正在编辑已有配置', { exact: false }).waitFor();
    if (phase !== 'rejected') assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), `N1 ${phase} ${suffix}`);
    assert.equal(wrote, 1); await close(page);
    pass(`${phase}: injected 200/null and 404 keep write lock; real nonnull read recovers without replay`);
  }
  for (const state of ['draft', 'confirmation', 'unknown']) {
    page.removeAllListeners('dialog'); page.on('dialog', dialog => dialog.dismiss());
    await locate(page, '.'); await drawer(page).getByLabel('名称', { exact: true }).fill(`N1 guard ${state} ${suffix}`);
    if (state !== 'draft') await review(page);
    const writePath = `${base}/upsert`; let writes = 0;
    if (state === 'unknown') {
      await page.route(writePath, async route => { writes++; const response = await route.fetch(); assert.equal(response.status(), 200); await route.abort('failed'); });
      await button(confirm(page), '确认保存').click(); await drawer(page).getByText('保存结果未确认，请勿重复提交', { exact: true }).waitFor();
    }
    const dialog = page.waitForEvent('dialog'); await page.evaluate(() => { location.hash = '#/platform/tenants'; });
    assert.equal((await dialog).type(), 'confirm'); await page.waitForURL('**/#/platform/clients');
    assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), `N1 guard ${state} ${suffix}`);
    if (state === 'confirmation') assert.ok(await confirm(page).isVisible());
    if (state === 'unknown') { assert.ok(await button(drawer(page), '核对并保存').isDisabled()); assert.equal(writes, 1); await page.unroute(writePath); }
    page.removeAllListeners('dialog'); page.on('dialog', d => d.accept());
    if (state === 'confirmation') await button(confirm(page), '返回修改').click();
    await close(page); pass(`dot-only ${state} survives cancelled cross-page navigation without replay`);
  }
  for (const phase of ['saved', 'unknown', 'rejected']) {
    await locate(page, '.'); const original = await drawer(page).getByLabel('名称', { exact: true }).inputValue();
    const name = `N1 abandon ${phase} ${suffix}`; await drawer(page).getByLabel('名称', { exact: true }).fill(name);
    let writes = 0;
    await page.route(`${base}/upsert`, async route => {
      writes++; if (phase === 'rejected') return route.fulfill({ status: 400, json: {} });
      const response = await route.fetch(); assert.equal(response.status(), 200);
      return phase === 'unknown' ? route.abort('failed') : route.fulfill({ response });
    });
    await page.route(lookup, route => route.fulfill({ status: 200, json: { client_id: '.', client: null } }));
    await review(page); await button(confirm(page), '确认保存').click();
    if (phase === 'saved') await drawer(page).getByText('配置已保存，重新读取失败', { exact: true }).waitFor();
    else { await drawer(page).getByText(phase === 'unknown' ? '保存结果未确认，请勿重复提交' : '服务端未接受本次保存，请重新读取当前配置后核对。', { exact: true }).waitFor(); await reload(page); }
    for (const status of [404, 503]) {
      await page.unroute(lookup); await page.route(lookup, route => route.fulfill({ status, json: {} }));
      await reload(page); assert.equal(await drawer(page).getByText('此 ID 尚未登记', { exact: false }).count(), 0);
      assert.equal(await button(drawer(page), '核对并保存').count(), 0); assert.equal(writes, 1);
    }
    if (phase !== 'saved') {
      const message = await answerDialog(page, () => button(drawer(page), '关闭配置').click(), false);
      assert.match(message, /结果未确认/); assert.ok(await drawer(page).isVisible());
      assert.equal(await button(drawer(page), '核对并保存').count(), 0); assert.equal(writes, 1);
      await answerDialog(page, () => close(page), true);
    } else await close(page);
    assert.equal(writes, 1); // Closing must work while the failed-read route is still installed.
    const persisted = await page.request.get(`${base}/-/lookup?client_id=.`, { headers: { authorization: t.bearer() } });
    assert.equal(persisted.status(), 200); assert.equal((await persisted.json()).client.client_name, phase === 'rejected' ? original : name);
    await page.unroute(lookup); await page.unroute(`${base}/upsert`);
    await locate(page, '.'); assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), phase === 'rejected' ? original : name);
    assert.equal(writes, 1); await close(page);
    pass(`${phase}: persistent null/404/503 read failure permits explicit close without registration or replay; independent read preserves durable outcome`);
  }
  await page.evaluate(() => { location.hash = '#/platform/tenants'; });
  await page.getByRole('heading', { name: '租户管理', exact: true }).waitFor();
  const tenants = `${host.origin}${host.mount}/admin/tenants`;
  for (const id of ['.', '..']) {
    const read = async () => {
      const response = await page.request.get(`${tenants}?tenant_id=${encodeURIComponent(id)}&limit=2`, { headers: { authorization: t.bearer() } });
      assert.equal(response.status(), 200); const data = await response.json(); assert.equal(data.items.length, 1); assert.equal(data.items[0].tenant_id, id); return data.items[0];
    };
    const before = await read(); await page.getByLabel('租户 ID', { exact: true }).fill(id); await button(page, '查询').click();
    await button(page, `设置租户 ${before.name}`).click(); const settings = page.getByRole('dialog', { name: '租户设置', exact: true });
    const newName = `N1 tenant ${id} ${suffix}`; await settings.getByLabel('租户名称', { exact: true }).fill(newName);
    await button(settings, '核对并保存').click(); let reviewDialog = page.getByRole('dialog', { name: '确认租户变更', exact: true });
    const summary = await reviewDialog.innerText(); assert.ok(summary.includes(before.name)); assert.ok(summary.includes(newName)); assert.ok(summary.includes(`当前版本：${before.version}`));
    let count = 0; const countPatch = r => { if (r.url() === tenants && r.method() === 'PATCH') count++; }; page.on('request', countPatch);
    await button(reviewDialog, '取消').click(); assert.equal(count, 0);
    await button(settings, '核对并保存').click(); reviewDialog = page.getByRole('dialog', { name: '确认租户变更', exact: true });
    const response = page.waitForResponse(r => r.url() === tenants && r.request().method() === 'PATCH');
    await button(reviewDialog, '确认提交').click(); const saved = await response; assert.equal(saved.status(), 200);
    const request = saved.request(); assert.equal(request.postDataJSON().tenant_id, id); assert.equal(request.postDataJSON().expected_version, before.version);
    assert.ok(!request.headers()['x-embedded-idp-tenant-id'] && !request.headers()['x-embedded-idp-business-id']);
    const after = await read(); assert.equal(after.name, newName); assert.equal(after.version, before.version + 1); assert.equal(count, 1);
    await settings.getByText(`已确认保存租户 ${id}。`, { exact: true }).waitFor();
    await settings.locator('button.ant-drawer-close').click(); await settings.waitFor({ state: 'hidden' }); page.off('request', countPatch);
  }
  pass('real dot-only tenant confirmation, cancel and collection PATCH preserve ID, version and platform scope');
  for (const id of ['.', '..']) for (const state of ['draft', 'confirmation', 'unknown']) {
    const test = await open('enabled', '#/platform/tenants'); const p = test.page;
    const homeMenu = p.locator('.management-sidebar').getByRole('menuitem', { name: '工作台', exact: true });
    const tenantMenu = p.locator('.management-sidebar').getByRole('menuitem', { name: '租户管理', exact: true });
    await homeMenu.click(); await p.getByRole('heading', { name: '工作台', exact: true }).waitFor();
    await tenantMenu.click(); await p.getByRole('heading', { name: '租户管理', exact: true }).waitFor();
    await homeMenu.click(); await p.getByRole('heading', { name: '工作台', exact: true }).waitFor();
    await p.goBack(); await p.getByRole('heading', { name: '租户管理', exact: true }).waitFor();
    const before = await openTenant(test, id); const name = `N1 tenant guard ${id} ${state} ${suffix}`;
    await settings(p).getByLabel('租户名称', { exact: true }).fill(name);
    let writes = 0;
    p.on('request', request => { if (request.url() === tenantUrl(test) && request.method() === 'PATCH') {
      writes++; assert.equal(request.postDataJSON().tenant_id, id); assert.equal(request.postDataJSON().expected_version, before.version);
      assert.ok(!request.headers()['x-embedded-idp-tenant-id'] && !request.headers()['x-embedded-idp-business-id']);
    } });
    if (state !== 'draft') { await button(settings(p), '核对并保存').click(); await tenantConfirm(p).waitFor(); }
    if (state === 'unknown') {
      await p.route(tenantUrl(test), async route => {
        if (route.request().method() !== 'PATCH') return route.continue();
        const response = await route.fetch(); assert.equal(response.status(), 200);
        const current = await readTenant(test, id); assert.equal(current.name, name); assert.equal(current.version, before.version + 1);
        await route.abort('failed');
      });
      await button(tenantConfirm(p), '确认提交').click();
      await settings(p).getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
    }
    const intact = async (confirmationOpen = state === 'confirmation') => {
      await p.waitForURL('**/#/platform/tenants'); assert.equal(await settings(p).getByLabel('租户 ID', { exact: true }).inputValue(), id);
      assert.equal(await settings(p).getByLabel('租户名称', { exact: true }).inputValue(), name);
      if (confirmationOpen) assert.ok(await tenantConfirm(p).isVisible());
      if (state === 'unknown') assert.ok(await button(settings(p), '核对并保存').isDisabled());
      assert.equal(writes, state === 'unknown' ? 1 : 0);
    };
    for (const action of [() => p.goBack(), () => p.goForward(), () => p.evaluate(() => { location.hash = '#/platform/clients'; }),
      () => p.evaluate(() => { location.hash = '#/tenants/tenant-a/home'; }), () => homeMenu.dispatchEvent('click')]) {
      await answerDialog(p, action, false); await intact();
    }
    // Probe the installed unload handler; native browser prompt policy is outside A1 evidence.
    assert.equal(await p.evaluate(() => { const event = new Event('beforeunload', { cancelable: true }); window.dispatchEvent(event); return event.defaultPrevented; }), true);
    if (state === 'confirmation') await button(tenantConfirm(p), '取消').click();
    await answerDialog(p, () => settings(p).locator('button.ant-drawer-close').click(), false); await intact(false);
    assert.equal(await settings(p).getByLabel('租户名称', { exact: true }).inputValue(), name);
    await answerDialog(p, () => settings(p).locator('button.ant-drawer-close').click(), true); await settings(p).waitFor({ state: 'hidden' });
    const current = await readTenant(test, id); assert.equal(current.name, state === 'unknown' ? name : before.name);
    assert.equal(current.version, before.version + (state === 'unknown' ? 1 : 0)); assert.equal(writes, state === 'unknown' ? 1 : 0);
    assert.equal((await (await p.request.get(`${test.host.origin}${test.host.mount}/admin/auth/session`, { headers: { authorization: test.bearer() } })).json()).tenant_id, '0');
    await p.unroute(tenantUrl(test)); await test.context.close();
    pass(`tenant ${id} ${state}: cancelled hash/back/forward/target/menu and close preserve scope; unload handler and confirmed discard do not replay`);
  }
  for (const id of ['.', '..']) for (const kind of ['initial-read', 'patch', 'readback']) {
    const test = await open('enabled', '#/platform/tenants'); const p = test.page;
    const before = await readTenant(test, id); const name = `N1 late ${id} ${kind} ${suffix}`;
    const hold = gate(); let seen, done; const observed = new Promise(resolve => { seen = resolve; }); const delivered = new Promise(resolve => { done = resolve; });
    let routeError, writes = 0, held = false, persisted = false;
    p.on('request', r => { if (r.url() === tenantUrl(test) && r.method() === 'PATCH') {
      writes++; assert.equal(r.postDataJSON().tenant_id, id); assert.equal(r.postDataJSON().expected_version, before.version);
      assert.ok(!r.headers()['x-embedded-idp-tenant-id'] && !r.headers()['x-embedded-idp-business-id']);
    } });
    const path = kind === 'patch' ? tenantUrl(test) : tenantRead(test, id);
    if (kind !== 'initial-read') await openTenant(test, id);
    await p.route(path, async route => {
      if ((kind === 'patch' && route.request().method() !== 'PATCH') || held) return route.continue();
      held = true;
      try {
        const response = await route.fetch(); assert.equal(response.status(), 200);
        if (kind === 'patch') { const saved = await readTenant(test, id); assert.equal(saved.name, name); assert.equal(saved.version, before.version + 1); persisted = true; }
        else { const body = await response.json(); assert.equal(body.items[0].tenant_id, id); assert.equal(body.items[0].name, kind === 'readback' ? name : before.name); }
        seen(); await hold.promise; await route.fulfill({ response });
      } catch (error) { routeError = error; seen(); } finally { done(); }
    });
    if (kind === 'initial-read') await openTenant(test, id, false);
    else {
      await settings(p).getByLabel('租户名称', { exact: true }).fill(name); await button(settings(p), '核对并保存').click();
      await button(tenantConfirm(p), '确认提交').click();
    }
    await bounded(observed, `${id} ${kind} real response held`); if (routeError) throw routeError;
    if (kind === 'readback') {
      const saved = await readTenant(test, id); assert.equal(saved.name, name); assert.equal(saved.version, before.version + 1); persisted = true;
      await settings(p).getByText(`已确认保存租户 ${id}。`, { exact: true }).waitFor();
    }
    if (kind === 'patch') {
      p.removeAllListeners('dialog'); p.once('dialog', d => d.accept()); const blocked = p.waitForEvent('dialog');
      await p.evaluate(() => { location.hash = '#/tenants/tenant-a/home'; }); assert.equal((await blocked).type(), 'alert');
      await p.waitForURL('**/#/platform/tenants'); assert.equal(writes, 1);
      assert.ok(await button(tenantConfirm(p), '取消').isDisabled()); assert.equal(await settings(p).locator('button.ant-drawer-close').count(), 0);
      p.on('dialog', d => d.accept());
    }
    const identityResponse = await p.request.get(`${test.host.origin}${test.host.mount}/admin/auth/session`, { headers: { authorization: test.bearer() } });
    assert.equal(identityResponse.status(), 200); const identity = await identityResponse.json(); assert.equal(identity.tenant_id, '0');
    const other = await test.context.newPage(); other.on('pageerror', e => errors.push(e.name));
    const verified = other.waitForResponse(r => r.url() === `${test.host.origin}${test.host.mount}/admin/auth/session` && r.request().method() === 'GET');
    await other.goto(`${test.host.origin}${test.host.ui}/#/platform/home`); await other.locator('.management-shell').waitFor();
    assert.deepEqual(await (await verified).json(), identity);
    const logout = other.waitForResponse(r => r.url() === `${test.host.origin}${test.host.mount}/admin/auth/browser/logout`);
    await button(other, '退出登录').click(); assert.equal((await logout).status(), 204);
    await p.getByText('其他页面已更改此会话，请重新加载后继续。', { exact: true }).waitFor();
    assert.equal(await p.locator('.management-shell').count(), 0); assert.equal(await settings(p).count(), 0);
    const late = p.waitForResponse(r => r.url() === path && r.request().method() === (kind === 'patch' ? 'PATCH' : 'GET'));
    hold.release(); await bounded(delivered, `${id} ${kind} delivered`); if (routeError) throw routeError;
    assert.equal(await (await late).finished(), null); heldResponses.delete(hold.release); await p.unroute(path);
    await p.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await p.locator('.management-shell').count(), 0); assert.equal(await settings(p).count(), 0); assert.equal(await tenantConfirm(p).count(), 0);
    assert.equal(await p.getByText(`已确认保存租户 ${id}。`, { exact: true }).count(), 0); assert.equal(writes, kind === 'initial-read' ? 0 : 1);
    assert.equal(persisted, kind !== 'initial-read');
    await other.close(); await test.context.close();
    pass(`tenant ${id} ${kind}: held real response after same-session cross-tab logout cannot restore identity, editor or success; no replay`);
  }
  assert.deepEqual(errors, []);
} catch (error) {
  failure = error;
  throw error;
} finally {
  for (const release of heldResponses) release();
  await finalizeFunctionalRun({ coverage, contexts, browser, failure,
    resultPath: `${output}/n1-browser-results.json`, result: { cases, pageErrors: errors, evidence: 'isolated compiled reference host; explicit route injections for response and write-outcome cases; no target-environment or deployment claim' } });
}
