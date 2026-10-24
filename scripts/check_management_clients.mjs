// Opt-in UI-C checks against the private UI-B fixture only. Network injections
// below are explicitly labelled; they do not simulate real packet loss.
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';

const fixture = JSON.parse(await readFile(process.env.IDP_UI_TEST_FIXTURE, 'utf8'));
assert.match(fixture.container, /^idp-ui-b-[a-f0-9]+$/);
for (const schema of Object.values(fixture.schemas)) assert.match(schema, /^uib_(enabled|disabled)_[a-f0-9]+$/);
for (const host of Object.values(fixture.hosts)) assert.equal(new URL(host.origin).hostname, '127.0.0.1');
const { chromium } = await import(process.env.IDP_UI_PLAYWRIGHT_PATH ? pathToFileURL(process.env.IDP_UI_PLAYWRIGHT_PATH).href : 'playwright');
const browser = await chromium.launch({ headless: process.env.IDP_UI_HEADED !== "1", ...(process.env.IDP_UI_BROWSER_EXECUTABLE ? { executablePath: process.env.IDP_UI_BROWSER_EXECUTABLE } : {}) });
const output = process.env.IDP_UI_OUTPUT_DIR ?? fixture.dir;
await mkdir(output, { recursive: true });
const contexts = [], cases = [], errors = [], contrast = [];
const heldResponses = new Set();
const pass = name => { cases.push(name); console.log(`PASS ${name}`); };
const runId = randomBytes(6).toString('hex');
const idFor = value => `${value}-${runId}`;
const lookupUrl = (base, id) => `${base}/-/lookup?client_id=${encodeURIComponent(id)}`;
const isLookup = (url, id) => url.pathname.endsWith('/clients/-/lookup') && url.searchParams.get('client_id') === id;
const secret = 'synthetic-ui-c-secret-one';
const secret2 = 'synthetic-ui-c-secret-two';
const button = (parent, name) => parent.getByRole('button', { name: name === '查询' ? /^查\s*询$/ : name, exact: true });
const drawer = page => page.getByRole('dialog', { name: '客户端配置', exact: true });
const confirm = page => page.getByRole('dialog', { name: '确认保存客户端配置', exact: true });
const waitList = page => page.waitForFunction(() => !document.querySelector('.management-client-loading'));
async function textContrast(locator, label) {
  const color = await locator.first().evaluate(el => getComputedStyle(el).color);
  const channels = color.match(/[\d.]+/g).map(Number), alpha = channels[3] ?? 1;
  const linear = channels.slice(0, 3).map(value => {
    const s = (value * alpha + 255 * (1 - alpha)) / 255;
    return s <= .04045 ? s / 12.92 : ((s + .055) / 1.055) ** 2.4;
  });
  const ratio = 1.05 / (.2126 * linear[0] + .7152 * linear[1] + .0722 * linear[2] + .05);
  assert.ok(ratio >= 4.5, `${label}: normal text contrast on white`);
  contrast.push({ label, color, ratio: Number(ratio.toFixed(2)) });
}
async function open(key, hash = key === 'disabled' ? '#/system/clients' : '#/platform/clients', email = 'admin@example.test') {
  const host = fixture.hosts[key];
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } }); contexts.push(context);
  const page = await context.newPage(); page.setDefaultTimeout(15000);
  page.on('pageerror', error => errors.push(error.name));
  page.on('dialog', dialog => dialog.dismiss());
  let bearer;
  page.on('request', request => { if (new URL(request.url()).pathname.startsWith(`${host.mount}/admin/`)) bearer = request.headers().authorization ?? bearer; });
  await page.goto(host.origin + host.ui + '/' + hash);
  await page.getByLabel('邮箱', { exact: true }).fill(email);
  await page.getByLabel('密码', { exact: true }).fill(fixture.password);
  await page.getByRole('button', { name: /^登\s*录$/ }).click();
  await page.locator('.management-shell').waitFor();
  return { page, host, context, getBearer: () => bearer };
}
async function locate(page, id) {
  await button(page, '按 ID 登记 / 编辑').click();
  const modal = page.getByRole('dialog', { name: '按 ID 登记 / 编辑', exact: true });
  await modal.getByLabel('客户端 ID', { exact: true }).fill(id);
  await button(modal, '读取配置').click();
  await drawer(page).waitFor(); await drawer(page).getByRole('button', { name: '重新读取配置', exact: true }).waitFor({ state: 'visible' });
  await page.waitForFunction(() => !document.querySelector('.management-client-editor .management-client-loading'));
}
async function selectType(page, text) {
  await drawer(page).getByLabel('客户端类型', { exact: true }).focus();
  await page.keyboard.press('ArrowDown');
  await page.locator('.ant-select-dropdown:visible').getByText(text, { exact: true }).click();
}
async function review(page) {
  await button(drawer(page), '核对并保存').click(); await confirm(page).waitFor();
  await page.waitForFunction(() => {
    const dialog = document.querySelector('.management-client-confirm [role="dialog"]');
    return dialog && getComputedStyle(dialog).opacity === '1' && getComputedStyle(dialog).transform === 'none' && document.activeElement?.textContent?.trim() === '返回修改';
  });
}
async function save(page) {
  const id = await drawer(page).locator('.management-client-summary code').innerText();
  const reread = page.waitForResponse(r => isLookup(new URL(r.url()), id) && r.request().method() === 'GET');
  const [response] = await Promise.all([reread, button(confirm(page), '确认保存').click()]);
  assert.ok(response.ok()); await page.getByText(/配置已保存/).first().waitFor();
  await page.waitForFunction(() => !document.querySelector('.management-client-editor .management-client-loading') &&
    [...document.querySelectorAll('.management-client-confirm .ant-modal-wrap')].every(el => getComputedStyle(el).display === 'none'));
}
async function close(page) { await button(drawer(page), '关闭配置').click(); await drawer(page).waitFor({ state: 'hidden' }); }
async function rereadConfiguration(page) {
  const id = await drawer(page).locator('.management-client-summary code').innerText();
  const response = page.waitForResponse(r => isLookup(new URL(r.url()), id) && r.request().method() === 'GET');
  await Promise.all([response, button(drawer(page), '重新读取配置').click()]);
  await page.waitForFunction(() => {
    const submit = document.querySelector('.management-client-editor button[type="submit"]');
    return submit && !submit.disabled && !document.querySelector('.management-client-editor .management-client-loading');
  });
}
async function assertNoSecrets(page) {
  assert.ok(!(await confirm(page).innerText()).includes(secret));
  assert.ok(!(await confirm(page).innerText()).includes(secret2));
  assert.ok(!page.url().includes(secret));
  assert.ok(!page.url().includes(secret2));
  const storage = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
  assert.ok(!storage.includes(secret)); assert.ok(!storage.includes(secret2));
}
try {
  for (const mode of ['enabled', 'disabled']) {
    const { page } = await open(mode); await page.getByRole('heading', { name: '客户端管理', exact: true }).waitFor(); await waitList(page);
    await locate(page, 'management-ui-b');
    await drawer(page).getByText('正在编辑已有配置', { exact: false }).waitFor(); await close(page);
    const id = idFor(`uic-${mode}-public`);
    await locate(page, id); await drawer(page).getByText('此 ID 尚未登记', { exact: false }).waitFor();
    await drawer(page).getByLabel('名称', { exact: true }).fill(`UI C ${mode} public`);
    await drawer(page).getByLabel('允许的回调地址（每行一个）', { exact: true }).fill('http://127.0.0.1/callback');
    await review(page); await save(page); await close(page);
    await locate(page, id); assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), `UI C ${mode} public`); await close(page);
    pass(`${mode}: real list, existing and missing ID, public create and readback`);
  }
  const fixed = await open('fixed', '#/tenants/tenant-a/members', 'tenant-a@example.test');
  await fixed.page.getByRole('heading', { name: '成员管理', exact: true }).waitFor();
  let fixedClientCalls = 0;
  fixed.page.on('request', request => { if (new URL(request.url()).pathname.includes('/admin/clients')) fixedClientCalls++; });
  await fixed.page.evaluate(() => { location.hash = '#/platform/clients'; });
  await fixed.page.getByRole('heading', { name: '无权访问', exact: true }).waitFor(); assert.equal(fixedClientCalls, 0);
  pass('Fixed nonzero cannot open platform clients');

  const test = await open('enabled'); const { page, host } = test; await waitList(page);
  await textContrast(page.locator('.management-client-page .ant-typography-secondary'), 'client page explanation');
  const clientWrites = [];
  let scopedRequests = 0;
  page.on('request', request => {
    const url = new URL(request.url());
    if (!url.pathname.startsWith(`${host.mount}/admin/clients`)) return;
    scopedRequests++;
    const headers = request.headers();
    assert.ok(!headers['x-embedded-idp-tenant-id'] && !headers['x-embedded-idp-business-id']);
    if (url.pathname.endsWith('/upsert') && request.method() === 'POST') {
      const body = request.postDataJSON();
      assert.ok(!Object.keys(body).some(key => /(?:version|etag|if_match)/i.test(key)));
      clientWrites.push(body);
    }
  });
  await locate(page, idFor('uic-confidential'));
  await drawer(page).getByLabel('名称', { exact: true }).fill('UI C confidential');
  await selectType(page, '机密 Web 客户端');
  await drawer(page).getByLabel('允许的回调地址（每行一个）', { exact: true }).fill('https://example.test/callback');
  await drawer(page).getByLabel('客户端密钥', { exact: true }).fill(secret);
  await review(page); await assertNoSecrets(page); await save(page);
  await drawer(page).getByText('已配置（不回显）', { exact: true }).waitFor();
  assert.ok(clientWrites.at(-1).client_secret === secret);
  await drawer(page).getByLabel('名称', { exact: true }).fill('UI C confidential edited');
  await review(page); await confirm(page).getByText('保留当前密钥', { exact: true }).waitFor(); await save(page);
  assert.ok(!Object.hasOwn(clientWrites.at(-1), 'client_secret'));
  await drawer(page).getByLabel('客户端密钥', { exact: true }).fill(secret2);
  await review(page); await assertNoSecrets(page); await confirm(page).getByText('替换密钥（不显示内容）', { exact: true }).waitFor(); await save(page);
  assert.ok(clientWrites.at(-1).client_secret === secret2);
  await selectType(page, '公开桌面客户端');
  await drawer(page).getByLabel('允许的回调地址（每行一个）', { exact: true }).fill('http://127.0.0.1/callback');
  await review(page); await confirm(page).getByText('清除已有密钥', { exact: true }).waitFor(); await save(page);
  assert.ok(!Object.hasOwn(clientWrites.at(-1), 'client_secret'));
  const publicGet = await page.request.get(host.origin + host.mount + '/admin/clients/' + idFor('uic-confidential'), { headers: { authorization: test.getBearer() } });
  assert.ok(publicGet.ok()); assert.equal((await publicGet.json()).client_secret_configured, false); assert.ok(scopedRequests > 0);
  await drawer(page).getByText('不适用', { exact: true }).first().waitFor();
  await textContrast(drawer(page).locator('.ant-form-item-extra'), 'field constraints');
  await textContrast(drawer(page).locator('.ant-descriptions-item-label'), 'current configuration labels');
  await page.screenshot({ path: `${output}/ui-c-detail.png`, animations: 'disabled' }); await close(page);
  pass('real confidential create, blank retain, replacement and conversion to public; secret absent from summary, URL and storage');
  pass('sampled explanatory text, field hints and configuration labels meet 4.5:1 on white');

  // Real API seeding uses the currently authenticated bearer only in memory.
  const base = host.origin + host.mount + '/admin/clients';
  const authorization = test.getBearer(); assert.ok(authorization?.startsWith('Bearer '));
  for (const id of ['.', '..']) {
    const seed = await page.request.post(base + '/upsert', { headers: { authorization }, data: {
      client_id: id, client_name: 'UI C dot ID fixture', client_type: 'public_desktop', pkce_required: true, redirect_uris: ['http://127.0.0.1/callback'],
    } }); assert.ok(seed.ok());
    await locate(page, id);
    await drawer(page).getByText('正在编辑已有配置', { exact: false }).waitFor();
    assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), 'UI C dot ID fixture');
    assert.equal(await drawer(page).getByText('此 ID 尚未登记', { exact: false }).count(), 0);
    await drawer(page).getByLabel('名称', { exact: true }).fill(`UI C dot ID ${id}`);
    await review(page); await save(page);
    assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), `UI C dot ID ${id}`);
    await close(page);
  }
  pass('dot-only client IDs read, edit and reread the same existing configuration');
  for (let i = 0; i < 52; i++) {
    const response = await page.request.post(base + '/upsert', { headers: { authorization }, data: {
      client_id: idFor(`uic-seed-${String(i).padStart(2, '0')}`), client_name: `UI C seed ${i}`,
      client_type: 'public_desktop', pkce_required: true, redirect_uris: ['http://127.0.0.1/callback'],
    } }); assert.ok(response.ok(), `fixture seed HTTP ${response.status()}`);
  }
  await button(page, '刷新客户端').click(); await waitList(page);
  await button(page, '下一页').click(); await page.getByText('第 2 页', { exact: true }).waitFor();
  await button(page, '重置筛选').click(); await page.getByText('第 1 页', { exact: true }).waitFor();
  pass('real cursor next page and reset after 52 synthetic API seeds');

  const queries = [];
  page.on('request', request => { const url = new URL(request.url()); if (url.origin + url.pathname === base && request.method() === 'GET') queries.push(url.searchParams); });
  async function firstPage(action, expected) {
    const before = queries.length;
    const requested = page.waitForRequest(request => request.url().split('?')[0] === base && request.method() === 'GET' && !new URL(request.url()).searchParams.has('cursor'));
    await Promise.all([requested, action()]);
    await page.waitForFunction(() => !document.querySelector('.management-client-loading'));
    await page.getByText('第 1 页', { exact: true }).waitFor();
    assert.ok(queries.length > before); const query = queries.at(-1);
    assert.equal(query.has('cursor'), false);
    for (const [key, value] of Object.entries(expected)) assert.equal(query.get(key), value);
  }
  async function secondPage() {
    const requested = page.waitForRequest(request => request.url().split('?')[0] === base && request.method() === 'GET' && new URL(request.url()).searchParams.has('cursor'));
    await Promise.all([requested, button(page, '下一页').click()]); await waitList(page); await page.getByText('第 2 页', { exact: true }).waitFor();
    assert.ok(queries.at(-1).get('cursor'));
  }
  async function filter(label, value) {
    await page.getByLabel(label, { exact: true }).focus();
    await page.keyboard.press('ArrowDown');
    await page.locator('.ant-select-dropdown:visible').getByText(value, { exact: true }).click();
  }
  await secondPage();
  await filter('类型', '公开桌面客户端');
  await firstPage(() => button(page, '查询').click(), { client_type: 'public_desktop' });
  await secondPage(); await filter('PKCE', '必需');
  await firstPage(() => button(page, '查询').click(), { client_type: 'public_desktop', pkce_required: 'true' });
  await secondPage(); await filter('登记顺序', '早登记在前');
  await firstPage(() => button(page, '查询').click(), { sort_order: 'asc' });
  await secondPage(); await firstPage(() => button(page, '重置筛选').click(), { sort_order: 'desc', client_type: null, pkce_required: null });
  pass('type, PKCE, sort, query and reset start at first page with no cursor; next page carries cursor');

  // Injected list responses isolate loading, unfiltered empty, filtered empty and error states.
  const listPattern = url => url.origin + url.pathname === base;
  let releaseList; const gate = new Promise(resolve => { releaseList = resolve; });
  let seenList; const listSeen = new Promise(resolve => { seenList = resolve; });
  await page.route(listPattern, async route => { seenList(); await gate; await route.fulfill({ status: 200, json: { items: [], has_more: false } }); });
  await button(page, '刷新客户端').click(); await listSeen;
  await page.getByText('正在读取客户端列表…', { exact: false }).waitFor();
  releaseList(); await page.getByText('尚无客户端配置，可按 ID 登记接入应用。', { exact: true }).waitFor();
  await filter('类型', '机密 Web 客户端'); await button(page, '查询').click();
  await page.getByText('没有符合筛选条件的客户端，请调整或重置筛选。', { exact: true }).waitFor();
  await page.unroute(listPattern);
  await page.route(listPattern, route => route.fulfill({ status: 500, json: {} }));
  await button(page, '重置筛选').click(); await page.getByText('读取客户端配置失败', { exact: true }).waitFor();
  assert.equal(await page.getByText('尚无客户端配置，可按 ID 登记接入应用。', { exact: true }).count(), 0);
  await page.unroute(listPattern); await button(page, '刷新客户端').click(); await waitList(page);
  pass('injected list loading, empty, filtered empty and error states are distinct');

  // Explicitly injected failed/malformed responses; each must prevent registration.
  for (const [label, status, body] of [['403', 403, {}], ['500', 500, {}], ['malformed', 200, {}], ['missing module', 404, {}]]) {
    const pattern = `${base}**`;
    await page.route(pattern, route => route.fulfill({ status, json: body }));
    await locate(page, idFor(`uic-injected-${label.replace(' ', '-')}`));
    assert.equal(await drawer(page).getByLabel('名称', { exact: true }).count(), 0);
    assert.equal(await button(drawer(page), '核对并保存').count(), 0);
    await close(page); await page.unroute(pattern);
  }
  pass('injected 403, 500, malformed GET and missing module cannot create');

  let writes = 0;
  page.on('request', request => { if (request.url() === base + '/upsert' && request.method() === 'POST') writes++; });
  await locate(page, idFor('uic-enabled-public'));
  const large = Array.from({ length: 10 }, (_, i) => `http://127.0.0.1/${i}${'a'.repeat(1800)}`).join('\n');
  await drawer(page).getByLabel('允许的回调地址（每行一个）', { exact: true }).fill(large);
  const beforeLarge = writes; await button(drawer(page), '核对并保存').click();
  await drawer(page).getByText(/请求上限 16 KiB/).first().waitFor();
  assert.equal(writes, beforeLarge); assert.equal(await confirm(page).count(), 0);
  // Restore without sending; accept the explicit discard prompt.
  page.removeAllListeners('dialog'); page.on('dialog', dialog => dialog.accept());
  await rereadConfiguration(page);
  await close(page);
  pass('16 KiB local request limit prevents POST');

  const detail = lookupUrl(base, idFor('uic-enabled-public'));
  await locate(page, idFor('uic-enabled-public'));
  await drawer(page).getByLabel('名称', { exact: true }).fill('UI C confirmed read failure');
  let posted = false;
  const readFail = url => url.href === detail;
  await page.route(readFail, route => posted ? route.fulfill({ status: 500, json: {} }) : route.continue());
  const postMark = request => { if (request.url() === base + '/upsert' && request.method() === 'POST') posted = true; };
  page.on('request', postMark);
  await review(page); await button(confirm(page), '确认保存').click();
  await drawer(page).getByText('配置已保存，重新读取失败', { exact: true }).waitFor();
  assert.ok(posted); page.off('request', postMark); await page.unroute(readFail);
  await rereadConfiguration(page);
  assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), 'UI C confirmed read failure'); await close(page);
  pass('real acknowledged POST with injected follow-up GET failure remains confirmed and recovers by reread');

  await locate(page, idFor('uic-enabled-public'));
  await drawer(page).getByLabel('名称', { exact: true }).fill('UI C uncertain response');
  let intercepted = 0, verified = false;
  const writePattern = base + '/upsert';
  await page.route(writePattern, async route => {
    if (route.request().method() !== 'POST') return route.continue();
    intercepted++;
    const response = await route.fetch(); assert.ok(response.ok(), `real POST HTTP ${response.status()}`);
    const reread = await page.request.get(detail, { headers: { authorization } }); assert.ok(reread.ok());
    const body = await reread.json(); assert.equal(body.client_id, idFor('uic-enabled-public')); assert.equal(body.client.client_id, body.client_id); assert.equal(body.client.client_name, 'UI C uncertain response'); verified = true;
    await route.abort('failed');
  });
  await review(page); await button(confirm(page), '确认保存').click();
  await drawer(page).getByText('保存结果未确认，请勿重复提交', { exact: true }).waitFor();
  assert.equal(intercepted, 1); assert.ok(verified);
  await page.waitForFunction(() => document.activeElement?.textContent?.trim() === '重新读取配置');
  assert.equal(await button(drawer(page), '核对并保存').isDisabled(), true);
  await page.waitForTimeout(300); assert.equal(intercepted, 1);
  await page.unroute(writePattern); await rereadConfiguration(page);
  assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), 'UI C uncertain response');
  assert.equal(await button(drawer(page), '核对并保存').isDisabled(), false); await close(page);
  pass('real POST and independent GET followed by injected abort: unknown, no replay, blocked until reread');
  // A definite client-side-visible rejection uses the same recovery focus.
  await locate(page, idFor('uic-enabled-public'));
  await drawer(page).getByLabel('名称', { exact: true }).fill('UI C rejected response');
  await page.route(writePattern, route => route.fulfill({ status: 400, json: {} }));
  await review(page); await button(confirm(page), '确认保存').click();
  await drawer(page).getByText('服务端未接受本次保存，请重新读取当前配置后核对。', { exact: true }).waitFor();
  await page.waitForFunction(() => document.activeElement?.textContent?.trim() === '重新读取配置');
  assert.ok(await button(drawer(page), '核对并保存').isDisabled());
  await page.unroute(writePattern); await rereadConfiguration(page); await close(page);
  pass('injected rejected POST focuses reread and blocks repeat until reread');
  page.removeAllListeners('dialog'); page.on('dialog', dialog => dialog.dismiss());

  await locate(page, idFor('uic-enabled-public'));
  await drawer(page).getByLabel('名称', { exact: true }).fill('UI C dirty draft');
  await button(drawer(page), '重新读取配置').click();
  assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), 'UI C dirty draft');
  await button(drawer(page), '关闭配置').click();
  assert.equal(await drawer(page).getByLabel('名称', { exact: true }).inputValue(), 'UI C dirty draft');
  await review(page);
  await confirm(page).screenshot({ path: `${output}/ui-c-confirm.png`, animations: 'allow' });
  await button(confirm(page), '返回修改').click();
  await button(drawer(page), '核对并保存').waitFor();
  await page.waitForFunction(() => document.activeElement?.textContent?.includes('核对并保存'));
  pass('cancel dirty reload and close preserve draft; confirmation returns focus');
  // Discard only the synthetic draft after verifying the cancellation path.
  page.removeAllListeners('dialog'); page.on('dialog', dialog => dialog.accept()); await close(page);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.setViewportSize({ width: 320, height: 900 });
  await locate(page, idFor('uic-enabled-public'));
  await drawer(page).getByLabel('允许的回调地址（每行一个）', { exact: true }).fill(
    Array.from({ length: 4 }, (_, i) => `http://127.0.0.1/${i}${'b'.repeat(1400)}`).join('\n'));
  await review(page);
  const longBox = await confirm(page).boundingBox();
  assert.ok(longBox && longBox.y >= 0 && longBox.y + longBox.height <= 900);
  const content = confirm(page).getByRole('region', { name: '待保存的完整配置', exact: true });
  assert.ok(await content.evaluate(el => el.scrollHeight > el.clientHeight));
  await content.focus(); await content.press('End');
  await page.waitForFunction(() => document.querySelector('.management-client-confirm-content').scrollTop > 0);
  await button(confirm(page), '返回修改').click(); await close(page);
  pass('long confirmation fits a narrow viewport with reduced motion and its complete callback list scrolls by keyboard');
  for (const width of [320, 390, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await page.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth);
    if (width === 320) { await page.evaluate(() => window.scrollTo(0, 0)); await page.screenshot({ path: `${output}/ui-c-list-mobile.png`, animations: 'disabled' }); }
    const table = page.locator('.management-client-page .ant-table-body, .management-client-page .ant-table-content').first();
    if (width < 760) {
      assert.ok(await table.evaluate(el => el.scrollWidth > el.clientWidth));
      await table.evaluate(el => { el.scrollLeft = el.scrollWidth; });
      assert.ok(await table.evaluate(el => el.scrollLeft > 0));
    }
    const trigger = button(page, '按 ID 登记 / 编辑'); await trigger.focus();
    await page.keyboard.press('Enter');
    const lookup = page.getByRole('dialog', { name: '按 ID 登记 / 编辑', exact: true });
    const modalBox = await lookup.boundingBox(); assert.ok(modalBox && modalBox.x >= 0 && modalBox.x + modalBox.width <= width + 1);
    await lookup.getByLabel('客户端 ID', { exact: true }).fill(idFor('uic-enabled-public'));
    await button(lookup, '读取配置').focus(); await page.keyboard.press('Enter');
    await drawer(page).waitFor(); await page.waitForFunction(() => !document.querySelector('.management-client-editor .management-client-loading'));
    await page.waitForFunction(() => {
      const dialog = document.querySelector('.management-client-editor [role="dialog"]');
      if (!dialog) return false;
      const box = dialog.getBoundingClientRect();
      return box.left >= 0 && box.right <= innerWidth + 1;
    });
    const box = await drawer(page).boundingBox(); assert.ok(box && box.x >= 0 && box.x + box.width <= width + 1);
    if (width === 390) await page.screenshot({ path: `${output}/ui-c-detail-mobile.png`, animations: 'disabled' });
    await button(drawer(page), '关闭配置').focus(); await page.keyboard.press('Enter'); await drawer(page).waitFor({ state: 'hidden' });
    await page.waitForFunction(() => document.activeElement?.textContent?.includes('按 ID 登记'));

  }
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: `${output}/ui-c-clients.png`, animations: 'disabled' });
  pass('320/390/768/1440 document, drawer and modal fit; narrow table scroll and keyboard entry/close work');

  // UI-C-specific guard and coordinator cases. The menu is covered by the
  // drawer/modal; dispatch activates the existing menu handler, not a fake click.
  const bounded = (promise, label) => Promise.race([promise, new Promise((_, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timed out: ${label}`)), 15000); timer.unref();
  })]);
  for (const mode of ['enabled', 'disabled']) {
    const home = mode === 'enabled' ? '#/platform/home' : '#/system/home';
    const clients = mode === 'enabled' ? '#/platform/clients' : '#/system/clients';
    const id = idFor(`uic-${mode}-public`);
    const apiPath = fixture.hosts[mode].origin + fixture.hosts[mode].mount + '/admin/clients';
    const homeMenu = page => page.locator('.management-sidebar').getByRole('menuitem', { name: '工作台', exact: true });
    const clientsMenu = page => page.locator('.management-sidebar').getByRole('menuitem', { name: '客户端管理', exact: true });
    for (const state of ['dirty', 'confirmation', 'unknown']) {
      const t = await open(mode); const p = t.page; let answer = 'dismiss';
      p.removeAllListeners('dialog'); p.on('dialog', async dialog => { await (answer === 'accept' ? dialog.accept() : dialog.dismiss()); });
      let posts = 0; let scoped = 0;
      p.on('request', request => {
        const url = new URL(request.url()); if (!url.pathname.startsWith(`${t.host.mount}/admin/clients`)) return;
        scoped++; const headers = request.headers();
        assert.ok(!headers['x-embedded-idp-tenant-id'] && !headers['x-embedded-idp-business-id']);
        if (url.pathname.endsWith('/upsert') && request.method() === 'POST') posts++;
      });
      await p.getByRole('heading', { name: '客户端管理', exact: true }).waitFor();
      // Build a genuine managed history chain with a forward and back target.
      await homeMenu(p).click(); await p.getByRole('heading', { name: '工作台', exact: true }).waitFor();
      await clientsMenu(p).click(); await p.getByRole('heading', { name: '客户端管理', exact: true }).waitFor();
      await homeMenu(p).click(); await p.getByRole('heading', { name: '工作台', exact: true }).waitFor();
      await p.goBack(); await p.getByRole('heading', { name: '客户端管理', exact: true }).waitFor();
      await locate(p, id);
      const name = drawer(p).getByLabel('名称', { exact: true });
      const original = await name.inputValue(); const edited = `UI C guard ${mode} ${state}`;
      await name.fill(edited);
      if (state !== 'dirty') await review(p);
      if (state === 'unknown') {
        const writePath = apiPath + '/upsert';
        await p.route(writePath, async route => {
          const response = await route.fetch(); assert.ok(response.ok());
          const read = await p.request.get(lookupUrl(apiPath, id), { headers: { authorization: t.getBearer() } });
          assert.ok(read.ok()); const value = await read.json(); assert.equal(value.client_id, id); assert.equal(value.client.client_id, id); assert.equal(value.client.client_name, edited);
          await route.abort('failed');
        });
        await button(confirm(p), '确认保存').click();
        await drawer(p).getByText('保存结果未确认，请勿重复提交', { exact: true }).waitFor();
        await p.unroute(writePath); assert.equal(posts, 1);
      }
      const intact = async () => {
        await p.waitForURL(`**/${clients}`); assert.ok((await drawer(p).innerText()).includes(id));
        assert.equal(await name.inputValue(), edited);
        if (state === 'confirmation') assert.equal(await confirm(p).isVisible(), true);
        if (state === 'unknown') {
          await drawer(p).getByText('保存结果未确认，请勿重复提交', { exact: true }).waitFor();
          assert.ok(await button(drawer(p), '核对并保存').isDisabled());
        }
      };
      const destination = mode === 'enabled' ? '#/tenants/tenant-a/members' : home;
      for (const action of [() => p.goBack(), () => p.goForward(), () => p.evaluate(hash => { location.hash = hash; }, destination), () => homeMenu(p).dispatchEvent('click')]) {
        const dialog = p.waitForEvent('dialog'); await action(); assert.equal((await dialog).type(), 'confirm'); await intact();
      }
      answer = 'accept'; const exitDialog = p.waitForEvent('dialog');
      await homeMenu(p).dispatchEvent('click'); assert.equal((await exitDialog).type(), 'confirm');
      await p.getByRole('heading', { name: '工作台', exact: true }).waitFor();
      assert.equal(await drawer(p).count(), 0); assert.equal(await confirm(p).count(), 0);
      await clientsMenu(p).click(); await p.getByRole('heading', { name: '客户端管理', exact: true }).waitFor();
      await locate(p, id); assert.equal(await drawer(p).getByLabel('名称', { exact: true }).inputValue(), state === 'unknown' ? edited : original);
      assert.equal(posts, state === 'unknown' ? 1 : 0); assert.ok(scoped > 0);
      await close(p); await t.context.close();
      pass(`${mode} ${state}: cancelled hash/back/forward preserve client state; confirmed exit reloads server state without replay`);
    }

    for (const kind of ['detail', 'post']) {
      const t = await open(mode); const p = t.page;
      await p.getByRole('heading', { name: '客户端管理', exact: true }).waitFor();
      let release; const gate = new Promise(resolve => { release = resolve; });
      heldResponses.add(release);
      let seen; const observed = new Promise(resolve => { seen = resolve; });
      let finished; const delivered = new Promise(resolve => { finished = resolve; });
      let posts = 0; const writePath = apiPath + '/upsert'; const detailPath = lookupUrl(apiPath, id);
      p.on('request', request => {
        const url = new URL(request.url()); if (!url.pathname.startsWith(`${t.host.mount}/admin/clients`)) return;
        const headers = request.headers(); assert.ok(!headers['x-embedded-idp-tenant-id'] && !headers['x-embedded-idp-business-id']);
        if (request.url() === writePath && request.method() === 'POST') posts++;
      });
      const routePath = kind === 'detail' ? detailPath : writePath;
      let routeError;
      await p.route(routePath, async route => {
        try {
          const response = await route.fetch(); assert.ok(response.ok());
          if (kind === 'post') {
            const read = await p.request.get(detailPath, { headers: { authorization: t.getBearer() } });
            assert.ok(read.ok()); const value = await read.json(); assert.equal(value.client_id, id); assert.equal(value.client.client_id, id); assert.equal(value.client.client_name, `UI C late ${mode}`);
          }
          seen(); await gate;
          await route.fulfill({ response });
        } catch (reason) { routeError = reason; seen(); }
        finally { finished(); }
      });
      if (kind === 'detail') {
        await button(p, '按 ID 登记 / 编辑').click();
        const lookup = p.getByRole('dialog', { name: '按 ID 登记 / 编辑', exact: true });
        await lookup.getByLabel('客户端 ID', { exact: true }).fill(id); await button(lookup, '读取配置').click();
      } else {
        await locate(p, id); await drawer(p).getByLabel('名称', { exact: true }).fill(`UI C late ${mode}`);
        await selectType(p, '机密 Web 客户端');
        await drawer(p).getByLabel('允许的回调地址（每行一个）', { exact: true }).fill('https://example.test/callback');
        await drawer(p).getByLabel('客户端密钥', { exact: true }).fill(secret);
        await review(p); await button(confirm(p), '确认保存').click();
      }
      await bounded(observed, `${mode} ${kind} received`);
      if (routeError) throw routeError;
      console.log(`CHECK ${mode} late ${kind}: real response held`);
      if (kind === 'post') {
        for (const action of [() => p.evaluate(hash => { location.hash = hash; }, home), () => homeMenu(p).dispatchEvent('click')]) {
          const dialog = p.waitForEvent('dialog'); await action(); const alert = await dialog; assert.equal(alert.type(), 'alert');
          await p.waitForURL(`**/${clients}`);
        }
        // Loading adds an accessible icon name; scope the actual footer button.
        const submitting = confirm(p).locator('.ant-modal-footer .ant-btn-primary');
        assert.match(await submitting.getAttribute('class'), /ant-btn-loading/);
        assert.ok(await button(confirm(p), '返回修改').isDisabled());
        assert.equal(await drawer(p).locator('button.ant-drawer-close').count(), 0);
        await p.keyboard.press('Escape'); assert.ok(await confirm(p).isVisible());
        await submitting.dispatchEvent('click'); assert.equal(posts, 1);
      }
      console.log(`CHECK ${mode} late ${kind}: guard checks complete`);
      const session = await p.request.get(t.host.origin + t.host.mount + '/admin/auth/session', { headers: { authorization: t.getBearer() } });
      assert.ok(session.ok()); const identity = await session.json();
      const other = await t.context.newPage();
      other.on('pageerror', error => errors.push(error.name));
      const restored = other.waitForResponse(r => r.url() === t.host.origin + t.host.mount + '/admin/auth/session' && r.request().method() === 'GET');
      await other.goto(t.host.origin + t.host.ui + '/' + home);
      await other.locator('.management-shell-header').waitFor();
      const verified = await restored; assert.equal(verified.status(), 200); assert.deepEqual(await verified.json(), identity);
      assert.equal(await p.locator('.management-shell').count(), 1);
      console.log(`CHECK ${mode} late ${kind}: second tab verified same session`);
      const loggedOut = other.waitForResponse(r => r.url() === t.host.origin + t.host.mount + '/admin/auth/browser/logout');
      await button(other, '退出登录').click(); assert.equal((await loggedOut).status(), 204);
      await other.getByLabel('邮箱', { exact: true }).waitFor();
      await p.getByText('其他页面已更改此会话，请重新加载后继续。', { exact: true }).waitFor();
      assert.equal(await p.locator('.management-shell').count(), 0); assert.equal(await drawer(p).count(), 0);
      assert.equal(await p.getByLabel('客户端密钥', { exact: true }).count(), 0);
      const late = p.waitForResponse(r => r.url() === routePath);
      release(); await bounded(delivered, `${mode} ${kind} delivered`);
      if (routeError) throw routeError;
      assert.equal(await (await late).finished(), null); await p.unroute(routePath); heldResponses.delete(release);
      await p.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      assert.equal(await p.locator('.management-shell').count(), 0); assert.equal(await drawer(p).count(), 0);
      assert.equal(await p.getByText(/配置已保存/).count(), 0); assert.equal(posts, kind === 'post' ? 1 : 0);
      await other.close(); await t.context.close();
      pass(`${mode} late ${kind}: real logout clears workspace before held real response; no restore or replay`);
    }
  }
  assert.deepEqual(errors, []);
} catch (error) {
  console.error(`UI-C failed after: ${cases.at(-1) ?? 'startup'}`);
  for (const [index, context] of contexts.entries()) for (const page of context.pages()) {
    await page.screenshot({ path: `${output}/ui-c-failure-${index}.png`, animations: 'disabled',
      mask: [page.locator('input, textarea, [contenteditable=true]')] }).catch(() => {});
  }
  throw error;
} finally {
  for (const release of heldResponses) release();
  await writeFile(`${output}/ui-c-results.json`, JSON.stringify({ cases, pageErrors: errors, contrast, evidence: 'isolated real hosts; list states, failed/malformed reads and readback failure injected; unknown writes complete real POST and independent GET before injected abort; UI-C hash/history and covered-menu guards tested in both modes; late real detail/POST responses held until same-session cross-tab real logout, then delivered' }, null, 2));
  for (const context of contexts) await context.close();
  await browser.close();
}
