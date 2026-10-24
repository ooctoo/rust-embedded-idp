// Opt-in UI-E checks against the disposable UI-B fixture. No .env or persistent tokens.
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { realpath } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, basename } from 'node:path';
import { runDeviceChecks } from './management_security_devices.mjs';
import { runSessionChecks } from './management_security_sessions.mjs';

assert.ok(process.env.IDP_UI_TEST_FIXTURE && process.env.IDP_UI_BROWSER_EXECUTABLE && process.env.IDP_UI_PLAYWRIGHT_PATH, 'explicit private fixture, installed browser and Playwright required');
const statePath = await realpath(process.env.IDP_UI_TEST_FIXTURE);
const fixtureDir = dirname(statePath);
assert.match(basename(fixtureDir), /^idp-ui-b-[a-zA-Z0-9_-]+$/);
assert.equal(dirname(fixtureDir), await realpath(tmpdir()));
const fixture = JSON.parse(await readFile(statePath, 'utf8'));
assert.equal(await realpath(fixture.dir), fixtureDir);
assert.match(fixture.container, /^idp-ui-b-[a-f0-9]+$/);
assert.equal(execFileSync('docker', ['inspect', '--format', '{{index .Config.Labels \"idp.ui-b.fixture\"}}', fixture.container], { encoding: 'utf8' }).trim(), fixtureDir);
assert.deepEqual(Object.keys(fixture.schemas).sort(), ['disabled', 'enabled']);
for (const [mode, schema] of Object.entries(fixture.schemas)) assert.match(schema, new RegExp(`^uib_${mode}_[a-f0-9]+$`));
for (const key of ['enabled', 'disabled', 'fixed', 'choose']) {
  const host = fixture.hosts[key], url = new URL(host.origin);
  assert.equal(url.protocol, 'http:'); assert.equal(url.hostname, '127.0.0.1');
  assert.ok(host.mount.startsWith('/') && host.ui.startsWith('/'));
}
const { chromium } = await import(process.env.IDP_UI_PLAYWRIGHT_PATH ? pathToFileURL(process.env.IDP_UI_PLAYWRIGHT_PATH).href : 'playwright');
const browser = await chromium.launch({ headless: process.env.IDP_UI_HEADED !== "1", ...(process.env.IDP_UI_BROWSER_EXECUTABLE ? { executablePath: process.env.IDP_UI_BROWSER_EXECUTABLE } : {}) });
const output = process.env.IDP_UI_OUTPUT_DIR ?? fixture.dir;
await mkdir(output, { recursive: true });
const contexts = [], cases = [], pageErrors = [], held = new Set(), dialogAnswers = new WeakMap();
const supplements = [];
function bounded(promise, stage) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`Timed out: ${stage}`)), 15000); })]).finally(() => clearTimeout(timer));
}
function gate() {
  let resolve; const promise = new Promise(r => { resolve = r; });
  const timer = setTimeout(() => release(), 15000);
  const release = () => { clearTimeout(timer); held.delete(release); resolve(); };
  held.add(release); return { promise, release };
}
async function accepting(page, action) {
  dialogAnswers.set(page, true);
  try { await action(); } finally { dialogAnswers.delete(page); }
}
const id = randomBytes(6).toString('hex');
const pass = name => { cases.push(name); console.log(`PASS ${name}`); };
const button = (p, name) => p.getByRole('button', { name: new RegExp('^' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/([\u3400-\u9fff])(?=[\u3400-\u9fff])/g, '$1\\s*') + '$') });
const dialog = (p, name) => p.getByRole('dialog', { name, exact: true });
const settle = p => p.waitForFunction(() => !document.querySelector('.ant-spin-spinning, .ant-spin-blur'));
const waitRoute = async (p, hash) => {
  await p.waitForFunction(h => location.hash === h, hash);
  await p.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  const title = { members: '成员管理', roles: '角色与权限', directory: '权限目录', tenants: '租户管理', home: '工作台', accounts: '账号安全', diagnostic: '权限诊断', audit: hash.includes('/platform/') ? '平台审计' : '审计记录', devices: '设备管理', sessions: '会话管理' }[hash.split('/').at(-1)];
  const target = hash.match(/^#\/tenants\/([^/]+)\//)?.[1];
  if (title) await p.waitForFunction(({ expected, target }) => {
    const heading = document.querySelector('.management-content > h1')?.textContent;
    if (document.querySelector('.ant-result-403')) return true;
    return heading === expected && (!target || document.querySelector('.management-target')?.textContent?.includes(target)) &&
      !document.querySelector('.management-page')?.textContent?.includes('正在读取管理目标');
  }, { expected: title, target });
  await settle(p);
};
const goto = async (p, hash) => accepting(p, async () => {
  await p.evaluate(h => { location.hash = h; }, hash);
  await waitRoute(p, hash);
});
// Only for the security departure cases: create real Back and Forward entries
// before establishing a draft, then exercise the unchanged shell guards.
async function prepareDeparture(p, current) {
  const home = current.startsWith('#/platform/') ? '#/platform/home' : current.replace(/\/[^/]+$/, '/home');
  const pageName = { accounts: '账号安全', devices: '设备管理', sessions: '会话管理', diagnostic: '权限诊断' }[current.split('/').at(-1)];
  assert.ok(pageName);
  await goto(p, current);
  const menu = name => p.locator('.management-sidebar').getByRole('menuitem', { name, exact: true });
  // Use the shell's managed entries. Raw hash edits deliberately start an
  // incomparable history chain and cannot establish a reliable Forward target.
  await accepting(p, async () => {
    await menu('工作台').click(); await waitRoute(p, home);
    await menu(pageName).click(); await waitRoute(p, current);
    await menu('工作台').click(); await waitRoute(p, home);
  });
  await p.goBack(); await waitRoute(p, current);
}
async function checkDeparture(t, current, verify, destination = '#/tenants/tenant-b/home') {
  const p = t.page, identity = await api(t, '/auth/session');
  const home = current.startsWith('#/platform/') ? '#/platform/home' : current.replace(/\/[^/]+$/, '/home');
  const homeMenu = p.locator('.management-sidebar').getByRole('menuitem', { name: '工作台', exact: true });
  await verify();
  for (const action of [() => p.goBack(), () => p.goForward(),
    () => p.evaluate(hash => { location.hash = hash; }, destination), () => homeMenu.dispatchEvent('click')]) {
    const prompt = p.waitForEvent('dialog'); await action(); assert.equal((await prompt).type(), 'confirm');
    await waitRoute(p, current); await verify();
    assert.deepEqual(await api(t, '/auth/session'), identity);
  }
  const prompt = p.waitForEvent('dialog');
  await accepting(p, () => p.evaluate(hash => { location.hash = hash; }, home)); assert.equal((await prompt).type(), 'confirm');
  await waitRoute(p, home); assert.equal(await p.getByRole('dialog').count(), 0);
  assert.deepEqual(await api(t, '/auth/session'), identity);
}
async function open(key, hash, user = 'admin@example.test', password = fixture.password) {
  const host = fixture.hosts[key];
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } }); contexts.push(context);
  const page = await context.newPage(); page.setDefaultTimeout(15000);
  page.on('pageerror', e => pageErrors.push(e.name));
  page.on('dialog', d => dialogAnswers.get(page) && d.type() === 'confirm' ? d.accept() : d.dismiss());
  let bearer;
  page.on('request', request => { if (new URL(request.url()).pathname.startsWith(`${host.mount}/admin/`)) bearer = request.headers().authorization ?? bearer; });
  await page.goto(`${host.origin}${host.ui}/${hash}`);
  await page.getByLabel('邮箱', { exact: true }).fill(user);
  await page.getByLabel('密码', { exact: true }).fill(password);
  await page.getByRole('button', { name: /^登\s*录$/ }).click();
  await page.locator('.management-shell').waitFor(); await settle(page);
  return { page, context, host, bearer: () => bearer };
}
async function api(t, path, target, biz) {
  assert.ok(t.bearer()?.startsWith('Bearer '));
  const response = await t.page.request.get(`${t.host.origin}${t.host.mount}/admin${path}`, { headers: {
    authorization: t.bearer(), ...(target ? { 'x-embedded-idp-tenant-id': target } : {}), ...(biz ? { 'x-embedded-idp-business-id': biz } : {}),
  } });
  assert.ok(response.ok(), `read ${path.split('?')[0]}: ${response.status()}`); return response.json();
}

async function writeApi(t, method, path, data, target, biz) {
  const response = await t.page.request.fetch(`${t.host.origin}${t.host.mount}/admin${path}`, { method,
    headers: { authorization: t.bearer(), ...(target ? { 'x-embedded-idp-tenant-id': target } : {}), ...(biz ? { 'x-embedded-idp-business-id': biz } : {}) },
    ...(data === undefined ? {} : { data }) });
  assert.ok(response.ok(), `seed ${method} ${path}: ${response.status()}`); return response.json();
}
function sql(mode, statement) {
  assert.ok(['enabled', 'disabled'].includes(mode));
  const schema = fixture.schemas[mode]; assert.ok(statement.includes(schema));
  return execFileSync('docker', ['exec', '-i', fixture.container, 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-U', 'uib', '-d', 'uib'], { input: statement, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}
async function loginApi(request, key, email, password, selected) {
  const host = fixture.hosts[key], path = `${host.origin}${host.mount}/admin/auth`;
  const response = await request.post(`${path}/login`, { data: { email, password } }); assert.ok(response.ok());
  let result = await response.json();
  if (result.status === 'tenant_selection_required') {
    assert.ok(selected && result.selection_ticket);
    const completion = await request.post(`${path}/tenant-selection/complete`, { headers: { authorization: `TenantSelection ${result.selection_ticket}` }, data: { tenant_id: selected } });
    assert.ok(completion.ok()); result = await completion.json();
  }
  assert.equal(result.status, 'authenticated'); return { host, ...result };
}
async function invalidCredentials(request, credentials) {
  const path = `${credentials.host.origin}${credentials.host.mount}/admin/auth`;
  const session = await request.get(`${path}/session`, { headers: { authorization: `Bearer ${credentials.tokens.access_token}` } }); assert.equal(session.status(), 401);
  const refresh = await request.post(`${path}/refresh`, { data: { refresh_token: credentials.tokens.refresh_token } }); assert.equal(refresh.status(), 401);
}

const target = 'tenant-a';
try {
  const operator = await open('enabled', '#/platform/accounts');
  const p = operator.page;
  assert.ok(operator.bearer()?.startsWith('Bearer '));
  const newEmail = `uie-${id}@example.test`;
  const created = await p.request.post(`${operator.host.origin}${operator.host.mount}/admin/platform/accounts`, {
    headers: { authorization: operator.bearer() }, data: { tenant_id: target, email: newEmail, password: fixture.password },
  });
  assert.ok(created.ok(), `isolated account create: ${created.status()}`);
  const account = (await created.json()).account;
  assert.equal(account.email, newEmail); assert.equal(account.membership.tenant_id, target);
  await p.getByLabel('邮箱', { exact: true }).fill(newEmail); await button(p, '查询').click();
  await button(p, `管理账号安全 ${newEmail}`).click(); const drawer = dialog(p, '账号安全');
  await writeApi(operator, 'POST', `/members/${account.account_id}/bind`, {}, 'tenant-b');
  const passwordSessions = [await loginApi(p.request, 'fixed', newEmail, fixture.password), await loginApi(p.request, 'choose', newEmail, fixture.password, 'tenant-b')];
  const newPassword = `UiE-${id}-Second9!`;
  await drawer.getByLabel('设置新密码', { exact: true }).fill(newPassword); await button(drawer, '更新密码').click();
  let review = dialog(p, '确认更新密码');
  assert.ok(!(await review.innerText()).includes(newPassword));
  assert.ok(!(await p.url()).includes(newPassword));
  assert.equal(await p.evaluate(secret => Object.values(localStorage).concat(Object.values(sessionStorage)).some(v => v.includes(secret)), newPassword), false);
  await button(review, '返回修改').click();
  assert.equal(await drawer.getByLabel('设置新密码', { exact: true }).inputValue(), '');
  pass('account password cancel clears input; summary, URL and browser storage omit secret');
  await drawer.getByLabel('设置新密码', { exact: true }).fill(newPassword); await button(drawer, '更新密码').click();
  review = dialog(p, '确认更新密码');
  const passResponse = p.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith(`/platform/accounts/${account.account_id}/password`));
  await button(review, '确认更新').click(); const passwordWrite = await passResponse; assert.ok(passwordWrite.ok());
  const passBody = passwordWrite.request().postDataJSON(); assert.equal(passBody.new_password, newPassword); assert.ok(!Object.hasOwn(passBody, 'expected_version')); assert.ok(!Object.hasOwn(passBody, 'expected_status'));
  await drawer.getByText(/密码更新已确认/).waitFor();
  const currentAccount = await api(operator, `/platform/accounts/${account.account_id}`); assert.equal(currentAccount.account_id, account.account_id);
  for (const credentials of passwordSessions) await invalidCredentials(p.request, credentials);
  pass('real account password change uses no-CAS and invalidates original access and refresh credentials in two domains');
  const statusSessions = [await loginApi(p.request, 'fixed', newEmail, newPassword), await loginApi(p.request, 'choose', newEmail, newPassword, 'tenant-b')];
  await button(drawer, '停用账号').click(); review = dialog(p, '确认账号状态变更');
  const disableResponse = p.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith(`/platform/accounts/${account.account_id}/status`));
  await button(review, '确认变更').click(); const disabled = await disableResponse; assert.ok(disabled.ok());
  assert.deepEqual(disabled.request().postDataJSON(), { status: 'disabled', expected_status: 'active' });
  assert.equal((await api(operator, `/platform/accounts/${account.account_id}`)).status, 'disabled');
  await button(drawer, '启用账号').click(); review = dialog(p, '确认账号状态变更');
  const enableResponse = p.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith(`/platform/accounts/${account.account_id}/status`));
  await button(review, '确认变更').click(); const enabled = await enableResponse; assert.ok(enabled.ok());
  assert.deepEqual(enabled.request().postDataJSON(), { status: 'active', expected_status: 'disabled' });
  assert.equal((await api(operator, `/platform/accounts/${account.account_id}`)).status, 'active');
  for (const credentials of statusSessions) await invalidCredentials(p.request, credentials);
  pass('real disable and enable preserve expected_status and do not restore old credentials in either domain');
  await drawer.locator('button.ant-drawer-close').click(); await drawer.waitFor({ state: 'hidden' });

  // Two independent Fixed-mode management sessions for the existing synthetic tenant administrator.
  const first = await open('fixed', '#/tenants/tenant-a/home', 'tenant-a@example.test');
  const second = await open('fixed', '#/tenants/tenant-a/home', 'tenant-a@example.test');
  const firstSession = await api(first, '/auth/session'); const secondSession = await api(second, '/auth/session');
  assert.notEqual(firstSession.session_id, secondSession.session_id);
  assert.equal(firstSession.account_id, secondSession.account_id);
  await goto(p, '#/tenants/tenant-a/sessions');
  await p.getByLabel('用户 ID', { exact: true }).fill(firstSession.account_id); await button(p, '查询').click();
  await button(p, `查看会话 ${firstSession.session_id}`).click(); const sessionDrawer = dialog(p, '会话详情');
  await button(sessionDrawer, '撤销会话').click(); const sessionReview = dialog(p, '确认撤销会话');
  assert.ok((await sessionReview.innerText()).includes(firstSession.session_id));
  const revokeResponse = p.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith(`/sessions/${firstSession.session_id}/revoke`));
  await button(sessionReview, '确认撤销').click(); assert.ok((await revokeResponse).ok());
  assert.equal((await api(operator, `/sessions/${firstSession.session_id}`, target)).status, 'revoked');
  assert.equal((await api(operator, `/sessions/${secondSession.session_id}`, target)).status, 'active');
  const old = await first.page.request.get(`${first.host.origin}${first.host.mount}/admin/auth/session`, { headers: { authorization: first.bearer() } });
  assert.equal(old.status(), 401); assert.equal((await api(second, '/auth/session')).session_id, secondSession.session_id);
  pass('single session revoke invalidates original bearer and retains other independent session');
  await accepting(p, () => sessionDrawer.locator('button.ant-drawer-close').click());
  async function accountEditor(test, email) {
    await goto(test.page, '#/platform/accounts');
    await test.page.getByLabel('邮箱', { exact: true }).fill(email); await button(test.page, '查询').click();
    await button(test.page, `管理账号安全 ${email}`).click(); const form = dialog(test.page, '账号安全');
    await form.getByText(`用户：${email}`, { exact: false }).waitFor(); return form;
  }
  // The original platform administrator is the only effective platform admin here.
  const operatorIdentity = await api(operator, '/auth/session');
  let security = await accountEditor(operator, 'admin@example.test');
  await button(security, '停用账号').click();
  const protectedPost = p.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith(`/platform/accounts/${operatorIdentity.account_id}/status`));
  await button(dialog(p, '确认账号状态变更'), '确认变更').click(); assert.equal((await protectedPost).status(), 409);
  assert.equal((await api(operator, `/platform/accounts/${operatorIdentity.account_id}`)).status, 'active');
  assert.deepEqual(await api(operator, '/auth/session'), operatorIdentity);
  await accepting(p, () => security.locator('button.ant-drawer-close').click());
  pass('real last platform administrator status protection returns 409 and preserves account and session');

  for (const kind of ['password', 'status']) {
    const ownEmail = `uie-self-${kind}-${id}@example.test`;
    const own = (await writeApi(operator, 'POST', '/platform/accounts', { tenant_id: target, email: ownEmail, password: fixture.password })).account;
    // There is no public platform membership creation flow; this is an explicit
    // isolated test seed, followed by the real dedicated administrator API.
    sql('enabled', `insert into ${fixture.schemas.enabled}.access_memberships(tenant_id,account_id,status,version,joined_at_epoch) values('0','${own.account_id}','active',1,extract(epoch from clock_timestamp())::bigint)`);
    await writeApi(operator, 'POST', `/platform/security-admins/${own.account_id}`);
    const ownTest = await open('enabled', '#/platform/accounts', ownEmail), ownPage = ownTest.page;
    const credentials = await loginApi(ownPage.request, 'enabled', ownEmail, fixture.password);
    const oldBearer = ownTest.bearer(); const ownForm = await accountEditor(ownTest, ownEmail);
    if (kind === 'password') {
      await ownForm.getByLabel('设置新密码', { exact: true }).fill(`UiE-self-${id}-9!`); await button(ownForm, '更新密码').click();
      await button(dialog(ownPage, '确认更新密码'), '确认更新').click();
    } else { await button(ownForm, '停用账号').click(); await button(dialog(ownPage, '确认账号状态变更'), '确认变更').click(); }
    await ownPage.getByLabel('密码', { exact: true }).waitFor(); assert.equal(await ownPage.locator('.management-shell').count(), 0);
    await invalidCredentials(ownPage.request, credentials);
    const old = await ownPage.request.get(`${ownTest.host.origin}${ownTest.host.mount}/admin/auth/session`, { headers: { authorization: oldBearer } }); assert.equal(old.status(), 401);
    const cookie = await ownPage.request.post(`${ownTest.host.origin}${ownTest.host.mount}/admin/auth/browser/restore`, { headers: { Origin: ownTest.host.origin, 'X-Embedded-Idp-Browser': '1' }, data: {} }); assert.equal(cookie.status(), 401);
    await writeApi(operator, 'DELETE', `/platform/security-admins/${own.account_id}`);
    pass(`self account ${kind} clears workspace and rejects old access, refresh and browser Cookie restoration`);
  }

  const uncertainEmail = `uie-uncertain-${id}@example.test`;
  const uncertain = (await writeApi(operator, 'POST', '/platform/accounts', { tenant_id: target, email: uncertainEmail, password: fixture.password })).account;
  security = await accountEditor(operator, uncertainEmail);
  const passwordPath = `${operator.host.origin}${operator.host.mount}/admin/platform/accounts/${uncertain.account_id}/password`;
  let passwordPosts = 0;
  try {
    await p.route(passwordPath, async route => {
      passwordPosts++; const actual = await route.fetch(); assert.ok(actual.ok()); const body = await actual.json();
      assert.ok(body.audit_id); const audit = await api(operator, `/platform/audit-events/${body.audit_id}`); assert.equal(audit.audit_id, body.audit_id);
      await route.abort('connectionfailed');
    });
    await security.getByLabel('设置新密码', { exact: true }).fill(`UiE-uncertain-${id}-9!`); await button(security, '更新密码').click();
    await button(dialog(p, '确认更新密码'), '确认更新').click();
    await security.getByText('账号回读不能证明新密码结果', { exact: true }).waitFor();
    assert.equal(await security.getByLabel('设置新密码', { exact: true }).inputValue(), '');
    const freshRead = p.waitForResponse(r => r.request().method() === 'GET' && r.url().endsWith(`/platform/accounts/${uncertain.account_id}`));
    await accepting(p, () => button(security, '重新加载账号').click()); assert.ok((await freshRead).ok());
    await security.getByText('账号回读不能证明新密码结果', { exact: true }).waitFor();
    assert.ok(await button(security, '更新密码').isDisabled()); assert.ok(await button(security, '停用账号').isDisabled()); assert.equal(passwordPosts, 1);
    await accepting(p, () => security.locator('button.ant-drawer-close').click());
  } finally { await p.unroute(passwordPath); }
  pass('lost real password response retains lock after original account GET and clears secret without automatic replay');

  security = await accountEditor(operator, uncertainEmail);
  const statusPath = `${operator.host.origin}${operator.host.mount}/admin/platform/accounts/${uncertain.account_id}/status`;
  let statusPosts = 0;
  try {
    await p.route(statusPath, async route => {
      statusPosts++; const actual = await route.fetch(); assert.ok(actual.ok());
      assert.equal((await api(operator, `/platform/accounts/${uncertain.account_id}`)).status, 'disabled'); await route.abort('connectionfailed');
    });
    await button(security, '停用账号').click(); await button(dialog(p, '确认账号状态变更'), '确认变更').click();
    await security.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
    assert.ok(await button(security, '停用账号').isDisabled());
    await accepting(p, () => button(security, '重新加载账号').click()); await button(security, '启用账号').waitFor();
    assert.ok(await button(security, '启用账号').isEnabled()); assert.equal(statusPosts, 1);
    await accepting(p, () => security.locator('button.ant-drawer-close').click());
  } finally { await p.unroute(statusPath); }
  pass('unknown account status keeps original account locked until fresh read and retains no-attribution warning');

  security = await accountEditor(operator, newEmail);
  const accountReadPath = `${operator.host.origin}${operator.host.mount}/admin/platform/accounts/${account.account_id}`;
  try {
    await p.route(accountReadPath, route => route.fulfill({ status: 503, body: '{}' }));
    await button(security, '停用账号').click(); await button(dialog(p, '确认账号状态变更'), '确认变更').click();
    await security.getByText('写入已确认，重新读取失败', { exact: true }).waitFor();
    await security.getByText(/账号状态变更已确认/).waitFor();
    assert.equal((await api(operator, `/platform/accounts/${account.account_id}`)).status, 'disabled');
  } finally { await p.unroute(accountReadPath); }
  await security.locator('button.ant-drawer-close').click();
  pass('acknowledged account status remains confirmed when the follow-up read fails');

  security = await accountEditor(operator, uncertainEmail);
  for (const width of [320, 390, 768, 1440]) {
    await p.setViewportSize({ width, height: 900 });
    await security.getByLabel('设置新密码', { exact: true }).fill(`UiE-layout-${id}-9!`); await button(security, '更新密码').click();
    const confirmation = dialog(p, '确认更新密码'); await confirmation.waitFor();
    const region = confirmation.getByRole('region', { name: '操作范围与后果' }); assert.equal(await region.getAttribute('tabindex'), '0');
    await p.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth);
    await p.waitForFunction(() => document.activeElement?.textContent?.replace(/\s/g, '') === '返回修改');
    await p.waitForFunction(() => document.getAnimations().every(a => a.playState !== 'running' || a.effect?.getTiming().iterations === Infinity));
    const box = await confirmation.boundingBox(); assert.ok(box.width >= Math.min(280, width - 32) && box.x >= 0 && box.x + box.width <= width + 1);
    if (width === 320 || width === 1440) await confirmation.screenshot({ animations: 'disabled', path: `${output}/ui-e-account-${width}.png`, mask: [confirmation.locator('input,textarea')] });
    await button(confirmation, '返回修改').click();
  }
  await p.setViewportSize({ width: 1440, height: 1000 });
  await security.getByLabel('设置新密码', { exact: true }).fill(`UiE-draft-${id}-9!`);
  const rejectedLeave = p.waitForEvent('dialog'); await p.evaluate(() => { location.hash = '#/platform/home'; }); await rejectedLeave;
  await p.waitForURL('**/#/platform/accounts'); assert.ok(await security.isVisible());
  assert.ok(await security.getByLabel('设置新密码', { exact: true }).inputValue());
  await goto(p, '#/platform/home'); assert.equal(await dialog(p, '账号安全').count(), 0);
  pass('password draft rejects hash departure and confirmation is cancel-focused and contained at four widths');

  const disabledTest = await open('disabled', '#/system/accounts');
  const disabledAccount = (await writeApi(disabledTest, 'POST', '/platform/accounts', { tenant_id: '0', email: `uie-disabled-${id}@example.test`, password: fixture.password })).account;
  await disabledTest.page.getByLabel('邮箱', { exact: true }).fill(disabledAccount.email); await button(disabledTest.page, '查询').click();
  await button(disabledTest.page, `管理账号安全 ${disabledAccount.email}`).click();
  const disabledForm = dialog(disabledTest.page, '账号安全'); assert.ok((await disabledForm.innerText()).includes('本系统'));
  await button(disabledForm, '停用账号').click(); await button(dialog(disabledTest.page, '确认账号状态变更'), '确认变更').click();
  assert.equal((await api(disabledTest, `/platform/accounts/${disabledAccount.account_id}`)).status, 'disabled');
  for (const key of ['fixed', 'choose']) {
    if (key === 'choose') {
      const host = fixture.hosts.choose, context = await browser.newContext(); contexts.push(context); const page = await context.newPage();
      page.on('pageerror', e => pageErrors.push(e.name)); page.on('dialog', d => d.dismiss());
      await page.goto(`${host.origin}${host.ui}/#/tenants/tenant-a/home`); await page.getByLabel('邮箱', { exact: true }).fill('tenant-a@example.test'); await page.getByLabel('密码', { exact: true }).fill(fixture.password); await button(page, '登录').click();
      await button(page, '进入 UI B tenant-a').click(); await page.locator('.management-shell').waitFor();
      await accepting(page, () => page.evaluate(() => { location.hash = '#/platform/accounts'; })); await page.getByText('无权访问此管理范围', { exact: true }).waitFor();
    } else { const fixed = await open('fixed', '#/platform/accounts', 'tenant-a@example.test'); await fixed.page.getByText('无权访问此管理范围', { exact: true }).waitFor(); }
  }
  pass('Disabled retains global account actions while Fixed and Choose cannot enter platform account scope');

  const closedEmail = `uie-closed-${id}@example.test`;
  const closed = (await writeApi(operator, 'POST', '/platform/accounts', { tenant_id: target, email: closedEmail, password: fixture.password })).account;
  sql('enabled', `update ${fixture.schemas.enabled}.accounts set status='closed' where id='${closed.account_id}'`);
  security = await accountEditor(operator, closedEmail);
  await security.getByText('已关闭账号只读，不能恢复状态或重置密码。', { exact: true }).waitFor();
  assert.equal(await button(security, '更新密码').count(), 0); assert.equal(await button(security, '启用账号').count(), 0); assert.equal(await button(security, '停用账号').count(), 0);
  await security.locator('button.ant-drawer-close').click();
  pass('closed account remains read-only without status recovery or password action');

  const lateWrite = await open('enabled', '#/platform/accounts'), wp = lateWrite.page;
  const beforeIdentity = await api(lateWrite, '/auth/session');
  const writeForm = await accountEditor(lateWrite, uncertainEmail);
  const latePath = `${lateWrite.host.origin}${lateWrite.host.mount}/admin/platform/accounts/${uncertain.account_id}/status`;
  const latch = gate(); let observedResolve, completedResolve, delivered = false, heldError, heldPosts = 0;
  const observed = new Promise(resolve => { observedResolve = resolve; }), completed = new Promise(resolve => { completedResolve = resolve; });
  try {
    await wp.route(latePath, async route => {
      try {
        heldPosts++; const actual = await route.fetch(); assert.ok(actual.ok());
        assert.equal((await api(lateWrite, `/platform/accounts/${uncertain.account_id}`)).status, 'active');
        observedResolve(); await latch.promise; await route.fulfill({ response: actual }); delivered = true;
      } catch (error) { heldError = error; observedResolve(); }
      finally { completedResolve(); }
    });
    await button(writeForm, '启用账号').click(); await button(dialog(wp, '确认账号状态变更'), '确认变更').click();
    await bounded(observed, 'real account write held'); if (heldError) throw heldError;
    const refused = wp.waitForEvent('dialog'); await wp.evaluate(() => { location.hash = '#/platform/home'; }); assert.equal((await refused).type(), 'alert');
    await wp.waitForURL('**/#/platform/accounts'); assert.equal(heldPosts, 1); assert.equal(delivered, false);
    const other = await lateWrite.context.newPage(); other.on('pageerror', error => pageErrors.push(error.name));
    const verified = other.waitForResponse(r => r.request().method() === 'GET' && r.url() === `${lateWrite.host.origin}${lateWrite.host.mount}/admin/auth/session`);
    await other.goto(`${lateWrite.host.origin}${lateWrite.host.ui}/#/platform/home`); await other.locator('.management-shell').waitFor();
    assert.deepEqual(await (await verified).json(), beforeIdentity);
    const logout = other.waitForResponse(r => r.url().endsWith('/auth/browser/logout'));
    await button(other, '退出登录').click(); assert.equal((await logout).status(), 204);
    await wp.getByText('其他页面已更改此会话，请重新加载后继续。', { exact: true }).waitFor(); assert.equal(await wp.locator('.management-shell').count(), 0);
    const response = wp.waitForResponse(r => r.url() === latePath && r.request().method() === 'POST'); latch.release();
    assert.equal(await (await response).finished(), null); await bounded(completed, 'late account write delivered'); if (heldError) throw heldError;
    await wp.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.ok(delivered); assert.equal(heldPosts, 1); assert.equal(await wp.locator('.management-shell').count(), 0); assert.equal(await dialog(wp, '账号安全').count(), 0);
  } finally { latch.release(); await wp.unroute(latePath); }
  pass('pending account write blocks departure and fully delivered success after same-session logout cannot restore workspace or replay');

  for (const width of [320, 390, 768, 1440]) {
    await p.setViewportSize({ width, height: 900 });
    for (const hash of ['#/platform/accounts', '#/tenants/tenant-a/devices', '#/tenants/tenant-a/sessions', '#/tenants/tenant-a/audit', '#/tenants/tenant-a/diagnostic']) {
      await goto(p, hash);
      await p.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth);
      const duplicates = await p.evaluate(() => { const ids = [...document.querySelectorAll('[id]')].map(e => e.id); return ids.filter((v,i) => ids.indexOf(v)!==i); }); assert.deepEqual(duplicates, []);
    }
  }
  await p.setViewportSize({ width: 1440, height: 1000 });
  pass('all five security surfaces fit 320 390 768 and 1440 viewports with unique form IDs');

  await runDeviceChecks({ fixture, id, output, browser, contexts, pageErrors, open, api, writeApi, sql, button, dialog, goto, accepting, bounded, gate, settle, prepareDeparture, checkDeparture, supplements, pass });
  await runSessionChecks({ fixture, id, output, browser, contexts, pageErrors, open, api, writeApi, sql, button, dialog, goto, accepting, bounded, gate, settle, prepareDeparture, checkDeparture, supplements, pass });
  for (const supplement of supplements) await supplement();

  for (const mode of ['draft', 'password-confirmation', 'status-confirmation', 'unknown-password', 'unknown-status']) {
    const test = await open('enabled', '#/platform/accounts'), page = test.page;
    const email = `uie-leave-${mode}-${id}@example.test`;
    const subject = (await writeApi(test, 'POST', '/platform/accounts', { tenant_id: target, email, password: fixture.password })).account;
    await prepareDeparture(page, '#/platform/accounts');
    let editor = await accountEditor(test, email);
    const path = `${test.host.origin}${test.host.mount}/admin/platform/accounts/${subject.account_id}/${mode === 'unknown-status' ? 'status' : 'password'}`;
    let posts = 0;
    const count = request => {
      if (request.method() === 'POST' && request.url().includes(`/platform/accounts/${subject.account_id}/`)) {
        posts++; assert.equal(request.headers()['x-embedded-idp-tenant-id'], undefined);
        assert.equal(request.headers()['x-embedded-idp-business-id'], undefined);
      }
    };
    page.on('request', count);
    const secret = `UiE-leave-${id}-9!`;
    try {
      if (mode.startsWith('unknown-')) await page.route(path, async route => {
        const actual = await route.fetch(); assert.ok(actual.ok());
        if (mode === 'unknown-password') {
          const body = await actual.json(); assert.ok(body.audit_id);
          assert.equal((await api(test, `/platform/audit-events/${body.audit_id}`)).audit_id, body.audit_id);
        } else assert.equal((await api(test, `/platform/accounts/${subject.account_id}`)).status, 'disabled');
        await route.abort('connectionfailed');
      });
      if (mode.includes('status')) {
        await button(editor, '停用账号').click();
        if (mode === 'unknown-status') await button(dialog(page, '确认账号状态变更'), '确认变更').click();
      } else {
        await editor.getByLabel('设置新密码', { exact: true }).fill(secret);
        if (mode !== 'draft') await button(editor, '更新密码').click();
        if (mode === 'unknown-password') await button(dialog(page, '确认更新密码'), '确认更新').click();
      }
      if (mode.startsWith('unknown-')) await editor.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
      await checkDeparture(test, '#/platform/accounts', async () => {
        assert.ok((await editor.innerText()).includes(subject.account_id));
        assert.equal(await editor.getByLabel('设置新密码', { exact: true }).inputValue(), mode.startsWith('unknown-') || mode.includes('status') ? '' : secret);
        if (mode.endsWith('confirmation')) {
          const title = mode === 'status-confirmation' ? '确认账号状态变更' : '确认更新密码';
          const review = dialog(page, title); assert.ok(await review.isVisible());
          assert.ok((await review.innerText()).includes(subject.account_id));
          assert.ok(!(await review.innerText()).includes(secret));
        }
        if (mode.startsWith('unknown-')) {
          assert.ok(await button(editor, '停用账号').isDisabled());
          assert.ok(await button(editor, '更新密码').isDisabled());
        }
        assert.equal(posts, mode.startsWith('unknown-') ? 1 : 0);
      });
      editor = await accountEditor(test, email);
      assert.equal(await editor.getByLabel('设置新密码', { exact: true }).inputValue(), '');
      assert.equal((await api(test, `/platform/accounts/${subject.account_id}`)).status, mode === 'unknown-status' ? 'disabled' : 'active');
      assert.equal(posts, mode.startsWith('unknown-') ? 1 : 0);
      await editor.locator('button.ant-drawer-close').click();
    } finally { await page.unroute(path); page.off('request', count); }
    pass(`account ${mode} survives rejected history/hash/menu departure and accepted departure clears local state without replay`);
  }
  assert.deepEqual(pageErrors, []);
} catch (error) {
  for (const release of held) release();
  console.error(`UI-E checks failed after: ${cases.at(-1) ?? 'startup'}`);
  for (const [index, context] of contexts.entries()) for (const page of context.pages()) {
    await page.screenshot({ animations: 'disabled', path: `${output}/ui-e-failure-${index}.png`, mask: [page.locator('input, textarea, [contenteditable=true]')] }).catch(() => {});
  }
  throw error;
} finally {
  for (const release of held) release();
  await writeFile(`${output}/ui-e-results.json`, JSON.stringify({ cases, pageErrors, evidence: 'isolated compiled hosts and PostgreSQL; temporary SQL seeds explicitly scoped; writes and independent reads real; error and delayed responses explicitly injected; no production or deployment acceptance' }, null, 2));
  await Promise.all(contexts.map(context => context.close().catch(() => {})));
  await browser.close();
}
