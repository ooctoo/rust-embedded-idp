// Opt-in UI-D checks against the disposable UI-B fixture. No .env or persistent tokens.
import { browserLaunchOptions } from './management_browser.mjs';
import { functionalOnly, createFunctionalCoverage, finalizeFunctionalRun } from './management_functional.mjs';
import assert from 'node:assert/strict';
import { readFile, mkdir } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';

const fixture = JSON.parse(await readFile(process.env.IDP_UI_TEST_FIXTURE, 'utf8'));
assert.match(fixture.container, /^idp-ui-b-[a-f0-9]+$/);
assert.deepEqual(Object.keys(fixture.schemas).sort(), ['disabled', 'enabled']);
for (const [mode, schema] of Object.entries(fixture.schemas)) assert.match(schema, new RegExp(`^uib_${mode}_[a-f0-9]+$`));
for (const key of ['enabled', 'disabled', 'fixed', 'choose']) {
  const host = fixture.hosts[key], url = new URL(host.origin);
  assert.equal(url.protocol, 'http:'); assert.equal(url.hostname, '127.0.0.1');
  assert.ok(host.mount.startsWith('/') && host.ui.startsWith('/'));
}
const { chromium } = await import(process.env.IDP_UI_PLAYWRIGHT_PATH ? pathToFileURL(process.env.IDP_UI_PLAYWRIGHT_PATH).href : 'playwright');
const browser = await chromium.launch(browserLaunchOptions());
const output = process.env.IDP_UI_OUTPUT_DIR ?? fixture.dir;
await mkdir(output, { recursive: true });
const coverage = createFunctionalCoverage('authorization', output);
const contexts = [], cases = [], pageErrors = [], held = new Set(), dialogAnswers = new WeakMap();
let failure, failureDiagnostics;
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
const tenant = `uid-${id}`, tenant2 = `uid-existing-${id}`, email = `uid-${id}@example.test`;
const business = `uid_${id}`, roleName = `UI D role ${id}`;
const pass = name => { coverage.pass(name); cases.push(name); console.log(`PASS ${name}`); };
const button = (p, name) => p.getByRole('button', { name: new RegExp('^' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/([\u3400-\u9fff])(?=[\u3400-\u9fff])/g, '$1\\s*') + '$') });
const dialog = (p, name) => p.getByRole('dialog', { name, exact: true });
const settle = p => p.waitForFunction(() => !document.querySelector('.ant-spin-spinning, .ant-spin-blur'));
const goto = async (p, hash) => accepting(p, async () => {
  await p.evaluate(h => { location.hash = h; }, hash);
  await p.waitForFunction(h => location.hash === h, hash);
  await p.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  const title = { members: '成员管理', roles: '角色与权限', directory: '权限目录', tenants: '租户管理', home: '工作台' }[hash.split('/').at(-1)];
  const target = hash.match(/^#\/tenants\/([^/]+)\//)?.[1];
  if (title) await p.waitForFunction(({ expected, target }) => {
    const heading = document.querySelector('.management-content > h1')?.textContent;
    if (document.querySelector('.ant-result-403')) return true;
    return heading === expected && (!target || document.querySelector('.management-target')?.textContent?.includes(target)) &&
      !document.querySelector('.management-page')?.textContent?.includes('正在读取管理目标');
  }, { expected: title, target });
  await settle(p);
});
async function open(key, hash, user = 'admin@example.test') {
  const host = fixture.hosts[key];
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } }); contexts.push(context);
  const page = await context.newPage(); page.setDefaultTimeout(15000);
  page.on('pageerror', e => pageErrors.push(e.name));
  page.on('dialog', d => dialogAnswers.get(page) && d.type() === 'confirm' ? d.accept() : d.dismiss());
  let bearer;
  page.on('request', request => { if (new URL(request.url()).pathname.startsWith(`${host.mount}/admin/`)) bearer = request.headers().authorization ?? bearer; });
  await page.goto(`${host.origin}${host.ui}/${hash}`);
  await page.getByLabel('邮箱', { exact: true }).fill(user);
  await page.getByLabel('密码', { exact: true }).fill(fixture.password);
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
async function captureReview(p, review, name) {
  await review.waitFor(); const element = await review.elementHandle();
  await p.waitForFunction(el => {
    const focused = document.activeElement;
    const wrapper = el.closest('.ant-modal-wrap');
    return !!wrapper && el.contains(focused) && focused?.classList.contains('ant-btn-default') &&
      Number(getComputedStyle(el).opacity) === 1 && Number(getComputedStyle(wrapper).opacity) === 1 &&
      getComputedStyle(wrapper).visibility === 'visible';
  }, element);
  if (!functionalOnly) await review.screenshot({ path: `${output}/${name}.png`, animations: 'allow', mask: [review.locator('input, textarea, [contenteditable=true]')] });
}
async function waitWrite(p, suffix, action) {
  const result = p.waitForResponse(r => new URL(r.url()).pathname.endsWith(suffix) && r.request().method() === 'POST');
  await action(); const response = await result; assert.ok(response.ok(), `${suffix}: ${response.status()}`); return response;
}
async function recoverDirectory(p, form) {
  let next = button(form, '读取原权限范围首页');
  for (let page = 0; page < 100; page++) {
    const read = p.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith('/access/permissions'));
    await next.click(); assert.ok((await read).ok());
    await p.waitForFunction(() => [...document.querySelectorAll('[role="dialog"]')].some(d => [...d.querySelectorAll('button')].some(b => /结束核对|读取下一页/.test(b.textContent) && !b.disabled)));
    if (await button(form, '结束核对').isVisible()) { await button(form, '结束核对').click(); await form.waitFor({ state: 'hidden' }); return; }
    next = button(form, '读取下一页');
  }
  throw new Error('Permission recovery exceeded 100 pages');
}
async function tenantForm(p, target, name) {
  await button(p, '创建租户').click(); const d = dialog(p, '创建租户');
  await d.getByLabel('租户 ID', { exact: true }).fill(target); await d.getByLabel('租户名称', { exact: true }).fill(name);
  return d;
}
async function createPermission(t, target) {
  const p = t.page; await goto(p, target === '0' ? '#/system/directory' : `#/tenants/${target}/directory`);
  await button(p, '创建权限').click(); const form = dialog(p, '创建权限');
  await form.getByLabel('业务标识', { exact: true }).fill(business);
  await form.getByLabel('资源类型', { exact: true }).fill('report');
  await form.getByLabel('动作', { exact: true }).fill('read');
  await form.getByLabel('权限说明', { exact: true }).fill('UI D synthetic read');
  await button(form, '核对').click(); const review = dialog(p, '确认创建权限');
  const response = await waitWrite(p, '/access/permissions', () => button(review, '确认').click());
  assert.equal(response.request().headers()['x-embedded-idp-tenant-id'], target);
  assert.equal(response.request().headers()['x-embedded-idp-business-id'], business);
  assert.deepEqual(response.request().postDataJSON(), { resource_type: 'report', action: 'read', description: 'UI D synthetic read' });
  await review.waitFor({ state: 'hidden' });
}
async function createRole(t, target) {
  const p = t.page; await goto(p, target === '0' ? '#/system/roles' : `#/tenants/${target}/roles`);
  await button(p, '新建角色').click(); const form = dialog(p, '新建业务角色');
  await form.getByLabel('业务标识', { exact: true }).fill(business);
  await form.getByLabel('角色标识', { exact: true }).fill(`reader_${id}`);
  await form.getByLabel('角色名称', { exact: true }).fill(roleName);
  await button(form, '创建角色').click(); const review = dialog(p, '确认创建角色');
  const response = await waitWrite(p, '/access/roles', () => button(review, '确认创建').click());
  assert.equal(response.request().headers()['x-embedded-idp-tenant-id'], target);
  assert.equal(response.request().headers()['x-embedded-idp-business-id'], business);
  assert.ok(!Object.hasOwn(response.request().postDataJSON(), 'expected_version'));
  await review.waitFor({ state: 'hidden' });
}
async function writeApi(t, method, path, data, target, biz) {
  const headers = { authorization: t.bearer(), ...(target ? { 'x-embedded-idp-tenant-id': target } : {}), ...(biz ? { 'x-embedded-idp-business-id': biz } : {}) };
  const response = await t.page.request.fetch(`${t.host.origin}${t.host.mount}/admin${path}`, { method, headers, ...(data === undefined ? {} : { data }) });
  assert.ok(response.ok(), `seed ${method} ${path}: ${response.status()}`); return response.json();
}
async function createUser(t, target, user) {
  const p = t.page; await button(p, '新建用户').click(); const form = dialog(p, '创建账号');
  await form.getByLabel('邮箱', { exact: true }).fill(user);
  await form.getByLabel('初始密码', { exact: true }).fill(fixture.password);
  await button(form, '下一步').click(); const review = dialog(p, '确认创建账号');
  assert.ok(!(await review.innerText()).includes(fixture.password));
  const response = await waitWrite(p, '/platform/accounts', () => button(review, '确认创建').click());
  assert.equal(response.request().postDataJSON().tenant_id, target);
  await form.waitFor({ state: 'hidden' });
  return (await response.json()).account.account_id;
}
async function memberDrawer(p, user) {
  await button(p, `查看成员角色 ${user}`).click();
  return dialog(p, `成员角色：${user}`);
}
async function chooseRole(p, d, name) {
  await button(d, '分配业务角色').click();
  await button(d, `选择角色 ${name}`).click();
}
async function selectOption(p, parent, label, option) {
  const input = parent.getByLabel(label, { exact: true });
  await input.focus(); await input.press('ArrowDown');
  const inputId = await input.getAttribute('id'); assert.ok(inputId);
  const controls = await input.getAttribute('aria-controls'); assert.ok(controls);
  await p.waitForFunction(({ inputId, controls, option }) => {
    const element = document.getElementById(inputId);
    const popup = document.getElementById(controls)?.closest('.ant-select-dropdown');
    return element?.getAttribute('aria-expanded') === 'true' && popup?.getClientRects().length &&
      [...popup.querySelectorAll('.ant-select-item-option-content')].some(item => item.textContent === option);
  }, { inputId, controls, option });
  for (let i = 0; ; i++) {
    const active = await input.evaluate(el => { const item = document.getElementById(el.getAttribute('aria-activedescendant')); return item?.getAttribute('aria-label') ?? item?.textContent; });
    if (active === option) break;
    assert.ok(i < 10, `keyboard did not reach ${option}`);
    await input.press('ArrowDown');
  }
  await input.press('Enter');
  // Form updates may replace the combobox node; resolve its stable form ID again.
  await p.waitForFunction(({ inputId, option }) => {
    const element = document.getElementById(inputId);
    return element?.getAttribute('aria-expanded') === 'false' &&
      element.closest('.ant-select')?.querySelector('.ant-select-selection-item')?.textContent === option;
  }, { inputId, option });
  await p.waitForFunction(() => !document.querySelector('.ant-select-dropdown:not(.ant-select-dropdown-hidden)'));
  await p.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

async function grant(t, d, target, subject, name, kind, resourceId) {
  const p = t.page; await chooseRole(p, d, name);
  if (kind === 'business') {
    assert.equal(await d.getByLabel('资源 ID', { exact: true }).count(), 0);
    await button(d, '预览业务管理员授权').click();
  } else {
    await selectOption(p, d, '资源类型', 'report');
    await selectOption(p, d, '授权范围', kind === 'instance' ? '仅一个具体资源' : '该类型的全部资源');
    if (kind === 'instance') {
      await d.getByLabel('资源 ID', { exact: true }).fill(resourceId);
      await selectOption(p, d, '授权范围', '该类型的全部资源');
      assert.equal(await d.getByLabel('资源 ID', { exact: true }).count(), 0);
      await selectOption(p, d, '授权范围', '仅一个具体资源');
      assert.equal(await d.getByLabel('资源 ID', { exact: true }).inputValue(), '');
      await d.getByLabel('资源 ID', { exact: true }).fill(resourceId);
    }
    else assert.equal(await d.getByLabel('资源 ID', { exact: true }).count(), 0);
    await button(d, '预览授权').click();
  }
  const review = dialog(p, kind === 'business' ? '确认业务管理员授权' : '确认成员角色分配');
  if (kind === 'instance' || kind === 'business') {
    await review.getByRole('region', { name: '操作范围与后果' }).waitFor();
    const suffix = target === '0' ? '-system' : '';
    await captureReview(p, review, `ui-d-grant-${kind}${suffix}`);
    if (kind === 'instance' && !functionalOnly) {
      await p.setViewportSize({ width: 320, height: 800 });
      const region = review.getByRole('region', { name: '操作范围与后果' });
      assert.equal(await region.getAttribute('tabindex'), '0');
      assert.match(await region.evaluate(el => getComputedStyle(el).overflowY), /auto|scroll/);
      await captureReview(p, review, `ui-d-grant-instance-320${suffix}`);
      await p.setViewportSize({ width: 1440, height: 1000 });
    }
  }
  const response = await waitWrite(p, `/access/subjects/${encodeURIComponent(subject)}/role-bindings`, () => button(review, kind === 'business' ? '确认授予业务权限' : '确认分配').click());
  const request = response.request(), body = request.postDataJSON();
  assert.equal(request.headers()['x-embedded-idp-tenant-id'], target);
  assert.equal(request.headers()['x-embedded-idp-business-id'], business);
  assert.equal(body.scope.kind, kind); assert.ok(!Object.hasOwn(body, 'expected_version'));
  if (kind === 'instance') assert.equal(body.scope.resource_id, resourceId);
  else assert.ok(!Object.hasOwn(body.scope, 'resource_id'));
  if (kind === 'business') assert.ok(!Object.hasOwn(body, 'resource_type'));
  else assert.equal(body.resource_type, 'report');
  await review.waitFor({ state: 'hidden' }); return (await response.json()).binding;
}
try {
  const t = await open('enabled', '#/platform/tenants'); const p = t.page;
  const identity = await api(t, '/auth/session');
  let form = await tenantForm(p, tenant, `UI D ${id}`);
  await form.getByLabel('管理员邮箱', { exact: true }).fill(email);
  await form.getByLabel('初始密码', { exact: true }).fill(fixture.password);
  await button(form, '核对并创建').click(); let review = dialog(p, '确认创建租户');
  assert.ok(!(await review.innerText()).includes(fixture.password));
  assert.ok(!(await review.innerText()).includes('expected_version'));
  assert.ok(!(await review.innerText()).includes('当前版本'));
  await review.getByRole('region', { name: '操作范围与后果' }).waitFor();
  await captureReview(p, review, 'ui-d-tenant-review');
  await p.waitForFunction(() => document.activeElement?.closest('.ant-modal-footer')?.querySelector('.ant-btn-default') === document.activeElement);
  await button(review, '取消').click(); assert.equal(await form.getByLabel('初始密码', { exact: true }).inputValue(), '');
  await form.getByLabel('初始密码', { exact: true }).fill(fixture.password);
  await button(form, '核对并创建').click(); review = dialog(p, '确认创建租户');
  const created = await waitWrite(p, '/admin/tenants', () => button(review, '确认提交').click());
  assert.equal(created.request().postDataJSON().administrator.kind, 'new');
  assert.equal(created.request().headers()['x-embedded-idp-tenant-id'], undefined);
  await review.waitFor({ state: 'hidden' });
  const members = await api(t, `/accounts?email=${encodeURIComponent(email)}&limit=50`, tenant);
  assert.equal(members.items.length, 1); const subject = members.items[0].account_id;
  assert.equal(members.items[0].membership.status, 'active');
  const admin = await api(t, `/access/security-admins/${encodeURIComponent(subject)}`, tenant);
  assert.equal(admin.account.account_id, subject); assert.ok(admin.binding);
  assert.deepEqual(await api(t, '/auth/session'), identity);
  pass('new tenant and initial administrator: UI confirmation, account/member/admin readback and unchanged session');
  await form.locator('button.ant-drawer-close').click(); await form.waitFor({ state: 'hidden' });
  form = await tenantForm(p, tenant2, `UI D existing ${id}`);
  await form.getByText('选择已有用户', { exact: true }).click();
  await form.getByLabel('用户邮箱', { exact: true }).fill(email); await button(form, '搜索已有用户').click();
  await button(form, `选择用户 ${email}`).click();
  assert.equal(await form.getByLabel('初始密码', { exact: true }).count(), 0);
  await button(form, '核对并创建').click(); review = dialog(p, '确认创建租户');
  const existing = await waitWrite(p, '/admin/tenants', () => button(review, '确认提交').click());
  assert.deepEqual(existing.request().postDataJSON().administrator, { kind: 'existing', subject_id: subject });
  const other = await api(t, `/accounts?email=${encodeURIComponent(email)}&limit=50`, tenant2);
  assert.equal(other.items[0].account_id, subject);
  assert.ok((await api(t, `/access/security-admins/${encodeURIComponent(subject)}`, tenant2)).binding);
  pass('existing initial administrator retains the same global account and sends no password');
  await form.locator('button.ant-drawer-close').click(); await form.waitFor({ state: 'hidden' });
  await createPermission(t, tenant); await createRole(t, tenant);
  pass('business permission and role created through reviewed UI with target and business headers');
  await button(p, `查看角色 ${roleName}`).click(); const detail = dialog(p, '角色详情');
  await button(detail, '编辑权限集').click(); const editor = dialog(p, `编辑角色权限：${roleName}`);
  await button(editor.getByRole('row').filter({ hasText: 'report::read' }), '添加').click();
  await button(editor, '核对权限集').click(); const permReview = dialog(p, '确认替换角色权限集');
  await permReview.getByRole('region', { name: '操作范围与后果' }).waitFor();
  await captureReview(p, permReview, 'ui-d-role-permissions-review');
  const put = p.waitForResponse(r => r.request().method() === 'PUT' && new URL(r.url()).pathname.endsWith('/permissions'));
  await button(permReview, '确认保存权限').click(); const saved = await put; assert.ok(saved.ok());
  assert.equal(saved.request().headers()['x-embedded-idp-tenant-id'], tenant);
  assert.equal(saved.request().headers()['x-embedded-idp-business-id'], business);
  assert.ok(Number.isInteger(saved.request().postDataJSON().expected_version));
  assert.deepEqual(saved.request().postDataJSON().permissions, [{ resource_type: 'report', action: 'read' }]);
  pass('complete role permission set is reviewed and saved with current version');
  await editor.waitFor({ state: 'hidden' });
  await detail.locator('button.ant-drawer-close').click(); await detail.waitFor({ state: 'hidden' });
  // Create a second, ordinary member; retain only synthetic identifiers in memory.
  const user = `uid-member-${id}@example.test`;
  await goto(p, `#/tenants/${tenant}/members`);
  const member = await createUser(t, tenant, user);
  assert.equal((await api(t, `/accounts/${encodeURIComponent(member)}`, tenant)).membership.status, 'active');
  pass('new member created through UI and read back as active');
  const adminName = `UI D business admin ${id}`;
  await goto(p, `#/tenants/${tenant}/roles`); await button(p, '创建业务管理员').click();
  const adminRoleForm = dialog(p, '创建业务管理员');
  await adminRoleForm.getByLabel('业务标识', { exact: true }).fill(business);
  await adminRoleForm.getByLabel('角色名称', { exact: true }).fill(adminName);
  await button(adminRoleForm, '创建角色').click();
  const adminRoleResponse = await waitWrite(p, '/access/business-admin', () => button(dialog(p, '确认创建角色'), '确认创建').click());
  assert.equal(adminRoleResponse.request().headers()['x-embedded-idp-tenant-id'], tenant);
  assert.equal(adminRoleResponse.request().headers()['x-embedded-idp-business-id'], business);
  assert.equal((await adminRoleResponse.json()).role.kind, 'business_admin');
  await adminRoleForm.waitFor({ state: 'hidden' });
  await goto(p, `#/tenants/${tenant}/members`);
  pass('business administrator role created through confirmation and real POST');
  await button(p, `管理管理员授权 ${user}`).click(); const appointment = dialog(p, '租户管理员任命与撤销');
  await button(appointment, '任命为租户管理员').click();
  await waitWrite(p, `/access/security-admins/${encodeURIComponent(member)}`, () => button(dialog(p, '确认任命租户管理员'), '确认任命').click());
  assert.ok((await api(t, `/access/security-admins/${encodeURIComponent(member)}`, tenant)).binding);
  await button(appointment, '撤销租户管理员').click();
  const revokeAdmin = p.waitForResponse(r => r.request().method() === 'DELETE' && new URL(r.url()).pathname.endsWith(`/access/security-admins/${encodeURIComponent(member)}`));
  await button(dialog(p, '确认撤销租户管理员'), '确认撤销').click(); assert.ok((await revokeAdmin).ok());
  assert.equal((await api(t, `/access/security-admins/${encodeURIComponent(member)}`, tenant)).binding, null);
  await appointment.locator('button.ant-drawer-close').click(); await appointment.waitFor({ state: 'hidden' });
  pass('ordinary member administrator appointment and revocation read back successfully');
  let md = await memberDrawer(p, user);
  const first = await grant(t, md, tenant, member, roleName, 'instance', `resource-${id}`);
  const second = await grant(t, md, tenant, member, roleName, 'type');
  const third = await grant(t, md, tenant, member, adminName, 'business');
  const bindings = await api(t, `/access/subjects/${encodeURIComponent(member)}/role-bindings?limit=50`, tenant, business);
  for (const binding of [first, second, third]) assert.ok(bindings.items.some(b => b.binding_id === binding.binding_id));
  pass('INSTANCE, TYPE and business-admin grants preserve scope and omit stale resource fields');
  const row = md.getByRole('row').filter({ hasText: first.role_id }).filter({ hasText: `resource-${id}` });
  await button(row, '撤销').click(); let reviewRevoke = dialog(p, '确认撤销角色分配');
  const deletion = p.waitForResponse(r => r.request().method() === 'DELETE' && new URL(r.url()).pathname.endsWith(`/access/role-bindings/${encodeURIComponent(first.binding_id)}`));
  await button(reviewRevoke, '确认撤销').click(); const deleted = await deletion;
  assert.ok(deleted.ok()); assert.equal(deleted.request().headers()['x-embedded-idp-tenant-id'], tenant);
  assert.equal(deleted.request().headers()['x-embedded-idp-business-id'], business);
  assert.equal(deleted.request().postData(), null);
  const remaining = await api(t, `/access/subjects/${encodeURIComponent(member)}/role-bindings?limit=50`, tenant, business);
  assert.ok(!remaining.items.some(b => b.binding_id === first.binding_id));
  assert.ok(remaining.items.some(b => b.binding_id === second.binding_id));
  pass('revoke addresses the original binding ID and retains other bindings');
  await md.locator('button.ant-drawer-close').click(); await md.waitFor({ state: 'hidden' });
  await button(p, `管理管理员授权 ${email}`).click(); const admins = dialog(p, '租户管理员任命与撤销');
  await button(admins, '撤销租户管理员').click(); const adminReview = dialog(p, '确认撤销租户管理员');
  const conflict = p.waitForResponse(r => r.request().method() === 'DELETE' && new URL(r.url()).pathname.endsWith(`/access/security-admins/${encodeURIComponent(subject)}`));
  await button(adminReview, '确认撤销').click(); assert.equal((await conflict).status(), 409);
  await adminReview.waitFor({ state: 'hidden' }); await admins.getByRole('alert').first().waitFor();
  assert.ok((await api(t, `/access/security-admins/${encodeURIComponent(subject)}`, tenant)).binding);
  pass('last tenant administrator revocation returns real 409 and leaves binding intact');
  await accepting(p, () => button(admins, '重新加载管理员状态').click()); await p.waitForFunction(() => [...document.querySelectorAll('.ant-drawer button')].some(b => b.textContent.replace(/\s/g, '') === '撤销租户管理员' && !b.disabled)); await admins.locator('button.ant-drawer-close').click(); await admins.waitFor({ state: 'hidden' });
  await button(p, `管理成员关系 ${user}`).click(); let relationship = dialog(p, '成员关系');
  const current = await api(t, `/accounts/${encodeURIComponent(member)}`, tenant);
  await button(relationship, '暂停成员').click(); let statusReview = dialog(p, '确认暂停成员');
  const suspended = await waitWrite(p, `/members/${encodeURIComponent(member)}/status`, () => button(statusReview, '确认暂停成员').click());
  assert.deepEqual(suspended.request().postDataJSON(), { status: 'suspended', expected_version: current.membership.version });
  await statusReview.waitFor({ state: 'hidden' });
  await relationship.locator('button.ant-drawer-close').click();
  md = await memberDrawer(p, user); assert.ok(await button(md, '分配业务角色').isDisabled());
  await md.locator('button.ant-drawer-close').click();
  await button(p, `管理成员关系 ${user}`).click(); relationship = dialog(p, '成员关系');
  await button(relationship, '恢复成员').click(); statusReview = dialog(p, '确认恢复成员');
  const restored = await waitWrite(p, `/members/${encodeURIComponent(member)}/status`, () => button(statusReview, '确认恢复成员').click());
  assert.equal(restored.request().postDataJSON().status, 'active');
  assert.ok(Number.isInteger(restored.request().postDataJSON().expected_version));
  await statusReview.waitFor({ state: 'hidden' }); await relationship.locator('button.ant-drawer-close').click();
  pass('suspend and restore use member versions and suspended members cannot receive grants');
  // A sole unremoved membership cannot be removed even when another administrator exists.
  await button(p, `管理成员关系 ${user}`).click(); relationship = dialog(p, '成员关系');
  await button(relationship, '移除成员').click(); statusReview = dialog(p, '确认移除成员');
  const lastMembership = p.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith(`/members/${encodeURIComponent(member)}/status`));
  await button(statusReview, '确认移除成员').click(); assert.equal((await lastMembership).status(), 409);
  await statusReview.waitFor({ state: 'hidden' }); await relationship.getByRole('alert').first().waitFor();
  assert.equal((await api(t, `/accounts/${encodeURIComponent(member)}`, tenant)).membership.status, 'active');
  pass('last unremoved membership returns real 409 and preserves membership');
  await accepting(p, () => button(relationship, '重新加载成员').click()); await p.waitForFunction(() => [...document.querySelectorAll('.ant-drawer button')].some(b => b.textContent.replace(/\s/g, '') === '暂停成员' && !b.disabled)); await relationship.locator('button.ant-drawer-close').click(); await relationship.waitFor({ state: 'hidden' });
  // Existing account binding enables removal from one tenant; rebinding must not restore grants.
  await goto(p, `#/tenants/${tenant2}/members`); await button(p, '绑定已有用户').click();
  let bind = dialog(p, '绑定已有用户'); await bind.getByLabel('用户邮箱', { exact: true }).fill(user);
  await button(bind, '搜索已有用户').click(); await button(bind, `选择用户 ${user}`).click();
  await button(bind, '核对并绑定').click(); let bindReview = dialog(p, '确认绑定成员');
  const bound = await waitWrite(p, `/members/${encodeURIComponent(member)}/bind`, () => button(bindReview, '确认绑定').click());
  assert.deepEqual(bound.request().postDataJSON(), {}); assert.equal(bound.request().headers()['x-embedded-idp-tenant-id'], tenant2);
  assert.equal((await api(t, `/accounts/${encodeURIComponent(member)}`, tenant2)).account_id, member);
  await bindReview.waitFor({ state: 'hidden' }); await accepting(p, () => bind.locator('button.ant-drawer-close').click()); await bind.waitFor({ state: 'hidden' });
  await goto(p, `#/tenants/${tenant}/members`); await button(p, `管理成员关系 ${user}`).click();
  relationship = dialog(p, '成员关系'); await button(relationship, '移除成员').click(); statusReview = dialog(p, '确认移除成员');
  const removed = await waitWrite(p, `/members/${encodeURIComponent(member)}/status`, () => button(statusReview, '确认移除成员').click());
  assert.equal(removed.request().postDataJSON().status, 'removed'); assert.ok(Number.isInteger(removed.request().postDataJSON().expected_version));
  await statusReview.waitFor({ state: 'hidden' }); await relationship.locator('button.ant-drawer-close').click();
  await button(p, '绑定已有用户').click(); bind = dialog(p, '绑定已有用户');
  await bind.getByLabel('用户邮箱', { exact: true }).fill(user); await button(bind, '搜索已有用户').click();
  await button(bind, `选择用户 ${user}`).click(); await button(bind, '核对并绑定').click(); bindReview = dialog(p, '确认绑定成员');
  await waitWrite(p, `/members/${encodeURIComponent(member)}/bind`, () => button(bindReview, '确认绑定').click());
  await bindReview.waitFor({ state: 'hidden' }); await accepting(p, () => bind.locator('button.ant-drawer-close').click()); await bind.waitFor({ state: 'hidden' });
  const afterRebind = await api(t, `/access/subjects/${encodeURIComponent(member)}/role-bindings?limit=50`, tenant, business);
  assert.equal(afterRebind.items.length, 0);
  pass('bind existing account, remove and rebind: same account, old bindings not restored');
  // Changing roles drops the entire resource draft, and a late previous detail is ignored.
  const alternate = await writeApi(t, 'POST', '/access/roles', { key: `other_${id}`, name: `UI D other ${id}` }, tenant, business);
  await goto(p, `#/tenants/${tenant}/members`); md = await memberDrawer(p, user);
  await chooseRole(p, md, roleName); await selectOption(p, md, '资源类型', 'report');
  await selectOption(p, md, '授权范围', '仅一个具体资源');
  await md.getByLabel('资源 ID', { exact: true }).fill(`draft-${id}`);
  await accepting(p, () => button(md, '重新选择角色').click()); await button(md, `选择角色 UI D other ${id}`).click();
  assert.equal(await md.getByLabel('资源 ID', { exact: true }).count(), 0);
  await accepting(p, () => button(md, '重新选择角色').click());
  const rolePath = `${t.host.origin}${t.host.mount}/admin/access/roles/${encodeURIComponent(alternate.role.role_id)}`;
  let roleSeen, roleDelivered;
  const roleGate = gate();
  const roleObserved = new Promise(r => { roleSeen = r; }), roleDone = new Promise(r => { roleDelivered = r; });
  await p.route(rolePath, async route => { const response = await route.fetch(), body = await response.json(); body.name = 'UI D stale role marker'; roleSeen(); await roleGate.promise; await route.fulfill({ response, json: body }); roleDelivered(); });
  await button(md, `选择角色 UI D other ${id}`).click(); await bounded(roleObserved, 'held role observed');
  await accepting(p, () => button(md, '重新选择角色').click()); await button(md, `选择角色 ${roleName}`).click();
  await md.getByLabel('资源类型', { exact: true }).waitFor(); roleGate.release(); await bounded(roleDone, 'held role delivered'); await p.unroute(rolePath);
  assert.equal(await md.getByText('UI D stale role marker', { exact: true }).count(), 0);
  assert.equal(await md.getByLabel('资源 ID', { exact: true }).count(), 0);
  await accepting(p, () => md.locator('button.ant-drawer-close').click());
  pass('role changes clear resource draft and held old-role detail cannot contaminate the new choice');
  // A cancelled business change keeps the original grant draft; an accepted change resets it.
  await goto(p, `#/tenants/${tenant}/members`); md = await memberDrawer(p, user);
  await chooseRole(p, md, roleName); await selectOption(p, md, '资源类型', 'report');
  await selectOption(p, md, '授权范围', '仅一个具体资源');
  const draftId = `filter-${id}`; await md.getByLabel('资源 ID', { exact: true }).fill(draftId);
  const nextBusiness = `next_${id}`; const filter = md.getByLabel('业务标识', { exact: true });
  await filter.fill(nextBusiness);
  const cancelFilter = p.waitForEvent('dialog'); await button(md, '查询').click(); await cancelFilter;
  assert.equal(await md.getByLabel('资源 ID', { exact: true }).inputValue(), draftId);
  assert.ok(await button(md, '重新选择角色').isVisible());
  const changedScope = p.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith(`/access/subjects/${encodeURIComponent(member)}/role-bindings`) && r.request().headers()['x-embedded-idp-business-id'] === nextBusiness);
  await accepting(p, () => button(md, '查询').click()); assert.ok((await changedScope).ok());
  assert.equal(await md.getByLabel('资源 ID', { exact: true }).count(), 0);
  assert.equal(await button(md, '重新选择角色').count(), 0);
  await filter.fill(business);
  const originalScope = p.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith(`/access/subjects/${encodeURIComponent(member)}/role-bindings`) && r.request().headers()['x-embedded-idp-business-id'] === business);
  await button(md, '查询').click(); assert.ok((await originalScope).ok());
  pass('cancelled business change retains resource draft; accepted change clears it and reads new business');
  // Execute one real grant, independently read its binding, and lose only its response.
  const bindingPath = `${t.host.origin}${t.host.mount}/admin/access/subjects/${encodeURIComponent(member)}/role-bindings`;
  const lostResource = `unknown-${id}`; let grantPosts = 0, observedBinding;
  await p.route(bindingPath, async route => {
    if (route.request().method() !== 'POST') return route.continue();
    grantPosts++; const response = await route.fetch(); assert.ok(response.ok());
    observedBinding = (await response.json()).binding;
    const request = route.request();
    const read = await p.request.get(`${bindingPath}?limit=50`, { headers: { authorization: request.headers().authorization,
      'x-embedded-idp-tenant-id': tenant, 'x-embedded-idp-business-id': business } });
    assert.ok(read.ok()); const original = await read.json();
    assert.ok(original.items.some(b => b.binding_id === observedBinding.binding_id));
    await route.abort('connectionfailed');
  });
  await chooseRole(p, md, roleName); await selectOption(p, md, '资源类型', 'report');
  await selectOption(p, md, '授权范围', '仅一个具体资源');
  await md.getByLabel('资源 ID', { exact: true }).fill(lostResource); await button(md, '预览授权').click();
  await button(dialog(p, '确认成员角色分配'), '确认分配').click();
  await md.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
  await p.unroute(bindingPath); assert.equal(grantPosts, 1); assert.ok(observedBinding?.binding_id);
  const contextText = await md.innerText();
  for (const value of [tenant, business, member, observedBinding.role_id]) assert.ok(contextText.includes(value));
  assert.ok(await filter.isDisabled());
  const memberRead = p.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith(`/accounts/${encodeURIComponent(member)}`));
  const resetBindings = p.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith(`/access/subjects/${encodeURIComponent(member)}/role-bindings`));
  await accepting(p, () => button(md, '重新加载分配').click()); assert.ok((await memberRead).ok()); assert.ok((await resetBindings).ok()); await settle(p);
  assert.ok(await filter.isDisabled()); assert.ok(await button(md, '分配业务角色').isDisabled());
  let failScope = true;
  await p.route(`${bindingPath}?*`, route => {
    if (route.request().method() === 'GET' && failScope) { failScope = false; return route.fulfill({ status: 503, body: '{}' }); }
    return route.continue();
  });
  await button(md, '读取原授权范围首页').click();
  await md.getByText('原成员或原业务授权读取失败，可重试当前页；写入仍锁定。', { exact: true }).waitFor();
  assert.ok(await filter.isDisabled()); assert.equal(await button(md, '结束授权核对').count(), 0);
  await p.unroute(`${bindingPath}?*`);
  let recoveryButton = button(md, '读取原授权范围首页');
  for (let page = 0; page < 100; page++) {
    const recoveryRead = p.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith(`/access/subjects/${encodeURIComponent(member)}/role-bindings`) && r.request().headers()['x-embedded-idp-business-id'] === business);
    await recoveryButton.click(); assert.ok((await recoveryRead).ok());
    await p.waitForFunction(() => [...document.querySelectorAll('[role="dialog"] button')].some(b => /结束授权核对|读取原授权下一页/.test(b.textContent) && !b.disabled));
    if (await button(md, '结束授权核对').isVisible()) break;
    recoveryButton = button(md, '读取原授权下一页');
    if (page === 99) throw new Error('Grant recovery exceeded 100 pages');
  }
  await button(md, '结束授权核对').click(); assert.ok(await filter.isEnabled()); assert.equal(grantPosts, 1);
  await accepting(p, () => md.locator('button.ant-drawer-close').click()); await md.waitFor({ state: 'hidden' });
  pass('lost real grant is locked through member read and injected scope failure until original-scope paginated recovery, without replay');
  // Edit and archive a separate synthetic permission with the server's current version.
  const archiveType = `archive_${id}`;
  await writeApi(t, 'POST', '/access/permissions', { resource_type: archiveType, action: 'read', description: 'UI D archive fixture' }, tenant, business);
  await goto(p, `#/tenants/${tenant}/directory`);
  let archiveRow = p.getByRole('row').filter({ hasText: `${archiveType}::read` });
  await button(archiveRow, '编辑').click(); const editPermission = dialog(p, '编辑权限');
  await editPermission.getByLabel('权限说明', { exact: true }).fill('UI D revised permission');
  await button(editPermission, '核对').click(); const editReview = dialog(p, '确认编辑权限');
  const patchPermission = p.waitForResponse(r => r.request().method() === 'PATCH' && new URL(r.url()).pathname.endsWith(`/access/permissions/${archiveType}/read`));
  await button(editReview, '确认').click(); const patchedPermission = await patchPermission; assert.ok(patchedPermission.ok());
  assert.ok(Number.isInteger(patchedPermission.request().postDataJSON().expected_version));
  await editPermission.waitFor({ state: 'hidden' });
  const editedPermission = await api(t, `/access/permissions/${archiveType}/read`, tenant, business);
  assert.equal(editedPermission.description, 'UI D revised permission');
  for (const [buttonLabel, desired] of [['停用', false], ['启用', true]]) {
    archiveRow = p.getByRole('row').filter({ hasText: `${archiveType}::read` });
    await button(archiveRow, buttonLabel).click();
    const toggleReview = dialog(p, '确认更改权限状态');
    const toggled = await waitWrite(p, `/access/permissions/${archiveType}/read/enabled`, () => button(toggleReview, '确认').click());
    assert.deepEqual(toggled.request().postDataJSON(), { enabled: desired, expected_enabled: !desired });
    assert.equal(toggled.request().headers()['x-embedded-idp-tenant-id'], tenant);
    assert.equal(toggled.request().headers()['x-embedded-idp-business-id'], business);
    assert.equal((await api(t, `/access/permissions/${archiveType}/read`, tenant, business)).enabled, desired);
    await toggleReview.waitFor({ state: 'hidden' });
  }
  const beforeArchive = await api(t, `/access/permissions/${archiveType}/read`, tenant, business);
  pass('permission disable and enable use expected_enabled and read back current state');
  archiveRow = p.getByRole('row').filter({ hasText: `${archiveType}::read` }); await button(archiveRow, '归档').click();
  const archiveResponse = p.waitForResponse(r => r.request().method() === 'DELETE' && new URL(r.url()).pathname.endsWith(`/access/permissions/${archiveType}/read`));
  await button(dialog(p, '确认归档权限'), '确认').click(); const archivedResponse = await archiveResponse;
  assert.ok(archivedResponse.ok()); assert.equal(archivedResponse.request().postDataJSON().expected_version, beforeArchive.version);
  const archivedPermission = await api(t, `/access/permissions/${archiveType}/read`, tenant, business);
  assert.equal(archivedPermission.archived, true);
  await archiveRow.getByText('不可更改', { exact: true }).waitFor();
  pass('permission edit and archive send current versions and archived permission is immutable');
  // Delete a separate unused role and verify its original ID is no longer readable.
  await goto(p, `#/tenants/${tenant}/roles`);
  await button(p, `查看角色 UI D other ${id}`).click(); const deleteDetail = dialog(p, '角色详情');
  await button(deleteDetail, '删除角色').click(); const deleteReview = dialog(p, '确认删除角色');
  const roleDelete = p.waitForResponse(r => r.request().method() === 'DELETE' && new URL(r.url()).pathname.endsWith(`/access/roles/${encodeURIComponent(alternate.role.role_id)}`));
  await button(deleteReview, '确认删除').click(); const roleDeleted = await roleDelete; assert.ok(roleDeleted.ok());
  assert.ok(Number.isInteger(roleDeleted.request().postDataJSON().expected_version));
  const gone = await p.request.get(`${t.host.origin}${t.host.mount}/admin/access/roles/${encodeURIComponent(alternate.role.role_id)}`, { headers: { authorization: t.bearer(), 'x-embedded-idp-tenant-id': tenant, 'x-embedded-idp-business-id': business } });
  assert.equal(gone.status(), 404); await deleteDetail.waitFor({ state: 'hidden' });
  pass('unused role deletion is confirmed and original role ID reads 404');
  // Protected IDP roles are visible but never offered through normal business mutation.
  await goto(p, `#/tenants/${tenant}/roles`);
  const protectedRoles = await api(t, '/access/roles?limit=50', tenant, 'idp');
  const protectedRole = protectedRoles.items.find(r => r.kind === 'tenant_security_admin');
  assert.ok(protectedRole);
  await button(p, `查看角色 ${protectedRole.name}`).click(); const protectedDetail = dialog(p, '角色详情');
  assert.equal(await button(protectedDetail, '编辑权限集').count(), 0);
  assert.equal(await button(protectedDetail, '删除角色').count(), 0);
  await protectedDetail.locator('button.ant-drawer-close').click();
  // A disabled business role cannot be selected for a fresh grant.
  const roles = await api(t, '/access/roles?limit=50', tenant, business);
  const ordinaryRole = roles.items.find(r => r.name === roleName); assert.ok(ordinaryRole);
  const roleDetail = await api(t, `/access/roles/${encodeURIComponent(ordinaryRole.role_id)}`, tenant, business);
  await writeApi(t, 'PATCH', `/access/roles/${encodeURIComponent(ordinaryRole.role_id)}`, { name: roleName, status: 'disabled', expected_version: roleDetail.version }, tenant, business);
  await goto(p, `#/tenants/${tenant}/members`); md = await memberDrawer(p, user);
  await button(md, '分配业务角色').click();
  assert.ok(await button(md, `选择角色 ${roleName}`).isDisabled());
  await accepting(p, () => md.locator('button.ant-drawer-close').click());
  pass('protected role is read-only and disabled ordinary role cannot be granted');
  if (!functionalOnly) {
  for (const width of [320, 390, 768, 1440]) {
    await p.setViewportSize({ width, height: 900 });
    const duplicate = await p.evaluate(() => { const ids = [...document.querySelectorAll('[id]')].map(x => x.id).filter(Boolean); return ids.length !== new Set(ids).size; });
    assert.equal(duplicate, false, `duplicate IDs at ${width}`);
    assert.ok(await p.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `page overflow at ${width}`);
    if (!functionalOnly) await p.screenshot({ path: `${output}/ui-d-${width}.png`, animations: 'disabled', mask: [p.locator('input, textarea, [contenteditable=true]')] });
  }
  pass('320, 390, 768 and 1440 widths: unique IDs and no document horizontal overflow');
  }
  const disabled = await open('disabled', '#/system/members'); const dp = disabled.page;
  assert.equal(await button(dp, '绑定已有用户').count(), 0);
  assert.equal(await button(dp, '创建租户').count(), 0);
  const disabledUser = `uid-disabled-${id}@example.test`;
  const disabledSubject = await createUser(disabled, '0', disabledUser);
  await createPermission(disabled, '0'); await createRole(disabled, '0');
  await button(dp, `查看角色 ${roleName}`).click(); const disabledDetail = dialog(dp, '角色详情');
  await button(disabledDetail, '编辑权限集').click(); const disabledEditor = dialog(dp, `编辑角色权限：${roleName}`);
  await button(disabledEditor.getByRole('row').filter({ hasText: 'report::read' }), '添加').click();
  await button(disabledEditor, '核对权限集').click(); const disabledReview = dialog(dp, '确认替换角色权限集');
  const disabledPut = dp.waitForResponse(r => r.request().method() === 'PUT' && new URL(r.url()).pathname.endsWith('/permissions'));
  await button(disabledReview, '确认保存权限').click(); assert.ok((await disabledPut).ok());
  await disabledEditor.waitFor({ state: 'hidden' }); await disabledDetail.locator('button.ant-drawer-close').click();
  await goto(dp, '#/system/members'); const disabledDrawer = await memberDrawer(dp, disabledUser);
  const disabledBinding = await grant(disabled, disabledDrawer, '0', disabledSubject, roleName, 'instance', `disabled-${id}`);
  assert.ok(disabledBinding.binding_id);
  pass('Disabled system creates permission, role and member and grants instance without tenant or bind entry');
  const fixed = await open('fixed', '#/tenants/tenant-a/members', 'tenant-a@example.test'); const fp = fixed.page;
  assert.equal(await button(fp, '新建用户').count(), 0); assert.equal(await button(fp, '绑定已有用户').count(), 0);
  assert.equal(await fp.getByRole('button', { name: /^管理管理员授权 / }).count(), 0);
  assert.equal(await fp.getByRole('button', { name: /^管理账号安全 / }).count(), 0);
  assert.equal(await button(fp, '更换管理目标').count(), 0);
  await goto(fp, '#/tenants/tenant-b/members'); await fp.getByText('无权访问', { exact: true }).first().waitFor();
  pass('Fixed nonzero excludes platform operations and rejects another target');
  // Choose begins with an authenticated selection ticket, before a shell exists.
  const ch = fixture.hosts.choose; const chooseContext = await browser.newContext(); contexts.push(chooseContext);
  const cp = await chooseContext.newPage(); cp.setDefaultTimeout(15000); cp.on('pageerror', e => pageErrors.push(e.name));
  let chooseBearer; cp.on('request', r => { if (r.headers().authorization?.startsWith('Bearer ')) chooseBearer = r.headers().authorization; });
  await cp.goto(`${ch.origin}${ch.ui}/#/`); await cp.getByLabel('邮箱', { exact: true }).fill('tenant-a@example.test');
  await cp.getByLabel('密码', { exact: true }).fill(fixture.password); await cp.getByRole('button', { name: /^登\s*录$/ }).click();
  await button(cp, '进入 UI B tenant-a').click(); await cp.locator('.management-shell').waitFor();
  const chooseTest = { page: cp, host: ch, bearer: () => chooseBearer }; const chooseSession = await api(chooseTest, '/auth/session');
  await button(cp, '切换登录租户').click(); await button(cp, '取消切换，返回当前会话').click();
  assert.deepEqual(await api(chooseTest, '/auth/session'), chooseSession);
  assert.equal(await button(cp, '新建用户').count(), 0); assert.equal(await button(cp, '更换管理目标').count(), 0);
  pass('Choose cancellation preserves source session and excludes platform target selection');
  // Read failure variants are injected at the HTTP boundary, one response at a time.
  await goto(p, `#/tenants/${tenant}/directory`);
  const reads = `${t.host.origin}${t.host.mount}/admin/access/permissions?*`;
  for (const [label, status, body] of [['403', 403, {}], ['malformed', 200, { items: 'invalid' }], ['empty', 200, { items: [], has_more: false, next_cursor: null }]]) {
    await p.route(reads, route => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) }));
    await button(p, '刷新目录').click();
    if (label === '403') await p.getByText('无权读取此管理范围', { exact: true }).waitFor();
    else if (label === 'malformed') await p.getByText('读取失败', { exact: true }).waitFor();
    else await p.getByText('没有符合条件的权限', { exact: true }).waitFor();
    await p.unroute(reads);
  }
  await button(p, '刷新目录').click(); await settle(p);
  pass('explicit injected empty, 403 and malformed permission reads have distinct states');
  // Unknown result: execute the real POST, read the original object, then abort only its response.
  const unknownResource = `lost_${id}`; const postPath = `${t.host.origin}${t.host.mount}/admin/access/permissions`;
  let writes = 0, persisted = false;
  await p.route(postPath, async route => {
    if (route.request().method() !== 'POST') return route.continue();
    writes++; const response = await route.fetch(); assert.ok(response.ok());
    const read = await p.request.get(`${postPath}/${unknownResource}/read`, { headers: {
      authorization: route.request().headers().authorization, 'x-embedded-idp-tenant-id': tenant, 'x-embedded-idp-business-id': business,
    } }); assert.ok(read.ok()); persisted = true; await route.abort('connectionfailed');
  });
  await button(p, '创建权限').click(); let lostForm = dialog(p, '创建权限');
  await lostForm.getByLabel('业务标识', { exact: true }).fill(business);
  await lostForm.getByLabel('资源类型', { exact: true }).fill(unknownResource);
  await lostForm.getByLabel('动作', { exact: true }).fill('read');
  await lostForm.getByLabel('权限说明', { exact: true }).fill('UI D lost response');
  await button(lostForm, '核对').click(); let lostReview = dialog(p, '确认创建权限');
  await button(lostReview, '确认').click(); await p.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).first().waitFor();
  assert.ok(persisted); assert.equal(writes, 1); await p.unroute(postPath);
  await recoverDirectory(p, lostForm);
  assert.equal(writes, 1);
  pass('real committed POST with injected lost response requires original-scope read and does not replay');
  // A confirmed response followed by injected read failure retains the success state.
  let failRead = false; await p.route(reads, route => failRead ? route.fulfill({ status: 503, body: '{}' }) : route.continue());
  await p.route(postPath, async route => { if (route.request().method() !== 'POST') return route.continue(); const response = await route.fetch(); failRead = true; await route.fulfill({ response }); });
  await button(p, '创建权限').click(); const savedForm = dialog(p, '创建权限');
  await savedForm.getByLabel('业务标识', { exact: true }).fill(business);
  await savedForm.getByLabel('资源类型', { exact: true }).fill(`saved_${id}`);
  await savedForm.getByLabel('动作', { exact: true }).fill('read');
  await savedForm.getByLabel('权限说明', { exact: true }).fill('UI D confirmed write');
  await button(savedForm, '核对').click(); await button(dialog(p, '确认创建权限'), '确认').click();
  await p.getByText('写入已确认，重新读取失败', { exact: true }).waitFor();
  await p.unroute(postPath); await p.unroute(reads);
  pass('real successful POST followed by injected failed read remains confirmed saved');
  // Server rejection is injected and must require rereading rather than retrying.
  await button(p, '刷新目录').click(); await settle(p);
  let conflictWrites = 0;
  await p.route(postPath, route => { if (route.request().method() !== 'POST') return route.continue(); conflictWrites++; return route.fulfill({ status: 409, body: '{}' }); });
  await button(p, '创建权限').click(); const conflictForm = dialog(p, '创建权限');
  await conflictForm.getByLabel('业务标识', { exact: true }).fill(business);
  await conflictForm.getByLabel('资源类型', { exact: true }).fill(`conflict_${id}`);
  await conflictForm.getByLabel('动作', { exact: true }).fill('read');
  await conflictForm.getByLabel('权限说明', { exact: true }).fill('UI D injected conflict');
  await button(conflictForm, '核对').click(); await button(dialog(p, '确认创建权限'), '确认').click();
  await button(conflictForm, '读取原权限范围首页').waitFor(); assert.equal(conflictWrites, 1);
  await p.unroute(postPath); await recoverDirectory(p, conflictForm);
  pass('injected 409 blocks duplicate mutation until original permission scope is reread');
  // Delay a real old-target response; it must not populate the newly selected tenant.
  const late = await open('enabled', '#/tenants/tenant-b/roles'); const lp = late.page;
  let seen, delivered; const targetGate = gate();
  const observed = new Promise(r => { seen = r; }), done = new Promise(r => { delivered = r; });
  const oldPath = `${late.host.origin}${late.host.mount}/admin/accounts?*`;
  await lp.route(oldPath, async route => {
    if (route.request().headers()['x-embedded-idp-tenant-id'] !== 'tenant-a') return route.continue();
    const response = await route.fetch(), body = await response.json();
    for (const item of body.items) item.display_name = 'UI D old target marker';
    seen(); await targetGate.promise; await route.fulfill({ response, json: body }); delivered();
  });
  await lp.evaluate(() => { location.hash = '#/tenants/tenant-a/members'; }); await bounded(observed, 'held target observed');
  await goto(lp, '#/tenants/tenant-b/members'); targetGate.release(); await bounded(done, 'held target delivered'); await lp.unroute(oldPath); await settle(lp);
  assert.equal(await lp.getByText('UI D old target marker', { exact: true }).count(), 0);
  assert.ok((await lp.locator('.management-target').innerText()).includes('tenant-b'));
  pass('held real old-target read cannot contaminate new target');
  // Same-session real logout in another tab invalidates an outstanding real read.
  let seenSession, deliveredSession;
  const sessionGate = gate();
  const sessionSeen = new Promise(r => { seenSession = r; }), sessionDone = new Promise(r => { deliveredSession = r; });
  await lp.route(oldPath, async route => { const response = await route.fetch(); seenSession(); await sessionGate.promise; await route.fulfill({ response }); deliveredSession(); });
  await button(lp, '刷新成员').click(); await bounded(sessionSeen, 'held session observed');
  const tab = await late.context.newPage(); tab.on('pageerror', e => pageErrors.push(e.name));
  await tab.goto(`${late.host.origin}${late.host.ui}/#/tenants/tenant-b/home`); await tab.locator('.management-shell').waitFor();
  const logout = tab.waitForResponse(r => r.url() === `${late.host.origin}${late.host.mount}/admin/auth/browser/logout`);
  await button(tab, '退出登录').click(); assert.equal((await logout).status(), 204);
  await lp.getByText('其他页面已更改此会话，请重新加载后继续。', { exact: true }).waitFor();
  sessionGate.release(); await bounded(sessionDone, 'held session delivered'); await lp.unroute(oldPath);
  assert.equal(await lp.locator('.management-shell').count(), 0);
  pass('cross-tab real logout discards a held real response without restoring the workspace');
  // Browser hash and history navigation retain drafts; a covered DOM click probes the pending guard.
  const guard = await open('enabled', '#/tenants/tenant-b/roles'); const gp = guard.page;
  await goto(gp, '#/tenants/tenant-b/members'); await goto(gp, '#/tenants/tenant-b/roles');
  await button(gp, '新建角色').click(); const guardForm = dialog(gp, '新建业务角色');
  await guardForm.getByLabel('业务标识', { exact: true }).fill(business);
  await guardForm.getByLabel('角色标识', { exact: true }).fill(`guard_${id}`);
  await guardForm.getByLabel('角色名称', { exact: true }).fill('UI D guarded draft');
  const draftDialog = gp.waitForEvent('dialog');
  await gp.evaluate(() => { location.hash = '#/tenants/tenant-a/members'; }); await draftDialog;
  await gp.waitForURL('**/#/tenants/tenant-b/roles');
  assert.equal(await guardForm.getByLabel('角色名称', { exact: true }).inputValue(), 'UI D guarded draft');
  // Rejected unmarked hash leaves an equivalent history entry; crossing it needs no prompt.
  await gp.goBack(); await gp.waitForURL('**/#/tenants/tenant-b/roles');
  assert.equal(await guardForm.getByLabel('角色名称', { exact: true }).inputValue(), 'UI D guarded draft');
  const backDialog = gp.waitForEvent('dialog'); await gp.goBack(); await backDialog;
  await gp.waitForURL('**/#/tenants/tenant-b/roles');
  assert.equal(await guardForm.getByLabel('角色名称', { exact: true }).inputValue(), 'UI D guarded draft');
  await button(guardForm, '创建角色').click(); const guardReview = dialog(gp, '确认创建角色');
  let guardSeen; const guardGate = gate();
  const guardObserved = new Promise(r => { guardSeen = r; }); let guardPosts = 0;
  const guardPath = `${guard.host.origin}${guard.host.mount}/admin/access/roles`;
  await gp.route(guardPath, async route => { if (route.request().method() !== 'POST') return route.continue(); guardPosts++; guardSeen(); await guardGate.promise; await route.continue(); });
  await button(guardReview, '确认创建').click(); await bounded(guardObserved, 'held mutation observed');
  for (const action of [() => gp.evaluate(() => { location.hash = '#/tenants/tenant-a/members'; }),
    () => gp.locator('.management-sidebar').getByRole('menuitem', { name: '成员管理', exact: true }).dispatchEvent('click')]) {
    const blocked = gp.waitForEvent('dialog'); await action(); await blocked;
    await gp.waitForURL('**/#/tenants/tenant-b/roles');
  }
  const guardResponse = gp.waitForResponse(r => r.url() === guardPath && r.request().method() === 'POST');
  guardGate.release(); assert.ok((await guardResponse).ok()); await gp.unroute(guardPath); assert.equal(guardPosts, 1);
  pass('real hash and history draft cancellation and covered DOM pending navigation retain target without replay');
  // Seed only this run's separate business, then exercise the server's real role cursor through the drawer.
  const cursorBusiness = `cursor_${id}`;
  for (let start = 0; start < 52; start += 8) {
    await Promise.all(Array.from({ length: Math.min(8, 52 - start) }, (_, offset) => {
      const n = String(start + offset).padStart(2, '0');
      return writeApi(t, 'POST', '/access/roles', { key: `cursor_${n}`, name: `UI D cursor ${n}` }, tenant, cursorBusiness);
    }));
  }
  const cursorTest = await open('enabled', `#/tenants/${tenant}/members`); const cursorPage = cursorTest.page;
  const cursorDrawer = await memberDrawer(cursorPage, user);
  await cursorDrawer.getByLabel('业务标识', { exact: true }).fill(cursorBusiness);
  await button(cursorDrawer, '查询').click();
  const firstRoles = cursorPage.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith('/access/roles') && r.request().headers()['x-embedded-idp-business-id'] === cursorBusiness);
  await button(cursorDrawer, '分配业务角色').click();
  const firstResponse = await firstRoles, firstRequest = firstResponse.request(), firstPage = await firstResponse.json();
  assert.ok(firstResponse.ok()); assert.equal(firstRequest.headers()['x-embedded-idp-tenant-id'], tenant);
  assert.equal(firstRequest.headers()['x-embedded-idp-business-id'], cursorBusiness);
  assert.equal(new URL(firstRequest.url()).searchParams.has('cursor'), false);
  assert.equal(firstPage.items.length, 50); assert.equal(firstPage.has_more, true); assert.ok(firstPage.next_cursor);
  await cursorPage.waitForFunction(expected => document.querySelectorAll('button[aria-label^="选择角色 UI D cursor " ]').length === expected, 50);
  assert.equal(await cursorDrawer.getByRole('button', { name: /^选择角色 UI D cursor / }).count(), 50);
  const nextRoles = cursorPage.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith('/access/roles') && new URL(r.url()).searchParams.has('cursor'));
  await button(cursorDrawer, '下一页').click(); const nextResponse = await nextRoles;
  const nextRequest = nextResponse.request(), nextPage = await nextResponse.json(); assert.ok(nextResponse.ok());
  assert.equal(nextRequest.headers()['x-embedded-idp-tenant-id'], tenant);
  assert.equal(nextRequest.headers()['x-embedded-idp-business-id'], cursorBusiness);
  assert.equal(new URL(nextRequest.url()).searchParams.get('cursor'), firstPage.next_cursor);
  assert.equal(nextPage.items.length, 2); assert.equal(nextPage.has_more, false);
  await cursorDrawer.getByText('第 2 页', { exact: true }).waitFor();
  await cursorPage.waitForFunction(expected => document.querySelectorAll('button[aria-label^="选择角色 UI D cursor " ]').length === expected, 2);
  assert.equal(await cursorDrawer.getByRole('button', { name: /^选择角色 UI D cursor / }).count(), 2);
  await accepting(cursorPage, () => button(cursorDrawer, '查询').click());
  const resetRoles = cursorPage.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith('/access/roles') && r.request().headers()['x-embedded-idp-business-id'] === cursorBusiness);
  await button(cursorDrawer, '分配业务角色').click(); const resetResponse = await resetRoles;
  assert.ok(resetResponse.ok()); assert.equal(new URL(resetResponse.url()).searchParams.has('cursor'), false);
  assert.equal(resetResponse.request().headers()['x-embedded-idp-tenant-id'], tenant);
  assert.equal((await resetResponse.json()).items.length, 50);
  await cursorDrawer.getByText('第 1 页', { exact: true }).waitFor();
  await accepting(cursorPage, () => cursorDrawer.locator('button.ant-drawer-close').click());
  pass('role chooser uses real 50 plus 2 cursor pages and same-business query resets cursor');
  // Hold the real committed business-admin grant until a second tab logs out the same session.
  const lateWrite = await open('enabled', `#/tenants/${tenant}/members`);
  const wp = lateWrite.page, writeIdentity = await api(lateWrite, '/auth/session');
  const writeDrawer = await memberDrawer(wp, user);
  await writeDrawer.getByLabel('业务标识', { exact: true }).fill(business);
  const writeScopeRead = wp.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith(`/access/subjects/${encodeURIComponent(member)}/role-bindings`) && r.request().headers()['x-embedded-idp-business-id'] === business);
  await button(writeDrawer, '查询').click(); assert.ok((await writeScopeRead).ok());
  await chooseRole(wp, writeDrawer, adminName);
  await button(writeDrawer, '预览业务管理员授权').click();
  const writeReview = dialog(wp, '确认业务管理员授权');
  const lateWritePath = `${lateWrite.host.origin}${lateWrite.host.mount}/admin/access/subjects/${encodeURIComponent(member)}/role-bindings`;
  const writeGate = gate(); let writeSeen, writeDelivered, writeError, latePosts = 0, wasDelivered = false;
  const writeObserved = new Promise(resolve => { writeSeen = resolve; });
  const writeDone = new Promise(resolve => { writeDelivered = resolve; });
  await wp.route(lateWritePath, async route => {
    if (route.request().method() !== 'POST') return route.continue();
    try {
      latePosts++; const response = await route.fetch(); assert.ok(response.ok());
      const binding = (await response.json()).binding;
      assert.equal(binding.scope.kind, 'business');
      const request = route.request(); assert.equal(request.headers()['x-embedded-idp-tenant-id'], tenant);
      assert.equal(request.headers()['x-embedded-idp-business-id'], business);
      const body = request.postDataJSON(); assert.deepEqual(body.scope, { kind: 'business' });
      assert.ok(!Object.hasOwn(body, 'resource_type'));
      const read = await wp.request.get(`${lateWritePath}?limit=50`, { headers: {
        authorization: request.headers().authorization, 'x-embedded-idp-tenant-id': tenant, 'x-embedded-idp-business-id': business,
      } });
      assert.ok(read.ok()); assert.ok((await read.json()).items.some(item => item.binding_id === binding.binding_id));
      writeSeen(); await writeGate.promise; await route.fulfill({ response });
    } catch (error) { writeError = error; writeSeen(); }
    finally { wasDelivered = true; writeDelivered(); }
  });
  await button(writeReview, '确认授予业务权限').click(); await bounded(writeObserved, 'real grant received');
  if (writeError) throw writeError;
  assert.equal(latePosts, 1);
  const writeTab = await lateWrite.context.newPage(); writeTab.setDefaultTimeout(15000);
  writeTab.on('pageerror', error => pageErrors.push(error.name));
  const restoredSession = writeTab.waitForResponse(r => r.url() === `${lateWrite.host.origin}${lateWrite.host.mount}/admin/auth/session` && r.request().method() === 'GET');
  await writeTab.goto(`${lateWrite.host.origin}${lateWrite.host.ui}/#/tenants/${tenant}/home`);
  await writeTab.locator('.management-shell').waitFor();
  const restoredResponse = await restoredSession; assert.ok(restoredResponse.ok());
  assert.deepEqual(await restoredResponse.json(), writeIdentity);
  assert.equal(wasDelivered, false);
  const actualLogout = writeTab.waitForResponse(r => r.url() === `${lateWrite.host.origin}${lateWrite.host.mount}/admin/auth/browser/logout`);
  await button(writeTab, '退出登录').click(); assert.equal((await actualLogout).status(), 204);
  await wp.getByText('其他页面已更改此会话，请重新加载后继续。', { exact: true }).waitFor();
  assert.equal(await wp.locator('.management-shell').count(), 0);
  assert.equal(await writeDrawer.count(), 0); assert.equal(await writeReview.count(), 0); assert.equal(wasDelivered, false);
  const deliveredResponse = wp.waitForResponse(r => r.url() === lateWritePath && r.request().method() === 'POST');
  writeGate.release(); await bounded(writeDone, 'real grant response delivered'); if (writeError) throw writeError;
  const lateResponse = await deliveredResponse; assert.equal(await lateResponse.finished(), null);
  await wp.unroute(lateWritePath);
  await wp.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await wp.locator('.management-shell').count(), 0);
  assert.equal(await writeDrawer.count(), 0); assert.equal(await writeReview.count(), 0);
  assert.equal(await wp.getByText(/已确认分配/).count(), 0); assert.equal(latePosts, 1);
  pass('held real successful business-admin grant arrives after cross-tab real logout without restoring workspace or replay');
  const unauthorized = await open('enabled', '#/tenants/tenant-a/directory');
  const up = unauthorized.page, unauthorizedRead = `${unauthorized.host.origin}${unauthorized.host.mount}/admin/access/permissions?*`;
  await up.route(unauthorizedRead, route => route.fulfill({ status: 401, body: '{}' }));
  await button(up, '刷新目录').click(); await up.getByLabel('密码', { exact: true }).waitFor();
  assert.equal(await up.locator('.management-shell').count(), 0);
  pass('injected ordinary 401 clears workspace and returns to login');

  // Fresh contexts isolate these recovery regressions from the original 34 groups.
  {
  const bindingCase = await open('enabled', `#/tenants/${tenant2}/members`);
  const bp = bindingCase.page, bindingUser = `uid-bind-race-${id}@example.test`;
  const bindingSubject = await createUser(bindingCase, tenant2, bindingUser);
  await goto(bp, `#/tenants/${tenant}/members`);
  await button(bp, '绑定已有用户').click();
  const bindingDrawer = dialog(bp, '绑定已有用户');
  await bindingDrawer.getByLabel('用户邮箱', { exact: true }).fill(bindingUser);
  await button(bindingDrawer, '搜索已有用户').click();
  await button(bindingDrawer, `选择用户 ${bindingUser}`).click();
  const memberPath = `${bindingCase.host.origin}${bindingCase.host.mount}/admin/accounts/${encodeURIComponent(bindingSubject)}`;
  const bindPath = `${bindingCase.host.origin}${bindingCase.host.mount}/admin/members/${encodeURIComponent(bindingSubject)}/bind`;
  let bindPosts = 0, bindPersisted = false, readSeen;
  const readGate = gate(), readObserved = new Promise(resolve => { readSeen = resolve; });
  let readError;
  try {
    await bp.route(memberPath, async route => {
      if (route.request().method() !== 'GET') return route.continue();
      try { readSeen(); await readGate.promise; await route.continue(); } catch (error) { readError = error; }
    });
    await bp.route(bindPath, async route => {
      if (route.request().method() !== 'POST') return route.continue();
      bindPosts++;
      assert.equal(route.request().headers()['x-embedded-idp-tenant-id'], tenant);
      const response = await route.fetch(); assert.ok(response.ok());
      const check = await bp.request.get(memberPath, { headers: { authorization: route.request().headers().authorization, 'x-embedded-idp-tenant-id': tenant } });
      assert.ok(check.ok()); assert.equal((await check.json()).account_id, bindingSubject);
      bindPersisted = true; await route.abort('connectionfailed');
    });
    await button(bindingDrawer, '重新读取原成员').click(); await bounded(readObserved, 'held pre-bind member read');
    assert.ok(await button(bindingDrawer, '核对并绑定').isDisabled());
    assert.equal(await dialog(bp, '确认绑定成员').count(), 0); assert.equal(bindPosts, 0);
    const readComplete = bp.waitForResponse(r => r.url() === memberPath && r.request().method() === 'GET');
    readGate.release(); await bounded(readComplete, 'pre-bind member read complete');
    await bp.unroute(memberPath); if (readError) throw readError;
    await button(bindingDrawer, '核对并绑定').click();
    await button(dialog(bp, '确认绑定成员'), '确认绑定').click();
    await bindingDrawer.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
    assert.ok(bindPersisted); assert.equal(bindPosts, 1);
    assert.ok(await button(bindingDrawer, '核对并绑定').isDisabled());
    const originalRead = bp.waitForResponse(r => r.url() === memberPath && r.request().method() === 'GET');
    await button(bindingDrawer, '重新读取原成员').click();
    const read = await originalRead; assert.ok(read.ok());
    assert.equal(read.request().headers()['x-embedded-idp-tenant-id'], tenant);
    await bindingDrawer.getByText(/当前成员关系：有效/).waitFor();
    assert.ok(await button(bindingDrawer, '核对并绑定').isEnabled()); assert.equal(bindPosts, 1);
  } finally { readGate.release(); await bp.unroute(memberPath); await bp.unroute(bindPath); }
  pass('binding blocks writes during old read and requires a fresh original member read after lost response');

  const scopeCase = await open('enabled', `#/tenants/${tenant}/members`);
  const sp = scopeCase.page, scopeName = `UI D reordered ${id}`, scopeResource = `reordered-${id}`;
  const scopeRole = (await writeApi(scopeCase, 'POST', '/access/roles', { key: `scope_${id}`, name: scopeName }, tenant, business)).role;
  await writeApi(scopeCase, 'PUT', `/access/roles/${encodeURIComponent(scopeRole.role_id)}/permissions`, {
    permissions: [{ resource_type: 'report', action: 'read' }], expected_version: scopeRole.version,
  }, tenant, business);
  const scopeDrawer = await memberDrawer(sp, user);
  const scopePath = `${scopeCase.host.origin}${scopeCase.host.mount}/admin/access/subjects/${encodeURIComponent(member)}/role-bindings`;
  let scopePosts = 0, scopeBinding;
  try {
    await sp.route(scopePath, async route => {
      if (route.request().method() !== 'POST') return route.continue();
      scopePosts++; const response = await route.fetch(); assert.ok(response.ok()); scopeBinding = (await response.json()).binding;
      const check = await sp.request.get(`${scopePath}?limit=50`, { headers: { authorization: route.request().headers().authorization,
        'x-embedded-idp-tenant-id': tenant, 'x-embedded-idp-business-id': business } });
      assert.ok(check.ok()); assert.ok((await check.json()).items.some(item => item.binding_id === scopeBinding.binding_id));
      await route.abort('connectionfailed');
    });
    await chooseRole(sp, scopeDrawer, scopeName); await selectOption(sp, scopeDrawer, '资源类型', 'report');
    await selectOption(sp, scopeDrawer, '授权范围', '仅一个具体资源');
    await scopeDrawer.getByLabel('资源 ID', { exact: true }).fill(scopeResource);
    await button(scopeDrawer, '预览授权').click(); await button(dialog(sp, '确认成员角色分配'), '确认分配').click();
    await scopeDrawer.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
    await sp.unroute(scopePath);
    await sp.route(`${scopePath}?*`, async route => {
      if (route.request().method() !== 'GET') return route.continue();
      const response = await route.fetch(); assert.ok(response.ok()); const body = await response.json();
      for (const item of body.items) if (item.binding_id === scopeBinding.binding_id)
        item.scope = { resource_id: scopeResource, kind: 'instance', extra: 'compatible' };
      await route.fulfill({ response, json: body });
    });
    await button(scopeDrawer, '读取原授权范围首页').click();
    await scopeDrawer.getByText(new RegExp(`原授权当前存在，绑定 ID：${scopeBinding.binding_id}`)).waitFor();
    await scopeDrawer.getByText(/不能据此确认请求归因/).waitFor();
    assert.equal(await scopeDrawer.getByText(/已读取至末页，未找到原授权/).count(), 0);
    assert.ok(await button(scopeDrawer, '结束授权核对').isVisible()); assert.equal(scopePosts, 1);
  } finally { await sp.unroute(scopePath); await sp.unroute(`${scopePath}?*`); }
  pass('lost grant recovery matches reordered and extended instance scope by value');

  const directoryCase = await open('enabled', `#/tenants/${tenant}/directory`);
  const dp = directoryCase.page, directoryResource = `close_${id}`;
  const directoryPath = `${directoryCase.host.origin}${directoryCase.host.mount}/admin/access/permissions`;
  let directoryPosts = 0, directoryPersisted = false, failStatus = 403;
  try {
    await dp.route(directoryPath, async route => {
      if (route.request().method() !== 'POST') return route.continue();
      directoryPosts++; const response = await route.fetch(); assert.ok(response.ok());
      const check = await dp.request.get(`${directoryPath}/${directoryResource}/read`, { headers: { authorization: route.request().headers().authorization,
        'x-embedded-idp-tenant-id': tenant, 'x-embedded-idp-business-id': business } });
      assert.ok(check.ok()); directoryPersisted = true; await route.abort('connectionfailed');
    });
    await button(dp, '创建权限').click(); const directoryForm = dialog(dp, '创建权限');
    await directoryForm.getByLabel('业务标识', { exact: true }).fill(business);
    await directoryForm.getByLabel('资源类型', { exact: true }).fill(directoryResource);
    await directoryForm.getByLabel('动作', { exact: true }).fill('read');
    await directoryForm.getByLabel('权限说明', { exact: true }).fill('UI D recovery close');
    await button(directoryForm, '核对').click(); await button(dialog(dp, '确认创建权限'), '确认').click();
    await directoryForm.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
    assert.ok(directoryPersisted); assert.equal(directoryPosts, 1); await dp.unroute(directoryPath);
    await dp.route(`${directoryPath}?*`, route => route.fulfill({ status: failStatus, body: '{}' }));
    for (const status of [403, 503]) {
      failStatus = status;
      const failed = dp.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith('/access/permissions'));
      await button(directoryForm, '读取原权限范围首页').click(); assert.equal((await failed).status(), status);
      await directoryForm.getByText('原权限范围读取失败，可重试当前页。', { exact: true }).waitFor();
      assert.ok(await button(directoryForm, '核对').isDisabled());
    }
    const declined = dp.waitForEvent('dialog'); await button(directoryForm, '取消').click(); await declined;
    assert.ok(await directoryForm.isVisible()); assert.equal(await directoryForm.getByLabel('资源类型', { exact: true }).inputValue(), directoryResource);
    await accepting(dp, () => button(directoryForm, '取消').click()); await directoryForm.waitFor({ state: 'hidden' });
    const main = dp.locator('.management-page');
    await main.getByText(new RegExp(`待核对原权限：${tenant} / ${business}，${directoryResource}::read`)).waitFor();
    await main.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
    assert.ok(await button(main, '创建权限').isDisabled());
    const writeButtons = main.getByRole('button', { name: /^(编\s*辑|停\s*用|启\s*用|归\s*档)$/ });
    assert.ok(await writeButtons.count() > 0);
    for (const control of await writeButtons.all()) assert.ok(await control.isDisabled());
    assert.equal(directoryPosts, 1); await goto(dp, `#/tenants/${tenant}/members`); assert.equal(directoryPosts, 1);
  } finally { await dp.unroute(directoryPath); await dp.unroute(`${directoryPath}?*`); }
  pass('permission unknown recovery permits confirmed close while retaining original scope and write lock');

  const tenantCase = await open('enabled', '#/platform/tenants'); const tp = tenantCase.page;
  const beforeTenant = await api(tenantCase, `/tenants/${encodeURIComponent(tenant2)}`);
  const nextName = `UI D updated ${id}`;
  await tp.getByLabel('租户 ID', { exact: true }).fill(tenant2); await button(tp, '查询').click();
  await button(tp, `设置租户 ${beforeTenant.name}`).click(); const settings = dialog(tp, '租户设置');
  await settings.getByLabel('租户名称', { exact: true }).fill(nextName);
  await button(settings, '核对并保存').click(); let settingsReview = dialog(tp, '确认租户变更');
  const summary = await settingsReview.innerText();
  for (const value of [tenant2, beforeTenant.name, nextName]) assert.ok(summary.includes(value));
  assert.ok(summary.includes(`当前版本：${beforeTenant.version}（提交时校验）`));
  const oldStatus = { active: '启用', suspended: '暂停', archived: '已归档' }[beforeTenant.status];
  assert.ok(summary.includes(`状态：${oldStatus} → ${oldStatus}`));
  const oldRegistration = beforeTenant.allow_registration ? '是' : '否';
  assert.ok(summary.includes(`允许注册：${oldRegistration} → ${oldRegistration}`));
  let patchCount = 0;
  const tenantPath = `${tenantCase.host.origin}${tenantCase.host.mount}/admin/tenants`;
  const countPatch = request => { if (request.method() === 'PATCH' && request.url() === tenantPath) patchCount++; };
  tp.on('request', countPatch);
  await button(settingsReview, '取消').click(); assert.equal(patchCount, 0);
  await button(settings, '核对并保存').click(); settingsReview = dialog(tp, '确认租户变更');
  const patchResponse = tp.waitForResponse(r => r.url() === tenantPath && r.request().method() === 'PATCH');
  await button(settingsReview, '确认提交').click(); const tenantUpdate = await patchResponse; assert.ok(tenantUpdate.ok());
  assert.equal(tenantUpdate.request().postDataJSON().expected_version, beforeTenant.version);
  assert.equal(tenantUpdate.request().postDataJSON().name, nextName);
  const afterTenant = await api(tenantCase, `/tenants/${encodeURIComponent(tenant2)}`);
  assert.equal(afterTenant.name, nextName); assert.ok(afterTenant.version > beforeTenant.version); assert.equal(patchCount, 1);
  tp.off('request', countPatch);
  pass('tenant edit reviews old and new values and current version before real expected-version PATCH');

  // Exercise the edit entry independently of the creation recovery case above.
  async function pendingPermissionEdit(test, resource, outcome = 'unknown') {
    await writeApi(test, 'POST', '/access/permissions', { resource_type: resource, action: 'read', description: 'UI D original edit' }, tenant, business);
    const before = await api(test, `/access/permissions/${resource}/read`, tenant, business);
    const page = test.page, listPath = `${test.host.origin}${test.host.mount}/admin/access/permissions`;
    const editPath = `${listPath}/${resource}/read`, description = `UI D edited ${resource}`;
    const state = { writes: 0, persisted: false, mutations: [] };
    await goto(page, `#/tenants/${tenant}/directory`);
    await page.getByLabel('业务标识', { exact: true }).fill(business);
    await page.getByLabel('资源类型', { exact: true }).fill(resource);
    await button(page, '查询').click();
    page.on('request', request => {
      if (['POST', 'PATCH', 'DELETE'].includes(request.method()) && request.url().startsWith(listPath))
        state.mutations.push({ method: request.method(), target: request.headers()['x-embedded-idp-tenant-id'] });
    });
    await page.route(editPath, async route => {
      if (route.request().method() !== 'PATCH') return route.continue();
      state.writes++;
      const request = route.request();
      assert.equal(request.headers()['x-embedded-idp-tenant-id'], tenant);
      assert.equal(request.headers()['x-embedded-idp-business-id'], business);
      assert.deepEqual(request.postDataJSON(), { description, expected_version: before.version });
      if (outcome === 'rejected') return route.fulfill({ status: 409, body: '{}' });
      const response = await route.fetch(); assert.ok(response.ok());
      const current = await api(test, `/access/permissions/${resource}/read`, tenant, business);
      assert.equal(current.description, description); assert.ok(current.version > before.version);
      state.persisted = true; await route.abort('connectionfailed');
    });
    const row = page.getByRole('row').filter({ hasText: `${resource}::read` });
    await button(row, '编辑').click(); const form = dialog(page, '编辑权限');
    for (const label of ['业务标识', '资源类型', '动作']) assert.ok(await form.getByLabel(label, { exact: true }).isDisabled());
    await form.getByLabel('权限说明', { exact: true }).fill(description);
    await button(form, '核对').click(); await button(dialog(page, '确认编辑权限'), '确认').click();
    if (outcome === 'unknown') await form.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
    else await form.getByRole('alert').filter({ hasText: '请重新读取原对象核对后再操作' }).waitFor();
    assert.equal(state.writes, 1); assert.equal(state.persisted, outcome === 'unknown');
    const current = await api(test, `/access/permissions/${resource}/read`, tenant, business);
    assert.equal(current.description, outcome === 'unknown' ? description : before.description);
    return { page, form, listPath, editPath, description, state };
  }
  async function directoryStillLocked(page, resource) {
    const main = page.locator('.management-page');
    await main.getByText(`待核对原权限：${tenant} / ${business}，${resource}::read。`, { exact: true }).waitFor();
    assert.ok(await button(main, '创建权限').isDisabled());
    assert.ok(await button(main, '查询').isDisabled()); assert.ok(await button(main, '重置').isDisabled());
    const controls = main.getByRole('button', { name: /^(编\s*辑|停\s*用|启\s*用|归\s*档)$/ });
    assert.ok(await controls.count() > 0);
    for (const control of await controls.all()) assert.ok(await control.isDisabled());
    return main;
  }
  for (const outcome of ['unknown', 'rejected']) {
    const test = await open('enabled', `#/tenants/${tenant}/directory`), resource = `edit_close_${outcome}_${id}`;
    const edit = await pendingPermissionEdit(test, resource, outcome);
    const { page, form, listPath, editPath, state } = edit;
    let failStatus = 403;
    try {
      await page.route(`${listPath}?*`, route => route.fulfill({ status: failStatus, body: '{}' }));
      for (const status of [403, 503, 503]) {
        failStatus = status;
        const read = page.waitForResponse(r => r.request().method() === 'GET' && r.url().startsWith(`${listPath}?`));
        await button(form, '读取原权限范围首页').click(); assert.equal((await read).status(), status);
        await form.getByText('原权限范围读取失败，可重试当前页。', { exact: true }).waitFor();
        // The fading Ant loading icon can temporarily prefix the accessible name.
        // Assert the original submit control itself remains disabled throughout recovery.
        const submitControl = form.locator('.ant-modal-footer button.ant-btn-primary');
        assert.equal(await submitControl.count(), 1); assert.ok(await submitControl.isDisabled());
        assert.equal(await button(form, '结束核对').count(), 0);
      }
      const declined = page.waitForEvent('dialog'); await button(form, '取消').click(); await declined;
      assert.ok(await form.isVisible()); assert.equal(await form.getByLabel('权限说明', { exact: true }).inputValue(), edit.description);
      await accepting(page, () => button(form, '取消').click()); await form.waitFor({ state: 'hidden' });
      const main = await directoryStillLocked(page, resource);
      assert.equal(await dialog(page, '确认编辑权限').count(), 0); assert.equal(state.writes, 1);
      if (outcome === 'unknown') await main.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
      else assert.equal(await main.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).count(), 0);
      await page.unroute(`${listPath}?*`);
      const recovery = page.waitForResponse(r => r.request().method() === 'GET' && r.url().startsWith(`${listPath}?`));
      await button(main, '读取原权限范围首页').click(); const response = await recovery; assert.ok(response.ok());
      assert.equal(response.request().headers()['x-embedded-idp-tenant-id'], tenant);
      assert.equal(response.request().headers()['x-embedded-idp-business-id'], business);
      assert.equal(new URL(response.url()).searchParams.get('resource_type'), resource);
      await main.getByText(new RegExp(`原权限当前状态：${resource}::read`)).waitFor();
      await directoryStillLocked(page, resource);
      await button(main, '结束核对').click(); await page.waitForFunction(() => [...document.querySelectorAll('button')].some(b => b.textContent === '创建权限' && !b.disabled));
      assert.equal(state.writes, 1); assert.equal(await form.count(), 0);
      assert.deepEqual(state.mutations, [{ method: 'PATCH', target: tenant }]);
    } finally { await page.unroute(editPath); await page.unroute(`${listPath}?*`); }
  }
  pass('permission edit unknown and rejected writes allow confirmed discard after persistent 403 and 503, retaining lock until explicit original-scope recovery');

  // Deliver a real successful member read only after the original drawer unmounts.
  const lateMember = await open('enabled', `#/tenants/${tenant}/members`), lp = lateMember.page;
  const lateMemberPath = `${lateMember.host.origin}${lateMember.host.mount}/admin/accounts/${encodeURIComponent(member)}`;
  let memberReads = 0, lateMemberWrites = 0, memberDelivered = false, lateMemberError, memberSeen, memberDone;
  const memberGate = gate(), memberObserved = new Promise(resolve => { memberSeen = resolve; }), memberFinished = new Promise(resolve => { memberDone = resolve; });
  const countMemberWrite = request => { if (request.method() === 'POST' && new URL(request.url()).pathname.includes('/members/')) lateMemberWrites++; };
  lp.on('request', countMemberWrite);
  try {
    await button(lp, '绑定已有用户').click(); let form = dialog(lp, '绑定已有用户');
    await form.getByLabel('用户邮箱', { exact: true }).fill(user); await button(form, '搜索已有用户').click(); await button(form, `选择用户 ${user}`).click();
    await lp.route(lateMemberPath, async route => {
      if (route.request().method() !== 'GET') return route.continue();
      memberReads++;
      try {
        assert.equal(route.request().headers()['x-embedded-idp-tenant-id'], tenant);
        const response = await route.fetch(); assert.ok(response.ok()); assert.equal((await response.json()).account_id, member);
        memberSeen(); await memberGate.promise; await route.fulfill({ response }); memberDelivered = true;
      } catch (error) { lateMemberError = error; memberSeen(); }
      finally { memberDone(); }
    });
    await button(form, '重新读取原成员').click(); await bounded(memberObserved, 'original member read held'); if (lateMemberError) throw lateMemberError;
    assert.ok(await button(form, '核对并绑定').isDisabled());
    const declined = lp.waitForEvent('dialog'); await form.locator('button.ant-drawer-close').click(); await declined; assert.ok(await form.isVisible());
    await accepting(lp, () => form.locator('button.ant-drawer-close').click()); await form.waitFor({ state: 'hidden' });
    assert.equal(memberDelivered, false);
    await button(lp, '绑定已有用户').click(); form = dialog(lp, '绑定已有用户');
    await form.getByLabel('用户邮箱', { exact: true }).fill('admin@example.test'); await button(form, '搜索已有用户').click();
    await button(form, '选择用户 admin@example.test').click();
    assert.ok(await button(form, '核对并绑定').isEnabled());
    const delivered = lp.waitForResponse(r => r.url() === lateMemberPath && r.request().method() === 'GET');
    memberGate.release(); await bounded(memberFinished, 'closed member read delivered'); if (lateMemberError) throw lateMemberError;
    assert.equal(await (await delivered).finished(), null);
    await lp.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.ok(memberDelivered); assert.equal(memberReads, 1); assert.equal(lateMemberWrites, 0);
    assert.ok(await form.isVisible()); assert.ok((await form.innerText()).includes('admin@example.test'));
    assert.equal(await form.getByText(/当前成员关系：|原用户当前未读取到/).count(), 0);
    assert.ok(await button(form, '核对并绑定').isEnabled()); assert.equal(await dialog(lp, '确认绑定成员').count(), 0);
    await accepting(lp, () => form.locator('button.ant-drawer-close').click());
  } finally { memberGate.release(); await lp.unroute(lateMemberPath); lp.off('request', countMemberWrite); }
  pass('closing a pending member read and reopening for another account discards the fully delivered late response without writes');

  // Closing only the editor retains its pending original-scope recovery; a late
  // success may expose current state but must not silently clear the write lock.
  for (const leaveTarget of [false, true]) {
    const test = await open('enabled', `#/tenants/${tenant}/directory`), resource = `edit_late_${leaveTarget ? 'target' : 'closed'}_${id}`;
    const originalSession = await api(test, '/auth/session');
    const { page, form, listPath, editPath, state } = await pendingPermissionEdit(test, resource);
    let readSeen, readDone, readError, delivered = false;
    const readGate = gate(), observed = new Promise(resolve => { readSeen = resolve; }), finished = new Promise(resolve => { readDone = resolve; });
    try {
      await page.route(`${listPath}?*`, async route => {
        const request = route.request();
        if (request.method() !== 'GET' || new URL(request.url()).searchParams.get('resource_type') !== resource) return route.continue();
        try {
          assert.equal(request.headers()['x-embedded-idp-tenant-id'], tenant); assert.equal(request.headers()['x-embedded-idp-business-id'], business);
          const response = await route.fetch(); assert.ok(response.ok()); assert.ok((await response.json()).items.some(item => item.resource_type === resource));
          readSeen(); await readGate.promise; await route.fulfill({ response }); delivered = true;
        } catch (error) { readError = error; readSeen(); }
        finally { readDone(); }
      });
      await button(form, '读取原权限范围首页').click(); await bounded(observed, 'permission recovery held'); if (readError) throw readError;
      assert.ok(await button(form, '读取原权限范围首页').isDisabled());
      await accepting(page, () => button(form, '取消').click()); await form.waitFor({ state: 'hidden' });
      const main = await directoryStillLocked(page, resource); assert.equal(delivered, false);
      if (leaveTarget) {
        await goto(page, `#/tenants/${tenant2}/directory`);
        assert.ok(await button(main, '创建权限').isEnabled());
        await button(main, '创建权限').click(); const nextForm = dialog(page, '创建权限');
        await nextForm.getByLabel('业务标识', { exact: true }).fill(business);
        await nextForm.getByLabel('资源类型', { exact: true }).fill(`untouched_${id}`);
        await nextForm.getByLabel('动作', { exact: true }).fill('read'); await nextForm.getByLabel('权限说明', { exact: true }).fill('new target draft retained');
      }
      const responseReady = page.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).searchParams.get('resource_type') === resource);
      readGate.release(); await bounded(finished, 'closed permission recovery delivered'); if (readError) throw readError;
      assert.equal(await (await responseReady).finished(), null);
      await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      assert.ok(delivered); assert.equal(state.writes, 1); assert.equal(await dialog(page, '编辑权限').count(), 0);
      if (leaveTarget) {
        assert.equal(await page.getByText(new RegExp(`待核对原权限：${tenant} /|原权限当前状态：${resource}`)).count(), 0);
        assert.equal(await main.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).count(), 0);
        assert.equal(await button(main, '结束核对').count(), 0);
        const nextForm = dialog(page, '创建权限'); assert.ok(await nextForm.isVisible());
        assert.equal(await nextForm.getByLabel('权限说明', { exact: true }).inputValue(), 'new target draft retained');
        assert.ok(await button(nextForm, '核对').isEnabled());
        await accepting(page, () => button(nextForm, '取消').click());
        assert.deepEqual(await api(test, '/auth/session'), originalSession);
      } else {
        await main.getByText(new RegExp(`原权限当前状态：${resource}::read`)).waitFor();
        await directoryStillLocked(page, resource);
        await main.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
        await button(main, '结束核对').click(); await page.waitForFunction(() => [...document.querySelectorAll('button')].some(b => b.textContent === '创建权限' && !b.disabled));
        assert.equal(await dialog(page, '编辑权限').count(), 0);
      }
      assert.equal(state.writes, 1);
      assert.deepEqual(state.mutations, [{ method: 'PATCH', target: tenant }]);
    } finally { readGate.release(); await page.unroute(editPath); await page.unroute(`${listPath}?*`); }
    pass(leaveTarget ? 'late permission recovery after confirmed close and target change cannot contaminate the new target draft or session' : 'late original permission recovery after editor close retains unknown result and lock until explicit finish without replay');
  }
  }
  assert.deepEqual(pageErrors, []);
} catch (error) {
  failure = error;
  // Persist only fixed flags and control geometry, never exception text or input values.
  const detail = String(error?.message ?? '');
  failureDiagnostics = {
    disabled: /element is not enabled/.test(detail), hidden: /element is not visible/.test(detail),
    moving: /element is not stable/.test(detail), intercepted: /intercepts pointer events/.test(detail),
    outsideViewport: /outside of the viewport/.test(detail),
    locatorResolved: /locator resolved to/.test(detail), waitingForLocator: /waiting for getByRole/.test(detail),
    clickPerformed: /click action done/.test(detail), navigationWait: /scheduled navigations/.test(detail),
    detached: /detached|not attached/.test(detail), pages: [],
  };
  for (const release of held) release();
  console.error(`UI-D failed after: ${cases.at(-1) ?? 'startup'}`);
  for (const [index, context] of contexts.entries()) for (const page of context.pages()) {
    const controls = await page.locator('[role="dialog"] .ant-modal-footer button').evaluateAll(buttons => buttons.slice(0, 20).map(button => {
      const name = button.textContent.replace(/\s/g, '');
      const rect = button.getBoundingClientRect();
      const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
      return {
        name: ['核对', '确认', '取消', '关闭', '保存'].includes(name) ? name : 'other',
        disabled: button.disabled, visible: !!rect.width && !!rect.height && getComputedStyle(button).visibility === 'visible',
        ariaHiddenAncestor: !!button.closest('[aria-hidden="true"]'), inertAncestor: !!button.closest('[inert]'),
        loading: button.classList.contains('ant-btn-loading'), loadingIcon: !!button.querySelector('[aria-label="loading"]'),
        top: Math.round(rect.top), bottom: Math.round(rect.bottom), viewportHeight: innerHeight,
        ownsCenter: !!hit && (hit === button || button.contains(hit)),
        anotherModalAtCenter: !!hit?.closest('.ant-modal-wrap') && hit.closest('.ant-modal-wrap') !== button.closest('.ant-modal-wrap'),
      };
    })).catch(() => null);
    const roleMatches = {
      createDialog: await dialog(page, '创建权限').count(),
      createDialogIncludingHidden: await page.getByRole('dialog', { name: '创建权限', exact: true, includeHidden: true }).count(),
      checkButton: await button(page, '核对').count(),
      checkButtonInCreateDialog: await button(dialog(page, '创建权限'), '核对').count(),
    };
    failureDiagnostics.pages.push({ context: index, controls, roleMatches });
    if (!functionalOnly) await page.screenshot({ path: `${output}/ui-d-failure-${index}.png`, animations: 'disabled', mask: [page.locator('input, textarea, [contenteditable=true]')] }).catch(() => {});
  }
  throw error;
} finally {
  for (const release of held) release();
  await finalizeFunctionalRun({ coverage, contexts, browser, failure,
    resultPath: `${output}/ui-d-results.json`, result: { cases, pageErrors, failureDiagnostics, evidence: 'isolated real UI-B hosts; screenshots mask inputs; empty, 401, 403, malformed, 409, lost response and readback failure explicitly injected; held responses and cross-tab logout use real hosts' } });
}
