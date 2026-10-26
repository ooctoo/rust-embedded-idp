// Browser-only scope and lifecycle regressions retained from the retired N2 matrix.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

const hash = (page, value) => page.evaluate(value => { location.hash = value; }, value);
const heading = (page, name) => page.getByRole('heading', { name, exact: true }).waitFor();
const gate = () => {
  let release;
  const promise = new Promise(resolve => { release = resolve; });
  return { promise, release };
};
async function bounded(promise, name) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(name)), 15000);
    })]);
  } finally { clearTimeout(timer); }
}
async function observeDialog(page, action) {
  const received = page.waitForEvent('dialog');
  await action();
  return received;
}

export async function runNavigationChecks(h) {
  const { context, open, session, button, dialog, settle, checked } = h;
  await checked('E02.choose_cancel_complete', async () => {
    const t = await open(await context(), 'choose');
    const p = t.page;
    await heading(p, '工作台');
    const source = await session(t);
    assert.equal(source.tenant_id, 'tenant-a');
    await button(p, '切换登录租户').click();
    await button(p, '取消切换，返回当前会话').click();
    await heading(p, '工作台');
    assert.deepEqual(await session(t), source);
    await button(p, '切换登录租户').click();
    await button(p, '进入 UI B tenant-b').click();
    await heading(p, '工作台'); await settle(p);
    const selected = await session(t);
    assert.equal(selected.tenant_id, 'tenant-b');
    assert.notEqual(selected.session_id, source.session_id);
    assert.equal(selected.account_id, source.account_id);
    assert.equal(selected.client_id, source.client_id);
    assert.equal(new URL(p.url()).hash, '#/tenants/tenant-b/home');
  });

  await checked('E02.old_target_response', async () => {
    const t = await open(await context()), p = t.page;
    const pattern = `${t.host.origin}${t.host.mount}/admin/accounts?*`;
    const held = gate(), seen = gate(), delivered = gate();
    let routeError;
    const targets = [];
    const handler = async route => {
      const target = route.request().headers()['x-embedded-idp-tenant-id'];
      targets.push(target);
      if (target !== 'tenant-a') return route.continue();
      try {
        const response = await route.fetch(); assert.equal(response.status(), 200);
        const body = await response.json(); assert.ok(body.items.length > 0);
        for (const row of body.items) row.display_name = 'CI delayed tenant A response';
        seen.release(); await held.promise;
        await route.fulfill({ response, json: body });
      } catch (error) { routeError = error; seen.release(); }
      finally { delivered.release(); }
    };
    await p.route(pattern, handler);
    try {
      await hash(p, '#/tenants/tenant-a/members');
      await bounded(seen.promise, 'old target read not observed');
      if (routeError) throw routeError;
      await hash(p, '#/tenants/tenant-b/members');
      await heading(p, '成员管理'); await settle(p);
      assert.ok(targets.includes('tenant-b'));
      held.release(); await bounded(delivered.promise, 'old target response not delivered');
      if (routeError) throw routeError;
      await p.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      assert.equal(await p.getByText('CI delayed tenant A response', { exact: true }).count(), 0);
      assert.ok((await p.locator('.management-target').innerText()).includes('tenant-b'));
      assert.equal(new URL(p.url()).hash, '#/tenants/tenant-b/members');
      assert.equal((await session(t)).tenant_id, '0');
    } finally { held.release(); await p.unroute(pattern, handler); }
  });

  await checked('E02.draft_and_pending_navigation_guard', async () => {
    const t = await open(await context()), p = t.page;
    const endpoint = `${t.host.origin}${t.host.mount}/admin/access/roles`;
    const key = 'ci-guard-' + randomBytes(6).toString('hex');
    let writes = 0;
    p.on('request', request => {
      if (request.url() === endpoint && request.method() === 'POST') writes++;
    });
    await hash(p, '#/tenants/tenant-b/roles'); await heading(p, '角色与权限'); await settle(p);
    await button(p, '新建角色').click();
    const editor = dialog(p, '新建业务角色');
    await editor.getByPlaceholder('例如 biz_test', { exact: true }).fill('uib');
    await editor.getByLabel('角色标识', { exact: true }).fill(key);
    await editor.getByLabel('角色名称', { exact: true }).fill('CI navigation guard');
    const cancelled = await observeDialog(p, () => hash(p, '#/tenants/tenant-a/members'));
    assert.equal(cancelled.type(), 'confirm');
    await p.waitForURL('**/#/tenants/tenant-b/roles');
    assert.equal(await editor.getByLabel('角色名称', { exact: true }).inputValue(), 'CI navigation guard');
    assert.equal(writes, 0);

    const held = gate(), seen = gate(), delivered = gate();
    let routeError;
    const handler = async route => {
      if (route.request().method() !== 'POST') return route.continue();
      try {
        assert.equal(route.request().headers()['x-embedded-idp-tenant-id'], 'tenant-b');
        assert.equal(route.request().headers()['x-embedded-idp-business-id'], 'uib');
        seen.release(); await held.promise; await route.continue();
      } catch (error) { routeError = error; seen.release(); }
      finally { delivered.release(); }
    };
    await p.route(endpoint, handler);
    try {
      await button(editor, '创建角色').click();
      await button(dialog(p, '确认创建角色'), '确认创建').click();
      await bounded(seen.promise, 'pending role write not observed');
      if (routeError) throw routeError;
      const blocked = await observeDialog(p, () => hash(p, '#/tenants/tenant-a/members'));
      assert.equal(blocked.type(), 'alert');
      await p.waitForURL('**/#/tenants/tenant-b/roles');
      assert.equal(writes, 1);
      const done = p.waitForResponse(r => r.url() === endpoint && r.request().method() === 'POST');
      held.release(); assert.equal((await done).status(), 201);
      await bounded(delivered.promise, 'pending role write not released');
      if (routeError) throw routeError;
      await editor.waitFor({ state: 'hidden' }); await settle(p);
      assert.equal(writes, 1);
      assert.equal((await session(t)).tenant_id, '0');
    } finally { held.release(); await p.unroute(endpoint, handler); }
  });
}

export async function runLateLogoutCheck(h) {
  const { context, open, session, button, checked } = h;
  await checked('E06.late_response_after_logout', async () => {
    const c = await context(), first = await open(c), p = first.page;
    const second = await open(c, 'enabled', false);
    await second.page.locator('.management-shell').waitFor();
    const identity = await session(first);
    assert.equal((await session(second)).session_id, identity.session_id);
    const endpoint = `${first.host.origin}${first.host.mount}/admin/clients`;
    const pattern = url => url.href.split('?')[0] === endpoint;
    const held = gate(), seen = gate(), delivered = gate();
    let routeError, writes = 0;
    p.on('request', request => {
      if (request.method() === 'POST' && new URL(request.url()).pathname.endsWith('/clients/upsert')) writes++;
    });
    const handler = async route => {
      try {
        const response = await route.fetch(); assert.equal(response.status(), 200);
        seen.release(); await held.promise; await route.fulfill({ response });
      } catch (error) { routeError = error; seen.release(); }
      finally { delivered.release(); }
    };
    await p.route(pattern, handler);
    try {
      await button(p, '刷新客户端').click();
      await bounded(seen.promise, 'pre-logout client read not observed');
      if (routeError) throw routeError;
      await button(second.page, '退出登录').click();
      await second.page.getByLabel('邮箱', { exact: true }).waitFor();
      await p.locator('.management-shell').waitFor({ state: 'hidden' });
      const late = p.waitForResponse(response => pattern(new URL(response.url())));
      held.release(); await bounded(delivered.promise, 'post-logout response not delivered');
      if (routeError) throw routeError;
      assert.equal(await (await late).finished(), null);
      await p.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      assert.equal(await p.locator('.management-shell').count(), 0);
      assert.equal(await p.getByRole('dialog').count(), 0);
      assert.equal(writes, 0);
      const response = await p.request.get(`${first.host.origin}${first.host.mount}/admin/auth/session`, {
        headers: { authorization: first.bearer() },
      });
      assert.equal(response.status(), 401);
    } finally { held.release(); await p.unroute(pattern, handler); }
  });
}
