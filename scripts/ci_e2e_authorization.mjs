// Critical authorization and partial-success checks; the caller owns the fixture.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

export function createAuthorizationChecks(h) {
  const { fixture, context, open, button, dialog, settle, accepting, checked } = h;
  const id = randomBytes(6).toString('hex');
  const tenant = 'tenant-a', business = `ci_auth_${id}`, roleName = `CI reader ${id}`;
  const email = `ci-member-${id}@example.test`;
  let test, member, role;
  const headers = (t, target, biz) => ({ authorization: t.bearer(),
    ...(target ? { 'x-embedded-idp-tenant-id': target } : {}),
    ...(biz ? { 'x-embedded-idp-business-id': biz } : {}) });
  const address = (t, path) => t.host.origin + t.host.mount + '/admin' + path;
  async function api(t, method, path, data, target, biz) {
    const response = await t.page.request.fetch(address(t, path), {
      method, headers: headers(t, target, biz), ...(data === undefined ? {} : { data }),
    });
    assert.ok(response.ok(), `synthetic ${method} request failed: ${response.status()}`);
    return response.json();
  }
  async function goto(p, hash, title) {
    await accepting(p, async () => {
      await p.evaluate(value => { location.hash = value; }, hash);
      await p.getByRole('heading', { name: title, exact: true }).waitFor();
      await settle(p);
    });
  }
  async function prepare() {
    if (test) return;
    test = await open(await context());
    await api(test, 'POST', '/access/permissions', {
      resource_type: 'report', action: 'read', description: 'CI synthetic permission',
    }, tenant, business);
    role = (await api(test, 'POST', '/access/roles', { key: `reader_${id}`, name: roleName }, tenant, business)).role;
    await api(test, 'PUT', `/access/roles/${encodeURIComponent(role.role_id)}/permissions`, {
      expected_version: role.version, permissions: [{ resource_type: 'report', action: 'read' }],
    }, tenant, business);
    member = (await api(test, 'POST', '/platform/accounts', {
      tenant_id: tenant, email, password: fixture.password,
    })).account.account_id;
  }
  async function memberDrawer() {
    await goto(test.page, `#/tenants/${tenant}/members`, '成员管理');
    await button(test.page, `查看成员角色 ${email}`).click();
    const d = dialog(test.page, `成员角色：${email}`);
    await d.getByLabel('业务标识', { exact: true }).fill(business);
    const loaded = test.page.waitForResponse(r => r.request().method() === 'GET' &&
      new URL(r.url()).pathname.endsWith(`/access/subjects/${member}/role-bindings`) &&
      r.request().headers()['x-embedded-idp-business-id'] === business);
    await button(d, '查询').click(); assert.ok((await loaded).ok()); await settle(test.page);
    return d;
  }
  async function select(d, label, option) {
    const input = d.getByLabel(label, { exact: true });
    await input.focus(); await input.press('ArrowDown');
    const inputId = await input.getAttribute('id'), controls = await input.getAttribute('aria-controls');
    assert.ok(inputId && controls);
    await test.page.waitForFunction(({ inputId, controls, option }) => {
      const input = document.getElementById(inputId);
      const popup = document.getElementById(controls)?.closest('.ant-select-dropdown');
      return input?.getAttribute('aria-expanded') === 'true' && popup?.getClientRects().length &&
        [...popup.querySelectorAll('.ant-select-item-option-content')].some(item => item.textContent === option);
    }, { inputId, controls, option });
    for (let index = 0; ; index++) {
      const active = await input.evaluate(el => {
        const item = document.getElementById(el.getAttribute('aria-activedescendant'));
        return item?.getAttribute('aria-label') ?? item?.textContent;
      });
      if (active === option) break;
      assert.ok(index < 10, 'expected keyboard option is absent'); await input.press('ArrowDown');
    }
    await input.press('Enter');
    await test.page.waitForFunction(({ inputId, option }) => {
      const input = document.getElementById(inputId);
      return input?.getAttribute('aria-expanded') === 'false' &&
        input.closest('.ant-select')?.querySelector('.ant-select-selection-item')?.textContent === option;
    }, { inputId, option });
  }
  async function reviewGrant(d, resource) {
    await button(d, '分配业务角色').click(); await button(d, `选择角色 ${roleName}`).click();
    await select(d, '资源类型', 'report'); await select(d, '授权范围', '仅一个具体资源');
    await d.getByLabel('资源 ID', { exact: true }).fill(resource);
    await button(d, '预览授权').click();
    const review = dialog(test.page, '确认成员角色分配'); await review.waitFor();
    const text = await review.innerText();
    for (const value of [tenant, business, member, resource]) assert.ok(text.includes(value));
    return review;
  }
  const bindingPath = () => `/access/subjects/${encodeURIComponent(member)}/role-bindings`;
  async function closeDrawer(d) {
    await accepting(test.page, () => d.locator('button.ant-drawer-close').click());
    await d.waitFor({ state: 'hidden' });
  }

  return {
    async writeAndReadback() {
      await checked('E03.authorization_write_readback', async () => {
        await prepare(); const d = await memberDrawer(), resource = `normal-${id}`;
        const review = await reviewGrant(d, resource);
        const written = test.page.waitForResponse(r => r.request().method() === 'POST' &&
          new URL(r.url()).pathname.endsWith(bindingPath()));
        await button(review, '确认分配').click(); const response = await written; assert.ok(response.ok());
        const request = response.request();
        assert.equal(request.headers()['x-embedded-idp-tenant-id'], tenant);
        assert.equal(request.headers()['x-embedded-idp-business-id'], business);
        assert.deepEqual(request.postDataJSON(), { role_id: role.role_id, resource_type: 'report',
          scope: { kind: 'instance', resource_id: resource } });
        const binding = (await response.json()).binding;
        const readback = await api(test, 'GET', bindingPath() + '?limit=50', undefined, tenant, business);
        assert.ok(readback.items.some(item => item.binding_id === binding.binding_id));
        await review.waitFor({ state: 'hidden' }); await settle(test.page); await closeDrawer(d);
      });
    },
    async recoverOriginalScope() {
      await checked('E05.authorization_original_scope_recovery', async () => {
        await prepare(); const d = await memberDrawer(), p = test.page;
        const url = address(test, bindingPath()); let writes = 0, observed, routeFailed = false;
        const onWrite = request => {
          if (request.method() === 'POST' && new URL(request.url()).pathname === new URL(url).pathname) writes++;
        };
        p.on('request', onWrite);
        await p.route(url, async route => {
          if (route.request().method() !== 'POST') return route.continue();
          try {
            const response = await route.fetch(); assert.ok(response.ok()); observed = (await response.json()).binding;
            const readback = await api(test, 'GET', bindingPath() + '?limit=50', undefined, tenant, business);
            assert.ok(readback.items.some(item => item.binding_id === observed.binding_id));
          } catch { routeFailed = true; }
          await route.abort('connectionfailed');
        });
        try {
          const review = await reviewGrant(d, `unknown-${id}`);
          await button(review, '确认分配').click();
          await d.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
          assert.equal(routeFailed, false); assert.ok(observed?.binding_id); assert.equal(writes, 1);
          await p.unroute(url);
          const filter = d.getByLabel('业务标识', { exact: true }); assert.ok(await filter.isDisabled());
          await accepting(p, () => button(d, '重新加载分配').click()); await settle(p);
          assert.ok(await filter.isDisabled()); assert.ok(await button(d, '分配业务角色').isDisabled());
          const scopeUrl = url + '?*';
          await p.route(scopeUrl, route => {
            assert.equal(route.request().headers()['x-embedded-idp-tenant-id'], tenant);
            assert.equal(route.request().headers()['x-embedded-idp-business-id'], business);
            return route.fulfill({ status: 503, json: {} });
          });
          await button(d, '读取原授权范围首页').click();
          await d.getByText('原成员或原业务授权读取失败，可重试当前页；写入仍锁定。', { exact: true }).waitFor();
          assert.ok(await filter.isDisabled()); assert.equal(await button(d, '结束授权核对').count(), 0);
          await p.unroute(scopeUrl);
          const recovered = p.waitForResponse(r => r.request().method() === 'GET' &&
            new URL(r.url()).pathname.endsWith(bindingPath()) &&
            r.request().headers()['x-embedded-idp-tenant-id'] === tenant &&
            r.request().headers()['x-embedded-idp-business-id'] === business);
          await button(d, '读取原授权范围首页').click(); const response = await recovered; assert.ok(response.ok());
          const matched = (await response.json()).items.find(item => item.binding_id === observed.binding_id);
          assert.ok(matched); assert.equal(matched.role_id, role.role_id);
          assert.equal(matched.resource_type, 'report'); assert.deepEqual(matched.scope, observed.scope);
          await d.getByText(`原授权当前存在，绑定 ID：${observed.binding_id}`, { exact: false }).waitFor();
          await button(d, '结束授权核对').waitFor(); await button(d, '结束授权核对').click();
          assert.ok(await filter.isEnabled()); assert.equal(writes, 1); await closeDrawer(d);
        } finally {
          await p.unroute(url).catch(() => {}); await p.unroute(url + '?*').catch(() => {}); p.off('request', onWrite);
        }
      });
    },
    async tenantPartialSuccess() {
      await checked('E05.tenant_creation_partial_success', async () => {
        const t = await open(await context()), p = t.page;
        const target = `ci-partial-${id}`, adminEmail = `ci-admin-${id}@example.test`;
        const createUrl = address(t, '/tenants'), tenantUrl = address(t, `/tenants/${target}`);
        const tenantPath = new URL(tenantUrl).pathname;
        let createPosts = 0, independent, routeFailed = false;
        const countCreation = request => {
          if (request.method() === 'POST' && new URL(request.url()).pathname === new URL(createUrl).pathname) createPosts++;
        };
        p.on('request', countCreation);
        async function evidence() {
          const record = await api(t, 'GET', `/tenants/${target}`);
          const members = await api(t, 'GET', `/accounts?email=${encodeURIComponent(adminEmail)}&limit=50`, undefined, target);
          const member = members.items.find(item => item.email.toLowerCase() === adminEmail);
          assert.equal(record.tenant_id, target); assert.equal(member?.membership.status, 'active');
          const admin = await api(t, 'GET', `/access/security-admins/${member.account_id}`, undefined, target);
          assert.ok(admin.binding); return { record, member, admin };
        }
        await goto(p, '#/platform/tenants', '租户管理');
        await p.route(createUrl, async route => {
          if (route.request().method() !== 'POST') return route.continue();
          try {
            const response = await route.fetch(); assert.ok(response.ok());
            assert.equal(route.request().postDataJSON().tenant_id, target); independent = await evidence();
          } catch { routeFailed = true; }
          await route.abort('connectionfailed');
        });
        const form = dialog(p, '创建租户');
        try {
          await button(p, '创建租户').click();
          await form.getByLabel('租户 ID', { exact: true }).fill(target);
          await form.getByLabel('租户名称', { exact: true }).fill('CI partial success');
          await form.getByLabel('管理员邮箱', { exact: true }).fill(adminEmail);
          await form.getByLabel('初始密码', { exact: true }).fill(fixture.password);
          await button(form, '核对并创建').click(); const review = dialog(p, '确认创建租户');
          assert.ok(!(await review.innerText()).includes(fixture.password));
          await button(review, '确认提交').click();
          await form.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
          assert.equal(routeFailed, false); assert.ok(independent?.admin.binding); assert.equal(createPosts, 1);
          assert.equal(await form.getByLabel('初始密码', { exact: true }).inputValue(), '');
          await p.unroute(createUrl);
          await p.route(tenantUrl, route => route.fulfill({ status: 503, json: {} }));
          await accepting(p, () => button(form, '重新加载租户').click());
          await form.getByText('读取失败', { exact: true }).waitFor();
          assert.equal(await form.locator('button[type="submit"]:enabled').count(), 0);
          await p.unroute(tenantUrl);
          await accepting(p, () => button(form, '重新加载租户').click());
          await form.getByText('当前可读取到租户', { exact: false }).waitFor();
          assert.equal(await form.locator('button[type="submit"]:enabled').count(), 0);
          assert.ok((await form.innerText()).includes('回读不能证明初始密码写入或请求归因'));
          assert.equal(createPosts, 1);
        } finally {
          await p.unroute(createUrl).catch(() => {}); await p.unroute(tenantUrl).catch(() => {});
        }
        await goto(p, `#/tenants/${target}/roles`, '角色与权限');
        let rolePosts = 0, compensatingDeletes = 0;
        const onRequest = request => {
          const path = new URL(request.url()).pathname;
          if ((path === tenantPath && ['DELETE', 'PATCH'].includes(request.method())) ||
              (path === new URL(createUrl).pathname && request.method() === 'PATCH' && request.postDataJSON()?.tenant_id === target)) compensatingDeletes++;
        };
        const roleUrl = address(t, '/access/roles'); p.on('request', onRequest);
        try {
          await button(p, '新建角色').click(); const editor = dialog(p, '新建业务角色');
          await editor.getByLabel('业务标识', { exact: true }).fill(`ci_partial_${id}`);
          await editor.getByLabel('角色标识', { exact: true }).fill(`reader_${id}`);
          await editor.getByLabel('角色名称', { exact: true }).fill('CI partial role');
          await button(editor, '创建角色').click();
          await p.route(roleUrl, route => {
            if (route.request().method() === 'POST') { rolePosts++; return route.fulfill({ status: 503, json: {} }); }
            return route.continue();
          });
          await button(dialog(p, '确认创建角色'), '确认创建').click();
          await p.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
          assert.equal(rolePosts, 1); assert.equal(compensatingDeletes, 0);
          const after = await evidence(); assert.equal(after.member.account_id, independent.member.account_id);
          assert.deepEqual(after.record, independent.record);
          assert.equal(rolePosts, 1); assert.equal(compensatingDeletes, 0);
          assert.equal(createPosts, 1);
          assert.equal(await p.getByText('失败全部回滚', { exact: true }).count(), 0);
          assert.equal(await p.getByText('整个向导回滚', { exact: false }).count(), 0);
        } finally {
          await p.unroute(roleUrl).catch(() => {}); p.off('request', onRequest); p.off('request', countCreation); p.off('request', countCreation);
        }
      });
    },
  };
}
