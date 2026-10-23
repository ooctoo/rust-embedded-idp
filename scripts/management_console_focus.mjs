import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

// Real permission writes; only the subsequent list read is held or failed.
export async function runPermissionFocusChecks({ open, goto, settle, button, focused, pass }) {
  for (const mode of ['enabled', 'disabled']) {
    const t = await open(mode, mode === 'enabled' ? '#/tenants/tenant-a/directory' : '#/system/directory');
    const { page: p, host } = t, tenant = mode === 'enabled' ? 'tenant-a' : '0';
    const business = 'uif_focus_' + randomBytes(6).toString('hex');
    const path = `${host.mount}/admin/access/permissions`, url = host.origin + path;
    const headers = { authorization: t.bearer(), 'x-embedded-idp-tenant-id': tenant, 'x-embedded-idp-business-id': business };
    const session = async () => {
      const r = await p.request.get(host.origin + host.mount + '/admin/auth/session', { headers: { authorization: t.bearer() } });
      assert.equal(r.status(), 200); return r.json();
    };
    const identity = await session();
    const refresh = button(p, '刷新目录');
    try {
      await p.getByLabel('业务标识', { exact: true }).fill(business);
      await button(p, '查询').click(); await settle(p);
      // Creation retains the stable toolbar trigger after both dialogs close.
      const create = button(p, '创建权限'); await create.click();
      const editor = p.getByRole('dialog', { name: '创建权限', exact: true });
      assert.equal(await editor.getByLabel('业务标识', { exact: true }).inputValue(), business);
      await editor.getByLabel('资源类型', { exact: true }).fill('report');
      await editor.getByLabel('动作', { exact: true }).fill('read');
      await editor.getByLabel('权限说明', { exact: true }).fill('UI F focus fixture');
      await button(editor, '核对').click();
      const created = p.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname === path);
      await button(p.getByRole('dialog', { name: '确认创建权限', exact: true }), '确认').click();
      assert.equal((await created).status(), 200); await editor.waitFor({ state: 'hidden' }); await settle(p); await focused(p, create);
      pass(`${mode}: successful permission creation restores the surviving toolbar trigger`);
      for (const action of ['edit', 'disable', 'enable', 'archive', 'leave']) {
        const row = p.getByRole('row').filter({ hasText: 'report::read' });
        const original = button(row, action === 'edit' ? '编辑' : action === 'archive' ? '归档' : action === 'enable' ? '启用' : '停用');
        // For leave, create a separate live permission after the first was archived.
        if (action === 'leave') {
          const seeded = await p.request.post(url, { headers, data: { resource_type: 'report', action: 'second', description: 'UI F late read fixture' } });
          assert.equal(seeded.status(), 200); await refresh.click(); await settle(p);
        }
        const trigger = action === 'leave' ? button(p.getByRole('row').filter({ hasText: 'report::second' }), '停用') : original;
        await trigger.click();
        let review;
        if (action === 'edit') {
          const edit = p.getByRole('dialog', { name: '编辑权限', exact: true });
          await edit.getByLabel('权限说明', { exact: true }).fill('UI F confirmed revision');
          await button(edit, '核对').click();
          review = p.getByRole('dialog', { name: '确认编辑权限', exact: true });
        } else review = p.getByRole('dialog', { name: action === 'archive' ? '确认归档权限' : '确认更改权限状态', exact: true });
        let release, started, reads = 0;
        const gate = new Promise(r => { release = r; }), entered = new Promise(r => { started = r; });
        const handler = async route => {
          if (route.request().method() !== 'GET') return route.continue();
          reads++; const response = await route.fetch(); started(); await gate;
          if (action === 'archive') await route.fulfill({ status: 503, json: {} });
          else await route.fulfill({ response });
        };
        await p.route(url + '?*', handler);
        const before = t.writes.length;
        const wrote = p.waitForResponse(r => ['POST', 'PATCH', 'DELETE'].includes(r.request().method()) && new URL(r.url()).pathname.startsWith(path + '/report/'));
        try {
          await button(review, '确认').click(); const response = await wrote; assert.equal(response.status(), 200);
          assert.equal(response.request().headers()['x-embedded-idp-tenant-id'], tenant);
          assert.equal(response.request().headers()['x-embedded-idp-business-id'], business);
          await entered; await review.waitFor({ state: 'hidden' });
          await p.getByRole('dialog', { name: '编辑权限', exact: true }).waitFor({ state: 'hidden' });
          await focused(p, refresh); assert.equal(await refresh.getAttribute('aria-disabled'), 'true');
          await refresh.press('Enter'); assert.equal(reads, 1, 'loading refresh is focusable but cannot issue another read');
          if (action === 'leave') {
            await goto(p, mode === 'enabled' ? '#/tenants/tenant-a/roles' : '#/system/roles');
            const next = button(p, '查询'); await next.focus(); release(); await focused(p, next);
            await p.waitForLoadState('networkidle'); await focused(p, next);
          } else {
            release(); await settle(p); await focused(p, refresh);
            if (action === 'archive') await p.getByText('写入已确认，重新读取失败', { exact: true }).waitFor();
            assert.equal(await refresh.getAttribute('aria-disabled'), 'false');
            assert.equal(await p.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).count(), 0);
          }
          assert.equal(t.writes.length - before, 1, 'confirmed write is never replayed');
          assert.deepEqual(await session(), identity);
          pass(`${mode}: permission ${action} success restores focus during held reload${action === 'archive' ? ' and failed read' : action === 'leave' ? ' without stealing focus after unmount' : ''}, one scoped write and unchanged session`);
        } finally { release(); await p.unroute(url + '?*', handler); }
      }
    } finally { await t.context.close(); }
  }
}
