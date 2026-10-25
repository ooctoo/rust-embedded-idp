import { functionalOnly } from './management_functional.mjs';
import assert from 'node:assert/strict';

// Runs only against the caller's validated, disposable UI-B fixture.
export async function runSessionChecks(h) {
  const { fixture, id, open, api, writeApi, sql, button, dialog, goto, accepting, bounded, gate, settle, pass } = h;
  const tenant = 'tenant-a';
  const operator = await open('enabled', `#/tenants/${tenant}/sessions`);
  const p = operator.page;
  const first = await open('fixed', `#/tenants/${tenant}/home`, 'tenant-a@example.test');
  const second = await open('fixed', `#/tenants/${tenant}/home`, 'tenant-a@example.test');
  const firstSession = await api(first, '/auth/session');
  const secondSession = await api(second, '/auth/session');
  const operatorSession = await api(operator, '/auth/session');
  assert.equal(firstSession.account_id, secondSession.account_id);
  assert.notEqual(firstSession.session_id, secondSession.session_id);
  const schema = fixture.schemas.enabled;
  assert.match(schema, /^uib_enabled_[a-f0-9]+$/);
  for (const value of [firstSession.session_id, firstSession.account_id, operatorSession.account_id]) assert.match(value, /^[a-f0-9-]{36}$/);
  await writeApi(operator, 'POST', `/members/${firstSession.account_id}/bind`, {}, 'tenant-b');
  async function cloneSession(target, account, status) {
    const result = await sql('enabled', `insert into ${schema}.auth_sessions (purpose,tenant_id,id,account_id,client_id,device_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,scope,authenticated_at_epoch) select purpose,'${target}',gen_random_uuid(),'${account}',client_id,null,'${status}',created_at_epoch,expires_at_epoch,refresh_token_version,scope,authenticated_at_epoch from ${schema}.auth_sessions where tenant_id='tenant-a' and id='${firstSession.session_id}' returning id`);
    const match = String(result).match(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/);
    assert.ok(match, 'inserted session ID'); return match[0];
  }
  const otherTenant = await cloneSession('tenant-b', firstSession.account_id, 'active');
  const otherAccount = (await writeApi(operator, 'POST', '/platform/accounts', { tenant_id: tenant, email: `uie-other-session-${id}@example.test`, password: fixture.password })).account;
  const otherSubject = await cloneSession(tenant, otherAccount.account_id, 'active');
  assert.equal((await api(operator, `/sessions/${otherTenant}`, 'tenant-b')).status, 'active');
  assert.equal((await api(operator, `/sessions/${otherSubject}`, tenant)).status, 'active');
  async function preview(subject) {
    await p.getByLabel('按用户撤销', { exact: true }).fill(subject);
    await button(p, '核对并撤销全部会话').click();
    const review = dialog(p, '确认撤销该用户的全部会话');
    await review.waitFor();
    assert.ok((await review.innerText()).includes(subject));
    return review;
  }
  let review = await preview(firstSession.account_id);
  if (!functionalOnly) await review.screenshot({ animations: 'disabled', path: `${h.output}/ui-e-session-confirm.png`, mask: [review.locator('input,textarea')] });
  const path = `${operator.host.origin}${operator.host.mount}/admin/accounts/${firstSession.account_id}/sessions/revoke`;
  const batch = p.waitForResponse(r => r.request().method() === 'POST' && r.url() === path);
  await button(review, '确认撤销全部会话').click();
  const response = await batch; assert.ok(response.ok());
  assert.deepEqual(response.request().postDataJSON(), {});
  const body = await response.json(); assert.equal(body.tenant_id, tenant); assert.equal(body.account_id, firstSession.account_id); assert.ok(body.revoked_session_count >= 2);
  await p.getByText(new RegExp(`已撤销 ${tenant} / ${firstSession.account_id} 的 ${body.revoked_session_count} 个`)).waitFor();
  for (const session of [firstSession, secondSession]) assert.equal((await api(operator, `/sessions/${session.session_id}`, tenant)).status, 'revoked');
  assert.equal((await api(operator, `/sessions/${otherTenant}`, 'tenant-b')).status, 'active');
  assert.equal((await api(operator, `/sessions/${otherSubject}`, tenant)).status, 'active');
  assert.deepEqual(await api(operator, '/auth/session'), operatorSession);
  const oldBearer = await first.page.request.get(`${first.host.origin}${first.host.mount}/admin/auth/session`, { headers: { authorization: first.bearer() } });
  assert.equal(oldBearer.status(), 401);
  pass('subject batch revoke returns real count and revokes two original sessions while operator remains active');

  // Exercise status rules on real rows before the paging seed is inserted.
  const pending = await cloneSession(tenant, firstSession.account_id, 'pending');
  const expired = await cloneSession(tenant, firstSession.account_id, 'expired');
  const revoked = await cloneSession(tenant, firstSession.account_id, 'revoked');
  await p.getByLabel('用户 ID', { exact: true }).fill(firstSession.account_id);
  await button(p, '查询').click(); await settle(p);
  for (const sessionId of [expired, revoked]) {
    await button(p, `查看会话 ${sessionId}`).click();
    const detail = dialog(p, '会话详情'); await detail.waitFor();
    await detail.getByText(sessionId, { exact: false }).waitFor();
    assert.ok(await button(detail, '撤销会话').isDisabled());
    await detail.locator('button.ant-drawer-close').click();
  }
  await button(p, `查看会话 ${pending}`).click();
  let single = dialog(p, '会话详情'); await single.getByText(pending, { exact: false }).waitFor();
  assert.ok(await button(single, '撤销会话').isEnabled());
  await button(single, '撤销会话').click();
  const singleReview = dialog(p, '确认撤销会话');
  await singleReview.getByText('原状态：待完成', { exact: false }).waitFor();
  const singlePost = p.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith(`/sessions/${pending}/revoke`));
  await button(singleReview, '确认撤销').click();
  const singleResult = await singlePost; assert.ok(singleResult.ok());
  assert.deepEqual(singleResult.request().postDataJSON(), {});
  assert.equal((await api(operator, `/sessions/${pending}`, tenant)).status, 'revoked');
  await single.locator('button.ant-drawer-close').click();
  pass('pending single session can be revoked with empty request; expired and revoked sessions are disabled');

  const self = await open('fixed', `#/tenants/${tenant}/sessions`, 'tenant-a@example.test');
  const selfIdentity = await api(self, '/auth/session');
  await self.page.getByLabel('按用户撤销', { exact: true }).fill(selfIdentity.account_id);
  await button(self.page, '核对并撤销全部会话').click();
  review = dialog(self.page, '确认撤销该用户的全部会话');
  await review.getByText('正在撤销当前账号在当前租户的全部会话。', { exact: true }).waitFor();
  const selfResponse = self.page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith(`/accounts/${selfIdentity.account_id}/sessions/revoke`));
  await button(review, '确认撤销全部会话').click(); assert.ok((await selfResponse).ok());
  await self.page.getByLabel('密码', { exact: true }).waitFor();
  const rejected = await self.page.request.get(`${self.host.origin}${self.host.mount}/admin/auth/session`, { headers: { authorization: self.bearer() } });
  assert.equal(rejected.status(), 401);
  pass('self subject revoke clears local management session and old bearer is rejected');

  // Clone harmless expired/revoked rows in the isolated schema to exercise real cursor paging.
  await sql('enabled', `insert into ${schema}.auth_sessions (purpose,tenant_id,id,account_id,client_id,device_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,scope,authenticated_at_epoch) select purpose,tenant_id,gen_random_uuid(),account_id,client_id,device_id,'revoked',created_at_epoch,expires_at_epoch,refresh_token_version,scope,authenticated_at_epoch from ${schema}.auth_sessions cross join generate_series(1,51) where tenant_id='tenant-a' and id='${firstSession.session_id}'`);
  const secondFixed = await open('fixed', `#/tenants/${tenant}/home`, 'tenant-a@example.test');
  const fresh = await api(secondFixed, '/auth/session');
  const before = await api(operator, `/sessions/${fresh.session_id}`, tenant); assert.equal(before.status, 'active');
  let writes = 0;
  try {
    await p.route(path, async route => {
      if (route.request().method() !== 'POST') return route.continue();
      writes++; const actual = await route.fetch(); assert.ok(actual.ok());
      assert.equal((await api(operator, `/sessions/${fresh.session_id}`, tenant)).status, 'revoked');
      await route.abort('connectionfailed');
    });
    review = await preview(firstSession.account_id);
    await button(review, '确认撤销全部会话').click();
    await p.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
    assert.equal(writes, 1); assert.ok(await p.getByLabel('按用户撤销', { exact: true }).isDisabled());
    const member = await api(operator, `/accounts/${firstSession.account_id}`, tenant); assert.equal(member.account_id, firstSession.account_id);
    assert.ok(await p.getByLabel('按用户撤销', { exact: true }).isDisabled());
    const listPattern = `${operator.host.origin}${operator.host.mount}/admin/sessions?*`;
    await p.route(listPattern, route => route.fulfill({ status: 503, body: '{}' }));
    await button(p, '读取原用户会话首页').click(); await p.getByText(/原用户会话读取失败/).waitFor();
    assert.ok(await p.getByLabel('按用户撤销', { exact: true }).isDisabled());
    await p.unroute(listPattern);
    let pages = 0;
    for (;;) {
      const label = pages ? '读取下一页' : '读取原用户会话首页';
      const got = p.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith('/admin/sessions') && new URL(r.url()).searchParams.get('account_id') === firstSession.account_id);
      await button(p, label).click(); const read = await got; assert.ok(read.ok()); pages++;
      assert.equal(read.request().headers()['x-embedded-idp-tenant-id'], tenant);
      await p.getByText(/当前状态不能证明原请求归因或撤销数量/).waitFor();
      if (await button(p, '结束会话核对').isVisible()) break;
      assert.ok(pages < 10);
    }
    assert.ok(pages >= 2); assert.ok(await p.getByLabel('按用户撤销', { exact: true }).isDisabled());
    await button(p, '结束会话核对').click(); assert.equal(writes, 1);
  } finally { await p.unroute(path); await p.unroute(`${operator.host.origin}${operator.host.mount}/admin/sessions?*`); }
  pass('lost batch response preserves original subject lock through 503 and real multi-page recovery without replay');

  // Exercise existing diagnostic endpoint and its audit record with real requests.
  await goto(p, `#/tenants/${tenant}/diagnostic`);
  await p.getByLabel('业务标识', { exact: true }).fill(`uie_${id}`);
  await p.getByLabel('用户 ID', { exact: true }).fill(firstSession.account_id);
  await p.getByLabel('资源类型', { exact: true }).fill('report');
  await p.getByLabel('动作', { exact: true }).fill('read');
  await button(p, '查询权限').click(); review = dialog(p, '确认权限诊断');
  const diagnosticPath = `${operator.host.origin}${operator.host.mount}/admin/access/check`;
  let diagnosticWrites = 0;
  const countWrite = request => { if (request.url() === diagnosticPath && request.method() === 'POST') diagnosticWrites++; };
  p.on('request', countWrite);
  const diagnosticResponse = p.waitForResponse(r => r.url() === diagnosticPath && r.request().method() === 'POST');
  await button(review, '确认查询').click(); const checked = await diagnosticResponse; assert.ok(checked.ok());
  const result = await checked.json(); assert.ok(result.audit_id); assert.ok(['allow', 'deny'].includes(result.decision));
  const event = await api(operator, `/access/audit-events/${result.audit_id}`, tenant); assert.equal(event.audit_id, result.audit_id);
  await p.getByText(/这是查询时刻的判断结果/).waitFor(); await review.waitFor({ state: 'hidden' }); assert.equal(diagnosticWrites, 1);
  if (!functionalOnly) await p.locator('.management-page').screenshot({ animations: 'disabled', path: `${h.output}/ui-e-diagnostic.png`, mask: [p.locator('input,textarea')] });
  pass('real diagnostic returns audit ID and current decision with independent audit detail read');

  try {
    await p.route(diagnosticPath, async route => {
      if (route.request().method() !== 'POST') return route.continue();
      const original = await route.fetch(); assert.ok(original.ok()); const data = await original.json();
      const read = await api(operator, `/access/audit-events/${data.audit_id}`, tenant); assert.equal(read.audit_id, data.audit_id);
      await route.abort('connectionfailed');
    });
    await button(p, '查询权限').click(); await button(dialog(p, '确认权限诊断'), '确认查询').click();
    await p.getByText(/再次查询是新的操作/).waitFor(); assert.equal(diagnosticWrites, 2);
    assert.ok(await p.getByLabel('业务标识', { exact: true }).isDisabled());
    await accepting(p, () => button(p, '放弃并允许新查询').click());
    assert.ok(await p.getByLabel('业务标识', { exact: true }).isEnabled()); assert.equal(diagnosticWrites, 2);
    await p.unroute(diagnosticPath);
    await button(p, '查询权限').click(); review = dialog(p, '确认权限诊断');
    const next = p.waitForResponse(r => r.url() === diagnosticPath && r.request().method() === 'POST');
    await button(review, '确认查询').click(); assert.ok((await next).ok()); assert.equal(diagnosticWrites, 3);
  } finally { await p.unroute(diagnosticPath); p.off('request', countWrite); }
  pass('lost diagnostic response is not replayed and explicit new query creates a separate audit-producing operation');

  const auditIds = new Set();
  for (let i = 0; i < 51; i++) {
    const created = await writeApi(operator, 'POST', '/access/check', { subject_id: firstSession.account_id, resource_type: 'report', action: 'read' }, tenant, `uie_${id}`);
    assert.ok(created.audit_id); auditIds.add(created.audit_id);
  }
  assert.equal(auditIds.size, 51);
  await goto(p, `#/tenants/${tenant}/audit`);
  await p.getByLabel('操作', { exact: true }).fill('access.check');
  const auditRead = () => p.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith('/admin/access/audit-events') && new URL(r.url()).searchParams.get('operation') === 'access.check');
  let auditResponse = auditRead(); await button(p, '查询').click();
  let auditResult = await auditResponse; assert.ok(auditResult.ok());
  const list = await auditResult.json(); assert.equal(list.items.length, 50); assert.equal(list.has_more, true); assert.ok(list.next_cursor);
  auditResponse = auditRead(); await button(p, '下一页').click();
  auditResult = await auditResponse; assert.equal(new URL(auditResult.url()).searchParams.get('cursor'), list.next_cursor); assert.ok(auditResult.ok());
  const nextPage = await auditResult.json(); assert.ok(nextPage.items.length > 0); await p.getByText('第 2 页', { exact: true }).waitFor();
  auditResponse = auditRead(); await button(p, '查询').click();
  auditResult = await auditResponse; assert.equal(new URL(auditResult.url()).searchParams.get('cursor'), null); assert.ok(auditResult.ok());
  assert.equal((await auditResult.json()).items[0].audit_id, list.items[0].audit_id);
  await p.getByText('第 1 页', { exact: true }).waitFor();
  await p.getByText(/记录时间以 UTC 显示/).waitFor();
  const chosen = list.items[0];
  await button(p, `查看审计记录 ${chosen.audit_id}`).click(); const detail = dialog(p, '审计记录详情');
  const direct = await api(operator, `/access/audit-events/${chosen.audit_id}`, tenant);
  await detail.getByLabel('审计变更内容').waitFor(); if (!functionalOnly) await detail.screenshot({ animations: 'disabled', path: `${h.output}/ui-e-audit-detail.png` });
  assert.ok((await detail.innerText()).includes(chosen.audit_id)); assert.ok((await detail.innerText()).includes(direct.request_id));
  for (const value of [direct.actor_id, direct.actor_session_id, direct.authentication_source, direct.operation, 'UTC']) if (value) assert.ok((await detail.innerText()).includes(value));
  assert.equal(direct.target_domain, tenant);
  assert.deepEqual(JSON.parse(await detail.getByLabel('审计变更内容').innerText()), direct.change);
  await detail.locator('button.ant-drawer-close').click();
  await button(p, '重置').click(); await settle(p);
  pass('51 real diagnostic audit records exercise cursor pagination, same-filter reset and real detail JSON');

  const tenantAudit = `${operator.host.origin}${operator.host.mount}/admin/access/audit-events?*`;
  try {
    for (const injected of ['empty', 403, 503]) {
      await p.route(tenantAudit, route => injected === 'empty'
        ? route.fulfill({ status: 200, json: { items: [], has_more: false, next_cursor: null } })
        : route.fulfill({ status: injected, body: '{}' }));
      const read = p.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith('/access/audit-events'));
      await button(p, '查询').click(); assert.equal((await read).status(), injected === 'empty' ? 200 : injected);
      if (injected === 'empty') await p.getByText('没有符合条件的审计记录', { exact: true }).waitFor();
      else if (injected === 403) await p.getByText('无权读取此管理范围', { exact: true }).waitFor();
      else await p.getByText('读取失败', { exact: true }).waitFor();
      await p.unroute(tenantAudit);
    }
  } finally { await p.unroute(tenantAudit); }
  pass('tenant audit distinguishes injected empty, 403 and 503 without synthesizing records');

  await goto(p, '#/platform/audit');
  const platformPage = await api(operator, '/platform/audit-events?limit=50');
  assert.ok(platformPage.items.length > 0);
  const platformRecord = platformPage.items[0]; assert.equal(platformRecord.target_domain, '0');
  await button(p, `查看审计记录 ${platformRecord.audit_id}`).click();
  const platformDetail = dialog(p, '审计记录详情');
  const realPlatformDetail = await api(operator, `/platform/audit-events/${platformRecord.audit_id}`);
  assert.ok((await platformDetail.innerText()).includes(realPlatformDetail.request_id));
  assert.deepEqual(JSON.parse(await platformDetail.getByLabel('审计变更内容').innerText()), realPlatformDetail.change);
  await platformDetail.locator('button.ant-drawer-close').click();
  pass('platform audit independently reads only platform event and actual change detail');

  // Deliver a real audit response only after a second tab logs out the shared session.
  const late = await open('enabled', `#/tenants/${tenant}/audit`);
  const latePage = late.page;
  const lateIdentity = await api(late, '/auth/session');
  const latePattern = `${late.host.origin}${late.host.mount}/admin/access/audit-events?*`;
  const latch = gate(); let seenResolve, deliveredResolve;
  const seen = new Promise(resolve => { seenResolve = resolve; });
  const delivered = new Promise(resolve => { deliveredResolve = resolve; });
  let count = 0, heldError;
  try {
    await latePage.route(latePattern, async route => {
      try {
        count++;
        const real = await route.fetch(); assert.ok(real.ok());
        const data = await real.json(); assert.ok(Array.isArray(data.items));
        seenResolve(); await latch.promise;
        await route.fulfill({ response: real });
      } catch (error) { heldError = error; seenResolve(); }
      finally { deliveredResolve(); }
    });
    await latePage.getByLabel('操作', { exact: true }).fill('access.check');
    const deliveredResponse = latePage.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith('/admin/access/audit-events') && new URL(r.url()).searchParams.get('operation') === 'access.check');
    await button(latePage, '查询').click(); await bounded(seen, 'actual audit response held');
    if (heldError) throw heldError;
    const other = await late.context.newPage();
    other.on('pageerror', e => h.pageErrors.push(e.name));
    await other.goto(`${late.host.origin}${late.host.ui}/#/tenants/${tenant}/home`);
    await other.locator('.management-shell-header').waitFor();
    const restored = await other.request.get(`${late.host.origin}${late.host.mount}/admin/auth/session`, { headers: { authorization: late.bearer() } });
    assert.ok(restored.ok()); assert.deepEqual(await restored.json(), lateIdentity);
    const logout = other.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/auth/browser/logout'));
    await button(other, '退出登录').click(); assert.ok((await logout).ok());
    await latePage.getByText('其他页面已更改此会话，请重新加载后继续。', { exact: true }).waitFor();
    assert.equal(await latePage.locator('.management-shell').count(), 0);
    latch.release();
    const arrived = await bounded(deliveredResponse, 'held response delivered');
    assert.equal(await arrived.finished(), null); assert.ok((await arrived.json()).items.length > 0);
    await bounded(delivered, 'route fulfillment'); if (heldError) throw heldError;
    await latePage.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await latePage.locator('.management-shell').count(), 0);
    assert.equal(await latePage.getByRole('button', { name: /查看审计记录/ }).count(), 0);
    assert.equal(count, 1);
  } finally { latch.release(); await latePage.unroute(latePattern); }
  pass('real held audit response delivered after shared-session logout cannot restore prior workspace');

  h.supplements.push(async () => {
    // Independent contexts keep history and discarded state separate from the paging cases.
    const sessionsHash = `#/tenants/${tenant}/sessions`;
    const diagnosticHash = `#/tenants/${tenant}/diagnostic`;
    const departureSubject = otherAccount.account_id;
    async function reopenSessions(t) {
      await goto(t.page, sessionsHash);
      await settle(t.page);
    }
    function watchPosts(page, suffix) {
      let count = 0;
      const listener = request => { if (request.method() === 'POST' && new URL(request.url()).pathname.endsWith(suffix)) count++; };
      page.on('request', listener);
      return { count: () => count, close: () => page.off('request', listener) };
    }

    const singleLeave = await open('enabled', sessionsHash);
    await h.prepareDeparture(singleLeave.page, sessionsHash);
    const singleCount = watchPosts(singleLeave.page, `/sessions/${otherSubject}/revoke`);
    try {
      await singleLeave.page.getByLabel('用户 ID', { exact: true }).fill(departureSubject);
      await button(singleLeave.page, '查询').click(); await settle(singleLeave.page);
      await button(singleLeave.page, `查看会话 ${otherSubject}`).click();
      const drawer = dialog(singleLeave.page, '会话详情');
      await drawer.getByText(otherSubject, { exact: false }).waitFor();
      await button(drawer, '撤销会话').click();
      await h.checkDeparture(singleLeave, sessionsHash, async () => {
        const confirmation = dialog(singleLeave.page, '确认撤销会话');
        await confirmation.waitFor();
        assert.ok((await confirmation.innerText()).includes(otherSubject));
        assert.ok((await confirmation.innerText()).includes(departureSubject));
        assert.equal(singleCount.count(), 0);
      });
      assert.equal(singleCount.count(), 0);
      await reopenSessions(singleLeave);
      assert.equal((await api(singleLeave, `/sessions/${otherSubject}`, tenant)).status, 'active');
      assert.equal(singleCount.count(), 0);
    } finally { singleCount.close(); }
    pass('single-session confirmation survives rejected history/hash/menu departure and accepted departure does not submit');

    const batchLeave = await open('enabled', sessionsHash);
    await h.prepareDeparture(batchLeave.page, sessionsHash);
    const batchSuffix = `/accounts/${departureSubject}/sessions/revoke`;
    const batchCount = watchPosts(batchLeave.page, batchSuffix);
    try {
      await batchLeave.page.getByLabel('按用户撤销', { exact: true }).fill(departureSubject);
      await button(batchLeave.page, '核对并撤销全部会话').click();
      await h.checkDeparture(batchLeave, sessionsHash, async () => {
        const confirmation = dialog(batchLeave.page, '确认撤销该用户的全部会话');
        await confirmation.waitFor();
        assert.ok((await confirmation.innerText()).includes(departureSubject));
        assert.equal(await batchLeave.page.getByLabel('按用户撤销', { exact: true }).inputValue(), departureSubject);
        assert.equal(batchCount.count(), 0);
      });
      await reopenSessions(batchLeave);
      assert.equal(await batchLeave.page.getByLabel('按用户撤销', { exact: true }).inputValue(), '');
      assert.equal((await api(batchLeave, `/sessions/${otherSubject}`, tenant)).status, 'active');
      assert.equal(batchCount.count(), 0);
    } finally { batchCount.close(); }
    pass('batch confirmation survives rejected history/hash/menu departure and accepted departure discards original draft without submit');

    const unknownLeave = await open('enabled', sessionsHash);
    await h.prepareDeparture(unknownLeave.page, sessionsHash);
    const unknownPath = `${unknownLeave.host.origin}${unknownLeave.host.mount}/admin${batchSuffix}`;
    const unknownCount = watchPosts(unknownLeave.page, batchSuffix);
    try {
      await unknownLeave.page.route(unknownPath, async route => {
        if (route.request().method() !== 'POST') return route.continue();
        const actual = await route.fetch(); assert.ok(actual.ok());
        assert.equal((await api(unknownLeave, `/sessions/${otherSubject}`, tenant)).status, 'revoked');
        await route.abort('connectionfailed');
      });
      await unknownLeave.page.getByLabel('按用户撤销', { exact: true }).fill(departureSubject);
      await button(unknownLeave.page, '核对并撤销全部会话').click();
      await button(dialog(unknownLeave.page, '确认撤销该用户的全部会话'), '确认撤销全部会话').click();
      await unknownLeave.page.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
      await h.checkDeparture(unknownLeave, sessionsHash, async () => {
        await unknownLeave.page.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).waitFor();
        await unknownLeave.page.getByText(`待核对原范围：${tenant} / ${departureSubject}。回读不能证明请求归因或原撤销数量。`, { exact: true }).waitFor();
        assert.ok(await unknownLeave.page.getByLabel('按用户撤销', { exact: true }).isDisabled());
        assert.equal(await unknownLeave.page.getByLabel('按用户撤销', { exact: true }).inputValue(), departureSubject);
        assert.equal(unknownCount.count(), 1);
      });
      await reopenSessions(unknownLeave);
      assert.equal(await unknownLeave.page.getByLabel('按用户撤销', { exact: true }).inputValue(), '');
      assert.equal(await unknownLeave.page.getByText('写入结果未确认，请先核对原对象，勿重复提交', { exact: true }).count(), 0);
      assert.equal((await api(unknownLeave, `/sessions/${otherSubject}`, tenant)).status, 'revoked');
      assert.equal(unknownCount.count(), 1);
    } finally { await unknownLeave.page.unroute(unknownPath); unknownCount.close(); }
    pass('lost real batch response keeps original subject locked through rejected departures and is not replayed after leaving');

    async function fillDiagnostic(page) {
      await page.getByLabel('业务标识', { exact: true }).fill(`uie_${id}`);
      await page.getByLabel('用户 ID', { exact: true }).fill(departureSubject);
      await page.getByLabel('资源类型', { exact: true }).fill('report');
      await page.getByLabel('动作', { exact: true }).fill('read');
    }
    async function assertDiagnostic(page) {
      assert.equal(await page.getByLabel('业务标识', { exact: true }).inputValue(), `uie_${id}`);
      assert.equal(await page.getByLabel('用户 ID', { exact: true }).inputValue(), departureSubject);
      assert.equal(await page.getByLabel('资源类型', { exact: true }).inputValue(), 'report');
      assert.equal(await page.getByLabel('动作', { exact: true }).inputValue(), 'read');
    }
    for (const mode of ['draft', 'confirmation']) {
      const diagLeave = await open('enabled', diagnosticHash);
      await h.prepareDeparture(diagLeave.page, diagnosticHash);
      const count = watchPosts(diagLeave.page, '/access/check');
      try {
        await fillDiagnostic(diagLeave.page);
        if (mode === 'confirmation') await button(diagLeave.page, '查询权限').click();
        await h.checkDeparture(diagLeave, diagnosticHash, async () => {
          await assertDiagnostic(diagLeave.page);
          if (mode === 'confirmation') {
            const confirmation = dialog(diagLeave.page, '确认权限诊断'); await confirmation.waitFor();
            assert.ok((await confirmation.innerText()).includes(departureSubject));
            assert.ok((await confirmation.innerText()).includes(`uie_${id}`));
          }
          assert.equal(count.count(), 0);
        });
        await goto(diagLeave.page, diagnosticHash);
        assert.equal(await diagLeave.page.getByLabel('业务标识', { exact: true }).inputValue(), '');
        assert.equal(await diagLeave.page.getByLabel('用户 ID', { exact: true }).inputValue(), '');
        assert.equal(count.count(), 0);
      } finally { count.close(); }
      pass(`diagnostic ${mode} survives rejected history/hash/menu departure and accepted departure discards it without submit`);
    }

    const diagUnknown = await open('enabled', diagnosticHash);
    await h.prepareDeparture(diagUnknown.page, diagnosticHash);
    const diagPath = `${diagUnknown.host.origin}${diagUnknown.host.mount}/admin/access/check`;
    const diagCount = watchPosts(diagUnknown.page, '/access/check');
    let auditId;
    try {
      await diagUnknown.page.route(diagPath, async route => {
        if (route.request().method() !== 'POST') return route.continue();
        const actual = await route.fetch(); assert.ok(actual.ok());
        const data = await actual.json(); auditId = data.audit_id; assert.ok(auditId);
        const record = await api(diagUnknown, `/access/audit-events/${auditId}`, tenant);
        assert.equal(record.audit_id, auditId); assert.equal(record.operation, 'access.check');
        await route.abort('connectionfailed');
      });
      await fillDiagnostic(diagUnknown.page);
      await button(diagUnknown.page, '查询权限').click();
      await button(dialog(diagUnknown.page, '确认权限诊断'), '确认查询').click();
      await diagUnknown.page.getByText(/再次查询是新的操作/).waitFor();
      await h.checkDeparture(diagUnknown, diagnosticHash, async () => {
        await diagUnknown.page.getByText(/再次查询是新的操作/).waitFor();
        await assertDiagnostic(diagUnknown.page);
        assert.ok(await diagUnknown.page.getByLabel('业务标识', { exact: true }).isDisabled());
        assert.equal(diagCount.count(), 1);
      });
      await goto(diagUnknown.page, diagnosticHash);
      assert.equal(await diagUnknown.page.getByLabel('业务标识', { exact: true }).inputValue(), '');
      assert.equal(await diagUnknown.page.getByText(/再次查询是新的操作/).count(), 0);
      const record = await api(diagUnknown, `/access/audit-events/${auditId}`, tenant);
      assert.equal(record.audit_id, auditId); assert.equal(diagCount.count(), 1);
    } finally { await diagUnknown.page.unroute(diagPath); diagCount.close(); }
    pass('lost real diagnostic response retains original draft and lock through rejected departures and does not replay');

  });
}
