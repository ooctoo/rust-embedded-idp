// Disposable UI-E device checks; caller owns fixture validation and cleanup.
import assert from 'node:assert/strict';
import { randomUUID, generateKeyPairSync, createHash } from 'node:crypto';

export async function runDeviceChecks(h) {
  const { fixture, id, open, api, writeApi, sql, button, dialog, accepting, pass } = h;
  const schema = fixture.schemas.enabled;
  assert.match(schema, /^uib_enabled_[a-f0-9]+$/); assert.match(id, /^[a-f0-9]+$/);
  const t = await open('enabled', '#/tenants/tenant-a/devices'), p = t.page, tenant = 'tenant-a';
  const users = [];
  for (const suffix of ['a', 'b', 'c']) {
    const value = await writeApi(t, 'POST', '/platform/accounts', { tenant_id: tenant, email: `uie-device-${suffix}-${id}@example.test`, password: fixture.password });
    users.push(value.account.account_id); assert.match(users.at(-1), /^[0-9a-f-]{36}$/);
  }
  await writeApi(t, 'POST', `/members/${users[0]}/bind`, {}, 'tenant-b');
  const ids = Object.fromEntries(['active', 'pending', 'disabled', 'revoked', 'receipt', 'uncertain', 'other'].map(k => [k, randomUUID()]));
  const bindings = [randomUUID(), randomUUID(), randomUUID()];
  const sessions = [randomUUID(), randomUUID(), randomUUID(), randomUUID()];
  const now = Math.floor(Date.now() / 1000), name = k => `UIE ${k} ${id}`;
  const { publicKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' });
  const publicJwk = JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: jwk.x });
  const keyId = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url');
  assert.match(keyId, /^[A-Za-z0-9_-]{43}$/); assert.match(jwk.x, /^[A-Za-z0-9_-]{43}$/);
  await sql('enabled', `begin;
    insert into ${schema}.devices(tenant_id,id,client_id,device_name,proof_key_id,status,registered_at_epoch) values
      ('tenant-a','${ids.active}','management-ui-b','${name('active')}','${keyId}','active',${now}),
      ('tenant-a','${ids.pending}','management-ui-b','${name('pending')}',null,'pending',${now}),
      ('tenant-a','${ids.disabled}','management-ui-b','${name('disabled')}',null,'disabled',${now}),
      ('tenant-a','${ids.revoked}','management-ui-b','${name('revoked')}',null,'revoked',${now}),
      ('tenant-a','${ids.receipt}','management-ui-b','${name('receipt')}',null,'active',${now}),
      ('tenant-a','${ids.uncertain}','management-ui-b','${name('uncertain')}',null,'active',${now}),
      ('tenant-b','${ids.other}','management-ui-b','${name('other')}',null,'active',${now});
    insert into ${schema}.device_proof_keys(tenant_id,key_id,device_id,algorithm,public_jwk,version,status,registered_at_epoch)
      values('tenant-a','${keyId}','${ids.active}','ed25519','${publicJwk}',1,'active',${now});
    insert into ${schema}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values
      ('tenant-a','${bindings[0]}','${users[0]}','${ids.active}','active',${now}),
      ('tenant-a','${bindings[1]}','${users[1]}','${ids.active}','suspended',${now}),
      ('tenant-a','${bindings[2]}','${users[2]}','${ids.active}','active',${now});
    insert into ${schema}.auth_sessions(purpose,tenant_id,id,account_id,client_id,device_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values
      ('management','tenant-a','${sessions[0]}','${users[0]}','management-ui-b','${ids.active}','active',${now},${now + 3600},1,${now}),
      ('management','tenant-a','${sessions[1]}','${users[1]}','management-ui-b','${ids.active}','active',${now},${now + 3600},1,${now}),
      ('management','tenant-a','${sessions[2]}','${users[2]}','management-ui-b','${ids.active}','active',${now},${now + 3600},1,${now}),
      ('management','tenant-b','${sessions[3]}','${users[0]}','management-ui-b','${ids.other}','active',${now},${now + 3600},1,${now});
    commit;`);
  await p.getByLabel('客户端 ID', { exact: true }).fill('management-ui-b'); await button(p, '查询').click();
  const device = key => api(t, `/devices/${ids[key]}`, tenant);
  const binding = i => api(t, `/devices/${ids.active}/bindings/${bindings[i]}`, tenant);
  const detail = async key => { await button(p, `查看设备 ${name(key)}`).click(); const d = dialog(p, '设备详情与状态'); await d.getByText(new RegExp(ids[key])).first().waitFor(); return d; };
  const close = async d => { await d.locator('button.ant-drawer-close').click(); await d.waitFor({ state: 'hidden' }); };
  const stateAction = async (d, action, title, ok, version) => {
    await button(d, action).click(); const review = dialog(p, title);
    assert.ok((await review.innerText()).includes(`版本 ${version}`));
    await review.getByLabel('操作原因').fill('合成设备处置');
    const responsePromise = p.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.startsWith(`${t.host.mount}/admin/devices/`) && !new URL(r.url()).pathname.includes('/operations/'));
    await button(review, ok).click(); const response = await responsePromise; assert.ok(response.ok());
    const body = response.request().postDataJSON(); assert.equal(body.expected_version, version); assert.equal(body.reason, '合成设备处置'); assert.match(body.operation_id, /^[0-9a-f-]{36}$/);
    await review.waitFor({ state: 'hidden' }); await h.settle(p); return response;
  };
  for (const [k, status] of [['pending','pending'],['active','active'],['disabled','disabled'],['revoked','revoked']]) assert.equal((await device(k)).status, status);
  let d = await detail('pending'); assert.ok(await button(d, '停用设备').isEnabled()); assert.equal(await button(d, '重新启用').count(), 0); await close(d);
  d = await detail('disabled'); assert.ok(await button(d, '重新启用').isDisabled()); await close(d);
  d = await detail('revoked'); assert.equal(await button(d, '撤销设备').count(), 0); await close(d);
  pass('device four states and prohibited terminal or keyless actions');
  d = await detail('active');
  for (let i = 0; i < 2; i++) {
    await button(d, `解绑用户 ${users[i]} 的设备绑定`).click(); const review = dialog(p, '确认解绑人员设备');
    const summary = await review.innerText(); assert.ok(summary.includes(bindings[i])); assert.ok(summary.includes(users[i])); assert.ok(summary.includes('版本 1'));
    await review.getByLabel('解绑原因').fill('合成人员解绑');
    const responsePromise = p.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith(`/bindings/${bindings[i]}/unbind`));
    await button(review, '确认解绑').click(); const response = await responsePromise; assert.ok(response.ok());
    assert.equal(response.request().postDataJSON().expected_version, 1); assert.equal(response.request().postDataJSON().reason, '合成人员解绑');
    assert.equal((await binding(i)).status, 'unbound'); await review.waitFor({ state: 'hidden' }); await h.settle(p);
  }
  assert.equal((await binding(2)).status, 'active');
  const sessionStatus = async i => (await api(t, `/sessions/${sessions[i]}`, i === 3 ? 'tenant-b' : tenant)).status;
  assert.equal(await sessionStatus(0), 'revoked'); assert.equal(await sessionStatus(1), 'revoked'); assert.equal(await sessionStatus(2), 'active'); assert.equal(await sessionStatus(3), 'active');
  pass('active and suspended bindings unbind independently; other user and tenant sessions survive');
  let cancelledPosts = 0; const countCancelled = request => { if (request.method() === 'POST' && request.url().includes('/admin/devices/')) cancelledPosts++; }; p.on('request', countCancelled);
  await button(d, '停用设备').click(); let review = dialog(p, '确认停用设备');
  await p.setViewportSize({ width: 320, height: 800 });
  const region = review.getByRole('region', { name: '操作范围与后果' });
  assert.equal(await region.getAttribute('tabindex'), '0');
  await review.getByLabel('操作原因').fill('测'.repeat(171)); assert.ok(await button(review, '确认停用').isDisabled());
  await review.getByLabel('操作原因').fill('合法原因');
  await p.waitForFunction(() => document.getAnimations().every(a => a.playState !== 'running' || a.effect?.getTiming().iterations === Infinity));
  const reviewBox = await review.boundingBox(); assert.ok(reviewBox.width >= 280 && reviewBox.x >= 0 && reviewBox.x + reviewBox.width <= 321);
  await review.screenshot({ animations: 'disabled', path: `${h.output}/ui-e-device-320.png`, mask: [review.locator('input,textarea')] }); await accepting(p, () => button(review, '取消').click()); await review.waitFor({ state: 'hidden' });
  await p.setViewportSize({ width: 1440, height: 1000 }); p.off('request', countCancelled); assert.equal(cancelledPosts, 0); assert.equal((await device('active')).version, 1);
  pass('device reason enforces UTF-8 byte limit and discarded confirmation sends no mutation');
  await stateAction(d, '停用设备', '确认停用设备', '确认停用', 1);
  assert.equal((await device('active')).status, 'disabled'); assert.equal((await binding(2)).status, 'active'); assert.equal(await sessionStatus(2), 'revoked'); assert.equal(await sessionStatus(3), 'active');
  await stateAction(d, '重新启用', '确认重新启用设备', '确认启用', 2);
  assert.equal((await device('active')).status, 'active'); assert.equal(await sessionStatus(2), 'revoked');
  await stateAction(d, '撤销设备', '确认撤销设备', '确认撤销', 3);
  assert.equal((await device('active')).status, 'revoked'); assert.equal((await binding(2)).status, 'unbound');
  const keyState = await sql('enabled', `select status from ${schema}.device_proof_keys where tenant_id='tenant-a' and key_id='${keyId}';`); assert.equal(keyState.trim(), 'retired');
  assert.equal(await sessionStatus(3), 'active');
  pass('real disable enable revoke preserves version, credential and key lifecycle'); await close(d);
  d = await detail('receipt');
  const path = `${t.host.origin}${t.host.mount}/admin/devices/${ids.receipt}/disable`; let posts = 0, receipts = 0;
  const onRequest = req => { if (req.method() === 'GET' && req.url().includes(`/devices/${ids.receipt}/operations/`)) receipts++; };
  p.on('request', onRequest);
  try {
    await p.route(path, async route => { posts++; const response = await route.fetch(); assert.ok(response.ok()); assert.equal((await device('receipt')).status, 'disabled'); await route.abort('connectionfailed'); });
    await button(d, '停用设备').click(); review = dialog(p, '确认停用设备'); await review.getByLabel('操作原因').fill('回执核对'); await button(review, '确认停用').click();
    await d.getByText(/已确认设备状态变更/).waitFor(); assert.equal(posts, 1); assert.equal(receipts, 1); assert.equal((await device('receipt')).status, 'disabled');
  } finally { await p.unroute(path); p.off('request', onRequest); }
  pass('lost real device write response recovers original operation receipt without replay'); await close(d);
  d = await detail('uncertain');
  const writePath = `${t.host.origin}${t.host.mount}/admin/devices/${ids.uncertain}/disable`, readPath = `${t.host.origin}${t.host.mount}/admin/devices/${ids.uncertain}`; posts = 0;
  try {
    await p.route(writePath, async route => { posts++; const response = await route.fetch(); assert.ok(response.ok()); assert.equal((await device('uncertain')).status, 'disabled'); await route.abort('connectionfailed'); });
    await p.route(`${readPath}/operations/*`, route => route.fulfill({ status: 503, body: '{}' }));
    await button(d, '停用设备').click(); review = dialog(p, '确认停用设备'); await review.getByLabel('操作原因').fill('结果核对'); await button(review, '确认停用').click();
    await d.getByText(/页面未取得完整结果/).waitFor(); assert.ok(await button(d, '停用设备').isDisabled()); assert.equal(posts, 1);
    await p.route(readPath, route => route.fulfill({ status: 503, body: '{}' }));
    await accepting(p, () => button(d, '重新加载设备').click()); await d.getByText('读取失败', { exact: true }).waitFor(); assert.equal(posts, 1);
    await p.unroute(readPath); await accepting(p, () => button(d, '重新加载设备').click()); await d.getByText(/状态：已停用/).waitFor(); assert.ok(await button(d, '撤销设备').isDisabled()); await button(d, '结束设备核对').click(); assert.ok(await button(d, '撤销设备').isEnabled()); assert.equal(posts, 1);
  } finally { await p.unroute(writePath); await p.unroute(`${readPath}/operations/*`); await p.unroute(readPath); }
  pass('receipt and original device read failure retain lock until original device reload and explicit finish, without replay');
  await close(d);
  const extraDevice = randomUUID(), extraBinding = randomUUID();
  await sql('enabled', `insert into ${schema}.devices(tenant_id,id,client_id,device_name,status,registered_at_epoch) values('tenant-a','${extraDevice}','management-ui-b','UIE binding recovery ${id}','active',${now}); insert into ${schema}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values('tenant-a','${extraBinding}','${users[0]}','${extraDevice}','active',${now});`);
  await button(p, '查询').click(); await button(p, `查看设备 UIE binding recovery ${id}`).click(); d = dialog(p, '设备详情与状态');
  const bindingPath = `${t.host.origin}${t.host.mount}/admin/devices/${extraDevice}/bindings/${extraBinding}`;
  const operations = `${t.host.origin}${t.host.mount}/admin/devices/${extraDevice}/operations/*`; let unbindPosts = 0;
  try {
    await p.route(`${bindingPath}/unbind`, async route => {
      unbindPosts++; const actual = await route.fetch(); assert.ok(actual.ok());
      assert.equal((await api(t, `/devices/${extraDevice}/bindings/${extraBinding}`, tenant)).status, 'unbound'); await route.abort('connectionfailed');
    });
    await p.route(operations, route => route.fulfill({ status: 503, body: '{}' }));
    await button(d, `解绑用户 ${users[0]} 的设备绑定`).click(); review = dialog(p, '确认解绑人员设备'); await review.getByLabel('解绑原因').fill('绑定未知核对');
    await button(review, '确认解绑').click(); await d.getByText(/待核对原绑定/).waitFor();
    assert.ok(await button(d, '撤销设备').isDisabled());
    await p.route(bindingPath, route => route.fulfill({ status: 503, body: '{}' }));
    await button(d, '重新读取原绑定').click(); await d.getByText('读取失败', { exact: true }).waitFor(); assert.equal(await button(d, '结束绑定核对').count(), 0);
    await p.unroute(bindingPath); await button(d, '重新读取原绑定').click(); await d.getByText(new RegExp(`当前绑定：${extraBinding}，已解绑`)).waitFor();
    assert.ok(await button(d, '撤销设备').isDisabled()); await button(d, '结束绑定核对').click(); await p.waitForFunction(el => !el.disabled, await button(d, '撤销设备').elementHandle()); assert.ok(await button(d, '撤销设备').isEnabled()); assert.equal(unbindPosts, 1);
  } finally { await p.unroute(`${bindingPath}/unbind`); await p.unroute(operations); await p.unroute(bindingPath); }
  pass('lost unbind receipt preserves original binding and parent write lock through read failure until explicit finish without replay');

  h.supplements.push(async () => {
    await close(d);
    // Isolated targets for late-read and departure checks; no audit rows are fabricated.
    const lateDevice = randomUUID(), lateBinding = randomUUID(), departureDevice = randomUUID();
    await sql('enabled', `insert into ${schema}.devices(tenant_id,id,client_id,device_name,status,registered_at_epoch) values
      ('tenant-a','${lateDevice}','management-ui-b','UIE late ${id}','active',${now}),
      ('tenant-a','${departureDevice}','management-ui-b','UIE departure ${id}','active',${now});
      insert into ${schema}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch)
      values('tenant-a','${lateBinding}','${users[0]}','${lateDevice}','active',${now});`);
    const hash = '#/tenants/tenant-a/devices';
    const fresh = await open('enabled', hash), q = fresh.page;
    const targetPath = `${fresh.host.origin}${fresh.host.mount}/admin/devices/${lateDevice}`;
    let postCount = 0;
    const countWrites = request => { if (request.method() === 'POST' && request.url().includes('/admin/devices/')) postCount++; };
    q.on('request', countWrites);
    const show = async label => {
      await button(q, `查看设备 UIE ${label} ${id}`).click();
      const drawer = dialog(q, '设备详情与状态');
      await drawer.getByText(new RegExp(label === 'late' ? lateDevice : departureDevice)).first().waitFor();
      return drawer;
    };
    // Fulfill the original successful HTTP response after its drawer was closed.
    async function holdRead(path, start, afterHeld, verify, label) {
      const latch = h.gate(); let observedResolve, completedResolve, failure, delivered = false, count = 0;
      const observed = new Promise(resolve => { observedResolve = resolve; });
      const completed = new Promise(resolve => { completedResolve = resolve; });
      try {
        await q.route(path, async route => {
          try {
            count++; const actual = await route.fetch(); assert.ok(actual.ok());
            observedResolve(); await latch.promise; await route.fulfill({ response: actual }); delivered = true;
          } catch (error) { failure = error; observedResolve(); }
          finally { completedResolve(); }
        });
        const response = q.waitForResponse(r => r.request().method() === 'GET' && r.url() === path);
        await start(); await h.bounded(observed, `${label}: real read held`); if (failure) throw failure;
        await afterHeld(); latch.release();
        assert.equal(await (await h.bounded(response, `${label}: response delivered`)).finished(), null);
        await h.bounded(completed, `${label}: route completed`); if (failure) throw failure;
        assert.ok(delivered); assert.equal(count, 1); await h.settle(q); await verify();
      } finally { latch.release(); await q.unroute(path); }
    }
    await holdRead(targetPath,
      () => button(q, `查看设备 UIE late ${id}`).click(),
      async () => {
        const heldDrawer = dialog(q, '设备详情与状态'); await heldDrawer.locator('button.ant-drawer-close').click();
        await heldDrawer.waitFor({ state: 'hidden' }); await show('departure');
      },
      async () => {
        const current = dialog(q, '设备详情与状态'); assert.ok((await current.innerText()).includes(departureDevice));
        assert.ok(!(await current.innerText()).includes(lateDevice)); assert.equal(postCount, 0);
      }, 'device GET');
    pass('held device GET delivered after close cannot replace a different device or write');
    await close(dialog(q, '设备详情与状态'));
    let lateDrawer = await show('late');
    const bindingReadPath = `${targetPath}/bindings/${lateBinding}`;
    await holdRead(bindingReadPath,
      () => button(lateDrawer, `解绑用户 ${users[0]} 的设备绑定`).click(),
      async () => {
        // A refused close preserves the original drawer and in-flight guard.
        await lateDrawer.locator('button.ant-drawer-close').click();
        assert.ok((await lateDrawer.innerText()).includes(lateDevice));
        assert.ok(await button(lateDrawer, '撤销设备').isDisabled());
        await h.accepting(q, () => lateDrawer.locator('button.ant-drawer-close').click());
        await lateDrawer.waitFor({ state: 'hidden' });
        await h.goto(q, '#/tenants/tenant-b/devices');
        await button(q, `查看设备 ${name('other')}`).click();
        const next = dialog(q, '设备详情与状态');
        await next.getByText(new RegExp(ids.other)).first().waitFor();
        await button(next, '停用设备').click();
        await dialog(q, '确认停用设备').getByLabel('操作原因').fill('新目标确认');
      },
      async () => {
        const current = dialog(q, '设备详情与状态'); const text = await current.innerText();
        assert.ok(text.includes('tenant-b')); assert.ok(text.includes(ids.other));
        assert.ok(!text.includes(lateDevice)); assert.ok(!text.includes(lateBinding));
        assert.equal(await dialog(q, '确认解绑人员设备').count(), 0);
        assert.equal(await dialog(q, '确认停用设备').getByLabel('操作原因').inputValue(), '新目标确认');
        // The new confirmation owns the drawer; its close guard must survive
        // delivery of the previous tenant's read. No new write is in flight.
        assert.equal(await current.locator('button.ant-drawer-close').count(), 0);
        assert.ok(await dialog(q, '确认停用设备').isVisible()); assert.equal(postCount, 0);
      }, 'binding GET');
    pass('held binding GET refused close preserves original, accepted close prevents late confirmation across tenants');
    await h.accepting(q, () => button(dialog(q, '确认停用设备'), '取消').click());
    await close(dialog(q, '设备详情与状态'));
    await h.goto(q, hash);
    await h.prepareDeparture(q, hash);
    let departDrawer = await show('departure');
    await button(departDrawer, '停用设备').click();
    let draft = dialog(q, '确认停用设备'); await draft.getByLabel('操作原因').fill('离页草稿');
    await h.checkDeparture(fresh, hash, async () => {
      assert.equal(await draft.getByLabel('操作原因').inputValue(), '离页草稿');
      assert.ok((await draft.innerText()).includes(departureDevice)); assert.equal(postCount, 0);
    });
    await h.goto(q, hash); departDrawer = await show('departure');
    assert.equal((await api(fresh, `/devices/${departureDevice}`, tenant)).status, 'active');
    assert.equal(await dialog(q, '确认停用设备').count(), 0); assert.equal(postCount, 0);
    await close(departDrawer);
    pass('device confirmation reason survives refused departures and accepted departure discards it without write');
    await h.prepareDeparture(q, hash); departDrawer = await show('departure');
    const depPath = `${fresh.host.origin}${fresh.host.mount}/admin/devices/${departureDevice}/disable`;
    try {
      await q.route(depPath, async route => { const actual = await route.fetch(); assert.ok(actual.ok());
        assert.equal((await api(fresh, `/devices/${departureDevice}`, tenant)).status, 'disabled'); await route.abort('connectionfailed'); });
      await q.route(`${fresh.host.origin}${fresh.host.mount}/admin/devices/${departureDevice}/operations/*`, route => route.fulfill({ status: 503, body: '{}' }));
      await button(departDrawer, '停用设备').click(); draft = dialog(q, '确认停用设备');
      await draft.getByLabel('操作原因').fill('离页未知核对'); await button(draft, '确认停用').click();
      await departDrawer.getByText(/待核对原设备/).waitFor();
      await h.checkDeparture(fresh, hash, async () => {
        assert.ok((await departDrawer.innerText()).includes(departureDevice));
        assert.ok(await button(departDrawer, '停用设备').isDisabled()); assert.equal(postCount, 1);
      });
      await h.goto(q, hash); departDrawer = await show('departure');
      assert.equal((await api(fresh, `/devices/${departureDevice}`, tenant)).status, 'disabled');
      assert.equal(await departDrawer.getByText(/待核对原设备/).count(), 0); assert.equal(postCount, 1);
      await close(departDrawer);
    } finally { await q.unroute(depPath); await q.unroute(`${fresh.host.origin}${fresh.host.mount}/admin/devices/${departureDevice}/operations/*`); q.off('request', countWrites); }
    pass('unknown device outcome remains locked on refused departures and accepted leave never replays write');
  });

}
