// UI-F integration supplement. Only an explicitly owned disposable fixture is accepted.
import { browserLaunchOptions } from './management_browser.mjs';
import { functionalOnly, createFunctionalCoverage, finalizeFunctionalRun } from './management_functional.mjs';
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile, realpath } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { dirname, basename, join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { runStateChecks } from './management_console_states.mjs';
import { runTenantChecks } from './management_console_tenant.mjs';
import { runPaginationChecks } from './management_console_pagination.mjs';
import { assertControlLabels } from './management_console_labels.mjs';
import { runPermissionFocusChecks } from './management_console_focus.mjs';

assert.ok(process.env.IDP_UI_TEST_FIXTURE && process.env.IDP_UI_PLAYWRIGHT_PATH && process.env.IDP_UI_BROWSER_EXECUTABLE);
const statePath = await realpath(process.env.IDP_UI_TEST_FIXTURE), fixtureDir = dirname(statePath);
assert.equal(dirname(fixtureDir), await realpath(tmpdir()));
assert.match(basename(fixtureDir), /^idp-ui-b-[a-zA-Z0-9_-]+$/);
const fixture = JSON.parse(await readFile(statePath, 'utf8'));
assert.equal(await realpath(fixture.dir), fixtureDir);
assert.match(fixture.container, /^idp-ui-b-[a-f0-9]+$/);
assert.equal(execFileSync('docker', ['inspect', '--format', '{{index .Config.Labels "idp.ui-b.fixture"}}', fixture.container], { encoding: 'utf8' }).trim(), fixtureDir);
for (const [mode, schema] of Object.entries(fixture.schemas)) assert.match(schema, new RegExp(`^uib_${mode}_[a-f0-9]+$`));
for (const host of Object.values(fixture.hosts)) { assert.equal(new URL(host.origin).hostname, '127.0.0.1'); assert.ok(host.mount.startsWith('/') && host.ui.startsWith('/')); }
const { chromium } = await import(pathToFileURL(process.env.IDP_UI_PLAYWRIGHT_PATH).href);
const browser = await chromium.launch(browserLaunchOptions());
const output = process.env.IDP_UI_OUTPUT_DIR ?? fixtureDir;
await mkdir(output, { recursive: true });
const coverage = createFunctionalCoverage('console', output);
const cases = [], pageErrors = [], contexts = [], contrast = [], layouts = [], labels = [], accepted = new WeakSet();
const layoutWidths = !functionalOnly && process.env.IDP_UI_N2_LAYOUT === '1' ? [320, 390, 767, 768, 1023, 1024, 1440] : [320, 390, 768, 1024, 1440];
const pass = name => { coverage.pass(name); cases.push(name); console.log(`PASS ${name}`); };
const button = (p, name) => p.getByRole('button', { name: new RegExp('^' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/([\u3400-\u9fff])(?=[\u3400-\u9fff])/g, '$1\\s*') + '$') });
const settle = p => p.waitForFunction(() => !document.querySelector('.ant-spin-spinning, .ant-spin-blur'));
const confirmationFocus = [];
const confirmationKeyboard = [];
let failure;
async function goto(p, hash) {
  accepted.add(p);
  try {
    await p.evaluate(value => { location.hash = value; }, hash);
    await p.waitForFunction(h => location.hash === h, hash);
    await p.evaluate(() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))));
    await settle(p);
  } finally { accepted.delete(p); }
}
async function open(key, hash, viewport = { width: 1440, height: 1000 }) {
  const host = fixture.hosts[key];
  if (functionalOnly) viewport = { width: 1440, height: 1000 };
  const context = await browser.newContext({ viewport, reducedMotion: 'reduce' }); contexts.push(context);
  const page = await context.newPage(); page.setDefaultTimeout(15000);
  page.on('pageerror', e => pageErrors.push(e.name));
  page.on('dialog', d => accepted.has(page) && d.type() === 'confirm' ? d.accept() : d.dismiss());
  let token;
  const writes = [];
  page.on('request', r => {
    const path = new URL(r.url()).pathname;
    if (path.startsWith(`${host.mount}/admin/`)) {
      token = r.headers().authorization ?? token;
      if (['POST', 'PATCH', 'DELETE'].includes(r.method()) && !path.startsWith(`${host.mount}/admin/auth/`)) writes.push({ method: r.method(), path });
    }
  });
  await page.goto(host.origin + host.ui + '/' + hash);
  await page.getByLabel('邮箱', { exact: true }).fill(key === 'choose' || key === 'fixed' ? 'tenant-a@example.test' : 'admin@example.test');
  await page.getByLabel('密码', { exact: true }).fill(fixture.password);
  await button(page, '登录').click();
  if (key === 'choose') await button(page, '进入 UI B tenant-a').click();
  await page.locator('.management-shell').waitFor(); await settle(page);
  return { page, host, context, writes, bearer: () => token };
}
async function api(t, path, target) {
  const response = await t.page.request.get(`${t.host.origin}${t.host.mount}/admin${path}`, { headers: { authorization: t.bearer(), ...(target ? { 'x-embedded-idp-tenant-id': target } : {}) } });
  assert.ok(response.ok(), `${path.split('?')[0]} GET: ${response.status()}`); return response.json();
}
async function focused(p, locator) {
  await p.waitForFunction(el => el === document.activeElement, await locator.elementHandle());
}
async function focusCycle(p, modal) {
  // Visibility can precede the component's after-open focus callback.
  await p.waitForFunction(el => (el.closest('.ant-drawer') ?? el).contains(document.activeElement), await modal.elementHandle());
  for (let i = 0; i < 16; i++) {
    await p.keyboard.press('Tab');
    assert.ok(await modal.evaluate(el => el.contains(document.activeElement) || !!document.activeElement?.hasAttribute('data-sentinel') && document.activeElement.closest('.ant-drawer') === el.closest('.ant-drawer')), 'Tab remains in the named dialog');
  }
  for (let i = 0; i < 16; i++) {
    await p.keyboard.press('Shift+Tab');
    assert.ok(await modal.evaluate(el => el.contains(document.activeElement) || !!document.activeElement?.hasAttribute('data-sentinel') && document.activeElement.closest('.ant-drawer') === el.closest('.ant-drawer')), 'Shift+Tab remains in the named dialog');
  }
}
async function colorRatio(locator, label, minimum = 4.5, property = 'color', background) {
  const sample = await locator.first().evaluate((el, { property, background }) => {
    const parse = s => s.match(/[\d.]+/g).map(Number);
    const blend = (fg, bg) => fg.slice(0, 3).map((c, i) => c * (fg[3] ?? 1) + bg[i] * (1 - (fg[3] ?? 1)));
    let bg = [255, 255, 255];
    const chain = []; for (let n = el; n; n = n.parentElement) chain.unshift(n);
    for (const n of chain) bg = blend(parse(getComputedStyle(n).backgroundColor), bg);
    if (background) bg = parse(background);
    const raw = getComputedStyle(el).getPropertyValue(property);
    const fg = blend(parse(raw), bg);
    return { foreground: fg, background: bg, raw };
  }, { property, background });
  const lum = c => c.map(v => v / 255).map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4).reduce((sum, v, i) => sum + v * [.2126, .7152, .0722][i], 0);
  const a = lum(sample.foreground), b = lum(sample.background), ratio = (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
  contrast.push({ label, property, ...sample, ratio: Number(ratio.toFixed(2)), minimum });
  assert.ok(ratio >= minimum, `${label}: ${ratio.toFixed(2)} < ${minimum}`);
}
async function layout(p, label, width) {
  await p.setViewportSize({ width, height: !functionalOnly && process.env.IDP_UI_N2_LAYOUT === '1' ? 600 : 1000 });
  const result = await p.evaluate(() => {
    const ids = [...document.querySelectorAll('input[id],select[id],textarea[id]')].map(el => el.id);
    return { viewport: innerWidth, height: innerHeight, dpr: devicePixelRatio, document: document.documentElement.scrollWidth, uniqueInputs: new Set(ids).size === ids.length,
      headings: document.querySelectorAll('h1').length };
  });
  assert.ok(result.document <= result.viewport + 1, `${label} at ${width}: document overflow`);
  assert.ok(result.uniqueInputs); assert.equal(result.headings, 1);
  layouts.push({ label, width, ...result });
}
async function shortConfirmation(p, modal, regionName, cancelName, confirmName, trial = 1) {
  await p.setViewportSize({ width: 320, height: 150 });
  const region = modal.getByRole('region', { name: regionName, exact: true });
  const dimensions = await region.evaluate(el => ({ height: el.clientHeight, scrollHeight: el.scrollHeight, width: el.clientWidth, scrollWidth: el.scrollWidth }));
  assert.ok(dimensions.height > 0, 'short viewport must not collapse the consequences to zero height');
  assert.ok(dimensions.scrollWidth <= dimensions.width + 1, 'consequence text reflows locally');
  await region.evaluate(el => { el.scrollTop = 0; });
  await region.focus();
  if (dimensions.scrollHeight > dimensions.height) {
    await p.keyboard.press('PageDown');
    await p.waitForFunction(el => el.scrollTop > 0, await region.elementHandle(), { timeout: 3000 });
  }
  for (const name of [confirmName, cancelName]) {
    const action = button(modal, name); await action.focus();
    const immediate = await action.boundingBox();
    try {
      await p.waitForFunction(el => {
        const rect = el.getBoundingClientRect();
        return document.activeElement === el && rect.top >= -1 && rect.bottom <= innerHeight + 1;
      }, await action.elementHandle(), { timeout: 3000 });
    } catch (error) {
      const scrollContext = await action.evaluate(el => {
        const ancestors = [];
        for (let node = el; node; node = node.parentElement) {
          const style = getComputedStyle(node), rect = node.getBoundingClientRect();
          ancestors.push({ tag: node.tagName, className: node.className, top: rect.top, bottom: rect.bottom,
            scrollTop: node.scrollTop, scrollHeight: node.scrollHeight, clientHeight: node.clientHeight,
            overflowY: style.overflowY, paddingBottom: style.paddingBottom, scrollPaddingBottom: style.scrollPaddingBottom });
        }
        return { focused: document.activeElement === el, innerHeight, visualHeight: visualViewport?.height, ancestors };
      });
      await writeFile(join(output, 'short-confirmation-failure.json'), JSON.stringify({ regionName, action: name, immediate, final: await action.boundingBox(), viewport: p.viewportSize(), scrollContext }, null, 2));
      if (!functionalOnly) await p.screenshot({ path: join(output, 'short-confirmation-failure.png'), mask: [p.locator('input,textarea')], animations: 'disabled' });
      throw error;
    }
    const rect = await action.boundingBox();
    assert.ok(rect && rect.y >= -1 && rect.y + rect.height <= 151, 'focused confirmation action is not clipped');
    confirmationFocus.push({ regionName, trial, action: name, immediate, settled: rect, fullyVisible: true });
  }
  // The loop ends on cancel: use a real Tab to reach the confirming action.
  await p.keyboard.press('Tab');
  const keyboardAction = button(modal, confirmName);
  await focused(p, keyboardAction);
  const keyboardRect = await keyboardAction.boundingBox();
  assert.ok(keyboardRect && keyboardRect.y >= -1 && keyboardRect.y + keyboardRect.height <= 151, 'keyboard-focused confirmation action is not clipped');
  confirmationKeyboard.push({ regionName, trial, action: confirmName, key: 'Tab', rect: keyboardRect, fullyVisible: true });
  if (regionName === '操作范围与后果') {
    await button(modal, cancelName).focus();
    const before = await keyboardAction.evaluate(el => {
      const wrap = el.closest('.ant-modal-wrap');
      if (!wrap) throw new Error('Confirmation scroll container missing');
      // Reproduce the observed 8px clipping deterministically before focus.
      wrap.scrollTop += el.getBoundingClientRect().bottom - (innerHeight + 8);
      const rect = el.getBoundingClientRect();
      return { top: rect.top, bottom: rect.bottom, viewportHeight: innerHeight };
    });
    assert.ok(before.bottom > before.viewportHeight + 7 && before.bottom <= before.viewportHeight + 9);
    let after;
    try {
      await keyboardAction.focus();
      await p.waitForFunction(el => { const rect = el.getBoundingClientRect(); return document.activeElement === el && rect.top >= -1 && rect.bottom <= innerHeight + 1; }, await keyboardAction.elementHandle(), { timeout: 3000 });
    } finally {
      after = await keyboardAction.boundingBox();
      await writeFile(join(output, `short-confirmation-focus-probe-${trial}.json`), JSON.stringify({ setup: 'explicit scroll-position injection reproducing the observed 8px clipping', before, after, fullyVisible: !!after && after.y >= -1 && after.y + after.height <= 151 }, null, 2));
    }
  }
  layouts.push({ label: regionName, viewportWidth: 320, viewportHeight: 150, ...dimensions });
  await p.setViewportSize({ width: 320, height: 600 });
}
try {
  const loginContext = await browser.newContext({ viewport: functionalOnly ? { width: 1440, height: 1000 } : { width: 320, height: 800 }, reducedMotion: 'reduce' }); contexts.push(loginContext);
  const login = await loginContext.newPage(); login.setDefaultTimeout(15000);
  login.on('pageerror', e => pageErrors.push(e.name));
  const host = fixture.hosts.enabled;
  let unavailable = true;
  await login.route(host.origin + host.mount + '/admin/auth/capabilities', route => unavailable ? route.fulfill({ status: 503, json: {} }) : route.continue());
  await login.goto(host.origin + host.ui + '/');
  await button(login, '重新连接').waitFor();
  assert.equal(await login.locator('.management-shell').count(), 0);
  unavailable = false; await button(login, '重新连接').click();
  await login.getByRole('heading', { name: '登录管理控制台', level: 1 }).waitFor();
  await login.getByLabel('邮箱', { exact: true }).fill('admin@example.test');
  await login.getByLabel('密码', { exact: true }).fill('UIF-wrong-password-123');
  await button(login, '登录').focus(); await login.keyboard.press('Enter');
  await login.locator('.management-error[role="alert"]').waitFor();
  assert.equal(await login.getByLabel('密码', { exact: true }).inputValue(), '');
  assert.equal(await login.getByLabel('邮箱', { exact: true }).inputValue(), 'admin@example.test');
  assert.equal(await login.locator('.management-shell').count(), 0);
  if (!functionalOnly) await layout(login, 'login failure', 320);
  if (!functionalOnly) await login.screenshot({ path: join(output, 'ui-f-login-320.png'), animations: 'disabled', mask: [login.locator('input[type="password"]')] });
  pass('capability failure reconnect and keyboard login rejection keep email, clear password and expose no old workspace');
  await loginContext.close();
  // The four policies use actual compiled Rust resources, not a Vite server.
  for (const key of ['enabled', 'disabled', 'fixed', 'choose']) {
    const t = await open(key, key === 'disabled' ? '#/system/home' : key === 'enabled' ? '#/platform/home' : '#/tenants/tenant-a/home');
    const { page: p, host } = t;
    assert.equal(await p.locator('meta[name="idp-api-base"]').count(), 1);
    assert.equal(await p.locator('meta[name="idp-api-base"]').getAttribute('content'), host.mount);
    assert.equal(await p.locator('meta[name="idp-browser-config"]').count(), 1);
    const config = JSON.parse(await p.locator('meta[name="idp-browser-config"]').getAttribute('content'));
    assert.equal(config.mode, 'cookie'); assert.equal(config.restore, true); assert.equal(config.refresh, true);
    const assets = await p.locator('script[src],link[rel="stylesheet"]').evaluateAll(nodes => nodes.map(n => n.src || n.href));
    assert.ok(assets.length >= 2);
    for (const asset of assets) {
      assert.ok(asset.startsWith(host.origin + host.ui + '/assets/'));
      assert.equal((await p.request.get(asset)).status(), 200);
      assert.equal((await p.request.get(host.origin + new URL(asset).pathname.replace(host.ui, ''))).status(), 404);
    }
    for (const path of ['/', '/api/admin/clients', '/admin/clients', '/auth/session', '/devices', '/oidc/jwks']) assert.equal((await p.request.get(host.origin + path)).status(), 404);
    const cookies = await t.context.cookies();
    const cookie = cookies.find(c => c.name === (host.cookie_name ?? 'idp_ui_b')); assert.ok(cookie);
    assert.equal(cookie.path, host.mount + '/admin/auth/browser'); assert.equal(cookie.httpOnly, true); assert.equal(cookie.sameSite, 'Strict');
    const markers = await p.evaluate(() => Object.keys(localStorage).filter(k => k.startsWith('embedded-idp:browser-session:')));
    assert.deepEqual(markers, [`embedded-idp:browser-session:${host.origin}|${host.mount}/admin/auth/browser|management`]);
    const state = await p.evaluate(() => Object.values(localStorage).map(v => JSON.parse(v)));
    assert.ok(state.every(v => Object.keys(v).sort().join(',') === 'state,version'));
    pass(`${key}: compiled meta assets mount Cookie Path and purpose marker; old paths are absent`);
    await t.context.close();
  }

  const t = await open('enabled', functionalOnly ? '#/platform/clients' : '#/platform/home', { width: 390, height: 844 }), p = t.page;
  const identity = await api(t, '/auth/session');
  if (!functionalOnly) {
  const toggle = button(p, '菜单');
  await toggle.focus(); await p.keyboard.press('Enter');
  const nav = p.getByRole('dialog', { name: '管理任务', exact: true }); await nav.waitFor();
  assert.equal(await toggle.getAttribute('aria-expanded'), 'true');
  assert.equal(await toggle.getAttribute('aria-haspopup'), 'dialog');
  const motion = await nav.evaluate(el => [...el.closest('.ant-drawer').querySelectorAll('*')].every(n => ['animationDuration', 'transitionDuration'].every(k => getComputedStyle(n)[k].split(',').every(v => parseFloat(v) <= .001))));
  assert.ok(motion);
  await p.waitForFunction(el => {
    const wrapper = el.closest('.ant-drawer-content-wrapper'), rect = wrapper.getBoundingClientRect();
    return Math.abs(rect.x) < 1 && rect.width >= 270 && rect.right <= innerWidth &&
      !wrapper.getAnimations().some(animation => animation.playState === 'running');
  }, await nav.elementHandle());
  if (!functionalOnly) await p.screenshot({ path: join(output, 'ui-f-menu-390.png'), animations: 'disabled' });
  assert.equal(await p.locator('#' + await toggle.getAttribute('aria-controls')).count(), 1);
  await focusCycle(p, nav); await p.keyboard.press('Escape'); await nav.waitFor({ state: 'hidden' }); await focused(p, toggle);
  assert.equal(await toggle.getAttribute('aria-expanded'), 'false');
  await p.keyboard.press('Enter'); await nav.waitFor();
  await nav.getByRole('menuitem', { name: '客户端管理', exact: true }).focus(); await p.keyboard.press('Enter');
  await nav.waitFor({ state: 'hidden' }); await focused(p, p.locator('.management-content > h1'));
  assert.equal(await p.locator('.management-content > h1').innerText(), '客户端管理');
  assert.equal(await p.locator('.management-sidebar [aria-current="page"]').innerText(), '客户端管理');
  assert.deepEqual(await api(t, '/auth/session'), identity);
  pass('mobile menu: keyboard trap Escape trigger return and page selection title focus with unchanged identity');
  }

  const current = button(p, '当前会话'); await current.focus(); await p.keyboard.press('Enter');
  const session = p.getByRole('dialog', { name: '当前管理会话', exact: true }); await session.waitFor();
  await focusCycle(p, session); await p.keyboard.press('Escape'); await session.waitFor({ state: 'hidden' }); await focused(p, current);
  pass('read-only current-session drawer: named keyboard trap and trigger return');

  if (!functionalOnly) await layout(p, 'clients', 1440);
  const type = p.getByLabel('类型', { exact: true }); await type.focus(); await p.keyboard.press('ArrowDown');
  await p.keyboard.press('ArrowDown'); await p.keyboard.press('Enter');
  await button(p, '查询').focus(); await p.keyboard.press('Enter'); await settle(p);
  await button(p, '重置筛选').click(); await settle(p);
  const clientLabels = await assertControlLabels(p.locator('main'));
  assert.ok(clientLabels.combobox > 0, 'client Select controls must actually be checked');
  labels.push({ scope: 'client filters', ...clientLabels });
  // Temporarily sever the actual association, proving the assertion detects it.
  const selectLabel = p.locator('label').filter({ hasText: /^类型$/ });
  const selectFor = await selectLabel.getAttribute('for'); assert.ok(selectFor);
  await selectLabel.evaluate(el => el.removeAttribute('for'));
  try { await assert.rejects(() => assertControlLabels(p.locator('main')), /without an accessible label/); }
  finally { await selectLabel.evaluate((el, value) => el.setAttribute('for', value), selectFor); }
  await assertControlLabels(p.locator('main'));
  pass('actual Select labels are checked and a severed label association is rejected');
  const trigger = button(p, '按 ID 登记 / 编辑'); await trigger.focus(); await p.keyboard.press('Enter');
  const lookup = p.getByRole('dialog', { name: '按 ID 登记 / 编辑', exact: true }); await lookup.waitFor();
  await focused(p, lookup.getByLabel('客户端 ID', { exact: true }));
  await p.keyboard.type('bad/id'); await p.keyboard.press('Enter');
  const invalid = lookup.getByLabel('客户端 ID', { exact: true });
  await p.waitForFunction(el => el.getAttribute('aria-invalid') === 'true', await invalid.elementHandle());
  const described = await invalid.getAttribute('aria-describedby'); assert.ok(described);
  assert.ok(await p.locator('[id="' + described + '"]').innerText());
  if (!functionalOnly) await colorRatio(lookup.locator('.ant-form-item-explain-error'), 'validation error text');
  await invalid.fill('management-ui-b'); await p.keyboard.press('Enter');
  const editor = p.getByRole('dialog', { name: '客户端配置', exact: true }); await editor.waitFor(); await settle(p);
  const name = editor.getByLabel('名称', { exact: true }); await focused(p, name);
  await focusCycle(p, editor);
  await button(editor, '核对并保存').focus(); await p.keyboard.press('Enter');
  const review = p.getByRole('dialog', { name: '确认保存客户端配置', exact: true }); await review.waitFor();
  await focused(p, button(review, '返回修改')); await focusCycle(p, review);
  if (!functionalOnly && process.env.IDP_UI_N2_LAYOUT === '1') {
    await shortConfirmation(p, review, '待保存的完整配置', '返回修改', '确认保存');
    pass('N2 short client confirmation keeps consequences scrollable and both keyboard actions reachable');
  }
  if (!functionalOnly) await layout(p, 'client confirmation', 320);
  if (!functionalOnly) await review.locator('.ant-modal-content').screenshot({ path: join(output, 'ui-f-confirm-320.png'), animations: 'disabled' });
  await p.keyboard.press('Escape'); await review.waitFor({ state: 'hidden' }); await focused(p, button(editor, '核对并保存'));
  await button(editor, '关闭配置').focus(); await p.keyboard.press('Enter'); await editor.waitFor({ state: 'hidden' }); await focused(p, trigger);
  assert.deepEqual(t.writes, []);
  pass('keyboard client filter lookup validation detail confirmation and cancellation restore focus without writing');

  await p.setViewportSize({ width: 1440, height: 1000 });
  if (!functionalOnly) await p.screenshot({ path: join(output, 'ui-f-clients-1440.png'), animations: 'disabled' });
  if (!functionalOnly) {
  await colorRatio(p.locator('.management-content > h1'), 'page title');
  await colorRatio(p.locator('.management-client-page .ant-typography-secondary'), 'secondary explanation');
  await colorRatio(trigger, 'primary button text');
  await trigger.hover(); await colorRatio(trigger, 'primary hover text');
  await p.mouse.move(0, 0);
  await colorRatio(p.locator('.management-client-filter .ant-select-selector'), 'idle select boundary', 3, 'border-top-color', 'rgb(255,255,255)');
  await trigger.focus(); await colorRatio(trigger, 'keyboard focus outline', 3, 'outline-color', 'rgb(255,255,255)');
  const outline = await trigger.evaluate(el => getComputedStyle(el).outlineStyle); assert.equal(outline, 'solid');
  pass('computed title secondary primary hover control boundary and keyboard focus contrast meet sampled thresholds');
  }

  if (!functionalOnly) {
  // Reflow and DOM reading order are local browser checks, not assistive-device certification.
  const pages = ['#/platform/home', '#/platform/tenants', '#/platform/administrators', '#/platform/accounts', '#/platform/clients', '#/platform/directory', '#/platform/audit',
    ...['home', 'members', 'roles', 'directory', 'diagnostic', 'devices', 'sessions', 'audit'].map(x => '#/tenants/tenant-a/' + x)];
  for (const hash of pages) {
    await goto(p, hash);
    for (const width of layoutWidths) await layout(p, hash, width);
    const reading = await p.evaluate(() => {
      const main = document.querySelector('main'), title = main.querySelector('h1');
      return { lang: document.documentElement.lang, titleBeforePage: !!(title.compareDocumentPosition(main.querySelector('.management-page')) & Node.DOCUMENT_POSITION_FOLLOWING) };
    });
    assert.equal(reading.lang, 'zh-CN'); assert.ok(reading.titleBeforePage);
    labels.push({ scope: hash, ...await assertControlLabels(p.locator('main')) });
    // CSS zoom is explicit; this does not stand in for OS/browser zoom or a screen-reader run.
    await p.setViewportSize({ width: 1440, height: 1000 }); await p.evaluate(() => { document.body.style.zoom = '2'; });
    const zoom = await p.evaluate(() => ({ viewport: innerWidth, document: document.documentElement.scrollWidth }));
    assert.ok(zoom.document <= zoom.viewport + 1, `${hash}: 200% CSS zoom overflow`);
    await p.evaluate(() => { document.body.style.zoom = ''; });
  }
  pass(`15 platform and tenant pages: ${layoutWidths.length} widths, 200-percent CSS zoom, one title, labels and DOM reading order`);
  }
  await goto(p, '#/platform/accounts');
  const email = 'no-match-uif@example.test';
  await p.getByLabel('邮箱', { exact: true }).fill(email); await button(p, '查询').click(); await settle(p);
  await p.getByText('没有符合邮箱条件的账号', { exact: true }).waitFor();
  assert.ok(!p.url().includes(email) && !decodeURIComponent(p.url()).includes(email));
  const copied = await t.context.newPage(); await copied.goto(p.url()); await copied.locator('.management-shell').waitFor();
  assert.equal(await copied.getByLabel('邮箱', { exact: true }).inputValue(), ''); await copied.close();
  pass('real unmatched email filter stays out of URL and copied page restores only the page locator');
  await goto(p, '#/tenants/tenant-a/directory');
  await p.setViewportSize({ width: 1440, height: 1000 });
  const createPermission = button(p, '创建权限'); await createPermission.focus(); await p.keyboard.press('Enter');
  const permission = p.getByRole('dialog', { name: '创建权限', exact: true }); await permission.waitFor();
  const permissionLabels = await assertControlLabels(permission);
  assert.equal(permissionLabels.textarea, 1, 'permission textarea must actually be checked');
  labels.push({ scope: 'permission editor', ...permissionLabels });
  const descriptionLabel = permission.locator('label').filter({ hasText: /^权限说明$/ });
  const descriptionFor = await descriptionLabel.getAttribute('for'); assert.ok(descriptionFor);
  await descriptionLabel.evaluate(el => el.removeAttribute('for'));
  try { await assert.rejects(() => assertControlLabels(permission), /without an accessible label/); }
  finally { await descriptionLabel.evaluate((el, value) => el.setAttribute('for', value), descriptionFor); }
  await assertControlLabels(permission);
  pass('actual permission textarea label is checked and a severed association is rejected');
  await focusCycle(p, permission);
  await permission.getByLabel('业务标识', { exact: true }).fill('uif_keyboard');
  await permission.getByLabel('资源类型', { exact: true }).fill('report');
  await permission.getByLabel('动作', { exact: true }).fill('read');
  await permission.getByLabel('权限说明', { exact: true }).fill('UI F keyboard only');
  const preview = button(permission, '核对'); await preview.focus(); await p.keyboard.press('Enter');
  const permissionReview = p.getByRole('dialog', { name: '确认创建权限', exact: true }); await permissionReview.waitFor();
  await focused(p, button(permissionReview, '取消')); await focusCycle(p, permissionReview);
  if (!functionalOnly && process.env.IDP_UI_N2_LAYOUT === '1') {
    for (let trial = 1; trial <= 10; trial++) await shortConfirmation(p, permissionReview, '操作范围与后果', '取消', '确认', trial);
    pass('N2 short SafeConfirm keeps scope and consequences scrollable and both keyboard actions reachable');
  }
  await p.keyboard.press('Escape'); await permissionReview.waitFor({ state: 'hidden' }); await focused(p, preview);
  accepted.add(p); try { await p.keyboard.press('Escape'); await permission.waitFor({ state: 'hidden' }); } finally { accepted.delete(p); }
  await focused(p, createPermission);
  assert.deepEqual(t.writes, []);
  pass('permission editor and nested SafeConfirm: keyboard scope review cancellation and trigger return use existing Ant focus management');
  await t.context.close();

  if (!functionalOnly) {
  const system = await open('disabled', '#/system/home');
  for (const key of ['home', 'members', 'roles', 'directory', 'diagnostic', 'devices', 'sessions', 'audit', 'accounts', 'clients', 'administrators']) {
    await goto(system.page, '#/system/' + key);
    labels.push({ scope: '#/system/' + key, ...await assertControlLabels(system.page.locator('main')) });
    for (const width of layoutWidths) await layout(system.page, '#/system/' + key, width);
    await system.page.evaluate(() => { document.body.style.zoom = '2'; });
    assert.ok(await system.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await system.page.evaluate(() => { document.body.style.zoom = ''; });
  }
  pass(`11 Disabled system pages: ${layoutWidths.length} widths, 200-percent CSS zoom and unique headings and form IDs`);
  await system.context.close();
  }
  const fixed = await open('fixed', '#/tenants/tenant-a/sessions');
  await fixed.page.getByRole('button', { name: /^查看会话 / }).first().click();
  const single = fixed.page.getByRole('dialog', { name: '会话详情', exact: true }); await single.waitFor(); await settle(fixed.page);
  if (!functionalOnly) {
  await colorRatio(button(single, '撤销会话'), 'danger action text');
  assert.deepEqual(fixed.writes, []);
  pass('computed danger action contrast meets text threshold without issuing a security write');
  }
  await fixed.context.close();

  await runTenantChecks({ open, goto, settle, button, pass, accepting: async (p, action) => {
    accepted.add(p); try { return await action(); } finally { accepted.delete(p); }
  } });
  await runPermissionFocusChecks({ open, goto, settle, button, focused, pass });
  await runPaginationChecks({ fixture, open, goto, settle, button, pass });
  await runStateChecks({ open, goto, settle, button, pass });
  assert.deepEqual(pageErrors, []);
} catch (error) {
  failure = error;
  throw error;
} finally {
  await finalizeFunctionalRun({ coverage, contexts, browser, failure,
    resultPath: join(output, 'results.json'),
    result: { cases, pageErrors, contrast, layouts, labels, confirmationFocus, confirmationKeyboard, keyboardWrites: t.writes.length, dangerPreviewWrites: fixed.writes.length, evidence: functionalOnly ? 'CI functional selection; isolated compiled reference host; explicit response injections; no visual, zoom or screen-reader acceptance' : 'compiled reference host; isolated DB; explicit response injection and CSS zoom labelled' } });
}
