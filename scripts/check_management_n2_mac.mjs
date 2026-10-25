// Mac H01 supplement: real desktop Chrome, explicit capability/time injection.
// Uses only an owned disposable fixture; never reads project environment files.
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { browserLaunchOptions } from './management_browser.mjs';
const fixture = JSON.parse(await readFile(process.env.IDP_UI_TEST_FIXTURE, 'utf8'));
assert.match(fixture.container, /^idp-ui-b-[a-f0-9]+$/);
assert.equal(execFileSync('docker', ['inspect', '--format', '{{index .Config.Labels "idp.ui-b.fixture"}}', fixture.container], { encoding: 'utf8' }).trim(), fixture.dir);
const output = process.env.IDP_UI_OUTPUT_DIR;
assert.ok(output && process.env.IDP_UI_PLAYWRIGHT_PATH);
const { chromium } = await import(pathToFileURL(process.env.IDP_UI_PLAYWRIGHT_PATH).href);
const cases = [], contexts = [], pageErrors = [], refreshResponses = [];
let failure, browserVersion;
async function newContext(options = {}) {
  const profile = await mkdtemp(join(tmpdir(), 'idp-n2-chrome-'));
  const entry = { profile }; contexts.push(entry);
  const launch = process.env.IDP_UI_PROFILE === 'ci-functional'
    ? { ...browserLaunchOptions(), viewport: { width: 1440, height: 1000 } }
    : { headless: false, executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' };
  entry.context = await chromium.launchPersistentContext(profile, { ...options, ...launch });
  browserVersion = entry.context.browser().version();
  return entry.context;
}
await mkdir(output, { recursive: true });
const pass = (name, details = {}) => { cases.push({ name, ...details }); console.log('PASS ' + name); };
const button = (p, name) => p.getByRole('button', { name: new RegExp('^' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/([\u3400-\u9fff])(?=[\u3400-\u9fff])/g, '$1\\s*') + '$') });
async function open(context, key = 'enabled', login = true) {
  const host = fixture.hosts[key], page = await context.newPage();
  page.setDefaultTimeout(15000); page.on('pageerror', e => pageErrors.push(e.name));
  let bearer;
  page.on('request', r => { if (new URL(r.url()).pathname.startsWith(host.mount + '/admin/')) bearer = r.headers().authorization ?? bearer; });
  await page.goto(host.origin + host.ui + '/#/platform/clients');
  if (login) {
    await page.getByLabel('邮箱', { exact: true }).fill(['fixed', 'choose'].includes(key) ? 'tenant-a@example.test' : 'admin@example.test');
    await page.getByLabel('密码', { exact: true }).fill(fixture.password); await button(page, '登录').click();
    if (key === 'choose') await button(page, '进入 UI B tenant-a').click();
    await page.locator('.management-shell').waitFor();
  }
  return { page, host, bearer: () => bearer };
}
async function session(t) {
  // Read the real authoritative session using the access credential observed
  // in this page; do not infer identity from cached login responses.
  await button(t.page, '当前会话').click();
  const dialog = t.page.getByRole('dialog', { name: '当前管理会话', exact: true });
  await dialog.waitFor();
  const response = await t.page.request.get(t.host.origin + t.host.mount + '/admin/auth/session', { headers: { authorization: t.bearer() } });
  assert.equal(response.status(), 200);
  const data = await response.json();
  await t.page.keyboard.press('Escape');
  await dialog.waitFor({ state: 'hidden' });
  return data;
}
try {
  const context = await newContext({ viewport: { width: 1440, height: 800 }, reducedMotion: 'reduce' });
  // All four ports share one actual Cookie jar. Names come from the existing
  // configuration, not a new routing or multi-business product contract.
  const entries = [];
  for (const key of ['enabled', 'disabled', 'fixed', 'choose']) entries.push(await open(context, key));
  const before = await Promise.all(entries.map(session));
  for (const t of entries) { await t.page.reload(); await t.page.locator('.management-shell').waitFor(); }
  const restored = await Promise.all(entries.map(session));
  for (let i = 0; i < before.length; i++) assert.equal(restored[i].session_id, before[i].session_id);
  const cookies = await context.cookies();
  assert.equal(cookies.length, 4); assert.equal(new Set(cookies.map(c => c.name)).size, 4);
  assert.ok(cookies.every(c => c.httpOnly && c.sameSite === 'Strict' && c.path.endsWith('/admin/auth/browser')));
  for (const [key, h] of Object.entries(fixture.hosts)) {
    const cookie = cookies.find(c => c.name === (h.cookie_name ?? 'idp_ui_b_' + key));
    assert.ok(cookie); assert.equal(cookie.path, h.mount + '/admin/auth/browser'); assert.equal(cookie.domain, '127.0.0.1');
  }
  for (const t of entries) {
    const { keys, origin } = await t.page.evaluate(() => ({ keys: Object.keys(localStorage), origin: location.origin }));
    assert.ok(keys.includes(`embedded-idp:browser-session:${origin}|${t.host.mount}/admin/auth/browser|management`), 'entry must publish its coordination marker');
    assert.ok(keys.every(k => k.startsWith(`embedded-idp:browser-session:${origin}|`)));
  }
  pass('four ports coexist in one Cookie jar and restore their exact sessions', {
    cookieMetadata: cookies.map(({ name, path, domain, httpOnly, sameSite, secure }) => ({ name, path, domain, httpOnly, sameSite, secure })),
    sessionEquality: restored.map((s, i) => s.session_id === before[i].session_id),
  });
  const unauthenticated = await entries[0].page.request.get(entries[0].host.origin + entries[0].host.mount + '/admin/tenants', {
    headers: { 'x-embedded-idp-subject': 'synthetic-admin', 'x-embedded-idp-tenant-id': '0' },
  });
  assert.equal(unauthenticated.status(), 401);
  const forgedTarget = await entries[2].page.request.get(entries[2].host.origin + entries[2].host.mount + '/admin/clients?limit=1', {
    headers: { authorization: entries[2].bearer(), 'x-embedded-idp-tenant-id': '0', 'x-embedded-idp-subject': 'synthetic-admin' },
  });
  assert.equal(forgedTarget.status(), 403);
  pass('forged subject without a credential and forged platform target cannot grant authority', { unauthenticated: 401, nonzeroPlatformTarget: 403 });
  await button(entries[0].page, '退出登录').click();
  await entries[0].page.getByLabel('邮箱', { exact: true }).waitFor();
  for (let i = 1; i < entries.length; i++) { await entries[i].page.reload(); await entries[i].page.locator('.management-shell').waitFor(); assert.equal((await session(entries[i])).session_id, before[i].session_id); }
  pass('logout at one port does not replace or revoke the three other entry sessions');

  const host = fixture.hosts.enabled;
  for (const mode of ['no-locks', 'storage-get', 'storage-set', 'storage-discard']) {
    const c = await newContext();
    await c.addInitScript(mode => {
      if (mode === 'no-locks') Object.defineProperty(navigator, 'locks', { value: undefined });
      else if (mode === 'storage-discard') Storage.prototype.setItem = () => {};
      else Storage.prototype[mode === 'storage-get' ? 'getItem' : 'setItem'] = () => { throw new DOMException('N2 explicit storage denial', 'SecurityError'); };
    }, mode);
    const t = await open(c, 'enabled', false); let admissions = 0;
    t.page.on('request', r => { if (r.method() === 'POST' && new URL(r.url()).pathname.startsWith(host.mount + '/admin/auth/browser')) admissions++; });
    await t.page.getByLabel('邮箱', { exact: true }).fill('admin@example.test');
    await t.page.getByLabel('密码', { exact: true }).fill(fixture.password); await button(t.page, '登录').click();
    await t.page.getByRole('alert').waitFor();
    assert.equal(await t.page.locator('.management-shell').count(), 0); assert.equal(admissions, 0);
    assert.equal(await t.page.getByLabel('密码', { exact: true }).inputValue(), '');
    pass(mode + ' injection fails closed before Cookie login and clears password', { injection: mode, browserLoginRequests: admissions });
    await c.close();
  }

  const c = await newContext({ reducedMotion: 'reduce' });
  await c.route(host.origin + host.mount + '/admin/auth/browser/login', async route => {
    const response = await route.fetch();
    if (response.status() !== 200) return route.fulfill({ response });
    const body = await response.json(); body.tokens.access_expires_at_unix_secs = Math.floor(Date.now() / 1000) + 300;
    await route.fulfill({ response, json: body });
  });
  await c.route(host.origin + host.mount + '/admin/auth/browser/restore', async route => {
    const response = await route.fetch();
    // The first page legitimately has no Cookie before login. Only successful
    // restoration gets a shortened client-side expiry for the refresh probe.
    if (response.status() !== 200) return route.fulfill({ response });
    const body = await response.json(); body.tokens.access_expires_at_unix_secs = Math.floor(Date.now() / 1000) + 300;
    await route.fulfill({ response, json: body });
  });
  const first = await open(c), second = await open(c, 'enabled', false);
  await second.page.locator('.management-shell').waitFor();
  const original = await session(first); assert.equal((await session(second)).session_id, original.session_id);
  let active = 0, maximum = 0, rotations = 0;
  await c.route(host.origin + host.mount + '/admin/auth/browser/refresh', async route => {
    active++; maximum = Math.max(maximum, active); rotations++;
    try { await new Promise(r => setTimeout(r, 150)); const response = await route.fetch(); refreshResponses.push(response.status()); await route.fulfill({ response }); }
    finally { active--; }
  });
  for (const t of [first, second]) await t.page.evaluate(() => { const originalNow = Date.now.bind(Date); Date.now = () => originalNow() + 280000; });
  await Promise.all([first, second].map(t => button(t.page, '刷新客户端').click()));
  await Promise.all([first, second].map(t => t.page.waitForFunction(() => !document.querySelector('.ant-spin-spinning, .ant-spin-blur'))));
  assert.equal(rotations, 2); assert.equal(maximum, 1);
  assert.deepEqual(refreshResponses, [200, 200]);
  for (const t of [first, second]) assert.equal((await session(t)).session_id, original.session_id);
  pass('two real tabs serialize actual refresh rotations under Web Locks', { injection: 'login/restore expiry and client clock only', rotations, maximumConcurrentRefresh: maximum, authoritativeSessionUnchanged: true });

  assert.deepEqual(pageErrors, []);
} catch (error) {
  failure = { name: error.name, message: error.message };
  throw error;
} finally {
  let profilesRemoved = 0;
  const cleanupErrors = [];
  for (const [index, entry] of contexts.entries()) {
    try {
      if (entry.context) await entry.context.close();
      await rm(entry.profile, { recursive: true });
      profilesRemoved++;
    } catch (error) {
      // Do not remove a profile while its browser may still be running. Keep
      // attempting the other owned profiles and always publish the result.
      cleanupErrors.push({ index, error: error.name });
      console.error(`Cleanup retained owned profile ${entry.profile}: ${error.name}`);
    }
  }
  await writeFile(output + '/results.json', JSON.stringify({ browserVersion, headed: process.env.IDP_UI_PROFILE !== 'ci-functional',
    profileMode: process.env.IDP_UI_PROFILE === 'ci-functional' ? 'owned Linux headless persistent profiles' : 'owned persistent regular profiles; not incognito contexts',
    profilesRemoved, cleanupErrors, cases, pageErrors, refreshResponses, failure, complete: !failure && cleanupErrors.length === 0 && cases.length === 8 }, null, 2) + '\n');
  if (cleanupErrors.length && !failure) throw new Error('Owned Chrome profile cleanup failed; see results.json');
}
