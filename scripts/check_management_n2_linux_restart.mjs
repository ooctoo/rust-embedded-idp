// N2 Linux L05: restart the owned app container and prove token/Cookie session continuity.
// Only a disposable fixture and a newly-created headed Chrome profile are accepted.
import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const fixturePath = process.env.IDP_UI_TEST_FIXTURE;
const output = process.env.IDP_UI_OUTPUT_DIR;
const playwrightPath = process.env.IDP_UI_PLAYWRIGHT_PATH;
const executablePath = process.env.IDP_UI_BROWSER_EXECUTABLE ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
if (!fixturePath || !output || !playwrightPath) throw new Error('IDP_UI_TEST_FIXTURE, IDP_UI_OUTPUT_DIR and IDP_UI_PLAYWRIGHT_PATH are required');

const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
const host = fixture.hosts?.enabled;
assert.match(fixture.container ?? '', /^idp-ui-b-[a-f0-9]{12}$/);
assert.match(fixture.schemas?.enabled ?? '', /^uib_enabled_[a-f0-9]+$/);
assert.ok(host && new URL(host.origin).hostname === '127.0.0.1' && host.mount === '/identity');
assert.ok(host.cookie_name && fixture.password);
assert.equal(execFileSync('docker', ['inspect', '--format', '{{index .Config.Labels "idp.ui-b.fixture"}}', fixture.container], { encoding: 'utf8' }).trim(), fixture.dir);

const { chromium, request } = await import(pathToFileURL(playwrightPath).href);
const cases = [];
const cleanupErrors = [];
let context;
let profile;
let profileClosed = false;
let apiContext;
let browserVersion;
let failure;
let stopExitCode;
let stopOomKilled;
let initialCookieSession;
let explicitSession;
let cookieExpiryBefore;
let explicitExpiryBefore;
let cookieExpiryAfter;
let explicitExpiryAfter;
let restoreStatus;
let staleRestoreStatus;
let explicitLogoutStatus;
let cookieLogoutStatus;
let revokedCookieValue;
let cookieSessionIdSameAcrossRestart = false;
let explicitSessionIdSameAcrossRestart = false;
let clientConfigurationUnchanged = false;

await mkdir(output, { recursive: true });
const check = (condition, label) => {
  if (!condition) throw new Error(label);
  cases.push(label);
  console.log(`PASS ${label}`);
};

const authPath = `${host.mount}/admin/auth`;
const apiUrl = suffix => host.origin + authPath + suffix;

async function readSession(page, bearer, label) {
  const response = await page.request.get(apiUrl('/session'), { headers: { authorization: `Bearer ${bearer}` } });
  if (response.status() !== 200) throw new Error(`${label} session status ${response.status()}`);
  const body = await response.json();
  if (typeof body.session_id !== 'string' || !/^[0-9a-f-]{36}$/i.test(body.session_id)) {
    throw new Error(`${label} session response shape`);
  }
  return body;
}

function readExpiry(sessionId) {
  if (!/^[0-9a-f-]{36}$/i.test(sessionId)) throw new Error('Invalid session key shape');
  const schema = fixture.schemas.enabled;
  const sql = `select expires_at_epoch::text from ${schema}.auth_sessions where id = '${sessionId}'::uuid;\n`;
  const value = execFileSync('docker', [
    'exec', '-i', fixture.container, 'psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
    '-U', 'uib', '-d', 'uib',
  ], { input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim();
  if (!/^\d+$/.test(value)) throw new Error('Session expiry query did not return one epoch value');
  return Number(value);
}

function clientConfiguration(sentinel = false) {
  const schema = fixture.schemas.enabled;
  const sql = (sentinel ? `update ${schema}.oidc_clients set client_name='N2 Linux restart sentinel' where client_id='management-ui-b';\n` : '') +
    `select row_to_json(c) from (select client_id,client_name,redirect_uris_json,client_type,pkce_required from ${schema}.oidc_clients where client_id='management-ui-b') c;\n`;
  const value = execFileSync('docker', ['exec', '-i', fixture.container, 'psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-U', 'uib', '-d', 'uib'],
    { input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim().split('\n').at(-1);
  if (!value || JSON.parse(value).client_name !== 'N2 Linux restart sentinel') throw new Error('Client sentinel missing');
  return value;
}

try {
  profile = await mkdtemp(join(tmpdir(), 'idp-n2-linux-l05-'));
  context = await chromium.launchPersistentContext(profile, {
    headless: false,
    executablePath,
    viewport: { width: 1440, height: 900 },
    reducedMotion: 'reduce',
  });
  browserVersion = context.browser().version();
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  let browserBearer;
  page.on('request', requestEvent => {
    const requestUrl = new URL(requestEvent.url());
    if (requestUrl.pathname.startsWith(`${host.mount}/admin/`)) {
      const authorization = requestEvent.headers().authorization;
      if (authorization?.startsWith('Bearer ')) browserBearer = authorization.slice('Bearer '.length);
    }
  });

  await page.goto(`${host.origin}${host.ui}/#/platform/clients`);
  await page.getByLabel('邮箱', { exact: true }).fill('admin@example.test');
  await page.getByLabel('密码', { exact: true }).fill(fixture.password);
  await page.getByRole('button', { name: /^登\s*录$/ }).click();
  await page.locator('.management-shell').waitFor();
  if (!browserBearer) throw new Error('Browser login did not issue an observed bearer request');
  initialCookieSession = await readSession(page, browserBearer, 'browser');
  const afterCookie = await page.request.get(apiUrl('/session'), { headers: { authorization: `Bearer ${browserBearer}` } });
  if (afterCookie.status() !== 200) throw new Error('Browser session preflight failed');
  cookieExpiryBefore = readExpiry(initialCookieSession.session_id);

  const login = await page.request.post(apiUrl('/login'), {
    data: { email: 'admin@example.test', password: fixture.password },
    timeout: 20000,
  });
  if (login.status() !== 200) throw new Error(`Explicit-token login status ${login.status()}`);
  const loginBody = await login.json();
  const explicitBearer = loginBody?.tokens?.access_token;
  explicitSession = loginBody?.session;
  if (loginBody.status !== 'authenticated' || typeof explicitBearer !== 'string' || !explicitSession?.session_id) {
    throw new Error('Explicit-token login response shape');
  }
  const explicitRead = await readSession(page, explicitBearer, 'explicit-token');
  if (explicitRead.session_id !== explicitSession.session_id) throw new Error('Explicit-token session identity mismatch');
  if (explicitRead.session_id === initialCookieSession.session_id) throw new Error('Login modes unexpectedly reused one session');
  explicitExpiryBefore = readExpiry(explicitRead.session_id);

  const cookie = (await context.cookies()).find(item => item.name === host.cookie_name);
  if (!cookie?.value || cookie.path !== `${host.mount}/admin/auth/browser`) throw new Error('Owned browser Cookie metadata missing');
  revokedCookieValue = cookie.value;
  check(true, 'separate browser Cookie and explicit-token sessions established');
  const clientBefore = clientConfiguration(true);

  const restartRaw = execFileSync('python3', [
    'scripts/prepare_management_n2_linux.py', '--restart', fixturePath, '--label', 'enabled',
  ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  const restart = JSON.parse(restartRaw);
  if (!Number.isInteger(restart?.stop?.exitCode) || typeof restart.stop.oomKilled !== 'boolean') {
    throw new Error('Restart result is missing stop exit/OOM status');
  }
  stopExitCode = restart.stop.exitCode;
  stopOomKilled = restart.stop.oomKilled;
  if (stopExitCode === 137 || stopOomKilled) throw new Error('App container was force-killed or OOM-killed');
  if (restart?.host?.origin !== host.origin || restart?.host?.mount !== host.mount || restart?.host?.ui !== host.ui) {
    throw new Error('Restart changed the enabled host origin or path configuration');
  }
  check(true, 'owned app stopped and rebuilt at the same origin and paths');
  clientConfigurationUnchanged = clientConfiguration() === clientBefore;
  if (!clientConfigurationUnchanged) throw new Error('Startup overwrote existing client configuration or sentinel');

  const explicitAfter = await readSession(page, explicitBearer, 'explicit-token-after-restart');
  explicitSessionIdSameAcrossRestart = explicitAfter.session_id === explicitRead.session_id;
  if (!explicitSessionIdSameAcrossRestart) throw new Error('Explicit-token session changed across restart');
  explicitExpiryAfter = readExpiry(explicitAfter.session_id);
  if (explicitExpiryAfter !== explicitExpiryBefore) throw new Error('Explicit-token session expiry changed across restart');
  check(true, 'explicit Bearer token still authenticates the same session after restart');

  const restoredBearerRequest = page.waitForRequest(requestEvent => {
    const url = new URL(requestEvent.url());
    return url.pathname.startsWith(`${host.mount}/admin/`) && requestEvent.headers().authorization?.startsWith('Bearer ');
  }, { timeout: 15000 });
  const restoreResponse = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.pathname === `${host.mount}/admin/auth/browser/restore` && response.request().method() === 'POST';
  });
  await page.reload();
  restoreStatus = (await restoreResponse).status();
  if (restoreStatus !== 200) throw new Error(`Browser Cookie restore status ${restoreStatus}`);
  await page.locator('.management-shell').waitFor();
  const restoredBearer = (await restoredBearerRequest).headers().authorization.slice('Bearer '.length);
  browserBearer = restoredBearer;
  const cookieAfter = await readSession(page, restoredBearer, 'browser-after-restart');
  cookieSessionIdSameAcrossRestart = cookieAfter.session_id === initialCookieSession.session_id;
  if (!cookieSessionIdSameAcrossRestart) throw new Error('Cookie restore changed the original session');
  cookieExpiryAfter = readExpiry(cookieAfter.session_id);
  if (cookieExpiryAfter !== cookieExpiryBefore) throw new Error('Cookie session expiry changed across restart');
  const restoredCookie = (await context.cookies()).find(item => item.name === host.cookie_name);
  if (!restoredCookie?.value || restoredCookie.path !== `${host.mount}/admin/auth/browser`) {
    throw new Error('Restored browser Cookie metadata missing');
  }
  revokedCookieValue = restoredCookie.value;
  check(true, 'existing persistent-profile Cookie restores the same session and expiry');

  const explicitLogout = await page.request.post(apiUrl('/logout'), {
    headers: { authorization: `Bearer ${explicitBearer}` },
  });
  explicitLogoutStatus = explicitLogout.status();
  if (explicitLogoutStatus !== 204) throw new Error(`Explicit-token logout status ${explicitLogoutStatus}`);
  const rejectedExplicit = await page.request.get(apiUrl('/session'), {
    headers: { authorization: `Bearer ${explicitBearer}` },
  });
  if (rejectedExplicit.status() !== 401) throw new Error(`Explicit token after logout status ${rejectedExplicit.status()}`);
  const preservedCookie = await readSession(page, browserBearer, 'browser-after-explicit-logout');
  if (preservedCookie.session_id !== initialCookieSession.session_id) throw new Error('Explicit-token logout changed the browser session');
  check(true, 'explicit-token logout revokes only its session');

  const browserLogoutResponse = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.pathname === `${host.mount}/admin/auth/browser/logout` && response.request().method() === 'POST';
  });
  await page.getByRole('button', { name: /^退出登录$/ }).click();
  cookieLogoutStatus = (await browserLogoutResponse).status();
  if (cookieLogoutStatus !== 204) throw new Error(`Browser UI logout status ${cookieLogoutStatus}`);
  await page.getByLabel('邮箱', { exact: true }).waitFor();
  const rejectedCookieBearer = await page.request.get(apiUrl('/session'), {
    headers: { authorization: `Bearer ${browserBearer}` },
  });
  if (rejectedCookieBearer.status() !== 401) throw new Error(`Browser Bearer after UI logout status ${rejectedCookieBearer.status()}`);

  apiContext = await request.newContext();
  const staleRestore = await apiContext.post(`${host.origin}${host.mount}/admin/auth/browser/restore`, {
    headers: {
      origin: host.origin,
      'x-embedded-idp-browser': '1',
      cookie: `${host.cookie_name}=${revokedCookieValue}`,
    },
    data: { expected_session: {
      tenant_id: initialCookieSession.tenant_id,
      account_id: initialCookieSession.account_id,
      session_id: initialCookieSession.session_id,
      client_id: 'management-ui-b',
    } },
  });
  staleRestoreStatus = staleRestore.status();
  if (staleRestoreStatus !== 401) throw new Error(`Revoked Cookie restore status ${staleRestoreStatus}`);
  check(true, 'browser UI logout revokes its session and rejects replay of the old Cookie');
} catch (error) {
  let message = String(error?.message ?? 'Unknown failure');
  for (const secret of [fixture.password, fixture.db_password, fixture.db_uri, revokedCookieValue]) {
    if (secret) message = message.replaceAll(secret, '[redacted]');
  }
  message = message.replaceAll(process.cwd(), '<repo>').replace(/\/Users\/[^/]+/g, '<home>');
  failure = { name: error?.name ?? 'Error', message };
} finally {
  if (apiContext) {
    try { await apiContext.dispose(); }
    catch (error) { cleanupErrors.push({ resource: 'api-context', operation: 'dispose', error: error?.name ?? 'Error' }); }
  }
  if (context) {
    try {
      await context.close();
      profileClosed = true;
    } catch (error) {
      cleanupErrors.push({ resource: 'chrome-profile', operation: 'close', error: error?.name ?? 'Error', retained: true });
    }
  } else if (profile) {
    cleanupErrors.push({ resource: 'chrome-profile', operation: 'launch', error: 'LaunchDidNotReturnContext', retained: true });
  }
  if (profile && profileClosed) {
    try { await rm(profile, { recursive: true }); }
    catch (error) { cleanupErrors.push({ resource: 'chrome-profile', operation: 'remove', error: error?.name ?? 'Error', retained: true }); }
  }

  const results = {
    scope: 'N2 L05 Linux arm64 app-container restart with Mac Chrome',
    browserVersion,
    headed: true,
    profileMode: 'new ordinary persistent profile owned by this run',
    restart: { stopExitCode, oomKilled: stopOomKilled, sameOrigin: host.origin, sameMount: host.mount, sameUiPath: host.ui },
    sessions: {
      clientConfigurationAndSentinelUnchanged: clientConfigurationUnchanged,
      separateBeforeRestart: Boolean(initialCookieSession?.session_id && explicitSession?.session_id && initialCookieSession.session_id !== explicitSession.session_id),
      cookieSessionIdSameAcrossRestart,
      explicitSessionIdSameAcrossRestart,
      cookieExpiryBefore: cookieExpiryBefore ?? null,
      cookieExpiryAfter: cookieExpiryAfter ?? null,
      cookieExpiryUnchanged: cookieExpiryBefore !== undefined && cookieExpiryAfter === cookieExpiryBefore,
      explicitExpiryBefore: explicitExpiryBefore ?? null,
      explicitExpiryAfter: explicitExpiryAfter ?? null,
      explicitExpiryUnchanged: explicitExpiryBefore !== undefined && explicitExpiryAfter === explicitExpiryBefore,
    },
    responses: { restoreStatus, explicitLogoutStatus, cookieLogoutStatus, staleRestoreStatus },
    profileRemoved: Boolean(profile && profileClosed && !cleanupErrors.some(item => item.resource === 'chrome-profile' && item.operation === 'remove')),
    cleanupErrors,
    cases,
    failure,
    complete: !failure && cleanupErrors.length === 0 && cases.length === 6,
  };
  await writeFile(join(output, 'l05-restart-results.json'), JSON.stringify(results, null, 2) + '\n', { mode: 0o600 });
  await chmod(join(output, 'l05-restart-results.json'), 0o600);
  if (profile && cleanupErrors.some(item => item.resource === 'chrome-profile' && item.retained)) {
    await writeFile(join(fixture.dir, 'l05-private-profile-recovery.txt'), profile + '\n', { mode: 0o600 });
  }
}

if (failure || cleanupErrors.length) {
  console.error('L05 restart check failed; inspect the sanitized result and private recovery note if present.');
  throw new Error('L05 restart check failed');
}
