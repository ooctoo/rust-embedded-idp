// Opt-in real-host UI-B acceptance. Fixture must own disposable uib_* schemas
// and a loopback-only idp-ui-b-* container; never point this at an existing instance.
import { browserLaunchOptions } from './management_browser.mjs';
import { functionalOnly, createFunctionalCoverage, finalizeFunctionalRun } from './management_functional.mjs';
import assert from "node:assert/strict";
import { readFile, mkdir } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const fixture = JSON.parse(await readFile(process.env.IDP_UI_TEST_FIXTURE, "utf8"));
assert.match(fixture.container, /^idp-ui-b-[a-f0-9]+$/);
for (const schema of Object.values(fixture.schemas)) assert.match(schema, /^uib_(enabled|disabled)_[a-f0-9]+$/);
for (const host of Object.values(fixture.hosts)) assert.equal(new URL(host.origin).hostname, "127.0.0.1");
const { chromium } = await import(process.env.IDP_UI_PLAYWRIGHT_PATH ? pathToFileURL(process.env.IDP_UI_PLAYWRIGHT_PATH).href : "playwright");
const browser = await chromium.launch(browserLaunchOptions());
const output = process.env.IDP_UI_OUTPUT_DIR ?? fixture.dir;
await mkdir(output, { recursive: true });
const coverage = createFunctionalCoverage('navigation', output);
const results = [], errors = [];
let failure;
const pass = name => { coverage.pass(name); results.push(name); console.log(`PASS ${name}`); };
const heading = page => page.locator(".management-content > h1");
const waitHeading = async (page, text) => {
  await page.waitForFunction(value => document.querySelector(".management-content > h1")?.textContent === value, text);
};
const settle = page => page.waitForFunction(() => !document.querySelector(".ant-spin-spinning, .ant-spin-blur"));
const setHash = (page, hash) => page.evaluate(value => { location.hash = value; }, hash);
const menu = (page, text) => page.locator(".management-sidebar").getByRole("menuitem", { name: text, exact: true });
const contexts = [];
const bounded = (promise, stage) => Promise.race([promise, new Promise((_, reject) => {
  const timer = setTimeout(() => reject(new Error(`Timed out: ${stage}`)), 15_000); timer.unref();
})]);
async function open(key, hash, email = "admin@example.test", earlierHash, shortExpiry = false) {
  const host = fixture.hosts[key];
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } }); contexts.push(context);
  const page = await context.newPage();
  page.setDefaultTimeout(15_000);
  if (shortExpiry) await page.route(`${host.origin}${host.mount}/admin/auth/browser/login`, async route => {
    const response = await route.fetch();
    assert.ok(response.ok());
    const body = await response.json();
    body.tokens.access_expires_at_unix_secs = Math.floor(Date.now() / 1000) + 300;
    await route.fulfill({ response, json: body });
  });
  if (earlierHash) await page.addInitScript(({ earlierHash, hash }) => {
    history.replaceState(null, "", `${location.pathname}${earlierHash}`);
    history.pushState(null, "", `${location.pathname}${hash}`);
  }, { earlierHash, hash });
  const calls = [], dialogs = []; let answer = "dismiss";
  page.on("pageerror", error => errors.push(error.message));
  page.on("request", request => {
    const url = new URL(request.url());
    if (url.pathname.startsWith(`${host.mount}/admin`)) calls.push({ path: url.pathname, query: url.search, method: request.method(), target: request.headers()["x-embedded-idp-tenant-id"] });
  });
  page.on("dialog", async dialog => {
    dialogs.push({ type: dialog.type(), message: dialog.message() });
    if (dialog.type() === "confirm" && answer === "accept" || dialog.type() === "beforeunload") await dialog.accept(); else await dialog.dismiss();
  });
  await page.goto(host.origin + host.ui + "/" + hash);
  await page.getByLabel("邮箱", { exact: true }).fill(email);
  await page.getByLabel("密码", { exact: true }).fill(fixture.password);
  await page.getByRole("button", { name: /^登\s*录$/ }).click();
  return { page, context, calls, dialogs, host, answer: value => { answer = value; } };
}
async function actualSession(test) {
  const { page, host } = test;
  await page.getByRole("button", { name: "当前会话", exact: true }).click();
  const drawer = page.getByRole("dialog", { name: "当前管理会话", exact: true });
  const id = (await drawer.locator(".ant-descriptions-item").filter({ hasText: "会话 ID" }).locator(".ant-descriptions-item-content").innerText()).trim();
  await page.waitForFunction(el => !el.closest(".ant-drawer-content-wrapper")?.getAnimations().some(animation => animation.playState === "running"), await drawer.elementHandle());
  await page.waitForFunction(el => {
    const wrapper = el.closest(".ant-drawer-content-wrapper");
    return wrapper && getComputedStyle(wrapper).transform === "none" && getComputedStyle(el).opacity === "1";
  }, await drawer.elementHandle());
  // Ant's loading icon contributes to the accessible name while busy.
  const verify = drawer.getByRole("button", { name: /校验当前会话$/ });
  await page.waitForFunction(button => !button.disabled && !button.classList.contains("ant-btn-loading"), await verify.elementHandle());
  const [verified] = await Promise.all([
    page.waitForResponse(r => r.url() === host.origin + host.mount + "/admin/auth/session" && r.request().method() === "GET"),
    verify.click(),
  ]);
  assert.equal(verified.status(), 200);
  const identity = await verified.json();
  assert.equal(identity.session_id, id);
  await drawer.locator("button.ant-drawer-close").click();
  await drawer.waitFor({ state: "hidden" });
  return identity;
}
async function expectDialog(test, action) {
  const next = test.page.waitForEvent("dialog", { timeout: 15_000 }); await action(); await next;
}
try {
  const platform = await open("enabled", "#/platform/clients");
  const { page, calls } = platform;
  await waitHeading(page, "客户端管理"); await settle(page);
  assert.equal(await menu(page, "客户端管理").getAttribute("aria-current"), "page");
  const verified = calls.findIndex(c => c.path.endsWith("/auth/session"));
  assert.ok(verified >= 0 && verified < calls.findIndex(c => c.path.endsWith("/clients")));
  const platformIdentity = await actualSession(platform);
  for (const [key, label] of [["home", "工作台"], ["tenants", "租户管理"], ["administrators", "系统管理员"], ["accounts", "账号安全"], ["clients", "客户端管理"], ["directory", "平台权限"], ["audit", "平台审计"]]) {
    await menu(page, label).click(); await waitHeading(page, label); assert.ok(page.url().endsWith(`#/platform/${key}`)); await settle(page);
  }
  await menu(page, "租户管理").click(); await waitHeading(page, "租户管理"); await settle(page);
  await page.getByRole("button", { name: "管理 UI B tenant-a", exact: true }).click();
  await waitHeading(page, "成员管理"); await settle(page);
  assert.ok(page.url().endsWith("#/tenants/tenant-a/members"));
  for (const [key, label] of [["roles", "角色与权限"], ["directory", "权限目录"], ["members", "成员管理"], ["diagnostic", "权限诊断"], ["devices", "设备管理"], ["sessions", "会话管理"], ["audit", "审计记录"]]) {
    await menu(page, label).click(); await waitHeading(page, label); await settle(page);
    assert.ok(page.url().endsWith(`#/tenants/tenant-a/${key}`));
  }
  assert.deepEqual(await actualSession(platform), platformIdentity);
  assert.equal(calls.filter(c => c.path.includes("tenant-selection")).length, 0);
  pass("platform and target retain every existing task without changing login session");
  await menu(page, "成员管理").click(); await waitHeading(page, "成员管理"); await settle(page);
  await menu(page, "角色与权限").click(); await waitHeading(page, "角色与权限"); await settle(page);
  await page.goBack(); await waitHeading(page, "成员管理"); await settle(page);
  await page.goForward(); await waitHeading(page, "角色与权限"); await settle(page);
  const reloadStart = calls.length;
  await page.reload(); await waitHeading(page, "角色与权限"); await settle(page);
  const reloadCalls = calls.slice(reloadStart);
  assert.ok(reloadCalls.findIndex(c => c.path.endsWith("/auth/session")) >= 0);
  assert.ok(reloadCalls.findIndex(c => c.path.endsWith("/auth/session")) < reloadCalls.findIndex(c => c.path.endsWith("/access/roles")));
  assert.deepEqual(await actualSession(platform), platformIdentity);
  assert.ok(page.url().endsWith("#/tenants/tenant-a/roles"));
  pass("hash Back Forward and Cookie reload restore the selected page");
  let releaseRead; const delayedRead = new Promise(resolve => { releaseRead = resolve; });
  let seenRead; const readSeen = new Promise(resolve => { seenRead = resolve; });
  let deliveredRead; const readDelivered = new Promise(resolve => { deliveredRead = resolve; });
  const latePattern = `${platform.host.origin}${platform.host.mount}/admin/accounts?*`;
  await page.route(latePattern, async route => {
    if (route.request().headers()["x-embedded-idp-tenant-id"] !== "tenant-a") return route.continue();
    const response = await route.fetch(), body = await response.json();
    for (const row of body.items) row.display_name = "Late tenant A response";
    seenRead(); await delayedRead; await route.fulfill({ response, json: body }); deliveredRead();
  });
  await setHash(page, "#/tenants/tenant-a/members"); await bounded(readSeen, "delayed member read");
  await setHash(page, "#/tenants/tenant-b/members"); await waitHeading(page, "成员管理"); await settle(page);
  releaseRead(); await readDelivered; await page.unroute(latePattern); await settle(page);
  assert.equal(await page.getByText("Late tenant A response", { exact: true }).count(), 0);
  assert.ok((await page.locator(".management-target").innerText()).includes("tenant-b"));
  pass("a delayed old-tenant response cannot populate the new target");
  await setHash(page, "#/platform/unknown"); await waitHeading(page, "页面不存在");
  const beforeMissing = calls.length;
  await setHash(page, "#/tenants/tenant-a/../members"); await waitHeading(page, "页面不存在");
  assert.equal(calls.length, beforeMissing);
  const beforeRecovery = calls.length;
  await menu(page, "客户端管理").click(); await waitHeading(page, "客户端管理"); await settle(page);
  assert.ok(calls.slice(beforeRecovery).every(c => c.target === undefined));
  await setHash(page, "#/tenants/missing-tenant/members"); await page.getByText("目标不存在或不可见", { exact: true }).waitFor();
  assert.equal(calls.filter(c => c.target === "missing-tenant").length, 0);
  pass("unknown and traversal hashes fail locally; missing targets never mount a data page");
  for (const id of [".", ".."]) {
    const start = calls.length;
    await setHash(page, `#/tenants/${id}/members`); await waitHeading(page, "成员管理"); await settle(page);
    assert.ok((await page.locator(".management-target").innerText()).includes(`UI B ${id}`));
    const targetCalls = calls.slice(start).filter(c => c.path.endsWith("/admin/tenants"));
    assert.ok(targetCalls.some(c => new URLSearchParams(c.query).get("tenant_id") === id));
    assert.ok(!calls.slice(start).some(c => c.path.endsWith("/admin/tenants/")));
    await page.reload(); await waitHeading(page, "成员管理"); await settle(page);
    assert.ok((await page.locator(".management-target").innerText()).includes(`UI B ${id}`));
  }
  pass("dot tenant IDs are managed and restored without normalized detail paths");
  await setHash(page, "#/tenants/tenant-b/roles"); await waitHeading(page, "角色与权限"); await settle(page);
  await page.getByRole("button", { name: "新建角色", exact: true }).click();
  // Keep shell acceptance scoped to the creation form, independent of the page filter.
  await page.getByRole("dialog").getByPlaceholder("例如 biz_test", { exact: true }).fill("uib");
  await page.getByLabel("角色标识", { exact: true }).fill(`navigation_guard_${Date.now()}`);
  await page.getByLabel("角色名称", { exact: true }).fill("UI B guard fixture");
  platform.answer("dismiss");
  await expectDialog(platform, () => setHash(page, "#/tenants/tenant-b/members"));
  await page.waitForURL("**/#/tenants/tenant-b/roles");
  assert.equal(await page.getByLabel("角色名称", { exact: true }).inputValue(), "UI B guard fixture");
  // Rejecting an unmarked edited hash anchors the current URL in that entry;
  // Back over its duplicate keeps the same page without discarding the draft.
  await page.goBack();
  await page.waitForURL("**/#/tenants/tenant-b/roles");
  assert.equal(await page.getByLabel("角色名称", { exact: true }).inputValue(), "UI B guard fixture");
  let releaseWrite; const delayedWrite = new Promise(resolve => { releaseWrite = resolve; });
  let seenWrite; const writeSeen = new Promise(resolve => { seenWrite = resolve; });
  const writePattern = `${platform.host.origin}${platform.host.mount}/admin/access/roles`;
  await page.route(writePattern, async route => { if (route.request().method() !== "POST") return route.continue(); seenWrite(); await delayedWrite; await route.continue(); });
  await page.getByRole("button", { name: "创建角色", exact: true }).click();
  await page.getByRole("dialog", { name: "确认创建角色", exact: true }).getByRole("button", { name: "确认创建", exact: true }).click(); await bounded(writeSeen, "role POST");
  await expectDialog(platform, () => setHash(page, "#/tenants/tenant-a/members"));
  await page.waitForURL("**/#/tenants/tenant-b/roles");
  assert.equal(platform.dialogs.at(-1).type, "alert");
  const writeDone = page.waitForResponse(r => r.url() === writePattern && r.request().method() === "POST");
  releaseWrite(); await writeDone; await page.unroute(writePattern);
  await page.getByRole("dialog", { name: "新建业务角色", exact: true }).waitFor({ state: "hidden" }); await settle(page);
  platform.answer("accept");
  await expectDialog(platform, () => setHash(page, "#/tenants/tenant-b/members")); await waitHeading(page, "成员管理");
  assert.equal(calls.filter(c => c.method === "POST" && c.path.endsWith("/access/roles")).length, 1);
  pass("draft cancellation restores history; pending writes block target changes without replay");
  await setHash(page, "#/tenants/tenant-b/roles"); await waitHeading(page, "角色与权限"); await settle(page);
  await page.getByRole("button", { name: "新建角色", exact: true }).click();
  await page.getByRole("dialog").getByPlaceholder("例如 biz_test", { exact: true }).fill("uib");
  const lostKey = `lost_response_${Date.now()}`;
  await page.getByLabel("角色标识", { exact: true }).fill(lostKey);
  await page.getByLabel("角色名称", { exact: true }).fill("UI B uncertain write fixture");
  const writesBeforeLost = calls.filter(c => c.method === "POST" && c.path.endsWith("/access/roles")).length;
  await page.route(writePattern, async route => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch();
    assert.ok(response.ok(), `write response status ${response.status()}`);
    const role = (await response.json()).role;
    assert.equal(role.tenant_id, "tenant-b"); assert.equal(role.business_id, "uib");
    assert.equal(role.key, lostKey); assert.ok(role.role_id);
    const headers = route.request().headers();
    const read = await page.request.get(`${writePattern}/${encodeURIComponent(role.role_id)}`, {
      headers: { authorization: headers.authorization, "x-embedded-idp-tenant-id": headers["x-embedded-idp-tenant-id"], "x-embedded-idp-business-id": headers["x-embedded-idp-business-id"] },
    });
    assert.ok(read.ok(), `readback status ${read.status()}`);
    const saved = await read.json();
    assert.equal(saved.role_id, role.role_id); assert.equal(saved.tenant_id, "tenant-b");
    assert.equal(saved.business_id, "uib"); assert.equal(saved.key, lostKey);
    await route.abort("connectionfailed");
  });
  await page.getByRole("button", { name: "创建角色", exact: true }).click();
  await page.getByRole("dialog", { name: "确认创建角色", exact: true }).getByRole("button", { name: "确认创建", exact: true }).click();
  await page.getByText("操作结果未确认，请先重新加载数据核对，勿重复提交。", { exact: true }).waitFor();
  platform.answer("dismiss");
  await expectDialog(platform, () => setHash(page, "#/tenants/tenant-a/members"));
  await page.waitForURL("**/#/tenants/tenant-b/roles");
  assert.ok((await page.getByRole("dialog", { name: "新建业务角色", exact: true }).innerText()).includes("tenant-b"));
  platform.answer("accept");
  await expectDialog(platform, () => setHash(page, "#/tenants/tenant-a/members")); await waitHeading(page, "成员管理"); await settle(page);
  await page.unroute(writePattern);
  assert.equal(calls.filter(c => c.method === "POST" && c.path.endsWith("/access/roles")).length, writesBeforeLost + 1);
  pass("a committed write with a lost response stays on its original target until explicit departure and is never replayed");
  const unknownHistory = await open("enabled", "#/tenants/tenant-a/roles", "admin@example.test", "#/platform/home");
  await waitHeading(unknownHistory.page, "角色与权限"); await settle(unknownHistory.page);
  await unknownHistory.page.getByRole("button", { name: "新建角色", exact: true }).click();
  await unknownHistory.page.getByLabel("角色名称", { exact: true }).fill("Preserve pre-login history draft");
  await expectDialog(unknownHistory, () => unknownHistory.page.goBack());
  await unknownHistory.page.waitForURL("**/#/tenants/tenant-a/roles");
  assert.equal(await unknownHistory.page.getByLabel("角色名称", { exact: true }).inputValue(), "Preserve pre-login history draft");
  pass("cancelling Back to an unmarked pre-login entry preserves the current page and draft");
  unknownHistory.answer("accept");
  await expectDialog(unknownHistory, () => unknownHistory.page.keyboard.press("Escape"));
  await unknownHistory.page.getByRole("dialog", { name: "新建业务角色", exact: true }).waitFor({ state: "hidden" });
  await menu(unknownHistory.page, "成员管理").click(); await waitHeading(unknownHistory.page, "成员管理");
  await menu(unknownHistory.page, "角色与权限").click(); await waitHeading(unknownHistory.page, "角色与权限"); await settle(unknownHistory.page);
  // Simulate a restored duplicate entry within a managed history chain. Its URL
  // stays identical while Back/Forward must still update the traversal position.
  const duplicateIndex = await unknownHistory.page.evaluate(() => {
    const next = { ...history.state.idpConsoleHistory, index: history.state.idpConsoleHistory.index + 1 };
    history.pushState({ ...history.state, idpConsoleHistory: next }, "", location.href);
    return next.index;
  });
  await unknownHistory.page.goBack(); await unknownHistory.page.goForward();
  await menu(unknownHistory.page, "成员管理").click(); await waitHeading(unknownHistory.page, "成员管理");
  await unknownHistory.page.goBack(); await waitHeading(unknownHistory.page, "角色与权限"); await settle(unknownHistory.page);
  await unknownHistory.page.getByRole("button", { name: "新建角色", exact: true }).click();
  unknownHistory.answer("dismiss");
  await expectDialog(unknownHistory, () => unknownHistory.page.goForward());
  await unknownHistory.page.waitForURL("**/#/tenants/tenant-a/roles");
  assert.equal(await unknownHistory.page.evaluate(() => history.state.idpConsoleHistory.index), duplicateIndex);
  pass("duplicate-hash entries retain their position when cancelling a later Forward");
  if (!functionalOnly) await page.screenshot({ path: `${output}/ui-b-tenant.png`, fullPage: true, animations: "disabled" });
  await setHash(page, "#/platform/clients"); await waitHeading(page, "客户端管理"); await settle(page);
  await page.waitForFunction(() => [...document.querySelectorAll("button")].some(button => button.textContent === "刷新客户端" && !button.disabled));
  if (!functionalOnly) await page.screenshot({ path: `${output}/ui-b-platform.png`, fullPage: true, animations: "disabled" });
  if (!functionalOnly) {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: /^菜\s*单$/ }).click();
  const navigation = page.getByRole("dialog", { name: "管理任务", exact: true });
  await navigation.getByRole("menuitem", { name: "租户管理", exact: true }).click();
  await waitHeading(page, "租户管理"); await navigation.waitFor({ state: "hidden" }); await settle(page);
  const widths = await page.evaluate(() => ({ viewport: innerWidth, document: document.documentElement.scrollWidth }));
  assert.equal(widths.document, widths.viewport);
  if (!functionalOnly) await page.screenshot({ path: `${output}/ui-b-mobile.png`, fullPage: true, animations: "disabled" });
  for (const width of [320, 390, 768, 1024, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const [hash, title] of [["#/platform/tenants", "租户管理"], ["#/platform/clients", "客户端管理"], ["#/tenants/tenant-a/roles", "角色与权限"]]) {
      await setHash(page, hash); await waitHeading(page, title); await settle(page);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), width, `${hash} at ${width}`);
      if (width === 320 && title === "客户端管理") {
        const table = page.locator(".ant-table-content").first();
        const scroll = await table.evaluate(element => {
          const max = element.scrollWidth - element.clientWidth;
          element.scrollLeft = max;
          return { max, left: element.scrollLeft };
        });
        assert.ok(scroll.max > 0 && scroll.left > 0, "narrow client table scrolls locally");
      }
      if (width === 320 && title === "角色与权限") {
        if (!functionalOnly) await page.screenshot({ path: `${output}/ui-b-roles-mobile.png`, fullPage: true, animations: "disabled" });
      }
    }
  }
  await page.setViewportSize({ width: 1440, height: 1000 });
  pass("narrow navigation closes on selection and the page has no global horizontal overflow");
  }
  const disabled = await open("disabled", "#/system/home");
  await waitHeading(disabled.page, "工作台");
  for (const [key, label] of [["members", "成员管理"], ["roles", "角色与权限"], ["directory", "权限目录"], ["diagnostic", "权限诊断"], ["devices", "设备管理"], ["sessions", "会话管理"], ["audit", "审计记录"], ["accounts", "账号安全"], ["clients", "客户端管理"], ["administrators", "系统管理员"]]) {
    await menu(disabled.page, label).click(); await waitHeading(disabled.page, label); await settle(disabled.page);
    assert.ok(disabled.page.url().endsWith(`#/system/${key}`));
  }
  assert.equal(await disabled.page.getByRole("button", { name: "更换管理目标" }).count(), 0);
  for (const [hash, title] of [["#/system/unknown", "页面不存在"], ["#/platform/clients", "无权访问"]]) {
    const before = disabled.calls.length;
    await setHash(disabled.page, hash); await waitHeading(disabled.page, title);
    assert.equal(disabled.calls.length, before);
    await menu(disabled.page, "系统管理员").click(); await waitHeading(disabled.page, "系统管理员"); await settle(disabled.page);
    assert.ok(disabled.page.url().endsWith("#/system/administrators"));
  }
  pass("Disabled retains all nine legacy pages and its dedicated administrator entry");
  const fixed = await open("fixed", "#/tenants/tenant-a/members", "tenant-a@example.test");
  await waitHeading(fixed.page, "成员管理"); await settle(fixed.page);
  const fixedCalls = fixed.calls.length;
  await setHash(fixed.page, "#/platform/clients"); await waitHeading(fixed.page, "无权访问");
  await setHash(fixed.page, "#/tenants/tenant-b/roles"); await waitHeading(fixed.page, "无权访问");
  assert.equal(fixed.calls.length, fixedCalls);
  await menu(fixed.page, "成员管理").click(); await waitHeading(fixed.page, "成员管理"); await settle(fixed.page);
  assert.ok(fixed.calls.slice(fixedCalls).every(c => c.target === undefined || c.target === "tenant-a"));
  pass("Fixed nonzero sessions cannot request platform or another tenant via URL");
  const choose = await open("choose", "#/", "tenant-a@example.test");
  await choose.page.getByRole("button", { name: "进入 UI B tenant-a", exact: true }).click();
  await waitHeading(choose.page, "工作台"); await settle(choose.page);
  const source = await actualSession(choose);
  await choose.page.getByRole("button", { name: "切换登录租户", exact: true }).click();
  await choose.page.getByRole("button", { name: "取消切换，返回当前会话", exact: true }).click();
  await waitHeading(choose.page, "工作台"); assert.deepEqual(await actualSession(choose), source);
  await choose.page.getByRole("button", { name: "切换登录租户", exact: true }).click();
  await choose.page.getByRole("button", { name: "进入 UI B tenant-b", exact: true }).click();
  await waitHeading(choose.page, "工作台"); await settle(choose.page);
  assert.ok(choose.page.url().endsWith("#/tenants/tenant-b/home"));
  const chosen = await actualSession(choose);
  assert.equal(chosen.tenant_id, "tenant-b"); assert.notEqual(chosen.session_id, source.session_id);
  assert.equal(chosen.account_id, source.account_id); assert.equal(chosen.client_id, source.client_id);
  pass("Choose cancellation preserves its source session and completion opens the new login scope");
  for (const id of [".", ".."]) {
    await choose.page.getByRole("button", { name: "切换登录租户", exact: true }).click();
    await choose.page.getByRole("button", { name: `进入 UI B ${id}`, exact: true }).click();
    await waitHeading(choose.page, "工作台"); await settle(choose.page);
    assert.equal((await actualSession(choose)).tenant_id, id);
    await choose.page.reload(); await waitHeading(choose.page, "工作台"); await settle(choose.page);
    assert.equal((await actualSession(choose)).tenant_id, id);
  }
  pass("Choose accepts and restores exact dot tenant identities");
  // One isolated page receives a shortened expiration declaration, retaining
  // the genuine access token. Date.now is advanced only in this page.
  const refreshing = await open("enabled", "#/tenants/tenant-b/roles", "admin@example.test", undefined, true);
  await waitHeading(refreshing.page, "角色与权限"); await settle(refreshing.page);
  await refreshing.page.getByRole("button", { name: "新建角色", exact: true }).click();
  await refreshing.page.getByRole("dialog").getByPlaceholder("例如 biz_test", { exact: true }).fill("uib");
  await refreshing.page.getByLabel("角色标识", { exact: true }).fill(`refresh_guard_${Date.now()}`);
  await refreshing.page.getByLabel("角色名称", { exact: true }).fill("Pending refresh draft");
  let releaseRefresh; const refreshGate = new Promise(resolve => { releaseRefresh = resolve; });
  let sawRefresh; const refreshSeen = new Promise(resolve => { sawRefresh = resolve; });
  const refreshPath = `${refreshing.host.origin}${refreshing.host.mount}/admin/auth/browser/refresh`;
  await refreshing.page.route(refreshPath, async route => { sawRefresh(); await refreshGate; await route.continue(); });
  await refreshing.page.evaluate(() => { const now = Date.now.bind(Date); Date.now = () => now() + 280_000; });
  await refreshing.page.getByRole("button", { name: "创建角色", exact: true }).click();
  await refreshing.page.getByRole("dialog", { name: "确认创建角色", exact: true }).getByRole("button", { name: "确认创建", exact: true }).click();
  await bounded(refreshSeen, "pre-write browser refresh");
  for (const action of [
    // The busy modal intentionally masks background pointer input. Explicit
    // DOM activation exercises the same shell guard in addition to a real hash edit.
    () => menu(refreshing.page, "成员管理").dispatchEvent("click"),
    () => setHash(refreshing.page, "#/tenants/tenant-a/members"),
    () => refreshing.page.getByRole("button", { name: "更换管理目标", exact: true }).dispatchEvent("click"),
  ]) {
    await expectDialog(refreshing, action);
    assert.equal(refreshing.dialogs.at(-1).type, "alert");
    assert.ok(refreshing.page.url().endsWith("#/tenants/tenant-b/roles"));
    assert.equal(await refreshing.page.getByLabel("角色名称", { exact: true }).inputValue(), "Pending refresh draft");
  }
  assert.equal(refreshing.calls.filter(c => c.method === "POST" && c.path.endsWith("/access/roles")).length, 0);
  const post = refreshing.page.waitForResponse(r => r.url() === writePattern.replace(platform.host.origin, refreshing.host.origin) && r.request().method() === "POST");
  releaseRefresh();
  const written = await bounded(post, "post after browser refresh"); assert.ok(written.ok());
  await refreshing.page.getByRole("dialog", { name: "新建业务角色", exact: true }).waitFor({ state: "hidden" });
  const writes = refreshing.calls.filter(c => c.method === "POST" && c.path.endsWith("/access/roles"));
  assert.equal(writes.length, 1); assert.equal(writes[0].target, "tenant-b");
  await refreshing.page.unroute(refreshPath);
  pass("a pending real refresh blocks navigation before one original-target write (time and expiry injected)");
  await setHash(page, "#/platform/clients"); await waitHeading(page, "客户端管理"); await settle(page);
  const other = await platform.context.newPage();
  await other.goto(platform.host.origin + platform.host.ui + "/#/platform/home");
  await other.locator(".management-shell-header").waitFor();
  // Restore preserves the existing session. A subsequent explicit logout changes
  // the shared Cookie and is the event that must invalidate the original tab.
  await other.getByRole("button", { name: "退出登录", exact: true }).click();
  await page.getByText("其他页面已更改此会话，请重新加载后继续。", { exact: true }).waitFor();
  assert.equal(await page.locator(".management-shell").count(), 0);
  await page.getByRole("button", { name: "重新加载", exact: true }).click();
  await page.getByLabel("邮箱", { exact: true }).waitFor();
  assert.equal(await page.locator(".management-shell").count(), 0);
  pass("another tab's logout clears the old workspace and reload returns to login");
  if (!functionalOnly) await disabled.page.screenshot({ path: `${output}/ui-b-system.png`, fullPage: true, animations: "disabled" });
  await menu(disabled.page, "会话管理").click(); await waitHeading(disabled.page, "会话管理"); await settle(disabled.page);
  await disabled.page.getByPlaceholder("用户 ID", { exact: true }).fill("fixture-subject");
  await expectDialog(disabled, () => menu(disabled.page, "系统管理员").click());
  assert.ok(disabled.page.url().endsWith("#/system/sessions"));
  assert.equal(await disabled.page.getByPlaceholder("用户 ID", { exact: true }).inputValue(), "fixture-subject");
  disabled.answer("accept");
  await expectDialog(disabled, () => menu(disabled.page, "系统管理员").click()); await waitHeading(disabled.page, "系统管理员");
  pass("the existing inline subject-session action draft uses the same navigation guard");
  const beforeSkip = new URL(disabled.page.url()).hash;
  await disabled.page.locator(".management-skip").focus(); await disabled.page.keyboard.press("Enter");
  assert.equal(await heading(disabled.page).evaluate(element => element === document.activeElement), true);
  assert.equal(new URL(disabled.page.url()).hash, beforeSkip);
  pass("the keyboard skip-navigation link focuses the page heading without altering its hash");
  const clientPattern = `${disabled.host.origin}${disabled.host.mount}/admin/clients?*`;
  await disabled.page.route(clientPattern, route => route.fulfill({ status: 403, json: {} }));
  await menu(disabled.page, "客户端管理").click(); await waitHeading(disabled.page, "客户端管理");
  await disabled.page.getByText("当前账号无权执行此操作。", { exact: true }).waitFor();
  assert.equal(await disabled.page.locator(".management-shell").count(), 1);
  await disabled.page.unroute(clientPattern);
  await disabled.page.route(clientPattern, route => route.fulfill({ status: 401, json: {} }));
  await disabled.page.getByRole("button", { name: "刷新客户端", exact: true }).click();
  await disabled.page.getByLabel("邮箱", { exact: true }).waitFor();
  assert.equal(await disabled.page.locator(".management-shell").count(), 0);
  pass("ordinary 403 retains the workspace while ordinary 401 clears authenticated page data");
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ passed: results.length, pageErrors: errors.length, output }));
} catch (error) {
  failure = error;
  for (const [index, context] of contexts.entries()) for (const page of context.pages()) {
    if (!functionalOnly) await page.screenshot({ path: `${output}/ui-b-failure-${index}.png`, fullPage: true, animations: "disabled" }).catch(() => {});
  }
  throw error;
} finally {
  await finalizeFunctionalRun({ coverage, contexts, browser, failure,
    resultPath: `${output}/ui-b-results.json`, result: { cases: results, pageErrors: errors, evidence: "real compiled hosts and PostgreSQL; delayed-read/write injections explicitly scoped" } });
}
