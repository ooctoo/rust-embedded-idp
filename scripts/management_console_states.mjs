import assert from "node:assert/strict";

const LIST_SPECS = [
  { name: "platform tenants", key: "enabled", home: "#/platform/home", hash: "#/platform/tenants", path: "/admin/tenants?", empty: "暂无租户", target: false },
  { name: "platform accounts", key: "enabled", home: "#/platform/home", hash: "#/platform/accounts", path: "/admin/platform/accounts?", empty: "暂无账号", target: false, search: "查询", heading: "账号安全" },
  { name: "platform administrators", key: "enabled", home: "#/platform/home", hash: "#/platform/administrators", path: "/admin/platform/accounts?", empty: "没有符合条件的用户", target: false, search: "查询用户", heading: "系统管理员" },
  { name: "platform clients", key: "enabled", home: "#/platform/home", hash: "#/platform/clients", path: "/admin/clients?", empty: "尚无客户端配置，可按 ID 登记接入应用。", target: false },
  { name: "platform directory", key: "enabled", home: "#/platform/home", hash: "#/platform/directory", path: "/admin/platform/permissions?", empty: "没有符合条件的权限", target: false, readOnly: true },
  { name: "platform audit", key: "enabled", home: "#/platform/home", hash: "#/platform/audit", path: "/admin/platform/audit-events?", empty: "没有符合条件的审计记录", target: false },
  { name: "tenant members", key: "enabled", home: "#/tenants/tenant-a/home", hash: "#/tenants/tenant-a/members", path: "/admin/accounts?", empty: "此域暂无成员。", target: true },
  { name: "tenant roles", key: "enabled", home: "#/tenants/tenant-a/home", hash: "#/tenants/tenant-a/roles", path: "/admin/access/roles?", empty: "此域暂无角色", target: true },
  { name: "tenant devices", key: "enabled", home: "#/tenants/tenant-a/home", hash: "#/tenants/tenant-a/devices", path: "/admin/devices?", empty: "没有符合条件的设备", target: true },
  { name: "tenant sessions", key: "enabled", home: "#/tenants/tenant-a/home", hash: "#/tenants/tenant-a/sessions", path: "/admin/sessions?", empty: "没有符合条件的会话", target: true },
  { name: "tenant directory", key: "enabled", home: "#/tenants/tenant-a/home", hash: "#/tenants/tenant-a/directory", path: "/admin/access/permissions?", empty: "没有符合条件的权限", target: true },
  { name: "tenant audit", key: "enabled", home: "#/tenants/tenant-a/home", hash: "#/tenants/tenant-a/audit", path: "/admin/access/audit-events?", empty: "没有符合条件的审计记录", target: true },
];

const waitForVisible = async (page, selectors) => {
  const locator = page.locator(selectors).first();
  await locator.waitFor({ state: "visible" });
  return locator;
};

const listBody = body => {
  assert.ok(body && typeof body === "object" && Array.isArray(body.items), "the first list response must be a real page");
  return { ...body, items: [], has_more: false, next_cursor: null };
};

/**
 * Run read-state checks; each page/state uses a fresh browser context.
 * The caller owns browser/fixture setup and supplies the repository's helpers.
 */
export async function runStateChecks({ open, goto, settle, button, pass }) {
  assert.equal(typeof open, "function");
  assert.equal(typeof goto, "function");
  assert.equal(typeof settle, "function");
  assert.equal(typeof button, "function");
  assert.equal(typeof pass, "function");

  async function withCase(spec, mode, check) {
    const test = await open(spec.key, spec.home);
    const { page, context, host } = test;
    const endpoint = `${host.origin}${host.mount}${spec.path}`;
    let firstBody;
    let releaseHeld;
    let markSeen;
    let markDelivered;
    const held = new Promise(resolve => { releaseHeld = resolve; });
    const seen = new Promise(resolve => { markSeen = resolve; });
    const delivered = new Promise(resolve => { markDelivered = resolve; });
    const handler = async route => {
      if (route.request().method() !== "GET") return route.continue();
      if (mode === "loading") {
        const response = await route.fetch();
        assert.ok(response.ok(), `${spec.name}: loading probe requires a real successful response`);
        firstBody = await response.body();
        markSeen();
        await held;
        await route.fulfill({ response, body: firstBody });
        markDelivered();
        return;
      }
      if (mode === "empty") {
        const response = await route.fetch();
        assert.ok(response.ok(), `${spec.name}: empty probe requires a real successful response`);
        const body = await response.json();
        firstBody = body;
        return route.fulfill({ status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify(listBody(body)) });
      }
      if (mode === "503" || mode === "403" || mode === "401") {
        return route.fulfill({ status: Number(mode), headers: { "content-type": "application/json" }, body: "{}" });
      }
      return route.continue();
    };
    try {
      await page.route(`${endpoint}*`, handler);
      await check({ test, page, host, endpoint, seen, release: releaseHeld, delivered });
    } finally {
      releaseHeld();
      await page.unroute(`${endpoint}*`, handler).catch(() => {});
      await context.close();
    }
  }

  async function activateList(page, spec, loading = false) {
    if (!spec.search) {
      if (loading) await page.evaluate(hash => { location.hash = hash; }, spec.hash);
      else await goto(page, spec.hash);
      return;
    }
    if (loading) {
      await page.evaluate(hash => { location.hash = hash; }, spec.hash);
      await page.locator(".management-content > h1").filter({ hasText: spec.heading }).waitFor();
    } else {
      await goto(page, spec.hash);
    }
    await button(page, spec.search).click();
  }

  for (const spec of LIST_SPECS) {
    await withCase(spec, "loading", async ({ page, seen, release, delivered }) => {
      await activateList(page, spec, true);
      await Promise.race([seen, page.waitForTimeout(15000).then(() => { throw new Error(`${spec.name}: list response not observed`); })]);
      await waitForVisible(page, '[role="status"].management-workflow-loading, [role="status"].management-client-loading');
      pass(`${spec.name}: loading status is visible before the real list response completes`);
      release();
      await delivered;
      await settle(page);
    });

    await withCase(spec, "empty", async ({ page }) => {
      await activateList(page, spec);
      await page.getByText(spec.empty, { exact: true }).waitFor();
      assert.equal(await page.getByText("读取失败", { exact: true }).count(), 0);
      pass(`${spec.name}: an injected empty page has a distinct empty state`);
    });

    await withCase(spec, "503", async ({ page }) => {
      await activateList(page, spec);
      await page.locator(".ant-result-error, .ant-result-403, .ant-result-404").first().waitFor({ state: "visible" });
      assert.equal(await page.getByText(spec.empty, { exact: true }).count(), 0);
      pass(`${spec.name}: 503 remains an error and is not rendered as empty`);
    });

    await withCase(spec, "403", async ({ page, test }) => {
      const before = await page.request.get(`${hostUrl(test.host)}/admin/auth/session`, { headers: { authorization: test.bearer() } });
      assert.equal(before.status(), 200);
      const identity = await before.json();
      await activateList(page, spec);
      await page.getByText(/无权读取此管理范围|无权读取客户端配置|无权访问/, { exact: false }).first().waitFor();
      const after = await page.request.get(`${hostUrl(test.host)}/admin/auth/session`, { headers: { authorization: test.bearer() } });
      assert.equal(after.status(), 200);
      assert.deepEqual(await after.json(), identity);
      assert.ok(await page.locator(".management-shell").count());
      pass(`${spec.name}: 403 preserves the authenticated workspace and identity`);
    });

    await withCase(spec, "401", async ({ page, test }) => {
      await activateList(page, spec);
      await page.locator(".management-shell").waitFor({ state: "hidden" });
      await page.getByLabel("邮箱", { exact: true }).waitFor();
      assert.equal(await page.locator(".management-shell").count(), 0);
      pass(`${spec.name}: 401 clears the management workspace and returns to login`);
    });
  }

  // Platform directory is intentionally read-only when tenancy is enabled.
  const readOnly = LIST_SPECS.find(spec => spec.readOnly);
  const test = await open(readOnly.key, readOnly.home);
  try {
    let writes = 0;
    const onRequest = request => {
      if (["POST", "PATCH", "DELETE"].includes(request.method()) && /\/admin\/(access|platform)\/permissions/.test(request.url())) writes++;
    };
    test.page.on("request", onRequest);
    await goto(test.page, readOnly.hash);
    await settle(test.page);
    for (const name of ["创建权限", "编辑", "启用", "停用", "归档"]) {
      assert.equal(await button(test.page, name).count(), 0, `platform directory must not expose ${name}`);
    }
    const refresh = test.page.waitForResponse(response => response.request().method() === "GET" && response.url().startsWith(`${test.host.origin}${test.host.mount}${readOnly.path.slice(0, -1)}`));
    await button(test.page, "刷新目录").click();
    assert.ok((await refresh).ok());
    test.page.off("request", onRequest);
    assert.equal(writes, 0);
    pass("platform directory remains read-only without permission mutation controls or POST");
  } finally {
    await test.context.close();
  }
}

function hostUrl(host) {
  return `${host.origin}${host.mount}`;
}
