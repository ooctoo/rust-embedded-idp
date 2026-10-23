import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

// UI-F UX18 checks. The caller owns browser/fixture setup; this module only
// drives the existing tenant and role management UI and uses independent
// management reads to verify the durable boundary.
export async function runTenantChecks({ open, goto, settle, button, pass, accepting }) {
  for (const [name, value] of Object.entries({ open, goto, settle, button, pass, accepting })) {
    assert.equal(typeof value, "function", `${name} helper is required`);
  }

  const id = randomBytes(6).toString("hex");
  const tenant = `uif-${id}`;
  const tenantName = `UI F tenant ${id}`;
  const email = `uif-admin-${id}@example.test`;
  const password = "UIF-Initial-Password-123";

  const dialog = (page, name) => page.getByRole("dialog", { name, exact: true });
  const authHeaders = test => ({ authorization: test.bearer() });
  async function read(test, path, target) {
    const response = await test.page.request.get(`${test.host.origin}${test.host.mount}/admin${path}`, {
      headers: { ...authHeaders(test), ...(target ? { "x-embedded-idp-tenant-id": target } : {}) },
    });
    assert.ok(response.ok(), `${path}: ${response.status()}`);
    return response.json();
  }
  async function tenantEvidence(test) {
    const record = await read(test, `/tenants/${encodeURIComponent(tenant)}`);
    assert.equal(record.tenant_id, tenant);
    const members = await read(test, `/accounts?email=${encodeURIComponent(email)}&limit=50`, tenant);
    const member = members.items.find(item => item.email.toLowerCase() === email.toLowerCase());
    assert.ok(member, "the initial administrator account must be readable in the new tenant");
    assert.equal(member.membership.status, "active");
    const admin = await read(test, `/access/security-admins/${encodeURIComponent(member.account_id)}`, tenant);
    assert.equal(admin.account.account_id, member.account_id);
    assert.ok(admin.binding, "the initial administrator binding must be readable");
    return { record, member, admin };
  }

  const test = await open("enabled", "#/platform/tenants");
  const { page, host } = test;
  const tenantPath = `${host.origin}${host.mount}/admin/tenants/${encodeURIComponent(tenant)}`;
  const createPath = `${host.origin}${host.mount}/admin/tenants`;
  const tenantPathname = new URL(tenantPath).pathname;
  let createPosts = 0;
  let independentEvidence;
  await page.route(createPath, async route => {
    if (route.request().method() !== "POST") return route.continue();
    createPosts += 1;
    const response = await route.fetch();
    assert.ok(response.ok(), `tenant creation: ${response.status()}`);
    const body = route.request().postDataJSON();
    assert.equal(body.tenant_id, tenant);
    assert.equal(body.administrator.kind, "new");
    assert.equal(body.administrator.email, email);
    independentEvidence = await tenantEvidence(test);
    await route.abort("connectionfailed");
  });

  let editor;
  try {
    await button(page, "创建租户").click();
    editor = dialog(page, "创建租户");
    await editor.getByLabel("租户 ID", { exact: true }).fill(tenant);
    await editor.getByLabel("租户名称", { exact: true }).fill(tenantName);
    await editor.getByLabel("管理员邮箱", { exact: true }).fill(email);
    await editor.getByLabel("初始密码", { exact: true }).fill(password);
    await button(editor, "核对并创建").click();
    const review = dialog(page, "确认创建租户");
    assert.ok(!(await review.innerText()).includes(password), "the initial password must not enter the confirmation summary");
    await button(review, "确认提交").click();
    await page.getByText("写入结果未确认，请先核对原对象，勿重复提交", { exact: true }).waitFor();
    assert.equal(createPosts, 1);
    assert.ok(independentEvidence?.record && independentEvidence.member && independentEvidence.admin);
    assert.equal(await editor.getByLabel("初始密码", { exact: true }).inputValue(), "", "password must be cleared after the unknown write");
    assert.ok(await button(editor, "重新加载租户").isEnabled());
    assert.ok(await button(editor, "核对并创建").isDisabled(), "unknown creation must remain locked before original-ID recovery");

    let tenantReads = 0;
    await page.route(tenantPath, async route => {
      if (route.request().method() !== "GET") return route.continue();
      tenantReads += 1;
      if (tenantReads === 1) return route.fulfill({ status: 503, headers: { "content-type": "application/json" }, body: "{}" });
      return route.continue();
    });
    await accepting(page, () => button(editor, "重新加载租户").click());
    await editor.getByText("读取失败", { exact: true }).waitFor();
    assert.equal(await editor.locator('button[type="submit"]:enabled').count(), 0, "a failed original read must retain the write lock");
    await accepting(page, () => button(editor, "重新加载租户").click());
    await editor.getByText("当前可读取到租户", { exact: false }).waitFor();
    assert.equal(tenantReads, 2);
    assert.equal(createPosts, 1, "original-ID recovery must not replay tenant creation");
    assert.ok((await editor.innerText()).includes("回读不能证明初始密码写入或请求归因"));
    assert.equal(await editor.locator('button[type="submit"]:enabled').count(), 0);
    pass("tenant creation unknown result: independent tenant/member/admin readback, password clearing, failed-read lock and no replay");
  } finally {
    await page.unroute(createPath).catch(() => {});
    await page.unroute(tenantPath).catch(() => {});
  }

  await goto(page, `#/tenants/${tenant}/roles`);
  await settle(page);
  assert.equal(await page.getByText("失败全部回滚", { exact: true }).count(), 0, "follow-up configuration must not claim whole-wizard rollback");
  const rolePath = `${host.origin}${host.mount}/admin/access/roles`;
  let rolePosts = 0;
  let compensatingDeletes = 0;
  const onRequest = request => {
    const url = new URL(request.url());
    if ((url.pathname === tenantPathname && request.method() === "DELETE") ||
        (url.pathname === new URL(createPath).pathname && request.method() === "PATCH" && request.postDataJSON()?.tenant_id === tenant)) compensatingDeletes += 1;
  };
  page.on("request", onRequest);
  try {
    await button(page, "新建角色").click();
    const form = dialog(page, "新建业务角色");
    const business = `uif_biz_${id}`;
    await form.getByLabel("业务标识", { exact: true }).fill(business);
    await form.getByLabel("角色标识", { exact: true }).fill(`reader_${id}`);
    await form.getByLabel("角色名称", { exact: true }).fill(`UI F reader ${id}`);
    await button(form, "创建角色").click();
    const review = dialog(page, "确认创建角色");
    await page.route(rolePath, route => {
      if (route.request().method() === "POST") {
        rolePosts += 1;
        return route.fulfill({ status: 503, headers: { "content-type": "application/json" }, body: "{}" });
      }
      return route.continue();
    });
    await button(review, "确认创建").click();
    await page.getByText("写入结果未确认，请先核对原对象，勿重复提交", { exact: true }).waitFor();
    assert.equal(rolePosts, 1);
    assert.equal(compensatingDeletes, 0);
    const evidence = await tenantEvidence(test);
    assert.equal(evidence.record.tenant_id, tenant);
    assert.equal(evidence.member.account_id, independentEvidence.member.account_id);
    assert.ok(evidence.admin.binding);
    assert.ok(!(await page.getByText("整个向导回滚", { exact: false }).count()));
    pass("post-creation role failure: tenant and initial administrator survive without compensating tenant deletion or rollback claim");
  } finally {
    await page.unroute(rolePath).catch(() => {});
    page.off("request", onRequest);
  }
}
