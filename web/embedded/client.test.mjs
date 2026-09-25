import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("./client.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } });
const { EmbeddedIdentityClient } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const fixed = { tenancy_enabled: false, login_tenant_policy: "fixed", fixed_tenant_id: "0" };
const choose = { tenancy_enabled: true, login_tenant_policy: "choose_after_authentication" };
const ticket = { status: "tenant_selection_required", selection_ticket: "synthetic-ticket", expires_in: 300 };
const identity = (tenant = "0") => ({ tenant_id: tenant, account_id: "user-1", session_id: "session-1", client_id: "public-app" });
const authenticated = (tenant = "0", ttl = 3600, suffix = "") => ({
  status: "authenticated", session: identity(tenant), tokens: {
    access_token: `synthetic-access${suffix}`, refresh_token: `synthetic-refresh${suffix}`,
    access_expires_at_unix_secs: Math.floor(Date.now() / 1000) + ttl,
    refresh_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 86400,
  },
});

function client(handler) {
  const calls = [];
  const instance = new EmbeddedIdentityClient("/idp", async (url, init) => {
    calls.push({ path: new URL(url, "https://host.test").pathname.replace("/idp", ""), url, ...init });
    assert.equal(init.credentials, "omit");
    assert.equal(init.cache, "no-store");
    assert.equal(init.redirect, "error");
    assert.equal(init.headers["X-Embedded-Idp-Tenant-Id"], undefined);
    return handler(calls.at(-1), calls);
  });
  return { instance, calls };
}

test("disabled and fixed login use public routes and keep tokens out of snapshots", async () => {
  for (const capabilities of [fixed, { tenancy_enabled: true, login_tenant_policy: "fixed", fixed_tenant_id: "tenant-a" }]) {
    const { instance, calls } = client(call => json(call.path === "/auth/access/capabilities" ? capabilities : authenticated(capabilities.fixed_tenant_id)));
    await instance.loadCapabilities();
    await instance.login("user@example.test", "synthetic-password");
    assert.equal(instance.getSnapshot().session.tenant_id, capabilities.fixed_tenant_id);
    assert.equal(JSON.stringify(instance.getSnapshot()).includes("synthetic-access"), false);
    assert.equal(calls[1].path, "/auth/login");
    assert.deepEqual(JSON.parse(calls[1].body), { email: "user@example.test", password: "synthetic-password" });
    assert.equal(calls[1].headers.Authorization, undefined);
    await assert.rejects(instance.beginSwitch());
  }
});

test("choose login pages using ticket, enters selected tenant, then switches without changing subject", async () => {
  const { instance, calls } = client(call => {
    if (call.path === "/auth/access/capabilities") return json(choose);
    if (call.path === "/auth/login" || call.path === "/auth/me/tenant-selection") return json(ticket);
    if (call.path === "/auth/tenant-selection/tenants") return json({ tenants: [
      { tenant_id: "tenant-a", name: "A", status: "active", membership_status: "active" },
      { tenant_id: "tenant-b", name: "B", status: "suspended", membership_status: "active" },
    ], has_more: true, next_cursor: "next+/=" });
    if (call.path === "/auth/tenant-selection/complete") return json(authenticated(JSON.parse(call.body).tenant_id));
    if (call.path === "/auth/session") return json(identity("tenant-a"));
    throw new Error(call.path);
  });
  await instance.loadCapabilities();
  await instance.login("user@example.test", "password");
  assert.equal(instance.getSnapshot().session, undefined);
  const page = await instance.listTenants();
  assert.equal(page.tenants.length, 2);
  await instance.listTenants(page.next_cursor);
  assert.equal(calls[2].headers.Authorization, "TenantSelection synthetic-ticket");
  assert.ok(String(calls[3].url).includes("cursor=next%2B%2F%3D"));
  await instance.selectTenant("tenant-a");
  assert.equal(instance.getSnapshot().session.tenant_id, "tenant-a");
  await instance.verifySession();
  await instance.beginSwitch();
  assert.equal(calls.at(-1).headers.Authorization, "Bearer synthetic-access");
  instance.cancelSelection();
  assert.equal(instance.getSnapshot().session.tenant_id, "tenant-a");
  assert.equal(instance.getSnapshot().selecting, false);
});

test("my roles use the business session and reject another tenant's roles", async () => {
  let wrongTenant = false;
  const { instance, calls } = client(call => {
    if (call.path === "/auth/access/capabilities") return json(fixed);
    if (call.path === "/auth/login") return json(authenticated());
    if (call.path === "/auth/me/roles") return json({ items: [{ tenant_id: wrongTenant ? "other" : "0", role_id: "role-1",
      key: "reader", name: "Reader", status: "active", kind: "business" }], has_more: false, next_cursor: null });
    throw new Error(call.path);
  });
  await instance.loadCapabilities();
  await instance.login("user@example.test", "password");
  assert.equal((await instance.listMyRoles()).items[0].key, "reader");
  assert.equal(calls.at(-1).headers.Authorization, "Bearer synthetic-access");
  assert.equal(calls.at(-1).path, "/auth/me/roles");
  wrongTenant = true;
  await assert.rejects(instance.listMyRoles());
});

test("one refresh serves concurrent checks and an uncertain refresh clears local credentials", async () => {
  let resolveRefresh;
  const pending = new Promise(resolve => { resolveRefresh = resolve; });
  const { instance, calls } = client(call => {
    if (call.path === "/auth/access/capabilities") return json(fixed);
    if (call.path === "/auth/login") return json(authenticated("0", 10));
    if (call.path === "/auth/refresh") return pending;
    if (call.path === "/auth/session") return json(identity());
    throw new Error(call.path);
  });
  await instance.loadCapabilities();
  await instance.login("user@example.test", "password");
  const checks = [instance.verifySession(), instance.verifySession()];
  resolveRefresh(json(authenticated("0", 3600, "-new")));
  await Promise.all(checks);
  assert.equal(calls.filter(call => call.path === "/auth/refresh").length, 1);
  assert.ok(calls.filter(call => call.path === "/auth/session").every(call => call.headers.Authorization === "Bearer synthetic-access-new"));
  assert.equal(await instance.accessToken(), "synthetic-access-new");

  const bad = client(call => {
    if (call.path === "/auth/access/capabilities") return json(fixed);
    if (call.path === "/auth/login") return json(authenticated("0", 10));
    throw new Error("lost refresh response");
  });
  await bad.instance.loadCapabilities();
  await bad.instance.login("user@example.test", "password");
  await assert.rejects(bad.instance.verifySession());
  assert.equal(bad.instance.getSnapshot().session, undefined);
  assert.equal(bad.calls.filter(call => call.path === "/auth/refresh").length, 1);
});

test("logout prevents a pending refresh from returning an access token", async () => {
  let resolveRefresh;
  const pending = new Promise(resolve => { resolveRefresh = resolve; });
  const { instance } = client(call => {
    if (call.path === "/auth/access/capabilities") return json(fixed);
    if (call.path === "/auth/login") return json(authenticated("0", 10));
    if (call.path === "/auth/refresh") return pending;
    if (call.path === "/auth/logout") return new Response(null, { status: 200 });
    throw new Error(call.path);
  });
  await instance.loadCapabilities();
  await instance.login("user@example.test", "password");
  const token = instance.accessToken();
  await instance.logout();
  resolveRefresh(json(authenticated("0", 3600, "-new")));
  await assert.rejects(token);
  assert.equal(instance.getSnapshot().session, undefined);
});

test("logout clears local state before sending the refresh-token form", async () => {
  const { instance, calls } = client(call => {
    if (call.path === "/auth/access/capabilities") return json(fixed);
    if (call.path === "/auth/login") return json(authenticated());
    if (call.path === "/auth/logout") {
      assert.equal(instance.getSnapshot().session, undefined);
      return new Response(null, { status: 200 });
    }
    throw new Error(call.path);
  });
  await instance.loadCapabilities();
  await instance.login("user@example.test", "password");
  await instance.logout();
  assert.equal(calls.at(-1).headers["Content-Type"], "application/x-www-form-urlencoded");
  assert.deepEqual(Object.fromEntries(new URLSearchParams(calls.at(-1).body)), { refresh_token: "synthetic-refresh", client_id: "public-app" });
  assert.equal(calls.at(-1).headers.Authorization, undefined);
});

test("invalid tenant or cross-domain session response is rejected", async () => {
  const { instance } = client(call => {
    if (call.path === "/auth/access/capabilities") return json(choose);
    if (call.path === "/auth/login") return json(ticket);
    if (call.path === "/auth/tenant-selection/complete") return json(authenticated("tenant-b"));
    throw new Error(call.path);
  });
  await instance.loadCapabilities();
  await instance.login("user@example.test", "password");
  await assert.rejects(instance.selectTenant("0"));
  await assert.rejects(instance.selectTenant("tenant-a"));
  assert.equal(instance.getSnapshot().session, undefined);
});
