import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("./client.ts", import.meta.url), "utf8");
const browserSource = await readFile(new URL("./browser-session.ts", import.meta.url), "utf8");
const browserModule = ts.transpileModule(browserSource, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const { outputText } = ts.transpileModule(source.replace('import { BrowserSessionCoordinator } from "./browser-session";', browserModule), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } });
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

function cookieEnvironment(t) {
  const values = new Map();
  const listeners = new Set();
  const events = [];
  const tails = new Map();
  const storage = { getItem: key => values.get(key) ?? null, setItem: (key, value) => { values.set(key, value); events.push({ key, newValue: value }); }, removeItem: key => { values.delete(key); } };
  const oldStorage = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  const oldNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const oldWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: storage });
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { locks: { request: async (key, _options, operation) => {
    const previous = tails.get(key) ?? Promise.resolve();
    let release;
    const current = new Promise(resolve => { release = resolve; });
    tails.set(key, current);
    await previous;
    try { return await operation(); } finally { release(); if (tails.get(key) === current) tails.delete(key); }
  } } } });
  Object.defineProperty(globalThis, "window", { configurable: true, value: { addEventListener: (_type, listener) => listeners.add(listener), removeEventListener: (_type, listener) => listeners.delete(listener) } });
  t.after(() => { for (const [key, descriptor] of [["localStorage", oldStorage], ["navigator", oldNavigator], ["window", oldWindow]]) descriptor ? Object.defineProperty(globalThis, key, descriptor) : delete globalThis[key]; });
  return { values, events, emitStorage() { while (events.length) { const event = events.shift(); listeners.forEach(listener => listener(event)); } } };
}

test("cookie mode restores without page refresh tokens and serializes shared session operations", async t => {
  const environment = cookieEnvironment(t);
  const calls = [];
  const handler = async (url, init) => {
    const path = new URL(url, "https://host.test").pathname.replace("/idp", "");
    calls.push({ path, init });
    if (path.startsWith("/auth/browser/")) {
      assert.equal(init.credentials, "same-origin");
      assert.equal(init.headers["X-Embedded-Idp-Browser"], "1");
    }
    if (path === "/auth/access/capabilities") return json(fixed);
    if (path === "/auth/browser/login" || path === "/auth/browser/restore" || path === "/auth/browser/refresh") {
      const value = authenticated("0", 3600, "-cookie");
      delete value.tokens.refresh_token;
      return json(value);
    }
    if (path === "/auth/browser/logout") return new Response(null, { status: 204 });
    if (path === "/auth/session") return json(identity());
    throw new Error(path);
  };
  const first = new EmbeddedIdentityClient("/idp", handler, { mode: "cookie" });
  const second = new EmbeddedIdentityClient("/idp", handler, { mode: "cookie" });
  await first.loadCapabilities();
  await first.login("user@example.test", "password");
  assert.equal(first.getSnapshot().session.tenant_id, "0");
  assert.equal(JSON.stringify(first.getSnapshot()).includes("refresh"), false);
  await second.loadCapabilities();
  await second.restore();
  assert.equal(second.getSnapshot().session.session_id, "session-1");
  await Promise.all([first.accessToken(), second.accessToken()]);
  assert.equal(calls.filter(call => call.path === "/auth/browser/refresh").length, 0);
  await second.logout();
  assert.equal(second.getSnapshot().session, undefined);
});

test("expired Cookie access tokens refresh under one shared Web Lock", async t => {
  cookieEnvironment(t);
  let active = 0, maximum = 0, refreshCalls = 0, releaseRefresh, signalRefresh;
  const refreshGate = new Promise(resolve => { releaseRefresh = resolve; });
  const refreshStarted = new Promise(resolve => { signalRefresh = resolve; });
  const handler = async (url, init) => {
    const path = new URL(url, "https://host.test").pathname.replace("/idp", "");
    if (path === "/auth/access/capabilities") return json(fixed);
    if (path === "/auth/browser/login" || path === "/auth/browser/restore") { const value = authenticated("0", 1); delete value.tokens.refresh_token; return json(value); }
    if (path === "/auth/browser/refresh") {
      refreshCalls++; active++; maximum = Math.max(maximum, active);
      if (refreshCalls === 1) signalRefresh(); await refreshGate;
      active--; const value = authenticated("0", 3600, `-${refreshCalls}`); delete value.tokens.refresh_token; return json(value);
    }
    if (path === "/auth/session") return json(identity());
    throw new Error(path);
  };
  const first = new EmbeddedIdentityClient("/idp", handler, { mode: "cookie" });
  const second = new EmbeddedIdentityClient("/idp/.", handler, { mode: "cookie" });
  await first.loadCapabilities(); await second.loadCapabilities(); await first.login("user@example.test", "password"); await second.restore();
  const pending = Promise.all([first.accessToken(), second.accessToken()]); await refreshStarted; releaseRefresh(); await pending;
  assert.equal(maximum, 1);
  assert.equal(refreshCalls, 2);
});

test("same-client restore is single-flight and sends expected identity when a session already exists", async t => {
  cookieEnvironment(t);
  let resolveRestore, restoreCalls = 0;
  const restoreGate = new Promise(resolve => { resolveRestore = resolve; });
  const calls = [];
  const handler = async (url, init) => {
    const path = new URL(url, "https://host.test").pathname.replace("/idp", ""); calls.push({ path, init });
    if (path === "/auth/access/capabilities") return json(fixed);
    if (path === "/auth/browser/login") { const value = authenticated("0", 3600, "-login"); delete value.tokens.refresh_token; return json(value); }
    if (path === "/auth/browser/restore") { restoreCalls++; await restoreGate; const value = authenticated("0", 3600, "-restore"); delete value.tokens.refresh_token; return json(value); }
    throw new Error(path);
  };
  const client = new EmbeddedIdentityClient("/idp", handler, { mode: "cookie" }); await client.loadCapabilities();
  await client.login("user@example.test", "password");
  const first = client.restore(); const second = client.restore();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(restoreCalls, 1); assert.deepEqual(JSON.parse(calls.at(-1).init.body).expected_session, identity());
  resolveRestore(); await Promise.all([first, second]); assert.equal(restoreCalls, 1);
});

test("stale 409 does not block a replacement Cookie login", async t => {
  cookieEnvironment(t);
  let restoreCalls = 0;
  const handler = async (url, init) => {
    const path = new URL(url, "https://host.test").pathname.replace("/idp", "");
    if (path === "/auth/access/capabilities") return json(fixed);
    if (path === "/auth/browser/login") { const value = authenticated("0", 3600, "-new"); delete value.tokens.refresh_token; return json(value); }
    if (path === "/auth/browser/restore") { restoreCalls++; return json({ error: "browser_session_changed" }, 409); }
    throw new Error(path);
  };
  const client = new EmbeddedIdentityClient("/idp", handler, { mode: "cookie" }); await client.loadCapabilities();
  await client.login("user@example.test", "password"); await assert.rejects(client.restore(), error => error.status === 409);
  await client.login("user@example.test", "password"); assert.equal(client.getSnapshot().session.tenant_id, "0");
  assert.equal(restoreCalls, 1);
});

test("same-document clients detect marker replacement even when storage events are missed", async t => {
  cookieEnvironment(t);
  const response = tenant => { const value = authenticated(tenant, 3600, `-${tenant}`); delete value.tokens.refresh_token; return json(value); };
  const handler = async (url, init) => {
    const path = new URL(url, "https://host.test").pathname.replace("/idp", "");
    if (path === "/auth/access/capabilities") return json(fixed);
    if (path === "/auth/browser/login" || path === "/auth/browser/restore") return response("0");
    if (path === "/auth/session") return json(identity());
    throw new Error(path);
  };
  const first = new EmbeddedIdentityClient("/idp", handler, { mode: "cookie" }); const second = new EmbeddedIdentityClient("/idp", handler, { mode: "cookie" });
  await first.loadCapabilities(); await second.loadCapabilities(); await first.login("user@example.test", "password"); await second.restore();
  await first.login("user@example.test", "password");
  await assert.rejects(second.accessToken()); assert.equal(second.getSnapshot().session, undefined);
});

test("cookie coordination rejects stale tenant refreshes, keeps delayed events from clearing newer restore, and requires login after uncertain restore", async t => {
  const environment = cookieEnvironment(t);
  let restoreFailure = false;
  let tenant = "tenant-a";
  const handler = async (url, init) => {
    const path = new URL(url, "https://host.test").pathname.replace("/idp", "");
    if (path === "/auth/access/capabilities") return json(choose);
    if (path === "/auth/browser/login") return json(ticket);
    if (path === "/auth/browser/tenant-selection/complete") return json({ ...authenticated(tenant, 3600, `-${tenant}`), tokens: { access_token: `access-${tenant}`, access_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 10, refresh_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 86400 } });
    if (path === "/auth/browser/restore") {
      if (restoreFailure) throw new Error("network");
      const value = authenticated(tenant, 3600, `-${tenant}`); delete value.tokens.refresh_token; return json(value);
    }
    if (path === "/auth/browser/refresh") {
      const value = authenticated(tenant, 3600, `-${tenant}`); delete value.tokens.refresh_token; return json(value);
    }
    throw new Error(path);
  };
  const first = new EmbeddedIdentityClient("/idp", handler, { mode: "cookie" });
  const second = new EmbeddedIdentityClient("/idp", handler, { mode: "cookie" });
  await first.loadCapabilities(); await second.loadCapabilities();
  await first.login("user@example.test", "password");
  // A stale event from the first login must not clear the newer restored identity.
  await second.restore();
  environment.emitStorage();
  assert.equal(second.getSnapshot().session.tenant_id, "tenant-a");
  restoreFailure = true;
  await assert.rejects(first.restore());
  await assert.rejects(first.restore());
  assert.equal(first.getSnapshot().session, undefined);
  restoreFailure = false;
  tenant = "tenant-b";
  await first.login("user@example.test", "password");
  assert.equal(first.getSnapshot().session, undefined);
});

test("cookie logout clears local identity before an in-flight refresh completes", async t => {
  cookieEnvironment(t);
  let resolveRefresh;
  const refresh = new Promise(resolve => { resolveRefresh = resolve; });
  let refreshStarted;
  const started = new Promise(resolve => { refreshStarted = resolve; });
  const handler = async (url, init) => {
    const path = new URL(url, "https://host.test").pathname.replace("/idp", "");
    if (path === "/auth/access/capabilities") return json(fixed);
    if (path === "/auth/browser/login" || path === "/auth/browser/restore") { const value = authenticated("0", 10); delete value.tokens.refresh_token; return json(value); }
    if (path === "/auth/browser/refresh") { refreshStarted(); return refresh; }
    if (path === "/auth/browser/logout") return new Response(null, { status: 204 });
    throw new Error(path);
  };
  const client = new EmbeddedIdentityClient("/idp", handler, { mode: "cookie" });
  await client.loadCapabilities(); await client.login("user@example.test", "password");
  const pending = client.accessToken(); await started;
  const logout = client.logout();
  assert.equal(client.getSnapshot().session, undefined);
  resolveRefresh(json({ ...authenticated("0", 3600), tokens: { access_token: "late", access_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 3600, refresh_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 86400 } }));
  await assert.rejects(pending); await logout;
});

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
    if (call.path === "/auth/me/roles") return json({ items: [{ tenant_id: wrongTenant ? "other" : "0", business_id: "f_01", role_id: "role-1",
      key: "reader", name: "Reader", status: "active", kind: "business" }], has_more: false, next_cursor: null });
    throw new Error(call.path);
  });
  await instance.loadCapabilities();
  await instance.login("user@example.test", "password");
  assert.equal((await instance.listMyRoles("f_01")).items[0].key, "reader");
  assert.equal(calls.at(-1).headers.Authorization, "Bearer synthetic-access");
  assert.equal(calls.at(-1).path, "/auth/me/roles");
  assert.ok(String(calls.at(-1).url).includes("business_id=f_01"));
  wrongTenant = true;
  await assert.rejects(instance.listMyRoles("f_01"));
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

test("Cookie mode rejects cross-origin endpoints and leaked refresh credentials", async t => {
  cookieEnvironment(t);
  assert.throws(() => new EmbeddedIdentityClient("https://other.example/idp", undefined, { mode: "cookie" }), /同源/);
  const client = new EmbeddedIdentityClient("/idp", async url => json(url.endsWith("capabilities") ? fixed : authenticated()), { mode: "cookie" });
  await client.loadCapabilities();
  await assert.rejects(client.login("user@example.test", "password"));
  assert.equal(client.getSnapshot().session, undefined);
});
