import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

// Use the installed compiler so these checks also run on Node 22 without TS loaders.
const source = await readFile(new URL("./client.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } });
const { ManagementClient } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);
const fixed = { tenancy_enabled: false, login_tenant_policy: "fixed", fixed_tenant_id: "0" };
const choose = { tenancy_enabled: true, login_tenant_policy: "choose_after_authentication" };
const ticket = { status: "tenant_selection_required", selection_ticket: "synthetic-ticket", expires_in: 300 };
const identity = (tenant = "0") => ({ tenant_id: tenant, account_id: "synthetic-user", session_id: "synthetic-session" });
const authenticated = (tenant = "0", ttl = 3600, suffix = "") => ({
  status: "authenticated", session: identity(tenant), tokens: {
    access_token: `synthetic-access${suffix}`, refresh_token: `synthetic-refresh${suffix}`,
    access_expires_at_unix_secs: Math.floor(Date.now() / 1000) + ttl,
    refresh_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 86400,
  },
});
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };

function setup(t, handler) {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (url, init) => {
    const adminPath = String(url).replace("/host/idp/admin", "");
    const path = adminPath.replace(/^\/auth/, "");
    calls.push({ path, ...init });
    assert.equal(init.credentials, "omit");
    assert.equal(init.redirect, "error");
    assert.equal(init.cache, "no-store");
    if (adminPath.startsWith("/auth/") || adminPath.startsWith("/tenants")) assert.equal(init.headers["X-Embedded-Idp-Tenant-Id"], undefined);
    assert.equal(init.headers["x-embedded-idp-admin-key"], undefined);
    return handler(path, init);
  });
  return { client: new ManagementClient("/host/idp"), calls };
}

test("disabled and fixed login obey server capabilities, keep credentials out of snapshots", async t => {
  for (const capabilities of [fixed, { ...fixed, tenancy_enabled: true, fixed_tenant_id: "tenant-a" }, { ...fixed, tenancy_enabled: true }]) {
    const { client, calls } = setup(t, path => json(path === "/capabilities" ? capabilities : authenticated(capabilities.fixed_tenant_id)));
    await client.loadCapabilities();
    await client.login("admin@example.test", "synthetic-password");
    assert.equal(client.getSnapshot().session.tenant_id, capabilities.fixed_tenant_id);
    assert.equal(client.canChoose(), false);
    await assert.rejects(client.beginSwitch());
    assert.equal(calls.length, 2);
    assert.equal(calls[1].headers.Authorization, undefined);
    assert.equal(JSON.stringify(client.getSnapshot()).includes("synthetic-access"), false);
    assert.equal(new ManagementClient().getSnapshot().session, undefined);
  }
});

test("choose pagination uses selection ticket only; switch can cancel to source session", async t => {
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json(choose);
    if (path === "/login" || path === "/me/tenant-selection") return json(ticket);
    if (path.startsWith("/tenant-selection/tenants")) return json({ tenants: [
      { tenant_id: "a", name: "A", status: "active", membership_status: "active" },
      { tenant_id: "b", name: "B", status: "suspended", membership_status: "active" },
    ], has_more: true, next_cursor: "cursor+/=" });
    if (path === "/tenant-selection/complete") return json(authenticated(JSON.parse(init.body).tenant_id));
    if (path === "/session") return json(identity("a"));
    throw new Error(path);
  });
  await client.loadCapabilities();
  await client.login("admin@example.test", "synthetic-password");
  assert.equal(client.getSnapshot().session, undefined);
  const page = await client.listTenants();
  await client.listTenants(page.next_cursor);
  assert.equal(calls[2].headers.Authorization, "TenantSelection synthetic-ticket");
  assert.ok(calls[3].path.endsWith("cursor=cursor%2B%2F%3D"));
  await client.selectTenant("a");
  await client.beginSwitch();
  assert.equal(calls.at(-1).headers.Authorization, "Bearer synthetic-access");
  client.cancelSelection();
  assert.equal(client.getSnapshot().session.tenant_id, "a");
  assert.equal(client.getSnapshot().selecting, false);
  await client.verifySession();
});

test("concurrent session checks rotate refresh once and use only the new access token", async t => {
  const refresh = deferred();
  const started = deferred();
  const { client, calls } = setup(t, path => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated("0", 10));
    if (path === "/refresh") { started.resolve(); return refresh.promise; }
    return json(identity());
  });
  await client.loadCapabilities();
  await client.login("admin@example.test", "synthetic-password");
  const first = client.verifySession();
  const second = client.verifySession();
  await started.promise;
  refresh.resolve(json(authenticated("0", 3600, "-rotated")));
  await Promise.all([first, second]);
  assert.equal(calls.filter(c => c.path === "/refresh").length, 1);
  assert.equal(calls.find(c => c.path === "/refresh").headers.Authorization, undefined);
  assert.ok(calls.filter(c => c.path === "/session").every(c => c.headers.Authorization === "Bearer synthetic-access-rotated"));
});

test("lost refresh response clears credentials and is never retried", async t => {
  const { client, calls } = setup(t, path => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated("0", 10));
    throw new Error("synthetic network failure with secret detail");
  });
  await client.loadCapabilities();
  await client.login("admin@example.test", "synthetic-password");
  await assert.rejects(client.verifySession(), e => !e.message.includes("secret"));
  assert.equal(client.getSnapshot().session, undefined);
  await assert.rejects(client.verifySession());
  assert.equal(calls.filter(c => c.path === "/refresh").length, 1);
});

test("logout prevents a late refresh from restoring the session", async t => {
  const refresh = deferred();
  const started = deferred();
  const { client } = setup(t, path => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated("0", 10));
    if (path === "/refresh") { started.resolve(); return refresh.promise; }
    return new Response(null, { status: 204 });
  });
  await client.loadCapabilities();
  await client.login("admin@example.test", "synthetic-password");
  const pending = assert.rejects(client.verifySession());
  await started.promise;
  await client.logout();
  refresh.resolve(json(authenticated()));
  await pending;
  assert.equal(client.getSnapshot().session, undefined);
});

test("cancelled login and tenant completion cannot restore credentials", async t => {
  for (const step of ["/login", "/tenant-selection/complete"]) {
    const response = deferred();
    const { client } = setup(t, path => {
      if (path === "/capabilities") return json(choose);
      if (path === step) return response.promise;
      return json(ticket);
    });
    await client.loadCapabilities();
    if (step !== "/login") await client.login("admin@example.test", "synthetic-password");
    const pending = assert.rejects(step === "/login" ? client.login("admin@example.test", "synthetic-password") : client.selectTenant("a"));
    await client.logout();
    response.resolve(json(authenticated("a")));
    await pending;
    assert.equal(client.getSnapshot().session, undefined);
  }
});

test("401 ends a session without retry; failed logout still clears local credentials", async t => {
  const { client, calls } = setup(t, path => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated());
    return new Response("private server detail", { status: 401 });
  });
  await client.loadCapabilities();
  await client.login("admin@example.test", "synthetic-password");
  await assert.rejects(client.verifySession(), e => e.status === 401 && !e.message.includes("private"));
  assert.equal(client.getSnapshot().session, undefined);
  assert.equal(calls.filter(c => c.path === "/session").length, 1);
  await client.login("admin@example.test", "synthetic-password");
  await assert.rejects(client.logout(), /未能确认服务端退出/);
  assert.equal(client.getSnapshot().session, undefined);
});

test("invalid capabilities, cross-domain identity and external API prefixes fail closed", async t => {
  for (const prefix of ["https://example.test", "//example.test", "/../other", "/api?redirect=x"]) assert.throws(() => new ManagementClient(prefix));
  const { client } = setup(t, path => json(path === "/capabilities" ? fixed : authenticated("other-tenant")));
  await client.loadCapabilities();
  await assert.rejects(client.login("admin@example.test", "synthetic-password"));
  assert.equal(client.getSnapshot().session, undefined);
  const invalid = setup(t, () => json({ ...choose, tenancy_enabled: false })).client;
  await assert.rejects(invalid.loadCapabilities());
  assert.equal(invalid.getSnapshot().capabilities, undefined);
});

test("selection expiry returns to login; an unexpected target cannot become the current tenant", async t => {
  const { client } = setup(t, path => {
    if (path === "/capabilities") return json(choose);
    if (path === "/login") return json(ticket);
    if (path === "/tenant-selection/complete") return json(authenticated("unexpected"));
    return json({}, 401);
  });
  await client.loadCapabilities();
  await client.login("admin@example.test", "synthetic-password");
  await assert.rejects(client.listTenants(), e => e.status === 401);
  assert.equal(client.getSnapshot().selecting, false);
  await client.login("admin@example.test", "synthetic-password");
  await assert.rejects(client.selectTenant("a"));
  assert.equal(client.getSnapshot().session, undefined);
  assert.equal(client.getSnapshot().selecting, false);
});

test("session revalidation must match all three identity fields", async t => {
  for (const field of ["tenant_id", "account_id", "session_id"]) {
    const { client } = setup(t, path => {
      if (path === "/capabilities") return json(fixed);
      if (path === "/login") return json(authenticated());
      return json({ ...identity(), [field]: "unexpected" });
    });
    await client.loadCapabilities();
    await client.login("admin@example.test", "synthetic-password");
    await assert.rejects(client.verifySession());
    assert.equal(client.getSnapshot().session, undefined);
  }
});

const role = (tenant = "0", overrides = {}) => ({ tenant_id: tenant, role_id: "reader-id", key: "reader", name: "Reader", version: 3,
  kind: "business", status: "active", permissions: [{ resource_type: "report", action: "read" }], ...overrides });
const page = items => ({ items, has_more: false, next_cursor: null });

test("platform target selection sends a target only to scoped role APIs and preserves actor 0", async t => {
  const { client, calls } = setup(t, path => {
    if (path === "/capabilities") return json({ ...fixed, tenancy_enabled: true });
    if (path === "/login") return json(authenticated());
    if (path.startsWith("/tenants?")) return json(page([{ tenant_id: "a", name: "A", status: "active" }]));
    if (path.startsWith("/access/roles?")) return json(page([role("a")]));
    if (path === "/access/roles/reader-id") return json(role("a"));
    return json(identity());
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await assert.rejects(client.listRoles("0"));
  await assert.rejects(client.listRoles(""));
  await client.listManagedTenants({ name: "研发 & A" }, "cursor+/=");
  assert.ok(calls.at(-1).path.includes("name=%E7%A0%94%E5%8F%91+%26+A"));
  assert.ok(calls.at(-1).path.includes("cursor=cursor%2B%2F%3D"));
  await client.listRoles("a");
  assert.equal(calls.filter(c => c.path === "/access/roles/reader-id").length, 0);
  await client.getRole("a", "reader-id");
  assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], "a");
  assert.equal(calls.at(-1).headers.Authorization, "Bearer synthetic-access");
  assert.equal(client.getSnapshot().session.tenant_id, "0");
  await client.verifySession();
});

test("disabled and tenant sessions reject out-of-domain role requests and tenant discovery locally", async t => {
  for (const tenant of ["0", "a"]) {
    const { client, calls } = setup(t, path => {
      if (path === "/capabilities") return json({ ...fixed, tenancy_enabled: tenant !== "0", fixed_tenant_id: tenant });
      if (path === "/login") return json(authenticated(tenant));
      return json(page([role(tenant)]));
    });
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    await client.listRoles(tenant);
    assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], tenant);
    const before = calls.length;
    await assert.rejects(client.listRoles("other"));
    await assert.rejects(client.getRole("other", "reader-id"));
    await assert.rejects(client.listManagedTenants({}));
    assert.equal(calls.length, before);
  }
});

test("role writes send exact versioned contracts, never protection kind or permissions", async t => {
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated());
    if (init.method === "DELETE") return json({ role: null, audit_id: "synthetic-audit" });
    return json({ role: role(), audit_id: "synthetic-audit" });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await client.createRole("0", "reader", "Reader");
  assert.deepEqual(JSON.parse(calls.at(-1).body), { key: "reader", name: "Reader" });
  await client.updateRole("0", role(), "New Reader", "disabled");
  assert.deepEqual(JSON.parse(calls.at(-1).body), { name: "New Reader", status: "disabled", expected_version: 3 });
  await client.deleteRole("0", role());
  assert.deepEqual(JSON.parse(calls.at(-1).body), { expected_version: 3 });
  const before = calls.length;
  await assert.rejects(client.updateRole("0", role("0", { kind: "system_admin" }), "Name", "active"));
  await assert.rejects(client.deleteRole("0", role("0", { kind: "tenant_security_admin" })));
  await assert.rejects(client.updateRole("0", role("other"), "Name", "active"));
  assert.equal(calls.length, before);
});

test("conflicting, forbidden and uncertain writes are not replayed; 401 clears authentication", async t => {
  for (const status of [409, 403, 401, 0]) {
    const { client, calls } = setup(t, path => {
      if (path === "/capabilities") return json(fixed);
      if (path === "/login") return json(authenticated());
      if (!status) throw new Error("synthetic lost response");
      return json({ message: "private internal detail" }, status);
    });
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    await assert.rejects(client.updateRole("0", role(), "Name", "active"), e => e.status === status && !e.message.includes("private"));
    assert.equal(calls.filter(c => c.method === "PATCH").length, 1);
    assert.equal(!!client.getSnapshot().session, status !== 401);
  }
});

test("cross-domain role payloads and responses arriving after logout are rejected", async t => {
  const response = deferred();
  const started = deferred();
  const { client } = setup(t, path => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated());
    if (path.startsWith("/access/roles?")) return json(page([role("other")]));
    if (path === "/access/roles/reader-id") { started.resolve(); return response.promise; }
    return new Response(null, { status: 204 });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await assert.rejects(client.listRoles("0"));
  const pending = assert.rejects(client.getRole("0", "reader-id"));
  await started.promise;
  await client.logout();
  response.resolve(json(role()));
  await pending;
});

const member = (tenant = "0") => ({ account_id: "member-1", email: "member@example.test", display_name: null, status: "active",
  membership: { account_id: "member-1", tenant_id: tenant, status: "active", version: 1 } });
const binding = (scope = { kind: "type" }, tenant = "0") => ({ binding_id: "binding-1", tenant_id: tenant, subject_id: "member-1", role_id: "reader-id", resource_type: "report", scope });
const directoryPermission = (overrides = {}) => ({ tenant_id: "0", resource_type: "report", action: "read", description: "Read reports", category: "business", enabled: true, archived: false, version: 1, ...overrides });

test("permission catalog is scoped, business-only, enabled-only and cursor-paginated", async t => {
  const { client, calls } = setup(t, path => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated());
    return json(page([directoryPermission()]));
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await client.listBusinessPermissions("0", "report", "cursor+/=");
  assert.equal(calls.at(-1).path, "/access/permissions?limit=50&category=business&enabled=true&resource_type=report&cursor=cursor%2B%2F%3D");
  assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], "0");
});

test("permission directory reads stay inside the selected tenant", async t => {
  for (const tenancy_enabled of [false, true]) {
    const tenant = tenancy_enabled ? "tenant-a" : "0";
    const permission = directoryPermission({ tenant_id: tenant });
    const { client, calls } = setup(t, path => {
      if (path === "/capabilities") return json({ ...fixed, tenancy_enabled, fixed_tenant_id: tenant });
      if (path === "/login") return json(authenticated(tenant));
      return json(page([permission]));
    });
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    const result = await client.listPermissionDirectory(tenant, { resource_type: "report", category: "business", enabled: true }, "cursor+/=");
    const call = calls.at(-1); const url = new URL(call.path, "http://test");
    assert.equal(url.pathname, "/access/permissions");
    assert.equal(url.searchParams.get("cursor"), "cursor+/=");
    assert.equal(call.headers["X-Embedded-Idp-Tenant-Id"], tenant);
    assert.deepEqual(result.items, [permission]);
  }
});

test("permission directory rejects a different tenant's rows", async t => {
  const { client } = setup(t, path => {
    if (path === "/capabilities") return json({ ...fixed, tenancy_enabled: true, fixed_tenant_id: "tenant-a" });
    if (path === "/login") return json(authenticated("tenant-a"));
    return json(page([directoryPermission({ tenant_id: "tenant-b" })]));
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await assert.rejects(client.listPermissionDirectory("tenant-a"));
});

test("permission definitions support manual create, read, edit, toggle and archive", async t => {
  const original = directoryPermission();
  const created = directoryPermission({ description: "Read reports" });
  const edited = directoryPermission({ description: "Open a report", version: 2 });
  const disabled = directoryPermission({ description: edited.description, enabled: false, version: 3 });
  const archived = directoryPermission({ ...disabled, archived: true, version: 4 });
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated("0"));
    if (init.method === "GET") return json(created);
    if (init.method === "POST" && path === "/access/permissions") return json({ audit_id: "audit", changes: [{ before: null, after: created }] });
    if (init.method === "PATCH") return json({ audit_id: "audit", changes: [{ before: created, after: edited }] });
    if (init.method === "POST") return json({ audit_id: "audit", changes: [{ before: edited, after: disabled }] });
    return json({ audit_id: "audit", changes: [{ before: disabled, after: archived }] });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  assert.deepEqual(await client.createPermission("0", original, original.description), created);
  assert.deepEqual(await client.getPermission("0", original), created);
  assert.deepEqual(await client.updatePermission("0", created, edited.description), edited);
  assert.deepEqual(await client.setPermissionEnabled("0", edited, false), disabled);
  assert.deepEqual(await client.archivePermission("0", disabled), archived);
  assert.deepEqual(calls.slice(-5).map(c => [c.method, c.path]), [
    ["POST", "/access/permissions"], ["GET", "/access/permissions/report/read"],
    ["PATCH", "/access/permissions/report/read"], ["POST", "/access/permissions/report/read/enabled"],
    ["DELETE", "/access/permissions/report/read"],
  ]);
});

test("role permissions replace the complete versioned set, allow empty set, reject duplicate and excessive sets", async t => {
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated());
    return json({ role: role("0", { permissions: JSON.parse(init.body).permissions, version: 4 }), audit_id: "synthetic-audit" });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const permissions = [{ resource_type: "report", action: "read" }, { resource_type: "order", action: "read" }];
  await client.replaceRolePermissions("0", role(), permissions);
  assert.equal(calls.at(-1).method, "PUT");
  assert.deepEqual(JSON.parse(calls.at(-1).body), { permissions, expected_version: 3 });
  assert.deepEqual((await client.replaceRolePermissions("0", role(), [])).permissions, []);
  const before = calls.length;
  await assert.rejects(client.replaceRolePermissions("0", role(), [permissions[0], permissions[0]]));
  await assert.rejects(client.replaceRolePermissions("0", role(), Array.from({ length: 201 }, (_, i) => ({ resource_type: "report", action: `action${i}` }))));
  await assert.rejects(client.replaceRolePermissions("0", role("0", { kind: "system_admin" }), permissions));
  await assert.rejects(client.replaceRolePermissions("0", role("other"), permissions));
  assert.equal(calls.length, before);
});

test("member and binding reads retain tenant and subject identity without per-row role lookups", async t => {
  const { client, calls } = setup(t, path => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated());
    if (path.startsWith("/accounts?")) return json(page([member()]));
    return json(page([binding(), binding({ kind: "instance", resource_id: "report-42" })]));
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await client.listMembers("0", "member+tag@example.test", "cursor+/=");
  assert.ok(calls.at(-1).path.includes("email=member%2Btag%40example.test"));
  const result = await client.listRoleBindings("0", "member-1");
  assert.equal(result.items[1].scope.resource_id, "report-42");
  assert.equal(calls.filter(c => c.path.startsWith("/access/roles/")).length, 0);
});

test("grants require explicit type or nonempty instance scope and send the exact immutable assignment", async t => {
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated());
    return json({ binding: binding(JSON.parse(init.body).scope), audit_id: "synthetic-audit" });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  for (const scope of [{ kind: "type" }, { kind: "instance", resource_id: "report-42" }]) {
    await client.grantRole("0", "member-1", role(), "report", scope);
    assert.equal(calls.at(-1).path, "/access/subjects/member-1/role-bindings");
    assert.deepEqual(JSON.parse(calls.at(-1).body), { role_id: "reader-id", resource_type: "report", scope });
  }
  const before = calls.length;
  for (const scope of [undefined, {}, { kind: "instance", resource_id: "" }, { kind: "instance", resource_id: "../report/42" }, { kind: "type", resource_id: "report-42" }]) {
    await assert.rejects(client.grantRole("0", "member-1", role(), "report", scope));
  }
  await assert.rejects(client.grantRole("0", "member-1", role("0", { kind: "system_admin" }), "report", { kind: "type" }));
  await assert.rejects(client.grantRole("0", "member-1", role("0", { status: "disabled" }), "report", { kind: "type" }));
  await assert.rejects(client.grantRole("0", "member-1", role(), "order", { kind: "type" }));
  assert.equal(calls.length, before);
});

test("revocation uses only the binding ID, has no body, and excludes protected roles", async t => {
  const { client, calls } = setup(t, path => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated());
    return json({ binding: null, audit_id: "synthetic-audit" });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await client.revokeRoleBinding("0", binding(), role());
  assert.equal(calls.at(-1).path, "/access/role-bindings/binding-1");
  assert.equal(calls.at(-1).method, "DELETE"); assert.equal(calls.at(-1).body, undefined);
  const before = calls.length;
  await assert.rejects(client.revokeRoleBinding("0", binding(), role("0", { kind: "tenant_security_admin" })));
  await assert.rejects(client.revokeRoleBinding("0", binding(), role("0", { role_id: "different" })));
  assert.equal(calls.length, before);
});

test("unexpected member, permission and assignment projections fail closed", async t => {
  let payload;
  const { client } = setup(t, path => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated());
    return json(payload);
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  payload = page([member("other")]); await assert.rejects(client.listMembers("0"));
  payload = page([{ resource_type: "idp.platform", action: "access.manage", description: "admin", category: "platform", enabled: true }]);
  await assert.rejects(client.listBusinessPermissions("0"));
  payload = page([{ ...binding(), subject_id: "other-user" }]); await assert.rejects(client.listRoleBindings("0", "member-1"));
  payload = { binding: binding({ kind: "type" }), audit_id: "synthetic-audit" };
  await assert.rejects(client.grantRole("0", "member-1", role(), "report", { kind: "instance", resource_id: "report-42" }));
});

test("permission and binding writes do not retry conflicts or unknown results", async t => {
  for (const status of [409, 0]) {
  const { client, calls } = setup(t, path => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated());
    if (!status) throw new Error("synthetic lost response");
    return json({}, status);
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await assert.rejects(client.replaceRolePermissions("0", role(), []), e => e.status === status);
  await assert.rejects(client.grantRole("0", "member-1", role(), "report", { kind: "type" }), e => e.status === status);
  await assert.rejects(client.revokeRoleBinding("0", binding(), role()), e => e.status === status);
  assert.equal(calls.length, 5);
  assert.ok(client.getSnapshot().session);
  }
});

test("all permission and membership operations reject another tenant before fetching", async t => {
  const { client, calls } = setup(t, path => json(path === "/capabilities" ? { ...fixed, tenancy_enabled: true, fixed_tenant_id: "a" } : authenticated("a")));
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await assert.rejects(client.listBusinessPermissions("b"));
  await assert.rejects(client.replaceRolePermissions("b", role("b"), []));
  await assert.rejects(client.listMembers("b"));
  await assert.rejects(client.listRoleBindings("b", "member-1"));
  await assert.rejects(client.grantRole("b", "member-1", role("b"), "report", { kind: "type" }));
  await assert.rejects(client.revokeRoleBinding("b", binding({ kind: "type" }, "b"), role("b")));
  assert.equal(calls.length, 2);
});

const managedTenant = (overrides = {}) => ({ tenant_id: "a", name: "A", status: "active", allow_registration: false, version: 4, ...overrides });
const platformCapabilities = { ...fixed, tenancy_enabled: true };

test("tenant creation and settings use platform scope, explicit initial admin and optimistic versions", async t => {
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json(platformCapabilities);
    if (path === "/login") return json(authenticated());
    if (init.method === "GET") return json(managedTenant());
    return json({ tenant: managedTenant(), audit_id: "audit" });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const tenant = await client.getManagedTenant("a");
  await client.createTenant("a", "A", false, { kind: "existing", subject_id: "member-1" });
  assert.deepEqual(JSON.parse(calls.at(-1).body), { tenant_id: "a", name: "A", allow_registration: false, administrator: { kind: "existing", subject_id: "member-1" } });
  await client.updateTenant(tenant, "New A", "suspended", true);
  assert.equal(calls.at(-1).method, "PATCH");
  assert.deepEqual(JSON.parse(calls.at(-1).body), { name: "New A", status: "suspended", allow_registration: true, expected_version: 4 });
  assert.ok(calls.slice(2).every(c => c.headers["X-Embedded-Idp-Tenant-Id"] === undefined));
  const count = calls.length;
  for (const id of ["0", "", "../a", "a b", "a".repeat(129)]) await assert.rejects(client.createTenant(id, "A", false, { kind: "existing", subject_id: "member-1" }));
  await assert.rejects(client.createTenant("a", "A", false, { kind: "existing", subject_id: "" }));
  assert.equal(calls.length, count);
});

test("existing account discovery is platform-only, paginated and distinct from scoped membership", async t => {
  const { client, calls } = setup(t, path => {
    if (path === "/capabilities") return json(platformCapabilities);
    if (path === "/login") return json(authenticated());
    return json(page([{ ...member("a"), membership: null }]));
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const result = await client.listPlatformAccounts("m+a@example.test", "next+/=");
  const url = new URL(calls.at(-1).path, "http://test");
  assert.equal(url.pathname, "/platform/accounts");
  assert.equal(url.searchParams.get("email"), "m+a@example.test");
  assert.equal(url.searchParams.get("cursor"), "next+/=");
  assert.equal(url.searchParams.get("status"), "active");
  assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], undefined);
  assert.equal(result.items[0].membership, undefined);
});

test("bind uses an empty object; status uses current membership version and never shared credentials", async t => {
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json(platformCapabilities);
    if (path === "/login") return json(authenticated());
    if (path === "/accounts/member-1") return json(member("a"));
    const status = init.body ? JSON.parse(init.body).status ?? "active" : "active";
    return json({ membership: { ...member("a").membership, status, version: 2 }, audit_id: "audit" });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const current = await client.getMember("a", "member-1");
  await client.bindMember("a", "member-1");
  assert.equal(calls.at(-1).path, "/members/member-1/bind"); assert.equal(calls.at(-1).body, "{}");
  const updated = await client.setMemberStatus("a", current.membership, "suspended");
  assert.equal(updated.version, 2);
  assert.equal(calls.at(-1).path, "/members/member-1/status");
  assert.deepEqual(JSON.parse(calls.at(-1).body), { status: "suspended", expected_version: 1 });
  assert.ok(calls.slice(2).every(c => c.headers["X-Embedded-Idp-Tenant-Id"] === "a"));
  const count = calls.length;
  await assert.rejects(client.setMemberStatus("a", { ...current.membership, status: "removed" }, "active"));
  await assert.rejects(client.setMemberStatus("b", current.membership, "active"));
  assert.equal(calls.length, count);
});

test("disabled hides relationship mutations and tenant sessions cannot search or bind across tenants", async t => {
  for (const tenant of ["0", "a"]) {
    const { client, calls } = setup(t, path => {
      if (path === "/capabilities") return json({ ...fixed, tenancy_enabled: tenant !== "0", fixed_tenant_id: tenant });
      if (path === "/login") return json(authenticated(tenant));
      return json({ membership: { ...member("a").membership, status: "suspended", version: 2 } });
    });
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    const count = calls.length;
    if (tenant !== "0") await assert.rejects(client.listPlatformAccounts(""));
    await assert.rejects(client.createTenant("b", "B", false, { kind: "existing", subject_id: "member-1" }));
    await assert.rejects(client.getManagedTenant("a"));
    await assert.rejects(client.updateTenant(managedTenant(), "B", "active", false));
    await assert.rejects(client.bindMember(tenant, "member-1"));
    await assert.rejects(client.getMember("b", "member-1"));
    await assert.rejects(client.setMemberStatus("b", member("b").membership, "active"));
    if (tenant === "0") await assert.rejects(client.setMemberStatus("0", member().membership, "suspended"));
    assert.equal(calls.length, count);
    if (tenant === "a") await client.setMemberStatus("a", member("a").membership, "suspended");
  }
});

test("tenant and membership responses reject wrong domain, subject and missing version", async t => {
  let payload;
  const { client } = setup(t, path => json(path === "/capabilities" ? platformCapabilities : path === "/login" ? authenticated() : payload));
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  for (const value of [managedTenant({ tenant_id: "b" }), managedTenant({ version: undefined }), managedTenant({ allow_registration: undefined })]) {
    payload = value; await assert.rejects(client.getManagedTenant("a"));
  }
  for (const membership of [{ ...member("b").membership }, { ...member("a").membership, account_id: "other" }, { ...member("a").membership, version: undefined }]) {
    payload = { membership }; await assert.rejects(client.bindMember("a", "member-1"));
    payload = { ...member("a"), membership }; await assert.rejects(client.getMember("a", "member-1"));
  }
  payload = { ...member("a"), account_id: "other", membership: { ...member("a").membership, account_id: "other" } };
  await assert.rejects(client.getMember("a", "member-1"));
  payload = page([member("a")]); await assert.rejects(client.listPlatformAccounts(""));
});

test("tenant and member writes do not replay conflicts, last-member refusal or uncertain results", async t => {
  for (const status of [409, 403, 0]) {
    const { client, calls } = setup(t, path => {
      if (path === "/capabilities") return json(platformCapabilities);
      if (path === "/login") return json(authenticated());
      if (!status) throw new Error("lost response");
      return json({}, status);
    });
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    const operations = [() => client.createTenant("a", "A", false, { kind: "existing", subject_id: "member-1" }), () => client.updateTenant(managedTenant(), "A", "archived", false),
      () => client.bindMember("a", "member-1"), () => client.setMemberStatus("a", member("a").membership, "removed")];
    for (const operation of operations) { const count = calls.length; await assert.rejects(operation()); assert.equal(calls.length, count + 1); }
  }
});

test("late member updates cannot resurrect a logged-out management session", async t => {
  const response = deferred();
  const { client } = setup(t, path => {
    if (path === "/capabilities") return json(platformCapabilities);
    if (path === "/login") return json(authenticated());
    if (path === "/logout") return new Response(null, { status: 204 });
    return response.promise;
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const pending = assert.rejects(client.bindMember("a", "member-1"));
  await Promise.resolve(); await client.logout();
  response.resolve(json({ membership: member("a").membership })); await pending;
  assert.equal(client.getSnapshot().session, undefined);
});

test("new tenant administrator sends explicit credentials only in its creation request", async t => {
  const { client, calls } = setup(t, path => json(path === "/capabilities" ? platformCapabilities : path === "/login" ? authenticated() : { tenant: managedTenant(), audit_id: "audit" }));
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await client.createTenant("a", "A", false, { kind: "new", email: "new@example.test", password: "Synthetic-admin-123", subject_id: "must-not-bind" });
  assert.deepEqual(JSON.parse(calls.at(-1).body), { tenant_id: "a", name: "A", allow_registration: false, administrator: { kind: "new", email: "new@example.test", password: "Synthetic-admin-123" } });
  assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], undefined);
  assert.equal(JSON.stringify(client.getSnapshot()).includes("Synthetic-admin-123"), false);
  const count = calls.length;
  for (const administrator of [{ kind: "new", email: "new@example.test", password: "" }, { kind: "new", email: "", password: "Synthetic-admin-123" }, { kind: "unknown" }]) await assert.rejects(client.createTenant("a", "A", false, administrator));
  assert.equal(calls.length, count);
});

const administratorSnapshot = (tenant = "a", appointed = false) => ({
  tenant_id: tenant, tenant_status: "active", account: member(tenant),
  role: role(tenant, { kind: tenant === "0" ? "system_admin" : "tenant_security_admin" }),
  binding: appointed ? { ...binding({ kind: "type" }, tenant), resource_type: tenant === "0" ? "idp.platform" : "idp.tenant" } : null,
});

test("administrator snapshots and bodyless writes use dedicated platform or explicit tenant targets", async t => {
  for (const enabled of [false, true]) {
    let snapshot;
    const { client, calls } = setup(t, (path, init) => {
      if (path === "/capabilities") return json({ ...fixed, tenancy_enabled: enabled });
      if (path === "/login") return json(authenticated());
      if (init.method === "GET") return json(snapshot);
      return json({ binding: init.method === "POST" ? administratorSnapshot(snapshot.tenant_id, true).binding : null, audit_id: "audit" });
    });
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    for (const tenant of enabled ? ["0", "a"] : ["0"]) {
      snapshot = administratorSnapshot(tenant);
      const current = await client.getSecurityAdministrator(tenant, "member-1");
      const assigned = await client.setSecurityAdministrator(current, true);
      await client.setSecurityAdministrator({ ...current, binding: assigned }, false);
      for (const call of calls.slice(-3)) {
        assert.equal(call.path, `/${tenant === "0" ? "platform" : "access"}/security-admins/member-1`);
        assert.equal(call.headers["X-Embedded-Idp-Tenant-Id"], tenant === "0" ? undefined : tenant);
        assert.equal(call.body, undefined); assert.equal(call.headers["Content-Type"], undefined);
      }
    }
  }
});

test("administrator snapshot decoder rejects wrong subject/domain/kind/scope and missing membership", async t => {
  let payload;
  const { client } = setup(t, path => json(path === "/capabilities" ? platformCapabilities : path === "/login" ? authenticated() : payload));
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const valid = administratorSnapshot();
  for (const bad of [
    { ...valid, tenant_id: "b" }, { ...valid, account: { ...valid.account, account_id: "other" } },
    { ...valid, account: { ...valid.account, membership: undefined } }, { ...valid, account: member("b") },
    { ...valid, role: role("a") }, { ...valid, binding: binding({ kind: "instance", resource_id: "report-1" }, "a") },
  ]) { payload = bad; await assert.rejects(client.getSecurityAdministrator("a", "member-1")); }
  payload = { ...administratorSnapshot("0"), account: { ...member("0"), membership: null } };
  assert.equal((await client.getSecurityAdministrator("0", "member-1")).account.membership, null);
});

test("administrator operations reject tenant actors, invalid target modes and ineligible appointments locally", async t => {
  for (const actor of ["0", "a"]) {
    const { client, calls } = setup(t, path => json(path === "/capabilities" ? { ...fixed, tenancy_enabled: actor !== "0", fixed_tenant_id: actor } : authenticated(actor)));
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    const before = calls.length;
    await assert.rejects(client.getSecurityAdministrator("b", "member-1"));
    await assert.rejects(client.setSecurityAdministrator(administratorSnapshot("b"), true));
    await assert.rejects(client.getSecurityAdministrator("../a", "member-1"));
    await assert.rejects(client.getSecurityAdministrator("0", "bad/id"));
    if (actor === "a") await assert.rejects(client.getSecurityAdministrator("a", "member-1"));
    else {
      const current = administratorSnapshot("0");
      for (const bad of [{ ...current, account: { ...current.account, membership: null } },
        { ...current, account: { ...current.account, status: "disabled" } },
        { ...current, tenant_status: "suspended" }, { ...current, role: { ...current.role, status: "disabled" } },
        administratorSnapshot("0", true)]) await assert.rejects(client.setSecurityAdministrator(bad, true));
      await assert.rejects(client.setSecurityAdministrator(current, false));
    }
    assert.equal(calls.length, before);
  }
});

test("administrator revocation permits inactive target cleanup and rejects incorrect write projections", async t => {
  let payload = { binding: null, audit_id: "audit" };
  const { client } = setup(t, path => json(path === "/capabilities" ? platformCapabilities : path === "/login" ? authenticated() : payload));
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await client.setSecurityAdministrator({ ...administratorSnapshot("a", true), tenant_status: "archived" }, false);
  for (const invalid of [{ binding: null }, { binding: binding({ kind: "type" }, "a"), audit_id: "audit" },
    { binding: administratorSnapshot("0", true).binding, audit_id: "audit" }]) {
    payload = invalid; await assert.rejects(client.setSecurityAdministrator(administratorSnapshot(), true));
  }
});

test("last-administrator conflicts, forbidden requests and lost responses never replay security writes", async t => {
  for (const status of [409, 403, 0]) {
    const { client, calls } = setup(t, path => {
      if (path === "/capabilities") return json(platformCapabilities);
      if (path === "/login") return json(authenticated());
      if (!status) throw new Error("lost response"); return json({}, status);
    });
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    const count = calls.length;
    await assert.rejects(client.setSecurityAdministrator(administratorSnapshot("0", true), false));
    assert.equal(calls.length, count + 1);
  }
});

test("platform administrator search includes disabled accounts so existing authority can be revoked", async t => {
  const { client, calls } = setup(t, path => json(path === "/capabilities" ? platformCapabilities : path === "/login" ? authenticated() : page([{ ...member("0"), status: "disabled", membership: null }])));
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const result = await client.listPlatformAccounts("member", "next", false);
  assert.equal(result.items[0].status, "disabled");
  const url = new URL(calls.at(-1).path, "http://test"); assert.equal(url.searchParams.has("status"), false);
  assert.equal(url.searchParams.get("cursor"), "next");
});

const account = (id = "account-1", overrides = {}) => ({ account_id: id, email: `${id}@example.test`, display_name: "Account", status: "active", ...overrides });
const device = (tenant = "tenant-a", overrides = {}) => ({ tenant_id: tenant, device_id: "device-1", client_id: "client-1", device_name: "Scanner", proof_key_id: null, status: "active", registered_at_unix_secs: 100, last_seen_at_unix_secs: 200, ...overrides });
const managedSession = (tenant = "tenant-a", overrides = {}) => ({ tenant_id: tenant, session_id: "session-1", account_id: "account-1", client_id: "client-1", device_id: "device-1", status: "active", created_at_unix_secs: 100, expires_at_unix_secs: 300, authenticated_at_unix_secs: 110, scope: "openid", ...overrides });

test("platform account security reads and writes preserve projections, initial tenant, and platform scope", async t => {
  const created = { ...account(), membership: { tenant_id: "tenant-a", account_id: "account-1", status: "active", version: 1 } };
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json(platformCapabilities);
    if (path === "/login") return json(authenticated());
    if (path === "/platform/accounts/account-1") return json({ ...account(), membership: null });
    if (path === "/platform/accounts") return json({ account: created, audit_id: "audit" });
    if (path.endsWith("/status")) return json({ account: { ...account("account-1", { status: JSON.parse(init.body).status }), membership: null }, audit_id: "audit" });
    return json({ account: account(), audit_id: "audit" });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  assert.deepEqual(await client.getAccountSecurity("account-1"), account());
  const made = await client.createAccount("tenant-a", { email: "new@example.test", password: "Synthetic-password", display_name: "New" });
  assert.equal(made.membership.tenant_id, "tenant-a");
  assert.deepEqual(JSON.parse(calls.at(-1).body), { tenant_id: "tenant-a", email: "new@example.test", password: "Synthetic-password", display_name: "New" });
  assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], undefined);
  await client.setAccountStatus(account(), "disabled");
  assert.deepEqual(JSON.parse(calls.at(-1).body), { status: "disabled", expected_status: "active" });
  const before = calls.length;
  await assert.rejects(client.createAccount("0", { email: "x", password: "y" }));
  assert.equal(calls.length, before);
});

test("account listing allows platform actor in both modes, rejects tenant actors, and strips null membership", async t => {
  for (const tenancy_enabled of [false, true]) {
    const { client, calls } = setup(t, path => {
      if (path === "/capabilities") return json({ ...fixed, tenancy_enabled });
      if (path === "/login") return json(authenticated());
      return json(page([{ ...account(), membership: null }]));
    });
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    const result = await client.listPlatformAccounts("account", undefined, false);
    assert.equal(result.items[0].membership, undefined);
    assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], undefined);
  }
  const { client } = setup(t, path => json(path === "/capabilities" ? { ...fixed, tenancy_enabled: true, fixed_tenant_id: "tenant-a" } : authenticated("tenant-a")));
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await assert.rejects(client.listPlatformAccounts(""), e => e.status === 403);
});

test("device lifecycle sends target headers, exact filters and cursors, and rejects mismatched responses", async t => {
  let payload = page([device()]);
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json({ ...fixed, tenancy_enabled: true, fixed_tenant_id: "tenant-a" });
    if (path === "/login") return json(authenticated("tenant-a"));
    if (path.endsWith("/disable")) return json({ device: device("tenant-a", { status: "disabled" }), audit_id: "audit" });
    return json(path.startsWith("/devices/device-1") ? payload : payload);
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const result = await client.listDevices("tenant-a", { client_id: "client-1", status: "active", registered_after_unix_secs: 50, registered_before_unix_secs: 150 }, "cursor+/=");
  const url = new URL(calls.at(-1).path, "http://test");
  assert.equal(url.searchParams.get("client_id"), "client-1"); assert.equal(url.searchParams.get("registered_after_unix_secs"), "50");
  assert.equal(url.searchParams.get("cursor"), "cursor+/="); assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], "tenant-a");
  assert.equal(result.items[0].device_id, "device-1");
  await client.setDeviceStatus("tenant-a", device(), "disabled");
  assert.deepEqual(JSON.parse(calls.at(-1).body), { expected_status: "active" });
  payload = { ...device(), tenant_id: "other" }; await assert.rejects(client.getDevice("tenant-a", "device-1"));
  await assert.rejects(client.listDevices("tenant-a", { registered_after_unix_secs: 151, registered_before_unix_secs: 150 }));
});

test("session lifecycle uses target filters and exact projections, including empty mutation bodies", async t => {
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json({ ...fixed, tenancy_enabled: true, fixed_tenant_id: "tenant-a" });
    if (path === "/login") return json(authenticated("tenant-a"));
    if (path.startsWith("/accounts/")) return json({ tenant_id: "tenant-a", account_id: "account-1", revoked_session_count: 2, audit_id: "audit" });
    if (path.endsWith("/revoke")) return json({ session: managedSession("tenant-a", { status: "revoked" }), audit_id: "audit" });
    return json(page([managedSession()]));
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const listed = await client.listSessions("tenant-a", { account_id: "account-1", device_id: "device-1", status: "active", created_after_unix_secs: 50, created_before_unix_secs: 150 }, "next");
  const url = new URL(calls.at(-1).path, "http://test");
  assert.equal(url.searchParams.get("account_id"), "account-1"); assert.equal(url.searchParams.get("created_before_unix_secs"), "150"); assert.equal(url.searchParams.get("cursor"), "next");
  assert.equal(listed.items[0].scope, "openid");
  await client.revokeSession("tenant-a", managedSession()); assert.equal(calls.at(-1).body, "{}");
  await client.revokeSubjectSessions("tenant-a", "account-1"); assert.equal(calls.at(-1).body, "{}");
});

test("self account and session mutations clear auth, while stale responses cannot restore it", async t => {
  const response = deferred();
  const self = account("synthetic-user");
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated("0"));
    if (path.endsWith("/password")) return response.promise;
    if (path.endsWith("/status")) return json({ account: { ...account("synthetic-user", { status: "disabled" }), membership: null }, audit_id: "audit" });
    if (path.endsWith("/revoke")) return json({ session: managedSession("0", { status: "revoked", session_id: "synthetic-session" }), audit_id: "audit" });
    return json({ tenant_id: "0", account_id: "synthetic-user", revoked_session_count: 1, audit_id: "audit" });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await client.setAccountStatus(self, "disabled"); assert.equal(client.getSnapshot().session, undefined);
  await client.login("admin@example.test", "synthetic-password");
  const pending = client.setAccountPassword(self, "new-password"); await Promise.resolve();
  response.resolve(json({ account: { ...self, membership: null }, audit_id: "audit" })); await pending; assert.equal(client.getSnapshot().session, undefined);
  await client.login("admin@example.test", "synthetic-password");
  await client.revokeSession("0", managedSession("0", { session_id: "synthetic-session" })); assert.equal(client.getSnapshot().session, undefined);
  assert.ok(calls.some(c => c.path.endsWith("/password")));
});

test("account and session writes do not retry conflicts, forbidden responses, or lost responses", async t => {
  for (const status of [409, 403, 0]) {
    const { client, calls } = setup(t, (path, init) => {
      if (path === "/capabilities") return json(platformCapabilities);
      if (path === "/login") return json(authenticated());
      if (!status) throw new Error("lost response");
      return json({}, status);
    });
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    const before = calls.length;
    await assert.rejects(client.setAccountPassword(account(), "new-password"));
    assert.equal(calls.length, before + 1); assert.ok(client.getSnapshot().session);
    await assert.rejects(client.revokeSubjectSessions("tenant-a", "account-1"));
    assert.equal(calls.length, before + 2); assert.ok(client.getSnapshot().session);
  }
});

test("session projection accepts absent OIDC scope and rejects malformed or cross-subject results", async t => {
  let payload = page([managedSession("tenant-a", { scope: null, device_id: null })]);
  const { client } = setup(t, path => json(path === "/capabilities" ? platformCapabilities : path === "/login" ? authenticated() : payload));
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  assert.equal((await client.listSessions("tenant-a", {})).items[0].scope, null);
  for (const overrides of [{ scope: [] }, { tenant_id: "other" }, { created_at_unix_secs: -1 }, { expires_at_unix_secs: Infinity }, { status: "unknown" }]) {
    payload = page([managedSession("tenant-a", overrides)]);
    await assert.rejects(client.listSessions("tenant-a", {}));
  }
  payload = { tenant_id: "tenant-a", account_id: "other", revoked_session_count: 1, audit_id: "audit" };
  await assert.rejects(client.revokeSubjectSessions("tenant-a", "account-1"));
});

test("lifecycle guards reject tenant account mutations and terminal devices before issuing a request", async t => {
  const { client, calls } = setup(t, path => json(path === "/capabilities" ? { ...fixed, tenancy_enabled: true, fixed_tenant_id: "tenant-a" } : authenticated("tenant-a")));
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const before = calls.length;
  await assert.rejects(client.getAccountSecurity("account-1"));
  await assert.rejects(client.createAccount("tenant-a", { email: "a@example.test", password: "Synthetic-password" }));
  await assert.rejects(client.setAccountPassword(account(), "Synthetic-password"));
  await assert.rejects(client.setAccountStatus(account(), "disabled"));
  await assert.rejects(client.listDevices("other", {}));
  await assert.rejects(client.listSessions("other", {}));
  await assert.rejects(client.setDeviceStatus("tenant-a", device("tenant-a", { status: "revoked" }), "disabled"));
  await assert.rejects(client.revokeSession("tenant-a", managedSession("tenant-a", { status: "revoked" })));
  assert.equal(calls.length, before);
});

test("self bulk revocation clears credentials and late lifecycle results cannot modify a new login", async t => {
  const pending = deferred();
  let delayed = false;
  const { client } = setup(t, path => {
    if (path === "/capabilities") return json(fixed);
    if (path === "/login") return json(authenticated());
    if (path.endsWith("/logout")) return new Response(null, { status: 204 });
    if (path.endsWith("/password")) return pending.promise;
    if (path.endsWith("/sessions/revoke")) return json({ tenant_id: "0", account_id: "synthetic-user", revoked_session_count: 1, audit_id: "audit" });
    throw new Error(`Unexpected ${path}`);
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await client.revokeSubjectSessions("0", "synthetic-user");
  assert.equal(client.getSnapshot().session, undefined);
  await client.login("admin@example.test", "synthetic-password");
  const stale = client.setAccountPassword(account("synthetic-user"), "Synthetic-new-password");
  const rejected = assert.rejects(stale, /取消/);
  await Promise.resolve(); await client.logout(); await client.login("admin@example.test", "synthetic-password");
  pending.resolve(json({ account: { ...account("synthetic-user"), membership: null }, audit_id: "audit" }));
  await rejected;
  assert.equal(client.getSnapshot().session.account_id, "synthetic-user");
});

const managedClient = (overrides = {}) => ({
  client_id: "desktop-client",
  client_name: "Desktop",
  redirect_uris: ["https://client.example/callback"],
  client_type: "public_desktop",
  pkce_required: true,
  client_secret_configured: false,
  ...overrides,
});

test("client reads use platform session 0 in both modes and encode filters and cursors", async t => {
  for (const enabled of [false, true]) {
    const { client, calls } = setup(t, path => {
      if (path === "/capabilities") return json({ ...fixed, tenancy_enabled: enabled });
      if (path === "/login") return json(authenticated("0"));
      const confidential = managedClient({ client_type: "confidential_web", pkce_required: false, client_secret_configured: true });
      if (path.startsWith("/clients?")) return json(page([confidential]));
      return json(confidential);
    });
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    const result = await client.listClients({ client_type: "confidential_web", pkce_required: false }, "cursor+/=");
    assert.deepEqual(result.items[0], managedClient({ client_type: "confidential_web", pkce_required: false, client_secret_configured: true }));
    const url = new URL(calls.at(-1).path, "http://test");
    assert.equal(url.pathname, "/clients");
    assert.equal(url.searchParams.get("limit"), "50");
    assert.equal(url.searchParams.get("client_type"), "confidential_web");
    assert.equal(url.searchParams.get("pkce_required"), "false");
    assert.equal(url.searchParams.get("cursor"), "cursor+/=");
    assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], undefined);
    assert.deepEqual(await client.getClient("desktop-client"), managedClient({ client_type: "confidential_web", pkce_required: false, client_secret_configured: true }));
    assert.equal(calls.at(-1).path, "/clients/desktop-client");
  }
});

test("client platform guard rejects tenant sessions before fetching in both modes", async t => {
  for (const enabled of [false, true]) {
    const { client, calls } = setup(t, path => {
      if (path === "/capabilities") return json(enabled ? { ...fixed, tenancy_enabled: true, fixed_tenant_id: "tenant-a" } : { ...fixed, tenancy_enabled: false, fixed_tenant_id: "0" });
      if (path === "/login") return json(authenticated(enabled ? "tenant-a" : "0"));
      return json(enabled ? page([]) : page([managedClient()]));
    });
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    const before = calls.length;
    if (enabled) {
      await assert.rejects(client.listClients());
      await assert.rejects(client.getClient("desktop-client"));
      await assert.rejects(client.upsertClient({ client_id: "desktop-client", client_name: "Desktop", redirect_uris: [], client_type: "public_desktop", pkce_required: true }));
      assert.equal(calls.length, before);
    } else {
      await client.listClients();
      assert.equal(calls.length, before + 1);
    }
  }
});

test("client upsert sends only the versionless contract and preserves omitted secrets", async t => {
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json(platformCapabilities);
    if (path === "/login") return json(authenticated("0"));
    const input = JSON.parse(init.body);
    return json({ client: managedClient({ client_id: input.client_id, client_name: input.client_name, redirect_uris: input.redirect_uris, client_type: input.client_type, pkce_required: input.pkce_required, client_secret_configured: input.client_type === "confidential_web" }), audit_id: "audit" });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const existing = { client_id: "web-client", client_name: "Web", redirect_uris: ["https://web.example/callback"], client_type: "confidential_web", pkce_required: false };
  await client.upsertClient(existing);
  assert.deepEqual(JSON.parse(calls.at(-1).body), existing);
  await client.upsertClient({ ...existing, client_secret: "exact-secret-\u0000" });
  assert.deepEqual(JSON.parse(calls.at(-1).body), { ...existing, client_secret: "exact-secret-\u0000" });
  assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], undefined);
});

test("client projections strip metadata and never expose returned secrets or hashes", async t => {
  const payload = { ...managedClient({ client_type: "confidential_web", pkce_required: false, client_secret_configured: true }),
    client_secret: "server-secret", client_secret_hash: "server-hash", tenant_id: "0", status: "active", version: 9, unknown: true };
  const { client } = setup(t, path => json(path === "/capabilities" ? platformCapabilities : path === "/login" ? authenticated("0") : path.startsWith("/clients?") ? page([payload]) : payload));
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  assert.deepEqual((await client.listClients()).items[0], managedClient({ client_type: "confidential_web", pkce_required: false, client_secret_configured: true }));
  assert.deepEqual(await client.getClient("desktop-client"), managedClient({ client_type: "confidential_web", pkce_required: false, client_secret_configured: true }));
});

test("client responses reject mismatched IDs, filters, metadata and write results", async t => {
  let mode = "wrong-id";
  const { client } = setup(t, path => {
    if (path === "/capabilities") return json(platformCapabilities);
    if (path === "/login") return json(authenticated("0"));
    if (mode === "wrong-id") return json(managedClient({ client_id: "other-client" }));
    if (mode === "filter-mismatch") return json(page([managedClient({ client_type: "confidential_web", pkce_required: false, client_secret_configured: true })]));
    if (mode === "bad-metadata") return json(page([{ ...managedClient(), pkce_required: "true", redirect_uris: [null] }]));
    if (mode === "missing-audit") return json({ client: managedClient() });
    return json({ client: managedClient({ client_name: "Different" }), audit_id: "audit" });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  await assert.rejects(client.getClient("desktop-client"));
  mode = "filter-mismatch"; await assert.rejects(client.listClients({ client_type: "public_desktop", pkce_required: true }));
  mode = "bad-metadata"; await assert.rejects(client.listClients());
  mode = "missing-audit"; await assert.rejects(client.upsertClient({ client_id: "desktop-client", client_name: "Desktop", redirect_uris: ["https://client.example/callback"], client_type: "public_desktop", pkce_required: true }));
  mode = "different-config"; await assert.rejects(client.upsertClient({ client_id: "desktop-client", client_name: "Desktop", redirect_uris: ["https://client.example/callback"], client_type: "public_desktop", pkce_required: true }));
});

test("client upsert validates fields locally without fetching", async t => {
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json(platformCapabilities);
    if (path === "/login") return json(authenticated("0"));
    const input = JSON.parse(init.body);
    return json({ client: { ...input, client_secret_configured: input.client_type === "confidential_web" }, audit_id: "audit" });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const valid = { client_id: "web-client", client_name: "Web", redirect_uris: ["https://web.example/callback"], client_type: "confidential_web", pkce_required: false };
  await client.upsertClient({ ...valid, client_name: "界".repeat(85) });
  for (const input of [
    { ...valid, client_id: "" }, { ...valid, client_name: "\u0000" }, { ...valid, client_name: "x".repeat(257) },
    { ...valid, client_name: "界".repeat(86) }, { ...valid, redirect_uris: [] }, { ...valid, redirect_uris: ["x".repeat(2049)] },
    { ...valid, redirect_uris: Array.from({ length: 33 }, () => "https://client.example/callback") },
    { ...valid, client_type: "public_desktop", pkce_required: false }, { ...valid, client_type: "public_desktop", client_secret: "secret" },
    { ...valid, client_secret: "" }, { ...valid, client_secret: "x".repeat(4097) }, { ...valid, client_secret: "界".repeat(1366) },
  ]) await assert.rejects(client.upsertClient(input));
  await assert.rejects(client.upsertClient({ ...valid, client_name: "Valid", redirect_uris: Array.from({ length: 9 }, (_, i) => `https://client.example/${i}${"x".repeat(1980)}`) }));
  assert.equal(calls.length, 3);
});

test("client writes do not retry and late responses after logout are rejected", async t => {
  for (const status of [409, 0]) {
    const { client, calls } = setup(t, path => {
      if (path === "/capabilities") return json(platformCapabilities);
      if (path === "/login") return json(authenticated("0"));
      if (!status) throw new Error("lost response");
      return json({}, status);
    });
    await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
    await assert.rejects(client.upsertClient({ client_id: "web-client", client_name: "Web", redirect_uris: ["https://web.example/callback"], client_type: "confidential_web", pkce_required: false }), e => e.status === status);
    assert.equal(calls.filter(c => c.path === "/clients/upsert").length, 1);
  }
  const response = deferred(); const started = deferred();
  const { client, calls } = setup(t, (path, init) => {
    if (path === "/capabilities") return json(platformCapabilities);
    if (path === "/login") return json(authenticated("0"));
    if (path === "/clients/upsert") { started.resolve(); return response.promise; }
    return new Response(null, { status: 204 });
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const pending = assert.rejects(client.upsertClient({ client_id: "web-client", client_name: "Web", redirect_uris: ["https://web.example/callback"], client_type: "confidential_web", pkce_required: false }));
  await started.promise; await client.logout();
  response.resolve(json({ client: managedClient({ client_id: "web-client" }), audit_id: "audit" }));
  await pending; assert.equal(client.getSnapshot().session, undefined); assert.equal(calls.filter(c => c.path === "/clients/upsert").length, 1);
});

test("permission write preflight rejects protected or cross-tenant definitions", async t => {
  const { client, calls } = setup(t, path => json(path === "/capabilities" ? { ...fixed, tenancy_enabled: true, fixed_tenant_id: "tenant-a" } : authenticated("tenant-a")));
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const permission = directoryPermission({ tenant_id: "tenant-a" }), before = calls.length;
  await assert.rejects(client.createPermission("tenant-a", { resource_type: "idp.custom", action: "read" }, "Protected"));
  await assert.rejects(client.updatePermission("tenant-b", permission, "new"));
  await assert.rejects(client.archivePermission("tenant-b", permission));
  await assert.rejects(client.setPermissionEnabled("tenant-a", { ...permission, archived: true }, false));
  await assert.rejects(client.listPermissionDirectory("tenant-b"));
  assert.equal(calls.length, before);
});

const auditRecord = (target_domain = "tenant-a", overrides = {}) => ({
  audit_id: "audit-1", occurred_at_unix_secs: 1_700_000_000, actor_id: "admin-1",
  actor_domain: "0", actor_session_id: null, authentication_source: "management",
  target_domain, operation: "access.check", request_id: "request-1", ...overrides,
});

test("audit reads keep platform and selected tenant separate and load detail only on demand", async t => {
  const record = auditRecord();
  const { client, calls } = setup(t, path => {
    if (path === "/capabilities") return json({ ...fixed, tenancy_enabled: true });
    if (path === "/login") return json(authenticated("0"));
    if (path.startsWith("/access/audit-events?")) return json({ items: [record], has_more: true, next_cursor: "next+/=" });
    if (path === "/access/audit-events/audit-1") return json({ ...record, change: { kind: "permission_checked", allowed: false } });
    if (path.startsWith("/platform/audit-events?")) return json({ items: [auditRecord("0")], has_more: false, next_cursor: null });
    if (path === "/platform/audit-events/audit-1") return json({ ...auditRecord("0"), change: { kind: "platform_change" } });
    throw new Error(path);
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const filter = { actor_id: "admin-1", operation: "access.check", occurred_after_unix_secs: 1_699_999_999, occurred_before_unix_secs: 1_700_000_001 };
  const first = await client.listAuditEvents("tenant-a", filter, "cursor+/=");
  assert.deepEqual(first.items, [record]);
  assert.equal(first.next_cursor, "next+/=");
  const tenantCall = calls.at(-1); const url = new URL(tenantCall.path, "http://test");
  assert.equal(url.pathname, "/access/audit-events");
  assert.equal(url.searchParams.get("cursor"), "cursor+/=");
  assert.equal(url.searchParams.get("actor_id"), "admin-1");
  assert.equal(url.searchParams.get("operation"), "access.check");
  assert.equal(url.searchParams.get("occurred_after_unix_secs"), "1699999999");
  assert.equal(tenantCall.headers["X-Embedded-Idp-Tenant-Id"], "tenant-a");
  assert.deepEqual((await client.getAuditEvent("tenant-a", "audit-1")).change, { kind: "permission_checked", allowed: false });
  assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], "tenant-a");
  assert.deepEqual((await client.listPlatformAuditEvents()).items, [auditRecord("0")]);
  assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], undefined);
  assert.deepEqual((await client.getPlatformAuditEvent("audit-1")).change, { kind: "platform_change" });
  assert.equal(calls.at(-1).headers["X-Embedded-Idp-Tenant-Id"], undefined);
  const count = calls.length;
  await assert.rejects(client.listAuditEvents("0"));
  await assert.rejects(client.listAuditEvents("tenant-b", { actor_id: "bad id" }));
  await assert.rejects(client.listAuditEvents("tenant-a", { occurred_after_unix_secs: 10, occurred_before_unix_secs: 9 }));
  assert.equal(calls.length, count);
});

test("audit projections reject cross-domain, mismatched filters and missing detail changes", async t => {
  let response = { items: [auditRecord()], has_more: false, next_cursor: null };
  const { client } = setup(t, path => {
    if (path === "/capabilities") return json({ ...fixed, tenancy_enabled: true, fixed_tenant_id: "tenant-a" });
    if (path === "/login") return json(authenticated("tenant-a"));
    return json(response);
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  for (const row of [auditRecord("tenant-b"), auditRecord("tenant-a", { actor_id: "other" }), auditRecord("tenant-a", { occurred_at_unix_secs: -1 })]) {
    response = { items: [row], has_more: false, next_cursor: null };
    await assert.rejects(client.listAuditEvents("tenant-a", { actor_id: "admin-1" }));
  }
  response = { ...auditRecord("tenant-a", { audit_id: "different" }), change: {} };
  await assert.rejects(client.getAuditEvent("tenant-a", "audit-1"));
  response = { ...auditRecord(), change: null };
  await assert.rejects(client.getAuditEvent("tenant-a", "audit-1"));
  await assert.rejects(client.listPlatformAuditEvents());
});

test("diagnosis sends only the selected query and rejects mismatched or uncertain results", async t => {
  let response = { audit_id: "audit-1", tenant_id: "tenant-a", subject_id: "user-1", resource_type: "report", action: "read", resource_id: "report-42", decision: "deny" };
  const { client, calls } = setup(t, path => {
    if (path === "/capabilities") return json({ ...fixed, tenancy_enabled: true });
    if (path === "/login") return json(authenticated("0"));
    if (response === null) throw new Error("lost response");
    return json(response);
  });
  await client.loadCapabilities(); await client.login("admin@example.test", "synthetic-password");
  const input = { subject_id: "user-1", resource_type: "report", action: "read", resource_id: "report-42" };
  assert.deepEqual(await client.diagnosePermission("tenant-a", input), response);
  const call = calls.at(-1);
  assert.equal(call.path, "/access/check");
  assert.equal(call.headers["X-Embedded-Idp-Tenant-Id"], "tenant-a");
  assert.deepEqual(JSON.parse(call.body), input);
  const count = calls.length;
  await assert.rejects(client.diagnosePermission("0", input));
  await assert.rejects(client.diagnosePermission("tenant-a", { ...input, resource_id: "bad id" }));
  assert.equal(calls.length, count);
  for (const bad of [{ ...response, tenant_id: "tenant-b" }, { ...response, resource_id: null }, { ...response, decision: "allowish" }, { ...response, audit_id: undefined }]) {
    response = bad;
    await assert.rejects(client.diagnosePermission("tenant-a", input));
  }
  response = null;
  await assert.rejects(client.diagnosePermission("tenant-a", input), e => e.message.includes("勿重复提交"));
  assert.equal(calls.filter(c => c.path === "/access/check").length, 6);
});
