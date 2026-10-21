import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("./navigation.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } });
const { resolveRoute, routeHash, defaultRoute, pagesFor } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);
const fixed = { tenancy_enabled: true, login_tenant_policy: "fixed", fixed_tenant_id: "tenant-a" };
const fixedDot = tenant => ({ tenancy_enabled: true, login_tenant_policy: "fixed", fixed_tenant_id: tenant });
const choose = { tenancy_enabled: true, login_tenant_policy: "choose_after_authentication" };
const disabled = { tenancy_enabled: false, login_tenant_policy: "fixed", fixed_tenant_id: "0" };
const session = tenant_id => ({ tenant_id, account_id: "synthetic", session_id: "synthetic", client_id: "synthetic" });
const route = (scope, page, tenant) => tenant === undefined ? { scope, page } : { scope, page, tenant };

test("all legacy task menu entries remain addressable in their permitted scope", () => {
  const expected = {
    platform: ["home", "tenants", "administrators", "accounts", "clients", "directory", "audit"],
    tenant: ["home", "members", "roles", "directory", "diagnostic", "devices", "sessions", "audit"],
    system: ["home", "members", "roles", "directory", "diagnostic", "devices", "sessions", "audit", "accounts", "clients", "administrators"],
  };
  for (const [scope, pages] of Object.entries(expected)) {
    assert.deepEqual(pagesFor(scope).map(([id]) => id), pages);
    for (const page of pages) {
      const value = route(scope, page, scope === "tenant" ? "tenant-a" : undefined);
      assert.deepEqual(resolveRoute(routeHash(value), scope === "system" ? disabled : choose, session("0")), { route: value });
    }
  }
});

test("defaults select the actual authenticated scope", () => {
  for (const [capabilities, tenant, expected] of [
    [disabled, "0", route("system", "home")], [fixed, "0", route("platform", "home")],
    [fixed, "tenant-a", route("tenant", "home", "tenant-a")], [choose, "tenant-b", route("tenant", "home", "tenant-b")],
    [choose, ".", route("tenant", "home", ".")], [choose, "..", route("tenant", "home", "..")],
    [fixedDot("."), ".", route("tenant", "home", ".")], [fixedDot(".."), "..", route("tenant", "home", "..")],
  ]) {
    assert.deepEqual(defaultRoute(capabilities, session(tenant)), expected);
    for (const hash of ["", "#", "#/"]) assert.deepEqual(resolveRoute(hash, capabilities, session(tenant)), { route: expected });
  }
});

test("encoded valid tenant IDs and pages decode once", () => {
  assert.deepEqual(resolveRoute("#/tenants/tenant%2Da/ro%6Ces", choose, session("tenant-a")), { route: route("tenant", "roles", "tenant-a") });
  assert.deepEqual(resolveRoute("#/tenants/team%2Ewest/home", choose, session("0")), { route: route("tenant", "home", "team.west") });
  for (const tenant of [".", ".."]) {
    const hash = routeHash(route("tenant", "home", tenant));
    assert.equal(hash, `#/tenants/${tenant}/home`);
    assert.deepEqual(resolveRoute(hash, choose, session(tenant)), { route: route("tenant", "home", tenant) });
    assert.deepEqual(resolveRoute(`#/tenants/${tenant === "." ? "%2e" : "%2e%2e"}/home`, choose, session(tenant)), { route: route("tenant", "home", tenant) });
  }
});

test("malformed, unknown, traversal and ambiguous locators are 404", () => {
  for (const hash of [
    "#/platform/unknown", "#/tenant/tenant-a/home", "#/platform/home/extra", "#/platform/home?x=1",
    "#/platform/home%3Fx%3D1", "#/tenants/tenant-a%2Fother/home", "#/tenants/%00/home",
    "#/tenants/%0A/home", "#/tenants/%/home", "#/tenants/%C3%28/home", "#/tenants/%252e/home",
    "#/tenants/%252e%252e/home", "#/tenants/tenant-a/../home",
    `#/tenants/${"a".repeat(129)}/home`, `#/platform/${"a".repeat(513)}`,
  ]) assert.deepEqual(resolveRoute(hash, choose, session("0")), { status: 404 }, hash);
});

test("scope access follows mode and authenticated tenant", () => {
  for (const hash of ["#/platform/home", "#/tenants/tenant-a/home"]) assert.deepEqual(resolveRoute(hash, disabled, session("0")), { status: 403 });
  assert.deepEqual(resolveRoute("#/system/home", disabled, session("tenant-a")), { status: 403 });
  assert.deepEqual(resolveRoute("#/system/home", choose, session("0")), { status: 403 });
  assert.deepEqual(resolveRoute("#/platform/home", choose, session("tenant-a")), { status: 403 });
  assert.deepEqual(resolveRoute("#/tenants/0/home", choose, session("0")), { status: 403 });
  for (const capabilities of [fixed, choose]) {
    assert.deepEqual(resolveRoute("#/tenants/tenant-b/roles", capabilities, session("tenant-a")), { status: 403 });
    assert.deepEqual(resolveRoute("#/tenants/tenant-a/roles", capabilities, session("tenant-a")), { route: route("tenant", "roles", "tenant-a") });
    assert.deepEqual(resolveRoute("#/tenants/tenant-b/roles", capabilities, session("0")), { route: route("tenant", "roles", "tenant-b") });
  }
  assert.deepEqual(resolveRoute("#/tenants/../roles", choose, session(".")), { status: 403 });
  assert.deepEqual(resolveRoute("#/tenants/./roles", fixed, session("tenant-a")), { status: 403 });
  assert.deepEqual(resolveRoute("#/tenants/../roles", choose, session("0")), { route: route("tenant", "roles", "..") });
});
