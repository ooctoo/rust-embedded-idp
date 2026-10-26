import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const browser = await readFile(new URL("./browser-session.ts", import.meta.url), "utf8");
const identity = await readFile(new URL("./client.ts", import.meta.url), "utf8");
const devices = await readFile(new URL("./device-client.ts", import.meta.url), "utf8");
const transpile = source => ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const browserModule = transpile(browser);
const identityModule = transpile(identity.replace(/^import .* from "\.\/browser-session";\n/m, browserModule));
const deviceModule = transpile(devices.replace(/^import .*;\n/gm, ""));
const loaded = await import(`data:text/javascript;base64,${Buffer.from(`${identityModule}\n${deviceModule}`).toString("base64")}`);
const { EmbeddedIdentityClient, EmbeddedDeviceClient } = loaded;
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const fixed = { tenancy_enabled: false, login_tenant_policy: "fixed", fixed_tenant_id: "0" };
const owner = (clientId = "client-a", sessionId = "session-a") => ({ tenant_id: "0", account_id: "account-a", session_id: sessionId, client_id: clientId });
const authenticated = (clientId = "client-a") => ({ status: "authenticated", session: owner(clientId), tokens: {
  access_token: "synthetic-access", refresh_token: "synthetic-refresh",
  access_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 3600,
  refresh_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 86400,
} });
const keyId = "A".repeat(43);
const device = (overrides = {}) => ({ tenant_id: "0", device_id: "device-a", client_id: "client-a", proof_key_id: keyId,
  status: "active", version: 3, key_version: 2, binding_id: "11111111-1111-4111-8111-111111111111", binding_version: 4,
  device_name: "Laptop", registered_at_unix_secs: 100, last_seen_at_unix_secs: null, binding_status: "active", ...overrides });
const receipt = intent => ({ operation_id: intent.operation_id, audit_id: "audit-1", device_id: intent.device_id,
  binding_id: intent.binding_id, operation: "device.binding.unbind.self", occurred_at_unix_secs: 200,
  result_version: intent.expected_version + 1, result_status: "unbound" });

function loggedIn(handler) {
  const calls = [];
  const identityClient = new EmbeddedIdentityClient("/idp", async (url, init) => {
    const parsed = new URL(url, "https://host.test");
    const path = parsed.pathname.replace("/idp", "") + parsed.search;
    const call = { path, init };
    calls.push(call);
    if (path === "/auth/access/capabilities") return json(fixed);
    if (path === "/auth/login") return json(authenticated());
    try { return await handler(call); } catch (error) { throw new Error(`test transport ${path}: ${error.message}`); }
  });
  return (async () => {
    await identityClient.loadCapabilities();
    await identityClient.login("a@example.test", "synthetic-password");
    return { identityClient, devicesClient: new EmbeddedDeviceClient(identityClient), calls };
  })();
}

test("device client pages, validates scopes and requests detail/key using authenticated identity transport", async () => {
  const cursor = "Y3Vyc29y";
  const context = await loggedIn(({ path, init }) => {
    assert.equal(init.method, "GET");
    assert.match(init.headers.Authorization, /^Bearer /);
    if (path.startsWith("/devices?")) return json({ items: [device()], has_more: true, next_cursor: cursor });
    if (path === "/devices/device-a") return json(device());
    if (path === `/devices/device-a/keys/${keyId}`) return json({ tenant_id: "0", device_id: "device-a", key_id: keyId,
      algorithm: "ed25519", version: 2, status: "active", registered_at_unix_secs: 100, retired_at_unix_secs: null });
    throw new Error(`unexpected path ${path}`);
  });
  const page = await context.devicesClient.list();
  assert.deepEqual(page.items.map(item => item.device_id), ["device-a"]);
  assert.equal(page.next_cursor, cursor);
  await context.devicesClient.list(page.next_cursor);
  assert.deepEqual(await context.devicesClient.detail("device-a"), page.items[0]);
  assert.equal((await context.devicesClient.keyMetadata("device-a", keyId)).algorithm, "ed25519");
  assert.ok(context.calls.some(call => call.path === "/devices?limit=50&cursor=Y3Vyc29y"));
  await assert.rejects(context.devicesClient.detail("../auth/session"), error => error.status === 400);
});

test("unbind reuses one frozen intent for the exact receipt and read-back", async () => {
  let operation;
  const context = await loggedIn(({ path, init }) => {
    if (path === "/devices?limit=50") return json({ items: [device()], has_more: false, next_cursor: null });
    if (path === "/devices/unbind") {
      operation = JSON.parse(init.body);
      return json(receipt(operation));
    }
    if (path.startsWith("/devices/operations/")) return json(receipt(operation));
    throw new Error(`unexpected path ${path}`);
  });
  const item = (await context.devicesClient.list()).items[0];
  const intent = await context.devicesClient.prepareUnbind(item);
  assert.equal(Object.isFrozen(intent), true);
  assert.equal(Object.isFrozen(intent.owner), true);
  const written = await context.devicesClient.unbind(intent);
  await context.identityClient.login("a@example.test", "synthetic-password");
  assert.deepEqual(written, await context.devicesClient.operationResult(intent));
  assert.equal(operation.device_id, "device-a");
  assert.equal(operation.expected_version, 4);
  assert.equal(operation.operation_id, intent.operation_id);
});

test("unbind DTO failures and non-active bindings fail before mutation", async () => {
  let writes = 0;
  const context = await loggedIn(({ path }) => {
    if (path === "/devices?limit=50") return json({ items: [device({ binding_status: "suspended" })], has_more: false, next_cursor: null });
    if (path === "/devices/unbind") { writes++; return json({}); }
    throw new Error(`unexpected path ${path}`);
  });
  const item = (await context.devicesClient.list()).items[0];
  assert.throws(() => context.devicesClient.prepareUnbind(item), { status: 409 });
  await assert.rejects(context.devicesClient.list("x".repeat(2049)), { status: 400 });
  assert.equal(writes, 0);
  const badCursor = await loggedIn(() => json({ items: [], has_more: false, next_cursor: "cursor/with/slash" }));
  await assert.rejects(badCursor.devicesClient.list(), error => error.code === "invalid_device_response");
});

test("invalid device scope, versions, duplicate rows and invalid receipts are rejected", async () => {
  const context = await loggedIn(({ path }) => {
    if (path.startsWith("/devices?")) return json({ items: [device({ tenant_id: "other" })], has_more: false, next_cursor: null });
    if (path.startsWith("/devices/operations/")) return json({});
    throw new Error(`unexpected path ${path}`);
  });
  await assert.rejects(context.devicesClient.list(), error => error.code === "invalid_device_response");
  const intent = await context.devicesClient.prepareUnbind(device());
  await assert.rejects(context.devicesClient.operationResult(intent), error => error.code === "invalid_device_response");
  const second = await loggedIn(() => json({ items: [device(), device()], has_more: false, next_cursor: null }));
  await assert.rejects(second.devicesClient.list(), error => error.code === "invalid_device_response");
});

test("operation intents cannot be forged or used by another client/owner", async () => {
  const first = await loggedIn(({ path }) => path === "/devices?limit=50"
    ? json({ items: [device()], has_more: false, next_cursor: null }) : json(receipt({})));
  const intent = await first.devicesClient.prepareUnbind((await first.devicesClient.list()).items[0]);
  await assert.rejects(first.devicesClient.operationResult({ ...intent }), { status: 403 });
  const other = await loggedIn(({ path }) => path.startsWith("/devices/operations/") ? json(receipt(intent)) : json({ items: [], has_more: false, next_cursor: null }));
  await assert.rejects(other.devicesClient.operationResult(intent), { status: 403 });
});

test("identity device bridge rejects routes, methods and query injection before transport", async () => {
  const context = await loggedIn(() => json({ items: [], has_more: false }));
  const before = context.calls.length;
  for (const [path, body] of [
    ["https://attacker.test/devices", undefined],
    ["/admin/devices", undefined],
    ["/devices?limit=50&cursor=x&admin=true", undefined],
    ["/devices/unbind", undefined],
    ["/devices/heartbeat", {}],
  ]) {
    await assert.rejects(context.identityClient.requestDevice(path, body), error => error.status === 400, path);
  }
  assert.equal(context.calls.length, before);
});

test("late device responses after logout are rejected by the identity revision guard", async () => {
  let finish;
  const context = await loggedIn(({ path }) => {
    if (path === "/auth/access/capabilities") return json(fixed);
    if (path === "/auth/login") return json(authenticated());
    if (path === "/devices?limit=50") return new Promise(resolve => { finish = resolve; });
    return json({ status: "logged_out" });
  });
  const pending = context.devicesClient.list();
  await new Promise(resolve => setImmediate(resolve));
  await context.identityClient.logout();
  await context.identityClient.login("a@example.test", "synthetic-password");
  finish(json({ items: [device()], has_more: false, next_cursor: null }));
  await assert.rejects(pending, error => error.message === "操作已取消。");
  assert.ok(context.identityClient.getSnapshot().session);
});

test("rotation bridge retains identity transport and only permits rotation challenge purpose", async () => {
  const context = await loggedIn(({ path, init }) => {
    assert.match(init.headers.Authorization, /^Bearer /);
    assert.equal(init.method, "POST");
    assert.ok(["/devices/proof/challenges", "/devices/rotate-key"].includes(path));
    return json({});
  });
  assert.equal(context.identityClient.deviceBaseUrl, "/idp");
  const body = { tenant_id: "0", device_id: "11111111-1111-4111-8111-111111111111", purpose: "device_key_rotation" };
  const before = context.calls.length;
  for (const invalid of [{ ...body, purpose: "device_registration" }, { ...body, tenant_id: "another" }, { ...body, device_id: "../auth" }, { ...body, credential: "untrusted" }]) {
    await assert.rejects(context.identityClient.requestDevice("/devices/proof/challenges", invalid), e => e.status === 400);
  }
  assert.equal(context.calls.length, before);
  await context.identityClient.requestDevice("/devices/proof/challenges", body);
  await context.identityClient.requestDevice("/devices/rotate-key", {});
  await assert.rejects(context.identityClient.requestDevice("/devices/rotate-key"), e => e.status === 400);
});
