import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

globalThis.crypto ??= (await import("node:crypto")).webcrypto;
globalThis.uuidCounter = 0;
const [protocol, client] = await Promise.all([
  readFile(new URL("./scan-login-protocol.ts", import.meta.url), "utf8"),
  readFile(new URL("./device-scan-client.ts", import.meta.url), "utf8"),
]);
const source = `const secureRandomUuid = () => \`11111111-1111-4111-8111-\${String(++globalThis.uuidCounter).padStart(12, "0")}\`;\n` +
  protocol.replace(/^import[\s\S]*?;\n/gm, "").replace(/\buuid\b/g, "protocolUuid") + "\n" + client.replace(/^import[\s\S]*?;\n/gm, "");
const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const { DeviceScanClient } = await import("data:text/javascript;base64," + Buffer.from(js).toString("base64"));
async function ok(promise) { try { return await promise; } catch (error) { throw new Error(error?.code ?? error?.message ?? "unknown failure"); } }

const target = { baseUrl: "/idp", tenant_id: "tenant-a", client_id: "client-a", entry_id: "entry-a",
  device_id: "11111111-1111-4111-8111-222222222222", audience: "idp", verification_uri: "/idp/auth/browser/device-scan/ui" };
const expiry = Math.floor(Date.now() / 1000) + 3600;
const b64 = n => Buffer.from(randomBytes(n)).toString("base64url");
const progress = (patch = {}) => ({ grant_id: "22222222-2222-4222-8222-222222222222", mode: "device_display", state: "waiting_device", version: 1,
  server_time_unix_secs: 1, expires_at_unix_secs: expiry, code_expires_at_unix_secs: expiry, approved_until_unix_secs: null,
  expires_in: 1000, poll_after_ms: 1500, delivery_state: null, issuance_operation_id: null, recover_until_unix_secs: null, next_action: "poll", ...patch });
const phoneProgress = (patch = {}) => progress({ mode: "phone_display", state: "awaiting_approval", next_action: "await_approval", ...patch });
const bundle = (nonce = b64(32)) => ({ session: { tenant_id: target.tenant_id, account_id: "account-a", session_id: "33333333-3333-4333-8333-333333333333", client_id: target.client_id, expires_at_unix_secs: 4102444800 },
  tokens: { access_token: "access-secret", refresh_token: "refresh-secret", access_expires_at_unix_secs: expiry - 100, refresh_expires_at_unix_secs: expiry }, receipt_nonce: nonce });

function harness(route) {
  const records = new Map(), state = { calls: [], activated: [], discarded: [], rows: records }, locks = new Map();
  const store = { async withLock(t, fn) { const key = JSON.stringify(t), prior = locks.get(key) ?? Promise.resolve(); let release;
    const next = new Promise(r => release = r); locks.set(key, prior.then(() => next)); await prior; try { return await fn(); } finally { release(); } },
    async load(t) { const value = records.get(JSON.stringify(t)); return value && structuredClone(value); },
    async save(value) { records.set(JSON.stringify(value.target), structuredClone(value)); } };
  const transport = async (url, init) => {
    const body = JSON.parse(init.body); state.calls.push({ url, body, headers: init.headers });
    if (url.endsWith("/devices/proof/challenges")) return Response.json({ challenge: b64(32), expires_at_unix_secs: Math.floor(Date.now() / 1000) + 60 });
    const action = url.split("/").at(-1);
    const result = await route(action, body, state);
    if (result instanceof Error) throw result;
    return Response.json(result.body ?? result, { status: result.status ?? 200 });
  };
  const sessions = { async activate(input) { state.activated.push(structuredClone(input)); }, async discard(input) { state.discarded.push(structuredClone(input)); } };
  const signer = { async signRequest({ body }) { state.signedBodies ??= []; state.signedBodies.push(body); return { key_id: b64(32), signature: b64(64) }; } };
  const client = (clientTarget = target) => new DeviceScanClient({ target: clientTarget, signer, store, sessions, transport });
  return { state, client, store, signer, sessions, transport };
}

test("create journals stable origin identity before request and snapshot never exposes delivery secret", async () => {
  const h = harness(async action => action === "create" ? { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" } : {});
  const c = h.client(); await ok(c.create());
  const saved = [...h.state.rows.values()][0];
  assert.equal(saved.phase, "waiting"); assert.equal(saved.origin_operation_id, h.state.calls.find(x => x.url.endsWith("/create")).body.operation_id);
  assert.equal(h.state.calls.find(x => x.url.endsWith("/create")).body.entry_id, target.entry_id);
  assert.equal(h.state.calls.find(x => x.url.endsWith("/create")).body.tenant_id, target.tenant_id);
  assert.equal(h.state.signedBodies.at(-1), JSON.stringify(h.state.calls.find(x => x.url.endsWith("/create")).body));
  assert.equal(JSON.stringify(c.getSnapshot()).includes(saved.delivery_secret), false);
  assert.equal(c.getSnapshot().next_poll_at_unix_ms > Date.now(), true);
  const snapshot = c.getSnapshot();
  assert.equal(c.getSnapshot(), snapshot);
  assert.equal(Object.isFrozen(snapshot), true); assert.equal(Object.isFrozen(snapshot.target), true);
  assert.equal(Object.isFrozen(snapshot.progress), true);
  assert.equal(Reflect.set(snapshot, "phase", "active"), false);
  assert.equal(Reflect.set(snapshot.progress, "state", "issued"), false);
  assert.equal(c.getSnapshot().phase, "waiting"); assert.equal(c.getSnapshot().progress.state, "waiting_device");
  c.dispose();
});

test("write-ahead exchange, recovery persists protected bundle before explicit acknowledge", async () => {
  let issuance;
  const h = harness(async (action, body, state) => {
    if (action === "create") return { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" };
    if (action === "status") return progress({ state: "approved" });
    if (action === "exchange") { issuance = body.operation_id; state.exchangeBody = body; return new Error("response lost"); }
    if (action === "recover") return { ...bundle(), progress: progress({ state: "issued", delivery_state: "recoverable", issuance_operation_id: issuance, recover_until_unix_secs: expiry }) };
    if (action === "acknowledge") return progress({ state: "issued", delivery_state: "acknowledged", issuance_operation_id: issuance, recover_until_unix_secs: expiry });
    throw Error(action);
  });
  const c = h.client(); await ok(c.create()); await ok(c.status()); await assert.rejects(c.exchange());
  const before = [...h.state.rows.values()][0]; assert.equal(before.phase, "exchange-unknown"); assert.equal(before.exchange_operation_id, issuance);
  await ok(c.recover());
  const pending = [...h.state.rows.values()][0]; assert.equal(pending.phase, "pending"); assert.equal(pending.bundle.receipt_nonce.length > 40, true);
  assert.equal(h.state.activated.length, 0); assert.equal(JSON.stringify(c.getSnapshot()).includes("access-secret"), false);
  await ok(c.acknowledge()); assert.equal([...h.state.rows.values()][0].phase, "active"); assert.equal(h.state.activated.length, 1);
  assert.equal(h.state.activated[0].bundle.tokens.access_token, "access-secret");
  assert.equal(h.state.calls.find(x => x.url.endsWith("/acknowledge")).body.operation_id, [...h.state.rows.values()][0].ack_operation_id);
  c.dispose();
});

test("delivery bound to another grant or issuance is rejected and never activated", async () => {
  const otherIssuance = "44444444-4444-4444-8444-444444444444";
  const h = harness(async action => action === "create" ? { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" } : action === "status" ? progress({ state: "approved" }) : action === "exchange"
    ? { ...bundle(), progress: progress({ state: "issued", delivery_state: "recoverable", issuance_operation_id: otherIssuance, recover_until_unix_secs: expiry }) } : {});
  const c = h.client(); await ok(c.create()); await ok(c.status()); await assert.rejects(c.exchange(), e => e.code === "issuance_mismatch");
  assert.equal(h.state.activated.length, 0);
  c.dispose();
});

test("revoked issued delivery stays out of pending and cannot be acknowledged", async () => {
  let issuance, statusCalls = 0;
  const h = harness(async (action, body) => {
    if (action === "create") return { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" };
    if (action === "status") return ++statusCalls === 1 ? progress({ state: "approved" }) : progress({ state: "issued", delivery_state: "revoked", issuance_operation_id: issuance, recover_until_unix_secs: expiry });
    if (action === "exchange") { issuance = body.operation_id; return { ...bundle(), progress: progress({ state: "issued", delivery_state: "recoverable", issuance_operation_id: issuance, recover_until_unix_secs: expiry }) }; }
    throw Error(action);
  });
  const c = h.client(); await ok(c.create()); await ok(c.status()); await ok(c.exchange());
  await ok(c.status());
  assert.equal(c.getSnapshot().phase, "exchange-unknown");
  await assert.rejects(c.acknowledge(), e => e.code === "invalid_phase");
  assert.equal(h.state.activated.length, 0);
  c.dispose();
});

test("cancel closes origin before discard; acknowledged race recovers and activates rather than discarding", async () => {
  let issued, mode = "ordinary";
  const h = harness(async (action, body) => {
    if (action === "create") return { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" };
    if (action === "status") return progress({ state: "approved" });
    if (action === "exchange") { issued = body.operation_id; return { ...bundle(), progress: progress({ state: "issued", delivery_state: "recoverable", issuance_operation_id: issued, recover_until_unix_secs: expiry }) }; }
    if (action === "abort") return mode === "ack-race" ? { status: 409, body: { error: "already_acknowledged" } } : { outcome: "aborted" };
    if (action === "close-origin") return { origin_operation_id: body.origin_operation_id, origin_action: body.origin_action, outcome: "closed" };
    if (action === "recover") return { ...bundle(), progress: progress({ state: "issued", delivery_state: "acknowledged", issuance_operation_id: issued, recover_until_unix_secs: expiry }) };
    throw Error(action);
  });
  const c = h.client(); await ok(c.create()); await ok(c.status()); await ok(c.exchange()); await ok(c.cancel());
  assert.equal([...h.state.rows.values()][0].phase, "closed"); assert.equal(h.state.discarded.length, 1);
  await ok(c.load()); assert.equal(c.getSnapshot().phase, "closed");
  mode = "ack-race";
  let statusCalls = 0;
  const h2 = harness(async (action, body) => {
    if (action === "create") return { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" };
    if (action === "status") return ++statusCalls === 1 ? progress({ state: "approved" }) : progress({ state: "issued", delivery_state: "acknowledged", issuance_operation_id: issued, recover_until_unix_secs: expiry });
    if (action === "exchange") { issued = body.operation_id; return { ...bundle(), progress: progress({ state: "issued", delivery_state: "recoverable", issuance_operation_id: issued, recover_until_unix_secs: expiry }) }; }
    if (action === "abort") return { status: 409, body: { error: "already_acknowledged" } };
    throw Error(action);
  });
  const c2 = h2.client(); await ok(c2.create()); await ok(c2.status()); await ok(c2.exchange());
  await ok(c2.cancel());
  assert.equal([...h2.state.rows.values()][0].phase, "active");
  assert.equal(h2.state.discarded.length, 0);
  c.dispose(); c2.dispose();
});

test("dispose between network awaits prevents later signed mutation", async () => {
  let resume;
  const gate = new Promise(resolve => resume = resolve);
  const h = harness(async action => { if (action === "create") { await gate; return { progress: progress() }; } throw Error(action); });
  const c = h.client(); const pending = c.create();
  while (!h.state.calls.some(call => call.url.endsWith("/create"))) await new Promise(resolve => setTimeout(resolve, 0));
  c.dispose(); resume(); await assert.rejects(pending, e => e.code === "disposed");
  assert.equal(h.state.calls.filter(call => !call.url.endsWith("/devices/proof/challenges")).length, 1);
});

test("claim accepts Axum's bare progress response and 404 retry reuses the journaled origin id", async () => {
  const claimCode = "P1." + b64(16);
  let originCalls = 0, lookupCalls = 0;
  const h = harness(async (action, body) => {
    if (action === "claim") { originCalls++; assert.equal(body.scan_code, claimCode); return originCalls === 1 ? Error("response lost") : phoneProgress(); }
    if (action === "lookup") { lookupCalls++; assert.equal(body.origin_operation_id, h.state.calls.find(x => x.url.endsWith("/claim")).body.operation_id);
      return { status: 404, body: { error: "scan_not_found" } }; }
    throw Error(action);
  });
  const c = h.client(); await assert.rejects(c.claim(claimCode), e => e.code === "network_unknown");
  const firstId = [...h.state.rows.values()][0].origin_operation_id;
  await ok(c.retryOrigin());
  assert.equal([...h.state.rows.values()][0].phase, "waiting");
  assert.equal([...h.state.rows.values()][0].origin_operation_id, firstId);
  assert.equal(originCalls, 2); assert.equal(lookupCalls, 1);
  assert.equal(h.state.calls.find(x => x.url.endsWith("/claim")).body.tenant_id, target.tenant_id);
  assert.equal(h.state.calls.find(x => x.url.endsWith("/claim")).body.entry_id, target.entry_id);
  assert.equal(JSON.stringify(c.getSnapshot()).includes(claimCode), false);
  c.dispose();
});

test("create retryOrigin looks up first, then reuses origin ID and delivery hash after a raw 404", async () => {
  let creates = 0, lookupId;
  const h = harness(async (action, body) => {
    if (action === "create") {
      creates++;
      if (creates === 1) { lookupId = body.operation_id; return Error("response lost"); }
      return { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" };
    }
    if (action === "lookup") return { status: 404, body: { error: "scan_not_found" } };
    throw Error(action);
  });
  const c = h.client(); await assert.rejects(c.create(), e => e.code === "network_unknown");
  const saved = [...h.state.rows.values()][0]; const secretHash = await (async () => {
    const raw = saved.delivery_secret.replace(/-/g, "+").replace(/_/g, "/") + "=";
    return Buffer.from(await crypto.subtle.digest("SHA-256", Uint8Array.from(atob(raw), ch => ch.charCodeAt(0)))).toString("base64url");
  })();
  await ok(c.retryOrigin());
  const attempts = h.state.calls.filter(call => call.url.endsWith("/create")).map(call => call.body);
  assert.equal(lookupId, saved.origin_operation_id); assert.equal(attempts.length, 2);
  assert.equal(attempts[0].operation_id, attempts[1].operation_id);
  assert.equal(attempts[0].delivery_secret_hash, secretHash); assert.equal(attempts[1].delivery_secret_hash, secretHash);
  assert.equal(h.state.calls.filter(call => call.url.endsWith("/lookup")).length, 1);
  assert.equal(JSON.stringify(c.getSnapshot()).includes(saved.delivery_secret), false);
  c.dispose();
});

test("failed write-ahead saves prevent origin writes and session activation", async () => {
  const noOrigin = harness(async () => { throw Error("must not send"); });
  noOrigin.store.save = async () => { throw Error("disk unavailable"); };
  const c0 = noOrigin.client(); await assert.rejects(c0.create(), e => e.code === "operation_failed");
  assert.equal(noOrigin.state.calls.length, 0); assert.equal(noOrigin.state.activated.length, 0); c0.dispose();

  const h = harness(async (action, body) => {
    if (action === "create") return { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" };
    if (action === "status") return progress({ state: "approved" });
    if (action === "exchange") return { ...bundle(), progress: progress({ state: "issued", delivery_state: "recoverable", issuance_operation_id: body.operation_id, recover_until_unix_secs: expiry }) };
    if (action === "acknowledge") return progress({ state: "issued", delivery_state: "acknowledged", issuance_operation_id: body.issuance_operation_id, recover_until_unix_secs: expiry });
    throw Error(action);
  });
  const save = h.store.save.bind(h.store);
  h.store.save = async record => {
    if (record.phase === "ack-unknown" && record.progress?.delivery_state === "acknowledged") throw Error("disk unavailable");
    return save(record);
  };
  const c = h.client(); await ok(c.create()); await ok(c.status()); await ok(c.exchange());
  await assert.rejects(c.acknowledge(), e => e.code === "operation_failed");
  assert.equal(h.state.activated.length, 0); c.dispose();
});

test("two clients sharing one store create only one origin; other flow sees existing_flow", async () => {
  let release;
  const gate = new Promise(resolve => release = resolve);
  const h = harness(async action => {
    if (action === "create") { await gate; return { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" }; }
    throw Error(action);
  });
  const first = h.client(), second = h.client();
  const creating = first.create();
  while (!h.state.calls.some(call => call.url.endsWith("/create"))) await new Promise(resolve => setTimeout(resolve, 0));
  const competing = second.create(); release();
  await ok(creating); await assert.rejects(competing, e => e.code === "existing_flow");
  assert.equal(h.state.calls.filter(call => call.url.endsWith("/create")).length, 1);
  first.dispose(); second.dispose();
});

test("journal loaded under a different tenant target is rejected", async () => {
  const h = harness(async action => action === "create" ? { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" } : {});
  const first = h.client(); await ok(first.create());
  const originalLoad = h.store.load.bind(h.store);
  const saved = await originalLoad(first.target); assert.ok(saved);
  h.store.load = async () => structuredClone(saved);
  const other = { ...target, tenant_id: "tenant-b" };
  const second = h.client(other);
  await assert.rejects(second.load(), e => e.code === "invalid_store");
  assert.equal(h.state.calls.filter(call => call.url.endsWith("/create")).length, 1);
  first.dispose(); second.dispose();
});

test("lost ACK response recovers progress only and activates the previously journaled bundle", async () => {
  let issuance, loseAck = true;
  const h = harness(async (action, body) => {
    if (action === "create") return { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" };
    if (action === "status") return progress({ state: "approved" });
    if (action === "exchange") { issuance = body.operation_id; return { ...bundle(), progress: progress({ state: "issued", delivery_state: "recoverable", issuance_operation_id: issuance, recover_until_unix_secs: expiry }) }; }
    if (action === "acknowledge") { if (loseAck) { loseAck = false; return Error("response lost after commit"); } }
    if (action === "recover") return { progress: progress({ state: "issued", delivery_state: "acknowledged", issuance_operation_id: issuance, recover_until_unix_secs: expiry }) };
    throw Error(action);
  });
  const first = h.client(); await ok(first.create()); await ok(first.status()); await ok(first.exchange());
  await assert.rejects(first.acknowledge(), e => e.code === "network_unknown");
  assert.equal(h.state.activated.length, 0); first.dispose();
  const restored = h.client(); await ok(restored.recover());
  assert.equal(h.state.activated.length, 1);
  assert.equal(h.state.activated[0].issuance_operation_id, issuance);
  assert.equal(h.state.activated[0].bundle.tokens.access_token, "access-secret");
  restored.dispose();
});

test("recovered bundle metadata must exactly match the protected original bundle", async () => {
  for (const mutate of [
    recovered => { recovered.session.account_id = "account-b"; },
    recovered => { recovered.session.expires_at_unix_secs++; },
    recovered => { recovered.tokens.access_expires_at_unix_secs++; },
    recovered => { recovered.tokens.refresh_expires_at_unix_secs++; },
  ]) {
    let issuance;
    const h = harness(async (action, body) => {
      if (action === "create") return { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" };
      if (action === "status") return progress({ state: "approved" });
      if (action === "exchange") { issuance = body.operation_id; return { ...bundle(), progress: progress({ state: "issued", delivery_state: "recoverable", issuance_operation_id: issuance, recover_until_unix_secs: expiry }) }; }
      if (action === "recover") {
        const changed = structuredClone(bundle()); mutate(changed);
        return { ...changed, progress: progress({ state: "issued", delivery_state: "recoverable", issuance_operation_id: issuance, recover_until_unix_secs: expiry }) };
      }
      throw Error(action);
    });
    const c = h.client(); await ok(c.create()); await ok(c.status()); await ok(c.exchange());
    await assert.rejects(c.recover(), e => e.code === "bundle_changed");
    assert.equal(h.state.activated.length, 0); c.dispose();
  }
});

test("approved recovery after an unreceived exchange permits retry with the same issuance id", async () => {
  let firstIssuance, attempts = 0, statusCalls = 0;
  const h = harness(async (action, body) => {
    if (action === "create") return { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" };
    if (action === "status") { statusCalls++; return progress({ state: "approved" }); }
    if (action === "exchange") {
      attempts++;
      if (firstIssuance === undefined) firstIssuance = body.operation_id;
      assert.equal(body.operation_id, firstIssuance);
      if (attempts === 1) return Error("request did not reach server");
      return { ...bundle(), progress: progress({ state: "issued", delivery_state: "recoverable", issuance_operation_id: firstIssuance, recover_until_unix_secs: expiry }) };
    }
    if (action === "recover") return { status: 409, body: { error: "scan_not_approved" } };
    throw Error(action);
  });
  const c = h.client(); await ok(c.create()); await ok(c.status());
  await assert.rejects(c.exchange(), e => e.code === "network_unknown");
  await assert.rejects(c.recover(), e => e.code === "scan_not_approved" && e.status === 409);
  await ok(c.status()); assert.equal(c.getSnapshot().phase, "waiting");
  await ok(c.exchange());
  assert.equal(statusCalls, 2); assert.equal(attempts, 2); assert.equal([...h.state.rows.values()][0].exchange_operation_id, firstIssuance);
  assert.equal([...h.state.rows.values()][0].phase, "pending"); c.dispose();
});

test("cancel closes origin when exchange write-ahead exists but abort reports not found", async () => {
  const actions = [];
  const h = harness(async (action, body) => {
    actions.push(action);
    if (action === "create") return { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" };
    if (action === "status") return progress({ state: "approved" });
    if (action === "exchange") return Error("request never arrived");
    if (action === "abort") return { status: 404, body: { error: "scan_not_found" } };
    if (action === "close-origin") return { origin_operation_id: body.origin_operation_id, origin_action: body.origin_action, outcome: "closed" };
    throw Error(action);
  });
  const c = h.client(); await ok(c.create()); await ok(c.status()); await assert.rejects(c.exchange());
  await ok(c.cancel());
  assert.deepEqual(actions.slice(-2), ["abort", "close-origin"]);
  assert.equal([...h.state.rows.values()][0].phase, "closed"); assert.equal(h.state.discarded.length, 1); c.dispose();
});

test("cancel closes origin when exchange is unapproved and abort reports Core 409 scan_not_approved", async () => {
  const actions = [];
  const h = harness(async (action, body) => {
    actions.push(action);
    if (action === "create") return { progress: progress(), display_code: "D1." + b64(32), verification_uri: "https://embedded-idp.invalid/idp/auth/browser/device-scan/ui" };
    if (action === "status") return progress({ state: "approved" });
    if (action === "exchange") return Error("request never arrived");
    if (action === "abort") return { status: 409, body: { error: "scan_not_approved" } };
    if (action === "close-origin") return { origin_operation_id: body.origin_operation_id, origin_action: body.origin_action, outcome: "closed" };
    throw Error(action);
  });
  const c = h.client(); await ok(c.create()); await ok(c.status()); await assert.rejects(c.exchange());
  await ok(c.cancel());
  assert.deepEqual(actions.slice(-2), ["abort", "close-origin"]);
  assert.equal([...h.state.rows.values()][0].phase, "closed"); assert.equal(h.state.discarded.length, 1); c.dispose();
});
