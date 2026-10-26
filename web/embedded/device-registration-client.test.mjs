import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import test from "node:test";
import ts from "typescript";

globalThis.crypto ??= webcrypto;
const source = await readFile(new URL("./device-registration-client.ts", import.meta.url), "utf8");
let uuidCount = 0;
const compiled = ts.transpileModule(source.replace(/^import .*;\n/gm, ""), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
}).outputText;
const code = `let uuidCount = 0; const secureRandomUuid = () => { uuidCount++; return '11111111-1111-4111-8111-' + String(uuidCount).padStart(12, '0'); };\n${compiled}`;
const { DeviceRegistrationClient, buildDeviceRegistrationProofBytes } = await import(`data:text/javascript;base64,${Buffer.from(code).toString("base64")}`);
const target = Object.freeze({ baseUrl: "https://idp.example.test/idp", tenant_id: "0", client_id: "client-a", entry_id: "entry-a", device_id: "11111111-1111-4111-8111-222222222222" });
const seed = Buffer.alloc(32, 0x42);
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
const publicKey = createPublicKey(privateKey);
const publicBytes = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
const encode64 = bytes => Buffer.from(bytes).toString("base64url");
const b32 = encode64(publicBytes);
function lockStore() {
  const rows = new Map(); const tails = new Map();
  const key = t => JSON.stringify([t.baseUrl, t.tenant_id, t.client_id, t.entry_id, t.device_id]);
  return {
    rows,
    async withLock(t, operation) {
      const k = key(t), previous = tails.get(k) ?? Promise.resolve();
      let release; const current = new Promise(resolve => { release = resolve; }); tails.set(k, previous.then(() => current));
      await previous;
      try { return await operation(); } finally { release(); if (tails.get(k) === current) tails.delete(k); }
    },
    async load(t) { const v = rows.get(key(t)); return v && structuredClone(v); },
    async save(r) { rows.set(key(r.target), structuredClone(r)); },
  };
}
function harness({ loseProvision = false, loseComplete = false, scope = "provider.grant-a", challengePersisted = true, store = lockStore() } = {}) {
  const state = { provisioned: false, completed: false, provisionBody: undefined, challenges: 0, challenge: undefined, active: 0, calls: [] };
  const signer = {
    async prepare() { state.key_id = await digestKey(b32); return { handle: "opaque-host-handle", public_jwk: { kty: "OKP", crv: "Ed25519", x: b32 }, key_id: state.key_id }; },
    async signRegistration({ target, key_id, challenge }) {
      const bytes = buildDeviceRegistrationProofBytes({ tenant_id: target.tenant_id, device_id: target.device_id, key_id, challenge });
      return encode64(sign(null, bytes, privateKey));
    },
    async activate() { state.active++; }, async discard() {},
  };
  const admission = { async authorize({ action }) { return { credential: "grant.secret", registration_scope: scope, expires_at_unix_secs: Math.floor(Date.now() / 1000) + 500 }; } };
  const transport = async (url, init) => {
    const path = new URL(url).pathname.replace("/idp", ""); const body = init.body ? JSON.parse(init.body) : {};
    state.calls.push({ path, init, body });
    if (init.credentials !== "omit" || init.cache !== "no-store" || init.redirect !== "error") throw Error("transport policy");
    if (path === "/devices/provision") {
      assert.equal(init.headers["x-embedded-idp-device-admission"], "grant.secret");
      assert.deepEqual(Object.keys(body.public_jwk).sort(), ["crv", "kid", "kty", "x"]);
      assert.equal(body.public_jwk.kid, state.key_id);
      if (state.provisionBody) assert.deepEqual(body, state.provisionBody);
      else state.provisionBody = body;
      state.provisioned = true;
      if (loseProvision) { loseProvision = false; throw Error("dropped response"); }
      return json(result(state, body), 201);
    }
    if (path === "/devices/registration-result") return state.provisioned ? json(result(state, state.provisionBody)) : json({ error: "missing" }, 404);
    if (path === "/devices/proof/challenges") {
      state.challenges++;
      state.challenge = "A".repeat(42) + ["E", "I", "M", "Q"][((state.challenges - 1) % 4)];
      return json({ challenge: state.challenge, expires_at_unix_secs: Math.floor(Date.now() / 1000) + 60 });
    }
    if (path === "/devices/complete") {
      if (!challengePersisted) return json({ error: "challenge not stored" }, 400);
      assert.deepEqual(Object.keys(body.public_jwk).sort(), ["crv", "kid", "kty", "x"]);
      assert.equal(body.public_jwk.kid, state.key_id);
      const proof = buildDeviceRegistrationProofBytes({ tenant_id: body.tenant_id, device_id: body.device_id, key_id: body.public_jwk.kid, challenge: body.challenge });
      assert.equal(verify(null, proof, publicKey, Buffer.from(body.signature, "base64url")), true);
      state.completed = true;
      if (loseComplete) { loseComplete = false; throw Error("dropped response"); }
      return json({ tenant_id: "0", device_id: target.device_id, key_id: state.key_id, version: 1 });
    }
    throw Error(`unexpected ${path}`);
  };
  const client = () => new DeviceRegistrationClient({ target, signer, admission, store, transport });
  return { state, client, store, signer, admission, transport };
}
async function digestKey(x) {
  const bytes = new TextEncoder().encode(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
function result(state, body) {
  const done = state.completed;
  return { tenant_id: "0", client_id: "client-a", device_id: target.device_id, expected_key_id: state.key_id,
    created_at_unix_secs: 100, expires_at_unix_secs: Math.floor(Date.now() / 1000) + 3600,
    completed_at_unix_secs: done ? Math.floor(Date.now() / 1000) : null,
    status: done ? "active" : "pending", version: done ? 2 : 1, proof_key_id: done ? state.key_id : null, key_version: done ? 1 : null,
  };
}
// Store the key identifier used in the service projection.

test("registration proof bytes match the Core canonical format and reject invalid input", () => {
  const actual = new TextDecoder().decode(buildDeviceRegistrationProofBytes({ tenant_id: "0", device_id: target.device_id, key_id: b32, challenge: b32 }));
  assert.equal(actual, `EMBEDDED-IDP-DEVICE-REGISTRATION-V2\ntenant-id:0\ndevice-id:${target.device_id}\nkey-id:${b32}\nchallenge:${b32}\n`);
  assert.throws(() => buildDeviceRegistrationProofBytes({ tenant_id: "0", device_id: target.device_id, key_id: "bad", challenge: b32 }));
});

test("prepare persists a secret-free public journal before network and discard is pre-send only", async () => {
  const h = harness(); const client = h.client();
  await client.prepare("Test laptop");
  assert.equal(client.getSnapshot().phase, "prepared");
  const saved = [...h.store.rows.values()][0];
  assert.equal(saved.device_name, "Test laptop");
  assert.equal(JSON.stringify(saved).includes("private"), false);
  assert.equal(h.state.calls.length, 0);
  await client.discard();
  assert.equal(client.getSnapshot().phase, "abandoned");
  assert.equal(h.state.calls.length, 0);
});

test("save failure during prepare sends no HTTP and discards only the unsent key", async () => {
  const h = harness(); let discards = 0;
  const signer = { ...h.client().signer, async prepare() { return { handle: "h", public_jwk: { kty: "OKP", crv: "Ed25519", x: b32 }, key_id: await digestKey(b32) }; }, async discard() { discards++; } };
  const store = { ...h.store, async save() { throw Error("disk full"); } };
  const client = new DeviceRegistrationClient({ target, signer, admission: { async authorize() { throw Error(); } }, store, transport: async () => { throw Error("must not send"); } });
  await assert.rejects(client.prepare("Laptop"), e => e.code === "operation_failed");
  assert.equal(discards, 1);
});

test("lost provision response recovers in a fresh client from the original durable request", async () => {
  const h = harness({ loseProvision: true }); const first = h.client();
  await first.prepare("Laptop");
  await assert.rejects(first.provision(), e => e.code === "network_unknown");
  assert.equal(first.getSnapshot().phase, "provision-unknown");
  first.dispose();
  const recovered = h.client(); await recovered.recover();
  assert.equal(recovered.getSnapshot().phase, "pending");
  assert.equal(h.state.provisionBody.registration_request_id, [...h.store.rows.values()][0].registration_request_id);
  assert.equal(h.state.calls.filter(c => c.path === "/devices/provision").length, 1);
});

test("lost complete response is reconciled by a fresh client before local activation", async () => {
  const h = harness({ loseComplete: true }); const first = h.client();
  await first.prepare("Laptop"); await first.provision();
  await assert.rejects(first.complete(), e => e.code === "network_unknown");
  assert.equal(first.getSnapshot().phase, "complete-unknown"); first.dispose();
  const recovered = h.client(); await recovered.recover();
  assert.equal(recovered.getSnapshot().phase, "active"); assert.equal(h.state.active, 1);
  assert.equal(h.state.calls.filter(c => c.path === "/devices/complete").length, 1);
});

test("an issued but unpersisted challenge is not treated as completion; a fresh challenge succeeds", async () => {
  const h = harness(); let rejectOneChallenge = true;
  const transport = async (url, init) => {
    if (new URL(url).pathname.endsWith("/devices/complete") && rejectOneChallenge) { rejectOneChallenge = false; return json({ error: "challenge absent" }, 400); }
    return h.transport(url, init);
  };
  const client = new DeviceRegistrationClient({ target, signer: h.signer, admission: h.admission, store: h.store, transport });
  await client.prepare("Laptop"); await client.provision();
  await assert.rejects(client.complete());
  assert.equal(client.getSnapshot().phase, "complete-unknown"); assert.equal(h.state.active, 0);
  await client.complete();
  assert.equal(client.getSnapshot().phase, "active"); assert.equal(h.state.active, 1); assert.equal(h.state.challenges, 2);
});

test("scope changes fail closed and target/response validation rejects malformed state", async () => {
  const h = harness(); const first = h.client(); await first.prepare("Laptop"); await first.provision();
  const changed = new DeviceRegistrationClient({ target, signer: h.signer, admission: { async authorize() { return { credential: "x", registration_scope: "other", expires_at_unix_secs: Math.floor(Date.now() / 1000) + 300 }; } }, store: h.store, transport: h.transport });
  await assert.rejects(changed.recover(), e => e.code === "scope_changed");
  assert.throws(() => new DeviceRegistrationClient({ target: { ...target, baseUrl: "https://u:p@example.test/idp?x" }, signer: h.signer, admission: h.admission, store: h.store }), e => e.code === "invalid_target");
  const invalidTransport = async () => json({ tenant_id: "wrong", client_id: "client-a", device_id: target.device_id,
    expected_key_id: b32, created_at_unix_secs: 100, expires_at_unix_secs: 200, completed_at_unix_secs: null,
    status: "pending", version: 1, proof_key_id: null, key_version: null });
  const malformed = new DeviceRegistrationClient({ target, signer: h.signer, admission: h.admission, store: h.store, transport: invalidTransport });
  await assert.rejects(malformed.recover(), e => e.code === "invalid_response");
});

test("two client instances serialize through the host lock and reload before preparing", async () => {
  const h = harness(); const a = h.client(), b = h.client();
  const settled = await Promise.allSettled([a.prepare("Laptop"), b.prepare("Laptop")]);
  assert.equal(settled.filter(v => v.status === "fulfilled").length, 1);
  assert.equal(settled.filter(v => v.status === "rejected").length, 1);
  assert.equal([...h.store.rows.values()].length, 1);
});

test("a 404 lookup retries provision only with the original request and DTO", async () => {
  const h = harness(); const client = h.client(); await client.prepare("Laptop");
  let provisionCalls = 0;
  const transport = async (url, init) => {
    if (new URL(url).pathname.endsWith("/devices/provision") && provisionCalls++ === 0) return json({ error: "not found" }, 404);
    return h.transport(url, init);
  };
  const retryClient = new DeviceRegistrationClient({ target, signer: h.signer, admission: h.admission, store: h.store, transport });
  await assert.rejects(retryClient.provision(), e => e.status === 404);
  const original = [...h.store.rows.values()][0];
  await retryClient.retryProvision();
  assert.equal(h.state.provisioned, true);
  assert.equal(h.state.provisionBody.registration_request_id, original.registration_request_id);
  assert.equal(provisionCalls, 2);
});

test("write-ahead journal failures stop provision and complete HTTP writes", async () => {
  const h1 = harness(); const baseStore1 = h1.store; let failProvisionJournal = true;
  const store1 = { ...baseStore1, async save(r) { if (r.phase === "provision-unknown" && failProvisionJournal) { failProvisionJournal = false; throw Error("storage unavailable"); } return baseStore1.save(r); } };
  const c1 = new DeviceRegistrationClient({ target, signer: h1.signer, admission: h1.admission, store: store1, transport: h1.transport });
  await c1.prepare("Laptop"); await assert.rejects(c1.provision());
  assert.equal(h1.state.calls.filter(c => c.path === "/devices/provision").length, 0);

  const h2 = harness(); const baseStore2 = h2.store; let failCompleteJournal = true;
  const store2 = { ...baseStore2, async save(r) { if (r.phase === "complete-unknown" && failCompleteJournal) { failCompleteJournal = false; throw Error("storage unavailable"); } return baseStore2.save(r); } };
  const c2 = new DeviceRegistrationClient({ target, signer: h2.signer, admission: h2.admission, store: store2, transport: h2.transport });
  await c2.prepare("Laptop"); await c2.provision(); await assert.rejects(c2.complete());
  assert.equal(h2.state.calls.filter(c => c.path === "/devices/complete").length, 0);
});

test("malformed signer keys are discarded before they can be provisioned", async () => {
  const h = harness(); let discarded = 0;
  const signer = { ...h.signer, async prepare() { const key_id = await digestKey(b32); return { handle: "h", public_jwk: { kty: "OKP", crv: "Ed25519", x: b32, d: "secret" }, key_id }; }, async discard() { discarded++; } };
  const client = new DeviceRegistrationClient({ target, signer, admission: h.admission, store: h.store, transport: h.transport });
  await assert.rejects(client.prepare("Laptop"), e => e.code === "invalid_key");
  assert.equal(discarded, 1); assert.equal(h.state.calls.length, 0);
});

test("expired admission and registration/challenge deadlines prevent writes", async () => {
  const h = harness(); const expiredAdmission = { async authorize() { return { credential: "x", registration_scope: "s", expires_at_unix_secs: 1 }; } };
  const c = new DeviceRegistrationClient({ target, signer: h.signer, admission: expiredAdmission, store: h.store, transport: h.transport });
  await c.prepare("Laptop"); await assert.rejects(c.provision());
  assert.equal(h.state.calls.length, 0);

  const h2 = harness(); const c2 = h2.client(); await c2.prepare("Laptop"); await c2.provision();
  const stale = async (url, init) => {
    const path = new URL(url).pathname;
    if (path.endsWith("/proof/challenges")) return json({ challenge: b32, expires_at_unix_secs: 1 });
    if (path.endsWith("/registration-result")) return json({ ...result(h2.state, h2.state.provisionBody), expires_at_unix_secs: Math.floor(Date.now() / 1000) - 1 });
    return h2.transport(url, init);
  };
  const c3 = new DeviceRegistrationClient({ target, signer: h2.signer, admission: h2.admission, store: h2.store, transport: stale });
  await assert.rejects(c3.complete(), e => e.code === "registration_expired");
  assert.equal(h2.state.calls.filter(x => x.path === "/devices/complete").length, 0);
});

test("dispose during a result lookup prevents subsequent signing and activation", async () => {
  const h = harness(); const first = h.client(); await first.prepare("Laptop"); await first.provision(); h.state.completed = true;
  let started; const began = new Promise(resolve => { started = resolve; }); let release;
  const wait = new Promise(resolve => { release = resolve; });
  const transport = async (url, init) => {
    if (new URL(url).pathname.endsWith("/registration-result")) { started(); await wait; return json(result(h.state, h.state.provisionBody)); }
    return h.transport(url, init);
  };
  const c = new DeviceRegistrationClient({ target, signer: h.signer, admission: h.admission, store: h.store, transport });
  const pending = c.recover(); await began; c.dispose(); release();
  await assert.rejects(pending, e => e.code === "disposed");
  assert.equal(h.state.active, 0);
});

test("a changed or revoked device result never activates the candidate", async () => {
  const h = harness(); const c = h.client(); await c.prepare("Laptop"); await c.provision(); h.state.completed = true;
  const revoked = async (url, init) => {
    if (new URL(url).pathname.endsWith("/registration-result")) return json({ ...result(h.state, h.state.provisionBody), status: "revoked" });
    return h.transport(url, init);
  };
  const recovery = new DeviceRegistrationClient({ target, signer: h.signer, admission: h.admission, store: h.store, transport: revoked });
  await assert.rejects(recovery.recover()); assert.equal(h.state.active, 0);
});

test("an expired challenge and a noncanonical 64-byte signature are rejected before complete", async () => {
  const h = harness(); const c = h.client(); await c.prepare("Laptop"); await c.provision();
  const expired = async (url, init) => new URL(url).pathname.endsWith("/proof/challenges")
    ? json({ challenge: b32, expires_at_unix_secs: Math.floor(Date.now() / 1000) - 1 }) : h.transport(url, init);
  const c2 = new DeviceRegistrationClient({ target, signer: h.signer, admission: h.admission, store: h.store, transport: expired });
  await assert.rejects(c2.complete(), e => e.code === "challenge_invalid");
  assert.equal(h.state.calls.filter(x => x.path === "/devices/complete").length, 0);

  const badSigner = { ...h.signer, async signRegistration() { return "A".repeat(85) + "V"; } };
  const c3 = new DeviceRegistrationClient({ target, signer: badSigner, admission: h.admission, store: h.store, transport: h.transport });
  await assert.rejects(c3.complete(), e => e.code === "signature_invalid");
  assert.equal(h.state.calls.filter(x => x.path === "/devices/complete").length, 0);
});

test("grant expiry while the write-ahead record is being saved blocks provision", async () => {
  const h = harness(); let saved = false;
  const store = { ...h.store, async save(r) {
    await h.store.save(r);
    if (r.phase === "provision-unknown" && !saved) { saved = true; await new Promise(resolve => setTimeout(resolve, 1100)); }
  } };
  const admission = { async authorize() { return { credential: "x", registration_scope: "provider.grant-a", expires_at_unix_secs: Math.floor(Date.now() / 1000) + 1 }; } };
  const c = new DeviceRegistrationClient({ target, signer: h.signer, admission, store, transport: h.transport });
  await c.prepare("Laptop"); await assert.rejects(c.provision(), e => e.code === "admission_expired");
  assert.equal(h.state.calls.filter(x => x.path === "/devices/provision").length, 0);
});

test("base URL rejects whitespace normalization and ambiguous path escapes", async () => {
  for (const baseUrl of ["/idp/\n/evil", "/idp/%2e%2e/admin", "https://example.test/idp%2f..%2fadmin"]) {
    assert.throws(() => new DeviceRegistrationClient({ target: { ...target, baseUrl }, signer: {}, admission: {}, store: {} }), e => e.code === "invalid_target");
  }
});

test("uncertain journal commit retains a candidate instead of deleting its key", async () => {
  const h = harness(); let discarded = 0;
  const signer = { ...h.signer, async discard() { discarded++; } };
  let attempted = false;
  const store = { ...h.store, async save(r) { attempted = true; await h.store.save(r); throw Error("commit acknowledgment lost"); }, async load(t) { if (attempted) throw Error("storage unavailable"); return h.store.load(t); } };
  const c = new DeviceRegistrationClient({ target, signer, admission: h.admission, store, transport: h.transport });
  await assert.rejects(c.prepare("Laptop"));
  assert.equal(attempted, true); assert.equal(h.store.rows.size, 1);
  assert.equal(discarded, 0); assert.equal(h.state.calls.length, 0);
});

test("dispose after signer preparation discards the unsent candidate", async () => {
  const h = harness(); let discarded = 0; let begin; const started = new Promise(resolve => { begin = resolve; }); let release;
  const wait = new Promise(resolve => { release = resolve; });
  const signer = { ...h.signer, async prepare(args) { const result = await h.signer.prepare(args); begin(); await wait; return result; }, async discard() { discarded++; } };
  const c = new DeviceRegistrationClient({ target, signer, admission: h.admission, store: h.store, transport: h.transport });
  const preparing = c.prepare("Laptop"); await started; c.dispose(); release(); await assert.rejects(preparing, e => e.code === "disposed");
  assert.equal(discarded, 1); assert.equal(h.state.calls.length, 0);
});


test("challenge TTL may outlive registration but both must be valid before signing", async t => {
  const originalNow = Date.now(); let now = originalNow;
  t.mock.method(Date, "now", () => now);
  const h = harness(); const first = h.client(); await first.prepare("Laptop"); await first.provision();
  let signed = 0; let delayed = false;
  const signer = { ...h.signer, async signRegistration(args) { signed++; return h.signer.signRegistration(args); } };
  const transport = async (url, init) => {
    if (new URL(url).pathname.endsWith("/registration-result")) return json({ ...result(h.state, h.state.provisionBody), expires_at_unix_secs: Math.floor(originalNow / 1000) + 10 });
    if (new URL(url).pathname.endsWith("/proof/challenges")) {
      if (delayed) now += 11_000;
      return json({ challenge: b32, expires_at_unix_secs: Math.floor(originalNow / 1000) + 300 });
    }
    return h.transport(url, init);
  };
  const c = new DeviceRegistrationClient({ target, signer, admission: h.admission, store: h.store, transport });
  delayed = true;
  await assert.rejects(c.complete(), e => e.code === "registration_expired");
  assert.equal(signed, 0, "do not ask host to sign after registration expires during challenge fetch");
  now = originalNow; delayed = false;
  await c.complete();
  assert.equal(signed, 1);
  assert.equal(c.getSnapshot().phase, "active");
});

test("activation and final journal failures recover without repeating a remote write", async () => {
  const h = harness(); let failActivate = true, failSave = true;
  const signer = { ...h.signer, async activate(args) { if (failActivate) { failActivate = false; throw Error("host unavailable"); } return h.signer.activate(args); } };
  const store = { ...h.store, async save(r) { if (r.phase === "active" && failSave) { failSave = false; throw Error("disk full"); } return h.store.save(r); } };
  const fresh = () => new DeviceRegistrationClient({ target, signer, admission: h.admission, store, transport: h.transport });
  let c = fresh(); await c.prepare("Laptop"); await c.provision(); await assert.rejects(c.complete());
  assert.equal((await h.store.load(target)).phase, "complete-unknown");
  c.dispose(); c = fresh(); await assert.rejects(c.recover());
  c.dispose(); c = fresh(); await c.recover();
  assert.equal(c.getSnapshot().phase, "active");
  assert.equal(h.state.calls.filter(x => x.path === "/devices/complete").length, 1);
});

test("journal scope corruption and a later rotation fail closed without activation or deletion", async () => {
  const h = harness(); const c = h.client(); await c.prepare("Laptop"); await c.provision(); h.state.completed = true;
  const rotated = async (url, init) => new URL(url).pathname.endsWith("/registration-result")
    ? json({ ...result(h.state, h.state.provisionBody), version: 3, key_version: 2, proof_key_id: b32 }) : h.transport(url, init);
  let discarded = 0;
  const signer = { ...h.signer, async discard() { discarded++; } };
  const changed = new DeviceRegistrationClient({ target, signer, admission: h.admission, store: h.store, transport: rotated });
  await assert.rejects(changed.recover(), e => e.code === "registration_changed");
  await assert.rejects(changed.discard(), e => e.code === "cannot_discard");
  assert.equal(h.state.active, 0); assert.equal(discarded, 0);
  const saved = await h.store.load(target); saved.target.entry_id = "wrong-entry";
  const brokenStore = { ...h.store, async load() { return saved; }, async save() { assert.fail("must not overwrite wrong target"); } };
  const broken = new DeviceRegistrationClient({ target, signer, admission: h.admission, store: brokenStore, transport: rotated });
  await assert.rejects(broken.load(), e => e.code === "invalid_store");
});


test("missing host methods fail before exposing an operational registration client", () => {
  const h = harness();
  for (const missing of [{ signer: {} }, { admission: {} }, { store: {} }]) {
    assert.throws(() => new DeviceRegistrationClient({ target, signer: h.signer, admission: h.admission, store: h.store, ...missing }), e => e.code === "missing_adapter");
  }
});
