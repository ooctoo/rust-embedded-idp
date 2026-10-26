import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign, verify, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";
const src = await readFile(new URL("./device-key-rotation-client.ts", import.meta.url), "utf8");
const pre = "class IdentityError extends Error {constructor(message,status,code){super(message);this.status=status;this.code=code}};let n=0;const secureRandomUuid=()=>{n++;return '11111111-1111-4111-8111-'+String(n).padStart(12,'0')};\n";
const js = ts.transpileModule(pre + src.replace(/^import .*;\n/gm, ""), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const { DeviceKeyRotationClient, buildDeviceKeyRotationProofBytes } = await import("data:text/javascript;base64," + Buffer.from(js).toString("base64"));
const target = { baseUrl: "/idp", tenant_id: "0", client_id: "client-a", entry_id: "entry-a", device_id: "11111111-1111-4111-8111-222222222222" };
const owner = { tenant_id: "0", account_id: "account-a", client_id: "client-a", session_id: "session-a" }, binding = "22222222-2222-4222-8222-222222222222";
const enc = b => Buffer.from(b).toString("base64url"), kid = x => createHash("sha256").update(JSON.stringify({ crv: "Ed25519", kty: "OKP", x })).digest("base64url");
function key(seed) { const priv = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, seed)]), format: "der", type: "pkcs8" }), p = createPublicKey(priv).export({ format: "jwk" }); return { priv, jwk: { kty: p.kty, crv: p.crv, x: p.x }, id: kid(p.x) }; }
function setup({ loseAfter = false, loseBefore = false, afterCommit } = {}) {
    const old = key(0x41), next = key(0x52), rows = new Map(), locks = new Map();
    let device = { tenant_id: "0", device_id: target.device_id, client_id: target.client_id, proof_key_id: old.id, status: "active", version: 4, key_version: 3, binding_id: binding, binding_version: 7, device_name: "fixture", registered_at_unix_secs: 10, last_seen_at_unix_secs: null, binding_status: "active" };
    const meta = new Map([[old.id, { tenant_id: "0", device_id: target.device_id, key_id: old.id, algorithm: "ed25519", version: 3, status: "active", registered_at_unix_secs: 10, retired_at_unix_secs: null }]]), state = { prep: 0, activated: 0, discarded: 0, writes: 0, challenges: 0 };
    const store = { async withLock(t, fn) { const k = JSON.stringify(t), prev = locks.get(k) || Promise.resolve(); let release; const gate = new Promise(r => release = r); locks.set(k, prev.then(() => gate)); await prev; try {
            return await fn();
        }
        finally {
            release();
        } }, async load(t) { const r = rows.get(JSON.stringify(t)); return r && structuredClone(r); }, async save(r) { rows.set(JSON.stringify(r.target), structuredClone(r)); } };
    const snap = { status: "authenticated", session: owner }, listeners = new Set();
    const identity = { deviceBaseUrl: "/idp", getSnapshot: () => snap, subscribe(f) { listeners.add(f); return () => listeners.delete(f); }, async requestDevice(path, body) {
            if (path.endsWith("challenges")) {
                state.challenges++;
                return { session: snap.session, value: { challenge: enc(randomBytes(32)), expires_at_unix_secs: Math.floor(Date.now() / 1000) + 60 } };
            }
            assert.equal(path, "/devices/rotate-key");
            state.writes++;
            assert.equal(body.proposed_public_jwk.kid, next.id);
            const bytes = buildDeviceKeyRotationProofBytes({ tenant_id: "0", device_id: target.device_id, old_key_id: old.id, new_key_id: next.id, new_key_version: 4, challenge: body.challenge });
            assert(verify(null, bytes, old.priv, Buffer.from(body.current_key_signature, "base64url")));
            assert(verify(null, bytes, next.priv, Buffer.from(body.proposed_key_signature, "base64url")));
            if (loseBefore) {
                loseBefore = false;
                throw new Error("lost before commit");
            }
            meta.set(old.id, { ...meta.get(old.id), status: "retired", retired_at_unix_secs: 20 });
            meta.set(next.id, { tenant_id: "0", device_id: target.device_id, key_id: next.id, algorithm: "ed25519", version: 4, status: "active", registered_at_unix_secs: 20, retired_at_unix_secs: null });
            device = { ...device, proof_key_id: next.id, key_version: 4, version: 5 };
            if (afterCommit)
                afterCommit({ device: { ...device }, state, snap, listeners, setDevice: d => device = d });
            if (loseAfter) {
                loseAfter = false;
                throw new Error("lost after commit");
            }
            return { session: snap.session, value: { tenant_id: "0", device_id: target.device_id, key_id: next.id, version: 4 } };
        } };
    const devices = { identity, async detail() { return { ...device }; }, async keyMetadata(d, k) { if (!meta.has(k))
            throw Object.assign(Error(), { status: 404 }); return { ...meta.get(k) }; } };
    const signer = { async prepare() { state.prep++; return { current_handle: "oldhandle", handle: "newhandle", public_jwk: next.jwk, key_id: next.id }; }, async signRotation({ challenge, new_key_version }) { const b = buildDeviceKeyRotationProofBytes({ tenant_id: "0", device_id: target.device_id, old_key_id: old.id, new_key_id: next.id, new_key_version, challenge }); return { current_key_signature: sign(null, b, old.priv).toString("base64url"), proposed_key_signature: sign(null, b, next.priv).toString("base64url") }; }, async activate() { state.activated++; }, async discard() { state.discarded++; } };
    return { state, old, next, metadata: meta, records: rows, device: () => device, setDevice: d => device = d, snap, listeners, store, signer, devices, client: () => new DeviceKeyRotationClient({ devices, target, signer, store }) };
}
test("builder produces the canonical Core ROTATION-V2 message", () => { const h = setup(), c = "A".repeat(43); assert.equal(new TextDecoder().decode(buildDeviceKeyRotationProofBytes({ tenant_id: "0", device_id: target.device_id, old_key_id: h.old.id, new_key_id: h.next.id, new_key_version: 4, challenge: c })), "EMBEDDED-IDP-DEVICE-KEY-ROTATION-V2\ntenant-id:0\ndevice-id:" + target.device_id + "\nold-key-id:" + h.old.id + "\nnew-key-id:" + h.next.id + "\nnew-key-version:4\nchallenge:" + c + "\n"); });
test("candidate is journaled; real old and new Ed25519 signatures are verified before activation", async () => { const h = setup(), c = h.client(); await c.prepare(); assert.equal([...h.records.values()][0].phase, "prepared"); await c.rotate(); assert.equal(c.getSnapshot().phase, "active"); assert.equal(h.state.activated, 1); assert.equal(h.state.writes, 1); assert.equal(h.state.prep, 1); assert.equal(JSON.stringify(c.getSnapshot()).includes("newhandle"), false); });
test("a lost successful response recovers through current pointer and metadata in a fresh client", async () => { const h = setup({ loseAfter: true }), a = h.client(); await a.prepare(); await assert.rejects(a.rotate()); assert.equal(a.getSnapshot().phase, "rotate-unknown"); a.dispose(); const b = h.client(); await b.recover(); assert.equal(b.getSnapshot().phase, "active"); assert.equal(h.state.writes, 1); assert.equal(h.state.activated, 1); });
test("unknown with old pointer keeps phase and candidate; explicit retry uses a fresh challenge", async () => { const h = setup({ loseBefore: true }), a = h.client(); await a.prepare(); await assert.rejects(a.rotate()); a.dispose(); const b = h.client(); await b.recover(); assert.equal(b.getSnapshot().phase, "rotate-unknown"); await assert.rejects(b.discard()); await b.rotate(); assert.equal(h.state.prep, 1); assert.equal(h.state.challenges, 2); assert.equal(h.state.writes, 2); assert.equal(h.state.activated, 1); });
test("wrong owner, changed binding, later rotation and disabled device cannot activate", async () => { const h = setup({ loseAfter: true }), a = h.client(); await a.prepare(); await assert.rejects(a.rotate()); h.setDevice({ ...h.device(), binding_version: 8 }); const b = h.client(); await assert.rejects(b.recover()); assert.equal(h.state.activated, 0); assert.equal(h.state.discarded, 0); h.snap.session = { ...owner, account_id: "other" }; for (const f of h.listeners)
    f(); await assert.rejects(b.load()); });
test("target path must match the identity transport and a failed write-ahead save sends no rotation", async () => {
    const h = setup(), c = h.client();
    assert.throws(() => new DeviceKeyRotationClient({ devices: c.devices, target: { ...target, baseUrl: "/other" }, signer: c.signer, store: h.store }), e => e.code === "entry_mismatch");
    await c.prepare();
    const bad = { ...h.store, async save() { throw Error("disk"); } }, d = new DeviceKeyRotationClient({ devices: c.devices, target, signer: c.signer, store: bad });
    await assert.rejects(d.rotate());
    assert.equal(h.state.writes, 0);
    assert.equal(h.state.discarded, 0);
});
test("strict target paths reject normalized traversal and allow the root entry", () => {
    const h = setup(), c = h.client();
    for (const baseUrl of ["/idp/../admin", "https://example.test/idp/../admin", "/idp/%2e%2e/admin"])
        assert.throws(() => new DeviceKeyRotationClient({ devices: h.devices, target: { ...target, baseUrl }, signer: h.signer, store: h.store }), e => e.code === "invalid_target");
    const rootDevices = { ...h.devices, identity: { ...h.devices.identity, deviceBaseUrl: "/" } };
    assert.doesNotThrow(() => new DeviceKeyRotationClient({ devices: rootDevices, target: { ...target, baseUrl: "/" }, signer: h.signer, store: h.store }));
});
test("same old and candidate handles are never passed to discard", async () => {
    const h = setup();
    h.signer.prepare = async () => ({ current_handle: "oldhandle", handle: "oldhandle", public_jwk: h.next.jwk, key_id: h.next.id });
    const c = new DeviceKeyRotationClient({ devices: h.devices, target, signer: h.signer, store: h.store });
    await assert.rejects(c.prepare(), e => e.code === "invalid_key");
    assert.equal(h.state.discarded, 0);
});
test("loading an empty host journal clears the prior public phase", async () => {
    const h = setup(), c = h.client();
    await c.prepare();
    await c.discard();
    assert.equal(c.getSnapshot().phase, "abandoned");
    h.records.clear();
    await c.load();
    assert.equal(c.getSnapshot().phase, "empty");
    assert.equal(c.getSnapshot().key_id, undefined);
});
test("an uncertain write-ahead commit never discards the candidate or sends the request", async () => {
    const h = setup(), c = h.client();
    await c.prepare();
    const save = h.store.save, load = h.store.load;
    let attempted = false;
    h.store.save = async (r) => { if (r.phase === "rotate-unknown") {
        attempted = true;
        await save(r);
        throw Error("save acknowledgement lost");
    } return save(r); };
    h.store.load = async (t) => { if (attempted)
        throw Error("read unavailable"); return load(t); };
    const d = h.client();
    await assert.rejects(d.rotate());
    assert.equal(attempted, true);
    assert.equal([...h.records.values()][0].phase, "rotate-unknown");
    assert.equal(h.state.writes, 0);
    assert.equal(h.state.discarded, 0);
});
test("signer activation failure and final active journal failure both recover", async () => {
    for (const failSave of [false, true]) {
        const h = setup(), c = h.client();
        await c.prepare();
        let failActivation = !failSave, failActiveSave = true;
        h.signer.activate = async () => { if (failActivation) {
            failActivation = false;
            throw Error("keystore unavailable");
        } h.state.activated++; };
        if (failSave) {
            const save = h.store.save;
            h.store.save = async (r) => { if (r.phase === "active" && failActiveSave) {
                failActiveSave = false;
                await save(r);
                throw Error("save acknowledgement lost");
            } return save(r); };
        }
        await assert.rejects(c.rotate());
        assert.equal(h.state.writes, 1);
        c.dispose();
        const d = h.client();
        await d.recover();
        assert.equal(d.getSnapshot().phase, "active");
        assert.equal(h.state.writes, 1);
        assert.equal(h.state.activated, failSave ? 2 : 1);
    }
});
test("challenge expiration during signing or write-ahead persistence prevents POST", async (t) => {
    const base = Date.now();
    let now = base;
    t.mock.method(Date, "now", () => now);
    let enter, release;
    const started = new Promise(r => enter = r), gate = new Promise(r => release = r);
    const h = setup(), c = h.client();
    await c.prepare();
    const signRotation = h.signer.signRotation;
    h.signer.signRotation = async (args) => { const result = await signRotation(args); enter(); await gate; return result; };
    const pending = c.rotate();
    await started;
    now = base + 61000;
    release();
    await assert.rejects(pending);
    assert.equal(h.state.writes, 0);
    assert.equal([...h.records.values()][0].phase, "prepared");
    const h2 = setup(), c2 = h2.client();
    await c2.prepare();
    const originalSave = h2.store.save;
    h2.store.save = async (r) => { await originalSave(r); if (r.phase === "rotate-unknown")
        now = base + 122000; };
    await assert.rejects(c2.rotate());
    assert.equal(h2.state.writes, 0);
    assert.equal([...h2.records.values()][0].phase, "rotate-unknown");
});
test("wrong active pointer or version after successful HTTP response prevents activation", async () => {
    for (const mutate of [d => ({ ...d, proof_key_id: "A".repeat(43) }), d => ({ ...d, version: 7 }), d => ({ ...d, key_version: 9 })]) {
        const h = setup({ afterCommit: ({ device, setDevice }) => setDevice(mutate(device)) }), c = h.client();
        await c.prepare();
        await assert.rejects(c.rotate());
        assert.equal(h.state.writes, 1);
        assert.equal(h.state.activated, 0);
        assert.equal(h.state.discarded, 0);
    }
});
test("session change after HTTP commit prevents local activation", async () => {
    const h = setup({ afterCommit: ({ snap, listeners }) => { snap.session = { ...owner, session_id: "session-new" }; for (const fn of listeners)
            fn(); } }), c = h.client();
    await c.prepare();
    await assert.rejects(c.rotate(), e => e.code === "operation_cancelled");
    assert.equal(h.state.writes, 1);
    assert.equal(h.state.activated, 0);
    assert.equal([...h.records.values()][0].phase, "rotate-unknown");
});
test("retired candidate metadata never activates or destroys either key", async () => {
    const h = setup({ loseAfter: true }), a = h.client();
    await a.prepare();
    await assert.rejects(a.rotate());
    h.metadata.set(h.next.id, { tenant_id: "0", device_id: target.device_id, key_id: h.next.id, algorithm: "ed25519", version: 4, status: "retired", registered_at_unix_secs: 20, retired_at_unix_secs: 21 });
    const b = h.client();
    await assert.rejects(b.recover());
    assert.equal(h.state.activated, 0);
    assert.equal(h.state.discarded, 0);
});
test("shared host lock serializes two instances without creating a second candidate", async () => {
    const h = setup();
    const a = h.client(), b = h.client();
    const results = await Promise.allSettled([a.prepare(), b.prepare()]);
    assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
    assert.equal(h.state.prep, 1);
    assert.equal(h.records.size, 1);
    await assert.rejects(b.prepare(), error => error.code === "existing_rotation");
});
test("prepare acknowledgement and journal read loss retains the newly persisted key", async () => {
    const h = setup();
    const save = h.store.save, load = h.store.load;
    let attempted = false;
    h.store.save = async (record) => { attempted = true; await save(record); throw Error("commit reply lost"); };
    h.store.load = async (target) => { if (attempted)
        throw Error("unavailable"); return load(target); };
    await assert.rejects(h.client().prepare());
    assert.equal(attempted, true);
    assert.equal(h.state.prep, 1);
    assert.equal(h.records.size, 1);
    assert.equal(h.state.discarded, 0);
    assert.equal(h.state.writes, 0);
});
test("switching away and back during signing still cancels the original operation", async () => {
    const h = setup(), client = h.client();
    await client.prepare();
    const signRotation = h.signer.signRotation;
    h.signer.signRotation = async (input) => {
        const result = await signRotation(input);
        h.snap.session = { ...owner, account_id: "other-account" };
        for (const listener of h.listeners)
            listener();
        h.snap.session = owner;
        for (const listener of h.listeners)
            listener();
        return result;
    };
    await assert.rejects(client.rotate(), error => error.code === "operation_cancelled");
    assert.equal(h.state.writes, 0);
    assert.equal(h.state.activated, 0);
    assert.equal(h.state.discarded, 0);
});
test("dispose while preparing cleans only a distinct unsent candidate", async () => {
    const h = setup(), client = h.client();
    const prepare = h.signer.prepare;
    h.signer.prepare = async (input) => { const result = await prepare(input); client.dispose(); return result; };
    await assert.rejects(client.prepare(), error => error.code === "operation_cancelled");
    assert.equal(h.state.discarded, 1);
    assert.equal(h.records.size, 0);
    assert.equal(h.state.writes, 0);
});
