// Isolated test host only: fixed synthetic keys and disk journal, in-process mutex.
import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdtemp, readFile, writeFile, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EmbeddedIdentityClient, EmbeddedDeviceClient, DeviceKeyRotationClient, buildDeviceKeyRotationProofBytes } from "./dist/embedded-idp.js";
const base = process.env.IDP_A04_BASE;
assert.ok(base?.startsWith("http://127.0.0.1:"));
const dir = await mkdtemp(join(tmpdir(), "idp-a04c-js-"));
function key(seed) {
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, seed)]), type: "pkcs8", format: "der" });
  const { kty, crv, x } = createPublicKey(privateKey).export({ format: "jwk" });
  return { privateKey, public_jwk: { kty, crv, x }, key_id: createHash("sha256").update(JSON.stringify({ crv, kty, x })).digest("base64url") };
}
const old = key(0x41), proposed = key(0x51);
let attempts = 0, prepares = 0, activated = 0, mode = "bad-old", lastBody, replay = false;
let lock = Promise.resolve();
const path = join(dir, "journal.json");
const store = {
  async withLock(_target, fn) { const previous = lock; let release; lock = new Promise(r => { release = r; }); await previous; try { return await fn(); } finally { release(); } },
  async load() { try { return JSON.parse(await readFile(path, "utf8")); } catch (e) { if (e.code === "ENOENT") return undefined; throw e; } },
  async save(record) { await writeFile(`${path}.next`, JSON.stringify(record), { mode: 0o600 }); await rename(`${path}.next`, path); },
};
const identity = new EmbeddedIdentityClient(base, async (url, init) => {
  if (!url.endsWith("/devices/rotate-key")) return fetch(url, init);
  const record = await store.load();
  assert.equal(record.phase, replay ? "active" : "rotate-unknown");
  attempts++;
  lastBody = JSON.parse(init.body);
  assert.equal(lastBody.expected_key_id, old.key_id);
  assert.equal(lastBody.expected_key_version, 1);
  assert.equal(lastBody.proposed_public_jwk.kid, proposed.key_id);
  const response = await fetch(url, init);
  if (replay) assert.equal(response.status, 409, "real server must reject stale expected key replay");
  if (mode === "lose-success") {
    assert.equal(response.status, 200, "real dual signature must succeed before dropping reply");
    await response.arrayBuffer();
    mode = "normal";
    throw Error("synthetic lost committed rotation response");
  }
  if (mode.startsWith("bad-")) assert.equal(response.ok, false, "each of the two signatures is mandatory");
  return response;
});
try {
  await identity.loadCapabilities();
  await identity.login("admin@example.test", "Runtime-Admin123");
  const devices = new EmbeddedDeviceClient(identity);
  const original = await devices.detail("41414141-4141-4141-8141-414141414141");
  assert.equal(original.proof_key_id, old.key_id);
  const target = { baseUrl: base, tenant_id: "0", client_id: "scan-one", entry_id: "scan-one", device_id: original.device_id };
  const signer = {
    async prepare(context) {
      assert.equal(++prepares, 1);
      assert.deepEqual(context.target, target);
      assert.equal(context.expected_key_id, old.key_id);
      assert.equal(context.expected_key_version, 1);
      await writeFile(join(dir, "candidate.pem"), proposed.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
      await writeFile(join(dir, "rotation-id"), context.rotation_id, { mode: 0o600 });
      return { current_handle: "synthetic-old", handle: "synthetic-new", public_jwk: proposed.public_jwk, key_id: proposed.key_id };
    },
    async signRotation(context) {
      assert.equal(context.rotation_id, await readFile(join(dir, "rotation-id"), "utf8"));
      assert.equal(context.current_handle, "synthetic-old");
      assert.equal(context.handle, "synthetic-new");
      assert.equal(context.new_key_version, 2);
      const bytes = buildDeviceKeyRotationProofBytes({ tenant_id: target.tenant_id, device_id: target.device_id, old_key_id: old.key_id, new_key_id: proposed.key_id, new_key_version: 2, challenge: context.challenge });
      return { current_key_signature: sign(null, bytes, mode === "bad-old" ? proposed.privateKey : old.privateKey).toString("base64url"),
        proposed_key_signature: sign(null, bytes, mode === "bad-new" ? old.privateKey : proposed.privateKey).toString("base64url") };
    },
    async activate(context) { assert.equal(context.handle, "synthetic-new"); assert.equal(context.current_handle, "synthetic-old"); activated++; },
    async discard() { assert.fail("do not delete keys after a rotation attempt"); },
  };
  const fresh = () => new DeviceKeyRotationClient({ devices, target, signer, store });
  let client = fresh();
  await client.prepare();
  const initialRecord = await store.load();
  await assert.rejects(client.rotate());
  // Invalid device proof is a 401: the identity client intentionally clears credentials.
  await identity.login("admin@example.test", "Runtime-Admin123");
  assert.equal((await devices.detail(target.device_id)).proof_key_id, old.key_id);
  mode = "bad-new";
  await assert.rejects(client.rotate());
  // Invalid device proof is a 401: the identity client intentionally clears credentials.
  await identity.login("admin@example.test", "Runtime-Admin123");
  assert.equal((await devices.detail(target.device_id)).proof_key_id, old.key_id);
  mode = "lose-success";
  await assert.rejects(client.rotate());
  assert.equal((await store.load()).phase, "rotate-unknown");
  assert.equal(activated, 0);
  client.dispose();
  await identity.logout();
  await identity.login("admin@example.test", "Runtime-Admin123");
  client = fresh(); await client.load(); await client.recover();
  assert.equal(client.getSnapshot().phase, "active");
  assert.equal(prepares, 1); assert.equal(activated, 1); assert.equal(attempts, 3);
  const final = await devices.detail(target.device_id);
  assert.equal(final.proof_key_id, proposed.key_id); assert.equal(final.key_version, 2);
  assert.equal(final.version, original.version + 1);
  assert.equal((await devices.keyMetadata(target.device_id, old.key_id)).status, "retired");
  assert.equal((await store.load()).rotation_id, initialRecord.rotation_id);
  assert.ok(!JSON.stringify(client.getSnapshot()).includes("synthetic-old"));
  // Replay the exact committed body: ordinary authenticated HTTP, not a new controller attempt.
  replay = true;
  await assert.rejects(identity.requestDevice("/devices/rotate-key", lastBody), error => error.status === 409);
  assert.equal(attempts, 4);
  assert.equal((await devices.detail(target.device_id)).key_version, 2);
  client.dispose(); await identity.logout();
  console.log("A04-C real old/new signature rejection, dual signature commit, lost response, reauthentication and disk-journal recovery passed");
} finally { await rm(dir, { recursive: true, force: true }); }
