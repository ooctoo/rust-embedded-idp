// Test-only host: synthetic fixed Ed25519 seed, private temp directory and local mutex.
// This is not a production keystore or cross-process lock implementation.
import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdtemp, readFile, writeFile, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DeviceRegistrationClient, buildDeviceRegistrationProofBytes } from "./dist/embedded-idp.js";

const target = { baseUrl: process.env.IDP_A04B_BASE, tenant_id: "0", client_id: "scan-one", entry_id: "scan-one", device_id: process.env.IDP_A04B_DEVICE };
assert.ok(target.baseUrl && target.device_id && process.env.IDP_A04B_ADMISSION);
const dir = await mkdtemp(join(tmpdir(), "idp-a04b-js-"));
const journalPath = join(dir, "journal.json");
let lock = Promise.resolve();
let prepared = 0;
let activated = 0;
let lostProvision = false;
let lostComplete = false;
const writes = [];
let scope = "enrollment.scan-grant-one";
const store = {
  async withLock(_target, fn) {
    const preceding = lock;
    let release;
    lock = new Promise(resolve => { release = resolve; });
    await preceding;
    try { return await fn(); } finally { release(); }
  },
  async load(t) {
    assert.deepEqual(t, target);
    try { return JSON.parse(await readFile(journalPath, "utf8")); }
    catch (error) { if (error.code === "ENOENT") return undefined; throw error; }
  },
  async save(record) {
    await writeFile(`${journalPath}.next`, JSON.stringify(record), { mode: 0o600 });
    await rename(`${journalPath}.next`, journalPath);
  },
};
function checkContext(context) {
  assert.deepEqual(context.target, target);
  assert.equal(context.handle, "test-candidate-one");
}
const signer = {
  async prepare({target: t, registration_request_id}) {
    assert.deepEqual(t, target);
    assert.equal(++prepared, 1, "recovery must not generate another candidate");
    const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 0x41)]), format: "der", type: "pkcs8" });
    const { kty, crv, x } = createPublicKey(key).export({ format: "jwk" });
    const public_jwk = { kty, crv, x };
    const key_id = createHash("sha256").update(JSON.stringify({ crv, kty, x })).digest("base64url");
    await writeFile(join(dir, "candidate.pem"), key.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
    await writeFile(join(dir, "context.json"), JSON.stringify({ target: t, registration_request_id, key_id }), { mode: 0o600 });
    return { handle: "test-candidate-one", public_jwk, key_id };
  },
  async signRegistration(context) {
    checkContext(context);
    const saved = JSON.parse(await readFile(join(dir, "context.json"), "utf8"));
    assert.equal(context.registration_request_id, saved.registration_request_id);
    assert.equal(context.key_id, saved.key_id);
    const key = createPrivateKey(await readFile(join(dir, "candidate.pem")));
    const bytes = buildDeviceRegistrationProofBytes({ ...target, key_id: context.key_id, challenge: context.challenge });
    return sign(null, bytes, key).toString("base64url");
  },
  async activate(context) {
    checkContext(context);
    const saved = JSON.parse(await readFile(join(dir, "context.json"), "utf8"));
    assert.equal(context.registration_request_id, saved.registration_request_id);
    assert.equal(context.key_id, saved.key_id);
    activated++;
  },
  async discard() { assert.fail("a remotely attempted candidate must never be discarded"); },
};
const admission = { async authorize(context) {
  assert.deepEqual(context.target, target);
  assert.ok(["provision", "registration-result"].includes(context.action));
  return { credential: process.env.IDP_A04B_ADMISSION, registration_scope: scope, expires_at_unix_secs: Number(process.env.IDP_A04B_EXPIRES) };
} };
const transport = async (url, init) => {
  assert.equal(init.credentials, "omit");
  assert.equal(init.redirect, "error");
  assert.equal(init.cache, "no-store");
  const path = new URL(url).pathname;
  const record = await store.load(target);
  if (path.endsWith("/devices/provision")) {
    assert.equal(record.phase, "provision-unknown", "persist before sending provision");
    writes.push(JSON.parse(init.body));
  }
  if (path.endsWith("/devices/complete")) {
    assert.equal(record.phase, "complete-unknown", "persist before sending complete");
    writes.push(JSON.parse(init.body));
  }
  const response = await fetch(url, init);
  if (path.endsWith("/devices/provision") && !lostProvision) {
    assert.equal(response.status, 201);
    lostProvision = true;
    throw new Error("synthetic lost successful provision response");
  }
  if (path.endsWith("/devices/complete") && !lostComplete) {
    assert.equal(response.status, 200);
    lostComplete = true;
    throw new Error("synthetic lost successful completion response");
  }
  return response;
};
const client = () => new DeviceRegistrationClient({ target, signer, admission, store, transport });
try {
  let current = client();
  await current.prepare("A04-B real signature fixture");
  const original = await store.load(target);
  await assert.rejects(current.provision());
  assert.equal((await store.load(target)).phase, "provision-unknown");
  current.dispose();
  current = client();
  await current.load();
  scope = "enrollment.other-grant";
  await assert.rejects(current.recover(), "changed admission scope must not recover");
  scope = "enrollment.scan-grant-one";
  await current.recover();
  assert.equal(current.getSnapshot().phase, "pending");
  assert.equal(activated, 0);
  await assert.rejects(current.complete());
  assert.equal((await store.load(target)).phase, "complete-unknown");
  current.dispose();
  current = client();
  await current.load();
  await current.recover();
  assert.equal(current.getSnapshot().phase, "active");
  assert.equal(activated, 1);
  const final = await store.load(target);
  assert.equal(final.registration_request_id, original.registration_request_id);
  assert.equal(final.handle, original.handle);
  assert.equal(final.key_id, original.key_id);
  assert.equal(writes.length, 2, "recovery must not repeat either committed write");
  assert.equal(prepared, 1);
  const snapshot = JSON.stringify(current.getSnapshot());
  assert.ok(!snapshot.includes("test-candidate-one"));
  assert.ok(!snapshot.includes(process.env.IDP_A04B_ADMISSION));
  assert.ok(!snapshot.includes("public_jwk"));
  current.dispose();
  console.log("A04-B real Ed25519 provision + completion loss, disk journal and new-instance recovery passed");
} finally { await rm(dir, { recursive: true, force: true }); }
