// Opt-in reference-host check. Only synthetic isolated fixtures supplied by Rust tests.
import assert from "node:assert/strict";
import { EmbeddedIdentityClient, EmbeddedDeviceClient } from "./dist/embedded-idp.js";
const base = process.env.IDP_A04_BASE;
assert.ok(base?.startsWith("http://127.0.0.1:"), "explicit local fixture required");
let loseResponse = true, writes = 0;
const identity = new EmbeddedIdentityClient(base, async (url, init) => {
  const response = await fetch(url, init);
  if (url.endsWith("/devices/unbind") && init.method === "POST") {
    writes++;
    assert.equal(response.status, 200, "real unbind must commit before simulated response loss");
    if (loseResponse) { loseResponse = false; await response.arrayBuffer(); throw new Error("synthetic lost response"); }
  }
  return response;
});
await identity.loadCapabilities();
await identity.login("admin@example.test", "Runtime-Admin123");
const client = new EmbeddedDeviceClient(identity);
const page = await client.list();
assert.equal(page.items.length, 1);
const device = await client.detail(page.items[0].device_id);
assert.equal(device.client_id, "scan-one");
assert.equal(device.binding_status, "active");
const key = await client.keyMetadata(device.device_id, device.proof_key_id);
assert.equal(key.status, "active");
const intent = client.prepareUnbind(device);
await assert.rejects(client.unbind(intent));
assert.equal(writes, 1);
const receipt = await client.operationResult(intent);
assert.equal(receipt.operation_id, intent.operation_id);
assert.equal(receipt.binding_id, device.binding_id);
assert.equal(receipt.result_status, "unbound");
assert.equal(receipt.result_version, device.binding_version + 1);
assert.deepEqual(await client.operationResult(intent), receipt);
assert.equal(writes, 1, "receipt recovery must not submit another write");
await identity.logout();
await identity.login("admin@example.test", "Runtime-Admin123");
assert.deepEqual(await client.operationResult(intent), receipt, "same owner can recover after reauthentication");
await identity.logout();
console.log("A04-A real client list/detail/key/unbind/lost-response/receipt/reauthentication passed");
