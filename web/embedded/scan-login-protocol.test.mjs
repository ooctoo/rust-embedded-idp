import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createPublicKey, verify } from "node:crypto";
import test from "node:test";
import ts from "typescript";
const source = await readFile(new URL("./scan-login-protocol.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source.replace(/^import .*;\n/gm, ""), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const { buildDeviceScanProofBytes, validateScanTarget, validScanCode, parseScanProgress, parseScanBundle, scanRequest, scanHashSecret } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);
const target = { baseUrl: "https://idp.example.test/api", tenant_id: "tenant-a", client_id: "workstation-native", entry_id: "terminal-login", device_id: "88888888-8888-4888-8888-888888888888", audience: "example-api", verification_uri: "https://idp.example.test/api/auth/browser/device-scan/ui" };
const fixtures = JSON.parse(await readFile(new URL("../../docs/fixtures/device-scan-login-v1.json", import.meta.url), "utf8"));
test("all ten existing independent SCAN-V2 vectors match bytes and Ed25519 signatures", async () => {
  const key = createPublicKey({ key: fixtures.public_jwk, format: "jwk" });
  for (const vector of fixtures.vectors) {
    const bytes = await buildDeviceScanProofBytes({ target, action: vector.action, purpose: vector.purpose, external_path: vector.path, body: vector.body_utf8, challenge: vector.challenge, signed_at: vector.signed_at, key_id: vector.key_id });
    assert.equal(new TextDecoder().decode(bytes), vector.canonical_utf8, vector.action);
    assert.equal(verify(null, bytes, key, Buffer.from(vector.signature, "base64url")), true);
  }
});
test("codes, fixed verification origin and canonical paths reject cross-flow injection", () => {
  assert.equal(validScanCode(`D1.${"A".repeat(43)}`, "create"), true);
  assert.equal(validScanCode(`P1.${"A".repeat(22)}`, "claim"), true);
  assert.equal(validScanCode(`D1.${"A".repeat(43)}`, "claim"), false);
  assert.equal(validScanCode(`P1.${"A".repeat(21)}B`, "claim"), false);
  for (const patch of [{ verification_uri: "https://other.test/api/auth/browser/device-scan/ui" }, { baseUrl: "https://idp.example.test/a/../api" }, { baseUrl: "/\n/evil.test" }, { baseUrl: "/api%20x" }, { baseUrl: "/api//v1" }, { baseUrl: "/身份" }, { verification_uri: `${target.verification_uri}?token=secret` }]) {
    assert.throws(() => validateScanTarget({ ...target, ...patch }));
  }
});
test("transport signs exact raw bytes and headers, never sends credentials, rejects expired proof", async () => {
  const body = { tenant_id: target.tenant_id, grant_id: "11111111-1111-4111-8111-111111111111", delivery_secret: "A".repeat(43) };
  let signed, calls = 0;
  const signer = { async signRequest(input) { signed = input; return { key_id: "A".repeat(43), signature: "A".repeat(86) }; } };
  const transport = async (url, init) => {
    calls++;
    assert.equal(init.credentials, "omit"); assert.equal(init.redirect, "error"); assert.equal(init.cache, "no-store");
    assert.equal(init.headers.Authorization, undefined);
    if (url.endsWith("/devices/proof/challenges")) return Response.json({ challenge: "A".repeat(43), expires_at_unix_secs: Math.floor(Date.now() / 1000) + 60 });
    assert.equal(signed.body, init.body); assert.equal(init.body, JSON.stringify(body));
    assert.equal(signed.external_path, "/api/auth/device-scan/status");
    assert.equal(init.headers["x-device-id"], target.device_id);
    return Response.json({ ok: true });
  };
  await scanRequest(target, signer, transport, "status", body, () => {});
  assert.equal(calls, 2);
  let signedExpired = false;
  await assert.rejects(scanRequest(target, { async signRequest() { signedExpired = true; } }, async () => Response.json({ challenge: "A".repeat(43), expires_at_unix_secs: 1 }), "status", body, () => {}));
  assert.equal(signedExpired, false);
  await assert.rejects(scanHashSecret("B".repeat(43)));
});

test("progress and bundle schemas reject wrong scope, unknown fields and inconsistent delivery", () => {
  const p = { grant_id: "11111111-1111-4111-8111-111111111111", mode: "device_display", state: "approved", version: 2,
    server_time_unix_secs: 123, expires_at_unix_secs: 456, code_expires_at_unix_secs: 400, approved_until_unix_secs: 450,
    expires_in: 333, poll_after_ms: 1000, delivery_state: null, issuance_operation_id: null, recover_until_unix_secs: null, next_action: "exchange" };
  assert.equal(parseScanProgress(p, target).state, "approved");
  for (const patch of [{ version: 0 }, { version: 1.5 }, { state: "active" }, { mode: "auto_approve" }, { poll_after_ms: -1 }, { unknown: true }, { delivery_state: "acknowledged" }])
    assert.throws(() => parseScanProgress({ ...p, ...patch }, target));
  assert.throws(() => parseScanProgress(p, target, { mode: "phone_display" }));
  assert.throws(() => parseScanProgress(p, target, { grant_id: "22222222-2222-4222-8222-222222222222" }));
  const bundle = { session: { tenant_id: target.tenant_id, account_id: "a", session_id: p.grant_id, client_id: target.client_id, expires_at_unix_secs: 500 },
    tokens: { access_token: "synthetic-a", refresh_token: "synthetic-r", access_expires_at_unix_secs: 400, refresh_expires_at_unix_secs: 500 }, receipt_nonce: "A".repeat(43) };
  assert.deepEqual(parseScanBundle(bundle, target), bundle);
  assert.throws(() => parseScanBundle({ ...bundle, session: { ...bundle.session, client_id: "other" } }, target));
  assert.throws(() => parseScanBundle({ ...bundle, session: { ...bundle.session, tenant_id: "other" } }, target));
  assert.throws(() => parseScanBundle({ ...bundle, receipt_nonce: "B".repeat(43) }, target));
});
