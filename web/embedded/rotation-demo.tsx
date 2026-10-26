// Local interaction fixture only. It uses generated in-memory keys, a synthetic session and an in-memory journal.
import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { EmbeddedIdentityClient } from "./client";
import { EmbeddedDeviceClient } from "./device-client";
import { DeviceKeyRotationClient, type DeviceKeyRotationRecord, type DeviceKeyRotationSigner, type DeviceKeyRotationStore, type DeviceKeyRotationTarget } from "./device-key-rotation-client";
import { DeviceKeyRotation } from "./device-key-rotation";

const target: DeviceKeyRotationTarget = { baseUrl: "/fixture", tenant_id: "0", client_id: "rotation-fixture", entry_id: "local-demo",
  device_id: "11111111-1111-4111-8111-111111111111" };
const binding_id = "22222222-2222-4222-8222-222222222222";
const binding_version = 1;
const handles = new Map<string, CryptoKey>();
const keys = new Map<string, CryptoKey>();
let oldPublicKey: CryptoKey;
let currentKeyId = "";
let currentKeyVersion = 1;
let activePrivate: CryptoKey;
let activeHandle = "fixture-old-handle";
let deviceVersion = 2;
let loseRotateResponse = false;
let rotateWrites = 0;
function fixtureMetric(id: string, value: unknown) { const el = document.querySelector(`[data-testid="${id}"]`); if (el) el.textContent = String(value); }
const enc = (value: ArrayBuffer | Uint8Array) => {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
async function keyId(publicKey: JsonWebKey) {
  const canonical = JSON.stringify({ crv: "Ed25519", kty: "OKP", x: publicKey.x });
  return enc(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical)));
}
const decode = (value: string) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const device = () => ({ tenant_id: "0", device_id: target.device_id, client_id: target.client_id, proof_key_id: currentKeyId,
  status: "active", version: deviceVersion, key_version: currentKeyVersion, binding_id, binding_version, device_name: "Fixture device",
  registered_at_unix_secs: 1, last_seen_at_unix_secs: null, binding_status: "active" });
const metadata = (id: string) => ({ tenant_id: "0", device_id: target.device_id, key_id: id, algorithm: "ed25519",
  version: id === currentKeyId ? currentKeyVersion : 1, status: id === currentKeyId ? "active" : "retired",
  registered_at_unix_secs: 1, retired_at_unix_secs: id === currentKeyId ? null : Math.floor(Date.now() / 1000) });
let oldPrivate: CryptoKey, oldPublic: JsonWebKey;
const storeRows = new Map<string, unknown>();
const locks = new Map<string, Promise<void>>();
let failNextLoad = new URLSearchParams(location.search).get("fail-load-once") === "1";
const store: DeviceKeyRotationStore = {
  async withLock(scope, operation) {
    const key = JSON.stringify([scope.baseUrl, scope.tenant_id, scope.client_id, scope.entry_id, scope.device_id]);
    const previous = locks.get(key) ?? Promise.resolve(); let release!: () => void;
    const current = new Promise<void>(resolve => { release = resolve; }); locks.set(key, previous.then(() => current));
    await previous; try { return await operation(); } finally { release(); }
  },
  async load(scope) { if (failNextLoad) { failNextLoad = false; throw Error("temporary fixture storage read failure"); } return structuredClone(storeRows.get(JSON.stringify([scope.baseUrl, scope.tenant_id, scope.client_id, scope.entry_id, scope.device_id]))) as DeviceKeyRotationRecord | undefined; },
  async save(record) { storeRows.set(JSON.stringify([record.target.baseUrl, record.target.tenant_id, record.target.client_id, record.target.entry_id, record.target.device_id]), structuredClone(record)); },
};
const signer: DeviceKeyRotationSigner = {
  async prepare() {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const public_jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const key_id = await keyId(public_jwk); const handle = crypto.randomUUID();
    handles.set(handle, pair.privateKey); keys.set(key_id, pair.publicKey);
    return { current_handle: activeHandle, handle, public_jwk: { kty: "OKP", crv: "Ed25519", x: public_jwk.x! }, key_id };
  },
  async signRotation(input) {
    const bytes = new TextEncoder().encode(`EMBEDDED-IDP-DEVICE-KEY-ROTATION-V2\ntenant-id:${input.target.tenant_id}\ndevice-id:${input.target.device_id}\nold-key-id:${input.expected_key_id}\nnew-key-id:${input.key_id}\nnew-key-version:${input.new_key_version}\nchallenge:${input.challenge}\n`);
    const currentSignature = await crypto.subtle.sign({ name: "Ed25519" }, activePrivate, bytes);
    const nextSignature = await crypto.subtle.sign({ name: "Ed25519" }, handles.get(input.handle)!, bytes);
    return { current_key_signature: enc(currentSignature), proposed_key_signature: enc(nextSignature) };
  },
  async activate(input) { const key = handles.get(input.handle); if (!key) throw Error("missing candidate"); activePrivate = key; activeHandle = input.handle; },
  async discard(input) { handles.delete(input.handle); keys.delete(input.key_id); },
};
let nonce = 0;
const transport = async (url: string, init: RequestInit) => {
  const path = new URL(url, location.origin).pathname;
  if (path === "/fixture/auth/access/capabilities") return json({ tenancy_enabled: false, login_tenant_policy: "fixed", fixed_tenant_id: "0" });
  if (path === "/fixture/auth/login") return json({ status: "authenticated", session: { tenant_id: "0", account_id: "fixture-owner", session_id: "fixture-session", client_id: target.client_id },
    tokens: { access_token: "fixture-token", refresh_token: "fixture-refresh", access_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 3600,
      refresh_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 7200 } });
  if (path === `/fixture/devices/${target.device_id}`) return json(device());
  const metadataMatch = path.match(new RegExp(`^/fixture/devices/${target.device_id}/keys/([A-Za-z0-9_-]{43})$`));
  if (metadataMatch) return json(metadata(metadataMatch[1]));
  if (path === "/fixture/devices/proof/challenges") {
    const challenge = enc(crypto.getRandomValues(new Uint8Array(32)));
    return json({ challenge, expires_at_unix_secs: Math.floor(Date.now() / 1000) + 300 });
  }
  if (path === "/fixture/devices/rotate-key") {
    const body = JSON.parse(String(init.body)); rotateWrites++; fixtureMetric("rotate-writes", rotateWrites); fixtureMetric("rotation-outcome", "checking");
    const bytes = new TextEncoder().encode(`EMBEDDED-IDP-DEVICE-KEY-ROTATION-V2\ntenant-id:${target.tenant_id}\ndevice-id:${body.device_id}\nold-key-id:${body.expected_key_id}\nnew-key-id:${body.proposed_public_jwk.kid}\nnew-key-version:${body.expected_key_version + 1}\nchallenge:${body.challenge}\n`);
    const newPublic = keys.get(body.proposed_public_jwk.kid)!;
    if (body.expected_key_version !== currentKeyVersion || body.expected_key_id !== currentKeyId) { fixtureMetric("rotation-outcome", "stale-key"); return json({ error: "stale key" }, 409); }
    if (!(await crypto.subtle.verify({ name: "Ed25519" }, oldPublicKey, decode(body.current_key_signature), bytes)) ||
        !(await crypto.subtle.verify({ name: "Ed25519" }, newPublic, decode(body.proposed_key_signature), bytes))) { fixtureMetric("rotation-outcome", "bad-signature"); return json({ error: "invalid proof" }, 400); }
    currentKeyId = body.proposed_public_jwk.kid; currentKeyVersion++; deviceVersion++; fixtureMetric("remote-current-key-version", currentKeyVersion); fixtureMetric("rotation-outcome", "committed");
    if (loseRotateResponse) { loseRotateResponse = false; throw new Error("Synthetic lost response after rotation"); }
    return json({ tenant_id: "0", device_id: target.device_id, key_id: currentKeyId, version: currentKeyVersion });
  }
  return json({ error: "not found" }, 404);
};
async function createClient() {
  const identity = new EmbeddedIdentityClient("/fixture", transport);
  await identity.loadCapabilities(); await identity.login("fixture@example.test", "fixture-password");
  const devices = new EmbeddedDeviceClient(identity);
  return new DeviceKeyRotationClient({ devices, target, signer, store });
}
const root = createRoot(document.getElementById("root")!);
function App() {
  const [client, setClient] = useState<DeviceKeyRotationClient>();
  const [generation, setGeneration] = useState(0);
  const missing = new URLSearchParams(location.search).get("missing") === "1";
  const creating = useRef<Promise<DeviceKeyRotationClient> | null>(null);
  useEffect(() => {
    if (missing) return;
    if (!creating.current) creating.current = createClient();
    void creating.current.then(value => { setClient(value); setGeneration(1); });
  }, [missing]);
  if (missing) return <main className="fixture"><DeviceKeyRotation /></main>;
  if (!client) return <p>正在创建合成登录与测试密钥…</p>;
  return <main className="fixture">
    <h1>密钥轮换交互夹具</h1>
    <p>仅浏览器交互模拟。测试私钥、会话与恢复记录都在页面内存中；真实双签另由隔离 Rust 测试验证。</p>
    <div className="controls">
      <span className="testMetric" aria-hidden="true" data-testid="remote-current-key-version">{currentKeyVersion}</span><span className="testMetric" aria-hidden="true" data-testid="rotate-writes">0</span><span className="testMetric" aria-hidden="true" data-testid="rotation-outcome">waiting</span>
      <span className="testMetric" aria-hidden="true" data-testid="generation" data-generation={generation}>{generation}</span>
      <button onClick={() => { loseRotateResponse = true; }}>模拟丢失轮换响应</button>
      <button onClick={() => { client.dispose(); void createClient().then(value => { setClient(value); setGeneration(v => v + 1); }); }}>重建同一身份并恢复</button>
      <button onClick={() => { client.dispose(); void createClientForAnotherOwner().then(value => { setClient(value); setGeneration(v => v + 1); }); }}>切换身份</button>
    </div>
    <DeviceKeyRotation client={client} />
  </main>;
}
async function createClientForAnotherOwner() {
  const identity = new EmbeddedIdentityClient("/fixture", async (url, init) => {
    const response = await transport(url, init); if (url.endsWith("/auth/login")) {
      const body = await response.json() as Record<string, unknown>; (body as any).session = { ...(body as any).session, account_id: "other-owner", session_id: "other-session" };
      return json(body);
    } return response;
  });
  await identity.loadCapabilities(); await identity.login("other@example.test", "fixture-password");
  return new DeviceKeyRotationClient({ devices: new EmbeddedDeviceClient(identity), target, signer, store });
}
const initial = crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]).then(async pair => {
  oldPrivate = pair.privateKey; activePrivate = pair.privateKey; oldPublicKey = pair.publicKey; oldPublic = await crypto.subtle.exportKey("jwk", pair.publicKey); currentKeyId = await keyId(oldPublic);
  keys.set(currentKeyId, oldPublicKey); handles.set("fixture-old-handle", oldPrivate);
});
void initial.then(() => root.render(<React.StrictMode><App /></React.StrictMode>));
