// Local interaction fixture only. The generated key, journal and admission are synthetic and in-memory.
import { createRoot } from "react-dom/client";
import React from "react";
import { DeviceRegistrationClient, type DeviceRegistrationAdmission, type DeviceRegistrationRecord,
  type DeviceRegistrationSigner, type DeviceRegistrationStore, type DeviceRegistrationTarget } from "./device-registration-client";
import { DeviceRegistration } from "./device-registration";

const target: DeviceRegistrationTarget = { baseUrl: "/fixture", tenant_id: "0", client_id: "registration-fixture", entry_id: "local-demo",
  device_id: "11111111-1111-4111-8111-111111111111" };
let record: DeviceRegistrationRecord | undefined;
let remote: Record<string, unknown> | undefined;
let loseProvision = false, loseComplete = false, delayNextResult = false;
let releaseResult!: () => void;
const handles = new Map<string, CryptoKey>();
const gate = new Map<string, Promise<void>>();
const store: DeviceRegistrationStore = {
  async withLock(scope, operation) {
    const key = `${scope.entry_id}|${scope.tenant_id}|${scope.client_id}|${scope.device_id}`;
    const previous = gate.get(key) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>(resolve => { release = resolve; });
    gate.set(key, previous.then(() => current));
    await previous;
    try { return await operation(); } finally { release(); }
  },
  async load() { return record ? structuredClone(record) : undefined; },
  async save(value) { record = structuredClone(value); },
};

function base64url(value: ArrayBuffer | Uint8Array) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function makeSigner(): Promise<DeviceRegistrationSigner> {
  let publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string };
  let key_id: string;
  const pub = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const exported = await crypto.subtle.exportKey("jwk", pub.publicKey);
  publicJwk = { kty: "OKP", crv: "Ed25519", x: exported.x! };
  const thumbprint = new TextEncoder().encode(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: publicJwk.x }));
  key_id = base64url(await crypto.subtle.digest("SHA-256", thumbprint));
  return {
    async prepare() { const handle = crypto.randomUUID(); handles.set(handle, pub.privateKey); return { handle, public_jwk: publicJwk, key_id }; },
    async signRegistration(input) {
      const bytes = new TextEncoder().encode(`EMBEDDED-IDP-DEVICE-REGISTRATION-V2\ntenant-id:${input.target.tenant_id}\ndevice-id:${input.target.device_id}\nkey-id:${input.key_id}\nchallenge:${input.challenge}\n`);
      const signature = await crypto.subtle.sign({ name: "Ed25519" }, handles.get(input.handle)!, bytes);
      return base64url(signature);
    },
    async activate(input) { if (!handles.has(input.handle)) throw new Error("missing test key"); },
    async discard(input) { handles.delete(input.handle); },
  };
}
const admission: DeviceRegistrationAdmission = { async authorize() { return { credential: "synthetic-grant", registration_scope: "fixture-grant", expires_at_unix_secs: Math.floor(Date.now() / 1000) + 3600 }; } };
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const registration = (status: "pending" | "active") => ({ tenant_id: target.tenant_id, client_id: target.client_id, device_id: target.device_id,
  proof_key_id: status === "active" ? record?.key_id : null, status, version: status === "active" ? 2 : 1, key_version: status === "active" ? 1 : null,
  expected_key_id: record?.key_id, created_at_unix_secs: Math.floor(Date.now() / 1000) - 1, expires_at_unix_secs: Math.floor(Date.now() / 1000) + 3600,
  completed_at_unix_secs: status === "active" ? Math.floor(Date.now() / 1000) : null });
const transport = async (url: string, init: RequestInit) => {
  const path = new URL(url, location.origin).pathname;
  const body = init.body ? JSON.parse(String(init.body)) : {};
  if (path === "/fixture/devices/provision") {
    remote = registration("pending");
    if (loseProvision) { loseProvision = false; throw new Error("Synthetic lost response after remote write"); }
    return json(remote, 201);
  }
  if (path === "/fixture/devices/registration-result") {
    if (delayNextResult) { delayNextResult = false; await new Promise<void>(resolve => { releaseResult = resolve; }); throw new Error("Synthetic delayed read failure"); }
    return remote ? json(remote) : json({}, 404);
  }
  if (path === "/fixture/devices/proof/challenges") return json({ challenge: "A".repeat(43), expires_at_unix_secs: Math.floor(Date.now() / 1000) + 300 });
  if (path === "/fixture/devices/complete") {
    remote = registration("active");
    if (loseComplete) { loseComplete = false; throw new Error("Synthetic lost response after remote write"); }
    return json({ tenant_id: target.tenant_id, device_id: target.device_id, key_id: record?.key_id, version: 1 });
  }
  return json({ error: "not found" }, 404);
};

async function createClient() {
  return new DeviceRegistrationClient({ target, signer: await makeSigner(), admission, store, transport });
}
const root = createRoot(document.getElementById("root")!);
function App() {
  const [client, setClient] = React.useState<DeviceRegistrationClient>();
  const [clientGeneration, setClientGeneration] = React.useState(0);
  const initialClient = React.useRef<Promise<DeviceRegistrationClient> | undefined>(undefined);
  const mode = new URLSearchParams(location.search).get("scenario") ?? "provision";
  const attachClient = (value: DeviceRegistrationClient) => { setClient(value); setClientGeneration(generation => generation + 1); };
  React.useEffect(() => {
    if (mode === "missing") return;
    let mounted = true;
    initialClient.current ??= createClient();
    void initialClient.current.then(value => { if (mounted) attachClient(value); });
    return () => { mounted = false; };
  }, []);
  if (mode === "missing") return <main className="fixture"><DeviceRegistration /></main>;
  return <main className="fixture">
    <h1>设备登记交互夹具</h1>
    <p>仅模拟流程。密钥、准入和恢复记录都在当前页面内存中，不代表真实持钥或持久化安全。</p>
    <output data-testid="client-generation" aria-label="客户端代次">{clientGeneration}</output>
    <div className="controls">
      <button onClick={() => { if (mode === "provision") loseProvision = true; else loseComplete = true; }}>模拟丢失{mode === "provision" ? "登记提交" : "完成登记"}响应</button>
      {mode === "provision" && <button onClick={() => { delayNextResult = true; }}>延迟下一次查询并返回错误</button>}
      {mode === "provision" && <button onClick={() => releaseResult?.()}>释放迟到错误</button>}
      <button onClick={() => { client?.dispose(); void createClient().then(attachClient); }}>重建客户端并恢复</button>
    </div>
    <DeviceRegistration client={client} />
  </main>;
}
root.render(<React.StrictMode><App /></React.StrictMode>);
