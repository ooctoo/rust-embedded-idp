// Local UI fixture only. Synthetic credentials and responses are not a real device enrollment.
import { createRoot } from "react-dom/client";
import { DeviceSelfService, EmbeddedDeviceClient, EmbeddedIdentityClient } from "./index";
const device = { tenant_id: "0", client_id: "fixture", device_id: "11111111-1111-4111-8111-111111111111", proof_key_id: "A".repeat(43),
  status: "active", version: 2, key_version: 1, binding_id: "22222222-2222-4222-8222-222222222222", binding_version: 1,
  device_name: "我的测试终端", registered_at_unix_secs: 1700000000, last_seen_at_unix_secs: null, binding_status: "active" };
if (new URLSearchParams(location.search).has("disabled")) device.status = "disabled";
let owner = "alice", lost = true, receipt: unknown;
let delayNextList = false, releaseList: (() => void) | undefined;
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
const identity = new EmbeddedIdentityClient("/fixture", async (url, init) => {
  const path = new URL(url, location.origin).pathname.slice("/fixture".length);
  if (path === "/auth/access/capabilities") return json({ tenancy_enabled: false, login_tenant_policy: "fixed", fixed_tenant_id: "0" });
  if (path === "/auth/login") return json({ status: "authenticated", session: { tenant_id: "0", account_id: owner, client_id: "fixture", session_id: crypto.randomUUID() },
    tokens: { access_token: "synthetic-access", refresh_token: "synthetic-refresh", access_expires_at_unix_secs: Math.floor(Date.now()/1000)+3600, refresh_expires_at_unix_secs: Math.floor(Date.now()/1000)+7200 } });
  if (path === "/auth/logout") return new Response(null, { status: 200 });
  if (path === "/devices") {
    const result = json({ items: owner === "alice" && device.binding_status !== "unbound" ? [device] : [], has_more: false, next_cursor: null });
    if (delayNextList) { delayNextList = false; await new Promise<void>(resolve => { releaseList = resolve; }); }
    return result;
  }
  if (path.includes("/keys/")) return json({ tenant_id:"0",device_id:device.device_id,key_id:device.proof_key_id,version:1,algorithm:"ed25519",status:"active",registered_at_unix_secs:1700000000,retired_at_unix_secs:null });
  if (path === `/devices/${device.device_id}`) return json(device);
  if (path === "/devices/unbind") {
    const body = JSON.parse(String(init.body)); device.binding_status = "unbound";
    receipt = { operation_id: body.operation_id, audit_id:"33333333-3333-4333-8333-333333333333", device_id:device.device_id,binding_id:device.binding_id,
      operation:"device.binding.unbind.self",occurred_at_unix_secs:1700000001,result_version:2,result_status:"unbound" };
    if (lost) { lost = false; throw new Error("Synthetic lost response after commit"); }
    return json(receipt);
  }
  if (path.startsWith("/devices/operations/")) return json(receipt, receipt ? 200 : 404);
  return json({}, 404);
});
const client = new EmbeddedDeviceClient(identity);
await identity.loadCapabilities();
await identity.login("fixture@example.test", "synthetic-password");
createRoot(document.getElementById("root")!).render(<main style={{maxWidth:900,margin:"24px auto",padding:16,fontFamily:"system-ui"}}>
  <h1>设备自助交互夹具</h1><p>模拟响应；第一次解绑提交后故意丢失响应，用于验证原操作回读。不是设备登记或真实宿主证明。</p>
  <button onClick={() => { void identity.logout().then(() => { owner = owner === "alice" ? "bob" : "alice"; return identity.login("fixture@example.test", "synthetic-password"); }); }}>切换测试用户</button>
  <button onClick={() => { delayNextList = true; }}>延迟下一次列表</button>
  <button onClick={() => { releaseList?.(); releaseList = undefined; }}>释放延迟列表</button>
  <DeviceSelfService client={client} />
</main>);
