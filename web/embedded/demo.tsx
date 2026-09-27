import { createRoot } from "react-dom/client";
import type { CSSProperties } from "react";
import { EmbeddedAuth, EmbeddedIdentityClient } from "./index";

const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { "Content-Type": "application/json" } });
function example(tenantMode: boolean) {
  const identity = (tenant: string) => ({ tenant_id: tenant, account_id: tenantMode ? "member-1" : "local-1", session_id: `session-${tenant}`, client_id: "host-app" });
  const authenticated = (tenant: string) => ({ status: "authenticated", session: identity(tenant), tokens: {
    access_token: `example-access-${tenant}`, refresh_token: `example-refresh-${tenant}`,
    access_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 3600,
    refresh_expires_at_unix_secs: Math.floor(Date.now() / 1000) + 7200,
  } });
  return new EmbeddedIdentityClient("/api", async (url, init) => {
    const path = new URL(url, location.origin).pathname;
    if (path === "/api/auth/access/capabilities") return json(tenantMode ?
      { tenancy_enabled: true, login_tenant_policy: "choose_after_authentication" } :
      { tenancy_enabled: false, login_tenant_policy: "fixed", fixed_tenant_id: "0" });
    if (path === "/api/auth/login") return json(tenantMode ?
      { status: "tenant_selection_required", selection_ticket: "example-ticket", expires_in: 300 } : authenticated("0"));
    if (path === "/api/auth/tenant-selection/tenants") return json({ tenants: [
      { tenant_id: "team-a", name: "研发团队", status: "active", membership_status: "active" },
      { tenant_id: "team-b", name: "暂停的团队", status: "suspended", membership_status: "active" },
    ], has_more: false });
    if (path === "/api/auth/tenant-selection/complete") return json(authenticated(JSON.parse(String(init.body)).tenant_id));
    if (path === "/api/auth/me/tenant-selection") return json({ status: "tenant_selection_required", selection_ticket: "example-ticket", expires_in: 300 });
    if (path === "/api/auth/me/roles") return json({ items: [{ tenant_id: tenantMode ? "team-a" : "0", business_id: "demo", role_id: "example-reader",
      key: "reader", name: "报告阅读者", status: "active", kind: "business" }], has_more: false, next_cursor: null });
    if (path === "/api/auth/session") return json(identity(tenantMode ? "team-a" : "0"));
    if (path === "/api/auth/logout") return new Response(null, { status: 200 });
    return json({ error: "missing" });
  });
}

const root = document.querySelector("#host-root");
if (!root) throw new Error("missing host root");
createRoot(root).render(<div style={{ maxWidth: 1080, margin: "32px auto", padding: 16, color: "#333", fontFamily: "Georgia, serif" }}>
  <h1>宿主页面</h1>
  <p>这一段沿用宿主自己的字体和样式。下方两份组件使用独立状态和主题。</p>
  <div style={{ display: "flex", flexWrap: "wrap", gap: 20, alignItems: "flex-start" }}>
    <EmbeddedAuth client={example(false)} businessId="demo" style={{ flex: "1 1 300px", "--embedded-idp-primary": "#2257bb" } as CSSProperties} />
    <EmbeddedAuth client={example(true)} businessId="demo" language="en-US" style={{ flex: "1 1 300px", "--embedded-idp-primary": "#385542" } as CSSProperties} />
  </div>
</div>);
