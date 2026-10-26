import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { ManagementClient, PermissionDirectory } from "../../../web/embedded/admin";
import { EmbeddedAuth, EmbeddedIdentityClient, IdentityError, type IdentitySnapshot } from "../../../web/embedded";
import "../../../web/embedded/admin.css";
import "../../../web/embedded/dist/embedded-idp.css";
import "./styles.css";

type Entry = "fixed" | "choose";
type Report = { tenant_id: string; report_id: string; title: string; body: string };
type ReportPage = { items: Report[]; has_more: boolean; next_cursor: string | null };
type ExampleConfig = { management_enabled: boolean; business_id: "reports" };
const entries: Record<Entry, { label: string; client: EmbeddedIdentityClient }> = {
  fixed: { label: "固定租户入口", client: new EmbeddedIdentityClient("/fixed", undefined, { mode: "cookie" }) },
  choose: { label: "选择租户入口", client: new EmbeddedIdentityClient("/choose", undefined, { mode: "cookie" }) },
};
const management = new ManagementClient("/control", { mode: "cookie" });
const errorText = (error: unknown) => error instanceof IdentityError ? error.message : "请求未完成，请重试。";
const sessionKey = (state: IdentitySnapshot) => state.session ? JSON.stringify([state.session.tenant_id, state.session.account_id, state.session.session_id, state.session.client_id]) : "";

function readReport(value: unknown, tenant: string, id: string): Report {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_report");
  const r = value as Record<string, unknown>;
  if (r.tenant_id !== tenant || r.report_id !== id || typeof r.title !== "string" || typeof r.body !== "string") throw new Error("invalid_report");
  return { tenant_id: r.tenant_id, report_id: r.report_id, title: r.title, body: r.body };
}
function readPage(value: unknown, tenant: string): ReportPage {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_page");
  const p = value as Record<string, unknown>;
  if (!Array.isArray(p.items) || typeof p.has_more !== "boolean" || !(p.next_cursor === null || typeof p.next_cursor === "string") || p.has_more !== (p.next_cursor !== null)) throw new Error("invalid_page");
  return { items: p.items.map(item => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("invalid_page");
    const r = item as Record<string, unknown>;
    if (r.tenant_id !== tenant || typeof r.report_id !== "string" || typeof r.title !== "string" || typeof r.body !== "string") throw new Error("invalid_page");
    return { tenant_id: r.tenant_id, report_id: r.report_id, title: r.title, body: r.body };
  }), has_more: p.has_more, next_cursor: p.next_cursor as string | null };
}

function ManagementSurface() {
  const state = useSyncExternalStore(management.subscribe, management.getSnapshot, management.getSnapshot);
  const [config, setConfig] = useState<ExampleConfig>();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tenant, setTenant] = useState("tenant-a");
  const [targetChosen, setTargetChosen] = useState(false);
  const [tenants, setTenants] = useState<{ tenant_id: string; name: string; status: string }[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const restoreAttempted = useRef(false);
  useEffect(() => {
    let live = true;
    void fetch("/example-config", { cache: "no-store", credentials: "omit" }).then(async response => {
      if (!response.ok) throw new Error("示例配置暂不可用。");
      const value = await response.json() as ExampleConfig;
      if (value.business_id !== "reports" || typeof value.management_enabled !== "boolean") throw new Error("示例配置无效。");
      if (live) setConfig(value);
    }).catch(reason => { if (live) setError(errorText(reason)); });
    void management.loadCapabilities().then(async () => {
      if (management.supportsRestore() && !restoreAttempted.current) {
        restoreAttempted.current = true;
        await management.restore();
      }
    }).catch(reason => { if (live && !(reason instanceof Error && "status" in reason && reason.status === 401)) setError(errorText(reason)); });
    return () => { live = false; };
  }, []);
  useEffect(() => {
    setTargetChosen(false);
    setTenants([]);
    if (!state.session || state.selecting) return;
    setTenants(["tenant-a", "tenant-b"].map(tenant_id => ({tenant_id, name: tenant_id, status: "active"})));
  }, [state.session?.session_id, state.selecting]);
  async function run(operation: () => Promise<void>) {
    setBusy(true); setError("");
    try { await operation(); } catch (reason) { setError(errorText(reason)); }
    finally { setBusy(false); }
  }
  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await run(() => management.login(email.trim(), password));
    setPassword("");
  }
  if (!config?.management_enabled) return <section className="th-card"><h2>独立管理组件</h2><p>{config ? "此示例未启用管理目录。" : error || "正在读取管理配置…"}</p><a href="/">返回业务入口</a></section>;
  return <main className="th-main">
    <header className="th-header"><div><p>示例管理入口</p><h1>权限目录</h1></div><a href="/">返回业务工作台</a></header>
    {error && <p role="alert" className="th-alert">{error}</p>}
    {!state.capabilities ? <section className="th-card"><h2>连接管理服务</h2><button disabled={busy} onClick={() => void run(() => management.loadCapabilities())}>重试</button></section>
      : state.session && !targetChosen ? <section className="th-card"><h2>选择管理目标租户</h2><p>这是与业务会话分开的平台管理身份；请选择权限目录目标。</p><label htmlFor="management-tenant">目标租户</label><select id="management-tenant" value={tenant} onChange={event => setTenant(event.target.value)}>{tenants.map(item => <option value={item.tenant_id} key={item.tenant_id}>{item.name} ({item.tenant_id})</option>)}</select><button disabled={busy || !tenants.some(item => item.tenant_id === tenant && item.status === "active")} onClick={() => setTargetChosen(true)}>打开权限目录</button><button className="th-secondary" disabled={busy} onClick={() => void run(() => management.logout())}>退出管理</button></section>
      : state.session ? <><section className="th-card"><h2>独立管理身份</h2><p>管理身份固定在平台域 0，当前权限目录目标为租户 {tenant}；目录 API 使用单独的 Management Bearer。</p><div className="th-actions"><button onClick={() => setTargetChosen(false)}>更换目标租户</button><button className="th-secondary" disabled={busy} onClick={() => void run(() => management.logout())}>退出管理</button></div></section><PermissionDirectory client={management} tenant={tenant} business="reports" /></>
      : <section className="th-card"><h2>管理登录</h2><p>管理 Cookie 仅用于会话恢复；目录 API 以单独的管理 Bearer 认证。</p><form className="th-form" onSubmit={event => void login(event)}><label htmlFor="admin-email">邮箱</label><input id="admin-email" autoComplete="username" type="email" required maxLength={320} value={email} onChange={event => setEmail(event.target.value)} /><label htmlFor="admin-password">密码</label><input id="admin-password" autoComplete="current-password" type="password" required maxLength={4096} value={password} onChange={event => setPassword(event.target.value)} /><button disabled={busy}>{busy ? "处理中…" : "登录"}</button></form></section>}
  </main>;
}

function BusinessSurface() {
  const [entry, setEntry] = useState<Entry>(location.pathname.startsWith("/choose") ? "choose" : "fixed");
  const identity = entries[entry].client;
  const state = useSyncExternalStore(identity.subscribe, identity.getSnapshot, identity.getSnapshot);
  const [config, setConfig] = useState<ExampleConfig>();
  const [reportId, setReportId] = useState("r001");
  const [prefix, setPrefix] = useState("");
  const [details, setDetails] = useState<{ key: string; report?: Report; message?: string }>();
  const [page, setPage] = useState<{ key: string; value: ReportPage }>();
  const [cursor, setCursor] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [listBusy, setListBusy] = useState(false);
  const [error, setError] = useState("");
  const [draft, setDraft] = useState("");
  const draftDirty = useRef(false);
  const requestGeneration = useRef(0);
  const scopeRef = useRef("");
  const activeSession = !state.selecting ? sessionKey(state) : "";
  const scope = `${entry}/${activeSession}/${state.selecting ? "selecting" : "ready"}`;
  scopeRef.current = scope;
  useEffect(() => {
    let previous = `${sessionKey(identity.getSnapshot())}/${identity.getSnapshot().selecting}`;
    return identity.subscribe(() => {
      const next = `${sessionKey(identity.getSnapshot())}/${identity.getSnapshot().selecting}`;
      if (next !== previous) {
        previous = next; requestGeneration.current++;
        setDetails(undefined); setPage(undefined); setCursor(undefined); setBusy(false); setListBusy(false); setError("");
      }
    });
  }, [identity]);
  useEffect(() => {
    requestGeneration.current++;
    setDetails(undefined); setPage(undefined); setCursor(undefined); setError(""); setBusy(false); setListBusy(false);
  }, [scope]);
  useEffect(() => {
    let live = true;
    void fetch("/example-config", { cache: "no-store", credentials: "omit" }).then(response => response.json() as Promise<ExampleConfig>).then(value => { if (live) setConfig(value); }).catch(() => { if (live) setError("无法读取示例配置。"); });
    return () => { live = false; };
  }, []);
  function confirmDraft(): boolean {
    if (!draftDirty.current) return true;
    if (!window.confirm("这份示例草稿只在当前页面内存中。切换租户或退出会放弃草稿，是否继续？")) return false;
    draftDirty.current = false; setDraft("");
    return true;
  }
  function changeEntry(next: Entry) {
    if (next === entry || !confirmDraft()) return;
    if (state.selecting) identity.cancelSelection();
    requestGeneration.current++;
    setEntry(next); setDetails(undefined); setPage(undefined); setCursor(undefined); setError("");
    history.replaceState(history.state, "", next === "fixed" ? "/fixed" : "/choose");
  }
  async function request(path: string, kind: "detail" | "list", expectedReportId?: string) {
    if (!state.session || state.selecting) return;
    const key = scope;
    const generation = ++requestGeneration.current;
    const valid = () => generation === requestGeneration.current && scopeRef.current === key && !identity.getSnapshot().selecting && sessionKey(identity.getSnapshot()) === activeSession;
    setBusy(kind === "detail"); setListBusy(kind === "list"); if (kind === "detail") setDetails(undefined);
    setError("");
    try {
      const token = await identity.accessToken();
      if (!valid()) return;
      const response = await fetch(`/${entry}${path}`, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store", credentials: "omit" });
      if (!valid()) return;
      if (response.status === 403) throw new IdentityError("当前用户没有读取这些报告的权限。");
      if (response.status === 404 && kind === "detail") throw new IdentityError("授权后没有找到此报告。");
      if (response.status === 401) throw new IdentityError("会话已失效，请重新登录。");
      if (!response.ok) throw new IdentityError("报告服务暂时不可用。");
      const value: unknown = await response.json();
      if (!valid()) return;
      if (kind === "detail") setDetails({ key, report: readReport(value, state.session.tenant_id, expectedReportId ?? "") });
      else setPage({ key, value: readPage(value, state.session.tenant_id) });
    } catch (reason) { if (valid()) { if (kind === "detail") setDetails({ key, message: errorText(reason) }); else setError(errorText(reason)); } }
    finally { if (valid()) { if (kind === "detail") setBusy(false); else setListBusy(false); } }
  }
  function submitDetail(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const id = reportId.trim();
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(id)) { setDetails({ key: scope, message: "报告 ID 格式无效。" }); return; }
    void request(`/api/reports/${encodeURIComponent(id)}`, "detail", id);
  }
  function loadPage(next?: string) {
    const q = new URLSearchParams({ limit: "10", ...(prefix ? { prefix } : {}), ...(next ? { cursor: next } : {}) });
    setCursor(next);
    void request(`/api/reports?${q}`, "list");
  }
  const beforeSessionChange = async () => confirmDraft();
  const showPanel = !!state.session && !state.selecting;
  const visibleDetails = details?.key === scope ? details : undefined;
  const visiblePage = page?.key === scope ? page.value : undefined;
  return <main className="th-main">
    <header className="th-header"><div><p>Enabled 嵌入宿主示例</p><h1>租户报告工作台</h1><span>业务 client 与租户均由固定入口配置、登录结果及服务端会话确定。</span></div>{config?.management_enabled && <a href="/management">独立管理入口</a>}</header>
    <nav className="th-entry" aria-label="登录入口"><button aria-pressed={entry === "fixed"} onClick={() => changeEntry("fixed")}>固定租户入口</button><button aria-pressed={entry === "choose"} onClick={() => changeEntry("choose")}>选择租户入口</button></nav>
    {error && <p role="alert" className="th-alert">{error}</p>}
    <div className="th-grid"><section><EmbeddedAuth client={identity} businessId="reports" beforeSessionChange={beforeSessionChange} />{state.selecting && <p className="th-note">进入租户前会从服务端确认成员关系；草稿确认已由登录组件处理。</p>}</section>
      {showPanel && <section className="th-card" data-testid="report-panel"><h2>报告业务界面</h2><p>租户 <strong>{state.session!.tenant_id}</strong> · 业务授权标识 <code>report::read</code></p>
        <label htmlFor="example-draft">本地未保存草稿</label><textarea id="example-draft" rows={3} value={draft} onChange={event => { draftDirty.current = event.target.value.length > 0; setDraft(event.target.value); }} placeholder="此输入不会提交到业务 API" />
        <form className="th-form" onSubmit={submitDetail}><label htmlFor="report-id">报告 ID</label><input id="report-id" value={reportId} maxLength={128} onChange={event => setReportId(event.target.value)} /><button disabled={busy}>{busy ? "正在读取…" : "读取单份报告"}</button></form>
        {visibleDetails?.message && <p role="status" className="th-alert">{visibleDetails.message}</p>}{visibleDetails?.report && <article><small>{visibleDetails.report.tenant_id} / {visibleDetails.report.report_id}</small><h3>{visibleDetails.report.title}</h3><p>{visibleDetails.report.body}</p></article>}
        <div className="th-form"><label htmlFor="report-prefix">列表 ID 前缀筛选</label><input id="report-prefix" value={prefix} maxLength={128} onChange={event => { setPrefix(event.target.value); setPage(undefined); setCursor(undefined); requestGeneration.current++; setBusy(false); setListBusy(false); }} /><button disabled={listBusy} onClick={() => loadPage()}>{listBusy ? "正在读取列表…" : "读取已授权报告列表"}</button></div>
        {error && <p role="status" className="th-alert">{error}</p>}{visiblePage && <><ul className="th-report-list">{visiblePage.items.map(item => <li key={item.report_id}><strong>{item.title}</strong><span>{item.tenant_id} / {item.report_id}</span></li>)}</ul><div className="th-actions"><button className="th-secondary" disabled={!cursor || listBusy} onClick={() => loadPage()}>返回首页</button><button disabled={!visiblePage.has_more || listBusy || !visiblePage.next_cursor} onClick={() => loadPage(visiblePage.next_cursor ?? undefined)}>继续读取</button></div><p className="th-note">列表不显示总数；空页也可能有下一页，请继续读取。</p></>}</section>}
    </div>
    <footer className="th-note">Fixed 与 Choose 使用不同 client 和 Cookie Path。Cookie 多标签页采用共享会话协调，不能让同一入口的不同标签保持不同租户。</footer>
  </main>;
}

function App() { return location.pathname === "/management" ? <ManagementSurface /> : <BusinessSurface />; }

createRoot(document.getElementById("root")!).render(<App />);
