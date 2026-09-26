import { useEffect, useState, useSyncExternalStore, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { EmbeddedAuth, EmbeddedIdentityClient } from "../../../web/embedded";
import "./styles.css";

const identity = new EmbeddedIdentityClient("/", undefined, { mode: "cookie" });
type Report = { tenant_id: string; report_id: string; title: string; body: string };

function App() {
  const state = useSyncExternalStore(identity.subscribe, identity.getSnapshot, identity.getSnapshot);
  const session = state.selecting ? undefined : state.session;
  const sessionKey = session ? `${session.tenant_id}/${session.account_id}/${session.session_id}` : "";
  const [reportId, setReportId] = useState("r001");
  const [report, setReport] = useState<Report>();
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => { setReport(undefined); setMessage(""); }, [sessionKey]);

  async function readReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setReport(undefined); setMessage("");
    const id = reportId.trim();
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(id)) { setMessage("请输入有效的报告 ID。"); return; }
    setBusy(true);
    const expectedSession = sessionKey;
    try {
      const token = await identity.accessToken();
      const response = await fetch(`/api/reports/${encodeURIComponent(id)}`, {
        headers: { Authorization: `Bearer ${token}` }, cache: "no-store", credentials: "omit",
      });
      const current = identity.getSnapshot().session;
      if (`${current?.tenant_id}/${current?.account_id}/${current?.session_id}` !== expectedSession) return;
      if (response.status === 403) { setMessage("当前用户没有读取这份报告的权限。"); return; }
      if (response.status === 404) { setMessage("没有这份报告。"); return; }
      if (response.status === 401) { setMessage("登录已失效，请重新登录。"); return; }
      if (!response.ok) { setMessage("报告服务暂时不可用。"); return; }
      const value = await response.json() as Report;
      if (value.tenant_id !== session?.tenant_id || value.report_id !== id) throw new Error("invalid report response");
      const latest = identity.getSnapshot().session;
      if (`${latest?.tenant_id}/${latest?.account_id}/${latest?.session_id}` !== expectedSession) return;
      setReport(value);
    } catch { setMessage("读取失败，请核对登录状态和报告服务。"); }
    finally { setBusy(false); }
  }

  return <main>
    <header><p>嵌入式 IdP · 无租户宿主示例</p><h1>报告工作台</h1><span>身份与权限来自 IdP；报告内容属于宿主。</span></header>
    <div className="columns">
      <EmbeddedAuth client={identity} language="zh-CN" />
      <section className="report-panel">
        <h2>读取业务报告</h2>
        <p>在管理后台创建 <code>report::read</code>，加入角色并给当前用户分配报告范围，然后在这里验证。</p>
        <form onSubmit={event => void readReport(event)}>
          <label htmlFor="report-id">报告 ID</label>
          <div className="report-input"><input id="report-id" value={reportId} onChange={event => setReportId(event.target.value)} maxLength={128} /><button disabled={!session || busy}>{busy ? "读取中…" : "读取"}</button></div>
        </form>
        {!session && <p className="hint">请先在左侧登录。</p>}
        {message && <p className="message" role="status">{message}</p>}
        {report && <article><small>{report.report_id}</small><h3>{report.title}</h3><p>{report.body}</p></article>}
      </section>
    </div>
  </main>;
}

createRoot(document.getElementById("root")!).render(<App />);
