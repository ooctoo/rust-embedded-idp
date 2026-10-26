import { lazy, Suspense, useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { Alert, App, Button, Card, ConfigProvider, Empty, Form, Input, Space, Spin, Tag, Typography } from "antd";
import zhCN from "antd/locale/zh_CN";
import { ManagementClient, ManagementError, type TenantPage } from "./client";
import { defaultRoute, routeHash } from "./navigation";
import "./styles.css";

const { Title, Paragraph, Text } = Typography;
const ManagementShell = lazy(() => import("./shell").then(module => ({ default: module.ManagementShell })));

function errorMessage(error: unknown) {
  return error instanceof ManagementError ? error.message : "操作未完成，请稍后重试。";
}

function TenantPicker({ client, busy, run, reportError }: {
  client: ManagementClient;
  busy: boolean;
  run: (operation: () => Promise<void>) => Promise<void>;
  reportError: (message: string) => void;
}) {
  const [page, setPage] = useState<TenantPage>();
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    setPage(undefined);
    client.listTenants(cursors.at(-1)).then(result => {
      if (active) setPage(result);
    }).catch(reason => {
      if (active) {
        if (!client.getSnapshot().selecting) reportError(errorMessage(reason));
        else setError(errorMessage(reason));
      }
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, cursors, attempt, reportError]);

  return <Card className="management-card">
    <h1 ref={heading} tabIndex={-1}>选择工作租户</h1>
    <Paragraph type="secondary">使用同一账号进入已加入的租户。停用的租户或成员关系无法进入。</Paragraph>
    {error && <Alert type="error" showIcon message={error} role="alert" action={<Button onClick={() => setAttempt(v => v + 1)}>重试</Button>} />}
    {loading && <div className="management-loading" role="status"><Spin /><span>正在读取已加入的租户…</span></div>}
    {page && <>
      {page.tenants.length === 0 && <Empty description="暂无可进入的租户，请联系管理员确认成员关系。" />}
      <ul className="management-tenants">
        {page.tenants.map(tenant => {
          const available = tenant.status === "active" && tenant.membership_status === "active";
          return <li key={tenant.tenant_id}>
            <div><Text strong>{tenant.name}</Text><div><Text type="secondary">ID：{tenant.tenant_id}</Text></div></div>
            <Space wrap>{!available && <Tag>不可进入</Tag>}<Button type={available ? "primary" : "default"} disabled={!available || busy || loading}
              aria-label={`进入 ${tenant.name}`} onClick={() => void run(() => client.selectTenant(tenant.tenant_id))}>进入</Button></Space>
          </li>;
        })}
      </ul>
      <div className="management-pagination">
        <Button disabled={cursors.length === 1 || busy} onClick={() => setCursors(v => v.slice(0, -1))}>上一页</Button>
        <Text type="secondary">第 {cursors.length} 页</Text>
        <Button disabled={!page.has_more || busy} onClick={() => setCursors(v => [...v, page.next_cursor])}>下一页</Button>
      </div>
    </>}
    <Button className="management-back" disabled={busy} onClick={() => client.cancelSelection()}>
      {client.getSnapshot().session ? "取消切换，返回当前会话" : "返回登录"}
    </Button>
  </Card>;
}

function Console({ client }: { client: ManagementClient }) {
  const state = useSyncExternalStore(client.subscribe, client.getSnapshot);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [verifiedAt, setVerifiedAt] = useState<string>();
  const restoreAttempted = useRef<ManagementClient | undefined>(undefined);
  const [verifiedKey, setVerifiedKey] = useState<string>();
  const [form] = Form.useForm();
  const run = useCallback(async (operation: () => Promise<void>) => {
    setError("");
    setBusy(true);
    try { await operation(); } catch (reason) { setError(errorMessage(reason)); }
    finally { setBusy(false); }
  }, []);
  useEffect(() => { void run(() => client.loadCapabilities()); }, [client, run]);
  useEffect(() => {
    if (!client.supportsRestore() || !state.capabilities || restoreAttempted.current === client) return;
    restoreAttempted.current = client;
    setBusy(true);
    void client.restore().catch(reason => { if (!(reason instanceof ManagementError && reason.status === 401)) setError(errorMessage(reason)); }).finally(() => setBusy(false));
  }, [client, state.capabilities]);
  useEffect(() => { setVerifiedAt(undefined); }, [state.session?.session_id]);
  const priorSelection = useRef({ selecting: state.selecting, tenant: state.session?.tenant_id });
  useEffect(() => {
    const previous = priorSelection.current;
    if (previous.selecting && !state.selecting && previous.tenant && state.session &&
        previous.tenant !== state.session.tenant_id && state.capabilities) {
      // An explicit Choose completion changes the login scope. Copied URLs and
      // ordinary logins still retain their original (revalidated) location.
      history.replaceState(history.state, "", `${location.pathname}${location.search}${routeHash(defaultRoute(state.capabilities, state.session))}`);
    }
    priorSelection.current = { selecting: state.selecting, tenant: state.session?.tenant_id };
  }, [state.selecting, state.session?.tenant_id, state.capabilities]);

  const sessionKey = state.session && JSON.stringify([state.session.tenant_id, state.session.account_id, state.session.session_id, state.session.client_id]);
  useEffect(() => {
    setVerifiedKey(undefined);
    if (!sessionKey || state.selecting) return;
    let active = true;
    void run(async () => {
      await client.verifySession();
      if (active) { setVerifiedKey(sessionKey); setVerifiedAt(new Date().toLocaleTimeString("zh-CN")); }
    });
    return () => { active = false; };
  }, [client, sessionKey, state.selecting, run]);
  useEffect(() => {
    if (!state.session || state.selecting || busy) return;
    const verify = () => void run(async () => {
      await client.verifySession();
      setVerifiedAt(new Date().toLocaleTimeString("zh-CN"));
    });
    const timeout = window.setTimeout(verify, Math.max(1000, Math.min(2_147_000_000, (state.accessExpiresAt! - (client.isDevelopmentMode() ? 0 : 30)) * 1000 - Date.now())));
    const visible = () => { if (document.visibilityState === "visible") verify(); };
    document.addEventListener("visibilitychange", visible);
    return () => { clearTimeout(timeout); document.removeEventListener("visibilitychange", visible); };
  }, [client, state.session, state.selecting, state.accessExpiresAt, busy, run]);

  const capabilities = state.capabilities;
  const modeLabel = !capabilities ? "连接管理服务" : !capabilities.tenancy_enabled ? "单域管理" :
    capabilities.fixed_tenant_id === "0" ? "平台管理" : capabilities.login_tenant_policy === "fixed" ? "固定租户" : "多租户管理";

  const notices = <>
    {client.isDevelopmentMode() && <Alert type="warning" message="开发登录模式：页面重载或会话到期后需重新登录。" />}
    {state.sessionChanged && <Alert type="info" message="其他页面已更改此会话，请重新加载后继续。" action={<Button onClick={() => window.location.reload()}>重新加载</Button>} />}
    {error && <Alert className="management-error" type="error" showIcon message={error} role="alert" />}
  </>;
  const verify = () => void run(async () => { await client.verifySession(); setVerifiedAt(new Date().toLocaleTimeString("zh-CN")); });
  return <div className="management-root">
    {state.session && !state.selecting && verifiedKey === sessionKey ? <Suspense fallback={<div className="management-loading" role="status"><Spin /> 正在加载管理工作区…</div>}>
      <ManagementShell key={sessionKey} client={client} busy={busy} verifiedAt={verifiedAt} notices={notices} verify={verify}
        logout={() => void run(() => client.logout())} switchTenant={() => void run(() => client.beginSwitch())} />
    </Suspense> : <>
      <header className="management-header"><div className="management-brand">IDP <span>身份管理控制台</span></div><Tag>{modeLabel}</Tag></header>
      <main className="management-main"><section className="management-panel" aria-label="管理认证" aria-busy={busy}>
        {notices}
        {!capabilities ? <Card className="management-card">
          <Title level={1}>连接管理服务</Title>
          {busy ? <div role="status"><Spin /> 正在读取登录方式…</div> : <Button onClick={() => void run(() => client.loadCapabilities())}>重新连接</Button>}
        </Card> : state.selecting ? <TenantPicker client={client} busy={busy} run={run} reportError={setError} /> : state.session ?
          <Card className="management-card"><div role="status"><Spin /> 正在验证当前管理会话…</div>
            {!busy && <Button onClick={() => void run(async () => { await client.verifySession(); setVerifiedKey(sessionKey); })}>重新验证会话</Button>}
          </Card> : <Card className="management-card">
          <Title level={1}>登录管理控制台</Title>
          <Paragraph type="secondary">{!capabilities.tenancy_enabled ? "使用管理员邮箱和密码登录。" : capabilities.login_tenant_policy === "fixed" ?
            capabilities.fixed_tenant_id === "0" ? "此入口用于平台管理员登录。" : `此入口仅登录租户 ${capabilities.fixed_tenant_id}。` : "验证账号后，选择已加入的租户。"}</Paragraph>
          <Form<{ email: string; password: string }> form={form} layout="vertical" disabled={busy} requiredMark={false}
            onFinish={async values => { try { await run(() => client.login(values.email, values.password)); } finally { form.resetFields(["password"]); } }}>
            <Form.Item name="email" label="邮箱" rules={[{ required: true, message: "请输入邮箱" }, { type: "email", message: "请输入有效邮箱" }]}>
              <Input size="large" autoComplete="username" type="email" autoFocus maxLength={320} />
            </Form.Item>
            <Form.Item name="password" label="密码" rules={[{ required: true, message: "请输入密码" }]}>
              <Input.Password size="large" autoComplete="current-password" maxLength={4096} />
            </Form.Item>
            <Button type="primary" htmlType="submit" block size="large" loading={busy}>登录</Button>
          </Form>
          <Paragraph type="secondary" className="management-note">{client.supportsRestore() ? "访问令牌仅保存在当前页面，刷新后会尝试恢复浏览器会话。" : "凭证仅保存在当前页面，刷新或到期后需重新登录。"}</Paragraph>
        </Card>}
      </section></main>
      <footer className="management-footer">Embedded IDP · 管理控制台</footer>
    </>}
  </div>;
}

export function ManagementApp({ client }: { client: ManagementClient }) {
  return <ConfigProvider locale={zhCN} theme={{ token: {
    colorPrimary: "#245cca", colorPrimaryHover: "#1e4da8", colorPrimaryActive: "#163b85",
    colorTextSecondary: "#58677c", colorTextDescription: "#58677c", colorTextPlaceholder: "#58677c",
    colorBorder: "#8290a3", colorError: "#b42318", colorErrorHover: "#941c14", colorErrorActive: "#7a1710",
    colorSuccess: "#17663c", colorWarning: "#8a4b00",
    borderRadius: 8, fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", sans-serif',
  } }}>
    <App><Console client={client} /></App>
  </ConfigProvider>;
}
