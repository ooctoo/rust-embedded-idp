import { useEffect, useId, useRef, useState, useSyncExternalStore, type CSSProperties, type FormEvent } from "react";
import { EmbeddedIdentityClient, IdentityError, type JoinedTenantPage, type MyRolePage } from "./client";
import styles from "./auth.module.css";

type Language = "zh-CN" | "en-US";
const copy = {
  "zh-CN": {
    connect: "连接身份服务", retry: "重新连接", loading: "正在读取登录方式…", login: "登录", email: "邮箱", password: "密码",
    signingIn: "正在登录…", choose: "选择租户", loadingTenants: "正在读取已加入的租户…", unavailable: "不可进入",
    enter: "进入", previous: "上一页", next: "下一页", page: "第", empty: "暂无可进入的租户，请联系管理员。",
    back: "返回登录", cancel: "取消切换，返回当前会话", switch: "切换租户", logout: "退出登录",
    current: "当前身份", account: "用户 ID", tenant: "租户", system: "当前系统", note: "访问令牌仅保存在本页内存中，刷新后会尝试恢复浏览器会话。",
    fixed: "此入口只登录指定租户。", selectable: "验证账号后，选择已加入的租户。", disabled: "使用账号邮箱和密码登录。",
    verify: "校验会话", verified: "会话有效", error: "操作失败，请重试。", busy: "正在处理…",
    roles: "我的角色", loadingRoles: "正在读取角色…", noRoles: "当前租户暂无角色。", disabledRole: "已停用",
  },
  "en-US": {
    connect: "Connect to identity service", retry: "Retry", loading: "Loading sign-in options…", login: "Sign in", email: "Email", password: "Password",
    signingIn: "Signing in…", choose: "Choose a tenant", loadingTenants: "Loading your tenants…", unavailable: "Unavailable",
    enter: "Enter", previous: "Previous", next: "Next", page: "Page", empty: "No tenant is available. Contact an administrator.",
    back: "Back to sign in", cancel: "Cancel switch and return", switch: "Switch tenant", logout: "Sign out",
    current: "Current identity", account: "User ID", tenant: "Tenant", system: "Current system", note: "The access token stays in this page's memory; a reload restores the browser session.",
    fixed: "This sign-in is limited to one tenant.", selectable: "Verify your account, then choose a tenant you have joined.", disabled: "Sign in with your account email and password.",
    verify: "Check session", verified: "Session active", error: "The operation failed. Please try again.", busy: "Working…",
    roles: "My roles", loadingRoles: "Loading roles…", noRoles: "No roles in this tenant.", disabledRole: "Disabled",
  },
} as const;

export interface EmbeddedAuthProps {
  client: EmbeddedIdentityClient;
  language?: Language;
  className?: string;
  style?: CSSProperties;
}

/** Public, host-embeddable sign-in UI. It never imports management routes or styles. */
export function EmbeddedAuth({ client, language = "zh-CN", className, style }: EmbeddedAuthProps) {
  const t = copy[language];
  const state = useSyncExternalStore(client.subscribe, client.getSnapshot, client.getSnapshot);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [page, setPage] = useState<JoinedTenantPage>();
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [tenantLoading, setTenantLoading] = useState(false);
  const [verified, setVerified] = useState(false);
  const [rolePage, setRolePage] = useState<{ key: string; page: MyRolePage }>();
  const [roleCursors, setRoleCursors] = useState<(string | undefined)[]>([undefined]);
  const [roleLoading, setRoleLoading] = useState(false);
  const restoreAttempted = useRef<EmbeddedIdentityClient | undefined>(undefined);
  const roleKey = state.session ? `${state.session.tenant_id}/${state.session.account_id}/${state.session.session_id}` : "";
  const emailId = useId(), passwordId = useId();
  const message = (reason: unknown) => language === "zh-CN" && reason instanceof IdentityError ? reason.message : t.error;

  async function run(operation: () => Promise<void>) {
    setError(""); setBusy(true);
    try { await operation(); } catch (reason) { setError(message(reason)); }
    finally { setBusy(false); }
  }

  useEffect(() => {
    let live = true;
    if (!state.capabilities) void client.loadCapabilities().catch(reason => { if (live) setError(message(reason)); });
    return () => { live = false; };
  }, [client, state.capabilities]);

  useEffect(() => {
    if (!client.isCookieMode() || !state.capabilities || restoreAttempted.current === client) return;
    restoreAttempted.current = client;
    setBusy(true);
    void client.restore().catch(reason => {
      if (reason instanceof IdentityError && reason.status === 401) return;
      setError(message(reason));
    }).finally(() => setBusy(false));
  }, [client, state.capabilities]);

  useEffect(() => { if (!state.selecting) { setPage(undefined); setCursors([undefined]); } }, [state.selecting]);

  useEffect(() => { setRolePage(undefined); setRoleCursors([undefined]); }, [client, roleKey]);

  useEffect(() => {
    if (!roleKey || state.selecting) return;
    let live = true;
    setRoleLoading(true);
    void client.listMyRoles(roleCursors.at(-1)).then(page => { if (live) setRolePage({ key: roleKey, page }); })
      .catch(reason => { if (live) setError(message(reason)); })
      .finally(() => { if (live) setRoleLoading(false); });
    return () => { live = false; };
  }, [client, roleKey, state.selecting, roleCursors]);

  useEffect(() => {
    if (!state.selecting) return;
    let live = true;
    setTenantLoading(true);
    void client.listTenants(cursors.at(-1)).then(result => { if (live) setPage(result); })
      .catch(reason => { if (live) setError(message(reason)); })
      .finally(() => { if (live) setTenantLoading(false); });
    return () => { live = false; };
  }, [client, state.selecting, cursors]);

  useEffect(() => {
    setVerified(false);
    if (!state.session || state.selecting || !state.accessExpiresAt) return;
    const check = () => void run(async () => { await client.verifySession(); setVerified(true); });
    const timeout = window.setTimeout(check, Math.max(1000, Math.min(2_147_000_000, (state.accessExpiresAt - 30) * 1000 - Date.now())));
    const visible = () => { if (document.visibilityState === "visible") check(); };
    document.addEventListener("visibilitychange", visible);
    return () => { window.clearTimeout(timeout); document.removeEventListener("visibilitychange", visible); };
  }, [client, state.session?.session_id, state.selecting, state.accessExpiresAt]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try { await run(() => client.login(email.trim(), password)); }
    finally { setPassword(""); }
  }

  return <section className={`${styles.root}${className ? ` ${className}` : ""}`} style={style} lang={language} aria-busy={busy || tenantLoading}>
    {state.sessionChanged && <p role="status">{language === "zh-CN" ? "其他页面已更改此会话，请重新加载后继续。" : "Another page changed this session. Reload to continue."} <button type="button" onClick={() => window.location.reload()}>{language === "zh-CN" ? "重新加载" : "Reload"}</button></p>}
    {error && <p className={styles.error} role="alert">{error}</p>}
    {!state.capabilities ? <div>
      <h2>{t.connect}</h2>
      <p role="status">{busy ? t.busy : t.loading}</p>
      <button type="button" disabled={busy} onClick={() => void run(() => client.loadCapabilities())}>{t.retry}</button>
    </div> : state.selecting ? <div>
      <h2>{t.choose}</h2>
      {tenantLoading && <p role="status">{t.loadingTenants}</p>}
      {page && <>
        {page.tenants.length === 0 && <p>{t.empty}</p>}
        <ul className={styles.tenants}>
          {page.tenants.map(tenant => {
            const available = tenant.status === "active" && tenant.membership_status === "active";
            return <li key={tenant.tenant_id}>
              <div><strong>{tenant.name}</strong><small>{tenant.tenant_id}</small></div>
              <button type="button" disabled={!available || busy || tenantLoading} onClick={() => void run(() => client.selectTenant(tenant.tenant_id))}>
                {available ? t.enter : t.unavailable}
              </button>
            </li>;
          })}
        </ul>
        <nav className={styles.pagination} aria-label={t.choose}>
          <button type="button" disabled={cursors.length === 1 || busy || tenantLoading} onClick={() => setCursors(v => v.slice(0, -1))}>{t.previous}</button>
          <span>{t.page} {cursors.length}</span>
          <button type="button" disabled={!page.has_more || busy || tenantLoading} onClick={() => setCursors(v => [...v, page.next_cursor])}>{t.next}</button>
        </nav>
      </>}
      <button type="button" className={styles.secondary} disabled={busy} onClick={() => { setError(""); client.cancelSelection(); }}>{state.session ? t.cancel : t.back}</button>
    </div> : state.session ? <div>
      <h2>{t.current}</h2>
      <dl className={styles.identity}>
        <div><dt>{state.capabilities.tenancy_enabled ? t.tenant : t.system}</dt><dd>{state.capabilities.tenancy_enabled ? state.session.tenant_id : t.system}</dd></div>
        <div><dt>{t.account}</dt><dd>{state.session.account_id}</dd></div>
      </dl>
      <h3>{t.roles}</h3>
      {roleLoading && <p role="status">{t.loadingRoles}</p>}
      {rolePage?.key === roleKey && <>
        {rolePage.page.items.length === 0 && <p>{t.noRoles}</p>}
        <ul className={styles.tenants}>
          {rolePage.page.items.map(role => <li key={role.role_id}><div><strong>{role.name}</strong><small>{role.key}{role.status === "disabled" ? ` · ${t.disabledRole}` : ""}</small></div></li>)}
        </ul>
        {(roleCursors.length > 1 || rolePage.page.has_more) && <nav className={styles.pagination} aria-label={t.roles}>
          <button type="button" disabled={roleCursors.length === 1 || roleLoading} onClick={() => setRoleCursors(v => v.slice(0, -1))}>{t.previous}</button>
          <span>{t.page} {roleCursors.length}</span>
          <button type="button" disabled={!rolePage.page.has_more || roleLoading} onClick={() => setRoleCursors(v => [...v, rolePage.page.next_cursor])}>{t.next}</button>
        </nav>}
      </>}
      {verified && <p className={styles.success} role="status">{t.verified}</p>}
      <div className={styles.actions}>
        <button type="button" disabled={busy} onClick={() => void run(async () => { await client.verifySession(); setVerified(true); })}>{t.verify}</button>
        {client.canChoose() && <button type="button" disabled={busy} onClick={() => void run(() => client.beginSwitch())}>{t.switch}</button>}
        <button type="button" className={styles.secondary} disabled={busy} onClick={() => void run(() => client.logout())}>{t.logout}</button>
      </div>
    </div> : <div>
      <h2>{t.login}</h2>
      <p className={styles.helper}>{!state.capabilities.tenancy_enabled ? t.disabled : state.capabilities.login_tenant_policy === "fixed" ? t.fixed : t.selectable}</p>
      <form onSubmit={event => void submit(event)}>
        <label htmlFor={emailId}>{t.email}</label>
        <input id={emailId} type="email" autoComplete="username" required maxLength={320} disabled={busy} value={email} onChange={event => setEmail(event.target.value)} />
        <label htmlFor={passwordId}>{t.password}</label>
        <input id={passwordId} type="password" autoComplete="current-password" required maxLength={4096} disabled={busy} value={password} onChange={event => setPassword(event.target.value)} />
        <button type="submit" disabled={busy}>{busy ? t.signingIn : t.login}</button>
      </form>
      <p className={styles.helper}>{client.isCookieMode() ? t.note : language === "zh-CN" ? "凭证仅保存在本页内存中，刷新后需重新登录。" : "Credentials stay in memory. Sign in again after a reload."}</p>
    </div>}
  </section>;
}
