import { useEffect, useId, useMemo, useRef, useState, useSyncExternalStore, type FormEvent } from "react";
import type { AccountSecurityPort, SecurityIdentity, SecuritySession, SecuritySessionPage } from "./account-security-client";
import { AccountSecurityWorkflow, validateAccountSecurityFeatures, type AccountSecurityFeatures, type SecurityJournalRecord, type SecurityJournalStore } from "./account-security-workflow";
import styles from "./account-security.module.css";

type Language = "zh-CN" | "en-US";
type SecurityIdentityPort = AccountSecurityPort & { subscribe(listener: () => void): () => void };
interface CommonProps {
  identity: SecurityIdentityPort;
  features?: AccountSecurityFeatures;
  store?: SecurityJournalStore;
  language?: Language;
  onClose?: () => void;
}

const copy = {
  "zh-CN": {
    title: "我的账号安全", close: "返回", sessions: "本人全域会话", loading: "正在读取会话…", empty: "没有可显示的会话。", refresh: "重新读取",
    previous: "上一页", next: "下一页", tenant: "租户", client: "客户端", purpose: "入口", device: "设备", created: "创建时间", expires: "到期时间",
    active: "有效", expired: "已到期", current: "当前会话", revoke: "撤销此会话", confirm: "确认撤销此会话", cancel: "取消", currentWarn: "这会结束当前会话。",
    password: "修改密码", currentPassword: "当前密码", newPassword: "新密码", confirmPassword: "确认新密码", changePassword: "提交改密", passwordMismatch: "两次输入的新密码不一致。",
    readOnly: "当前未启用安全写操作；你仍可查看本人会话和核对已有操作。", noSession: "当前没有有效登录身份。可以核对已保存的安全操作。",
    record: "安全操作记录", pending: "结果待确认", ready: "可以继续", completed: "操作已完成。请重新登录。", unknown: "结果未知。请核对操作结果，不要创建新的操作。",
    result: "核对结果", retryStart: "用原请求重试", discard: "放弃本地记录", closeRecord: "关闭记录", discardConfirm: "确认删除本地记录？这不会撤销服务端操作。", closeRecordConfirm: "确认关闭记录？这会删除本地凭据记录，但不会取消服务端操作。", keep: "保留记录",
    storageError: "本地记录不可用；请检查浏览器存储后重试。", storageDiscard: "确认移除损坏的本地记录", recovery: "找回密码", email: "邮箱", start: "发送验证码",
    code: "邮箱验证码", codePassword: "设置新密码", codeConfirm: "确认新密码", complete: "完成密码恢复", flowExpired: "验证码有效期已过，不能提交验证码；仍可核对操作结果。",
    recoveryHint: "如果账号符合恢复条件，将发送验证码。", protected: "具备安全管理权限的账号请联系管理员。", noRecovery: "当前未启用密码恢复。", retry: "重试", status: "操作状态",
    pendingStart: "请求结果未知。只能用原请求重试或放弃本地记录。", otherRecord: "已有另一项安全操作记录，请先核对或明确放弃。", notReady: "此记录当前不能执行写操作。",
  },
  "en-US": {
    title: "My account security", close: "Back", sessions: "Sessions across my account", loading: "Loading sessions…", empty: "No sessions to display.", refresh: "Reload",
    previous: "Previous", next: "Next", tenant: "Tenant", client: "Client", purpose: "Entry", device: "Device", created: "Created", expires: "Expires",
    active: "Active", expired: "Expired", current: "Current session", revoke: "Revoke session", confirm: "Confirm revocation", cancel: "Cancel", currentWarn: "This will end your current session.",
    password: "Change password", currentPassword: "Current password", newPassword: "New password", confirmPassword: "Confirm new password", changePassword: "Change password", passwordMismatch: "The new passwords do not match.",
    readOnly: "Security writes are not enabled. You can still view your sessions and check existing operations.", noSession: "There is no active identity. You can check a saved security operation.",
    record: "Security operation", pending: "Result pending", ready: "Ready to continue", completed: "Operation completed. Please sign in again.", unknown: "The result is unknown. Check the operation; do not create a new one.",
    result: "Check result", retryStart: "Retry the original request", discard: "Discard local record", closeRecord: "Close record", discardConfirm: "Delete the local record? This does not cancel the server operation.", closeRecordConfirm: "Close this record? This deletes the local credential record but does not cancel the server operation.", keep: "Keep record",
    storageError: "The local record is unavailable. Check browser storage and retry.", storageDiscard: "Confirm removal of damaged local record", recovery: "Recover password", email: "Email", start: "Send code",
    code: "Email code", codePassword: "New password", codeConfirm: "Confirm new password", complete: "Complete recovery", flowExpired: "The code has expired. You can still check the operation result.",
    recoveryHint: "If the account is eligible, a code will be sent.", protected: "Accounts with security-administration access should contact an administrator.", noRecovery: "Password recovery is not enabled.", retry: "Retry", status: "Operation status",
    pendingStart: "The result is unknown. Retry the original request or discard the local record.", otherRecord: "Another security operation is recorded. Check it or explicitly discard it first.", notReady: "This record cannot currently perform a write.",
  },
} as const;

function identityOf(value: unknown): SecurityIdentity | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const item = value as Record<string, unknown>;
  if (![item.tenant_id, item.account_id, item.session_id, item.client_id].every(v => typeof v === "string" && v.length > 0)) return undefined;
  return { tenant_id: item.tenant_id as string, account_id: item.account_id as string, session_id: item.session_id as string, client_id: item.client_id as string };
}
function sameIdentity(left: SecurityIdentity | undefined, right: unknown) {
  const candidate = identityOf(right);
  return !!left && !!candidate && left.tenant_id === candidate.tenant_id && left.account_id === candidate.account_id &&
    left.session_id === candidate.session_id && left.client_id === candidate.client_id;
}
function identityKey(owner: SecurityIdentity | undefined, scope: string) {
  return JSON.stringify([scope, owner ? [owner.tenant_id, owner.account_id, owner.session_id, owner.client_id] : null]);
}
function formatTime(value: number, language: Language) {
  const date = new Date(value * 1000);
  if (!Number.isFinite(date.getTime())) return language === "zh-CN" ? "时间不可用" : "Time unavailable";
  return new Intl.DateTimeFormat(language, { dateStyle: "medium", timeStyle: "short" }).format(date);
}
function completedMessage(record: SecurityJournalRecord, language: Language) {
  const zh = language === "zh-CN";
  if (record.intent.kind === "revoke" &&
      (record.intent.target_tenant_id !== record.intent.owner.tenant_id || record.intent.target_session_id !== record.intent.owner.session_id)) {
    return zh ? "会话已撤销。" : "The session was revoked.";
  }
  if (record.intent.kind === "recovery-complete") return zh ? "密码恢复已完成，请登录。" : "Password recovery completed. Sign in again.";
  return zh ? "操作已完成。请重新登录。" : "Operation completed. Please sign in again.";
}
function messageFor(code: string | undefined, language: Language) {
  const chinese = language === "zh-CN";
  const messages: Record<string, string> = chinese ? {
    invalid_credentials: "当前密码不正确，请检查后重试。", invalid_session: "当前会话已失效，请重新登录。", rate_limited: "操作过于频繁，请稍后重试。",
    session_not_found: "会话不存在或已结束。", invalid_recovery: "恢复信息无效，请检查后重试。", invalid_request: "请求无效，请检查后重试。",
    browser_origin_rejected: "当前页面来源未获授权。", security_session_changed: "身份已变化，请重新读取后操作。", invalid_security_intent: "安全操作记录无效。",
    invalid_security_response: "服务响应无效，请核对操作结果。",
  } : {
    invalid_credentials: "The current password is incorrect.", invalid_session: "The session is no longer active. Sign in again.", rate_limited: "Too many requests. Try again later.",
    session_not_found: "The session was not found or has ended.", invalid_recovery: "Recovery details are invalid.", invalid_request: "The request is invalid.",
    browser_origin_rejected: "This page origin is not allowed.", security_session_changed: "Your identity changed. Reload before continuing.", invalid_security_intent: "The saved security operation is invalid.",
    invalid_security_response: "The service response is invalid. Check the operation result.",
  };
  return code ? messages[code] ?? (chinese ? "操作未能完成，请核对结果后重试。" : "The operation did not complete. Check its result before retrying.") :
    (chinese ? "操作未能确认，请核对结果。" : "The operation could not be confirmed. Check its result.");
}
function useWorkflow(identity: SecurityIdentityPort, features: AccountSecurityFeatures | undefined, store?: SecurityJournalStore) {
  const safeFeatures = validateAccountSecurityFeatures(features);
  const workflow = useMemo(() => new AccountSecurityWorkflow(identity, safeFeatures, store),
    [identity, safeFeatures.enabled, safeFeatures.recovery, store]);
  const snapshot = useSyncExternalStore(workflow.subscribe, workflow.getSnapshot, workflow.getSnapshot);
  return { workflow, snapshot };
}
function useIdentity(identity: SecurityIdentityPort) {
  return useSyncExternalStore(identity.subscribe, identity.getSnapshot, identity.getSnapshot);
}
function safeRun(action: () => Promise<unknown> | void) { void Promise.resolve().then(action).catch(() => {}); }
function JournalStatus({ identity, features, language = "zh-CN", workflow, snapshot }: CommonProps & {
  workflow: AccountSecurityWorkflow;
  snapshot: ReturnType<AccountSecurityWorkflow["getSnapshot"]>;
}) {
  const t = copy[language];
  const authSnapshot = useIdentity(identity);
  const owner = identityOf(authSnapshot.session);
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  const record = snapshot.record;
  const revocation = record?.intent.kind === "revoke" ? record.intent : undefined;
  const id = useId();
  if (!record && !snapshot.storageError && !snapshot.error) return null;
  const kind = record?.intent.kind;
  const title = kind === "revoke" ? (language === "zh-CN" ? "撤销会话" : "Revoke session") : kind === "password" ? t.password : kind?.startsWith("recovery-") ? t.recovery : t.record;
  return <section className={styles.record} aria-labelledby={`${id}-journal`}>
    <h3 id={`${id}-journal`}>{title}</h3>
    {snapshot.storageError && <p role="alert">{t.storageError}</p>}
    {snapshot.error && <p role="alert">{messageFor(snapshot.error, language)}</p>}
    {record && <p role="status">{record.stage === "completed" ? completedMessage(record, language) : record.stage === "ready" ? t.ready : t.unknown}</p>}
    {snapshot.busy && <p role="status">{language === "zh-CN" ? "正在处理…" : "Working…"}</p>}
    <div className={styles.actions}>
      <button type="button" className={styles.secondary} disabled={snapshot.busy} onClick={() => safeRun(() => workflow.refresh())}>{t.refresh}</button>
      {record?.stage === "pending" && record.intent.kind !== "recovery-start" &&
        <button type="button" disabled={snapshot.busy} onClick={() => safeRun(() => workflow.checkResult())}>{t.result}</button>}
      {features?.recovery && record?.intent.kind === "recovery-start" && record.stage === "pending" && !record.flow &&
        <button type="button" disabled={snapshot.busy} onClick={() => safeRun(() => workflow.retryStart())}>{t.retryStart}</button>}
      {features?.enabled && revocation && record?.stage === "ready" && sameIdentity(owner, revocation.owner) &&
        <button type="button" disabled={snapshot.busy} onClick={() => safeRun(() => workflow.revoke(revocation.target_tenant_id, revocation.target_session_id))}>{t.retry}</button>}
      {record && <button type="button" className={styles.secondary} disabled={snapshot.busy} onClick={() => setConfirmDiscard(true)}>{record.stage === "completed" ? t.closeRecord : t.discard}</button>}
      {snapshot.storageError && <button type="button" className={styles.secondary} disabled={snapshot.busy} onClick={() => setConfirmDiscard(true)}>{t.storageDiscard}</button>}
    </div>
    {confirmDiscard && <div className={styles.confirm}>
      <p>{record?.stage === "completed" ? t.closeRecordConfirm : t.discardConfirm}</p>
      <button type="button" disabled={snapshot.busy} onClick={() => { safeRun(async () => { await workflow.discard(); setConfirmDiscard(false); }); }}>{record?.stage === "completed" ? t.closeRecord : t.discard}</button>
      <button type="button" className={styles.secondary} onClick={() => setConfirmDiscard(false)}>{t.keep}</button>
    </div>}
  </section>;
}

export interface AccountSecurityPanelProps extends CommonProps {}
export function AccountSecurityPanel(props: AccountSecurityPanelProps) {
  const authSnapshot = useIdentity(props.identity);
  const owner = identityOf(authSnapshot.session);
  const { workflow, snapshot } = useWorkflow(props.identity, props.features, props.store);
  return <AccountSecurityPanelView key={identityKey(owner, props.identity.accountSecurityScope)} {...props} owner={owner} workflow={workflow} snapshot={snapshot} />;
}

function AccountSecurityPanelView({ identity, features, language = "zh-CN", onClose, owner, workflow, snapshot }: AccountSecurityPanelProps & {
  owner?: SecurityIdentity;
  workflow: AccountSecurityWorkflow;
  snapshot: ReturnType<AccountSecurityWorkflow["getSnapshot"]>;
}) {
  const t = copy[language];
  const [page, setPage] = useState<SecuritySessionPage>();
  const [cursorStack, setCursorStack] = useState<(string | undefined)[]>([undefined]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<SecuritySession>();
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [formError, setFormError] = useState("");
  const [epoch, setEpoch] = useState(0);
  const listGeneration = useRef(0);
  const currentKey = identityKey(owner, identity.accountSecurityScope);

  async function load(cursors: (string | undefined)[]) {
    if (!owner) return;
    const requestedKey = currentKey;
    const generation = ++listGeneration.current;
    setLoading(true); setFormError("");
    try {
      const value = await workflow.listSessions(cursors.at(-1));
      const active = identityOf(identity.getSnapshot().session);
      const activeKey = identityKey(active, identity.accountSecurityScope);
      if (generation === listGeneration.current && requestedKey === activeKey) {
        setPage(value);
        setCursorStack(cursors);
      }
    } catch (error) {
      const active = identityOf(identity.getSnapshot().session);
      const activeKey = identityKey(active, identity.accountSecurityScope);
      if (generation === listGeneration.current && requestedKey === activeKey) setFormError(messageFor((error as { code?: string })?.code, language));
    }
    finally { if (generation === listGeneration.current) setLoading(false); }
  }
  useEffect(() => {
    setPage(undefined); setCursorStack([undefined]);
    if (owner) void load([undefined]);
    return () => { listGeneration.current++; };
  // The keyed inner view isolates identity-specific state before its first render.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [identity, currentKey]);
  useEffect(() => { if (owner && epoch > 0) void load(cursorStack); }, [epoch]); // eslint-disable-line react-hooks/exhaustive-deps
  const id = useId();
  const recoveryRecord = snapshot.record?.intent.kind === "recovery-start" || snapshot.record?.intent.kind === "recovery-complete";
  const canChangePassword = !!features?.enabled && !!owner && (!snapshot.record || snapshot.record.intent.kind === "password" && snapshot.record.stage === "ready" && sameIdentity(owner, snapshot.record.intent.owner));
  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setFormError("");
    if (newPassword !== confirmPassword) { setFormError(t.passwordMismatch); return; }
    try { await workflow.changePassword(currentPassword, newPassword); }
    catch (error) { setFormError(messageFor((error as { code?: string })?.code, language)); }
    finally { setCurrentPassword(""); setNewPassword(""); setConfirmPassword(""); }
  }
  return <section className={styles.root} lang={language} aria-busy={snapshot.busy || loading}>
    <header className={styles.header}><h2>{t.title}</h2>{onClose && <button type="button" className={styles.secondary} disabled={snapshot.busy} onClick={onClose}>{t.close}</button>}</header>
    {!features?.enabled && <p className={styles.status} role="status">{t.readOnly}</p>}
    {!owner && <p className={styles.status} role="status">{t.noSession}</p>}
    {(formError || snapshot.error) && <p className={styles.alert} role="alert">{formError || messageFor(snapshot.error, language)}</p>}
    {snapshot.storageError && <p className={styles.alert} role="alert">{t.storageError}</p>}
    {!recoveryRecord && <JournalStatus identity={identity} features={features} language={language} workflow={workflow} snapshot={snapshot} />}
    {recoveryRecord && <RecoveryView identity={identity} features={features} language={language} workflow={workflow} snapshot={snapshot} />}
    <section aria-labelledby={`${id}-sessions`}>
      <h3 id={`${id}-sessions`}>{t.sessions}</h3>
      {loading && <p className={styles.status} role="status">{t.loading}</p>}
      {!loading && page?.items.length === 0 && <p>{t.empty}</p>}
      <ul className={styles.sessionList}>
        {page?.items.map(session => <li key={`${session.tenant_id}/${session.session_id}`}>
          <div className={styles.sessionInfo}>
            <strong>{session.current ? t.current : `${t.client}: ${session.client_id}`}</strong>
            <span>{t.tenant}: {session.tenant_id}</span><span>{t.client}: {session.client_id}</span>
            <span>{t.purpose}: {session.purpose}</span><span>{t.device}: {session.device_id ?? "—"}</span>
            <span>{t.created}: {formatTime(session.created_at, language)}</span><span>{t.expires}: {formatTime(session.expires_at, language)}</span>
            <span>{session.status === "active" ? t.active : t.expired}</span>
          </div>
          {features?.enabled && owner && (!snapshot.record || snapshot.record.intent.kind === "revoke" && snapshot.record.stage === "ready" && sameIdentity(owner, snapshot.record.intent.owner) && snapshot.record.intent.target_tenant_id === session.tenant_id && snapshot.record.intent.target_session_id === session.session_id) && <button type="button" disabled={snapshot.busy || loading} onClick={() => { setSelected(session); setConfirmRevoke(false); }}>{t.revoke}</button>}
        </li>)}
      </ul>
      {selected && <div className={styles.confirm}>
        <p>{`${t.revoke}: ${selected.tenant_id} / ${selected.session_id}`}</p>
        {selected.current && <p role="status">{t.currentWarn}</p>}
        {!confirmRevoke ? <button type="button" disabled={snapshot.busy} onClick={() => setConfirmRevoke(true)}>{t.revoke}</button> : <>
          <button type="button" disabled={snapshot.busy} onClick={() => safeRun(async () => { await workflow.revoke(selected.tenant_id, selected.session_id); setSelected(undefined); setConfirmRevoke(false); if (!selected.current) await load(cursorStack); })}>{t.confirm}</button>
          <button type="button" className={styles.secondary} onClick={() => { setSelected(undefined); setConfirmRevoke(false); }}>{t.cancel}</button>
        </>}
      </div>}
      {owner && <nav className={styles.pagination} aria-label={t.sessions}>
        <button type="button" disabled={cursorStack.length <= 1 || loading} onClick={() => { void load(cursorStack.slice(0, -1)); }}>{t.previous}</button>
        <button type="button" disabled={!page?.next_cursor || loading} onClick={() => { void load([...cursorStack, page?.next_cursor ?? undefined]); }}>{t.next}</button>
        <button type="button" className={styles.secondary} disabled={loading || snapshot.busy} onClick={() => setEpoch(value => value + 1)}>{t.refresh}</button>
      </nav>}
    </section>
    {canChangePassword && <form className={styles.form} onSubmit={event => void changePassword(event)} aria-labelledby={`${id}-password`}>
      <h3 id={`${id}-password`}>{t.password}</h3>
      <label htmlFor={`${id}-current`}>{t.currentPassword}</label>
      <input id={`${id}-current`} type="password" autoComplete="current-password" required maxLength={4096} disabled={snapshot.busy} value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} />
      <label htmlFor={`${id}-new`}>{t.newPassword}</label>
      <input id={`${id}-new`} type="password" autoComplete="new-password" required maxLength={4096} disabled={snapshot.busy} value={newPassword} onChange={event => setNewPassword(event.target.value)} />
      <label htmlFor={`${id}-confirm`}>{t.confirmPassword}</label>
      <input id={`${id}-confirm`} type="password" autoComplete="new-password" required maxLength={4096} disabled={snapshot.busy} value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} />
      <button type="submit" disabled={snapshot.busy}>{t.changePassword}</button>
    </form>}
  </section>;
}

export interface PasswordRecoveryProps extends CommonProps {}
function RecoveryView({ features, language = "zh-CN", onClose, workflow, snapshot }: CommonProps & {
  workflow: AccountSecurityWorkflow;
  snapshot: ReturnType<AccountSecurityWorkflow["getSnapshot"]>;
}) {
  const t = copy[language];
  const record = snapshot.record;
  const [email, setEmail] = useState(""); const [code, setCode] = useState(""); const [password, setPassword] = useState(""); const [confirm, setConfirm] = useState("");
  const [confirmDiscard, setConfirmDiscard] = useState(false); const [formError, setFormError] = useState("");
  const id = useId();
  const flow = record?.flow;
  const flowTime = flow && Number.isSafeInteger(flow.expires_at_unix_secs) ? formatTime(flow.expires_at_unix_secs, language) : t.notReady;
  const flowExpired = !!flow && Number.isSafeInteger(flow.expires_at_unix_secs) && flow.expires_at_unix_secs <= Date.now() / 1000;
  const isStart = record?.intent.kind === "recovery-start";
  const isComplete = record?.intent.kind === "recovery-complete";
  const canEnterCode = !!features?.recovery && !!record && record.stage === "ready" && (isStart || isComplete) && !!flow && !flowExpired;

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setFormError("");
    try { await workflow.startRecovery(email); }
    catch (error) { setFormError(messageFor((error as { code?: string })?.code, language)); }
    finally { setCode(""); setPassword(""); setConfirm(""); }
  }
  async function complete(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setFormError("");
    if (password !== confirm) { setFormError(t.passwordMismatch); return; }
    if (flowExpired) { setFormError(t.flowExpired); return; }
    try { await workflow.completeRecovery(code, password); }
    catch (error) { setFormError(messageFor((error as { code?: string })?.code, language)); }
    finally { setCode(""); setPassword(""); setConfirm(""); }
  }
  const showStart = !record && !snapshot.storageError;
  return <section className={styles.root} lang={language} aria-busy={snapshot.busy}>
    <header className={styles.header}><h2>{t.recovery}</h2>{onClose && <button type="button" className={styles.secondary} disabled={snapshot.busy} onClick={onClose}>{t.close}</button>}</header>
    {formError && <p className={styles.alert} role="alert">{formError}</p>}
    {snapshot.error && <p className={styles.alert} role="alert">{messageFor(snapshot.error, language)}</p>}
    {snapshot.storageError && <p className={styles.alert} role="alert">{t.storageError}</p>}
    {record?.stage === "completed" && <p className={styles.success} role="status">{t.completed}</p>}
    {record && record.stage !== "completed" && <p className={styles.status} role="status">{record.stage === "pending" ? t.unknown : t.ready}</p>}
    {record && flow && <p>{t.expires}: {flowTime}</p>}
    {flowExpired && <p className={styles.status} role="status">{t.flowExpired}</p>}
    {isComplete && record?.stage === "pending" && <p className={styles.status}>{t.unknown}</p>}
    {isStart && record?.stage === "pending" && !flow && <><p className={styles.status}>{t.pendingStart}</p>{features?.recovery && <button type="button" disabled={snapshot.busy} onClick={() => safeRun(() => workflow.retryStart())}>{t.retryStart}</button>}</>}
    {showStart && <>
      {!features?.recovery && <p className={styles.status}>{t.noRecovery}</p>}
      {features?.recovery && <><p className={styles.status}>{t.recoveryHint} {t.protected}</p>
        <form className={styles.form} onSubmit={event => void start(event)} aria-labelledby={`${id}-start`}>
          <label id={`${id}-start`} htmlFor={`${id}-email`}>{t.email}</label>
          <input id={`${id}-email`} type="email" autoComplete="email" required maxLength={254} disabled={snapshot.busy} value={email} onChange={event => setEmail(event.target.value)} />
          <button type="submit" disabled={snapshot.busy}>{t.start}</button>
        </form></>}
    </>}
    {canEnterCode && <form className={styles.form} onSubmit={event => void complete(event)} aria-labelledby={`${id}-complete`}>
      <h3 id={`${id}-complete`}>{t.complete}</h3>
      <label htmlFor={`${id}-code`}>{t.code}</label>
      <input id={`${id}-code`} inputMode="numeric" autoComplete="one-time-code" required pattern="[0-9]{6}" minLength={6} maxLength={6} disabled={snapshot.busy || flowExpired} value={code} onChange={event => setCode(event.target.value)} />
      <label htmlFor={`${id}-password`}>{t.codePassword}</label>
      <input id={`${id}-password`} type="password" autoComplete="new-password" required maxLength={4096} disabled={snapshot.busy || flowExpired} value={password} onChange={event => setPassword(event.target.value)} />
      <label htmlFor={`${id}-confirm`}>{t.codeConfirm}</label>
      <input id={`${id}-confirm`} type="password" autoComplete="new-password" required maxLength={4096} disabled={snapshot.busy || flowExpired} value={confirm} onChange={event => setConfirm(event.target.value)} />
      <button type="submit" disabled={snapshot.busy || flowExpired}>{t.complete}</button>
    </form>}
    {(record || snapshot.storageError) && <section className={styles.record} aria-label={t.status}>
      <h3>{t.status}</h3>
      <div className={styles.actions}>
        <button type="button" className={styles.secondary} disabled={snapshot.busy} onClick={() => safeRun(() => workflow.refresh())}>{t.refresh}</button>
        {record?.stage === "pending" && !isStart &&
          <button type="button" disabled={snapshot.busy} onClick={() => safeRun(() => workflow.checkResult())}>{t.result}</button>}
        {(record || snapshot.storageError) && <button type="button" className={styles.secondary} disabled={snapshot.busy} onClick={() => setConfirmDiscard(true)}>{snapshot.storageError && !record ? t.storageDiscard : record?.stage === "completed" ? t.closeRecord : t.discard}</button>}
      </div>
      {confirmDiscard && <div className={styles.confirm}><p>{record?.stage === "completed" ? t.closeRecordConfirm : t.discardConfirm}</p>
        <button type="button" disabled={snapshot.busy} onClick={() => safeRun(async () => { await workflow.discard(); setConfirmDiscard(false); setCode(""); setPassword(""); setConfirm(""); })}>{record?.stage === "completed" ? t.closeRecord : t.discard}</button>
        <button type="button" className={styles.secondary} onClick={() => setConfirmDiscard(false)}>{t.keep}</button>
      </div>}
    </section>}
  </section>;
}

export function PasswordRecovery(props: PasswordRecoveryProps) {
  const authSnapshot = useIdentity(props.identity);
  const owner = identityOf(authSnapshot.session);
  const workflowState = useWorkflow(props.identity, props.features, props.store);
  return <RecoveryView key={identityKey(owner, props.identity.accountSecurityScope)} {...props} workflow={workflowState.workflow} snapshot={workflowState.snapshot} />;
}
