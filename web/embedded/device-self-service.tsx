import { useEffect, useId, useRef, useState, useSyncExternalStore, type CSSProperties } from "react";
import type { DeviceOperationReceipt, DevicePage, EmbeddedDeviceClient, DeviceKeyMetadata, SubjectDevice, UnbindIntent } from "./device-client";
import styles from "./device-self-service.module.css";

type Language = "zh-CN" | "en-US";
const copy = {
  "zh-CN": {
    title: "我的设备", tenant: "当前租户", client: "身份入口", refresh: "刷新列表", loading: "正在读取设备…", empty: "当前登录身份没有已绑定设备。",
    detail: "查看详情", close: "收起详情", device: "设备", deviceState: "设备状态", bindingState: "本人绑定状态", key: "当前证明密钥 ID", keyVersion: "密钥版本", version: "设备版本", bindingVersion: "绑定版本", registered: "绑定时间", lastSeen: "最后活动",
    keyDetails: "查看密钥信息", keyUnavailable: "设备和本人绑定均启用时才可查询密钥信息。", keyAlgorithm: "算法", keyState: "密钥状态", keyRegistered: "登记时间", keyRetired: "退役时间", noKey: "设备尚无证明密钥。",
    unbind: "解除本人绑定", confirmTitle: "确认解除本人绑定？", confirmText: "此操作会解除当前账号与设备的绑定并撤销该绑定下的设备会话，不会删除设备或替代管理员吊销设备。", confirm: "确认解除", cancel: "取消", working: "正在提交…",
    pendingTitle: "核对解绑结果", pending: "操作结果未确认。请查询原操作回执；不要重复提交解绑。", queryReceipt: "查询原操作", receipt: "解绑回执已确认", receiptId: "操作 ID", receiptTime: "完成时间", receiptStatus: "结果", receiptVersion: "结果版本", audit: "审计 ID", notConfirmed: "尚未查到回执，操作结果仍未确认。稍后可继续查询。", noSession: "请先登录后查看本人设备。", noAccess: "当前身份无法读取设备信息。", loadError: "无法读取设备信息，请重试。", page: "页", previous: "上一页", next: "下一页", retry: "重试",
    status: { pending: "待完成", active: "启用", disabled: "已停用", revoked: "已撤销" }, binding: { active: "已绑定", suspended: "已暂停", unbound: "已解除" }, keyStatuses: { active: "当前", retired: "已退役" },
  },
  "en-US": {
    title: "My devices", tenant: "Current tenant", client: "Identity entry", refresh: "Refresh list", loading: "Loading devices…", empty: "No devices are bound to this signed-in identity.",
    detail: "View details", close: "Hide details", device: "Device", deviceState: "Device status", bindingState: "My binding", key: "Current proof key ID", keyVersion: "Key version", version: "Device version", bindingVersion: "Binding version", registered: "Bound at", lastSeen: "Last activity",
    keyDetails: "View key details", keyUnavailable: "Key details require an active device and an active binding.", keyAlgorithm: "Algorithm", keyState: "Key status", keyRegistered: "Registered", keyRetired: "Retired",
    noKey: "This device has no proof key yet.", unbind: "Unbind this device", confirmTitle: "Unbind this device?", confirmText: "This removes your account binding and revokes device sessions for this binding. It does not delete the device or replace an administrator revocation.", confirm: "Confirm unbind", cancel: "Cancel", working: "Submitting…",
    pendingTitle: "Check unbind result", pending: "The result is unconfirmed. Look up the original operation receipt; do not submit unbind again.", queryReceipt: "Look up original operation", receipt: "Unbind receipt confirmed", receiptId: "Operation ID", receiptTime: "Completed", receiptStatus: "Result", receiptVersion: "Result version", audit: "Audit ID", notConfirmed: "No receipt is available yet; the result remains unconfirmed. You can check again later.", noSession: "Sign in to view your devices.", noAccess: "This identity cannot read device details.", loadError: "Could not load device data. Try again.", page: "Page", previous: "Previous", next: "Next", retry: "Retry",
    status: { pending: "Pending", active: "Active", disabled: "Disabled", revoked: "Revoked" }, binding: { active: "Bound", suspended: "Suspended", unbound: "Unbound" }, keyStatuses: { active: "Active", retired: "Retired" },
  },
} as const;

export type DeviceSelfServiceProps = {
  client: EmbeddedDeviceClient;
  language?: Language;
  className?: string;
  style?: CSSProperties;
};

type Owned<T> = { scope: string; value: T };
const firstPage: (string | undefined)[] = [undefined];
function identityKey(clientId: number, session?: { tenant_id: string; account_id: string; client_id: string; session_id: string }, includeSession = true) {
  if (!session) return "";
  return JSON.stringify(includeSession
    ? [clientId, session.tenant_id, session.account_id, session.client_id, session.session_id]
    : [clientId, session.tenant_id, session.account_id, session.client_id]);
}
function label(value: string, table: Record<string, string>) { return table[value] ?? value; }
function date(value: number | null, language: Language) {
  if (value === null) return "—";
  const time = new Date(value * 1000);
  return Number.isNaN(time.valueOf()) ? "—" : new Intl.DateTimeFormat(language, { dateStyle: "medium", timeStyle: "short" }).format(time);
}

/** Displays the current person's device bindings and recovers unbind receipts. */
export function DeviceSelfService({ client, language = "zh-CN", className, style }: DeviceSelfServiceProps) {
  const text = copy[language];
  const identity = useSyncExternalStore(client.identity.subscribe, client.identity.getSnapshot, client.identity.getSnapshot);
  const clientIds = useRef<WeakMap<object, number> | null>(null);
  const nextClientId = useRef(1);
  if (!clientIds.current) clientIds.current = new WeakMap();
  let clientId = clientIds.current.get(client);
  if (!clientId) { clientId = nextClientId.current++; clientIds.current.set(client, clientId); }
  const scopeFor = (session?: typeof identity.session, includeSession = true) => identityKey(clientId!, session, includeSession);
  const scope = scopeFor(identity.session);
  const ownerScope = scopeFor(identity.session, false);
  const activeScope = useRef(scope);
  activeScope.current = scope;
  const [list, setList] = useState<Owned<DevicePage>>();
  const [listError, setListError] = useState<Owned<string>>();
  const [loading, setLoading] = useState(false);
  const [cursorState, setCursorState] = useState<Owned<(string | undefined)[]>>();
  const cursorStack = cursorState?.scope === scope ? cursorState.value : firstPage;
  const [selected, setSelected] = useState<Owned<SubjectDevice>>();
  const [keyMetadata, setKeyMetadata] = useState<Owned<DeviceKeyMetadata>>();
  const [intent, setIntent] = useState<{ ownerScope: string; value: UnbindIntent }>();
  const [receipt, setReceipt] = useState<Owned<DeviceOperationReceipt>>();
  const [confirming, setConfirming] = useState(false);
  const [busyScope, setBusyScope] = useState("");
  const [receiptLoadingScope, setReceiptLoadingScope] = useState("");
  const busy = busyScope === scope;
  const receiptLoading = receiptLoadingScope === scope;
  const [receiptMessage, setReceiptMessage] = useState("");
  const [operationError, setOperationError] = useState<Owned<string>>();
  const [notice, setNotice] = useState<Owned<string>>();
  const listRequest = useRef(0);
  const detailRequest = useRef(0);
  const mutationRequest = useRef(0);
  const receiptRequest = useRef(0);
  const mounted = useRef(false);
  const unbindInFlight = useRef(new Set<string>());
  const receiptInFlight = useRef(new Set<string>());
  const alertRef = useRef<HTMLParagraphElement>(null);
  const errorId = useId();
  const detailHeadingId = useId();
  const unbindHeadingId = useId();
  const receiptHeadingId = useId();

  const own = <T,>(value?: Owned<T>) => value?.scope === scope ? value.value : undefined;
  const currentList = own(list);
  const currentDevice = own(selected);
  const currentKey = own(keyMetadata);
  const currentIntent = intent?.ownerScope === ownerScope ? intent.value : undefined;
  const currentReceipt = own(receipt);
  const currentNotice = own(notice);
  const currentListError = own(listError);
  const currentOperationError = own(operationError);
  const hasSession = !!identity.session && !identity.selecting;

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      listRequest.current++; detailRequest.current++; mutationRequest.current++; receiptRequest.current++;
    };
  }, []);

  useEffect(() => {
    detailRequest.current++;
    mutationRequest.current++;
    receiptRequest.current++;
    setCursorState({ scope, value: firstPage });
    setSelected(undefined); setKeyMetadata(undefined);
    setListError(undefined); setOperationError(undefined);
    return () => { detailRequest.current++; };
  }, [scope]);

  const isCurrent = (startedScope: string, sequence: number, current: { current: number }) => {
    const snapshot = client.identity.getSnapshot();
    return mounted.current && !snapshot.selecting && current.current === sequence && activeScope.current === startedScope &&
      startedScope === scopeFor(snapshot.session);
  };

  useEffect(() => {
    const sequence = ++listRequest.current;
    if (!hasSession) { setLoading(false); return; }
    setLoading(true); setListError(undefined); setNotice(undefined);
    void client.list(cursorStack.at(-1)).then(value => {
      if (isCurrent(scope, sequence, listRequest)) setList({ scope, value });
    }).catch(() => {
      if (isCurrent(scope, sequence, listRequest)) setListError({ scope, value: text.loadError });
    }).finally(() => {
      if (isCurrent(scope, sequence, listRequest)) setLoading(false);
    });
    return () => { if (listRequest.current === sequence) listRequest.current++; };
  }, [client, scope, hasSession, cursorStack, text.loadError]);

  function changePage(cursor: string | undefined) {
    detailRequest.current++;
    setCursorState({ scope, value: [...cursorStack, cursor] });
    setSelected(undefined); setKeyMetadata(undefined);
  }

  async function showDetails(deviceId: string) {
    if (currentDevice?.device_id === deviceId) {
      detailRequest.current++; setSelected(undefined); setKeyMetadata(undefined); return;
    }
    const sequence = ++detailRequest.current;
    const startedScope = scope;
    setOperationError(undefined); setNotice(undefined); setKeyMetadata(undefined);
    try {
      const value = await client.detail(deviceId);
      if (isCurrent(startedScope, sequence, detailRequest)) setSelected({ scope: startedScope, value });
    } catch {
      if (isCurrent(startedScope, sequence, detailRequest)) setOperationError({ scope: startedScope, value: text.noAccess });
    }
  }

  async function showKey(device: SubjectDevice) {
    if (device.status !== "active" || device.binding_status !== "active") return;
    if (!device.proof_key_id) { setSelected({ scope, value: device }); setKeyMetadata(undefined); return; }
    const sequence = ++detailRequest.current;
    const startedScope = scope;
    setOperationError(undefined);
    try {
      const value = await client.keyMetadata(device.device_id, device.proof_key_id);
      if (isCurrent(startedScope, sequence, detailRequest)) {
        setSelected({ scope, value: device }); setKeyMetadata({ scope, value });
      }
    } catch {
      if (isCurrent(startedScope, sequence, detailRequest)) setOperationError({ scope: startedScope, value: text.noAccess });
    }
  }

  async function prepare(device: SubjectDevice) {
    if (currentIntent) return;
    const startedScope = scope;
    const sequence = ++mutationRequest.current;
    try {
      const value = await client.prepareUnbind(device);
      if (!isCurrent(startedScope, sequence, mutationRequest)) return;
      setIntent({ ownerScope, value }); setReceipt(undefined); setReceiptMessage(""); setOperationError(undefined); setConfirming(true);
    } catch {
      if (isCurrent(startedScope, sequence, mutationRequest)) setOperationError({ scope: startedScope, value: text.noAccess });
    }
  }

  async function refreshAfterOperation(startedScope: string, sequence: number, current: { current: number }) {
    if (!isCurrent(startedScope, sequence, current)) return;
    detailRequest.current++;
    const listSequence = ++listRequest.current;
    const currentRead = () => isCurrent(startedScope, sequence, current) && listRequest.current === listSequence;
    setSelected(undefined); setKeyMetadata(undefined);
    setList(undefined); setLoading(true); setListError(undefined);
    try {
      const refreshed = await client.list(cursorStack.at(-1));
      if (currentRead()) setList({ scope: startedScope, value: refreshed });
    } catch {
      if (currentRead()) setListError({ scope: startedScope, value: text.loadError });
    } finally {
      if (currentRead()) setLoading(false);
    }
  }

  async function submitUnbind() {
    if (!currentIntent || busy || confirming === false || unbindInFlight.current.has(scope)) return;
    const startedScope = scope;
    unbindInFlight.current.add(startedScope);
    const sequence = ++mutationRequest.current;
    setBusyScope(startedScope); setOperationError(undefined); setReceiptMessage(""); setConfirming(false);
    try {
      const value = await client.unbind(currentIntent);
      if (!isCurrent(startedScope, sequence, mutationRequest)) return;
      setReceipt({ scope: startedScope, value }); setReceiptMessage(""); setNotice({ scope: startedScope, value: text.receipt }); setIntent(undefined);
      if (selected?.scope === startedScope && selected.value.device_id === currentIntent.device_id) setSelected(undefined);
      if (keyMetadata?.scope === startedScope && keyMetadata.value.device_id === currentIntent.device_id) setKeyMetadata(undefined);
      await refreshAfterOperation(startedScope, sequence, mutationRequest);
    } catch (error) {
      if (!isCurrent(startedScope, sequence, mutationRequest)) return;
      setIntent({ ownerScope, value: currentIntent });
      const status = typeof error === "object" && error !== null && "status" in error ? Number(error.status) : undefined;
      setReceiptMessage(status === 404 ? text.notConfirmed : text.pending);
    } finally {
      unbindInFlight.current.delete(startedScope);
      if (isCurrent(startedScope, sequence, mutationRequest)) setBusyScope("");
    }
  }

  async function lookupReceipt() {
    if (!currentIntent || busy || receiptLoading || receiptInFlight.current.has(scope)) return;
    const startedScope = scope;
    receiptInFlight.current.add(startedScope);
    const sequence = ++receiptRequest.current;
    setReceiptLoadingScope(startedScope); setReceiptMessage(""); setOperationError(undefined);
    try {
      const value = await client.operationResult(currentIntent);
      if (!isCurrent(startedScope, sequence, receiptRequest)) return;
      setReceipt({ scope: startedScope, value }); setIntent(undefined); setReceiptMessage(""); setNotice({ scope: startedScope, value: text.receipt });
      if (selected?.scope === startedScope && selected.value.device_id === currentIntent.device_id) setSelected(undefined);
      if (keyMetadata?.scope === startedScope && keyMetadata.value.device_id === currentIntent.device_id) setKeyMetadata(undefined);
      await refreshAfterOperation(startedScope, sequence, receiptRequest);
    } catch (error) {
      if (!isCurrent(startedScope, sequence, receiptRequest)) return;
      const status = typeof error === "object" && error !== null && "status" in error ? Number(error.status) : undefined;
      setReceiptMessage(status === 404 ? text.notConfirmed : text.pending);
    } finally {
      receiptInFlight.current.delete(startedScope);
      if (isCurrent(startedScope, sequence, receiptRequest)) setReceiptLoadingScope("");
    }
  }

  useEffect(() => {
    if (currentListError || currentOperationError) alertRef.current?.focus();
  }, [currentListError, currentOperationError]);

  const rootClass = `${styles.root}${className ? ` ${className}` : ""}`;
  if (!hasSession) return <section className={rootClass} style={style} lang={language} aria-busy="false">
    <h2>{text.title}</h2><p className={styles.muted} role="status">{text.noSession}</p>
  </section>;

  return <section className={rootClass} style={style} lang={language} aria-busy={loading || busy || receiptLoading}>
    <div className={styles.header}>
      <div><h2>{text.title}</h2><p className={styles.muted}>{text.tenant}: {identity.session!.tenant_id} · {text.client}: {identity.session!.client_id}</p></div>
      <button type="button" className={styles.secondary} disabled={loading || busy} onClick={() => { listRequest.current++; detailRequest.current++; setListError(undefined); setList(undefined); setSelected(undefined); setKeyMetadata(undefined); setCursorState({ scope, value: [undefined] }); }}>{text.refresh}</button>
    </div>
    {currentListError && <p ref={alertRef} className={styles.alert} id={errorId} tabIndex={-1} role="alert">{currentListError} <button type="button" className={styles.secondary} onClick={() => { listRequest.current++; detailRequest.current++; setSelected(undefined); setKeyMetadata(undefined); setCursorState({ scope, value: [...cursorStack] }); }}>{text.retry}</button></p>}
    {currentOperationError && <p ref={alertRef} className={styles.alert} tabIndex={-1} role="alert">{currentOperationError}</p>}
    {currentNotice && <p className={styles.success} role="status">{currentNotice}</p>}
    {loading && <p className={styles.status} role="status">{text.loading}</p>}
    {currentList && !loading && currentList.items.length === 0 && <p className={styles.muted}>{text.empty}</p>}
    <ul className={styles.deviceList}>
      {currentList?.items.map(device => <li key={`${device.device_id}/${device.binding_id}`}>
        <div className={styles.deviceInfo}><strong>{device.device_name}</strong><span>{device.device_id}</span><span className={styles.badges}>
          <span className={styles.badge}>{text.deviceState}: {label(device.status, text.status)}</span>
          <span className={styles.badge}>{text.bindingState}: {label(device.binding_status, text.binding)}</span>
        </span></div>
        <div className={styles.actions}>
          <button type="button" className={styles.secondary} disabled={busy || receiptLoading} onClick={() => void showDetails(device.device_id)}>{currentDevice?.device_id === device.device_id ? text.close : text.detail}</button>
          {device.binding_status === "active" && <button type="button" className={styles.danger} disabled={busy || receiptLoading || !!currentIntent} onClick={() => void prepare(device)}>{text.unbind}</button>}
        </div>
      </li>)}
    </ul>
    {(cursorStack.length > 1 || currentList?.has_more) && <nav className={styles.pagination} aria-label={text.title}>
      <button type="button" className={styles.secondary} disabled={loading || cursorStack.length === 1} onClick={() => { detailRequest.current++; setCursorState({ scope, value: cursorStack.slice(0, -1) }); setSelected(undefined); setKeyMetadata(undefined); }}>{text.previous}</button>
      <span>{text.page} {cursorStack.length}</span>
      <button type="button" className={styles.secondary} disabled={loading || !currentList?.has_more || !currentList.next_cursor} onClick={() => currentList?.next_cursor && changePage(currentList.next_cursor)}>{text.next}</button>
    </nav>}
    {currentDevice && <section className={styles.detail} aria-labelledby={detailHeadingId}>
      <h3 id={detailHeadingId}>{text.device}: {currentDevice.device_name}</h3>
      <dl className={styles.fields}>
        <dt>{text.device}</dt><dd>{currentDevice.device_id}</dd>
        <dt>{text.deviceState}</dt><dd>{label(currentDevice.status, text.status)}</dd>
        <dt>{text.bindingState}</dt><dd>{label(currentDevice.binding_status, text.binding)}</dd>
        <dt>{text.version}</dt><dd>{currentDevice.version}</dd>
        <dt>{text.bindingVersion}</dt><dd>{currentDevice.binding_version}</dd>
        <dt>{text.key}</dt><dd>{currentDevice.proof_key_id ?? text.noKey}</dd>
        <dt>{text.keyVersion}</dt><dd>{currentDevice.key_version ?? "—"}</dd>
        <dt>{text.registered}</dt><dd>{date(currentDevice.registered_at_unix_secs, language)}</dd>
        <dt>{text.lastSeen}</dt><dd>{date(currentDevice.last_seen_at_unix_secs, language)}</dd>
      </dl>
      {currentDevice.proof_key_id && currentDevice.status === "active" && currentDevice.binding_status === "active" && <button type="button" className={styles.secondary} disabled={busy} onClick={() => void showKey(currentDevice)}>{text.keyDetails}</button>}
      {currentDevice.proof_key_id && (currentDevice.status !== "active" || currentDevice.binding_status !== "active") && <p className={styles.muted}>{text.keyUnavailable}</p>}
      {currentKey && <dl className={styles.fields}>
        <dt>{text.keyAlgorithm}</dt><dd>{currentKey.algorithm}</dd><dt>{text.keyState}</dt><dd>{label(currentKey.status, text.keyStatuses)}</dd>
        <dt>{text.keyRegistered}</dt><dd>{date(currentKey.registered_at_unix_secs, language)}</dd><dt>{text.keyRetired}</dt><dd>{date(currentKey.retired_at_unix_secs, language)}</dd>
      </dl>}
    </section>}
    {currentIntent && <section className={styles.confirm} aria-labelledby={unbindHeadingId}>
      <h3 id={unbindHeadingId}>{confirming ? text.confirmTitle : text.pendingTitle}</h3>
      {confirming ? <><p>{text.confirmText}</p><p className={styles.muted}>{currentIntent.device_id}</p><div className={styles.actions}>
        <button type="button" className={styles.danger} disabled={busy} onClick={() => void submitUnbind()}>{busy ? text.working : text.confirm}</button>
        <button type="button" className={styles.secondary} disabled={busy} onClick={() => { setConfirming(false); setIntent(undefined); }}>{text.cancel}</button>
      </div></> : <><p role="status">{receiptMessage || text.pending}</p><button type="button" className={styles.secondary} disabled={busy || receiptLoading} onClick={() => void lookupReceipt()}>{receiptLoading ? text.working : text.queryReceipt}</button></>}
    </section>}
    {currentReceipt && <section className={styles.success} aria-labelledby={receiptHeadingId}>
      <h3 id={receiptHeadingId}>{text.receipt}</h3>
      <dl className={styles.fields}><dt>{text.receiptId}</dt><dd>{currentReceipt.operation_id}</dd><dt>{text.device}</dt><dd>{currentReceipt.device_id}</dd>
        <dt>{text.receiptStatus}</dt><dd>{text.binding[currentReceipt.result_status]}</dd><dt>{text.receiptVersion}</dt><dd>{currentReceipt.result_version}</dd>
        <dt>{text.receiptTime}</dt><dd>{date(currentReceipt.occurred_at_unix_secs, language)}</dd><dt>{text.audit}</dt><dd>{currentReceipt.audit_id}</dd></dl>
    </section>}
  </section>;
}
