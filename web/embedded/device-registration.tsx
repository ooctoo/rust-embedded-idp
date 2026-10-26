import { useEffect, useId, useRef, useState, useSyncExternalStore, type CSSProperties } from "react";
import type { DeviceRegistrationClient } from "./device-registration-client";
import styles from "./device-registration.module.css";

type Language = "zh-CN" | "en-US";
type Phase = "empty" | "prepared" | "provision-unknown" | "pending" | "complete-unknown" | "active" | "abandoned";
type Snapshot = ReturnType<DeviceRegistrationClient["getSnapshot"]>;

const copy = {
  "zh-CN": {
    title: "登记此设备", intro: "登记设备证明密钥。此流程不需要先登录个人账号。", unavailable: "设备登记暂不可用：宿主未提供登记客户端、持钥签名器、准入或持久存储能力。",
    target: "登记目标", tenant: "租户", client: "客户端", entry: "入口", device: "设备", phase: "当前阶段", key: "公开密钥 ID", name: "设备名称",
    prepare: "准备登记", confirmPrepare: "确认准备密钥", cancel: "取消", preparing: "正在准备…", provision: "提交登记", recover: "查询登记结果", retryProvision: "查询后重试原登记", complete: "继续完成登记", discard: "放弃未提交的候选密钥", confirmDiscard: "确认放弃候选密钥", working: "正在处理…", load: "读取本地恢复状态", retry: "重试",
    phases: { empty: "尚未准备", prepared: "已准备，尚未提交", "provision-unknown": "登记提交结果未确认", pending: "服务端待完成", "complete-unknown": "完成请求结果未确认", active: "登记已完成", abandoned: "登记已放弃" },
    active: "设备登记与持钥状态已核对。接下来仍需使用此设备完成登录，才会建立个人账号与设备的关系。", pending: "服务器已建立待完成登记；请继续完成持钥证明。", unknown: "远端结果尚未确认。查询会重新读取原登记记录；只有明确查无记录时，重试操作才会提交原登记请求。", empty: "准备会在宿主持钥设施中创建候选密钥。", abandoned: "登记已放弃；候选密钥清理状态需由宿主核对。", needName: "请填写设备名称。", loading: "正在读取本地恢复状态…", errors: { generic: "操作未完成。请读取恢复状态后再决定下一步。", disposed: "客户端已关闭，请重新打开登记流程。", busy: "已有登记操作正在进行。", invalid_target: "登记目标配置无效。", invalid_store: "登记恢复记录无效，已停止操作。", invalid_key: "候选公钥校验失败，请由宿主核对候选密钥状态。", invalid_name: "设备名称无效。", existing_registration: "此设备已有登记记录，请读取现有恢复状态。", invalid_phase: "当前阶段不支持此操作。", invalid_response: "服务器响应未通过校验，候选密钥仍保留。", registration_changed: "服务器登记状态已变化，请重新读取结果。", admission_invalid: "宿主未能确认当前登记准入。", admission_expired: "登记准入已过期，请重新取得宿主授权。", scope_changed: "准入范围已变化，不能恢复此登记。", registration_pending: "服务器尚未确认登记完成。", registration_expired: "登记或挑战已过期，请读取登记状态。", challenge_invalid: "无法取得有效的登记挑战，请读取登记状态。", signature_invalid: "签名或挑战有效期校验失败，候选密钥仍保留。", cannot_discard: "此阶段不能放弃候选密钥。", request_failed: "服务器请求失败。请读取恢复状态。", network_unknown: "无法确认服务器响应，请读取恢复状态。", not_found: "暂未查到登记结果；这不代表原请求没有在途。", operation_failed: "操作未完成。请读取恢复状态后再决定下一步。" },
  },
  "en-US": {
    title: "Register this device", intro: "Register a device proof key. A personal sign-in is not required first.", unavailable: "Device registration is unavailable because the host has not supplied the client, signer, admission, or durable store.",
    target: "Registration target", tenant: "Tenant", client: "Client", entry: "Entry", device: "Device", phase: "Current phase", key: "Public key ID", name: "Device name",
    prepare: "Prepare registration", confirmPrepare: "Confirm key preparation", cancel: "Cancel", preparing: "Preparing…", provision: "Submit registration", recover: "Check registration result", retryProvision: "Check, then retry original request", complete: "Continue registration", discard: "Discard unsent candidate key", confirmDiscard: "Confirm candidate discard", working: "Working…", load: "Read recovery state", retry: "Retry",
    phases: { empty: "Not prepared", prepared: "Prepared, not submitted", "provision-unknown": "Submission result unknown", pending: "Pending on server", "complete-unknown": "Completion result unknown", active: "Registration complete", abandoned: "Registration abandoned" },
    active: "The server registration and host key state were checked. The device still needs to sign in before it is linked to a personal account.", pending: "The server has a pending registration. Continue with the device proof.", unknown: "The remote result is unknown. Check reads the original registration; retry submits the same request only after the server reports no record.", empty: "Preparation creates a candidate key in the host key facility.", abandoned: "Registration was abandoned; the host must confirm candidate key cleanup.", needName: "Enter a device name.", loading: "Reading local recovery state…", errors: { generic: "The operation did not finish. Read recovery state before choosing the next step.", disposed: "The client is closed. Reopen the registration flow.", busy: "A registration operation is already running.", invalid_target: "The registration target is invalid.", invalid_store: "The recovery record is invalid. The operation was stopped.", invalid_key: "The candidate public key failed validation. Ask the host to check its key state.", invalid_name: "The device name is invalid.", existing_registration: "A registration record already exists. Read its recovery state.", invalid_phase: "This action is not available in the current phase.", invalid_response: "The server response failed validation. The candidate key is retained.", registration_changed: "The server registration changed. Read its current result.", admission_invalid: "The host could not confirm registration admission.", admission_expired: "Registration admission expired. Obtain host authorization again.", scope_changed: "Admission scope changed; this registration cannot be recovered.", registration_pending: "The server has not confirmed registration completion.", registration_expired: "The registration or challenge expired. Read registration state.", challenge_invalid: "A valid registration challenge is unavailable. Read registration state.", signature_invalid: "The signature or challenge validity check failed. The candidate key is retained.", cannot_discard: "The candidate key cannot be discarded in this phase.", request_failed: "The server request failed. Read recovery state.", network_unknown: "The server response is unknown. Read recovery state.", not_found: "No registration result was found yet; the original request may still be in flight.", operation_failed: "The operation did not finish. Read recovery state before choosing the next step." },
  },
} as const;

export type DeviceRegistrationProps = { client?: DeviceRegistrationClient; language?: Language; className?: string; style?: CSSProperties };
const emptySubscribe = () => () => {};
const EMPTY_SNAPSHOT: Snapshot = Object.freeze({ target: Object.freeze({ baseUrl: "", tenant_id: "", client_id: "", entry_id: "", device_id: "" }), phase: "empty", busy: false });
const getEmptySnapshot = () => EMPTY_SNAPSHOT;
const initialLoads = new WeakMap<DeviceRegistrationClient, Promise<void>>();

function initialLoad(client: DeviceRegistrationClient) {
  let pending = initialLoads.get(client);
  if (!pending) {
    pending = client.load();
    initialLoads.set(client, pending);
    void pending.then(
      () => { if (initialLoads.get(client) === pending) initialLoads.delete(client); },
      () => { if (initialLoads.get(client) === pending) initialLoads.delete(client); },
    );
  }
  return pending;
}

function safeError(code: unknown, language: Language) {
  const errors = copy[language].errors as Record<string, string>;
  return typeof code === "string" ? errors[code] ?? errors.generic : errors.generic;
}

/** Standalone registration flow for an unauthenticated device setup surface. */
export function DeviceRegistration({ client, language = "zh-CN", className, style }: DeviceRegistrationProps) {
  const text = copy[language];
  const snapshot = useSyncExternalStore(client?.subscribe ?? emptySubscribe, client?.getSnapshot ?? getEmptySnapshot, client?.getSnapshot ?? getEmptySnapshot);
  const [deviceName, setDeviceName] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [localBusy, setLocalBusy] = useState(false);
  const [localError, setLocalError] = useState("");
  const [loadedFor, setLoadedFor] = useState<DeviceRegistrationClient | null>(null);
  const headingId = useId();
  const errorRef = useRef<HTMLDivElement>(null);
  const liveClient = useRef(client);
  const generation = useRef(0);
  const mounted = useRef(false);
  if (liveClient.current !== client) {
    liveClient.current = client;
    generation.current++;
    setDeviceName(""); setConfirming(false); setLocalBusy(false); setLocalError(""); setLoadedFor(null);
  }

  useEffect(() => {
    let current = true;
    mounted.current = true;
    const expectedGeneration = generation.current;
    if (client) void initialLoad(client).then(() => {
      if (current && liveClient.current === client && generation.current === expectedGeneration) setLoadedFor(client);
    }).catch(() => {
      if (current && liveClient.current === client && generation.current === expectedGeneration) setLocalError(text.errors.generic);
    });
    return () => { current = false; mounted.current = false; };
  }, [client]);

  useEffect(() => { if (localError) errorRef.current?.focus(); }, [localError]);

  async function run(operation: (value: DeviceRegistrationClient) => Promise<void>) {
    const current = liveClient.current;
    if (!current || localBusy || snapshot.busy) return;
    const expectedGeneration = generation.current;
    setLocalBusy(true);
    setLocalError("");
    try {
      await operation(current);
      if (liveClient.current === current && generation.current === expectedGeneration && mounted.current) setLoadedFor(current);
    } catch (error) {
      if (liveClient.current === current && generation.current === expectedGeneration && mounted.current)
        setLocalError(safeError((error as { code?: unknown })?.code, language));
    } finally {
      if (liveClient.current === current && generation.current === expectedGeneration && mounted.current) setLocalBusy(false);
    }
  }

  const busy = localBusy || snapshot.busy;
  const target = snapshot.target;
  const phase = snapshot.phase as Phase;
  const ready = loadedFor === client;
  const phaseLabel = (text.phases as Record<Phase, string>)[phase] ?? text.phases.empty;
  const failure = localError || (snapshot.error ? safeError(snapshot.error, language) : "");

  return <section className={`${styles.root} ${className ?? ""}`} style={style} aria-labelledby={headingId}>
    <header className={styles.header}><div><h2 id={headingId}>{text.title}</h2><p className={styles.muted}>{text.intro}</p></div></header>
    {!client ? <p className={styles.alert} role="status">{text.unavailable}</p> : <>
      <dl className={styles.fields} aria-label={text.target}>
        <dt>{text.tenant}</dt><dd>{target.tenant_id}</dd><dt>{text.client}</dt><dd>{target.client_id}</dd>
        <dt>{text.entry}</dt><dd>{target.entry_id}</dd><dt>{text.device}</dt><dd>{target.device_id}</dd>
        <dt>{text.phase}</dt><dd><span className={styles.badge} role="status">{phaseLabel}</span></dd>
        {snapshot.key_id && <><dt>{text.key}</dt><dd>{snapshot.key_id}</dd></>}
      </dl>
      {phase === "empty" && <div className={styles.form}>
        <label htmlFor={`${headingId}-name`}>{text.name}</label>
        <input id={`${headingId}-name`} value={deviceName} maxLength={256} autoComplete="off" onChange={event => setDeviceName(event.target.value)} disabled={busy} />
        {!ready && <p className={styles.status} role="status">{failure || text.loading}</p>}
        {confirming ? <div className={styles.actions}>
          <button type="button" disabled={busy || !ready || !!failure} onClick={() => { setConfirming(false); void run(value => value.prepare(deviceName)); }}>{busy ? text.preparing : text.confirmPrepare}</button>
          <button type="button" className={styles.secondary} disabled={busy} onClick={() => setConfirming(false)}>{text.cancel}</button>
        </div> : <button type="button" disabled={busy || !ready || !!failure || !deviceName.trim()} onClick={() => deviceName.trim() ? setConfirming(true) : setLocalError(text.needName)}>{text.prepare}</button>}
        <p className={styles.muted}>{text.empty}</p>
      </div>}
      {phase === "prepared" && <div className={styles.actions}>
        <button type="button" disabled={busy} onClick={() => void run(value => value.provision())}>{busy ? text.working : text.provision}</button>
        <button type="button" className={styles.danger} disabled={busy} onClick={() => setConfirming(true)}>{text.discard}</button>
        {confirming && <div className={styles.confirm} role="group" aria-label={text.confirmDiscard}>
          <button type="button" className={styles.danger} disabled={busy} onClick={() => { setConfirming(false); void run(value => value.discard()); }}>{text.confirmDiscard}</button>
          <button type="button" className={styles.secondary} disabled={busy} onClick={() => setConfirming(false)}>{text.cancel}</button>
        </div>}
      </div>}
      {(phase === "provision-unknown" || phase === "complete-unknown") && <div className={styles.detail}>
        <p>{text.unknown}</p>
        <div className={styles.actions}>
          <button type="button" className={styles.secondary} disabled={busy} onClick={() => void run(value => value.recover())}>{text.recover}</button>
          {phase === "provision-unknown" && <button type="button" disabled={busy} onClick={() => void run(value => value.retryProvision())}>{text.retryProvision}</button>}
          {phase === "complete-unknown" && <button type="button" disabled={busy} onClick={() => void run(value => value.complete())}>{text.complete}</button>}
        </div>
      </div>}
      {phase === "pending" && <div className={styles.detail}>
        <p>{text.pending}</p>
        <div className={styles.actions}>
          <button type="button" className={styles.secondary} disabled={busy} onClick={() => void run(value => value.recover())}>{text.recover}</button>
          <button type="button" disabled={busy} onClick={() => void run(value => value.complete())}>{text.complete}</button>
        </div>
      </div>}
      {phase === "active" && <p className={styles.success}>{text.active}</p>}
      {phase === "abandoned" && <p className={styles.status}>{text.abandoned}</p>}
      <div className={styles.footer}><button type="button" className={styles.secondary} disabled={busy} onClick={() => void run(value => value.load())}>{busy ? text.working : text.load}</button></div>
      {failure && <div ref={errorRef} className={styles.alert} role="alert" tabIndex={-1}>{failure}<button type="button" className={styles.inlineButton} disabled={busy} onClick={() => void run(value => value.load())}>{text.retry}</button></div>}
    </>}
  </section>;
}
