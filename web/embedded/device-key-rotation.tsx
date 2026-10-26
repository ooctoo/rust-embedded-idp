import { useEffect, useId, useRef, useState, useSyncExternalStore, type CSSProperties } from "react";
import type { DeviceKeyRotationClient } from "./device-key-rotation-client";
import type { IdentitySnapshot } from "./client";
import styles from "./device-key-rotation.module.css";

type Language = "zh-CN" | "en-US";
type Phase = "empty" | "prepared" | "rotate-unknown" | "active" | "abandoned";
type Snapshot = ReturnType<DeviceKeyRotationClient["getSnapshot"]>;
const text = {
  "zh-CN": {
    title: "轮换设备证明密钥", intro: "需要当前登录身份和当前、候选密钥共同签名。旧密钥在核对成功后仍由宿主持有。",
    unavailable: "密钥轮换不可用：请先登录，并由宿主提供当前设备、持钥签名器和安全恢复存储。",
    readState: "读取本地恢复记录",
    tenant: "租户", client: "客户端", entry: "入口", device: "设备", phase: "当前阶段", current: "轮换前密钥 ID", expected: "轮换前密钥版本", candidate: "候选密钥 ID", proposed: "候选密钥版本",
    name: "准备新密钥", prepare: "准备候选密钥", confirmPrepare: "确认准备新密钥", rotate: "双签并轮换", confirmRotate: "确认提交轮换", discard: "放弃未提交候选", confirmDiscard: "确认放弃候选密钥", recover: "查询当前设备密钥", retry: "使用同一候选重新签名", confirmRetry: "确认重新双签", reload: "读取恢复状态", cancel: "取消", working: "正在处理…", retryLoad: "重试读取",
    phases: { empty: "未准备", prepared: "候选已准备，尚未提交", "rotate-unknown": "轮换结果未确认", active: "候选密钥已核对为当前密钥", abandoned: "轮换已放弃" },
    empty: "准备操作会在宿主安全持钥设施中创建新的候选密钥。", pending: "未知结果时，先查询当前密钥。若旧密钥仍为当前密钥，可明确选择用同一候选和新挑战重试。不要放弃候选或删除旧密钥。",
    active: "上次核对已确认服务端当前密钥及版本。旧密钥仍由宿主持有，可按宿主保留策略处理。", abandoned: "候选已标记放弃；如需确认宿主清理状态，请联系宿主管理员。",
    errors: { generic: "操作未完成。请查询当前密钥后再决定下一步。", busy: "已有密钥操作正在进行。", disposed: "轮换流程已关闭，请重新打开。", not_authenticated: "请登录后操作设备密钥。", owner_changed: "当前登录身份已变化，请重新读取状态。", scope_changed: "轮换记录与当前入口不一致。", invalid_store: "恢复记录校验失败，已停止操作。", invalid_key: "候选公钥校验失败，请核对宿主持钥状态。", invalid_phase: "当前阶段不能执行此操作。", no_active_key: "当前设备没有可轮换的活动密钥。", binding_changed: "本人设备绑定已变化，请重新读取。", key_changed: "设备密钥版本已变化，请重新读取。", request_failed: "服务请求失败。请查询当前密钥状态。", network_unknown: "无法确认服务器响应。请查询当前密钥状态。", challenge_invalid: "没有取得有效轮换挑战，请查询当前密钥状态。", signature_invalid: "双签或期限校验失败，密钥均予以保留。", rotation_changed: "当前密钥已再次变化，请由原身份核对。", invalid_response: "服务器返回的数据未通过校验。", not_found: "当前身份无法读取此设备密钥。", operation_failed: "操作未完成。请查询当前密钥状态。", rotation_pending: "尚未核对候选密钥已经生效。" },
    },
  "en-US": {
    title: "Rotate device proof key", intro: "The signed-in identity and both old and candidate keys are required. The host retains the old key after verification.",
    unavailable: "Key rotation is unavailable. Sign in and have the host provide the device, signer, and recovery store.",
    readState: "Read local recovery record",
    tenant: "Tenant", client: "Client", entry: "Entry", device: "Device", phase: "Current phase", current: "Key ID before rotation", expected: "Key version before rotation", candidate: "Candidate key ID", proposed: "Candidate key version",
    name: "Prepare a new key", prepare: "Prepare candidate key", confirmPrepare: "Confirm key preparation", rotate: "Sign both keys and rotate", confirmRotate: "Confirm key rotation", discard: "Discard unsent candidate", confirmDiscard: "Confirm candidate discard", recover: "Check current device key", retry: "Sign again with same candidate", confirmRetry: "Confirm new signatures", reload: "Read recovery state", cancel: "Cancel", working: "Working…", retryLoad: "Retry read",
    phases: { empty: "Not prepared", prepared: "Candidate prepared, not submitted", "rotate-unknown": "Rotation result unknown", active: "Candidate verified as current", abandoned: "Registration abandoned" },
    empty: "Preparation creates a candidate key in the host's secure key facility.", pending: "For an unknown result, first check the current key. If the old key is still current, you can explicitly retry with the same candidate and a fresh challenge. Do not discard the candidate or delete the old key.",
    active: "The server's current key and version were checked. The host still retains the old key under its retention policy.", abandoned: "The candidate was marked abandoned. Ask the host to confirm its cleanup state.",
    errors: { generic: "The operation did not finish. Check the current key before choosing the next step.", busy: "A key operation is already running.", disposed: "The rotation flow is closed. Reopen it to continue.", not_authenticated: "Sign in before managing device keys.", owner_changed: "The signed-in identity changed. Read the state again.", scope_changed: "The rotation record does not match this entry.", invalid_store: "The recovery record failed validation. The operation stopped.", invalid_key: "Candidate key validation failed. Check the host key state.", invalid_phase: "This action is unavailable in the current phase.", no_active_key: "This device has no active key to rotate.", binding_changed: "The device binding changed. Read it again.", key_changed: "The device key version changed. Read it again.", request_failed: "The request failed. Check the current key state.", network_unknown: "The server response is unknown. Check the current key state.", challenge_invalid: "A valid rotation challenge is unavailable. Check the current key state.", signature_invalid: "Signature or deadline validation failed. Both keys are retained.", rotation_changed: "The current key changed again. Check it using the original identity.", invalid_response: "The server response failed validation.", not_found: "This identity cannot read the device key.", operation_failed: "The operation did not finish. Check the current key state.", rotation_pending: "The candidate has not been confirmed as active." },
  },
} as const;

export interface DeviceKeyRotationProps { client?: DeviceKeyRotationClient; language?: Language; className?: string; style?: CSSProperties }
const noSub = () => () => {};
const emptySnapshot: Snapshot = Object.freeze({ target: Object.freeze({ baseUrl: "", tenant_id: "", client_id: "", entry_id: "", device_id: "" }), phase: "empty", busy: false });
const emptyGet = () => emptySnapshot;
const emptyIdentity: IdentitySnapshot = Object.freeze({ selecting: false });
const emptyIdentityGet = () => emptyIdentity;
const initialLoads = new WeakMap<DeviceKeyRotationClient, Map<string, Promise<void>>>();
function initialLoad(client: DeviceKeyRotationClient, sessionKey: string) {
  let bySession = initialLoads.get(client);
  if (!bySession) { bySession = new Map(); initialLoads.set(client, bySession); }
  let pending = bySession.get(sessionKey);
  if (!pending) {
    pending = client.load(); bySession.set(sessionKey, pending);
    void pending.then(() => { if (bySession?.get(sessionKey) === pending) bySession.delete(sessionKey); },
      () => { if (bySession?.get(sessionKey) === pending) bySession.delete(sessionKey); });
  }
  return pending;
}
function safeError(code: unknown, language: Language) {
  const table = text[language].errors as Record<string, string>;
  return typeof code === "string" ? table[code] ?? table.generic : table.generic;
}

/** Optional rotation UI. The host owns all private key operations and persistence. */
export function DeviceKeyRotation({ client, language = "zh-CN", className, style }: DeviceKeyRotationProps) {
  const copy = text[language];
  const identity = useSyncExternalStore(client?.identity.subscribe ?? noSub, client?.identity.getSnapshot ?? emptyIdentityGet, client?.identity.getSnapshot ?? emptyIdentityGet);
  const identityStamp = identity.session ? JSON.stringify([identity.session.tenant_id, identity.session.account_id, identity.session.client_id, identity.session.session_id]) : "";
  const [loadedKey, setLoadedKey] = useState("");
  const [confirm, setConfirm] = useState<"prepare" | "rotate" | "retry" | "discard" | null>(null);
  const [localBusy, setLocalBusy] = useState(false);
  const [error, setError] = useState("");
  const generation = useRef(0);
  const liveClient = useRef(client);
  const liveStamp = useRef(identityStamp);
  const mounted = useRef(false);
  const heading = useId();
  const errorRef = useRef<HTMLDivElement>(null);
  if (liveClient.current !== client || liveStamp.current !== identityStamp) {
    liveClient.current = client; liveStamp.current = identityStamp; generation.current++;
    setLoadedKey(""); setConfirm(null); setLocalBusy(false); setError("");
  }
  useEffect(() => {
    let current = true; mounted.current = true;
    const expected = generation.current;
    if (client && identityStamp) void initialLoad(client, identityStamp).then(() => {
      if (current && mounted.current && liveClient.current === client && liveStamp.current === identityStamp && generation.current === expected)
        setLoadedKey(identityStamp);
    }).catch(value => {
      if (current && mounted.current && liveClient.current === client && liveStamp.current === identityStamp && generation.current === expected)
        setError(safeError((value as { code?: unknown })?.code, language));
    });
    return () => { current = false; mounted.current = false; };
  }, [client, identityStamp]);
  useEffect(() => { if (error) errorRef.current?.focus(); }, [error]);

  const snapshot = useSyncExternalStore(client?.subscribe ?? noSub, client?.getSnapshot ?? emptyGet, client?.getSnapshot ?? emptyGet);
  const ready = !!client && !!identityStamp && loadedKey === identityStamp;
  const busy = localBusy || snapshot.busy;
  const target = snapshot.target;
  const sameScope = !!identity.session && identity.session.tenant_id === target.tenant_id && identity.session.client_id === target.client_id &&
    client?.identity.deviceBaseUrl === target.baseUrl;
  async function run(operation: (value: DeviceKeyRotationClient) => Promise<void>, needsReady = true) {
    const value = liveClient.current; const expected = generation.current;
    if (!value || needsReady && !ready || !sameScope || busy) return;
    setLocalBusy(true); setError("");
    try { await operation(value); if (mounted.current && liveClient.current === value && generation.current === expected) setLoadedKey(identityStamp); }
    catch (cause) { if (mounted.current && liveClient.current === value && generation.current === expected) setError(safeError((cause as { code?: unknown })?.code, language)); }
    finally { if (mounted.current && liveClient.current === value && generation.current === expected) setLocalBusy(false); }
  }
  const phase = snapshot.phase as Phase;
  const phases = copy.phases as Record<Phase, string>;
  const unavailable = !client || !identityStamp || !sameScope;
  const failure = error || (snapshot.error ? safeError(snapshot.error, language) : "");
  const confirmText = confirm === "prepare" ? copy.confirmPrepare : confirm === "discard" ? copy.confirmDiscard : confirm === "retry" ? copy.confirmRetry : copy.confirmRotate;
  return <section className={`${styles.root} ${className ?? ""}`} style={style} aria-labelledby={heading}>
    <header className={styles.header}><div><h2 id={heading}>{copy.title}</h2><p className={styles.muted}>{copy.intro}</p></div></header>
    {unavailable ? <p className={styles.alert} role="status">{copy.unavailable}</p> : <>
      <dl className={styles.fields} aria-label={copy.phase}>
        <dt>{copy.tenant}</dt><dd>{target.tenant_id}</dd><dt>{copy.client}</dt><dd>{target.client_id}</dd><dt>{copy.entry}</dt><dd>{target.entry_id}</dd><dt>{copy.device}</dt><dd>{target.device_id}</dd>
        <dt>{copy.phase}</dt><dd><span className={styles.badge} role="status">{phases[phase] ?? phases.empty}</span></dd>
        {snapshot.expected_key_id && <><dt>{copy.current}</dt><dd>{snapshot.expected_key_id}</dd></>}
        {snapshot.expected_key_version !== undefined && <><dt>{copy.expected}</dt><dd>{snapshot.expected_key_version}</dd></>}
        {snapshot.key_id && <><dt>{copy.candidate}</dt><dd>{snapshot.key_id}</dd></>}
        {snapshot.new_key_version !== undefined && <><dt>{copy.proposed}</dt><dd>{snapshot.new_key_version}</dd></>}
      </dl>
      {!ready && <p className={styles.status} role="status">{failure || copy.reload}</p>}
      {ready && phase === "empty" && <div className={styles.actions}>
        <button type="button" disabled={busy} onClick={() => setConfirm("prepare")}>{copy.prepare}</button>
      </div>}
      {ready && phase === "prepared" && <div className={styles.actions}>
        <button type="button" disabled={busy} onClick={() => setConfirm("rotate")}>{copy.rotate}</button>
        <button type="button" className={styles.danger} disabled={busy} onClick={() => setConfirm("discard")}>{copy.discard}</button>
      </div>}
      {ready && phase === "rotate-unknown" && <div className={styles.detail}>
        <p>{copy.pending}</p>
        <div className={styles.actions}>
          <button type="button" className={styles.secondary} disabled={busy} onClick={() => void run(value => value.recover())}>{copy.recover}</button>
          <button type="button" disabled={busy} onClick={() => setConfirm("retry")}>{copy.retry}</button>
        </div>
      </div>}
      {ready && phase === "active" && <p className={styles.success}>{copy.active}</p>}
      {ready && phase === "abandoned" && <p className={styles.status}>{copy.abandoned}</p>}
      {ready && <div className={styles.footer}><button type="button" className={styles.secondary} disabled={busy} onClick={() => void run(value => value.load(), false)}>{copy.readState}</button></div>}
      {confirm && ready && <div className={styles.confirm} role="group" aria-label={confirmText}>
        <p>{confirmText}</p>
        <div className={styles.actions}><button type="button" disabled={busy} onClick={() => {
          const action = confirm; setConfirm(null);
          if (action === "prepare") void run(value => value.prepare());
          else if (action === "discard") void run(value => value.discard());
          else void run(value => value.rotate());
        }}>{confirmText}</button><button type="button" className={styles.secondary} disabled={busy} onClick={() => setConfirm(null)}>{copy.cancel}</button></div>
      </div>}
      {failure && <div ref={errorRef} className={styles.alert} role="alert" tabIndex={-1}>{failure}<button type="button" className={styles.inlineButton} disabled={busy} onClick={() => void run(value => value.load(), false)}>{copy.retryLoad}</button></div>}
    </>}
  </section>;
}
