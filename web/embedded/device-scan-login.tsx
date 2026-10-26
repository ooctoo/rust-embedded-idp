import { useEffect, useId, useRef, useState, useSyncExternalStore, type CSSProperties } from "react";
import type { DeviceScanClient } from "./device-scan-client";
import { validScanCode } from "./scan-login-protocol";
import { ScanSourceEntry } from "./scan-source-entry";
import styles from "./device-scan-login.module.css";

type Language = "zh-CN" | "en-US";
type Phase = "empty" | "origin-unknown" | "waiting" | "exchange-unknown" | "pending" | "ack-unknown" | "active" | "closing" | "closed";
type Snapshot = ReturnType<DeviceScanClient["getSnapshot"]>;
type Action = "create" | "claim" | "retry-origin" | "exchange" | "acknowledge" | "cancel";

export interface ScanCodeRenderer { render(element: Element, value: string, kind: "qr" | "barcode"): void; clear(element: Element): void; }

const text = {
  "zh-CN": {
    title: "扫码登录", intro: "请在可信手机页面核对这台设备并明确批准。扫码或认领短码本身不代表批准。",
    unavailable: "扫码登录暂不可用：需要宿主提供设备证明签名、保护存储和会话激活能力。",
    target: "登录目标", tenant: "租户", client: "客户端", entry: "入口", device: "设备", phase: "当前阶段", mode: "扫码方向", directions: { device_display: "设备展示码", phone_display: "手机展示码" },
    create: "显示设备码", claim: "输入手机码", codeLabel: "手机显示的 P1 短码", createQr: "设备展示码", source: "手机确认页面",
    query: "查询状态", lookup: "恢复原操作", retryOrigin: "重试原扫码发起", retryCancel: "重试取消", exchange: "领取待激活会话", acknowledge: "确认接收并激活", cancel: "取消此扫码登录",
    confirm: { create: "确认发起设备展示登录？手机仍需核对设备并批准。", claim: "确认使用该手机短码认领？手机仍需核对设备并批准。", "retry-origin": "确认使用同一操作标识重试原扫码发起？", exchange: "确认领取已批准的Pending会话？本步骤仍不会开放业务访问。", acknowledge: "确认已安全保存交付，并请求服务器激活此会话？", cancel: "确认取消并关闭原始扫码操作？" },
    yes: "确认继续", no: "返回", working: "正在处理…", retryLoad: "重试读取恢复记录", reload: "读取本地恢复记录",
    phases: { empty: "尚未开始", "origin-unknown": "扫码发起结果未确认", waiting: "等待手机明确批准", "exchange-unknown": "领取结果未确认", pending: "Pending会话已安全保存，尚未激活", "ack-unknown": "接收确认结果未确认", active: "服务器已确认激活", closing: "正在关闭原扫码操作", closed: "扫码登录已取消" },
    states: { waiting_user: "等待手机扫码", waiting_device: "等待目标设备", awaiting_approval: "手机正在核对目标", approved: "手机已批准，可领取交付", issued: "交付已生成，等待恢复", denied: "手机已拒绝", cancelled: "服务端已取消", expired: "扫码授权已过期", invalidated: "扫码授权已撤销" },
    pending: "Pending会话不可用于业务访问。请确认宿主已经保护保存了交付，再明确确认接收；ACK后还须由宿主验证服务器当前session。",
    active: "服务器确认ACK。宿主仍需用状态化验证确认session当前有效后才开放业务访问。",
    closed: "原始扫码操作已关闭。可读取关闭状态，不能复用原操作ID。", noRenderer: "当前宿主没有二维码渲染器，请使用显示的短码或接入现有码渲染器。",
    errors: {
      generic: "操作未完成。请查询或恢复原扫码操作。", busy: "已有扫码操作正在进行。", disposed: "扫码流程已关闭，请重新打开。", invalid_target: "扫码入口配置无效。", invalid_store: "扫码恢复记录无效，已停止操作。", missing_adapter: "扫码安全能力不完整。", existing_operation: "已有扫码操作，请先恢复或关闭原操作。", invalid_phase: "当前阶段不支持此操作。", invalid_code: "短码格式无效。", invalid_response: "扫码服务响应未通过校验。", network_unknown: "无法确认服务器响应；保留原操作并查询状态。", request_failed: "请求失败；保留恢复材料。", not_found: "暂未找到原操作；不能因此开始新的扫码登录。", scan_not_found: "服务端暂未找到原扫码操作；可重试原发起动作。", expired: "扫码材料已过期，请读取当前操作状态。", origin_mismatch: "扫码结果不属于原始操作。", delivery_mismatch: "交付与原操作不匹配，材料仍保留供核对。", admission_denied: "宿主当前准入未通过。", operation_failed: "操作未完成；原扫码材料已保留。", already_acknowledged: "服务器已确认接收；正在核对原交付。", session_required: "宿主没有可恢复的会话材料。", verification_url: "手机确认地址校验失败。",
    },
  },
  "en-US": {
    title: "Scan to sign in", intro: "Review this device and explicitly approve it on a trusted phone. Scanning or claiming a code does not approve access.",
    unavailable: "Scan sign-in is unavailable. The host must provide device signing, protected storage, and session activation.",
    target: "Sign-in target", tenant: "Tenant", client: "Client", entry: "Entry", device: "Device", phase: "Current phase", mode: "Scan direction", directions: { device_display: "Device displays code", phone_display: "Phone displays code" },
    create: "Show device code", claim: "Enter phone code", codeLabel: "P1 code shown on the phone", createQr: "Device display code", source: "Phone confirmation page",
    query: "Check status", lookup: "Recover original operation", retryOrigin: "Retry original start", retryCancel: "Retry cancellation", exchange: "Receive pending session", acknowledge: "Confirm receipt and activate", cancel: "Cancel this scan sign-in",
    confirm: { create: "Start device-display sign-in? A phone must still review and approve this device.", claim: "Claim this phone code? A phone must still review and approve this device.", "retry-origin": "Retry the original scan start with its original operation identity?", exchange: "Receive the approved pending session? Business access remains unavailable at this stage.", acknowledge: "Confirm the bundle is safely stored and ask the server to activate this session?", cancel: "Cancel and close the original scan operation?" },
    yes: "Confirm", no: "Back", working: "Working…", retryLoad: "Retry loading recovery state", reload: "Read local recovery record",
    phases: { empty: "Not started", "origin-unknown": "Start result unknown", waiting: "Waiting for explicit phone approval", "exchange-unknown": "Delivery result unknown", pending: "Pending session saved, not active", "ack-unknown": "Receipt result unknown", active: "Server acknowledged activation", closing: "Closing original scan operation", closed: "Scan sign-in cancelled" },
    states: { waiting_user: "Waiting for phone scan", waiting_device: "Waiting for target device", awaiting_approval: "Phone is reviewing the target", approved: "Phone approved; delivery can be received", issued: "Delivery created; recover it", denied: "Phone denied the request", cancelled: "Cancelled on the server", expired: "Scan authorization expired", invalidated: "Scan authorization revoked" },
    pending: "A pending session cannot access business services. Confirm the host safely stored the bundle before confirming receipt; after ACK the host must check that the server session remains active.",
    active: "The server acknowledged receipt. The host must still validate the live session before enabling business access.",
    closed: "The original scan operation is closed. Check its result; do not reuse its operation ID.", noRenderer: "No QR renderer is configured. Use the displayed code or connect the existing code renderer.",
    errors: { generic: "The operation did not finish. Check or recover the original scan.", busy: "A scan operation is already running.", disposed: "The scan flow is closed. Reopen it to continue.", invalid_target: "The scan entry is invalid.", invalid_store: "The scan recovery record is invalid; the operation stopped.", missing_adapter: "The required scan security capability is unavailable.", existing_operation: "A scan operation already exists. Recover or close it first.", invalid_phase: "This action is unavailable in the current phase.", invalid_code: "The code format is invalid.", invalid_response: "The scan service response failed validation.", network_unknown: "The server response is unknown. Keep the original operation and check its status.", request_failed: "The request failed. Recovery material is retained.", not_found: "The original operation was not found yet. Do not start another scan.", scan_not_found: "The server has not found the original scan yet. You can retry its original start action.", expired: "Scan material expired. Read the current operation status.", origin_mismatch: "The scan result does not match the original operation.", delivery_mismatch: "The delivery does not match the original operation. Material is retained for review.", admission_denied: "Current host admission did not pass.", operation_failed: "The operation did not finish. Original scan material is retained.", already_acknowledged: "The server acknowledged receipt. Checking the original delivery.", session_required: "The host has no recoverable session bundle.", verification_url: "The phone confirmation URL failed validation." },
  },
} as const;

export type DeviceScanLoginProps = { client?: DeviceScanClient; renderer?: ScanCodeRenderer; language?: Language; className?: string; style?: CSSProperties };
const emptySubscribe = () => () => {};
const EMPTY: Snapshot = Object.freeze({ target: Object.freeze({ baseUrl: "", tenant_id: "", client_id: "", entry_id: "", device_id: "", audience: "", verification_uri: "" }), phase: "empty", busy: false });
const emptySnapshot = () => EMPTY;
const initialLoads = new WeakMap<DeviceScanClient, Promise<void>>();
function loadOnce(client: DeviceScanClient) {
  let load = initialLoads.get(client);
  if (!load) { load = client.load(); initialLoads.set(client, load); void load.then(() => { if (initialLoads.get(client) === load) initialLoads.delete(client); }, () => { if (initialLoads.get(client) === load) initialLoads.delete(client); }); }
  return load;
}
const phaseLabels = (language: Language) => text[language].phases as Record<Phase, string>;
function safeError(value: unknown, language: Language) { const errors = text[language].errors as Record<string, string>; return typeof value === "string" ? errors[value] ?? errors.generic : errors.generic; }
function date(seconds: number, language: Language) { try { return new Intl.DateTimeFormat(language, { dateStyle: "medium", timeStyle: "short" }).format(new Date(seconds * 1000)); } catch { return "—"; } }

/** Embeddable device-side scan flow. It owns no credentials or durable storage itself. */
export function DeviceScanLogin({ client, renderer, language = "zh-CN", className, style }: DeviceScanLoginProps) {
  const copy = text[language];
  const snapshot = useSyncExternalStore(client?.subscribe ?? emptySubscribe, client?.getSnapshot ?? emptySnapshot, client?.getSnapshot ?? emptySnapshot);
  const [loaded, setLoaded] = useState<DeviceScanClient | null>(null);
  const [code, setCode] = useState("");
  const [confirm, setConfirm] = useState<Action | null>(null);
  const [claimPending, setClaimPending] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [originNotFound, setOriginNotFound] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const clientGeneration = useRef(0);
  const activeClient = useRef(client);
  const mounted = useRef(false);
  const heading = useId();
  const canvas = useRef<HTMLDivElement>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  if (activeClient.current !== client) {
    activeClient.current = client;
    clientGeneration.current++;
    setLoaded(null); setCode(""); setConfirm(null); setClaimPending(false); setBusy(false); setError(""); setOriginNotFound(false);
  }
  useEffect(() => {
    let current = true; mounted.current = true;
    const generation = clientGeneration.current;
    if (client) void loadOnce(client).then(() => {
      if (current && mounted.current && activeClient.current === client && clientGeneration.current === generation) setLoaded(client);
    }).catch(cause => {
      if (current && mounted.current && activeClient.current === client && clientGeneration.current === generation) setError(safeError((cause as { code?: unknown })?.code, language));
    });
    return () => { current = false; mounted.current = false; };
  }, [client]);
  useEffect(() => { if (error) errorRef.current?.focus(); }, [error]);
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer); }, []);

  async function run(action: Action) {
    if (!client || loaded !== client || busy || snapshot.busy) return;
    setBusy(true); setError(""); setConfirm(null); setClaimPending(false); setOriginNotFound(false);
    const generation = clientGeneration.current;
    try {
      if (action === "create") await client.create();
      else if (action === "claim") { if (!validScanCode(code.trim(), "claim")) { setError(safeError("invalid_code", language)); return; } await client.claim(code.trim()); setCode(""); }
      else if (action === "retry-origin") await client.retryOrigin();
      else if (action === "exchange") await client.exchange();
      else if (action === "acknowledge") await client.acknowledge();
      else await client.cancel();
    } catch (cause) { if (activeClient.current === client && clientGeneration.current === generation) { const code = (cause as { code?: unknown })?.code; setError(safeError(code, language)); setOriginNotFound(code === "scan_not_found"); } }
    finally { if (activeClient.current === client && clientGeneration.current === generation) setBusy(false); }
  }

  async function query(method: "load" | "lookup" | "status" | "recover") {
    if (!client || loaded !== client || busy || snapshot.busy || (method !== "load" && (snapshot.next_poll_at_unix_ms ?? 0) > Date.now())) return;
    setBusy(true); setError(""); const generation = clientGeneration.current;
    try { await client[method](); setOriginNotFound(false); }
    catch (cause) { if (activeClient.current === client && clientGeneration.current === generation) { const code = (cause as { code?: unknown })?.code; setError(safeError(code, language)); setOriginNotFound(code === "scan_not_found"); } }
    finally { if (activeClient.current === client && clientGeneration.current === generation) setBusy(false); }
  }

  const phase = snapshot.phase as Phase;
  const target = snapshot.target;
  const progress = snapshot.progress;
  const displayCode = progress?.code_expires_at_unix_secs && progress.code_expires_at_unix_secs * 1000 <= now ? undefined : snapshot.display_code;
  useEffect(() => {
    const node = canvas.current;
    if (!node || !renderer) return;
    if (displayCode) { try { renderer.render(node, displayCode, "qr"); } catch { renderer.clear(node); } }
    else renderer.clear(node);
    return () => renderer.clear(node);
  }, [renderer, displayCode]);
  const ready = Boolean(client && loaded === client);
  const cooling = Boolean(snapshot.next_poll_at_unix_ms && snapshot.next_poll_at_unix_ms > now);
  const remaining = cooling ? Math.ceil((snapshot.next_poll_at_unix_ms! - now) / 1000) : 0;
  const stateKey = progress?.state;
  const serverState = stateKey === "issued" && progress?.delivery_state === "acknowledged" ? (language === "zh-CN" ? "交付已确认接收" : "Delivery receipt acknowledged")
    : stateKey === "issued" && progress?.delivery_state === "revoked" ? (language === "zh-CN" ? "交付已撤销" : "Delivery revoked")
      : stateKey && stateKey in copy.states ? copy.states[stateKey as keyof typeof copy.states] : undefined;
  const direction = progress?.mode ? copy.directions[progress.mode] : undefined;
  const hideCode = phase !== "waiting" || ["approved", "issued"].includes(String(stateKey));
  const phaseText = phaseLabels(language)[phase] ?? phaseLabels(language).empty;

  return <section className={`${styles.root} ${className ?? ""}`} style={style} aria-labelledby={heading}>
    <h2 id={heading}>{copy.title}</h2><p className={styles.muted}>{copy.intro}</p>
    {!client && <div className={styles.alert} role="status">{copy.unavailable}</div>}
    {client && !ready && <div className={styles.status} role="status">{error || copy.working}{error && <button type="button" onClick={() => { setError(""); void loadOnce(client).then(() => setLoaded(client)).catch(cause => setError(safeError((cause as { code?: unknown })?.code, language))); }}>{copy.retryLoad}</button>}</div>}
    {client && <>
      <dl className={styles.fields}>
        <dt>{copy.target}</dt><dd>{target.audience || "—"}</dd><dt>{copy.tenant}</dt><dd>{target.tenant_id || "—"}</dd>
        <dt>{copy.client}</dt><dd>{target.client_id || "—"}</dd><dt>{copy.entry}</dt><dd>{target.entry_id || "—"}</dd>
        <dt>{copy.device}</dt><dd>{target.device_id || "—"}</dd><dt>{copy.phase}</dt><dd><span className={styles.badge}>{phaseText}</span></dd>
        {direction && <><dt>{copy.mode}</dt><dd>{direction}</dd></>}
      </dl>
      {progress && <div className={styles.detail}>{serverState && <p>{serverState}</p>}{progress.expires_at_unix_secs && <p>{language === "zh-CN" ? "授权过期时间" : "Authorization expires"}: {date(progress.expires_at_unix_secs, language)}</p>}{progress.delivery_state === "recoverable" && <p>{language === "zh-CN" ? "交付可恢复" : "Delivery is recoverable"}</p>}</div>}
      {displayCode && !hideCode && <><p>{copy.createQr}</p>{renderer ? <div ref={canvas} className={styles.qr} aria-label={copy.createQr} /> : <p className={styles.muted}>{copy.noRenderer}</p>}<code className={styles.code}>{displayCode}</code><ScanSourceEntry target={target} displayCode={displayCode} language={language} /></>}
      {phase === "pending" && <div className={styles.alert} role="status">{copy.pending}</div>}
      {phase === "active" && <div className={styles.success} role="status">{copy.active}</div>}
      {phase === "closed" && <div className={styles.status} role="status">{copy.closed}</div>}
      {phase === "empty" && <div className={styles.actions}><button type="button" disabled={!ready || busy || snapshot.busy} onClick={() => setConfirm("create")}>{copy.create}</button><button type="button" className={styles.secondary} disabled={!ready || busy || snapshot.busy} onClick={() => setConfirm("claim")}>{copy.claim}</button></div>}
      {phase === "empty" && confirm === "claim" && <form className={styles.form} onSubmit={event => { event.preventDefault(); if (validScanCode(code.trim(), "claim")) setClaimPending(true); }}><label htmlFor={`${heading}-code`}>{copy.codeLabel}</label><input id={`${heading}-code`} autoComplete="off" value={code} maxLength={25} onChange={event => setCode(event.target.value)} /><div className={styles.actions}><button type="button" disabled={!ready || busy || snapshot.busy || !validScanCode(code.trim(), "claim")} onClick={() => setClaimPending(true)}>{copy.claim}</button><button type="button" className={styles.secondary} onClick={() => { setConfirm(null); setClaimPending(false); setCode(""); }}>{copy.no}</button></div></form>}
      {phase !== "empty" && phase !== "active" && phase !== "closed" && <div className={styles.actions}><button type="button" disabled={!ready || busy || snapshot.busy || cooling} onClick={() => void query(phase === "origin-unknown" ? "lookup" : "status")}>{copy.query}{cooling ? ` (${remaining}s)` : ""}</button>{["origin-unknown", "exchange-unknown", "ack-unknown"].includes(phase) && <button type="button" className={styles.secondary} disabled={!ready || busy || snapshot.busy || cooling} onClick={() => void query("recover")}>{copy.lookup}</button>}{phase === "origin-unknown" && originNotFound && <button type="button" className={styles.secondary} disabled={!ready || busy || snapshot.busy} onClick={() => setConfirm("retry-origin")}>{copy.retryOrigin}</button>}{phase === "waiting" && progress?.state === "approved" && <button type="button" disabled={!ready || busy || snapshot.busy} onClick={() => setConfirm("exchange")}>{copy.exchange}</button>}{phase === "pending" && <button type="button" disabled={!ready || busy || snapshot.busy} onClick={() => setConfirm("acknowledge")}>{copy.acknowledge}</button>}<button type="button" className={styles.danger} disabled={!ready || busy || snapshot.busy} onClick={() => setConfirm("cancel")}>{phase === "closing" ? copy.retryCancel : copy.cancel}</button></div>}
      {phase === "empty" && ready && <button type="button" className={styles.secondary} disabled={busy || snapshot.busy} onClick={() => void query("load")}>{copy.reload}</button>}
      {(busy || snapshot.busy) && <p className={styles.status} role="status">{copy.working}</p>}
    </>}
    {error && <div ref={errorRef} className={styles.alert} role="alert" tabIndex={-1}>{error}</div>}
    {claimPending && <div className={styles.confirm} role="group" aria-label={copy.yes}><p>{copy.confirm.claim}</p><div className={styles.actions}><button type="button" disabled={busy || snapshot.busy} onClick={() => void run("claim")}>{copy.yes}</button><button type="button" className={styles.secondary} onClick={() => setClaimPending(false)}>{copy.no}</button></div></div>}
    {confirm && confirm !== "claim" && <div className={styles.confirm} role="group" aria-label={copy.yes}><p>{copy.confirm[confirm]}</p><div className={styles.actions}><button type="button" disabled={busy || snapshot.busy} onClick={() => void run(confirm)}>{copy.yes}</button><button type="button" className={styles.secondary} onClick={() => setConfirm(null)}>{copy.no}</button></div></div>}
  </section>;
}
