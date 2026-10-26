import { secureRandomUuid } from "./browser-session";
import type { IdentityTransport } from "./client";
import {
  parseScanBundle, parseScanProgress, scanRequest, scanSecret, scanHashSecret, ScanError,
  validScanCode, validateScanTarget, type ScanBundle, type ScanProgress,
  type ScanSigner, type ScanTarget,
} from "./scan-login-protocol";

export type DeviceScanPhase = "origin-unknown" | "waiting" | "exchange-unknown" | "pending" | "ack-unknown" | "active" | "closing" | "closed";
export interface DeviceScanRecord {
  schema_version: 1;
  target: ScanTarget;
  origin_action: "create" | "claim";
  origin_operation_id: string;
  delivery_secret: string;
  claim_code?: string;
  grant_id?: string;
  progress?: ScanProgress;
  display_code?: string;
  exchange_operation_id?: string;
  ack_operation_id?: string;
  abort_operation_id?: string;
  bundle?: ScanBundle;
  phase: DeviceScanPhase;
}
export interface DeviceScanSnapshot {
  target: ScanTarget;
  phase: DeviceScanPhase | "empty";
  progress?: ScanProgress;
  display_code?: string;
  verification_url?: string;
  next_poll_at_unix_ms?: number;
  busy: boolean;
  error?: string;
}
export interface DeviceScanStore {
  withLock<T>(target: ScanTarget, operation: () => Promise<T>): Promise<T>;
  load(target: ScanTarget): Promise<DeviceScanRecord | undefined>;
  save(record: DeviceScanRecord): Promise<void>;
}
export interface DeviceScanSessions {
  activate(input: { target: ScanTarget; issuance_operation_id: string; bundle: ScanBundle }): Promise<void>;
  discard(input: { target: ScanTarget; issuance_operation_id?: string }): Promise<void>;
}
export interface DeviceScanClientOptions {
  target: ScanTarget;
  signer: ScanSigner;
  store: DeviceScanStore;
  sessions: DeviceScanSessions;
  transport?: IdentityTransport;
}

const phaseValues: DeviceScanPhase[] = ["origin-unknown", "waiting", "exchange-unknown", "pending", "ack-unknown", "active", "closing", "closed"];
const uuid = (value: unknown): value is string => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
const exactKeys = (value: Record<string, unknown>, keys: string[]) => Object.keys(value).sort().join(",") === [...keys].sort().join(",");
const recordObject = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new DeviceScanError("invalid_response");
  return value as Record<string, unknown>;
};

export class DeviceScanError extends Error {
  constructor(public readonly code: string, public readonly status?: number) { super(code); this.name = "DeviceScanError"; }
}

function sameTarget(a: ScanTarget, b: ScanTarget): boolean {
  return a.baseUrl === b.baseUrl && a.tenant_id === b.tenant_id && a.client_id === b.client_id && a.entry_id === b.entry_id &&
    a.device_id === b.device_id && a.audience === b.audience && a.verification_uri === b.verification_uri;
}
function validateRecord(value: unknown, target: ScanTarget): DeviceScanRecord {
  const raw = recordObject(value);
  const keys = ["schema_version", "target", "origin_action", "origin_operation_id", "delivery_secret", "phase",
    ...(raw.claim_code === undefined ? [] : ["claim_code"]), ...(raw.grant_id === undefined ? [] : ["grant_id"]),
    ...(raw.progress === undefined ? [] : ["progress"]), ...(raw.display_code === undefined ? [] : ["display_code"]),
    ...(raw.exchange_operation_id === undefined ? [] : ["exchange_operation_id"]), ...(raw.ack_operation_id === undefined ? [] : ["ack_operation_id"]),
    ...(raw.abort_operation_id === undefined ? [] : ["abort_operation_id"]), ...(raw.bundle === undefined ? [] : ["bundle"])];
  if (!exactKeys(raw, keys) || raw.schema_version !== 1 || !raw.target || typeof raw.target !== "object" ||
      !sameTarget(validateScanTarget(raw.target as ScanTarget), target) || !["create", "claim"].includes(String(raw.origin_action)) ||
      !uuid(raw.origin_operation_id) || typeof raw.delivery_secret !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(raw.delivery_secret) ||
      !phaseValues.includes(raw.phase as DeviceScanPhase)) throw new DeviceScanError("invalid_store");
  if (raw.claim_code !== undefined && !validScanCode(raw.claim_code, "claim")) throw new DeviceScanError("invalid_store");
  if (raw.grant_id !== undefined && (typeof raw.grant_id !== "string" || !/^[A-Za-z0-9_.-]{1,128}$/.test(raw.grant_id))) throw new DeviceScanError("invalid_store");
  let storedProgress: ScanProgress | undefined;
  if (raw.progress !== undefined) {
    const expected = { ...(raw.grant_id ? { grant_id: raw.grant_id as string } : {}), mode: raw.origin_action === "create" ? "device_display" : "phone_display" };
    storedProgress = parseScanProgress(raw.progress, target, expected);
    if (!raw.grant_id || storedProgress.grant_id !== raw.grant_id) throw new DeviceScanError("invalid_store");
  }
  if (raw.display_code !== undefined && !validScanCode(raw.display_code, raw.origin_action as "create" | "claim")) throw new DeviceScanError("invalid_store");
  for (const name of ["exchange_operation_id", "ack_operation_id", "abort_operation_id"] as const)
    if (raw[name] !== undefined && !uuid(raw[name])) throw new DeviceScanError("invalid_store");
  const bundle = raw.bundle === undefined ? undefined : parseScanBundle(raw.bundle, target);
  if (["pending", "ack-unknown", "active"].includes(String(raw.phase)) && (!bundle || !raw.exchange_operation_id || !raw.grant_id)) throw new DeviceScanError("invalid_store");
  if (raw.phase === "active" && storedProgress?.delivery_state !== "acknowledged") throw new DeviceScanError("invalid_store");
  if (raw.phase === "closed" && (raw.bundle !== undefined || raw.display_code !== undefined || raw.claim_code !== undefined)) throw new DeviceScanError("invalid_store");
  return {
    schema_version: 1, target, origin_action: raw.origin_action as "create" | "claim", origin_operation_id: raw.origin_operation_id,
    delivery_secret: raw.delivery_secret, phase: raw.phase as DeviceScanPhase,
    ...(raw.claim_code === undefined ? {} : { claim_code: raw.claim_code as string }), ...(raw.grant_id === undefined ? {} : { grant_id: raw.grant_id as string }),
    ...(storedProgress ? { progress: storedProgress } : {}),
    ...(raw.display_code === undefined ? {} : { display_code: raw.display_code as string }),
    ...(raw.exchange_operation_id === undefined ? {} : { exchange_operation_id: raw.exchange_operation_id as string }),
    ...(raw.ack_operation_id === undefined ? {} : { ack_operation_id: raw.ack_operation_id as string }),
    ...(raw.abort_operation_id === undefined ? {} : { abort_operation_id: raw.abort_operation_id as string }), ...(bundle ? { bundle } : {}),
  };
}
function sameBundle(a: ScanBundle, b: ScanBundle): boolean {
  return a.session.tenant_id === b.session.tenant_id && a.session.account_id === b.session.account_id && a.session.session_id === b.session.session_id &&
    a.session.client_id === b.session.client_id && a.session.expires_at_unix_secs === b.session.expires_at_unix_secs &&
    a.tokens.access_token === b.tokens.access_token && a.tokens.refresh_token === b.tokens.refresh_token &&
    a.tokens.access_expires_at_unix_secs === b.tokens.access_expires_at_unix_secs && a.tokens.refresh_expires_at_unix_secs === b.tokens.refresh_expires_at_unix_secs &&
    a.receipt_nonce === b.receipt_nonce;
}
function verificationUrl(target: ScanTarget, code?: string): string | undefined {
  if (!code) return undefined;
  const uri = new URL(target.verification_uri, typeof location === "undefined" ? "https://embedded.invalid" : location.origin);
  uri.hash = `code=${encodeURIComponent(code)}`;
  return uri.href;
}
function freezeSnapshot(snapshot: DeviceScanSnapshot): DeviceScanSnapshot {
  return Object.freeze({ ...snapshot, ...(snapshot.progress ? { progress: Object.freeze({ ...snapshot.progress }) } : {}) });
}

/** Device-side two-way scan flow. Secret material remains in the host store. */
export class DeviceScanClient {
  readonly target: ScanTarget;
  readonly signer: ScanSigner;
  private readonly store: DeviceScanStore;
  private readonly sessions: DeviceScanSessions;
  private readonly transport: IdentityTransport;
  private listeners = new Set<() => void>();
  private snapshot: DeviceScanSnapshot;
  private disposed = false;
  private busy = false;
  private generation = 0;
  private displayTimer?: ReturnType<typeof setTimeout>;

  constructor(options: DeviceScanClientOptions) {
    this.target = validateScanTarget(options.target);
    if (typeof options.signer?.signRequest !== "function" || typeof options.store?.withLock !== "function" ||
      typeof options.store.load !== "function" || typeof options.store.save !== "function" ||
      typeof options.sessions?.activate !== "function" || typeof options.sessions.discard !== "function") throw new DeviceScanError("missing_adapter");
    this.signer = options.signer;
    this.store = options.store;
    this.sessions = options.sessions;
    this.transport = options.transport ?? ((url, init) => fetch(url, init));
    this.snapshot = freezeSnapshot({ target: this.target, phase: "empty", busy: false });
  }
  getSnapshot = () => this.snapshot;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private notify() { this.listeners.forEach(listener => listener()); }
  private publish(record?: DeviceScanRecord, error?: string, nextPoll?: number) {
    if (this.displayTimer) clearTimeout(this.displayTimer);
    const displayCode = record?.display_code && (record.progress?.code_expires_at_unix_secs ?? 0) * 1000 > Date.now() ? record.display_code : undefined;
    this.snapshot = freezeSnapshot({
      target: this.target, phase: record?.phase ?? "empty", ...(record?.progress ? { progress: record.progress } : {}),
      ...(displayCode ? { display_code: displayCode, verification_url: verificationUrl(this.target, displayCode) } : {}),
      ...(nextPoll ? { next_poll_at_unix_ms: nextPoll } : {}), busy: this.busy, ...(error ? { error } : {}),
    });
    if (displayCode && record?.progress?.code_expires_at_unix_secs) {
      const delay = Math.max(0, record.progress.code_expires_at_unix_secs * 1000 - Date.now());
      this.displayTimer = setTimeout(() => { if (!this.disposed) this.publish(record, this.snapshot.error, nextPoll); }, delay);
    }
    this.notify();
  }
  private check(gen: number) { if (this.disposed || this.generation !== gen) throw new DeviceScanError("disposed"); }
  private async run(operation: (record: DeviceScanRecord | undefined, gen: number) => Promise<void>): Promise<void> {
    if (this.disposed) throw new DeviceScanError("disposed");
    if (this.busy) throw new DeviceScanError("busy");
    this.busy = true;
    this.snapshot = freezeSnapshot({ ...this.snapshot, busy: true, error: undefined });
    this.notify();
    const gen = this.generation;
    try {
      await this.store.withLock(this.target, async () => {
        this.check(gen);
        const raw = await this.store.load(this.target); this.check(gen);
        const record = raw === undefined ? undefined : validateRecord(raw, this.target);
        await operation(record, gen);
      });
    } catch (error) {
      if (this.disposed || this.generation !== gen) throw new DeviceScanError("disposed");
      const known = error instanceof DeviceScanError || error instanceof ScanError;
      const code = known ? error.code : "operation_failed";
      this.snapshot = freezeSnapshot({ ...this.snapshot, error: code, busy: this.busy, ...(retryPollAt(code, this.snapshot.progress) ? { next_poll_at_unix_ms: retryPollAt(code, this.snapshot.progress) } : {}) });
      this.notify();
      if (error instanceof DeviceScanError) throw error;
      throw new DeviceScanError(code, known ? error.status : undefined);
    } finally {
      this.busy = false;
      if (!this.disposed) { this.snapshot = freezeSnapshot({ ...this.snapshot, busy: false }); this.notify(); }
    }
  }
  private async save(record: DeviceScanRecord, gen: number) { this.check(gen); await this.store.save(structuredClone(record)); this.check(gen); }
  private publishProgress(record: DeviceScanRecord, progress: ScanProgress, error?: string, notify = true) {
    if (record.grant_id && progress.grant_id !== record.grant_id) throw new DeviceScanError("grant_mismatch");
    const expectedMode = record.origin_action === "create" ? "device_display" : "phone_display";
    if (progress.mode !== expectedMode || progress.issuance_operation_id && record.exchange_operation_id && progress.issuance_operation_id !== record.exchange_operation_id) throw new DeviceScanError("flow_mismatch");
    record.grant_id = progress.grant_id;
    record.progress = progress;
    const phase: DeviceScanPhase = record.phase;
    if (["cancelled", "denied", "expired", "invalidated"].includes(progress.state)) {
      delete record.display_code; delete record.claim_code;
    }
    if (record.phase !== "closing" && record.phase !== "closed" && record.phase !== "active") record.phase = phaseFor(record, progress);
    if (notify) this.publish(record, error, error ? retryPollAt(error, progress) : Date.now() + Math.max(0, progress.poll_after_ms));
  }
  private async call(record: DeviceScanRecord, action: Parameters<typeof scanRequest>[3], body: Record<string, unknown>, gen: number) {
    this.check(gen);
    let result: unknown;
    try { result = await scanRequest(this.target, this.signer, this.transport, action, body, () => this.check(gen)); }
    catch (error) {
      this.check(gen);
      if (error instanceof ScanError) throw new DeviceScanError(error.code, error.status);
      throw error;
    }
    this.check(gen);
    return recordObject(result);
  }
  private async updateProgress(record: DeviceScanRecord, value: unknown, gen: number, display?: unknown) {
    this.check(gen);
    const expected = { ...(record.grant_id ? { grant_id: record.grant_id } : {}), mode: record.origin_action === "create" ? "device_display" : "phone_display",
      ...(record.exchange_operation_id ? { issuance_operation_id: record.exchange_operation_id } : {}) };
    const p = parseScanProgress(value, this.target, expected);
    if (p.issuance_operation_id && record.exchange_operation_id && p.issuance_operation_id !== record.exchange_operation_id) throw new DeviceScanError("issuance_mismatch");
    if (display !== undefined && display !== null) {
      const mode = record.origin_action === "create" ? "create" : "claim";
      if (!validScanCode(display, mode)) throw new DeviceScanError("invalid_display_code");
      if (record.display_code && record.display_code !== display) throw new DeviceScanError("display_code_changed");
      record.display_code = display as string;
    }
    this.publishProgress(record, p, undefined, false);
    await this.save(record, gen);
    this.check(gen);
    this.publish(record, undefined, Date.now() + Math.max(0, p.poll_after_ms));
  }
  async load(): Promise<void> {
    await this.run(async (record, gen) => { this.check(gen); this.publish(record); });
  }
  private async begin(action: "create" | "claim", code?: string): Promise<void> {
    await this.run(async (record, gen) => {
      if (record) {
        if (record.phase === "origin-unknown" && record.origin_action === action && (action === "create" || record.claim_code === code)) {
          try { await this.lookupRecord(record, gen); return; }
          catch (error) { if (!(error instanceof DeviceScanError) || error.status !== 404 || error.code !== "scan_not_found") throw error; }
          await this.sendOrigin(record, gen); return;
        }
        throw new DeviceScanError("existing_flow");
      }
      if (action === "claim" && !validScanCode(code, "claim")) throw new DeviceScanError("invalid_scan_code");
      const delivery_secret = scanSecret();
      const next: DeviceScanRecord = {
        schema_version: 1, target: this.target, origin_action: action, origin_operation_id: secureRandomUuid(), delivery_secret,
        phase: "origin-unknown", ...(action === "claim" ? { claim_code: code } : {}),
      };
      await this.save(next, gen);
      await this.sendOrigin(next, gen);
    });
  }
  async create(): Promise<void> { return this.begin("create"); }
  async claim(code: string): Promise<void> { return this.begin("claim", code); }
  private async sendOrigin(record: DeviceScanRecord, gen: number) {
    const hash = await scanHashSecret(record.delivery_secret); this.check(gen);
    const body = record.origin_action === "create"
      ? { operation_id: record.origin_operation_id, entry_id: this.target.entry_id, tenant_id: this.target.tenant_id, delivery_secret_hash: hash }
      : { operation_id: record.origin_operation_id, entry_id: this.target.entry_id, tenant_id: this.target.tenant_id, scan_code: record.claim_code, delivery_secret_hash: hash };
    record.phase = "origin-unknown"; await this.save(record, gen); this.publish(record);
    const value = await this.call(record, record.origin_action, body, gen);
    const progress = record.origin_action === "create" ? value.progress : value;
    const display = record.origin_action === "create" ? value.display_code : undefined;
    if (record.origin_action === "create" && value.verification_uri !== this.target.verification_uri) throw new DeviceScanError("verification_uri_mismatch");
    await this.updateProgress(record, progress, gen, display);
  }
  private async lookupRecord(record: DeviceScanRecord, gen: number) {
    const value = await this.call(record, "lookup", { origin_action: record.origin_action, origin_operation_id: record.origin_operation_id,
      entry_id: this.target.entry_id, tenant_id: this.target.tenant_id, delivery_secret: record.delivery_secret }, gen);
    if (value.origin_operation_id !== record.origin_operation_id) throw new DeviceScanError("origin_mismatch");
    await this.updateProgress(record, value.progress, gen, value.display_code);
    return value;
  }
  async lookup(): Promise<void> {
    await this.run(async (record, gen) => {
      if (!record || record.phase === "closed") throw new DeviceScanError("invalid_phase");
      try { await this.lookupRecord(record, gen); } catch (error) {
        if (error instanceof DeviceScanError && error.status === 404) throw new DeviceScanError("scan_not_found", 404);
        throw error;
      }
    });
  }
  async retryOrigin(): Promise<void> {
    await this.run(async (record, gen) => {
      if (!record || record.phase !== "origin-unknown") throw new DeviceScanError("invalid_phase");
      try { await this.lookupRecord(record, gen); }
      catch (error) {
        if (!(error instanceof DeviceScanError) || error.code !== "scan_not_found" || error.status !== 404) throw error;
        await this.sendOrigin(record, gen);
      }
    });
  }
  async status(): Promise<void> {
    await this.run(async (record, gen) => {
      if (!record?.grant_id || record.phase === "closed") throw new DeviceScanError("invalid_phase");
      await this.queryStatus(record, gen);
    });
  }
  private async queryStatus(record: DeviceScanRecord, gen: number) {
    const value = await this.call(record, "status", { grant_id: record.grant_id, delivery_secret: record.delivery_secret, tenant_id: this.target.tenant_id }, gen);
    await this.updateProgress(record, value, gen);
  }
  async exchange(): Promise<void> {
    await this.run(async (record, gen) => {
      if (!record?.grant_id || record.phase !== "waiting" || record.progress?.state !== "approved") throw new DeviceScanError("not_approved");
      if (!record.exchange_operation_id) record.exchange_operation_id = secureRandomUuid();
      record.phase = "exchange-unknown"; await this.save(record, gen); this.publish(record);
      const value = await this.call(record, "exchange", { operation_id: record.exchange_operation_id, grant_id: record.grant_id, delivery_secret: record.delivery_secret, tenant_id: this.target.tenant_id }, gen);
      await this.acceptDelivery(record, value, gen);
    });
  }
  private async acceptDelivery(record: DeviceScanRecord, value: Record<string, unknown>, gen: number) {
    this.check(gen);
    if (value.progress === undefined) throw new DeviceScanError("invalid_response");
    const progress = parseScanProgress(value.progress, this.target, { grant_id: record.grant_id, mode: record.origin_action === "create" ? "device_display" : "phone_display" });
    if (progress.issuance_operation_id !== record.exchange_operation_id) throw new DeviceScanError("issuance_mismatch");
    if (progress.state !== "issued" || !["recoverable", "acknowledged"].includes(String(progress.delivery_state))) throw new DeviceScanError("delivery_not_recoverable");
    if (value.receipt_nonce === undefined) {
      if (progress.delivery_state === "acknowledged") {
        await this.activateAcknowledged(record, progress, gen); return;
      }
      record.progress = progress; record.phase = "exchange-unknown"; await this.save(record, gen); this.publish(record); return;
    }
    const bundle = parseScanBundle(value, this.target);
    if (record.bundle && !sameBundle(record.bundle, bundle)) throw new DeviceScanError("bundle_changed");
    record.bundle = bundle; record.progress = progress; record.phase = progress.delivery_state === "acknowledged" ? "ack-unknown" : "pending";
    await this.save(record, gen); this.check(gen); this.publish(record);
    if (record.phase === "ack-unknown") await this.activateAcknowledged(record, progress, gen);
  }
  async recover(): Promise<void> {
    await this.run(async (record, gen) => {
      if (!record || record.phase === "closed") throw new DeviceScanError("invalid_phase");
      if (record.phase === "origin-unknown" || !record.grant_id) { await this.lookupRecord(record, gen); return; }
      const issuance = record.exchange_operation_id;
      if (!issuance) { await this.queryStatus(record, gen); return; }
      const value = await this.call(record, "recover", { issuance_operation_id: issuance, grant_id: record.grant_id, delivery_secret: record.delivery_secret, tenant_id: this.target.tenant_id }, gen);
      await this.acceptDelivery(record, value, gen);
    });
  }
  async acknowledge(): Promise<void> {
    await this.run(async (record, gen) => {
      if (!record?.bundle || !record.exchange_operation_id || !record.grant_id || !["pending", "ack-unknown"].includes(record.phase)) throw new DeviceScanError("invalid_phase");
      if (!record.ack_operation_id) record.ack_operation_id = secureRandomUuid();
      record.phase = "ack-unknown"; await this.save(record, gen); this.publish(record);
      const value = await this.call(record, "acknowledge", { operation_id: record.ack_operation_id, issuance_operation_id: record.exchange_operation_id,
        grant_id: record.grant_id, delivery_secret: record.delivery_secret, receipt_nonce: record.bundle.receipt_nonce, tenant_id: this.target.tenant_id }, gen);
      const progress = parseScanProgress(value, this.target, { grant_id: record.grant_id, issuance_operation_id: record.exchange_operation_id, mode: record.origin_action === "create" ? "device_display" : "phone_display" });
      if (progress.delivery_state !== "acknowledged") throw new DeviceScanError("ack_unconfirmed");
      await this.activateAcknowledged(record, progress, gen);
    });
  }
  private async activateAcknowledged(record: DeviceScanRecord, progress: ScanProgress, gen: number) {
    this.check(gen);
    if (!record.bundle || !record.exchange_operation_id || progress.issuance_operation_id !== record.exchange_operation_id || progress.delivery_state !== "acknowledged")
      throw new DeviceScanError("delivery_material_missing");
    record.progress = progress;
    await this.save(record, gen);
    this.check(gen);
    await this.sessions.activate({ target: this.target, issuance_operation_id: record.exchange_operation_id, bundle: structuredClone(record.bundle) });
    this.check(gen);
    record.phase = "active";
    await this.save(record, gen);
    this.publish(record);
  }
  async cancel(): Promise<void> {
    await this.run(async (record, gen) => {
      if (!record || ["active", "closed"].includes(record.phase)) throw new DeviceScanError("invalid_phase");
      record.phase = "closing"; await this.save(record, gen); this.publish(record);
      if (record.grant_id && record.exchange_operation_id) {
        if (!record.abort_operation_id) record.abort_operation_id = secureRandomUuid();
        await this.save(record, gen);
        try {
          await this.call(record, "abort", { operation_id: record.abort_operation_id, issuance_operation_id: record.exchange_operation_id,
            grant_id: record.grant_id, delivery_secret: record.delivery_secret, tenant_id: this.target.tenant_id }, gen);
        } catch (error) {
          if (error instanceof DeviceScanError && error.code === "already_acknowledged") {
            await this.queryStatus(record, gen);
            if (record.progress?.delivery_state === "acknowledged") {
              await this.activateAcknowledged(record, record.progress, gen);
              return;
            }
            throw new DeviceScanError("delivery_state_unknown");
          }
          // No delivery exists to abort; closing the origin fences a delayed exchange.
          if (!((error instanceof DeviceScanError && error.code === "scan_not_found" && error.status === 404) ||
              (error instanceof DeviceScanError && error.code === "scan_not_approved" && error.status === 409))) throw error;
        }
      }
      const closed = await this.call(record, "close-origin", { entry_id: this.target.entry_id, tenant_id: this.target.tenant_id,
        origin_action: record.origin_action, origin_operation_id: record.origin_operation_id, delivery_secret: record.delivery_secret }, gen);
      if (closed.origin_operation_id !== record.origin_operation_id || closed.origin_action !== record.origin_action) throw new DeviceScanError("origin_mismatch");
      if (closed.outcome !== "closed") {
        if (closed.outcome === "already_activated") {
          if (!record.exchange_operation_id) throw new DeviceScanError("delivery_material_missing");
          await this.recoverAcknowledged(record, gen);
          return;
        }
        throw new DeviceScanError("close_unconfirmed");
      }
      await this.sessions.discard({ target: this.target, ...(record.exchange_operation_id ? { issuance_operation_id: record.exchange_operation_id } : {}) });
      this.check(gen);
      record.phase = "closed"; delete record.bundle; delete record.display_code; delete record.claim_code;
      await this.save(record, gen); this.publish(record);
    });
  }
  private async recoverAcknowledged(record: DeviceScanRecord, gen: number) {
    const value = await this.call(record, "recover", { issuance_operation_id: record.exchange_operation_id, grant_id: record.grant_id,
      delivery_secret: record.delivery_secret, tenant_id: this.target.tenant_id }, gen);
    if (value.receipt_nonce !== undefined) await this.acceptDelivery(record, value, gen);
    else {
      const progress = parseScanProgress(value.progress, this.target, { grant_id: record.grant_id, mode: record.origin_action === "create" ? "device_display" : "phone_display", issuance_operation_id: record.exchange_operation_id });
      await this.activateAcknowledged(record, progress, gen);
    }
  }
  dispose() { this.disposed = true; this.generation++; if (this.displayTimer) clearTimeout(this.displayTimer); this.listeners.clear(); }
}

function phaseFor(record: DeviceScanRecord, progress: ScanProgress): DeviceScanPhase {
  if (["cancelled", "denied", "expired", "invalidated"].includes(progress.state)) return "waiting";
  if (progress.state === "issued") {
    if (progress.delivery_state === "acknowledged") return "ack-unknown";
    if (progress.delivery_state === "revoked") return "exchange-unknown";
    return record.bundle ? "pending" : "exchange-unknown";
  }
  if (progress.state === "approved" && record.origin_action === "create") return "waiting";
  if (["waiting_user", "waiting_device", "awaiting_approval", "approved"].includes(progress.state)) return "waiting";
  return record.phase;
}
function retryPollAt(code: string | undefined, progress?: ScanProgress): number | undefined {
  if (!code && !["exchange-unknown", "ack-unknown", "origin-unknown", "closing"].includes(String(progress?.state))) return undefined;
  const wait = Math.max(1000, Math.min(progress?.poll_after_ms ?? 1000, 30_000));
  return Date.now() + wait;
}
