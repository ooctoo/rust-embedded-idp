import type { EmbeddedDeviceClient, SubjectDevice, DeviceKeyMetadata } from "./device-client";
import { IdentityError, type IdentitySession } from "./client";
import { secureRandomUuid } from "./browser-session";

export interface DeviceKeyRotationTarget { readonly baseUrl: string; readonly tenant_id: string; readonly client_id: string; readonly entry_id: string; readonly device_id: string }
export interface DeviceKeyRotationOwner { readonly tenant_id: string; readonly account_id: string; readonly client_id: string }
export interface DeviceKeyRotationPublicJwk { readonly kty: "OKP"; readonly crv: "Ed25519"; readonly x: string }
export type DeviceKeyRotationPhase = "prepared" | "rotate-unknown" | "active" | "abandoned";
export interface DeviceKeyRotationRecord {
  schema_version: 1; target: DeviceKeyRotationTarget; owner: DeviceKeyRotationOwner; rotation_id: string;
  binding_id: string; binding_version: number; device_version: number; expected_key_id: string; expected_key_version: number;
  current_handle: string; handle: string; public_jwk: DeviceKeyRotationPublicJwk; key_id: string; phase: DeviceKeyRotationPhase;
}
export type DeviceKeyRotationContext = Readonly<DeviceKeyRotationRecord>;
export interface DeviceKeyRotationSigner {
  prepare(input: { target: DeviceKeyRotationTarget; owner: DeviceKeyRotationOwner; rotation_id: string; expected_key_id: string; expected_key_version: number }): Promise<{ current_handle: string; handle: string; public_jwk: DeviceKeyRotationPublicJwk; key_id: string }>;
  signRotation(input: DeviceKeyRotationContext & { challenge: string; new_key_version: number }): Promise<{ current_key_signature: string; proposed_key_signature: string }>;
  activate(input: DeviceKeyRotationContext): Promise<void>;
  discard(input: DeviceKeyRotationContext): Promise<void>;
}
export interface DeviceKeyRotationStore {
  withLock<T>(target: DeviceKeyRotationTarget, operation: () => Promise<T>): Promise<T>;
  load(target: DeviceKeyRotationTarget): Promise<DeviceKeyRotationRecord | undefined>;
  save(record: DeviceKeyRotationRecord): Promise<void>;
}
export interface DeviceKeyRotationSnapshot {
  target: DeviceKeyRotationTarget; phase: DeviceKeyRotationPhase | "empty"; expected_key_id?: string; expected_key_version?: number;
  key_id?: string; new_key_version?: number; busy: boolean; error?: string;
}
export interface DeviceKeyRotationClientOptions { devices: EmbeddedDeviceClient; target: DeviceKeyRotationTarget; signer: DeviceKeyRotationSigner; store: DeviceKeyRotationStore }

const phases: DeviceKeyRotationPhase[] = ["prepared", "rotate-unknown", "active", "abandoned"];
const uuid = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
const b32 = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(v);
const b64 = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9_-]{85}[AQgw]$/.test(v);
const positive = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) > 0;
const timestamp = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const obj = (v: unknown): Record<string, unknown> => { if (!v || typeof v !== "object" || Array.isArray(v)) throw new DeviceKeyRotationError("invalid_response"); return v as Record<string, unknown>; };
const exact = (v: Record<string, unknown>, keys: string[]) => Object.keys(v).sort().join(",") === [...keys].sort().join(",");
const id = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9_.-]{1,128}$/.test(v);

export class DeviceKeyRotationError extends Error {
  constructor(public readonly code: string, public readonly status?: number) { super(code); this.name = "DeviceKeyRotationError"; }
}
function hasDotSegment(path: string): boolean { return path.split("/").some(part => part === "." || part === ".."); }
function normalizeBase(value: unknown): string {
  if (typeof value !== "string" || !value || /[\\\u0000-\u0020\u007f]/.test(value) || /%(?:2e|2f|5c)/i.test(value)) throw new DeviceKeyRotationError("invalid_target");
  if (value.startsWith("/") && !value.startsWith("//")) {
    if (value.includes("?") || value.includes("#") || hasDotSegment(value)) throw new DeviceKeyRotationError("invalid_target");
    return value.replace(/\/$/, "") || "/";
  }
  let url: URL; try { url = new URL(value); } catch { throw new DeviceKeyRotationError("invalid_target"); }
  const local = url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (!(url.protocol === "https:" || local) || url.username || url.password || url.search || url.hash || value.includes("?") || value.includes("#") || hasDotSegment(value.slice(value.indexOf("://") + 3).split("/").slice(1).join("/"))) throw new DeviceKeyRotationError("invalid_target");
  return url.href.replace(/\/$/, "");
}
function targetValue(value: DeviceKeyRotationTarget): DeviceKeyRotationTarget {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new DeviceKeyRotationError("invalid_target");
  const t = value as unknown as Record<string, unknown>;
  if (!exact(t, ["baseUrl", "tenant_id", "client_id", "entry_id", "device_id"]) || !id(t.tenant_id) || !id(t.client_id) || !id(t.entry_id) || !uuid(t.device_id)) throw new DeviceKeyRotationError("invalid_target");
  return Object.freeze({ baseUrl: normalizeBase(t.baseUrl), tenant_id: t.tenant_id, client_id: t.client_id, entry_id: t.entry_id, device_id: t.device_id });
}
function ownerOf(s?: IdentitySession): DeviceKeyRotationOwner | undefined { return s && Object.freeze({ tenant_id: s.tenant_id, account_id: s.account_id, client_id: s.client_id }); }
function sameOwner(a?: DeviceKeyRotationOwner, b?: DeviceKeyRotationOwner): boolean { return !!a && !!b && a.tenant_id === b.tenant_id && a.account_id === b.account_id && a.client_id === b.client_id; }
function sameTarget(a: DeviceKeyRotationTarget, b: DeviceKeyRotationTarget): boolean { return a.baseUrl === b.baseUrl && a.tenant_id === b.tenant_id && a.client_id === b.client_id && a.entry_id === b.entry_id && a.device_id === b.device_id; }
function validJwk(v: unknown): DeviceKeyRotationPublicJwk {
  const x = obj(v); if (!exact(x, ["kty", "crv", "x"]) || x.kty !== "OKP" || x.crv !== "Ed25519" || !b32(x.x)) throw new DeviceKeyRotationError("invalid_key");
  return Object.freeze({ kty: "OKP", crv: "Ed25519", x: x.x });
}
function handle(v: unknown): v is string { return typeof v === "string" && v.length > 0 && v.length <= 512; }
function validateRecord(v: unknown, target: DeviceKeyRotationTarget): DeviceKeyRotationRecord {
  const r = obj(v); const keys = ["schema_version", "target", "owner", "rotation_id", "binding_id", "binding_version", "device_version", "expected_key_id", "expected_key_version", "current_handle", "handle", "public_jwk", "key_id", "phase"];
  if (!exact(r, keys) || r.schema_version !== 1 || !r.target || typeof r.target !== "object" || !sameTarget(targetValue(r.target as DeviceKeyRotationTarget), target) ||
      !r.owner || typeof r.owner !== "object" || !exact(r.owner as Record<string, unknown>, ["tenant_id", "account_id", "client_id"]) ||
      !id((r.owner as DeviceKeyRotationOwner).tenant_id) || !id((r.owner as DeviceKeyRotationOwner).account_id) || !id((r.owner as DeviceKeyRotationOwner).client_id) ||
      !uuid(r.rotation_id) || !uuid(r.binding_id) || !positive(r.binding_version) || !positive(r.device_version) || !b32(r.expected_key_id) || !positive(r.expected_key_version) ||
      !handle(r.current_handle) || !handle(r.handle) || !b32(r.key_id) || !phases.includes(r.phase as DeviceKeyRotationPhase)) throw new DeviceKeyRotationError("invalid_store");
  const jwk = validJwk(r.public_jwk);
  if (r.expected_key_version >= Number.MAX_SAFE_INTEGER || r.device_version >= Number.MAX_SAFE_INTEGER || r.key_id === r.expected_key_id || r.handle === r.current_handle) throw new DeviceKeyRotationError("invalid_store");
  return { schema_version: 1, target, owner: Object.freeze({ ...(r.owner as DeviceKeyRotationOwner) }), rotation_id: r.rotation_id, binding_id: r.binding_id,
    binding_version: r.binding_version, device_version: r.device_version, expected_key_id: r.expected_key_id, expected_key_version: r.expected_key_version,
    current_handle: r.current_handle, handle: r.handle, public_jwk: jwk, key_id: r.key_id, phase: r.phase as DeviceKeyRotationPhase };
}
export function buildDeviceKeyRotationProofBytes(input: { tenant_id: string; device_id: string; old_key_id: string; new_key_id: string; new_key_version: number; challenge: string }): Uint8Array {
  if (!id(input.tenant_id) || !id(input.device_id) || !b32(input.old_key_id) || !b32(input.new_key_id) || !positive(input.new_key_version) || !b32(input.challenge)) throw new DeviceKeyRotationError("invalid_proof_input");
  return new TextEncoder().encode("EMBEDDED-IDP-DEVICE-KEY-ROTATION-V2\ntenant-id:" + input.tenant_id + "\ndevice-id:" + input.device_id + "\nold-key-id:" + input.old_key_id + "\nnew-key-id:" + input.new_key_id + "\nnew-key-version:" + input.new_key_version + "\nchallenge:" + input.challenge + "\n");
}
async function thumbprint(jwk: DeviceKeyRotationPublicJwk): Promise<string> {
  const bytes = new TextEncoder().encode('{"crv":"Ed25519","kty":"OKP","x":"' + jwk.x + '"}');
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function sameDevice(a: SubjectDevice, b: SubjectDevice): boolean {
  return a.tenant_id === b.tenant_id && a.device_id === b.device_id && a.client_id === b.client_id && a.status === b.status && a.version === b.version &&
    a.proof_key_id === b.proof_key_id && a.key_version === b.key_version && a.binding_id === b.binding_id && a.binding_version === b.binding_version && a.binding_status === b.binding_status;
}
function assertUsable(d: SubjectDevice, target: DeviceKeyRotationTarget): void {
  if (d.tenant_id !== target.tenant_id || d.client_id !== target.client_id || d.device_id !== target.device_id || d.status !== "active" || d.binding_status !== "active" || d.proof_key_id === null || d.key_version === null) throw new DeviceKeyRotationError("device_unavailable");
}
function context(r: DeviceKeyRotationRecord): DeviceKeyRotationContext { return Object.freeze({ ...r, target: Object.freeze({ ...r.target }), owner: Object.freeze({ ...r.owner }), public_jwk: Object.freeze({ ...r.public_jwk }) }); }

export class DeviceKeyRotationClient {
  readonly target: DeviceKeyRotationTarget;
  readonly identity: EmbeddedDeviceClient["identity"];
  private readonly devices: EmbeddedDeviceClient; private readonly signer: DeviceKeyRotationSigner; private readonly store: DeviceKeyRotationStore;
  private readonly listeners = new Set<() => void>(); private readonly unsubscribeIdentity: () => void;
  private snapshot: DeviceKeyRotationSnapshot; private busy = false; private disposed = false; private generation = 0; private owner?: DeviceKeyRotationOwner; private observedIdentityStamp = "";
  constructor(options: DeviceKeyRotationClientOptions) {
    this.target = targetValue(options.target);
    if (!options.devices || typeof options.signer?.prepare !== "function" || typeof options.signer.signRotation !== "function" || typeof options.signer.activate !== "function" || typeof options.signer.discard !== "function" ||
        typeof options.store?.withLock !== "function" || typeof options.store.load !== "function" || typeof options.store.save !== "function") throw new DeviceKeyRotationError("missing_adapter");
    this.devices = options.devices; this.identity = options.devices.identity; this.signer = options.signer; this.store = options.store;
    if (normalizeBase(this.devices.identity.deviceBaseUrl || "/") !== this.target.baseUrl) throw new DeviceKeyRotationError("entry_mismatch");
    this.snapshot = { target: this.target, phase: "empty", busy: false };
    this.observedIdentityStamp = this.stamp();
    this.unsubscribeIdentity = this.devices.identity.subscribe(() => this.onIdentity()); this.onIdentity();
  }
  getSnapshot = () => this.snapshot;
  subscribe = (fn: () => void) => { this.listeners.add(fn); return () => { this.listeners.delete(fn); }; };
  private currentOwner() { return ownerOf(this.devices.identity.getSnapshot().session); }
  private stamp() { const s = this.devices.identity.getSnapshot(); const o = ownerOf(s.session); return JSON.stringify([o?.tenant_id, o?.account_id, o?.client_id, s.session?.session_id, s.sessionChanged]); }
  private onIdentity() {
    if (this.disposed) return;
    const state = this.devices.identity.getSnapshot(); const next = ownerOf(state.session); const stamp = this.stamp();
    if (stamp !== this.observedIdentityStamp) {
      this.observedIdentityStamp = stamp; this.owner = next; this.generation++;
      this.snapshot = { target: this.target, phase: "empty", busy: this.busy, ...(next ? {} : { error: "session_required" }) }; this.emit();
    }
  }
  private notify() { this.listeners.forEach(fn => fn()); }
  private emit(record?: DeviceKeyRotationRecord, error?: string) {
    const r = record && sameOwner(record.owner, this.currentOwner()) ? record : undefined;
    if (r) this.snapshot = { target: this.target, phase: r.phase, busy: this.busy, expected_key_id: r.expected_key_id,
      expected_key_version: r.expected_key_version, key_id: r.key_id, new_key_version: r.expected_key_version + 1, ...(error ? { error } : {}) };
    else if (error) this.snapshot = { ...this.snapshot, error };
    this.notify();
  }
  private check(gen: number, stamp: string) {
    if (this.disposed || gen !== this.generation || stamp !== this.stamp()) throw new DeviceKeyRotationError("operation_cancelled");
    const o = this.currentOwner(); if (!o || o.tenant_id !== this.target.tenant_id || o.client_id !== this.target.client_id) throw new DeviceKeyRotationError("wrong_owner");
  }
  private async run(fn: (gen: number, stamp: string, owner: DeviceKeyRotationOwner) => Promise<void>): Promise<void> {
    if (this.disposed) throw new DeviceKeyRotationError("disposed"); if (this.busy) throw new DeviceKeyRotationError("busy");
    const owner = this.currentOwner(); if (!owner) throw new DeviceKeyRotationError("session_required");
    if (owner.tenant_id !== this.target.tenant_id || owner.client_id !== this.target.client_id) throw new DeviceKeyRotationError("wrong_owner");
    const gen = this.generation, stamp = this.stamp(); this.busy = true; this.snapshot = { ...this.snapshot, busy: true, error: undefined }; this.notify();
    try { await this.store.withLock(this.target, async () => { this.check(gen, stamp); await fn(gen, stamp, owner); }); }
    catch (error) {
      if (this.disposed || gen !== this.generation) throw new DeviceKeyRotationError("operation_cancelled");
      const code = error instanceof DeviceKeyRotationError ? error.code : error instanceof IdentityError ? "request_failed" : "operation_failed";
      this.snapshot = { ...this.snapshot, busy: true, error: code }; this.notify();
      throw error instanceof DeviceKeyRotationError ? error : new DeviceKeyRotationError(code, error instanceof IdentityError ? error.status : undefined);
    } finally { this.busy = false; if (!this.disposed) { this.snapshot = { ...this.snapshot, busy: false }; this.notify(); } }
  }
  private async loadRecord(gen: number, stamp: string, owner: DeviceKeyRotationOwner): Promise<DeviceKeyRotationRecord | undefined> {
    this.check(gen, stamp); const v = await this.store.load(this.target); this.check(gen, stamp); if (v === undefined) return undefined;
    const r = validateRecord(v, this.target); if (!sameOwner(r.owner, owner)) throw new DeviceKeyRotationError("record_owner_mismatch"); return r;
  }
  private async save(r: DeviceKeyRotationRecord, gen: number, stamp: string): Promise<void> { this.check(gen, stamp); await this.store.save(r); this.check(gen, stamp); }
  private async detail(gen: number, stamp: string): Promise<SubjectDevice> {
    this.check(gen, stamp); const d = await this.devices.detail(this.target.device_id); this.check(gen, stamp); assertUsable(d, this.target); return d;
  }
  private async key(d: SubjectDevice, keyId: string, gen: number, stamp: string): Promise<DeviceKeyMetadata> {
    this.check(gen, stamp); const k = await this.devices.keyMetadata(d.device_id, keyId); this.check(gen, stamp);
    if (k.tenant_id !== this.target.tenant_id || k.device_id !== d.device_id || k.key_id !== keyId || k.algorithm !== "ed25519" || !positive(k.version) || !["active", "retired"].includes(k.status) || !timestamp(k.registered_at_unix_secs) || !(k.retired_at_unix_secs === null || timestamp(k.retired_at_unix_secs))) throw new DeviceKeyRotationError("invalid_response");
    return k;
  }
  private async stableCurrent(gen: number, stamp: string): Promise<{ device: SubjectDevice; key: DeviceKeyMetadata }> {
    const a = await this.detail(gen, stamp); const k = await this.key(a, a.proof_key_id!, gen, stamp); const b = await this.detail(gen, stamp);
    if (!sameDevice(a, b) || k.status !== "active" || k.version !== a.key_version || k.retired_at_unix_secs !== null) throw new DeviceKeyRotationError("device_changed"); return { device: b, key: k };
  }
  private async currentFor(r: DeviceKeyRotationRecord, gen: number, stamp: string) {
    const before = await this.detail(gen, stamp);
    if (before.binding_id !== r.binding_id || before.binding_version !== r.binding_version) throw new DeviceKeyRotationError("binding_changed");
    let selected: string;
    if (before.proof_key_id === r.key_id && before.key_version === r.expected_key_version + 1 && before.version === r.device_version + 1) selected = r.key_id;
    else if (before.proof_key_id === r.expected_key_id && before.key_version === r.expected_key_version && before.version === r.device_version) selected = r.expected_key_id;
    else throw new DeviceKeyRotationError("device_changed");
    const metadata = await this.key(before, selected, gen, stamp); const after = await this.detail(gen, stamp);
    if (!sameDevice(before, after)) throw new DeviceKeyRotationError("device_changed");
    if (selected === r.key_id && (metadata.status !== "active" || metadata.version !== r.expected_key_version + 1 || metadata.retired_at_unix_secs !== null)) throw new DeviceKeyRotationError("candidate_changed");
    if (selected === r.expected_key_id && (metadata.status !== "active" || metadata.version !== r.expected_key_version || metadata.retired_at_unix_secs !== null)) throw new DeviceKeyRotationError("current_key_changed");
    return { device: after, selected };
  }
  private async activate(r: DeviceKeyRotationRecord, gen: number, stamp: string) { this.check(gen, stamp); await this.signer.activate(context(r)); this.check(gen, stamp); r.phase = "active"; await this.save(r, gen, stamp); this.emit(r); }
  async load(): Promise<void> { await this.run(async (g, s, o) => { const r = await this.loadRecord(g, s, o); this.check(g, s); if (r) this.emit(r); else { this.snapshot = { target: this.target, phase: "empty", busy: this.busy }; this.notify(); } }); }
  async prepare(): Promise<void> {
    await this.run(async (g, s, o) => {
      if (await this.loadRecord(g, s, o)) throw new DeviceKeyRotationError("existing_rotation");
      const { device, key } = await this.stableCurrent(g, s); this.check(g, s);
      if (key.version >= Number.MAX_SAFE_INTEGER || device.version >= Number.MAX_SAFE_INTEGER) throw new DeviceKeyRotationError("version_overflow");
      const rotation_id = secureRandomUuid(); let made: Awaited<ReturnType<DeviceKeyRotationSigner["prepare"]>> | undefined;
      let saveTried = false, saved = false, unknown = false;
      try {
        made = await this.signer.prepare({ target: this.target, owner: o, rotation_id, expected_key_id: key.key_id, expected_key_version: key.version }); this.check(g, s);
        const jwk = validJwk(made.public_jwk); if (!handle(made.current_handle) || !handle(made.handle) || made.handle === made.current_handle || !b32(made.key_id) || made.key_id === key.key_id || await thumbprint(jwk) !== made.key_id) throw new DeviceKeyRotationError("invalid_key"); this.check(g, s);
        const r: DeviceKeyRotationRecord = { schema_version: 1, target: this.target, owner: o, rotation_id, binding_id: device.binding_id, binding_version: device.binding_version,
          device_version: device.version, expected_key_id: key.key_id, expected_key_version: key.version, current_handle: made.current_handle, handle: made.handle, public_jwk: jwk, key_id: made.key_id, phase: "prepared" };
        saveTried = true; await this.store.save(r); saved = true; this.check(g, s); this.emit(r);
      } catch (error) {
        if (made && saveTried && !saved) try { const persisted = await this.store.load(this.target); this.check(g, s); saved = !!persisted && (persisted as DeviceKeyRotationRecord).rotation_id === rotation_id; } catch { unknown = true; }
        if (made && !saved && (!saveTried || !unknown) && handle(made.current_handle) && handle(made.handle) && made.current_handle !== made.handle) try { await this.signer.discard({ schema_version: 1, target: this.target, owner: o, rotation_id, binding_id: device.binding_id,
          binding_version: device.binding_version, device_version: device.version, expected_key_id: key.key_id, expected_key_version: key.version, current_handle: made.current_handle,
          handle: made.handle, public_jwk: made.public_jwk, key_id: made.key_id, phase: "prepared" }); } catch { /* Definitely not submitted. */ }
        throw error;
      }
    });
  }
  async rotate(): Promise<void> {
    await this.run(async (g, s, o) => {
      const r = await this.loadRecord(g, s, o); if (!r || !["prepared", "rotate-unknown"].includes(r.phase)) throw new DeviceKeyRotationError("invalid_phase");
      const state = await this.currentFor(r, g, s); this.check(g, s); if (state.selected === r.key_id) return this.activate(r, g, s);
      const next = r.expected_key_version + 1;
      const challenge = obj((await this.devices.identity.requestDevice("/devices/proof/challenges", { tenant_id: this.target.tenant_id, device_id: this.target.device_id, purpose: "device_key_rotation" })).value); this.check(g, s);
      if (!exact(challenge, ["challenge", "expires_at_unix_secs"]) || !b32(challenge.challenge) || !timestamp(challenge.expires_at_unix_secs) || challenge.expires_at_unix_secs <= Date.now() / 1000) throw new DeviceKeyRotationError("challenge_invalid");
      const signatures = await this.signer.signRotation({ ...context(r), challenge: challenge.challenge as string, new_key_version: next }); this.check(g, s);
      if (!signatures || !b64(signatures.current_key_signature) || !b64(signatures.proposed_key_signature) || Date.now() / 1000 >= challenge.expires_at_unix_secs) throw new DeviceKeyRotationError("signature_invalid");
      r.phase = "rotate-unknown"; await this.save(r, g, s); this.emit(r); this.check(g, s); if (Date.now() / 1000 >= challenge.expires_at_unix_secs) throw new DeviceKeyRotationError("challenge_expired");
      const response = obj((await this.devices.identity.requestDevice("/devices/rotate-key", { device_id: this.target.device_id, expected_key_id: r.expected_key_id,
        expected_key_version: r.expected_key_version, proposed_public_jwk: { ...r.public_jwk, kid: r.key_id }, challenge: challenge.challenge,
        current_key_signature: signatures.current_key_signature, proposed_key_signature: signatures.proposed_key_signature })).value); this.check(g, s);
      if (!exact(response, ["tenant_id", "device_id", "key_id", "version"]) || response.tenant_id !== this.target.tenant_id || response.device_id !== this.target.device_id || response.key_id !== r.key_id || response.version !== next) throw new DeviceKeyRotationError("invalid_response");
      const latest = await this.currentFor(r, g, s); if (latest.selected !== r.key_id) throw new DeviceKeyRotationError("rotation_unconfirmed"); await this.activate(r, g, s);
    });
  }
  async recover(): Promise<void> {
    await this.run(async (g, s, o) => {
      const r = await this.loadRecord(g, s, o); if (!r || r.phase === "prepared" || r.phase === "abandoned") throw new DeviceKeyRotationError("invalid_phase");
      const latest = await this.currentFor(r, g, s); if (latest.selected === r.key_id) await this.activate(r, g, s); else { this.emit(r); }
    });
  }
  async discard(): Promise<void> {
    await this.run(async (g, s, o) => { const r = await this.loadRecord(g, s, o); if (!r || r.phase !== "prepared") throw new DeviceKeyRotationError("cannot_discard");
      r.phase = "abandoned"; await this.save(r, g, s); this.emit(r); this.check(g, s); await this.signer.discard(context(r)); this.check(g, s); });
  }
  dispose() { this.disposed = true; this.generation++; this.unsubscribeIdentity(); this.listeners.clear(); }
}
