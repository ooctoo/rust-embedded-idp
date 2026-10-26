import { secureRandomUuid } from "./browser-session";
import type { IdentityTransport } from "./client";

export type DeviceRegistrationPhase = "prepared" | "provision-unknown" | "pending" | "complete-unknown" | "active" | "abandoned";
export interface DeviceRegistrationTarget {
  readonly baseUrl: string;
  readonly tenant_id: string;
  readonly client_id: string;
  readonly entry_id: string;
  readonly device_id: string;
}
export interface DeviceRegistrationPublicJwk { readonly kty: "OKP"; readonly crv: "Ed25519"; readonly x: string }
export interface DeviceRegistrationRecord {
  schema_version: 1;
  target: DeviceRegistrationTarget;
  registration_request_id: string;
  device_name: string;
  handle: string;
  public_jwk: DeviceRegistrationPublicJwk;
  key_id: string;
  phase: DeviceRegistrationPhase;
  registration_scope?: string;
}
export interface DeviceRegistrationContext {
  readonly target: DeviceRegistrationTarget;
  readonly registration_request_id: string;
  readonly device_name: string;
  readonly handle: string;
  readonly public_jwk: DeviceRegistrationPublicJwk;
  readonly key_id: string;
}
export interface DeviceRegistrationSigner {
  prepare(input: { target: DeviceRegistrationTarget; registration_request_id: string }): Promise<{
    handle: string; public_jwk: DeviceRegistrationPublicJwk; key_id: string;
  }>;
  signRegistration(input: DeviceRegistrationContext & { challenge: string }): Promise<string>;
  activate(input: DeviceRegistrationContext): Promise<void>;
  discard(input: DeviceRegistrationContext): Promise<void>;
}
export interface DeviceRegistrationAdmission {
  authorize(input: { target: DeviceRegistrationTarget; registration_request_id: string; action: "provision" | "registration-result" }): Promise<{
    credential: string; registration_scope: string; expires_at_unix_secs: number;
  }>;
}
export interface DeviceRegistrationStore {
  withLock<T>(target: DeviceRegistrationTarget, operation: () => Promise<T>): Promise<T>;
  load(target: DeviceRegistrationTarget): Promise<DeviceRegistrationRecord | undefined>;
  save(record: DeviceRegistrationRecord): Promise<void>;
}
export interface DeviceRegistrationSnapshot {
  target: DeviceRegistrationTarget;
  phase: DeviceRegistrationPhase | "empty";
  key_id?: string;
  busy: boolean;
  error?: string;
}
export interface DeviceRegistrationClientOptions {
  target: DeviceRegistrationTarget;
  signer: DeviceRegistrationSigner;
  admission: DeviceRegistrationAdmission;
  store: DeviceRegistrationStore;
  transport?: IdentityTransport;
}

const phases: DeviceRegistrationPhase[] = ["prepared", "provision-unknown", "pending", "complete-unknown", "active", "abandoned"];
const uuid = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
const b64url32 = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(v);
const b64url64 = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9_-]{85}[AQgw]$/.test(v);
const safeTime = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const safeVersion = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) > 0;
const object = (v: unknown): Record<string, unknown> => {
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new RegistrationError("invalid_response");
  return v as Record<string, unknown>;
};

export class RegistrationError extends Error {
  constructor(public readonly code: string, public readonly status?: number) {
    super(code); this.name = "RegistrationError";
  }
}

function validBase(raw: unknown): string {
  if (typeof raw !== "string" || !raw || /\\/.test(raw) || /[\u0000-\u0020\u007f]/.test(raw) || /%(?:2e|2f|5c)/i.test(raw) || /\/(?:\.{1,2})(?:\/|$)/.test(raw)) throw new RegistrationError("invalid_target");
  if (raw.startsWith("/") && !raw.startsWith("//")) {
    const path = raw;
    if (raw.includes("?") || raw.includes("#") || path.split("/").some(part => part === ".." || part === ".")) throw new RegistrationError("invalid_target");
    return path.replace(/\/$/, "");
  }
  let url: URL;
  try { url = new URL(raw); } catch { throw new RegistrationError("invalid_target"); }
  const localHttp = url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (!(url.protocol === "https:" || localHttp) || url.username || url.password || url.search || url.hash ||
      raw.includes("?") || raw.includes("#") || url.pathname.split("/").some(part => part === ".." || part === ".")) throw new RegistrationError("invalid_target");
  return url.href.replace(/\/$/, "");
}
function validId(v: unknown): v is string { return typeof v === "string" && /^[A-Za-z0-9_.-]{1,128}$/.test(v); }
function canonicalObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).sort().join(",") === [...keys].sort().join(",");
}
function validatePublic(value: unknown): DeviceRegistrationPublicJwk {
  if (!canonicalObject(value)) throw new RegistrationError("invalid_key");
  const keys = Object.keys(value).sort();
  if (keys.join(",") !== "crv,kty,x" || value.kty !== "OKP" || value.crv !== "Ed25519" || !b64url32(value.x)) throw new RegistrationError("invalid_key");
  return Object.freeze({ kty: "OKP", crv: "Ed25519", x: value.x });
}
function targetValue(value: unknown): DeviceRegistrationTarget {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new RegistrationError("invalid_target");
  const input = value as Record<string, unknown>;
  const baseUrl = validBase(input.baseUrl);
  if (!validId(input.tenant_id) || !validId(input.client_id) || !validId(input.entry_id) || !uuid(input.device_id)) throw new RegistrationError("invalid_target");
  return Object.freeze({ baseUrl, tenant_id: input.tenant_id, client_id: input.client_id, entry_id: input.entry_id, device_id: input.device_id });
}
function sameTarget(a: DeviceRegistrationTarget, b: DeviceRegistrationTarget) {
  return a.baseUrl === b.baseUrl && a.tenant_id === b.tenant_id && a.client_id === b.client_id && a.entry_id === b.entry_id && a.device_id === b.device_id;
}
function validName(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && new TextEncoder().encode(value).length <= 256 && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
}
function wirePublicJwk(r: DeviceRegistrationRecord) { return { ...r.public_jwk, kid: r.key_id }; }
function context(r: DeviceRegistrationRecord): DeviceRegistrationContext {
  return Object.freeze({ target: r.target, registration_request_id: r.registration_request_id, device_name: r.device_name,
    handle: r.handle, public_jwk: r.public_jwk, key_id: r.key_id });
}
function validateRecord(value: unknown, target: DeviceRegistrationTarget): DeviceRegistrationRecord {
  const r = object(value);
  if (!exactKeys(r, ["schema_version", "target", "registration_request_id", "device_name", "handle", "public_jwk", "key_id", "phase", ...(r.registration_scope === undefined ? [] : ["registration_scope"])]) ||
      r.schema_version !== 1 || !canonicalObject(r.target) || !exactKeys(r.target, ["baseUrl", "tenant_id", "client_id", "entry_id", "device_id"]) || !sameTarget(targetValue(r.target), target) ||
      !uuid(r.registration_request_id) || !validName(r.device_name) || typeof r.handle !== "string" || !r.handle || r.handle.length > 512 ||
      !b64url32(r.key_id) || !phases.includes(r.phase as DeviceRegistrationPhase)) throw new RegistrationError("invalid_store");
  if (r.phase === "prepared" || r.phase === "abandoned") { if (r.registration_scope !== undefined) throw new RegistrationError("invalid_store"); }
  const pub = validatePublic(r.public_jwk);
  if (r.registration_scope !== undefined && (typeof r.registration_scope !== "string" || !validId(r.registration_scope))) throw new RegistrationError("invalid_store");
  if (["provision-unknown", "pending", "complete-unknown", "active"].includes(String(r.phase)) && r.registration_scope === undefined) throw new RegistrationError("invalid_store");
  return { schema_version: 1, target, registration_request_id: r.registration_request_id, device_name: r.device_name,
    handle: r.handle, public_jwk: pub, key_id: r.key_id, phase: r.phase as DeviceRegistrationPhase,
    ...(r.registration_scope === undefined ? {} : { registration_scope: r.registration_scope }) };
}

export function buildDeviceRegistrationProofBytes(input: { tenant_id: string; device_id: string; key_id: string; challenge: string }): Uint8Array {
  if (!validId(input.tenant_id) || !uuid(input.device_id) || !b64url32(input.key_id) || !b64url32(input.challenge)) throw new RegistrationError("invalid_proof_input");
  return new TextEncoder().encode(`EMBEDDED-IDP-DEVICE-REGISTRATION-V2\ntenant-id:${input.tenant_id}\ndevice-id:${input.device_id}\nkey-id:${input.key_id}\nchallenge:${input.challenge}\n`);
}

export class DeviceRegistrationClient {
  readonly target: DeviceRegistrationTarget;
  private readonly signer: DeviceRegistrationSigner;
  private readonly admission: DeviceRegistrationAdmission;
  private readonly store: DeviceRegistrationStore;
  private readonly transport: IdentityTransport;
  private listeners = new Set<() => void>();
  private snapshot: DeviceRegistrationSnapshot;
  private disposed = false;
  private running = false;
  private generation = 0;

  constructor(options: DeviceRegistrationClientOptions) {
    this.target = targetValue(options.target);
    if (!options.signer || !options.admission || !options.store ||
        [options.signer.prepare, options.signer.signRegistration, options.signer.activate, options.signer.discard,
          options.admission.authorize, options.store.withLock, options.store.load, options.store.save].some(method => typeof method !== "function"))
      throw new RegistrationError("missing_adapter");
    this.signer = options.signer; this.admission = options.admission; this.store = options.store;
    this.transport = options.transport ?? ((url, init) => fetch(url, init));
    this.snapshot = { target: this.target, phase: "empty", busy: false };
  }
  getSnapshot = () => this.snapshot;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish(record?: DeviceRegistrationRecord, error?: string) {
    this.snapshot = { target: this.target, phase: record?.phase ?? "empty", ...(record ? { key_id: record.key_id } : {}), busy: this.running, ...(error ? { error } : {}) };
    this.listeners.forEach(listener => listener());
  }
  private check(gen = this.generation) { if (this.disposed || gen !== this.generation) throw new RegistrationError("disposed"); }
  private async locked(operation: (gen: number) => Promise<void>): Promise<void> {
    if (this.disposed) throw new RegistrationError("disposed");
    if (this.running) throw new RegistrationError("busy");
    this.running = true;
    this.snapshot = { ...this.snapshot, busy: true, error: undefined };
    this.listeners.forEach(listener => listener());
    const gen = this.generation;
    try {
      await this.store.withLock(this.target, async () => {
        this.check(gen);
        await operation(gen);
      });
    } catch (error) {
      this.snapshot = { ...this.snapshot, busy: true, error: error instanceof RegistrationError ? error.code : "operation_failed" };
      this.listeners.forEach(listener => listener());
      throw error instanceof RegistrationError ? error : new RegistrationError("operation_failed");
    } finally {
      this.running = false;
      if (!this.disposed) {
        this.snapshot = { ...this.snapshot, busy: false };
        this.listeners.forEach(listener => listener());
      }
    }
  }
  private async reload(): Promise<DeviceRegistrationRecord | undefined> {
    const gen = this.generation; this.check(gen);
    const raw = await this.store.load(this.target); this.check(gen);
    return raw === undefined ? undefined : validateRecord(raw, this.target);
  }
  private async save(r: DeviceRegistrationRecord, gen: number) {
    this.check(gen); await this.store.save(r); this.check(gen);
  }
  private async refresh(error?: string) {
    try { const r = await this.reload(); this.publish(r, error); }
    catch { if (!this.disposed) { this.snapshot = { ...this.snapshot, busy: this.running, error: "store_unavailable" }; this.listeners.forEach(listener => listener()); } }
  }
  private async request(path: string, body: unknown, expectedStatus: number, credential?: string): Promise<Record<string, unknown>> {
    this.check();
    let response: Response;
    const base = this.target.baseUrl;
    const url = `${base}${path}`;
    try {
      response = await this.transport(url, { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json",
        ...(credential ? { "x-embedded-idp-device-admission": credential } : {}) }, body: JSON.stringify(body),
        credentials: "omit", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(15_000) });
    } catch { this.check(); throw new RegistrationError("network_unknown"); }
    this.check();
    if (response.status !== expectedStatus) throw new RegistrationError(response.status === 404 ? "not_found" : "request_failed", response.status);
    try { const value = object(await response.json()); this.check(); return value; } catch (error) { this.check(); throw error instanceof RegistrationError ? error : new RegistrationError("invalid_response"); }
  }
  private checkResult(value: Record<string, unknown>, r: DeviceRegistrationRecord) {
    if (!exactKeys(value, ["tenant_id", "client_id", "device_id", "expected_key_id", "created_at_unix_secs", "expires_at_unix_secs", "completed_at_unix_secs", "status", "version", "proof_key_id", "key_version"]) ||
        value.tenant_id !== this.target.tenant_id || value.client_id !== this.target.client_id || value.device_id !== this.target.device_id ||
        value.expected_key_id !== r.key_id || !safeTime(value.created_at_unix_secs) || !safeTime(value.expires_at_unix_secs) ||
        value.expires_at_unix_secs <= value.created_at_unix_secs || !(value.completed_at_unix_secs === null || safeTime(value.completed_at_unix_secs)) ||
        !safeVersion(value.version) || !["pending", "active", "disabled", "revoked"].includes(String(value.status)) ||
        !(value.proof_key_id === null || b64url32(value.proof_key_id)) || !(value.key_version === null || safeVersion(value.key_version)) ||
        (value.proof_key_id === null) !== (value.key_version === null)) throw new RegistrationError("invalid_response");
    if (value.completed_at_unix_secs !== null && (value.completed_at_unix_secs < (value.created_at_unix_secs as number) || value.completed_at_unix_secs > (value.expires_at_unix_secs as number) || value.status !== "active" || value.version !== 2 || value.proof_key_id !== r.key_id || value.key_version !== 1) ||
        value.completed_at_unix_secs === null && (value.status !== "pending" || value.version !== 1 || value.proof_key_id !== null || value.key_version !== null)) throw new RegistrationError("registration_changed");
    return value;
  }
  private async authorize(r: DeviceRegistrationRecord, action: "provision" | "registration-result") {
    this.check();
    const grant = await this.admission.authorize({ target: this.target, registration_request_id: r.registration_request_id, action });
    this.check();
    if (!grant || typeof grant.credential !== "string" || !grant.credential || grant.credential.length > 4096 ||
        !validId(grant.registration_scope) || !safeTime(grant.expires_at_unix_secs) || grant.expires_at_unix_secs <= Math.floor(Date.now() / 1000)) throw new RegistrationError("admission_invalid");
    if (r.registration_scope !== undefined && r.registration_scope !== grant.registration_scope) throw new RegistrationError("scope_changed");
    if (r.registration_scope === undefined) r.registration_scope = grant.registration_scope;
    return grant;
  }
  private async lookup(r: DeviceRegistrationRecord): Promise<Record<string, unknown>> {
    const grant = await this.authorize(r, "registration-result");
    if (grant.expires_at_unix_secs <= Math.floor(Date.now() / 1000)) throw new RegistrationError("admission_expired");
    const value = await this.request("/devices/registration-result", { tenant_id: this.target.tenant_id,
      device_id: this.target.device_id, registration_request_id: r.registration_request_id }, 200, grant.credential);
    this.check(); return this.checkResult(value, r);
  }
  private async activate(r: DeviceRegistrationRecord, result: Record<string, unknown>, gen: number) {
    this.check(gen);
    if (result.completed_at_unix_secs === null || result.status !== "active" || result.proof_key_id !== r.key_id || result.key_version !== 1) throw new RegistrationError("registration_pending");
    await this.signer.activate(context(r)); this.check(gen);
    r.phase = "active"; await this.save(r, gen); this.publish(r);
  }
  private async provisionRecord(r: DeviceRegistrationRecord, gen: number) {
    const grant = await this.authorize(r, "provision");
    this.check(gen);
    r.phase = "provision-unknown"; await this.save(r, gen); this.publish(r);
    if (grant.expires_at_unix_secs <= Math.floor(Date.now() / 1000)) throw new RegistrationError("admission_expired");
    const value = await this.request("/devices/provision", { tenant_id: this.target.tenant_id, device_id: this.target.device_id,
      registration_request_id: r.registration_request_id, device_name: r.device_name, public_jwk: wirePublicJwk(r) }, 201, grant.credential);
    this.check(gen);
    this.checkResult(value, r);
    if (value.completed_at_unix_secs !== null) { const latest = await this.lookup(r); return this.activate(r, latest, gen); }
    r.phase = "pending"; await this.save(r, gen); this.publish(r);
  }
  async load(): Promise<void> {
    await this.locked(async gen => { const r = await this.reload(); this.check(gen); this.publish(r); });
  }
  async prepare(deviceName: string): Promise<void> {
    await this.locked(async gen => {
      if (!validName(deviceName)) throw new RegistrationError("invalid_name");
      if (await this.reload()) throw new RegistrationError("existing_registration");
      const id = secureRandomUuid();
      let created: Awaited<ReturnType<DeviceRegistrationSigner["prepare"]>> | undefined;
      let saved = false;
      let saveAttempted = false;
      let storageUnknown = false;
      try {
        created = await this.signer.prepare({ target: this.target, registration_request_id: id }); this.check(gen);
        const r = validateRecord({ schema_version: 1, target: this.target, registration_request_id: id, device_name: deviceName,
          handle: created.handle, public_jwk: created.public_jwk, key_id: created.key_id, phase: "prepared" }, this.target);
        const canonicalKey = await keyId(r.public_jwk.x); this.check(gen);
        if (canonicalKey !== r.key_id) throw new RegistrationError("invalid_key");
        saveAttempted = true; await this.store.save(r); saved = true; this.check(gen); this.publish(r);
      } catch (error) {
        if (created && saveAttempted && !saved) try {
          const persisted = await this.store.load(this.target); this.check(gen);
          saved = !!persisted && (persisted as DeviceRegistrationRecord).registration_request_id === id;
        } catch { storageUnknown = true; }
        if (created && !saved && (!saveAttempted || !storageUnknown)) try { await this.signer.discard({ target: this.target, registration_request_id: id, device_name: deviceName,
          handle: created.handle, public_jwk: created.public_jwk, key_id: created.key_id }); } catch { /* Candidate was never sent remotely. */ }
        throw error;
      }
    });
  }
  async provision(): Promise<void> {
    await this.locked(async gen => {
      const r = await this.reload(); if (!r || r.phase !== "prepared") throw new RegistrationError("invalid_phase");
      try { await this.provisionRecord(r, gen); } catch (error) { await this.refresh(error instanceof RegistrationError ? error.code : "operation_failed"); throw error; }
    });
  }
  async recover(): Promise<void> {
    await this.locked(async gen => {
      const r = await this.reload(); if (!r || r.phase === "prepared" || r.phase === "abandoned") throw new RegistrationError("invalid_phase");
      try { const result = await this.lookup(r); if (result.completed_at_unix_secs !== null) await this.activate(r, result, gen);
        else { r.phase = "pending"; await this.save(r, gen); this.publish(r); }
      } catch (error) { await this.refresh(error instanceof RegistrationError ? error.code : "operation_failed"); throw error; }
    });
  }
  async retryProvision(): Promise<void> {
    await this.locked(async gen => {
      const r = await this.reload(); if (!r || !["provision-unknown", "pending"].includes(r.phase)) throw new RegistrationError("invalid_phase");
      try {
        try { const value = await this.lookup(r); if (value.completed_at_unix_secs !== null) return await this.activate(r, value, gen);
          r.phase = "pending"; await this.save(r, gen); this.publish(r); return; }
        catch (error) { if (!(error instanceof RegistrationError) || error.status !== 404 || error.code !== "not_found") throw error; }
        await this.provisionRecord(r, gen);
      } catch (error) { await this.refresh(error instanceof RegistrationError ? error.code : "operation_failed"); throw error; }
    });
  }
  async complete(): Promise<void> {
    await this.locked(async gen => {
      const r = await this.reload(); if (!r || !["pending", "complete-unknown", "provision-unknown"].includes(r.phase)) throw new RegistrationError("invalid_phase");
      try {
        const result = await this.lookup(r);
        if (result.completed_at_unix_secs !== null) return await this.activate(r, result, gen);
        const now = Math.floor(Date.now() / 1000);
        if ((result.expires_at_unix_secs as number) <= now) throw new RegistrationError("registration_expired");
        const challenge = await this.request("/devices/proof/challenges", { tenant_id: this.target.tenant_id, device_id: this.target.device_id, purpose: "device_registration" }, 200);
        this.check(gen);
        if (!exactKeys(challenge, ["challenge", "expires_at_unix_secs"]) || !b64url32(challenge.challenge) || !safeTime(challenge.expires_at_unix_secs) || challenge.expires_at_unix_secs <= Math.floor(Date.now() / 1000)) throw new RegistrationError("challenge_invalid");
        if ((result.expires_at_unix_secs as number) <= Math.floor(Date.now() / 1000)) throw new RegistrationError("registration_expired");
        const signature = await this.signer.signRegistration({ ...context(r), challenge: challenge.challenge }); this.check(gen);
        if (!b64url64(signature) || Math.floor(Date.now() / 1000) >= challenge.expires_at_unix_secs || Math.floor(Date.now() / 1000) >= (result.expires_at_unix_secs as number)) throw new RegistrationError("signature_invalid");
        r.phase = "complete-unknown"; await this.save(r, gen); this.publish(r);
        if (Math.floor(Date.now() / 1000) >= challenge.expires_at_unix_secs || Math.floor(Date.now() / 1000) >= (result.expires_at_unix_secs as number)) throw new RegistrationError("registration_expired");
        const key = await this.request("/devices/complete", { tenant_id: this.target.tenant_id, device_id: this.target.device_id,
          public_jwk: wirePublicJwk(r), challenge: challenge.challenge, signature }, 200);
        this.check(gen);
        if (!exactKeys(key, ["tenant_id", "device_id", "key_id", "version"]) || key.tenant_id !== this.target.tenant_id || key.device_id !== this.target.device_id || key.key_id !== r.key_id || key.version !== 1) throw new RegistrationError("invalid_response");
        const latest = await this.lookup(r);
        await this.activate(r, latest, gen);
      } catch (error) { await this.refresh(error instanceof RegistrationError ? error.code : "operation_failed"); throw error; }
    });
  }
  async discard(): Promise<void> {
    await this.locked(async gen => {
      const r = await this.reload(); if (!r || r.phase !== "prepared") throw new RegistrationError("cannot_discard");
      r.phase = "abandoned"; await this.save(r, gen); this.publish(r);
      await this.signer.discard(context(r)); this.check(gen);
    });
  }
  dispose() { this.disposed = true; this.generation++; this.listeners.clear(); }
}

async function keyId(x: string): Promise<string> {
  const bytes = new TextEncoder().encode(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
