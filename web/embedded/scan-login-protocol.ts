import type { IdentityTransport } from "./client";

export interface ScanTarget {
  readonly baseUrl: string; readonly tenant_id: string; readonly client_id: string;
  readonly entry_id: string; readonly device_id: string; readonly audience: string; readonly verification_uri: string;
}
export type ScanAction = "create" | "claim" | "lookup" | "status" | "cancel" | "exchange" | "recover" | "acknowledge" | "abort" | "close-origin";
export interface ScanProgress {
  grant_id: string; mode: "device_display" | "phone_display";
  state: "waiting_user" | "waiting_device" | "awaiting_approval" | "approved" | "issued" | "denied" | "cancelled" | "expired" | "invalidated";
  version: number; server_time_unix_secs: number; expires_at_unix_secs: number; code_expires_at_unix_secs: number;
  approved_until_unix_secs: number | null; expires_in: number; poll_after_ms: number;
  delivery_state: "recoverable" | "acknowledged" | "revoked" | null;
  issuance_operation_id: string | null; recover_until_unix_secs: number | null; next_action: string;
}
export interface ScanBundle {
  session: { tenant_id: string; account_id: string; session_id: string; client_id: string; expires_at_unix_secs: number };
  tokens: { access_token: string; refresh_token: string; access_expires_at_unix_secs: number; refresh_expires_at_unix_secs: number };
  receipt_nonce: string;
}
export interface ScanSignInput {
  target: ScanTarget; action: ScanAction; purpose: string; external_path: string; body: string; challenge: string; signed_at: number;
}
export interface ScanSigner { signRequest(input: ScanSignInput): Promise<{ key_id: string; signature: string }> }
export class ScanError extends Error {
  constructor(public readonly code: string, public readonly status?: number) { super(code); this.name = "ScanError"; }
}
const purposes: Record<ScanAction, string> = {
  create: "scan_login_create", claim: "scan_login_claim", lookup: "scan_login_lookup", status: "scan_login_status", cancel: "scan_login_cancel",
  exchange: "scan_login_exchange", recover: "scan_login_recover", acknowledge: "scan_login_ack", abort: "scan_login_abort", "close-origin": "scan_login_close_origin",
};
const id = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9_.-]{1,128}$/.test(v);
const uuid = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
const time = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const positive = (v: unknown): v is number => time(v) && v > 0;
const b32 = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(v);
const b16 = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9_-]{21}[AQgw]$/.test(v);
const b64 = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9_-]{85}[AQgw]$/.test(v);
const object = (v: unknown): Record<string, unknown> => { if (!v || typeof v !== "object" || Array.isArray(v)) throw new ScanError("invalid_response"); return v as Record<string, unknown>; };
const exact = (v: object, keys: string[]) => Object.keys(v).sort().join(",") === [...keys].sort().join(",");
function base(value: unknown): string {
  if (typeof value !== "string" || !value || /[\\\u0000-\u0020\u007f]/.test(value) || /%(?:2e|2f|5c)/i.test(value) || /\/(?:\.|\.\.)(?:\/|$)/.test(value)) throw new ScanError("invalid_target");
  if (/^\/(?!\/)/.test(value)) {
    if (/[?#%]/.test(value) || value.includes("//") || /[^\x21-\x7e]/.test(value)) throw new ScanError("invalid_target");
    return value.replace(/\/$/, "") || "/";
  }
  let u: URL; try { u = new URL(value); } catch { throw new ScanError("invalid_target"); }
  if (!(u.protocol === "https:" || u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)) || u.username || u.password || /[?#]/.test(value) || u.pathname.includes("%") || u.pathname.includes("//") || /[^\x21-\x7e]/.test(u.pathname)) throw new ScanError("invalid_target");
  return u.href.replace(/\/$/, "");
}
const currentOrigin = () => typeof location === "undefined" ? "https://embedded-idp.invalid" : location.origin;
export function validateScanSourceUri(value: string): string {
  const normalized = base(value);
  const url = new URL(normalized, currentOrigin());
  if (!url.pathname.endsWith("/auth/browser/device-scan/ui")) throw new ScanError("invalid_verification_uri");
  return url.href;
}
export function validateScanTarget(input: ScanTarget): ScanTarget {
  const t = object(input);
  if (!exact(t, ["baseUrl", "tenant_id", "client_id", "entry_id", "device_id", "audience", "verification_uri"]) ||
      !id(t.tenant_id) || !id(t.client_id) || !id(t.entry_id) || !uuid(t.device_id) || typeof t.audience !== "string" || !/^[\x21-\x7e]{1,256}$/.test(t.audience) || typeof t.verification_uri !== "string") throw new ScanError("invalid_target");
  const baseUrl = base(t.baseUrl), url = new URL(baseUrl, currentOrigin());
  const verification_uri = validateScanSourceUri(t.verification_uri);
  const expected = `${url.origin}${url.pathname.replace(/\/$/, "")}/auth/browser/device-scan/ui`;
  if (verification_uri !== expected) throw new ScanError("invalid_verification_uri");
  return Object.freeze({ baseUrl, tenant_id: t.tenant_id, client_id: t.client_id, entry_id: t.entry_id, device_id: t.device_id, audience: t.audience, verification_uri });
}
export function validScanCode(value: unknown, mode: "create" | "claim"): value is string {
  return typeof value === "string" && (mode === "create" ? value.startsWith("D1.") && b32(value.slice(3)) : value.startsWith("P1.") && b16(value.slice(3)));
}
const encode = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function sha(bytes: Uint8Array): Promise<string> { return encode(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>))); }
export function scanSecret(): string { return encode(crypto.getRandomValues(new Uint8Array(32))); }
export async function scanHashSecret(secret: string): Promise<string> {
  if (!b32(secret)) throw new ScanError("invalid_secret");
  return sha(Uint8Array.from(atob(secret.replace(/-/g, "+").replace(/_/g, "/") + "="), c => c.charCodeAt(0)));
}
export async function buildDeviceScanProofBytes(input: ScanSignInput & { key_id: string }): Promise<Uint8Array> {
  const target = validateScanTarget(input.target);
  if (!Object.hasOwn(purposes, input.action) || input.purpose !== purposes[input.action] || !b32(input.key_id) || !b32(input.challenge) || !positive(input.signed_at) || typeof input.body !== "string") throw new ScanError("invalid_proof_input");
  const path = new URL(target.baseUrl, currentOrigin()).pathname.replace(/\/$/, "") + `/auth/device-scan/${input.action}`;
  if (input.external_path !== path) throw new ScanError("invalid_proof_path");
  const encoder = new TextEncoder();
  const parts = [input.purpose, target.client_id, target.entry_id].map(x => encoder.encode(x));
  const prefix = encoder.encode("EMBEDDED-IDP-SCAN-CONTEXT-V1\n");
  const bytes = new Uint8Array(prefix.length + parts.reduce((sum, p) => sum + 8 + p.length, 0));
  bytes.set(prefix); let offset = prefix.length;
  for (const p of parts) { new DataView(bytes.buffer).setBigUint64(offset, BigInt(p.length), false); offset += 8; bytes.set(p, offset); offset += p.length; }
  const bodyHash = await sha(encoder.encode(input.body)), contextHash = await sha(bytes);
  return encoder.encode(`EMBEDDED-IDP-DEVICE-SCAN-V2\ntenant-id:${target.tenant_id}\naudience:${target.audience}\nmethod:POST\npath:${path}\nbody-sha256:${bodyHash}\nchallenge:${input.challenge}\ndevice-id:${target.device_id}\nkey-id:${input.key_id}\nsigned-at:${input.signed_at}\nscan-context-sha256:${contextHash}\n`);
}
export function parseScanProgress(value: unknown, _target: ScanTarget, expected: { grant_id?: string; mode?: string; issuance_operation_id?: string } = {}): ScanProgress {
  const p = object(value);
  const keys = ["grant_id", "mode", "state", "version", "server_time_unix_secs", "expires_at_unix_secs", "code_expires_at_unix_secs", "approved_until_unix_secs", "expires_in", "poll_after_ms", "delivery_state", "issuance_operation_id", "recover_until_unix_secs", "next_action"];
  if (!exact(p, keys) || !uuid(p.grant_id) || !["device_display", "phone_display"].includes(String(p.mode)) || !["waiting_user", "waiting_device", "awaiting_approval", "approved", "issued", "denied", "cancelled", "expired", "invalidated"].includes(String(p.state)) ||
      !positive(p.version) || !time(p.server_time_unix_secs) || !time(p.expires_at_unix_secs) || !time(p.code_expires_at_unix_secs) || !time(p.expires_in) || !time(p.poll_after_ms) ||
      !(p.approved_until_unix_secs === null || time(p.approved_until_unix_secs)) || ![null, "recoverable", "acknowledged", "revoked"].includes(p.delivery_state as string | null) ||
      !(p.issuance_operation_id === null || uuid(p.issuance_operation_id)) || !(p.recover_until_unix_secs === null || time(p.recover_until_unix_secs)) || typeof p.next_action !== "string" || p.next_action.length > 128 ||
      p.delivery_state !== null && (p.state !== "issued" || p.issuance_operation_id === null || p.recover_until_unix_secs === null) ||
      expected.grant_id !== undefined && p.grant_id !== expected.grant_id || expected.mode !== undefined && p.mode !== expected.mode ||
      expected.issuance_operation_id !== undefined && p.issuance_operation_id !== null && p.issuance_operation_id !== expected.issuance_operation_id) throw new ScanError("invalid_progress");
  return { ...p } as unknown as ScanProgress;
}
export function parseScanBundle(value: unknown, target: ScanTarget): ScanBundle {
  const b = object(value), s = object(b.session), t = object(b.tokens);
  if (!exact(s, ["tenant_id", "account_id", "session_id", "client_id", "expires_at_unix_secs"]) || s.tenant_id !== target.tenant_id || s.client_id !== target.client_id || !id(s.account_id) || !uuid(s.session_id) || !positive(s.expires_at_unix_secs) ||
      !exact(t, ["access_token", "refresh_token", "access_expires_at_unix_secs", "refresh_expires_at_unix_secs"]) ||
      typeof t.access_token !== "string" || !t.access_token || t.access_token.length > 16384 || typeof t.refresh_token !== "string" || !t.refresh_token || t.refresh_token.length > 16384 ||
      !positive(t.access_expires_at_unix_secs) || !positive(t.refresh_expires_at_unix_secs) || t.access_expires_at_unix_secs > t.refresh_expires_at_unix_secs || !b32(b.receipt_nonce)) throw new ScanError("invalid_bundle");
  return { session: { ...s } as unknown as ScanBundle["session"], tokens: { ...t } as unknown as ScanBundle["tokens"], receipt_nonce: b.receipt_nonce };
}
export async function scanRequest(target: ScanTarget, signer: ScanSigner, transport: IdentityTransport, action: ScanAction, body: unknown, check: () => void): Promise<unknown> {
  if (!Object.hasOwn(purposes, action)) throw new ScanError("invalid_action");
  const dto = object(body);
  if (dto.tenant_id !== target.tenant_id) throw new ScanError("invalid_scope");
  check();
  const prefix = target.baseUrl === "/" ? "" : target.baseUrl;
  const request = async (path: string, raw: string, headers: Record<string, string> = {}) => {
    check(); let response: Response;
    try { response = await transport(prefix + path, { method: "POST", body: raw, headers: { Accept: "application/json", "Content-Type": "application/json", ...headers }, credentials: "omit", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(15_000) }); }
    catch { check(); throw new ScanError("network_unknown"); }
    check(); let value: unknown;
    try { value = await response.json(); } catch { check(); throw new ScanError("invalid_response"); }
    check();
    if (!response.ok) {
      const error = typeof value === "object" && value !== null ? (value as { error?: unknown }).error : undefined;
      const safe = ["already_acknowledged", "scan_not_found", "origin_operation_closed", "scan_not_approved", "delivery_revoked", "delivery_expired", "exchange_already_started"];
      throw new ScanError(typeof error === "string" && safe.includes(error) ? error : response.status === 429 ? "rate_limited" : "request_failed", response.status);
    }
    return value;
  };
  const challenge = object(await request("/devices/proof/challenges", JSON.stringify({ tenant_id: target.tenant_id, device_id: target.device_id, purpose: purposes[action] })));
  check();
  if (!exact(challenge, ["challenge", "expires_at_unix_secs"]) || !b32(challenge.challenge) || !positive(challenge.expires_at_unix_secs) || challenge.expires_at_unix_secs <= Date.now() / 1000) throw new ScanError("challenge_invalid");
  const raw = JSON.stringify(dto), path = `/auth/device-scan/${action}`;
  const external_path = new URL(target.baseUrl, currentOrigin()).pathname.replace(/\/$/, "") + path;
  const signed_at = Math.floor(Date.now() / 1000);
  const proof = await signer.signRequest({ target, action, purpose: purposes[action], external_path, body: raw, challenge: challenge.challenge, signed_at });
  check();
  if (!proof || !b32(proof.key_id) || !b64(proof.signature) || challenge.expires_at_unix_secs <= Date.now() / 1000) throw new ScanError("invalid_signature");
  return request(path, raw, { "x-device-id": target.device_id, "x-device-key-id": proof.key_id, "x-device-challenge": challenge.challenge,
    "x-device-signature": proof.signature, "x-device-signed-at": String(signed_at) });
}
