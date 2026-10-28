import { secureRandomUuid } from "./browser-session";

export interface SecurityIdentity {
  tenant_id: string;
  account_id: string;
  session_id: string;
  client_id: string;
}

export type AccountSecurityOperation =
  | "sessions"
  | "revoke"
  | "password"
  | "revoke-result"
  | "password-result"
  | "recovery-start"
  | "recovery-complete"
  | "recovery-result";

export interface AccountSecurityPort {
  readonly accountSecurityScope: string;
  getSnapshot(): { session?: unknown };
  requestAccountSecurity(
    operation: AccountSecurityOperation,
    body: Record<string, unknown>,
    expected?: SecurityIdentity,
  ): Promise<unknown>;
  forgetAccountSecuritySession(expected: SecurityIdentity): void;
}

export interface SecuritySession {
  tenant_id: string;
  session_id: string;
  client_id: string;
  purpose: "business" | "management";
  device_id: string | null;
  created_at: number;
  expires_at: number;
  status: "active" | "expired";
  current: boolean;
}

export interface SecuritySessionPage {
  items: SecuritySession[];
  next_cursor: string | null;
}

interface IntentBase<K extends string> {
  readonly version: 1;
  readonly scope: string;
  readonly kind: K;
  readonly operation_id: string;
  readonly receipt_secret: string;
}

export interface RevocationIntent extends IntentBase<"revoke"> {
  readonly owner: Readonly<SecurityIdentity>;
  readonly target_tenant_id: string;
  readonly target_session_id: string;
}

export interface PasswordChangeIntent extends IntentBase<"password"> {
  readonly owner: Readonly<SecurityIdentity>;
}

export interface RecoveryStartIntent extends IntentBase<"recovery-start"> {
  readonly email: string;
}

export interface RecoveryCompletionIntent extends IntentBase<"recovery-complete"> {
  readonly handle: string;
}

export type SecurityIntent =
  | RevocationIntent
  | PasswordChangeIntent
  | RecoveryStartIntent
  | RecoveryCompletionIntent;

export class AccountSecurityError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: "invalid_security_intent" | "invalid_security_response" | "security_random_unavailable" | "security_session_changed",
  ) {
    super(errorMessages[code]);
    this.name = "AccountSecurityError";
  }
}

const errorMessages = {
  invalid_security_intent: "安全操作意图无效，请重新操作。",
  invalid_security_response: "身份服务返回了无效安全数据，请核对操作结果。",
  security_random_unavailable: "当前环境无法生成安全操作凭据。",
  security_session_changed: "当前身份已变化，请重新核对安全操作。",
} as const;

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const idPattern = /^[A-Za-z0-9_.-]{1,128}$/;
const secretPattern = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

function invalidIntent(): AccountSecurityError {
  return new AccountSecurityError(0, "invalid_security_intent");
}

function invalidResponse(): AccountSecurityError {
  return new AccountSecurityError(0, "invalid_security_response");
}

function sessionChanged(): AccountSecurityError {
  return new AccountSecurityError(0, "security_session_changed");
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidResponse();
  return value as Record<string, unknown>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.prototype.hasOwnProperty.call(value, key));
}

function validId(value: unknown): value is string {
  return typeof value === "string" && idPattern.test(value);
}

function validIdentity(value: unknown): value is SecurityIdentity {
  if (!isRecord(value)) return false;
  return exactKeys(value, ["tenant_id", "account_id", "session_id", "client_id"]) &&
    [value.tenant_id, value.account_id, value.session_id, value.client_id].every(validId);
}

function sameIdentity(left: SecurityIdentity, right: SecurityIdentity): boolean {
  return left.tenant_id === right.tenant_id && left.account_id === right.account_id &&
    left.session_id === right.session_id && left.client_id === right.client_id;
}

function nonzeroBytes(bytes: Uint8Array): boolean {
  return bytes.some(byte => byte !== 0);
}

function encodeBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function decodeBase64Url(value: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return undefined;
  try {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
    const bytes = Uint8Array.from(atob(base64), character => character.charCodeAt(0));
    return encodeBase64Url(bytes) === value ? bytes : undefined;
  } catch {
    return undefined;
  }
}

function validReceiptSecret(value: unknown): value is string {
  if (typeof value !== "string" || !secretPattern.test(value)) return false;
  const bytes = decodeBase64Url(value);
  return !!bytes && bytes.length === 32 && nonzeroBytes(bytes);
}

function validUuid(value: unknown): value is string {
  return typeof value === "string" && uuidPattern.test(value) && value !== "00000000-0000-0000-0000-000000000000";
}

function scopeOf(port: AccountSecurityPort): string {
  const scope = port.accountSecurityScope;
  if (typeof scope !== "string" || scope.length < 1 || scope.length > 2048) throw invalidIntent();
  return scope;
}

function currentOwner(port: AccountSecurityPort): SecurityIdentity {
  const session = port.getSnapshot().session;
  if (!validIdentity(session)) throw sessionChanged();
  return Object.freeze({
    tenant_id: session.tenant_id,
    account_id: session.account_id,
    session_id: session.session_id,
    client_id: session.client_id,
  });
}

function assertOwner(port: AccountSecurityPort, expected: SecurityIdentity, scope: string): void {
  const session = port.getSnapshot().session;
  if (scopeOf(port) !== scope || !validIdentity(session) || !sameIdentity(session, expected)) throw sessionChanged();
}

function assertScope(port: AccountSecurityPort, scope: string): void {
  if (scopeOf(port) !== scope) throw sessionChanged();
}

function makeBase<K extends string>(port: AccountSecurityPort, kind: K): IntentBase<K> {
  const scope = scopeOf(port);
  let operationId: string;
  let secretBytes: Uint8Array;
  try {
    operationId = secureRandomUuid();
    if (!validUuid(operationId) || typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") {
      throw new Error("random unavailable");
    }
    secretBytes = crypto.getRandomValues(new Uint8Array(32));
  } catch {
    throw new AccountSecurityError(0, "security_random_unavailable");
  }
  if (!nonzeroBytes(secretBytes)) throw new AccountSecurityError(0, "security_random_unavailable");
  return {
    version: 1,
    scope,
    kind,
    operation_id: operationId,
    receipt_secret: encodeBase64Url(secretBytes),
  };
}

function validateBase(value: Record<string, unknown>, kind: SecurityIntent["kind"], scope: string): boolean {
  return value.version === 1 && value.kind === kind && value.scope === scope &&
    validUuid(value.operation_id) && validReceiptSecret(value.receipt_secret);
}

function validateOwner(value: unknown): value is SecurityIdentity {
  return validIdentity(value);
}

export function parseSecurityIntent(value: unknown, scope: string): SecurityIntent {
  if (typeof scope !== "string" || scope.length < 1 || scope.length > 2048 || !isRecord(value)) throw invalidIntent();
  const intent = value;
  if (intent.scope !== scope) throw invalidIntent();
  if (intent.kind === "revoke") {
    if (!exactKeys(intent, ["version", "scope", "kind", "operation_id", "receipt_secret", "owner", "target_tenant_id", "target_session_id"]) ||
        !validateBase(intent, "revoke", scope) || !validateOwner(intent.owner) ||
        !validId(intent.target_tenant_id) || !validId(intent.target_session_id)) throw invalidIntent();
    const owner = Object.freeze({
      tenant_id: intent.owner.tenant_id,
      account_id: intent.owner.account_id,
      session_id: intent.owner.session_id,
      client_id: intent.owner.client_id,
    });
    return Object.freeze({ ...intent, owner }) as RevocationIntent;
  }
  if (intent.kind === "password") {
    if (!exactKeys(intent, ["version", "scope", "kind", "operation_id", "receipt_secret", "owner"]) ||
        !validateBase(intent, "password", scope) || !validateOwner(intent.owner)) throw invalidIntent();
    const owner = Object.freeze({
      tenant_id: intent.owner.tenant_id,
      account_id: intent.owner.account_id,
      session_id: intent.owner.session_id,
      client_id: intent.owner.client_id,
    });
    return Object.freeze({ ...intent, owner }) as PasswordChangeIntent;
  }
  if (intent.kind === "recovery-start") {
    if (!exactKeys(intent, ["version", "scope", "kind", "operation_id", "receipt_secret", "email"]) ||
        !validateBase(intent, "recovery-start", scope) || typeof intent.email !== "string" ||
        intent.email !== trimAsciiSpaces(intent.email) || !intent.email || intent.email.length > 254) throw invalidIntent();
    return Object.freeze({ ...intent }) as unknown as RecoveryStartIntent;
  }
  if (intent.kind === "recovery-complete") {
    if (!exactKeys(intent, ["version", "scope", "kind", "operation_id", "receipt_secret", "handle"]) ||
        !validateBase(intent, "recovery-complete", scope) || !validHandle(intent.handle)) throw invalidIntent();
    return Object.freeze({ ...intent }) as unknown as RecoveryCompletionIntent;
  }
  throw invalidIntent();
}

function validateIntent(port: AccountSecurityPort, value: unknown): SecurityIntent {
  return parseSecurityIntent(value, scopeOf(port));
}

function trimAsciiSpaces(value: string): string {
  return value.replace(/^ +| +$/g, "");
}

function validHandle(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 64 || !/^[A-Za-z0-9_-]{64}$/.test(value)) return false;
  return decodeBase64Url(value)?.length === 48;
}

function validCursor(value: unknown): value is string | null {
  return value === null || typeof value === "string" && value.length > 0 && value.length <= 1024 && !!decodeBase64Url(value);
}

function safeTime(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function securitySession(value: unknown): SecuritySession {
  const row = object(value);
  const keys = ["tenant_id", "session_id", "client_id", "purpose", "device_id", "created_at", "expires_at", "status", "current"];
  if (!exactKeys(row, keys) || !validId(row.tenant_id) || !validId(row.session_id) || !validId(row.client_id) ||
      !(row.purpose === "business" || row.purpose === "management") ||
      !(row.device_id === null || validId(row.device_id)) || !safeTime(row.created_at) || !safeTime(row.expires_at) ||
      !(row.status === "active" || row.status === "expired") || typeof row.current !== "boolean") throw invalidResponse();
  return {
    tenant_id: row.tenant_id,
    session_id: row.session_id,
    client_id: row.client_id,
    purpose: row.purpose,
    device_id: row.device_id as string | null,
    created_at: row.created_at,
    expires_at: row.expires_at,
    status: row.status,
    current: row.current,
  };
}

function sessionPage(value: unknown, owner: SecurityIdentity): SecuritySessionPage {
  const page = object(value);
  if (!exactKeys(page, ["items", "next_cursor"]) || !Array.isArray(page.items) || page.items.length > 50 || !validCursor(page.next_cursor)) {
    throw invalidResponse();
  }
  const items = page.items.map(securitySession);
  const seen = new Set<string>();
  for (const session of items) {
    const key = `${session.tenant_id}\0${session.session_id}`;
    const isOwnerSession = session.tenant_id === owner.tenant_id &&
      session.session_id === owner.session_id && session.client_id === owner.client_id;
    if (seen.has(key) || session.current !== isOwnerSession) throw invalidResponse();
    seen.add(key);
  }
  return { items, next_cursor: page.next_cursor };
}

function completion(value: unknown, mustBeTrue: boolean): { completed: boolean } {
  const result = object(value);
  if (!exactKeys(result, ["completed"]) || typeof result.completed !== "boolean" || mustBeTrue && result.completed !== true) {
    throw invalidResponse();
  }
  return { completed: result.completed };
}

function recoveryStarted(value: unknown): { handle: string; expires_at_unix_secs: number } {
  const result = object(value);
  if (!exactKeys(result, ["handle", "expires_at_unix_secs"]) || !validHandle(result.handle) || !safeTime(result.expires_at_unix_secs)) {
    throw invalidResponse();
  }
  return { handle: result.handle, expires_at_unix_secs: result.expires_at_unix_secs };
}

export class AccountSecurityClient {
  constructor(private readonly port: AccountSecurityPort) {}

  async listSessions(cursor?: string): Promise<SecuritySessionPage> {
    const scope = scopeOf(this.port);
    const owner = currentOwner(this.port);
    if (cursor !== undefined && !validCursor(cursor)) throw invalidIntent();
    assertOwner(this.port, owner, scope);
    const body: Record<string, unknown> = { limit: 50, ...(cursor === undefined ? {} : { cursor }) };
    const value = await this.port.requestAccountSecurity("sessions", body, owner);
    assertOwner(this.port, owner, scope);
    return sessionPage(value, owner);
  }

  prepareRevocation(targetTenantId: string, targetSessionId: string): RevocationIntent {
    const owner = currentOwner(this.port);
    if (!validId(targetTenantId) || !validId(targetSessionId)) throw invalidIntent();
    const base = makeBase(this.port, "revoke");
    return Object.freeze({ ...base, owner, target_tenant_id: targetTenantId, target_session_id: targetSessionId });
  }

  async revoke(input: RevocationIntent): Promise<{ completed: true }> {
    const intent = validateIntent(this.port, input);
    if (intent.kind !== "revoke") throw invalidIntent();
    assertOwner(this.port, intent.owner, intent.scope);
    const value = await this.port.requestAccountSecurity("revoke", {
      target_tenant_id: intent.target_tenant_id,
      target_session_id: intent.target_session_id,
      operation_id: intent.operation_id,
      receipt_secret: intent.receipt_secret,
    }, intent.owner);
    assertOwner(this.port, intent.owner, intent.scope);
    completion(value, true);
    if (intent.target_tenant_id === intent.owner.tenant_id && intent.target_session_id === intent.owner.session_id) {
      this.port.forgetAccountSecuritySession(intent.owner);
    }
    return { completed: true };
  }

  preparePasswordChange(): PasswordChangeIntent {
    const owner = currentOwner(this.port);
    return Object.freeze({ ...makeBase(this.port, "password"), owner });
  }

  async changePassword(input: PasswordChangeIntent, currentPassword: string, newPassword: string): Promise<{ completed: true }> {
    const intent = validateIntent(this.port, input);
    if (intent.kind !== "password" || typeof currentPassword !== "string" || typeof newPassword !== "string") throw invalidIntent();
    assertOwner(this.port, intent.owner, intent.scope);
    const value = await this.port.requestAccountSecurity("password", {
      current_password: currentPassword,
      new_password: newPassword,
      operation_id: intent.operation_id,
      receipt_secret: intent.receipt_secret,
    }, intent.owner);
    assertOwner(this.port, intent.owner, intent.scope);
    completion(value, true);
    this.port.forgetAccountSecuritySession(intent.owner);
    return { completed: true };
  }

  async result(input: SecurityIntent): Promise<{ completed: boolean }> {
    const intent = validateIntent(this.port, input);
    if (intent.kind === "recovery-start") throw invalidIntent();
    const operation = intent.kind === "revoke" ? "revoke-result" : intent.kind === "password" ? "password-result" : "recovery-result";
    const value = await this.port.requestAccountSecurity(operation, {
      operation_id: intent.operation_id,
      receipt_secret: intent.receipt_secret,
    });
    assertScope(this.port, intent.scope);
    const result = completion(value, false);
    if (result.completed && intent.kind === "password") this.port.forgetAccountSecuritySession(intent.owner);
    if (result.completed && intent.kind === "revoke" && intent.target_tenant_id === intent.owner.tenant_id &&
        intent.target_session_id === intent.owner.session_id) this.port.forgetAccountSecuritySession(intent.owner);
    return result;
  }

  prepareRecoveryStart(email: string): RecoveryStartIntent {
    if (typeof email !== "string") throw invalidIntent();
    const normalized = trimAsciiSpaces(email);
    if (!normalized || normalized.length > 254) throw invalidIntent();
    return Object.freeze({ ...makeBase(this.port, "recovery-start"), email: normalized });
  }

  async startRecovery(input: RecoveryStartIntent): Promise<{ handle: string; expires_at_unix_secs: number }> {
    const intent = validateIntent(this.port, input);
    if (intent.kind !== "recovery-start") throw invalidIntent();
    const value = await this.port.requestAccountSecurity("recovery-start", {
      email: intent.email,
      operation_id: intent.operation_id,
      receipt_secret: intent.receipt_secret,
    });
    assertScope(this.port, intent.scope);
    return recoveryStarted(value);
  }

  prepareRecoveryCompletion(handle: string): RecoveryCompletionIntent {
    if (!validHandle(handle)) throw invalidIntent();
    return Object.freeze({ ...makeBase(this.port, "recovery-complete"), handle });
  }

  async completeRecovery(input: RecoveryCompletionIntent, code: string, newPassword: string): Promise<{ completed: true }> {
    const intent = validateIntent(this.port, input);
    if (intent.kind !== "recovery-complete" || typeof code !== "string" || !/^\d{6}$/.test(code) || typeof newPassword !== "string") {
      throw invalidIntent();
    }
    const value = await this.port.requestAccountSecurity("recovery-complete", {
      handle: intent.handle,
      code,
      new_password: newPassword,
      operation_id: intent.operation_id,
      receipt_secret: intent.receipt_secret,
    });
    assertScope(this.port, intent.scope);
    completion(value, true);
    return { completed: true };
  }
}
