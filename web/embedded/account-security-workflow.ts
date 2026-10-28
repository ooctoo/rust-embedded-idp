import {
  AccountSecurityClient,
  AccountSecurityError,
  parseSecurityIntent,
  type AccountSecurityPort,
  type SecurityIntent,
  type SecuritySessionPage,
} from "./account-security-client";

export interface AccountSecurityFeatures { readonly enabled: boolean; readonly recovery: boolean }
export type SecurityJournalStage = "pending" | "ready" | "completed";
export interface SecurityJournalFlow { readonly handle: string; readonly expires_at_unix_secs: number }
export interface SecurityJournalRecord {
  readonly version: 1;
  readonly scope: string;
  readonly intent: SecurityIntent;
  readonly stage: SecurityJournalStage;
  readonly flow?: SecurityJournalFlow;
}
export interface SecurityJournalStore {
  read(): string | null;
  compareAndSet(expectedRaw: string | null, nextRaw: string | null): void;
}
export interface AccountSecurityWorkflowSnapshot {
  readonly record?: SecurityJournalRecord;
  readonly busy: boolean;
  readonly error?: string;
  readonly storageError?: "storage_unavailable" | "journal_corrupt" | "journal_conflict";
}

const maxBytes = 16 * 1024;
const errorCodes = new Set([
  "features_invalid", "security_unavailable", "operation_busy", "operation_disabled", "recovery_disabled",
  "journal_exists", "journal_corrupt", "journal_conflict", "storage_unavailable", "result_unavailable",
  "result_unconfirmed", "operation_unknown", "invalid_request", "invalid_recovery", "invalid_credentials",
  "browser_origin_rejected", "session_not_found", "rate_limited", "flow_expired", "invalid_session",
  "invalid_security_intent", "invalid_security_response", "security_random_unavailable", "security_session_changed",
]);

export class AccountSecurityWorkflowError extends Error {
  constructor(readonly code: string) { super(code); this.name = "AccountSecurityWorkflowError"; }
}

function fail(code: string): AccountSecurityWorkflowError {
  return new AccountSecurityWorkflowError(errorCodes.has(code) ? code : "security_unavailable");
}
function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
function hasKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function freezeRecord(record: SecurityJournalRecord): SecurityJournalRecord {
  if (record.flow) Object.freeze(record.flow);
  return Object.freeze(record);
}
function utf8Size(value: string): number { return new TextEncoder().encode(value).byteLength; }
function validFlowHandle(value: unknown): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{64}$/.test(value)) return false;
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
    const decoded = atob(padded);
    return decoded.length === 48 && btoa(decoded).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") === value;
  } catch { return false; }
}

export function validateAccountSecurityFeatures(value?: unknown): AccountSecurityFeatures {
  if (value === undefined) return Object.freeze({ enabled: false, recovery: false });
  if (!isObject(value) || !hasKeys(value, ["enabled", "recovery"]) ||
      typeof value.enabled !== "boolean" || typeof value.recovery !== "boolean" || (value.recovery && !value.enabled)) {
    throw fail("features_invalid");
  }
  return Object.freeze({ enabled: value.enabled, recovery: value.recovery });
}

export function createSessionSecurityJournal(scope: string, storage?: Storage): SecurityJournalStore {
  if (typeof scope !== "string" || scope.length === 0) throw fail("storage_unavailable");
  const target = storage;
  const key = `idp.account-security.v1:${encodeURIComponent(globalThis.location?.origin ?? "")}:${encodeURIComponent(scope)}`;
  const getStorage = (): Storage => target ?? globalThis.sessionStorage;
  return {
    read() {
      try { return getStorage().getItem(key); } catch { throw fail("storage_unavailable"); }
    },
    compareAndSet(expectedRaw, nextRaw) {
      let store: Storage;
      try { store = getStorage(); } catch { throw fail("storage_unavailable"); }
      try {
        if (store.getItem(key) !== expectedRaw) throw fail("journal_conflict");
        if (nextRaw === null) store.removeItem(key); else store.setItem(key, nextRaw);
        if (store.getItem(key) !== nextRaw) throw fail("storage_unavailable");
      } catch (error) {
        if (error instanceof AccountSecurityWorkflowError) throw error;
        throw fail("storage_unavailable");
      }
    },
  };
}

function parseRecord(raw: string | null, scope: string): SecurityJournalRecord | undefined {
  if (raw === null) return undefined;
  if (utf8Size(raw) > maxBytes) throw fail("journal_corrupt");
  try {
    const value: unknown = JSON.parse(raw);
    if (!isObject(value)) throw fail("journal_corrupt");
    const keys = value.flow === undefined ? ["version", "scope", "intent", "stage"] : ["version", "scope", "intent", "stage", "flow"];
    if (!hasKeys(value, keys) || value.version !== 1 || value.scope !== scope ||
        !["pending", "ready", "completed"].includes(String(value.stage))) throw fail("journal_corrupt");
    const intent = parseSecurityIntent(value.intent, scope);
    let flow: SecurityJournalFlow | undefined;
    if (value.flow !== undefined) {
      if (!isObject(value.flow) || !hasKeys(value.flow, ["handle", "expires_at_unix_secs"]) ||
          !validFlowHandle(value.flow.handle) ||
          !Number.isSafeInteger(value.flow.expires_at_unix_secs) || (value.flow.expires_at_unix_secs as number) < 0) throw fail("journal_corrupt");
      flow = Object.freeze({ handle: value.flow.handle, expires_at_unix_secs: value.flow.expires_at_unix_secs as number });
    }
    const stage = value.stage as SecurityJournalStage;
    if (intent.kind === "recovery-start") {
      if ((stage === "ready") !== !!flow || stage === "completed") throw fail("journal_corrupt");
    } else if (intent.kind === "recovery-complete") {
      if (!flow || flow.handle !== intent.handle) throw fail("journal_corrupt");
    } else if (flow) throw fail("journal_corrupt");
    return freezeRecord({ version: 1, scope, intent, stage, ...(flow ? { flow } : {}) });
  } catch (error) {
    if (error instanceof AccountSecurityWorkflowError) throw error;
    throw fail("journal_corrupt");
  }
}

function classify(error: unknown): string {
  if (error instanceof AccountSecurityWorkflowError) return error.code;
  if (error instanceof AccountSecurityError && errorCodes.has(error.code)) return error.code;
  if (isObject(error) && typeof error.code === "string" && typeof error.status === "number") {
    const allowed: Record<number, string[]> = {
      400: ["invalid_request", "invalid_recovery"], 401: ["invalid_credentials", "invalid_session"],
      403: ["browser_origin_rejected"], 404: ["session_not_found"], 429: ["rate_limited"],
    };
    if (allowed[error.status]?.includes(error.code)) return error.code;
  }
  return "operation_unknown";
}
function correctable(error: unknown): boolean {
  if (!isObject(error) || typeof error.status !== "number" || typeof error.code !== "string") return false;
  const allowed: Record<number, string[]> = {
    400: ["invalid_request", "invalid_recovery"], 401: ["invalid_credentials"],
    403: ["browser_origin_rejected"], 404: ["session_not_found"], 429: ["rate_limited"],
  };
  return allowed[error.status]?.includes(error.code) ?? false;
}

export class AccountSecurityWorkflow {
  private readonly client: AccountSecurityClient;
  private readonly store: SecurityJournalStore;
  private readonly scope: string;
  private readonly listeners = new Set<() => void>();
  private raw: string | null = null;
  private snapshot: AccountSecurityWorkflowSnapshot = Object.freeze({ busy: false });

  constructor(private readonly identity: AccountSecurityPort, private readonly features: AccountSecurityFeatures,
              store?: SecurityJournalStore) {
    this.scope = identity.accountSecurityScope;
    this.features = validateAccountSecurityFeatures(features);
    if (typeof this.scope !== "string" || this.scope.length < 1 || this.scope.length > 2048) throw fail("security_unavailable");
    this.client = new AccountSecurityClient(identity);
    try {
      this.store = store ?? createSessionSecurityJournal(this.scope);
      this.readCurrent();
    } catch (error) {
      this.store = store ?? { read: () => { throw error; }, compareAndSet: () => { throw error; } };
      this.snapshot = Object.freeze({ busy: false, storageError: classify(error) === "journal_corrupt" ? "journal_corrupt" : "storage_unavailable" });
    }
  }

  getSnapshot = (): AccountSecurityWorkflowSnapshot => this.snapshot;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  private publish(next: AccountSecurityWorkflowSnapshot): void { this.snapshot = Object.freeze(next); for (const listener of this.listeners) listener(); }
  private readCurrent(): void {
    const busy = this.snapshot.busy;
    try { this.raw = this.store.read(); }
    catch {
      this.publish({ busy, error: "storage_unavailable", storageError: "storage_unavailable" });
      return;
    }
    try {
      const record = parseRecord(this.raw, this.scope);
      this.publish({ busy, ...(record ? { record } : {}) });
    }
    catch (error) {
      const code = classify(error) === "journal_corrupt" ? "journal_corrupt" : "storage_unavailable";
      this.publish({ busy, error: code, storageError: code });
    }
  }
  refresh(): void { if (!this.snapshot.busy) this.readCurrent(); }
  private async run<T>(action: () => Promise<T>): Promise<T> {
    if (this.snapshot.busy) throw fail("operation_busy");
    this.publish({ ...this.snapshot, busy: true, error: undefined });
    try {
      let current: string | null;
      try { current = this.store.read(); } catch { throw fail("storage_unavailable"); }
      if (current !== this.raw) { this.readCurrent(); throw fail("journal_conflict"); }
      if (this.snapshot.storageError) throw fail(this.snapshot.storageError);
      return await action();
    } catch (error) {
      const code = classify(error);
      this.publish({ ...this.snapshot, busy: true, error: code });
      throw fail(code);
    } finally { this.publish({ ...this.snapshot, busy: false }); }
  }
  private save(record: SecurityJournalRecord | null): void {
    const next = record ? JSON.stringify(record) : null;
    if (next !== null && utf8Size(next) > maxBytes) throw fail("journal_corrupt");
    try {
      this.store.compareAndSet(this.raw, next);
      if (this.store.read() !== next) throw fail("storage_unavailable");
      this.raw = next;
      const parsed = parseRecord(next, this.scope);
      this.publish({ busy: true, ...(parsed ? { record: parsed } : {}) });
    } catch (error) {
      if (classify(error) === "journal_conflict") {
        this.readCurrent();
        throw fail("journal_conflict");
      }
      this.publish({ ...this.snapshot, busy: true, error: "storage_unavailable", storageError: "storage_unavailable" });
      throw fail("storage_unavailable");
    }
  }
  private requireEnabled(recovery = false): void {
    if (!this.features.enabled) throw fail("operation_disabled");
    if (recovery && !this.features.recovery) throw fail("recovery_disabled");
  }
  private record(): SecurityJournalRecord | undefined {
    if (this.snapshot.storageError) throw fail(this.snapshot.storageError);
    return this.snapshot.record;
  }
  private ensureEmptyOr(kind: SecurityIntent["kind"], match: (intent: SecurityIntent) => boolean): SecurityJournalRecord | undefined {
    const record = this.record();
    if (!record) return undefined;
    if (record.intent.kind !== kind || !match(record.intent) || record.stage === "pending" || record.stage === "completed") throw fail("journal_exists");
    return record;
  }
  private make(intent: SecurityIntent, stage: SecurityJournalStage, flow?: SecurityJournalFlow): SecurityJournalRecord {
    return freezeRecord({ version: 1, scope: this.scope, intent, stage, ...(flow ? { flow } : {}) });
  }
  async listSessions(cursor?: string): Promise<SecuritySessionPage> {
    try { return await this.client.listSessions(cursor); }
    catch (error) { throw fail(classify(error)); }
  }

  async revoke(tenant: string, session: string): Promise<void> {
    return this.run(async () => {
      this.requireEnabled();
      const old = this.ensureEmptyOr("revoke", i => i.kind === "revoke" && i.target_tenant_id === tenant && i.target_session_id === session);
      const intent = old?.intent as Extract<SecurityIntent, {kind:"revoke"}> ?? this.client.prepareRevocation(tenant, session);
      this.save(this.make(intent, "pending"));
      try { await this.client.revoke(intent); }
      catch (error) {
        if (correctable(error)) this.save(this.make(intent, "ready"));
        throw error;
      }
      this.save(this.make(intent, "completed"));
    });
  }
  async changePassword(current: string, next: string): Promise<void> {
    return this.run(async () => {
      this.requireEnabled();
      const old = this.ensureEmptyOr("password", () => true);
      const intent = old?.intent as Extract<SecurityIntent, {kind:"password"}> ?? this.client.preparePasswordChange();
      this.save(this.make(intent, "pending"));
      try { await this.client.changePassword(intent, current, next); }
      catch (error) {
        if (correctable(error)) this.save(this.make(intent, "ready"));
        throw error;
      }
      this.save(this.make(intent, "completed"));
    });
  }
  async startRecovery(email: string): Promise<void> {
    return this.run(async () => {
      this.requireEnabled(true);
      if (this.record()) throw fail("journal_exists");
      const intent = this.client.prepareRecoveryStart(email);
      this.save(this.make(intent, "pending"));
      const flow = await this.client.startRecovery(intent);
      this.save(this.make(intent, "ready", flow));
    });
  }
  async retryStart(): Promise<void> {
    return this.run(async () => {
      this.requireEnabled(true);
      const record = this.record();
      if (!record || record.intent.kind !== "recovery-start" || record.stage !== "pending") throw fail("journal_exists");
      const flow = await this.client.startRecovery(record.intent);
      this.save(this.make(record.intent, "ready", flow));
    });
  }
  async completeRecovery(code: string, newPassword: string): Promise<void> {
    return this.run(async () => {
      this.requireEnabled(true);
      const record = this.record();
      if (!record || !record.flow || record.stage !== "ready") throw fail("journal_exists");
      if (typeof code !== "string" || !/^[0-9]{6}$/.test(code) || typeof newPassword !== "string") throw fail("invalid_request");
      if (record.flow.expires_at_unix_secs <= Math.floor(Date.now() / 1000)) throw fail("flow_expired");
      const intent = record.intent.kind === "recovery-complete" ? record.intent : this.client.prepareRecoveryCompletion(record.flow.handle);
      const flow = record.flow;
      this.save(this.make(intent, "pending", flow));
      try { await this.client.completeRecovery(intent, code, newPassword); }
      catch (error) {
        if (correctable(error)) this.save(this.make(intent, "ready", flow));
        throw error;
      }
      this.save(this.make(intent, "completed", flow));
    });
  }
  async checkResult(): Promise<void> {
    return this.run(async () => {
      const record = this.record();
      if (!record || record.stage !== "pending" || record.intent.kind === "recovery-start") throw fail("result_unavailable");
      const result = await this.client.result(record.intent);
      if (!result.completed) { this.publish({ ...this.snapshot, busy: true, error: "result_unconfirmed" }); return; }
      this.save(this.make(record.intent, "completed", record.flow));
    });
  }
  discard(): void {
    if (this.snapshot.busy) throw fail("operation_busy");
    let current: string | null;
    try { current = this.store.read(); }
    catch {
      this.publish({ ...this.snapshot, error: "storage_unavailable", storageError: "storage_unavailable" });
      throw fail("storage_unavailable");
    }
    if (current !== this.raw) { this.readCurrent(); throw fail("journal_conflict"); }
    if (current === null) return;
    try {
      this.store.compareAndSet(current, null);
      if (this.store.read() !== null) throw fail("storage_unavailable");
    } catch (error) {
      const code = classify(error) === "journal_conflict" ? "journal_conflict" : "storage_unavailable";
      if (code === "journal_conflict") this.readCurrent();
      else this.publish({ ...this.snapshot, error: code, storageError: code });
      throw fail(code);
    }
    this.raw = null;
    this.publish({ busy: false });
  }
}
