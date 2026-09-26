export interface Capabilities {
  tenancy_enabled: boolean;
  login_tenant_policy: "fixed" | "choose_after_authentication";
  fixed_tenant_id?: string;
}

import { BrowserSessionCoordinator } from "../embedded/browser-session";

export interface Session {
  tenant_id: string;
  account_id: string;
  session_id: string;
  client_id?: string;
}

interface Credentials {
  session: Session;
  tokens: {
    access_token: string;
    refresh_token: string;
    access_expires_at_unix_secs: number;
    refresh_expires_at_unix_secs: number;
  };
}

export interface Tenant {
  tenant_id: string;
  name: string;
  status: "active" | "suspended" | "archived";
  membership_status: "active" | "suspended" | "removed";
}

export interface TenantPage {
  tenants: Tenant[];
  has_more: boolean;
  next_cursor?: string;
}

export interface AuthState {
  capabilities?: Capabilities;
  session?: Session;
  selecting: boolean;
  accessExpiresAt?: number;
  sessionChanged?: boolean;
}

export interface AdminPage<T> { items: T[]; has_more: boolean; next_cursor?: string | null }
export type SortOrder = "asc" | "desc";
export interface ManagedTenant {
  tenant_id: string; name: string; status: "active" | "suspended" | "archived";
}
export type InitialAdministrator = { kind: "existing"; subject_id: string } | { kind: "new"; email: string; password: string; display_name?: string };
export interface TenantDetail extends ManagedTenant { allow_registration: boolean; version: number }
export interface Role {
  tenant_id: string; role_id: string; key: string; name: string; version: number;
  status: "active" | "disabled";
  kind: "business" | "system_admin" | "tenant_security_admin";
}
export interface PermissionKey { resource_type: string; action: string }
export interface RoleDetail extends Role { permissions: PermissionKey[] }
export interface PermissionDefinition extends PermissionKey { tenant_id: string; description: string; category: "business"; enabled: boolean; archived: boolean; version: number }
export interface DirectoryPermission extends PermissionKey { tenant_id: string; description: string; category: "business" | "tenant" | "platform"; enabled: boolean; archived: boolean; version: number }
export interface PermissionDirectoryFilter { resource_type?: string; category?: DirectoryPermission["category"]; enabled?: boolean }
export interface PermissionChange { before: DirectoryPermission | null; after: DirectoryPermission }
export interface AuditRecord {
  audit_id: string; occurred_at_unix_secs: number; actor_id: string; actor_domain: string;
  actor_session_id: string | null; authentication_source: string; target_domain: string;
  operation: string; request_id: string;
}
export interface AuditDetail extends AuditRecord { change: Record<string, unknown> }
export interface AuditFilter {
  actor_id?: string; operation?: string;
  occurred_after_unix_secs?: number; occurred_before_unix_secs?: number;
}
export interface DiagnosticInput extends PermissionKey { subject_id: string; resource_id?: string }
export interface DiagnosticResult extends Omit<DiagnosticInput, "resource_id"> { audit_id: string; tenant_id: string; resource_id: string | null; decision: "allow" | "deny" }
const permissionName = (value: unknown): value is string => typeof value === "string" && /^[a-z][a-z0-9_.-]{0,63}$/.test(value);
const permissionId = (key: PermissionKey) => `${key.resource_type}::${key.action}`;
function auditRecordFrom(value: unknown, target: string): AuditRecord {
  const r = object(value);
  if (r.target_domain !== target || ![r.audit_id, r.actor_id, r.actor_domain, r.authentication_source, r.request_id].every(validId) ||
      !(r.actor_session_id === null || validId(r.actor_session_id)) || !permissionName(r.operation) || !validTime(r.occurred_at_unix_secs)) throw invalidResponse();
  return { audit_id: r.audit_id as string, occurred_at_unix_secs: r.occurred_at_unix_secs as number,
    actor_id: r.actor_id as string, actor_domain: r.actor_domain as string, actor_session_id: r.actor_session_id as string | null,
    authentication_source: r.authentication_source as string, target_domain: target, operation: r.operation as string, request_id: r.request_id as string };
}
function auditFilterQuery(filter: AuditFilter, cursor?: string) {
  if (filter.actor_id !== undefined && !validId(filter.actor_id) || filter.operation !== undefined && !permissionName(filter.operation) ||
      filter.occurred_after_unix_secs !== undefined && !validTime(filter.occurred_after_unix_secs) ||
      filter.occurred_before_unix_secs !== undefined && !validTime(filter.occurred_before_unix_secs) ||
      filter.occurred_after_unix_secs !== undefined && filter.occurred_before_unix_secs !== undefined &&
      filter.occurred_after_unix_secs > filter.occurred_before_unix_secs) throw new ManagementError("请核对审计筛选条件。", 400);
  const query = new URLSearchParams({ limit: "50", ...(cursor ? { cursor } : {}) });
  for (const key of ["actor_id", "operation", "occurred_after_unix_secs", "occurred_before_unix_secs"] as const)
    if (filter[key] !== undefined) query.set(key, String(filter[key]));
  return query;
}
function sortOrderQuery(query: URLSearchParams, sortOrder: SortOrder) {
  if (sortOrder !== "asc" && sortOrder !== "desc") throw new ManagementError("请选择有效排序方式。", 400);
  query.set("sort_order", sortOrder);
  return query;
}
function directoryPermissionFrom(value: unknown): DirectoryPermission {
  const p = object(value);
  if (!validId(p.tenant_id) || !permissionName(p.resource_type) || !permissionName(p.action) || typeof p.description !== "string" ||
      !["business", "tenant", "platform"].includes(String(p.category)) || typeof p.enabled !== "boolean" ||
      typeof p.archived !== "boolean" || !Number.isSafeInteger(p.version) || (p.version as number) < 1) throw invalidResponse();
  return { tenant_id: p.tenant_id, resource_type: p.resource_type, action: p.action, description: p.description, category: p.category as DirectoryPermission["category"], enabled: p.enabled, archived: p.archived, version: p.version as number };
}
function permissionChangesFrom(value: unknown): PermissionChange[] {
  const result = auditResult(value);
  if (!Array.isArray(result.changes) || result.changes.length > 200) throw invalidResponse();
  const seen = new Set<string>();
  return result.changes.map(value => {
    const c = object(value), after = directoryPermissionFrom(c.after);
    const before = c.before === null ? null : directoryPermissionFrom(c.before);
    const key = permissionId(after);
    if (seen.has(key) || before && (permissionId(before) !== key || before.category !== after.category || before.tenant_id !== after.tenant_id)) throw invalidResponse();
    seen.add(key);
    return { before, after };
  });
}
export interface Account {
  account_id: string; email: string; display_name: string | null;
  status: "pending_verification" | "active" | "disabled" | "closed";
}
export interface Membership { tenant_id: string; account_id: string; status: "active" | "suspended" | "removed"; version: number }
export interface Member extends Account {
  membership: Membership;
}
export type ResourceScope = { kind: "type" } | { kind: "instance"; resource_id: string };
export interface RoleBinding {
  binding_id: string; tenant_id: string; subject_id: string; role_id: string;
  resource_type: string; scope: ResourceScope;
}

export interface ManagedDevice {
  tenant_id: string; device_id: string; client_id: string; device_name: string;
  proof_key_id: string | null; status: "pending" | "active" | "disabled" | "revoked";
  registered_at_unix_secs: number; last_seen_at_unix_secs: number | null;
}
export interface ManagedSession {
  tenant_id: string; session_id: string; account_id: string; client_id: string; device_id: string | null;
  status: "pending" | "active" | "revoked" | "expired";
  created_at_unix_secs: number; expires_at_unix_secs: number; authenticated_at_unix_secs: number; scope: string | null;
}
export interface DeviceFilter {
  account_id?: string; client_id?: string; status?: ManagedDevice["status"];
  registered_after_unix_secs?: number; registered_before_unix_secs?: number;
}
export interface SessionFilter {
  account_id?: string; client_id?: string; device_id?: string; status?: ManagedSession["status"];
  created_after_unix_secs?: number; created_before_unix_secs?: number;
}

export interface ManagedClient {
  client_id: string; client_name: string; redirect_uris: string[];
  client_type: "public_desktop" | "confidential_web";
  pkce_required: boolean; client_secret_configured: boolean;
}
export interface ClientFilter { client_type?: ManagedClient["client_type"]; pkce_required?: boolean }
export type ClientConfiguration = Omit<ManagedClient, "client_secret_configured"> & { client_secret?: string };

function clientFrom(value: unknown): ManagedClient {
  const c = object(value);
  if (!validId(c.client_id) || typeof c.client_name !== "string" || !c.client_name.trim() ||
      !Array.isArray(c.redirect_uris) || c.redirect_uris.length === 0 || c.redirect_uris.length > 32 ||
      !c.redirect_uris.every(u => typeof u === "string" && u.length > 0) ||
      !["public_desktop", "confidential_web"].includes(String(c.client_type)) ||
      typeof c.pkce_required !== "boolean" || typeof c.client_secret_configured !== "boolean" ||
      (c.client_type === "public_desktop" && (!c.pkce_required || c.client_secret_configured)) ||
      (c.client_type === "confidential_web" && !c.client_secret_configured)) throw invalidResponse();
  return { client_id: c.client_id, client_name: c.client_name, redirect_uris: [...c.redirect_uris],
    client_type: c.client_type as ManagedClient["client_type"], pkce_required: c.pkce_required, client_secret_configured: c.client_secret_configured };
}

const validId = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9_.-]{1,128}$/.test(value);
const validTime = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 8_640_000_000_000;
function requireId(value: string) {
  if (!validId(value)) throw new ManagementError("请输入有效 ID，最多 128 位字母、数字、点、下划线或连字符。", 400);
}
function deviceFrom(value: unknown, tenant: string): ManagedDevice {
  const d = object(value);
  if (d.tenant_id !== tenant || !validId(d.device_id) || !validId(d.client_id) || typeof d.device_name !== "string" ||
      !(d.proof_key_id === null || typeof d.proof_key_id === "string" && d.proof_key_id.length > 0) ||
      !["pending", "active", "disabled", "revoked"].includes(String(d.status)) || !validTime(d.registered_at_unix_secs) ||
      !(d.last_seen_at_unix_secs === null || validTime(d.last_seen_at_unix_secs))) throw invalidResponse();
  return { tenant_id: tenant, device_id: d.device_id, client_id: d.client_id, device_name: d.device_name,
    proof_key_id: d.proof_key_id as string | null, status: d.status as ManagedDevice["status"],
    registered_at_unix_secs: d.registered_at_unix_secs, last_seen_at_unix_secs: d.last_seen_at_unix_secs as number | null };
}
function managedSessionFrom(value: unknown, tenant: string): ManagedSession {
  const s = object(value);
  if (s.tenant_id !== tenant || ![s.session_id, s.account_id, s.client_id].every(validId) ||
      !(s.device_id === null || validId(s.device_id)) || !(s.scope === null || typeof s.scope === "string") ||
      !["pending", "active", "revoked", "expired"].includes(String(s.status)) ||
      ![s.created_at_unix_secs, s.expires_at_unix_secs, s.authenticated_at_unix_secs].every(validTime)) throw invalidResponse();
  return { tenant_id: tenant, session_id: s.session_id as string, account_id: s.account_id as string, client_id: s.client_id as string,
    device_id: s.device_id as string | null, scope: s.scope as string | null, status: s.status as ManagedSession["status"],
    created_at_unix_secs: s.created_at_unix_secs as number, expires_at_unix_secs: s.expires_at_unix_secs as number, authenticated_at_unix_secs: s.authenticated_at_unix_secs as number };
}
function filterQuery(filter: DeviceFilter | SessionFilter, statuses: string[], after: string, before: string, cursor?: string) {
  const query = new URLSearchParams({ limit: "50", ...(cursor ? { cursor } : {}) });
  for (const key of ["account_id", "client_id", "device_id"] as const) {
    const value = (filter as SessionFilter)[key];
    if (value !== undefined) { requireId(value); query.set(key, value); }
  }
  if (filter.status !== undefined) {
    if (!statuses.includes(filter.status)) throw new ManagementError("请选择有效状态。", 400);
    query.set("status", filter.status);
  }
  const values = filter as Record<string, unknown>;
  for (const key of [after, before]) {
    if (values[key] !== undefined) {
      if (!validTime(values[key])) throw new ManagementError("请选择有效时间。", 400);
      query.set(key, String(values[key]));
    }
  }
  if (values[after] !== undefined && values[before] !== undefined && (values[after] as number) > (values[before] as number)) {
    throw new ManagementError("开始时间不能晚于结束时间。", 400);
  }
  return query;
}
function auditResult(value: unknown) {
  const result = object(value);
  if (typeof result.audit_id !== "string" || !result.audit_id) throw invalidResponse();
  return result;
}

export interface SecurityAdministrator {
  tenant_id: string; tenant_status: ManagedTenant["status"];
  account: Account & { membership: Membership | null };
  role: Role; binding: RoleBinding | null;
}

function tenantDetailFrom(value: unknown, tenant: string): TenantDetail {
  const t = object(value);
  if (t.tenant_id !== tenant || tenant === "0" || typeof t.name !== "string" ||
      !["active", "suspended", "archived"].includes(String(t.status)) || typeof t.allow_registration !== "boolean" ||
      !Number.isSafeInteger(t.version) || (t.version as number) < 1) throw invalidResponse();
  return t as unknown as TenantDetail;
}

function accountFrom(value: unknown): Account {
  const a = object(value);
  if (typeof a.account_id !== "string" || !a.account_id || typeof a.email !== "string" ||
      !(a.display_name === null || typeof a.display_name === "string") ||
      !["pending_verification", "active", "disabled", "closed"].includes(String(a.status))) throw invalidResponse();
  return { account_id: a.account_id, email: a.email, display_name: a.display_name as string | null, status: a.status as Account["status"] };
}

function membershipFrom(value: unknown, tenant: string, subject: string): Membership {
  const m = object(value);
  if (m.tenant_id !== tenant || m.account_id !== subject || !["active", "suspended", "removed"].includes(String(m.status)) ||
      !Number.isSafeInteger(m.version) || (m.version as number) < 1) throw invalidResponse();
  return m as unknown as Membership;
}

function memberFrom(value: unknown, tenant: string): Member {
  const account = accountFrom(value);
  return { ...account, membership: membershipFrom(object(value).membership, tenant, account.account_id) };
}

function bindingFrom(value: unknown, tenant: string, subject: string): RoleBinding {
  const b = object(value);
  const scope = object(b.scope);
  if (b.tenant_id !== tenant || b.subject_id !== subject ||
      ![b.binding_id, b.role_id, b.resource_type].every(v => typeof v === "string" && v.length) ||
      !(scope.kind === "type" && scope.resource_id === undefined ||
        scope.kind === "instance" && typeof scope.resource_id === "string" && /^[A-Za-z0-9_.-]{1,256}$/.test(scope.resource_id))) throw invalidResponse();
  return b as unknown as RoleBinding;
}

function pageFrom<T>(value: unknown, decode: (item: unknown) => T): AdminPage<T> {
  const page = object(value);
  if (!Array.isArray(page.items) || page.items.length > 50 || typeof page.has_more !== "boolean" ||
      (page.has_more && (typeof page.next_cursor !== "string" || !page.next_cursor))) throw invalidResponse();
  return { items: page.items.map(decode), has_more: page.has_more, next_cursor: page.has_more ? page.next_cursor as string : undefined };
}

function roleFrom(value: unknown, tenant: string): Role {
  const r = object(value);
  if (r.tenant_id !== tenant || ![r.role_id, r.key, r.name].every(v => typeof v === "string" && v.length) ||
      typeof r.version !== "number" || !Number.isSafeInteger(r.version) || r.version < 1 ||
      !["active", "disabled"].includes(String(r.status)) || !["business", "system_admin", "tenant_security_admin"].includes(String(r.kind))) throw invalidResponse();
  return r as unknown as Role;
}

function detailFrom(value: unknown, tenant: string): RoleDetail {
  const role = roleFrom(value, tenant);
  const permissions = object(value).permissions;
  if (!Array.isArray(permissions) || permissions.length > 200) throw invalidResponse();
  for (const entry of permissions) {
    const p = object(entry);
    if (![p.resource_type, p.action].every(v => typeof v === "string" && v.length)) throw invalidResponse();
  }
  return { ...role, permissions: permissions as RoleDetail["permissions"] };
}

export class ManagementError extends Error {
  status: number;
  constructor(message: string, status = 0) {
    super(message);
    this.status = status;
  }
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidResponse();
  return value as Record<string, unknown>;
}

function invalidResponse() {
  return new ManagementError("管理服务响应无效，请重新登录或联系管理员。");
}

function sessionFrom(value: unknown): Session {
  const s = object(value);
  if (![s.tenant_id, s.account_id, s.session_id].every(v => typeof v === "string" && v.length)) {
    throw invalidResponse();
  }
  return { tenant_id: s.tenant_id as string, account_id: s.account_id as string, session_id: s.session_id as string,
    ...(typeof s.client_id === "string" && s.client_id.length ? { client_id: s.client_id } : {}) };
}

// Credentials never enter React state, browser storage or the legacy API-key client.
export class ManagementClient {
  private basePath: string;
  private credentials?: Credentials;
  private selection?: { ticket: string; expiresAt: number };
  private revision = 0;
  private refreshing?: Promise<Credentials>;
  private listeners = new Set<() => void>();
  private state: AuthState = { selecting: false };
  private sessionChanged = false;
  private readonly browser?: BrowserSessionCoordinator;
  private restoring?: Promise<Session | undefined>;

  constructor(basePath = "/api", options: { mode?: "token" | "cookie" } = {}) {
    if (!/^\/(?!\/)[\w/.-]*$/.test(basePath) || basePath.split("/").includes("..")) {
      throw new Error("管理 API 前缀必须是同源绝对路径。");
    }
    this.basePath = basePath.replace(/\/$/, "");
    if (options.mode === "cookie") {
      this.basePath = new URL(this.basePath || "/", "https://embedded-idp.invalid").pathname.replace(/\/$/, "");
      this.browser = new BrowserSessionCoordinator(`${this.basePath}/admin/auth/browser`, "management");
      this.browser.subscribe(() => { this.sessionChanged = true; this.clear(); });
    }
  }

  getSnapshot = () => this.state;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };

  private publish() {
    this.state = {
      capabilities: this.state.capabilities,
      session: this.credentials?.session,
      ...(this.sessionChanged ? { sessionChanged: true } : {}),
      selecting: !!this.selection,
      accessExpiresAt: this.credentials?.tokens.access_expires_at_unix_secs,
    };
    this.listeners.forEach(listener => listener());
  }

  private current(revision: number) {
    if (revision !== this.revision) throw new ManagementError("操作已取消。");
  }

  private clear() {
    this.revision++;
    this.credentials = undefined;
    this.selection = undefined;
    this.refreshing = undefined;
    this.publish();
  }

  private async request(path: string, method = "GET", body?: unknown, authorization?: string, target?: string): Promise<unknown> {
    let response: Response;
    try {
      response = await fetch(`${this.basePath}/admin${path}`, {
        method,
        headers: {
          Accept: "application/json",
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          ...(authorization ? { Authorization: authorization } : {}),
          ...(target === undefined ? {} : { "X-Embedded-Idp-Tenant-Id": target }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "omit", cache: "no-store", redirect: "error",
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      throw new ManagementError(method === "GET" || path.startsWith("/auth/") ? "无法连接管理服务，请检查网络后重试。" : "操作结果未确认，请先重新加载数据核对，勿重复提交。");
    }
    if (!response.ok) {
      const messages: Record<number, string> = {
        400: "请求无效，请重新操作。", 401: "凭证无效或已过期，请重新登录。",
        403: "当前账号无权执行此操作。",
        404: path.startsWith("/auth/") ? "管理入口不可用，请检查宿主接入配置。" : "目标资源不存在或不可见，请重新加载。",
        409: "数据已变化或操作与当前状态冲突，请重新加载后核对。",
        429: "操作过于频繁，请稍后重试。",
      };
      throw new ManagementError(messages[response.status] ?? "管理服务暂时不可用，请稍后重试。", response.status);
    }
    if (response.status === 204) return undefined;
    try { return await response.json(); } catch { throw invalidResponse(); }
  }

  isCookieMode() { return !!this.browser; }
  private expectedSession() {
    const session = this.credentials?.session;
    return session && { expected_session: session };
  }
  private async browserRequest(path: string, body: Record<string, unknown> = {}, authorization?: string): Promise<unknown> {
    if (!this.browser) throw new ManagementError("当前客户端未启用 Cookie 会话。", 400);
    let response: Response;
    try {
      response = await fetch(`${this.basePath}/admin/auth/browser${path}`, { method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json", "X-Embedded-Idp-Browser": "1", ...(authorization ? { Authorization: authorization } : {}) },
        body: JSON.stringify(body), credentials: "same-origin", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(15_000) });
    } catch { throw new ManagementError("无法连接管理服务，请检查网络后重试。"); }
    if (!response.ok) {
      const messages: Record<number, string> = { 400: "请求无效，请重新操作。", 401: "凭证无效或已过期，请重新登录。", 403: "当前账号无权执行此操作。", 409: "浏览器会话已被其他页面替换，请重新加载。", 429: "操作过于频繁，请稍后重试。" };
      throw new ManagementError(messages[response.status] ?? "管理服务暂时不可用，请稍后重试。", response.status);
    }
    if (response.status === 204) return undefined;
    try { return await response.json(); } catch { throw invalidResponse(); }
  }

  async loadCapabilities() {
    const c = object(await this.request("/auth/capabilities"));
    if (typeof c.tenancy_enabled !== "boolean" ||
        !(c.login_tenant_policy === "fixed" && typeof c.fixed_tenant_id === "string" && c.fixed_tenant_id.length ||
          c.login_tenant_policy === "choose_after_authentication" && c.tenancy_enabled) ||
        (!c.tenancy_enabled && c.fixed_tenant_id !== "0")) throw invalidResponse();
    this.state = { ...this.state, capabilities: c as unknown as Capabilities };
    this.publish();
  }

  private accept(value: unknown, allowSelection: boolean) {
    this.sessionChanged = false;
    const result = object(value);
    if (allowSelection && result.status === "tenant_selection_required" && this.canChoose()) {
      if (typeof result.selection_ticket !== "string" || !/^[\w-]+$/.test(result.selection_ticket) ||
          typeof result.expires_in !== "number" || !Number.isSafeInteger(result.expires_in) || result.expires_in <= 0) throw invalidResponse();
      this.selection = { ticket: result.selection_ticket, expiresAt: Date.now() + result.expires_in * 1000 };
    } else {
      if (result.status !== "authenticated") throw invalidResponse();
      const session = sessionFrom(result.session);
      if (this.browser && !session.client_id) throw invalidResponse();
      const tokens = object(result.tokens);
      if (this.browser && (tokens.refresh_token !== undefined || !session.client_id)) throw invalidResponse();
      if (!(typeof tokens.access_token === "string" && tokens.access_token.length) || (!this.browser && !(typeof tokens.refresh_token === "string" && tokens.refresh_token.length)) ||
          ![tokens.access_expires_at_unix_secs, tokens.refresh_expires_at_unix_secs].every(v => typeof v === "number" && Number.isSafeInteger(v) && v > Date.now() / 1000)) throw invalidResponse();
      const c = this.state.capabilities;
      if (!c || (c.login_tenant_policy === "fixed" && session.tenant_id !== c.fixed_tenant_id) ||
          (c.login_tenant_policy === "choose_after_authentication" && session.tenant_id === "0")) throw invalidResponse();
      this.credentials = { session, tokens: tokens as unknown as Credentials["tokens"] };
      this.selection = undefined;
    }
    this.publish();
  }

  canChoose() {
    return this.state.capabilities?.tenancy_enabled && this.state.capabilities.login_tenant_policy === "choose_after_authentication";
  }

  async login(email: string, password: string) {
    if (!this.state.capabilities) throw invalidResponse();
    this.clear();
    const revision = this.revision;
    if (this.browser) {
      await this.browser.run(async () => {
        this.current(revision);
        try {
          const result = await this.browserRequest("/login", { email, password });
          this.current(revision);
          this.browser!.mark("changed");
          this.accept(result, true);
        } catch (error) { this.browserFailure(error, revision, false); throw error; }
      });
      return;
    }
    const result = await this.request("/auth/login", "POST", { email, password });
    this.current(revision); this.accept(result, true);
  }

  private browserFailure(error: unknown, revision: number, readsCookie = true) {
    if (revision !== this.revision) return;
    this.clear();
    const status = error instanceof ManagementError ? error.status : 0;
    if (status === 401 && readsCookie) this.browser!.mark("changed");
    else if (!status || status >= 500) this.browser!.mark("blocked");
  }

  async restore() {
    if (!this.browser) throw new ManagementError("当前客户端未启用 Cookie 会话。", 400);
    if (this.restoring) return this.restoring;
    const revision = this.revision;
    const expected = this.expectedSession();
    const pending = this.browser.run(async () => {
      this.browser!.check();
      this.current(revision);
      try {
        const value = await this.browserRequest("/restore", expected);
        this.current(revision);
        const restored = sessionFrom(object(value).session);
        const original = expected?.expected_session;
        if (original && (restored.tenant_id !== original.tenant_id || restored.account_id !== original.account_id ||
            restored.session_id !== original.session_id || restored.client_id !== original.client_id)) throw invalidResponse();
        this.accept(value, false);
        return this.state.session;
      } catch (error) { this.browserFailure(error, revision); throw error; }
    });
    this.restoring = pending;
    try { return await pending; } finally { if (this.restoring === pending) this.restoring = undefined; }
  }

  private async access(): Promise<Credentials> {
    if (this.browser && this.selection) throw new ManagementError("请先完成或取消租户切换。", 409);
    const credentials = this.credentials;
    if (!credentials) throw new ManagementError("请先登录。", 401);
    if (this.browser) {
      this.browser.check();
      if (this.refreshing) return this.refreshing;
      if (credentials.tokens.access_expires_at_unix_secs > Date.now() / 1000 + 30) return credentials;
      const revision = this.revision;
      const expected = this.expectedSession();
      const pending = this.browser.run(async () => {
        this.browser!.check();
        this.current(revision);
        try {
          const result = await this.browserRequest("/refresh", expected);
          this.current(revision);
          const s = sessionFrom(object(result).session);
          if (s.account_id !== credentials.session.account_id || s.tenant_id !== credentials.session.tenant_id || s.session_id !== credentials.session.session_id || s.client_id !== credentials.session.client_id) throw invalidResponse();
          this.accept(result, false);
          return this.credentials!;
        } catch (error) {
          this.browserFailure(error, revision);
          throw error;
        } finally { if (revision === this.revision) this.refreshing = undefined; }
      });
      this.refreshing = pending;
      return pending;
    }
    if (this.refreshing) return this.refreshing;
    if (credentials.tokens.access_expires_at_unix_secs > Date.now() / 1000 + 30) return credentials;
    const revision = this.revision;
    const pending = (async () => {
      try {
        const result = await this.request("/auth/refresh", "POST", { refresh_token: credentials.tokens.refresh_token });
        this.current(revision);
        const s = sessionFrom(object(result).session);
        if (s.account_id !== credentials.session.account_id || s.tenant_id !== credentials.session.tenant_id || s.session_id !== credentials.session.session_id) throw invalidResponse();
        this.accept(result, false);
        return this.credentials!;
      } catch (error) {
        // A lost refresh response may already have rotated the token. Never replay it.
        if (revision === this.revision) this.clear();
        throw error;
      } finally {
        if (revision === this.revision) this.refreshing = undefined;
      }
    })();
    this.refreshing = pending;
    return pending;
  }

  private async authenticated(path: string, method = "GET", body?: unknown, target?: string) {
    const revision = this.revision;
    try {
      const c = await this.access();
      this.current(revision);
      const result = await this.request(path, method, body, `Bearer ${c.tokens.access_token}`, target);
      this.current(revision);
      return result;
    } catch (error) {
      if (revision === this.revision && error instanceof ManagementError && error.status === 401) this.clear();
      throw error;
    }
  }

  private requireTarget(tenant: string) {
    const { session, capabilities } = this.state;
    if (!session || !capabilities || this.selection) throw new ManagementError("请先完成登录。", 401);
    if (!tenant || /[\s\x00-\x1f\x7f]/.test(tenant) ||
        (!capabilities.tenancy_enabled && tenant !== "0") ||
        (capabilities.tenancy_enabled && tenant === "0") ||
        (session.tenant_id !== "0" && session.tenant_id !== tenant)) {
      throw new ManagementError("请选择当前身份可管理的目标租户。", 403);
    }
  }

  private requirePlatform() {
    if (!this.state.capabilities || this.state.session?.tenant_id !== "0" || this.selection) {
      throw new ManagementError("此操作需要平台管理身份。", 403);
    }
  }

  private requireTenantPlatform() {
    this.requirePlatform();
    if (!this.state.capabilities?.tenancy_enabled) {
      throw new ManagementError("此操作需要已启用租户能力的平台管理身份。", 403);
    }
  }

  async getManagedTenant(tenant: string): Promise<TenantDetail> {
    this.requireTenantPlatform(); this.requireTarget(tenant);
    return tenantDetailFrom(await this.authenticated(`/tenants/${encodeURIComponent(tenant)}`), tenant);
  }

  async createTenant(tenant: string, name: string, allowRegistration: boolean, administrator: InitialAdministrator): Promise<TenantDetail> {
    this.requireTenantPlatform(); this.requireTarget(tenant);
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(tenant) || !administrator || !(administrator.kind === "existing" && administrator.subject_id || administrator.kind === "new" && administrator.email && administrator.password)) throw new ManagementError("请填写有效租户 ID 及首位管理员信息。", 400);
    const result = object(await this.authenticated("/tenants", "POST", {
      tenant_id: tenant, name, allow_registration: allowRegistration, administrator: administrator.kind === "existing" ? { kind: "existing", subject_id: administrator.subject_id } : { kind: "new", email: administrator.email, password: administrator.password, ...(administrator.display_name ? { display_name: administrator.display_name } : {}) },
    }));
    return tenantDetailFrom(result.tenant, tenant);
  }

  async updateTenant(tenant: TenantDetail, name: string, status: ManagedTenant["status"], allowRegistration: boolean): Promise<TenantDetail> {
    this.requireTenantPlatform(); this.requireTarget(tenant.tenant_id);
    const result = object(await this.authenticated(`/tenants/${encodeURIComponent(tenant.tenant_id)}`, "PATCH", {
      name, status, allow_registration: allowRegistration, expected_version: tenant.version,
    }));
    return tenantDetailFrom(result.tenant, tenant.tenant_id);
  }

  async listPlatformAccounts(email: string, cursor?: string, activeOnly = true, sortOrder: SortOrder = "desc"): Promise<AdminPage<Account>> {
    this.requirePlatform();
    const query = sortOrderQuery(new URLSearchParams({ limit: "50", ...(activeOnly ? { status: "active" } : {}), ...(email ? { email } : {}), ...(cursor ? { cursor } : {}) }), sortOrder);
    return pageFrom(await this.authenticated(`/platform/accounts?${query}`), value => {
      const account = accountFrom(value);
      if (object(value).membership !== null || (activeOnly && account.status !== "active")) throw invalidResponse();
      return account;
    });
  }

  async getAccountSecurity(subject: string): Promise<Account> {
    this.requirePlatform(); requireId(subject);
    const result = await this.authenticated(`/platform/accounts/${encodeURIComponent(subject)}`);
    const account = accountFrom(result);
    if (account.account_id !== subject || object(result).membership !== null) throw invalidResponse();
    return account;
  }

  async listClients(filter: ClientFilter = {}, cursor?: string, sortOrder: SortOrder = "desc"): Promise<AdminPage<ManagedClient>> {
    this.requirePlatform();
    const query = new URLSearchParams({ limit: "50", ...(cursor ? { cursor } : {}) });
    if (filter.client_type !== undefined) {
      if (!["public_desktop", "confidential_web"].includes(filter.client_type)) throw new ManagementError("请选择有效客户端类型。", 400);
      query.set("client_type", filter.client_type);
    }
    if (filter.pkce_required !== undefined) {
      if (typeof filter.pkce_required !== "boolean") throw new ManagementError("请选择有效 PKCE 策略。", 400);
      query.set("pkce_required", String(filter.pkce_required));
    }
    sortOrderQuery(query, sortOrder);
    return pageFrom(await this.authenticated(`/clients?${query}`), value => {
      const c = clientFrom(value);
      if (filter.client_type !== undefined && c.client_type !== filter.client_type ||
          filter.pkce_required !== undefined && c.pkce_required !== filter.pkce_required) throw invalidResponse();
      return c;
    });
  }

  async getClient(id: string): Promise<ManagedClient> {
    this.requirePlatform(); requireId(id);
    const c = clientFrom(await this.authenticated(`/clients/${encodeURIComponent(id)}`));
    if (c.client_id !== id) throw invalidResponse();
    return c;
  }

  async upsertClient(input: ClientConfiguration): Promise<ManagedClient> {
    this.requirePlatform(); requireId(input.client_id);
    const bytes = (s: string) => new TextEncoder().encode(s).length;
    if (typeof input.client_name !== "string" || !input.client_name.trim() || bytes(input.client_name) > 256 || /[\u0000-\u001f\u007f-\u009f]/.test(input.client_name) ||
        !Array.isArray(input.redirect_uris) || !input.redirect_uris.length || input.redirect_uris.length > 32 ||
        input.redirect_uris.some(u => typeof u !== "string" || !u.trim() || bytes(u) > 2048 || /[\u0000-\u001f\u007f-\u009f]/.test(u)) ||
        !["public_desktop", "confidential_web"].includes(input.client_type) || typeof input.pkce_required !== "boolean" ||
        (input.client_type === "public_desktop" && (!input.pkce_required || input.client_secret !== undefined)) ||
        (input.client_secret !== undefined && (typeof input.client_secret !== "string" || !input.client_secret.trim() || bytes(input.client_secret) > 4096))) {
      throw new ManagementError("请核对名称、回调地址、PKCE 和密钥；公开客户端必须启用 PKCE 且不能设置密钥。", 400);
    }
    const body = { client_id: input.client_id, client_name: input.client_name, redirect_uris: [...input.redirect_uris],
      client_type: input.client_type, pkce_required: input.pkce_required,
      ...(input.client_secret === undefined ? {} : { client_secret: input.client_secret }) };
    if (bytes(JSON.stringify(body)) > 16384) throw new ManagementError("客户端配置过长，请减少回调地址或字段内容（请求上限 16 KiB）。", 400);
    const result = auditResult(await this.authenticated("/clients/upsert", "POST", body));
    const c = clientFrom(result.client);
    if (c.client_id !== input.client_id || c.client_name !== input.client_name || c.client_type !== input.client_type ||
        c.pkce_required !== input.pkce_required || JSON.stringify(c.redirect_uris) !== JSON.stringify(input.redirect_uris)) throw invalidResponse();
    return c;
  }

  async createAccount(tenant: string, input: { email: string; password: string; display_name?: string }): Promise<Member> {
    this.requirePlatform(); this.requireTarget(tenant);
    if (!input.email || !input.password) throw new ManagementError("请填写邮箱和初始密码。", 400);
    const result = auditResult(await this.authenticated("/platform/accounts", "POST", {
      tenant_id: tenant, email: input.email, password: input.password, ...(input.display_name ? { display_name: input.display_name } : {}),
    }));
    const account = memberFrom(result.account, tenant);
    if (account.status !== "active" || account.membership.status !== "active") throw invalidResponse();
    return account;
  }

  async setAccountStatus(account: Account, status: "active" | "disabled"): Promise<Account> {
    this.requirePlatform(); requireId(account.account_id);
    if (!["active", "disabled"].includes(status) || account.status === "closed" || account.status === status) throw new ManagementError("当前账号状态不能执行此操作，请重新加载。", 409);
    const result = auditResult(await this.authenticated(`/platform/accounts/${encodeURIComponent(account.account_id)}/status`, "POST", { status, expected_status: account.status }));
    const updated = accountFrom(result.account);
    if (updated.account_id !== account.account_id || updated.status !== status || object(result.account).membership !== null) throw invalidResponse();
    if (this.state.session?.account_id === account.account_id) this.clear();
    return updated;
  }

  async setAccountPassword(account: Account, password: string): Promise<void> {
    this.requirePlatform(); requireId(account.account_id);
    if (account.status === "closed" || !password) throw new ManagementError("请核对账号状态并填写新密码。", 400);
    const result = auditResult(await this.authenticated(`/platform/accounts/${encodeURIComponent(account.account_id)}/password`, "POST", { new_password: password }));
    const updated = accountFrom(result.account);
    if (updated.account_id !== account.account_id || object(result.account).membership !== null) throw invalidResponse();
    if (this.state.session?.account_id === account.account_id) this.clear();
  }

  async listDevices(tenant: string, filter: DeviceFilter, cursor?: string, sortOrder: SortOrder = "desc"): Promise<AdminPage<ManagedDevice>> {
    this.requireTarget(tenant);
    const query = sortOrderQuery(filterQuery(filter, ["pending", "active", "disabled", "revoked"], "registered_after_unix_secs", "registered_before_unix_secs", cursor), sortOrder);
    return pageFrom(await this.authenticated(`/devices?${query}`, "GET", undefined, tenant), value => {
      const d = deviceFrom(value, tenant);
      if (filter.client_id !== undefined && d.client_id !== filter.client_id || filter.status !== undefined && d.status !== filter.status ||
          filter.registered_after_unix_secs !== undefined && d.registered_at_unix_secs < filter.registered_after_unix_secs ||
          filter.registered_before_unix_secs !== undefined && d.registered_at_unix_secs > filter.registered_before_unix_secs) throw invalidResponse();
      return d;
    });
  }

  async getDevice(tenant: string, id: string): Promise<ManagedDevice> {
    this.requireTarget(tenant); requireId(id);
    const d = deviceFrom(await this.authenticated(`/devices/${encodeURIComponent(id)}`, "GET", undefined, tenant), tenant);
    if (d.device_id !== id) throw invalidResponse();
    return d;
  }

  async setDeviceStatus(tenant: string, device: ManagedDevice, status: "disabled" | "revoked"): Promise<ManagedDevice> {
    this.requireTarget(tenant); requireId(device.device_id);
    if (device.tenant_id !== tenant || !["disabled", "revoked"].includes(status) || device.status === "revoked" || device.status === status) throw new ManagementError("设备状态已变化，请重新加载核对。", 409);
    const result = auditResult(await this.authenticated(`/devices/${encodeURIComponent(device.device_id)}/${status === "disabled" ? "disable" : "revoke"}`, "POST", { expected_status: device.status }, tenant));
    const updated = deviceFrom(result.device, tenant);
    if (updated.device_id !== device.device_id || updated.client_id !== device.client_id || updated.status !== status) throw invalidResponse();
    return updated;
  }

  async listSessions(tenant: string, filter: SessionFilter, cursor?: string, sortOrder: SortOrder = "desc"): Promise<AdminPage<ManagedSession>> {
    this.requireTarget(tenant);
    const query = sortOrderQuery(filterQuery(filter, ["pending", "active", "revoked", "expired"], "created_after_unix_secs", "created_before_unix_secs", cursor), sortOrder);
    return pageFrom(await this.authenticated(`/sessions?${query}`, "GET", undefined, tenant), value => {
      const s = managedSessionFrom(value, tenant);
      if (["account_id", "client_id", "device_id", "status"].some(key => (filter as Record<string, unknown>)[key] !== undefined && (filter as Record<string, unknown>)[key] !== s[key as keyof ManagedSession]) ||
          filter.created_after_unix_secs !== undefined && s.created_at_unix_secs < filter.created_after_unix_secs ||
          filter.created_before_unix_secs !== undefined && s.created_at_unix_secs > filter.created_before_unix_secs) throw invalidResponse();
      return s;
    });
  }

  async getSession(tenant: string, id: string): Promise<ManagedSession> {
    this.requireTarget(tenant); requireId(id);
    const s = managedSessionFrom(await this.authenticated(`/sessions/${encodeURIComponent(id)}`, "GET", undefined, tenant), tenant);
    if (s.session_id !== id) throw invalidResponse();
    return s;
  }

  async revokeSession(tenant: string, session: ManagedSession): Promise<ManagedSession> {
    this.requireTarget(tenant); requireId(session.session_id);
    if (session.tenant_id !== tenant || !["pending", "active"].includes(session.status)) throw new ManagementError("此会话已结束，请重新加载核对。", 409);
    const result = auditResult(await this.authenticated(`/sessions/${encodeURIComponent(session.session_id)}/revoke`, "POST", {}, tenant));
    const updated = managedSessionFrom(result.session, tenant);
    if (updated.session_id !== session.session_id || updated.account_id !== session.account_id || updated.client_id !== session.client_id || updated.device_id !== session.device_id || updated.status !== "revoked") throw invalidResponse();
    if (this.state.session?.tenant_id === tenant && this.state.session.session_id === session.session_id) this.clear();
    return updated;
  }

  async revokeSubjectSessions(tenant: string, subject: string): Promise<number> {
    this.requireTarget(tenant); requireId(subject);
    const result = auditResult(await this.authenticated(`/accounts/${encodeURIComponent(subject)}/sessions/revoke`, "POST", {}, tenant));
    if (result.tenant_id !== tenant || result.account_id !== subject || !Number.isSafeInteger(result.revoked_session_count) || (result.revoked_session_count as number) < 0) throw invalidResponse();
    if (this.state.session?.tenant_id === tenant && this.state.session.account_id === subject) this.clear();
    return result.revoked_session_count as number;
  }

  async getMember(tenant: string, subject: string): Promise<Member> {
    this.requireTarget(tenant);
    const member = memberFrom(await this.authenticated(`/accounts/${encodeURIComponent(subject)}`, "GET", undefined, tenant), tenant);
    if (member.account_id !== subject) throw invalidResponse();
    return member;
  }

  async bindMember(tenant: string, subject: string): Promise<Membership> {
    this.requireTenantPlatform(); this.requireTarget(tenant);
    const result = object(await this.authenticated(`/members/${encodeURIComponent(subject)}/bind`, "POST", {}, tenant));
    const membership = membershipFrom(result.membership, tenant, subject);
    if (membership.status !== "active") throw invalidResponse();
    return membership;
  }

  async setMemberStatus(tenant: string, membership: Membership, status: Membership["status"]): Promise<Membership> {
    this.requireTarget(tenant);
    if (!this.state.capabilities?.tenancy_enabled || membership.tenant_id !== tenant || membership.status === "removed") {
      throw new ManagementError("此成员关系不能修改；已移除成员须由平台重新绑定。", 403);
    }
    const result = object(await this.authenticated(`/members/${encodeURIComponent(membership.account_id)}/status`, "POST", {
      status, expected_version: membership.version,
    }, tenant));
    const updated = membershipFrom(result.membership, tenant, membership.account_id);
    if (updated.status !== status) throw invalidResponse();
    return updated;
  }

  async listManagedTenants(filter: { tenant_id?: string; name?: string }, cursor?: string, sortOrder: SortOrder = "desc"): Promise<AdminPage<ManagedTenant>> {
    this.requireTenantPlatform();
    const query = sortOrderQuery(new URLSearchParams({ limit: "50", ...filter, ...(cursor ? { cursor } : {}) }), sortOrder);
    return pageFrom(await this.authenticated(`/tenants?${query}`), value => {
      const t = object(value);
      if (typeof t.tenant_id !== "string" || !t.tenant_id || t.tenant_id === "0" || typeof t.name !== "string" ||
          !["active", "suspended", "archived"].includes(String(t.status))) throw invalidResponse();
      return { tenant_id: t.tenant_id, name: t.name, status: t.status as ManagedTenant["status"] };
    });
  }

  async listRoles(tenant: string, cursor?: string, sortOrder: SortOrder = "desc"): Promise<AdminPage<Role>> {
    this.requireTarget(tenant);
    const query = sortOrderQuery(new URLSearchParams({ limit: "50", ...(cursor ? { cursor } : {}) }), sortOrder);
    return pageFrom(await this.authenticated(`/access/roles?${query}`, "GET", undefined, tenant), value => roleFrom(value, tenant));
  }

  async getRole(tenant: string, roleId: string): Promise<RoleDetail> {
    this.requireTarget(tenant);
    const role = detailFrom(await this.authenticated(`/access/roles/${encodeURIComponent(roleId)}`, "GET", undefined, tenant), tenant);
    if (role.role_id !== roleId) throw invalidResponse();
    return role;
  }

  async createRole(tenant: string, key: string, name: string): Promise<RoleDetail> {
    this.requireTarget(tenant);
    const result = object(await this.authenticated("/access/roles", "POST", { key, name }, tenant));
    const role = detailFrom(result.role, tenant);
    if (role.kind !== "business" || role.key !== key) throw invalidResponse();
    return role;
  }

  async updateRole(tenant: string, role: RoleDetail, name: string, status: Role["status"]): Promise<RoleDetail> {
    this.requireTarget(tenant);
    if (role.tenant_id !== tenant || role.kind !== "business") throw new ManagementError("保护角色不能通过业务角色页面修改。", 403);
    const result = object(await this.authenticated(`/access/roles/${encodeURIComponent(role.role_id)}`, "PATCH", {
      name, status, expected_version: role.version,
    }, tenant));
    const updated = detailFrom(result.role, tenant);
    if (updated.role_id !== role.role_id) throw invalidResponse();
    return updated;
  }

  async deleteRole(tenant: string, role: RoleDetail) {
    this.requireTarget(tenant);
    if (role.tenant_id !== tenant || role.kind !== "business") throw new ManagementError("保护角色不能通过业务角色页面删除。", 403);
    const result = object(await this.authenticated(`/access/roles/${encodeURIComponent(role.role_id)}`, "DELETE", { expected_version: role.version }, tenant));
    if (result.role !== null || typeof result.audit_id !== "string" || !result.audit_id) throw invalidResponse();
  }

  async listBusinessPermissions(tenant: string, resourceType?: string, cursor?: string, sortOrder: SortOrder = "desc"): Promise<AdminPage<PermissionDefinition>> {
    this.requireTarget(tenant);
    const query = sortOrderQuery(new URLSearchParams({ limit: "50", category: "business", enabled: "true",
      ...(resourceType ? { resource_type: resourceType } : {}), ...(cursor ? { cursor } : {}) }), sortOrder);
    return pageFrom(await this.authenticated(`/access/permissions?${query}`, "GET", undefined, tenant), value => {
      const p = object(value);
      if (![p.resource_type, p.action, p.description].every(v => typeof v === "string") ||
          !p.resource_type || !p.action || p.category !== "business" || p.enabled !== true || p.archived !== false || p.tenant_id !== tenant) throw invalidResponse();
      return p as unknown as PermissionDefinition;
    });
  }

  async listPermissionDirectory(tenant: string, filter: PermissionDirectoryFilter = {}, cursor?: string, sortOrder: SortOrder = "desc"): Promise<AdminPage<DirectoryPermission>> {
    const platform = tenant === "0" && this.state.capabilities?.tenancy_enabled;
    if (platform) this.requirePlatform(); else this.requireTarget(tenant);
    if (filter.resource_type !== undefined && !permissionName(filter.resource_type) ||
        filter.category !== undefined && !["business", "tenant", "platform"].includes(filter.category) ||
        filter.enabled !== undefined && typeof filter.enabled !== "boolean") throw new ManagementError("请核对权限目录筛选条件。", 400);
    const query = new URLSearchParams({ limit: "50", ...(cursor ? { cursor } : {}) });
    for (const key of ["resource_type", "category", "enabled"] as const) if (filter[key] !== undefined) query.set(key, String(filter[key]));
    sortOrderQuery(query, sortOrder);
    return pageFrom(await this.authenticated(`${platform ? "/platform" : "/access"}/permissions?${query}`, "GET", undefined, platform ? undefined : tenant), value => {
      const p = directoryPermissionFrom(value);
      if (p.tenant_id !== tenant || filter.resource_type !== undefined && p.resource_type !== filter.resource_type ||
          filter.category !== undefined && p.category !== filter.category || filter.enabled !== undefined && p.enabled !== filter.enabled) throw invalidResponse();
      return p;
    });
  }

  private permissionChange(value: unknown, tenant: string, key: PermissionKey, created: boolean): DirectoryPermission {
    const changes = permissionChangesFrom(value), change = changes[0];
    if (changes.length !== 1 || !change || (change.before === null) !== created ||
        change.after.tenant_id !== tenant || permissionId(change.after) !== permissionId(key) || change.after.category !== "business") throw invalidResponse();
    return change.after;
  }

  async getPermission(tenant: string, key: PermissionKey): Promise<DirectoryPermission> {
    this.requireTarget(tenant);
    if (!permissionName(key.resource_type) || !permissionName(key.action)) throw new ManagementError("权限标识无效。", 400);
    const p = directoryPermissionFrom(await this.authenticated(`/access/permissions/${encodeURIComponent(key.resource_type)}/${encodeURIComponent(key.action)}`, "GET", undefined, tenant));
    if (p.tenant_id !== tenant || permissionId(p) !== permissionId(key)) throw invalidResponse();
    return p;
  }

  async createPermission(tenant: string, key: PermissionKey, description: string): Promise<DirectoryPermission> {
    this.requireTarget(tenant);
    if (!permissionName(key.resource_type) || key.resource_type.startsWith("idp.") || !permissionName(key.action) || !description.trim() || description.length > 512) throw new ManagementError("请填写有效的权限标识和说明。", 400);
    return this.permissionChange(await this.authenticated("/access/permissions", "POST", { ...key, description: description.trim() }, tenant), tenant, key, true);
  }

  async updatePermission(tenant: string, permission: DirectoryPermission, description: string): Promise<DirectoryPermission> {
    this.requireTarget(tenant);
    if (permission.tenant_id !== tenant || permission.category !== "business" || permission.archived || !description.trim() || description.length > 512) throw new ManagementError("权限不能修改。", 400);
    const path = `/access/permissions/${encodeURIComponent(permission.resource_type)}/${encodeURIComponent(permission.action)}`;
    return this.permissionChange(await this.authenticated(path, "PATCH", { description: description.trim(), expected_version: permission.version }, tenant), tenant, permission, false);
  }

  async archivePermission(tenant: string, permission: DirectoryPermission): Promise<DirectoryPermission> {
    this.requireTarget(tenant);
    if (permission.tenant_id !== tenant || permission.category !== "business" || permission.archived) throw new ManagementError("权限不能归档。", 400);
    const path = `/access/permissions/${encodeURIComponent(permission.resource_type)}/${encodeURIComponent(permission.action)}`;
    return this.permissionChange(await this.authenticated(path, "DELETE", { expected_version: permission.version }, tenant), tenant, permission, false);
  }

  async setPermissionEnabled(tenant: string, permission: DirectoryPermission, enabled: boolean): Promise<DirectoryPermission> {
    this.requireTarget(tenant);
    if (permission.tenant_id !== tenant || permission.category !== "business" || permission.archived || enabled === permission.enabled) throw new ManagementError("权限状态无效，请重新加载。", 400);
    const path = `/access/permissions/${encodeURIComponent(permission.resource_type)}/${encodeURIComponent(permission.action)}/enabled`;
    return this.permissionChange(await this.authenticated(path, "POST", { enabled, expected_enabled: permission.enabled }, tenant), tenant, permission, false);
  }

  private async auditPage(path: string, target: string, filter: AuditFilter, cursor?: string, header?: string, sortOrder: SortOrder = "desc"): Promise<AdminPage<AuditRecord>> {
    const query = sortOrderQuery(auditFilterQuery(filter, cursor), sortOrder);
    return pageFrom(await this.authenticated(`${path}?${query}`, "GET", undefined, header), value => {
      const record = auditRecordFrom(value, target);
      if (filter.actor_id !== undefined && record.actor_id !== filter.actor_id ||
          filter.operation !== undefined && record.operation !== filter.operation ||
          filter.occurred_after_unix_secs !== undefined && record.occurred_at_unix_secs < filter.occurred_after_unix_secs ||
          filter.occurred_before_unix_secs !== undefined && record.occurred_at_unix_secs > filter.occurred_before_unix_secs) throw invalidResponse();
      return record;
    });
  }

  private async auditDetail(path: string, target: string, id: string, header?: string): Promise<AuditDetail> {
    requireId(id);
    const raw = object(await this.authenticated(`${path}/${encodeURIComponent(id)}`, "GET", undefined, header));
    const record = auditRecordFrom(raw, target);
    if (record.audit_id !== id) throw invalidResponse();
    return { ...record, change: object(raw.change) };
  }

  async listAuditEvents(tenant: string, filter: AuditFilter = {}, cursor?: string, sortOrder: SortOrder = "desc"): Promise<AdminPage<AuditRecord>> {
    this.requireTarget(tenant);
    return this.auditPage("/access/audit-events", tenant, filter, cursor, tenant, sortOrder);
  }

  async getAuditEvent(tenant: string, id: string): Promise<AuditDetail> {
    this.requireTarget(tenant);
    return this.auditDetail("/access/audit-events", tenant, id, tenant);
  }

  async listPlatformAuditEvents(filter: AuditFilter = {}, cursor?: string, sortOrder: SortOrder = "desc"): Promise<AdminPage<AuditRecord>> {
    this.requirePlatform();
    return this.auditPage("/platform/audit-events", "0", filter, cursor, undefined, sortOrder);
  }

  async getPlatformAuditEvent(id: string): Promise<AuditDetail> {
    this.requirePlatform();
    return this.auditDetail("/platform/audit-events", "0", id);
  }

  async diagnosePermission(tenant: string, input: DiagnosticInput): Promise<DiagnosticResult> {
    this.requireTarget(tenant);
    if (!input || !validId(input.subject_id) || !permissionName(input.resource_type) || !permissionName(input.action) ||
        input.resource_id !== undefined && (typeof input.resource_id !== "string" || !/^[A-Za-z0-9_.-]{1,256}$/.test(input.resource_id)))
      throw new ManagementError("请核对目标用户与权限标识。", 400);
    const result = object(await this.authenticated("/access/check", "POST", {
      subject_id: input.subject_id, resource_type: input.resource_type, action: input.action,
      ...(input.resource_id === undefined ? {} : { resource_id: input.resource_id }),
    }, tenant));
    if (result.tenant_id !== tenant || result.subject_id !== input.subject_id || result.resource_type !== input.resource_type ||
        result.action !== input.action || result.resource_id !== (input.resource_id ?? null) || !validId(result.audit_id) ||
        !["allow", "deny"].includes(String(result.decision))) throw invalidResponse();
    return { audit_id: result.audit_id as string, tenant_id: tenant, subject_id: input.subject_id,
      resource_type: input.resource_type, action: input.action, resource_id: input.resource_id ?? null,
      decision: result.decision as DiagnosticResult["decision"] };
  }

  async replaceRolePermissions(tenant: string, role: RoleDetail, permissions: PermissionKey[]): Promise<RoleDetail> {
    this.requireTarget(tenant);
    if (role.tenant_id !== tenant || role.kind !== "business") throw new ManagementError("保护角色的权限不能在此修改。", 403);
    if (permissions.length > 200 || new Set(permissions.map(p => `${p.resource_type}::${p.action}`)).size !== permissions.length ||
        permissions.some(p => !/^[a-z][a-z0-9_.-]{0,63}$/.test(p.resource_type) || !/^[a-z][a-z0-9_.-]{0,63}$/.test(p.action))) {
      throw new ManagementError("权限集合无效，最多选择 200 项且不能重复。", 400);
    }
    const result = object(await this.authenticated(`/access/roles/${encodeURIComponent(role.role_id)}/permissions`, "PUT", {
      permissions: permissions.map(({ resource_type, action }) => ({ resource_type, action })), expected_version: role.version,
    }, tenant));
    const updated = detailFrom(result.role, tenant);
    if (updated.role_id !== role.role_id) throw invalidResponse();
    return updated;
  }

  async listMembers(tenant: string, email?: string, cursor?: string, sortOrder: SortOrder = "desc"): Promise<AdminPage<Member>> {
    this.requireTarget(tenant);
    const query = sortOrderQuery(new URLSearchParams({ limit: "50", ...(email ? { email } : {}), ...(cursor ? { cursor } : {}) }), sortOrder);
    return pageFrom(await this.authenticated(`/accounts?${query}`, "GET", undefined, tenant), value => memberFrom(value, tenant));
  }

  async listRoleBindings(tenant: string, subject: string, cursor?: string, sortOrder: SortOrder = "desc"): Promise<AdminPage<RoleBinding>> {
    this.requireTarget(tenant);
    const query = sortOrderQuery(new URLSearchParams({ limit: "50", ...(cursor ? { cursor } : {}) }), sortOrder);
    return pageFrom(await this.authenticated(`/access/subjects/${encodeURIComponent(subject)}/role-bindings?${query}`, "GET", undefined, tenant), value => bindingFrom(value, tenant, subject));
  }

  async grantRole(tenant: string, subject: string, role: RoleDetail, resourceType: string, scope: ResourceScope): Promise<RoleBinding> {
    this.requireTarget(tenant);
    if (role.tenant_id !== tenant || role.kind !== "business" || role.status !== "active" || !role.permissions.some(p => p.resource_type === resourceType)) {
      throw new ManagementError("请选择当前域中启用的业务角色及其资源类型。", 403);
    }
    if (!scope || !(scope.kind === "type" && !("resource_id" in scope) ||
        scope.kind === "instance" && typeof scope.resource_id === "string" && /^[A-Za-z0-9_.-]{1,256}$/.test(scope.resource_id))) {
      throw new ManagementError("必须明确选择全部资源或一个有效的资源 ID。", 400);
    }
    const result = object(await this.authenticated(`/access/subjects/${encodeURIComponent(subject)}/role-bindings`, "POST", {
      role_id: role.role_id, resource_type: resourceType,
      scope: scope.kind === "type" ? { kind: "type" } : { kind: "instance", resource_id: scope.resource_id },
    }, tenant));
    const binding = bindingFrom(result.binding, tenant, subject);
    if (binding.role_id !== role.role_id || binding.resource_type !== resourceType || binding.scope.kind !== scope.kind ||
        (scope.kind === "instance" && binding.scope.kind === "instance" && binding.scope.resource_id !== scope.resource_id)) throw invalidResponse();
    return binding;
  }

  async revokeRoleBinding(tenant: string, binding: RoleBinding, role: RoleDetail) {
    this.requireTarget(tenant);
    if (binding.tenant_id !== tenant || role.tenant_id !== tenant || role.role_id !== binding.role_id || role.kind !== "business") {
      throw new ManagementError("保护角色请通过专用管理员任命流程管理。", 403);
    }
    const result = object(await this.authenticated(`/access/role-bindings/${encodeURIComponent(binding.binding_id)}`, "DELETE", undefined, tenant));
    if (result.binding !== null || typeof result.audit_id !== "string" || !result.audit_id) throw invalidResponse();
  }

  private securityAdministratorTarget(tenant: string, subject: string) {
    this.requirePlatform();
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(tenant) || !/^[A-Za-z0-9_.-]{1,128}$/.test(subject) ||
        (!this.state.capabilities!.tenancy_enabled && tenant !== "0")) throw new ManagementError("管理员目标域或用户无效。", 403);
    return { path: `/${tenant === "0" ? "platform" : "access"}/security-admins/${encodeURIComponent(subject)}`, target: tenant === "0" ? undefined : tenant };
  }

  async getSecurityAdministrator(tenant: string, subject: string): Promise<SecurityAdministrator> {
    const { path, target } = this.securityAdministratorTarget(tenant, subject);
    const value = object(await this.authenticated(path, "GET", undefined, target));
    const account = accountFrom(value.account), role = roleFrom(value.role, tenant);
    const member = object(value.account).membership;
    const binding = value.binding === null ? null : bindingFrom(value.binding, tenant, subject);
    if (value.tenant_id !== tenant || !["active", "suspended", "archived"].includes(String(value.tenant_status)) || account.account_id !== subject ||
        role.kind !== (tenant === "0" ? "system_admin" : "tenant_security_admin") ||
        (binding && (binding.role_id !== role.role_id || binding.resource_type !== (tenant === "0" ? "idp.platform" : "idp.tenant") || binding.scope.kind !== "type"))) throw invalidResponse();
    return { tenant_id: tenant, tenant_status: value.tenant_status as ManagedTenant["status"],
      account: { ...account, membership: member === null ? null : membershipFrom(member, tenant, subject) }, role, binding };
  }

  async setSecurityAdministrator(snapshot: SecurityAdministrator, appointed: boolean): Promise<RoleBinding | null> {
    const tenant = snapshot.tenant_id, subject = snapshot.account.account_id;
    const { path, target } = this.securityAdministratorTarget(tenant, subject);
    const kind = tenant === "0" ? "system_admin" : "tenant_security_admin";
    if (snapshot.role.tenant_id !== tenant || snapshot.role.kind !== kind || appointed === !!snapshot.binding ||
        (appointed && (snapshot.tenant_status !== "active" || snapshot.role.status !== "active" || snapshot.account.status !== "active" ||
          snapshot.account.membership?.status !== "active" || snapshot.account.membership.tenant_id !== tenant || snapshot.account.membership.account_id !== subject))) {
      throw new ManagementError("管理员状态或成员关系不满足要求，请重新加载核对。", 409);
    }
    const result = object(await this.authenticated(path, appointed ? "POST" : "DELETE", undefined, target));
    if (typeof result.audit_id !== "string" || !result.audit_id) throw invalidResponse();
    if (!appointed) { if (result.binding !== null) throw invalidResponse(); return null; }
    const binding = bindingFrom(result.binding, tenant, subject);
    if (binding.role_id !== snapshot.role.role_id || binding.resource_type !== (tenant === "0" ? "idp.platform" : "idp.tenant") || binding.scope.kind !== "type") throw invalidResponse();
    return binding;
  }

  async verifySession() {
    const s = sessionFrom(await this.authenticated("/auth/session"));
    const current = this.credentials?.session;
    if (!current || s.account_id !== current.account_id || s.tenant_id !== current.tenant_id || s.session_id !== current.session_id) {
      this.clear();
      throw invalidResponse();
    }
  }

  async beginSwitch() {
    if (!this.canChoose()) throw new ManagementError("此入口不支持切换租户。");
    this.accept(await this.authenticated("/auth/me/tenant-selection", "POST"), true);
  }

  cancelSelection() {
    // Discard an uncertain in-flight rotation rather than keep its old refresh token.
    if (this.refreshing) {
      this.clear();
      return;
    }
    this.revision++;
    this.selection = undefined;
    this.refreshing = undefined;
    this.publish();
  }

  private async withSelection(path: string, body?: unknown) {
    const selection = this.selection;
    if (!selection) throw new ManagementError("请重新登录以选择租户。");
    if (selection.expiresAt <= Date.now()) {
      this.cancelSelection();
      throw new ManagementError("租户选择已过期，请重新操作。");
    }
    const revision = this.revision;
    try {
      const result = await this.request(`/auth${path}`, body === undefined ? "GET" : "POST", body, `TenantSelection ${selection.ticket}`);
      this.current(revision);
      return result;
    } catch (error) {
      if (revision === this.revision && error instanceof ManagementError && error.status === 401) this.cancelSelection();
      throw error;
    }
  }

  async listTenants(cursor?: string): Promise<TenantPage> {
    const value = object(await this.withSelection(`/tenant-selection/tenants?${new URLSearchParams({ limit: "50", ...(cursor ? { cursor } : {}) })}`));
    if (!Array.isArray(value.tenants) || typeof value.has_more !== "boolean" ||
        (value.has_more && (typeof value.next_cursor !== "string" || !value.next_cursor))) throw invalidResponse();
    for (const item of value.tenants) {
      const t = object(item);
      if (typeof t.tenant_id !== "string" || !t.tenant_id || t.tenant_id === "0" || typeof t.name !== "string" ||
          !["active", "suspended", "archived"].includes(String(t.status)) ||
          !["active", "suspended", "removed"].includes(String(t.membership_status))) throw invalidResponse();
    }
    return value as unknown as TenantPage;
  }

  async selectTenant(tenantId: string) {
    if (this.browser) {
      const selection = this.selection;
      if (!selection || selection.expiresAt <= Date.now()) throw new ManagementError("请重新登录以选择租户。", 401);
      const revision = this.revision;
      const original = this.credentials?.session;
      await this.browser.run(async () => {
        this.browser!.check(); this.current(revision);
        try {
          const result = await this.browserRequest("/tenant-selection/complete", { tenant_id: tenantId }, `TenantSelection ${selection.ticket}`);
          this.current(revision);
          const session = sessionFrom(object(result).session);
          if (session.tenant_id !== tenantId || original && session.account_id !== original.account_id) throw invalidResponse();
          this.browser!.mark("changed");
          this.accept(result, false); this.revision++; this.refreshing = undefined;
        } catch (error) { this.browserFailure(error, revision, false); throw error; }
      });
      return;
    }
    const result = await this.withSelection("/tenant-selection/complete", { tenant_id: tenantId });
    const session = sessionFrom(object(result).session);
    if (session.tenant_id !== tenantId || (this.credentials && session.account_id !== this.credentials.session.account_id)) {
      this.cancelSelection();
      throw invalidResponse();
    }
    this.accept(result, false);
    this.revision++;
    this.refreshing = undefined;
  }

  async logout() {
    if (this.browser) {
      const expected = this.expectedSession();
      this.clear();
      const revision = this.revision;
      await this.browser.run(async () => {
        this.browser!.check(); this.current(revision);
        try {
          await this.browserRequest("/logout", expected);
          this.current(revision);
          this.browser!.mark("changed");
        } catch (error) { this.browserFailure(error, revision); throw error; }
      });
      return;
    }
    const token = this.credentials?.tokens.access_token;
    this.clear();
    if (token) {
      try { await this.request("/auth/logout", "POST", undefined, `Bearer ${token}`); }
      catch { throw new ManagementError("本页凭证已清除，但未能确认服务端退出。请重新登录后核查会话。"); }
    }
  }
}
