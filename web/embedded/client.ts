export type LoginCapabilities =
  | { tenancy_enabled: false; login_tenant_policy: "fixed"; fixed_tenant_id: "0" }
  | { tenancy_enabled: true; login_tenant_policy: "fixed"; fixed_tenant_id: string }
  | { tenancy_enabled: true; login_tenant_policy: "choose_after_authentication" };

export interface IdentitySession {
  tenant_id: string;
  account_id: string;
  session_id: string;
  client_id: string;
}

export interface JoinedTenant {
  tenant_id: string;
  name: string;
  status: "active" | "suspended" | "archived";
  membership_status: "active" | "suspended" | "removed";
}

export interface JoinedTenantPage {
  tenants: JoinedTenant[];
  has_more: boolean;
  next_cursor?: string;
}

export interface MyRole {
  tenant_id: string;
  role_id: string;
  key: string;
  name: string;
  status: "active" | "disabled";
  kind: "business" | "system_admin" | "tenant_security_admin";
}

export interface MyRolePage {
  items: MyRole[];
  has_more: boolean;
  next_cursor?: string;
}

export interface IdentitySnapshot {
  capabilities?: LoginCapabilities;
  session?: IdentitySession;
  selecting: boolean;
  accessExpiresAt?: number;
}

export type IdentityTransport = (url: string, init: RequestInit) => Promise<Response>;

export class IdentityError extends Error {
  constructor(message: string, public readonly status?: number) { super(message); }
}

interface Credentials {
  session: IdentitySession;
  tokens: {
    access_token: string;
    refresh_token: string;
    access_expires_at_unix_secs: number;
    refresh_expires_at_unix_secs: number;
  };
}

const id = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9_.-]{1,128}$/.test(value);
const record = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidResponse();
  return value as Record<string, unknown>;
};
const invalidResponse = () => new IdentityError("身份服务返回了无效数据，请重新登录。");

function sessionFrom(value: unknown): IdentitySession {
  const session = record(value);
  if (![session.tenant_id, session.account_id, session.session_id, session.client_id].every(id)) throw invalidResponse();
  return { tenant_id: session.tenant_id as string, account_id: session.account_id as string,
    session_id: session.session_id as string, client_id: session.client_id as string };
}

function basePath(value: string) {
  if (/^\/(?!\/)[\w/.-]*$/.test(value) && !value.split("/").includes("..")) return value.replace(/\/$/, "");
  try {
    const url = new URL(value);
    if ((url.protocol === "https:" || url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) &&
        !url.username && !url.password && !url.search && !url.hash && !url.pathname.split("/").includes("..")) return url.href.replace(/\/$/, "");
  } catch { /* Invalid URLs use the same public error. */ }
  throw new Error("身份服务地址必须是以 / 开头的路径或 HTTPS 地址；本机 localhost 可使用 HTTP。");
}

/** Keeps public identity credentials in memory; callers may replace fetch to attach host device proof. */
export class EmbeddedIdentityClient {
  private readonly base: string;
  private readonly transport: IdentityTransport;
  private credentials?: Credentials;
  private selection?: { ticket: string; expiresAt: number };
  private refreshing?: Promise<Credentials>;
  private revision = 0;
  private listeners = new Set<() => void>();
  private snapshot: IdentitySnapshot = { selecting: false };

  constructor(baseUrl: string, transport: IdentityTransport = (url, init) => fetch(url, init)) {
    this.base = basePath(baseUrl);
    this.transport = transport;
  }

  getSnapshot = () => this.snapshot;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish() {
    this.snapshot = { capabilities: this.snapshot.capabilities, session: this.credentials?.session,
      selecting: !!this.selection, accessExpiresAt: this.credentials?.tokens.access_expires_at_unix_secs };
    this.listeners.forEach(listener => listener());
  }
  private current(revision: number) { if (revision !== this.revision) throw new IdentityError("操作已取消。"); }
  private clear() {
    this.revision++;
    this.credentials = undefined;
    this.selection = undefined;
    this.refreshing = undefined;
    this.publish();
  }

  private async request(path: string, method = "GET", body?: string, authorization?: string): Promise<unknown> {
    let response: Response;
    try {
      response = await this.transport(`${this.base}${path}`, {
        method, headers: { Accept: "application/json", ...(body === undefined ? {} : { "Content-Type": path === "/auth/logout" ? "application/x-www-form-urlencoded" : "application/json" }),
          ...(authorization ? { Authorization: authorization } : {}) },
        body, credentials: "omit", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(15_000),
      });
    } catch { throw new IdentityError(method === "GET" || path.startsWith("/auth/") ? "无法连接身份服务，请检查网络后重试。" : "操作结果未确认，请重新核对。"); }
    if (!response.ok) {
      const messages: Record<number, string> = { 400: "请求无效，请重新操作。", 401: "凭证无效或已过期，请重新登录。",
        403: "当前身份无权执行此操作。", 404: "身份入口不可用，请检查宿主接入。", 409: "数据已变化，请重新加载核对。", 429: "操作过于频繁，请稍后重试。" };
      throw new IdentityError(messages[response.status] ?? "身份服务暂时不可用，请稍后重试。", response.status);
    }
    if (response.status === 204 || response.status === 200 && path === "/auth/logout") return undefined;
    try { return await response.json(); } catch { throw invalidResponse(); }
  }

  async loadCapabilities() {
    const value = record(await this.request("/auth/access/capabilities"));
    if (typeof value.tenancy_enabled !== "boolean" ||
        !(value.login_tenant_policy === "fixed" && id(value.fixed_tenant_id) && (value.tenancy_enabled || value.fixed_tenant_id === "0") ||
          value.login_tenant_policy === "choose_after_authentication" && value.tenancy_enabled === true && value.fixed_tenant_id === undefined)) throw invalidResponse();
    this.snapshot = { ...this.snapshot, capabilities: value as unknown as LoginCapabilities };
    this.publish();
  }

  private accept(value: unknown, allowSelection: boolean) {
    const result = record(value);
    if (allowSelection && result.status === "tenant_selection_required" && this.canChoose()) {
      if (typeof result.selection_ticket !== "string" || !/^[A-Za-z0-9_-]+$/.test(result.selection_ticket) ||
          typeof result.expires_in !== "number" || !Number.isSafeInteger(result.expires_in) || result.expires_in <= 0) throw invalidResponse();
      this.selection = { ticket: result.selection_ticket, expiresAt: Date.now() + result.expires_in * 1000 };
    } else {
      if (result.status !== "authenticated") throw invalidResponse();
      const session = sessionFrom(result.session);
      const tokens = record(result.tokens);
      if (![tokens.access_token, tokens.refresh_token].every(v => typeof v === "string" && v.length > 0) ||
          ![tokens.access_expires_at_unix_secs, tokens.refresh_expires_at_unix_secs].every(v => typeof v === "number" && Number.isSafeInteger(v) && v > Date.now() / 1000)) throw invalidResponse();
      const capabilities = this.snapshot.capabilities;
      if (!capabilities || capabilities.login_tenant_policy === "fixed" && session.tenant_id !== capabilities.fixed_tenant_id ||
          capabilities.login_tenant_policy === "choose_after_authentication" && session.tenant_id === "0") throw invalidResponse();
      this.credentials = { session, tokens: tokens as unknown as Credentials["tokens"] };
      this.selection = undefined;
    }
    this.publish();
  }

  canChoose() { return this.snapshot.capabilities?.login_tenant_policy === "choose_after_authentication"; }
  async login(email: string, password: string) {
    if (!this.snapshot.capabilities) throw invalidResponse();
    this.clear();
    const revision = this.revision;
    const result = await this.request("/auth/login", "POST", JSON.stringify({ email, password }));
    this.current(revision);
    this.accept(result, true);
  }

  private async access(): Promise<Credentials> {
    const credentials = this.credentials;
    if (!credentials) throw new IdentityError("请先登录。", 401);
    if (this.refreshing) return this.refreshing;
    if (credentials.tokens.access_expires_at_unix_secs > Date.now() / 1000 + 30) return credentials;
    const revision = this.revision;
    const pending = (async () => {
      try {
        const value = await this.request("/auth/refresh", "POST", JSON.stringify({ refresh_token: credentials.tokens.refresh_token }));
        this.current(revision);
        const session = sessionFrom(record(value).session);
        if (session.account_id !== credentials.session.account_id || session.tenant_id !== credentials.session.tenant_id ||
            session.session_id !== credentials.session.session_id || session.client_id !== credentials.session.client_id) throw invalidResponse();
        this.accept(value, false);
        return this.credentials!;
      } catch (error) {
        if (revision === this.revision) this.clear();
        throw error;
      } finally { if (revision === this.revision) this.refreshing = undefined; }
    })();
    this.refreshing = pending;
    return pending;
  }

  /** The host uses this for its own APIs; refresh is single-flight and failed rotation clears the session. */
  async accessToken() {
    const revision = this.revision;
    const credentials = await this.access();
    this.current(revision);
    return credentials.tokens.access_token;
  }

  private async authenticated(path: string, method = "GET") {
    const revision = this.revision;
    try {
      const credentials = await this.access();
      this.current(revision);
      const result = await this.request(path, method, undefined, `Bearer ${credentials.tokens.access_token}`);
      this.current(revision);
      return result;
    } catch (error) {
      if (revision === this.revision && error instanceof IdentityError && error.status === 401) this.clear();
      throw error;
    }
  }

  async verifySession() {
    const current = this.credentials?.session;
    const session = sessionFrom(await this.authenticated("/auth/session"));
    if (!current || session.account_id !== current.account_id || session.tenant_id !== current.tenant_id || session.session_id !== current.session_id) {
      this.clear(); throw invalidResponse();
    }
  }

  async beginSwitch() {
    if (!this.canChoose()) throw new IdentityError("此入口不支持切换租户。", 403);
    const result = await this.authenticated("/auth/me/tenant-selection", "POST");
    this.accept(result, true);
  }
  cancelSelection() {
    if (this.refreshing) { this.clear(); return; }
    this.revision++;
    this.selection = undefined;
    this.publish();
  }
  private async withSelection(path: string, body?: string) {
    const selection = this.selection;
    if (!selection) throw new IdentityError("请重新登录以选择租户。", 401);
    if (selection.expiresAt <= Date.now()) { this.cancelSelection(); throw new IdentityError("租户选择已过期，请重新操作。"); }
    const revision = this.revision;
    try {
      const result = await this.request(path, body === undefined ? "GET" : "POST", body, `TenantSelection ${selection.ticket}`);
      this.current(revision);
      return result;
    } catch (error) {
      if (revision === this.revision && error instanceof IdentityError && error.status === 401) this.cancelSelection();
      throw error;
    }
  }
  async listTenants(cursor?: string): Promise<JoinedTenantPage> {
    const query = new URLSearchParams({ limit: "50", ...(cursor ? { cursor } : {}) });
    const value = record(await this.withSelection(`/auth/tenant-selection/tenants?${query}`));
    if (!Array.isArray(value.tenants) || typeof value.has_more !== "boolean" ||
        value.has_more && (typeof value.next_cursor !== "string" || !value.next_cursor) || value.tenants.length > 50) throw invalidResponse();
    const tenants = value.tenants.map(item => {
      const tenant = record(item);
      if (!id(tenant.tenant_id) || tenant.tenant_id === "0" || typeof tenant.name !== "string" ||
          !["active", "suspended", "archived"].includes(String(tenant.status)) ||
          !["active", "suspended", "removed"].includes(String(tenant.membership_status))) throw invalidResponse();
      return tenant as unknown as JoinedTenant;
    });
    return { tenants, has_more: value.has_more, next_cursor: value.next_cursor as string | undefined };
  }
  async listMyRoles(cursor?: string): Promise<MyRolePage> {
    const session = this.credentials?.session;
    if (!session) throw new IdentityError("请先登录。", 401);
    const query = new URLSearchParams({ limit: "50", ...(cursor ? { cursor } : {}) });
    const value = record(await this.authenticated(`/auth/me/roles?${query}`));
    if (!Array.isArray(value.items) || value.items.length > 50 || typeof value.has_more !== "boolean" ||
        value.has_more && (typeof value.next_cursor !== "string" || !value.next_cursor)) throw invalidResponse();
    const items = value.items.map(item => {
      const role = record(item);
      if (role.tenant_id !== session.tenant_id || !id(role.role_id) || !id(role.key) ||
          typeof role.name !== "string" || !["active", "disabled"].includes(String(role.status)) ||
          !["business", "system_admin", "tenant_security_admin"].includes(String(role.kind))) throw invalidResponse();
      return role as unknown as MyRole;
    });
    return { items, has_more: value.has_more, next_cursor: typeof value.next_cursor === "string" ? value.next_cursor : undefined };
  }
  async selectTenant(tenantId: string) {
    if (!id(tenantId) || tenantId === "0") throw new IdentityError("请选择有效租户。", 400);
    const value = await this.withSelection("/auth/tenant-selection/complete", JSON.stringify({ tenant_id: tenantId }));
    const session = sessionFrom(record(value).session);
    if (session.tenant_id !== tenantId || this.credentials && session.account_id !== this.credentials.session.account_id) {
      this.cancelSelection(); throw invalidResponse();
    }
    this.accept(value, false);
    this.revision++;
    this.refreshing = undefined;
  }

  async logout() {
    const credentials = this.credentials;
    this.clear();
    if (!credentials) return;
    try {
      await this.request("/auth/logout", "POST", new URLSearchParams({ refresh_token: credentials.tokens.refresh_token,
        client_id: credentials.session.client_id }).toString());
    } catch { throw new IdentityError("本页凭证已清除，但未能确认服务端退出。请重新登录后核查会话。"); }
  }
}
