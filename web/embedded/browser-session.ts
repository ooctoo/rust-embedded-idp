type Change = "changed" | "blocked";
type Marker = { version: string; state: Change };

/** Coordinates credentials shared by the browser, without storing credentials in script storage. */
export class BrowserSessionCoordinator {
  private readonly key: string;
  private initialized = false;
  private seenVersion?: string;
  private readonly listeners = new Set<(state: Change) => void>();

  constructor(path: string, purpose: "business" | "management") {
    const origin = typeof location === "undefined" ? "unknown" : location.origin;
    this.key = `embedded-idp:browser-session:${origin}|${path}|${purpose}`;
    if (typeof window !== "undefined") window.addEventListener("storage", event => {
      if (event.key !== null && event.key !== this.key) return;
      // Read the latest marker: a queued event may describe an already superseded session.
      try { this.synchronize(this.read()); }
      catch { this.listeners.forEach(listener => listener("blocked")); }
    });
  }

  subscribe(listener: (state: Change) => void) {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  }

  private storage() {
    if (typeof localStorage === "undefined" || typeof navigator === "undefined" || !navigator.locks?.request)
      throw new Error("当前浏览器不支持安全的 Cookie 会话协调。");
    return localStorage;
  }

  private read(): Marker | undefined {
    const raw = this.storage().getItem(this.key);
    if (raw === null) return undefined;
    const value = JSON.parse(raw);
    if (!value || typeof value.version !== "string" || !["changed", "blocked"].includes(value.state))
      throw new Error("浏览器会话状态无效，请重新登录。");
    return value;
  }

  private synchronize(value: Marker | undefined) {
    const changed = this.initialized && value?.version !== this.seenVersion;
    this.initialized = true;
    this.seenVersion = value?.version;
    if (changed) this.listeners.forEach(listener => listener(value?.state ?? "changed"));
    return changed;
  }

  check() {
    const value = this.read();
    const changed = this.synchronize(value);
    if (value?.state === "blocked") throw new Error("当前浏览器会话状态不确定，请重新登录。");
    if (changed) throw new Error("浏览器会话已被其他页面替换，请重新加载。");
  }

  mark(state: Change) {
    const value: Marker = { version: secureRandomUuid(), state };
    this.storage().setItem(this.key, JSON.stringify(value));
    this.initialized = true;
    this.seenVersion = value.version;
  }

  async run<T>(operation: () => Promise<T>) {
    // Probe writability before an operation can change the server's cookie.
    const storage = this.storage();
    const probe = `${this.key}:probe`;
    storage.setItem(probe, "1"); storage.removeItem(probe);
    return navigator.locks.request(`${this.key}:lock`, { mode: "exclusive" }, operation);
  }
}

/** Produced by trusted host configuration; never infer development mode from browser capabilities. */
export interface BrowserClientConfig {
  mode: "cookie" | "development_login";
  session_ttl_secs: number | null;
  restore: boolean;
  refresh: boolean;
}

export function validateBrowserClientConfig(value: unknown): BrowserClientConfig {
  if (!value || typeof value !== "object") throw new Error("浏览器会话配置无效。");
  const c = value as BrowserClientConfig;
  if (!(c.mode === "cookie" && c.session_ttl_secs === null && c.restore === true && c.refresh === true ||
        c.mode === "development_login" && Number.isSafeInteger(c.session_ttl_secs) && c.session_ttl_secs! >= 60 && c.session_ttl_secs! <= 3600 && c.restore === false && c.refresh === false))
    throw new Error("浏览器会话配置无效。");
  return { mode: c.mode, session_ttl_secs: c.session_ttl_secs, restore: c.restore, refresh: c.refresh };
}

export function developmentBrowserMode(mode: "token" | "cookie" | "development_login" | undefined, config?: BrowserClientConfig) {
  if (config && validateBrowserClientConfig(config).mode !== mode) throw new Error("浏览器会话模式与服务端配置不一致。");
  if (mode === "development_login" && !config) throw new Error("开发登录模式需要宿主提供服务端会话配置。");
  return mode === "development_login";
}

export function privateNetworkHttp(url: URL, raw = url.href): boolean {
  const host = url.hostname;
  const parts = host.split(".");
  if (url.protocol !== "http:" || parts.length !== 4 || !parts.every(p => /^(0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255)) return false;
  // URL normalizes alternate numeric spellings; accept only the original canonical IPv4 authority.
  if (!raw.startsWith(`http://${host}/`) && !raw.startsWith(`http://${host}:`) && raw !== `http://${host}`) return false;
  const [a, b] = parts.map(Number);
  return a === 10 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168;
}

/** Cryptographic UUID v4 also works outside secure contexts; never use Math.random. */
export function secureRandomUuid(): string {
  if (typeof crypto === "undefined") throw new Error("当前浏览器不支持安全随机数。");
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  if (typeof crypto.getRandomValues !== "function") throw new Error("当前浏览器不支持安全随机数。");
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function assertBrowserOrigin(origin: string, development: boolean) {
  const url = new URL(origin);
  if (url.protocol === "https:" || url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) || development && privateNetworkHttp(url, origin)) return;
  throw new Error("浏览器会话需要 HTTPS、本机地址或显式配置的开发私网 HTTP。");
}
