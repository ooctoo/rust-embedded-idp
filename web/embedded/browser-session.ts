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
    const value: Marker = { version: crypto.randomUUID(), state };
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
