import type {
  AccountRecord,
  AccountsResponse,
  ClientRecord,
  ClientsResponse,
  DeviceDetail,
  DevicesResponse,
  SessionsResponse,
  SessionRecord,
} from "./types";

export type AdminApiClientOptions = {
  apiKey: string;
  basePath?: string;
};

export class AdminApiError extends Error {
  readonly code?: string;
  readonly status: number;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = "AdminApiError";
    this.code = code;
    this.status = status;
  }
}

export class AdminApiClient {
  private readonly apiKey: string;
  private readonly basePath: string;

  constructor(options: AdminApiClientOptions) {
    this.apiKey = options.apiKey;
    this.basePath = options.basePath ?? "";
  }

  listAccounts(query: Record<string, string>) {
    return this.get<AccountsResponse>(`/admin/accounts${toQueryString(query)}`);
  }

  validateAccess() {
    return this.listAccounts({ limit: "1" });
  }

  createAccount(input: {
    display_name?: string | null;
    email: string;
    password: string;
  }) {
    return this.post<AccountRecord>("/admin/accounts", input);
  }

  getAccount(accountId: string) {
    return this.get<AccountRecord>(`/admin/accounts/${accountId}`);
  }

  activateAccount(accountId: string) {
    return this.post<AccountRecord>("/admin/accounts/activate", { account_id: accountId });
  }

  disableAccount(accountId: string) {
    return this.post<AccountRecord>("/admin/accounts/disable", { account_id: accountId });
  }

  setAccountPassword(accountId: string, password: string) {
    return this.post<AccountRecord>("/admin/accounts/set-password", {
      account_id: accountId,
      new_password: password,
    });
  }

  revokeAccountSessions(accountId: string) {
    return this.post("/admin/accounts/revoke-sessions", {
      account_id: accountId,
      revoked_at_unix_secs: unixNow(),
    });
  }

  listSessions(query: Record<string, string>) {
    return this.get<SessionsResponse>(`/admin/sessions${toQueryString(query)}`);
  }

  getSession(sessionId: string) {
    return this.get<SessionRecord>(`/admin/sessions/${sessionId}`);
  }

  revokeSession(sessionId: string) {
    return this.post<SessionRecord>("/admin/sessions/revoke", {
      revoked_at_unix_secs: unixNow(),
      session_id: sessionId,
    });
  }

  listClients(query: Record<string, string>) {
    return this.get<ClientsResponse>(`/admin/clients${toQueryString(query)}`);
  }

  getClient(clientId: string) {
    return this.get<ClientRecord>(`/admin/clients/${clientId}`);
  }

  upsertClient(input: {
    client_id: string;
    client_name: string;
    client_secret?: string | null;
    client_type: string;
    pkce_required: boolean;
    redirect_uris: string[];
  }) {
    return this.post<ClientRecord>("/admin/clients/upsert", input);
  }

  listDevices(query: Record<string, string>) {
    return this.get<DevicesResponse>(`/admin/devices${toQueryString(query)}`);
  }

  getDevice(deviceId: string) {
    return this.get<DeviceDetail>(`/admin/devices/${deviceId}`);
  }

  disableDevice(deviceId: string) {
    return this.post("/admin/devices/disable", { device_id: deviceId });
  }

  revokeDevice(deviceId: string) {
    return this.post("/admin/devices/revoke", { device_id: deviceId });
  }

  unbindDevice(accountId: string, deviceId: string) {
    return this.post("/admin/devices/unbind", {
      account_id: accountId,
      device_id: deviceId,
      unbound_at_unix_secs: unixNow(),
    });
  }

  private async get<T>(path: string) {
    return this.request<T>(path, { method: "GET" });
  }

  private async post<T>(path: string, body: unknown) {
    return this.request<T>(path, {
      body: JSON.stringify(body),
      method: "POST",
    });
  }

  private async request<T>(path: string, init: RequestInit) {
    const response = await fetch(`${this.basePath}${path}`, {
      ...init,
      headers: {
        "content-type": "application/json",
        "x-embedded-idp-admin-key": this.apiKey,
      },
    });

    if (!response.ok) {
      let message = `${response.status} ${response.statusText}`;
      let code: string | undefined;
      try {
        const error = await response.json();
        if (typeof error.code === "string") {
          code = error.code;
        }
        if (typeof error.message === "string") {
          message = error.message;
        }
      } catch {}
      throw new AdminApiError(message, response.status, code);
    }

    return (await response.json()) as T;
  }
}

function toQueryString(input: Record<string, string>) {
  const params = new URLSearchParams();
  Object.entries(input).forEach(([key, value]) => {
    if (value.trim()) params.set(key, value.trim());
  });
  const text = params.toString();
  return text ? `?${text}` : "";
}

function unixNow() {
  return Math.floor(Date.now() / 1000);
}
