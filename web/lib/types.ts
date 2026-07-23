export type AccountStatus = "active" | "disabled" | "pending_verification";
export type SessionStatus = "active" | "expired" | "pending" | "revoked";
export type DeviceStatus = "active" | "disabled" | "pending" | "revoked";
export type ClientType = "confidential_web" | "public_desktop";

export type PageResponse = {
  has_more: boolean;
  limit: number;
  next_cursor?: string | null;
  offset: number;
  returned: number;
  total: number;
};

export type AccountRecord = {
  account_id: string;
  created_at_unix_secs: number;
  display_name?: string | null;
  email: string;
  status: AccountStatus;
};

export type SessionRecord = {
  account_id: string;
  client_id: string;
  created_at_unix_secs: number;
  device_id?: string | null;
  expires_at_unix_secs: number;
  refresh_token_version: number;
  session_id: string;
  status: SessionStatus;
};

export type ClientRecord = {
  client_id: string;
  client_name: string;
  client_secret_configured: boolean;
  client_type: ClientType;
  pkce_required: boolean;
  redirect_uris: string[];
};

export type DeviceRecord = {
  client_id: string;
  device_id: string;
  proof_key_id?: string | null;
  status: DeviceStatus;
};

export type DeviceBindingRecord = {
  account_id: string;
  binding_id: string;
  device_id: string;
  status: "active" | "disabled" | "revoked";
};

export type DeviceDetail = {
  bindings: DeviceBindingRecord[];
  device: DeviceRecord;
};

export type AccountsResponse = { accounts: AccountRecord[]; page: PageResponse };
export type SessionsResponse = { page: PageResponse; sessions: SessionRecord[] };
export type ClientsResponse = { clients: ClientRecord[]; page: PageResponse };
export type DevicesResponse = { devices: DeviceRecord[]; page: PageResponse };
