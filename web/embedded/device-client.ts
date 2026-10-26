import { IdentityError, type EmbeddedIdentityClient, type IdentitySession } from "./client";
import { secureRandomUuid } from "./browser-session";

export interface SubjectDevice {
  tenant_id: string;
  device_id: string;
  client_id: string;
  proof_key_id: string | null;
  status: "pending" | "active" | "disabled" | "revoked";
  version: number;
  key_version: number | null;
  binding_id: string;
  binding_version: number;
  device_name: string;
  registered_at_unix_secs: number;
  last_seen_at_unix_secs: number | null;
  binding_status: "active" | "suspended" | "unbound";
}

export interface DevicePage {
  items: SubjectDevice[];
  has_more: boolean;
  next_cursor?: string;
}

export interface DeviceKeyMetadata {
  tenant_id: string;
  device_id: string;
  key_id: string;
  algorithm: string;
  version: number;
  status: "active" | "retired";
  registered_at_unix_secs: number;
  retired_at_unix_secs: number | null;
}

export interface UnbindIntent {
  readonly owner: Readonly<Pick<IdentitySession, "tenant_id" | "account_id" | "client_id">>;
  readonly operation_id: string;
  readonly device_id: string;
  readonly binding_id: string;
  readonly expected_version: number;
}

export interface DeviceOperationReceipt {
  operation_id: string;
  audit_id: string;
  device_id: string;
  binding_id: string | null;
  operation: "device.binding.unbind.self";
  occurred_at_unix_secs: number;
  result_version: number;
  result_status: "unbound";
}

const deviceObject = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidDeviceResponse();
  return value as Record<string, unknown>;
};
const invalidDeviceResponse = () => new IdentityError("设备服务返回的数据无效，请重新加载。", undefined, "invalid_device_response");
const deviceIdValid = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9_.-]{1,128}$/.test(value);
const keyIdValid = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
const deviceUuidValid = (value: unknown): value is string => typeof value === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
const validDeviceVersion = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) > 0;
const validDeviceTimestamp = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
const nullableDeviceValue = <T>(value: unknown, valid: (item: unknown) => item is T): value is T | null => value === null || valid(value);

function validatedDeviceSession(value: IdentitySession): IdentitySession {
  if (!deviceIdValid(value.tenant_id) || !deviceIdValid(value.account_id) || !deviceIdValid(value.session_id) || !deviceIdValid(value.client_id)) throw invalidDeviceResponse();
  return { tenant_id: value.tenant_id, account_id: value.account_id, session_id: value.session_id, client_id: value.client_id };
}
function ownerOf(value: IdentitySession): UnbindIntent["owner"] {
  const current = validatedDeviceSession(value);
  return Object.freeze({ tenant_id: current.tenant_id, account_id: current.account_id, client_id: current.client_id });
}
function sameOwner(left: UnbindIntent["owner"], right: UnbindIntent["owner"]): boolean {
  return left.tenant_id === right.tenant_id && left.account_id === right.account_id && left.client_id === right.client_id;
}
function deviceFrom(value: unknown, current: IdentitySession): SubjectDevice {
  const item = deviceObject(value);
  if (item.tenant_id !== current.tenant_id || item.client_id !== current.client_id || !deviceIdValid(item.device_id) ||
      !nullableDeviceValue(item.proof_key_id, keyIdValid) || !["pending", "active", "disabled", "revoked"].includes(String(item.status)) ||
      !validDeviceVersion(item.version) || !nullableDeviceValue(item.key_version, validDeviceVersion) || !deviceUuidValid(item.binding_id) ||
      (item.proof_key_id === null) !== (item.key_version === null) ||
      !validDeviceVersion(item.binding_version) || typeof item.device_name !== "string" || item.device_name.length > 256 ||
      !validDeviceTimestamp(item.registered_at_unix_secs) || !nullableDeviceValue(item.last_seen_at_unix_secs, validDeviceTimestamp) ||
      !["active", "suspended", "unbound"].includes(String(item.binding_status))) throw invalidDeviceResponse();
  return {
    tenant_id: item.tenant_id, device_id: item.device_id, client_id: item.client_id,
    proof_key_id: item.proof_key_id, status: item.status as SubjectDevice["status"], version: item.version,
    key_version: item.key_version, binding_id: item.binding_id, binding_version: item.binding_version,
    device_name: item.device_name, registered_at_unix_secs: item.registered_at_unix_secs,
    last_seen_at_unix_secs: item.last_seen_at_unix_secs, binding_status: item.binding_status as SubjectDevice["binding_status"],
  };
}
function keyFrom(value: unknown, current: IdentitySession, deviceId: string, keyId: string): DeviceKeyMetadata {
  const item = deviceObject(value);
  if (item.tenant_id !== current.tenant_id || item.device_id !== deviceId || item.key_id !== keyId ||
      item.algorithm !== "ed25519" ||
      !validDeviceVersion(item.version) || !["active", "retired"].includes(String(item.status)) ||
      !validDeviceTimestamp(item.registered_at_unix_secs) || !nullableDeviceValue(item.retired_at_unix_secs, validDeviceTimestamp)) throw invalidDeviceResponse();
  return { tenant_id: item.tenant_id, device_id: item.device_id, key_id: item.key_id,
    algorithm: item.algorithm, version: item.version, status: item.status as DeviceKeyMetadata["status"],
    registered_at_unix_secs: item.registered_at_unix_secs, retired_at_unix_secs: item.retired_at_unix_secs };
}
function receiptFrom(value: unknown, intent: UnbindIntent, current: IdentitySession): DeviceOperationReceipt {
  const item = deviceObject(value);
  if (!sameOwner(intent.owner, ownerOf(current)) || item.operation_id !== intent.operation_id ||
      item.device_id !== intent.device_id || item.binding_id !== intent.binding_id ||
      item.operation !== "device.binding.unbind.self" || item.result_status !== "unbound" ||
      !deviceIdValid(item.audit_id) || item.result_version !== intent.expected_version + 1 || !validDeviceVersion(item.result_version) ||
      !validDeviceTimestamp(item.occurred_at_unix_secs)) throw invalidDeviceResponse();
  return { operation_id: item.operation_id, audit_id: item.audit_id, device_id: item.device_id,
    binding_id: item.binding_id, operation: item.operation, result_status: item.result_status,
    result_version: item.result_version, occurred_at_unix_secs: item.occurred_at_unix_secs };
}
/** Thin, memory-only client for the authenticated device routes. It never receives a token. */
export class EmbeddedDeviceClient {
  private readonly intents = new WeakSet<object>();

  constructor(public readonly identity: EmbeddedIdentityClient) {}

  async list(cursor?: string): Promise<DevicePage> {
    if (cursor !== undefined && (typeof cursor !== "string" || !/^[A-Za-z0-9_-]{1,2048}$/.test(cursor))) throw new IdentityError("设备列表游标无效。", 400);
    const query = { limit: "50", ...(cursor === undefined ? {} : { cursor }) };
    const { session: current, value } = await this.identity.requestDevice(`/devices?${new URLSearchParams(query)}`);
    const result = deviceObject(value);
    if (!Array.isArray(result.items) || result.items.length > 50 || typeof result.has_more !== "boolean" ||
        result.has_more && typeof result.next_cursor !== "string" ||
        typeof result.next_cursor === "string" && !/^[A-Za-z0-9_-]{1,2048}$/.test(result.next_cursor) ||
        result.next_cursor !== undefined && result.next_cursor !== null && typeof result.next_cursor !== "string") throw invalidDeviceResponse();
    const items = result.items.map(item => deviceFrom(item, current));
    if (new Set(items.map(item => item.device_id)).size !== items.length) throw invalidDeviceResponse();
    return { items, has_more: result.has_more, ...(typeof result.next_cursor === "string" ? { next_cursor: result.next_cursor } : {}) };
  }

  async detail(deviceId: string): Promise<SubjectDevice> {
    if (!deviceIdValid(deviceId)) throw new IdentityError("设备标识无效。", 400);
    const { session: current, value } = await this.identity.requestDevice(`/devices/${encodeURIComponent(deviceId)}`);
    const result = deviceFrom(value, current);
    if (result.device_id !== deviceId) throw invalidDeviceResponse();
    return result;
  }

  async keyMetadata(deviceId: string, keyId: string): Promise<DeviceKeyMetadata> {
    if (!deviceIdValid(deviceId) || !keyIdValid(keyId)) throw new IdentityError("设备密钥标识无效。", 400);
    const { session: current, value } = await this.identity.requestDevice(`/devices/${encodeURIComponent(deviceId)}/keys/${encodeURIComponent(keyId)}`);
    return keyFrom(value, current, deviceId, keyId);
  }

  prepareUnbind(device: SubjectDevice): UnbindIntent {
    const current = this.identity.getSnapshot().session;
    if (!current) throw new IdentityError("请先登录。", 401);
    const owner = ownerOf(current);
    if (device.tenant_id !== owner.tenant_id || device.client_id !== owner.client_id || device.binding_status !== "active" ||
        !deviceIdValid(device.device_id) || !deviceUuidValid(device.binding_id) || !validDeviceVersion(device.binding_version) ||
        device.binding_version >= Number.MAX_SAFE_INTEGER) throw new IdentityError("设备或本人绑定状态已变化，请重新加载。", 409);
    const intent: UnbindIntent = Object.freeze({ owner, operation_id: secureRandomUuid(), device_id: device.device_id,
      binding_id: device.binding_id, expected_version: device.binding_version });
    this.intents.add(intent);
    return intent;
  }

  async unbind(intent: UnbindIntent): Promise<DeviceOperationReceipt> {
    this.requireIntent(intent);
    const { session: current, value } = await this.identity.requestDevice("/devices/unbind", {
      device_id: intent.device_id, binding_id: intent.binding_id, expected_version: intent.expected_version, operation_id: intent.operation_id,
    });
    return receiptFrom(value, intent, current);
  }

  async operationResult(intent: UnbindIntent): Promise<DeviceOperationReceipt> {
    this.requireIntent(intent);
    const { session: current, value } = await this.identity.requestDevice(`/devices/operations/${encodeURIComponent(intent.operation_id)}`);
    return receiptFrom(value, intent, current);
  }

  private requireIntent(value: UnbindIntent) {
    const current = this.identity.getSnapshot().session;
    if (!current) throw new IdentityError("请先登录。", 401);
    if (!value || !this.intents.has(value) || !sameOwner(value.owner, ownerOf(current))) {
      throw new IdentityError("此解绑操作不属于当前身份或客户端。", 403);
    }
  }
}
