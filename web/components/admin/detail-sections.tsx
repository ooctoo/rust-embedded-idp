import { DetailPanel } from "./detail-panel";
import type { AdminApiClient } from "../../lib/admin-api";
import type {
  AccountRecord,
  ClientRecord,
  DeviceDetail,
  SessionRecord,
} from "../../lib/types";

export function AccountDetailSection({
  account,
  api,
  onFeedback,
  onOpenPassword,
  onReload,
}: {
  account: AccountRecord | null;
  api: AdminApiClient;
  onFeedback: (value: string) => void;
  onOpenPassword: (open: boolean) => void;
  onReload: () => Promise<void>;
}) {
  if (!account) return <EmptyDetail title="Account Detail" />;
  return (
    <DetailPanel
      actions={[
        { label: "Activate", onClick: () => void runAction(() => api.activateAccount(account.account_id), onReload, onFeedback) },
        { intent: "danger", label: "Disable", onClick: () => void runAction(() => api.disableAccount(account.account_id), onReload, onFeedback) },
        { label: "Set password", onClick: () => onOpenPassword(true) },
        { label: "Revoke sessions", onClick: () => void runAction(() => api.revokeAccountSessions(account.account_id), onReload, onFeedback) },
      ]}
      items={[
        { label: "Email", value: account.email },
        { label: "Display Name", value: account.display_name ?? "N/A" },
        { label: "Created At", value: formatUnix(account.created_at_unix_secs) },
        { label: "Status", value: account.status },
      ]}
      notice="账户治理通过现有 admin API 完成，没有新增后端协议。"
      status={{ label: account.status, tone: toneForStatus(account.status) }}
      title="Account Detail"
    />
  );
}

export function SessionDetailSection({
  api,
  onFeedback,
  onReload,
  session,
}: {
  api: AdminApiClient;
  onFeedback: (value: string) => void;
  onReload: () => Promise<void>;
  session: SessionRecord | null;
}) {
  if (!session) return <EmptyDetail title="Session Detail" />;
  return (
    <DetailPanel
      actions={[
        { intent: "danger", label: "Revoke session", onClick: () => void runAction(() => api.revokeSession(session.session_id), onReload, onFeedback) },
      ]}
      items={[
        { label: "Account", value: session.account_id },
        { label: "Client", value: session.client_id },
        { label: "Device", value: session.device_id ?? "N/A" },
        { label: "Created At", value: formatUnix(session.created_at_unix_secs) },
        { label: "Expires At", value: formatUnix(session.expires_at_unix_secs) },
        { label: "Refresh Version", value: String(session.refresh_token_version) },
      ]}
      status={{ label: session.status, tone: toneForStatus(session.status) }}
      title="Session Detail"
    />
  );
}

export function ClientDetailSection({
  client,
  onOpenDialog,
}: {
  client: ClientRecord | null;
  onOpenDialog: (open: boolean) => void;
}) {
  if (!client) return <EmptyDetail title="Client Detail" />;
  return (
    <DetailPanel
      actions={[{ label: "Edit client", onClick: () => onOpenDialog(true) }]}
      items={[
        { label: "Client Name", value: client.client_name },
        { label: "Type", value: client.client_type },
        { label: "PKCE Required", value: String(client.pkce_required) },
        { label: "Secret Configured", value: String(client.client_secret_configured) },
        { label: "Redirect URIs", value: client.redirect_uris.join(", ") },
      ]}
      status={{ label: client.client_secret_configured ? "secret configured" : "secret missing", tone: client.client_secret_configured ? "active" : "warning" }}
      title="Client Detail"
    />
  );
}

export function DeviceDetailSection({
  api,
  detail,
  onFeedback,
  onReload,
}: {
  api: AdminApiClient;
  detail: DeviceDetail | null;
  onFeedback: (value: string) => void;
  onReload: () => Promise<void>;
}) {
  if (!detail) return <EmptyDetail title="Device Detail" />;
  const binding = detail.bindings[0];
  return (
    <DetailPanel
      actions={[
        { label: "Unbind", onClick: () => binding ? void runAction(() => api.unbindDevice(binding.account_id, binding.device_id), onReload, onFeedback) : onFeedback("No binding to unbind.") },
        { intent: "danger", label: "Disable", onClick: () => void runAction(() => api.disableDevice(detail.device.device_id), onReload, onFeedback) },
        { intent: "danger", label: "Revoke", onClick: () => void runAction(() => api.revokeDevice(detail.device.device_id), onReload, onFeedback) },
      ]}
      bindings={detail.bindings.map((item) => ({
        id: item.binding_id,
        meta: `${item.account_id} · ${item.device_id}`,
        status: item.status,
        tone: toneForStatus(item.status),
      }))}
      items={[
        { label: "Client", value: detail.device.client_id },
        { label: "Status", value: detail.device.status },
        { label: "Proof Key", value: detail.device.proof_key_id ?? "N/A" },
      ]}
      status={{ label: detail.device.status, tone: toneForStatus(detail.device.status) }}
      title="Device Detail"
    />
  );
}

export function EmptyDetail({ title }: { title: string }) {
  return <DetailPanel items={[{ label: "Selection", value: "Choose a row from the left table." }]} title={title} />;
}

async function runAction(action: () => Promise<unknown>, reload: () => Promise<void>, setFeedback: (value: string) => void) {
  try {
    await action();
    await reload();
    setFeedback("操作已完成。");
  } catch (error) {
    setFeedback((error as Error).message);
  }
}

function formatUnix(value: number) {
  return new Date(value * 1000).toLocaleString();
}

function toneForStatus(value: string): "active" | "danger" | "neutral" | "warning" {
  if (value === "active") return "active";
  if (value === "pending" || value === "pending_verification") return "warning";
  if (value === "disabled" || value === "revoked" || value === "expired") return "danger";
  return "neutral";
}
