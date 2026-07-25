import { useEffect, useMemo, useState, type ComponentProps, type Dispatch, type SetStateAction } from "react";
import {
  AdminAccessGate,
  AccountFormDialog,
  AccountDetailSection,
  ClientDetailSection,
  ClientFormDialog,
  DeviceDetailSection,
  Input,
  RecordsTable,
  SessionDetailSection,
  SummaryCards,
  TabFilters,
  Tabs,
} from "./components/index";
import { AdminApiClient, AdminApiError } from "./lib/admin-api";
import type {
  AccountRecord,
  ClientRecord,
  DeviceDetail,
  DeviceRecord,
  SessionRecord,
} from "./lib/types";

type AdminTab = "accounts" | "clients" | "devices" | "sessions";
type AccountFormState = ComponentProps<typeof AccountFormDialog>["value"];
type ClientFormState = ComponentProps<typeof ClientFormDialog>["value"];
type AccessState = "checking" | "locked" | "unlocked";

const STORAGE_KEY = "embedded-idp-admin-api-key";
const API_BASE_PATH = "/api";

export function AdminApp() {
  const [tab, setTab] = useState<AdminTab>("accounts");
  const [apiKeyInput, setApiKeyInput] = useState(() => localStorage.getItem(STORAGE_KEY) ?? "");
  const [apiKey, setApiKey] = useState("");
  const [accessState, setAccessState] = useState<AccessState>(() =>
    localStorage.getItem(STORAGE_KEY) ? "checking" : "locked",
  );
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [feedback, setFeedback] = useState<string>(() =>
    localStorage.getItem(STORAGE_KEY)
      ? "正在校验已保存的 admin key。"
      : "输入正确的 admin key 后才能进入管理页。",
  );
  const [authSubmitting, setAuthSubmitting] = useState(false);
  const [accountDialogOpen, setAccountDialogOpen] = useState(false);
  const [clientDialogOpen, setClientDialogOpen] = useState(false);
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);
  const [passwordDraft, setPasswordDraft] = useState("");
  const [accountForm, setAccountForm] = useState<AccountFormState>(emptyAccountForm());
  const [clientForm, setClientForm] = useState<ClientFormState>(emptyClientForm());
  const [accountFormError, setAccountFormError] = useState("");
  const [clientFormError, setClientFormError] = useState("");
  const [passwordFormError, setPasswordFormError] = useState("");
  const [accounts, setAccounts] = useState<{ items: AccountRecord[]; total: number }>({ items: [], total: 0 });
  const [sessions, setSessions] = useState<{ items: SessionRecord[]; total: number }>({ items: [], total: 0 });
  const [clients, setClients] = useState<{ items: ClientRecord[]; total: number }>({ items: [], total: 0 });
  const [devices, setDevices] = useState<{ items: DeviceRecord[]; total: number }>({ items: [], total: 0 });
  const [selectedAccount, setSelectedAccount] = useState<AccountRecord | null>(null);
  const [selectedSession, setSelectedSession] = useState<SessionRecord | null>(null);
  const [selectedClient, setSelectedClient] = useState<ClientRecord | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<DeviceDetail | null>(null);

  const api = useMemo(() => new AdminApiClient({ apiKey, basePath: API_BASE_PATH }), [apiKey]);

  useEffect(() => {
    const storedKey = localStorage.getItem(STORAGE_KEY);
    if (storedKey) {
      void unlockAccess(storedKey, true);
    }
  }, []);

  useEffect(() => {
    if (accessState === "unlocked" && apiKey) {
      void reloadCurrentTab();
    }
  }, [tab, apiKey, accessState]);

  async function reloadCurrentTab() {
    if (accessState !== "unlocked" || !apiKey) return;
    try {
      if (tab === "accounts") {
        const response = await api.listAccounts({ ...filters, limit: "20" });
        setAccounts({ items: response.accounts, total: response.page.total });
      } else if (tab === "sessions") {
        const response = await api.listSessions({ ...filters, limit: "20" });
        setSessions({ items: response.sessions, total: response.page.total });
      } else if (tab === "clients") {
        const response = await api.listClients({ ...filters, limit: "20" });
        setClients({ items: response.clients, total: response.page.total });
      } else {
        const response = await api.listDevices({ ...filters, limit: "20" });
        setDevices({ items: response.devices, total: response.page.total });
      }
      setFeedback("数据已刷新。");
    } catch (error) {
      setFeedback((error as Error).message);
    }
  }

  async function unlockAccess(candidateKey: string, fromStorage = false) {
    const normalized = candidateKey.trim();
    if (!normalized) {
      setAccessState("locked");
      setFeedback("请输入 admin key。");
      return;
    }

    setAuthSubmitting(true);
    setAccessState("checking");
    setFeedback(fromStorage ? "正在校验已保存的 admin key。" : "正在校验 admin key。");

    try {
      const candidateApi = new AdminApiClient({
        apiKey: normalized,
        basePath: API_BASE_PATH,
      });
      await candidateApi.validateAccess();
      localStorage.setItem(STORAGE_KEY, normalized);
      setApiKey(normalized);
      setApiKeyInput(normalized);
      setAccessState("unlocked");
      setFeedback("Admin key 校验通过。");
    } catch (error) {
      localStorage.removeItem(STORAGE_KEY);
      setApiKey("");
      setAccessState("locked");
      setFeedback(formatAccessError(error));
    } finally {
      setAuthSubmitting(false);
    }
  }

  function currentTotals() {
    return {
      accounts: accounts.total,
      clients: clients.total,
      devices: devices.total,
      sessions: sessions.total,
    };
  }

  if (accessState !== "unlocked") {
    return (
      <AdminAccessGate
        feedback={feedback}
        onChange={setApiKeyInput}
        onSubmit={() => void unlockAccess(apiKeyInput)}
        submitting={authSubmitting || accessState === "checking"}
        value={apiKeyInput}
      />
    );
  }

  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-[1480px] flex-col gap-6 px-4 py-6 lg:px-8">
      <section className="rounded-[32px] border border-[var(--border-subtle)] bg-[var(--surface-elevated)] p-6 shadow-[var(--shadow-card)]">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-3xl">
            <p className="text-sm uppercase tracking-[0.18em] text-[var(--text-muted)]">Embedded module admin</p>
            <h1 className="mt-3 text-4xl font-semibold tracking-tight text-[var(--text-primary)]">Embedded IDP Admin</h1>
            <p className="mt-3 text-sm leading-7 text-[var(--text-secondary)]">
              组件与整页都放在 `web` 层。宿主后续可以直接复用 `components/*`，也可以继续消费本页打包后的静态产物。
            </p>
          </div>
          <div className="max-w-xl text-sm leading-7 text-[var(--text-secondary)]">
            当前管理接口挂在 <code className="rounded bg-[var(--surface-muted)] px-2 py-1 text-xs">/api/admin/*</code>，
            静态资源挂在 <code className="rounded bg-[var(--surface-muted)] px-2 py-1 text-xs">/static/*</code>。
            <p className="mt-3">{feedback}</p>
          </div>
        </div>
      </section>

      <SummaryCards totals={currentTotals()} />

      <section className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <Tabs
          onChange={(value) => setTab(value as AdminTab)}
          options={[
            { label: "Accounts", value: "accounts" },
            { label: "Sessions", value: "sessions" },
            { label: "Clients", value: "clients" },
            { label: "Devices", value: "devices" },
          ]}
          value={tab}
        />
        <div className="flex gap-3">
          {tab === "accounts" ? (
            <button
              className="min-h-10 rounded-xl bg-[var(--accent-strong)] px-4 text-sm font-medium text-[var(--accent-ink)]"
              onClick={() => {
                setAccountFormError("");
                setAccountDialogOpen(true);
              }}
              type="button"
            >
              Create account
            </button>
          ) : null}
          <button className="min-h-10 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-muted)] px-4 text-sm text-[var(--text-primary)]" onClick={() => void reloadCurrentTab()} type="button">
            Refresh
          </button>
        </div>
      </section>

      <TabFilters
        filters={filters}
        onApply={() => void reloadCurrentTab()}
        onChange={(key, value) => setFilters((current) => ({ ...current, [key]: value }))}
        tab={tab}
      />

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.45fr)_minmax(360px,0.85fr)]">
        <div>
          {tab === "accounts" ? (
            <RecordsTable emptyText="No accounts found." rows={accounts.items.map((account) => ({ id: account.account_id, meta: `${account.email} · ${formatUnix(account.created_at_unix_secs)}`, statusLabel: account.status, tone: toneForStatus(account.status) }))} selectedId={selectedAccount?.account_id} title="Accounts" totalLabel={`${accounts.total} total`} onSelect={(accountId) => void selectAccount(api, accountId, setSelectedAccount, setFeedback)} />
          ) : null}
          {tab === "sessions" ? (
            <RecordsTable emptyText="No sessions found." rows={sessions.items.map((session) => ({ id: session.session_id, meta: `${session.account_id} · ${session.client_id}`, statusLabel: session.status, tone: toneForStatus(session.status) }))} selectedId={selectedSession?.session_id} title="Sessions" totalLabel={`${sessions.total} total`} onSelect={(sessionId) => void selectSession(api, sessionId, setSelectedSession, setFeedback)} />
          ) : null}
          {tab === "clients" ? (
            <RecordsTable emptyText="No clients found." rows={clients.items.map((client) => ({ id: client.client_id, meta: `${client.client_name} · ${client.client_type}`, statusLabel: client.client_secret_configured ? "secret configured" : "secret missing", tone: client.client_secret_configured ? "active" : "warning" }))} selectedId={selectedClient?.client_id} title="Clients" totalLabel={`${clients.total} total`} onSelect={(clientId) => void selectClient(api, clientId, setSelectedClient, setClientForm, setFeedback)} />
          ) : null}
          {tab === "devices" ? (
            <RecordsTable emptyText="No devices found." rows={devices.items.map((device) => ({ id: device.device_id, meta: `${device.client_id} · ${device.proof_key_id ?? "no proof key"}`, statusLabel: device.status, tone: toneForStatus(device.status) }))} selectedId={selectedDevice?.device.device_id} title="Devices" totalLabel={`${devices.total} total`} onSelect={(deviceId) => void selectDevice(api, deviceId, setSelectedDevice, setFeedback)} />
          ) : null}
        </div>
        <div className="space-y-6">
          {tab === "accounts" ? <AccountDetailSection account={selectedAccount} api={api} onFeedback={setFeedback} onOpenPassword={(open) => {
            if (open) setPasswordFormError("");
            setPasswordDialogOpen(open);
          }} onReload={reloadCurrentTab} /> : null}
          {tab === "sessions" ? <SessionDetailSection api={api} onFeedback={setFeedback} onReload={reloadCurrentTab} session={selectedSession} /> : null}
          {tab === "clients" ? <ClientDetailSection client={selectedClient} onOpenDialog={(open) => {
            if (open) setClientFormError("");
            setClientDialogOpen(open);
          }} /> : null}
          {tab === "devices" ? <DeviceDetailSection api={api} detail={selectedDevice} onFeedback={setFeedback} onReload={reloadCurrentTab} /> : null}
        </div>
      </section>

      <AccountFormDialog
        error={accountFormError}
        onCancel={() => {
          setAccountFormError("");
          setAccountDialogOpen(false);
        }}
        onChange={(value) => {
          setAccountForm(value);
          setAccountFormError("");
        }}
        onSubmit={() =>
          void submitAccount(api, accountForm, reloadCurrentTab, setAccountDialogOpen, setAccountForm, setAccountFormError, setFeedback)
        }
        open={accountDialogOpen}
        value={accountForm}
      />

      <ClientFormDialog
        error={clientFormError}
        onCancel={() => {
          setClientFormError("");
          setClientDialogOpen(false);
        }}
        onChange={(value) => {
          setClientForm(value);
          setClientFormError("");
        }}
        onSubmit={() => void submitClient(api, clientForm, reloadCurrentTab, setClientDialogOpen, setClientFormError, setFeedback)}
        open={clientDialogOpen}
        value={clientForm}
      />

      {passwordDialogOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-[28px] border border-[var(--border-subtle)] bg-[var(--surface-elevated)] p-6 shadow-[var(--shadow-card)]">
            <h2 className="text-xl font-semibold text-[var(--text-primary)]">Set Account Password</h2>
            <p className="mt-2 text-sm text-[var(--text-secondary)]">直接调用 `/api/admin/accounts/set-password`。</p>
            <Input
              className="mt-4"
              type="password"
              value={passwordDraft}
              onChange={(event) => {
                setPasswordDraft(event.target.value);
                setPasswordFormError("");
              }}
            />
            {passwordFormError ? (
              <p aria-live="polite" className="mt-3 rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200" role="alert">
                {passwordFormError}
              </p>
            ) : null}
            <div className="mt-6 flex justify-end gap-3">
              <button className="min-h-10 rounded-xl border border-[var(--border-subtle)] px-4 text-sm text-[var(--text-primary)]" onClick={() => {
                setPasswordFormError("");
                setPasswordDialogOpen(false);
              }} type="button">
                Cancel
              </button>
              <button
                className="min-h-10 rounded-xl bg-[var(--accent-strong)] px-4 text-sm font-medium text-[var(--accent-ink)]"
                onClick={() => void submitPassword(api, selectedAccount, passwordDraft, reloadCurrentTab, setPasswordDialogOpen, setPasswordDraft, setPasswordFormError, setFeedback)}
                type="button"
              >
                Apply
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </main>
  );
}

async function submitClient(
  api: AdminApiClient,
  form: ClientFormState,
  reload: () => Promise<void>,
  setOpen: (open: boolean) => void,
  setError: (value: string) => void,
  setFeedback: (value: string) => void,
) {
  setError("");
  const error = await runAction(
    () =>
      api.upsertClient({
        client_id: form.clientId,
        client_name: form.clientName,
        client_secret: form.clientSecret || null,
        client_type: form.clientType,
        pkce_required: form.pkceRequired === "true",
        redirect_uris: form.redirectUris.split("\n").map((value) => value.trim()).filter(Boolean),
      }),
    reload,
    setFeedback,
  );
  if (error !== null) {
    setError(error);
    return;
  }
  setOpen(false);
}

async function submitAccount(
  api: AdminApiClient,
  form: AccountFormState,
  reload: () => Promise<void>,
  setOpen: (open: boolean) => void,
  setForm: Dispatch<SetStateAction<AccountFormState>>,
  setError: (value: string) => void,
  setFeedback: (value: string) => void,
) {
  setError("");
  const error = await runAction(
    () =>
      api.createAccount({
        email: form.email,
        password: form.password,
        display_name: form.displayName.trim() ? form.displayName.trim() : null,
      }),
    reload,
    setFeedback,
  );
  if (error !== null) {
    setError(error);
    return;
  }
  setOpen(false);
  setForm(emptyAccountForm());
}

async function submitPassword(
  api: AdminApiClient,
  account: AccountRecord | null,
  password: string,
  reload: () => Promise<void>,
  setOpen: (open: boolean) => void,
  setPassword: (value: string) => void,
  setError: (value: string) => void,
  setFeedback: (value: string) => void,
) {
  if (!account) return;
  setError("");
  const error = await runAction(() => api.setAccountPassword(account.account_id, password), reload, setFeedback);
  if (error !== null) {
    setError(error);
    return;
  }
  setOpen(false);
  setPassword("");
}

async function runAction(
  action: () => Promise<unknown>,
  reload: () => Promise<void>,
  setFeedback: (value: string) => void,
): Promise<string | null> {
  try {
    await action();
    await reload();
    setFeedback("操作已完成。");
    return null;
  } catch (error) {
    const message = (error as Error).message;
    setFeedback(message);
    return message;
  }
}

async function selectAccount(
  api: AdminApiClient,
  accountId: string,
  setSelected: (value: AccountRecord) => void,
  setFeedback: (value: string) => void,
) {
  try {
    setSelected(await api.getAccount(accountId));
  } catch (error) {
    setFeedback((error as Error).message);
  }
}

async function selectSession(
  api: AdminApiClient,
  sessionId: string,
  setSelected: (value: SessionRecord) => void,
  setFeedback: (value: string) => void,
) {
  try {
    setSelected(await api.getSession(sessionId));
  } catch (error) {
    setFeedback((error as Error).message);
  }
}

async function selectClient(
  api: AdminApiClient,
  clientId: string,
  setSelected: (value: ClientRecord) => void,
  setForm: (value: ClientFormState) => void,
  setFeedback: (value: string) => void,
) {
  try {
    const client = await api.getClient(clientId);
    setSelected(client);
    setForm({
      clientId: client.client_id,
      clientName: client.client_name,
      clientSecret: "",
      clientType: client.client_type,
      pkceRequired: String(client.pkce_required) as ClientFormState["pkceRequired"],
      redirectUris: client.redirect_uris.join("\n"),
    });
  } catch (error) {
    setFeedback((error as Error).message);
  }
}

async function selectDevice(
  api: AdminApiClient,
  deviceId: string,
  setSelected: (value: DeviceDetail) => void,
  setFeedback: (value: string) => void,
) {
  try {
    setSelected(await api.getDevice(deviceId));
  } catch (error) {
    setFeedback((error as Error).message);
  }
}

function emptyClientForm(): ClientFormState {
  return {
    clientId: "",
    clientName: "",
    clientSecret: "",
    clientType: "public_desktop",
    pkceRequired: "true",
    redirectUris: "",
  };
}

function emptyAccountForm(): AccountFormState {
  return {
    displayName: "",
    email: "",
    password: "",
  };
}

function formatAccessError(error: unknown) {
  if (error instanceof AdminApiError) {
    if (error.status === 401 || error.code === "admin_api_key_required") {
      return "Admin key 缺失或不正确，请重新输入。";
    }
    if (error.status === 404) {
      return "管理接口未启用，确认 embedded-idp-app 已配置 EMBEDDED_IDP_APP_ADMIN_API_KEY。";
    }
  }

  return (error as Error).message;
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
