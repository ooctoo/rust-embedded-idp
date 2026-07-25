import type { ReactNode } from "react";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Textarea } from "../ui/textarea";

export type ClientFormValue = {
  clientId: string;
  clientName: string;
  clientSecret: string;
  clientType: "confidential_web" | "public_desktop";
  pkceRequired: "false" | "true";
  redirectUris: string;
};

export function ClientFormDialog({
  error,
  onCancel,
  onChange,
  onSubmit,
  open,
  value,
}: {
  error?: string;
  onCancel: () => void;
  onChange: (value: ClientFormValue) => void;
  onSubmit: () => void;
  open: boolean;
  value: ClientFormValue;
}) {
    if (!open) return null;

    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-sm">
        <div className="w-full max-w-2xl rounded-[28px] border border-[var(--border-subtle)] bg-[var(--surface-elevated)] p-6 shadow-[var(--shadow-card)]">
          <div>
            <h2 className="text-xl font-semibold text-[var(--text-primary)]">Upsert OIDC Client</h2>
            <p className="mt-2 text-sm leading-6 text-[var(--text-secondary)]">
              这层是模块内组件装配页。后续宿主也可以直接复用同一个表单组件。
            </p>
          </div>
          <div className="mt-5 grid gap-4 md:grid-cols-2">
            <Field label="Client ID">
              <Input value={value.clientId} onChange={(event) => onChange({ ...value, clientId: event.target.value })} />
            </Field>
            <Field label="Client Name">
              <Input value={value.clientName} onChange={(event) => onChange({ ...value, clientName: event.target.value })} />
            </Field>
            <Field label="Client Type">
              <select
                className="min-h-10 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-panel)] px-3 text-sm text-[var(--text-primary)]"
                onChange={(event) => onChange({ ...value, clientType: event.target.value as ClientFormValue["clientType"] })}
                value={value.clientType}
              >
                <option value="public_desktop">public_desktop</option>
                <option value="confidential_web">confidential_web</option>
              </select>
            </Field>
            <Field label="PKCE Required">
              <select
                className="min-h-10 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-panel)] px-3 text-sm text-[var(--text-primary)]"
                onChange={(event) => onChange({ ...value, pkceRequired: event.target.value as ClientFormValue["pkceRequired"] })}
                value={value.pkceRequired}
              >
                <option value="true">true</option>
                <option value="false">false</option>
              </select>
            </Field>
            <Field className="md:col-span-2" label="Redirect URIs">
              <Textarea value={value.redirectUris} onChange={(event) => onChange({ ...value, redirectUris: event.target.value })} />
            </Field>
            <Field className="md:col-span-2" label="Client Secret">
              <Input type="password" value={value.clientSecret} onChange={(event) => onChange({ ...value, clientSecret: event.target.value })} />
            </Field>
          </div>
          {error ? (
            <p
              aria-live="polite"
              className="mt-4 rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200"
              role="alert"
            >
              {error}
            </p>
          ) : null}
          <div className="mt-6 flex justify-end gap-3">
            <Button onClick={onCancel} variant="outline">Cancel</Button>
            <Button onClick={onSubmit}>Save client</Button>
          </div>
        </div>
      </div>
    );
}

function Field({
  children,
  className,
  label,
}: {
  children: ReactNode;
  className?: string;
  label: string;
}) {
  return (
    <label className={className}>
      <span className="mb-2 block text-xs uppercase tracking-[0.12em] text-[var(--text-muted)]">{label}</span>
      {children}
    </label>
  );
}
