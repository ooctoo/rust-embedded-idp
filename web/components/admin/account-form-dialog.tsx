import type { ReactNode } from "react";

import { Button } from "../ui/button";
import { Input } from "../ui/input";

export type AccountFormValue = {
  displayName: string;
  email: string;
  password: string;
};

export function AccountFormDialog({
  error,
  onCancel,
  onChange,
  onSubmit,
  open,
  value,
}: {
  error?: string;
  onCancel: () => void;
  onChange: (value: AccountFormValue) => void;
  onSubmit: () => void;
  open: boolean;
  value: AccountFormValue;
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-sm">
      <div className="w-full max-w-xl rounded-[28px] border border-[var(--border-subtle)] bg-[var(--surface-elevated)] p-6 shadow-[var(--shadow-card)]">
        <div>
          <h2 className="text-xl font-semibold text-[var(--text-primary)]">Create Account</h2>
          <p className="mt-2 text-sm leading-6 text-[var(--text-secondary)]">
            这是 admin-only 创建入口，不会创建登录 session 或返回 token。
          </p>
        </div>
        <div className="mt-5 grid gap-4">
          <Field label="Email">
            <Input
              onChange={(event) => onChange({ ...value, email: event.target.value })}
              type="email"
              value={value.email}
            />
          </Field>
          <Field label="Display Name">
            <Input
              onChange={(event) => onChange({ ...value, displayName: event.target.value })}
              value={value.displayName}
            />
          </Field>
          <Field label="Password">
            <Input
              onChange={(event) => onChange({ ...value, password: event.target.value })}
              type="password"
              value={value.password}
            />
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
          <Button onClick={onCancel} variant="outline">
            Cancel
          </Button>
          <Button onClick={onSubmit}>Create account</Button>
        </div>
      </div>
    </div>
  );
}

function Field({
  children,
  label,
}: {
  children: ReactNode;
  label: string;
}) {
  return (
    <label>
      <span className="mb-2 block text-xs uppercase tracking-[0.12em] text-[var(--text-muted)]">
        {label}
      </span>
      {children}
    </label>
  );
}
