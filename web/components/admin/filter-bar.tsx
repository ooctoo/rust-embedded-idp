import type { InputHTMLAttributes, ReactNode } from "react";
import { Button } from "../ui/button";
import { Input } from "../ui/input";

export function FilterBar({
  children,
  onApply,
}: {
  children: ReactNode;
  onApply: () => void;
}) {
  return (
    <div className="flex flex-col gap-4 rounded-3xl border border-[var(--border-subtle)] bg-[var(--surface-elevated)] p-5 shadow-[var(--shadow-card)] md:flex-row md:items-end">
      <div className="grid flex-1 gap-4 md:grid-cols-3">{children}</div>
      <Button onClick={onApply}>Apply filters</Button>
    </div>
  );
}

export function FilterField({
  label,
  ...props
}: { label: string } & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="grid gap-2">
      <span className="text-xs uppercase tracking-[0.14em] text-[var(--text-muted)]">{label}</span>
      <Input {...props} />
    </label>
  );
}

export function FilterSelect({
  label,
  onChange,
  options,
  value,
}: {
  label: string;
  onChange: (value: string) => void;
  options: Array<{ label: string; value: string }>;
  value: string;
}) {
  return (
    <label className="grid gap-2">
      <span className="text-xs uppercase tracking-[0.14em] text-[var(--text-muted)]">{label}</span>
      <select
        className="min-h-10 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-panel)] px-3 text-sm text-[var(--text-primary)] outline-none focus:border-[var(--accent-strong)] focus:ring-2 focus:ring-[var(--accent-soft)]"
        onChange={(event) => onChange(event.target.value)}
        value={value}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}
