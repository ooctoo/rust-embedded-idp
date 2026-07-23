import { cn } from "../../lib/cn";

export function Tabs({
  onChange,
  options,
  value,
}: {
  onChange: (value: string) => void;
  options: Array<{ label: string; value: string }>;
  value: string;
}) {
  return (
    <div className="flex flex-wrap rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface-muted)] p-1">
      {options.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={option.value}
            className={cn(
              "rounded-2xl px-4 py-2 text-sm font-medium transition",
              active
                ? "bg-[var(--surface-panel)] text-[var(--text-primary)] shadow-[var(--shadow-soft)]"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]",
            )}
            onClick={() => onChange(option.value)}
            type="button"
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
