import { cn } from "../../lib/cn";

type BadgeTone = "active" | "danger" | "neutral" | "warning";

const tones: Record<BadgeTone, string> = {
  active: "border-emerald-500/20 bg-emerald-500/10 text-emerald-200",
  danger: "border-rose-500/20 bg-rose-500/10 text-rose-200",
  neutral: "border-[var(--border-subtle)] bg-[var(--surface-muted)] text-[var(--text-secondary)]",
  warning: "border-amber-500/20 bg-amber-500/10 text-amber-200",
};

export function Badge({ children, tone }: { children: string; tone: BadgeTone }) {
  return (
    <span className={cn("inline-flex rounded-full border px-2.5 py-1 text-[11px] font-medium", tones[tone])}>
      {children}
    </span>
  );
}
