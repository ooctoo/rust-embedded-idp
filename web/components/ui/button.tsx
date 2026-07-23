import type { ButtonHTMLAttributes, PropsWithChildren } from "react";
import { cn } from "../../lib/cn";

type ButtonVariant = "default" | "outline" | "danger";

const variants: Record<ButtonVariant, string> = {
  default:
    "border-transparent bg-[var(--accent-strong)] text-[var(--accent-ink)] hover:bg-[var(--accent-bright)]",
  outline:
    "border-[var(--border-subtle)] bg-[var(--surface-muted)] text-[var(--text-primary)] hover:bg-[var(--surface-panel)]",
  danger:
    "border-transparent bg-[var(--danger-strong)] text-white hover:bg-[var(--danger-bright)]",
};

export function Button({
  children,
  className,
  variant = "default",
  ...props
}: PropsWithChildren<ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }>) {
  return (
    <button
      className={cn(
        "inline-flex min-h-10 items-center justify-center rounded-xl border px-4 py-2 text-sm font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-soft)] disabled:cursor-not-allowed disabled:opacity-50",
        variants[variant],
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}
