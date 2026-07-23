import type { HTMLAttributes, PropsWithChildren } from "react";
import { cn } from "../../lib/cn";

export function Card({
  children,
  className,
  ...props
}: PropsWithChildren<HTMLAttributes<HTMLDivElement>>) {
  return (
    <section
      className={cn(
        "rounded-3xl border border-[var(--border-subtle)] bg-[var(--surface-elevated)] shadow-[var(--shadow-card)] backdrop-blur",
        className,
      )}
      {...props}
    >
      {children}
    </section>
  );
}
