import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card } from "../ui/card";

export function DetailPanel({
  actions,
  bindings,
  items,
  notice,
  status,
  title,
}: {
  actions?: Array<{ intent?: "danger" | "outline"; label: string; onClick: () => void }>;
  bindings?: Array<{ id: string; meta: string; status: string; tone: "active" | "danger" | "neutral" | "warning" }>;
  items: Array<{ label: string; value: string }>;
  notice?: string;
  status?: { label: string; tone: "active" | "danger" | "neutral" | "warning" };
  title: string;
}) {
  return (
    <Card className="p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-[var(--text-primary)]">{title}</h2>
          {notice ? <p className="mt-2 text-sm leading-6 text-[var(--text-secondary)]">{notice}</p> : null}
        </div>
        {status ? <Badge tone={status.tone}>{status.label}</Badge> : null}
      </div>
      <div className="mt-5 grid gap-4 sm:grid-cols-2">
        {items.map((item) => (
          <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface-panel)] p-4" key={item.label}>
            <div className="text-xs uppercase tracking-[0.12em] text-[var(--text-muted)]">{item.label}</div>
            <div className="mt-2 text-sm font-medium text-[var(--text-primary)]">{item.value}</div>
          </div>
        ))}
      </div>
      {actions?.length ? (
        <div className="mt-5 flex flex-wrap gap-3">
          {actions.map((action) => (
            <Button key={action.label} onClick={action.onClick} variant={action.intent === "danger" ? "danger" : "outline"}>
              {action.label}
            </Button>
          ))}
        </div>
      ) : null}
      {bindings?.length ? (
        <div className="mt-6 space-y-3">
          {bindings.map((binding) => (
            <div className="flex items-center justify-between rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface-panel)] p-4" key={binding.id}>
              <div>
                <div className="text-sm font-medium text-[var(--text-primary)]">{binding.id}</div>
                <div className="text-sm text-[var(--text-secondary)]">{binding.meta}</div>
              </div>
              <Badge tone={binding.tone}>{binding.status}</Badge>
            </div>
          ))}
        </div>
      ) : null}
    </Card>
  );
}
