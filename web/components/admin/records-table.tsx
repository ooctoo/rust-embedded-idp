import { ChevronRight } from "lucide-react";
import { Badge } from "../ui/badge";
import { Card } from "../ui/card";

type Row = {
  id: string;
  meta: string;
  statusLabel: string;
  tone: "active" | "danger" | "neutral" | "warning";
};

export function RecordsTable({
  emptyText,
  rows,
  selectedId,
  title,
  totalLabel,
  onSelect,
}: {
  emptyText: string;
  rows: Row[];
  selectedId?: string | null;
  title: string;
  totalLabel: string;
  onSelect: (id: string) => void;
}) {
  return (
    <Card className="overflow-hidden">
      <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-5 py-4">
        <div>
          <h2 className="text-base font-semibold text-[var(--text-primary)]">{title}</h2>
          <p className="text-sm text-[var(--text-secondary)]">{totalLabel}</p>
        </div>
      </div>
      <div className="divide-y divide-[var(--border-subtle)]">
        {rows.length ? (
          rows.map((row) => (
            <button
              className={`flex w-full items-center justify-between gap-4 px-5 py-4 text-left transition hover:bg-white/5 ${
                selectedId === row.id ? "bg-white/6" : ""
              }`}
              key={row.id}
              onClick={() => onSelect(row.id)}
              type="button"
            >
              <div className="min-w-0">
                <div className="truncate text-sm font-medium text-[var(--text-primary)]">{row.id}</div>
                <div className="truncate text-sm text-[var(--text-secondary)]">{row.meta}</div>
              </div>
              <div className="flex items-center gap-3">
                <Badge tone={row.tone}>{row.statusLabel}</Badge>
                <ChevronRight className="h-4 w-4 text-[var(--text-muted)]" />
              </div>
            </button>
          ))
        ) : (
          <div className="px-5 py-10 text-sm text-[var(--text-secondary)]">{emptyText}</div>
        )}
      </div>
    </Card>
  );
}
