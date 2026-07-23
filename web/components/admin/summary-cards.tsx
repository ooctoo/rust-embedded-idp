import { Activity, KeyRound, ShieldCheck, Smartphone } from "lucide-react";
import { Card } from "../ui/card";

const icons = {
  accounts: ShieldCheck,
  clients: KeyRound,
  devices: Smartphone,
  sessions: Activity,
};

export function SummaryCards({
  totals,
}: {
  totals: Record<"accounts" | "clients" | "devices" | "sessions", number>;
}) {
  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {Object.entries(totals).map(([key, value]) => {
        const Icon = icons[key as keyof typeof icons];
        return (
          <Card className="p-5" key={key}>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.18em] text-[var(--text-muted)]">{key}</p>
                <p className="mt-3 text-3xl font-semibold text-[var(--text-primary)]">{value}</p>
              </div>
              <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface-panel)] p-3 text-[var(--accent-bright)]">
                <Icon className="h-5 w-5" />
              </div>
            </div>
          </Card>
        );
      })}
    </div>
  );
}
