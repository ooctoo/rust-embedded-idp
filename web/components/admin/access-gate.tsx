import { Input } from "../ui/input";

type AdminAccessGateProps = {
  feedback: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  submitting: boolean;
  value: string;
};

export function AdminAccessGate({
  feedback,
  onChange,
  onSubmit,
  submitting,
  value,
}: AdminAccessGateProps) {
  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-[760px] items-center px-4 py-10">
      <section className="w-full rounded-[32px] border border-[var(--border-subtle)] bg-[var(--surface-elevated)] p-8 shadow-[var(--shadow-card)]">
        <p className="text-sm uppercase tracking-[0.18em] text-[var(--text-muted)]">
          Embedded module admin
        </p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight text-[var(--text-primary)]">
          Admin Access Required
        </h1>
        <p className="mt-4 max-w-2xl text-sm leading-7 text-[var(--text-secondary)]">
          管理页不会在 key 校验通过前加载具体管理内容。请输入
          <code className="mx-1 rounded bg-[var(--surface-muted)] px-2 py-1 text-xs">
            x-embedded-idp-admin-key
          </code>
          对应的值。
        </p>

        <label className="mt-8 grid gap-3">
          <span className="text-xs uppercase tracking-[0.14em] text-[var(--text-muted)]">
            Admin key
          </span>
          <div className="flex flex-col gap-3 sm:flex-row">
            <Input
              onChange={(event) => onChange(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  onSubmit();
                }
              }}
              type="password"
              value={value}
            />
            <button
              className="min-h-10 rounded-xl bg-[var(--accent-strong)] px-5 text-sm font-medium text-[var(--accent-ink)] disabled:cursor-not-allowed disabled:opacity-60"
              disabled={submitting || !value.trim()}
              onClick={onSubmit}
              type="button"
            >
              {submitting ? "Checking..." : "Unlock"}
            </button>
          </div>
        </label>

        <p className="mt-4 text-sm text-[var(--text-secondary)]">{feedback}</p>
      </section>
    </main>
  );
}
