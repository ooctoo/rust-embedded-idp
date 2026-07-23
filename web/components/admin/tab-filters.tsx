import { FilterBar, FilterField, FilterSelect } from "./filter-bar";

export function TabFilters({
  filters,
  onApply,
  onChange,
  tab,
}: {
  filters: Record<string, string>;
  onApply: () => void;
  onChange: (key: string, value: string) => void;
  tab: "accounts" | "clients" | "devices" | "sessions";
}) {
  if (tab === "accounts") {
    return (
      <FilterBar onApply={onApply}>
        <FilterSelect label="Status" onChange={(value) => onChange("status", value)} options={statusOptions(["", "active", "pending_verification", "disabled"])} value={filters.status ?? ""} />
        <FilterField label="Email" onChange={(event) => onChange("email", event.target.value)} value={filters.email ?? ""} />
      </FilterBar>
    );
  }
  if (tab === "sessions") {
    return (
      <FilterBar onApply={onApply}>
        <FilterSelect label="Status" onChange={(value) => onChange("status", value)} options={statusOptions(["", "active", "pending", "revoked", "expired"])} value={filters.status ?? ""} />
        <FilterField label="Account ID" onChange={(event) => onChange("account_id", event.target.value)} value={filters.account_id ?? ""} />
        <FilterField label="Client ID" onChange={(event) => onChange("client_id", event.target.value)} value={filters.client_id ?? ""} />
      </FilterBar>
    );
  }
  if (tab === "clients") {
    return (
      <FilterBar onApply={onApply}>
        <FilterSelect label="Client Type" onChange={(value) => onChange("client_type", value)} options={statusOptions(["", "public_desktop", "confidential_web"])} value={filters.client_type ?? ""} />
        <FilterSelect
          label="PKCE"
          onChange={(value) => onChange("pkce_required", value)}
          options={[{ label: "all", value: "" }, { label: "true", value: "true" }, { label: "false", value: "false" }]}
          value={filters.pkce_required ?? ""}
        />
      </FilterBar>
    );
  }
  return (
    <FilterBar onApply={onApply}>
      <FilterSelect label="Status" onChange={(value) => onChange("status", value)} options={statusOptions(["", "active", "pending", "disabled", "revoked"])} value={filters.status ?? ""} />
      <FilterField label="Account ID" onChange={(event) => onChange("account_id", event.target.value)} value={filters.account_id ?? ""} />
      <FilterField label="Client ID" onChange={(event) => onChange("client_id", event.target.value)} value={filters.client_id ?? ""} />
    </FilterBar>
  );
}

function statusOptions(values: string[]) {
  return values.map((value) => ({ label: value || "all", value }));
}
