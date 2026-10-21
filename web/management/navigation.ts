import type { Capabilities, Session } from "./client";

export const platformPages = [
  ["home", "工作台"], ["tenants", "租户管理"], ["administrators", "系统管理员"],
  ["accounts", "账号安全"], ["clients", "客户端管理"], ["directory", "平台权限"], ["audit", "平台审计"],
] as const;
export const tenantPages = [
  ["home", "工作台"], ["members", "成员管理"], ["roles", "角色与权限"], ["directory", "权限目录"],
  ["diagnostic", "权限诊断"], ["devices", "设备管理"], ["sessions", "会话管理"], ["audit", "审计记录"],
] as const;
export const systemPages = [
  ...tenantPages, ["accounts", "账号安全"], ["clients", "客户端管理"], ["administrators", "系统管理员"],
] as const;
export type Page = typeof systemPages[number][0] | typeof platformPages[number][0];
export type ConsoleRoute = { scope: "platform" | "system" | "tenant"; page: Page; tenant?: string };
export type RouteResult = { route: ConsoleRoute; status?: never } | { status: 403 | 404; route?: never };

export function pagesFor(scope: ConsoleRoute["scope"]) {
  return scope === "platform" ? platformPages : scope === "system" ? systemPages : tenantPages;
}
export function routeHash(route: ConsoleRoute) {
  return route.scope === "tenant" ? `#/tenants/${encodeURIComponent(route.tenant!)}/${route.page}` : `#/${route.scope}/${route.page}`;
}
export function defaultRoute(capabilities: Capabilities, session: Session): ConsoleRoute {
  return !capabilities.tenancy_enabled ? { scope: "system", page: "home" } : session.tenant_id === "0"
    ? { scope: "platform", page: "home" } : { scope: "tenant", tenant: session.tenant_id, page: "home" };
}
// A hash is a fixed page locator, never an API path or an authorization claim.
export function resolveRoute(hash: string, capabilities: Capabilities, session: Session): RouteResult {
  if (["", "#", "#/"].includes(hash)) return { route: defaultRoute(capabilities, session) };
  if (hash.length > 512) return { status: 404 };
  let parts: string[];
  try { parts = hash.replace(/^#/, "").split("/").map(decodeURIComponent); }
  catch { return { status: 404 }; }
  let route: ConsoleRoute;
  if (parts[0] === "" && parts.length === 3 && ["platform", "system"].includes(parts[1])) {
    route = { scope: parts[1] as "platform" | "system", page: parts[2] as Page };
  } else if (parts[0] === "" && parts.length === 4 && parts[1] === "tenants" && /^[A-Za-z0-9_.-]{1,128}$/.test(parts[2])) {
    // This fragment is a fixed locator, not an HTTP path: dot-only tenant IDs
    // remain data and never collapse or traverse these four segments.
    route = { scope: "tenant", tenant: parts[2], page: parts[3] as Page };
  } else return { status: 404 };
  if (!pagesFor(route.scope).some(([key]) => key === route.page)) return { status: 404 };
  if (!capabilities.tenancy_enabled) return route.scope === "system" && session.tenant_id === "0" ? { route } : { status: 403 };
  if (route.scope === "system" || route.scope === "platform" && session.tenant_id !== "0" ||
      route.scope === "tenant" && (route.tenant === "0" || session.tenant_id !== "0" && route.tenant !== session.tenant_id)) return { status: 403 };
  return { route };
}
