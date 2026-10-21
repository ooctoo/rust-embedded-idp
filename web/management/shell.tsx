import { useCallback, useEffect, useRef, useState } from "react";
import { Button, Card, Descriptions, Drawer, Menu, Result, Space, Spin, Tag } from "antd";
import { ManagementClient, ManagementError, type ManagedTenant } from "./client";
import { defaultRoute, pagesFor, resolveRoute, routeHash, type ConsoleRoute } from "./navigation";
import { useHashNavigation } from "./hash-navigation";
import { RoleTable } from "./roles";
import { MemberRoles } from "./members";
import { TenantManagement } from "./tenants";
import { PlatformAdministrators } from "./administrators";
import { AccountSecurityAccounts } from "./accounts";
import { DeviceManagement } from "./devices";
import { SessionManagement } from "./sessions";
import { ClientManagement } from "./clients";
import { PermissionDirectory } from "./permission-directory";
import { AuditManagement } from "./audit";
import { AccessDiagnostic } from "./diagnostic";

// All page dialogs live under this React tree (including Ant portals). Navigation
// drawers and the read-only identity drawer do not contain page drafts.
function pageDialogOpen() {
  return [...document.querySelectorAll<HTMLElement>('[role="dialog"]')].some(element =>
    element.getClientRects().length > 0 && !element.closest(".management-navigation-drawer, .management-identity-dialog"));
}

export function ManagementShell({ client, busy, verifiedAt, notices, verify, logout, switchTenant }: {
  client: ManagementClient; busy: boolean; verifiedAt?: string; notices: React.ReactNode;
  verify: () => void; logout: () => void; switchTenant: () => void;
}) {
  const { capabilities, session } = client.getSnapshot();
  const caps = capabilities!, identity = session!;
  const platform = caps.tenancy_enabled && identity.tenant_id === "0";
  const acknowledged = useRef(client.getMutationSnapshot().revision);
  const draft = useRef(false);
  const canLeave = useCallback(() => {
    const activity = client.getMutationSnapshot();
    if (activity.pending) { window.alert("正在提交操作，请等待结果后再离开当前页面。"); return false; }
    if ((draft.current || pageDialogOpen() || activity.revision !== acknowledged.current) &&
      !window.confirm("本页有编辑内容或写入记录。离开前请核对原目标的提交结果；确认离开并放弃未保存内容？")) return false;
    acknowledged.current = activity.revision;
    draft.current = false;
    return true;
  }, [client]);
  const { hash, navigate } = useHashNavigation(canLeave);
  const result = resolveRoute(hash, caps, identity);
  const route = result.route;
  const fallback = defaultRoute(caps, identity);
  const [menuOpen, setMenuOpen] = useState(false);
  const [identityOpen, setIdentityOpen] = useState(false);
  const [target, setTarget] = useState<{ id: string; record?: ManagedTenant; error?: ManagementError }>();
  const [targetRevision, setTargetRevision] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (["", "#", "#/"].includes(hash)) navigate(routeHash(fallback), true);
  }, [hash, fallback.scope, fallback.tenant, navigate]);
  useEffect(() => { heading.current?.focus(); setMenuOpen(false); }, [hash]);
  useEffect(() => {
    const prevent = (event: BeforeUnloadEvent) => {
      const activity = client.getMutationSnapshot();
      if (draft.current || pageDialogOpen() || activity.pending || activity.revision !== acknowledged.current) {
        event.preventDefault(); event.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", prevent);
    return () => window.removeEventListener("beforeunload", prevent);
  }, [client]);
  useEffect(() => {
    if (!platform || route?.scope !== "tenant") { setTarget(undefined); return; }
    let active = true;
    const id = route.tenant!;
    setTarget({ id });
    client.getManagedTenant(id).then(record => { if (active) setTarget({ id, record }); })
      .catch(error => { if (active) setTarget({ id, error: error instanceof ManagementError ? error : new ManagementError("读取目标租户失败，请重试。") }); });
    return () => { active = false; };
  }, [client, platform, route?.scope, route?.tenant, targetRevision]);

  const open = (next: ConsoleRoute) => navigate(routeHash(next));
  const scope = route?.scope ?? fallback.scope;
  const entries = pagesFor(scope);
  const title = entries.find(([key]) => key === route?.page)?.[1] ?? (result.status === 403 ? "无权访问" : "页面不存在");
  const scopeLabel = !caps.tenancy_enabled ? "系统管理" : scope === "tenant" ? "租户管理" : "平台工作区";
  const loginScope = !caps.tenancy_enabled ? "系统（0）" : identity.tenant_id === "0" ? "平台（0）" : `租户 ${identity.tenant_id}`;
  const menus = <>
    <div className="management-workspace-name"><strong>{scopeLabel}</strong>
      <div>{scope === "tenant" ? (route ?? fallback).tenant : !caps.tenancy_enabled ? "单域 0" : "整套部署"}</div></div>
    <Menu mode="inline" aria-label="管理任务" selectedKeys={route ? [route.page] : []}
      items={entries.map(([key, label]) => ({ key, label, "aria-current": route?.page === key ? "page" as const : undefined }))}
      onClick={({ key }) => open({ ...(route ?? fallback), page: key as ConsoleRoute["page"] })} />
    {platform && scope === "tenant" && <div className="management-navigation-extra"><Button onClick={() => open(fallback)}>返回平台工作区</Button></div>}
  </>;
  const targetLoading = platform && route?.scope === "tenant" && (target?.id !== route.tenant || !target?.record && !target?.error);
  return <div className="management-shell">
    <a href="#management-content" className="management-skip" onClick={event => { event.preventDefault(); heading.current?.focus(); }}>跳过导航</a>
    <header className="management-shell-header">
      <div className="management-shell-brand"><Button className="management-menu-toggle" onClick={() => setMenuOpen(true)}>菜单</Button><strong>IDP · 身份管理</strong></div>
      <Space wrap><span>登录范围：{loginScope}</span><Button onClick={() => setIdentityOpen(true)}>当前会话</Button>
        {client.canChoose() && <Button disabled={busy} onClick={() => { if (canLeave()) switchTenant(); }}>切换登录租户</Button>}
        <Button disabled={busy} onClick={() => { if (canLeave()) logout(); }}>退出登录</Button></Space>
    </header>
    <div className="management-shell-body"><aside className="management-sidebar">{menus}</aside>
      <main id="management-content" className="management-content">
        {notices}
        <div className="management-breadcrumb">{scopeLabel} / {title}</div>
        {route?.scope === "tenant" && <div className="management-target">
          <div><strong>管理目标：{target?.record && target.id === route.tenant ? `${target.record.name}（${route.tenant}）` : route.tenant}</strong>
            <div className="management-scope-note">登录范围：{loginScope}；管理目标不改变认证会话。</div></div>
          {platform && <Button onClick={() => open({ scope: "platform", page: "tenants" })}>更换管理目标</Button>}
          {target?.record && target.record.status !== "active" && <Tag>目标状态：{target.record.status === "suspended" ? "暂停" : "已归档"}</Tag>}
        </div>}
        <h1 ref={heading} tabIndex={-1}>{title}</h1>
        <div key={hash} className="management-page" onChangeCapture={event => { if ((event.target as HTMLElement).closest('[role="dialog"], [data-management-draft]')) draft.current = true; }}>
          {result.status ? <Result status={result.status} title={result.status === 403 ? "无权访问此管理范围" : "页面不存在"}
            subTitle="页面地址不授予权限。请返回当前会话的管理范围。" extra={<Button onClick={() => open(fallback)}>返回当前管理范围</Button>} />
          : targetLoading ? <div role="status"><Spin /> 正在读取管理目标…</div>
          : platform && route?.scope === "tenant" && target?.error ? <Result
            status={target.error.status === 403 ? "403" : target.error.status === 404 ? "404" : "error"}
            title={target.error.status === 403 ? "无权读取此管理目标" : target.error.status === 404 ? "目标不存在或不可见" : "读取管理目标失败"}
            subTitle={target.error.message} extra={<Space><Button onClick={() => setTargetRevision(v => v + 1)}>重新读取目标</Button><Button onClick={() => open(fallback)}>返回平台工作区</Button></Space>} />
          : route && <PageContent client={client} route={route} open={open} />}
        </div>
      </main>
    </div>
    <Drawer rootClassName="management-navigation-drawer" title="管理任务" placement="left" open={menuOpen} onClose={() => setMenuOpen(false)} width={280}>{menus}</Drawer>
    <Drawer rootClassName="management-identity-dialog" title="当前管理会话" open={identityOpen} onClose={() => setIdentityOpen(false)} width={480}>
      <Descriptions column={1} items={[
        { key: "scope", label: "登录范围", children: loginScope }, { key: "account", label: "账号 ID", children: identity.account_id },
        { key: "session", label: "会话 ID", children: identity.session_id }, { key: "client", label: "客户端", children: identity.client_id ?? "未提供" },
        { key: "verified", label: "最近校验", children: verifiedAt ?? "已验证当前会话" },
      ]} /><Button loading={busy} onClick={verify}>校验当前会话</Button>
    </Drawer>
  </div>;
}

function PageContent({ client, route, open }: { client: ManagementClient; route: ConsoleRoute; open: (route: ConsoleRoute) => void }) {
  const tenant = route.scope === "system" ? "0" : route.tenant!;
  if (route.page === "home") return <Card title="管理任务" className="management-card">
    <p>按当前会话范围选择任务。实际操作权限由服务端实时校验。</p>
    <Space wrap>{pagesFor(route.scope).filter(([key]) => key !== "home").map(([key, label]) =>
      <Button key={key} onClick={() => open({ ...route, page: key })}>{label}</Button>)}</Space>
  </Card>;
  if (route.scope === "platform") {
    switch (route.page) {
      case "tenants": return <TenantManagement client={client} select={selected => open({ scope: "tenant", tenant: selected.tenant_id, page: "members" })} />;
      case "administrators": return <PlatformAdministrators client={client} />;
      case "accounts": return <AccountSecurityAccounts client={client} />;
      case "clients": return <ClientManagement client={client} />;
      case "directory": return <PermissionDirectory client={client} tenant="0" />;
      case "audit": return <AuditManagement client={client} tenant="0" platformScope />;
    }
  }
  switch (route.page) {
    case "roles": return <RoleTable client={client} tenant={tenant} />;
    case "members": return <MemberRoles client={client} tenant={tenant} />;
    case "directory": return <PermissionDirectory client={client} tenant={tenant} />;
    case "diagnostic": return <AccessDiagnostic client={client} tenant={tenant} />;
    case "devices": return <DeviceManagement client={client} tenant={tenant} />;
    case "sessions": return <SessionManagement client={client} tenant={tenant} />;
    case "audit": return <AuditManagement client={client} tenant={tenant} />;
    case "accounts": return <AccountSecurityAccounts client={client} />;
    case "clients": return <ClientManagement client={client} />;
    case "administrators": return <PlatformAdministrators client={client} />;
  }
  return null;
}
