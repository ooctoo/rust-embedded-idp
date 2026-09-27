import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Drawer, Form, Input, Modal, Popconfirm, Select, Space, Table, Tabs, Tag, Typography } from "antd";
import { ManagementClient, ManagementError, type ManagedTenant, type Role, type RoleDetail } from "./client";

import { useCursorPage } from "./pagination";
import { RolePermissions } from "./permissions";
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

const { Text, Paragraph } = Typography;
const statusLabel = { active: "启用", suspended: "停用", archived: "已归档", disabled: "停用" };
const kindLabel = { business: "业务角色", business_admin: "业务管理员", system_admin: "IDP 管理员", tenant_security_admin: "IDP 租户管理员" };
const failure = (error: unknown) => error instanceof ManagementError ? error.message : "操作失败，请重新加载后核对。";


const nameRules = [{ required: true, whitespace: true, message: "请输入角色名称" }, {
  validator: (_: unknown, value: string) => !value || (new TextEncoder().encode(value).length <= 256 && !/[\x00-\x1f\x7f]/.test(value))
    ? Promise.resolve() : Promise.reject(new Error("名称不能包含控制字符，且 UTF-8 长度不能超过 256 字节")),
}];

function CreateRole({ client, tenant, business, businessAdmin, close }: {
  client: ManagementClient; tenant: string; business?: string; businessAdmin: boolean; close: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return <Modal open title={businessAdmin ? "创建业务管理员" : "新建业务角色"} footer={null} onCancel={close} closable={!busy} maskClosable={false} keyboard={!busy}>
    <Paragraph type="secondary">目标域：{tenant}。{businessAdmin ? "每个业务只能创建一个。分配给成员后，自动拥有此业务全部有效权限。" : "新角色默认启用，初始权限为空。"}</Paragraph>
    {error && <Alert type="error" showIcon role="alert" message={error} description="请关闭窗口并核对角色列表，再决定是否重新创建。" />}
    <Form layout="vertical" disabled={busy || !!error} onFinish={async (values: { business_id: string; key: string; name: string }) => {
      setBusy(true);
      try {
        if (businessAdmin) await client.createBusinessAdmin(tenant, values.business_id, values.name);
        else await client.createRole(tenant, values.business_id, values.key, values.name);
        close();
      }
      catch (reason) { setError(failure(reason)); }
      finally { setBusy(false); }
    }}>
      <Form.Item name="business_id" label="业务标识" initialValue={business === "idp" ? undefined : business} rules={[
        { required: true, message: "请输入所属业务标识" }, { pattern: /^[a-z][a-z0-9_.-]{0,63}$/, message: "请输入有效业务标识" },
        { validator: (_, value) => value === "idp" || value?.startsWith("idp.") ? Promise.reject(new Error("不能使用 IDP 保留标识")) : Promise.resolve() },
      ]}><Input maxLength={64} placeholder="例如 biz_test" /></Form.Item>
      {!businessAdmin && <Form.Item name="key" label="角色标识" rules={[{ required: true, message: "请输入角色标识" },
        { pattern: /^[a-z][a-z0-9_.-]{0,63}$/, message: "小写字母开头，仅含小写字母、数字、点、下划线或连字符，最多 64 位" },
        { validator: (_, value) => ["system_admin", "tenant_security_admin", "idp_system_admin", "idp_tenant_security_admin", "business_admin"].includes(value) ? Promise.reject(new Error("此标识为系统保留")) : Promise.resolve() }]}>
        <Input autoFocus maxLength={64} />
      </Form.Item>}
      <Form.Item name="name" label="角色名称" initialValue={businessAdmin ? "业务管理员" : undefined} rules={nameRules}><Input maxLength={256} autoFocus={businessAdmin} /></Form.Item>
      <Button type="primary" htmlType="submit" loading={busy}>创建角色</Button>
    </Form>
  </Modal>;
}

function RoleEditor({ client, tenant, business, roleId, close, changed }: {
  client: ManagementClient; tenant: string; business: string; roleId: string; close: () => void; changed: () => void;
}) {
  const [role, setRole] = useState<RoleDetail>();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const reloadButton = useRef<HTMLButtonElement>(null);
  const [form] = Form.useForm();
  useEffect(() => {
    let active = true;
    setLoading(true); setRole(undefined); setError(""); setSaved(false);
    client.getRole(tenant, business, roleId).then(value => {
      if (active) { setRole(value); form.setFieldsValue(value); setBlocked(false); }
    }).catch(reason => { if (active) setError(failure(reason)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, tenant, business, roleId, attempt, form]);
  const mutation = async (operation: () => Promise<void>) => {
    setBusy(true); setError(""); setSaved(false);
    try { await operation(); changed(); requestAnimationFrame(() => reloadButton.current?.focus()); }
    catch (reason) { setError(failure(reason)); setBlocked(true); }
    finally { setBusy(false); }
  };
  return <Drawer open title="角色详情" width={620} onClose={close} closable={!busy} maskClosable={!busy} keyboard={!busy}>
    <Paragraph type="secondary">目标域：{tenant} / {business}</Paragraph>
    {error && <Alert type="error" showIcon role="alert" message={error} description="重新加载会丢弃未保存内容。请核对最新状态后再操作。" />}
    {saved && <Alert type="success" showIcon role="status" message="角色已保存" />}
    <Button ref={reloadButton} disabled={busy || loading} onClick={() => setAttempt(v => v + 1)}>重新加载详情</Button>
    {loading ? <Card loading /> : role && <>
      <Paragraph className="management-note"><Tag>{kindLabel[role.kind]}</Tag> {role.key} · 版本 {role.version}</Paragraph>
      {!["business", "business_admin"].includes(role.kind) && <Alert type="info" message="系统保护角色只读，请通过专用管理员任命流程管理。" />}
      {role.kind === "business_admin" && <Alert type="info" message="业务管理员自动拥有此业务内全部有效权限，无需配置权限集。" />}
      <Form form={form} layout="vertical" disabled={busy || blocked || !["business", "business_admin"].includes(role.kind)}
        onFinish={(values: { name: string; status: Role["status"] }) => void mutation(async () => {
          const updated = await client.updateRole(tenant, business, role, values.name, values.status);
          setRole(updated); form.setFieldsValue(updated); setSaved(true);
        })}>
        <Form.Item name="name" label="角色名称" rules={nameRules}><Input maxLength={256} /></Form.Item>
        <Form.Item name="status" label="状态" rules={[{ required: true }]}><Select options={[{ value: "active", label: "启用" }, { value: "disabled", label: "停用" }]} /></Form.Item>
        {["business", "business_admin"].includes(role.kind) && <Space>
          <Button type="primary" htmlType="submit" loading={busy}>保存</Button>
          <Popconfirm title={`删除角色“${role.name}”？`} description={role.kind === "business_admin" ? "请先撤销此角色的全部成员分配，再删除角色。" : "删除后无法恢复，依赖该角色的授权将失效。"} okText="确认删除" cancelText="取消"
            onConfirm={() => mutation(async () => { await client.deleteRole(tenant, business, role); close(); })}>
            <Button danger disabled={busy || blocked}>删除角色</Button>
          </Popconfirm>
        </Space>}
      </Form>
      <RolePermissions key={role.version} client={client} tenant={tenant} business={business} role={role} busy={busy} blocked={blocked} error={error}
        save={permissions => mutation(async () => { setRole(await client.replaceRolePermissions(tenant, business, role, permissions)); setSaved(true); })} />
    </>}
  </Drawer>;
}

function RoleTable({ client, tenant }: { client: ManagementClient; tenant: string }) {
  const [business, setBusiness] = useState<string>();
  const load = useCallback((cursor?: string) => client.listRoles(tenant, business, cursor), [client, tenant, business]);
  const result = useCursorPage(load);
  const [creating, setCreating] = useState<"business" | "business_admin">();
  const [selected, setSelected] = useState<Role>();
  const trigger = useRef<HTMLElement | null>(null);
  const createButton = useRef<HTMLButtonElement>(null);
  const close = () => {
    setCreating(undefined); setSelected(undefined);
    requestAnimationFrame(() => { (trigger.current?.isConnected ? trigger.current : createButton.current)?.focus(); });
  };
  return <Card title="角色" className="management-card" extra={<Space><Button onClick={result.reload} disabled={result.loading}>刷新</Button><Button onClick={event => { trigger.current = event.currentTarget; setCreating("business_admin"); }}>创建业务管理员</Button><Button ref={createButton} type="primary" onClick={event => { trigger.current = event.currentTarget; setCreating("business"); }}>新建角色</Button></Space>}>
    <Form layout="inline" className="management-filter" onFinish={(values: { business_id?: string }) => {
      setSelected(undefined); setCreating(undefined); setBusiness(values.business_id?.trim() || undefined); result.reload();
    }}>
      <Form.Item name="business_id" label="业务标识" rules={[{ pattern: /^(?!idp\.)[a-z][a-z0-9_.-]{0,63}$/, message: "请输入有效业务标识" }]}><Input allowClear maxLength={64} placeholder="全部业务" /></Form.Item>
      <Button htmlType="submit">查询</Button>
    </Form>
    {result.error && <Alert type="error" showIcon role="alert" message={result.error} />}
    <Table<Role> rowKey="role_id" loading={result.loading} dataSource={result.page?.items ?? []} pagination={false} scroll={{ x: 680 }}
      locale={{ emptyText: result.error ? "未能读取角色" : "此域暂无角色" }} columns={[
        { title: "角色", dataIndex: "name", render: (name, role) => <><Text strong>{name}</Text><br /><Text type="secondary">{role.key}</Text></> },
        { title: "业务标识", dataIndex: "business_id" },
        { title: "类型", dataIndex: "kind", render: (kind: Role["kind"]) => kindLabel[kind] },
        { title: "状态", dataIndex: "status", render: (status: Role["status"]) => <Tag>{statusLabel[status]}</Tag> },
        { title: "操作", key: "action", render: (_, role) => <Button aria-label={`查看角色 ${role.name}`} onClick={event => { trigger.current = event.currentTarget; setSelected(role); }}>查看详情</Button> },
      ]} />
    {result.controls}
    {creating && <CreateRole client={client} tenant={tenant} business={business} businessAdmin={creating === "business_admin"} close={() => { close(); result.reload(); }} />}
    {selected && <RoleEditor key={selected.role_id} client={client} tenant={tenant} business={selected.business_id} roleId={selected.role_id} close={close} changed={result.reload} />}
  </Card>;
}

export function RoleWorkspace({ client }: { client: ManagementClient }) {
  const { capabilities, session } = client.getSnapshot();
  const platform = capabilities!.tenancy_enabled && session!.tenant_id === "0";
  const [selected, setSelected] = useState<ManagedTenant>();
  const tenant = platform ? selected?.tenant_id : session!.tenant_id;
  return <section className="management-role-workspace" aria-label="身份与访问管理">
    {platform && !selected ? <Tabs destroyOnHidden items={[
      { key: "tenants", label: "租户管理", children: <TenantManagement client={client} select={setSelected} /> },
      { key: "administrators", label: "系统管理员", children: <PlatformAdministrators client={client} /> },
      { key: "accounts", label: "账号安全", children: <AccountSecurityAccounts client={client} /> },
      { key: "clients", label: "客户端管理", children: <ClientManagement client={client} /> },
      { key: "directory", label: "平台权限", children: <PermissionDirectory client={client} tenant="0" /> },
      { key: "audit", label: "审计记录", children: <AuditManagement client={client} tenant="0" platformScope /> },
    ]} /> : <>
      <div className="management-target"><Text strong>管理目标：{capabilities!.tenancy_enabled ? `${selected?.name ?? tenant}（${tenant}）` : "单域"}</Text>
        {platform && <Button onClick={() => setSelected(undefined)}>更换管理目标</Button>}</div>
      <Tabs key={tenant} destroyOnHidden items={[
        { key: "roles", label: "角色与权限", children: <RoleTable client={client} tenant={tenant!} /> },
        { key: "directory", label: "权限目录", children: <PermissionDirectory client={client} tenant={tenant!} /> },
        { key: "members", label: "成员管理", children: <MemberRoles client={client} tenant={tenant!} /> },
        { key: "diagnostic", label: "权限诊断", children: <AccessDiagnostic client={client} tenant={tenant!} /> },
        { key: "devices", label: "设备管理", children: <DeviceManagement client={client} tenant={tenant!} /> },
        { key: "sessions", label: "会话管理", children: <SessionManagement client={client} tenant={tenant!} /> },
        { key: "audit", label: "审计记录", children: <AuditManagement client={client} tenant={tenant!} /> },
        ...(!capabilities!.tenancy_enabled ? [
          { key: "accounts", label: "账号安全", children: <AccountSecurityAccounts client={client} /> },
          { key: "clients", label: "客户端管理", children: <ClientManagement client={client} /> },
        ] : []),
      ]} />
    </>}
  </section>;
}
