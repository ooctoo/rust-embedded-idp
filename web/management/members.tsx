import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Drawer, Form, Input, Modal, Select, Space, Table, Typography } from "antd";
import { ManagementClient, ManagementError, type Account, type Member, type Membership, type ResourceScope, type Role, type RoleBinding, type RoleDetail } from "./client";
import { useCursorPage } from "./pagination";
import { AccountPicker } from "./tenants";
import { AdministratorDrawer } from "./administrators";
import { AccountSecurityDrawer, CreateAccount } from "./accounts";

const failure = (reason: unknown) => reason instanceof ManagementError ? reason.message : "操作失败，请重新加载后核对。";
const scopeLabel = (scope: ResourceScope) => scope.kind === "type" ? "该类型的全部资源" : `仅资源 ${scope.resource_id}`;
const accountStatus = { active: "启用", pending_verification: "待验证", disabled: "停用", closed: "已关闭" };
const memberStatus = { active: "有效", suspended: "暂停", removed: "已移除" };

function RoleChoice({ client, tenant, business, choose, disabled }: { client: ManagementClient; tenant: string; business?: string; choose: (role: Role) => void; disabled: boolean }) {
  const load = useCallback((cursor?: string) => client.listRoles(tenant, business, cursor), [client, tenant, business]);
  const result = useCursorPage(load);
  return <>
    {result.error && <Alert type="error" role="alert" message={result.error} action={<Button onClick={result.reload}>重试</Button>} />}
    <Table<Role> scroll={{ x: 440 }} rowKey="role_id" dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} columns={[
      { title: "业务标识", dataIndex: "business_id" },
      { title: "角色", dataIndex: "name", render: (name, role) => <>{name}<br /><Typography.Text type="secondary">{role.key}</Typography.Text></> },
      { title: "操作", render: (_, role) => <Button disabled={disabled || !["business", "business_admin"].includes(role.kind) || role.status !== "active"} onClick={() => choose(role)} aria-label={`选择角色 ${role.name}`}>选择</Button> },
    ]} />{result.controls}
  </>;
}

function GrantForm({ client, tenant, business, subject, busy, blocked, error, grant }: {
  client: ManagementClient; tenant: string; business?: string; subject: Member; busy: boolean; blocked: boolean; error: string;
  grant: (role: RoleDetail, resource?: string, scope?: ResourceScope | { kind: "business" }) => Promise<void>;
}) {
  const [selected, setSelected] = useState<Role>();
  const [role, setRole] = useState<RoleDetail>();
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [draft, setDraft] = useState<{ resource: string; scope: ResourceScope }>();
  useEffect(() => {
    if (!selected) return;
    let active = true;
    setRole(undefined); setLoading(true); setLoadError("");
    client.getRole(tenant, selected.business_id, selected.role_id).then(value => { if (active) setRole(value); })
      .catch(reason => { if (active) setLoadError(failure(reason)); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, tenant, business, selected]);
  return <>
    {loadError && <Alert type="error" role="alert" message={loadError} />}
    {!selected ? <RoleChoice client={client} tenant={tenant} business={business} choose={setSelected} disabled={busy || blocked} /> : <>
      <Button disabled={busy} onClick={() => { setSelected(undefined); setRole(undefined); setLoadError(""); }}>重新选择角色</Button>
      {loading && <Card loading />}
      {role && (!["business", "business_admin"].includes(role.kind) || role.status !== "active") && <Alert type="warning" message="角色状态已变化，请重新选择可用的业务角色。" />}
      {role?.kind === "business_admin" && <>
        <Alert type="info" message={`将 ${subject.email} 设为 ${tenant} / ${role.business_id} 的业务管理员`} description="拥有此业务全部有效权限，包括以后新增的权限。不获得 IDP 管理权限。" />
        <Button type="primary" disabled={busy || blocked || role.status !== "active"} onClick={() => grant(role, undefined, { kind: "business" })}>确认分配业务管理员</Button>
      </>}
      {role?.kind === "business" && !role.permissions.length && <Alert type="info" message="此角色尚无可分配的资源类型，请先配置角色权限。" />}
      {role?.kind === "business" && <Form key={role.role_id} layout="vertical" disabled={busy || blocked || role.status !== "active"}
        onFinish={(values: { resource: string; kind: "type" | "instance"; resource_id?: string }) => setDraft({ resource: values.resource,
          scope: values.kind === "instance" ? { kind: "instance", resource_id: values.resource_id! } : { kind: "type" } })}>
        <Typography.Paragraph>业务标识：{role.business_id}<br />角色：{role.name}</Typography.Paragraph>
        <Form.Item name="resource" label="资源类型" rules={[{ required: true, message: "请选择资源类型" }]}>
          <Select options={[...new Set(role.permissions.map(p => p.resource_type))].map(value => ({ value, label: value }))} />
        </Form.Item>
        <Form.Item name="kind" label="授权范围" rules={[{ required: true, message: "必须明确选择授权范围" }]}>
          <Select options={[{ value: "instance", label: "仅一个具体资源" }, { value: "type", label: "该类型的全部资源" }]} />
        </Form.Item>
        <Form.Item noStyle shouldUpdate={(before, after) => before.kind !== after.kind}>{({ getFieldValue }) => getFieldValue("kind") === "instance" ?
          <Form.Item name="resource_id" label="资源 ID" preserve={false} rules={[{ required: true, message: "请输入具体资源 ID" }, { pattern: /^[A-Za-z0-9_.-]{1,256}$/, message: "仅含字母、数字、点、下划线或连字符，最多 256 位" }]}><Input maxLength={256} /></Form.Item> : null}</Form.Item>
        <Button htmlType="submit" type="primary">预览授权</Button>
      </Form>}
    </>}
    <Modal rootClassName="management-overlay" open={!!draft} title="确认成员角色分配" okText="确认分配" cancelText="返回修改" confirmLoading={busy} okButtonProps={{ disabled: blocked }}
      cancelButtonProps={{ disabled: busy }} maskClosable={false} closable={!busy} keyboard={!busy} onCancel={() => setDraft(undefined)}
      onOk={() => role && draft ? grant(role, draft.resource, draft.scope) : undefined}>
      {error && <Alert type="error" role="alert" message={error} description="请关闭授权表单，重新读取已有分配后核对。" />}
      {role && draft && <>
        <Typography.Paragraph>目标域：{tenant} / {role.business_id}<br />成员：{subject.email}（{subject.account_id}）<br />角色：{role.name}<br />资源类型：{draft.resource}<br />范围：{scopeLabel(draft.scope)}</Typography.Paragraph>
        <Typography.Paragraph>当前动作：{role.permissions.filter(p => p.resource_type === draft.resource).map(p => p.action).join("、")}</Typography.Paragraph>
        <Alert type={draft.scope.kind === "type" ? "warning" : "info"} showIcon message={scopeLabel(draft.scope)} description="分配后可执行的动作随角色权限变化。具体资源的存在和租户归属仍由业务宿主校验。" />
      </>}
    </Modal>
  </>;
}

function BindingDrawer({ client, tenant, subject, close }: { client: ManagementClient; tenant: string; subject: Member; close: () => void }) {
  const [business, setBusiness] = useState<string>();
  const load = useCallback((cursor?: string) => client.listRoleBindings(tenant, business, subject.account_id, cursor), [client, tenant, business, subject.account_id]);
  const result = useCursorPage(load);
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [error, setError] = useState("");
  const [revoke, setRevoke] = useState<{ binding: RoleBinding; role: RoleDetail }>();
  const reloadButton = useRef<HTMLButtonElement>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const mutate = async (operation: () => Promise<unknown>) => {
    setBusy(true); setError("");
    try { await operation(); if (mounted.current) { setAdding(false); setRevoke(undefined); result.reload(); requestAnimationFrame(() => reloadButton.current?.focus()); } }
    catch (reason) { if (mounted.current) { setError(failure(reason)); setBlocked(true); } }
    finally { if (mounted.current) setBusy(false); }
  };
  return <Drawer open title={`成员角色：${subject.email}`} width={720} onClose={close} closable={!busy} keyboard={!busy} maskClosable={!busy}>
    <Typography.Paragraph>目标域：{tenant} · 用户 ID：{subject.account_id}</Typography.Paragraph>
    {(error || result.error) && <Alert type="error" showIcon role="alert" message={error || result.error} />}
    <Form layout="inline" className="management-filter" disabled={busy} onFinish={(values: { business_id?: string }) => {
      setRevoke(undefined); setError(""); setBlocked(false); setBusiness(values.business_id?.trim() || undefined); result.reload();
    }}>
      <Form.Item name="business_id" label="业务标识" rules={[{ pattern: /^(?!idp\.)[a-z][a-z0-9_.-]{0,63}$/, message: "请输入有效业务标识" }]}><Input allowClear maxLength={64} placeholder="全部业务" /></Form.Item>
      <Button htmlType="submit">查询</Button>
    </Form>
    <Space className="management-filter">
      <Button ref={reloadButton} disabled={busy} onClick={() => { setAdding(false); setRevoke(undefined); setError(""); setBlocked(false); result.reload(); }}>重新加载分配</Button>
      <Button type={adding ? "default" : "primary"} disabled={busy || blocked || result.loading || !!result.error || subject.status !== "active" || subject.membership.status !== "active"} onClick={() => setAdding(v => !v)}>{adding ? "取消分配" : "分配业务角色"}</Button>
    </Space>
    <Typography.Title level={4}>{adding ? "选择要分配的角色" : "已分配角色"}</Typography.Title>
    <Typography.Paragraph type="secondary">{adding ? "可按业务标识筛选，然后选择角色并确认授权范围。" : "下方仅显示该成员已有的角色。添加其他业务的角色，请点击“分配业务角色”。"}</Typography.Paragraph>
    {adding ? <GrantForm key={business ?? ""} client={client} tenant={tenant} business={business} subject={subject} busy={busy} blocked={blocked} error={error}
      grant={(role, resource, scope) => mutate(() => client.grantRole(tenant, role.business_id, subject.account_id, role, resource, scope))} /> : <>
      <Table<RoleBinding> rowKey="binding_id" dataSource={result.page?.items ?? []} pagination={false} loading={result.loading} scroll={{ x: 520 }}
        locale={{ emptyText: result.error ? "未能读取分配" : "此成员暂无角色分配" }} columns={[
          { title: "业务标识", dataIndex: "business_id" },
          { title: "角色 ID", dataIndex: "role_id" }, { title: "资源类型", render: (_, binding) => "resource_type" in binding ? binding.resource_type : "全部业务权限" },
          { title: "范围", render: (_, binding) => binding.scope.kind === "business" ? "整个业务" : scopeLabel(binding.scope) },
          { title: "操作", render: (_, binding) => binding.business_id === "idp" ? <Typography.Text type="secondary">通过管理员授权管理</Typography.Text> : <Button danger disabled={busy || blocked} onClick={async () => {
            setBusy(true); setError("");
            try {
              const role = await client.getRole(tenant, binding.business_id, binding.role_id);
              if (mounted.current) {
                if (!["business", "business_admin"].includes(role.kind)) setError("保护角色请通过专用管理员任命流程管理。");
                else setRevoke({ binding, role });
              }
            } catch (reason) { if (mounted.current) setError(failure(reason)); }
            finally { if (mounted.current) setBusy(false); }
          }}>撤销</Button> },
        ]} />{result.controls}
    </>}
    <Modal rootClassName="management-overlay" open={!!revoke} title="确认撤销角色分配" okText="确认撤销" cancelText="取消" confirmLoading={busy}
      okButtonProps={{ danger: true, disabled: blocked }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false}
      onCancel={() => setRevoke(undefined)} onOk={() => revoke ? mutate(() => client.revokeRoleBinding(tenant, revoke.binding.business_id, revoke.binding, revoke.role)) : undefined}>
      {error && <Alert type="error" role="alert" message={error} description="请取消并重新加载分配后核对。" />}
      {revoke && <Typography.Paragraph>目标域：{tenant} / {revoke.binding.business_id}<br />成员：{subject.email}<br />角色：{revoke.role.name}<br />资源类型：{"resource_type" in revoke.binding ? revoke.binding.resource_type : "全部业务权限"}<br />范围：{revoke.binding.scope.kind === "business" ? "整个业务" : scopeLabel(revoke.binding.scope)}</Typography.Paragraph>}
      <Typography.Paragraph>仅移除此项分配，不删除成员或角色。</Typography.Paragraph>
    </Modal>
  </Drawer>;
}

function MembershipEditor({ client, tenant, subject, close, changed }: {
  client: ManagementClient; tenant: string; subject: string; close: () => void; changed: () => void;
}) {
  const [member, setMember] = useState<Member>();
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState<Membership["status"]>();
  const reloadButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    let active = true;
    setLoading(true); setMember(undefined); setStatus(undefined); setError("");
    client.getMember(tenant, subject).then(value => { if (active) { setMember(value); setBlocked(false); } })
      .catch(reason => { if (active) setError(failure(reason)); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, tenant, subject, attempt]);
  return <Drawer open title="成员关系" width={620} onClose={close} closable={!busy} keyboard={!busy} maskClosable={!busy}>
    <Typography.Paragraph>目标租户：{tenant}</Typography.Paragraph>
    {error && <Alert type="error" role="alert" message={error} description="请重新加载成员核对，不要重复提交。" />}
    <Button ref={reloadButton} disabled={busy || loading} onClick={() => setAttempt(v => v + 1)}>重新加载成员</Button>
    {loading ? <Card loading /> : member && <>
      <Typography.Paragraph className="management-note">用户：{member.email}（{member.account_id}）<br />账号：{accountStatus[member.status]}<br />成员关系：{memberStatus[member.membership.status]} · 版本 {member.membership.version}</Typography.Paragraph>
      {member.membership.status === "removed" ? <Alert type="info" message="已移除的成员须由平台重新绑定；重新加入不会恢复原有角色与设备绑定。" /> : <Space wrap>
        <Button disabled={busy || blocked || member.membership.status !== "suspended" || member.status !== "active"} onClick={() => setStatus("active")}>恢复成员</Button>
        <Button disabled={busy || blocked || member.membership.status !== "active"} onClick={() => setStatus("suspended")}>暂停成员</Button>
        <Button danger disabled={busy || blocked} onClick={() => setStatus("removed")}>移除成员</Button>
      </Space>}
    </>}
    <Modal rootClassName="management-overlay" open={!!status} title="确认成员关系变更" okText="确认变更" cancelText="取消" confirmLoading={busy}
      okButtonProps={{ danger: status !== "active", disabled: blocked }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false}
      onCancel={() => setStatus(undefined)} onOk={async () => {
        if (!member || !status) return;
        setBusy(true); setError("");
        try {
          const membership = await client.setMemberStatus(tenant, member.membership, status);
          setMember({ ...member, membership }); setStatus(undefined); changed(); requestAnimationFrame(() => reloadButton.current?.focus());
        } catch (reason) { setError(failure(reason)); setBlocked(true); }
        finally { setBusy(false); }
      }}>
      {error && <Alert type="error" role="alert" message={error} description="请取消并重新加载成员核对。" />}
      <Typography.Paragraph>租户：{tenant}<br />用户：{member?.email}（{subject}）<br />目标状态：{status && memberStatus[status]}</Typography.Paragraph>
      <Alert type="warning" showIcon message={status === "removed" ? "移除会撤销此租户中的会话、角色和设备绑定，重新加入不会自动恢复。" : status === "suspended" ? "暂停会撤销此租户中的会话并阻止访问；恢复后需要重新登录。" : "恢复后，成员可重新登录并使用保留的角色授权。"}
        description="不修改共享账号或密码。服务端会阻止移除最后一个租户关系，以及破坏最后一位有效管理员的变更。" />
    </Modal>
  </Drawer>;
}

function BindMember({ client, tenant, close }: { client: ManagementClient; tenant: string; close: () => void }) {
  const [account, setAccount] = useState<Account>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return <Drawer open title="绑定已有用户" width={620} onClose={close} closable={!busy} keyboard={!busy} maskClosable={!busy}>
    <Typography.Paragraph>目标租户：{tenant}。从不同租户的已有用户中选择，保留同一用户 ID 和登录凭证。</Typography.Paragraph>
    {!account && <AccountPicker client={client} select={setAccount} />}
    <Modal rootClassName="management-overlay" open={!!account} title="确认绑定成员" okText="确认绑定" cancelText="取消" confirmLoading={busy}
      okButtonProps={{ disabled: !!error }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false}
      onCancel={() => { if (error) close(); else setAccount(undefined); }} onOk={async () => {
        if (!account) return;
        setBusy(true);
        try { await client.bindMember(tenant, account.account_id); close(); }
        catch (reason) { setError(failure(reason)); }
        finally { setBusy(false); }
      }}>
      {error && <Alert type="error" role="alert" message={error} description="请取消并核对成员列表，再决定是否重新绑定。" />}
      <Typography.Paragraph>租户：{tenant}<br />用户：{account?.email}（{account?.account_id}）</Typography.Paragraph>
      <Alert type="info" message="只建立有效成员关系，不自动分配业务角色。" description="已有效的成员保持不变；已暂停的成员需使用恢复操作；已移除的成员重新加入后，原角色和设备绑定不会恢复。" />
    </Modal>
  </Drawer>;
}

function MemberTable({ client, tenant, email }: { client: ManagementClient; tenant: string; email: string }) {
  const load = useCallback((cursor?: string) => client.listMembers(tenant, email, cursor), [client, tenant, email]);
  const result = useCursorPage(load);
  const [subject, setSubject] = useState<Member>();
  const [relationship, setRelationship] = useState<string>();
  const [administrator, setAdministrator] = useState<string>();
  const [binding, setBinding] = useState(false);
  const [security, setSecurity] = useState<string>();
  const [creating, setCreating] = useState(false);
  const trigger = useRef<HTMLElement | null>(null);
  const refreshButton = useRef<HTMLButtonElement>(null);
  const state = client.getSnapshot();
  const enabled = state.capabilities!.tenancy_enabled;
  const platform = enabled && state.session!.tenant_id === "0";
  const close = () => {
    setSubject(undefined); setRelationship(undefined); setAdministrator(undefined); setBinding(false); setSecurity(undefined); setCreating(false); result.reload();
    requestAnimationFrame(() => (trigger.current?.isConnected ? trigger.current : refreshButton.current)?.focus());
  };
  return <>
    <Space wrap className="management-filter"><Button ref={refreshButton} disabled={result.loading} onClick={result.reload}>刷新成员</Button>
      {state.session!.tenant_id === "0" && <Button type="primary" onClick={event => { trigger.current = event.currentTarget; setCreating(true); }}>新建用户</Button>}
      {platform && <Button onClick={event => { trigger.current = event.currentTarget; setBinding(true); }}>绑定已有用户</Button>}
    </Space>
    {result.error && <Alert type="error" role="alert" message={result.error} />}
    <Table<Member> rowKey="account_id" dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 660 }}
      locale={{ emptyText: result.error ? "未能读取成员" : "没有符合条件的成员" }} columns={[
        { title: "成员", render: (_, member) => <>{member.display_name || member.email}<br /><Typography.Text type="secondary">{member.email}</Typography.Text></> },
        { title: "账号状态", dataIndex: "status", render: (status: Member["status"]) => accountStatus[status] },
        { title: "成员关系", render: (_, member) => memberStatus[member.membership.status] },
        { title: "操作", render: (_, member) => <Space wrap>
          <Button onClick={event => { trigger.current = event.currentTarget; setSubject(member); }} aria-label={`查看成员角色 ${member.email}`}>角色分配</Button>
          {state.session!.tenant_id === "0" && <Button onClick={event => { trigger.current = event.currentTarget; setAdministrator(member.account_id); }} aria-label={`管理管理员授权 ${member.email}`}>管理员授权</Button>}
          {state.session!.tenant_id === "0" && <Button onClick={event => { trigger.current = event.currentTarget; setSecurity(member.account_id); }} aria-label={`管理账号安全 ${member.email}`}>账号安全</Button>}
          {enabled && <Button onClick={event => { trigger.current = event.currentTarget; setRelationship(member.account_id); }} aria-label={`管理成员关系 ${member.email}`}>成员关系</Button>}
        </Space> },
      ]} />{result.controls}
    {subject && <BindingDrawer client={client} tenant={tenant} subject={subject} close={close} />}
    {administrator && <AdministratorDrawer client={client} tenant={tenant} subject={administrator} close={close} />}
    {relationship && <MembershipEditor client={client} tenant={tenant} subject={relationship} close={close} changed={result.reload} />}
    {security && <AccountSecurityDrawer client={client} subject={security} close={close} />}
    {creating && <CreateAccount client={client} tenant={tenant} close={close} />}
    {binding && <BindMember client={client} tenant={tenant} close={close} />}
  </>;
}

export function MemberRoles({ client, tenant }: { client: ManagementClient; tenant: string }) {
  const [email, setEmail] = useState("");
  return <Card title="成员管理" className="management-card">
    <Form layout="inline" className="management-filter" onFinish={(values: { email?: string }) => setEmail(values.email?.trim() ?? "")}>
      <Form.Item name="email" label="邮箱"><Input allowClear maxLength={320} /></Form.Item><Button htmlType="submit">查询</Button>
    </Form>
    <MemberTable key={`${tenant}:${email}`} client={client} tenant={tenant} email={email} />
  </Card>;
}
