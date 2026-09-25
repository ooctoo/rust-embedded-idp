import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Checkbox, Drawer, Form, Input, Modal, Radio, Select, Space, Table, Typography } from "antd";
import { ManagementClient, ManagementError, type Account, type ManagedTenant, type TenantDetail } from "./client";
import { useCursorPage } from "./pagination";

const failure = (reason: unknown) => reason instanceof ManagementError ? reason.message : "操作失败，请重新加载后核对。";
const statusLabel = { active: "启用", suspended: "暂停", archived: "已归档" };

function AccountResults({ client, email, select }: { client: ManagementClient; email: string; select: (account: Account) => void }) {
  const load = useCallback((cursor?: string) => client.listPlatformAccounts(email, cursor), [client, email]);
  const result = useCursorPage(load);
  return <>
    {result.error && <Alert type="error" role="alert" message={result.error} action={<Button onClick={result.reload}>重试</Button>} />}
    <Table<Account> rowKey="account_id" dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 380 }}
      locale={{ emptyText: result.error ? "未能读取用户" : "没有符合条件的有效用户" }} columns={[
        { title: "用户", render: (_, a) => <>{a.display_name || a.email}<br />{a.email}<br /><Typography.Text type="secondary">{a.account_id}</Typography.Text></> },
        { title: "操作", render: (_, a) => <Button onClick={() => select(a)} aria-label={`选择用户 ${a.email}`}>选择</Button> },
      ]} />{result.controls}
  </>;
}

// Shared only by the two platform workflows that select an existing account.
export function AccountPicker({ client, select }: { client: ManagementClient; select: (account: Account) => void }) {
  const [email, setEmail] = useState<string>();
  return <>
    <Form name="platform-account-search" layout="inline" className="management-filter" onFinish={(v: { email?: string }) => setEmail(v.email?.trim() ?? "")}>
      <Form.Item name="email" label="用户邮箱"><Input allowClear maxLength={320} /></Form.Item><Button htmlType="submit">搜索已有用户</Button>
    </Form>
    {email !== undefined && <AccountResults key={email} client={client} email={email} select={select} />}
  </>;
}

type TenantValues = { tenant_id: string; name: string; status: ManagedTenant["status"]; allow_registration: boolean; email?: string; password?: string };
function TenantEditor({ client, tenantId, close, changed }: {
  client: ManagementClient; tenantId?: string; close: () => void; changed: () => void;
}) {
  const [record, setRecord] = useState<TenantDetail>();
  const [administrator, setAdministrator] = useState<Account>();
  const [administratorKind, setAdministratorKind] = useState<"new" | "existing">("new");
  const [loading, setLoading] = useState(!!tenantId);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [blocked, setBlocked] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [draft, setDraft] = useState<TenantValues>();
  const [form] = Form.useForm<TenantValues>();
  const reloadButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!tenantId) return;
    let active = true;
    setLoading(true); setRecord(undefined); setError(""); setDraft(undefined);
    client.getManagedTenant(tenantId).then(value => {
      if (active) { setRecord(value); form.setFieldsValue(value); setBlocked(false); }
    }).catch(reason => { if (active) setError(failure(reason)); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, tenantId, attempt, form]);
  return <Drawer open title={tenantId ? "租户设置" : "创建租户"} width={680} onClose={close} closable={!busy} maskClosable={!busy} keyboard={!busy}>
    {error && <Alert type="error" role="alert" message={error} description={tenantId ? "请重新加载详情，核对最新状态后再操作。" : "请关闭窗口核对是否已创建；发生冲突时，请检查租户 ID 或管理员邮箱是否已存在。"} />}
    {tenantId && <Button ref={reloadButton} disabled={busy || loading} onClick={() => setAttempt(v => v + 1)}>重新加载租户</Button>}
    {loading ? <Card loading /> : (!tenantId || record) && <>
      {!tenantId && <>
        <Typography.Paragraph>选择已有用户或新建账号作为首位管理员。账号、租户、成员关系和管理员授权会一起提交，失败全部回滚。</Typography.Paragraph>
        <Radio.Group aria-label="管理员来源" value={administratorKind} disabled={busy || blocked} onChange={event => {
          setAdministratorKind(event.target.value); setAdministrator(undefined); setDraft(undefined); form.setFieldsValue({ email: undefined, password: undefined });
        }} options={[{ value: "new", label: "新建管理员账号" }, { value: "existing", label: "选择已有用户" }]} />
        {administratorKind === "existing" && (administrator ? <Typography.Paragraph>首位管理员：{administrator.email}（{administrator.account_id}） <Button disabled={busy || blocked} onClick={() => setAdministrator(undefined)}>重新选择</Button></Typography.Paragraph>
          : <AccountPicker client={client} select={setAdministrator} />)}
      </>}
      <Form name="tenant-settings" form={form} layout="vertical" initialValues={{ allow_registration: false }} disabled={busy || blocked} onFinish={({ password: _password, ...values }) => setDraft(values)}>
        <Form.Item name="tenant_id" label="租户 ID" rules={[{ required: true }, { pattern: /^(?!0$)[A-Za-z0-9_.-]{1,128}$/, message: "1–128 位字母、数字、点、下划线或连字符；0 为保留域" }]}>
          <Input disabled={!!tenantId || busy || blocked} maxLength={128} />
        </Form.Item>
        <Form.Item name="name" label="租户名称" rules={[{ required: true, whitespace: true }, { validator: (_, value: string) => !value || (new TextEncoder().encode(value).length <= 256 && !/[\x00-\x1f\x7f]/.test(value)) ? Promise.resolve() : Promise.reject(new Error("名称不能包含控制字符，UTF-8 长度不超过 256 字节")) }]}><Input maxLength={256} /></Form.Item>
        {tenantId && <Form.Item name="status" label="状态" rules={[{ required: true }]}><Select options={Object.entries(statusLabel).map(([value, label]) => ({ value, label }))} /></Form.Item>}
        {!tenantId && administratorKind === "new" && <>
          <Form.Item name="email" label="管理员邮箱" preserve={false} rules={[{ required: true, message: "请输入管理员邮箱" }, { type: "email", max: 254, message: "请输入有效邮箱" }]}><Input autoComplete="off" maxLength={254} /></Form.Item>
          <Form.Item name="password" label="初始密码" preserve={false} rules={[{ required: true, message: "请输入初始密码" }]} extra="至少包含字母和数字，长度按服务端密码规则校验。请通过安全渠道交付给管理员。"><Input.Password autoComplete="new-password" /></Form.Item>
          <Typography.Paragraph type="secondary">邮箱已存在时，请改为选择已有用户；不会覆盖已有账号密码。</Typography.Paragraph>
        </>}
        <Form.Item name="allow_registration" valuePropName="checked"><Checkbox>允许用户在此租户注册</Checkbox></Form.Item>
        <Button type="primary" htmlType="submit" disabled={busy || blocked || (!tenantId && administratorKind === "existing" && !administrator)}>核对并{tenantId ? "保存" : "创建"}</Button>
      </Form>
    </>}
    <Modal rootClassName="management-overlay" open={!!draft} title={tenantId ? "确认租户变更" : "确认创建租户"} okText="确认提交" cancelText="取消" confirmLoading={busy}
      okButtonProps={{ disabled: blocked }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false} onCancel={() => setDraft(undefined)} onOk={async () => {
        if (!draft || (!record && administratorKind === "existing" && !administrator)) return;
        setBusy(true); setError("");
        try {
          const updated = record ? await client.updateTenant(record, draft.name, draft.status, draft.allow_registration)
            : await client.createTenant(draft.tenant_id, draft.name, draft.allow_registration, administratorKind === "existing" ? { kind: "existing", subject_id: administrator!.account_id }
              : { kind: "new", email: draft.email!, password: form.getFieldValue("password") });
          setRecord(updated); form.setFieldsValue(updated); setDraft(undefined); changed();
          if (!tenantId) close(); else requestAnimationFrame(() => reloadButton.current?.focus());
        } catch (reason) { setError(failure(reason)); setBlocked(true); }
        finally { form.setFieldValue("password", undefined); setBusy(false); }
      }}>
      {error && <Alert type="error" role="alert" message={error} description="请取消并核对最新数据后再操作。" />}
      {draft && <Typography.Paragraph>租户：{draft.name}（{draft.tenant_id}）<br />状态：{statusLabel[draft.status ?? "active"]}<br />允许注册：{draft.allow_registration ? "是" : "否"}<br />{!tenantId && (administratorKind === "new" ? `新建管理员：${draft.email}` : `已有管理员：${administrator?.email}（${administrator?.account_id}）`)}</Typography.Paragraph>}
      <Alert type="warning" showIcon message={tenantId ? "暂停或归档后，该租户中的登录和受保护操作将被拒绝。" : "首位管理员将获得此租户的管理权限。"} description="最终状态和权限由服务端在提交时校验。" />
    </Modal>
  </Drawer>;
}

function TenantTable({ client, filter, select }: { client: ManagementClient; filter: { tenant_id?: string; name?: string }; select: (tenant: ManagedTenant) => void }) {
  const load = useCallback((cursor?: string) => client.listManagedTenants(filter, cursor), [client, filter]);
  const result = useCursorPage(load);
  const [editor, setEditor] = useState<{ tenantId?: string }>();
  const trigger = useRef<HTMLElement | null>(null);
  const createButton = useRef<HTMLButtonElement>(null);
  const close = () => { setEditor(undefined); result.reload(); requestAnimationFrame(() => (trigger.current?.isConnected ? trigger.current : createButton.current)?.focus()); };
  return <>
    <Space className="management-filter"><Button onClick={result.reload} disabled={result.loading}>刷新租户</Button><Button ref={createButton} type="primary" onClick={event => { trigger.current = event.currentTarget; setEditor({}); }}>创建租户</Button></Space>
    {result.error && <Alert type="error" role="alert" message={result.error} />}
    <Table<ManagedTenant> rowKey="tenant_id" dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 600 }}
      locale={{ emptyText: result.error ? "未能读取租户" : "没有符合条件的租户" }} columns={[
        { title: "租户", render: (_, t) => <>{t.name}<br /><Typography.Text type="secondary">{t.tenant_id}</Typography.Text></> },
        { title: "状态", dataIndex: "status", render: (status: ManagedTenant["status"]) => statusLabel[status] },
        { title: "操作", render: (_, t) => <Space wrap><Button onClick={() => select(t)} aria-label={`管理 ${t.name}`}>角色与成员</Button><Button aria-label={`设置租户 ${t.name}`} onClick={event => { trigger.current = event.currentTarget; setEditor({ tenantId: t.tenant_id }); }}>设置</Button></Space> },
      ]} />{result.controls}
    {editor && <TenantEditor client={client} tenantId={editor.tenantId} close={close} changed={result.reload} />}
  </>;
}

export function TenantManagement({ client, select }: { client: ManagementClient; select: (tenant: ManagedTenant) => void }) {
  const [filter, setFilter] = useState<{ tenant_id?: string; name?: string }>({});
  return <Card title="租户管理" className="management-card">
    <Typography.Paragraph type="secondary">当前使用平台身份。选择管理目标仅决定数据范围，不会切换登录身份。</Typography.Paragraph>
    <Form name="tenant-search" layout="inline" className="management-filter" onFinish={(v: { tenant_id?: string; name?: string }) => setFilter({ ...(v.tenant_id?.trim() ? { tenant_id: v.tenant_id.trim() } : {}), ...(v.name?.trim() ? { name: v.name.trim() } : {}) })}>
      <Form.Item name="tenant_id" label="租户 ID"><Input allowClear maxLength={128} /></Form.Item><Form.Item name="name" label="名称"><Input allowClear maxLength={256} /></Form.Item><Button htmlType="submit">查询</Button>
    </Form>
    <TenantTable key={JSON.stringify(filter)} client={client} filter={filter} select={select} />
  </Card>;
}
