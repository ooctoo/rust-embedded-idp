import { useCallback, useEffect, useRef, useState, useId } from "react";
import { Alert, Button, Card, Checkbox, Drawer, Form, Input, Radio, Select, Space, Table, Typography } from "antd";
import { ManagementClient, type Account, type ManagedTenant, type TenantDetail } from "./client";
import { useCursorPage } from "./pagination";
import { discardChanges, ReadState, SafeConfirm, useWriteFeedback, WriteFeedback } from "./workflow";

const statusLabel = { active: "启用", suspended: "暂停", archived: "已归档" };

function AccountResults({ client, email, select }: { client: ManagementClient; email: string; select: (account: Account) => void }) {
  const load = useCallback((cursor?: string) => client.listPlatformAccounts(email, cursor), [client, email]);
  const result = useCursorPage(load);
  return <>
    <ReadState loading={result.loading} error={result.error} status={result.errorStatus} empty={!!result.page && result.page.items.length === 0} emptyText="没有符合条件的有效用户" retry={result.reload}>
    <Table<Account> rowKey="account_id" dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 380 }}
      locale={{ emptyText: result.error ? "未能读取用户" : "没有符合条件的有效用户" }} columns={[
        { title: "用户", render: (_, a) => <>{a.display_name || a.email}<br />{a.email}<br /><Typography.Text type="secondary">{a.account_id}</Typography.Text></> },
        { title: "操作", render: (_, a) => <Button onClick={() => select(a)} aria-label={`选择用户 ${a.email}`}>选择</Button> },
      ]} />{result.controls}
    </ReadState>
  </>;
}

// Shared only by the two platform workflows that select an existing account.
export function AccountPicker({ client, select }: { client: ManagementClient; select: (account: Account) => void }) {
  const [email, setEmail] = useState<string>();
  const [search] = Form.useForm();
  const id = useId().replace(/[^A-Za-z0-9_-]/g, "");
  const [revision, setRevision] = useState(0);
  return <>
    <Form form={search} name={`platform-account-search-${id}`} layout="inline" className="management-filter" onFinish={(v: { email?: string }) => { setEmail(v.email?.trim() ?? ""); setRevision(n => n + 1); }}>
      <Form.Item name="email" label="用户邮箱"><Input allowClear maxLength={320} /></Form.Item><Button htmlType="submit">搜索已有用户</Button><Button onClick={() => { search.resetFields(); setEmail(""); setRevision(v => v + 1); }}>重置</Button>
    </Form>
    {email !== undefined && <AccountResults key={`${email}-${revision}`} client={client} email={email} select={select} />}
  </>;
}

type TenantValues = { tenant_id: string; name: string; status: ManagedTenant["status"]; allow_registration: boolean; email?: string; password?: string };
function TenantEditor({ client, tenantId, close, changed, select }: {
  client: ManagementClient; tenantId?: string; close: () => void; changed: () => void; select: (tenant: ManagedTenant) => void;
}) {
  const [record, setRecord] = useState<TenantDetail>();
  const [administrator, setAdministrator] = useState<Account>();
  const [administratorKind, setAdministratorKind] = useState<"new" | "existing">("new");
  const [loading, setLoading] = useState(!!tenantId);
  const write = useWriteFeedback(client);
  const { busy, blocked } = write;
  const [readError, setReadError] = useState<unknown>();
  const [dirty, setDirty] = useState(false);
  const [originalId, setOriginalId] = useState<string>();
  const [readTarget, setReadTarget] = useState(tenantId);
  const [attempt, setAttempt] = useState(0);
  const [draft, setDraft] = useState<TenantValues>();
  const [form] = Form.useForm<TenantValues>();
  const reloadButton = useRef<HTMLButtonElement>(null);
  const mounted = useRef(true);
  const formId = useId().replace(/[^A-Za-z0-9_-]/g, "");
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    const target = readTarget;
    if (!target) return;
    let active = true;
    setLoading(true); setReadError(undefined); setDraft(undefined);
    client.getManagedTenant(target).then(value => {
      if (active) { setRecord(value); form.setFieldsValue(value); setDirty(false); write.recovered(); }
    }).catch(reason => { if (active) setReadError(reason); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, readTarget, attempt, form]);
  useEffect(() => () => { form.setFieldValue("password", undefined); }, [form]);
  const reload = () => { if (busy || loading) return; if (discardChanges(dirty || blocked)) { form.setFieldValue("password", undefined); setReadTarget(tenantId ?? originalId); setAttempt(v => v + 1); } };
  const closeEditor = () => { if (!busy && !draft && discardChanges(dirty || blocked)) { form.setFieldValue("password", undefined); close(); } };
  return <Drawer rootClassName="management-workflow-editor" open title={tenantId ? "租户设置" : "创建租户"} width={680} onClose={closeEditor} closable={!busy && !draft} maskClosable={false} keyboard={!busy && !draft}>
    <WriteFeedback state={write} />
    {(tenantId || originalId) && <Button ref={reloadButton} disabled={busy || loading} onClick={reload}>重新加载租户</Button>}
    <ReadState loading={loading} error={readError} saved={!!write.success} retry={reload}>
    {!tenantId && record && <>
      <Typography.Paragraph>{write.success ? "已确认创建租户" : "当前可读取到租户"}：{record.name}（{record.tenant_id}）<br />状态：{statusLabel[record.status]}；允许注册：{record.allow_registration ? "是" : "否"}。回读不能证明初始密码写入或请求归因。</Typography.Paragraph>
      <Typography.Paragraph>接下来可管理成员、目录和角色；选择目标不会切换登录身份。</Typography.Paragraph><Button onClick={() => select(record)}>角色与成员</Button>
    </>}
    {(!tenantId ? !record : !!record) && <>
      {!tenantId && <>
        <Typography.Paragraph>选择已有用户或新建账号作为首位管理员。账号、租户、成员关系和管理员授权会一起提交，失败全部回滚。</Typography.Paragraph>
        <Radio.Group aria-label="管理员来源" value={administratorKind} disabled={busy || blocked} onChange={event => {
          setAdministratorKind(event.target.value); setAdministrator(undefined); setDraft(undefined); setDirty(true); write.edit(); form.setFieldsValue({ email: undefined, password: undefined });
        }} options={[{ value: "new", label: "新建管理员账号" }, { value: "existing", label: "选择已有用户" }]} />
        {administratorKind === "existing" && (administrator ? <Typography.Paragraph>首位管理员：{administrator.email}（{administrator.account_id}） <Button disabled={busy || blocked} onClick={() => setAdministrator(undefined)}>重新选择</Button></Typography.Paragraph>
          : <AccountPicker client={client} select={account => { setAdministrator(account); setDirty(true); write.edit(); }} />)}
      </>}
      <Form name={`tenant-settings-${formId}`} form={form} onValuesChange={() => { setDirty(true); write.edit(); }} layout="vertical" initialValues={{ allow_registration: false }} disabled={busy || blocked} onFinish={({ password: _password, ...values }) => setDraft(values)}>
        <Form.Item name="tenant_id" label="租户 ID" rules={[{ required: true }, { pattern: /^(?!0$)[A-Za-z0-9_.-]{1,128}$/, message: "1–128 位字母、数字、点、下划线或连字符；0 为保留域" }]}>
          <Input disabled={!!tenantId || !!originalId || busy || blocked} maxLength={128} />
        </Form.Item>
        <Form.Item name="name" label="租户名称" rules={[{ required: true, whitespace: true }, { validator: (_, value: string) => !value || (new TextEncoder().encode(value).length <= 256 && !/[\x00-\x1f\x7f]/.test(value)) ? Promise.resolve() : Promise.reject(new Error("名称不能包含控制字符，UTF-8 长度不超过 256 字节")) }]}><Input maxLength={256} /></Form.Item>
        {tenantId && <Form.Item name="status" label="状态" rules={[{ required: true }]}><Select options={Object.entries(statusLabel).map(([value, label]) => ({ value, label }))} /></Form.Item>}
        {!tenantId && administratorKind === "new" && <>
          <Form.Item name="email" label="管理员邮箱" preserve={false} rules={[{ required: true, message: "请输入管理员邮箱" }, { type: "email", max: 254, message: "请输入有效邮箱" }]}><Input autoComplete="off" maxLength={254} /></Form.Item>
          <Form.Item name="password" label="初始密码" preserve={false} rules={[{ required: true, message: "请输入初始密码" }]} extra="至少包含字母和数字，长度按服务端密码规则校验。请通过安全渠道交付给管理员。"><Input.Password autoComplete="new-password" /></Form.Item>
          <Typography.Paragraph type="secondary">邮箱已存在时，请改为选择已有用户；不会覆盖已有账号密码。</Typography.Paragraph>
        </>}
        <Form.Item name="allow_registration" valuePropName="checked"><Checkbox>允许用户在此租户注册</Checkbox></Form.Item>
        <Button type="primary" htmlType="submit" disabled={busy || blocked || (!tenantId && !!record) || (!tenantId && administratorKind === "existing" && !administrator)}>核对并{tenantId ? "保存" : "创建"}</Button>
      </Form>
    </>}
    </ReadState>
    <SafeConfirm rootClassName="management-overlay" open={!!draft} title={tenantId ? "确认租户变更" : "确认创建租户"} okText="确认提交" cancelText="取消" confirmLoading={busy}
      okButtonProps={{ disabled: blocked }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false} onCancel={() => { form.setFieldValue("password", undefined); setDraft(undefined); }} onOk={async () => {
        if (!draft || (!record && administratorKind === "existing" && !administrator)) return;
        const id = draft.tenant_id;
        const before = client.getMutationSnapshot().revision;
        const result = await write.run(() => record ? client.updateTenant(record, draft.name, draft.status, draft.allow_registration)
          : client.createTenant(id, draft.name, draft.allow_registration, administratorKind === "existing" ? { kind: "existing", subject_id: administrator!.account_id }
            : { kind: "new", email: draft.email!, password: form.getFieldValue("password") }), `已确认保存租户 ${id}。`);
        if (!mounted.current) return;
        form.setFieldValue("password", undefined);
        if (result.ok || client.getMutationSnapshot().revision !== before) setOriginalId(id);
        if (result.ok) { setRecord(result.value); setDirty(false); setDraft(undefined); changed(); setReadTarget(id); setAttempt(v => v + 1); requestAnimationFrame(() => reloadButton.current?.focus()); }
        else { setDraft(undefined); requestAnimationFrame(() => reloadButton.current?.focus()); }
      }}>
      <WriteFeedback state={write} />
      {draft && (tenantId && record ? <Typography.Paragraph>
        租户 ID：{record.tenant_id}<br />
        当前版本：{record.version}（提交时校验）<br />
        租户名称：{record.name} → {draft.name}<br />
        状态：{statusLabel[record.status]} → {statusLabel[draft.status]}<br />
        允许注册：{record.allow_registration ? "是" : "否"} → {draft.allow_registration ? "是" : "否"}
      </Typography.Paragraph> : <Typography.Paragraph>租户：{draft.name}（{draft.tenant_id}）<br />状态：{statusLabel[draft.status ?? "active"]}<br />允许注册：{draft.allow_registration ? "是" : "否"}<br />{administratorKind === "new" ? `新建管理员：${draft.email}` : `已有管理员：${administrator?.email}（${administrator?.account_id}）`}</Typography.Paragraph>)}
      <Alert type="warning" showIcon message={tenantId ? "暂停或归档后，该租户中的登录和受保护操作将被拒绝。" : "首位管理员将获得此租户的管理权限。"} description="最终状态和权限由服务端在提交时校验。" />
    </SafeConfirm>
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
    <ReadState loading={result.loading} error={result.error} status={result.errorStatus} empty={!!result.page && result.page.items.length === 0} emptyText={Object.keys(filter).length ? "没有符合条件的租户" : "暂无租户"} retry={result.reload}>
    <Table<ManagedTenant> rowKey="tenant_id" dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 600 }}
      locale={{ emptyText: result.error ? "未能读取租户" : "没有符合条件的租户" }} columns={[
        { title: "租户", render: (_, t) => <>{t.name}<br /><Typography.Text type="secondary">{t.tenant_id}</Typography.Text></> },
        { title: "状态", dataIndex: "status", render: (status: ManagedTenant["status"]) => statusLabel[status] },
        { title: "操作", render: (_, t) => <Space wrap><Button onClick={() => select(t)} aria-label={`管理 ${t.name}`}>角色与成员</Button><Button aria-label={`设置租户 ${t.name}`} onClick={event => { trigger.current = event.currentTarget; setEditor({ tenantId: t.tenant_id }); }}>设置</Button></Space> },
      ]} />{result.controls}
    </ReadState>
    {editor && <TenantEditor client={client} tenantId={editor.tenantId} close={close} changed={result.reload} select={select} />}
  </>;
}

export function TenantManagement({ client, select }: { client: ManagementClient; select: (tenant: ManagedTenant) => void }) {
  const [filter, setFilter] = useState<{ tenant_id?: string; name?: string }>({});
  const [search] = Form.useForm();
  const [revision, setRevision] = useState(0);
  const formId = useId().replace(/[^A-Za-z0-9_-]/g, "");
  return <Card title="租户管理" className="management-card management-workflow-page">
    <Typography.Paragraph type="secondary">当前使用平台身份。选择管理目标仅决定数据范围，不会切换登录身份。</Typography.Paragraph>
    <Form form={search} name={`tenant-search-${formId}`} layout="inline" className="management-filter" onFinish={(v: { tenant_id?: string; name?: string }) => { setFilter({ ...(v.tenant_id?.trim() ? { tenant_id: v.tenant_id.trim() } : {}), ...(v.name?.trim() ? { name: v.name.trim() } : {}) }); setRevision(n => n + 1); }}>
      <Form.Item name="tenant_id" label="租户 ID"><Input allowClear maxLength={128} /></Form.Item><Form.Item name="name" label="名称"><Input allowClear maxLength={256} /></Form.Item><Button htmlType="submit">查询</Button><Button onClick={() => { search.resetFields(); setFilter({}); setRevision(v => v + 1); }}>重置</Button>
    </Form>
    <TenantTable key={`${JSON.stringify(filter)}-${revision}`} client={client} filter={filter} select={select} />
  </Card>;
}
