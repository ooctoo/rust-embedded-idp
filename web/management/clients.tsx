import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Drawer, Form, Input, Modal, Select, Switch, Table, Tag, Typography } from "antd";
import { ManagementClient, ManagementError, type ClientConfiguration, type ClientFilter, type ManagedClient } from "./client";
import { useCursorPage } from "./pagination";

const kindLabel = { public_desktop: "公开桌面客户端", confidential_web: "机密 Web 客户端" };
const failure = (reason: unknown) => reason instanceof ManagementError ? reason.message : "操作失败，请重新读取配置后核对。";
const redirects = (text: string) => text.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
const bytes = (text: string) => new TextEncoder().encode(text).length;
interface Fields { client_name: string; client_type: ManagedClient["client_type"]; pkce_required: boolean; redirect_text: string; client_secret?: string }

function ClientEditor({ client, id, close }: { client: ManagementClient; id: string; close: () => void }) {
  const [snapshot, setSnapshot] = useState<ManagedClient | null>();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const [draft, setDraft] = useState<Omit<ClientConfiguration, "client_secret">>();
  const [rotating, setRotating] = useState(false);
  const [form] = Form.useForm<Fields>();
  const kind = Form.useWatch("client_type", form) ?? "public_desktop";
  const mounted = useRef(true);
  const reloadButton = useRef<HTMLButtonElement>(null);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; form.resetFields(); }; }, [form]);
  useEffect(() => {
    let active = true;
    setLoading(true); setSnapshot(undefined); setError(""); setDraft(undefined); form.resetFields();
    client.getClient(id).then(value => {
      if (active) {
        setSnapshot(value); setBlocked(false);
        form.setFieldsValue({ ...value, redirect_text: value.redirect_uris.join("\n") });
      }
    }).catch(reason => {
      if (!active) return;
      if (reason instanceof ManagementError && reason.status === 404) {
        setSnapshot(null); setBlocked(false);
        form.setFieldsValue({ client_name: "", client_type: "public_desktop", pkce_required: true, redirect_text: "" });
      } else setError(failure(reason));
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, id, attempt, form]);

  const save = async () => {
    if (!draft) return;
    setBusy(true); setError(""); setSaved(false);
    try {
      const secret = form.getFieldValue("client_secret");
      await client.upsertClient({ ...draft, ...(rotating ? { client_secret: secret } : {}) });
      if (mounted.current) {
        setDraft(undefined); form.resetFields(["client_secret"]); setSaved(true); setAttempt(value => value + 1);
        requestAnimationFrame(() => reloadButton.current?.focus());
      }
    } catch (reason) { if (mounted.current) { setError(failure(reason)); setBlocked(true); } }
    finally { form.resetFields(["client_secret"]); if (mounted.current) setBusy(false); }
  };

  return <Drawer rootClassName="management-overlay" open title="客户端配置" width={680} onClose={close} closable={!busy} keyboard={!busy} maskClosable={!busy}>
    <Typography.Paragraph>客户端 ID：<Typography.Text code>{id}</Typography.Text></Typography.Paragraph>
    {saved && <Alert type="success" showIcon role="status" message="客户端配置已保存" />}
    {error && <Alert type="error" showIcon role="alert" message={error} description="请重新读取并核对配置，不要重复提交。未保存内容将被清除。" />}
    <Button ref={reloadButton} disabled={busy || loading} onClick={() => { setSaved(false); setAttempt(value => value + 1); }}>重新读取配置</Button>
    {loading ? <Card loading /> : snapshot !== undefined && <>
      <Typography.Paragraph className="management-note">{snapshot === null ? "此 ID 尚未登记，保存后创建客户端配置。" : `当前类型：${kindLabel[snapshot.client_type]}；密钥：${snapshot.client_secret_configured ? "已配置（不回显）" : "不适用"}。`}</Typography.Paragraph>
      <Form name="oidc-client-editor" form={form} layout="vertical" disabled={busy || blocked}
        onValuesChange={changed => { if (changed.client_type) { form.resetFields(["client_secret"]); if (changed.client_type === "public_desktop") form.setFieldValue("pkce_required", true); } }}
        onFinish={values => {
          setError(""); setSaved(false); setRotating(values.client_type === "confidential_web" && !!values.client_secret);
          setDraft({ client_id: id, client_name: values.client_name, client_type: values.client_type,
            pkce_required: values.pkce_required, redirect_uris: redirects(values.redirect_text) });
        }}>
        <Form.Item name="client_name" label="名称" rules={[{ required: true, whitespace: true, message: "请输入客户端名称" }, {
          validator: (_, value) => !value || bytes(value) <= 256 && !/[\u0000-\u001f\u007f-\u009f]/.test(value) ? Promise.resolve() : Promise.reject(new Error("名称最多 256 字节，不能包含控制字符")),
        }]}><Input maxLength={256} /></Form.Item>
        <Form.Item name="client_type" label="客户端类型" rules={[{ required: true }]}><Select options={Object.entries(kindLabel).map(([value, label]) => ({ value, label }))} /></Form.Item>
        <Form.Item name="pkce_required" label="要求 PKCE" valuePropName="checked" extra={kind === "public_desktop" ? "公开客户端必须启用 PKCE，且不能保存客户端密钥。" : "启用后，授权码换取令牌还需提供 PKCE 验证信息。"}>
          <Switch disabled={kind === "public_desktop" || busy || blocked} />
        </Form.Item>
        <Form.Item name="redirect_text" label="允许的回调地址（每行一个）" extra={kind === "public_desktop" ? "支持本机回环地址或应用专用协议；不能使用普通 HTTPS 回调。" : "支持 HTTPS 或本机回环地址。"}
          rules={[{ required: true, whitespace: true, message: "请至少填写一个回调地址" }, {
            validator: (_, value) => !value || redirects(value).length <= 32 && redirects(value).every(u => bytes(u) <= 2048 && !/[\u0000-\u001f\u007f-\u009f]/.test(u)) ? Promise.resolve() : Promise.reject(new Error("最多 32 个地址，每个不超过 2048 字节且不能包含控制字符")),
          }]}><Input.TextArea rows={5} spellCheck={false} /></Form.Item>
        {kind === "confidential_web" && <Form.Item name="client_secret" label="客户端密钥" preserve={false}
          extra={snapshot?.client_secret_configured ? "留空保留当前密钥；填写新值将替换旧密钥。" : "首次登记机密客户端或从公开客户端转换时必须填写。"}
          rules={[{ required: !snapshot?.client_secret_configured, message: "请输入客户端密钥" }, {
            validator: (_, value) => !value || value.trim() === value && bytes(value) <= 4096 ? Promise.resolve() : Promise.reject(new Error("密钥首尾不能包含空白，且最多 4096 字节")),
          }]}><Input.Password autoComplete="new-password" maxLength={4096} /></Form.Item>}
        <Button type="primary" htmlType="submit" disabled={busy || blocked}>核对并保存</Button>
      </Form>
    </>}
    <Modal rootClassName="management-overlay" open={!!draft} title="确认保存客户端配置" okText="确认保存" cancelText="返回修改" confirmLoading={busy}
      focusTriggerAfterClose={false} afterClose={() => reloadButton.current?.focus()}
      okButtonProps={{ disabled: blocked }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false}
      onCancel={() => { form.resetFields(["client_secret"]); setDraft(undefined); }} onOk={() => void save()}>
      {draft && <>
        <Typography.Paragraph>客户端：{draft.client_name}（{draft.client_id}）<br />类型：{kindLabel[draft.client_type]}<br />PKCE：{draft.pkce_required ? "必需" : "不强制"}<br />密钥：{draft.client_type === "public_desktop" ? "不使用；已有密钥将清除" : rotating ? "设置新密钥（不显示内容）" : "保留当前密钥"}</Typography.Paragraph>
        <Typography.Paragraph>保存后的完整回调地址：</Typography.Paragraph>
        <ul>{draft.redirect_uris.map((uri, index) => <li key={index}>{uri}</li>)}</ul>
        <Alert type="warning" showIcon message={client.getSnapshot().capabilities?.tenancy_enabled ? "此配置作用于整套部署，影响使用该客户端的所有租户。" : "此配置影响本系统中使用该客户端的应用。"} description="保存会按同一 ID 登记或覆盖配置，回调地址按完整列表替换；并发保存可能覆盖其他管理员的修改。不会自动撤销已有会话。" />
        {rotating && <Alert type="warning" message="旧密钥会被替换，请同步更新接入应用的配置。" />}
      </>}
      {error && <Alert type="error" role="alert" message={error} description="请返回并重新读取配置，核对后再操作。" />}
    </Modal>
  </Drawer>;
}

function ClientTable({ client, filter }: { client: ManagementClient; filter: ClientFilter }) {
  const load = useCallback((cursor?: string) => client.listClients(filter, cursor), [client, filter]);
  const result = useCursorPage(load);
  const [selected, setSelected] = useState<string>();
  const trigger = useRef<HTMLElement | null>(null);
  const refreshButton = useRef<HTMLButtonElement>(null);
  return <>
    <Button ref={refreshButton} disabled={result.loading} onClick={result.reload}>刷新客户端</Button>
    <Form name="oidc-client-lookup" layout="inline" className="management-filter" onFinish={({ id }: { id: string }) => setSelected(id)}>
      <Form.Item name="id" label="客户端 ID" rules={[{ required: true, message: "请输入客户端 ID" }, { pattern: /^[A-Za-z0-9_.-]{1,128}$/, message: "最多 128 位字母、数字、点、下划线或连字符" }]}><Input maxLength={128} /></Form.Item>
      <Button htmlType="submit" onClick={event => { trigger.current = event.currentTarget; }}>按 ID 登记 / 编辑</Button>
    </Form>
    {result.error && <Alert type="error" role="alert" message={result.error} />}
    <Table<ManagedClient> rowKey="client_id" dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 720 }}
      locale={{ emptyText: result.error ? "未能读取客户端" : "没有符合条件的客户端" }} columns={[
        { title: "客户端", render: (_, c) => <>{c.client_name}<br /><Typography.Text type="secondary">{c.client_id}</Typography.Text></> },
        { title: "类型", dataIndex: "client_type", render: (value: ManagedClient["client_type"]) => kindLabel[value] },
        { title: "PKCE", dataIndex: "pkce_required", render: (value: boolean) => <Tag>{value ? "必需" : "不强制"}</Tag> },
        { title: "密钥", dataIndex: "client_secret_configured", render: (value: boolean) => value ? "已配置" : "不适用" },
        { title: "操作", render: (_, c) => <Button aria-label={`配置客户端 ${c.client_id}`} onClick={event => { trigger.current = event.currentTarget; setSelected(c.client_id); }}>配置</Button> },
      ]} />{result.controls}
    {selected && <ClientEditor key={selected} client={client} id={selected} close={() => {
      setSelected(undefined); result.reload(); requestAnimationFrame(() => (trigger.current?.isConnected ? trigger.current : refreshButton.current)?.focus());
    }} />}
  </>;
}

export function ClientManagement({ client }: { client: ManagementClient }) {
  const [filter, setFilter] = useState<ClientFilter>({});
  return <Card title="客户端管理" className="management-card">
    <Typography.Paragraph type="secondary">配置接入身份服务的应用。{client.getSnapshot().capabilities?.tenancy_enabled ? "客户端在整套部署中共享，仅平台管理员可维护；租户登录策略由宿主配置。" : "仅系统管理员可维护客户端配置。"}登记配置后，还需在宿主侧接入对应应用的登录入口。</Typography.Paragraph>
    <Form name="oidc-client-filter" layout="inline" className="management-filter" onFinish={(values: { client_type?: ManagedClient["client_type"]; pkce?: "true" | "false" }) => setFilter({
      ...(values.client_type ? { client_type: values.client_type } : {}), ...(values.pkce ? { pkce_required: values.pkce === "true" } : {}),
    })}>
      <Form.Item name="client_type" label="类型"><Select allowClear style={{ minWidth: 190 }} options={Object.entries(kindLabel).map(([value, label]) => ({ value, label }))} /></Form.Item>
      <Form.Item name="pkce" label="PKCE"><Select allowClear style={{ minWidth: 120 }} options={[{ value: "true", label: "必需" }, { value: "false", label: "不强制" }]} /></Form.Item>
      <Button htmlType="submit">查询</Button>
    </Form>
    <ClientTable key={JSON.stringify(filter)} client={client} filter={filter} />
  </Card>;
}
