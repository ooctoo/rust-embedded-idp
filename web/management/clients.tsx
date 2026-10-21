import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Descriptions, Drawer, Empty, Form, Input, Modal, Result, Select, Space, Spin, Switch, Table, Tag, Typography, type InputRef } from "antd";
import { ManagementClient, ManagementError, type ClientConfiguration, type ClientFilter, type ManagedClient, type SortOrder } from "./client";
import { useCursorPage } from "./pagination";

const kindLabel = { public_desktop: "公开桌面客户端", confidential_web: "机密 Web 客户端" };
const failure = (reason: unknown) => reason instanceof ManagementError ? reason.message : "操作未完成，请重新读取配置后核对。";
const redirects = (text: string) => text.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
const bytes = (text: string) => new TextEncoder().encode(text).length;
interface Fields { client_name: string; client_type: ManagedClient["client_type"]; pkce_required: boolean; redirect_text: string; client_secret?: string }

function ReadFailure({ status, message, retry, saved = false }: { status?: number; message: string; retry: () => void; saved?: boolean }) {
  return <Result status={status === 403 ? "403" : status === 404 ? "404" : "error"}
    title={saved ? "配置已保存，重新读取失败" : status === 403 ? "无权读取客户端配置" : status === 404 ? "客户端管理入口不可用" : "读取客户端配置失败"}
    subTitle={message} extra={<Button onClick={retry}>重新读取</Button>} />;
}

function ClientEditor({ client, id, close, changed }: { client: ManagementClient; id: string; close: () => void; changed: () => void }) {
  const [snapshot, setSnapshot] = useState<ManagedClient | null>();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [readError, setReadError] = useState<{ message: string; status?: number }>();
  const [error, setError] = useState("");
  const [outcome, setOutcome] = useState<"saved" | "unknown" | "rejected">();
  const [savedChanges, setSavedChanges] = useState("");
  const [draft, setDraft] = useState<Omit<ClientConfiguration, "client_secret">>();
  const [rotating, setRotating] = useState(false);
  const [form] = Form.useForm<Fields>();
  const kind = Form.useWatch("client_type", form) ?? "public_desktop";
  const mounted = useRef(true);
  const nameInput = useRef<InputRef>(null);
  const reloadButton = useRef<HTMLButtonElement>(null);
  const reviewButton = useRef<HTMLButtonElement>(null);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; form.resetFields(); }; }, [form]);
  useEffect(() => {
    let active = true;
    setLoading(true); setSnapshot(undefined); setReadError(undefined); setDraft(undefined); form.resetFields();
    void (async () => {
      try {
        if (id === "." || id === "..") throw new ManagementError("当前管理入口暂不支持读取这个客户端 ID。请通过宿主受信接口核对，勿按未登记处理。", 400);
        let value: ManagedClient | null;
        try { value = await client.getClient(id); }
        catch (reason) {
          if (!(reason instanceof ManagementError && reason.status === 404)) throw reason;
          if (!active) return;
          // A resource 404 is the existing registration branch. First verify the
          // client module is readable; a missing/broken mount must never create it.
          await client.listClients();
          value = null;
        }
        if (active) {
          setSnapshot(value); setBlocked(false); setDirty(false);
          form.setFieldsValue(value ? { ...value, redirect_text: value.redirect_uris.join("\n") }
            : { client_name: "", client_type: "public_desktop", pkce_required: true, redirect_text: "" });
        }
      } catch (reason) {
        if (active) setReadError({ message: failure(reason), status: reason instanceof ManagementError ? reason.status : undefined });
      } finally { if (active) setLoading(false); }
    })();
    return () => { active = false; };
  }, [client, id, attempt, form]);
  useEffect(() => {
    if (!loading) requestAnimationFrame(() => readError ? reloadButton.current?.focus() : nameInput.current?.focus());
  }, [loading, readError]);

  const reread = () => {
    if (busy || loading) return;
    if ((dirty || outcome === "unknown") && !window.confirm("重新读取会清除未保存内容和密钥输入。请核对原客户端的当前配置；回读不能确认具体密钥。继续？")) return;
    setError(""); setAttempt(value => value + 1);
  };
  const leave = () => {
    if (busy) return;
    if ((dirty || outcome === "unknown") && !window.confirm("关闭会放弃未保存内容。若操作结果未确认，请先核对原客户端和接入应用；确认关闭？")) return;
    form.resetFields(["client_secret"]); close();
  };
  const save = async () => {
    if (!draft || busy || blocked) return;
    const revision = client.getMutationSnapshot().revision;
    setBusy(true); setError(""); setOutcome(undefined);
    try {
      const secret = form.getFieldValue("client_secret");
      await client.upsertClient({ ...draft, ...(rotating ? { client_secret: secret } : {}) });
      if (mounted.current) {
        setSavedChanges(snapshot === null ? "登记客户端配置" : changedFields?.join("、") || "重新保存当前可见配置");
        setDraft(undefined); setOutcome("saved"); setDirty(false); setAttempt(value => value + 1); changed();
      }
    } catch (reason) {
      if (mounted.current) {
        setDraft(undefined); setError(failure(reason));
        const sent = client.getMutationSnapshot().revision !== revision;
        setBlocked(sent);
        setOutcome(!sent ? undefined : reason instanceof ManagementError && reason.status && reason.status < 500 ? "rejected" : "unknown");
      }
    } finally { form.resetFields(["client_secret"]); if (mounted.current) setBusy(false); }
  };
  const secretAction = draft?.client_type === "public_desktop" ? snapshot?.client_secret_configured ? "清除已有密钥" : "不使用密钥"
    : rotating ? snapshot?.client_secret_configured ? "替换密钥（不显示内容）" : "设置密钥（不显示内容）" : "保留当前密钥";
  const changedFields = draft && [
    snapshot?.client_name !== draft.client_name && "名称",
    snapshot?.client_type !== draft.client_type && "类型",
    snapshot?.pkce_required !== draft.pkce_required && "PKCE",
    JSON.stringify(snapshot?.redirect_uris) !== JSON.stringify(draft.redirect_uris) && "回调地址",
    (rotating || draft.client_type === "public_desktop" && snapshot?.client_secret_configured) && "密钥处理",
  ].filter(Boolean);

  return <Drawer rootClassName="management-overlay management-client-editor" open title="客户端配置" width={600}
    onClose={leave} closable={!busy} keyboard={!busy && !draft} maskClosable={false}>
    <div className="management-client-summary"><Typography.Text type="secondary">部署级客户端</Typography.Text>
      <Typography.Paragraph>客户端 ID：<Typography.Text code>{id}</Typography.Text></Typography.Paragraph></div>
    {outcome === "saved" && <Alert type="success" showIcon role="status" message={`客户端 ${id} 的配置已保存`}
      description={`已确认变化：${savedChanges}。影响整套部署中使用此客户端的应用；下方回读用于更新当前配置，已有会话不会自动撤销。`} />}
    {outcome === "unknown" && <Alert type="warning" showIcon role="alert" message="保存结果未确认，请勿重复提交"
      description="先重新读取原客户端并核对可见配置。密钥只能显示是否已配置，不能证明新密钥已写入；请同时核对接入应用。" />}
    {error && <Alert type="error" showIcon role="alert" message={error}
      description={outcome === "rejected" ? "服务端未接受本次保存，请重新读取当前配置后核对。" : outcome === "unknown" ? "保留原客户端 ID；重新读取前不能再次保存。" : "本地校验未通过，未发送保存请求。请调整字段后重新核对。"} />}
    <div className="management-client-actions"><Button ref={reloadButton} disabled={busy || loading} onClick={reread}>重新读取配置</Button>
      <Button disabled={busy} onClick={leave}>关闭配置</Button></div>
    {loading ? <div className="management-client-loading" role="status"><Spin /> 正在读取客户端配置…</div>
      : readError ? <ReadFailure {...readError} saved={outcome === "saved"} retry={reread} /> : snapshot !== undefined && <>
        <Alert type={snapshot === null ? "info" : "warning"} showIcon
          message={snapshot === null ? "此 ID 尚未登记，确认保存后登记配置" : "正在编辑已有配置；保存可能覆盖并发修改"}
          description="配置在整套部署中共享。回调按完整列表替换，不提供版本冲突检测；登记配置不代表宿主登录入口已启用。" />
        {snapshot && <Descriptions className="management-client-details" size="small" column={1} items={[
          { key: "type", label: "当前类型", children: kindLabel[snapshot.client_type] },
          { key: "pkce", label: "当前 PKCE", children: snapshot.pkce_required ? "必需" : "不强制" },
          { key: "secret", label: "当前密钥", children: snapshot.client_secret_configured ? "已配置（不回显）" : "不适用" },
        ]} />}
        <Form name="oidc-client-editor" form={form} layout="vertical" disabled={busy || blocked}
          onValuesChange={values => { setDirty(true); setOutcome(value => value === "saved" ? undefined : value); if (values.client_type) { form.resetFields(["client_secret"]); if (values.client_type === "public_desktop") form.setFieldValue("pkce_required", true); } }}
          onFinish={values => {
            const next = { client_id: id, client_name: values.client_name, client_type: values.client_type,
              pkce_required: values.pkce_required, redirect_uris: redirects(values.redirect_text) };
            const secret = values.client_type === "confidential_web" && values.client_secret ? values.client_secret : undefined;
            if (bytes(JSON.stringify({ ...next, ...(secret === undefined ? {} : { client_secret: secret }) })) > 16384) {
              setError("客户端配置过长，请减少回调地址或字段内容（请求上限 16 KiB）。"); setOutcome(undefined); return;
            }
            setError(""); setOutcome(undefined); setRotating(secret !== undefined); setDraft(next);
          }}>
          <Form.Item name="client_name" label="名称" rules={[{ required: true, whitespace: true, message: "请输入客户端名称" }, {
            validator: (_, value) => !value || bytes(value) <= 256 && !/[\u0000-\u001f\u007f-\u009f]/.test(value) ? Promise.resolve() : Promise.reject(new Error("名称最多 256 字节，不能包含控制字符")),
          }]}><Input ref={nameInput} maxLength={256} /></Form.Item>
          <Form.Item name="client_type" label="客户端类型" rules={[{ required: true }]}><Select options={Object.entries(kindLabel).map(([value, label]) => ({ value, label }))} /></Form.Item>
          <Form.Item name="pkce_required" label="要求 PKCE" valuePropName="checked" extra={kind === "public_desktop" ? "公开客户端必须启用 PKCE，且不能保存客户端密钥。" : "启用后，授权码换取令牌还需提供 PKCE 验证信息。"}>
            <Switch disabled={kind === "public_desktop" || busy || blocked} />
          </Form.Item>
          <Form.Item name="redirect_text" label="允许的回调地址（每行一个）" extra={kind === "public_desktop" ? "支持本机回环地址或应用专用协议；不能使用普通 HTTPS 回调。完整列表将替换原配置。" : "支持 HTTPS 或本机回环地址；完整列表将替换原配置。"}
            rules={[{ required: true, whitespace: true, message: "请至少填写一个回调地址" }, {
              validator: (_, value) => !value || redirects(value).length <= 32 && redirects(value).every(u => bytes(u) <= 2048 && !/[\u0000-\u001f\u007f-\u009f]/.test(u)) ? Promise.resolve() : Promise.reject(new Error("最多 32 个地址，每个不超过 2048 字节且不能包含控制字符")),
            }]}><Input.TextArea rows={5} spellCheck={false} /></Form.Item>
          {kind === "confidential_web" && <Form.Item name="client_secret" label="客户端密钥" preserve={false}
            extra={snapshot?.client_secret_configured ? "留空保留当前密钥；填写新值将替换旧密钥。" : "首次登记机密客户端或从公开客户端转换时必须填写。"}
            rules={[{ required: !snapshot?.client_secret_configured, message: "请输入客户端密钥" }, {
              validator: (_, value) => !value || value.trim() === value && bytes(value) <= 4096 ? Promise.resolve() : Promise.reject(new Error("密钥首尾不能包含空白，且最多 4096 字节")),
            }]}><Input.Password autoComplete="new-password" maxLength={4096} /></Form.Item>}
          <Button ref={reviewButton} type="primary" htmlType="submit" disabled={busy || blocked}>核对并保存</Button>
        </Form>
      </>}
    <Modal rootClassName="management-overlay management-client-confirm" style={{ top: 24 }} open={!!draft} title="确认保存客户端配置" okText="确认保存" cancelText="返回修改" confirmLoading={busy}
      afterOpenChange={open => { if (open) document.querySelector<HTMLButtonElement>(".management-client-confirm .ant-modal-footer .ant-btn-default")?.focus(); }}
      focusTriggerAfterClose={false} afterClose={() => outcome || blocked ? reloadButton.current?.focus() : reviewButton.current?.focus()}
      okButtonProps={{ disabled: blocked }} cancelButtonProps={{ disabled: busy, autoFocus: true }} closable={!busy} keyboard={!busy} maskClosable={false}
      onCancel={() => { form.resetFields(["client_secret"]); setDraft(undefined); }} onOk={() => void save()}>
      {draft && <div className="management-client-confirm-content" role="region" aria-label="待保存的完整配置" tabIndex={0}>
        <Typography.Paragraph>客户端：{draft.client_name}（{draft.client_id}）</Typography.Paragraph>
        <Typography.Paragraph>本次变化：{snapshot === null ? "登记客户端配置" : changedFields?.join("、") || "可见配置未变化"}</Typography.Paragraph>
        <Descriptions size="small" column={1} items={[
          { key: "name", label: "名称", children: snapshot && snapshot.client_name !== draft.client_name ? `${snapshot.client_name} → ${draft.client_name}` : draft.client_name },
          { key: "kind", label: "类型", children: snapshot && snapshot.client_type !== draft.client_type ? `${kindLabel[snapshot.client_type]} → ${kindLabel[draft.client_type]}` : kindLabel[draft.client_type] },
          { key: "pkce", label: "PKCE", children: `${snapshot ? `${snapshot.pkce_required ? "必需" : "不强制"} → ` : ""}${draft.pkce_required ? "必需" : "不强制"}` },
          { key: "secret", label: "密钥处理", children: secretAction },
        ]} />
        {snapshot && <><Typography.Paragraph>原回调地址：</Typography.Paragraph>
          <ul>{snapshot.redirect_uris.map((uri, index) => <li key={index}>{uri}</li>)}</ul></>}
        <Typography.Paragraph>保存后的完整回调地址：</Typography.Paragraph>
        <ul>{draft.redirect_uris.map((uri, index) => <li key={index}>{uri}</li>)}</ul>
        <Alert type="warning" showIcon message="影响整套部署中使用此客户端的应用"
          description="保存会按同一 ID 登记或覆盖配置，回调地址按完整列表替换；没有版本冲突检测，并发保存可能覆盖其他管理员的修改。不会自动撤销已有会话。" />
        {rotating && <Alert type="warning" message="请同步核对接入应用的密钥配置。密钥内容不显示在确认摘要中。" description="返回修改后密钥输入会清除；如仍需设置或替换，请重新输入。" />}
      </div>}
    </Modal>
  </Drawer>;
}

function ClientTable({ client, filter, order, select }: { client: ManagementClient; filter: ClientFilter; order: SortOrder; select: (id: string, trigger: HTMLElement) => void }) {
  const load = useCallback((cursor?: string) => client.listClients(filter, cursor, order), [client, filter, order]);
  const result = useCursorPage(load);
  const filtered = Object.keys(filter).length > 0;
  return <>
    <div className="management-client-list-actions"><Typography.Text type="secondary">{filtered ? "当前显示筛选结果" : "整套部署的客户端配置"}</Typography.Text>
      <Button disabled={result.loading} onClick={result.reload}>刷新客户端</Button></div>
    {result.loading ? <div className="management-client-loading" role="status"><Spin /> 正在读取客户端列表…</div>
      : result.error ? <ReadFailure status={result.errorStatus} message={result.error} retry={result.reload} />
      : !result.page?.items.length ? <Empty description={filtered ? "没有符合筛选条件的客户端，请调整或重置筛选。" : "尚无客户端配置，可按 ID 登记接入应用。"} />
      : <Table<ManagedClient> rowKey="client_id" dataSource={result.page.items} pagination={false} scroll={{ x: 760 }} columns={[
        { title: "客户端", render: (_, c) => <div className="management-client-name"><Typography.Text strong>{c.client_name}</Typography.Text><br /><Typography.Text code>{c.client_id}</Typography.Text></div> },
        { title: "类型", dataIndex: "client_type", render: (value: ManagedClient["client_type"]) => kindLabel[value] },
        { title: "PKCE", dataIndex: "pkce_required", render: (value: boolean) => <Tag>{value ? "必需" : "不强制"}</Tag> },
        { title: "密钥", dataIndex: "client_secret_configured", render: (value: boolean) => value ? "已配置" : "不适用" },
        { title: "操作", render: (_, c) => <Button aria-label={`配置客户端 ${c.client_id}`} onClick={event => select(c.client_id, event.currentTarget)}>配置</Button> },
      ]} />}
    {result.controls}
  </>;
}

export function ClientManagement({ client }: { client: ManagementClient }) {
  const [query, setQuery] = useState<{ filter: ClientFilter; order: SortOrder; revision: number }>({ filter: {}, order: "desc", revision: 0 });
  const [selected, setSelected] = useState<string>();
  const [lookup, setLookup] = useState(false);
  const [filterForm] = Form.useForm();
  const [lookupForm] = Form.useForm();
  const trigger = useRef<HTMLElement | null>(null);
  const lookupInput = useRef<InputRef>(null);
  const registerButton = useRef<HTMLButtonElement>(null);
  const choose = (id: string, source: HTMLElement) => { trigger.current = source; setSelected(id); };
  return <Card className="management-card management-client-page" title="客户端配置"
    extra={<Button ref={registerButton} type="primary" disabled={!!selected} onClick={() => { lookupForm.resetFields(); setLookup(true); }}>按 ID 登记 / 编辑</Button>}>
    <Typography.Paragraph type="secondary">配置接入身份服务的应用。客户端在整套部署中共享，{client.getSnapshot().capabilities?.tenancy_enabled ? "租户登录策略" : "登录入口"}由宿主配置。登记配置后，还需在宿主侧接入对应应用的登录入口。</Typography.Paragraph>
    <Form name="oidc-client-filter" form={filterForm} layout="inline" className="management-filter management-client-filter" disabled={!!selected}
      initialValues={{ order: "desc" }} onFinish={(values: { client_type?: ManagedClient["client_type"]; pkce?: "true" | "false"; order: SortOrder }) => setQuery({
        filter: { ...(values.client_type ? { client_type: values.client_type } : {}), ...(values.pkce ? { pkce_required: values.pkce === "true" } : {}) }, order: values.order, revision: query.revision + 1,
      })}>
      <Form.Item name="client_type" label="类型"><Select allowClear style={{ minWidth: 190 }} options={Object.entries(kindLabel).map(([value, label]) => ({ value, label }))} /></Form.Item>
      <Form.Item name="pkce" label="PKCE"><Select allowClear style={{ minWidth: 120 }} options={[{ value: "true", label: "必需" }, { value: "false", label: "不强制" }]} /></Form.Item>
      <Form.Item name="order" label="登记顺序"><Select style={{ minWidth: 130 }} options={[{ value: "desc", label: "新登记在前" }, { value: "asc", label: "早登记在前" }]} /></Form.Item>
      <Space wrap><Button type="primary" htmlType="submit">查询</Button><Button onClick={() => { filterForm.resetFields(); setQuery({ filter: {}, order: "desc", revision: query.revision + 1 }); }}>重置筛选</Button></Space>
    </Form>
    <ClientTable key={JSON.stringify(query)} client={client} filter={query.filter} order={query.order} select={choose} />
    <Modal rootClassName="management-overlay management-client-lookup" title="按 ID 登记 / 编辑" open={lookup} footer={null}
      onCancel={() => setLookup(false)} afterOpenChange={open => { if (open) lookupInput.current?.focus(); }} afterClose={() => { if (!selected) registerButton.current?.focus(); }}>
      <Typography.Paragraph>输入客户端的稳定 ID。先读取配置：已有 ID 进入编辑，未登记 ID 才进入登记流程。</Typography.Paragraph>
      <Form name="oidc-client-lookup" form={lookupForm} layout="vertical" onFinish={({ id }: { id: string }) => { setLookup(false); choose(id, registerButton.current!); }}>
        <Form.Item name="id" label="客户端 ID" rules={[{ required: true, message: "请输入客户端 ID" }, { pattern: /^[A-Za-z0-9_.-]{1,128}$/, message: "最多 128 位字母、数字、点、下划线或连字符" }]}><Input ref={lookupInput} maxLength={128} autoComplete="off" /></Form.Item>
        <Button type="primary" htmlType="submit">读取配置</Button>
      </Form>
    </Modal>
    {selected && <ClientEditor key={selected} client={client} id={selected} changed={() => setQuery(value => ({ ...value, revision: value.revision + 1 }))} close={() => {
      setSelected(undefined); requestAnimationFrame(() => (trigger.current?.isConnected ? trigger.current : registerButton.current)?.focus());
    }} />}
  </Card>;
}
