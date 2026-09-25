import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Drawer, Form, Input, Modal, Select, Table, Tag, Typography } from "antd";
import { ManagementClient, ManagementError, type ManagedSession, type Member, type SessionFilter } from "./client";
import { useCursorPage } from "./pagination";

const failure = (reason: unknown) => reason instanceof ManagementError ? reason.message : "操作失败，请重新加载后核对。";
const statusLabel = { pending: "待完成", active: "有效", revoked: "已撤销", expired: "已过期" };
const time = (value: number) => new Date(value * 1000).toLocaleString("zh-CN");
const unix = (value?: string) => {
  if (!value) return undefined;
  const seconds = Math.floor(new Date(value).getTime() / 1000);
  return Number.isSafeInteger(seconds) && seconds >= 0 ? seconds : undefined;
};

function SessionDrawer({ client, tenant, sessionId, close }: { client: ManagementClient; tenant: string; sessionId: string; close: () => void }) {
  const [session, setSession] = useState<ManagedSession>();
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [error, setError] = useState("");
  const [confirm, setConfirm] = useState(false);
  const reloadButton = useRef<HTMLButtonElement>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    let active = true;
    setLoading(true); setSession(undefined); setError("");
    client.getSession(tenant, sessionId).then(value => { if (active) { setSession(value); setBlocked(false); } })
      .catch(reason => { if (active) setError(failure(reason)); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, tenant, sessionId, attempt]);
  const self = session?.session_id === client.getSnapshot().session?.session_id && session?.tenant_id === client.getSnapshot().session?.tenant_id;
  const revoke = async () => {
    if (!session) return;
    setBusy(true); setError("");
    try {
      await client.revokeSession(tenant, session);
      if (mounted.current) { setConfirm(false); setAttempt(v => v + 1); requestAnimationFrame(() => reloadButton.current?.focus()); }
    } catch (reason) { if (mounted.current) { setError(failure(reason)); setBlocked(true); } }
    finally { if (mounted.current) setBusy(false); }
  };
  return <Drawer rootClassName="management-overlay" open title="会话详情" width={680} onClose={close} closable={!busy} keyboard={!busy} maskClosable={!busy}>
    {error && <Alert type="error" role="alert" message={error} description="操作结果可能未确认；请重新加载详情后再操作。" />}
    <Button ref={reloadButton} disabled={loading || busy} onClick={() => setAttempt(v => v + 1)}>重新加载会话</Button>
    {loading ? <Card loading /> : session && <>
      <Typography.Paragraph className="management-note">{client.getSnapshot().capabilities?.tenancy_enabled && <>租户：{session.tenant_id}<br /></>}会话：{session.session_id}<br />用户 ID：{session.account_id}<br />客户端：{session.client_id}<br />设备：{session.device_id ?? "无"}<br />状态：{statusLabel[session.status]}<br />认证：{time(session.authenticated_at_unix_secs)}<br />创建：{time(session.created_at_unix_secs)}<br />到期：{time(session.expires_at_unix_secs)}<br />范围：{session.scope || "无"}</Typography.Paragraph>
      <Button danger disabled={busy || blocked || !["pending", "active"].includes(session.status)} onClick={() => setConfirm(true)}>撤销会话</Button>
    </>}
    <Modal rootClassName="management-overlay" open={confirm} title="确认撤销会话" okText="确认撤销" cancelText="取消" confirmLoading={busy} okButtonProps={{ danger: true, disabled: blocked }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false} onCancel={() => setConfirm(false)} onOk={() => void revoke()}>
      {error && <Alert type="error" role="alert" message={error} description="请取消并重新加载当前会话。" />}
      <Typography.Paragraph>{client.getSnapshot().capabilities?.tenancy_enabled && <>租户：{tenant}<br /></>}会话：{session?.session_id}<br />用户 ID：{session?.account_id}<br />客户端：{session?.client_id}<br />设备：{session?.device_id ?? "无"}</Typography.Paragraph>
      <Alert type="warning" showIcon message="撤销会话会立即使其续期凭证和相关授权失效。" description="不修改账号、设备或其他会话；用户可按当前账号状态重新登录。" />
      {self && <Alert type="warning" showIcon message="正在撤销当前管理会话。" description="成功后本页凭证会被清除，后续管理请求需要重新登录。" />}
    </Modal>
  </Drawer>;
}

function SessionTable({ client, tenant, filter }: { client: ManagementClient; tenant: string; filter: SessionFilter }) {
  const load = useCallback((cursor?: string) => client.listSessions(tenant, filter, cursor), [client, tenant, filter]);
  const result = useCursorPage(load);
  const [selected, setSelected] = useState<string>();
  const trigger = useRef<HTMLElement | null>(null);
  return <>
    {result.error && <Alert type="error" role="alert" message={result.error} action={<Button onClick={result.reload}>重试</Button>} />}
    <Table<ManagedSession> rowKey="session_id" dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 900 }} locale={{ emptyText: result.error ? "未能读取会话" : "没有符合条件的会话" }} columns={[
      { title: "用户", dataIndex: "account_id" }, { title: "客户端 / 设备", render: (_, s) => <>{s.client_id}<br /><Typography.Text type="secondary">{s.device_id ?? "无设备"}</Typography.Text></> },
      { title: "状态", dataIndex: "status", render: (status: ManagedSession["status"]) => <Tag>{statusLabel[status]}</Tag> }, { title: "创建时间", dataIndex: "created_at_unix_secs", render: (value: number) => time(value) },
      { title: "操作", render: (_, s) => <Button onClick={event => { trigger.current = event.currentTarget; setSelected(s.session_id); }} aria-label={`查看会话 ${s.session_id}`}>详情</Button> },
    ]} />{result.controls}
    {selected && <SessionDrawer client={client} tenant={tenant} sessionId={selected} close={() => { setSelected(undefined); result.reload(); requestAnimationFrame(() => trigger.current?.focus()); }} />}
  </>;
}

export function SessionManagement({ client, tenant }: { client: ManagementClient; tenant: string }) {
  const [filter, setFilter] = useState<SessionFilter>({});
  const [error, setError] = useState("");
  const [subject, setSubject] = useState("");
  const [member, setMember] = useState<Member>();
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [listRevision, setListRevision] = useState(0);
  const reloadButton = useRef<HTMLButtonElement>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const domainLabel = client.getSnapshot().capabilities?.tenancy_enabled ? "当前租户" : "本系统";
  const self = member?.account_id === client.getSnapshot().session?.account_id && tenant === client.getSnapshot().session?.tenant_id;
  const preview = async () => {
    const accountId = subject.trim();
    if (!accountId) { setError("请输入要撤销全部会话的用户 ID。"); return; }
    setBusy(true); setError(""); setMember(undefined);
    try {
      const value = await client.getMember(tenant, accountId);
      if (mounted.current) { setMember(value); setBlocked(false); setConfirm(true); }
    } catch (reason) { if (mounted.current) setError(failure(reason)); }
    finally { if (mounted.current) setBusy(false); }
  };
  const revokeSubject = async () => {
    if (!member) return;
    setBusy(true); setError("");
    try {
      const count = await client.revokeSubjectSessions(tenant, member.account_id);
      if (mounted.current) { setConfirm(false); setError(`已撤销该用户在${domainLabel}中的 ${count} 个有效或待完成会话。`); setBlocked(false); setListRevision(v => v + 1); requestAnimationFrame(() => reloadButton.current?.focus()); }
    } catch (reason) { if (mounted.current) { setError(failure(reason)); setBlocked(true); } }
    finally { if (mounted.current) setBusy(false); }
  };
  return <Card title="会话管理" className="management-card">
    <Typography.Paragraph type="secondary">所有操作只作用于{domainLabel}。单个撤销不影响其他会话；按用户撤销会覆盖该用户在{domainLabel}的全部客户端和设备会话。</Typography.Paragraph>
    {error && <Alert type={error.startsWith("已撤销") ? "success" : "error"} role="alert" message={error} />}
    <Form name="session-filter" layout="inline" className="management-filter" onFinish={(values: { account_id?: string; client_id?: string; device_id?: string; status?: ManagedSession["status"]; created_after?: string; created_before?: string }) => {
      const after = unix(values.created_after), before = unix(values.created_before);
      if ((values.created_after && after === undefined) || (values.created_before && before === undefined) || (after !== undefined && before !== undefined && after > before)) { setError("创建时间范围无效：起始时间不能晚于结束时间。"); return; }
      setError(""); setFilter({ ...(values.account_id?.trim() ? { account_id: values.account_id.trim() } : {}), ...(values.client_id?.trim() ? { client_id: values.client_id.trim() } : {}), ...(values.device_id?.trim() ? { device_id: values.device_id.trim() } : {}), ...(values.status ? { status: values.status } : {}), ...(after !== undefined ? { created_after_unix_secs: after } : {}), ...(before !== undefined ? { created_before_unix_secs: before } : {}) });
    }}>
      <Form.Item name="account_id" label="用户 ID"><Input allowClear maxLength={128} /></Form.Item><Form.Item name="client_id" label="客户端 ID"><Input allowClear maxLength={128} /></Form.Item><Form.Item name="device_id" label="设备 ID"><Input allowClear maxLength={128} /></Form.Item>
      <Form.Item name="status" label="状态"><Select allowClear style={{ minWidth: 110 }} options={Object.entries(statusLabel).map(([value, label]) => ({ value, label }))} /></Form.Item><Form.Item name="created_after" label="创建起始"><Input type="datetime-local" /></Form.Item><Form.Item name="created_before" label="创建结束"><Input type="datetime-local" /></Form.Item><Button htmlType="submit">查询</Button>
    </Form>
    <Form name="subject-session-revoke" layout="inline" className="management-filter" onFinish={() => void preview()}><Form.Item label="按用户撤销" htmlFor="revoke-subject-id" required><Input id="revoke-subject-id" disabled={busy} value={subject} onChange={event => setSubject(event.target.value)} maxLength={128} placeholder="用户 ID" /></Form.Item><Button danger htmlType="submit" ref={reloadButton} disabled={busy}>{blocked ? "重新读取用户并核对" : "核对并撤销全部会话"}</Button></Form>
    <SessionTable key={`${tenant}:${listRevision}:${JSON.stringify(filter)}`} client={client} tenant={tenant} filter={filter} />
    <Modal rootClassName="management-overlay" open={confirm} title="确认撤销该用户的全部会话" okText="确认撤销全部会话" cancelText="取消" confirmLoading={busy} okButtonProps={{ danger: true, disabled: blocked }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false} onCancel={() => setConfirm(false)} onOk={() => void revokeSubject()}>
      {error && <Alert type="error" role="alert" message={error} description="请取消并重新读取成员后核对。" />}
      <Typography.Paragraph>{client.getSnapshot().capabilities?.tenancy_enabled && <>租户：{tenant}<br /></>}用户：{member?.email}（{member?.account_id}）</Typography.Paragraph>
      <Alert type="warning" showIcon message={`这会撤销该用户在${domainLabel}中的全部客户端和设备会话。`} description={client.getSnapshot().capabilities?.tenancy_enabled ? "只包括有效和待完成会话，不影响其他租户、其他用户、账号、设备或密钥。" : "只包括有效和待完成会话，不修改账号、设备或密钥，也不影响其他用户。"} />
      {self && <Alert type="warning" showIcon message={`正在撤销当前账号在${domainLabel}的全部会话。`} description="成功后当前管理凭证会被清除，需要重新登录。" />}
    </Modal>
  </Card>;
}
