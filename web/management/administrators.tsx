import { useCallback, useEffect, useRef, useState, useId } from "react";
import { Alert, Button, Card, Drawer, Form, Input, Space, Table, Typography } from "antd";
import { ManagementClient, type Account, type SecurityAdministrator } from "./client";
import { useCursorPage } from "./pagination";
import { discardChanges, ReadState, SafeConfirm, useWriteFeedback, WriteFeedback } from "./workflow";


export function AdministratorDrawer({ client, tenant, subject, close }: {
  client: ManagementClient; tenant: string; subject: string; close: () => void;
}) {
  const [snapshot, setSnapshot] = useState<SecurityAdministrator>();
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(true);
  const write = useWriteFeedback(client);
  const { busy, blocked } = write;
  const [readError, setReadError] = useState<unknown>();
  const [pending, setPending] = useState<boolean>();
  const reloadButton = useRef<HTMLButtonElement>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    let active = true;
    setLoading(true); setSnapshot(undefined); setPending(undefined); setReadError(undefined);
    client.getSecurityAdministrator(tenant, subject).then(value => { if (active) { setSnapshot(value); write.recovered(); } })
      .catch(reason => { if (active) setReadError(reason); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, tenant, subject, attempt]);
  const reload = () => { if (busy || loading) return; if (discardChanges(blocked)) setAttempt(v => v + 1); };
  const label = tenant === "0" ? "系统管理员" : "租户管理员";
  const eligible = snapshot?.tenant_status === "active" && snapshot.role.status === "active" && snapshot.account.status === "active" && snapshot.account.membership?.status === "active";
  const self = client.getSnapshot().session?.account_id === subject && client.getSnapshot().session?.tenant_id === tenant;
  return <Drawer rootClassName="management-overlay management-workflow-editor" open title={`${label}任命与撤销`} width={640} onClose={() => { if (!busy && pending === undefined && discardChanges(blocked)) close(); }} closable={!busy && pending === undefined} keyboard={!busy && pending === undefined} maskClosable={false}>
    <Typography.Paragraph>管理范围：{tenant === "0" ? "系统平台（0）" : `租户 ${tenant}`}</Typography.Paragraph>
    <WriteFeedback state={write} />
    <Button ref={reloadButton} disabled={busy || loading} onClick={reload}>重新加载管理员状态</Button>
    <ReadState loading={loading} error={readError} saved={!!write.success} retry={reload}>
    {snapshot && <>
      <Typography.Paragraph className="management-note">用户：{snapshot.account.email}（{subject}）<br />角色 ID：{snapshot.role.role_id}<br />绑定 ID：{snapshot.binding?.binding_id ?? "无"}<br />当前授权：{snapshot.binding ? `已任命${label}` : `未任命${label}`}</Typography.Paragraph>
      <Typography.Paragraph>{tenant === "0" ? (client.getSnapshot().capabilities!.tenancy_enabled ? "系统管理员可管理平台和各租户的身份与访问权限。" : "系统管理员可管理本系统的身份与访问权限。") : "租户管理员可管理本租户成员、角色、授权、设备、会话和审计。"}</Typography.Paragraph>
      {!eligible && !snapshot.binding && <Alert type="info" message="当前不能任命" description={snapshot.account.membership === null && tenant === "0"
        ? "此用户没有平台成员身份，暂不能任命。业务租户成员不会自动加入平台。"
        : "账号、目标域、成员关系及保护角色均须有效。请先处理相应状态。"} />}
      <Space className="management-filter">
        {snapshot.binding ? <Button danger disabled={busy || blocked} onClick={() => setPending(false)}>撤销{label}</Button>
          : <Button type="primary" disabled={busy || blocked || !eligible} onClick={() => setPending(true)}>任命为{label}</Button>}
      </Space>
    </>}
    </ReadState>
    <SafeConfirm rootClassName="management-overlay" open={pending !== undefined} title={`确认${pending ? "任命" : "撤销"}${label}`} okText={pending ? "确认任命" : "确认撤销"} cancelText="取消"
      confirmLoading={busy} okButtonProps={{ danger: !pending, disabled: blocked }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false}
      onCancel={() => setPending(undefined)} onOk={async () => {
        if (!snapshot || pending === undefined) return;
        const appointed = pending;
        const result = await write.run(() => client.setSecurityAdministrator(snapshot, appointed), `${appointed ? "已任命" : "已撤销"}${label}；范围 ${tenant}，账号 ${subject}，角色 ${snapshot.role.role_id}，原绑定 ${snapshot.binding?.binding_id ?? "无"}。后续管理请求按最新授权校验。`);
        if (mounted.current) { setPending(undefined); if (result.ok) setAttempt(v => v + 1); requestAnimationFrame(() => reloadButton.current?.focus()); }
      }}>
      <WriteFeedback state={write} />
      <Typography.Paragraph>范围：{tenant === "0" ? "系统平台（0）" : `租户 ${tenant}`}<br />用户：{snapshot?.account.email}（{subject}）<br />角色：{label}（{snapshot?.role.role_id}）<br />绑定 ID：{snapshot?.binding?.binding_id ?? "无"}</Typography.Paragraph>
      <Alert type="warning" showIcon message={pending ? `此操作授予${label}权限。` : "只撤销管理员授权，保留账号、成员关系和业务角色。"}
        description={pending ? "不创建账号或成员关系，实际任命资格由服务端在提交时复查。" : "最后一位有效管理员受服务端保护；管理权限实时复查，已有会话不会保留被撤销的权限。"} />
      {!pending && self && <Alert type="warning" message="正在撤销自己的管理员授权，成功后可能无法继续使用当前管理页面。" />}
    </SafeConfirm>
  </Drawer>;
}

function PlatformAccountTable({ client, email }: { client: ManagementClient; email: string }) {
  const load = useCallback((cursor?: string) => client.listPlatformAccounts(email, cursor, false), [client, email]);
  const result = useCursorPage(load);
  const [subject, setSubject] = useState<string>();
  const trigger = useRef<HTMLElement | null>(null);
  return <>
    {result.error && <Alert type="error" role="alert" message={result.error} action={<Button onClick={result.reload}>重试</Button>} />}
    <Table<Account> rowKey="account_id" dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 520 }} columns={[
      { title: "用户", render: (_, a) => <>{a.display_name || a.email}<br />{a.email}<br /><Typography.Text type="secondary">{a.account_id}</Typography.Text></> },
      { title: "操作", render: (_, a) => <Button aria-label={`管理系统管理员 ${a.email}`} onClick={event => { trigger.current = event.currentTarget; setSubject(a.account_id); }}>管理员授权</Button> },
    ]} />{result.controls}
    {subject && <AdministratorDrawer client={client} tenant="0" subject={subject} close={() => { setSubject(undefined); requestAnimationFrame(() => trigger.current?.focus()); }} />}
  </>;
}

export function PlatformAdministrators({ client }: { client: ManagementClient }) {
  const [email, setEmail] = useState<string>();
  const formId = useId().replace(/[^A-Za-z0-9_-]/g, "");
  return <Card title="系统管理员" className="management-card management-workflow-page">
    <Typography.Paragraph>搜索已有用户并查看平台管理员状态。只有已有有效平台成员身份的用户才能被任命。</Typography.Paragraph>
    <Form name={`system-admin-search-${formId}`} layout="inline" className="management-filter" onFinish={(v: { email?: string }) => setEmail(v.email?.trim() ?? "")}>
      <Form.Item name="email" label="邮箱"><Input allowClear maxLength={254} /></Form.Item><Button htmlType="submit">查询用户</Button>
    </Form>
    {email !== undefined && <PlatformAccountTable key={email} client={client} email={email} />}
  </Card>;
}
