import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Drawer, Form, Input, Modal, Space, Table, Typography } from "antd";
import { ManagementClient, ManagementError, type Account } from "./client";
import { useCursorPage } from "./pagination";

const failure = (reason: unknown) => reason instanceof ManagementError ? reason.message : "操作失败，请重新加载后核对。";
const accountStatus: Record<Account["status"], string> = {
  pending_verification: "待验证", active: "启用", disabled: "停用", closed: "已关闭",
};
type AccountMutationStatus = "active" | "disabled";

function AccountIdentity({ account, tenant }: { account: Account; tenant?: string }) {
  return <Typography.Paragraph>
    用户：{account.email}（{account.account_id}）{tenant ? <><br />租户：{tenant}</> : null}
  </Typography.Paragraph>;
}

export function AccountSecurityDrawer({ client, subject, close }: {
  client: ManagementClient; subject: string; close: () => void;
}) {
  const [snapshot, setSnapshot] = useState<Account>();
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [status, setStatus] = useState<AccountMutationStatus>();
  const [passwordConfirm, setPasswordConfirm] = useState(false);
  const reloadButton = useRef<HTMLButtonElement>(null);
  const mounted = useRef(true);
  const [form] = Form.useForm<{ password: string }>();

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; form.resetFields(); }; }, [form]);
  useEffect(() => {
    let active = true;
    setLoading(true); setSnapshot(undefined); setStatus(undefined); setPasswordConfirm(false); setError("");
    client.getAccountSecurity(subject).then(value => {
      if (active) { setSnapshot(value); setBlocked(false); }
    }).catch(reason => { if (active) setError(failure(reason)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, subject, attempt]);

  const self = client.getSnapshot().session?.account_id === subject;
  const canStatus = snapshot && snapshot.status !== "closed";
  const statusOptions: AccountMutationStatus[] = snapshot?.status === "pending_verification" ? ["active", "disabled"] : snapshot?.status === "active" ? ["disabled"] : snapshot?.status === "disabled" ? ["active"] : [];
  const sharedScope = client.getSnapshot().capabilities?.tenancy_enabled ? "所有租户（共享账号）" : "本系统";
  const submitStatus = async () => {
    if (!snapshot || !status) return;
    setBusy(true); setError(""); setSuccess("");
    try {
      const updated = await client.setAccountStatus(snapshot, status);
      if (mounted.current) {
        setSnapshot(updated); setStatus(undefined); setSuccess(`账号已${accountStatus[status]}。`); setAttempt(v => v + 1);
        requestAnimationFrame(() => reloadButton.current?.focus());
      }
    } catch (reason) {
      if (mounted.current) { setError(failure(reason)); setBlocked(true); }
    } finally { if (mounted.current) setBusy(false); }
  };
  const submitPassword = async ({ password }: { password: string }) => {
    if (!snapshot) return;
    setBusy(true); setError(""); setSuccess("");
    try {
      await client.setAccountPassword(snapshot, password);
      if (mounted.current) { setPasswordConfirm(false); setSuccess("密码已更新。已有会话和现有凭证已失效，请重新登录。"); form.resetFields(); setAttempt(v => v + 1); }
    } catch (reason) {
      if (mounted.current) { setError(failure(reason)); setBlocked(true); }
    } finally { form.resetFields(["password"]); if (mounted.current) setBusy(false); }
  };

  return <Drawer rootClassName="management-overlay" open title="账号安全" width={640}
    onClose={() => { form.resetFields(); close(); }} closable={!busy} keyboard={!busy} maskClosable={!busy}>
    {success && <Alert type="success" showIcon role="status" message={success} />}
    {error && <Alert type="error" showIcon role="alert" message={error} description="请重新加载账号后核对，不要重复提交。" />}
    <Button ref={reloadButton} disabled={busy || loading} onClick={() => { form.resetFields(); setSuccess(""); setAttempt(v => v + 1); }}>重新加载账号</Button>
    {loading ? <Card loading /> : snapshot && <>
      <AccountIdentity account={snapshot} />
      <Typography.Paragraph className="management-note">账号状态：{accountStatus[snapshot.status]}</Typography.Paragraph>
      {snapshot.status === "closed" && <Alert type="info" message="已关闭账号只读，不能恢复状态或重置密码。" />}
      {canStatus && <Space wrap>
        {statusOptions.map(nextStatus => <Button key={nextStatus} danger={nextStatus === "disabled"} disabled={busy || blocked} onClick={() => setStatus(nextStatus)}>{nextStatus === "active" ? "启用账号" : "停用账号"}</Button>)}
      </Space>}
      {snapshot.status !== "closed" && <Form name="account-password" form={form} layout="vertical" onFinish={() => setPasswordConfirm(true)} disabled={busy || blocked}>
        <Form.Item name="password" label="设置新密码" rules={[{ required: true, message: "请输入新密码" }]}>
          <Input.Password autoComplete="new-password" maxLength={4096} />
        </Form.Item>
        <Button type="primary" htmlType="submit">更新密码</Button>
      </Form>}
      {self && (status || snapshot.status !== "closed") && <Alert className="management-note" type="warning" showIcon message="这是当前登录账号" description="修改自己的状态或密码会使当前会话和现有凭证失效；客户端会清除当前凭证，请重新登录。" />}
    </>}
    <Modal rootClassName="management-overlay" open={!!status} title="确认账号状态变更" okText="确认变更" cancelText="取消"
      confirmLoading={busy} okButtonProps={{ danger: status === "disabled", disabled: blocked }} cancelButtonProps={{ disabled: busy }}
      closable={!busy} keyboard={!busy} maskClosable={false} onCancel={() => setStatus(undefined)} onOk={submitStatus}>
      {snapshot && status && <>
        <AccountIdentity account={snapshot} />
        <Typography.Paragraph>目标状态：{accountStatus[status]}</Typography.Paragraph>
        <Alert type="warning" showIcon message={`账号状态影响此用户的${sharedScope}。`} description="停用会阻止登录并使现有凭证失效；启用待验证账号表示已由管理员确认，不会恢复已经结束的旧会话。服务端会保护最后一位管理员。" />
        {self && <Alert type="warning" message="正在修改自己的账号状态，成功后当前会话可能结束。" />}
      </>}
      {error && <Alert type="error" role="alert" message={error} description="请取消并重新加载后核对，不要重复提交。" />}
    </Modal>
    <Modal rootClassName="management-overlay" open={passwordConfirm} title="确认更新密码" okText="确认更新" cancelText="取消" confirmLoading={busy}
      okButtonProps={{ disabled: blocked }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false}
      onCancel={() => { form.resetFields(["password"]); setPasswordConfirm(false); }} onOk={() => void submitPassword({ password: form.getFieldValue("password") })}>
      {snapshot && <>
        <AccountIdentity account={snapshot} />
        <Typography.Paragraph>范围：{sharedScope}</Typography.Paragraph>
        <Alert type="warning" showIcon message={`密码变更会影响此用户的${sharedScope}。`} description="密码不会显示在确认信息中；现有会话和凭证会失效。" />
        {self && <Alert type="warning" message="这是当前登录账号，更新后当前会话和现有凭证会失效；客户端会清除凭证，请重新登录。" />}
      </>}
      {error && <Alert type="error" role="alert" message={error} description="请取消并重新加载后核对，不要重复提交。" />}
    </Modal>
  </Drawer>;
}

function PlatformAccountTable({ client, email }: { client: ManagementClient; email: string }) {
  const load = useCallback((cursor?: string) => client.listPlatformAccounts(email, cursor, false), [client, email]);
  const result = useCursorPage(load);
  const [subject, setSubject] = useState<string>();
  const trigger = useRef<HTMLElement | null>(null);
  return <>
    {result.error && <Alert type="error" role="alert" message={result.error} action={<Button onClick={result.reload}>重试</Button>} />}
    <Button disabled={result.loading} onClick={result.reload}>刷新账号列表</Button>
    <Table<Account> rowKey="account_id" dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 560 }}
      locale={{ emptyText: result.error ? "未能读取账号" : "没有符合条件的账号" }} columns={[
        { title: "账号", render: (_, account) => <>{account.display_name || account.email}<br />{account.email}<br /><Typography.Text type="secondary">{account.account_id}</Typography.Text></> },
        { title: "状态", dataIndex: "status", render: (value: Account["status"]) => accountStatus[value] },
        { title: "操作", render: (_, account) => <Button onClick={event => { trigger.current = event.currentTarget; setSubject(account.account_id); }} aria-label={`管理账号安全 ${account.email}`}>账号安全</Button> },
      ]} />{result.controls}
    {subject && <AccountSecurityDrawer client={client} subject={subject} close={() => { setSubject(undefined); result.reload(); requestAnimationFrame(() => trigger.current?.focus()); }} />}
  </>;
}

export function AccountSecurityAccounts({ client }: { client: ManagementClient }) {
  const [email, setEmail] = useState<string>();
  const sharedScope = client.getSnapshot().capabilities?.tenancy_enabled ? "已加入租户间" : "本系统内";
  return <Card title="账号安全" className="management-card">
    <Typography.Paragraph type="secondary">同一用户在{sharedScope}共享账号状态和密码。</Typography.Paragraph>
    <Form name="account-security-search" layout="inline" className="management-filter" onFinish={(values: { email?: string }) => setEmail(values.email?.trim() || "")}>
      <Form.Item name="email" label="邮箱"><Input allowClear maxLength={320} /></Form.Item><Button htmlType="submit">查询</Button>
    </Form>
    {email === undefined ? <Typography.Paragraph type="secondary">输入邮箱筛选，或直接查询全部账号。</Typography.Paragraph> : <PlatformAccountTable key={email} client={client} email={email} />}
  </Card>;
}

export function CreateAccount({ client, tenant, close }: { client: ManagementClient; tenant: string; close: () => void }) {
  const [form] = Form.useForm<{ email: string; password: string; display_name?: string }>();
  const [draft, setDraft] = useState<{ email: string; display_name?: string }>();
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [error, setError] = useState("");
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; form.resetFields(); }; }, [form]);
  const done = () => { form.resetFields(); setDraft(undefined); close(); };
  const tenantEnabled = client.getSnapshot().capabilities?.tenancy_enabled;
  const submit = (values: { email: string; password: string; display_name?: string }) => { setError(""); setDraft({ email: values.email.trim(), display_name: values.display_name?.trim() || undefined }); };
  const confirm = async () => {
    const values = form.getFieldsValue();
    if (!draft || !values.password) return;
    setBusy(true); setError("");
    try {
      await client.createAccount(tenant, { email: draft.email, password: values.password, ...(draft.display_name ? { display_name: draft.display_name } : {}) });
      if (mounted.current) done();
    }
    catch (reason) { if (mounted.current) { setError(failure(reason)); setBlocked(true); form.resetFields(["password"]); } }
    finally { form.resetFields(["password"]); if (mounted.current) setBusy(false); }
  };
  return <Modal rootClassName="management-overlay" open title="创建账号" okText="下一步" cancelText="取消" confirmLoading={busy}
    okButtonProps={{ disabled: blocked }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false}
    onCancel={done} onOk={() => form.submit()}>
    {error && <Alert type="error" role="alert" showIcon message={error} description="请关闭并核对账号列表后再决定下一步。" />}
    <Form name="account-create" form={form} layout="vertical" onFinish={submit} disabled={busy || blocked}>
      <Form.Item name="email" label="邮箱" rules={[{ required: true, message: "请输入邮箱" }, { type: "email", message: "请输入有效邮箱" }]}><Input autoComplete="username" maxLength={320} /></Form.Item>
      <Form.Item name="display_name" label="显示名称"><Input maxLength={256} /></Form.Item>
      <Form.Item name="password" label="初始密码" rules={[{ required: true, message: "请输入初始密码" }]}><Input.Password autoComplete="new-password" maxLength={4096} /></Form.Item>
    </Form>
    <Modal rootClassName="management-overlay" open={!!draft} title="确认创建账号" okText="确认创建" cancelText="返回修改" confirmLoading={busy}
      okButtonProps={{ disabled: blocked }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false}
      onCancel={() => { if (!busy) { form.resetFields(["password"]); setDraft(undefined); } }} onOk={confirm}>
      {draft && <><Typography.Paragraph>{tenantEnabled && <>租户：{tenant}<br /></>}邮箱：{draft.email}{draft.display_name ? <><br />显示名称：{draft.display_name}</> : null}</Typography.Paragraph>
        <Alert type="info" showIcon message={tenantEnabled ? "创建账号并加入当前租户。" : "在本系统创建用户。"} description="不会自动分配业务角色；密码不会显示在确认信息中。" /></>}
      {error && <Alert type="error" role="alert" message={error} description="请关闭并核对账号列表，不要重复提交。" />}
    </Modal>
  </Modal>;
}
