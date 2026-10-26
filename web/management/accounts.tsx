import { useCallback, useEffect, useId, useRef, useState } from "react";
import { Alert, Button, Card, Drawer, Form, Input, Modal, Space, Table, Typography } from "antd";
import { ManagementClient, ManagementError, type Account, type Member } from "./client";
import { useCursorPage } from "./pagination";
import { discardChanges, ReadState, SafeConfirm, useWriteFeedback, WriteFeedback } from "./workflow";

const failure = (reason: unknown) => reason instanceof ManagementError ? reason.message : "操作失败，请重新加载后核对。";
const accountStatus: Record<Account["status"], string> = {
  pending_verification: "待验证", active: "启用", disabled: "停用", closed: "已关闭",
};
type AccountMutationStatus = "active" | "disabled";

function AccountIdentity({ account }: { account: Account }) {
  return <Typography.Paragraph>用户：{account.email}（{account.account_id}）</Typography.Paragraph>;
}

export function AccountSecurityDrawer({ client, subject, close }: {
  client: ManagementClient; subject: string; close: () => void;
}) {
  const [snapshot, setSnapshot] = useState<Account>();
  const [attempt, setAttempt] = useState(0), [loading, setLoading] = useState(true);
  const [readError, setReadError] = useState<unknown>();
  const [dirty, setDirty] = useState(false);
  const [status, setStatus] = useState<AccountMutationStatus>();
  const [passwordConfirm, setPasswordConfirm] = useState(false);
  const [originalKind, setOriginalKind] = useState<"password" | "status">();
  const write = useWriteFeedback(client);
  const reloadButton = useRef<HTMLButtonElement>(null), mounted = useRef(true);
  const [form] = Form.useForm<{ password: string }>();
  const formId = useId();
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; form.resetFields(); }; }, [form]);
  useEffect(() => {
    let active = true;
    setLoading(true); setSnapshot(undefined); setReadError(undefined); setStatus(undefined); setPasswordConfirm(false); form.resetFields(); setDirty(false);
    client.getAccountSecurity(subject).then(value => {
      if (active) {
        setSnapshot(value);
        // Account metadata cannot establish the outcome of an uncertain password change.
        if (!(originalKind === "password" && write.outcome === "unknown")) write.recovered();
      }
    }).catch(reason => { if (active) setReadError(reason); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, subject, attempt, form]);
  const self = client.getSnapshot().session?.account_id === subject;
  const sharedScope = client.getSnapshot().capabilities?.tenancy_enabled ? "平台与所有租户（共享账号）" : "本系统";
  const statusOptions: AccountMutationStatus[] = snapshot?.status === "pending_verification" ? ["active", "disabled"] : snapshot?.status === "active" ? ["disabled"] : snapshot?.status === "disabled" ? ["active"] : [];
  const reload = () => {
    if (write.busy || loading || !discardChanges(dirty || !!status || passwordConfirm || write.blocked)) return;
    form.resetFields(); setLoading(true); setAttempt(v => v + 1);
  };
  const closeEditor = () => {
    if (!write.busy && !status && !passwordConfirm && discardChanges(dirty || write.blocked)) { form.resetFields(); close(); }
  };
  const submitStatus = async () => {
    if (!snapshot || !status) return;
    const next = status; setOriginalKind("status");
    const result = await write.run(() => client.setAccountStatus(snapshot, next), `账号状态变更已确认：${snapshot.email}（${subject}），${accountStatus[snapshot.status]} → ${accountStatus[next]}；范围：${sharedScope}。启用不恢复旧凭证。`);
    form.resetFields();
    if (mounted.current) { setStatus(undefined); setDirty(false); if (result.ok) { setSnapshot(result.value); setAttempt(v => v + 1); } requestAnimationFrame(() => reloadButton.current?.focus()); }
  };
  const submitPassword = async () => {
    if (!snapshot || !form.getFieldValue("password")) return;
    setOriginalKind("password");
    const result = await write.run(() => client.setAccountPassword(snapshot, form.getFieldValue("password")), `密码更新已确认：${snapshot.email}（${subject}）；${sharedScope}的现有登录和待完成登录已失效，用户需重新登录。`);
    form.resetFields();
    if (mounted.current) { setPasswordConfirm(false); setDirty(false); if (result.ok) setAttempt(v => v + 1); requestAnimationFrame(() => reloadButton.current?.focus()); }
  };
  return <Drawer rootClassName="management-overlay management-workflow-editor" open title="账号安全" width={640}
    onClose={closeEditor} closable={!write.busy && !status && !passwordConfirm} keyboard={!write.busy && !status && !passwordConfirm} maskClosable={false}>
    <Typography.Paragraph>共享账号 ID：{subject}<br />处置范围：{sharedScope}。不同于只调整一个租户的成员关系或会话。</Typography.Paragraph>
    <WriteFeedback state={write} />
    {originalKind === "password" && write.outcome === "unknown" && <Alert type="warning" showIcon message="账号回读不能证明新密码结果"
      description="读取状态不会解除本次写锁或再次改密。请由有权管理员按既有会话与运维边界核查；如需离开，必须明确放弃当前核对。" />}
    <Button ref={reloadButton} disabled={write.busy || loading} onClick={reload}>重新加载账号</Button>
    <ReadState loading={loading} error={readError} saved={!!write.success} retry={reload}>
      {snapshot && <>
        <AccountIdentity account={snapshot} />
        <Typography.Paragraph>账号状态：{accountStatus[snapshot.status]}</Typography.Paragraph>
        {snapshot.status === "closed" && <Alert type="info" message="已关闭账号只读，不能恢复状态或重置密码。" />}
        <Space wrap>{statusOptions.map(next => <Button key={next} danger={next === "disabled"} disabled={write.busy || write.blocked} onClick={() => setStatus(next)}>{next === "active" ? "启用账号" : "停用账号"}</Button>)}</Space>
        {snapshot.status !== "closed" && <Form name={`account-password-${formId}`} form={form} layout="vertical" onValuesChange={() => { setDirty(true); write.edit(); }} onFinish={() => setPasswordConfirm(true)} disabled={write.busy || write.blocked}>
          <Form.Item name="password" label="设置新密码" rules={[{ required: true, message: "请输入新密码" }]} extra="管理员设置共享密码；不是用户自助找回。密码不会进入确认摘要，返回修改须重输。">
            <Input.Password autoComplete="new-password" maxLength={4096} />
          </Form.Item><Button type="primary" htmlType="submit">更新密码</Button>
        </Form>}
        {self && <Alert type="warning" showIcon message="这是当前登录账号" description="成功改密或变更自己的状态后，沿用现有客户端清理当前凭证并返回登录。" />}
      </>}
    </ReadState>
    <SafeConfirm open={!!status && !write.blocked} title="确认账号状态变更" okText="确认变更" cancelText="取消" confirmLoading={write.busy} okButtonProps={{ danger: status === "disabled" }} onCancel={() => setStatus(undefined)} onOk={() => void submitStatus()}>
      {snapshot && status && <><AccountIdentity account={snapshot} /><Typography.Paragraph>范围：{sharedScope}<br />原状态：{accountStatus[snapshot.status]} → {accountStatus[status]}（提交时核对原状态）</Typography.Paragraph></>}
      <Alert type="warning" showIcon message="状态影响共享账号，不是局部成员处置" description="停用阻止所有域登录并退役现有session、refresh、授权码和未完成租户选择。启用待验证账号表示管理员确认，不恢复旧凭证；最后有效管理员由服务端保护，冲突后先回读。" />
      {self && <Alert type="warning" message="正在处置自己，成功后当前管理会话将结束。" />}
      <WriteFeedback state={write} />
    </SafeConfirm>
    <SafeConfirm open={passwordConfirm && !write.blocked} title="确认更新密码" okText="确认更新" cancelText="返回修改" confirmLoading={write.busy}
      onCancel={() => { form.resetFields(["password"]); setDirty(false); setPasswordConfirm(false); }} onOk={() => void submitPassword()}>
      {snapshot && <><AccountIdentity account={snapshot} /><Typography.Paragraph>范围：{sharedScope}。密码不显示在摘要中；本操作没有密码版本CAS。</Typography.Paragraph></>}
      <Alert type="warning" showIcon message="所有域的现有登录和待完成登录将失效" description="退役session、refresh、授权码和未完成租户选择。回读账号状态不能证明新密码已设置；响应未确认时不可自动重放。" />
      {self && <Alert type="warning" message="正在修改自己的密码，成功后当前会话将结束，请重新登录。" />}
      <WriteFeedback state={write} />
    </SafeConfirm>
  </Drawer>;
}

function PlatformAccountTable({ client, email }: { client: ManagementClient; email: string }) {
  const load = useCallback((cursor?: string) => client.listPlatformAccounts(email, cursor, false), [client, email]);
  const result = useCursorPage(load);
  const [subject, setSubject] = useState<string>();
  const trigger = useRef<HTMLElement | null>(null);
  return <>
    <Button disabled={result.loading} onClick={result.reload}>刷新账号列表</Button>
    <ReadState loading={result.loading} error={result.error} status={result.errorStatus} empty={!result.page?.items.length} emptyText={email ? "没有符合邮箱条件的账号" : "暂无账号"} retry={result.reload}>
      <Table<Account> rowKey="account_id" dataSource={result.page?.items ?? []} pagination={false} scroll={{ x: 560 }} columns={[
        { title: "账号", render: (_, account) => <>{account.display_name || account.email}<br />{account.email}<br /><Typography.Text type="secondary">{account.account_id}</Typography.Text></> },
        { title: "状态", dataIndex: "status", render: (value: Account["status"]) => accountStatus[value] },
        { title: "操作", render: (_, account) => <Button onClick={event => { trigger.current = event.currentTarget; setSubject(account.account_id); }} aria-label={`管理账号安全 ${account.email}`}>账号安全</Button> },
      ]} />{result.controls}
    </ReadState>
    {subject && <AccountSecurityDrawer key={subject} client={client} subject={subject} close={() => { setSubject(undefined); result.reload(); requestAnimationFrame(() => trigger.current?.focus()); }} />}
  </>;
}

export function AccountSecurityAccounts({ client }: { client: ManagementClient }) {
  const [query, setQuery] = useState<{ email: string; revision: number }>();
  const [search] = Form.useForm(); const formId = useId();
  const sharedScope = client.getSnapshot().capabilities?.tenancy_enabled ? "平台与所有租户" : "本系统";
  return <Card title="账号安全" className="management-card management-workflow-page">
    <Typography.Paragraph type="secondary">同一用户在{sharedScope}共享账号状态和密码；实际处置权限由服务端检查。</Typography.Paragraph>
    <Form name={`account-security-search-${formId}`} form={search} layout="inline" className="management-filter" onFinish={(values: { email?: string }) => setQuery(old => ({ email: values.email?.trim() ?? "", revision: (old?.revision ?? 0) + 1 }))}>
      <Form.Item name="email" label="邮箱"><Input allowClear maxLength={320} /></Form.Item><Button htmlType="submit">查询</Button><Button onClick={() => { search.resetFields(); setQuery(old => ({ email: "", revision: (old?.revision ?? 0) + 1 })); }}>重置筛选</Button>
    </Form>
    {query === undefined ? <Typography.Paragraph>输入邮箱筛选，或直接查询全部账号。</Typography.Paragraph> : <PlatformAccountTable key={`${query.email}:${query.revision}`} client={client} email={query.email} />}
  </Card>;
}

export function CreateAccount({ client, tenant, close, created }: { client: ManagementClient; tenant: string; close: () => void; created?: (member: Member) => void }) {
  const [form] = Form.useForm<{ email: string; password: string; display_name?: string }>();
  const [draft, setDraft] = useState<{ email: string; display_name?: string }>();
  const [originalEmail, setOriginalEmail] = useState("");
  const [readback, setReadback] = useState("");
  const write = useWriteFeedback(client);
  const id = useId(), mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; form.resetFields(); }; }, [form]);
  const done = () => { if (!write.busy && discardChanges(form.isFieldsTouched() || write.outcome === "unknown")) { form.resetFields(); setDraft(undefined); close(); } };
  return <Modal rootClassName="management-overlay management-workflow-editor" open title="创建账号" okText="下一步" cancelText="取消" confirmLoading={write.busy}
    okButtonProps={{ disabled: write.blocked }} cancelButtonProps={{ disabled: write.busy }} closable={!write.busy} keyboard={!write.busy && !draft} maskClosable={false}
    onCancel={done} onOk={() => form.submit()}>
    <Typography.Paragraph>目标域：{tenant}。创建共享账号及本域有效成员关系，不自动分配业务角色或管理员权限。</Typography.Paragraph>
    <WriteFeedback state={write} />
    {write.blocked && <><Typography.Paragraph>请按原邮箱 {originalEmail} 核对本域成员。回读不能证明初始密码已写入，不可盲目再次创建。</Typography.Paragraph><Button onClick={async () => {
      try {
        const page = await client.listMembers(tenant, originalEmail);
        if (mounted.current) setReadback(page.items.filter(m => m.email.toLowerCase() === originalEmail.toLowerCase()).map(m => `${m.email}（${m.account_id} / ${m.membership.status}）`).join("、") || (page.has_more ? "当前页未找到，请返回成员列表继续分页核对。" : "当前未读取到匹配成员；这不能证明此前请求归因或密码结果。"));
      } catch (reason) { if (mounted.current) setReadback(failure(reason)); }
    }}>读取原邮箱成员</Button>{readback && <Typography.Paragraph role="status">{readback}</Typography.Paragraph>}</>}
    <Form name={`account-create-${id}`} form={form} layout="vertical" onValuesChange={write.edit} onFinish={values => setDraft({ email: values.email.trim(), display_name: values.display_name?.trim() || undefined })} disabled={write.busy || write.blocked}>
      <Form.Item name="email" label="邮箱" rules={[{ required: true, message: "请输入邮箱" }, { type: "email", message: "请输入有效邮箱" }]}><Input autoComplete="username" maxLength={320} /></Form.Item>
      <Form.Item name="display_name" label="显示名称"><Input maxLength={256} /></Form.Item>
      <Form.Item name="password" label="初始密码" rules={[{ required: true, message: "请输入初始密码" }]}><Input.Password autoComplete="new-password" maxLength={4096} /></Form.Item>
    </Form>
    <SafeConfirm open={!!draft} title="确认创建账号" okText="确认创建" cancelText="返回修改" confirmLoading={write.busy} okButtonProps={{ disabled: write.blocked }}
      onCancel={() => { form.resetFields(["password"]); setDraft(undefined); }} onOk={async () => {
        if (!draft || !form.getFieldValue("password")) return;
        setOriginalEmail(draft.email);
        const response = await write.run(() => client.createAccount(tenant, { ...draft, password: form.getFieldValue("password") }), `已确认创建 ${tenant} / ${draft.email}。`);
        form.resetFields(["password"]);
        if (mounted.current) setDraft(undefined);
        if (response.ok) { created?.(response.value); form.resetFields(); close(); }
      }}>
      {draft && <Typography.Paragraph>目标域：{tenant}<br />邮箱：{draft.email}<br />显示名称：{draft.display_name || "未填写"}</Typography.Paragraph>}
      <Alert type="info" showIcon message="创建账号并加入当前域" description="邮箱已存在须使用已有账号关联，不覆盖共享凭证。密码不显示，返回修改后须重输；不会自动分配角色。" />
    </SafeConfirm>
  </Modal>;
}
