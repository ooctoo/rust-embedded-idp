import { useCallback, useEffect, useId, useRef, useState } from "react";
import { Alert, Button, Card, Drawer, Form, Input, Select, Space, Table, Typography } from "antd";
import { ManagementClient, ManagementError, type Account, type Member, type Membership, type ResourceScope, type Role, type RoleBinding, type RoleDetail } from "./client";
import { useCursorPage } from "./pagination";
import { AccountPicker } from "./tenants";
import { AdministratorDrawer } from "./administrators";
import { AccountSecurityDrawer, CreateAccount } from "./accounts";
import { discardChanges, failureMessage, ReadState, SafeConfirm, useWriteFeedback, WriteFeedback } from "./workflow";

const scopeLabel = (scope: ResourceScope) => scope.kind === "type" ? "该类型的全部资源（含以后新增）" : `仅资源 ${scope.resource_id}`;
const accountStatus = { active: "启用", pending_verification: "待验证", disabled: "停用", closed: "已关闭" };
const memberStatus = { active: "有效", suspended: "暂停", removed: "已移除" };
const businessRule = /^(?!idp\.)[a-z][a-z0-9_.-]{0,63}$/;

function RoleChoice({ client, tenant, business, choose, disabled }: { client: ManagementClient; tenant: string; business?: string; choose: (role: Role) => void; disabled: boolean }) {
  const load = useCallback((cursor?: string) => client.listRoles(tenant, business, cursor), [client, tenant, business]);
  const result = useCursorPage(load);
  return <>
    <ReadState loading={result.loading} error={result.error} status={result.errorStatus} retry={result.reload} empty={!result.page?.items.length} emptyText="当前页无匹配角色，请调整业务筛选。">
      <Table<Role> scroll={{ x: 520 }} rowKey="role_id" dataSource={result.page?.items} pagination={false} columns={[
        { title: "业务标识", dataIndex: "business_id" },
        { title: "角色", render: (_, role) => <>{role.name}<br /><Typography.Text code>{role.key}</Typography.Text><br />{role.role_id}</> },
        { title: "状态", render: (_, role) => role.status === "active" ? "启用" : "停用" },
        { title: "操作", render: (_, role) => <Button disabled={disabled || !["business", "business_admin"].includes(role.kind) || role.status !== "active"} onClick={() => choose(role)} aria-label={`选择角色 ${role.name}`}>选择</Button> },
      ]} />
    </ReadState>{result.controls}
  </>;
}

type GrantDraft = { role: RoleDetail; resource?: string; scope: ResourceScope | { kind: "business" } };
function GrantForm({ client, tenant, business, subject, write, grant }: {
  client: ManagementClient; tenant: string; business?: string; subject: Member; write: ReturnType<typeof useWriteFeedback>;
  grant: (draft: GrantDraft) => Promise<void>;
}) {
  const [selected, setSelected] = useState<Role>();
  const [role, setRole] = useState<RoleDetail>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>();
  const [draft, setDraft] = useState<GrantDraft>();
  const [form] = Form.useForm();
  const formId = useId();
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    setRole(undefined); setDraft(undefined); form.resetFields(); setError(undefined);
    if (!selected) return;
    let active = true; setLoading(true);
    client.getRole(tenant, selected.business_id, selected.role_id).then(value => { if (active) setRole(value); })
      .catch(reason => { if (active) setError(reason); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, tenant, business, selected, form]);
  const eligible = subject.status === "active" && subject.membership.status === "active";
  const disabled = write.busy || write.blocked || !eligible;
  return <>
    {!eligible && <Alert type="warning" message="账号和本域成员关系均须有效，才可新增角色分配。请重新读取成员核对。" />}
    {!selected ? <RoleChoice client={client} tenant={tenant} business={business} choose={setSelected} disabled={disabled} /> : <>
      <Button disabled={write.busy} onClick={() => {
        if (!discardChanges(form.isFieldsTouched() || !!draft)) return;
        setSelected(undefined); setRole(undefined); setDraft(undefined); form.resetFields();
      }}>重新选择角色</Button>
      <ReadState loading={loading} error={error} retry={() => setSelected(value => value && { ...value })}>
        {role && <>
          <Typography.Paragraph>业务：{role.business_id} · 角色：{role.name}（{role.key} / {role.role_id}）</Typography.Paragraph>
          {(!["business", "business_admin"].includes(role.kind) || role.status !== "active") && <Alert type="warning" message="角色状态已变化，请重新选择可用业务角色。保护角色使用专用管理员入口。" />}
          {role.kind === "business_admin" && <>
            <Alert type="warning" message="此业务当前与以后新增的全部有效权限" description="业务管理员不获得 IDP 管理权限，也不需要资源类型或资源 ID。" />
            <Button type="primary" disabled={disabled || role.status !== "active"} onClick={() => setDraft({ role, scope: { kind: "business" } })}>预览业务管理员授权</Button>
          </>}
          {role.kind === "business" && !role.permissions.length && <Alert type="info" message="此角色尚无可分配资源类型，请先配置角色权限。" />}
          {role.kind === "business" && <Form name={`member-grant-${formId}`} form={form} layout="vertical" disabled={disabled || role.status !== "active" || !role.permissions.length}
            onValuesChange={values => {
              setDraft(undefined);
              if (values.resource) form.setFieldsValue({ kind: undefined, resource_id: undefined });
              if (values.kind) form.setFieldValue("resource_id", undefined);
            }} onFinish={(values: { resource: string; kind: "type" | "instance"; resource_id?: string }) => setDraft({ role, resource: values.resource,
              scope: values.kind === "instance" ? { kind: "instance", resource_id: values.resource_id! } : { kind: "type" } })}>
            <Form.Item name="resource" label="资源类型" rules={[{ required: true, message: "请选择资源类型" }]}><Select options={[...new Set(role.permissions.map(p => p.resource_type))].map(value => ({ value, label: value }))} /></Form.Item>
            <Form.Item name="kind" label="授权范围" rules={[{ required: true, message: "必须明确选择授权范围" }]}><Select options={[{ value: "instance", label: "仅一个具体资源" }, { value: "type", label: "该类型的全部资源" }]} /></Form.Item>
            <Form.Item noStyle shouldUpdate={(before, after) => before.kind !== after.kind}>{({ getFieldValue }) => getFieldValue("kind") === "instance" ?
              <Form.Item name="resource_id" label="资源 ID" preserve={false} rules={[{ required: true, message: "请输入具体资源 ID" }, { pattern: /^[A-Za-z0-9_.-]{1,256}$/, message: "1–256 位字母、数字、点、下划线或连字符" }]}><Input maxLength={256} /></Form.Item> : null}</Form.Item>
            <Button htmlType="submit" type="primary">预览授权</Button>
          </Form>}
        </>}
      </ReadState>
    </>}
    <SafeConfirm open={!!draft} title={draft?.scope.kind === "business" ? "确认业务管理员授权" : "确认成员角色分配"}
      okText={draft?.scope.kind === "business" ? "确认授予业务权限" : "确认分配"} cancelText="返回修改" confirmLoading={write.busy} okButtonProps={{ disabled: write.blocked }}
      onCancel={() => setDraft(undefined)} onOk={async () => { if (!draft) return; await grant(draft); if (alive.current) setDraft(undefined); }}>
      {draft && <>
        <Typography.Paragraph>目标租户：{tenant}<br />业务：{draft.role.business_id}<br />成员：{subject.email}（{subject.account_id}）<br />角色：{draft.role.name}（{draft.role.key} / {draft.role.role_id}）<br />范围：{draft.scope.kind === "business" ? "整个业务的全部有效权限（含未来新增）" : scopeLabel(draft.scope)}</Typography.Paragraph>
        {draft.scope.kind !== "business" && <Typography.Paragraph>资源类型：{draft.resource}<br />当前动作：{draft.role.permissions.filter(p => p.resource_type === draft.resource).map(p => p.action).join("、")}</Typography.Paragraph>}
        <Alert type="warning" message={draft.scope.kind === "business" ? "不获得 IDP 管理权限" : "动作随角色权限变化，type 范围包含以后新增资源"}
          description="此接口没有角色版本 CAS。服务端按提交时的成员、角色和有效权限检查；具体资源存在及租户归属由业务宿主负责。" />
      </>}
    </SafeConfirm>
  </>;
}

function BindingDrawer({ client, tenant, subject, close }: { client: ManagementClient; tenant: string; subject: Member; close: () => void }) {
  const [business, setBusiness] = useState<string>();
  const [member, setMember] = useState<Member>();
  const [attempt, setAttempt] = useState(0);
  const [readError, setReadError] = useState<unknown>();
  const [reading, setReading] = useState(false);
  const [adding, setAdding] = useState(false);
  const [revoke, setRevoke] = useState<{ binding: RoleBinding; role: RoleDetail }>();
  const [bindingId, setBindingId] = useState("");
  const [original, setOriginal] = useState<{ business: string; role: string; binding?: string; resource?: string; scope?: GrantDraft["scope"] }>();
  const [recoveryCursor, setRecoveryCursor] = useState<string>();
  const [recoveryStarted, setRecoveryStarted] = useState(false);
  const [recoveryDone, setRecoveryDone] = useState(false);
  const [readback, setReadback] = useState("");
  const beginRecovery = (context: NonNullable<typeof original>) => {
    setOriginal(context); setRecoveryCursor(undefined); setRecoveryStarted(false); setRecoveryDone(false); setReadback("");
  };
  const load = useCallback((cursor?: string) => client.listRoleBindings(tenant, business, subject.account_id, cursor), [client, tenant, business, subject.account_id]);
  const result = useCursorPage(load);
  const write = useWriteFeedback(client);
  const formId = useId(), reloadButton = useRef<HTMLButtonElement>(null), alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    let active = true; setMember(undefined); setReadError(undefined);
    client.getMember(tenant, subject.account_id).then(value => { if (active) { setMember(value); } })
      .catch(reason => { if (active) setReadError(reason); });
    return () => { active = false; };
  }, [client, tenant, subject.account_id, attempt]);
  const busy = write.busy || reading;
  const recover = async () => {
    if (!original || busy) return;
    setReading(true);
    try {
      const [current, page] = await Promise.all([client.getMember(tenant, subject.account_id), client.listRoleBindings(tenant, original.business, subject.account_id, recoveryCursor)]);
      if (!alive.current) return;
      setMember(current);
      const match = page.items.find(binding => original.binding ? binding.binding_id === original.binding : binding.role_id === original.role &&
        ("resource_type" in binding ? binding.resource_type : undefined) === original.resource && binding.scope.kind === original.scope?.kind &&
        (binding.scope.kind !== "instance" || original.scope?.kind === "instance" && binding.scope.resource_id === original.scope.resource_id));
      setRecoveryStarted(true); setRecoveryCursor(page.next_cursor ?? undefined); setRecoveryDone(!!match || !page.has_more);
      setReadback(match ? `原授权当前存在，绑定 ID：${match.binding_id}。不能据此确认请求归因。` : page.has_more ? "本页未找到原授权，可继续读取下一页。" : "已读取至末页，未找到原授权；不能据此确认请求结果。");
    } catch { if (alive.current) setReadback("原成员或原业务授权读取失败，可重试当前页；写入仍锁定。"); }
    finally { if (alive.current) setReading(false); }
  };
  const reset = () => {
    if (busy || !discardChanges(adding || !!revoke || write.outcome === "unknown", "重新读取会清除授权草稿。请先核对原成员及原业务的写入结果；继续？")) return;
    setAdding(false); setRevoke(undefined); setAttempt(v => v + 1); result.reload();
  };
  return <Drawer rootClassName="management-overlay management-workflow-editor" open title={`成员角色：${subject.email}`} width={720}
    onClose={() => { if (!busy && discardChanges(adding || !!revoke || write.outcome === "unknown")) close(); }} closable={!busy} keyboard={!busy && !revoke} maskClosable={false}>
    <Typography.Paragraph>目标域：{tenant} · 用户 ID：{subject.account_id}<br />授权只作用于当前租户与明确业务，不改变登录身份。</Typography.Paragraph>
    <WriteFeedback state={write} />
    {write.blocked && original && <>
      <Typography.Paragraph>待核对原授权：{tenant} / {original.business}，成员 {subject.account_id}，角色 {original.role}，绑定 {original.binding ?? "创建时尚无 ID"}。核对原范围前不能变更业务或再次写入。</Typography.Paragraph>
      {readback && <Alert type="info" role="status" message={readback} />}
      <Space wrap><Button disabled={busy || recoveryDone} onClick={() => void recover()}>{recoveryStarted ? "读取原授权下一页" : "读取原授权范围首页"}</Button>
        {recoveryDone && <Button disabled={busy} onClick={() => { write.recovered(); setAdding(false); setRevoke(undefined); setOriginal(undefined); setAttempt(v => v + 1); result.reload(); }}>结束授权核对</Button>}</Space>
    </>}
    {write.success && bindingId && <Typography.Paragraph role="status">原绑定 ID：{bindingId}</Typography.Paragraph>}
    <Form name={`binding-filter-${formId}`} layout="inline" className="management-filter" disabled={busy || write.blocked} onFinish={(values: { business_id?: string }) => {
      if (!discardChanges(adding || !!revoke || write.outcome === "unknown")) return;
      setAdding(false); setRevoke(undefined); setBusiness(values.business_id?.trim() || undefined); setAttempt(v => v + 1); result.reload();
    }}>
      <Form.Item name="business_id" label="业务标识" rules={[{ pattern: businessRule, message: "请输入有效业务标识" }]}><Input allowClear maxLength={64} placeholder="全部业务" /></Form.Item><Button htmlType="submit">查询</Button>
    </Form>
    <Space wrap className="management-filter"><Button ref={reloadButton} disabled={busy} onClick={reset}>重新加载分配</Button>
      <Button type={adding ? "default" : "primary"} disabled={busy || write.blocked || !member || result.loading || !!result.error || member.status !== "active" || member.membership.status !== "active"} onClick={() => {
        if (adding && !discardChanges(true)) return; setAdding(v => !v);
      }}>{adding ? "取消分配" : "分配业务角色"}</Button></Space>
    <ReadState loading={!member && !readError} error={readError} retry={reset} saved={!!write.success}>
      {member && (adding ? <GrantForm key={`${tenant}:${business ?? ""}:${member.account_id}:${attempt}`} client={client} tenant={tenant} business={business} subject={member} write={write}
        grant={async draft => {
          beginRecovery({ business: draft.role.business_id, role: draft.role.role_id, resource: draft.resource, scope: draft.scope });
          const response = await write.run(() => client.grantRole(tenant, draft.role.business_id, member.account_id, draft.role, draft.resource, draft.scope),
            `已确认分配：${tenant} / ${draft.role.business_id}，成员 ${member.account_id}，角色 ${draft.role.role_id}；${draft.scope.kind === "business" ? "整个业务有效权限" : scopeLabel(draft.scope)}。`);
          if (response.ok) { setBindingId(response.value.binding_id); setAdding(false); result.reload(); requestAnimationFrame(() => reloadButton.current?.focus()); }
        }} /> : <ReadState loading={result.loading} error={result.error} status={result.errorStatus} retry={reset} saved={!!write.success} empty={!result.page?.items.length} emptyText="此成员当前筛选下暂无角色分配。">
          <Table<RoleBinding> rowKey="binding_id" dataSource={result.page?.items} pagination={false} scroll={{ x: 640 }} columns={[
            { title: "业务标识", dataIndex: "business_id" },
            { title: "角色 / 绑定 ID", render: (_, binding) => <>{binding.role_id}<br /><Typography.Text code>{binding.binding_id}</Typography.Text></> },
            { title: "资源类型", render: (_, binding) => "resource_type" in binding ? binding.resource_type : "全部业务权限" },
            { title: "范围", render: (_, binding) => binding.scope.kind === "business" ? "整个业务" : scopeLabel(binding.scope) },
            { title: "操作", render: (_, binding) => binding.business_id === "idp" ? <Typography.Text type="secondary">通过管理员授权管理</Typography.Text> : <Button danger disabled={busy || write.blocked} onClick={async () => {
              setReading(true); setReadError(undefined);
              try { const role = await client.getRole(tenant, binding.business_id, binding.role_id); if (alive.current) {
                if (!["business", "business_admin"].includes(role.kind)) setReadError(new ManagementError("保护角色请通过专用管理员入口管理。", 403));
                else setRevoke({ binding, role });
              } } catch (reason) { if (alive.current) setReadError(reason); } finally { if (alive.current) setReading(false); }
            }}>撤销</Button> },
          ]} />
        </ReadState>)}
      {!adding && result.controls}
    </ReadState>
    <SafeConfirm open={!!revoke} title="确认撤销角色分配" okText="确认撤销" cancelText="取消" confirmLoading={write.busy} okButtonProps={{ danger: true, disabled: write.blocked }}
      onCancel={() => setRevoke(undefined)} afterClose={() => reloadButton.current?.focus()} onOk={async () => {
        if (!revoke) return;
        const original = revoke.binding;
        beginRecovery({ business: original.business_id, role: original.role_id, binding: original.binding_id });
        const response = await write.run(() => client.revokeRoleBinding(tenant, original.business_id, original, revoke.role), `已确认撤销绑定 ${original.binding_id}：${tenant} / ${original.business_id}，成员 ${subject.account_id}。`);
        if (alive.current) setRevoke(undefined);
        if (response.ok) { setBindingId(original.binding_id); result.reload(); }
      }}>
      {revoke && <Typography.Paragraph>租户：{tenant} / {revoke.binding.business_id}<br />成员：{subject.email}（{subject.account_id}）<br />角色：{revoke.role.name}（{revoke.role.key} / {revoke.role.role_id}）<br />绑定 ID：{revoke.binding.binding_id}<br />资源类型：{"resource_type" in revoke.binding ? revoke.binding.resource_type : "全部业务权限"}<br />范围：{revoke.binding.scope.kind === "business" ? "整个业务" : scopeLabel(revoke.binding.scope)}</Typography.Paragraph>}
      <Alert type="warning" message="只撤销此项分配，保留账号、成员关系与其他授权" description="其他有效授权可能仍允许访问。此接口没有角色版本 CAS，提交时由服务端复查原绑定与角色。" />
    </SafeConfirm>
  </Drawer>;
}

function MembershipEditor({ client, tenant, subject, close, changed }: { client: ManagementClient; tenant: string; subject: string; close: () => void; changed: () => void }) {
  const [member, setMember] = useState<Member>();
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(true);
  const [readError, setReadError] = useState<unknown>();
  const [status, setStatus] = useState<Membership["status"]>();
  const write = useWriteFeedback(client);
  const reloadButton = useRef<HTMLButtonElement>(null);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const actionLabel = status === "removed" ? "移除成员" : status === "suspended" ? "暂停成员" : "恢复成员";
  useEffect(() => {
    let active = true; setLoading(true); setMember(undefined); setStatus(undefined); setReadError(undefined);
    client.getMember(tenant, subject).then(value => { if (active) { setMember(value); write.recovered(); } })
      .catch(reason => { if (active) setReadError(reason); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, tenant, subject, attempt]);
  const reload = () => { if (!write.busy && discardChanges(!!status || write.outcome === "unknown")) setAttempt(v => v + 1); };
  return <Drawer rootClassName="management-overlay management-workflow-editor" open title="成员关系" width={620} onClose={() => { if (!write.busy && discardChanges(!!status || write.outcome === "unknown")) close(); }} closable={!write.busy} keyboard={!write.busy && !status} maskClosable={false}>
    <Typography.Paragraph>目标租户：{tenant} · 用户 ID：{subject}</Typography.Paragraph><WriteFeedback state={write} />
    <Button ref={reloadButton} disabled={write.busy || loading} onClick={reload}>重新加载成员</Button>
    <ReadState loading={loading} error={readError} retry={reload} saved={!!write.success}>
      {member && <>
        <Typography.Paragraph>用户：{member.email}（{member.account_id}）<br />全局账号：{accountStatus[member.status]}<br />本租户成员关系：{memberStatus[member.membership.status]} · 版本 {member.membership.version}</Typography.Paragraph>
        {member.membership.status === "removed" ? <Alert type="info" message="已移除成员须平台重新关联，不恢复原角色或设备绑定。" /> : <Space wrap>
          <Button disabled={write.busy || write.blocked || member.membership.status !== "suspended" || member.status !== "active"} onClick={() => setStatus("active")}>恢复成员</Button>
          <Button disabled={write.busy || write.blocked || member.membership.status !== "active"} onClick={() => setStatus("suspended")}>暂停成员</Button>
          <Button danger disabled={write.busy || write.blocked} onClick={() => setStatus("removed")}>移除成员</Button>
        </Space>}
      </>}
    </ReadState>
    <SafeConfirm open={!!status} title={`确认${actionLabel}`} okText={`确认${actionLabel}`} cancelText="取消" confirmLoading={write.busy} okButtonProps={{ danger: status !== "active", disabled: write.blocked }}
      onCancel={() => setStatus(undefined)} afterClose={() => reloadButton.current?.focus()} onOk={async () => {
        if (!member || !status) return;
        const desired = status;
        const response = await write.run(() => client.setMemberStatus(tenant, member.membership, desired), `已确认${actionLabel}：${tenant} / ${subject}。全局账号与其他租户的既有会话不由此操作统一撤销。`);
        if (!alive.current) return;
        if (response.ok) { setMember({ ...member, membership: response.value }); setStatus(undefined); changed(); setAttempt(v => v + 1); }
        else setStatus(undefined);
      }}>
      <Typography.Paragraph>租户：{tenant}<br />用户：{member?.email}（{subject}）<br />成员版本：{member?.membership.version}<br />目标状态：{status && memberStatus[status]}</Typography.Paragraph>
      <Alert type="warning" message={status === "active" ? "恢复后须重新登录；保留的角色与设备绑定继续按当前规则生效" : "清理本租户session、refresh、授权码及邮箱验证码，并撤销以本租户为来源或无来源域的选择票据"}
        description={status === "removed" ? "另删除本租户角色绑定并解绑设备，不删除全局账号。已移除不能直接恢复，平台重新关联也不恢复旧绑定。" : status === "suspended" ? "保留本租户角色与设备绑定；不更改全局账号密码，不统一撤销其他租户的既有会话。" : "只有暂停且全局账号有效的成员可恢复；不会恢复已退役登录凭证。"} />
      <Typography.Paragraph>服务端保护最后有效管理员；移除还保护该账号最后一个未移除的成员关系（暂停也计入），并检查expected_version。409后须重读，不推断为某个特定冲突原因。</Typography.Paragraph>
    </SafeConfirm>
  </Drawer>;
}

function BindMember({ client, tenant, close }: { client: ManagementClient; tenant: string; close: () => void }) {
  const [account, setAccount] = useState<Account>();
  const [confirming, setConfirming] = useState(false);
  const [readError, setReadError] = useState<unknown>();
  const [current, setCurrent] = useState("");
  const [reading, setReading] = useState(false);
  const alive = useRef(true), sequence = useRef(0), readPending = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; sequence.current++; }; }, []);
  const write = useWriteFeedback(client);
  const reread = async () => {
    if (!account || write.busy || readPending.current) return;
    readPending.current = true; setReading(true); setReadError(undefined); setCurrent("");
    const revision = ++sequence.current;
    try {
      let member: Member | undefined;
      try { member = await client.getMember(tenant, account.account_id); }
      catch (reason) { if (!(reason instanceof ManagementError && reason.status === 404)) throw reason; await client.listMembers(tenant, account.email); }
      if (!alive.current || revision !== sequence.current) return;
      setCurrent(member ? `当前成员关系：${memberStatus[member.membership.status]}，版本 ${member.membership.version}` : "原用户当前未读取到本租户成员关系；回读不能证明此前请求归因。"); write.recovered();
    } catch (reason) { if (alive.current && revision === sequence.current) setReadError(reason); }
    finally { if (alive.current && revision === sequence.current) { readPending.current = false; setReading(false); } }
  };
  return <Drawer rootClassName="management-overlay management-workflow-editor" open title="绑定已有用户" width={620} onClose={() => { if (!write.busy && discardChanges(!!account || write.outcome === "unknown")) close(); }} closable={!write.busy} keyboard={!write.busy && !confirming} maskClosable={false}>
    <Typography.Paragraph>目标租户：{tenant}。复用全局账号 ID 与凭证，只建立本域成员关系，不自动授予业务或管理员权限。</Typography.Paragraph>
    <WriteFeedback state={write} />
    {!account ? <AccountPicker client={client} select={setAccount} /> : <>
      <Typography.Paragraph>用户：{account.email}（{account.account_id}）</Typography.Paragraph>
      {current && <Typography.Paragraph role="status">{current}</Typography.Paragraph>}
      <Space wrap><Button disabled={write.busy || write.blocked || reading} onClick={() => setConfirming(true)}>核对并绑定</Button><Button disabled={write.busy || reading} onClick={() => void reread()}>重新读取原成员</Button></Space>
      <ReadState loading={reading} error={readError} retry={() => void reread()} saved={!!write.success} />
    </>}
    <SafeConfirm open={confirming} title="确认绑定成员" okText="确认绑定" cancelText="返回修改" confirmLoading={write.busy} okButtonProps={{ disabled: write.blocked || reading }} onCancel={() => setConfirming(false)} onOk={async () => {
      if (!account || readPending.current) return;
      sequence.current++; setCurrent(""); setReadError(undefined);
      const response = await write.run(() => client.bindMember(tenant, account.account_id), `已确认关联 ${tenant} / ${account.account_id}；原账号与密码未更改。`);
      if (alive.current) { setConfirming(false); if (response.ok) void reread(); }
    }}>
      <Typography.Paragraph>租户：{tenant}<br />用户：{account?.email}（{account?.account_id}）</Typography.Paragraph>
      <Alert type="info" message="只建立有效成员关系，不自动分配角色" description="已有效的关系不变；暂停成员须使用恢复。已移除成员重新加入也不恢复旧角色或设备绑定。" />
    </SafeConfirm>
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
  const [notice, setNotice] = useState("");
  const trigger = useRef<HTMLElement | null>(null), refreshButton = useRef<HTMLButtonElement>(null);
  const state = client.getSnapshot(), enabled = state.capabilities!.tenancy_enabled;
  const platform = enabled && state.session!.tenant_id === "0";
  const close = () => {
    setSubject(undefined); setRelationship(undefined); setAdministrator(undefined); setBinding(false); setSecurity(undefined); setCreating(false); result.reload();
    requestAnimationFrame(() => (trigger.current?.isConnected ? trigger.current : refreshButton.current)?.focus());
  };
  return <>
    {notice && <Alert type="success" role="status" showIcon message={notice} />}
    <Space wrap className="management-filter"><Button ref={refreshButton} disabled={result.loading} onClick={result.reload}>刷新成员</Button>
      {state.session!.tenant_id === "0" && <Button type="primary" onClick={event => { trigger.current = event.currentTarget; setCreating(true); }}>新建用户</Button>}
      {platform && <Button onClick={event => { trigger.current = event.currentTarget; setBinding(true); }}>绑定已有用户</Button>}
    </Space>
    <ReadState loading={result.loading} error={result.error} status={result.errorStatus} retry={result.reload} saved={!!notice} empty={!result.page?.items.length} emptyText={email ? "没有匹配此邮箱筛选的成员。" : "此域暂无成员。"}>
      <Table<Member> rowKey="account_id" dataSource={result.page?.items} pagination={false} scroll={{ x: 760 }} columns={[
        { title: "成员", render: (_, member) => <>{member.display_name || member.email}<br /><Typography.Text type="secondary">{member.email}</Typography.Text><br /><Typography.Text code>{member.account_id}</Typography.Text></> },
        { title: "全局账号状态", render: (_, member) => accountStatus[member.status] },
        { title: "本域成员关系", render: (_, member) => memberStatus[member.membership.status] },
        { title: "操作", render: (_, member) => <Space wrap>
          <Button onClick={event => { trigger.current = event.currentTarget; setSubject(member); }} aria-label={`查看成员角色 ${member.email}`}>角色分配</Button>
          {state.session!.tenant_id === "0" && <Button onClick={event => { trigger.current = event.currentTarget; setAdministrator(member.account_id); }} aria-label={`管理管理员授权 ${member.email}`}>管理员授权</Button>}
          {state.session!.tenant_id === "0" && <Button onClick={event => { trigger.current = event.currentTarget; setSecurity(member.account_id); }} aria-label={`管理账号安全 ${member.email}`}>账号安全</Button>}
          {enabled && <Button onClick={event => { trigger.current = event.currentTarget; setRelationship(member.account_id); }} aria-label={`管理成员关系 ${member.email}`}>成员关系</Button>}
        </Space> },
      ]} />
    </ReadState>{result.controls}
    {subject && <BindingDrawer key={`${tenant}:${subject.account_id}`} client={client} tenant={tenant} subject={subject} close={close} />}
    {administrator && <AdministratorDrawer key={`${tenant}:${administrator}`} client={client} tenant={tenant} subject={administrator} close={close} />}
    {relationship && <MembershipEditor key={`${tenant}:${relationship}`} client={client} tenant={tenant} subject={relationship} close={close} changed={result.reload} />}
    {security && <AccountSecurityDrawer client={client} subject={security} close={close} />}
    {creating && <CreateAccount client={client} tenant={tenant} close={close} created={member => setNotice(`已确认创建账号及 ${tenant} 成员：${member.email}（${member.account_id}），尚未分配业务角色。`)} />}
    {binding && <BindMember key={tenant} client={client} tenant={tenant} close={close} />}
  </>;
}

export function MemberRoles({ client, tenant }: { client: ManagementClient; tenant: string }) {
  const [query, setQuery] = useState({ email: "", revision: 0 });
  const [form] = Form.useForm(); const id = useId();
  return <Card title="成员管理" className="management-card management-workflow-page">
    <Typography.Paragraph type="secondary">管理目标：{tenant}。账号状态与本域成员关系分别显示；权限、角色和资源范围由各自业务标识限定。</Typography.Paragraph>
    <Form name={`member-search-${id}`} form={form} layout="inline" className="management-filter" onFinish={(values: { email?: string }) => setQuery(value => ({ email: values.email?.trim() ?? "", revision: value.revision + 1 }))}>
      <Form.Item name="email" label="邮箱"><Input allowClear maxLength={320} /></Form.Item><Space wrap><Button htmlType="submit">查询</Button><Button onClick={() => { form.resetFields(); setQuery(value => ({ email: "", revision: value.revision + 1 })); }}>重置筛选</Button></Space>
    </Form>
    <MemberTable key={`${tenant}:${JSON.stringify(query)}`} client={client} tenant={tenant} email={query.email} />
  </Card>;
}
