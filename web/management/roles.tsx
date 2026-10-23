import { useCallback, useEffect, useId, useRef, useState } from "react";
import { Alert, Button, Card, Drawer, Form, Input, Modal, Select, Space, Table, Tag, Typography } from "antd";
import { ManagementClient, ManagementError, type Role, type RoleDetail } from "./client";

import { useCursorPage } from "./pagination";
import { RolePermissions } from "./permissions";
import { discardChanges, ReadState, SafeConfirm, useWriteFeedback, WriteFeedback } from "./workflow";

const { Text, Paragraph } = Typography;
const statusLabel = { active: "启用", suspended: "停用", archived: "已归档", disabled: "停用" };
const kindLabel = { business: "业务角色", business_admin: "业务管理员", system_admin: "IDP 管理员", tenant_security_admin: "IDP 租户管理员" };
const failure = (error: unknown) => error instanceof ManagementError ? error.message : "操作失败，请重新加载后核对。";


const nameRules = [{ required: true, whitespace: true, message: "请输入角色名称" }, {
  validator: (_: unknown, value: string) => !value || (new TextEncoder().encode(value).length <= 256 && !/[\x00-\x1f\x7f]/.test(value))
    ? Promise.resolve() : Promise.reject(new Error("名称不能包含控制字符，且 UTF-8 长度不能超过 256 字节")),
}];

function CreateRole({ client, tenant, business, businessAdmin, close, created }: {
  client: ManagementClient; tenant: string; business?: string; businessAdmin: boolean; close: () => void; created: (role: RoleDetail) => void;
}) {
  const write = useWriteFeedback(client);
  const formName = useId();
  const [review, setReview] = useState<{ business_id: string; key: string; name: string }>();
  const [form] = Form.useForm();
  const [dirty, setDirty] = useState(false);
  const [readback, setReadback] = useState("");
  const [recoveryCursor, setRecoveryCursor] = useState<string>();
  const [recoveryStarted, setRecoveryStarted] = useState(false);
  const [recoveryDone, setRecoveryDone] = useState(false);
  const [reading, setReading] = useState(false);
  return <Modal open title={businessAdmin ? "创建业务管理员" : "新建业务角色"} footer={null} onCancel={() => { if (!write.busy && discardChanges(dirty || write.blocked)) close(); }} closable={!write.busy} maskClosable={false} keyboard={!write.busy}>
    <Paragraph type="secondary">目标域：{tenant}。{businessAdmin ? "每个业务只能创建一个。分配给成员后，自动拥有此业务全部有效权限。" : "新角色默认启用，初始权限为空。"}</Paragraph>
    <WriteFeedback state={write} />
    {readback && <Alert type="info" role="status" message={readback} />}
    {write.blocked && review && <Space>
      <Button disabled={reading || recoveryDone} onClick={async () => {
        setReading(true);
        try {
          const page = await client.listRoles(tenant, review.business_id, recoveryCursor);
          const match = page.items.find(role => role.key === (businessAdmin ? "business_admin" : review.key));
          setRecoveryStarted(true); setRecoveryCursor(page.next_cursor ?? undefined);
          setRecoveryDone(!!match || !page.has_more);
          setReadback(match ? `原标识当前存在：${match.name}（${match.role_id}）。不能据此确认创建请求的结果。` : page.has_more ? "本页未找到原标识，可继续读取下一页。" : "已读取至末页，未找到原标识；不能据此确认请求结果。");
        } catch { setReadback("原业务角色列表读取失败，可重试当前页。"); }
        finally { setReading(false); }
      }}>{recoveryStarted ? "读取下一页" : "读取原业务角色首页"}</Button>
      {recoveryDone && <Button onClick={() => { write.recovered(); setReview(undefined); }}>结束核对</Button>}
    </Space>}
    <Form form={form} name={formName} layout="vertical" disabled={write.busy || write.blocked} onValuesChange={() => { setDirty(true); write.edit(); }} onFinish={(values: { business_id: string; key: string; name: string }) => { setRecoveryCursor(undefined); setRecoveryStarted(false); setRecoveryDone(false); setReadback(""); setReview(values); }}>
      <Form.Item name="business_id" label="业务标识" initialValue={business === "idp" ? undefined : business} rules={[
        { required: true, message: "请输入所属业务标识" }, { pattern: /^[a-z][a-z0-9_.-]{0,63}$/, message: "请输入有效业务标识" },
        { validator: (_, value) => value === "idp" || value?.startsWith("idp.") ? Promise.reject(new Error("不能使用 IDP 保留标识")) : Promise.resolve() },
      ]}><Input maxLength={64} placeholder="例如 biz_test" /></Form.Item>
      {!businessAdmin && <Form.Item name="key" label="角色标识" rules={[{ required: true, message: "请输入角色标识" },
        { pattern: /^[a-z][a-z0-9_.-]{0,63}$/, message: "小写字母开头，仅含小写字母、数字、点、下划线或连字符，最多 64 位" },
        { validator: (_, value) => ["system_admin", "tenant_security_admin", "idp_system_admin", "idp_tenant_security_admin", "business_admin"].includes(value) ? Promise.reject(new Error("此标识为系统保留")) : Promise.resolve() }]}>
        <Input autoFocus maxLength={64} />
      </Form.Item>}
      <Form.Item name="name" label="角色名称" initialValue={businessAdmin ? "业务管理员" : undefined} rules={nameRules}><Input maxLength={256} autoFocus={businessAdmin} /></Form.Item>
      <Button type="primary" htmlType="submit" loading={write.busy}>创建角色</Button>
    </Form>
    <SafeConfirm open={!!review && !write.blocked} title="确认创建角色" okText="确认创建" cancelText="返回修改" confirmLoading={write.busy} onCancel={() => setReview(undefined)} onOk={async () => {
      if (!review) return;
      const result = await write.run(() => businessAdmin ? client.createBusinessAdmin(tenant, review.business_id, review.name) : client.createRole(tenant, review.business_id, review.key, review.name), "角色创建已确认。");
      if (result.ok) created(result.value);
    }}>
      <WriteFeedback state={write} />
      <Paragraph>目标域：{tenant} / {review?.business_id}；角色标识：{businessAdmin ? "business_admin" : review?.key}；名称：{review?.name}。</Paragraph>
      <Paragraph>{businessAdmin ? "分配后拥有该业务当前及未来全部有效权限。" : "新角色启用且初始权限为空。"}</Paragraph>
    </SafeConfirm>
  </Modal>;
}

function RoleEditor({ client, tenant, business, roleId, close, changed, deleted }: {
  client: ManagementClient; tenant: string; business: string; roleId: string; close: () => void; changed: () => void; deleted: (role: RoleDetail) => void;
}) {
  const [role, setRole] = useState<RoleDetail>();
  const [loading, setLoading] = useState(true);
  const write = useWriteFeedback(client);
  const [error, setError] = useState<unknown>();
  const [permissionsDirty, setPermissionsDirty] = useState(false);
  const [review, setReview] = useState<{ type: "save"; name: string; status: Role["status"] } | { type: "delete" }>();
  const [dirty, setDirty] = useState(false);
  const formName = useId();
  const [attempt, setAttempt] = useState(0);
  const reloadButton = useRef<HTMLButtonElement>(null);
  const [form] = Form.useForm();
  useEffect(() => {
    let active = true;
    setLoading(true); setRole(undefined); setError(undefined);
    client.getRole(tenant, business, roleId).then(value => {
      if (active) { setRole(value); form.setFieldsValue(value); setDirty(false); setPermissionsDirty(false); setReview(undefined); write.recovered(); }
    }).catch(reason => { if (active) setError(reason); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, tenant, business, roleId, attempt, form]);
  const deletedCallback = deleted;
  const mutation = async (operation: () => Promise<RoleDetail | void>, message: string, deleted = false) => {
    const result = await write.run(operation, `${message} 目标域：${tenant} / ${business}；角色 ID：${roleId}。`);
    if (result.ok) { if (deleted) { if (role) deletedCallback(role); changed(); close(); return true; } if (result.value) { setRole(result.value); form.setFieldsValue(result.value); } setDirty(false); setPermissionsDirty(false); setReview(undefined); changed(); setAttempt(v => v + 1); requestAnimationFrame(() => reloadButton.current?.focus()); return true; }
    return false;
  };
  return <Drawer rootClassName="management-overlay management-workflow-editor" open title="角色详情" width={620} onClose={() => { if (!write.busy && discardChanges(dirty || permissionsDirty || write.blocked)) close(); }} closable={!write.busy} maskClosable={!write.busy} keyboard={!write.busy}>
    <Paragraph type="secondary">目标域：{tenant} / {business}；角色 ID：{roleId}</Paragraph>
    <WriteFeedback state={write} />
    <Button ref={reloadButton} disabled={write.busy || loading} onClick={() => { if (discardChanges(dirty || permissionsDirty || write.blocked)) setAttempt(v => v + 1); }}>重新加载详情</Button>
    <ReadState loading={loading} error={error} saved={!!write.success} retry={() => { if (discardChanges(dirty || permissionsDirty || write.blocked)) setAttempt(v => v + 1); }}>
    {role && <>
      <Paragraph className="management-note"><Tag>{kindLabel[role.kind]}</Tag> {role.key} · 版本 {role.version}</Paragraph>
      {!["business", "business_admin"].includes(role.kind) && <Alert type="info" message="系统保护角色只读，请通过专用管理员任命流程管理。" />}
      {role.kind === "business_admin" && <Alert type="info" message="业务管理员自动拥有此业务内全部有效权限，无需配置权限集。" />}
      <Form form={form} name={formName} layout="vertical" onValuesChange={() => { setDirty(true); write.edit(); }} disabled={write.busy || write.blocked || !["business", "business_admin"].includes(role.kind)}
        onFinish={(values: { name: string; status: Role["status"] }) => setReview({ type: "save", ...values })}>
        <Form.Item name="name" label="角色名称" rules={nameRules}><Input maxLength={256} /></Form.Item>
        <Form.Item name="status" label="状态" rules={[{ required: true }]}><Select options={[{ value: "active", label: "启用" }, { value: "disabled", label: "停用" }]} /></Form.Item>
        {["business", "business_admin"].includes(role.kind) && <Space>
          <Button type="primary" htmlType="submit" loading={write.busy}>保存</Button>
          <Button danger disabled={write.busy || write.blocked} onClick={() => setReview({ type: "delete" })}>删除角色</Button>
        </Space>}
      </Form>
      <RolePermissions key={role.version} client={client} tenant={tenant} business={business} role={role} busy={write.busy} blocked={write.blocked} error={write.error}
        onDraftChange={setPermissionsDirty} save={permissions => mutation(() => client.replaceRolePermissions(tenant, business, role, permissions), "权限集保存已确认。")} />
      <SafeConfirm open={!!review && !write.blocked} title={review?.type === "delete" ? "确认删除角色" : "确认保存角色"} okText={review?.type === "delete" ? "确认删除" : "确认保存"} okButtonProps={{ danger: review?.type === "delete" }} confirmLoading={write.busy} onCancel={() => setReview(undefined)} onOk={() => {
        if (review?.type === "delete") void mutation(() => client.deleteRole(tenant, business, role), "角色删除已确认。", true);
        else if (review?.type === "save") void mutation(() => client.updateRole(tenant, business, role, review.name, review.status), "角色保存已确认。");
      }}>
        <WriteFeedback state={write} />
        <Paragraph>目标域：{tenant} / {business}；角色：{role.name}（{role.key}，{role.role_id}）；版本 {role.version}。</Paragraph>
        {review?.type === "save" ? <Paragraph>保存名称：{review.name}；状态：{statusLabel[review.status]}。</Paragraph> : <Paragraph>删除不可恢复；服务端检查已有绑定。业务管理员须先撤销全部成员分配。</Paragraph>}
      </SafeConfirm>
    </>}</ReadState>
  </Drawer>;
}

export function RoleTable({ client, tenant }: { client: ManagementClient; tenant: string }) {
  const filterName = useId();
  const [business, setBusiness] = useState<string>();
  const load = useCallback((cursor?: string) => client.listRoles(tenant, business, cursor), [client, tenant, business]);
  const result = useCursorPage(load);
  const [creating, setCreating] = useState<"business" | "business_admin">();
  const [selected, setSelected] = useState<Role>();
  const [success, setSuccess] = useState("");
  const trigger = useRef<HTMLElement | null>(null);
  const createButton = useRef<HTMLButtonElement>(null);
  const close = () => {
    setCreating(undefined); setSelected(undefined);
    requestAnimationFrame(() => { (trigger.current?.isConnected ? trigger.current : createButton.current)?.focus(); });
  };
  return <Card title="角色" className="management-card management-workflow-page" extra={<Space><Button onClick={result.reload} disabled={result.loading}>刷新</Button><Button onClick={event => { trigger.current = event.currentTarget; setCreating("business_admin"); }}>创建业务管理员</Button><Button ref={createButton} type="primary" onClick={event => { trigger.current = event.currentTarget; setCreating("business"); }}>新建角色</Button></Space>}>
    <Form name={filterName} layout="inline" className="management-filter" onFinish={(values: { business_id?: string }) => {
      setSelected(undefined); setCreating(undefined); setBusiness(values.business_id?.trim() || undefined); result.reload();
    }}>
      <Form.Item name="business_id" label="业务标识" rules={[{ pattern: /^(?!idp\.)[a-z][a-z0-9_.-]{0,63}$/, message: "请输入有效业务标识" }]}><Input allowClear maxLength={64} placeholder="全部业务" /></Form.Item>
      <Button htmlType="submit">查询</Button>
    </Form>
    {success && <Alert type="success" role="status" showIcon message={success} />}
    <ReadState loading={result.loading} error={result.error} status={result.errorStatus} retry={result.reload} saved={!!success} empty={!result.page?.items.length} emptyText={business ? "没有符合条件的角色" : "此域暂无角色"}>
    <Table<Role> rowKey="role_id" loading={result.loading} dataSource={result.page?.items ?? []} pagination={false} scroll={{ x: 680 }}
      locale={{ emptyText: result.error ? "未能读取角色" : "此域暂无角色" }} columns={[
        { title: "角色", dataIndex: "name", render: (name, role) => <><Text strong>{name}</Text><br /><Text type="secondary">{role.key}</Text></> },
        { title: "业务标识", dataIndex: "business_id" },
        { title: "类型", dataIndex: "kind", render: (kind: Role["kind"]) => kindLabel[kind] },
        { title: "状态", dataIndex: "status", render: (status: Role["status"]) => <Tag>{statusLabel[status]}</Tag> },
        { title: "操作", key: "action", render: (_, role) => <Button aria-label={`查看角色 ${role.name}`} onClick={event => { trigger.current = event.currentTarget; setSelected(role); }}>查看详情</Button> },
      ]} />
    </ReadState>
    {!result.loading && !result.error && result.controls}
    {creating && <CreateRole client={client} tenant={tenant} business={business} businessAdmin={creating === "business_admin"} close={() => { close(); result.reload(); }} created={role => { setSuccess(`角色创建已确认：${tenant} / ${role.business_id}，${role.key}（${role.role_id}），版本 ${role.version}。`); close(); result.reload(); }} />}
    {selected && <RoleEditor key={selected.role_id} client={client} tenant={tenant} business={selected.business_id} roleId={selected.role_id} close={close} changed={result.reload} deleted={role => { setSuccess(`角色删除已确认：${tenant} / ${role.business_id}，${role.key}（${role.role_id}），版本 ${role.version}。`); }} />}
  </Card>;
}
