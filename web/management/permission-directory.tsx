import { useCallback, useEffect, useId, useRef, useState } from "react";
import { Alert, Button, Card, Form, Input, Modal, Select, Space, Table, Tag, Typography } from "antd";
import { type ManagementClient, type DirectoryPermission, type PermissionDirectoryFilter, type PermissionKey } from "./client";
import { useCursorPage } from "./pagination";
import { discardChanges, ReadState, SafeConfirm, useWriteFeedback, WriteFeedback } from "./workflow";

export type PermissionDirectoryClient = Pick<ManagementClient,
  "getSnapshot" | "listPermissionDirectory" | "createPermission" | "updatePermission" | "setPermissionEnabled" | "archivePermission">;
export interface PermissionDirectoryProps { client: PermissionDirectoryClient; tenant: string; business?: string }

const categories = { business: "业务权限", tenant: "租户管理权限", platform: "平台管理权限" };
const keyOf = (p: PermissionKey) => `${p.resource_type}::${p.action}`;
const nameRule = /^[a-z][a-z0-9_.-]{0,63}$/;

function DirectoryTable({ client, tenant, business, filter, onLocked }: PermissionDirectoryProps & { filter: PermissionDirectoryFilter; onLocked: (locked: boolean) => void }) {
  const load = useCallback((cursor?: string) => client.listPermissionDirectory(tenant, business, filter, cursor), [client, tenant, business, filter]);
  const result = useCursorPage(load);
  const [editing, setEditing] = useState<DirectoryPermission | null>();
  const [form] = Form.useForm<{ business_id: string; resource_type: string; action: string; description: string }>();
  const write = useWriteFeedback(client);
  const refreshButton = useRef<HTMLButtonElement>(null);
  const trigger = useRef<HTMLElement | null>(null);
  const successFocus = useRef<{ editor: boolean; confirm: boolean; original: HTMLElement | null } | null>(null);
  const restoreSuccessFocus = (closed: "editor" | "confirm") => {
    const pending = successFocus.current;
    if (!pending) return;
    pending[closed] = false;
    if (pending.editor || pending.confirm) return;
    successFocus.current = null;
    const original = pending.original;
    const target = original?.isConnected && original.getClientRects().length && !original.matches(":disabled") ? original : refreshButton.current;
    target?.focus();
  };

  const formName = useId();
  const [dirty, setDirty] = useState(false);
  const [readback, setReadback] = useState("");
  const [confirmed, setConfirmed] = useState("");
  const [recoveryCursor, setRecoveryCursor] = useState<string>();
  const [recoveryStarted, setRecoveryStarted] = useState(false);
  const [recoveryDone, setRecoveryDone] = useState(false);
  const [reading, setReading] = useState(false);
  type Values = { business_id: string; resource_type: string; action: string; description: string };
  const [review, setReview] = useState<{ type: "save"; values: Values; original?: DirectoryPermission } | { type: "archive" | "toggle"; original: DirectoryPermission }>();
  useEffect(() => { onLocked(write.busy || write.blocked || editing !== undefined || !!review); }, [write.busy, write.blocked, editing, review, onLocked]);
  const platformOnly = business === "idp" || tenant === "0" && !!client.getSnapshot().capabilities?.tenancy_enabled;
  const close = () => {
    if (!write.busy && discardChanges(dirty || write.blocked, write.blocked
      ? "关闭将放弃当前编辑，但写入结果仍待核对，其他写入继续锁定。确认关闭？"
      : undefined)) { setEditing(undefined); setDirty(false); }
  };
  const recover = async () => {
    if (!review) return;
    const scope = review.type === "save" ? review.values : review.original;
    setReading(true);
    try {
      const page = await client.listPermissionDirectory(tenant, scope.business_id, { resource_type: scope.resource_type }, recoveryCursor);
      const match = page.items.find(p => p.action === scope.action);
      setRecoveryStarted(true); setRecoveryCursor(page.next_cursor ?? undefined); setRecoveryDone(!!match || !page.has_more);
      setReadback(match ? `原权限当前状态：${keyOf(match)}，版本 ${match.version}，${match.archived ? "已归档" : match.enabled ? "启用" : "停用"}。不能据此确认请求归因。` : page.has_more ? "本页未找到原权限，可继续读取下一页。" : "已读取至末页，未找到原权限；不能据此确认请求结果。");
    } catch { setReadback("原权限范围读取失败，可重试当前页。"); }
    finally { setReading(false); }
  };
  const submit = async () => {
    if (!review) return;
    const context = review;
    setRecoveryCursor(undefined); setRecoveryStarted(false); setRecoveryDone(false); setReadback("");
    const resultWrite = await write.run(() => context.type === "save"
      ? context.original ? client.updatePermission(tenant, context.original.business_id, context.original, context.values.description)
        : client.createPermission(tenant, context.values.business_id, context.values, context.values.description)
      : context.type === "archive" ? client.archivePermission(tenant, context.original.business_id, context.original)
        : client.setPermissionEnabled(tenant, context.original.business_id, context.original, !context.original.enabled), "权限目录写入已确认。");
    if (resultWrite.ok) { const p = resultWrite.value;
      // Row triggers are replaced by reload; only the create toolbar survives.
      successFocus.current = { editor: editing !== undefined, confirm: true, original: context.type === "save" && !context.original ? trigger.current : null };
      setConfirmed(`权限写入已确认：${tenant} / ${p.business_id}，${keyOf(p)}，版本 ${p.version}。`); setReview(undefined); setEditing(undefined); setDirty(false); result.reload(); }
  };
  return <>
    <div className="management-filter"><Button ref={refreshButton} disabled={write.busy || write.blocked} aria-disabled={write.busy || write.blocked || result.loading} onClick={() => { if (!result.loading) result.reload(); }}>刷新目录</Button>{" "}
      {!platformOnly && <Button type="primary" disabled={write.busy || write.blocked || editing !== undefined || !!review} onClick={event => { trigger.current = event.currentTarget; form.resetFields(); form.setFieldsValue({ business_id: business }); setDirty(false); write.edit(); setEditing(null); }}>创建权限</Button>}</div>
    <WriteFeedback state={write} />
    {confirmed && <Alert type="success" role="status" message={confirmed} />}
    {write.blocked && review && <Alert type="info" message={`待核对原权限：${tenant} / ${review.type === "save" ? review.values.business_id : review.original.business_id}，${keyOf(review.type === "save" ? review.values : review.original)}。`} />}
    {readback && <Alert type="info" role="status" message={readback} />}
    {write.blocked && <Space><Button disabled={reading || recoveryDone} onClick={() => void recover()}>{recoveryStarted ? "读取下一页" : "读取原权限范围首页"}</Button>{recoveryDone && <Button onClick={() => { write.recovered(); setReview(undefined); setEditing(undefined); setDirty(false); result.reload(); }}>结束核对</Button>}</Space>}
    <ReadState loading={result.loading} error={result.error} status={result.errorStatus} retry={result.reload} saved={!!write.success} empty={!result.page?.items.length} emptyText="没有符合条件的权限">
    <Table<DirectoryPermission> rowKey={p => `${p.business_id}::${keyOf(p)}`} dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 760 }}
      locale={{ emptyText: result.error ? "未能读取权限目录" : "没有符合条件的权限" }} columns={[
        { title: "权限", render: (_, p) => <><Typography.Text code>{keyOf(p)}</Typography.Text><br />{p.description}</> },
        { title: "业务标识", dataIndex: "business_id" },
        { title: "类别", dataIndex: "category", render: (value: DirectoryPermission["category"]) => categories[value] },
        { title: "状态", render: (_, p) => <Tag>{p.archived ? "已归档" : p.enabled ? "启用" : "停用"}</Tag> },
        { title: "操作", render: (_, p) => p.category !== "business" || p.archived || platformOnly
          ? <Typography.Text type="secondary">{p.archived ? "不可更改" : "系统保护"}</Typography.Text>
          : <Space><Button disabled={write.busy || write.blocked} onClick={() => { form.setFieldsValue(p); setDirty(false); write.edit(); setEditing(p); }}>编辑</Button>
            <Button disabled={write.busy || write.blocked} onClick={() => setReview({ type: "toggle", original: p })}>{p.enabled ? "停用" : "启用"}</Button>
            <Button danger disabled={write.busy || write.blocked} onClick={() => setReview({ type: "archive", original: p })}>归档</Button></Space> },
      ]} /></ReadState>
    {!result.loading && !result.error && result.controls}
    <Modal rootClassName="management-overlay" open={editing !== undefined} title={editing ? "编辑权限" : "创建权限"}
      afterClose={() => restoreSuccessFocus("editor")}
      onCancel={close} onOk={() => void form.submit()} confirmLoading={write.busy} closable={!write.busy} maskClosable={false} keyboard={!write.busy} okText="核对" okButtonProps={{ disabled: write.blocked, "aria-label": "核对" }}>
      <Form form={form} name={formName} layout="vertical" disabled={write.busy || write.blocked} onValuesChange={() => { setDirty(true); write.edit(); }} onFinish={values => setReview({ type: "save", values, original: editing || undefined })}>
        <Form.Item name="business_id" label="业务标识" rules={[
          { required: true, message: "请输入所属业务标识" }, { pattern: nameRule, message: "请输入有效业务标识" },
          { validator: (_, value) => value === "idp" || value?.startsWith("idp.") ? Promise.reject(new Error("不能使用 IDP 保留标识")) : Promise.resolve() },
        ]}><Input disabled={!!editing || !!business} maxLength={64} placeholder="例如 biz_test" /></Form.Item>
        <Form.Item name="resource_type" label="资源类型" rules={[{ required: true }, { pattern: nameRule }]}><Input disabled={!!editing} maxLength={64} placeholder="report" /></Form.Item>
        <Form.Item name="action" label="动作" rules={[{ required: true }, { pattern: nameRule }]}><Input disabled={!!editing} maxLength={64} placeholder="read" /></Form.Item>
        <Form.Item name="description" label="权限说明" rules={[{ required: true }, { max: 512 }]}><Input.TextArea rows={3} maxLength={512} /></Form.Item>
      </Form>
      <WriteFeedback state={write} />
      {readback && <Alert type="info" role="status" message={readback} />}
      {write.blocked && <Space><Button disabled={reading || recoveryDone} onClick={() => void recover()}>{recoveryStarted ? "读取下一页" : "读取原权限范围首页"}</Button>{recoveryDone && <Button onClick={() => { write.recovered(); setReview(undefined); setEditing(undefined); setDirty(false); result.reload(); }}>结束核对</Button>}</Space>}
    </Modal>
    <SafeConfirm afterClose={() => restoreSuccessFocus("confirm")} open={!!review && !write.blocked} title={review?.type === "save" ? review.original ? "确认编辑权限" : "确认创建权限" : review?.type === "archive" ? "确认归档权限" : "确认更改权限状态"} okText="确认" okButtonProps={{ danger: review?.type === "archive" || review?.type === "toggle" && review.original.enabled }} confirmLoading={write.busy} onCancel={() => setReview(undefined)} onOk={() => void submit()}>
      <WriteFeedback state={write} />
      {review && <><Typography.Paragraph>目标域：{tenant} / {review.type === "save" ? review.values.business_id : review.original.business_id}；权限标识：{keyOf(review.type === "save" ? review.values : review.original)}；{review.type === "save" ? review.original ? `版本 ${review.original.version}` : "新建" : `版本 ${review.original.version}`}。</Typography.Paragraph>
      <Typography.Paragraph>{review.type === "save" ? `权限说明：${review.values.description}。权限标识创建后不可修改。` : review.type === "archive" ? "归档后立即拒绝授权，标识不可重新创建。" : review.original.enabled ? "停用后拒绝此权限授权。" : "启用可能恢复已有角色授权。"}</Typography.Paragraph></>}
    </SafeConfirm>
  </>;
}

export function PermissionDirectory(props: PermissionDirectoryProps) {
  return <DirectoryScope key={`${props.tenant}:${props.business ?? ""}`} {...props} />;
}

function DirectoryScope({ client, tenant, business }: PermissionDirectoryProps) {
  const filterName = useId();
  const [locked, setLocked] = useState(false);
  const [filterRevision, setFilterRevision] = useState(0);
  const [filterForm] = Form.useForm();
  const [filter, setFilter] = useState<PermissionDirectoryFilter>({});
  const [businessFilter, setBusinessFilter] = useState<string>();
  const platform = tenant === "0" && !!client.getSnapshot().capabilities?.tenancy_enabled;
  return <Card title="权限目录" className="management-card management-workflow-page embedded-idp-permission-directory">
    <Typography.Paragraph type="secondary">列出当前租户的权限，可按业务标识筛选。普通角色需配置权限集；已分配的业务管理员自动覆盖新增有效权限。</Typography.Paragraph>
    <Form form={filterForm} name={filterName} disabled={locked} layout="inline" className="management-filter" onFinish={(values: { business_id?: string; resource_type?: string; category?: DirectoryPermission["category"]; enabled?: "true" | "false" }) => { setFilterRevision(v => v + 1); setBusinessFilter(values.business_id?.trim() || undefined); setFilter({
      ...(values.resource_type?.trim() ? { resource_type: values.resource_type.trim() } : {}), ...(values.category ? { category: values.category } : {}),
      ...(values.enabled ? { enabled: values.enabled === "true" } : {}),
    }); }}>
      {!business && !platform && <Form.Item name="business_id" label="业务标识" rules={[{ pattern: /^(?!idp\.)[a-z][a-z0-9_.-]{0,63}$/, message: "请输入有效业务标识" }]}><Input allowClear maxLength={64} placeholder="全部业务" /></Form.Item>}
      <Form.Item name="resource_type" label="资源类型" rules={[{ pattern: nameRule, message: "请输入有效资源类型" }]}><Input allowClear maxLength={64} /></Form.Item>
      <Form.Item name="category" label="类别"><Select allowClear style={{ minWidth: 155 }} options={Object.entries(categories).map(([value, label]) => ({ value, label }))} /></Form.Item>
      <Form.Item name="enabled" label="状态"><Select allowClear style={{ minWidth: 100 }} options={[{ value: "true", label: "启用" }, { value: "false", label: "停用" }]} /></Form.Item>
      <Button htmlType="submit" disabled={locked}>查询</Button><Button disabled={locked} onClick={() => { filterForm.resetFields(); setBusinessFilter(undefined); setFilter({}); setFilterRevision(v => v + 1); }}>重置</Button>
    </Form>
    <DirectoryTable key={`${tenant}:${business ?? businessFilter}:${JSON.stringify(filter)}:${filterRevision}`} client={client} tenant={tenant} business={business ?? businessFilter} filter={filter} onLocked={setLocked} />
  </Card>;
}
