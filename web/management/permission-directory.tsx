import { useCallback, useState } from "react";
import { Alert, Button, Card, Form, Input, Modal, Select, Space, Table, Tag, Typography } from "antd";
import { ManagementError, type ManagementClient, type DirectoryPermission, type PermissionDirectoryFilter, type PermissionKey } from "./client";
import { useCursorPage } from "./pagination";

export type PermissionDirectoryClient = Pick<ManagementClient,
  "getSnapshot" | "listPermissionDirectory" | "createPermission" | "updatePermission" | "setPermissionEnabled" | "archivePermission">;
export interface PermissionDirectoryProps { client: PermissionDirectoryClient; tenant: string }

const categories = { business: "业务权限", tenant: "租户管理权限", platform: "平台管理权限" };
const keyOf = (p: PermissionKey) => `${p.resource_type}::${p.action}`;
const nameRule = /^[a-z][a-z0-9_.-]{0,63}$/;
const failure = (reason: unknown) => reason instanceof ManagementError ? reason.message : "操作失败，请重新加载后核对。";

function DirectoryTable({ client, tenant, filter }: PermissionDirectoryProps & { filter: PermissionDirectoryFilter }) {
  const load = useCallback((cursor?: string) => client.listPermissionDirectory(tenant, filter, cursor), [client, tenant, filter]);
  const result = useCursorPage(load);
  const [editing, setEditing] = useState<DirectoryPermission | null>();
  const [form] = Form.useForm<{ resource_type: string; action: string; description: string }>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const platformOnly = tenant === "0" && !!client.getSnapshot().capabilities?.tenancy_enabled;
  const close = () => { setEditing(undefined); setError(""); result.reload(); };
  const submit = async (values: { resource_type: string; action: string; description: string }) => {
    setBusy(true); setError("");
    try {
      const permission = editing
        ? await client.updatePermission(tenant, editing, values.description)
        : await client.createPermission(tenant, values, values.description);
      setSuccess(`${keyOf(permission)} 已${editing ? "更新" : "创建"}。`); close();
    } catch (reason) { setError(failure(reason)); }
    finally { setBusy(false); }
  };
  const act = async (permission: DirectoryPermission, action: "archive" | "toggle") => {
    setBusy(true); setError("");
    try {
      if (action === "archive") await client.archivePermission(tenant, permission);
      else await client.setPermissionEnabled(tenant, permission, !permission.enabled);
      setSuccess(`${keyOf(permission)} 已${action === "archive" ? "归档" : permission.enabled ? "停用" : "启用"}。`);
      result.reload();
    } catch (reason) { setError(failure(reason)); result.reload(); }
    finally { setBusy(false); }
  };
  const confirm = (permission: DirectoryPermission, action: "archive" | "toggle") => {
    Modal.confirm({ rootClassName: "embedded-idp-permission-overlay", title: action === "archive" ? "归档权限" : "更改权限状态",
      content: action === "archive"
        ? `归档 ${keyOf(permission)} 后将立即拒绝授权，且该标识不能重新创建。`
        : `${permission.enabled ? "停用" : "启用"} ${keyOf(permission)}？启用可能恢复已有角色授权。`,
      okText: "确认", cancelText: "取消", okButtonProps: { danger: action === "archive" || permission.enabled },
      onOk: () => act(permission, action),
    });
  };
  return <>
    <div className="management-filter"><Button disabled={busy || result.loading} onClick={result.reload}>刷新目录</Button>{" "}
      {!platformOnly && <Button type="primary" onClick={() => { form.resetFields(); setError(""); setEditing(null); }}>创建权限</Button>}</div>
    {success && <Alert type="success" showIcon role="status" message={success} />}
    {error && <Alert type="error" showIcon role="alert" message={error} />}
    {result.error && <Alert type="error" showIcon role="alert" message={result.error} />}
    <Table<DirectoryPermission> rowKey={keyOf} dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 760 }}
      locale={{ emptyText: result.error ? "未能读取权限目录" : "没有符合条件的权限" }} columns={[
        { title: "权限", render: (_, p) => <><Typography.Text code>{keyOf(p)}</Typography.Text><br />{p.description}</> },
        { title: "类别", dataIndex: "category", render: (value: DirectoryPermission["category"]) => categories[value] },
        { title: "状态", render: (_, p) => <Tag>{p.archived ? "已归档" : p.enabled ? "启用" : "停用"}</Tag> },
        { title: "操作", render: (_, p) => p.category !== "business" || p.archived || platformOnly
          ? <Typography.Text type="secondary">{p.archived ? "不可更改" : "系统保护"}</Typography.Text>
          : <Space><Button onClick={() => { form.setFieldsValue(p); setError(""); setEditing(p); }}>编辑</Button>
            <Button onClick={() => confirm(p, "toggle")}>{p.enabled ? "停用" : "启用"}</Button>
            <Button danger onClick={() => confirm(p, "archive")}>归档</Button></Space> },
      ]} />{result.controls}
    <Modal rootClassName="management-overlay" open={editing !== undefined} title={editing ? "编辑权限" : "创建权限"}
      onCancel={close} onOk={() => void form.submit()} confirmLoading={busy} okText="保存" okButtonProps={{ disabled: !!error }}>
      <Form form={form} layout="vertical" onFinish={values => void submit(values)}>
        <Form.Item name="resource_type" label="资源类型" rules={[{ required: true }, { pattern: nameRule }]}><Input disabled={!!editing} maxLength={64} placeholder="report" /></Form.Item>
        <Form.Item name="action" label="动作" rules={[{ required: true }, { pattern: nameRule }]}><Input disabled={!!editing} maxLength={64} placeholder="read" /></Form.Item>
        <Form.Item name="description" label="权限说明" rules={[{ required: true }, { max: 512 }]}><Input.TextArea rows={3} maxLength={512} /></Form.Item>
      </Form>
      {error && <Alert type="error" role="alert" message={error} description="请关闭并重新加载目录核对结果。" />}
    </Modal>
  </>;
}

export function PermissionDirectory({ client, tenant }: PermissionDirectoryProps) {
  const [filter, setFilter] = useState<PermissionDirectoryFilter>({});
  return <Card title="权限目录" className="management-card embedded-idp-permission-directory">
    <Typography.Paragraph type="secondary">权限定义只属于当前租户。业务含义和调用时机由宿主决定；创建定义不会自动授予角色。</Typography.Paragraph>
    <Form name="permission-directory-filter" layout="inline" className="management-filter" onFinish={(values: { resource_type?: string; category?: DirectoryPermission["category"]; enabled?: "true" | "false" }) => setFilter({
      ...(values.resource_type?.trim() ? { resource_type: values.resource_type.trim() } : {}), ...(values.category ? { category: values.category } : {}),
      ...(values.enabled ? { enabled: values.enabled === "true" } : {}),
    })}>
      <Form.Item name="resource_type" label="资源类型" rules={[{ pattern: nameRule, message: "请输入有效资源类型" }]}><Input allowClear maxLength={64} /></Form.Item>
      <Form.Item name="category" label="类别"><Select allowClear style={{ minWidth: 155 }} options={Object.entries(categories).map(([value, label]) => ({ value, label }))} /></Form.Item>
      <Form.Item name="enabled" label="状态"><Select allowClear style={{ minWidth: 100 }} options={[{ value: "true", label: "启用" }, { value: "false", label: "停用" }]} /></Form.Item>
      <Button htmlType="submit">查询</Button>
    </Form>
    <DirectoryTable key={`${tenant}:${JSON.stringify(filter)}`} client={client} tenant={tenant} filter={filter} />
  </Card>;
}
