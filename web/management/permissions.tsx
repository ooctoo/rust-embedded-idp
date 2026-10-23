import { useCallback, useEffect, useId, useRef, useState } from "react";
import { Alert, Button, Form, Input, Modal, Space, Table, Typography } from "antd";
import { ManagementClient, type PermissionDefinition, type PermissionKey, type RoleDetail } from "./client";
import { useCursorPage } from "./pagination";
import { discardChanges, ReadState, SafeConfirm } from "./workflow";

const keyOf = (p: PermissionKey) => `${p.resource_type}::${p.action}`;

function Catalog({ client, tenant, business, filter, selected, setSelected, disabled }: {
  client: ManagementClient; tenant: string; business: string; filter: string; selected: PermissionKey[];
  setSelected: (next: PermissionKey[]) => void; disabled: boolean;
}) {
  const load = useCallback((cursor?: string) => client.listBusinessPermissions(tenant, business, filter, cursor), [client, tenant, business, filter]);
  const result = useCursorPage(load);
  return <>
    <ReadState loading={result.loading} error={result.error} status={result.errorStatus} retry={result.reload} empty={!result.page?.items.length} emptyText="暂无可添加的业务权限">
    <Table<PermissionDefinition> rowKey={keyOf} dataSource={result.page?.items ?? []} pagination={false} loading={result.loading} scroll={{ x: 440 }}
      locale={{ emptyText: result.error ? "权限目录读取失败" : "暂无可添加的业务权限" }} columns={[
        { title: "权限", render: (_, p) => <><Typography.Text strong>{keyOf(p)}</Typography.Text><br />{p.description}</> },
        { title: "操作", render: (_, p) => {
          const included = selected.some(item => keyOf(item) === keyOf(p));
          return <Button disabled={disabled || included || selected.length >= 200} onClick={() => setSelected([...selected, { business_id: business, resource_type: p.resource_type, action: p.action }])}>{included ? "已选择" : "添加"}</Button>;
        } },
      ]} />
    </ReadState>
    {!result.loading && !result.error && result.controls}
  </>;
}

export function RolePermissions({ client, tenant, business, role, busy, blocked, error, save, onDraftChange }: {
  client: ManagementClient; tenant: string; business: string; role: RoleDetail; busy: boolean; blocked: boolean; error: string;
  save: (permissions: PermissionKey[]) => Promise<boolean>; onDraftChange: (dirty: boolean) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [review, setReview] = useState(false);
  const formName = useId();
  const [selected, setSelected] = useState<PermissionKey[]>(role.permissions);
  const [filter, setFilter] = useState("");
  const [filterRevision, setFilterRevision] = useState(0);
  const removed = role.permissions.filter(p => !selected.some(item => keyOf(item) === keyOf(p)));
  const added = selected.filter(p => !role.permissions.some(item => keyOf(item) === keyOf(p)));
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => { onDraftChange(editing && (!!added.length || !!removed.length)); }, [editing, added.length, removed.length, onDraftChange]);
  const columns = [{ title: "资源类型", dataIndex: "resource_type" }, { title: "动作", dataIndex: "action" }];
  return <>
    <Typography.Title level={3}>角色权限</Typography.Title>
    <Typography.Paragraph type="secondary">{role.kind === "business_admin" ? "业务管理员按业务范围自动拥有全部有效权限。" : "角色定义资源类型与动作；具体资源范围由成员角色分配决定。"}</Typography.Paragraph>
    {role.kind !== "business_admin" && <Table scroll={{ x: 440 }} rowKey={keyOf} dataSource={role.permissions} columns={columns} pagination={{ pageSize: 10, showSizeChanger: false }} locale={{ emptyText: "此角色暂无权限" }} />}
    {role.kind === "business" && <Button disabled={busy || blocked} onClick={() => { setSelected(role.permissions); setEditing(true); }}>编辑权限集</Button>}
    <Modal rootClassName="management-overlay" open={editing} title={`编辑角色权限：${role.name}`} width={760} onCancel={() => { if (!busy && discardChanges(!!added.length || !!removed.length)) setEditing(false); }} maskClosable={false} keyboard={!busy} closable={!busy}
      okText="核对权限集" cancelText="取消" confirmLoading={busy} okButtonProps={{ disabled: blocked || !added.length && !removed.length }} cancelButtonProps={{ disabled: busy }}
      onOk={() => setReview(true)}>
      <Typography.Paragraph>目标域：{tenant} · 基于版本 {role.version}。最多 200 项。</Typography.Paragraph>
      {error && <Alert type="error" role="alert" showIcon message={error} description="请关闭此窗口，重新加载角色详情后核对。" />}
      <Alert type="warning" showIcon message="修改会影响已分配此角色的成员" description="移除某资源类型的全部权限，会同时撤销该类型的已有角色分配。重新添加权限不会恢复这些分配。" />
      <Form name={formName} layout="inline" className="management-filter" disabled={busy || blocked} onFinish={(values: { resource_type?: string }) => { setFilter(values.resource_type?.trim() ?? ""); setFilterRevision(v => v + 1); }}>
        <Form.Item label="资源类型" name="resource_type"><Input allowClear maxLength={64} /></Form.Item><Button htmlType="submit">筛选目录</Button>
      </Form>
      <Catalog key={`${filter}:${filterRevision}`} client={client} tenant={tenant} business={business} filter={filter} selected={selected} setSelected={setSelected} disabled={busy || blocked} />
      <Typography.Title level={4}>完整待保存集合（{selected.length} 项）</Typography.Title>
      <Table<PermissionKey> scroll={{ x: 440 }} rowKey={keyOf} dataSource={selected} pagination={{ pageSize: 5, showSizeChanger: false }} locale={{ emptyText: "保存后此角色将没有权限" }} columns={[
        ...columns, { title: "操作", render: (_, p) => <Button danger disabled={busy || blocked} onClick={() => setSelected(selected.filter(item => keyOf(item) !== keyOf(p)))}>移除</Button> },
      ]} />
      <Space direction="vertical" role="status"><Typography.Text>新增 {added.length} 项，移除 {removed.length} 项</Typography.Text>
        {removed.length > 0 && <Typography.Text type="danger">将移除：{removed.map(keyOf).join("、")}</Typography.Text>}</Space>
    </Modal>
    <SafeConfirm open={review && !blocked} title="确认替换角色权限集" okText="确认保存权限" cancelText="返回修改" confirmLoading={busy} onCancel={() => setReview(false)} onOk={async () => { const saved = await save(selected); if (alive.current) { setReview(false); if (saved) { setEditing(false); onDraftChange(false); } } }}>
      <Typography.Paragraph>目标域：{tenant} / {business}；角色：{role.name}（{role.key}，{role.role_id}）；版本 {role.version}。</Typography.Paragraph>
      <Typography.Paragraph>完整权限集：{selected.length ? selected.map(keyOf).join("、") : "空"}。</Typography.Paragraph>
      <Alert type="warning" showIcon message="移除某资源类型的最后一项权限会撤销该类型的已有角色分配，重新添加不会恢复分配。" />
    </SafeConfirm>
  </>;
}
