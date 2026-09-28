import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Drawer, Form, Input, Modal, Select, Space, Table, Tag, Typography } from "antd";
import { ManagementClient, ManagementError, type DeviceFilter, type ManagedDevice, type ManagedDeviceBinding } from "./client";
import { useCursorPage } from "./pagination";

const failure = (reason: unknown) => reason instanceof ManagementError ? reason.message : "操作失败，请重新加载后核对。";
const statusLabel = { pending: "待登记", active: "有效", disabled: "已停用", revoked: "已撤销" };
const bindingStatusLabel = { active: "有效", suspended: "已暂停", unbound: "已解绑" };
const time = (value: number | null) => value === null ? "从未" : new Date(value * 1000).toLocaleString("zh-CN");
const unix = (value?: string) => {
  if (!value) return undefined;
  const seconds = Math.floor(new Date(value).getTime() / 1000);
  return Number.isSafeInteger(seconds) && seconds >= 0 ? seconds : undefined;
};

function DeviceBindings({ client, tenant, deviceId }: { client: ManagementClient; tenant: string; deviceId: string }) {
  const load = useCallback((cursor?: string) => client.listDeviceBindings(tenant, deviceId, cursor), [client, tenant, deviceId]);
  const result = useCursorPage(load);
  const [target, setTarget] = useState<ManagedDeviceBinding>();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [error, setError] = useState("");
  const trigger = useRef<HTMLElement | null>(null);
  const select = async (binding: ManagedDeviceBinding) => {
    setBusy(true); setError("");
    try {
      const current = await client.getDeviceBinding(tenant, deviceId, binding.binding_id);
      if (current.status !== "unbound") { setTarget(current); setBlocked(false); }
      else result.reload();
    } catch (cause) { setError(failure(cause)); setBlocked(true); }
    finally { setBusy(false); }
  };
  const unbind = async () => {
    if (!target) return;
    setBusy(true); setError("");
    try {
      await client.unbindDeviceBinding(tenant, target, reason);
      setTarget(undefined); setReason(""); result.reload();
      requestAnimationFrame(() => trigger.current?.focus());
    } catch (cause) { setError(failure(cause)); setBlocked(true); }
    finally { setBusy(false); }
  };
  return <Card title="人员设备绑定" className="management-card">
    <Typography.Paragraph type="secondary">解绑只作用于选中的人员绑定，并撤销该人员在此设备上的登录凭证。</Typography.Paragraph>
    {(result.error || error) && <Alert type="error" role="alert" message={result.error || error} action={<Button onClick={() => { setError(""); result.reload(); }}>重新加载绑定</Button>} />}
    <Table<ManagedDeviceBinding> rowKey="binding_id" dataSource={result.page?.items ?? []} loading={result.loading || busy} pagination={false} scroll={{ x: 620 }} locale={{ emptyText: result.error ? "未能读取绑定" : "暂无人员绑定" }} columns={[
      { title: "用户 ID", dataIndex: "account_id" },
      { title: "状态", dataIndex: "status", render: (status: ManagedDeviceBinding["status"]) => <Tag>{bindingStatusLabel[status]}</Tag> },
      { title: "绑定时间", dataIndex: "bound_at_unix_secs", render: (value: number) => time(value) },
      { title: "版本", dataIndex: "version" },
      { title: "操作", render: (_, binding) => binding.status !== "unbound" && <Button danger disabled={busy} onClick={event => { trigger.current = event.currentTarget; void select(binding); }} aria-label={`解绑用户 ${binding.account_id} 的设备绑定`}>解绑</Button> },
    ]} />{result.controls}
    <Modal rootClassName="management-overlay" open={!!target} title="确认解绑人员设备" okText="确认解绑" okButtonProps={{ danger: true, disabled: blocked || !reason.trim() }} cancelText="取消" confirmLoading={busy}
      closable={!busy} keyboard={!busy} maskClosable={false} cancelButtonProps={{ disabled: busy }} onCancel={() => { setTarget(undefined); setReason(""); setError(""); setBlocked(false); result.reload(); }} onOk={() => void unbind()}>
      {error && <Alert type="error" role="alert" message={error} description="结果可能未确认；请取消并重新加载绑定后核对。" />}
      <Typography.Paragraph>用户：{target?.account_id}<br />设备：{deviceId}<br />绑定：{target?.binding_id}<br />状态：{target && bindingStatusLabel[target.status]}（版本 {target?.version}）</Typography.Paragraph>
      <Input.TextArea aria-label="解绑原因" placeholder="填写解绑原因" value={reason} onChange={event => setReason(event.target.value)} maxLength={512} showCount rows={3} disabled={busy} />
    </Modal>
  </Card>;
}

function DeviceDrawer({ client, tenant, deviceId, close }: { client: ManagementClient; tenant: string; deviceId: string; close: () => void }) {
  const [device, setDevice] = useState<ManagedDevice>();
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [error, setError] = useState("");
  const [target, setTarget] = useState<"active" | "disabled" | "revoked">();
  const [reason, setReason] = useState("");
  const reloadButton = useRef<HTMLButtonElement>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    let active = true;
    setLoading(true); setDevice(undefined); setError("");
    client.getDevice(tenant, deviceId).then(value => { if (active) { setDevice(value); setBlocked(false); } })
      .catch(reason => { if (active) setError(failure(reason)); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, tenant, deviceId, attempt]);
  const change = async () => {
    if (!device || !target) return;
    setBusy(true); setError("");
    try {
      await client.setDeviceStatus(tenant, device, target, reason);
      if (mounted.current) { setTarget(undefined); setReason(""); setAttempt(v => v + 1); requestAnimationFrame(() => reloadButton.current?.focus()); }
    } catch (reason) { if (mounted.current) { setError(failure(reason)); setBlocked(true); } }
    finally { if (mounted.current) setBusy(false); }
  };
  return <Drawer rootClassName="management-overlay" open title="设备详情与状态" width={680} onClose={close} closable={!busy} keyboard={!busy} maskClosable={!busy}>
    {error && <Alert type="error" role="alert" message={error} description="请重新加载详情后再操作。" />}
    <Button ref={reloadButton} disabled={loading || busy} onClick={() => setAttempt(v => v + 1)}>重新加载设备</Button>
    {loading ? <Card loading /> : device && <>
      <Typography.Paragraph className="management-note">{client.getSnapshot().capabilities?.tenancy_enabled && <>租户：{device.tenant_id}<br /></>}设备：{device.device_name}（{device.device_id}）<br />客户端：{device.client_id}<br />证明密钥：{device.proof_key_id ?? "无"}（版本 {device.key_version ?? "无"}）<br />状态：{statusLabel[device.status]}（版本 {device.version}）<br />登记：{time(device.registered_at_unix_secs)}<br />最后使用：{time(device.last_seen_at_unix_secs)}</Typography.Paragraph>
      {device.status === "disabled" && !device.proof_key_id && <Alert type="warning" message="缺少证明密钥，不能重新启用。" description="请撤销此设备，并重新登记新的设备身份。" />}
      {device.status === "revoked" ? <Alert type="info" message="设备已撤销，不能恢复。" description="密钥已退役，所有用户绑定已解除。需要重新登记新设备。" /> : <Space wrap className="management-filter">
        {device.status === "disabled" && <Button disabled={busy || blocked || !device.proof_key_id} onClick={() => setTarget("active")}>重新启用</Button>}
        <Button disabled={busy || blocked || !["pending", "active"].includes(device.status)} onClick={() => setTarget("disabled")}>停用设备</Button>
        <Button danger disabled={busy || blocked || !["pending", "active", "disabled"].includes(device.status)} onClick={() => setTarget("revoked")}>撤销设备</Button>
      </Space>}
      <DeviceBindings client={client} tenant={tenant} deviceId={deviceId} />
    </>}
    <Modal rootClassName="management-overlay" open={!!target} title={target === "active" ? "确认重新启用设备" : target === "disabled" ? "确认停用设备" : "确认撤销设备"} okText={target === "active" ? "确认启用" : target === "disabled" ? "确认停用" : "确认撤销"} cancelText="取消" confirmLoading={busy}
      okButtonProps={{ danger: target === "revoked", disabled: blocked || !reason.trim() }} cancelButtonProps={{ disabled: busy }} closable={!busy} keyboard={!busy} maskClosable={false} onCancel={() => { setTarget(undefined); setReason(""); }} onOk={() => void change()}>
      {error && <Alert type="error" role="alert" message={error} description="请取消并重新加载当前设备状态。" />}
      <Typography.Paragraph>{client.getSnapshot().capabilities?.tenancy_enabled && <>租户：{tenant}<br /></>}设备：{device?.device_name}（{device?.device_id}）<br />客户端：{device?.client_id}<br />目标状态：{target && statusLabel[target]}</Typography.Paragraph>
      <Input.TextArea aria-label="操作原因" placeholder="填写操作原因" value={reason} onChange={event => setReason(event.target.value)} maxLength={512} showCount rows={3} disabled={busy} />
      <Alert type="warning" showIcon message={target === "active" ? "重新启用后仍需重新登录。" : target === "disabled" ? "停用会撤销此设备关联的所有用户会话和凭证。" : "撤销会使所有绑定用户的凭证失效，并退役该设备密钥。"}
        description={target === "active" ? "旧会话和刷新凭证不会恢复。" : target === "disabled" ? "保留设备记录、密钥和绑定，但设备无法继续使用。" : "撤销后解除全部用户绑定，不能恢复；需重新登记设备。"} />
    </Modal>
  </Drawer>;
}

function DeviceTable({ client, tenant, filter }: { client: ManagementClient; tenant: string; filter: DeviceFilter }) {
  const load = useCallback((cursor?: string) => client.listDevices(tenant, filter, cursor), [client, tenant, filter]);
  const result = useCursorPage(load);
  const [selected, setSelected] = useState<string>();
  const trigger = useRef<HTMLElement | null>(null);
  return <>
    {result.error && <Alert type="error" role="alert" message={result.error} action={<Button onClick={result.reload}>重试</Button>} />}
    <Table<ManagedDevice> rowKey="device_id" dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 880 }} locale={{ emptyText: result.error ? "未能读取设备" : "没有符合条件的设备" }} columns={[
      { title: "设备", render: (_, d) => <>{d.device_name}<br /><Typography.Text type="secondary">{d.device_id}</Typography.Text></> },
      { title: "客户端", dataIndex: "client_id" },
      { title: "状态", dataIndex: "status", render: (status: ManagedDevice["status"]) => <Tag>{statusLabel[status]}</Tag> },
      { title: "登记时间", dataIndex: "registered_at_unix_secs", render: (value: number) => time(value) },
      { title: "操作", render: (_, d) => <Button onClick={event => { trigger.current = event.currentTarget; setSelected(d.device_id); }} aria-label={`查看设备 ${d.device_name}`}>详情</Button> },
    ]} />{result.controls}
    {selected && <DeviceDrawer client={client} tenant={tenant} deviceId={selected} close={() => { setSelected(undefined); result.reload(); requestAnimationFrame(() => trigger.current?.focus()); }} />}
  </>;
}

export function DeviceManagement({ client, tenant }: { client: ManagementClient; tenant: string }) {
  const [filter, setFilter] = useState<DeviceFilter>({});
  const [error, setError] = useState("");
  return <Card title="设备管理" className="management-card">
    <Typography.Paragraph type="secondary">{client.getSnapshot().capabilities?.tenancy_enabled ? "设备归属当前租户。" : "管理本系统的设备。"}停用或撤销都会使其关联用户的凭证失效；撤销同时退役密钥并解除绑定，不能恢复。</Typography.Paragraph>
    {error && <Alert type="error" role="alert" message={error} />}
    <Form name="device-filter" layout="inline" className="management-filter" onFinish={(values: { account_id?: string; client_id?: string; status?: ManagedDevice["status"]; registered_after?: string; registered_before?: string }) => {
      const after = unix(values.registered_after), before = unix(values.registered_before);
      if ((values.registered_after && after === undefined) || (values.registered_before && before === undefined) || (after !== undefined && before !== undefined && after > before)) { setError("登记时间范围无效：起始时间不能晚于结束时间。"); return; }
      setError(""); setFilter({ ...(values.account_id?.trim() ? { account_id: values.account_id.trim() } : {}), ...(values.client_id?.trim() ? { client_id: values.client_id.trim() } : {}), ...(values.status ? { status: values.status } : {}), ...(after !== undefined ? { registered_after_unix_secs: after } : {}), ...(before !== undefined ? { registered_before_unix_secs: before } : {}) });
    }}>
      <Form.Item name="account_id" label="用户 ID"><Input allowClear maxLength={128} /></Form.Item><Form.Item name="client_id" label="客户端 ID"><Input allowClear maxLength={128} /></Form.Item>
      <Form.Item name="status" label="状态"><Select allowClear style={{ minWidth: 110 }} options={Object.entries(statusLabel).map(([value, label]) => ({ value, label }))} /></Form.Item>
      <Form.Item name="registered_after" label="登记起始"><Input type="datetime-local" /></Form.Item><Form.Item name="registered_before" label="登记结束"><Input type="datetime-local" /></Form.Item><Button htmlType="submit">查询</Button>
    </Form>
    <DeviceTable key={`${tenant}:${JSON.stringify(filter)}`} client={client} tenant={tenant} filter={filter} />
  </Card>;
}
