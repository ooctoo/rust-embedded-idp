import { useCallback, useEffect, useId, useRef, useState } from "react";
import { Alert, Button, Card, Drawer, Form, Input, Select, Space, Table, Tag, Typography } from "antd";
import { ManagementClient, type DeviceFilter, type ManagedDevice, type ManagedDeviceBinding } from "./client";
import { useCursorPage } from "./pagination";
import { discardChanges, ReadState, SafeConfirm, useWriteFeedback, WriteFeedback } from "./workflow";

const statusLabel = { pending: "待登记", active: "有效", disabled: "已停用", revoked: "已撤销" };
const bindingStatusLabel = { active: "有效", suspended: "已暂停", unbound: "已解绑" };
const time = (value: number | null) => value === null ? "从未" : new Date(value * 1000).toLocaleString("zh-CN");
const validReason = (value: string) => { const trimmed = value.trim(); return !!trimmed && new TextEncoder().encode(trimmed).length <= 512 && !/[\u0000-\u001f\u007f]/.test(trimmed); };
const unix = (value?: string) => {
  if (!value) return undefined;
  const seconds = Math.floor(new Date(value).getTime() / 1000);
  return Number.isSafeInteger(seconds) && seconds >= 0 ? seconds : undefined;
};

function DeviceBindings({ client, tenant, deviceId, parentBusy, onGuard }: { client: ManagementClient; tenant: string; deviceId: string; parentBusy: boolean; onGuard: (busy: boolean, dirty: boolean) => void }) {
  const load = useCallback((cursor?: string) => client.listDeviceBindings(tenant, deviceId, cursor), [client, tenant, deviceId]);
  const result = useCursorPage(load);
  const [target, setTarget] = useState<ManagedDeviceBinding>();
  const [original, setOriginal] = useState<ManagedDeviceBinding>();
  const [reason, setReason] = useState("");
  const [reading, setReading] = useState(false);
  const [readError, setReadError] = useState<unknown>();
  const [current, setCurrent] = useState<ManagedDeviceBinding>();
  const [readDone, setReadDone] = useState(false);
  const write = useWriteFeedback(client);
  const alive = useRef(true), pendingRead = useRef(false), trigger = useRef<HTMLElement | null>(null);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => { onGuard(write.busy, reading || !!target || write.blocked); return () => onGuard(false, false); }, [write.busy, reading, target, write.blocked, onGuard]);
  const read = async (binding: ManagedDeviceBinding, selecting = false) => {
    if (pendingRead.current || write.busy || parentBusy) return;
    pendingRead.current = true; setReading(true); setReadError(undefined); setCurrent(undefined); setReadDone(false);
    try {
      const value = await client.getDeviceBinding(tenant, deviceId, binding.binding_id);
      if (!alive.current) return;
      setCurrent(value);
      if (selecting) { if (value.status !== "unbound") { setTarget(value); setReason(""); } else result.reload(); }
      else { setReadDone(true); setTarget(undefined); setReason(""); result.reload(); }
    } catch (error) { if (alive.current) setReadError(error); }
    finally { pendingRead.current = false; if (alive.current) setReading(false); }
  };
  const cancel = () => { if (!write.busy && discardChanges(!!reason || write.blocked)) { setTarget(undefined); setReason(""); } };
  return <Card title="人员设备绑定" className="management-card">
    <Typography.Paragraph type="secondary">解绑仅撤销选中人员在此设备上的凭证，不影响其他用户的绑定。</Typography.Paragraph>
    <WriteFeedback state={write} />
    {original && write.blocked && <><Typography.Paragraph>待核对原绑定：{tenant} / {deviceId} / {original.binding_id}，用户 {original.account_id}。页面未取得完整结果；回读显示当前状态，不能证明请求归因。</Typography.Paragraph><Button disabled={reading || write.busy || parentBusy} onClick={() => void read(original)}>重新读取原绑定</Button></>}
    {current && write.blocked && <Typography.Paragraph>当前绑定：{current.binding_id}，{bindingStatusLabel[current.status]}，版本 {current.version}。</Typography.Paragraph>}
    {write.blocked && readDone && <Button onClick={() => { write.recovered(); setReadDone(false); }}>结束绑定核对</Button>}
    <ReadState loading={reading} error={readError} retry={original ? () => void read(original) : undefined} saved={!!write.success} />
    <ReadState loading={result.loading} error={result.error} status={result.errorStatus} retry={result.reload} saved={!!write.success} empty={!result.page?.items.length} emptyText="暂无人员绑定">
      <Table<ManagedDeviceBinding> rowKey="binding_id" dataSource={result.page?.items} pagination={false} scroll={{ x: 620 }} columns={[
        { title: "用户 ID", dataIndex: "account_id" },
        { title: "状态", dataIndex: "status", render: (status: ManagedDeviceBinding["status"]) => <Tag>{bindingStatusLabel[status]}</Tag> },
        { title: "绑定时间", dataIndex: "bound_at_unix_secs", render: (value: number) => time(value) },
        { title: "版本", dataIndex: "version" },
        { title: "操作", render: (_, binding) => binding.status !== "unbound" && <Button danger disabled={parentBusy || reading || write.busy || write.blocked || !!target} onClick={event => { trigger.current = event.currentTarget; void read(binding, true); }} aria-label={`解绑用户 ${binding.account_id} 的设备绑定`}>解绑</Button> },
      ]} />
    </ReadState>{result.controls}
    <SafeConfirm open={!!target} title="确认解绑人员设备" okText="确认解绑" cancelText="取消" confirmLoading={write.busy} okButtonProps={{ danger: true, disabled: write.blocked || !validReason(reason) }} onCancel={cancel} onOk={async () => {
      if (!target || !validReason(reason) || pendingRead.current) return;
      const binding = target; setOriginal(binding);
      const response = await write.run(() => client.unbindDeviceBinding(tenant, binding, reason), `已确认解绑：${tenant} / ${deviceId}，用户 ${binding.account_id}，绑定 ${binding.binding_id}。`);
      if (!alive.current) return;
      setTarget(undefined); setReason("");
      if (response.ok) { setCurrent(response.value); result.reload(); requestAnimationFrame(() => trigger.current?.focus()); }
    }}>
      <Typography.Paragraph>租户：{tenant}<br />设备：{deviceId}<br />用户：{target?.account_id}<br />绑定：{target?.binding_id}<br />原状态：{target && bindingStatusLabel[target.status]}（版本 {target?.version}）</Typography.Paragraph>
      <Alert type="warning" message="仅解绑此人员设备关系，撤销该人员在此设备上的凭证。" />
      <Input.TextArea aria-label="解绑原因" placeholder="填写解绑原因" value={reason} onChange={event => setReason(event.target.value)} maxLength={512} showCount rows={3} disabled={write.busy} />
      {reason && !validReason(reason) && <Alert type="error" message="原因去除首尾空白后须非空、最多 512 UTF-8 字节且不能包含控制字符。" />}
    </SafeConfirm>
  </Card>;
}

function DeviceDrawer({ client, tenant, deviceId, close }: { client: ManagementClient; tenant: string; deviceId: string; close: () => void }) {
  const [device, setDevice] = useState<ManagedDevice>();
  const [attempt, setAttempt] = useState(0), [loading, setLoading] = useState(true);
  const [readError, setReadError] = useState<unknown>();
  const [readDone, setReadDone] = useState(false);
  const [target, setTarget] = useState<"active" | "disabled" | "revoked">();
  const [reason, setReason] = useState("");
  const [child, setChild] = useState({ busy: false, dirty: false });
  const write = useWriteFeedback(client);
  const reloadButton = useRef<HTMLButtonElement>(null), alive = useRef(true);
  const onGuard = useCallback((busy: boolean, dirty: boolean) => setChild({ busy, dirty }), []);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    let active = true; setLoading(true); setDevice(undefined); setReadError(undefined); setReadDone(false);
    client.getDevice(tenant, deviceId).then(value => { if (active) { setDevice(value); if (write.blocked) setReadDone(true); else write.recovered(); } })
      .catch(error => { if (active) setReadError(error); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, tenant, deviceId, attempt]);
  const busy = write.busy || child.busy;
  const reload = () => { if (!busy && !loading && !child.dirty && discardChanges(!!target || write.blocked)) { setTarget(undefined); setReason(""); setAttempt(v => v + 1); } };
  const leave = () => { if (!busy && discardChanges(!!target || !!reason || write.blocked || child.dirty)) close(); };
  return <Drawer rootClassName="management-overlay management-workflow-editor" open title="设备详情与状态" width={680} onClose={leave} closable={!busy && !target} keyboard={!busy && !target} maskClosable={false}>
    <WriteFeedback state={write} />
    {write.blocked && <Typography.Paragraph>待核对原设备：{tenant} / {deviceId}。页面未取得完整结果；原设备回读只能显示当前状态，不能证明请求归因。</Typography.Paragraph>}
    <Button ref={reloadButton} disabled={loading || busy || child.dirty} onClick={reload}>重新加载设备</Button>
    {write.blocked && readDone && <Button onClick={() => { write.recovered(); setReadDone(false); }}>结束设备核对</Button>}
    <ReadState loading={loading} error={readError} retry={reload} saved={!!write.success}>
      {device && <>
        <Typography.Paragraph className="management-note">租户：{device.tenant_id}<br />设备：{device.device_name}（{device.device_id}）<br />客户端：{device.client_id}<br />证明密钥：{device.proof_key_id ?? "无"}（版本 {device.key_version ?? "无"}）<br />状态：{statusLabel[device.status]}（版本 {device.version}）<br />登记：{time(device.registered_at_unix_secs)}<br />最后使用：{time(device.last_seen_at_unix_secs)}</Typography.Paragraph>
        {device.status === "disabled" && !device.proof_key_id && <Alert type="warning" message="缺少证明密钥，不能重新启用。" description="请撤销此设备，并重新登记新的设备身份。" />}
        {device.status === "revoked" ? <Alert type="info" message="设备已撤销，不能恢复。" description="密钥已退役，所有用户绑定已解除。需要重新登记新设备。" /> : <Space wrap className="management-filter">
          {device.status === "disabled" && <Button disabled={busy || write.blocked || child.dirty || !device.proof_key_id} onClick={() => setTarget("active")}>重新启用</Button>}
          <Button disabled={busy || write.blocked || child.dirty || !["pending", "active"].includes(device.status)} onClick={() => setTarget("disabled")}>停用设备</Button>
          <Button danger disabled={busy || write.blocked || child.dirty || !["pending", "active", "disabled"].includes(device.status)} onClick={() => setTarget("revoked")}>撤销设备</Button>
        </Space>}
        <DeviceBindings client={client} tenant={tenant} deviceId={deviceId} parentBusy={write.busy || write.blocked || !!target} onGuard={onGuard} />
      </>}
    </ReadState>
    <SafeConfirm open={!!target} title={target === "active" ? "确认重新启用设备" : target === "disabled" ? "确认停用设备" : "确认撤销设备"} okText={target === "active" ? "确认启用" : target === "disabled" ? "确认停用" : "确认撤销"} cancelText="取消" confirmLoading={write.busy} okButtonProps={{ danger: target === "revoked", disabled: write.blocked || !validReason(reason) }} onCancel={() => { if (discardChanges(!!reason)) { setTarget(undefined); setReason(""); } }} onOk={async () => {
      if (!device || !target || !validReason(reason)) return;
      const before = device, desired = target;
      const response = await write.run(() => client.setDeviceStatus(tenant, before, desired, reason), `已确认设备状态变更：${tenant} / ${deviceId}，${statusLabel[before.status]} → ${statusLabel[desired]}。`);
      if (!alive.current) return;
      setTarget(undefined); setReason("");
      if (response.ok) { setDevice(response.value); setAttempt(v => v + 1); requestAnimationFrame(() => reloadButton.current?.focus()); }
    }}>
      <Typography.Paragraph>租户：{tenant}<br />设备：{device?.device_name}（{deviceId}）<br />客户端：{device?.client_id}<br />原状态：{device && statusLabel[device.status]}（版本 {device?.version}）<br />目标状态：{target && statusLabel[target]}</Typography.Paragraph>
      <Input.TextArea aria-label="操作原因" placeholder="填写操作原因" value={reason} onChange={event => setReason(event.target.value)} maxLength={512} showCount rows={3} disabled={write.busy} />
      {reason && !validReason(reason) && <Alert type="error" message="原因去除首尾空白后须非空、最多 512 UTF-8 字节且不能包含控制字符。" />}
      <Alert type="warning" showIcon message={target === "active" ? "重新启用后仍需重新登录。" : target === "disabled" ? "停用会撤销此设备关联的所有用户会话和凭证。" : "撤销会使所有绑定用户的凭证失效，并退役该设备密钥。"} description={target === "active" ? "旧会话和刷新凭证不会恢复；服务端还会检查密钥是否有效。" : target === "disabled" ? "保留设备记录、密钥和绑定，但设备无法继续使用。" : "撤销后解除全部用户绑定，不能恢复；需重新登记设备。"} />
    </SafeConfirm>
  </Drawer>;
}

function DeviceTable({ client, tenant, filter }: { client: ManagementClient; tenant: string; filter: DeviceFilter }) {
  const load = useCallback((cursor?: string) => client.listDevices(tenant, filter, cursor), [client, tenant, filter]);
  const result = useCursorPage(load);
  const [selected, setSelected] = useState<string>();
  const trigger = useRef<HTMLElement | null>(null);
  return <>
    <ReadState loading={result.loading} error={result.error} status={result.errorStatus} retry={result.reload} empty={!result.page?.items.length} emptyText="没有符合条件的设备">
      <Table<ManagedDevice> rowKey="device_id" dataSource={result.page?.items} pagination={false} scroll={{ x: 880 }} columns={[
        { title: "设备", render: (_, d) => <>{d.device_name}<br /><Typography.Text type="secondary">{d.device_id}</Typography.Text></> },
        { title: "客户端", dataIndex: "client_id" }, { title: "状态", dataIndex: "status", render: (status: ManagedDevice["status"]) => <Tag>{statusLabel[status]}</Tag> },
        { title: "登记时间", dataIndex: "registered_at_unix_secs", render: (value: number) => time(value) },
        { title: "操作", render: (_, d) => <Button onClick={event => { trigger.current = event.currentTarget; setSelected(d.device_id); }} aria-label={`查看设备 ${d.device_name}`}>详情</Button> },
      ]} />
    </ReadState>{result.controls}
    {selected && <DeviceDrawer key={`${tenant}:${selected}`} client={client} tenant={tenant} deviceId={selected} close={() => { setSelected(undefined); result.reload(); requestAnimationFrame(() => trigger.current?.focus()); }} />}
  </>;
}

export function DeviceManagement({ client, tenant }: { client: ManagementClient; tenant: string }) {
  const [filter, setFilter] = useState<DeviceFilter>({}), [revision, setRevision] = useState(0), [error, setError] = useState("");
  const [form] = Form.useForm(); const id = useId();
  return <Card title="设备管理" className="management-card management-workflow-page">
    <Typography.Paragraph type="secondary">{client.getSnapshot().capabilities?.tenancy_enabled ? "设备归属当前租户。" : "管理本系统的设备。"}停用或撤销都会使其关联用户的凭证失效；撤销同时退役密钥并解除绑定，不能恢复。</Typography.Paragraph>
    {error && <Alert type="error" role="alert" message={error} />}
    <Form form={form} name={`device-filter-${id}`} layout="inline" className="management-filter" onFinish={(values: { account_id?: string; client_id?: string; status?: ManagedDevice["status"]; registered_after?: string; registered_before?: string }) => {
      const after = unix(values.registered_after), before = unix(values.registered_before);
      if ((values.registered_after && after === undefined) || (values.registered_before && before === undefined) || (after !== undefined && before !== undefined && after > before)) { setError("登记时间范围无效：起始时间不能晚于结束时间。"); return; }
      setError(""); setFilter({ ...(values.account_id?.trim() ? { account_id: values.account_id.trim() } : {}), ...(values.client_id?.trim() ? { client_id: values.client_id.trim() } : {}), ...(values.status ? { status: values.status } : {}), ...(after !== undefined ? { registered_after_unix_secs: after } : {}), ...(before !== undefined ? { registered_before_unix_secs: before } : {}) }); setRevision(v => v + 1);
    }}>
      <Form.Item name="account_id" label="用户 ID"><Input allowClear maxLength={128} /></Form.Item><Form.Item name="client_id" label="客户端 ID"><Input allowClear maxLength={128} /></Form.Item>
      <Form.Item name="status" label="状态"><Select allowClear style={{ minWidth: 110 }} options={Object.entries(statusLabel).map(([value, label]) => ({ value, label }))} /></Form.Item>
      <Form.Item name="registered_after" label="登记起始"><Input type="datetime-local" /></Form.Item><Form.Item name="registered_before" label="登记结束"><Input type="datetime-local" /></Form.Item><Button htmlType="submit">查询</Button><Button onClick={() => { form.resetFields(); setError(""); setFilter({}); setRevision(v => v + 1); }}>重置</Button>
    </Form>
    <DeviceTable key={`${tenant}:${JSON.stringify(filter)}:${revision}`} client={client} tenant={tenant} filter={filter} />
  </Card>;
}
