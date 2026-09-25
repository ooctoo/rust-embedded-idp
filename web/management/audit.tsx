import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Descriptions, Drawer, Form, Input, Table, Typography } from "antd";
import { ManagementClient, ManagementError, type AuditDetail, type AuditFilter, type AuditRecord } from "./client";
import { useCursorPage } from "./pagination";

const failure = (reason: unknown) => reason instanceof ManagementError ? reason.message : "读取审计记录失败，请重试。";
const time = (value: number) => new Date(value * 1000).toLocaleString("zh-CN");
const domain = (value: string, tenancyEnabled?: boolean) => tenancyEnabled ? value === "0" ? "平台" : value : "当前系统";
const unix = (value?: string) => {
  if (!value) return undefined;
  const seconds = Math.floor(new Date(value).getTime() / 1000);
  return Number.isSafeInteger(seconds) && seconds >= 0 ? seconds : undefined;
};

function AuditDetailDrawer({ client, tenant, platformScope, auditId, close }: {
  client: ManagementClient; tenant: string; platformScope: boolean; auditId: string; close: () => void;
}) {
  const [detail, setDetail] = useState<AuditDetail>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const reloadButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    let active = true;
    setLoading(true); setDetail(undefined); setError("");
    const request = platformScope ? client.getPlatformAuditEvent(auditId) : client.getAuditEvent(tenant, auditId);
    request.then(value => { if (active) setDetail(value); })
      .catch(reason => { if (active) setError(failure(reason)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, tenant, platformScope, auditId, attempt]);
  return <Drawer rootClassName="management-overlay" open title="审计记录详情" width={720}
    onClose={close}>
    {error && <Alert type="error" role="alert" message={error} description="记录详情可能已变化，请重新加载后核对。" />}
    <Button ref={reloadButton} disabled={loading} onClick={() => setAttempt(value => value + 1)}>重新加载详情</Button>
    {loading ? <Card loading /> : detail && <>
      <Descriptions className="management-note" column={1} bordered size="small">
        <Descriptions.Item label="审计 ID">{detail.audit_id}</Descriptions.Item>
        <Descriptions.Item label="发生时间">{time(detail.occurred_at_unix_secs)}</Descriptions.Item>
        <Descriptions.Item label="目标域">{domain(detail.target_domain, client.getSnapshot().capabilities?.tenancy_enabled)}</Descriptions.Item>
        <Descriptions.Item label="操作者">{detail.actor_id}</Descriptions.Item>
        <Descriptions.Item label="操作者域">{domain(detail.actor_domain, client.getSnapshot().capabilities?.tenancy_enabled)}</Descriptions.Item>
        <Descriptions.Item label="会话">{detail.actor_session_id ?? "无"}</Descriptions.Item>
        <Descriptions.Item label="认证来源">{detail.authentication_source}</Descriptions.Item>
        <Descriptions.Item label="操作">{detail.operation}</Descriptions.Item>
        <Descriptions.Item label="请求 ID">{detail.request_id}</Descriptions.Item>
      </Descriptions>
      <Typography.Title level={5}>变更内容</Typography.Title>
      <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", margin: 0 }} aria-label="审计变更内容">
        {JSON.stringify(detail.change, null, 2)}
      </pre>
    </>}
  </Drawer>;
}

function AuditTable({ client, tenant, platformScope, filter }: {
  client: ManagementClient; tenant: string; platformScope: boolean; filter: AuditFilter;
}) {
  const load = useCallback((cursor?: string) => platformScope
    ? client.listPlatformAuditEvents(filter, cursor)
    : client.listAuditEvents(tenant, filter, cursor), [client, tenant, platformScope, filter]);
  const result = useCursorPage(load);
  const [selected, setSelected] = useState<string>();
  const trigger = useRef<HTMLElement | null>(null);
  const close = () => {
    setSelected(undefined);
    requestAnimationFrame(() => trigger.current?.focus());
  };
  return <>
    {result.error && <Alert type="error" role="alert" message={result.error} action={<Button onClick={result.reload}>重试</Button>} />}
    <Table<AuditRecord> rowKey="audit_id" dataSource={result.page?.items ?? []} loading={result.loading} pagination={false} scroll={{ x: 1080 }}
      locale={{ emptyText: result.error ? "未能读取审计记录" : "没有符合条件的审计记录" }} columns={[
        { title: "发生时间", dataIndex: "occurred_at_unix_secs", render: (value: number) => time(value) },
        { title: "目标域", dataIndex: "target_domain", render: (value: string) => domain(value, client.getSnapshot().capabilities?.tenancy_enabled) },
        { title: "操作者", dataIndex: "actor_id" },
        { title: "操作", dataIndex: "operation" },
        { title: "请求 ID", dataIndex: "request_id" },
        { title: "查看", key: "detail", render: (_, record) => <Button aria-label={`查看审计记录 ${record.audit_id}`} onClick={event => { trigger.current = event.currentTarget; setSelected(record.audit_id); }}>详情</Button> },
      ]} />
    <div className="management-note"><Typography.Text type="secondary">每页最多 50 条记录，按服务端游标翻页。</Typography.Text></div>
    {result.controls}
    {selected && <AuditDetailDrawer client={client} tenant={tenant} platformScope={platformScope} auditId={selected} close={close} />}
  </>;
}

export function AuditManagement({ client, tenant, platformScope = false }: { client: ManagementClient; tenant: string; platformScope?: boolean }) {
  const [filter, setFilter] = useState<AuditFilter>({});
  const [filterError, setFilterError] = useState("");
  const scopeLabel = platformScope ? "平台" : client.getSnapshot().capabilities?.tenancy_enabled ? tenant : "当前系统";
  return <Card title="审计记录" className="management-card">
    <Typography.Paragraph type="secondary">查看“{scopeLabel}”范围内的审计记录。记录按目标域查询，不会混合不同租户的数据。</Typography.Paragraph>
    <Form name={`audit-filter-${platformScope ? "platform" : tenant}`} layout="inline" className="management-filter"
      onFinish={(values: { actor_id?: string; operation?: string; occurred_after?: string; occurred_before?: string }) => {
        const after = unix(values.occurred_after), before = unix(values.occurred_before);
        if ((values.occurred_after && after === undefined) || (values.occurred_before && before === undefined) ||
          (after !== undefined && before !== undefined && after > before)) {
          setFilterError("时间范围无效：起始时间不能晚于结束时间。");
          return;
        }
        setFilterError("");
        setFilter({ ...(values.actor_id?.trim() ? { actor_id: values.actor_id.trim() } : {}),
          ...(values.operation?.trim() ? { operation: values.operation.trim() } : {}),
          ...(after !== undefined ? { occurred_after_unix_secs: after } : {}),
          ...(before !== undefined ? { occurred_before_unix_secs: before } : {}) });
      }}>
      <Form.Item name="actor_id" label="操作者" rules={[{ pattern: /^[A-Za-z0-9_.-]{1,128}$/, message: "请输入有效操作者 ID" }]}><Input allowClear maxLength={128} /></Form.Item>
      <Form.Item name="operation" label="操作" rules={[{ pattern: /^[a-z][a-z0-9_.-]{0,63}$/, message: "请输入有效操作标识" }]}><Input allowClear maxLength={64} /></Form.Item>
      <Form.Item name="occurred_after" label="起始时间"><Input type="datetime-local" /></Form.Item>
      <Form.Item name="occurred_before" label="结束时间"><Input type="datetime-local" /></Form.Item>
      <Button htmlType="submit">查询</Button>
    </Form>
    {filterError && <Alert type="error" role="alert" message={filterError} />}
    <AuditTable key={`${platformScope ? "platform" : tenant}:${JSON.stringify(filter)}`} client={client} tenant={tenant} platformScope={platformScope} filter={filter} />
  </Card>;
}
