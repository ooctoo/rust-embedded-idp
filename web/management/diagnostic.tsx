import { useEffect, useId, useRef, useState } from "react";
import { Alert, Button, Card, Form, Input, Tag, Typography } from "antd";
import { ManagementClient, type DiagnosticInput, type DiagnosticResult } from "./client";
import { discardChanges, SafeConfirm, useWriteFeedback } from "./workflow";

const permissionName = /^[a-z][a-z0-9_.-]{0,63}$/;
const resourceId = /^[A-Za-z0-9_.-]{1,256}$/;

type Draft = DiagnosticInput;

function scopeLabel(input: DiagnosticInput) {
  return input.resource_id ? `具体资源 ${input.resource_id}` : "资源类型下的全部资源";
}

export function AccessDiagnostic({ client, tenant }: { client: ManagementClient; tenant: string }) {
  const [form] = Form.useForm<Draft>();
  const [draft, setDraft] = useState<Draft>();
  const [result, setResult] = useState<DiagnosticResult>();
  const write = useWriteFeedback(client);
  const formId = useId();
  const trigger = useRef<HTMLButtonElement>(null);
  const mounted = useRef(true);
  const tenancyEnabled = client.getSnapshot().capabilities?.tenancy_enabled;
  const targetLabel = tenancyEnabled ? tenant : "当前系统";

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  const submit = (values: Draft) => {
    setResult(undefined);
    setDraft({
      business_id: values.business_id.trim(),
      subject_id: values.subject_id.trim(),
      resource_type: values.resource_type.trim(),
      action: values.action.trim(),
      ...(values.resource_id?.trim() ? { resource_id: values.resource_id.trim() } : {}),
    });
  };

  const diagnose = async () => {
    if (!draft) return;
    const response = await write.run(() => client.diagnosePermission(tenant, draft.business_id, draft), `已确认诊断 ${tenant} / ${draft.business_id} / ${draft.subject_id}。`);
    if (mounted.current) { if (response.ok) setResult(response.value); setDraft(undefined); }
  };
  return <Card title="权限诊断" className="management-card management-workflow-page">
    <Typography.Paragraph type="secondary">
      查询指定用户在{tenancyEnabled ? "目标租户" : "当前系统"}中指定业务与资源范围内当前是否允许执行动作。每次查询都会写入审计记录，请确认后再提交。
    </Typography.Paragraph>
    <Alert type="info" showIcon message={`当前目标：${targetLabel}`} description={
      tenancyEnabled ? "诊断只针对当前目标租户生效，不会切换登录租户或修改授权。" : "诊断只针对当前系统生效，不会修改授权。"
    } />
    {write.success && <Alert type="success" role="status" message={write.success} />}
    {write.error && <Alert type="error" role="alert" message={write.error} description={write.outcome === "local" ? "本地校验未通过，未发送查询。" : "本次结果未确认或被拒绝，不会自动重试。"} />}
    {write.blocked && <Alert type="warning" message="本次诊断结果未确认或被拒绝" description="再次查询是新的操作，可能新增一条审计记录；不能据回读证明原请求结果。" action={<Button onClick={() => { if (discardChanges(true, "放弃本次结果核对并允许手动新查询？新查询可能新增审计记录。")) write.recovered(); }}>放弃并允许新查询</Button>} />}
    {result && <Card size="small" className="management-note" title="查询结果">
      <Typography.Paragraph>
        <Tag color={result.decision === "allow" ? "success" : "error"}>{result.decision === "allow" ? "允许" : "拒绝"}</Tag>
        <br />业务标识：{result.business_id}
        <br />用户：{result.subject_id}
        <br />权限：{result.resource_type}::{result.action}
        <br />范围：{result.resource_id === null ? "资源类型下的全部资源" : `具体资源 ${result.resource_id}`}
        <br />审计记录：<Typography.Text code copyable>{result.audit_id}</Typography.Text>
      </Typography.Paragraph>
      <Typography.Text type="secondary">这是查询时刻的判断结果，不代表永久授权，也不代表用户拥有该资源。</Typography.Text>
    </Card>}
    <Form<Draft> name={`permission-diagnostic-${formId}`} data-management-draft form={form} disabled={write.busy || write.blocked} layout="vertical" onValuesChange={() => { setResult(undefined); write.edit(); }} onFinish={submit}>
      <Form.Item name="business_id" label="业务标识" rules={[
        { required: true, message: "请输入业务标识" }, { pattern: permissionName, message: "请输入有效业务标识" },
        { validator: (_, value) => value === "idp" || value?.startsWith("idp.") ? Promise.reject(new Error("请选择业务权限标识")) : Promise.resolve() },
      ]}><Input maxLength={64} placeholder="例如 biz_test" /></Form.Item>
      <Form.Item name="subject_id" label="用户 ID" rules={[{ required: true, whitespace: true, message: "请输入用户 ID" }, { pattern: /^[A-Za-z0-9_.-]{1,128}$/, message: "用户 ID 最多 128 位，仅可使用字母、数字、点、下划线或连字符" }]}>
        <Input maxLength={128} autoComplete="off" />
      </Form.Item>
      <Form.Item name="resource_type" label="资源类型" rules={[{ required: true, message: "请输入资源类型" }, { pattern: permissionName, message: "请输入有效资源类型：小写字母开头，最多 64 位" }]}>
        <Input maxLength={64} placeholder="report" />
      </Form.Item>
      <Form.Item name="action" label="动作" rules={[{ required: true, message: "请输入动作" }, { pattern: permissionName, message: "请输入有效动作：小写字母开头，最多 64 位" }]}>
        <Input maxLength={64} placeholder="read" />
      </Form.Item>
      <Form.Item name="resource_id" label="资源 ID（可选）" extra="留空表示按资源类型查询；填写后只判断这一份资源。" rules={[{ max: 256, message: "资源 ID 不能超过 256 个字符" }, { pattern: resourceId, message: "资源 ID 仅可包含字母、数字、点、下划线或连字符，最多 256 位" }]}>
        <Input maxLength={256} />
      </Form.Item>
      <Button ref={trigger} type="primary" htmlType="submit">查询权限</Button>
    </Form>
    <SafeConfirm rootClassName="management-overlay" open={!!draft} title="确认权限诊断" okText="确认查询" cancelText="取消" confirmLoading={write.busy}
      okButtonProps={{ disabled: write.busy }} cancelButtonProps={{ disabled: write.busy }} closable={!write.busy} keyboard={!write.busy} maskClosable={false}
      focusTriggerAfterClose={false} afterClose={() => trigger.current?.focus()} onCancel={() => setDraft(undefined)} onOk={() => void diagnose()}>
      {draft && <>
        <Typography.Paragraph>
          目标：{targetLabel} / {draft.business_id}<br />用户：{draft.subject_id}<br />权限：{draft.resource_type}::{draft.action}<br />范围：{scopeLabel(draft)}
        </Typography.Paragraph>
        <Alert type="warning" showIcon message="本次查询会写入审计记录" description="结果只表示服务端在查询时刻的 Allow 或 Deny，不会授予权限，也不会修改任何角色或资源授权。" />
      </>}
    </SafeConfirm>
  </Card>;
}
