import { useEffect, useId, useRef, useState } from "react";
import { Alert, Button, Empty, Modal, Result, Space, Spin, type ModalProps } from "antd";
import { ManagementError, type ManagementClient } from "./client";

export const failureMessage = (reason: unknown) => reason instanceof ManagementError ? reason.message : "操作未完成，请重新读取原对象后核对。";
export function discardChanges(dirty: boolean, message = "离开会清除未保存内容。若写入结果未确认，请先核对原对象；确认继续？") {
  return !dirty || window.confirm(message);
}

// UI feedback only: authentication, mutation accounting and response checks stay in the client.
export function useWriteFeedback(client: Pick<ManagementClient, "getSnapshot"> & Partial<Pick<ManagementClient, "getMutationSnapshot">>) {
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [outcome, setOutcome] = useState<"local" | "rejected" | "unknown">();
  const alive = useRef(true), pending = useRef(false), locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  async function run<T>(operation: () => Promise<T>, message: string): Promise<{ ok: true; value: T } | { ok: false }> {
    if (pending.current || locked.current) return { ok: false };
    const before = client.getMutationSnapshot?.().revision;
    pending.current = true; setBusy(true); setError(""); setSuccess(""); setOutcome(undefined);
    try {
      const value = await operation();
      if (!alive.current) return { ok: false };
      setSuccess(message); return { ok: true, value };
    } catch (reason) {
      if (alive.current) {
        const sent = before === undefined || client.getMutationSnapshot?.().revision !== before;
        locked.current = sent; setBlocked(sent); setError(failureMessage(reason));
        setOutcome(!sent ? "local" : reason instanceof ManagementError && reason.status > 0 && reason.status < 500 ? "rejected" : "unknown");
      }
      return { ok: false };
    } finally { pending.current = false; if (alive.current) setBusy(false); }
  }
  return { busy, blocked, error, success, outcome, run,
    recovered: () => { locked.current = false; setBlocked(false); setError(""); },
    edit: () => setSuccess(""),
  };
}

export function WriteFeedback({ state }: { state: ReturnType<typeof useWriteFeedback> }) {
  return <>
    {state.success && <Alert type="success" role="status" showIcon message={state.success} />}
    {state.outcome === "unknown" && <Alert type="warning" role="alert" showIcon message="写入结果未确认，请先核对原对象，勿重复提交"
      description="回读只能显示当前状态，不能证明密码等敏感值或请求归因；不要自动重放。" />}
    {state.error && <Alert type="error" role="alert" showIcon message={state.error}
      description={state.outcome === "local" ? "本地校验未通过，未发送写请求。" : "请重新读取原对象核对后再操作；冲突不代表某一种特定原因。"} />}
  </>;
}

export function ReadState({ loading, error, status, empty, emptyText, retry, saved, children }: {
  loading?: boolean; error?: unknown; status?: number; empty?: boolean; emptyText?: string; retry?: () => void; saved?: boolean; children?: React.ReactNode;
}) {
  if (loading) return <Space role="status" className="management-workflow-loading"><Spin />正在读取…</Space>;
  if (error) {
    const code = status ?? (error instanceof ManagementError ? error.status : undefined);
    return <div role="alert"><Result status={code === 403 ? "403" : code === 404 ? "404" : "error"}
      title={saved ? "写入已确认，重新读取失败" : code === 403 ? "无权读取此管理范围" : code === 404 ? "对象不存在或不可见" : "读取失败"}
      subTitle={typeof error === "string" ? error : failureMessage(error)} extra={retry && <Button onClick={retry}>重新读取</Button>} /></div>;
  }
  if (empty) return <Empty description={emptyText ?? "暂无符合条件的数据，请调整筛选。"} />;
  return <>{children}</>;
}

export function SafeConfirm({ children, rootClassName = "", afterOpenChange, ...props }: ModalProps) {
  const id = useId().replace(/[^A-Za-z0-9_-]/g, "");
  return <Modal width={560} style={{ top: 24 }} {...props}
    rootClassName={`management-overlay embedded-idp-workflow-confirm workflow-confirm-${id} ${rootClassName}`}
    maskClosable={false} closable={!props.confirmLoading} keyboard={!props.confirmLoading}
    cancelButtonProps={{ ...props.cancelButtonProps, disabled: !!props.confirmLoading }}
    afterOpenChange={open => {
      if (open) document.querySelector<HTMLButtonElement>(`.workflow-confirm-${id} .ant-modal-footer .ant-btn-default`)?.focus();
      afterOpenChange?.(open);
    }}>
    <div role="region" aria-label="操作范围与后果" tabIndex={0} style={{ maxHeight: "calc(100dvh - 260px)", overflowY: "auto" }}>{children}</div>
  </Modal>;
}
