import { useEffect, useState } from "react";
import { Button, Typography } from "antd";
import { type AdminPage, ManagementError } from "./client";
const { Text } = Typography;
const failure = (error: unknown) => error instanceof ManagementError ? error.message : "读取失败，请重试。";

// Cursor APIs do not expose totals or random page jumps. Keep one page of records.
export function useCursorPage<T>(load: (cursor?: string) => Promise<AdminPage<T>>) {
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [reloadRevision, setReloadRevision] = useState(0);
  const [page, setPage] = useState<AdminPage<T>>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    setPage(undefined);
    setError("");
    setLoading(true);
    load(cursors.at(-1)).then(value => { if (active) setPage(value); })
      .catch(reason => { if (active) setError(failure(reason)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [load, cursors, reloadRevision]);
  return { page, error, loading,
    reload: () => { setCursors([undefined]); setReloadRevision(v => v + 1); },
    controls: <div className="management-pagination">
      <Button disabled={loading || cursors.length === 1} onClick={() => setCursors(v => v.slice(0, -1))}>上一页</Button>
      <Text type="secondary">第 {cursors.length} 页</Text>
      <Button disabled={loading || !page?.has_more} onClick={() => setCursors(v => [...v, page!.next_cursor!])}>下一页</Button>
    </div>,
  };
}
