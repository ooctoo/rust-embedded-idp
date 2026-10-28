# 一期目标交付前复核（2026-10-28）

复核范围仍为S01、最小O01a、S03本人会话/撤销/改密/邮件恢复及Web入口，不包含完整验收、部署、MFA和原生平台适配。先复核设计及实际代码，再修正、测试、准备本地签名提交；不推送、不合回main。

## 发现与修复

1. 恢复验证码的本地格式检查发生在pending保存之后。短码/字母码没有发送HTTP，却把用户困在结果核对状态。已在ready转pending前校验6位ASCII数字code和string密码，保留原ready原始记录，UI加pattern/minLength。没有把篡改intent类错误泛化成可重试。
2. 会话列表错误写入安全写操作共享snapshot；重试成功仍留错误，迟到失败还可能污染新身份/已完成操作。现在列表只分类reject，由已有身份/generation保护的组件处理，不改写journal状态。
3. 翻页先改游标栈再发送请求，失败后重试会重复入栈。现在仅在成功且身份/generation仍匹配时同时更新page与stack，失败保留原位置。

修复前已将详细决策、实施顺序和验证要求追加到[S03-C2设计](s03-c2-web-ui-design.md)。没有新增依赖或改变HTTP合同。

## 独立复核结果

- Core/PG：全局屏障与锁顺序、错误尝试提交、KDF后的资格/版本复验、全域凭据退役、成功事件/收据事务原子性及用途绑定，未发现新的确定性阻断缺陷。
- S01/O01a宿主：取消后物理许可、worker超时kill/reap、Unknown不重发、NotStarted有界重试、恢复关闭时cleanup、显式迁移/readiness与governor精确版本/许可文本一致。
- Web：上述三项已修复；SDK身份/scope、未知结果仅查询、CAS与管理/业务入口隔离保持。

## 工作树与提交范围

本次发现原临时工作树的.git连接和381个已跟踪文件缺失，现存文件先备份到 `/private/tmp/idp-review-survivors-20261028.tar.gz`，再仅恢复缺失的索引文件，不覆盖现有增量。未推断缺失原因。锁定Web依赖已从本地缓存恢复，Git未记录依赖目录/构建产物。

既有8个未跟踪测试与 `/private/tmp/idp-premerge-7018120/manifest.json` 的SHA-256一致，继续排除于本次提交；主目录main上既有openapi_contract.rs的17→19改动未动。本次仅归档工作分支的一期实现、设计、合同、测试及本次修正。

## 验证

新增workflow 4项回归，覆盖读失败/重试不改snapshot、迟到读失败不污染完成写/新身份、ready-start及ready-complete非法输入不变更raw/不发送请求且合法码可继续。定向workflow 22/22通过。

Playwright合成页面通过：首次读取失败→重试清除错误；下一页失败→重试成功→上一页返回首页；短码/字母码无请求且原记录不变→正确码完成。该证据属于本机故障注入，不是本轮重新运行真实PG浏览器验收；此前真实PG/SMTP证据仍见[C2实施记录](s03-c2-implementation-result.md)。本轮没有修改Rust事务实现。

最终重跑结果补充于交付清单。日志前缀 `/private/tmp/idp-review-20261028-`，浏览器夹具/记录在 `/private/tmp/idp-review-browser-20261028/`。本地提交成功以Git历史为准；没有远端CI、推送、完整验收或部署结论。
