# CI分层提交前复审摘要（2026-10-26）

这些JSON来自本机Mac arm64的隔离测试，源码HEAD为`ad37ccef3f55d0813cdeeefa5bcf9fc596e2591d`，另含本轮及并行产品工作区改动。不能视为纯提交树或远端Actions验证。版本、执行范围与清理结果见各JSON；详细过程见[实施记录](../../../ci-quality-implementation-result.md)。

- `migration-failure.json`：复现迁移约束查询并发OID错误。
- `parallel-compile-failure.json`：PG修复后八个存储目标通过，宿主因并行A04-B编译错误未执行。
- `integration-result.json`：完整十目标实际运行，166通过/1失败/0 ignored；A02B-B3原失败已通过，唯一失败为并行A04-B注册客户端not_found。清理确认。
- `integration-cases.json`：从最后一次私有日志抽取测试名称和状态，并记录日志哈希；不含响应体、凭证或数据库诊断。
- `checks.json`：工作区单测、Web与离线检查结果及本地日志哈希。
- `e2e-execution.json`、`e2e-results.json`：六组关键E2E通过，页面错误为零，浏览器和夹具清理通过。

原始日志与此前失败位于`/private/tmp/idp-ci-review-20261026`，是本地临时证据，未上传或写Git；本目录仅保留本次重要修复与复审的结果白名单，不建立逐轮全量附件入Git流程。没有执行完整N2、远端Actions、推送、部署、缩放、旁白或M1-03–06。
