# 本地工作分支整合记录（2026-10-26）

## 范围与基线

按用户确认，将 `main` 的 `d19f93b` 合入唯一工作分支 `codex/registration-physical-timeout`（合并前 `7018120`）。不合回主干，不推送。主干目录继续检出 main；整合发生在 `/private/tmp/sut-idp-physical-timeout-20261023`。

先前 `codex/registration-abuse-i1` 的 `6b6f9d9` 已是 `7018120` 的祖先，移除其干净工作树和冗余本地分支无需再做代码合并。当前仅保留 main 与上述工作分支。

原有8个未跟踪的 registration prepare/processing 测试文件先备份到 `/private/tmp/idp-premerge-7018120`，逐文件SHA-256核对保持不变，不纳入合并提交，也不视为本次交付的新测试。

## 冲突处理

主干通过squash收录过M1-02/UI-B，导致共同历史不能直接按提交关系识别。逐文件对照 `45a2584`：工作分支自该基线没有修改的管理UI、composition、宿主入口及相关文档采用main最新版；确有注册增量的文件逐项合并，不整批覆盖。

- 保留主干A01–A05、设备/扫码装配、OpenAPI合同及新CI布局。
- 保留工作分支注册邮件合同/领域/存储/HTTP runtime、密码工作预算、物理数据库截止时间与worker关闭保护。
- Axum同时导出注册runtime与主干OpenAPI模块。
- 管理事务保留`PgTransaction`并采用main要求的模块内可见性；新增management preparation改用`PgExecutor`及tokio-postgres隔离级别。显式审计表准备沿既有setup连接预算，在线prepare仍沿普通预算；SQL、锁序和原子审计规则不改。
- 主干并发DDL回归使用新连接错误类型`PgError`，不改变测试断言。
- Cargo.lock保留工作分支数据库依赖路线，补齐main所需合同/信号依赖；不恢复已移除的同步连接池。

## 能力与验证边界

注册分支提供了防滥用、邮件投递与运行控制的候选基础，后续S01/O01a设计应先复用和审查这些现有实现。不能把“代码已整合”写成S01/O01a完整完成：所有入口的共同策略、真实宿主接线、通用安全事件和邮件outbox范围仍须按修订4逐项核对；历史物理故障矩阵、统计防枚举、自然长窗口等未因此闭合。参见[注册runtime](registration-email-v1-runtime.md)和[控制流程记录](registration-control-closeout-2026-10-24.md)。

本次验证仅用于合并兼容性，不执行部署、完整产品验收或远端CI。结果在本记录末尾汇总。

## 合并验证结果

- `pnpm --dir web build`通过；Web单测185项、embedded bundle测试7项通过。
- `cargo check --workspace --all-targets --locked --offline`通过；测试夹具既有dead_code警告保留，无编译错误。
- `cargo test --workspace --locked --offline`：570 passed、0 failed、258 ignored；ignored不算已执行通过，包含保留工作区中可选live测试，不能据此宣称完整故障矩阵通过。
- `scripts/check_api_contracts.sh`：15项合同测试及A05静态漂移检查通过；registration-email-v1合同检查36个夹具及冻结摘要通过。
- 新建专用PostgreSQL 18.6容器执行`live_access_bootstrap`全部9项，以及`schema_inspection_ignores_unrelated_concurrent_ddl`1项，全部通过。覆盖管理准备冲突/原子审计/并发/触发器规则拒绝、bootstrap回滚及并发DDL隔离；测试结束清理容器。
- `cargo fmt --all -- --check`、暂存diff空白检查通过；8个原有未跟踪文件SHA-256保持一致且未暂存。

本次没有重跑所有物理故障live矩阵、A04/A05浏览器全流程或目标Linux/远端CI；没有部署或推送。主干仍为`d19f93b`，后续从整合后的唯一工作分支继续开发。
