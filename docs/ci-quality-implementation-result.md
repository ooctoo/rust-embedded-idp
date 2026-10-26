# CI质量分层实施记录

> 最新状态（2026-10-26）：后续已授权必要用例迁移和旧N2编排删除，当前收敛结果见[N2退役实施记录](n2-retirement-implementation-result.md)。本文保留原实施/复审历史，原“暂留手动入口”不再作为活动执行计划。

初始实施日期：2026-10-25，提交前复审：2026-10-26。依据[设计](ci-quality-design.md)、[计划](ci-quality-implementation-plan.md)及[覆盖映射](ci-quality-coverage.md)。初始实施获准推进代码及本地验证；2026-10-26另获本轮范围内本地提交授权，不推送、触发远端补验或部署，未修改分支保护或tag触发规则。缩放、旁白和M1-03–06不在本轮范围。

## 实现

普通CI保留原有`check`，增加在其成功后独立运行的`integration`和`e2e`。两个新增job使用Ubuntu 24.04 x64、Node 22.23.4、pnpm 10.30.1和Postgres 18.6-bookworm；浏览器工具复用既有锁文件的Playwright 1.64.1/完整Chromium。没有增加缓存、自动选套、分片、生产镜像或CD。原`v*`触发保持，`release/x.y.z`仍是另行安排的可选入口。

- `scripts/run_ci_integration.sh`：建立独占、loopback Postgres容器；生成私有合成配置覆盖`.env`入口，显式执行十个既有live测试目标。必须按名称核对十个不同目标、各自passed>0且failed/ignored=0；任何测试、超时、中断或清理不确定均失败。
- `scripts/run_ci_e2e.py`＋`scripts/check_ci_e2e.mjs`：固定E01–E06，直接运行编译后的参考宿主；覆盖登录/恢复/退出、模式/作用域、客户端写入回读、撤销取消/确认、错误及未知结果恢复、真实双标签刷新和独立入口退出隔离。错误注入范围显式记录，不冒充自然网络故障。
- 共享浏览器夹具增加准备中ownership journal、命令超时；准备失败同样先检查容器label，Linux清理使用pidfd固定进程身份。无权确认退出时保留私有恢复数据，不删除仍可能使用中的数据。
- Actions只上传JSON白名单，建议30天保留；本地诊断日志不上传，不自动将附件写Git。复现命令见[CONTRIBUTING](../CONTRIBUTING.md#ci-quality-lanes)。完整N2保留手动专项和原八套严格门槛。

## 发现与修复

1. 新CI驱动的信号异常最初使用`InterruptedError`，可能被Python subprocess当作EINTR重试；改为独立取消异常，复用既有有界进程清理，并保留真实子进程中断/超时回归。
2. 新E2E在写入后导航、未知结果回读/关闭时最初默认取消原生确认；改为仅对明确动作接受确认。未知写入回读后仍保留历史警告符合现有合同，验证当前服务端状态及禁止自动重放，不要求警告消失。
3. 实际PG测试连续复现结构检查失败，数据库诊断为`could not open relation with OID ...`，发生于`pg_get_constraintdef`查询。该函数可能在优化器筛选schema前接触其他schema正在删除的表。`access.rs`改为MATERIALIZED CTE先限定目标schema、表和有效约束，再解析定义；保留原结构完整性校验。新增`schema_inspection_ignores_unrelated_concurrent_ddl`以40轮并行DDL/结构检查回归；不通过全局串行化或忽略测试规避失败。

初始实施唯一产品源码变更为上述Postgres结构检查修复；提交前复审另补齐同类迁移查询，见下节。其他产品/API工作区修改属于并行工作，不纳入本轮提交。

## 2026-10-25本地验证及边界

本地证据根为`/private/tmp/idp-ci-quality-20261025.uK8fIR`，包含失败历史、最终JSON和离线测试日志。它是本机临时目录，不是永久远端artifact；可公开的结果仅为JSON摘要，`integration.log`含私有诊断，不应上传。源码基线HEAD为`ad37ccef3f55d0813cdeeefa5bcf9fc596e2591d`，工作树有本轮及并行未提交改动，不能将其当作已冻结执行SHA。

- Web 115项测试通过；Web与Rust参考宿主/fixture工具构建通过。
- 新集成驱动8项离线测试、E2E runner 7项、checker 2项、共享fixture 6项通过；既有N2工具/process/functional离线回归保持通过。
- 六组E2E已在本机Mac arm64、Chromium 156.0.8078.4及隔离PG18.6上完整通过，资源清理确认；首次全过29.45秒，重建宿主后的最终`e2e-final`复验30.65秒，实际Playwright 1.64.1。实际Node24.19.0/pnpm10.28.2与目标CI不同，不能称Linux x64或远端Actions已通过。
- PostgreSQL修复后的完整复验（`integration-attempt4`）：前九个目标141项通过，含新增并发DDL回归；`live_reference_host`为23项通过、1项失败，总计164通过/1失败/0 ignored。失败来自并行工作新增的`a02b_b3_scan_entries_isolate_proofs_sources_and_recover_pending_delivery`，宿主报同步Postgres调用在异步runtime中启动runtime。该用例和相关并行源码未删除、跳过或代改；完整integration保持失败。所有本轮真实PG容器清理确认。
- 全仓格式检查中途曾发现并行修改的`embedded-idp-axum/src/openapi.rs`格式差异，本轮未代改；最终重新执行`cargo fmt --all -- --check`通过。本轮Rust文件单独检查也通过。没有运行远端job或修改required checks。

## 后续边界

上述2026-10-25失败保留为历史证据，最新复审以末节为准。本地验证和远端Actions须分别表述，推送及观察真实Actions仍需单独授权。远端尚未验证的耗时、runner版本、artifact上传和保留策略不能由本地结果替代。下游生产配置、集成、镜像发布和部署不进入本仓库CI计划。


## 2026-10-26提交前复审

复审CI workflow、两个执行器、六组浏览器断言、共享夹具、离线测试、PG修复及文档。发现并修正两类遗漏：

- 迁移脚本的v6幂等重入仍有三处同类`pg_get_constraintdef`查询，完整集成实际复现无关schema并发DROP导致OID错误。三处先用MATERIALIZED CTE筛选目标约束，再保留原主键、secret长度与action断言；事务/锁和v5→v6迁移语义不变。既有并发DDL回归扩展为同时执行结构检查与v6重入；这是并发压力回归，不声称穷举调度或验证psql外层锁包装。
- 当前设计/计划及旧文档入口仍有“仅设计、尚未实施”描述，已更新状态并保留历史段落。N2不是长期必备CI层；暂留可选手动诊断，因为角色/成员/租户、多入口及部分安全覆盖未全部迁入关键E2E。它不构成PR/release门槛、不要求定期执行，也不继续扩建。删除旧编排前须确认独有合同的去留，并保留复用中的依赖锁文件及清理helper；本轮未删除或执行完整N2。

A02B-B3原runtime嵌套panic已有并行修复：保留Router服务树至runtime停止后同步释放。本轮复验期间并行A04-B又新增了需要可变host的调用，导致E0596；只补上该局部变量的`mut`以恢复编译，这一行与所在文件保留在工作区，不纳入CI提交。

本轮证据目录为`/private/tmp/idp-ci-review-20261026`。首次沙箱内运行无法访问Docker，失败保留；获得本机Docker执行权限后重试。随后迁移失败、并行编译失败及修复后复验分别记录，失败结果未覆盖。所有测试仅使用合成数据与自有隔离资源；原始日志不入Git。


复验结果：完整十个集成目标实际执行，166通过/1失败/0 ignored，清理确认。`a02b_b3_scan_entries_isolate_proofs_sources_and_recover_pending_delivery`已通过；唯一失败为并行新增`a04b_registration_client_recovers_provision_and_complete_against_reference_host`的JS注册请求返回not_found，不属于本轮CI/PG修复，未修改其断言或跳过。当前工作区不能声明整体CI全绿。

六组关键E2E再次通过（43.85秒，包含夹具准备/清理），页面错误为零，浏览器及夹具清理确认。实际环境仍为Mac arm64、Node24.19.0/pnpm10.28.2/Rust1.93.0、Postgres18.6、Playwright1.64.1/Chromium156.0.8078.4；未替代目标Linux x64环境验证。

工作区单测复审另发现一条原有CLI测试仍要求“business entries不受支持”，与现有宿主能力矛盾；已将它更新为分别验证业务入口与仅管理配置均拒绝缺失凭证、先于密钥加载失败，并保留无凭证输出断言。该基线测试修正纳入本轮提交，未改业务实现。

离线复验：集成驱动8、E2E runner7、checker2、共享夹具6、进程清理21、N2 Linux工具28、N2 CI工具39、功能检查34全部通过；迁移wrapper静态检查通过。格式、diff空白及文档链接核对通过。最小结果摘要保存在[复审证据](design/ci-quality/20261026/README.md)，历史失败不改写。此次本地提交仅包含CI/测试/文档及明确列出的PG修复；README按段暂存，A02B/A04及其他产品/API修改均保留在工作区。

Web单测本次122项通过；Web在每次真实集成入口中重建，Rust参考宿主与fixture工具重建通过。本轮没有执行或宣称目标Linux runner、全部feature/release矩阵通过。

最终`cargo test --workspace --locked`退出0：478项通过、0失败、169项ignored（真实PG用例等依既有策略需显式启用，独立集成结果如上）。本轮CI范围复审完成，可作限定范围本地提交；这不改变A04-B实际集成失败的状态。
