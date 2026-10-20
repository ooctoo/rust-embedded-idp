# M1-02 审查调整设计修订回传

| 项目 | 内容 |
| --- | --- |
| 文档标识 | UP-M1-02-ADJUSTMENTS-RESULT，修订 1，2026-10-20 |
| 文档上下文 | `rust-embedded-idp` 按四项调整交接件第 6 节形成的设计回传；供需求方核对接收 |
| 需求目标 | 落实 R01–R04，明确设计、实现和运行验收的边界，保护原嵌入及旧参考模式 |
| 执行方案 | 只读核对基线与现有工作区，修订设计、检查文档一致性；不修改或验收代码 |
| 接收依据 | [UP-M1-02-ADJUSTMENTS 修订 1](m1-02-design-adjustments-handoff.md) |
| 交接件 SHA-256 | `0eeca2b39109b778914992b5cd9a1de569bfe388e5d3cd650316948ed88956b4` |
| 实际 HEAD | `1835ec35790568fefb9f6792a120b3041cfe77ae`，本地 `main`；未刷新远端；与交接提交基线一致 |
| 软件 / schema | workspace 版本 3.0.0 / `tenant_v6`；无本任务 schema 变化 |
| 修订前 | UP-M1-02-DESIGN 修订 2；SHA-256 `d7402bd472d427062c1bf29ec6a745b31518d54dd16dbc644f5c666b651e9ab2` |
| 修订后 | [UP-M1-02-DESIGN 修订 3](m1-02-configuration-composition-design.md)；SHA-256 `3af4eba26944b352264a47bc9c11038117db83dffa412ab5d9792de8f92a9e5f` |
| 本次结论 | R01–R04 已落实到设计文字及断言；所有软件运行验收均为本任务未执行 |
| 授权边界 | 未改代码/测试实现/依赖/schema/运行配置；未执行构建、软件测试、初始化、迁移、启动、部署或提交/推送；未启动 M1-03/04 实施 |

## 1 基线与工作区差异

提交基线没有变化，设计稿修订前摘要与交接件一致。以下为开始时已经存在的工作区变化，不由本任务产生、修改或验收：

| 类别 | 路径 |
| --- | --- |
| 依赖 | `Cargo.lock`、`crates/embedded-idp-app/Cargo.toml` |
| app 实现 | `crates/embedded-idp-app/src/admin_ui.rs`、`bootstrap.rs`、`config.rs`、`main.rs`；新增 `composition_config.rs` |
| 测试 | `crates/embedded-idp-app/tests/live_reference_host.rs`；新增 `explicit_config_cli.rs` |
| 示例 | 新增 `docs/examples/m1-02-management.json` |
| 文档 | README 已有改动；M1-01 三份文档、M1-02 修订 2 与本次交接件已有于工作区 |

只读查看显示工作区已新增 `--config`、显式配置与管理装配相关代码/测试，因此修订 3 将“当前 app 尚无新输入”等表述限定为**提交基线**。不能从 HEAD 未变或本任务只改文档推断整个工作区没有实现。

还发现工作区 `composition_config.rs` 的 `Runtime.http`、`Http.browser_origin`、`Management.browser` 当前仍为必填类型，归一时访问 `management.browser.cookie_name`。这与 R04 的 token/API-only 新要求存在待核对差异。本轮保持代码原样；后续实现接收必须检查，不声称设计修改已自动满足 R04。

现有工作区测试名字及实现可作为后续候选素材，不作为本次运行证据，也不能视为四项调整已完成实现。

执行期间另有任务在 README 增加 `docs/m1-02-implementation-result.md` 的实施结果入口。本次写入前检测到索引变化，保留该入口并基于最新 README 合并本设计回传链接；未将该实施报告的测试结论并入本回传，也未将其作为修订 3 已实现的证据。

## 2 R01–R04 逐项回传

| 调整 | 设计处理结论 / 修改位置 | 兼容保护 | 断言与后续责任 | 设计修订 | 运行验收 |
| --- | --- | --- | --- | --- | --- |
| R01 管理完整生命周期 | §6.3.1 定义 token/已启用 Cookie 登录→API→刷新→API→退出及失效；§6.5/§8/§9 明确 M1-02 门槛 | 复用现有管理状态机；仅对应会话撤销，不承诺离线 JWT 签名立即失效或其他独立会话退出 | 扩充 Q11/Q12；M1-02，可用预备夹具，不等 P3/多业务入口 | 已完成 | 本任务未执行 |
| R02 业务调用矩阵 | §5.4.1 增公共/confidential token、browser、证明矩阵；说明 router 替代/附带路由/Secret 边界 | 不叠加两套完整认证 router，不向公共前端交付 confidential Secret，不放宽原 client/证明校验 | Q19、§6.5/§9；M1-04 选择复用/拆分及实际组合，本次不选择拆分 | 已完成 | 本任务未执行 |
| R03 同源 P3 准备 | §6.4.1 将 DB/schema/mode/TLS/CA/SecretRef 与 P1/P2/P4 对齐；准备属性与启动引用分离 | 不另建长期配置源，不覆盖在线 client，不新增准备控制器，不承诺跨步骤总事务 | Q20/Q21、§6.5/§9；M1-03 冻结命令/并发/审计，P6 仍归 M1-04 | 已完成 | 本任务未执行 |
| R04 按需 browser | §3.3/3.4、两个完整 JSON 示例、§5.2/5.3、§6.3.1、附录 A 明确条件；管理 UI 关闭可 token/API-only | 旧参考 Origin/Cookie/UI 默认和嵌入公共 API 不变；关闭 browser 不关闭管理认证 | Q04/Q11/Q12、§9；M1-02，工作区必填实现另待处理 | 已完成 | 本任务未执行 |

本次采用交接件要求，没有以等价替代为名改变安全语义。字段表进一步明确新模式 `browser/ui` 可省略或 null，默认关闭；仅在任一 browser 启用时必需相应 Origin，`runtime.http` 对全体 browser 关闭的组合可省略。这些属于修订稿中的拟定配置契约，不代表已发布接口或整份配置已获最终冻结。

## 3 源码和测试映射

以下位置已做只读定位。测试仅作为可复用素材；原测试通常只证明原组合，仍需在后续实施中补充新配置/挂载条件的断言。本任务没有新增或运行测试。

| 调整 | 现有事实 / 可复用测试位置 | 后续需补足或核对 |
| --- | --- | --- |
| R01 | [管理 router](../crates/embedded-idp-axum/src/management_auth.rs) 已含 login/session/refresh/logout；`crates/embedded-idp-storage-postgres/tests/authentication/management.rs` 的 `management_login_enforces_persisted_purpose_live_authority_refresh_and_logout_in_both_modes`；`crates/embedded-idp-app/tests/live_reference_host.rs` 的 `reference_host_runs_management_and_business_flows_in_both_modes`、`browser_cookie_restore_logout_and_purpose_isolation_in_both_modes` | 新模式三个合法组合的实际管理链路、非默认 mount、Cookie 清除/恢复及退出后 access/refresh 当前状态拒绝；不以原组合通过推定新组合通过 |
| R02 | [device auth router](../crates/embedded-idp-axum/src/tenant_device_auth.rs) 复用基础路由；[device transport](../crates/embedded-idp-core/src/access/authentication/device_transport.rs) 的无证明刷新；[resource service](../crates/embedded-idp-core/src/access/authentication/oidc/resource.rs) 与 [client 认证](../crates/embedded-idp-core/src/service/client_auth.rs)；`live_tenant_registration.rs` 的 `http_login_selection_authentication_and_switch_use_real_postgres_and_rs256` | 新配置实际复用面、每类 client/transport 的请求与 Secret、重复端点、全部附带面和退出范围；矩阵与运行证据归 M1-04 |
| R03 | [既有初始化示例](../crates/embedded-idp-storage-postgres/examples/bootstrap_local_postgres.rs)、[管理员准备](../crates/embedded-idp-app/src/administrator_init.rs)；`tests/live_access.rs` 的 `access_initialization_is_atomic_idempotent_and_allows_host_tables`、`tests/live_access_bootstrap.rs` 的 `bootstrap_initializes_both_modes_and_is_idempotent`、`bootstrap_concurrent_first_call_initializes_once` | P3 目标/TLS/Secret 同源、创建/相同/冲突、并发/审计及未知结果恢复；M1-03 实施时确定具体新增测试 |
| R04 | 公共库已有可选 router；旧配置与管理 UI 组合继续保留。工作区 `composition_config.rs` 的 `management_and_legacy_conflicts`、`ui_and_paths_are_checked`，`live_reference_host.rs` 的 `explicit_management_probe_missing_client_and_no_ui` 是候选检查入口，未纳入本次验收 | 关闭 UI 不等于已支持关闭 browser；需补三种合法组合及 UI 无 browser 负例、任一业务 browser 的 Origin 要求；不运行当前测试来代替设计修订 |

`authentication/management.rs` 的实库测试由 `live_tenant_registration` 测试目标引入，不能假定它是独立 integration test target。上表 R03 的两个 `tests/` 路径均相对 `crates/embedded-idp-storage-postgres/`。

## 4 阶段责任和接收边界

| 阶段 | 负责 | 完成边界 |
| --- | --- | --- |
| M1-02 | R01/R04，共同参数、按需管理 browser 与完整管理链路 | 可在已准备隔离夹具验证；不等待 P3 才定义/验证管理组合，不宣称空库准备完成 |
| M1-03 | R03，P1 初始化/P2 管理员/P3 管理 client/P4 仅管理启动，P5 可创建业务对象 | P3 命令/并发/审计待该任务确定；不提前验收 P6 业务路由 |
| M1-04 | R02，P6 业务启用及多 client/transport/路由矩阵 | 缺少完整生命周期的构建拒绝启用，配置非空仍合法；协议按需，不强制所有组合 |
| M1-05/06 | 接口契约随变更维护；最终汇总 P1–P6 与兼容证据 | 安全与受影响回归随实际改动执行，不推迟到最后 |

本任务只完成上述设计责任的文本划分，没有启动 M1-03/04 的实施或运行验收，也没有替用户选择试点、部署、域名、Secret/邮件供应或运行指标。

## 5 一致性检查和交付范围

文档静态检查内容：

- R01–R04 均有正文位置、阶段责任和 Q 断言，Q01–Q22 编号保留且唯一。
- 字段表、token/API-only 与 UI+browser 两个完整 JSON 示例、Cookie/UI 条件、仅管理阶段表和附录一致；示例 JSON 可解析及条件静态检查不代表 app 解析器接受。
- 旧配置标识、管理 Fixed 0 例外、Choose 源会话语义、原 provider/transport/catalog 边界保留；本次没有修改旧默认。
- 文档链接、章节锚点、修订前后摘要和修订差异检查；不运行构建、格式化代码或软件测试。
- 工作区必填 browser/Origin 与 R04 的差异显式登记；不把已有实现冒充本次交付。

本任务在上游只修改或新增：

1. `docs/m1-02-configuration-composition-design.md`：修订 3。
2. `docs/m1-02-design-adjustments-result.md`：本文。
3. `README.md`：M1-02 设计与回传入口。

交接件、M1-01 历史资料、现有 JSON 示例和所有代码/依赖/测试保持不由本任务修改。运行状态统一为“本任务未执行”；没有继承或宣称其他任务的运行结果。需求方 `idp` 仓库的接收记录属于另一侧文档更新，不是上游软件交付。

## 6 未闭合事项与下一步

| 事项 | 后续处理 |
| --- | --- |
| M1-02 管理条件与链路实现 | 按修订 3 单独核对现有工作区代码及测试，尤其 R04 必填差异；本次不修代码 |
| P3 管理 client 准备 | M1-03 冻结命令、比较规范、并发、审计及恢复；保持同源参数 |
| 业务组合 | M1-04 冻结 client/transport/路由矩阵、附带端点与必要最小拆分；不放宽 Secret 或证明规则 |
| 其他原待定 | OpenAPI、OIDC/设备/扫码映射、探针运行预算、试点与部署按原工作包处理 |

先由接收方核对修订 3 和本回传的逐项映射，记录设计接收。文档交付不启动代码、测试、M1-03/04 或部署；后续按明确授权的工作包推进。设计接收与软件运行验收分别记录。
