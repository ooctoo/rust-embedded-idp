# 管理员预建 schema 初始化实施与验证记录

日期：2026-10-29。分支：`codex/precreated-schema-init`，基线：`d19f93b`。依据：[设计方案修订 2](precreated-schema-initialization-design.md)。已完成本地实施、相关验证和最终复审；没有待修复的范围内阻塞项。本记录归档本地验证结果，远端 CI 状态以 PR 为准。

## 实现结果

`initialize_access_schema` 现在可在管理员所有的既有 schema 中，用仅获 schema `USAGE, CREATE` 的普通登录角色创建当前 IdP 对象，不要求数据库级 `CREATE` 或 schema 所有权。不存在的 schema 保留原有创建路径。

生产代码集中在 [access.rs](../crates/embedded-idp-storage-postgres/src/access.rs) 的原初始化方法：

1. 连接前拒绝 `pg_` 保留名称。
2. 显式开启 `READ COMMITTED` 初始化事务，沿用原迁移锁。
3. 锁后参数化查询 schema 是否存在，仅对缺失目标执行原创建语句。
4. 首次 DDL 和状态/目录初始数据写入后，在同一事务中运行原结构校验，再提交。

既有结构的校验分支、对象冲突映射、系统域及权限目录写入规则保持原样。没有改变 DDL、`tenant_v6`、公共配置结构、Core/HTTP 契约或依赖；没有自动授权、重设管理员、升级旧表或更换目标逻辑。已更新 README、宿主及参考服务接入指南；CONTRIBUTING 增补了一次性角色夹具的测试连接前提。

## 回归与验收对应

新用例放在 [schema_initialization/mod.rs](../crates/embedded-idp-storage-postgres/tests/schema_initialization/mod.rs)，由现有 `live_access` target 引入，包括十项显式 live 测试和一项不连接数据库的离线测试。各 live 测试在内部覆盖相关模式、权限或冲突组合，不把组合数当成独立测试数量。

| 修订 2 验收项 | 实际验证 |
| --- | --- |
| A01、A02 | 独立登录角色无数据库 CREATE、非数据库/schema 所有者、无高权限角色继承；成功初始化；schema 和宿主表的身份、定义、所有者、ACL、数据保留，新 IdP 对象归初始化角色 |
| A03、A11 | bootstrap 前后重复执行；撤销 schema CREATE 后仍可校验；真实 Core bootstrap、构造 store 和 readiness；对象及管理员/目录数据不变 |
| A04、A19 | 分别缺 USAGE、缺 CREATE，以及仅有 schema USAGE 而无 IdP 表读取权限时失败；无补建、授权或其他残留 |
| A05、A06 | 缺失 schema 无数据库 CREATE 时失败；授予该测试角色数据库 CREATE 后兼容原创建路径 |
| A07、A10、A17 | 表、access_state 视图、显式索引、独立 domain、同签名触发函数冲突；对比关系、函数、类型、约束和 ACL；错误后同一池连接可复用、锁可由独立连接取得，明确修复夹具后可重试 |
| A08 | 模式错误、缺表、禁用必需触发器及 tenant_v2/v3/v4/v5 均拒绝，不迁移或修复 |
| A09、A14 | 两个独立适配器实际等待同一迁移锁；默认 read committed 和 repeatable read 下均成功，等待者看到已提交状态，会话默认隔离设置保持不变 |
| A12 | 真实复现宿主索引占用自动约束名称；原实现返回成功，新增提交前结构校验后拒绝，并撤销 DDL 和初始数据 |
| A13 | pg_catalog、pg_temp、其他 pg_ 名称在连接前拒绝，不操作系统 schema |
| A15 | 可信搜索路径指向其他 schema，其他 schema 同名表及目标中的合法函数重载、业务触发器可共存，操作落在指定目标 |
| A16 | 独立在线角色只读授权能通过 readiness，但真实管理写入失败；明确授予 IdP 对象 DML 后，两种模式的真实管理写入成功，业务表不被附带授权 |
| A18 | 成功调用后的同参数重复请求不改数据，确认回滚后同参数重新初始化成功；这验证恢复协议，不代表提交瞬间真实断网注入 |

另在缺失 schema 路径中，通过测试角色私有的 `default_tablespace=pg_global` 触发建表失败，确认本次自动创建的 schema 也整体回滚；恢复该角色配置后，同一目标初始化成功。该夹具不变更共享或 PUBLIC 权限，也不增加产品故障注入接口。

所有角色和 schema 名随机生成。管理连接只负责准备、核对和显式清理；普通角色实际执行初始化。夹具捕获测试失败以先清理资源再传播失败，清理失败也使测试失败。数据库 ACL 只撤销本夹具实际授予的权限，避免并行测试无谓更新同一数据库 ACL 行。没有使用共享对象的 DROP OWNED、REASSIGN OWNED 或开发连接配置。

## 验证记录

实施前，受限角色初始化回归按预期失败；独立使用管理角色的自动命名回归也按预期失败，证明后者没有被权限问题遮蔽。修正后，最终十项 live 回归及离线保留名称用例均已通过，一次性验证实例均已清理。

| 检查 | 结果 |
| --- | --- |
| `pnpm --dir web build` | 通过；最终集成入口以 Node 22 再次构建，生成物保持忽略 |
| `pnpm --dir web test` | 185 通过，零失败或跳过 |
| `pnpm --dir web test:embedded-bundle` | 7 通过，零失败或跳过 |
| `cargo fmt --all -- --check` | 通过 |
| `cargo check --workspace --all-targets --locked` | 通过 |
| `cargo test --workspace --locked` | 484 通过、零失败；181 项显式 live 用例按标记忽略，数据库行为由独立集成实跑 |
| 定向 live 初始化回归 | 10 通过，零失败或忽略；连接前保留名称离线用例另行通过 |
| 最终 `scripts/run_ci_integration.sh` | 十个 live targets 共 179 通过，零失败、零忽略，资源和命令进程组清理确认 |

最终完整集成环境为本地 macOS arm64、Rust 1.93.0、Node 22.23.2、pnpm 10.30.1 和 `postgres:18.6-bookworm`；Web 测试及嵌入包测试也以 Node 22 / pnpm 10.30.1 复核通过。真实数据库检查包含当前最终回归文件，`live_access` target 的 21 项 live 用例全部执行。普通工作区测试中的 181 项忽略不计入离线通过数；其中包含两个迁移文件的独立 target，它们的同一用例已由 live_access 引入并在集成中执行。

最终集成耗时约 224 秒，结果 JSON 为 `passed`，`cleanup` 和 `ownedCommandGroups` 均为 `confirmed`。机器可读结果和诊断日志保存在本机临时验证目录，未加入仓库；仓库内只保留本记录和可复现的测试代码。

## 最终复审与边界

复审按四个直接风险核对实际差异：初始化角色权限没有被扩大；旧版本和模式拒绝路径仍在；所有新 DDL 与目录数据保留在原事务内，提交前执行布局校验；错误后连接池和事务锁可恢复。首次新增的结构校验会提前拒绝过去“首次成功、后续校验失败”的目标，这是设计要求的成功条件收紧。

复审补充了宿主对象身份与 ACL 的成功路径断言、旧版本拒绝，以及自动新建 schema 的失败回滚实测。测试夹具的并行数据库 ACL 更新和 Enabled 管理命令目标问题已修正；最终回归通过后未扩大产品实现范围。

当前结构校验仍是原有部分校验，不是完整 schema 审计。schema 所有者、创建者和搜索路径仍由可信部署方控制。在线角色权限、默认 ACL、bootstrap 以及宿主业务表准备仍由各自部署步骤负责。真实 COMMIT 瞬间断连未注入，不能把模拟恢复等同于网络故障实测；遇到确认丢失仍须按设计以同一目标显式重试，不能删除重建。

工作区原有 `crates/embedded-idp-axum/tests/openapi_contract.rs` 的 `17 → 19` 修改保持原样，不纳入本需求提交。上述验证针对本地工作区，不能作为远端 CI 或生产部署通过的证明；普通工作区检查未启用可选 `openapi` feature。本轮未操作现有开发数据库。
