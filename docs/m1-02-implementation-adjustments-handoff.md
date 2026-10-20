# M1-02 实现审查调整交接说明

| 项目 | 内容 |
| --- | --- |
| 文档标识 | UP-M1-02-IMPLEMENTATION-ADJUSTMENTS，修订 1，2026-10-20 |
| 文档上下文 | 面向 `rust-embedded-idp` 的独立需求交接件；接收方仅凭本件和同仓设计、源码即可核对任务，无需当前对话或需求方私有文档 |
| 需求目标 | 按 UP-M1-02-DESIGN 修订 3 收齐 app 按需 browser、管理生命周期及受影响兼容保障，补正基于修订 2 的实施报告映射 |
| 建议实施方案 | 后续只在 app 配置与条件装配层做必要调整，复用既有管理服务和 BrowserSession，补受影响断言与增量回传，不重建身份状态机 |
| 认可状态 | 需求方已认可 A01–A05 审查结论及本件列出的调整范围；认可结论、同步文档不等于授权代码实施或运行验收 |
| 当前执行范围 | 本轮仅同步本件和必要索引。接收方后续先按第 6 节静态核对并回传调整计划；不改代码/测试/依赖/schema/运行配置，不构建、不运行验收，不启动 M1-03/04 |

## 1 背景与适用范围

`rust-embedded-idp` 提供可直接嵌入的身份模块及开发/参考宿主 `embedded-idp-app`。M1-02 在 app 内将旧 env 和新增显式 JSON 输入归一，再完成共同管理装配；不是要求所有嵌入宿主转用独立服务或 JSON。参考宿主不因此被认定为生产宿主。

当前实现已接入原管理 login/session/refresh/logout 和 BrowserSession，支持显式空业务列表、管理挂载及 UI 路径配置，保留旧参考业务分支。已接收的设计修订 3 增补了按需 browser、完整管理生命周期和阶段边界；现有实施报告仍声明基于修订 2。

本次静态审查确定：A01/A02 为配置及装配契约差异，A03/A04 为需要补足的管理链路与受影响兼容证据，A05 为实施报告与版本映射调整。没有据此确认管理退出存在运行故障，也没有发现完成这些调整必须修改公共库或 schema 的理由。

本件所有相对链接和源码路径以上游仓库为准；需求方保存的副本与上游交付副本应逐字节一致。

## 2 基线与工作区保护

| 项目 | 审查及交接基线 |
| --- | --- |
| 实际本地 HEAD | `1835ec35790568fefb9f6792a120b3041cfe77ae`，本地 `main`；未刷新远端 |
| 软件与 schema | 3.0.0 / `tenant_v6` |
| 权威设计 | [UP-M1-02-DESIGN 修订 3](m1-02-configuration-composition-design.md)，SHA-256 `3af4eba26944b352264a47bc9c11038117db83dffa412ab5d9792de8f92a9e5f` |
| 被审实施报告 | [M1-02 实施结果](m1-02-implementation-result.md)，声明基于修订 2；SHA-256 `30229cb4ad5226573f687de124d21c8ff4f9a6f9bafc9cbddd93b2de36698f77` |
| 配置模块 | `crates/embedded-idp-app/src/composition_config.rs`；SHA-256 `007fa4bffdd6ef61e051ad7267b707aa9af7f937019ebda4ed071fb05301bd48` |
| 装配模块 | `crates/embedded-idp-app/src/bootstrap.rs`；SHA-256 `de73c504b91e9c5de37d88fb849146067fb115d48bad7f9652058f9722df02f4` |
| 进程测试 | `crates/embedded-idp-app/tests/live_reference_host.rs`；SHA-256 `5228a9f1cd7c4c4e89fc6abb00448b96bee2470dc6f831c5d0293e969e1818ff` |
| 历史兼容依据 | [UP-M1-01 修订 2](m1-01-compatibility-handoff.md)、[M1-01 设计回传](m1-01-design-review-result.md)、[M1-02 四项设计调整](m1-02-design-adjustments-handoff.md)、[设计修订回传](m1-02-design-adjustments-result.md) |

已有工作区变化包括 app 配置/装配/页面/主入口、Cargo.toml/Cargo.lock、进程测试，新增配置模块、CLI 测试、JSON 示例及文档。它们是被审对象，不能撤回、覆盖、格式化或冒领为本轮交付。报告所述已有构建、实库、浏览器通过只属于其原版本与组合，不自动成为修订 3 的通过证据。

接收方先记录实际 HEAD、文件摘要和工作区状态；如与本表不同，说明差异、A01–A05 是否仍成立及受影响范围。不能只以 HEAD 相同认定工作区相同，也不能机械套用可能漂移的行号。

## 3 五项调整与最小范围

以下是后续 M1-02 的工作范围。当前仅核对和回传，不实施。

| 编号 | 事实与定位 | 后续最小调整 | 契约及断言 |
| --- | --- | --- | --- |
| A01 按需 browser/Origin | `composition_config.rs` 的 `Runtime.http`、`Http.browser_origin`、`Management.browser` 必填，归一固定 `Some(browser)`；`bootstrap.rs::build_composition` 无条件构造管理 browser 配置、服务和 router | 同步调整输入、共同参数、校验和条件装配，使无 UI/无 browser 的管理 token/API-only 可用。全体 browser 关闭可省略 http，不填假 Origin/Cookie；管理 token 服务与受保护 API 保留 | 修订 3 §3.3/3.4、§6.3.1，Q04/Q12；R04 |
| A02 UI 省略语义 | 解析器额外拒绝省略 `management.ui`，`structural_errors_report_path_without_value` 还断言该输入失败 | 省略/null 均关闭 UI，修正对应反向断言；UI 开启但 browser 关闭明确拒绝，无 UI但 browser 开启合法，不自动启用 browser | §3.4、§5.3、§6.3.1，Q03/Q04/Q11/Q12；R04 |
| A03 管理完整生命周期 | 现有管理服务及 router 已有刷新/退出；新显式测试主要覆盖 token 登录/读取、Cookie 刷新 200/退出 204，未闭合修订 3 全链路 | 扩充原进程测试及可复用夹具，验证 token 和启用 Cookie 的刷新后 API、退出失效、Cookie 清除、恢复拒绝和用途边界，不新增管理状态机 | §6.3.1，Q11/Q12；R01；证据缺口不等同运行故障 |
| A04 受影响兼容保障 | 当前公共 Core/Axum/Postgres/Web 契约未见变更，旧参考分支保留；A01/A02 将影响共同参数和 browser 条件 | 保持旧输入原值归一、两模式参考行为、Cookie/UI/入口及受限期限；复用现有回归并按实际差异补覆盖，不复制整套测试或新增公共包装层 | Q01/Q17/Q18 及受影响 Q15；原 M1-01 兼容约束 |
| A05 报告版本与证据映射 | 报告标设计修订 2，链接已指向被更新的修订 3 同一路径；Q12 原“通过”不包含新增条件 | 保留旧结果，固定其历史版本/摘要；后续另补修订 3 的 A01–A05、Q 子断言、实际源码版本/摘要和增量验证结果，不只换标题或全量重标通过 | Q04/Q11/Q12、Q01/Q18，及 Q19–Q21 后续边界 |

### 3.1 字段与装配契约

- 新 JSON 的 `management.browser`、`management.ui` 均可省略或为 null，表示关闭；旧 env 默认不变。
- 全体 browser 关闭时 `runtime.http` 可省略，但不接受 null；显式给出的字段仍按设计校验类型/语法。任一管理或业务 browser 启用仍要求有效 Origin/Cookie，不绕过原 feature、transport、开发 TTL 等安全门禁。
- UI 关闭不关闭管理鉴权。UI 无 browser 必须拒绝，不暗中恢复默认 browser；无 UI+browser、无 UI+无 browser 均合法。
- browser 关闭时不构造相应 Cookie、router 或相关 browser 服务依赖；UI 关闭时不挂页面/assets、不执行页面 meta 注入。不能只让 JSON 解析成功，却在装配时仍读取必填 browser。
- 未来业务 browser 的 Origin 规则可通过配置层核对；合法非空业务集合在当前构建仍在监听/密钥加载/DB 访问前明确拒绝，不为本任务提前启用业务运行。

建议直接沿用当前 app 类型和模块完成条件化，不指定新的公共类型体系、配置框架、通用准备控制器或路由 DSL。

### 3.2 可复用代码与测试入口

- [配置模块](../crates/embedded-idp-app/src/composition_config.rs)：输入模型、`from_file_with_lookup`、`validate_static`、`from_legacy`；额外 UI 必填检查及其反向单元断言。
- [装配模块](../crates/embedded-idp-app/src/bootstrap.rs)：`build_composition` 中管理 browser 无条件构造/合并；保留管理 token 和受保护 API。
- [管理 HTTP](../crates/embedded-idp-axum/src/management_auth.rs)、[Core 管理服务](../crates/embedded-idp-core/src/access/authentication/management.rs)、[BrowserSession HTTP](../crates/embedded-idp-axum/src/browser_session.rs)：已有刷新、退出、状态核对和 Cookie 清除，无需重建。
- [进程测试](../crates/embedded-idp-app/tests/live_reference_host.rs)：`explicit_management_only_is_read_only_at_startup_in_both_modes_and_mounts`、`explicit_management_probe_missing_client_and_no_ui`、`explicit_management_restart_preserves_credentials_and_existing_client`；辅助 `explicit_command` 当前始终提供 http/browser，需要随覆盖调整。
- 原 `reference_host_runs_management_and_business_flows_in_both_modes`、`browser_cookie_restore_logout_and_purpose_isolation_in_both_modes` 与私网受限 browser 用例继续复用。Core 管理实库测试位于 `crates/embedded-idp-storage-postgres/tests/authentication/management.rs`，由 `live_tenant_registration` target 引入，不是独立 target。

## 4 兼容和安全约束

1. **公共嵌入路径继续独立。**Core 不依赖 HTTP/DB；宿主可信注入 provider/token/transport/catalog 并自行组合原模块 router，保留模块本地根。不得强制新 JSON、app、中央服务或新的持久入口表。`build_composition` 属二进制内部装配，不为其新增无必要的公共兼容 API。
2. **旧输入行为持续保护。**无参数启动仍按旧 env；原 entry/client/purpose/policy、audience、TTL、路径、开关和错误语义不变。管理名 `management`、client `idp-management`、业务入口 `business` 及原配置业务 client 保留。旧 Cookie 名为 `idp_{port}_management/business`，Path 分别为 `/api/admin/auth/browser`、`/auth/browser`，UI 原 API base `/api`。新 JSON 可省略 browser，不得使旧模式随之关闭。
3. **租户策略不重新定义。**Enabled 管理 Fixed 0 例外保留，业务 Fixed 0 拒绝；管理 Choose 不进入平台域 0；Disabled 只允许 Fixed 0；管理 proof=true 明确拒绝。Choose 成功切换不撤销仍有效源会话，来源已撤销/失格时未完成切换拒绝。
4. **认证和撤销边界保留。**管理 API 继续要求 Bearer 及服务端当前状态校验，Cookie 不直接充当 API 身份。管理/业务用途不能互用；退出撤销同一会话，不承诺其他独立会话全部退出，不以离线 JWT 签名仍有效判定退出失败。
5. **受限 browser 不放宽。**私网开发 browser 继续按原契约拒绝 refresh/restore，保留过时身份拒绝及期限；普通 token/设备服务期限不能被 browser 限制连带缩短。不能为“完整生命周期”把受限刷新改成成功。
6. **准备和业务副作用不增加。**新模式启动不 seed、不迁移、不补管理员/client/权限、不生成密钥；只核对已准备引用。旧参考仍只补缺、已有不覆盖，不能升级成 P3 匹配协议。旧注册、设备、扫码和 OIDC 不因新模式暂不支持业务而删除。
7. **范围内保持简单。**当前未发现需要公共 Core/Axum/Web 变更或 schema 升级的理由；如果后续核对发现必须跨该边界，先说明必要性和兼容影响，不直接扩大实施范围。

## 5 后续验证计划应包含的最小断言

本节定义未来验收条件，本次不新增测试实现、不执行测试。

| 组合或链路 | 必须规划的断言 |
| --- | --- |
| 输入组合 | UI+browser、无 UI+browser、无 UI+无 browser 三种合法组合；UI 无 browser 为负例。省略/null、http 可省略但不可 null、任一 browser 的 Origin 要求用配置断言覆盖 |
| 管理 token | 登录→受保护 API→刷新→新 token 再访问→退出；退出后刷新前后该会话 access/refresh 经服务端状态校验拒绝。不要先重用旧 refresh 触发家族撤销，混淆 logout 的效果 |
| 正常 Cookie | 登录→用返回的 access 访问管理 API→刷新→再次访问→退出；核对清除同名同 Path、`Max-Age=0`；旧 Cookie refresh/restore 拒绝、对应 access 不通过当前状态校验 |
| 外部路径与关闭条件 | 根及非默认 API mount、独立 UI base 正确；UI 关闭页面/assets 不挂，browser 关闭相关端点不挂，非默认 mount 不留下旧 `/api/admin` 旁路 |
| 用途与既有模式 | 复用已有业务凭证夹具核对用途拒绝，不要求新业务装配；保留 Enabled/Disabled 和受限 browser 原行为 |
| 旧参考及直接嵌入 | 先核对旧归一和共同装配受影响回归，再按实际变化覆盖原参考/独立宿主。既有测试优先，不机械扩大组合笛卡尔积，不以文件未改等同运行通过 |

未来可用已准备的隔离夹具验证管理装配，不依赖 P3 命令；夹具不表示空库全过程已完成，也不能写成 app 自动准备能力。沿用现有两模式/多 mount 用例；新增组合选择代表性非默认 mount 并说明覆盖即可。

阶段归属保持：A01–A05 属 M1-02 收尾；R03 的 P3 同源准备、命令/并发/审计留给 M1-03；R02 的业务 client/transport/路由矩阵和 P6 实际业务启用留给 M1-04。M1-05/06 不用于推迟本次受影响的接口维护或安全回归，且本轮不启动这些工作包。

## 6 回传要求与实施授权边界

接收方后续任务先新增 `docs/m1-02-implementation-adjustments-result.md`，建议标识 `UP-M1-02-IMPLEMENTATION-ADJUSTMENTS-RESULT`，以**静态核对与调整计划**回传。该回传不代表已实施，也不得因本件列有验收断言就开始运行。

必须包含：

1. 本件标识、修订、SHA-256，实际 HEAD/软件/schema、被核对设计与实施报告的版本及摘要；列出工作区差异和是否影响结论，不静默沿用过期行号。
2. A01–A05 逐项表：结论是否仍成立、源码/测试位置、拟修改文件与最小措施、兼容语义、关联 Q 子断言、预计复用素材、剩余待定。实现差异、证据缺口、报告调整分清；如已有变化满足要求，给出静态证据，不重复建设。
3. 依赖顺序：输入缺省与校验→条件装配→管理链路及受影响兼容断言→报告映射。注明当前只是计划，未来代码/测试实现及运行需另行授权。
4. 第 4 节逐项兼容/安全影响及第 5 节覆盖映射，说明哪些原证据仅限历史版本、哪些需要未来增量验证。
5. Q04/Q11/Q12、Q01/Q18 和 Q19–Q21 的状态校正建议：保留修订 2 原始事实及摘要，修订 3 尚无证据的子断言标待验证，不将旧“通过”直接升级。
6. 本任务文档变更范围；现有代码/依赖/测试/示例变化单列为未修改、未验收。代码实施与全部运行验收标为“本任务未执行”，记录未初始化、迁移、构建、部署、提交/推送、未启动 M1-03/04。
7. 待明确事项和下一步最小建议；如实际需要公共契约变更，列理由与替代方案供确认，不直接实施。

如以后明确授权 M1-02 代码调整与验收，再增补实际改动、版本/摘要、命令、夹具范围、结果/失败及 A01–A05/Q 子断言的增量证据。不覆盖当前静态回传或修订 2 历史结果；未运行、ignored、失败与通过分别如实记录。当前不生成未来运行结果。

**本轮到文档同步结束。**不修改上游设计、实施报告或代码，不执行构建、单元/集成/实库/浏览器验收，不初始化、迁移、启动服务、部署或提交推送；试点和部署继续待定。文档同步不代表已向远端或其他聊天发送任务。

## 7 可直接使用的交接任务说明

请阅读 `docs/m1-02-implementation-adjustments-handoff.md`（UP-M1-02-IMPLEMENTATION-ADJUSTMENTS 修订 1），对照 M1-02 设计修订 3 和实际工作区，静态核对 A01–A05，按第 6 节回传 `docs/m1-02-implementation-adjustments-result.md`。重点明确按需 browser/Origin、UI 省略/null、管理 token/Cookie 完整生命周期、旧参考及独立嵌入兼容、修订 2/3 报告映射的最小调整位置和未来验证计划。复用既有管理服务与测试，不重建身份状态机。本次仅源码只读核对和文档回传，不改代码/测试/依赖/schema/运行配置，不构建、不启动运行验收或 M1-03/04；保留现有工作区，代码实施及运行另待明确授权。
