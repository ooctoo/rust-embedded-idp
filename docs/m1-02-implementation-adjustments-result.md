# M1-02 实现审查调整静态核对与计划回传

| 项目 | 内容 |
| --- | --- |
| 文档标识 | UP-M1-02-IMPLEMENTATION-ADJUSTMENTS-RESULT，修订 1，2026-10-20 |
| 文档上下文 | `rust-embedded-idp` 按实现审查交接件第 6 节形成的上游静态回传，供需求方接收调整计划 |
| 需求目标 | 核对 A01–A05 是否仍成立，给出最小文件范围、兼容影响、验证映射及剩余事项 |
| 建议实施方案 | 后续依次调整 app 输入缺省/校验、条件装配、管理链路及受影响兼容断言、报告映射；复用既有认证服务，不改领域状态机 |
| 接收依据 | [UP-M1-02-IMPLEMENTATION-ADJUSTMENTS 修订 1](m1-02-implementation-adjustments-handoff.md)，SHA-256 `7e391497ee954e7910e4d121c292522848ef40609855245f2d0e5358cb347b81` |
| 实际基线 | 本地 `main`，HEAD `1835ec35790568fefb9f6792a120b3041cfe77ae`；workspace 3.0.0；Access schema `tenant_v6`；未刷新远端 |
| 结论 | A01–A05 均仍成立；没有发现可直接关闭的调整项，也没有发现必须改公共契约或 schema 的前置需求 |
| 授权边界 | 仅静态核对及文档回传。代码/测试实现及全部运行验收均为“本任务未执行”；不启动 M1-03/04，未来实施与运行另待明确授权 |

## 1 实际版本与工作区差异

交接基线中的五份文件摘要全部一致，源码静态定位也与交接事实一致。HEAD 相同不代表这些未提交文件属于该提交；本次核对包含工作区增量。

| 被核对对象 | 版本与 SHA-256 |
| --- | --- |
| [权威设计](m1-02-configuration-composition-design.md) | UP-M1-02-DESIGN 修订 3；`3af4eba26944b352264a47bc9c11038117db83dffa412ab5d9792de8f92a9e5f` |
| [既有实施报告](m1-02-implementation-result.md) | 日期 2026-10-20，声明基于设计修订 2；`30229cb4ad5226573f687de124d21c8ff4f9a6f9bafc9cbddd93b2de36698f77` |
| `composition_config.rs` | `007fa4bffdd6ef61e051ad7267b707aa9af7f937019ebda4ed071fb05301bd48` |
| `bootstrap.rs` | `de73c504b91e9c5de37d88fb849146067fb115d48bad7f9652058f9722df02f4` |
| `live_reference_host.rs` | `5228a9f1cd7c4c4e89fc6abb00448b96bee2470dc6f831c5d0293e969e1818ff` |

软件版本已从根 `Cargo.toml` 核对；schema 从 `crates/embedded-idp-storage-postgres/src/access.rs::ACCESS_SCHEMA_VERSION` 核对。这里没有数据库运行探测。

开始时既有工作区变化如下，均未由本任务修改或验收：

| 类别 | 路径 |
| --- | --- |
| 已有依赖改动 | `Cargo.lock`、`crates/embedded-idp-app/Cargo.toml` |
| 已有 app 改动 | `src/admin_ui.rs`、`src/bootstrap.rs`、`src/config.rs`、`src/main.rs`；新增 `src/composition_config.rs`，均相对 `crates/embedded-idp-app/` |
| 已有测试改动 | `crates/embedded-idp-app/tests/live_reference_host.rs`；新增 `tests/explicit_config_cli.rs` |
| 已有示例 | 新增 `docs/examples/m1-02-management.json` |
| 已有文档 | README 的先前入口改动、M1-01 三份资料、M1-02 设计与四项调整交接/回传、五项实现调整交接件、既有实施结果 |

公共 Core/Axum/Postgres/Web 文件未出现在当前 tracked diff 中。下文仍逐项查看相关服务和独立宿主入口；“公共文件未改”仅支持静态边界判断，不是运行通过。

## 2 A01–A05 逐项核对与最小措施

| 编号与性质 | 当前静态证据 | 后续拟修改文件与最小措施 | 兼容与 Q 映射 | 复用素材与待办 |
| --- | --- | --- | --- | --- |
| A01 实现差异，仍成立 | [配置模块](../crates/embedded-idp-app/src/composition_config.rs) 第 77/138/197 行依次要求 http/Origin/browser；第 490 行固定 `Some`；[装配模块](../crates/embedded-idp-app/src/bootstrap.rs) 第 118–120、266–276 行无条件创建管理 browser | 只在 app 配置模块调整输入可省略与内部缺省表达，在 `validate_static` 保留已给字段校验、按启用 browser 校验 Origin/Cookie；装配模块按条件构造/挂载 browser，独立保留管理 token/API | 全体 browser 关闭可省略 http，不接受 http=null，不填假 Origin/Cookie；任一 browser 启用保留原安全门禁。Q04/Q12、R04 | 复用现有配置单元测试和显式进程夹具；内部可选值的具体写法留实施，不新增配置框架或公开类型 |
| A02 实现/反向测试差异，仍成立 | 配置模块第 394–401 行主动拒绝省略 ui；`structural_errors_report_path_without_value` 第 1054 行起断言该输入失败；当前 ui 已是可选类型 | 在同一模块去除额外必填检查、更新该断言；增加 UI 启用且 browser 关闭的明确校验；保留 UI 已有路径冲突检查 | 省略/null 均关闭 UI；无 UI+browser 合法；不自动开启 browser。Q03/Q04/Q11/Q12、R04 | 复用 `ui_and_paths_are_checked` 及模板测试；`admin_ui.rs` 无需为“无 UI”增加空页面或可选 meta，装配不调用即可 |
| A03 管理链路证据缺口，仍成立 | `management_router` 已有 refresh/logout；显式进程测试第 1401–1452 行覆盖 token 登录/读取、Cookie 刷新200/退出204，但未闭合新模式 token 刷新退出和退出后失效 | 扩充 `tests/live_reference_host.rs` 的配置辅助与现有显式管理测试，补 token/Cookie 全链路及关闭组合；若以后运行发现实现问题，再限定在实际问题处处理，不预先重建状态机 | 对应会话撤销、Bearer 管理 API、用途拒绝、真实 Cookie Path、私网受限语义。Q11/Q12、R01 | 原管理 router、Core 管理服务、BrowserSession 清除；旧两模式 token/browser 测试；详细覆盖见第 5 节。测试存在不视为运行通过 |
| A04 受影响兼容保障，仍需补齐 | `from_legacy` 第 323 行起显式保留两个 browser、旧标识/挂载；原参考分支保留；独立宿主依赖不含 app，公共接口未见变更 | 配置模块的旧归一测试与现有进程回归随 A01/A02 补核对；优先扩充既有断言，不另建宿主/兼容包装层；公共库与 Web 原则上不改 | 旧默认不得随新 JSON 可省略而关闭；原 proof/Choose/Fixed/Disabled 与 provider/catalog 注入不变。Q01/Q17/Q18、受影响 Q15 | `legacy_mapping_preserves_existing_browser_contract`、旧参考/扫码/受限 browser、独立宿主现有素材；原报告只覆盖原实现，不替代调整后回归 |
| A05 报告映射调整，仍成立 | 既有报告仍写设计修订 2，Q12 为“通过”；其设计链接现指向修订 3 同一路径，缺少新增条件的结果区分 | 当前只在本回传列出修正建议；未来实施回传增补 A/Q 子断言和源码摘要，保留修订 2 原始结果，标识固定历史依据 | 不把旧通过升级为修订 3 全部通过；Q04/Q11/Q12、Q01/Q18 和 Q19–Q21 分阶段。见第 6 节 | 历史修订 2 摘要可从已有四项设计调整交接件核对；未来报告组织可直接增补历史与增量章节，无需报告框架 |

本任务对 A01/A02 的结论为“确认仍有契约差异”；对 A03/A04 为“确认需补覆盖/证据”；对 A05 为“确认需修正映射”。五项计划均未实施，全部运行验收为本任务未执行。

## 3 后续调整顺序与文件范围

1. **输入与静态校验。**在 `composition_config.rs` 保留严格 JSON、重复 key/未知字段/错误类型与惰性 SecretRef 行为；使 browser/ui 缺省符合修订 3，http 可省略且不可 null。仅给出 http 的情况仍校验其字段类型/语法，不能靠构造假 Cookie 满足校验。保留显式字段原安全门禁，不新增环境 fallback。
2. **条件装配。**在 `bootstrap.rs` 保留管理 token 服务与受保护 API。仅对启用 browser 构造 BrowserSession 服务/router；仅对启用 UI 调用既有 UI 构造器。browser 生命周期限制仅作用于对应 browser 服务，不连带缩短普通 token/设备服务。`from_legacy` 持续显式填入原两个 browser 和 UI，旧入口不改。
3. **管理链路与兼容断言。**先扩充配置单元断言，再调整原 `live_reference_host.rs` 配置辅助，保留默认既有组合，补三种合法组合、非法 UI 组合及完整管理生命周期。复用已有重启、无写、用途隔离及旧参考测试；CLI 离线 target 主要继续保护来源/错误，无需为了新增组合创建第二套 CLI。
4. **增量回传。**实际实施及运行获明确授权后，记录当时源码与设计摘要、真实命令/夹具/失败及 A/Q 子断言状态，再增补报告。当前仅交付这份计划，不修改既有实施报告，也不生成未来运行结果。

预期必要代码/测试文件仅为 app 的 `composition_config.rs`、`bootstrap.rs` 和 `tests/live_reference_host.rs`，单元测试随配置模块维护。`admin_ui.rs`、`main.rs`、旧 env parser、CLI target、现有示例原则上复用；若实施发现必须修改，须说明具体触发和必要性，不能把上述范围写成已经修改。当前未发现需新增依赖、改 lockfile、公共服务契约、SQL/schema 或 Web 公共构造器的理由。

## 4 兼容和安全影响逐项回传

| 交接件第 4 节约束 | 静态核对与后续保护 |
| --- | --- |
| 1 公共嵌入独立 | [独立宿主 Cargo.toml](../examples/no-tenant-host/Cargo.toml)直接依赖原库，未依赖 app。新 JSON 不进入 Core/Axum 模块契约，原宿主可信 provider/token/transport/catalog 注入及模块根路由不变；无需为内部 `build_composition` 新增公共包装 |
| 2 旧输入行为 | `from_legacy` 显式生成 `management/idp-management`、`business`、原 client/policy；Cookie 名与 `/api/admin/auth/browser`、`/auth/browser` 保留。旧 UI 包装仍使用 `/api`。后续对旧来源保留原值，不从新 JSON 缺省倒推旧默认 |
| 3 租户策略 | `policy` 继续管理 Fixed 0 例外再调用原校验；原服务仍执行用途/成员/权限规则。管理 Fixed 0、管理 Choose 不进平台0、Disabled Fixed0、管理 proof拒绝及 Choose源会话语义均不因可选 browser 改变；未运行矩阵 |
| 4 认证与撤销 | [管理 router](../crates/embedded-idp-axum/src/management_auth.rs)第 34 行起已有独立 login/session/refresh/logout，受保护管理路由有 Bearer 中间件；[管理服务](../crates/embedded-idp-core/src/access/authentication/management.rs)第 115 行起复用刷新、退出事务核对身份并撤销家族。保留当前状态校验、对应会话范围，不能以离线 JWT 签名判断退出失败 |
| 5 受限 browser | [BrowserSession HTTP](../crates/embedded-idp-axum/src/browser_session.rs)退出仍保留受限模式 expected_session 要求；原私网回归明确覆盖 refresh/restore 拒绝。后续不改其能力，不将 browser TTL 传播给普通 token；验证计划分别覆盖正常和受限模式 |
| 6 准备/业务副作用 | 旧 seed 仍只在 reference 分支，显式模式只检查引用并只管理装配；合法非空业务集合仍由 `validate_for_startup` 拒绝。后续不加入管理员/client准备命令、启动seed、迁移或默认业务入口，不删除旧注册/设备/OIDC/扫码 |
| 7 最小公共影响 | 当前仅 app 条件依赖需调整；若实际发现公共接口或认证语义必须变化，先回报理由与替代方案，不能直接扩范围 |

## 5 后续验证覆盖与素材映射

以下均是**计划，测试实现与运行本任务未执行**。可用已准备隔离夹具，不依赖 P3，也不把夹具当成软件准备能力。

| 覆盖主题与 Q | 计划断言 | 预计复用位置 |
| --- | --- | --- |
| 输入组合，Q03/Q04/Q12 | browser/ui 省略与 null 均关闭；三种合法组合及 UI 无 browser 负例；全体 browser 关闭可无 http，http=null 拒绝；任一 browser 启用要求有效 Origin/Cookie，保留 feature/transport/TTL 门禁 | 配置 `structural_errors_report_path_without_value`、`rejects_duplicate_null_and_unknown`、`ui_and_paths_are_checked`、原安全配置测试；业务 browser 仅做配置层断言 |
| 管理 token，Q12 | 三种合法组合均登录→受保护 API→刷新→新 token 再访问→退出；退出后该会话刷新前后 access/refresh 均按状态拒绝；先不要重用旧 refresh，以免家族撤销混淆 logout 效果 | `explicit_management_only_is_read_only_at_startup_in_both_modes_and_mounts`；旧参考 token 链路素材 |
| 正常 Cookie，Q11/Q12 | 两个启用 browser 的合法组合分别登录，用返回 access 调管理 API，刷新后再访问，退出；清除同名同 Path且Max-Age=0；退出前最后有效 Cookie 的 restore/refresh 拒绝、对应 access 拒绝，不能只拿已因轮换失效的更早 Cookie 作为退出证据 | 上述显式管理测试、`browser_cookie_restore_logout_and_purpose_isolation_in_both_modes`、原 BrowserSession helper |
| 路径与关闭，Q11/Q12 | 根及非默认 mount，独立 UI base；无 UI 页面/assets 不挂，无 browser 端点不挂，管理 API仍鉴权；非默认 mount 不留下旧 `/api/admin` 旁路 | 原多mount循环、`explicit_management_probe_missing_client_and_no_ui`、UI meta唯一/模板错误测试 |
| 用途与受限模式，Q12/Q17 | 用既有业务夹具核对管理/业务凭证不能互用，不启用新业务装配；受限 browser 的 refresh/restore 继续拒绝，expected_session、过时身份和期限保留 | 旧用途隔离、`private_http_development_bounds_browser_sessions_and_rejects_stale_identity` |
| 旧参考/嵌入，Q01/Q15/Q17/Q18 | 旧归一逐字段和原 Cookie配置一致；两个mode旧参考、重启期限/在线client保留、扫码及独立宿主契约按实际改动回归 | `legacy_mapping_preserves_existing_browser_contract`、旧参考流程、重启测试、独立宿主现有素材 |
| 原安全/无写边界，Q02/Q07/Q13及受影响项 | 缺依赖/坏配置仍拒绝、无Secret输出、无旧fallback；关闭 browser不减少签名/DB/管理员/client前置，启动与probe不写 | 既有缺依赖/坏key-client/快照/sentinel、配置惰性lookup、独立CLI target |

沿用原两模式/多 mount 用例，不要求把所有选项做笛卡尔积。新增关闭组合选择代表性非默认 mount；回传说明哪个用例覆盖哪个分支。原 Core 管理实库测试 `authentication/management.rs` 由 `live_tenant_registration` 引入，后续复用时不能误当独立 target。

## 6 实施报告与 Q 状态修正建议

本节是后续报告修正计划，未修改旧报告，也未宣布任何新的运行通过。

| Q 范围 | 旧报告可保留的历史事实 | 修订 3 当前状态及后续补充 |
| --- | --- | --- |
| Q03 | 旧严格结构/错误输入记录 | 省略 ui 从拒绝改为合法，新增关闭组合仍待实施验证，不能继续引用原反向断言作支持 |
| Q04 | 原 Secret、传输门禁记录及其未验真实TLS/私网范围 | browser可关闭、http可省略、非法UI组合仍有实现差异；修订3增量待验证 |
| Q11 | 原 UI meta/挂载、DOM/登录读取报告 | 仅历史原组合；补省略UI、无browser和新链路映射，不把原通过扩为全部条件通过 |
| Q12 | 原两mode空业务、依赖负例和ui:null报告 | 旧“通过”只针对原断言子集；修订3完整token/Cookie生命周期及三合法组合未完成，待实施验证 |
| Q01/Q18 | 原归一、旧参考和workspace/Web/独立宿主离线报告 | 未见公共契约破坏是静态结论；A01/A02后的受影响兼容回归待运行，不升级历史证据 |
| Q19 | 原合法非空解析、当前构建拒绝启用 | 保持本构建边界；业务支持组合及真实生命周期仍属M1-04 |
| Q20/Q21 | 原参数/CLI/夹具和管理员保护报告及已注明限制 | P3同源准备/命令/并发/审计仍属M1-03；P6属M1-04，不因本回传列为完成 |

历史设计修订 2 的 SHA-256 为 `d7402bd472d427062c1bf29ec6a745b31518d54dd16dbc644f5c666b651e9ab2`，已由 [四项设计调整交接件](m1-02-design-adjustments-handoff.md)记录。现有报告的“修订2”链接指向最新同一路径，未来应固定历史依据并将修订3增量单列。若未提交，记录工作区相关文件摘要，不能只记相同 HEAD；不删除旧失败、串行重跑、ignored 或本地合成浏览器限制。

## 7 待明确事项与下一步最小建议

| 事项 | 当前判断及后续处理 |
| --- | --- |
| 产品或部署选择 | 五项收尾没有新增必须由需求方选择的产品参数；试点/部署仍待定，本回传不选值 |
| 内部可选字段写法 | 在 app 内完成，不冻结公开 Rust类型或整份JSON/CLI发布契约；保持“http省略合法、null非法”和已给字段校验 |
| 未来测试夹具与命令 | 需要实施/运行任务时再确定隔离目标和最窄测试范围；本次不创建DB、启动进程或运行现有测试 |
| 公共出口或schema需求 | 当前未发现；若后续发现必要，说明触发、兼容影响及最小替代，先回报再扩范围 |
| 下一步 | 先接收本静态核对和调整计划，再明确是否授权M1-02代码调整及相应运行范围。不得据本文件自动实施 |

R03/P3 的同源准备、命令/并发/审计仍归 M1-03；R02/P6 的业务client/transport/路由矩阵和实际组合仍归 M1-04。当前没有启动这些工作包，也没有把正常管理链路验收延期给它们。

## 8 本次交付和检查边界

本任务在上游仅新增本文 `docs/m1-02-implementation-adjustments-result.md`，并在 README 更新对应回传入口。原交接件、设计修订3、设计回传、实施报告及示例不改；既有代码/测试/依赖/schema/运行配置变化均保持，不纳入本任务验收。

静态核对包含实际版本/摘要、A01–A05源码与测试位置、已存在管理路由/撤销/Cookie清除、兼容边界及A/Q映射；文档检查包含链接、章节、编号与摘要一致性。这些检查不等于 app配置解析或软件测试。

代码/测试实现及全部构建、单元/集成/实库/浏览器运行验收均为**本任务未执行**。未初始化、迁移、启动服务、部署、提交或推送，未启动 M1-03/04；当前回传只关闭静态核对与计划交付，不关闭五项实现/运行待办。需求方另行记录接收，不因本文存在自动认定计划已获实施授权。
