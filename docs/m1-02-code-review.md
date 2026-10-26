# M1-02 实际代码审查与证据核对

| 项目 | 记录 |
| --- | --- |
| 日期 / 状态 | 2026-10-20；只读源码审查完成，问题未修复；本轮未运行软件验收 |
| 被审对象 | `main` / `1835ec35790568fefb9f6792a120b3041cfe77ae` 加当前未提交的 app、依赖与测试增量；3.0.0 / tenant_v6 |
| 原实施依据 | [设计修订 2 固定快照](m1-02-configuration-composition-design-r2.md)、[原实施验收报告](m1-02-implementation-result.md) |
| 后续设计依据 | [当前修订 3](m1-02-configuration-composition-design.md)、[R01–R04 回传](m1-02-design-adjustments-result.md)、[A01–A05 计划](m1-02-implementation-adjustments-result.md) |
| 本轮边界 | 只读代码、测试与调用链，更新文档；不修改代码/测试/依赖，不构建、不启动进程或数据库、不提交；M1-03–06、试点与部署未启动 |

本文记录修复前的审查事实；后续处置与运行证据见[M1-02 修订 3 收尾回传](m1-02-closure-result.md)，以下行号、摘要和当时状态保留。

## 1 结论与基线

**最小共同装配方向可保留，尚不能认定 M1-02 全部契约闭合。**未发现可确认的旧参考默认回归、新模式隐式 seed、管理 API 匿名开放或业务路由意外启用。确认两项修订 2 已有的归一契约偏差，以及修订 3 尚未落地的两个输入/装配差异；管理生命周期证据缺口仍成立。后续修复可限定在 app 内，不需据此重建 Core、修改 schema 或提前启用业务多入口。

本轮没有复跑原验收。原报告的运行次数和通过记录属于历史证据；本报告验证的是断言源码与报告口径能否对应，不把静态阅读写成新一次运行通过。没有找到可确认的 P0/P1 级问题，也不以静态审查证明不存在其他缺陷。

原设计路径已由其他任务更新成修订 3。为防止同一路径造成基线漂移，本轮从当前对话的原始文档修改记录恢复修订 2，逐字节摘要与已有交接件相符，单独保存，不覆盖修订 3。原报告及既有回传均不改写。

| 对象 | SHA-256 |
| --- | --- |
| 修订 2 固定快照 | `d7402bd472d427062c1bf29ec6a745b31518d54dd16dbc644f5c666b651e9ab2` |
| 当前修订 3 | `3af4eba26944b352264a47bc9c11038117db83dffa412ab5d9792de8f92a9e5f` |
| 原实施报告 | `30229cb4ad5226573f687de124d21c8ff4f9a6f9bafc9cbddd93b2de36698f77` |
| composition_config.rs | `007fa4bffdd6ef61e051ad7267b707aa9af7f937019ebda4ed071fb05301bd48` |
| bootstrap.rs | `de73c504b91e9c5de37d88fb849146067fb115d48bad7f9652058f9722df02f4` |
| live_reference_host.rs | `5228a9f1cd7c4c4e89fc6abb00448b96bee2470dc6f831c5d0293e969e1818ff` |

## 2 确认的问题

### F01 · P2 · 构建能力拒绝晚于 Secret 读取（修订 2 偏差，新增发现）

位置：[composition_config.rs](../crates/embedded-idp-app/src/composition_config.rs) 558–576、609–613 行；[main.rs](../crates/embedded-idp-app/src/main.rs) 36/50 行；[bootstrap.rs](../crates/embedded-idp-app/src/bootstrap.rs) 116–117 行。

触发：提供结构、策略、挂载均合法的非空 `business_entries`，同时让声明的数据库 Secret 不存在。`from_file` 先执行 `SecretRef::resolve`，尚未返回 `AppConfig` 就报 `missing secret`；只有解析成功进入 `build_composition` 才检查当前构建不支持业务入口。Secret 存在时也会进行无必要的读取。

修订 2 §3.1 要求所需能力静态校验先于 Secret 解析；原报告所称“不支持组合在密钥/数据库/监听前拒绝”仍成立，但不能延伸成“不读取 Secret”。这不是数据库写入或已证实的 Secret 泄漏，影响是错误优先级、配置诊断和早期失败边界不符。

建议：启动路径按“严格结构与冲突 → 静态绑定/挂载 → 当前构建支持 → 必要 Secret 解析 → 密钥/数据库 → 装配”处理。保留独立配置解析对合法非空集合的支持，不把当前构建能力限制写成格式永久禁令。无需新增公共配置框架。

补充断言：合法非空集合、缺 Secret 时首先得到明确 unsupported，lookup 次数为 0；空集合合法输入仍读取已声明 Secret；静态非法输入与来源冲突仍优先拒绝。纳入 Q02/Q04/Q19 增量。

### F02 · P2 · 显式 email 配置未形成共同参数（修订 2 偏差，新增发现）

位置：同一配置文件 47–59、558–577、859–889 行。`runtime.email` 被反序列化和检查；SMTP password 被解析后立即丢弃。显式模式 `AppConfig` 没有保存 email；`EmailDeliveryConfig` 仅存在于 `ReferenceBusinessConfig`。

触发：显式配置有效 `runtime.email`（例如 smtp、合法 username/password_ref）后解析成功，返回值没有 provider、发送参数及 Secret 的有效配置。sendmail 相对路径也没有进入与 JSON 目录一致的归一结果。修订 2 §3.3 / 附录 A.4 要求共同 typed email；“已解析校验”不足以证明“已归一”。

当前 `business_entries=[]` 不需要发送邮件，非空集合又被构建拒绝，因此没有可运行的注册邮件故障。问题是配置层交付不完整，未来消费者若读取环境或再次解析 JSON，会破坏单一来源；应在业务装配前闭合，不能仅依靠原 Q20 的“部分通过”隐藏具体缺口。P1/P2 本身不需要邮件参数，不把它写成管理员准备已故障。

建议：app 内保存可选 typed email 的有效值及必要引用/解析结果，复用现有默认；仅消费对应 provider 时构造发送器。不新增邮件服务、不执行发送、不因本项启用注册或 M1-04。无消费方时是否延后解析 SMTP Secret，应在实现前明确并写入同一处理顺序，不能读取后无声丢弃。

补充断言：email 缺省为 None；显式 log/sendmail/smtp 的有效默认及路径有可检查的归一结果；Secret 来源与空值错误保持，诊断不含内容；旧 email 逐字段不变。归入 Q01/Q04 与配置完整性增量。

### F03 · P2 · 管理 browser 仍不可关闭（修订 3 差异，既有 A01）

位置：配置文件 77/138/197、490 行；bootstrap 118–120、266–276 行。HTTP/Origin/browser 强制存在，装配无条件创建 browser router。修订 3 的 token/API-only 示例会在结构阶段被拒绝。

这符合修订 2 当时“管理 browser 必需”的定义，不能反向写成原实现违约；但不满足已接受的 R04。建议按启用条件构造 browser，管理 token/API 保留；旧输入显式填原 browser，不继承新缺省。关闭后不能填假 Origin 通过校验，也不能移除签名、管理员或 client 前置。沿用 A01 的最小范围和三组合断言。

### F04 · P2 · 省略 management.ui 被主动拒绝（修订 3 差异，既有 A02）

位置：配置文件 394–401、1054–1063 行。虽然字段为 Option，额外检查要求必须出现，测试还明确断言省略失败。修订 2 要求字段出现且允许 null；修订 3 改为省略/null 均关闭，因此需同步改输入与反向断言。UI 开启但 browser 关闭的负例仍须拒绝；不能为了页面显示暗中恢复 browser。

### F05 · P2 · 新模式管理生命周期证据未闭环（覆盖缺口，既有 A03/A05）

位置：[live_reference_host.rs](../crates/embedded-idp-app/tests/live_reference_host.rs) 1401–1453 行。当前显式模式测试覆盖 token 登录/session/受保护 clients API；Cookie 登录、刷新 200、退出 204。缺少 token 刷新/退出、新 token 再访问、退出后 access/refresh 当前状态拒绝、Cookie 清除同名/同 Path/Max-Age=0、最后有效 Cookie 退出后的恢复/刷新拒绝和该会话 access 拒绝。

这些端点在原管理 router/Core 已存在；缺断言不等于实现必定错误。修订 2 Q12 只要求仅管理路由与依赖前置，原报告“通过”可以保留为该历史子集；修订 3 已扩大 Q12，当前只能标“旧子集有历史证据，新增生命周期待验证”。旧参考组合回归和单入口浏览器截图不能代替新挂载条件下闭环。复用 A03 的验证计划，不重复建状态机。

用最后有效 refresh/Cookie 做退出后断言；不要先重放旧 refresh 触发家族撤销，再把失效归因给 logout。业务用途对照可用原夹具，不必启动新业务装配。

### F06 · P2 · 历史报告链接指向变化中的设计（文档可追溯性，既有 A05）

原报告标“修订 2”，链接实际打开修订 3；仅记录同一 HEAD 也无法识别未提交源码差异。后续报告应链接固定快照并记录工作区摘要，分开历史与增量状态。本轮提供固定快照和本表，不重写旧运行记录、不把原失败或 ignored 消除。

## 3 已核对而未发现偏差的主要面

| 审查面 | 实际代码结论 | 证据与限制 |
| --- | --- | --- |
| 旧输入与默认 | `config.rs` 旧 parser 未改；`from_legacy` 原值转换，原 entry/client/策略、注册 true、Cookie 名/Path、UI/API 路径保留 | 配置 323 行起；逐字段测试及 HEAD diff。未重新运行旧环境矩阵 |
| 旧补缺 | public → management → optional confidential 顺序、`ON CONFLICT DO NOTHING` 保留；已有不覆盖，不比较匹配，部分失败仍可留下此前插入 | bootstrap 189–208 行及 seed helper；不是 P3 原子准备 |
| 旧扩展 | device/registration/OIDC/scan 仍在 legacy 分支；原 provider、证明路径、JWT/JWKS 及 cleanup 保留 | bootstrap 300 行后与 HEAD 对比；没有把新业务 unsupported 用于删除旧路由 |
| 严格配置 | 递归检测重复 key 后才转 map；未知字段/类型/null/version 拒绝；CLI 不回退环境 | composition_config Unique/Document、main 与 explicit_config_cli；错误细节见 F01 |
| 来源与 Secret | 先收集引用名称、判冲突，只有明确 PG/SMTP 旧 Secret 白名单例外；未指定环境不覆盖；文本限量、UTF-8、非空、常规文件检查 | SecretRef/read_limited；未输出原始值。未做文件竞态/故障注入，不泛称安全认证 |
| 管理安全 | purpose/audience 独立，管理 proof=true 明确拒绝；管理 API 仍经原管理服务与当前状态鉴权 | bootstrap、Axum management_auth、Core management；F05 是新组合证据缺口 |
| 仅管理边界 | 显式模式无 legacy extension，管理路由构造后返回；无 business/registration/device/scan/OIDC/discovery/JWKS 或 scan cleanup | bootstrap 298 行附近早返回；合法非空集合明确拒绝 |
| 新模式无写启动 | readiness + auth_transaction 查询 tenant/client；FOR SHARE 属锁，不是身份数据修改；未调用写接口或准备函数 | bootstrap 594 行起、Postgres transaction 实现；运行中的登录/刷新/管理写入正常保留 |
| 挂载与 Cookie | ASCII mount、逻辑入口/client/Cookie 唯一、路由族和 UI/assets 冲突；根 API meta 使用 `/`，非默认原值；原 meta 替换且唯一 | 配置 validate_static/admin_ui；单文件无法保证跨进程 Cookie/entry 唯一 |
| 探针 | readyz 只做基础 readiness，不重跑入口引用行锁；client 移除后基础 ready 不代表入口可登录 | health_router 与显式缺 client 测试；总时限/SQL取消/容量未得到证明 |
| 嵌入边界 | 未改 Core/Axum/Postgres/Web 公共出口、schema；no-tenant-host 不依赖 app 配置 | tracked diff 与依赖；本轮未复验独立宿主 |

模板是仓库控制的构建产物，当前字符串替换足够匹配已知模板；不能把它描述为通用 HTML 解析器。UI 改版仍须保留两个 meta 的唯一性，不能因此引入宽泛 HTTP fallback。

## 4 Q01–Q22 完整证据核对

“历史支持”表示原报告记录了相应运行且当前断言源码存在，本轮没有复跑。r3 状态不能沿用 r2 整项标签。

| Q | 当前审查判断 | 未闭合或增量 |
| --- | --- | --- |
| 01 | 旧归一/旧流程有历史支持 | A01/A02 调整后仍需旧默认回归；F02 typed email |
| 02 | 来源冲突与惰性 lookup 有断言 | F01：不支持能力也须在读取 Secret 前拒绝 |
| 03 | 严格结构与 CLI 错误有断言 | r3 省略 ui/http/browser 合法组合未实现；不可引用原反向测试作通过 |
| 04 | Secret/密钥/传输负例有历史支持 | F01/F02；r3 可选 browser 条件；真实 TLS/CA 未验证 |
| 05 | 静态矩阵及新两 mode Fixed0 有支持 | 新管理 Choose/Fixed 非0完整 HTTP 组合未执行 |
| 06 | entry/client/Cookie 唯一静态覆盖 | 新业务实际多入口未启用 |
| 07 | 缺/坏 client、缺管理员/错 mode 无写负例有支持 | 多 Fixed 引用组合待后续；不据“缺管理员”替代“缺 tenant” |
| 08 | 原 Core 规则保持，配置静态部分有支持 | 新组合停用租户、Choose 零业务域未完整验证 |
| 09 | 路径语法/冲突及管理多 mount 有支持 | 不等于未来附带业务端点全部展开完成 |
| 10 | Cookie 静态冲突与单入口有支持 | 跨入口 A/B、多标签及跨进程审阅未完成 |
| 11 | 根/非默认 mount、唯一 meta、历史浏览器有支持 | r3 关闭组合；退出闭环、协调范围保持需随 UI 改版再验 |
| 12 | r2 启动前置与仅管理范围有支持 | r3 只能部分覆盖：F03/F04/F05，未完成三合法组合生命周期 |
| 13 | 成功/失败启动、probe 全表快照与 sentinel 有支持 | 快照不证明无锁或严格总时限 |
| 14 | 旧 seed 代码语义保留，原报告已标部分 | 旧模式在线修改后重启、部分 seed 失败故障注入尚不完整；新模式不覆盖测试不能充当旧 seed 测试 |
| 15 | 新管理重启 token/Cookie/原期限有支持 | refresh/selection/code、无关入口增删/重排不能由此推定 |
| 16 | 原绑定检查保持 | 无自动迁移/历史注册表；未完整验证每类凭证变更 |
| 17 | 新不支持扩展明确拒绝；旧组合保留 | 新协议组合待后续，F01 改错误顺序不应改变旧能力 |
| 18 | 公共层未变、历史离线回归 | 完整独立宿主运行/浏览器未另验，不升级证据 |
| 19 | 独立解析允许非空、build 拒绝 | F01 早期 Secret 边界；支持业务的构建对照未交付 |
| 20 | 参数设计与部分解析/fixture 有支持 | 非默认 TLS/CA 和真实 P1/P2 全字段同源没有完整证据；无投影工具不等于违约（原设计明确不新增） |
| 21 | CLI 冲突/干净环境、管理员保护部分有支持 | P3 和完整 P1–P6 未交付，保持 M1-03/04 边界 |
| 22 | 基础 probe 无写/缺client后的行为有支持 | 并发探针、锁等待、取消与容量未验；串行通过不证明并发 catalog 问题解决 |

原报告保留的首次并行 catalog 失败、串行重跑、ignored 实库用例，以及本地合成浏览器边界均应继续保留。这里没有发现把 ignored 直接计为实库通过的表述。没有复核原机器运行日志的全部时间戳，不能作独立运行复证。

## 5 后续最小修复与设计衔接

建议后续获授权后按以下顺序工作，本轮只给计划：

1. app 配置层闭合 F01/F02 与 A01/A02；保持格式有效性和构建支持两阶段，不增加环境 fallback 或新的配置格式。
2. app 条件装配启用完整管理 token/API 与可选 browser/UI；继续复用原服务，不增加认证状态机。
3. 在原配置/CLI/真实进程夹具补 F01–F05 子断言，补旧补缺不覆盖的实际旧模式证据；保留被影响的旧参考/嵌入回归。
4. 增量报告用固定 r2 与 r3 映射，不改历史运行结果；相关验收通过后再决定后续阶段。

管理后台与社区能力的详细提案见[管理后台与能力补齐设计](management-console-capability-design.md)。UI 工作可以复用现有 API；新增身份能力分别立项，不能把后台换外观算成这些能力已交付，也不能把这些建议悄悄塞进 M1-02。

本轮只做文档链接、基线摘要和源码未变检查。所有修复、运行验收、部署与提交均未执行。
