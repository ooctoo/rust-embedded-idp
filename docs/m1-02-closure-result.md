# M1-02 修订 3 收尾实施与验收回传

| 项目 | 记录 |
| --- | --- |
| 日期 / 工作包 | 2026-10-20；M1-02 配置归一与最小共同装配收尾 |
| 依据 | [设计修订 3](m1-02-configuration-composition-design.md)、[实际代码审查 F01–F06](m1-02-code-review.md)、[A01–A05 调整计划](m1-02-implementation-adjustments-result.md) |
| 历史依据 | [设计修订 2 固定快照](m1-02-configuration-composition-design-r2.md)、[原实施报告 §1–5](m1-02-implementation-result.md)；保留原并行失败、串行重跑、ignored 与证据边界 |
| 源码基线 | `main` / `1835ec35790568fefb9f6792a120b3041cfe77ae` 加既有未提交工作；软件3.0.0 / tenant_v6。本轮未刷新远端 |
| 执行范围 | 修复归一偏差、可选 browser/UI、管理生命周期与受影响兼容回归；后台界面未改 |
| 本轮结论 | 上述收尾范围已完成，相关检查通过；Q01–Q22 按本阶段子断言回传，未扩展为完整 M1 交付 |
| 后续边界 | 不启动 M1-03–06；管理 client 准备、业务运行组合、OpenAPI、整体交付、试点与部署继续待定；未提交或推送 |

## 1 实际处理

| 项目 | 本轮改动 | 兼容与范围 |
| --- | --- | --- |
| F01 能力门禁顺序 | 严格结构/来源冲突/静态校验后，生产 `from_file` 先核对当前构建支持，再解析 PG/SMTP Secret；build 前保留防御检查 | 独立解析仍接受合法非空集合，当前构建不支持运行；没有写成永久格式限制或环境 fallback |
| F02 typed email | `AppConfig.email_delivery: Option<EmailDeliveryConfig>` 保存有效 provider、默认、路径和已解析 Secret；legacy 从原参数原值转入共同字段 | 仅 legacy 消费该配置并构造原发送器；显式仅管理不发送邮件或启用注册；没有新增 provider |
| A01 / F03 browser 可选 | 内部 Origin 为 Option；新输入缺省/null browser 关闭，http 可省略且不可 null；按实际入口依赖检查 Origin | 没有假 Origin/Cookie；任一业务 browser 也要求 Origin（配置层验证，不启用业务运行）；旧输入显式保留两个 browser |
| A02 / F04 UI 可选 | 去掉 UI 额外必填和旧反向断言；缺省/null 关闭，UI 开启而 browser 关闭在监听前拒绝 | 无 UI 不调用原 UI 构造器、不挂首页/assets；已有 UI 资源与注入方式不改 |
| A03 / F05 生命周期 | 复用原管理 token/browser 服务，补完整 HTTP/DB 断言与三合法组合 | 没有新增认证状态机、撤销规则或新业务 router |
| A04 旧参考保障 | 保留旧 env parser/default/entry/client/注册/Cookie/路由/seed；新增两 mode 旧 client 修改回调后重启不覆盖断言 | 旧 seed 仍为原缺失插入，不改成创建/匹配/冲突协议；部分补缺失败不承诺原子 |
| A05 / F06 回传 | 本文记录修订 3 增量、固定历史基线和本轮摘要；原报告指向固定修订 2 并增加后续入口 | 不把历史 Q12 子集通过当作修订 3 全部通过，也不抹去原失败 |

### 1.1 具体输入与 Secret 规则

合法组合为：UI+browser、仅 browser、token/API-only。`ui` 与 `browser` 可省略或为 null，均关闭；`runtime.http` 可在无任何 browser 时省略，给出 null 仍失败。给出的字段继续校验类型/语法、传输 policy 构建门禁及开发 TTL 范围。启用 browser 才调用原 BrowserSession 构造器，保留原 Origin/Cookie/Path 与安全校验。

有意保留“显式 email 配置要完整归一”的语义：即使仅管理不消费发送器，显式声明的 SMTP Secret 仍在能力门禁后解析、校验并保留，不读取后丢弃。省略 email 则为 None，不要求邮件 Secret。只读启动不构造显式发送器、不发测试邮件。SMTP 的 localhost/587/starttls、默认发件人/主题等沿用既有值；显式 sendmail 相对路径以 JSON 所在目录解析，旧来源原路径不改。

新增[仅 token/API 示例](examples/m1-02-management-token-only.json)，保留[原 UI+browser 示例](examples/m1-02-management.json)。两者均只引用预先准备的 schema、密钥、管理员和 public/PKCE 管理 client；不是准备命令或生产部署配置。`bootstrap-admin --config` 仍不支持，原 P1/P2 同源临时参数衔接不变。

## 2 真实验收断言

### 2.1 正常管理生命周期

在两种 tenancy mode 下验证：

- UI+browser：根、`/api`、`/identity` 三种 API mount，UI 独立位于 `/console/`。
- 仅 browser：代表性 `/identity`，UI 省略。
- token/API-only：代表性 `/identity`，browser/UI 分别省略和 null，http 省略。

每种合法组合均执行 token 登录 → 当前 session / 受保护 clients API → refresh → 新 access 访问 → Bearer logout。退出后刷新前后 access 都被受保护 API 按当前状态拒绝，刷新前后 refresh 均拒绝；另一个独立登录会话仍可用。退出前不重放旧 refresh；退出后先检查最后有效的 refresh，再检查已轮换的旧 refresh，避免重放副作用干扰对 logout 的归因。

启用 browser 的两类组合另外执行 Cookie 登录 → 返回 access 访问管理 API → Cookie refresh → 新 access 访问 → 带完整 expected_session 退出。清除 Cookie 的名称与 Path 精确匹配，Max-Age 精确为0；退出前最后有效 Cookie 的 restore/refresh 均拒绝，刷新前后 access 均拒绝，独立 token 会话仍可用。

关闭 browser 后 login/refresh/restore/logout 四端点均404；管理 API 无凭据仍401。关闭 UI 后首页与实际编译资源在 UI base / 根 assets 路径均404；`/api/admin/clients` 不作为 `/identity` 的旧旁路。UI 无 browser 的非法配置真实进程退出，全部表快照和宿主 sentinel 不变。

### 2.2 用途、期限与兼容

跨用途用例在 Disabled 夹具的**相同 issuer、密钥和 schema**下依次启动 legacy、显式仅管理、legacy，再恢复显式仅管理。旧业务 access/refresh 和改成管理名称的业务 Cookie 不能认证/恢复新管理入口；新管理登录、token 刷新及 Cookie 刷新正常。反向管理 access/refresh 被旧业务 session/refresh 接口拒绝，管理 Cookie 保留原值并改为重启后旧宿主实际读取的业务 Cookie 名称，其 restore/refresh 均返回401；原有效业务 access 仍可用，业务 refresh 仍可成功轮换。最后恢复原显式配置，刚被拒绝的同一管理 refresh/Cookie 在原管理入口仍可刷新/恢复，排除凭据本来无效或被错误请求消耗、撤销造成的假通过。这是隔离测试夹具的对照，不是在新模式启用业务装配，也不扩展为 Enabled 多业务组合验收。

私网开发 feature 另验证显式管理 browser 的实际数据库 session/refresh 期限不超过120秒，restore/refresh 返回原403且不轮换；普通 token 保持较长期限、可刷新。带完整身份断言退出只撤对应 browser，普通 token 仍可访问；同时回归原 legacy 私网 stale-identity、expected_session、期限与拒绝恢复/续期用例。TCP 为本机回环，可信 Origin 为私网示意值，不能推导真实私网浏览器/手机/现场验收。

旧两 mode 的管理/业务/注册/权限/设备/扫码用例保持；新增旧 `desktop-app` 在线修改回调后重启保留。旧/new 重启、schema/mode/管理员/client/密钥错误的无写负例与基础 readyz 继续回归。未把旧部分 seed 失败注入、所有 Choose/Fixed非0 管理组合或多产品业务矩阵写成已经覆盖。

## 3 检查命令与结果

验收使用本任务新建的临时 PostgreSQL 容器 `idp-m102-closure-20261020`，只发布随机本机回环端口。测试显式传入 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI`，各用例创建/清理随机 schema 和合成身份；已有 `pg` 与其他任务容器均不作为目标。不使用旧开发脚本 source 实例环境。

| 检查 | 本轮结果 |
| --- | --- |
| `pnpm --dir web build` | 通过，类型检查及管理/扫码/嵌入构建完成；沿用已安装依赖，没有依赖版本变更，原 chunk size 提示保留 |
| `pnpm --dir web test` | 93项通过 |
| `pnpm --dir web test:embedded-bundle` | 3项通过 |
| `cargo fmt --all -- --check` / `git diff --check` | 通过 |
| `cargo check --workspace --all-targets --locked --offline` | 通过 |
| `cargo test --workspace --locked --offline` | 通过，命令成功退出；实库用例仍明确 ignored，不计作 workspace 实库通过 |
| 默认 app + 显式隔离PG + `--include-ignored --test-threads=1` | 全部通过：33项 app单元（配置15项）、2项离线CLI、2项管理员CLI实库、13项真实进程用例；整组命令成功退出 |
| 私网开发 feature app + 同一显式隔离PG + 串行 | 全部通过：33项单元、2项离线CLI、2项管理员CLI实库、15项真实进程用例；包含原/新受限browser，各target均无ignored |
| 代码与文档复核 | 配置/条件装配再审未发现新的确定错误；Q01–Q22、相对链接、JSON示例、固定设计及源码摘要核对 |

数据库版本实际核对为 PostgreSQL 18.3；实库用例结束后确认测试 schema 已清理，并删除本任务临时容器/卷。未启动独立试点或部署实例。本轮没有执行新的真实浏览器界面验收；HTTP/DB证据不替代其范围。

相关实库复现方式如下，变量必须指向独立隔离测试库；URI 不放入版本化实例配置或报告：

```sh
cargo test -p embedded-idp-app --locked --offline -- --include-ignored --test-threads=1
cargo test -p embedded-idp-app --features development-private-network-http --locked --offline -- --include-ignored --test-threads=1
```

串行方式沿用原报告已知的并发随机 schema DDL/catalog 限制；本次未修改库 SQL，不宣称消除了该问题。workspace 离线命令中 ignored 的实库条目不算运行通过，只有上述显式 app 验收记录作为本轮实库依据。

## 4 Q01–Q22 增量状态

本表只对本轮 M1-02 子断言给状态；与旧报告一起阅读。

| Q | 本轮结果 / 与历史的关系 |
| --- | --- |
| Q01 | 本轮旧映射（含邮件）、旧两模式真实流程通过；旧 parser/default 保留 |
| Q02 | 来源冲突、惰性 lookup 回归通过；新增 unsupported 前 lookup=0 通过 |
| Q03 | 严格结构回归通过；ui/browser 省略/null、http 省略和 http=null 拒绝等新条件通过 |
| Q04 | 本轮 Secret/路径/条件依赖与传输门禁通过；真实 TLS/CA、现场私网仍未验，不升级为完整通过 |
| Q05 | 保持静态矩阵及 Fixed0 两mode；管理 Choose/Fixed非0完整HTTP矩阵仍未追加 |
| Q06 | 稳定 entry/client/Cookie 唯一性静态回归通过；业务集合实际运行未启用 |
| Q07 | 缺/坏client、错mode、缺管理员/坏key无写回归通过；多业务Fixed引用组合未执行 |
| Q08 | 原当前状态语义保持；新业务停用/Choose零业务域完整组合仍待后续 |
| Q09 | 静态路径/冲突与三管理mount回归通过；未声称未来附带业务端点全部展开 |
| Q10 | Cookie静态冲突与本轮单管理入口精确Path/清除通过；跨入口多标签/跨进程仍待后续 |
| Q11 | HTML唯一meta/挂载回归、三组合真实HTTP、UI关闭及实际assets404通过；本轮未另做真实浏览器复验，原DOM证据属历史 |
| Q12 | 本轮修订3管理三合法组合、非法UI组合、token/Cookie完整生命周期、退出后最后有效refresh优先检查及双向access/refresh/Cookie隔离通过；限定本报告所列夹具和mode/mount |
| Q13 | 原成功/失败启动与基础probe快照/sentinel回归、新关闭组合/非法UI无写通过；不推导无锁或总时限 |
| Q14 | 本轮新增旧两mode在线修改client后重启不覆盖通过；原非原子部分补缺失败边界保留，未新增该类故障注入 |
| Q15 | 原新管理重启token/Cookie/原期限回归，新增旧client重启与同issuer切换对照通过；selection/code/多入口重排仍待后续 |
| Q16 | 不提供原地绑定迁移；逐类凭证变化与自动历史对账未交付 |
| Q17 | 当前构建不支持的新业务/证明组合明确拒绝；旧注册、设备、扫码、OIDC相关原流程保持回归，非完整新协议组合 |
| Q18 | Core/Axum/Postgres/Web公共源码未改；workspace/Web/嵌入bundle按本轮检查表记录，未另验完整独立宿主浏览器 |
| Q19 | 独立解析非空合法、生产启动在Secret前unsupported均通过；业务支持构建对照仍归后续 |
| Q20 | 本轮补共同typed email/默认/Secret保留；既有P1/P2字段设计保持，非默认TLS/CA全链投影仍不宣称通过 |
| Q21 | CLI错误/无fallback、管理员重复保护、无启动seed回归通过；P3及完整P1–P6未执行 |
| Q22 | 基础readyz无写、移除client后ready/认证/重启范围回归通过；并发probe、SQL取消、锁等待与容量仍未验 |

本阶段通过不等于完整 M1/P1–P6、生产或设备现场通过。业务多入口、多标签、OIDC/device/scan 外部路径矩阵、准备重试/并发/审计，以及生产探针预算仍保留原阶段边界。

## 5 最终文件与摘要

本轮产品代码只改 app 的 `composition_config.rs` 与 `bootstrap.rs`；测试只改 `live_reference_host.rs` 与 `explicit_config_cli.rs`。CLI 集成 target 的新增断言用于证明 F01 的真实命令错误优先级，因此虽超出原 A01–A05 计划的三文件候选，也仍在本轮新增偏差的必要范围。没有新依赖、schema、公开 Rust/Web API 或后台界面改动。

文档增加本文及 token-only 示例，给历史报告/审查/README 增加后续入口。设计修订 2/3、原设计调整和实现计划保留为历史依据，不将其当时的“未执行”批量改为通过。

| 对象 | SHA-256 |
| --- | --- |
| docs/m1-02-configuration-composition-design-r2.md | `d7402bd472d427062c1bf29ec6a745b31518d54dd16dbc644f5c666b651e9ab2` |
| docs/m1-02-configuration-composition-design.md | `3af4eba26944b352264a47bc9c11038117db83dffa412ab5d9792de8f92a9e5f` |
| crates/embedded-idp-app/src/composition_config.rs | `656973f4d1e6fa3948593947b480268e1e7fbf581e6f488e2f5abc42c74f8fd2` |
| crates/embedded-idp-app/src/bootstrap.rs | `be12acecd2e4dc75685355bcc70218450c6474b439bb4f8fca2a25cbcc15b404` |
| crates/embedded-idp-app/tests/live_reference_host.rs | `cd8fb39ff9ecdd4b21ffb593127f7f5df76a54914ed7de742b549333f7424d62` |
| crates/embedded-idp-app/tests/explicit_config_cli.rs | `caab9b8c9be440a806ed3bbf73d527cbac21094753450ea863940371ffc221a9` |

复核确认本轮未修改 Web 源码、Core/Axum/Postgres 公共源码、旧 config.rs、admin_ui.rs 或依赖/lockfile；构建仅刷新忽略的 Web 产物。

所有改动留在本地工作区，未提交、推送或发布。试点、部署、域名、Secret/邮件供应和运行指标继续待定。

## 6 复审后验收补强（2026-10-20）

本次仅修改 `tests/live_reference_host.rs` 与本报告，补齐复审提出的两处非阻断覆盖缺口；产品实现、旧环境变量/seed/路由行为和后台界面均未改。未新增测试函数数量，原跨用途用例更名为 `explicit_management_and_legacy_business_credentials_are_isolated_with_same_issuer_and_key` 并增强断言。

- 管理 refresh → 旧 `/auth/refresh` 返回401；管理 Cookie → 旧 `/auth/browser/restore`、`/auth/browser/refresh` 返回401。Cookie 使用目标宿主真实业务名称，且在原入口有拒绝前、后的成功对照。与原业务 → 管理断言共同形成同 issuer/key/schema 下的双向凭据隔离证据。
- 共同 `token_lifecycle` 在退出后先提交最后有效 refresh，再提交已轮换旧 refresh，均返回401；原刷新前后 access 失效、独立会话仍有效等断言保留。UI+browser、仅 browser、token-only 的现有调用均采用该顺序。

本次重新执行的相关验收均通过，整组命令成功退出：

| 检查 | 本次结果 |
| --- | --- |
| `pnpm --dir web build` | 通过；按仓库要求先构建嵌入资源，原 chunk size 提示保留，未修改界面 |
| 新增双向隔离断言的独立定向运行 | 1项通过；作为默认 app 完整回归前的窄检查 |
| 默认 app：`cargo test -p embedded-idp-app --locked --offline -- --include-ignored --test-threads=1` | 33项单元 + 2项配置CLI + 2项管理员CLI实库 + 13项真实宿主，共50项通过；0失败、0 ignored |
| 私网开发 feature app：上述命令增加 `--features development-private-network-http` | 33项单元 + 2项配置CLI + 2项管理员CLI实库 + 15项真实宿主，共52项通过；0失败、0 ignored；包含原/新受限browser回归 |
| `cargo fmt --all -- --check` / `git diff --check` | 通过 |
| 报告与源码核对 | 第5节六项摘要、相对链接与本次增量复核通过；产品实现未改 |

本次使用新建的临时 PostgreSQL 18.3 容器 `idp-m102-coverage-20261020`，仅绑定本机回环随机端口，并显式传入 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI`；不使用已有开发实例。串行运行沿用既有 DDL/catalog 限制，未修改SQL或扩大并发结论。用例结束后额外核对自建测试 schema 遗留数为0，并删除本任务容器及卷。原有 `pg` 和其他任务容器未作为目标。原始本地日志为 `/private/tmp/idp-m102-coverage-focused.log`、`/private/tmp/idp-m102-coverage-default.log`、`/private/tmp/idp-m102-coverage-feature.log`，Web构建日志为 `/private/tmp/idp-m102-coverage-web-build.log`。

第5节现记录补强后的测试源码摘要；初次收尾时该文件摘要为 `5d5b60917a0b6ab213abbc20c4093c97e0532e6d76c01a032e1e855e854ab459`。修订2/3与两份产品实现源码摘要保持不变。本次不把既有 workspace/Web测试、真实浏览器、TLS/CA或现场证据标为重新验收；原Q01–Q22的其他未验边界保留。不提交或推送，不启动M1-03–06，试点和部署继续待定。


## 7 提交前核对与本地提交范围（2026-10-20）

第1–6节保留收尾与补强时的历史状态，其中“未提交”描述对应轮次。本次按用户后续授权，在核对通过后进行 M1-02 本地提交；提交标识以 Git 记录为准，不推送。本文不把本地提交视为部署或完整M1交付。

本次再次对照修订3、实际代码与第6节验收记录，未发现新增阻断性偏差。能力门禁早于Secret读取、共同typed email、三种合法browser/UI组合、管理生命周期、双向凭据隔离、退出后最后有效refresh优先检查及旧参考兼容均与报告一致。第5节六项摘要与当前文件一致，最近默认50项及私网开发feature 52项验收日志均无失败或ignored；产品/测试源码自该次验收后未改，因此本次不重复实库验收。提交前另核对格式、暂存差异、文档引用、示例与文件范围。

提交范围为 app 配置归一、最小共同装配、CLI与管理页面配置注入、相关依赖声明、测试、两个显式配置示例，以及M1-02设计/审查/验收文档和README导航。尚未入库的三份M1-01交接/设计核对文档作为M1-02直接引用的兼容依据一并保存。`admin_ui.rs` 的改动仅服务既有API/browser配置注入与资源挂载，没有后台布局、样式或业务页面改版。

独立的 `management-console-capability-design.md` 提案及README、历史审查中的该提案链接不纳入本次暂存，原工作区内容保留。没有Web源码、schema、Core/Axum/Postgres公共源码或真实凭据进入本次提交；生成产物与依赖目录不入库。M1-03–06未启动；试点、部署与原报告列明的其他未验边界继续待定。
