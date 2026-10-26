# M1-01 兼容基线与接口影响设计核对结果

| 项目 | 记录 |
| --- | --- |
| 文档标识 | UP-M1-01-RESULT，修订 1，2026 年 10 月 20 日 |
| 文档上下文 | `ooctoo/rust-embedded-idp` 对 [UP-M1-01 修订 2](m1-01-compatibility-handoff.md) 第 7.1 节的设计回传；配套[任务说明](m1-01-design-review-task.md) |
| 需求目标 | 为多入口装配确定现有能力、兼容约束、实际缺口和测试映射；使现有嵌入宿主保持独立使用 |
| 建议实施方案 | 复用 Core/Axum/Postgres/Web，在 app 内统一配置适配与装配；后续单独补显式管理 client 准备，不重建认证与授权模型 |
| 实际源码基线 | 本地 main，`1835ec35790568fefb9f6792a120b3041cfe77ae`；软件 `3.0.0`，schema `tenant_v6` |
| 基线差异 | 与交接件提交一致，未发现源码版本差异；开始核对时仅 README 和两份交接文档存在本地改动 |
| 完成层级 | 第 7.1 节设计文档交付完成；30 个运行用例全部未执行，运行基线和完整 M1 未验收 |
| 执行边界 | 只读源码及现有测试；未改代码、测试实现、依赖或 schema，未运行构建/测试、初始化、迁移或部署，未启动 M1-02–06 |

## 1 结论与核对范围

现有 Core 已提供 Fixed/Choose、Enabled/Disabled、独立管理认证、票据绑定、当前状态检查与事务契约。M1 的主要增量在参考 app：共同配置参数、多业务入口装配、空业务列表启动、显式管理 client 准备及引用检查。当前证据不要求为此修改既有 Core 构造器、store trait 或 `tenant_v6`。

每个自有产品映射一个租户，全局共享账号和凭证，各产品成员、权限、会话独立；这属于需求方实例选择，不能强加给其他宿主。共享账号不自动建立成员或 SSO。通用 UI/API/迁移由本仓库维护，需求方 `idp` 只管理版本、实例配置和运行资料，产品负责真实业务资源和设备归属。M1-01 不交付完整托管 UI、MFA、远程决策或部署环境。

阅读范围包括仓库 `AGENTS.md`、`CONTRIBUTING.md`、README、交接件，以及相关 Core、Axum、Postgres、app、Web、示例和现有测试。安全边界同时参照[生产安全要求](rust-embedded-idp-production-security-delivery-v2.md)、[浏览器会话设计](browser-session-design.md)、[当前扫码设计](device-scan-login-design-v1.md)。旧文档的历史描述以当前源码和当前专项契约校正。本文未刷新远端；结论绑定上述本地提交。

## 2 B01–B12 现有能力和兼容分类

以下路径均相对本仓库；为避免重复，C=`crates/embedded-idp-core/src/`，A=`crates/embedded-idp-axum/src/`，P=`crates/embedded-idp-storage-postgres/src/`，H=`crates/embedded-idp-app/src/`，W=`web/embedded/`。公共表示下游宿主可直接依赖的 Rust/Web 接口；内部表示当前二进制内部组合；可观察表示调用者实际依赖的协议、配置、数据与凭证行为。一个条目可同时属于多类。

| 编号 | 文件、类型或函数 | 分类与实际调用方 | 源码核对结论 |
| --- | --- | --- | --- |
| B01 | C`access/model.rs`：`TenancyMode`、`LoginTenantPolicy::validate/validate_selection` | 公共；认证、注册、app 和独立宿主 | 两种 mode、两种 policy 已有。Disabled 业务只允许 Fixed 0；Enabled 业务排除 0。不能把 Disabled 当作第三个 policy |
| B02 | C`access/authentication.rs`：`TenantLoginEntry` | 公共及可观察；Core 构造器、H`bootstrap.rs`、独立宿主 | 已有 client_id/login_entry/policy/require_device_proof。服务端可信构造；不增加请求可控入口策略或旧 struct 必填字段 |
| B03 | 同上：`CoreTenantAuthenticationService::new` | 公共；Axum 服务注入、参考 app、`examples/no-tenant-host/src/main.rs` | mode/config/entry/store/tokens/generator/digester/clock/ids 独立注入；无需 app 环境、中央 HTTP 或新配置文件 |
| B04 | 同上：`TenantAuthenticationService`，`authentication/management.rs` | 公共及可观察；普通/device/browser/management 适配器 | 登录、列域、选择、认证、切换已存在；业务/管理服务用途分开。来源失效拒绝未完成切换，成功切换不自动注销有效源会话 |
| B05 | C`access/authentication.rs`：`TenantAuthStore`/`TenantAuthTransaction`；P`access/authentication.rs` | 公共事务契约；Postgres 和自定义 store | Read Committed，状态及 mode/bootstrap 检查后按域、账号、票据顺序锁定，成功才提交；装配不改变授权事务或引入缓存 Allow |
| B06 | A`tenant_auth.rs`、`tenant_device_auth.rs`、`management_auth.rs`、`tenant_registration.rs` 的 router；C`access/registration.rs` | 公共路由及可观察 wire；app 和选择性嵌入宿主 | 路由可组合，管理认证与目标域授权分离，注册继续受固定域及注册开关约束。当前 app 实际使用 device auth 组合，不能仅按普通 router 推断全 app 暴露面 |
| B07 | P`access.rs`：`initialize_access_schema/inspect_access_schema`、`PostgresAccessStore::check_readiness`；C`access/bootstrap.rs`：`CoreAccessBootstrapService`、`AccessBootstrapStore` | 公共及可观察；离线工具、app、嵌入宿主 | Access 初始化不清理宿主表，不自动迁移；bootstrap 事务包含管理员、域 0 成员、保护角色、绑定、审计；重复不重设凭证。readiness 只读，不能替代新入口引用检查 |
| B08 | H`config.rs`：`EmbeddedIdpAppConfig::from_env/parse_login_policy`；H`bootstrap.rs`：`build_app_with_scan_cleanup/insert_client_if_missing`；H`main.rs` | 内部及可观察；参考进程、通过 path 包含源码的集成测试 | app 是 binary，`mod config/bootstrap` 非公共库出口，即使内部类型写 pub 也不等于发布 API。旧环境变量/default/URL/seed 行为须保留；Enabled 业务默认 Choose，Disabled Fixed 0，管理 Fixed 0；启动补缺 client，冲突不覆盖 |
| B09 | C`access/admin/clients.rs`：`ClientAdminService`、`AdminUpsertClient`、`CoreClientAdminService`；A`client_admin.rs` | 公共及可观察；平台管理 UI/API | list/get/upsert 已有；平台权限和当前会话在事务内检查，confidential 的 secret=None 保留旧值；没有删除/停用契约，不能把所有 upsert 改为 create-only |
| B10 | W`client.ts`：`EmbeddedIdentityClient`、`IdentityTransport`；W`browser-session.ts`：`BrowserSessionCoordinator`；A`browser_session.rs` | 公共及可观察；React、独立宿主、管理客户端 | 默认 token、可注入 transport，可选同源 Cookie；base URL 已支持前缀，协调键含 origin/path/purpose。同一 Cookie 入口只有一个当前会话；多入口隔离不能靠每个标签不同租户或端口本身推断 |
| B11 | C`access/authentication/device_transport.rs`、C`access/device_proof.rs`；device/scan provider、security/email crates | 公共及可观察；app、设备及自定义宿主 | 三类保证分开：人员设备会话、人员请求签名、无人员设备传输签名。扫码准入/展示/交付恢复继续注入；已有邮件是验证码和到期时间，不是验证链接；不强制 app 的 JWT/密钥/邮件实现 |
| B12 | C`access/model.rs`：`PermissionCatalog`；P`access.rs`、P`access/admin.rs::check_readiness`；A`tenant_self.rs::tenant_self_router` | 公共及可观察；初始化/readiness、RBAC、本人角色和宿主业务 | business_id 是租户内授权命名空间，不等于 client/入口。本人角色明确 business_id 查询、会话身份和游标范围；不能用入口名替代 |

### 2.1 对交接描述的精确化

以下是同一提交的语义补充，不是新增能力，也不改写 UP-M1-01 修订 2 的需求。

1. **PermissionCatalog 的保留不等于把动态业务权限重新配置化。**`PermissionCatalog::new` 会加入内置管理权限并可接收合法宿主业务模板。Access 首次初始化在 Enabled 模式跳过 Business 模板，在 Disabled 模式可插入域 0 的模板；已初始化 schema 重复初始化不重写目录。当前 readiness 跳过 Business 类，只检查管理权限及有效平台管理员。须保留这套分工和注入，不能声称它校验了全部业务权限，也不能让新装配在启动时重灌业务目录。
2. **旧参考注册默认与新实例默认分开。**H`config.rs::auth_config_from_env` 的 `EMBEDDED_IDP_APP_ALLOW_LOCAL_REGISTRATION` 默认 true；Access 首次初始化也让 Disabled 域 0 的 `allow_registration` 为 true。保留旧输入的现有行为。新装配输入应显式关闭未启用的注册面，P5 创建产品租户明确传 `allow_registration=false`；不能为自营默认而偷偷改旧环境变量、库默认或已存数据库状态。
3. **public 的内部 app 类型不必新建兼容包装库。**Cargo 和 H`main.rs` 显示 app 当前只有二进制目标；集成测试通过包含源码复用装配。可以改私有结构并更新同仓测试，仍需保护旧配置、命令、路由和凭证行为。以后若新增可导入库出口，另列新增公共契约。
4. **login_entry 不是所有 access session 的隔离或撤销字段。**选择票据、授权码/证明上下文检查入口；现有会话认证还依赖 client、purpose、租户策略和当前状态。仅改入口名或撤掉路由不承诺离线 JWT 失效；独立产品入口使用独立 client，token/browser 等同一逻辑入口的适配可共享 client。

### 2.2 管理与业务矩阵

| mode 与用途 | Fixed 0 | Fixed 非 0 | Choose |
| --- | --- | --- | --- |
| Enabled 业务 | 构造拒绝 | 合法标识，认证时验证当前资格 | 允许，排除平台 0 |
| Enabled 管理 | 允许平台管理认证 | 保留现有管理身份规则，管理操作另验权限 | 允许业务域选择，列表与完成排除 0 |
| Disabled 业务 | 允许 | 拒绝 | 拒绝 |
| Disabled 管理 | 允许，独立管理 purpose | 拒绝 | 拒绝 |

C`access/authentication/management.rs::new` 对 `require_device_proof=true` 返回 `management_device_proof_unsupported`；不得静默改 false。该构造注释提到初期 Bearer，但当前已有 `BrowserSessionService` 管理实现及 app 的 browser management 装配，不能用旧注释删除 Cookie 适配。通用配置先识别用途，再使用对应服务校验；不对所有入口统一调用业务 policy 校验。

### 2.3 HTTP 与 Web 兼容观察点

普通 A`tenant_auth.rs` 的 `/auth/login` 使用严格 email/password DTO，不接受请求指定可信 client/policy/tenant；Choose 的三个选择/切换路径只在 Enabled+Choose 挂载。capabilities 保留 `tenancy_enabled`、`login_tenant_policy`（`fixed`/`choose_after_authentication`）、可选 `fixed_tenant_id`、分页上下限。Choose 返回 selection ticket，没有无域 session/tokens；完成使用 `Authorization: TenantSelection`。

现有错误映射中 InvalidCredentials/InvalidSelection/InvalidSession 归为 `401 invalid_credentials`，证明不足 `403 device_proof_required`；内部失败拒绝。保留 no-store、Pragma no-cache、body limit、重复头拒绝和字段省略规则；框架拒绝未知 JSON 字段的现有测试预期为 422，不强改为统一 400。device/browser/management 分别按实际 adapter 建快照，不能都套普通 router 的 404。

`/auth/me/roles` 保留必填 business_id 查询，拒绝 `x-embedded-idp-business-id`，租户来自本人会话，可选租户头只能匹配。管理模块局部 `/admin/auth/...` 当前 app 外挂 `/api`。外层路径由可信宿主传递给 Cookie 与 proof binding；不能从未受信 Host/Forwarded 头放宽来源。

## 3 I01–I10 接口影响及调用方

| 编号 | 具体接口与调用方 | 最小处理及兼容门槛 |
| --- | --- | --- |
| I01 | B02/B03 公共入口 struct、构造器；app、示例、自定义 store/token 宿主 | 保持旧签名和字面量构造；集合由 app 组合。若后续确需破坏另提版本/迁移，不预加必填字段 |
| I02 | B04/B05 服务与 GAT store/事务 trait；各 adapter 和 Postgres | 保持；不因多入口新增全体宿主必选方法。票据消费、锁等待、回滚、当前状态为同一基线 |
| I03 | H`config.rs/main.rs/bootstrap.rs`；旧环境变量入口及 live app 测试 | 旧输入、新输入归一为单套内部参数；旧默认原样映射；空业务列表只能由新模式显式表达。冲突输入拒绝，不按加载顺序静默覆盖 |
| I04 | H`administrator_init.rs` 和启动路径；离线操作员 | 复用 bootstrap-admin；新增管理 client 准备属于缺口。区分旧参考补建与新模式只读启动，不以更名恢复 legacy seed |
| I05 | B06、A`tenant_self.rs`、A`management_auth.rs`；Web/HTTP 宿主 | 保留公共 router 和 wire；新增外层 mount 由装配定义，局部根不重写；管理矩阵和 business_id 单独验收 |
| I06 | W`client.ts/browser-session.ts`、`web/management/client.ts` 和 A`browser_session.rs`；托管/嵌入 UI | 已有 base URL/transport 先复用，只有证明确有缺口才改公开 API；Cookie 名、含外层前缀的 path、purpose、协调键同时设计 |
| I07 | C`access/authentication/oidc.rs`、refresh/device proof；H`bootstrap.rs` discovery/JWKS/token 组合 | 保留按 client 的 Core 服务和既有 issuer/audience。app 当前单 discovery/issuer 不能机械复制到每入口；多入口协议路由映射需后续验证 |
| I08 | B07/B12 初始化、readiness、bootstrap；CLI/宿主 | 复用 tenant_v6、注入目录和已有事务；补新入口引用及 mount 冲突检查。不得让库宿主必须使用新 app 文件或额外数据库 |
| I09 | C`access/admin/clients.rs`、`access/admin/tenants.rs`，A`client_admin.rs/tenant_management_admin.rs`；平台后台 | 复用受控 list/get/upsert、租户创建和成员管理。P4 丢响应恢复是调用编排，不把现有 upsert 改成 create-only 或承诺请求级幂等 |
| I10 | Axum public routers、app 条件挂载与 Web 调用；外部接入方 | M1-05 形成完整路由清单；新增/变更 OpenAPI 完整，代表性旧接口校验，剩余登记。当前 manifests 未配置 utoipa/aide，未找到 OpenAPI/swagger 命名制品；不能声称已存在生成链，也不据此否定现有 HTTP API |

当前未识别必须破坏的公共契约或 schema 变化。管理 client 离线准备可能需要窄存储能力；其类型、审计表达及是否新增公开方法留给 M1-03 契约验证，不能直接扩展 `TenantAuthStore` 或伪造管理会话绕过现有授权。

## 4 首次准备流程与真正缺口

| 步骤 | 已有能力及来源 | 缺口与建议 |
| --- | --- | --- |
| P1 数据库 | P`access.rs::initialize_access_schema`；`examples/bootstrap_local_postgres.rs` 的 Access 分支；显式迁移工具 | 复用同一 mode/schema/catalog。旧 legacy 分支存在覆盖式 client seed，不能当作新准备入口；不新增通用安装控制器 |
| P2 管理员 | H`administrator_init.rs::run` → `CoreAccessBootstrapService::initialize_administrator` → `AccessBootstrapStore::bootstrap_access` | 已有密码 stdin、参数边界和原子 bootstrap，流程可直接复用。重复核对有效管理员，不重设密码或修复未知状态 |
| P3 管理 client | OidcClient 校验、已有存储和平台管理 upsert；H`bootstrap.rs` 有参考 seed | **缺独立受限离线入口。**管理 API 需先登录，因此不能用管理 API 自己准备其首次必需 client。建议仅准备一个已指定管理 public client：缺失创建、相同返回、冲突停止；并发需在同一事务插入/读取再比较，禁止只做 ON CONFLICT DO NOTHING 就宣称匹配 |
| P4 仅管理启动 | 独立 management auth、管理 routers/UI、readiness 已有 | **缺空业务集合组合。**现有 app 总会创建业务服务/routes/seed/browser/discovery；新模式应只装管理、必要静态资源和健康能力，不因空列表退回默认业务入口 |
| P5 在线创建 | 平台租户/client 管理接口、成员角色管理和审计已有 | 没有新领域服务需求。租户创建明确关闭注册；先读再决定重试，必要更新沿用版本/权限和 secret 保留规则。跨多个 API 不承诺总事务或自动恢复 |
| P6 启用业务 | 单入口服务/router 和数据库对象已存在 | **缺集合引用验证和纯读启动。**校验所有 entry/client/Fixed tenant、用途、mount/Cookie 冲突；任何缺失或冲突整次拒绝，不能自动补建或跳过。在线成员/角色/回调仍由 API/数据库维护 |

流程没有不可解决的循环：P1/P2 均是离线库/CLI；P3 在受控 DB 操作边界准备管理 client；P4 只依赖这三步，不依赖业务租户；P5 经已认证平台 API 建业务对象；P6 才要求业务引用存在。P3 是明确待补的软件缺口，现有参考启动 seed 不是新流程完成证据。

管理 client 准备的候选比较字段为 client_id、client_name、client_type、PKCE 与 redirect URI 集合；返回不可包含 secret/hash。最小方案只支持 public 管理 client，不拓展批量业务 client 管理或离线 secret 轮换。URI 顺序/规范化、并发锁、审计语义和 API 落点需 M1-03 验证后确定。受控离线主体使用数据库运维权限，不伪造 `AccessAdminContext`，不暴露匿名 HTTP 安装 API。

显式准备与正常启动不能混同：P3 重复执行按已声明的比较规则发现在线变更时停止，由操作者核对；P6 不拿旧准备快照覆盖在线回调。P6 只验证当前对象可供入口安全使用和必要绑定，不做声明式目录调和。旧参考模式继续按原契约补缺 client；新模式永远不自动调用该 seed。

## 5 入口稳定性与方案边界

| 场景 | 必须保持或声明 | 设计结论 |
| --- | --- | --- |
| S01 重排/无关增删 | login_entry、client_id、policy、purpose、issuer/audience、外部地址与 Cookie 范围保持 | 使用稳定显式值；旧 `business`、`management`、scan 配置 entry 值原样转换，不由数组下标生成 |
| S02 普通重启 | 原密钥、原 DB、当前状态、原 TTL；已消费/撤销不复活 | 新模式纯读启动；不能通过增加 TTL 或重灌 seed 使测试通过。token、refresh、selection、适用 OIDC code 分别验证 |
| S03 绑定变化 | 上述任一安全绑定变化都不是重排 | 建议 M1 只支持明确的新逻辑入口和旧凭证处置；不承诺自动原地迁移。不新增持久入口注册表来识别历史配置；静态校验不能证明历史未变，操作者版本化配置/变更记录需声明影响 |
| S04 Cookie 与多标签 | 不同逻辑入口独立 Cookie 名/Path；协调键与实际 mount 一致；用途独立 | 两产品各两标签验证串行刷新和退出隔离；单入口仍只有一个当前浏览器会话。路径是凭证发送与协调范围，同源脚本仍处于共同信任边界 |

参考 app 的 Cookie 名为 `idp_{port}_business/management`，路径分别 `/auth/browser`、`/api/admin/auth/browser`。旧输入转换时必须保留；新输入不能把所有业务 Cookie 继续命名为同一 port 的 business，且不能仅凭端口隔离 Cookie。外层前缀变化也影响设备签名的真实路径，必须成套更新可信 binding。

同一逻辑入口的 token/browser 适配可共享 client；不同安全绑定的逻辑入口默认拒绝 client 复用，除非后续明确证明兼容隔离。此为新 app 配置校验建议，不限制现有库的合法自定义组合。tenant、client、login_entry、business_id 不合并为一个标识。

当前 OIDC app discovery 从全局 issuer 直接构造 `/oidc/*` 地址，而 Core 服务绑定认证入口。多入口下应先核对 discovery、authorize/token/resource 实际路由及 client 分派；尚不能冻结“每入口 issuer”或“全局 token endpoint 自动分派”。M1-02 可先完成普通登录/管理配置设计，M1-04 在 OIDC 启用或挂载受影响前闭合该映射；旧单入口 OIDC 保持回归门槛。

## 6 测试设计映射

所有行的运行状态统一为 **未执行**。表中“已有”只表示阅读过相关测试源码，不能据此宣称测试通过或整例覆盖。沿用 UP-M1-01 第 6.1 节 Uab/Ua/Ub/Usa/Usb/Uoff/Uremoved 夹具，Enabled A/B 与 Disabled 独立 schema；各负例从干净状态只改一个条件。表中还列出本例动作和必须观察的状态，详细 wire 约束见第 2.3 节。

### 6.1 测试文件索引

| 简称 | 实际文件 |
| --- | --- |
| K | [Core authentication_tests](../crates/embedded-idp-core/src/access/authentication_tests.rs) |
| KM | [Core management tests](../crates/embedded-idp-core/src/access/authentication_tests/management.rs) |
| TA | [Axum tenant_auth 内测试](../crates/embedded-idp-axum/src/tenant_auth.rs) |
| PB | [Postgres bootstrap](../crates/embedded-idp-storage-postgres/tests/live_access_bootstrap.rs) |
| PI | [Postgres schema 初始化](../crates/embedded-idp-storage-postgres/tests/live_access.rs) |
| PT | [Postgres 租户管理](../crates/embedded-idp-storage-postgres/tests/live_access_tenants.rs) |
| PR | [Postgres 普通认证内嵌 authentication 模块](../crates/embedded-idp-storage-postgres/tests/live_tenant_registration.rs) |
| PM | [Postgres 管理认证](../crates/embedded-idp-storage-postgres/tests/authentication/management.rs) |
| AM | [Axum 管理认证测试](../crates/embedded-idp-axum/src/management_auth/tests.rs) |
| HC | [app 配置内测试](../crates/embedded-idp-app/src/config.rs) |
| RH | [参考宿主](../crates/embedded-idp-app/tests/live_reference_host.rs) |
| BC | [管理员 CLI](../crates/embedded-idp-app/tests/live_bootstrap_admin.rs) |
| PC | [Postgres client 管理](../crates/embedded-idp-storage-postgres/tests/access_admin/clients.rs) |
| PA | [Postgres account/member 管理](../crates/embedded-idp-storage-postgres/tests/access_admin/accounts.rs) |
| DP | [Postgres device proof](../crates/embedded-idp-storage-postgres/tests/authentication/device_proofs.rs) |
| DO | [Postgres device OIDC](../crates/embedded-idp-storage-postgres/tests/authentication/device_proofs/oidc.rs) |
| WC | [Web 嵌入客户端](../web/embedded/client.test.mjs) |
| NH | [独立宿主 reports](../examples/no-tenant-host/src/reports.rs) |

PR 中的普通认证测试直接写在父文件内；DP/DO/PM 的父测试 target 同为 `live_tenant_registration`，PC/PA 的父 target 是 `live_access_admin`；不能只查子模块而遗漏父文件内测试，也不能把模块文件名误当 cargo integration target。PB、PI、PT、RH、BC 各有同名独立 target。相关实库测试带显式数据库环境门槛，未来检查使用隔离的 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI`；未配置或跳过不计通过。新增 case 优先补到这些现有层次，不新建测试平台。

### 6.2 首次准备与稳定性

| 用例 | 现有函数或测试名称及覆盖程度 | 待补前置、动作与状态断言 |
| --- | --- | --- |
| P01 | PB `bootstrap_initializes_both_modes_and_is_idempotent`；PI `access_initialization_is_atomic_idempotent_and_allows_host_tables`；RH `reference_host_runs_management_and_business_flows_in_both_modes` | 已有两模式初始化及 Enabled 共 schema 宿主表保留；补新 P1–P6 空业务到 A/B 的完整组合及 Disabled 共 schema；宿主行不变，不直接写业务身份表 |
| P02 | BC `cli_bootstrap_initializes_both_modes_and_never_resets_existing_credentials`；管理员重复保护 | 重跑管理员及新管理 client 准备；分别相同/冲突；对象、密码、角色、初始化审计不增加/改变；冲突不覆盖；随后重启不写身份配置 |
| P03 | RH `reference_host_refuses_uninitialized_or_wrong_mode_without_mutating_schema`；PB `readiness_requires_prepared_catalog_and_effective_admin_without_mutating_state`；PI `access_initialization_is_atomic_idempotent_and_allows_host_tables` | 已有 mode/schema/对象冲突保护；补 client 引用及坏密钥等组合，逐例只改一项；启动失败且库不被修复、无宽松入口 |
| P04 | PC `concurrent_client_updates_preserve_the_current_secret_and_audit_each_commit`；PT `tenant_create_is_atomic_gated_and_unique`；单操作并发和原子性已有 | 补平台 API 提交后丢响应，先读再决定重试；不重复授予、轮换 secret 或伪称跨步事务；完整编排场景待补 |
| P05 | PC `client_admin_rejects_tenant_actors_and_observes_platform_permission_and_session_revocation` | 匿名、业务身份、普通产品管理员分别调用准备相关 API；均不越权、不改密；受限离线能力不能出现匿名 HTTP 路径 |
| P06 | PA `member_http_changes_are_tenant_scoped_atomic_and_rebinding_does_not_restore_credentials`；PT `tenant_state_version_cleanup_restore_and_audit_rollback`；已有撤销和恢复不复活 | 补在线改回调/成员/授权并撤销会话后重启新模式，逐项比对库和认证拒绝；隔离夹具移除引用 client，拒绝启动且不重建 |
| S01 | K `selection_record_metadata_and_membership_are_rechecked`；票据入口绑定起点 | A/B 重排、无关入口增删、旧输入归一；绑定不变，原 TTL 内未消费/撤销票据及适用 code/refresh 继续按原语义可用 |
| S02 | K `bearer_refresh_rotates_in_both_modes_and_reuse_revokes_only_its_family`；refresh 局部基线 | 持久库、相同密钥与 Clock 语义重启真实宿主；有效产物不延寿，已撤销/消费仍拒绝，DB 状态不被复写 |
| S03 | K `selection_record_metadata_and_membership_are_rechecked`；entry/client 元数据拒绝 | policy/client/login_entry/issuer/path 各独立变化；标记不支持迁移或采用新入口并处置旧凭证；不能用旧 token 验证通过证明名字可任意改 |
| S04 | WC `expired Cookie access tokens refresh under one shared Web Lock`；共享锁局部模拟 | 同源 A/B 各两真实标签，A 退出/B 恢复/同入口并发刷新；不误清 B，未知结果阻断与恢复；跨入口 Cookie 与旧 Cookie 迁移待补 |

### 6.3 Fixed、Choose、Disabled 和管理矩阵

| 用例 | 现有函数或测试名称及覆盖程度 | 待补前置、动作与状态断言 |
| --- | --- | --- |
| F01 | K `fixed_login_requires_membership_and_issues_session`；PR `fixed_login_creates_bound_session_and_rechecks_current_state_in_both_modes`；已有两模式 session/refresh 绑定断言 | 改造后复用；补 Uab/Ua 在多入口 Fixed-A 成功后 B 成员/角色无新增，仍无选择票据 |
| F02 | PR `fixed_login_creates_bound_session_and_rechecks_current_state_in_both_modes` 已有成员 suspended 后登录/认证拒绝；K `fixed_login_requires_membership_and_issues_session` | 补 Uoff/仅 B 成员等独立负例和 A 停用后有效 B 会话不误停；无 A 新会话，不重复实现当前状态校验 |
| F03 | TA `login_rejects_unknown_fields_and_never_caches_credentials`、`optional_tenant_header_rejects_invalid_or_conflicting_values`；PR `http_login_selection_authentication_and_switch_use_real_postgres_and_rs256` 已有未知 client_id 422 | 补 Fixed-A 上 tenant/client/policy 各自负例与状态断言；按旧头/DTO 拒绝、无 session、正常 wire 不变 |
| F04 | K `session_insert_failure_rolls_back_and_fixed_policy_rejects_switch`；PR `fixed_login_creates_bound_session_and_rechecks_current_state_in_both_modes`；Core/实库已拒绝 | 补 Enabled 普通 Fixed 路由组合；device/browser 按实际契约另验，不能统一断言 404 |
| C01 | K `choose_login_creates_only_ticket_then_selects_and_authenticates`；PR `choose_lists_only_joined_tenants_and_switch_requires_live_source`、`http_login_selection_authentication_and_switch_use_real_postgres_and_rs256` | 已有仅票据、无 session/refresh、本人分页及票据 DB 元数据；补 removed/status 细项与新多入口，不得泄漏他人成员 |
| C02 | PR `choose_lists_only_joined_tenants_and_switch_requires_live_source`、`http_login_selection_authentication_and_switch_use_real_postgres_and_rs256`；已有选择、消费、匹配头和 0 拒绝 | 改造后复用；补 A/B 入口组合中的完整 session/初始 refresh/一次消费断言，不新增选择状态机 |
| C03 | K `consumed_expired_and_revoked_tickets_fail`、`selection_record_metadata_and_membership_are_rechecked` | 非成员/停用/归档域、过期/重复票据各自干净负例；无目标新增会话、不产生额外域权限，错误不泄漏敏感状态 |
| C04 | K `selection_record_metadata_and_membership_are_rechecked`；TA `selection_scheme_rejects_bearer_and_ambiguous_credentials`；PR `http_login_selection_authentication_and_switch_use_real_postgres_and_rs256` 已有真实 scheme 正反例 | Core 测试复用票据逐项改 client/entry/purpose；补每项成功对照后新干净票据、只改一项，断言无 session 且不误消费；真实跨入口逐字段不依靠 404 掩盖 |
| C05 | PR `choose_lists_only_joined_tenants_and_switch_requires_live_source`、`http_login_selection_authentication_and_switch_use_real_postgres_and_rs256`；DP `proof_selection_signs_exact_ticket_and_switch_requires_live_source_and_target_device`；DO `tenant_oidc_exchange_is_single_use_and_keeps_scope_on_refresh_and_switch` | 普通和设备实库均已有源会话保留，另有 OIDC scope 起点；复用并补原 authenticated_at/适用 scope 精确对照及改造后入口组合，不重复建设普通切换测试 |
| C06 | K `switch_ticket_rechecks_source_session_and_cursor_scope`；PR `choose_lists_only_joined_tenants_and_switch_requires_live_source`；DP `source_unbind_committed_while_tenant_switch_waits_prevents_issuance` | 已有普通来源撤销和设备绑定锁等待；补普通来源资格/撤销等待锁及零新增 session/refresh 断言，不能误写为成功切换主动撤销来源 |
| C07 | PR `selection_rollback_and_concurrent_different_tenants_allow_one_session`；同票据 barrier 下选 t1/t2，已有恰好一成功、一个 session 和 refresh | 复用已有实库并发测试，改造后回归；补显式 consumed 状态核对及必要入口组合。nonce 并发不是本例证据 |
| C08 | PR `selection_rollback_and_concurrent_different_tenants_allow_one_session`；K `session_insert_failure_rolls_back_and_fixed_policy_rejects_switch` | 已有签发失败、refresh 插入 trigger 故障、零 session/refresh、票据仍可列及解除故障后成功；复用并补显式票据未消费/原 TTL 及必要不同插入点断言，不把实库回滚列为全新缺口 |
| D01 | PR `fixed_login_creates_bound_session_and_rechecks_current_state_in_both_modes`；WC `disabled and fixed login use public routes and keep tokens out of snapshots`；NH `report_authorization_uses_authenticated_tenant_subject_and_exact_id` | 已有域 0 真实登录/当前状态与宿主授权基线；补改造后独立宿主登录/恢复/角色/资源完整链，保留 provider/token/custom transport，权限撤销后拒绝 |
| D02 | HC `login_policies_keep_platform_and_business_domains_separate` 已覆盖部分非法策略；RH `reference_host_refuses_uninitialized_or_wrong_mode_without_mutating_schema` | 复用原配置门槛；补 Disabled 业务 Fixed 非 0、管理 Choose 等缺少的明确构造负例，以及请求/资源上下文非 0；不切模式、不写会话 |
| D03 | PR `http_login_selection_authentication_and_switch_use_real_postgres_and_rs256` 已有 Disabled capabilities 的 mode、域 0 登录及普通选择/切换 404；WC `disabled and fixed login use public routes and keep tokens out of snapshots` | 补 server 完整 fixed/0 字段快照和改造后 Web 联动；无需重建 Disabled 路由测试，mock 不替代已有 HTTP/DB 证据 |
| D04 | PI `access_initialization_is_atomic_idempotent_and_allows_host_tables`；NH `report_authorization_uses_authenticated_tenant_subject_and_exact_id` | 已有 Enabled 宿主表与数据保留、IdP 对象冲突拒绝；补 Disabled 共 schema 和改造后业务/管理独立进程组合，业务身份无管理权限且无中央服务依赖 |
| M01 | KM `management_sessions_refresh_and_logout_are_separate_from_business_in_both_modes`；PM `management_login_enforces_persisted_purpose_live_authority_refresh_and_logout_in_both_modes`；HC `login_policies_keep_platform_and_business_domains_separate` | 已有两模式 Fixed 0、认证不等于授权、Enabled 业务 0 配置拒绝；复用并补共同装配矩阵，管理操作仍按目标域权限 |
| M02 | KM `management_selection_cannot_exchange_business_tickets_or_enter_platform_domain`；PM `management_selection_is_separate_and_session_creation_is_atomic`；AM `management_http_mounts_only_configured_selection_and_bounds_inputs` | 已有列表/选择排除 0、有效域切换、持久化失败回滚和 HTTP 挂载；补共同装配和真实 HTTP/DB 串联，保留错误票据拒绝 |
| M03 | 构造器源码明确拒绝，未确认专门回归测试 | 管理 proof=true 单一变更；返回明确不支持，零会话，不改 false 或借业务证明路由降级 |
| M04 | PM `management_login_enforces_persisted_purpose_live_authority_refresh_and_logout_in_both_modes` 已覆盖两模式双向 token/refresh 用途拒绝；HC `login_policies_keep_platform_and_business_domains_separate` 含 Disabled 管理 Fixed 非 0 | 补 Disabled 管理 Choose 等未单列的构造负例及共同配置回归；拒绝错误用途不能误撤销另一用途的有效会话 |

### 6.4 后续验证顺序

后续首次相关实现前先固定 Core/HTTP 的旧行为基线，再将新配置与准备负例接入已有测试层；完成最小 A 两 clients、B 一 client、独立管理 client 的装配后，验证 P/S 和跨入口组合。OIDC、Cookie、设备与扫码按启用或受影响范围追加，既有已启用功能不能以“可选”豁免。

构建遵循仓库约定：先 Web 安装/构建，再 Rust fmt/check/test；实际浏览器、隔离 Postgres、实体设备及部署分层记录。本文没有运行这些命令，也没有新增任何测试函数；上表待补函数名、具体位置由对应实现工作包确定。

## 7 技术待定项与下一工作包建议

| 项目 | 本次建议 | 必须验证后才可冻结 |
| --- | --- | --- |
| 新输入与内部类型 | 旧 env 与新显式输入共用 app 内部装配；复用现有 serde_json 可作为格式候选，不先加配置依赖 | 格式/字段、排他输入与诊断、Secret 引用、空列表、稳定命名、mount 冲突；不给现有公开 struct 加必填字段 |
| 管理 client 准备 | 窄离线能力，只准备管理 client，创建/相同/冲突三态，不覆盖 | 命令名、事务与并发、比较规则、审计及存储 API；不伪造管理 actor、不自动补授角色、不返回 secret |
| OIDC 与地址 | 保持旧单入口 issuer/audience，按实际服务绑定设计多入口映射 | discovery/authorize/token/resource 路由与 client 的一致性、旧 code/refresh、proof 外部路径；不预定每 client issuer |
| 公共 API 与版本 | 当前无必须破坏证据；优先新增内部组合 | 如确需新增库导出/方法，逐项给调用方与版本影响；不要预填发行版本或 tenant_v7 |
| OpenAPI | 先列全部挂载和条件，再验证代表接口与新增/改动契约 | 工具、制品位置、构建/漂移检查及覆盖缺口；不要求全仓 SDK |
| 绑定变更 | 只承诺稳定配置重排/重启，变化显式记录并处置旧凭证 | 是否拒绝原地变更、哪些产物需重新登录/撤销；无历史配置存储时不假称能自动检测历史变化 |

建议下一任务仅为 **M1-02 的配置归一与共同装配边界工作包**：输入是本文 B/I、管理矩阵和 P/S 约束；先确定旧 env 映射、显式新输入、空业务列表、入口/client/mount/Cookie 冲突规则和新增模式的只读启动边界。其交付应包括配置契约和相应变更证据，后续才能实现新装配；不把管理 client 准备、完整 OIDC 多入口或全套 UI 一次塞入该包。

随后 M1-03 交付 P3 及管理独立准备闭环，M1-04 才做最小双产品多客户端组合；M1-05 路由/契约随改动维护，M1-06 汇总分层证据。以上仅为依赖顺序建议，本次未启动任一工作包。试点产品、加入方式实际取值、域名、数据库部署、Secret 供应、代理/副本、SLO/RPO/RTO 和发布时间继续待定，不作为本次设计交付缺项。

## 8 第 7.1 节交付核对

| 要求 | 本文位置及结果 |
| --- | --- |
| 实际提交、软件/schema 与差异 | 文首及第 1 节；与需求基线相同 |
| B/I 文件、类型、调用方与三类兼容面 | 第 2–3 节；12 项基线及 10 项接口逐项核对 |
| 首次准备、稳定性、管理矩阵 | 第 2.2、4–5 节；已有能力和缺口分开，无首次管理循环依赖 |
| 30 用例的现有/待补映射与断言 | 第 6 节；P6+S4+F4+C8+D4+M4，全部运行未执行 |
| 技术待定、未支持与下一工作包 | 第 7 节；候选方案不当作已发布接口 |

本文完成 M1-01 设计回传，供需求方接收文档完整性与边界。实现提交、运行通过证据、API 制品和迁移结果按 UP-M1-01 第 7.2 节在后续任务单独回传；不能由本次静态核对推导完整 M1 或生产可用。
