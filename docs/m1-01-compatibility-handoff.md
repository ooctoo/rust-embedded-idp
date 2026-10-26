# rust-embedded-idp M1-01 兼容基线与接口影响清单

| 项目 | 内容 |
| --- | --- |
| 文档标识 | UP-M1-01，修订 2，2026 年 10 月 19 日 |
| 文档上下文 | 供 `ooctoo/rust-embedded-idp` 维护者接收的通用软件改造交接；可单独复制，不依赖需求方仓库的其他文件 |
| 需求来源 | 自营多产品 IDP 项目；下文已完整列出与上游有关的约束 |
| 需求目标 | 明确多入口装配前的兼容基线、首次准备流程、稳定标识、接口影响与验收场景 |
| 建议实施方案 | app 内共用装配器，复用现有 Core/Axum/Postgres/Web；先确定契约，再按 M1 后续任务实现 |
| 分析基线 | `1835ec35790568fefb9f6792a120b3041cfe77ae`，软件 3.0.0，schema `tenant_v6` |
| 当前任务 | M1-01 设计核对：只读核对源码并形成设计文档，不启动后续实现或运行验收 |
| 当前状态 | 修订 2 已通过需求方最终审查；本次交接仅供 M1-01 设计核对，尚未实施或执行运行验收 |

## 1 背景与需求目标

需求方希望多个自有产品直接使用同一 IDP 的注册登录、用户设备关系、管理后台和正式 API；已有后台的产品可嵌入同一套管理模块。需求方将每个产品映射为一个租户，全局共享账号和凭证，各租户成员、权限和会话独立，加入方式按租户配置。共享账号不等于自动加入或跨产品 SSO。

成员停用限定在该租户；全局账号停用和凭证变更有跨产品影响，只能由平台或本人受控安全流程执行。产品管理员不能重设已有全局账号密码、查看其他租户成员或凭邮箱自动认领身份。

通用服务、完整 UI、嵌入模块、接口和迁移均由本开源仓库维护。需求方仓库只管理实例版本、配置和运行资料，产品继续维护业务实体与资源归属。**需求方的“一产品一租户、固定入口”不能变成所有嵌入宿主的强制约束。** 原有 Fixed、Choose、Disabled 和注入式使用均须保留。

M1-01 本身交付基线、接口影响和测试设计；实现工作分属后续 M1-02 配置适配、M1-03 显式准备、M1-04 多入口装配、M1-05 接口契约、M1-06 组合验收。本文的“应当”描述目标，不表示当前软件已经支持新装配。

### 1.1 接收方本次执行范围

接收方只拿到本文即可按以下顺序完成 M1-01；源码从开源仓库读取，无需取得需求方环境或本轮对话：

1. 记录实际分析提交、软件/schema 版本，与分析基线比较，注明新增能力及行为差异。
2. 核对 B/I 清单，区分公共接口、app 内部结构和外部可观察行为；补实际文件、类型和测试函数映射。
3. 核对 P1–P6 首次准备流程、稳定标识及业务/管理策略矩阵，列出已有能力、真正缺口和候选方案。
4. 将 P/S/F/C/D/M 用例映射到现有或待补测试，回传第 7.1 节的设计交付；保留待工程验证项并提出下一工作包。

本次不修改运行代码，不执行初始化/迁移、不准备真实环境，也不要求跑完本文运行用例。代码、运行基线和后续实现交付需按后续任务推进，不能把整份验收设计视为一次性实现任务。

### 1.2 约束与建议的效力

- **需求约束：**账号/成员边界、既有安全语义、嵌入兼容、两仓职责和默认拒绝必须满足；如发现与实际能力冲突，明确报告，不能静默删除约束。
- **源码事实：**B 清单描述固定提交，接收方必须更新为其实际分析提交，不能因文字写了“保持”而忽略已发生的安全修正或接口变化。
- **建议方案：**app 共用装配器、P1–P6 及后续具体配置/命令是实施建议。上游可提出满足同等约束的更小方案，说明兼容、安全和运维影响后形成设计结论；候选 Rust 签名、命令名和 issuer 映射并未冻结。

M1 不建设第二套身份模型、通用安装控制器、动态入口注册平台、第二份权限目录或策略 DSL；不要求新增 schema、客户端删除/停用 API、每 client 独立 issuer 或完整协议栈。完整托管体验、验证链接、远程决策、MFA、SSO、生产部署和真实账号迁移不在本次细化范围。实际试点、域名、基础设施、运行指标及发布时间均未指定。

## 2 现有兼容基线

下列路径均相对本开源仓库。事实以分析提交为准；接收方若基于新提交实施，先记录差异，不将历史基线当成当前测试结果。

| 编号 | 模块或接口 | 已有行为与保留要求 |
| --- | --- | --- |
| B01 | Core `access/model.rs` | `TenancyMode::Enabled/Disabled` 与 `LoginTenantPolicy::Fixed/ChooseAfterAuthentication` 已存在。Disabled 不是第三种 LoginTenantPolicy；其业务入口采用 Fixed 域 0 |
| B02 | Core `access/authentication.rs` | `TenantLoginEntry` 已有 client_id、login_entry、policy、require_device_proof；由可信宿主注入，不能从登录请求反序列化成可信策略 |
| B03 | 同上 | `CoreTenantAuthenticationService::new(mode, config, entry, store, tokens, generator, digester, clock, ids)` 可独立构造；不依赖中央服务、app 环境变量或文件配置 |
| B04 | 同上及 `authentication/` | `TenantAuthenticationService` 的 login_capabilities/login/list_tenants/select_tenant/authenticate/begin_switch 已存在；票据与当前账号、client、成员、域和会话状态共同校验 |
| B05 | `TenantAuthStore::auth_transaction` | 现有事务约定为 Read Committed 加状态、域、账号、票据锁；只有成功才提交。M1 不借装配改为另一套授权事务模型 |
| B06 | Axum `tenant_auth.rs`、`management_auth.rs`、`tenant_registration.rs` | 业务、管理、注册分别组合；管理认证与目标租户选择分离。注册已有固定域校验；不得在外层再造一套注册或管理规则 |
| B07 | Postgres `access.rs`、Core `access/bootstrap.rs` | 已有 Access schema 初始化、只读 readiness、管理员事务初始化及重复执行保护。共 schema 的非 IdP 业务对象不能被清理或接管 |
| B08 | app `config.rs`、`bootstrap.rs` | 旧参考 app 使用环境变量、单业务入口及独立管理入口；启动可补建缺失客户端。旧 Enabled 业务默认 Choose，Disabled 业务默认 Fixed 0，管理默认 Fixed 0；不能静默改成自营 Fixed |
| B09 | Core `access/admin/clients.rs` | 平台级 client 查询/upsert 与 confidential secret 保留语义已存在；没有公开删除/停用 API，也没有产品管理员任意管理全局 clients 的能力 |
| B10 | Web `embedded/client.ts`、`browser-session.ts` | 默认 token、自定义 transport 和可选同源 Cookie 已存在；多标签协调键使用 origin/path/purpose。禁止强制所有宿主切换 Cookie |
| B11 | Core device/scan、security 与 email | 三类设备保证和 provider 注入保持；邮件当前为验证码及到期时间。装配改造不强制宿主采用 app 的 JWT/密钥/邮件实现 |
| B12 | Core `PermissionCatalog`、Postgres `access.rs`、Axum `tenant_self.rs` | 初始化与 readiness 使用可信宿主注入的权限目录；business_id 保持租户内业务授权命名空间。已有本人角色接口不可改成无 business 范围的租户统一角色 |

### 2.1 管理入口的现有例外

共同装配的校验必须结合 TenancyMode、purpose 和对应服务，不能对所有入口直接套业务 `LoginTenantPolicy::validate`。`CoreManagementAuthenticationService` 现有构造器明确支持管理 Fixed 0：

| 模式与用途 | Fixed 0 | Fixed 非 0 | Choose |
| --- | --- | --- | --- |
| Enabled 业务 | 拒绝 | 按合法租户语法及当前资格验证 | 支持，仅选有效业务成员域 |
| Enabled 管理 | 支持平台管理身份 | 按现有管理身份和权限规则验证 | 保留现有选择，列表/完成不允许进入平台域 0 |
| Disabled 业务 | 支持无租户业务 | 拒绝 | 拒绝 |
| Disabled 管理 | 支持管理身份，与业务身份用途不同 | 拒绝 | 拒绝 |

平台管理身份可在管理 API 的权限检查后操作目标租户；这不意味着业务域 0 是通配符。现有管理构造器遇到 `require_device_proof=true` 明确返回不支持，不能自动改成 false；也不据此禁止已有 BrowserSession 管理适配器。

### 2.2 设备与业务授权边界

| 现有保证 | 验证结果及保留要求 |
| --- | --- |
| 人员设备会话 | `authenticate_device` 验证当前人员会话及其设备绑定，取得可信用户、会话和设备；本身不证明本次请求由设备私钥签署 |
| 人员单次请求证明 | `verify_request` 在所需身份检查之外验证签名、用途、audience、实际 method/外部 path、原始 body 摘要与单次 challenge；不能用“已有设备会话”替代 |
| 无人员设备传输证明 | `verify_device_transport_request` 使用固定的设备传输用途和当前设备/密钥，不赋予用户身份；产品仍验证设备到业务资源的归属和最终操作条件 |

设备/扫码 provider 和受信宿主上下文保持注入式边界；不由请求任意选择较弱证明策略。仅在启用或受改动影响时运行相应组合验证，不为 M1 增加一套证明协议。

`business_id` 与 client/login_entry 不同，不能由多入口名称替代。`GET /auth/me/roles` 保留本人会话身份、显式 business_id、游标范围和既有 Header 规则。初始化与 readiness 应传递同一可信宿主权限目录；旧宿主的自定义目录不能被共同装配器重置为空或镜像为第二份动态目录。参考 app 当前可使用其已有空宿主目录，这不改变其他宿主的注入能力。

### 2.3 本轮触及的 HTTP 基线

以下是普通 `tenant_auth_router` 的局部路由；device/browser/management 适配器另有契约，不得由此表覆盖。宿主可以加外层前缀，路径前缀不是新的租户权威来源。

| 路由 | 调用输入与现有结果 |
| --- | --- |
| `POST /auth/login` | email/password；不接受调用方指定登录域。Fixed 成功返回 `status=authenticated`、session/tokens；Choose 返回 `status=tenant_selection_required`、selection_ticket/expires_in，不创建无域会话 |
| `GET /auth/access/capabilities` | 返回 tenancy_enabled、login_tenant_policy、fixed_tenant_id 及分页上限；维持 Web 客户端可识别值 |
| `GET /auth/session` | Bearer access token，经当前状态认证取得可信身份 |
| `GET /auth/tenant-selection/tenants` | `Authorization: TenantSelection <ticket>`，受控分页列出本人非 removed 成员及状态；列表中可有停用项，不能等同于可选项 |
| `POST /auth/tenant-selection/complete` | 同一票据方案，body 为 tenant_id；可选租户头必须匹配目标；只有有效租户与 active 成员才能完成 |
| `POST /auth/me/tenant-selection` | 有效来源会话发起切换，签发绑定该来源的选择票据 |

后三个选择/切换路由仅在 Enabled + Choose 下由该普通适配器挂载。Fixed/Disabled 的普通路由中没有这些路径；设备适配器应按自身代码核对暴露面，并继续由 Core 拒绝不允许的操作，不能误把普通适配器的 404 预期套到所有适配器。

普通认证错误中的 InvalidCredentials/InvalidSelection/InvalidSession 等目前映射 `401 invalid_credentials`；设备证明不足映射 `403 device_proof_required`，存储/签发等内部失败不放行。错误 code、JSON 投影、`no-store`/`no-cache`、请求体大小限制和重复头拒绝逻辑都属于兼容面。框架 JSON 解析错误不强制改造成新的统一错误格式；具体 wire 快照由接收方从当前测试提取，不改旧客户端依赖。

管理模块根为 `/admin/auth/...`；现有参考 app 外挂 `/api`。业务 Bearer 不能变成管理凭证，管理目标 Header 也不能替代管理认证。

## 3 接口影响清单

“保持”是本次默认设计要求；若实现证明必须破坏，单独给出原因、版本和迁移，不使用默认放行的兼容实现。

| 编号 | 接口面及位置 | 预计处理 | 受影响调用方及验收 |
| --- | --- | --- | --- |
| I01 | B02/B03 公共类型与构造器 | 保持；新集合在 app 内组合，不给旧公共 struct 强加必填字段 | 自定义 store/token 宿主编译；Fixed/Choose/Disabled 场景 |
| I02 | B04/B05 服务、store/事务 trait | 保持；不新增无用途必选方法，不改变锁和提交语义 | 并发消费、失败回滚、当前状态及源会话失效用例 |
| I03 | app 内部结构与外部配置输入 | app 私有结构可重构，无需为旧内部类型建立长期兼容层；旧环境变量、默认入口及外部可观察行为保持，共同参数承接新增输入 | 旧环境变量启动、空业务列表、冲突输入与重排；实际公共导出另按 I01/I05/I06 评估 |
| I04 | app 启动/准备入口 | 新增受限管理 client 显式准备；新模式启动只校验，旧参考补建显式保留 | P01–P06；不得让新实例启动退回 legacy seed |
| I05 | Axum 路由、DTO、capabilities 和本人角色 | 默认保持路径/字段及 business_id 语义；新外部挂载明确记录，业务/管理策略分开传递 | HTTP 正反例、管理 Fixed 0、本人角色与业务游标；Choose 不被全局 Fixed 门禁破坏 |
| I06 | BrowserSession/Web | 保持 token/custom transport；只在需要时适配 basePath 和配置注入 | S04；同源协调与旧 Cookie 路径迁移 |
| I07 | OIDC/token/证明 | 复用现有按 client 服务；issuer 映射待验证；login_entry 保持稳定 | S01–S03；启用/改变挂载的 code、refresh、proof 回归 |
| I08 | Access schema/readiness/bootstrap | 复用 tenant_v6、初始化事务、可信 PermissionCatalog 和校验；只补必要入口引用验证 | P01/P03；业务表与自定义目录保留、错模式拒绝、旧宿主无新数据库要求 |
| I09 | 租户/client 管理 API | 复用平台权限下的现有创建/upsert；不改为统一 create-only，不新增删除/停用要求 | P04/P05；产品管理员不得升权或覆盖全局凭证 |
| I10 | OpenAPI 与构建产物 | M1 全量路由清单，新增/修改接口完整描述，代表性既有接口验证；其他文档缺口登记 | 有覆盖范围及版本说明；未描述不等于免认证；不强制全仓 SDK |

M1-01 的输出应逐项确认上述分类、依赖与现有测试位置。未来新增签名、命令名、配置字段及 schema 编号由实现前的技术验证决定，本文不虚构已存在的 API。

公共 Core/Axum/Web 导出及协议按其公共兼容范围评估；内部 app 结构可以重构，环境变量、默认值、URL、Cookie、会话和凭证行为则必须记录可观察差异。给公共 struct 增字段也可能破坏字面量构造，不能因为 app 内部可变而忽略实际公共边界。

## 4 建议的首次准备流程

### 4.1 顺序与权限

| 步骤 | 执行主体与输入 | 完成条件、失败处理及兼容边界 |
| --- | --- | --- |
| P1 准备数据库 | 受控运维调用 Access 初始化/受支持迁移；明确连接、schema、TenancyMode 和可信 PermissionCatalog | 目录沿用宿主注入并用于 readiness；使用 Access 分支，模式/对象冲突停止；不用覆盖式 legacy seed |
| P2 准备管理员 | 受控离线调用已有 `bootstrap-admin`，密码走 stdin | 复用账号/域 0 成员/受保护平台角色/绑定/审计事务；已初始化按现有不变更凭证规则处理，不修复或接管未知状态 |
| P3 准备管理 client | 受限显式离线步骤，仅准备装配必需管理 client | 此命令是待补缺口，不是已有接口；缺失则创建，匹配则核对返回，冲突则停止；不为业务 clients 新建离线管理平台 |
| P4 启动管理入口 | 共同装配器允许空业务入口列表；管理入口沿用独立管理身份，首次使用平台域 0 | readiness 与管理引用均有效才启动；只暴露所需管理登录/API/后台和健康能力，不匿名暴露安装功能或默认业务入口 |
| P5 创建业务运行对象 | 平台管理员登录后通过现有管理 API 创建租户、clients；按需要显式建立成员/角色 | 租户新建输入明确关闭公开注册，避免缺省误开；每步重试先核对已完成对象，不用声明重放覆盖在线修改 |
| P6 启用业务入口 | 在新配置中引用已准备对象，经校验后重新装配/启动 | 缺引用或冲突拒绝启动，不静默跳过、不放宽租户策略；重启不写身份配置、不恢复撤销状态 |

这里的步骤号用于流程说明；下节 P01–P06 是验收编号。数据库/密钥/Secret 的供应方式仍由宿主或部署方决定；不会要求所有库使用者执行 app 的准备流程。首次管理尚未具备后续 MFA 交付条件，因此该流程的本阶段证据只用于隔离软件验收，不形成生产开放承诺。

### 4.2 首次准备验收

| 用例 | 前置与动作 | 预期结果 |
| --- | --- | --- |
| P01 全新安装 | 新隔离 schema 完成 P1–P6；含宿主自有业务表的场景另跑 | 管理入口可先独立使用，再创建并启用 A/B；无直接业务表写入或身份模型复制，宿主表保留 |
| P02 重复执行 | 再次执行管理员和管理 client 准备；随后重启新模式 | 无重复对象、密码重设、额外角色授予或重复初始化审计；管理 client 冲突不得覆盖 |
| P03 错误前置 | 错模式、错误 schema、缺管理员/管理 client 或坏密钥分别启动 | 按现有 readiness 和新增引用检查失败，不自动迁移、修复或挂载宽松入口 |
| P04 中断与重试 | 管理 API 已提交但调用方未收到响应，再次准备对象 | 读取已完成状态再决定重试；不自动轮换 secret，不承诺跨步骤整体事务；显式 upsert 修改能力仍存在 |
| P05 权限负例 | 匿名、业务身份、普通产品管理员尝试平台 client/租户准备操作 | 无越权创建或改密；离线准备不暴露为绕过管理认证的 HTTP 接口 |
| P06 在线变更保护 | 修改回调、成员/权限，撤销会话后重启；另用隔离夹具移除被引用 client | 不覆盖修改或复活凭证；缺引用拒绝启用且不重建。夹具不代表新增客户端删除 API |

P01–P06 中新增流程目前均待实现验证；现有 bootstrap/readiness 测试可复用，不宣称整个流程已经支持。

## 5 入口标识稳定性

| 标识或参数 | 当前作用 | 必须维持的规则 |
| --- | --- | --- |
| login_entry | 选择票据、授权码及部分 proof context 的绑定 | 稳定显式值；旧 business/management 及配置中的扫码入口值保留；不从数组位置、启动时间、随机数生成 |
| client_id | 会话、client 记录、令牌及设备域绑定 | 独立 client 不混用；同一个逻辑入口可组合 token/browser 等 transport，不为每条路由创建新 client |
| tenant policy 与 purpose | 决定登录选择规则和业务/管理身份 | app 自营 Fixed 不改变库级 Choose/Disabled；管理目标域选择仍独立 |
| issuer/audience | 签发及验证边界 | 不因配置格式变化而改值；OIDC 映射技术验证后确定，不接受调用方自选验证规则 |
| 外部路径、Cookie 名及范围 | 浏览器凭证发送、路由及设备请求证明上下文 | 外层前缀由宿主负责；不能用未受信转发头覆盖；改变值需声明迁移影响 |
| origin/path/purpose 协调键 | 同源浏览器多标签串行刷新和状态广播 | 与实际 Cookie/路由范围一致；不按入口列表重排生成新键，不跨产品误清状态 |

**边界提醒：**login_entry 不能单独当作所有 access token 的隔离字段。现有 access token 校验还依赖 client、purpose、租户策略、issuer/audience 和当前会话；不能只改入口名称就认为旧 access token 已撤销。改租户、用途或关键绑定时默认采用新入口/client，并制定旧凭证处理；涉及设备绑定时也需评估迁移，不能直接复制设备记录。

| 用例 | 动作 | 预期结果 |
| --- | --- | --- |
| S01 配置重排 | A/B 入口调序，增删无关入口，旧输入转换成共同参数 | 原有 client/login_entry/外部地址/Cookie 范围不变；未过期、未撤销且未消费的票据仍按原契约可用 |
| S02 普通重启 | 保持密钥、库、时钟语义和全部绑定重启 | 现有会话及适用的 code/refresh 继续有效；已撤销或已消费的产物仍拒绝，不延长原到期时间 |
| S03 绑定变更 | 修改 login_entry、client、租户策略、issuer 或外部路径 | 不能作为“无影响重排”接受；可以明确拒绝不支持的原地变更，要求新入口及旧凭证处理；禁止放宽校验。M1 不要求自动迁移工具 |
| S04 多标签隔离 | 同源 A/B 各开两标签；A 退出，B 恢复；同入口并发刷新 | A 操作不误清 B；同入口协调仍成立，未知结果按旧策略阻断并恢复；不把同源脚本当作彼此隔离的安全主体 |

普通重启的用例必须在凭证原有有效期内执行，并以数据库核对确认撤销未被抹去，不能用扩大 TTL 让测试通过。

## 6 Fixed Choose Disabled 验收用例

### 6.1 夹具和观测方式

Enabled 测试使用虚构租户 A/B 与独立管理 client；Disabled 使用独立的域 0 schema/宿主，不能在同一已初始化 schema 中随意切换模式。每个负例从干净夹具恢复，只改变待验证条件，不叠加多个失败原因。

| 夹具 | 明确状态与用途 |
| --- | --- |
| Uab、Ua、Ub | 全局 active；Uab 为 A/B active 成员，Ua 仅 A，Ub 仅 B；覆盖 F01/F02 和跨域正反例 |
| Usa、Usb | 全局 active；Usa 在 A suspended/B active，Usb 在 A active/B suspended；成员级拒绝不得误停另一个有效域 |
| Uoff、Uremoved | Uoff 全局停用，不能保留其他有效会话；Uremoved 另有 removed 成员，用于列表与完成选择的不同规则 |
| 租户状态 | A/B 默认为 active；停用或归档测试使用隔离副本，只改变目标租户状态；非成员选择可用 Ua 选择 B |
| 入口 | Fixed-A、Fixed-B、Choose-C 使用明确稳定绑定；另备同策略的测试服务/适配器供 C04 逐字段负例，不能仅请求未挂载路由来证明票据绑定 |
| 时钟、并发和故障 | 使用可控 Clock 构造原有效期内、刚过期及锁等待后到期；C07 使用同一票据同步竞争；C08 在签发或插入点注入故障。新组合实库测试沿用仓库隔离方式 |

这些是测试专用构造，不要求生产配置允许同 client 多个冲突逻辑入口，也不要求实现通用故障注入平台。具体类型和夹具写法由现有测试框架承接。

普通策略用例先关闭 device proof，以单独验证策略；设备回归另在启用配置下执行，不得改变实际 require_device_proof 来绕过检查。每个负例核对会话、票据消费和授权变化，而不只看 HTTP 状态。

| 用例 | 输入与动作 | 预期结果及状态断言 |
| --- | --- | --- |
| F01 固定域成功 | Uab 或 Ua 在 Fixed-A 使用正确账号密码登录 | 直接取得 A 会话，无选择票据；不会自动创建 B 成员或额外角色 |
| F02 当前资格失效 | 只属 B 的账号、A 停用成员、全局停用账号登录 Fixed-A | 拒绝，无 A 会话；A 会话签发后 A 成员停用，后续当前状态认证拒绝，其他有效 B 会话不误停 |
| F03 不接受调用方选域 | Fixed-A 登录带 B 的租户头，或 body 加 tenant/client/policy 字段 | 按原有头/严格 DTO 规则拒绝；不能据此改选 B，也不改变正常登录 wire 格式 |
| F04 禁止固定域切换 | 在普通 Fixed 路由请求选择/切换；直接调用服务 begin_switch | 普通适配器未挂选择路由；Core 拒绝切换。其他适配器按自身契约拒绝，不统一要求 HTTP 404 |
| C01 认证后选择 | Uab 在 Choose-C 登录并列租户 | 仅给选择票据，不产生 session/tokens；只列本人非 removed 成员及状态，无权查看其他用户成员 |
| C02 合法完成 | 使用 C01 票据选择 active A 或 B，并使用匹配的可选租户头 | 产生目标域会话，票据一次消费；tenant_id 来自经验证选择，不把域 0 当业务通配符 |
| C03 无效目标或票据 | 选择非成员/停用/归档域，过期票据，或重复消费 | 拒绝且无新增目标会话；票据未被错误赋予额外域权限，错误投影不泄露敏感状态 |
| C04 跨入口冒用 | client、login_entry、purpose 各单独构造不匹配；另将票据当 Bearer | 每项分别拒绝，不能依靠其他字段或 404 掩盖遗漏；同入口合法选 B 仍成功，逐字段要求见下文 |
| C05 合法切换 | A 当前会话 begin_switch，再由有效票据选 B | B 新会话成功；保留原 authenticated_at 和适用 scope，不能扩大授权；Core 基线不因成功切换自动注销仍有效源 A 会话 |
| C06 来源失效 | 发起切换后撤销来源会话/失去来源资格，再完成 B；含等待锁期间撤销 | 拒绝，不签发 B 会话；设备启用时还需验证来源绑定失效。来源失效检查不等于成功切换必撤销来源 |
| C07 并发消费 | 同一票据两请求并发完成选择 | 最多一个成功，最多一个新会话和初始 refresh 记录；不能两个域同时用同一票据签发 |
| C08 失败回滚 | 在消费票据后签发或插入会话失败 | 事务回滚，票据不成为“已消费但无会话”；在仍有效且状态允许时可重试，不缓存旧 Allow |
| D01 无租户正常使用 | Disabled + Fixed 0 独立宿主登录、恢复、查本人角色和访问真实业务资源 | 使用域 0；provider 注入、token/custom transport 保持；宿主仍检查资源归属，权限撤销后拒绝 |
| D02 非法配置/请求 | Disabled 配 Choose 或 Fixed 非 0；认证请求/资源上下文伪造非 0 | 配置构造或请求按原契约拒绝；不自动切模式，不接受 0 代表全部租户 |
| D03 无选择面 | Disabled 普通路由查询 capabilities，并访问选择/切换路径 | 返回 disabled/fixed/0 对应字段；普通选择路径未挂载，前端不出现租户切换要求 |
| D04 管理与数据边界 | 独立业务宿主不挂管理路由，管理进程可共 schema；保留宿主业务表 | 业务身份不取得管理权限；无中央服务依赖；宿主表、既有账号和身份对象命名冲突保护保持 |

F01–D04 是待执行的验收设计，不表示当前所有组合已有自动化覆盖。C05 的源会话保留可由现有 `proof_selection_signs_exact_ticket_and_switch_requires_live_source_and_target_device` 测试末尾双会话认证断言核对；不得将旧规划中的“源会话撤销”误解为自动注销要求。

C04 每个子例均先证明未修改的票据可完成选择，再从新的干净票据开始只改变 client、login_entry 或 purpose 一项，保持其他元数据和当前状态有效，核对无新会话且无错误消费。优先复用 `selection_record_metadata_and_membership_are_rechecked` 的逐字段方法；跨适配器部分仍应验证真实的票据认证方案。这里的元数据/测试服务构造不授权运行方改写生产票据记录。

### 6.2 管理入口兼容用例

| 用例 | 输入与动作 | 预期结果及状态断言 |
| --- | --- | --- |
| M01 平台 Fixed 0 | 分别在 Enabled/Disabled 构造管理 Fixed 0 并认证；对照 Enabled 业务 Fixed 0 | 管理平台身份按既有规则成功，业务构造拒绝；管理目标租户仍需管理 API 权限检查 |
| M02 管理 Choose | Enabled 管理 Choose 登录、列域、完成有效业务域选择，再尝试选 0 | 保留合法业务域选择；域 0 不在该列表且完成选择被拒绝，不通过 Choose 取得平台身份 |
| M03 不支持的证明配置 | 管理构造器设 require_device_proof=true | 明确返回不支持且不创建会话；不能自动设 false、沿用业务证明路由或降级登录 |
| M04 用途与模式负例 | 业务 token 用于管理、管理 token 用于业务；Disabled 管理 Choose/Fixed 非 0 | 均按既有边界拒绝；管理 Fixed 0 与 Disabled 业务 Fixed 0 不因同域而共享身份用途 |

## 7 验证入口与交付标准

本节的验证位置和用例是后续运行基线的执行设计。M1-01 当前只核对映射和差异；不以跑完全部运行用例作为本次设计交付要求。

| 层次 | 现有位置或入口 | 本次用途 |
| --- | --- | --- |
| Core | `access/authentication_tests.rs` 及其子模块 | 策略、票据元数据、当前状态、失败回滚；补缺口，不复制所有既有测试 |
| Axum | `tenant_auth.rs` 内测试、`management_auth/tests.rs`、`browser_session/tests.rs` | 真实 DTO、错误、capabilities、挂载与认证边界 |
| PostgreSQL | `tests/authentication/`、`tests/live_access_tenants.rs`、`tests/live_access_bootstrap.rs` | 并发、锁等待、成员状态、bootstrap 和持久化断言；父测试入口由接收方按当前代码确认 |
| app | `tests/live_reference_host.rs`、`tests/live_bootstrap_admin.rs` | 旧参考进程和新装配首次准备；需补的新多入口用例单独标记 |
| Web/宿主 | `web/embedded/client.test.mjs`、`web/management/client.test.mjs`、`examples/no-tenant-host` | 默认传输、独立嵌入、同源浏览器与多标签实际验证 |

| 用例组 | 复用起点 | 待补证据 |
| --- | --- | --- |
| P01–P06 | Access/bootstrap、租户/client 管理及 app live 测试 | 新管理 client 准备、空业务列表、完整首次准备及中断重试组合 |
| S01–S04 | 既有票据、code/refresh、BrowserSession 和 Web 客户端测试 | 多入口重排/普通重启、命名迁移、同源 A/B 多标签隔离 |
| F01–F04、C01–C04 | Core authentication_tests、Axum tenant_auth 内测试 | 同一 app 多入口组合、按实际适配器区分未挂路由和策略拒绝 |
| C05–C08 | Core 源会话/回滚用例、实库 device_proofs 切换测试 | 无证明路径的源会话保留对照、并发单次消费与失败回滚实库证据；不能用设备路径通过替代所有路径 |
| D01–D04 | no-tenant-host、app both-modes、共 schema 初始化测试 | 在改造后用旧配置、旧 provider 和未启用新能力的宿主重新验证 |
| M01–M04 | Core authentication_tests/management、Postgres tests/authentication/management 及 Axum management_auth 测试 | 共同配置校验器保留管理 Fixed 0 例外、Choose 选域和不支持证明配置拒绝 |

“复用起点”仅表示存在相关实现或测试文件，不代表已经逐例覆盖或本轮已通过；接收方在改动前将具体测试函数和缺口补入回传清单。

从首个相关改动起执行通用兼容门槛；OIDC/Cookie/设备/扫码按已启用或受影响范围执行组合验收，未改变的旧路径保留原基线。不枚举全部功能组合，也不以可选为由跳过已启用能力。

上游基线构建顺序仍为 Web 安装/构建后再 Rust fmt/check/test，因为 app 编译时嵌入 Web 产物。真实 PostgreSQL 必须使用显式隔离的 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI`，不使普通离线测试强制连接数据库。浏览器证据与设备硬件、实际部署验收分开。

### 7.1 M1-01 本次设计交付

| 交付项 | 必须包含的内容 |
| --- | --- |
| 当前基线对照 | 实际分析提交、软件/schema、与本文基线差异；新增事实不能只靠历史记录推断 |
| 兼容与接口分类 | B01–B12/I01–I10 的文件、类型和调用方；公共 API、内部结构、外部可观察行为分别列出 |
| 首次准备与稳定性结论 | P1–P6 各步的已有能力/缺口、无循环依赖的说明、S 变更分类和管理策略矩阵；建议替代方案注明理由 |
| 测试设计映射 | P/S/F/C/D/M 用例到现有测试函数或待补测试；记录前置、单一变更、期望结果和状态断言。本次全部运行结果可标“未执行” |
| 技术待定与下一工作包 | 必要 API/schema/version 变化的候选影响、未支持范围、待验证项、后续任务建议；不把候选实现当已发布契约 |

回传文档注明 UP-M1-01 修订 2 和实际源码提交。设计内容齐备可完成本次文档交付，但不能据此声称运行基线或整个 M1 已通过；本次不要求代码提交、迁移结果或完整运行证据。

### 7.2 后续实现任务的回传

进入后续实现任务后，再回传实施提交、实际改动接口、版本/schema 影响、逐用例运行结果与证据、未支持组合、OpenAPI 覆盖缺口及迁移/重新登录说明。结果区分未执行、通过、失败和有理由的不适用，不只报告测试数量。代码或运行结果不属于第 7.1 节本次必交内容。

### 7.3 待工程验证项

仍待工程验证：新配置格式及内部类型、管理 client 准备命令和冲突比较规则、OIDC issuer 映射、必要的公共契约变更与版本、OpenAPI 工具。不得把这些技术项转成需求方必须预先选定的部署条件。

## 8 固定提交证据

- [入口模型](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-core/src/access/model.rs)、[认证服务和事务契约](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-core/src/access/authentication.rs)、[普通认证 HTTP](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-axum/src/tenant_auth.rs)。
- [app 配置](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-app/src/config.rs)、[app 装配](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-app/src/bootstrap.rs)、[管理员 bootstrap](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-core/src/access/bootstrap.rs)、[Access 初始化分支](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-storage-postgres/examples/bootstrap_local_postgres.rs)。
- [客户端管理](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-core/src/access/admin/clients.rs)、[浏览器协调](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/web/embedded/browser-session.ts)、[设备选择和切换实库测试](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-storage-postgres/tests/authentication/device_proofs.rs)、[无租户宿主](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/examples/no-tenant-host/README.md)。
- [管理入口及 Fixed 0 例外](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-core/src/access/authentication/management.rs)、[人员设备会话](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-core/src/access/authentication/device_transport.rs)、[两类单次设备证明](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-core/src/access/device_proof.rs)。
- [本人角色与 business_id](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-axum/src/tenant_self.rs)、[Access 初始化与权限目录](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-storage-postgres/src/access.rs)、[票据元数据逐字段测试](https://github.com/ooctoo/rust-embedded-idp/blob/1835ec35790568fefb9f6792a120b3041cfe77ae/crates/embedded-idp-core/src/access/authentication_tests.rs)。

## 9 修订 2 变更记录

修订 2 取代修订 1 的交接内容：分开本次设计与后续实现回传；增加管理 Fixed 0 例外及 M01–M04；完整定义三类设备保证、business_id 和权限目录；补齐夹具及 C04 逐字段负例；区分公共 API、app 内部结构和外部行为。新增基线 B12，原有 I/P/S/F/C/D 编号保持，运行用例共 30 个（C04 内含逐字段子例）。需求内容经最终审查认可；文档同步不改变修订号，也不表示已启动实现。
