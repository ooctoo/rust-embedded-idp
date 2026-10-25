# 剩余产品能力技术设计

| 项目 | 内容 |
| --- | --- |
| 标识 / 修订 | IDP-PRODUCT-COMPLETION，修订 4，2026-10-25；完成开源适配、许可、依赖与现有代码的完整复审 |
| 状态 | 修订4设计基线；后续A01/A02A局部实施见下方记录，其余仍为提案；不代表完整验收或部署 |
| 核对基线 | 修订4开始时本地HEAD `de50eb9`；产品源码对照基线`d721481`，3.0.0 / `tenant_v6`，两者间crates/web/examples无差异；初稿基线`8fd9f46`；未查询本仓库远端状态 |
| 范围依据 | 本次需求：除完整验收外，对剩余产品能力给出详细技术设计和实施方案 |
| 配套方案 | [分阶段实施方案](product-capability-completion-plan.md) |
| 现有边界 | [M1-02 修订3](m1-02-configuration-composition-design.md)、[当前能力汇总](management-console-delivery-summary-and-plan.md)、[设备生命周期](device-identity-lifecycle-design-v1.md)、[扫码协议](device-scan-login-design-v1.md) |

并行工作说明：修订1期间其他工作将HEAD推进至`d721481`，同时产生N2实际执行文档和证据。本轮以该HEAD重新核对当前源码；不修改或接管N2工作，也不据此判断远端终态。完整验收最新进展由所属任务维护，本文只记录开发设计范围。

修订2收尾时另一个任务提交了`de50eb9`；已核对它相对`d721481`仅涉及N2测试脚本/选集和证据，crates/web/examples产品源码无差异。因此本轮产品审查基线不变，不把并行测试工作计入本文验证结果。

修订3在本地`de50eb9`再次确认上述产品源码无差异；新增的是设计决策及上游资料核查，不是代码实施。2026-10-25核对的上游默认分支清单仅作为选型证据，不等于已发布版本、依赖锁定或兼容性验证。该次冻结了WebAuthn优先和Standard Webhooks方向；后续细节以修订4正文为准。

修订4进一步按上游实际API和本仓库实现修正文档；§16.1–16.3仅为历史记录，当前合同以修订4正文及§16.4为准。上游默认分支源码、已发布包和最终锁定依赖是三个不同层次，本轮静态核查不替代后续G0的所选release验证。

修订4收尾时并行任务已将HEAD推进至`6442583`；再次核对相对`d721481`的crates/web/examples无差异，产品审查基线仍有效。新增N2提交、未提交文档和诊断证据均由所属任务维护，本轮不改写其结论。

实施记录：A01见[第一批](a01-implementation-result.md)，A02A普通业务组合及A03本批合同见[第二批](a02a-implementation-result.md)。A02B-B1配置v2与共享OIDC见[第三批](a02b-b1-implementation-result.md)。下文保留修订4设计基线；实施范围与局部验证以对应记录为准。

## 1 范围、结论与提案效力

核心身份服务与管理后台已有实现，剩余工作分成三条线：完成既定接入能力；补足设备自助与租户嵌入体验；按实际消费者选择安全和身份增强。本文覆盖三条线，提出推荐技术方案，不将候选增强自动纳入首版，不把文档完成称为功能完成。

完整 N2 环境补验、M1-06 组合验收、性能/容量、实体终端和生产环境签认不在本轮执行范围。实现阶段仍须做与改动直接相关的单元、事务、接口及局部交互测试；“暂不完整验收”不等于允许省略安全回归。基础设施部署、实际密钥供应、真实账号迁移、试点及发布不由本文决定。运行保障只设计软件接口及操作机制。

下文“拟新增”“建议”“目标”均是本提案，不是现有 API 或已批准上线政策。接口路径是模块内候选路径，宿主仍决定外层前缀。已有路由和类型以源码为准；本文不会把旧生产安全文档中早期单域 DTO 覆盖到当前租户设备合同。

### 1.1 能力清单

| 编号 | 能力 | 现状 | 本设计的处理 |
| --- | --- | --- | --- |
| A01 / M1-03 | 管理 client 显式准备 | 缺独立 create/match/conflict 准备流程 | §4，既定缺口 |
| A02 / M1-04 | 新配置业务入口、多入口与协议组合 | JSON 可解析非空集合，当前构建拒绝运行；旧参考组合可用 | §5，分普通认证与协议组合完成 |
| A03 / M1-05 | 接口合同制品与漂移约束 | 未交付该工作包 | §6，覆盖清单先行，合同随代码演进 |
| A04 | 设备自助登记、密钥轮换与结果恢复 UI | 领域及接口已有，缺持钥端自助闭环 | §7，复用协议，不重造设备身份 |
| A05 | 带租户嵌入示例；设备/扫码为可选扩展 | 登录组件已有；真实示例仅 Disabled；扫码 H5 已有 | §8，基础退出条件与可选接入分开 |
| S01 / C10 | 密码入口防滥用 | 扫码有专用限流，网络准入主要由宿主负责 | §9，宿主准入与领域尝试计数分开 |
| S02 / C05 | MFA 与 step-up | 无通用因子、登录挑战、敏感操作授权票据 | §10，WebAuthn优先完成管理/高权限闭环，TOTP为后续兼容子批 |
| S03 / C06 | 自助安全中心与账号恢复 | 有管理员改密和撤销基础，无自助恢复流程 | §11，普通账号与管理身份恢复分开 |
| X01 / C07 | 邀请、加入和可选审批 | 已有管理成员与授权，无邀请票据 | §12.1 |
| X02 / C08 | 外部 OIDC、LDAP/SCIM | 当前是 OIDC provider，无 broker/目录同步 | §12.2，OIDC 优先，目录接入独立合同 |
| X03 / C09 | 机器身份 | client 认证不等于机器主体或 client_credentials | §12.3 |
| X04 / C13 | 组、组织与受限委派 | 已有角色和 business_admin | §12.4，先平面组，层级另设边界 |
| O01 / C11 | 认证事件与可靠外部投递 | 已有管理审计，无通用投递闭环 | §13 |
| O02 / C12 | 签名轮换及运行保障软件接口 | 有构造时 active/overlap 验证密钥，无运行控制面 | §14 |
| U01 | client CAS、导出、统计、配置快照 | 现有客户端 upsert 无 CAS；其他为可选增强 | §15，按需求独立实施 |

M1-06 是整体交付/组合验收，不在本文伪装成新的开发工作包。N1 的 dot-only 新 UI/新服务端兼容已完成，不重新列为缺口。扫码登录 H5 位于 `crates/embedded-idp-app/src/scan_ui.rs`，扫码 renderer 位于 `web/scan-code/main.tsx`，都不是从零待建。

## 2 实际代码落点与架构约束

| 层 | 当前复用点 | 增量责任 |
| --- | --- | --- |
| Core | `access/authentication.rs` 及子模块、`access/registration.rs`、`access/admin.rs`、`access/device_proof/` | 状态机、授权、原子事务合同、可注入验证器；不接 HTTP、环境变量或数据库 |
| Security | `jwt.rs`、`jwk.rs`、`ed25519.rs`、refresh/scan-result adapters | 新因子密码学、摘要、密钥包验证；不决定租户准入 |
| Email | `embedded-idp-email/src/lib.rs` | 按用途拆分恢复/邀请/安全通知合同，供应商适配保持中立 |
| Axum | tenant/management auth、browser session、tenant devices、OIDC resource/authorization routers | 类型化输入、来源/CSRF/proof、响应投影及错误映射，不写业务 SQL |
| PostgreSQL | `access.rs` 及 `access/` 下事务实现 | 唯一约束、锁、条件更新、审计/outbox 与事务一致性 |
| App | `composition_config.rs`、`bootstrap.rs`、`administrator_init.rs` | 配置、离线命令、参考装配、任务启停；不变成强制生产宿主 |
| Web / 示例 | `web/embedded/`、`web/management/`、`examples/no-tenant-host/` | 复用认证协调、作用域隔离和结果未知保护；业务资源归属仍归宿主 |

全局账号共享身份和凭据，租户成员关系不共享授权。`client_id`、`login_entry`、`business_id`、设备和机器主体不可互相代用。新登录来源验证成功只证明身份，仍须检查账号、成员、租户、入口及当前策略。

管理与业务 session purpose 始终分离；业务 MFA 或机器令牌不产生管理权限。管理会话的租户与本次管理目标租户分别记录。新能力不得用默认 trait 方法返回允许，绕过未实现的宿主安全依赖。

现有租户会话 `TenantSession` 已有 `authenticated_at`，但没有完整 MFA assurance；扩展以租户感知服务为主，不能把早期单域 `CoreAuthService` 当作 Enabled 模式实现。账号改密的全域凭据退役机制应从 `access/admin/account_security.rs` 和存储事务复用，不能仅改密码哈希。

### 2.1 复用原则与组件选型

采用顺序固定为：仓库既有能力 → 成熟协议/算法库 → 成熟产品的流程和失败处理模式 → 本项目必须拥有的最小领域实现。保留Core、Security、HTTP、存储与宿主边界；不引入完整IAM服务作为强制运行依赖，不为选型建立通用插件平台。库只能证明它验证的协议事实，不能替代本地账号状态、租户资格、用途、策略或权限检查。

下表是已选定的首选组件；对应能力启动时按实施方案G0锁定具体已发布版本和feature集合。当前未安装依赖、未更改Cargo清单、未完成适配试验。只有核查发现明确不兼容时才记录原因并更新两份文档，不默认为重新自写协议。

| 编号 / 切片 | 首选组件及上游许可依据 | 复用内容 / 拟归属 | 本项目保留的责任与限制 |
| --- | --- | --- | --- |
| OSS-01 / S02a–c | [webauthn-rs](https://github.com/kanidm/webauthn-rs)，[清单：MPL-2.0](https://github.com/kanidm/webauthn-rs/blob/master/Cargo.toml) | WebAuthn注册/认证验证，放在Security的可选adapter；浏览器使用原生WebAuthn API | Core拥有因子绑定、策略、单次状态与会话；Postgres拥有原子消费和凭据更新；不是设备Ed25519 proof替代品 |
| OSS-02 / S02d | [totp-rs](https://github.com/constantoine/totp-rs)，[清单：MIT](https://github.com/constantoine/totp-rs/blob/master/Cargo.toml) | TOTP计算/验证及配置URI，Security可选adapter；只启用所需features | 密钥封装、接受counter、限速、登记确认、恢复码与事务由本项目负责；二维码能力按UI需要选择 |
| OSS-03 / X02a | [openidconnect-rs](https://github.com/ramosbugs/openidconnect-rs)，[清单：MIT](https://github.com/ramosbugs/openidconnect-rs/blob/main/Cargo.toml) | 外部OIDC RP客户端、发现/换码/ID Token验证；隔离在可选联邦基础设施adapter，由宿主注入Core | 网络出站策略、缓存预算、state单次性、link和本地准入由本项目负责；它不是Provider，不替换现有OIDC服务端；不另建重复oauth2客户端栈 |
| OSS-04 / S01 | [governor](https://github.com/boinkor-net/governor)，[清单：MIT](https://github.com/boinkor-net/governor/blob/master/governor/Cargo.toml) | 进程内预算算法，用于宿主准入adapter；初期直接接现有Axum/Tower边界 | 可信来源、账号键、容量/清理、多维策略、KDF并发及共享原子store另行负责；不声称分布式一致；不默认再加tower_governor |
| OSS-05 / A03 | [utoipa](https://github.com/juhaku/utoipa)，[清单：MIT OR Apache-2.0](https://github.com/juhaku/utoipa/blob/master/utoipa/Cargo.toml) | HTTP DTO/schema与接口合同生成，限Axum可选文档feature或合同工具层 | Core不加HTTP/文档注解依赖；实际装配清单、认证组合、外层prefix和协议字节说明由本项目维护；生成物仍须审阅和漂移检查 |
| OSS-06 / O01b | [standardwebhooks](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries/rust)，[Rust库清单：MIT](https://github.com/standard-webhooks/standard-webhooks/blob/main/libraries/rust/Cargo.toml)；[规范：Apache-2.0](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md) | Standard Webhooks的HMAC v1签名/验签，位于投递基础设施adapter | 事件授权/投影、事务outbox、worker租约、重试、去重、SSRF和密钥供应仍归本项目；库不提供完整投递系统，也不据此宣称支持非对称v1a |

纯Core调用方不因这些选型被迫依赖网络、Web框架、OpenAPI、外部服务或全部新增因子算法；Core目前已有argon2/sha2等依赖，不将其描述为完全无密码学依赖。第三方协议类型不直接进入Core公开合同：以本项目类型表达已验证事实，以有版本/长度限制的不透明状态材料保存库协议状态，序列化只在adapter边界发生。

现有六个crate没有通用联邦/HTTP投递基础设施层。X02a拟新增可选`embedded-idp-federation`，容纳RP客户端与受控出站HTTP；O01b拟新增可选`embedded-idp-delivery`，容纳Webhook签名与受控HTTP发送adapter。二者各随自己的切片创建，不预建通用插件平台；不持有业务SQL或决定租户授权。O01a先复用Email契约和参考app的有限worker，outbox状态合同归Core、事务实现归Postgres；后续worker启停仍由宿主负责，不让投递crate自动启动线程或读取环境。WebAuthn/TOTP留在Security可选adapter，HTTP DTO/文档留在Axum，配置及引用装配留在App。网络等待不得进入Core同步事务或密码学adapter。现有ring/argon2/lettre继续复用，不进行无关替换。

### 2.2 许可证与版本门槛

本仓库workspace声明MIT；引用第三方不会把其许可证改成MIT。G0记录选定release/tag、源码校验信息、直接/传递依赖、features、最低Rust版本、原生/TLS依赖、许可证及NOTICE来源。对MIT/Apache依赖保留要求的归属和许可文本；使用或修改MPL覆盖文件时明确对应源码提供及文件边界，不能把复制代码重新标成纯MIT。具体交付形态按选定版本的LICENSE及文件头核对，本表不替代发行前核查。优先以依赖方式使用，避免复制/长期fork上游。

本轮另核对了实际许可文本：[webauthn-rs MPL](https://github.com/kanidm/webauthn-rs/blob/master/LICENSE.md)、[openidconnect-rs MIT](https://github.com/ramosbugs/openidconnect-rs/blob/main/LICENSE)、[totp-rs MIT](https://github.com/constantoine/totp-rs/blob/master/LICENSE)、[governor MIT](https://github.com/boinkor-net/governor/blob/master/LICENSE)、utoipa的[MIT](https://github.com/juhaku/utoipa/blob/master/LICENSE-MIT)与[Apache](https://github.com/juhaku/utoipa/blob/master/LICENSE-APACHE)，以及Standard Webhooks的[Rust源文件MIT标识](https://github.com/standard-webhooks/standard-webhooks/blob/main/libraries/rust/src/lib.rs)。后者的规范/根目录Apache许可不能替换Rust包自身的MIT归属；G0还需核查发布包实际携带的许可文件。utoipa的`OR`表示可择一合规，并非必须同时采用两种许可。

MPL是文件级许可：分别记录内部运行、源码分发和包含该库的二进制/容器分发形态；对外分发时落实所覆盖源码的获取方式和相应声明，不误解为整个宿主必须改为MPL，也不误解为静态链接便免除该库的义务。依据[Mozilla官方FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)，最终仍按选定版本许可与具体交付核查。传递依赖和原生OpenSSL许可另列，不凭顶层crate SPDX覆盖全部依赖。本轮未锁定release或生成发布物，因此这些是实施交付门槛，不是已完成许可证审计的结论。

尤其不能将webauthn-rs误记为MIT，也不能将openidconnect-rs误记为MIT/Apache双许可。本次上游默认分支清单中webauthn-rs与totp-rs均标注最低Rust 1.88，后者使用edition 2024；这不等于本仓库要立刻升级，也不等于这些分支版本已发布。实施时用目标Mac/Linux宿主工具链和所选release验证，再决定兼容版本或显式工具链调整。暂不为整个仓库冻结六个库的版本，更不默认使用浮动git依赖。

### 2.3 完整产品的借鉴边界

| 参考项目 | 借鉴范围 | 使用方式与许可依据 |
| --- | --- | --- |
| [Rauthy](https://github.com/sebadob/rauthy) | Rust身份服务中OIDC/WebAuthn、管理交互、事件和迁移的组织方式 | 参考实现和负例，不整库搬入；[workspace声明Apache-2.0](https://github.com/sebadob/rauthy/blob/main/Cargo.toml) |
| [Kanidm](https://kanidm.github.io/kanidm/stable/accounts/authentication_and_credentials.html) | Passkey优先、凭据重置权限、高权限账号保护 | 参考流程；[主仓库MPL-2.0](https://github.com/kanidm/kanidm/blob/master/LICENSE.md)；SCIM协议类型可在X02b再评估，不视为现成SCIM服务 |
| [Keycloak](https://www.keycloak.org/docs/latest/server_admin/index.html) | step-up、required actions、服务账号及管理委派 | 参考产品行为和协议测试场景；[Apache-2.0](https://github.com/keycloak/keycloak/blob/main/LICENSE.txt)，不引入其Java运行时/存储模型 |
| [Ory Kratos](https://github.com/ory/kratos) / [Hydra](https://github.com/ory/hydra) | 自助flow生命周期、浏览器/API边界、身份与授权服务分工 | 参考流程；上游[Kratos许可](https://github.com/ory/kratos/blob/master/LICENSE)、[Hydra许可](https://github.com/ory/hydra/blob/master/LICENSE)为Apache-2.0；不把商业能力文档等同OSS功能或嵌入库 |
| [ZITADEL](https://github.com/zitadel/zitadel) | 多租户策略、身份链接和事件模型 | 仅设计参考；[当前主仓库默认AGPL-3.0-only，存在目录例外](https://github.com/zitadel/zitadel/blob/main/LICENSING.md)，不能沿用旧Apache印象；不纳入本方案直接代码依赖 |

A01/A02/A04/A05的现有装配与设备协议、共享账号的租户授权、一次性票据及跨表安全事务继续由本仓库拥有，没有选定能直接替换它们的完整框架。X03/X04先复用现有权限定义及上述成熟流程，不新增关系授权服务或策略DSL。LDAP/SCIM的具体库随消费者和协议子集在X02b冻结，当前只定义候选调查范围，不把未核查的目录库写成已选依赖。所有上游代码复制均须先核对该版本/文件及传递许可，并说明为何直接依赖不能满足需求。

### 2.4 上游API与构建适配约束

| 组件 | 本轮核实的边界 | 实施必须落实的适配 |
| --- | --- | --- |
| webauthn-rs | [默认feature包含attestation](https://github.com/kanidm/webauthn-rs/blob/master/webauthn-rs/Cargo.toml)；[core直接依赖openssl/openssl-sys](https://github.com/kanidm/webauthn-rs/blob/master/webauthn-rs-core/Cargo.toml) | 显式关闭默认features；为服务端持久化有界启用`danger-allow-state-serialisation`并验证读取兼容，不启其他danger/preview扩展。关闭attestation不等于去掉OpenSSL；G0验证Mac和Linux构建/运行链接及许可证，不能假定沿现有ring即可纯Rust编译 |
| openidconnect-rs | [README明确不验证azp](https://github.com/ramosbugs/openidconnect-rs/blob/main/README.md)；[默认reqwest/rustls](https://github.com/ramosbugs/openidconnect-rs/blob/main/Cargo.toml) | 关闭默认features后只选择需要的HTTP/TLS能力；现有Rust生产依赖未提供通用出站HTTP客户端，新增出站能力是该切片责任。库验证之后补最小已验证claims策略，详见§12.2 |
| utoipa | [Version31序列化为3.1.0](https://github.com/juhaku/utoipa/blob/master/utoipa/src/openapi.rs)，不是3.1.1 | 首批制品统一改为3.1.0；不改字符串伪装版本，也不为追补丁版本建立后处理平台。不默认引入utoipa-axum收集器或升级现有Axum 0.7 |
| totp-rs | [当前默认分支Totp::check返回匹配step的Option](https://github.com/constantoine/totp-rs/blob/master/src/lib.rs)，API随版本变化 | 所选release必须能以显式时间返回匹配step，优先用库接口；仅bool的旧API不能用“当前step”冒充匹配step。精确counter/算法/时间窗及输入边界在G0固定，不自写HMAC/逐窗口协议替代现成接口 |
| governor | [键控store提供retain_recent等清理能力](https://docs.rs/governor/latest/governor/state/keyed/trait.ShrinkableKeyedStateStore.html) | 使用单调时钟预算；清理不等于硬容量上限。达到容量时拒绝新键或使用更严格的有界汇总预算，不淘汰仍有效的账号桶来重置限额 |
| standardwebhooks | [一个Webhook实例持一把key；sign生成一份签名，verify_with_timestamp接受外部now](https://github.com/standard-webhooks/standard-webhooks/blob/main/libraries/rust/src/lib.rs) | adapter分别调用新旧key签名再按规范拼接；管理可信key集合/轮换期、头重复检查和去重。传入业务Clock转换的Unix秒，限制输入数值范围，不能假定库自动管理keyring或拒绝所有歧义头 |

以上是2026-10-25上游源码事实，不是G0已经通过。优先选择具备所需API的已发布兼容版本；未有合适release时保持该能力关闭并记录替代，不直接引入浮动主分支。Cargo feature会在依赖图中合并，G0须检查最终解析结果，单个声明的`default-features=false`不能证明所有上游默认能力都已关闭。

## 3 跨能力合同

### 3.1 身份、时间与错误

领域TTL、认证新鲜度和状态转换使用既有`Clock::now() -> SystemTime`。TOTP、OIDC时间验证和Webhook adapter显式转换到所选库需要的时间表示，拒绝epoch前/溢出/无效时间，不各自调用系统当前时间。governor的速率窗口和执行超时使用宿主单调时钟，不能用业务墙钟回拨重置预算；它不替代领域Clock，测试分别覆盖两类时钟。外部subject、来源地址、proof上下文、回调地址及policy仅从经过验证的宿主依赖取得。参数里的tenant/client只用于与可信上下文比对，不能创建授权。

新接口区分：输入错误、身份失效、授权拒绝、版本冲突、限流、暂不可用、结果未知。已公开错误码保持兼容；新增错误码和状态在 M1-05 制品中登记。匿名恢复/邀请查询不泄漏账号存在性，认证后详情按作用域授权。网络错误不能映射为“未发生”。

### 3.2 一次性操作与并发

不透明flow/URL票据统一要求高熵随机值、摘要持久化、用途绑定、截止时间、消费/撤销状态及原子条件更新；人工输入的短邮件code是明确例外，按§11使用密钥摘要和严格尝试预算。WebAuthn公开challenge及库服务端协议状态按§10保存，不能以“只存摘要”删掉库完成验证必需的状态。不先建立覆盖所有身份功能的通用工作流引擎，各领域维护最小记录和事务接口。

安全变更、挑战消费、会话退役、审计和必要 outbox 必须在同一事务中提交。外部邮件/HTTP 不在持锁事务中发送。遵循现有状态、租户、账号、会话等锁序；新增单次记录在读取路由提示后于事务内重查。具体跨域锁序由实现时逐操作列出，不能仅靠隔离级别名称证明安全。

锁序基线来自 `AccessWriteScope` / Postgres `lock_scope` 与当前设备/扫码合同：state → 排序tenant → 排序account，之后才取该操作需要的session/refresh、device/key/binding/challenge及grant/operation/delivery等锁。管理写依现有exclusive_state规则，认证路径依当前共享state/tenant规则；不把两者机械改成同一锁模式。当前全局账号安全写持state排他锁串行化，恢复应复用同级全局安全事务屏障，不能先持账号锁再补取其他租户锁。无锁查询只定位对象；范围变化则退出重试，不在事务末端逆序补锁。邀请接受先定位邀请的tenant/account，再按上述顺序取身份锁，最后锁邀请并重查版本与授予依据。

失败认证也可能包含必须提交的安全状态：尝试次数、challenge锁定、refresh reuse撤销应作为类型化拒绝结果提交后再映射HTTP错误；相应事件能同事务落地时一起写。完全不改变领域状态的拒绝才使用独立受限事件写入，不能将失败计数回滚或拆成不一致的两个事务。

涉及数据库提交结果未知时，不自动重放非幂等操作。新 receipt 仅返回操作归属、状态和安全摘要，不能存原始密码、恢复码或 token。回读当前状态不一定证明原请求归因。设备继续使用专用 registration/result/operation 合同，不将其泛化给所有管理写入。

### 3.3 数据及版本

不预占下一个 `tenant_v*` 编号。每个含数据库增量的切片提交独立迁移、前置版本检查、数据保留规则和升级说明，集成时按真实基线分配版本。迁移仅显式运行，在线启动不修复身份数据。

优先新增独立可选服务/trait，避免给所有已有 store 和公共 struct 强加字段。确需改变已有会话、主体或登录结果公共合同，按破坏性变化评估，提供新旧调用矩阵和版本说明，不能以 Serde 默认值掩盖 Rust 源码兼容破坏。

数据库降级可能丢失因子、邀请、组或审计语义，不能默认提供破坏性 down migration。安全回退首先是关闭新入口并保留数据；旧二进制不能理解新安全策略时拒绝启动。历史凭据不得因回退重新获得权限。

“旧版本拒绝”不能只依赖新程序中的校验：启用强制策略前必须通过schema版本/宿主能力版本门槛及入口清单，证明旧实例、旧Core调用方和后台worker已停止或被隔离。纯Core宿主没有统一数据库readiness，须由宿主提供等价版本屏障；无法保证时不得对共享数据开启新强制策略。

## 4 A01：管理 client 显式准备（M1-03）

### 4.1 输入与命令

拟增加离线命令 `prepare-management-client --config <path> --definition <path>`。命令名为提案；不得提供匿名 HTTP 安装接口。运行配置沿 M1-02 同源解析取得 DB/schema/mode/TLS/CA/SecretRef 与 management.client_id，后者是唯一client_id来源，定义文件只允许client_name、redirect_uris，拒绝额外或重复字段。类型固定 PublicDesktop，PKCE 必须开启，无 client secret 输入。

配置解析需拆出“准备所需结构/连接参数校验”与“当前构建启动能力校验”：准备步骤可以读取尚未启用的合法业务配置，但不启动业务、不解析无关 SMTP/签名材料；错误配置仍拒绝，不能借准备模式绕过字段校验。连接 Secret 不出现在命令行或日志。

### 4.2 Core 与事务

拟新增 `ManagementClientPreparationService` / `ManagementClientPreparationStore`，独立于在线 `ClientAdminService::upsert_client`。命令转成受限计划，Core 校验 client 合法性、PublicDesktop/PKCE/无 secret，再委托原子存储操作。

结果仅三类：`Created`、`AlreadyMatches`、`Conflict`。比较 client_id、名称、类型、PKCE、回调集合及 secret 缺省；回调使用既有 URI 校验，除集合排序/去重外不做尾斜线或大小写等额外归一。创建时间不参与比较。已有 secret、类型变化或回调差异一律冲突，不做更新。

Postgres 先校验已准备的schema/mode及P2状态，按全局准备写的state/域锁顺序进入事务，再使用唯一client_id约束insert-if-absent并锁定回读；与在线upsert保持一致锁序，不先锁client再倒取state。匹配不改记录且不重复创建审计。现有 `AccessAdminContext` 是人员会话上下文，不能伪造人类管理员actor；推荐独立、secret-free的准备审计投影，与创建同事务写入。它只记录离线系统操作、目标client、request_id和配置摘要，不复制整套管理审计平台；引入持久记录时按显式迁移交付。

COMMIT 回执丢失：以相同定义重跑，只核对当前完整匹配状态；输出 `AlreadyMatches` 不声称可归因到原命令。发现在线修改则冲突退出，不恢复旧值。数据库连接失败/结果不明使用独立非零退出码，避免把失败当不匹配。

### 4.3 首次准备闭环

保留 P1 schema 准备、P2 管理员初始化、P3 管理 client、P4 仅管理启动、P5 在线创建业务对象、P6 启用业务入口。新模式P4在通用readiness后、开放监听前只读检查管理client和策略引用，不等待业务入口才检查；LegacyReference的补缺seed只在旧路径运行。P4配置使用空business_entries，P5创建所需租户/client后才在P6加入业务引用，避免全新实例被尚不存在的业务对象阻塞。P5需明确注册开关，不默认开启公开注册。P1/P2/P3不是跨命令事务，失败只核对该步骤，不自动清库或撤销已有管理员初始化。M1-03局部退出包含P4登录并完成一次受限P5对象准备；P6和完整流程验收仍分别归M1-04/M1-06。

开发退出条件：创建、重复、冲突、并发同定义/异定义、COMMIT-unknown 后核对、非默认 schema/TLS 参数来源及旧启动行为均有局部测试。全新实例 P1–P6 的最终组合验收仍归 M1-06。

## 5 A02：业务入口与多入口组合（M1-04）

### 5.1 分阶段支持矩阵

| 组合 | M1-04A 普通认证 | M1-04B 协议与设备 |
| --- | --- | --- |
| Enabled Fixed 非0、Choose；Disabled Fixed0 | 支持，保留当前策略语义 | 同样适用，逐协议验证 |
| 管理 Fixed0/Fixed 非0/Choose、无 UI/可选 browser | 保留 M1-02 | 不隐式开启管理 proof |
| PublicDesktop token / 同源 browser | 完整 login/session/refresh/logout、选择/切换及本人角色 | 可叠加经显式配置的 OIDC/设备/扫码 |
| ConfidentialWeb | 仅服务端持有 secret 的调用方；不得向浏览器暴露 secret | authorization code + PKCE、client 认证与已支持 resource 面 |
| 注册 | 显式开启且邮件配置有效才挂载；继续现有固定域/注册策略限制 | 不因 OIDC/扫码自动开启注册 |
| 设备 proof / scan / OIDC | 新配置中暂不宣称支持；旧参考保持 | 在显式协议配置和路径绑定完整后启用 |

M1-04A 是可独立交付的子集，不能宣布 M1-04 整体完成。新配置 v1 只开启可表达且已闭合的普通组合；协议扩展建议定义配置 v2，v1 仍可读取，未知版本和未实现协议明确拒绝。不把旧 `reference_business` seed 作为新组合的实现方式。

### 5.2 普通认证装配

每个 EntryConfig 构造同一套租户感知服务，管理与业务共享依赖创建方式，但分别注入 client、entry、policy、purpose。集合校验、路径冲突和引用检查在监听前完成；业务入口重排不得改变任何稳定 ID、Cookie path 或 audience。

当前 `tenant_auth_router` 本身不含 refresh/logout，但现有 `tenant_device_auth_router` 已支持普通刷新与设备刷新，`tenant_oidc_resource_router` 已提供 logout；缺口是新配置的组合与暴露面，不能称为这些领域或 HTTP 能力从未实现。推荐从既有实现提取可独立挂载的普通会话 router，保留路径/DTO/错误和现有 router 的行为：refresh 调用已有 `CoreTenantAuthenticationService::rotate_refresh`，logout 复用 OIDC resource 中的 client 验证及精确 family 撤销。现有服务 trait 足够时直接复用，只有无法窄化依赖才新增可选合同；不重写第二套算法。

选择窄 router 的原因是普通配置不应为取得 refresh 隐式开放 `/devices/proof/challenges`，也不应为 logout 隐式开放 userinfo/introspect/revoke。提取前列清真实附带路径，旧完整 router 通过组合复用提取后的实现，避免两套代码漂移。若实际提取代价大于显式支持已有完整组合，须在 M1-04A 合同评审中记录替代方案与全部暴露面，再决定实现。

当前router依赖的是较宽的`TenantDeviceAuthenticationService`和`TenantOidcResourceService`，并非已存在一个通用窄会话trait。A02A先固定所提取router的state/服务依赖及client验证归属，再决定直接复用宽trait还是新增可选窄合同；路径裁剪不能省去原先的proof分支拒绝、client认证或撤销事务。

普通 refresh 只接受非设备绑定会话；绑定设备或入口要求 proof 必须拒绝，不能降级。logout 继续按当前 form/Basic client 认证规则：public 客户端提交 client_id；confidential 由后端提交凭据。浏览器只使用 browser-session 路由，客户端配置和 JS 均不包含 confidential secret。

上述“浏览器使用browser-session”限定登录/恢复/刷新/退出的凭据管理；当前浏览器响应仍提供短期access token并由 `EmbeddedIdentityClient` 保存在内存，资源及本人设备API继续发送Bearer。只有refresh在HttpOnly Cookie中，不能误称所有设备/业务接口已经接受Cookie直连，也不能读取该Cookie拼Bearer。纯token/custom transport模式继续可选，不强制所有宿主采用Cookie。

新 refresh DTO/错误投影复用既有普通刷新语义；新增服务 trait 必须明确 `ReuseDetected` 是先提交撤销再返回失败的成功事务结果，不能因映射 HTTP 错误而回滚撤销。退出只撤销对应会话和 refresh family；离线 JWT 的即时失效不作承诺。

### 5.3 浏览器与本人角色

每入口独立 cookie_name、实际 path 和协调键，复用 BrowserSessionCoordinator。浏览器 TTL 按本入口计算，不能借用管理入口的 lifetime；同入口 token/browser 服务的 client/policy 必须一致。多入口同源只保证状态协调不串用，不视为抵抗同源恶意脚本的安全隔离。

实施复审补充：新JSON私网HTTP受限browser的Choose票据与完整token通道隔离；为保持非滑动期限，短期受限会话的切换要求重新密码登录，普通完整会话仍可直接切换。该可选Core策略与旧票据300秒切换窗口见[第二批复审](a02a-implementation-result.md)。

兼容范围：上述按入口TTL规则适用于新多入口装配。当前LegacyReference由管理browser计算出的lifetime供业务browser使用，见 `bootstrap.rs`；本切片保留其现有可观察期限及旧模式测试，不把共用装配重构变成隐式TTL调整。若以后修正旧行为，单列兼容变化和受影响会话测试，不能同时声称旧期限完全未变。

本人角色接口保留必填 business_id 和作用域游标；客户端入口不推导业务权限命名空间。跨入口/租户切换时清理旧数据和迟到请求；Choose 完成前没有可用于业务 API 的正式 session。注册的邮件发送路径只在启用注册时创建，纯登录入口不强制 SMTP。

### 5.4 OIDC 单 issuer 分派

推荐保持单 issuer、一组 discovery/JWKS/协议端点，使用启动时冻结的 `client_id → entry` 注册表分派，而不是给每个入口复制一份全局 discovery。首批一个 client 只能属于一个业务 entry；已有配置重复 client 检查保持。管理 client 不进入业务 OIDC 分派。

授权请求的 client_id 必须命中注册表，再校验 redirect URI、PKCE、当前用户会话与该 entry 一致；用户会话来自该入口的受信 browser/bearer 验证，不能把任意管理登录状态转换成业务授权。token/revoke/introspect 从 client 认证及受验证凭据确定分派；userinfo 先验证签名、issuer/audience，再以验证后的 client_id 选择服务并核查当前 session。不能用未经验证 JWT 的 claim 作授权。

授权码继续绑定 client、entry、redirect、PKCE 与原会话；分派错误、未配置/未启用的协议入口、错误issuer或入口不匹配都拒绝。当前client没有停用字段/API，本切片不能写成已有客户端停用能力；移除配置仅阻止该入口服务，不承诺全域吊销已经签发的token。refresh grant仅在当前服务确实支持并完成合同后登记，不因有普通 `/auth/refresh` 就宣告OIDC token endpoint支持该grant。协议发现内容必须由实际启用能力生成。

当前authorize由Bearer认证，并非直接读取其他入口path下Cookie的通用SSO页。共享端点必须保留此调用合同，浏览器可在对应入口先恢复会话再提交短期access token；不能假定路径受限Cookie会发往共享 `/oidc`。如要提供顶层交互式重定向/授权页，应另补受信return destination和浏览器认证桥接合同，未实现前不宣称浏览器无缝SSO。固定外部 `/oidc/token` 同时用于设备证明的实际路径校验，跨entry分派不能改变验签上下文。

协议安全核对采用 [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)：本提案要求授权码流程使用 PKCE S256、严格匹配已登记回调并绑定事务状态；不新增 implicit/password grant。这是新组合设计选择，不声称已完成符合性认证。

### 5.5 设备和扫码组合

配置 v2 在业务 entry 下显式给出 device/scan 的 provider 引用、audience、外部路径、稳定 host_scope/entry、结果密钥引用和 cleanup 参数。它们是宿主可注入依赖，不允许 JSON 直接声明“已通过设备准入”。参考 app 提供适配示例，任意嵌入宿主可用自己的实现。

签名验证使用真实外部 method/path 和原始 body 摘要，路径在代理/挂载之后的映射必须唯一且可信。所有附带 routes 进入冲突清单。未配置可信 admission/presentation 时拒绝开启对应能力，不能沿用开发用无限期准入。

后台 cleanup 从旧单个 handle 扩展为实际启用服务的有限列表，统一取消、停止接收及 drain；不建设通用任务平台。扫码复用 Pending、ack/recover/abort，密文交付 keyring 与 JWT keyring 分开管理。

## 6 A03：OpenAPI 与接口合同（M1-05）

首批制品统一为OpenAPI 3.1.0，依据[官方规范](https://spec.openapis.org/oas/v3.1.0.html)及utoipa的实际Version31输出；撤回修订3的3.1.1要求。首选utoipa（OSS-05）从HTTP DTO/路由描述生成可审阅的静态合同；设备字节协议等不能自动表达的语义采用明确的手工扩展。每个operation/schema只维护一个权威源，不同时手写和生成相同定义。G0验证所选release的实际输出及schema语义，不替换版本字符串冒充支持，不为补丁版本增加后处理层。路由清单可先交付，生成器不兼容时记录差异并保留已交付的静态合同，不阻塞A01/A02，也不自建通用生成框架。

当前DTO分散在Axum的`dto.rs`及各路由模块，另有动态`json!`响应；不是给单个DTO文件加derive即可覆盖。清单逐项登记权威响应类型/构造点。对本切片覆盖的动态响应优先提取等价HTTP响应类型，再在HTTP层生成schema；Core外部类型采用本地HTTP投影或显式schema映射，不在Axum为外部trait/外部类型违反Rust孤儿规则实现，也不为文档向Core添加Serde/ToSchema。保留线上的字段、可空性和错误语义；不默认引入utoipa-axum或升级当前Axum 0.7。

拟增加 `docs/api/route-inventory.md`、按 management/auth/device/oidc 拆分的合同源及组合说明。完整清单登记所有实际路由：方法、模块根、挂载条件、认证 scheme、purpose、tenant/client/business、body limit、内容类型、成功/错误、no-store、分页及版本要求。参考 app 的外层地址作为 profile，不能写成库的固定前缀。

清单也纳入app的healthz/readyz、discovery/JWKS、管理/扫码HTML与静态资源、重定向及可选挂载面；静态资源可登记路由族与验证方式，不必为每个构建hash生成OpenAPI operation。M1-05既定退出是全量路由清单、新改接口完整合同和代表性既有接口验证；全仓历史接口逐一补齐schema是扩展子批，不能反向扩大既定M1-05门槛，也不能把前者称为全API schema全集完成。

M1 新增/改动接口必须完整建模；既有接口先完整清单，再按模块补齐 schema 和响应样例。设备 proof 需要同时存在的 headers、精确字节签名和可信外部路径用额外描述/扩展字段表达，不能把多个 security alternative 写成“任取一个头”。Cookie 写入记录 Origin/CSRF 条件；Basic/form 不得被文档示例降为 query secret。

漂移检查分两层：静态验证 operationId/schema 引用和 inventory 覆盖；局部 HTTP 测试校验真实 DTO、状态码、内容类型和代表失败路径。不能仅用 `rg route` 的结果证明动态路由完整覆盖。不自动生成全平台 SDK；现有 TS client 为受检查的真实消费者。

## 7 A04：设备自助与持钥端交互

### 7.1 已有合同与新增界面

复用 `TenantDeviceService` 的 provision/registration_result/complete/rotate/devices/device/key_metadata/unbind/self_operation_result；本人解绑走 `/devices/unbind` 和 `/devices/operations/:operation_id`。后者是当前有效本人、当前租户的自助操作回执，不是管理端device_operation_result。管理设备界面继续承担管理员启停/撤销/绑定处置，不获得代替设备持有者更换私钥的能力。

拟增加可嵌入的 `DeviceSelfService` 界面及薄 client 方法。设备列表、绑定详情、操作回执可在普通登录浏览器使用；“登记当前设备”“轮换密钥”只有宿主提供安全持钥能力才启用。UI 清楚说明缺少持钥适配，不提供把私钥复制到输入框的替代路径。

本人列表只呈现现有响应中的本人绑定投影，不调用管理员的全绑定列表。认证复用§5.2的内存access token/Bearer与认证revision；宿主只提供纯Cookie身份而无该transport时必须先接等价认证adapter，不能将管理或未验证actor注入本人服务。

实际登记组合需要两个独立前提：宿主认证准入后注入 `TrustedDeviceAdmission`，提供稳定registration_scope及有效期限；同时挂载由 `tenant_device_auth_router` 拥有的 `/devices/proof/challenges`。`tenant_device_router` 单独不提供challenge。provision/result重查admission，complete靠已登记公钥与challenge签名，不要求还不存在的本人session；rotate/本人读取/解绑则需要当前有效人员身份。夹具可供UI先行开发，不能替代这些真实接线退出条件。

### 7.2 宿主持钥边界

建议由宿主注入窄接口：能力查询、创建候选密钥返回 handle/public JWK、签名登记/轮换/请求、按确认结果激活候选密钥、清理候选密钥。私钥永不返回 React，不放 localStorage、URL、日志或服务端。

首批支持“宿主提供 signer”的接口和确定性测试 adapter，不承诺所有浏览器拥有相同 Ed25519 安全存储能力。原生 keychain/硬件具体适配按平台独立交付；WebAuthn 凭据不可直接充当本项目 Ed25519 proof 密钥。签名 adapter 必须限制用途、方法和目标，不能成为任意字节签名的远程通道。

### 7.3 状态流与恢复

登记：`未登记 → 本地候选密钥已保存 → 准入已取得 → provision 待确认 → pending → complete 待确认 → active`。提交前持久保存非秘密的 registration_request_id、device_id、候选 key handle 和入口标识；宿主重新验证准入，scope 不能来自 UI 自报。provision 超时用原 registration-result 查询，不生成新设备规避未知结果。

complete 前重新获取有效 challenge，签署既有规范字节；未知结果首选通过重新授权的 registration-result 中 completed_at、设备状态及预期key核实，不把 challenge 已消费当失败证明。初次登记可能尚无本人会话，不能依赖要求 AccessActor 的 key metadata；已登录后的轮换恢复才使用该接口。过期/撤销按已有协议退出并清理无用候选，不删除仍可能是远端 active 的本地密钥。

轮换：保留当前密钥并准备新密钥，从当前元数据取得既有 `expected_key_id` / `expected_key_version`，获取轮换 challenge，按当前协议用旧/新密钥双签并提交这些并发前置条件。收到成功或回读确认远端 active key 后才切换本地 active handle。若丢响应，查询 key metadata；无法判定时停在恢复状态，不自动发下一次轮换或销毁旧密钥。新版本仍由服务端根据锁定状态推进，UI 不自行指定下一版本。

当前rotate没有operation_id/receipt。恢复必须结合本人设备详情的当前active key指针、候选key元数据及本地保存的预期版本核对；单个历史key元数据不是原请求归因证明。若候选key后来被再次轮换、设备撤销或本人绑定失效，只报告当前不确定/不可用，不自动再次轮换或删除唯一可能可用的本地密钥。

解绑：确认目标绑定及影响，使用现有 expected version/operation 合同；回读原 operation，禁止用“设备列表消失”推断所有会话均已即时失效。列表分页、空/403/失效状态与管理后台一致，但只呈现本人可见字段。

### 7.4 扫码体验

复用已有 H5 inspect/approve/deny 和码渲染器，补嵌入入口和设备端的状态呈现。扫码内容不得包含密码/长期凭据；批准前显示可信设备资料、目标域和动作。扫描成功、批准成功、交付完成、会话 active 分开显示。Pending 不开放业务功能，交付丢失沿 recover/ack，用户取消沿 abort，保留过期和原操作终止语义。

实体手机/扫码枪、原生安全存储和真实网络异常的最终验证归宿主/目标平台；不以测试 signer 或浏览器模拟器替代这些证据。

## 8 A05：Enabled 嵌入体验

新增独立 `examples/tenant-host` 示例目录，保留 `no-tenant-host` 的 Disabled 行为与启动脚本。新示例复用现有 React 登录、本人角色、权限目录和 BrowserSessionCoordinator，展示 Fixed 与 Choose 两种可信入口配置，并提供两个租户同名报告 ID 的隔离样本。

业务 API 沿当前示例顺序：认证得到真实 tenant/subject → 对目标 business/资源ID调用业务权限检查，拒绝时统一403 → 按 `(tenant_id, report_id)` 查资源 → 返回数据或已获授权后的404。不得通过未授权时不同的403/404泄漏对象存在性。资源归属检查仍归宿主，不能仅用全局 report_id 查找。报告列表授权过滤属于示例宿主：在受限批量中检查候选资源并继续扫描，返回绑定过滤条件和作用域的不透明游标；不得先暴露全部报告再让前端过滤，不宣称拥有全库授权 SQL 编译器或精确总数。达到扫描预算可返回空页及继续游标，不把空页当列表结束。

同一账号只有分别具有A/B的active成员资格才可选择对应租户；共享凭据不赋予另一租户资格。停用/移除后新请求重新检查当前身份与授权，已通过检查的在途请求不承诺与独立业务数据库读取原子线性化。若真实宿主要求更强一致性，需要宿主自有事务或版本屏障，不能由此示例推导。

切租户前确认草稿，切换后更新认证 revision、清理业务查询缓存和权限目录状态，丢弃旧请求结果；同一 Cookie 入口多标签遵循既有协调限制，不承诺每个标签独立租户。管理组件仍使用独立管理会话，普通业务 token 不能调用管理 API。

示例初始化只操作有明确标记的隔离数据；真实宿主不执行示例 seed。嵌入包先保持本地消费，不把 npm 发布当作开发完成条件。公开 exports 增量、CSS 命名空间、宿主 React 版本与无 UI 用法须记录；真实第三方消费者组合验收另列。

A05基础交付为Enabled登录/选择/业务资源与独立管理组件示例；设备和扫码接入是依赖A04及A02B对应子批的可选扩展，不作为基础示例的隐含退出条件。

## 9 S01：密码与匿名入口防滥用

推荐分两层实施，不把 IP 策略写进 Core：宿主边界执行来源/client/入口/全局预算及并发 KDF 限制；Core 对恢复/MFA/邀请等单次凭据执行原子尝试次数和失效规则。密码登录如增加账号尝试状态，使用独立的 account admission 合同，不能用攻击者输入永久禁用账号。

宿主注入可信来源分类，只信任明确允许的代理链；来源或规范化账号用带服务端密钥的摘要作限流键，避免日志泄漏邮箱。默认拒绝策略按操作配置：敏感写、匿名挑战和高风险登录在预算存储不可用时返回安全的暂不可用；已有健康会话读取不因可选限流存储失败全部失效。

建议初始参考策略：来源+入口短窗、账号+入口中窗、全局 KDF 并发上限；具体阈值是部署方配置，不在库内硬编码。无账号和错密码保持一致外显，采用有界 dummy KDF 减少明显时序差异；先全局限流再做高成本密码验证。Retry-After 粗粒度且不暴露账号是否存在。渐进延迟不持数据库事务或工作线程睡眠。

进程内参考adapter选用governor（OSS-04），只包裹本项目必要的准入映射、预算键容量/过期清理与失败投影，不重写其限流算法；KDF并发用现有运行时的有界许可机制。另定义可注入共享store合同，多副本使用方须选共享原子实现并独立验证，不能把多个本地桶相加称为全局预算。无需默认引入Redis或tower_governor。新密码策略只作用于新设/改密，现有哈希按验证成功后受控升级；不在本次悄悄改变历史密码规则。

governor使用单调时钟和其清理接口；硬容量另设，不能淘汰仍有效的桶让攻击者获得新预算。现有同步Core/存储调用由HTTP边界通过`spawn_blocking`执行，取消等待不停止已运行任务；KDF/阻塞任务许可须持有到实际工作结束，不能随请求future丢弃提前归还。S02/S03/X01开放匿名或凭据验证入口前均先接入对应S01预算。

## 10 S02：MFA 与敏感操作 step-up

### 10.1 因子与范围

S02先完成WebAuthn/passkey及单次恢复码的安全闭环，优先覆盖管理身份和高权限动作；TOTP改为后续兼容子批，不再作为WebAuthn的实施前提。借鉴[Kanidm的凭据优先级](https://kanidm.github.io/kanidm/stable/accounts/authentication_and_credentials.html)，使用webauthn-rs（OSS-01）；TOTP采用totp-rs（OSS-02）。普通账号是否强制、何时切换仍由采用方冻结，候选S02不自动成为A01–A05交付前置。

首批保留现有密码身份流程，WebAuthn作为密码后的优先认证方法和step-up证明；不在本次悄悄引入无密码账号、discoverable credential或用户名枚举流程。独立的passwordless登录须另行冻结账号发现、首次登记、跨端支持与恢复合同。管理/高权限WebAuthn策略要求user verification（UV），服务端核实实际结果，不把“存在公钥签名”自动等同完成多因子认证。TOTP及恢复码不抗钓鱼，不能满足要求抗钓鱼的登录/敏感动作；使用恢复码只能进入策略明确允许的较低保证流程，否则进入受限恢复/人工流程，不自动下发原高保证会话。依据[NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/)。

因子属于全局账号；认证结果必须同时满足账号最低保护、受信入口/目标域及管理动作的要求，弱入口不能降低其他来源的要求。策略表达为允许的方法集合、必要保证和新鲜度，同一认证结果可满足多个要求；不是把所有已登记因子机械累加验证。普通账号选择开启MFA意味着启用账号最低保护，不是只登记一个从不要求使用的因子。租户管理员不能替全局共享账号移除因子或降低最低保护。管理员强制MFA、恢复码数量和策略生效时间仍待采用方冻结；启用策略不在启动时自动修改账号。原来没有MFA合同的入口在账号开启后必须升级或拒绝登录，兼容不等于继续放行。

全局归属不代表WebAuthn凭据可跨RP使用：入口映射到受信RP/origin集合，只接受对应RP凭据。开启账号最低保护前盘点各入口可用凭据和受限重新登记路径；不兼容入口拒绝或引导到预先批准的登记流程，不能扩大origin集合、伪造跨RP保证或隐式新增SSO桥接。

### 10.2 记录与状态机

拟新增：`AccountFactor(id, account_id, kind, state, material_ref, version)`及按kind区分的材料：TOTP密文/key id/last_accepted_counter；WebAuthn的RP ID、credential ID、公钥、库要求的凭据状态及备份/计数信息。禁止把两类counter当作同一规则。另有`AccountSecurityState(account_id, credential_version, factor_version, minimum_policy_version)`；`AuthenticationChallenge(id, digest, account_id, client_id, login_entry, purpose, target_tenant?, source_tenant/session?, credential_version, factor_version, policy_version, expires_at, attempts, state, protocol_state_ref)`；`SessionAssurance(tenant_id, session_id, methods, authenticated_at, factor_verified_at, policy_version)`，其中methods包含实际UV/抗钓鱼等已验证事实；恢复码摘要集合。会话表真实主键为`(tenant_id,id)`，assurance按复合键关联原session，并在事务内核对account/client/purpose，不假定session_id全局唯一。

凭据/因子/策略变化在同一安全事务推进相应version，旧challenge/grant在消费前重新比对；这些版本是待新增合同，不是现有字段。新增状态必须被所有相关密码/账号/因子修改路径维护，不能仅新自助接口更新。挑战记录有显式状态与到期清理，不把多种用途合成无边界的万能票据。

另保存稳定的`WebAuthnUserHandle(account_id, rp_id, opaque_uuid)`映射及唯一约束。[库的注册接口要求UUID](https://github.com/kanidm/webauthn-rs/blob/master/webauthn-rs/src/lib.rs)，而现有`IdGenerator::next_id`允许任意字符串；不能因默认生成器使用UUID就强制解析所有历史account_id。每账号/RP生成一次不含邮箱等资料的不透明handle，并发登记复用同一映射，不按租户或每次ceremony重新生成。

TOTP secret需要可解密使用，不能只哈希；用宿主注入的密钥封装adapter加密，key id单列；数据库备份不包含解密主密钥。WebAuthn凭据与ceremony状态由OSS-01处理，Core仅通过受信adapter取得类型化验证结果。库的注册/认证状态必须保存在服务端，绑定challenge/账号/入口/用途/版本并有期限；浏览器只持不透明flow引用和公开options，不能把库状态放入客户端Cookie，即使Cookie经过签名或加密。明确关闭默认features，只为此服务端持久化启用`danger-allow-state-serialisation`；在G0固定格式版本、读取大小和升级兼容，不启用其他danger/preview扩展。参见[webauthn-rs状态安全说明](https://docs.rs/webauthn-rs/latest/webauthn_rs/)。

因子状态`pending → active → revoked`：建立pending必须近期重认证或持有明确授权的受限enrollment流程，已有因子时新增/删除须满足当前step-up，因子全丢失仅走下述专用恢复。WebAuthn完成注册验证、可信RP/origin和同RP credential ID唯一性检查后，首批再用该凭据完成一次新challenge的认证、核实策略要求的实际UV，才激活/推进enrollment；不把注册结果或attestation直接当作登录/step-up完成证明。TOTP须确认首个OTP，使用所选库显式时间验证返回的匹配step，与last_accepted_counter比较并原子推进；不能将当前时钟step代替实际匹配step。WebAuthn计数/备份信息按库的验证结果及凭据版本更新，不要求所有同步passkey计数严格递增。协议验证可在短事务外计算，但最终须原子重检身份/凭据版本、消费challenge并保存凭据更新或session/grant；版本变化时拒绝或重新发起，不复用过时结果覆盖并发更新。失败尝试增加计数、达到阈值锁定challenge属于必须提交的拒绝结果，不能因返回认证错误回滚。恢复码只在生成成功时展示一次，服务端保存摘要；重新生成使旧集合失效。

恢复码首批只替代第二因子，仍须先完成当前密码验证，不能单独重置密码、取得管理会话或变成长期免MFA凭据。消耗恢复码的登录记录降级方法并触发安全通知；删除因子/重置恢复码仍须专用敏感操作流程。密码和所有因子都丢失时走预定义人工/离线恢复。首次强制MFA但尚未登记的账号只获得用途为enrollment的受限流程，完成登记与确认前不得发正式session；启用策略前须准备有可用因子的管理员或可审计的受限引导，避免全员锁出。S02a的未完成后续保护阶段只能在隔离测试中验证，不能提前对真实账号开放因子删除。

S02c自身交付最低因子丢失恢复及可执行的受控离线恢复机制/操作说明，不等待S03完整安全中心或邮箱改密。抗钓鱼管理策略下，密码加恢复码不能自行删除最后WebAuthn或直接授予管理会话；必须经预先冻结的独立恢复授权，限定账号/操作/期限，审计并退役旧会话和待授权产物，仅签发受限重新登记能力。完成新凭据认证后仍重新登录并检查当前资格。已有有效强因子时优先走正常step-up；本设计不增加匿名紧急口令或重复bootstrap后门。该最小机制、引导、通知和旧入口防绕过齐备前，不开放S02a–c真实账号；S03复用并扩展其界面与邮件密码恢复，避免循环依赖。

### 10.3 登录与租户选择

不直接给现有 `TenantLoginOutcome` 增加未兼容分支。拟增加可选的新认证流程服务/路由（如 `/auth/flows`、`/admin/auth/flows`），已有登录合同保留；策略要求 MFA 时旧登录入口返回明确“不支持此流程/需升级客户端”，不能发出绕过 MFA 的完整 session。

状态为 `password_verified → factor_required / tenant_required → ready → consumed`。Fixed 在已知目标域下验证资格；Choose 只在完成账号所需因子后列出可选域，选择时再次检查该域策略，若需要更强因子回到受限 challenge。所有条件满足后一次事务消费 flow、重检当前身份资格并创建正式 session/refresh；中间票据不能访问业务或管理 API。

跨入口、跨 purpose、跨账号的 challenge 不可复用；策略升级、账号禁用、源会话撤销后 challenge 失效。Browser flow token 使用短期 HttpOnly Cookie 或内存保管的受限票据，禁止持久浏览器存储；所有写操作保留同源/CSRF 保护。

强制策略检查落在Core最终创建/使用会话的边界，不仅在新HTTP路由。逐一覆盖旧密码登录、browser、租户选择、refresh、OIDC code/token、设备登录及扫码Pending激活；设备proof不是通用MFA完成证据。入口强制策略升级时，不合格已有会话由显式变更操作退役，不能靠refresh获得新的assurance。纯Core宿主必须注入同一策略或显式保持未启用状态，不能让开启MFA的部署通过另一router绕过。

账号主动启用/提高最低MFA保护适用相同切换规则：用户明确确认，因子确认、账号policy版本推进、全部域/purpose不合格session及refresh/待授权产物退役在全局安全事务中完成；当前会话不满足新要求时也退出并进入新的认证flow，不能仅改UI状态或自动标记旧session已完成MFA。在线Core/session验证在后续请求读取当前policy与assurance。仅离线验JWT的宿主看不到即时撤销：接入合同必须选择在线当前状态检查、同步可验证的失效屏障，或明确接受已签发token剩余TTL及缓存上界；未配置该边界的入口不能宣称MFA已即时保护所有请求。要求立即生效且无法确认下游失效的入口保持关闭；选择延迟生效的消费者必须在状态展示和交付报告中列明最大残余窗口。

### 10.4 step-up

拟增加 challenge/verify 接口，产出短期、单用途的 `SensitiveActionGrant`。绑定 session、account、purpose、目标 tenant/business、操作类型、规范化参数摘要、资源版本及有效期。首批用于因子删除、恢复码重置、管理账号改密和高影响授权；不能把它实现成长期万能“已验证”开关。

执行原操作时在同一事务校验并消费grant、重检权限和适用的expected version，随后写入变更/审计。为相关admin/security事务新增可选grant校验原语，不允许先开认证事务消费grant再调用另一个独立管理事务。拟新增grant必须持久化摘要、状态、actor的tenant/session与目标范围、credential/factor/policy版本及operation_id；对含密码等秘密参数的绑定使用宿主密钥支持的用途隔离MAC或等价受保护承诺值，不能保存原始秘密或可离线猜测的普通密码摘要，canonical编码版本固定。

当前管理改密等多数写接口没有通用operation receipt或资源version。S02c必须为选中的操作明确新增版本化DTO/结果查询合同：以当前actor+目标+operation_id+参数承诺去重，同ID不同语义冲突；只有原actor在当前仍具权限时可读取secret-free结果。状态变更、grant消费和结果记录同事务，回滚保留未消费状态，COMMIT-unknown回读原operation。没有receipt的旧接口保持保守未知结果处理，不能把当前状态或审计列表匹配当原请求证明；强制策略启用后旧无grant写法必须拒绝，而不是留下旁路。参数变化需重新挑战，不能消费新grant自动重试。近期认证只提供判断材料，不替代当前授权。

WebAuthn在S02a即固定RP ID/可信origin集合、UV要求、credential ID唯一范围、challenge单次性及库凭据状态的存储版本；RP与origin由宿主配置，不从Host/请求参数推断可信值。RP变更涉及凭据可用性，须给出重新登记路径，不能静默迁移。同步/备份passkey不等同物理设备唯一身份；硬件绑定/attestation策略仅在消费者明确需要时单列。S02c使用相同验证adapter，但challenge必须绑定具体操作和原session，不能复用登录响应签发任意grant。

## 11 S03：自助安全中心与恢复

安全中心首批包括本人会话及撤销、近期认证、因子管理、恢复码、改密、受限设备入口。跨租户会话展示需要新增本人专用合同和脱敏投影，不能把平台管理查询开放给业务用户；不披露无权查看的租户资料。撤销当前会话后立即清理浏览器状态。

本人改密需当前密码重验证，并满足账号/入口的因子和敏感动作策略；不能仅凭一个已登录业务会话调用管理员改密能力。跨域会话查询按全局账号本人身份授权，但仍过滤可披露租户元数据；撤销使用精确tenant/session绑定，不能只传可能跨域重名的session_id。

拟新增 `/auth/recovery/start` 和 `/auth/recovery/complete`：start对存在/不存在账号返回相同202文案，校验发送预算，按支持矩阵生成短期恢复证明；高熵link票据存摘要，短code按下述密钥摘要和预算处理。发送通过用途明确的邮件合同和outbox。推荐邮件链接将秘密放fragment，由第一方页面读入内存并立即移除；页面不加载第三方资源，设置no-store和Referrer-Policy: no-referrer，屏蔽访问/分析/错误日志中的秘密。GET/HEAD只渲染，不消费票据；只有用户明确提交新密码的POST才验证和消费，防止邮件安全扫描器预取改变状态。

start的统一响应也覆盖flow_id、字段形状及后续匿名状态：不存在账号返回不可区分的不透明引用，不返回null/不同状态暴露存在性。账号/来源尝试总预算独立于单flow，重新start或重发不能清零；code密钥摘要保存key id，轮换只接受显式有限重叠期，无法继续验证时撤销并重新发起，不遍历全部历史密钥。

桌面/原生消费者优先支持在原发起界面输入一次性邮件验证码，借鉴[Ory恢复流程](https://www.ory.com/docs/kratos/self-service/flows/account-recovery-password-reset)。S03实施前选择并记录code、link或两者支持矩阵；Web的fragment链接可保留，不为跟随参考项目删除已有预取保护。code绑定服务端恢复flow和用途，使用密码学随机源，按较低熵设置严格的flow/账号/来源尝试上限、短TTL和重发预算，保存带服务端密钥的摘要以降低离线枚举风险；不得套用高熵URL票据的默认预算。重发新凭据时使旧代次失效，投递重试只重发同代有效内容。若同flow提供code与link，两者消费同一恢复记录，任何一种成功都使另一种失效；GET、仅验证code或切换客户端均不得直接产生正式session。该验证码与S02的离线因子恢复码是不同凭据，不恢复或绕过WebAuthn保证。

摘要型恢复表不保存原始票据；为了可重试发信，邮件outbox如必须保存包含链接或验证码的内容，只保存独立投递密钥加密的短期payload，worker边界解密，成功/过期后清除密文。该秘密payload不进入通用审计/webhook，管理员不能回读；投递密钥由宿主供应并与数据库备份分离。邀请邮件采用相同边界，不能将恢复秘密写入明文事件表。

恢复记录包含不透明flow_id、account_id、generation、允许的方法及各自摘要（link摘要、code密钥摘要及key id，按需存在）、credential_version、purpose、可信恢复入口标识、expires_at、尝试/重发计数、consumed_at/revoked_at。code提交须带同一服务端flow引用，不能只按邮箱在所有未过期验证码中搜索；跨客户端仅转移明确的flow引用，不改变账号、入口及用途。该流程恢复全局账号密码，不授予租户资格；入口仅限定可信恢复服务和返回地址，不能由调用者任意指定管理purpose或目标账号。完成复用§3.2全局安全事务屏障，按序锁定相关身份后验证证明、当前状态/凭据版本和密码策略，原子更新密码、推进credential_version、消费/撤销同代恢复证明、撤销全部用途/租户的相关会话及待授权产物，并写审计/安全通知事件。不能先锁账号再按遍历结果倒取租户锁。设备公钥身份不自动删除；人员绑定会话按现有账号安全退役规则处理。普通密码重置保留有效因子及尚未消费的因子恢复码，不把账号永久锁死；被盗因子/恢复码的撤销属于明确的独立安全处置。

邮箱控制权不自动绕过已配置MFA。普通忘记密码只重置密码，登录仍需现有因子；因子丢失按§10.2的保证要求使用恢复码或独立恢复流程。租户管理员不能恢复全局管理员凭据。管理员完全失联的受控离线机制由S02c先交付，S03复用其账号/操作绑定、独立审计及强制退役规则，不重新建立可绕过强因子的邮件恢复通道；真实应急演练另属运行验收。

账号禁用/closed、入口暂停、邮件失败、票据过期、并发完成、邮箱变更和COMMIT-unknown都有独立内部结果，对匿名调用保持统一无效投影，不暴露账号状态。单个租户失效不应决定全局账号能否重置密码，完成后各租户准入仍重新校验。成功不自动登录、不回传token；再次使用返回统一无效状态，UI引导重新登录，不能声称第二次失败表示第一次未提交。

## 12 X 系列：按消费者选择的身份增强

### 12.1 X01 邀请与加入

硬前置为S01对应入口预算和O01a可靠邮件/安全事件；不因邀请是可选能力就跳过匿名接受、受限注册和发送预算。

拟新增 Invitation：id、tenant_id、目标邮箱规范化值/安全查询摘要、inviter、拟授角色及 business_id、expires_at、state、version、token_digest、accepted_account_id。状态 `draft/approval_pending → pending → accepted`，旁路终态 revoked/expired。首批直接邀请可不启用审批；启用审批时审批人必须具有该域授权且与申请人分离，审批通过不代替接受时重检。

管理入口拟为 `/admin/invitations` 创建/列表/撤销，用户入口 `/auth/invitations/accept`。管理邀请记录权限限定目标域；租户安全管理员只能授予自己可授且非平台级角色。接受需要匹配已验证身份：既有账号登录并验证目标邮箱；新账号通过专用受限注册完成验证，同时创建初始成员。不能按同邮箱无认证认领已有账号。

接受前读取邀请仅作定位，事务按§3.2先state、排序tenant、排序account（邀请人、接受者及必要审批人）再锁邀请/角色等对象，重查快照、当前邀请人授予资格和拟授角色作用域；邀请人的原登录session到期不等于失去邀请资格，应检查当前身份及权限。再原子消费邀请、建立允许的成员/绑定、审计/outbox；已removed或suspended成员不默认复活，需显式管理员重新准入。首批不邀请授予受保护管理角色，普通业务角色授权也须按业务域限制。重复点击由已验证接受者读取邀请中的accepted_account_id及安全结果，当前身份/权限仍需核实，不能把持有链接作为永久查询凭据。

租户关闭公开注册不自动禁止管理员显式邀请：专用受限注册只对该有效邀请开放，不能调用无约束公开注册绕过准入。账号仍必须在创建事务获得初始成员；两份邀请并发认领相同邮箱由全局账号唯一约束裁决，落败方转“登录既有账号后接受”，绝不覆盖密码或自动认领。邮箱比较沿当前账号存储的规范，不另加宽松大小写/别名合并；若要改变规范，先有全局迁移合同。

共享账号不因一份邀请进入其他租户。已加入后撤销邀请不等于撤销成员；UI 必须区分两种动作。邮件只含必要目标与一次性链接，无角色密钥或密码。

### 12.2 X02 外部身份与目录

OIDC broker 首批：宿主配置 Provider(id, issuer, client_ref, allowed_algorithms, endpoints/discovery policy, claims mapping, enabled)；Core 保存 ExternalIdentityLink(provider_id, issuer, subject, account_id, version)，唯一键包含 provider/issuer/sub，不以邮箱作身份主键。

拟新增 `/auth/federation/{provider}/start` 与 callback。start 保存绑定浏览器/入口/return destination 的 state、nonce、PKCE 和过期时间；callback 通过注入网络 adapter 换码并验证签名/issuer/audience/nonce/time/算法，再把已验证身份交给 Core。discover/JWKS 只访问配置允许目标，限制重定向、响应大小、超时及私网访问，防 SSRF；未知 kid 仅受限刷新缓存，失败不接受未验证 token。

该adapter位于拟新增的可选`embedded-idp-federation`，选用openidconnect-rs（OSS-03）的RP客户端；关闭默认features后按所选release明确启用必要HTTP/Rustls能力，宿主注入受控客户端，不让默认网络行为绕过限制。采用库的ID Token verifier及[显式时间函数](https://github.com/ramosbugs/openidconnect-rs/blob/main/src/verification/mod.rs)接入Clock，不自写JWT解析/验证链。库目前不验证azp：仅在库完整验证成功后检查已验证claims；若azp出现，必须等于配置client_id；多audience必须含azp，且全部audience在provider允许集合中，集合未配置则拒绝；单一audience不强制azp出现，仍须匹配本client。该多audience允许集合策略是本项目合同，不宣称上游默认具备。JWE/P-521等库未支持能力保持关闭，算法集合在G0固定。Core只接收已验证的最小身份投影，provider CRUD和本项目现有OIDC Provider继续独立；oauth2-rs作为所选OIDC客户端栈依赖，不另加第二套换码或PKCE实现。

Core仍采用同步的prepare/claim与complete领域操作；宿主编排器在两者之间await网络adapter，不在Core方法或持锁事务中等待网络。X02a自己交付出站目标限制、超时/响应上限及有界并发，不等待O02后续运行控制面。回调获得上游身份后，只能作为新认证flow的已验证首要身份来源，继续执行本地账号最低保护、入口/目标域MFA和当前准入；未满足前不签正式session。上游acr/amr不默认满足本地WebAuthn策略，未来映射需独立信任合同；外部身份不能成为本地MFA旁路。

§10.3的`password_verified`是S02首批的本地密码状态；X02a接线时将首要身份状态显式扩展为区分本地密码/受信外部身份的类型化结果，保存来源、link/provider版本及验证时间，随后复用因子/租户/消费步骤。不能将外部验证伪标为密码已验证，也不隐式要求所有外部登录再次输入本地密码；敏感操作和恢复的专用证明要求继续独立检查。

state还绑定provider及发起的login或link意图；link绑定当前actor/session和已完成的step-up，callback不得根据同邮箱或当前页面账号临时改成link。通过原子claim/consume确保一次回调至多产生一次链接或登录结果，外部换码不持数据库锁；换码结果未知时结束原流程并重新发起，不盲目重放已消费code。return destination只取本地允许集合，callback和provider配置有版本绑定；provider禁用或配置变化时在最终提交前复查。对授权服务器混淆、多个audience/azp等验证规则由provider adapter合同和测试固定。

首批关闭自动同邮箱合并和开放 JIT：已关联身份可登录；未关联先登录本地账号并经 step-up 建立链接，或走显式邀请的新账号流程。上游 email_verified 不能单独认领已有账号。链接/解绑写审计；不能解绑最后一个可用登录方式。上游成功不自动创建租户成员或管理角色，本地禁用立即约束新认证。

上游 logout、下游会话撤销和跨产品 SSO 是不同能力：初版仅承诺已验证外部登录；单点退出/back-channel logout 需单独合同和回放保护，不以 broker 登录完成宣称全部 SSO。

LDAP与SCIM分开实施：LDAP connector在边界验证/读取目录身份，禁止把目录密码持久化到本库；首批LDAP不反向写目录。SCIM则是明确会修改本地成员投影的入站provisioning协议，不能称为只读；由受限机器身份在专用audience和租户provisioning grant下调用，不开放全部人员/管理API。Users映射externalId、ETag、过滤/分页、幂等与停用，Groups如纳入则依赖X04；不要求先实现OIDC broker才能启用SCIM。

目录绑定基于稳定externalId和受信连接，不按邮箱自动认领共享账号；新增外部账号的本地凭据策略必须在切片内明确，不能把当前必需密码哈希设空绕过校验。停用一个目录成员只影响该域，不直接禁用跨租户全局账号。属性权威方、冲突优先级和本地手改是否允许须冻结；首批不做双向同步或通用账号合并。

### 12.3 X03 机器身份

新增 ServicePrincipal(id, tenant_id, name, status, version) 与 Credential(id, principal_id, digest/public_key_ref, expires_at, revoked_at)；client 继续是协议调用方，显式关联机器主体，不能把 client_id 当人员 account_id。首批一个机器主体属于一个业务租户，Disabled 属于0；不授予平台管理角色。

新增独立机器授权绑定到同域 business/role/scope。复用权限定义与资源范围判定，明确区分 human/machine actor，避免给所有现有人类绑定加可伪造的字符串前缀。公共 Actor 模型调整需版本化；旧授权入口只接受人员，新的机器检查通过独立明确服务进入。

按需启用 `client_credentials` grant：校验 client、凭据、principal、tenant 与允许 audience/scope 后签短期机器 access token，包含不可混淆的主体类型；不发 ID token、人员 session 或 refresh token。人类接口默认拒绝机器主体；调用业务资源仍验证资源归属和当前权限。凭据轮换为创建新凭据→短期重叠→撤销旧凭据，明文只展示一次，过期/撤销不可恢复。

现有OIDC只允许public_desktop/confidential_web且要求redirect_uri。不得为纯机器client伪造回调或借人员client_secret当全部机器凭据；X03需选定版本化机器client注册/认证adapter与Credential的一对多关系，独立于人类授权码client的字段约束。secret验证必须定位有效credential_id或受限候选集合，不遍历任意历史密钥；保留旧client API/schema语义，新增类型则给显式迁移和旧宿主兼容门槛。只有显式新增的SCIM等专用服务才能接受受限机器actor，不能因此放开现有人员管理路由。

实际 token endpoint 与 discovery 只在实现该 grant 后声明。密钥丢失不通过普通用户改密恢复；本地 token 验证与在线主体停用检查的失效延迟须明确，不能承诺离线 JWT 立即吊销。

### 12.4 X04 组、组织与委派

首批平面租户组：Group(tenant_id,id,name,status,version)、GroupMember(tenant_id,group_id,subject_id)、GroupRoleBinding(tenant_id,group_id,business_id,role_id,scope)。关系使用同域复合外键关联组、成员和业务角色，不能假定裸group_id/role_id全局唯一。用户账号和目标租户成员均active、组/角色/权限有效时才继承授权；直接绑定与有效组绑定取并集，不新增隐式deny。组变更同步影响查询，若引入缓存须以租户授权版本失效，不能静默保留旧权限。

管理操作使用既有平台/租户/业务权限边界；委派定义允许的操作、业务集合、资源范围及可授角色上界，不能以“拥有某角色”推导可授予同等或更大权限。受保护系统角色、最后有效管理员保护和全局账号安全接口不参加普通组委派。

后续组织层级先定义为管理展示关系，不自动继承权限。若消费者要求层级授权，再增加无环树约束、最大深度、移动子树的原子版本及授权重算；跨租户移动禁止。删除有成员/绑定的组采用明确清理事务或归档，不能级联删除全局账号。

## 13 O01：认证事件与可靠投递

先列事件矩阵：密码/因子认证成功失败、refresh reuse、恢复、因子变化、邀请、外部链接、机器凭据、设备操作和现有管理审计。成功安全变更必须事务审计；失败尝试计数/挑战锁定/reuse撤销按§3.2作为已提交的拒绝结果与事件同事务。无领域状态变更的拒绝通过独立受限事件合同记录，限制速率，存储失败策略按事件重要性明确配置。现有管理审计依赖人员管理context，不能伪造管理员记录匿名/MFA/系统事件；O01a先提供最小安全事件及邮件outbox合同，供S02/S03/X01复用，外部webhook不作为它们的前置条件。

事件投影拟含event_id、schema_version、occurred_at、actor_type/id、tenant_id可空、purpose、operation、outcome、request_id、目标摘要，另可携带明确来源的aggregate_type/id/version。只有领域维护连续版本时才能据其检测缺口，不以时间或UUID推导顺序。跨租户账号事件不得伪造为某个业务域；租户读取只能看到授权投影。绝不记录密码、OTP、恢复票据、完整token/proof或私钥；来源信息最小化并设保留期限。

需可靠外部投递的事件与业务事务一起插入 Outbox(event_id,payload_version,payload,available_at,state)。每订阅Delivery保存固定投影的payload引用/版本、attempt、lease_owner、lease_generation、lease_until、last_error_class。worker短事务claim，事务外发送，按owner/generation/状态及租约仍有效的条件提交回执；超时/worker重启至少一次重试，旧worker不能提交过期ack，接收端按event_id去重，不承诺exactly-once。

Webhook接收端返回2xx才记ack；429/5xx/网络错误按有上限退避重试，永久4xx进入暂停/死信。邮件投递单列provider accepted、可重试/永久拒绝和结果未知，SMTP接受不等于最终送达，不套用HTTP2xx；重试可能造成重复邮件，沿相同有效票据发送，不能每次生成新凭据。重放保留原event_id、增加attempt；过期/删除的payload不伪造重建。领域事件可能乱序，有aggregate_version时按其核对，无版本时只承诺去重与重新查询当前状态，不提供全局顺序保证。订阅配置/授权在claim和发送前核查，撤销后不再启动新投递，已经在途的网络发送不能承诺收回。

当前`EmailSenderProvider::send(OutboundEmail)`是同步调用，`EmailSendError`只有message，尚不能提供上述分类。O01a先在Email定义可选的类型化投递结果/adapter合同，由lettre等provider适配accepted、确定临时/永久拒绝和结果未知；保留旧接口兼容，无可靠证据的旧错误映射为unknown，不能凭错误文本猜“未发送”。参考宿主使用有界阻塞worker并设置真实provider超时；许可持有到实际发送结束，取消等待不宣称发送已停止。邮件投递加密key provider随O01a交付，因子加密key provider随S02交付，均不等待O02的完整轮换控制面。

Webhook采用[Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md)及OSS-06，取消修订2拟定的私有签名字节格式；该私有格式尚未实施，无需新增双协议兼容。首批采用Rust库支持的HMAC-SHA256/v1，适用于明确接受共享密钥信任模型的接收方；每订阅endpoint独立生成32字节密码学随机密钥，按库/规范编码装载，不与JWT、设备或其他客户共用。外部接收方若要求仅验证、不得具备签发能力，则单列规范v1a非对称子批并另核实现，当前库选型不冒称已支持。

发送`webhook-id`、`webhook-timestamp`、`webhook-signature`，签名输入为`{id}.{timestamp}.{原始body}`，签名编码按规范使用标准Base64和`v1,`前缀，不混用base64url或自定义kid前缀。id/timestamp由服务端产生且不含分隔点；首批webhook-id使用领域event_id，去重范围为订阅内。payload固定为UTF-8 JSON，先序列化成字节，再对相同字节签名和发送，接收端验签前不得重序列化。每endpoint投影与payload版本在delivery生成时冻结，重投保持同一id和body；授权收窄后不能继续发送旧投影时终止该delivery，不就地修改重投内容。新业务变化产生新事件；改变历史事件投影的重新导出不在首批重放能力内。

正常轮换时按规范在同一`webhook-signature`字段内以空格携带新旧两份签名；接收方只使用该endpoint预配的有限可信密钥集合验证，内部key id仅用于密钥管理和审计，不成为自创wire协议。泄漏密钥立即移出可信集合，不能沿正常轮换继续接受。adapter拒绝重复id/timestamp字段和歧义的多个物理signature字段，允许单字段内规范规定的多签名，并限制字段长度/签名数量。以服务端Clock验证时间；已核查Rust实现支持传入当前时间、时间容差为固定300秒，首批沿用此窗口，不承诺任意可配。每次重投用新timestamp重新签名；库之外按订阅/事件id去重，去重保留覆盖约定的重投/人工重放期限，不能仅保存300秒。

endpoint由受信配置/受限管理员维护，网络adapter限制目标、DNS解析结果、响应大小/超时并禁跟随重定向，防SSRF；这些不由签名库提供。接收示例和测试向量覆盖原始字节、非ASCII/空白、过期/未来时间、双签轮换、错误endpoint密钥、重复字段及重投去重，并使用独立语言的官方SDK交叉验证。业务通知、恢复邮件、审计事件使用不同订阅/模板/权限；邮箱provider不是事件总线。

O01b在可选`embedded-idp-delivery`中为每把key创建库实例，分别签名后拼接规范多签字段，接收方在有界可信key集合上验证；库本身不管理轮换keyring。调用`verify_with_timestamp`前校验单一规范十进制非负时间戳和可安全运算范围，Clock转换/时间差不能溢出；不依赖HeaderMap首值读取代替重复头检查。验签及时间验证通过后，接收示例才在其业务事务中原子写入去重记录并应用业务变化，失败回滚，不能提前标记processed或让未验证id污染去重表；无法与接收方业务写原子提交时须明确其幂等键/恢复合同。出站超时/并发限制及最小key供应由O01b当期交付，不等待O02。

## 14 O02：签名轮换与运行保障软件接口

### 14.1 JWT keyring

现有 Rs256JwtService 构造支持 active + overlap 验证材料。拟新增宿主装载的版本化 `SigningKeySnapshot`，包含 active kid、可验证公钥集合、退役期限及 generation。先验证算法、kid 唯一性、active 私钥与公钥一致、issuer/audience 不变，再原子替换 signer/validator/JWKS 一致快照；失败继续旧快照并报告失败，不能进入半更新状态。

顺序为发布新公钥→确认所有验证方已取得→激活新签名→保留旧验证钥到最长相关 token 有效期、允许时钟偏差与 JWKS 缓存窗口均结束→退役。多副本装载与确认由宿主管理；参考 app 仅提供受控本地 reload/诊断接口，不开放匿名上传私钥。JWT、设备 proof、扫码结果加密分别使用各自生命周期。

紧急泄漏时允许显式立即撤旧钥，但必须报告有效 token 被拒的影响，不能沿正常重叠流程掩盖事件。回退只能选择未撤销且仍有效的 key generation，禁止恢复已经撤销的密钥。私钥引用由宿主供应，不存管理数据库明文。

### 14.2 预算、取消和健康

沿用现有 DB pool typed config；增加操作级截止时间、事务 lock/statement timeout、SMTP/外部IdP/webhook 网络预算及有界后台队列。HTTP 取消不等于数据库回滚：已经提交或提交不明的写操作返回可恢复状态，不能自动重试。同步存储的取消能力必须按驱动实际行为实现，不用 async timeout 假装底层已停止。

当前healthz表示进程存活，readyz仅调用 `PostgresAccessStore::check_readiness`；必要client引用和签名材料主要在启动时校验，并非已经实时检查所有依赖。O02目标是增加分入口的必需依赖状态与脱敏就绪聚合：模式/schema、必要引用、当前key snapshot和强制安全依赖均可用才对该入口ready。可选webhook暂停不使普通登录全停；强制MFA关键密钥不可用时相关入口fail closed。指标低基数，不把邮箱、account_id或token作为labels；记录延迟、拒绝分类、队列积压、密钥generation和清理滞后。

### 14.3 恢复与迁移机制

软件提供版本/schema/配置摘要、只读预检、迁移预演、影响清单和恢复后身份状态检查入口。备份覆盖数据库、配置版本和各密钥引用的可恢复性，具体保管和 RPO/RTO 归部署方。恢复旧数据库可能复活曾撤销的会话/票据，恢复流程必须进入隔离状态，不得仅以旧数据上的readyz为恢复完成证明。

推荐宿主维护不随该数据库备份回滚的 `recovery_generation`：恢复时生成新代际，隔离所有入口与worker。先以状态屏障标记“未完成恢复”，按有界可重启批次退役人员session/refresh、OIDC code、selection、Pending扫码交付、MFA challenge/session assurance、step-up grant及恢复/邀请票据，暂停机器凭据和旧outbox；保留审计、操作终止标记和拒绝索引。完成全部子批后才原子记录该代际ready，不能为一次巨大事务牺牲可恢复性，也不能中途开放业务。

这不是删除MFA因子。恢复出的密码、factor/恢复码、外部链接和设备active key可能也是已被替换/撤销的旧状态，必须与独立保管的变更记录/可信密钥状态核对；无法证明仍有效则保持相关登录方式/设备准入隔离，通过受控重新验证或重新登记恢复，不能用重置会话掩盖旧认证材料复活。角色/成员也需恢复后授权核对。每个实例及离线token验证方确认受信代际、数据库完成代际和旧token失效措施一致后才开放；旧实例/缓存必须移出服务。代际只存同一可回滚数据库不能作为外部权威。旧outbox不可自动重放过时恢复邮件。

本设计不执行备份、还原或故障演练；这些是之后完整运行验收的独立工作。M1-03 的准备命令不能兼作管理员应急恢复或数据库修复。

## 15 U01：可选后台增强

| 增强 | 建议合同与实现边界 | 退出条件 |
| --- | --- | --- |
| client CAS | 增加持久版本及新条件更新接口；旧upsert在升级后的实现中仍可更新，但必须推进同一版本；新UI发送expected_version，冲突回读确认；部署中不能残留不推进版本的旧写入程序 | 过期CAS写入被拒绝；旧无条件upsert仍可能在之后覆盖成功写入，不宣称所有写入均受CAS保护；Secret仅显示状态 |
| 受权导出 | 同列表权限与过滤条件，冻结发起者/目标域；有界分页任务，下载时重检权限，短期单用途地址；CSV 转义及公式注入处理 | 无越域/敏感字段，取消/过期/权限撤销处理明确；不宣称全局一致快照 |
| 统计总览 | 按目标域/时间窗定义只读聚合与“截至时间”，不从一页列表推算总数；无明确业务指标先不新增 | 聚合权限、数据新鲜度与空状态有合同 |
| 配置快照 | 先只读显示脱敏有效配置、generation 和来源；不导出 SecretRef 实际值；在线发布另走 draft/validate/activate 和宿主协调 | 没有未实现的“立即生效”按钮；发布失败保留旧完整快照 |

这些增强不绑定一个大版本一起交付。CAS 的兼容模型如无法通过统一版本推进保证，应选择版本化接口/迁移，不能在 UI 上加一个无服务端约束的版本字段。

## 16 决策、风险与下一步

| 决策 | 本文建议 | 何时必须冻结 |
| --- | --- | --- |
| 首批产品范围 | A01–A05；S01 安全接入优先，S02/S03 作为安全增量；X/O/U 按消费者选择 | 对应实施切片启动前，不阻碍本轮文档 |
| 因子与管理策略 | WebAuthn优先、管理/高权限要求UV；TOTP后续兼容；不自动强制所有账号或引入passwordless | S02 公共合同/迁移前 |
| 开源组件与版本 | §2.1确定六项首选，G0锁定已发布版本/features并核查许可/MSRV/接口；优先依赖、不整库复制 | 各组件首次引入前，不要求一次引入全部候选依赖 |
| Webhook协议 | Standard Webhooks HMAC v1；内部key id、规范多签轮换；非对称模式另列能力 | O01b首个消费者和G0核查时 |
| 恢复交互 | 原生端优先邮件code，Web可保留fragment链接；同flow原子失效，不绕过MFA | S03接口与UI开发前 |
| 设备端首批平台 | 先宿主 signer 协议与演示，不假定浏览器/原生平台 | 原生 adapter 开发前 |
| OIDC 新配置 | 单 issuer、client 唯一分派；协议扩展配置 v2 | M1-04B 开发前 |
| 外部系统/目录/机器消费者 | 未指定，按本文模型准备，保持关闭 | X02/X03 实施前 |
| 邮件/事件保留与密钥供应 | 注入合同，实际 provider/期限由宿主确定 | 开启对应能力前 |
| 完整验收及部署 | 单列，不作为本轮执行内容 | 后续单独安排 |

主要风险是配置多入口引入会话串用、MFA 绕过旧入口、恢复削弱管理身份、共享账号误授租户权限、外部身份同邮箱误合并，以及回退恢复已经退役的凭据。各风险在所属章节落实到服务端重检和事务条件；不能仅靠前端按钮或文案控制。

详细顺序、文件归属、开发检查与完成标准见[实施方案](product-capability-completion-plan.md)。本轮仅静态核对与文档检查，不声称以上候选服务、数据表、接口或迁移已存在。

### 16.1 修订1文档复审记录

对照源码及两个独立只读核对结果，已修正refresh/logout既有能力与待补组合的表述、轮换expected key/version、首次登记恢复的认证前提及示例资源查询的存在性保护。安全复审补充恢复链接预取/秘密投递、Webhook签名格式/kid、恢复代际、MFA失败计数提交和Core全入口策略检查。上述为文档修正，不是本轮产品修复或测试通过记录。

两个新文档及README入口的本地链接、代码围栏和空白检查通过；仅检查本任务文件，其他任务正在产生的N2证据保持原样。没有执行产品测试、迁移、服务启动或部署。

### 16.2 修订2全文审查与修正

2026-10-25按用户要求再次阅读全文，并对照当前`d721481`产品源码、M1-01/02合同、设备生命周期/扫码锁序及原C04–C13能力矩阵核对。主审负责跨章节合同与实施闭环；三个只读专项分别核对装配/接口、设备/宿主与计划、安全/身份/运行软件。发现的问题直接修正于本文和配套方案，没有据审查启动实施。

| 项目 | 原问题 | 修订2处置 |
| --- | --- | --- |
| R01 基线与兼容 | 初稿基线滞后；入口TTL要求可能被套到旧参考行为 | 复核当前HEAD且确认产品源码未变；新多入口与LegacyReference期限分开 |
| R02 显式准备 | 系统审计、锁序、P4空业务配置和P5局部退出不够明确 | 固定client_id来源、独立最小准备审计、P3/P4/P5顺序与迁移边界 |
| R03 认证与OIDC | Cookie/Bearer描述过宽；提及不存在的client停用；共享端点缺浏览器调用边界 | 分开refresh Cookie与资源Bearer；明确无停用API、无隐式SSO及固定proof外部路径 |
| R04 接口合同 | 非典型路由未点明；全集schema与既定M1-05退出混淆 | 纳入探针/静态族/discovery；全schema补齐单列扩展 |
| R05 设备接线 | signer/UI计划未落实admission与challenge真实前提；本人/管理回执易混 | 列服务与权限映射、认证transport，夹具/真实API/平台adapter分层退出 |
| R06 设备恢复 | 元数据回读可能被误当轮换请求回执 | 明确rotate无receipt，组合当前key指针/元数据/本地版本，只核对当前状态 |
| R07 嵌入范围 | A05基础与可选设备混用；“实时拒绝”超出跨库能力 | 明确独立成员资格、后续请求重检、在途边界与可选扩展 |
| R08 事务与身份键 | 恢复/邀请锁序有歧义；assurance缺tenant键 | 固定state/tenant/account顺序及全局安全屏障；复合会话键与版本重检 |
| R09 MFA生效 | 首次enrollment、账号最低策略、已有会话与离线JWT未闭合 | 受限引导、有效要求合并、原子退役、下游即时/延迟生效边界 |
| R10 step-up | 假定已有通用receipt/version；秘密参数摘要可能不安全 | 选定操作新增版本化grant/receipt合同、秘密参数MAC、旧写法不能绕过 |
| R11 自助恢复 | 改密验证、全局与租户关系、因子恢复码保留说法不足 | 当前密码/因子要求、全局版本退役、匿名一致投影；普通改密保留有效因子恢复码 |
| R12 邀请 | 关闭注册、并发同邮箱、管理角色授予及重复接受语义不明确 | 受限邀请注册、唯一约束后重新登录、禁隐式认领/管理升权、已验证接受者回读 |
| R13 联邦与目录 | callback意图/单次性不足；SCIM与只读LDAP混淆、依赖错误 | 绑定provider/login-link意图、未知换码重启；SCIM写入及机器grant/Groups依赖分开 |
| R14 机器与组 | 机器client与现有redirect模型不兼容；组关系缺域键 | 明确机器注册/认证版本合同，不造假回调；组/角色复合外键与有效状态 |
| R15 事件与计划 | S02缺事件前置；失败状态可能回滚；SMTP/HTTP/版本顺序混用 | O01a最小前置、提交型拒绝事件、加密邮件例外、不同投递结果及可选aggregate_version |
| R16 运行与可选增强 | readyz现状过度概括；恢复范围不明/大事务；CAS保护过度承诺 | 当前与目标探针分开，代际屏障+有界清理+旧凭据核对，明确旧无条件写仍可覆盖 |

上述修正逐项回写实施顺序、数据影响、开发负例和退出条件，并完成专项回读。能力矩阵未漏掉C04–C13；M1-06/完整N2仍排除，原生平台、外部消费者、因子政策及运行参数仍按§16待冻结，不将这些产品选择冒称已批准。

本轮只更新这两份Markdown，README及原有无关修改保持原样。检查包括本地链接、围栏/表格结构、空白、修订前后差异和文档间关键约束一致性；没有运行产品测试、改变代码/依赖/schema/CI、提交、推送或部署。文档审查完成不证明候选设计已具备运行正确性或生产验收证据。

### 16.3 修订3社区方案与开源复用决策

按本次用户要求，将社区对照结论落实到设计和配套实施方案，优先复用成熟协议构件。当前定位为现代、审慎的嵌入式身份设计，不据资料对照宣称社区领先、协议认证完成或安全审计通过。

| 决策 | 正文调整 | 实施影响 |
| --- | --- | --- |
| R17 组件选型 | §2.1确定webauthn-rs、totp-rs、openidconnect-rs、governor、utoipa、standardwebhooks及所属边界 | 各切片G0先核release/许可/MSRV/features和最小适配，随后锁定版本；未引入任何依赖 |
| R18 许可与产品借鉴 | 更正webauthn-rs为MPL-2.0、openidconnect-rs为MIT；区分Standard Webhooks规范与Rust库许可；ZITADEL仅设计参考 | 不复制整套IAM，不把本仓库MIT声明覆盖第三方；按选定版本/文件保留归属和交付责任 |
| R19 因子优先级 | WebAuthn前置，服务端ceremony状态、UV、凭据更新和恢复降级规则纳入首批；TOTP后置 | S02a–c交付WebAuthn安全闭环，S02d为兼容子批；不默增passwordless或削弱旧入口保护 |
| R20 标准Webhook | 取消未实施的私有签名协议，采用Standard Webhooks HMAC v1、规范多签和独立endpoint密钥 | 同步签名/轮换/时间/去重测试；库之外仍有outbox/授权/租约/网络控制；v1a另列 |
| R21 恢复交互 | 增加邮件code与fragment link的支持矩阵、独立预算、同flow单次消费 | 桌面/原生优先code；不等同MFA恢复码、不自动登录、不绕过抗钓鱼策略 |
| R22 接入与顺序 | utoipa只进HTTP合同层；OIDC RP只进联邦adapter；governor仅进程内预算 | A01/A02与A03先行，S01/O01a为安全基础，WebAuthn闭环后再按需TOTP/联邦/外投递 |

上游事实依据为2026-10-25读取的官方规范、文档及Cargo/许可证文件；链接见各节。未检出上游仓库、未审计全部源码、未执行组件兼容试验。核查文档本地链接/锚点、围栏/表格、变更差异、两文档选型/顺序一致性及工作区范围；本轮只修改这两份Markdown，不改产品代码、依赖、schema、配置或CI，不运行产品测试/完整验收、提交、推送或部署。复核期间并行N2任务继续更新验收脚本和证据，这些变化保留且不计入本文产物，不据全工作区dirty状态声称本轮修改了代码。

### 16.4 修订4开源适配与实施依赖复审

本轮对两份全文及相关Core/HTTP/Email/配置和依赖清单再次核对，并读取上游实际API、feature和LICENSE文本。发现的问题直接回写正文与实施方案；六项首选组件保留，修正的是适配合同与进入条件，不以组件成熟度替代本地事务/授权职责。

| 项目 | 发现及修正 | 同步实施要求 |
| --- | --- | --- |
| R23 OpenAPI适配 | utoipa的Version31输出3.1.0，修订3要求的3.1.1不能直接生成；DTO分散且含动态JSON | 首批统一3.1.0；逐路由定位权威类型/投影，不向Core加文档依赖或违反孤儿规则，不默认升级Axum |
| R24 WebAuthn构建/状态 | 默认attestation、原生OpenSSL、服务端序列化feature及UUID user handle未具体落实 | 关闭默认、仅有界启用状态序列化；Mac/Linux链接与许可检查；稳定账号/RP映射、注册后独立认证及跨RP可用性检查 |
| R25 OIDC验证/分层 | 库不验证azp，网络adapter无明确归属，上游认证可能被误作本地MFA完成 | 库验证后补claims策略及Clock；可选federation crate，Core事务外await；外部认证继续本地因子/准入 |
| R26 时间/并发/容量 | 业务Clock与governor计时混用；取消等待不停止同步工作，清理不保证容量 | 墙钟与单调时钟分开；阻塞许可持到真实完成；活跃桶不被淘汰重置；TOTP保存库返回的匹配step |
| R27 Webhook适配 | 库单key不等于自动轮换；时间/重复头及接收去重事务边界不完整 | 单key实例组合双签、有限key集合、数值/头校验；验签后原子去重与业务处理；可选delivery crate |
| R28 邮件现状 | 同步Email接口及message错误不能直接表达完整投递状态 | O01a先补可选类型化结果，旧未知错误不猜成功/未发送；复用lettre和有界worker，保持旧注册接口兼容 |
| R29 依赖闭合 | 邀请漏S01；最低因子恢复可能被推迟至S03；密钥/网络预算可能误等O02 | X01依赖S01+O01a；S02c内交付最低恢复再开放，S03复用；各切片自行交付最低key供应/网络预算 |
| R30 许可与代码边界 | 顶层许可、原生依赖和交付形态易混；普通会话router仍依赖宽trait | 逐包许可/NOTICE及MPL覆盖源码分发核查，区分规范与Rust包；窄router先定state/trait，保留原认证拒绝与事务行为 |
| R31 恢复与持久化 | flow_id/重发可遗漏匿名保护或累计预算；“验证表只存摘要”不适用于全部因子状态 | 匿名响应一致、跨flow预算、摘要key有限轮换；明确公开challenge、库状态、TOTP密文及邮件密文的不同存储规则 |

可复查的上游源码快照包括：utoipa `utoipa/src/openapi.rs` blob `0aee6ecb86606f982833ac596a8be5d5b6e24608`；openidconnect-rs `src/verification/mod.rs` blob `47b64f5028fe9f7b5a6b7548b8de714beb873bf8`；totp-rs `src/lib.rs` blob `7958997b3e8379157a1a09a968558daf47cfcbd2`；Standard Webhooks Rust `src/lib.rs` blob `56c59726982e9de052a56edc10aecf799e9ef63a`。这些是读取时的文件内容标识，不是选定release或可直接安装的crate版本，官方链接见对应章节。

本轮仅文档审查和修正；G0版本锁定、组件构建/负例试验及发行许可证清单仍待实施切片执行。检查两文档的本地链接/锚点、表格/围栏、差异和关键合同一致性；不把静态检查算作产品测试或完整验收，也不接管并行N2变更。
