# M1-02 审查调整交接说明：先修订设计并回传

| 项目 | 内容 |
| --- | --- |
| 文档标识 | UP-M1-02-ADJUSTMENTS，修订 1，2026-10-20 |
| 文档上下文 | `rust-embedded-idp` 接收的独立设计修订任务；不依赖需求方私有仓库或此前对话 |
| 需求目标 | 将已认可的四项审查调整纳入 M1-02 设计，明确 M1-02、M1-03/04 的责任和验收边界 |
| 建议执行方案 | 只读核对当前源码与设计，修订设计稿，按第 6 节逐项回传；本任务不实施代码或运行验收 |
| 审查基线 | `docs/m1-02-configuration-composition-design.md`，UP-M1-02-DESIGN 修订 2 |
| 审查对象 SHA-256 | `d7402bd472d427062c1bf29ec6a745b31518d54dd16dbc644f5c666b651e9ab2` |
| 源码基线 | `1835ec35790568fefb9f6792a120b3041cfe77ae`，软件 3.0.0，schema `tenant_v6` |
| 已认可内容 | R01–R04 调整要求与阶段责任；不等于原稿所有 CLI、JSON 字段、公共接口已冻结 |
| 本次交付 | 修订后的设计稿、设计修订回传文档；可更新必要的文档索引 |
| 实施状态 | 任务说明已形成；交接文件存在不代表上游已修订、接收方已验收或任何运行用例通过 |

## 1 背景与不可改变的边界

需求方为多个自有产品建设 4A（账号、认证、授权、审计）实例。实例采用一产品一租户、全局共享账号/凭证、各产品成员/权限/会话独立、按产品配置加入方式。账号共享不代表跨产品 SSO，也不自动加入其他产品。

通用身份内核、独立 app、完整 UI、嵌入模块和 API 由 `rust-embedded-idp` 提供；需求方 `idp` 仓库负责版本、配置、产品接入和运营；产品负责业务资源与设备资产归属。上游通用库不强制采用“一产品一租户”，也不要求嵌入宿主连接中央服务。

M1 聚焦兼容、配置归一、共同装配和显式准备。本任务只修订这部分设计，不新增 SSO、MFA、身份恢复、完整托管 UI、服务身份、生产部署或其他阶段功能。

保留以下约束：

- 原 Core/Axum 公共契约、提供者注入、token/Cookie/custom transport、可选路由、同 schema 宿主表和可信 PermissionCatalog。
- Enabled 业务 Fixed 非 0 / Choose，Disabled 业务 Fixed 0；管理 Fixed 0 在两种 mode 下均是合法例外，管理 Choose 不进入平台域 0。
- Choose 成功切换保留仍有效的源会话；来源已撤销/失去资格时未完成切换拒绝。管理 `require_device_proof=true` 维持明确拒绝。
- 旧 env/无参数参考模式保留默认、路径、Cookie、注册、补缺 client 等可观察语义；新模式是显式采用，不把新约束偷渡到旧模式。
- 新模式启动不 seed、不迁移、不补管理员/client/权限；运行数据库与 API 是运行对象的权威源。
- 稳定 entry/client/purpose/policy，重排/普通重启不使原有效凭证意外失效；不新增持久入口表、热更新、通用准备控制器或路由 DSL。
- 区分人员设备会话、人员请求持钥证明和无人员设备传输证明，不降级安全保证。

更完整的兼容基线已在同仓 [UP-M1-01 修订 2](m1-01-compatibility-handoff.md)及 `docs/m1-01-design-review-result.md` 中。本文已包含本次任务所需背景；M1-01 原件及其历史回传不需改写。

## 2 执行范围与工作区保护

开始前阅读仓库 `AGENTS.md`、`CONTRIBUTING.md`、上述 M1-01 资料及 M1-02 当前设计。记录实际 HEAD、软件/schema、设计版本/摘要和工作区状态；本任务不要求刷新远端。

上游工作区已有 app、依赖和测试改动。不得覆盖、撤回、格式化或继续实现这些改动，也不能以它们存在为由宣称本任务获得代码实施授权。源码只读核对，区分提交基线事实和工作区新实现；本文的源码事实如已变化，回传差异与兼容影响，不静默修改既有约束。

本次允许：

1. 修订 `docs/m1-02-configuration-composition-design.md`。若仍为修订 2，递增为修订 3；若已有更新，基于当前稿增量合并，保留其他已接受修订，说明差异。
2. 新增 `docs/m1-02-design-adjustments-result.md`，按第 6 节回传。
3. 更新 README 或文档索引中的必要链接与设计状态。
4. 检查 Markdown 链接、示例结构、编号与文本一致性。

本次不修改源代码、测试实现、依赖/lockfile、schema、运行配置或 Secret；不执行构建、单元/集成/实库/浏览器运行验收、初始化、迁移、服务启动或部署；不启动 M1-03/04 实施，不提交/推送。不用“顺便验证”扩大范围。

## 3 四项已认可调整及本次设计动作

### R01：仅管理装配必须有完整生命周期——M1-02

现有 `management_router` 已有 login/session/refresh/logout，不新增管理状态机。修订 §6.3 和 Q11/Q12 等相关段落，使后续 M1-02 验收包含：

- 管理登录 → 访问受保护管理 API → 刷新 → 再次访问 → 退出 → 该会话原 access/refresh 经当前状态验证被拒绝。
- token 与实际启用的 BrowserSession 分别验证；Cookie 退出清除同一名称与 Path，刷新/恢复不复活已退出会话。
- 非默认 API mount、独立 UI base 的请求正确；管理与业务用途凭证不能互用，不留下旧路径绕过。
- 撤销范围是对应会话，不承诺同时撤销其他独立会话，也不把离线 JWT 签名有效误当成服务端会话有效。

**管理装配验收属于 M1-02，不全部推迟到 M1-04。**后续可以使用已准备的受控夹具，复用既有管理/用途隔离测试；这不证明空库准备完成，也不能让启动调用 seed。本次只写断言和测试映射，不运行这些链路。

### R02：明确业务 client × transport × 路由矩阵——M1-04

普通刷新已能通过 device authentication adapter 的无证明分支复用；退出已有 OIDC resource adapter。源码文件名不代表必须先开放完整设备或 OIDC 配置。

修订 §5.4、Q19 和待定项，明确 M1-04 启用业务组合前要交付的矩阵：

| 调用方式 | 后续必须明确的内容 |
| --- | --- |
| 公共客户端 token | login/session/refresh/logout 的路径、请求格式、凭证与错误；公共客户端不持有 confidential Secret |
| confidential 后端 token | 哪些协议执行 client-secret 认证、Secret 的后端所有者；普通密码登录和无证明刷新不冒称完成了同等 OAuth client 认证 |
| BrowserSession | Cookie、Origin/CSRF、专用刷新/退出/恢复及外部 Path；不替代显式 token 生命周期 |
| 证明会话 | 是否支持、必需证明、实际路径绑定；不支持时拒绝，不能降级普通刷新 |

必须明确：

- `tenant_device_auth_router` 已包含认证基础路由，替代普通认证 router；不能整体叠加 `tenant_auth_router` 来补刷新，导致重复端点。
- 整组复用时登记 challenge、userinfo、introspect、revoke 等全部附带端点和依赖，不能声称仅暴露 refresh/logout。
- resource logout 现有 confidential client Secret 校验必须保留；不能让前端能登录/刷新，却为了退出而持有后端 Secret。
- 若需要最小拆分，M1-04 先评估公共出口与兼容影响，不复制身份状态机。
- 非空业务集合是合法配置；构建尚未实现完整组合时明确拒绝，不能变成 JSON 永久禁用或按工作包编号开关。

**本次仅在 M1-02 设计中登记后续交付要求与启用门槛，不要求现在选定拆分方案、实现端点或提供业务运行证据。**M1-05 随实际接口变更维护契约。

### R03：P3 也必须使用同源准备参数——M1-03

首次准备术语：

| 步骤 | 含义 |
| --- | --- |
| P1 | 显式 Access schema 初始化，或采用另行受支持的迁移流程；不误走 legacy 覆盖式 seed |
| P2 | 既有管理员 bootstrap，保留密码 stdin、事务与重复执行保护 |
| P3 | 最小管理 public client 离线准备；创建/相同/冲突、并发和审计待 M1-03 冻结 |
| P4 | 同一新配置的仅管理只读启动 |
| P5 | 通过受保护管理 API 创建业务租户、clients 等运行对象 |
| P6 | 配置引用对象并启用完整业务入口 |

修订 2 已明确 P1/P2 从同一 JSON 投影临时环境。修订 §6.4、Q20/Q21 与待定项，将适用规则延伸至 P3：

- P3 与 P1/P2/P4 使用同一版本配置解释的数据库、schema、mode、TLS/CA 和 SecretRef；调用前核对目标，缺失/不一致时停止。
- 相对路径、Secret 读取和临时环境规则一致；不另建长期 `.env`，不把 Secret 放到命令行、日志或 shell 拼接，不因命令默认值不同降低 TLS。
- 管理 client_id 与配置引用一致；名称、类型、PKCE、redirect URI 是独立准备输入，不进入正常启动作为覆盖数据库的权威源。
- 合法已有 client 不要求 P3 历史执行标记；P4 检查当前引用，不隐式补建。
- 不消费的字段不机械复制，不新建通用导出器/准备控制器。

**M1-03 冻结具体命令、最小存储落点、并发、审计、冲突与未知结果核对。**本次只补设计边界与后续验收要求，不提前选择这些实现。各准备步骤不是整体事务，不能承诺失败时全部回滚。

### R04：管理 UI 关闭时不强制 BrowserSession——M1-02

修订字段表、示例、共同参数、仅管理装配与 Q04/Q11/Q12 等断言：

| 新模式组合 | 契约 |
| --- | --- |
| UI 启用 | 必须配置现有 UI 依赖的 BrowserSession；缺失则监听前失败 |
| UI 关闭、browser 开启 | 提供管理 token/API 与所选 browser 路由，不挂管理页面 |
| UI 关闭、browser 关闭 | 合法 token/API-only 管理入口；不挂 browser 路由、不生成 Cookie 配置 |

只有实际启用的 browser transport 要求 Origin、Cookie 及相应校验；若业务入口启用 browser，仍满足其要求。token-only 不豁免其既有安全规则。关闭 browser 不表示关闭管理认证或放开管理 API。

这项调整只针对显式新 app 配置；保留旧参考默认及原嵌入公共构造器。无需新增第三个认证框架。

## 4 阶段责任与完成条件

| 阶段 | 后续责任 | 本次设计修订不得混淆的边界 |
| --- | --- | --- |
| M1-02 | R01/R04；配置归一、共同装配、仅管理生命周期、UI/browser 条件与受影响兼容回归 | 可用预备夹具验证，不等于 P3 或空库全过程已完成 |
| M1-03 | R03；P1–P4 首次管理准备，并验证 P5 可创建业务对象 | 不提前宣称 P6 业务路由与业务生命周期已经交付 |
| M1-04 | R02；P6 业务启用、客户端/transport/路由矩阵、多产品多 client 组合及按需协议验证 | 不把解析非空配置当成运行支持，不提前实现所有可选协议 |
| M1-05/06 | 持续接口契约与最终 P1–P6/兼容证据汇总 | 安全及受影响兼容回归随改动执行，不等最后汇总才开始 |

以上是未来设计/实现/验收的责任划分。本次只完成设计修订和设计回传。试点、实际产品策略值、域名、数据库/代理/副本/Secret/邮件、SLO/RPO/RTO 和部署继续待定。

## 5 源码与文档核对入口

以下均相对上游仓库；可只读核对，不能把测试源码存在写成运行通过：

- `crates/embedded-idp-axum/src/management_auth.rs`：管理完整 token 路由。
- `crates/embedded-idp-axum/src/tenant_auth.rs`、`tenant_device_auth.rs`、`tenant_oidc_resource.rs`：实际组合、请求格式与附带端点。
- `crates/embedded-idp-core/src/access/authentication/device_transport.rs`、`authentication/oidc/resource.rs`、`crates/embedded-idp-core/src/service/client_auth.rs`：无证明刷新、退出与 client-secret 校验。
- `crates/embedded-idp-app/src/administrator_init.rs`、`crates/embedded-idp-storage-postgres/examples/bootstrap_local_postgres.rs`：P1/P2 参数与现有工具限制。
- `crates/embedded-idp-app/src/config.rs`、`bootstrap.rs`、`admin_ui.rs`、`web/management/main.tsx`：装配与 UI 条件；区分已有工作区变化与基线事实。
- `docs/m1-02-configuration-composition-design.md`：同时核对正文、字段表、示例、阶段表、Q01–Q22、附录和版本状态，不能只添加末尾说明而留下相反契约。

## 6 上游回传要求

新增 `docs/m1-02-design-adjustments-result.md`，标识建议为 `UP-M1-02-ADJUSTMENTS-RESULT`。必须包含：

1. **接收依据与基线**：本文标识/修订/摘要、实际 HEAD、软件/schema、设计稿修订前后版本及 SHA-256；如不同于审查基线，说明差异。
2. **逐项回传表**：每个 R01–R04 的处理结论、设计稿章节、具体变更、保持的兼容语义、关联 Q 断言/现有测试位置、后续责任阶段、剩余待定项。设计修订完成和运行验收未执行分栏记录。
3. **阶段责任表**：明确 R01/R04 属 M1-02、R03 属 M1-03、R02 属 M1-04；P1–P4/P5/P6 依赖以及最终汇总归属。
4. **一致性核对**：字段/示例/正文/断言/附录是否一致，旧 env 与嵌入契约有无被误改；不能把关闭 browser 写成关闭管理鉴权。
5. **交付文件与范围**：列出本任务修改的文档；既有代码/依赖/测试工作区变化单列为未纳入本任务，不冒领或撤回。
6. **证据与限制**：文档检查结果；全部运行验收标为“本任务未执行”，无代码/测试实现、初始化、迁移、构建、部署或提交/推送。
7. **未闭合事项与下一步**：必要技术待定和最小建议；不得自动开始代码或 M1-03/04 实施。若提出更小的等价方案，说明如何满足同一要求，不能静默改变已认可约束。

接收方将核对四项要求和阶段边界后记录设计接收；上游写完文档不等于需求方已接受，也不等于 M1-02 或整个 M1 的运行验收通过。

## 7 可直接使用的交接任务说明

请按 `docs/m1-02-design-adjustments-handoff.md`（UP-M1-02-ADJUSTMENTS 修订 1）先修订 M1-02 设计稿，并按第 6 节回传 `docs/m1-02-design-adjustments-result.md`。落实 R01 管理完整生命周期、R04 按需 BrowserSession；将 R03 同源 P3 准备明确留给 M1-03，将 R02 业务 client/transport/路由矩阵明确留给 M1-04。保持原有嵌入、旧参考模式和安全语义，保留工作区已有改动。本任务只读核对源码并修改设计文档，不改代码或测试实现，不启动构建、运行验收、初始化、迁移、部署或后续实现。先完成设计修订与逐项回传，再等待接收。
