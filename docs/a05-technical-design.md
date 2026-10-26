# A05 Enabled 嵌入示例技术设计

2026-10-26，修订4的独立示例批。状态：前置核对及编码前 double check 完成，修正客户端准备边界后完成实施，局部验证见[实施记录](a05-implementation-result.md)。

## 1 范围和前置依赖

A01 已有公开管理 client preparation 与 Postgres 原子实现；A02A 已有普通 tenant_auth/refresh/logout、独立 browser router、Fixed/Choose 和多入口隔离；A03 已有按策略生成的业务合同及漂移测试。A04 A–D 不作为本批基础前置，不挂设备/扫码/OIDC授权服务。新增 `examples/tenant-host` workspace binary，直接消费 Core/Axum/security/Postgres 公共API，不依赖 reference-app 内部模块，不改变 `no-tenant-host`。

复用现有 React19/MIT、antd/MIT 管理子入口、Axum/MIT、Postgres/MIT或Apache-2.0、ring/Apache-2.0 AND ISC、base64ct/MIT或Apache-2.0等现有锁定依赖；不引入身份框架、UI框架、游标库或SQL授权编译器。代码为本仓 MIT，新示例保留 workspace 本地消费，不发布 npm。

## 2 可信装配

示例固定 Enabled。两个业务入口 `/fixed`（tenant-a）和 `/choose`（验证凭据后选租户），分别使用 `tenant-host-fixed` / `tenant-host-choose` client、不同 login_entry/audience、不同 Cookie 名与精确外层 Path。普通 Bearer/login/refresh/logout 与 Cookie/restore 复用公开 router；本人角色使用配置 business_id=reports。路由根仍由模块拥有，宿主只 nest 前缀。

独立可选管理组件页 `/management`，API `/control/admin/*`，管理身份 Fixed0、单独 client/purpose/audience/Cookie。仅明确装配管理认证与权限目录所需 router；普通业务凭据拒绝管理接口，管理凭据也不被业务报告入口接受。管理目录的目标租户由用户明确选择；管理认证不随业务切租户变化，但目录状态随目标重建。

配置只来自示例自己的 `.env`/环境：IdP连接、独立业务连接/schema、RSA key、issuer、bind、精确browser origin、管理是否启用。过程环境仅在宿主composition边界读取。数据库及bind仅允许loopback，示例明确使用NoTls本地连接与PgTlsMode::Disable，拒绝非本地连接而非静默降级；文档明确生产须另行接入TLS/池。启动只检查 schema、bootstrap、预备clients/tenants和业务marker，不创建、不迁移、不seed。

## 3 初始化与数据保护

`run.sh` 仅加载示例自己的配置，不读取根 `.env`。显式 init/key-init/db-init/bootstrap-admin/prepare-clients/seed-fixtures/serve/build-web 分离；密码只由stdin进入bootstrap和fixtures，不在参数、日志或模板硬编码。

所有示例写入要求示例专用 schema 名以 `a05_` 开头，业务与IdP schema不同，并在业务 schema 中有固定版本marker。db-init在已有未标记业务schema时拒绝接管，不覆盖任意已有表；不会重置schema。fixture只创建固定demo租户/用户/角色/报告，已有同名记录冲突失败或验证相同，不能upsert覆盖真实数据；部分失败可明确报错，不能虚称跨IdP/业务库原子提交。管理员使用现有公开bootstrap。管理client准备复用A01显式服务（PublicDesktop+PKCE、无secret、冲突不覆盖）。业务client由示例自己的离线Postgres事务准备（锁定、ON CONFLICT DO NOTHING、读取完整定义比较，冲突回滚），不调用管理preparation或在线隐式seed。Core authentication.rs:405等明确要求client_exists，即使没有OIDC授权路由也必须准备业务client。该SQL仅示例基础设施，不新增Core API。

fixture：tenant-a/tenant-b、同ID r001不同标题；both账号分别有A/B active membership，only-a只在A；另有受限报告实例授权。初始化/seed命令不挂HTTP。生产宿主不执行fixture命令。

## 4 宿主报告API与列表

每个入口挂 `GET /api/reports/:id` 和 `GET /api/reports`（完整外层为/fixed或/choose）。拒绝caller tenant/business header和歧义Bearer，认证使用该入口stateful service获得actor，业务ID固定reports。

详情严格先authenticate→check真实tenant/subject、report/read、精确ID→按(tenant_id,report_id)查询。拒绝统一403；仅已授权而资源不存在返回404；无有效会话401、后端故障503、非法输入400。所有结果no-store；不接受跨租户路径参数。

列表query严格 `{limit?,cursor?,prefix?}`，limit默认10最大20，prefix只允许报告ID合法字符。按report_id稳定升序读取当前tenant且prefix匹配的候选ID（最多扫描40条/请求），逐条check或等价check_many，只有授权后才取正文。达到页大小或扫描预算时返回绑定作用域的继续游标，不能跳过尚未检查的候选；空items+has_more仍须继续，不输出精确总数或未授权ID/标题。授权变化时每页重新检查。

游标由宿主用ring HMAC-SHA256认证，payload版本、tenant、subject、session、business、入口、prefix、limit、最后已扫描ID、到期时间绑定；base64url只是opaque传输，HMAC防改范围。key为进程启动强随机，15分钟到期，重启旧游标400，客户端从首页重查。无需配置另一个长期秘密；不承诺跨重启继续。检查长度、规范编码和MAC后再用payload。不会把scope外cursor降级为空首页。

跨库身份检查/授权与报告读取不在同一事务。撤销对之后的请求生效，已通过检查的在途响应不承诺与撤销线性化；更强保证归宿主版本屏障/事务。

## 5 UI与异步隔离

复用 EmbeddedAuth（包含本人roles）、EmbeddedIdentityClient 与 BrowserSessionCoordinator；显式入口选择Fixed/Choose，两个client实例及Cookie生命周期隔离。新增可选 `EmbeddedAuth.beforeSessionChange` 钩子，只在切租户/退出前调用，用宿主草稿确认；缺省保留现有行为。取消确认不执行身份动作。入口切换由宿主同样确认。草稿只为本地示例文本，不写业务数据。

所有列表/详情请求绑定入口、actor/session和宿主递增generation：身份快照变化、selection开始/取消、入口切换立即使旧结果失效并清缓存；token等待、HTTP返回、body解析、catch/finally每个阶段均检查generation。不能只依赖request开始的tenant。加载中切换后的失败不能覆盖新视图，空页继续游标不当作结束。业务缓存不存token；权限目录独立管理client，切目标租户重新挂载。明确跨标签同Cookie不能同时保持不同租户，沿用协调器现有规则。

## 6 合同和局部退出

不新增IdP公共HTTP行为；复用Fixed/Choose业务profile。示例报告独立合同在 `examples/tenant-host/api-contract.json`，列路由、query、分页/error/no-store以及可信scope；不混入IdP business-openapi。A03 route inventory/README链接并在漂移入口增加示例合同检查，响应与真实HTTP局部测试对照。

验证顺序：静态类型/UT→Web构建→隔离PG真实宿主（两同名报告、两策略、独立成员资格、removed/suspended/disabled后请求拒绝、授权过滤、游标篡改/跨scope、403/404不泄漏、Cookie restore、管理purpose隔离）→浏览器真实宿主局部交互与延迟结果用例→合同/格式。保留Disabled现有测试。真实手机/设备、第三方宿主全组合、性能、完整验收和部署不在本批。

## Double check记录

独立复核指出A01管理preparation不能冒充业务准备，已拆分。主代理进一步核对client_exists，纠正“普通登录不需client行”的调查误判。管理路由明确permission_admin_router→management_router保护→merge独立browser router→nest /control，Cookie path=/control/admin/auth/browser；Cookie仅用于认证生命周期，目录API仍Bearer Management。业务marker与schema/table创建同一事务；已有schema未标记拒绝，IdP保持现有tenant_v6 marker。游标基于最后已检查ID，额外最多一条候选探测has_more，不读取未授权正文。以上修正不改变修订4退出范围。

实施复核补充：本地包必须先执行Web构建再构建示例，否则Vite可能读取旧dist而TypeScript仍读取新源类型。初始化进一步绑定marker中的IdP schema，拒绝以新业务marker接管已存在的IdP schema；以IdP专属准备锁串行化初始化。
