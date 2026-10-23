# N1 既有 ID 兼容专项设计

| 项目 | 内容 |
| --- | --- |
| 标识 / 版本 | IDP-CONSOLE-N1，修订2，2026-10-23；完成完整复审及提交前静态核对 |
| 状态 | 专项设计稿修订2；补齐响应元数据、公共错误语义及分阶段恢复契约；建议契约未实现、未运行验收 |
| 上位基线 | [N0修订2](management-console-n0-support-baseline-design.md)，本地归档`b3bf2920fa620b35e272d89da29b8d5dd80c39aa`；[交付总结修订2](management-console-delivery-summary-and-plan.md)，原归档`d4b318e` |
| 产品基线 | UI-F提交`d4be6a5479cae75cd1d304be2a2552fbb3abf397`；3.0.0 / `tenant_v6`；当前分支`codex/management-console-ui-b` |
| 设计依据 | [UI-A修订2](design/ui-a/README.md)、[详细设计修订2](management-console-capability-design.md)、[UI-C报告](ui-c-implementation-result.md)、[UI-D报告](ui-d-implementation-result.md)、[UI-F报告修订2](ui-f-implementation-result.md) |
| 本轮边界 | 只设计与维护文档入口；未改产品或验收代码、未运行产品验收；随本批文档本地归档、未推送；D02–D07继续待决，不启动N2–N5或M1-03–06，试点和部署继续待定 |

## 1 问题、目标与可行性

交付总结K01/K02已披露：精确`.`/`..`是合法租户及客户端ID，但作为HTTP路径段可能在到达业务处理器前被归一化。现有管理后台对租户读取已有安全回退，对租户更新和客户端详情仍主动阻止。本专项要让这些既有ID在原管理职责内完成读取、编辑和结果恢复，同时保留旧调用方、身份与租户边界。

**建议可行**：租户继续复用现有精确列表查询；增加集合地址的租户PATCH及不含动态ID路径段的客户端精确查询。复用现有Core读取/写入、版本校验、权限、事务和审计，不需修改ID语法、存量ID或schema，不需新增认证方式，也不依赖N0其他范围决策先行冻结。该结论是代码与协议设计核对，尚不是新端点或dot-only完整管理已通过的结论。

目标只涵盖：

1. 平台身份管理真实租户的详情与设置，含`.`/`..`。
2. 平台身份管理部署级客户端的精确查询、登记/编辑、写后回读，含`.`/`..`。
3. 普通ID与原路由继续可用；新协议不新增保留ID，不把寻址/挂载失败当成可登记对象。
4. 保留原草稿、危险确认、未知写入、会话失效与迟到响应保护；提供未来可执行的正反验收断言。

不增加租户管理员的全局权限，不改变租户选择/业务目标协议，不新增客户端删除、租户删除、客户端CAS、跨产品SSO、部署或代理实现。其他实体（账号、角色、设备、会话等）即使复用相似ID语法，也不据此宣称所有HTTP寻址已解决；发现相同限制应单独登记，不夹带改造。原M1-03–06多入口及路由契约工作不由本专项替代。

## 2 实际代码与现有证据

### 2.1 调用链与限制

| 面 | 当前事实及代码依据 | N1处理 |
| --- | --- | --- |
| ID语法 | [Core validate_id](../crates/embedded-idp-core/src/access/query.rs)允许1–128字节ASCII字母、数字、`_`、`.`、`-`；[租户模式](../crates/embedded-idp-core/src/access/model.rs)复用同一语法，Enabled真实租户不得为`0`，Disabled业务域固定`0` | 精确`.`/`..`仍合法；不重命名、不规范化、不额外保留`-`、`lookup`等词 |
| 租户读取 | [ManagementClient.getManagedTenant](../web/management/client.ts)对dot-only使用`GET /admin/tenants?tenant_id=<ID>&limit=2`；单条、ID精确一致、无后页才接受；其他ID沿`GET /admin/tenants/:tenant_id` | 保留现有两条读取路径及严格回读校验，不再新增租户查询服务 |
| 租户更新 | [tenant_management_admin_router](../crates/embedded-idp-axum/src/tenant_management_admin.rs)只提供路径PATCH；client仍拼路径；[TenantEditor](../web/management/tenants.tsx)在提交前拒绝`.`/`..` | 增加集合PATCH，更新统一使用JSON定位；后端和client先具备后才移除UI拒绝 |
| 客户端读取 | [client_admin_router](../crates/embedded-idp-axum/src/client_admin.rs)只提供动态路径详情；列表没有精确client_id过滤；[ClientEditor](../web/management/clients.tsx)主动阻止dot-only，避免误404登记 | 增加精确查询入口，UI不再用HTTP404加列表探测判断可登记 |
| 客户端写入 | `POST /admin/clients/upsert`已在JSON中承载client_id；[CoreClientAdminService](../crates/embedded-idp-core/src/access/admin/clients.rs)校验配置、Secret、平台权限并在事务中写入审计 | 原样复用；没有CAS，也不因增加查询而变成原子“仅创建”或“仅更新” |
| 平台与目标 | [platform_context](../crates/embedded-idp-axum/src/tenant_admin.rs)接受缺省或唯一值`0`的目标头，拒绝业务头；[Core管理权限](../crates/embedded-idp-core/src/access/service.rs)要求域0当前身份与相应权限 | ID来自query/body只定位资源，不提供身份或权限；不使用目标头传递被编辑的租户 |
| 装配与直接嵌入 | [参考宿主](../crates/embedded-idp-app/src/bootstrap.rs)将两个独立管理router装入[management_router](../crates/embedded-idp-axum/src/management_auth.rs)的认证组；另外存在[通用admin_router](../crates/embedded-idp-axum/src/admin_api.rs)及其宿主注入的旧AdminService | 新入口仅属于独立管理router；不向通用旧router自动加接口，也不把两组重叠路径直接merge；同一宿主使用两组接口时须隔离外层前缀与认证边界 |

### 2.2 路径归一化及路由名称冲突

`encodeURIComponent`不会把`.`/`..`变成可可靠寻址的HTTP路径数据；改写为`%2e`或`%2e%2e`也不能作为解决方案。浏览器URL标准将这些编码形式识别为点段；规范化发生在URL处理链，不能归因于Axum单独的行为。[WHATWG URL：点段定义与路径解析](https://url.spec.whatwg.org/#single-dot-url-path-segment)说明了这一点。双重编码则要求额外解码协议，容易产生不同中间层解释，本方案不采用。

还需防止新增静态单段路径占用合法ID。当前`/admin/clients/upsert`是静态POST路径，和`/:client_id`并存。根据[Axum 0.7.9路由规则](https://docs.rs/axum/0.7.9/axum/struct.Router.html#method.route)，静态路径优先；据本仓库注册方式推断，旧`GET /admin/clients/upsert`会命中静态路径的405，而非ID为`upsert`的详情。本轮只作源码推断，未执行验证。新入口应让该ID也可被精确查询，但不改原POST、不重新解释旧GET，不宣称修复全部旧路径。

因此不新增`GET /admin/clients/lookup`或`/detail`一类单段固定地址：它们会再占用同名合法ID。采用固定两段`/-/lookup`，没有动态ID进入pathname，且单段ID为`-`或`lookup`时的旧详情路由仍保留。任意宿主若已自定义使用新地址，须先确认挂载冲突，不能假定所有外部宿主没有私有扩展。

### 2.3 历史覆盖与未覆盖

- [client单元断言](../web/management/client.test.mjs)已覆盖dot-only租户精确过滤读取及空/错ID/重复/后页/畸形结果拒绝。
- [hash单元断言](../web/management/navigation.test.mjs)及[导航脚本](../scripts/check_management_navigation.mjs)覆盖dot-only目标定位、刷新恢复与Choose身份；hash是数据定位符，不能类推为HTTP路径安全。
- [客户端脚本](../scripts/check_management_clients.mjs)通过原JSON upsert准备`.`/`..`，验证UI拒绝不安全读取，不进入误登记分支；这是安全阻止证据，不是成功编辑证据。
- UI-C/D历史报告与UI-F复跑保留K01/K02，尚无本设计新查询、集合PATCH及相应UI成功流程的运行记录。N1后续实现须另存新报告与JSON，不能改写旧截图/结果，或把UI-F96组重新解释为已经覆盖本方案。

## 3 方案比较与建议

| 候选 | 影响 | 结论 |
| --- | --- | --- |
| 禁止`.`/`..`、改ID、增加保留词 | 改变领域与旧调用方合同，可能需要迁移身份、授权、会话引用 | 不采用 |
| 转义点、双重编码、尾斜线、客户端或代理关闭归一化 | 不同URL处理层的解释仍有差异；需要新的解码/代理前提 | 不采用，不把原始请求恰好可达当浏览器支持 |
| 扫描客户端列表找精确ID，或增加client_id列表过滤 | 前者需跨页扫描且不可靠；后者需更改Core过滤模型、游标绑定与列表合同 | 本专项不采用；不是查询详情的必要前提 |
| 客户端单段`/lookup`或通用RPC网关 | 前者占合法ID，后者增加不必要的公共协议与抽象 | 不采用 |
| 租户精确过滤读取＋集合PATCH；客户端固定两段query查询＋原JSON upsert | 两处HTTP增量；现有Core服务不变，原路径保留，不依赖新编码 | **建议采用**，详细合同见§4–6 |

这里先审阅现有Core合同，确认已有`get_client`、`get_tenant/list_tenants`、`execute(UpdateTenant)`及`upsert_client`完整表达原业务。新增的是HTTP表示方式和查询结果投影，没有新增领域操作；无需为了端点别名新增Core trait或存储方法。若实施时发现必须改变领域语义，应停止扩张，先单独修订Core合同和本设计。

## 4 HTTP寻址合同（建议，尚未实现）

以下路径为模块内根路径；宿主外层前缀仍由宿主决定。参考宿主默认例为`/api`，显式配置可以是`/identity`，不得硬编码在模块中。独立管理认证仍提供可信AccessAdminContext。

### 4.1 路由矩阵

| 方法 / 模块内路径 | ID载体与用途 | 兼容及响应 |
| --- | --- | --- |
| GET `/admin/tenants?tenant_id=<ID>&limit=2` | 既有精确租户列表；dot-only详情读取复用 | 原分页envelope不变，单条ID/版本严格验证；空页只表示未读到对象，不触发创建或重放 |
| GET `/admin/tenants/:tenant_id` | 原普通ID详情读取 | 保留；不承诺dot-only经旧路径可达 |
| **PATCH `/admin/tenants`** | **新增**，JSON必填tenant_id与原更新字段 | 成功200，原`{tenant, audit_id}`；仍使用UpdateTenant、expected_version及原事务 |
| PATCH `/admin/tenants/:tenant_id` | 原路径ID与原body | 保留原语义；body仍不得新增tenant_id，不为冲突来源定义优先级 |
| POST `/admin/tenants` | 原创建及初始管理员JSON | 原样保留，方法不同不会解释为更新；不增加第二创建协议 |
| **GET `/admin/clients/-/lookup?client_id=<ID>`** | **新增**，精确单对象查询，支持全部合法客户端ID | 成功200为§4.2 envelope；无分页，不遍历客户端列表 |
| GET `/admin/clients`、GET `/admin/clients/:client_id` | 原列表与路径详情 | 旧响应/过滤/游标不变；原路径归一化与`upsert`冲突不被新协议掩盖 |
| POST `/admin/clients/upsert` | 原JSON定位与配置写入 | 原样保留；dot-only无需新写入协议，不能误改为POST新查询地址 |

所有新入口继承`no-store`；新PATCH继续16KiB body上限。新查询只接受恰好一个必填`client_id`，未知参数、重复键（同值也拒绝）、空值及非法ID拒绝；不接受body定位或分页参数。查询只做一次标准form/query解码后校验ID，不再`decodeURIComponent`或额外URL解码。重复键拒绝是新增合同，须针对实际提取器验证；优先直接反序列化为带约束的类型化DTO，不先转成会覆盖重复键的Map/JSON Value，也不在缺乏证据时另建解析框架。

合法例：`client_id=.`、`client_id=..`；query中的`%2E`解码后精确等于`.`，可接受；`%252e`一次解码后为非法字符串`%2e`，拒绝。JSON中的`"%2e"`不是`.`，不解码、不接受为租户ID。大小写、前后空白、Unicode相似字符不得被trim、大小写折叠或转换；ASCII原值就是领域键。`...`、`.a`、`a..`、`-`、`lookup`、`upsert`均不属于精确dot-only，也不新增禁用规则。

### 4.2 客户端精确查询与明确的“不存在”

新GET成功响应必须为以下两种之一；`client`中的字段复用现有metadata，不增加Secret/哈希。

```json
{"client_id":".","client":{"client_id":".","client_name":"Example","redirect_uris":["https://app.example.test/callback"],"client_type":"public_desktop","pkce_required":true,"client_secret_configured":false}}
```

```json
{"client_id":".","client":null}
```

请求先走管理认证与平台头校验，再调用原`ClientAdminService.get_client(context, id)`。仅该调用返回精确`AccessError::NotFound("client")`时转换为200且`client:null`；这表示**当前经过授权的精确查询未找到该ID**，不承诺稍后写入时仍不存在。Forbidden、其他NotFound、存储/响应异常都沿错误处理，不转换为null；handler不直接访问store，也不通过字符串错误文案识别不存在。

目的在于区分“对象不存在”与“新端点没挂载”：后者404、错误页面或HTML绝不能打开登记表单，即使原客户端列表仍可读。新UI只接受HTTP200且envelope完整、外层client_id精确等于请求ID、client明确为null或ID一致的合法metadata。缺字段、错ID、畸形metadata、204、200 HTML都保持读取失败；禁止宽松地把undefined当null。

HTTP成功状态须在解析envelope前保留并核对，具体调用链约束见§5.1；不能只检查现有`response.ok`或返回的JSON对象。查询不新增审计事件、查询票据或长期状态；仍按原服务先校验当前管理身份/权限，再得到资源或不存在。该协议没有新增客户端删除、唯一创建或CAS能力。

### 4.3 租户集合PATCH

请求必填字段：

```json
{"tenant_id":"..","name":"Example tenant","status":"active","allow_registration":false,"expected_version":4}
```

新DTO拒绝未知、重复、缺失和错误类型字段；拒绝actor、subject、business、密码、初始管理员或其他创建字段。不从query、目标头或路径再取资源ID，也不容许多个来源任选一个。query非空时拒绝，不将意外`?tenant_id=other`静默忽略。原路径PATCH继续原DTO，不容许body覆盖path。

handler复用platform_context，将body的原值放进`AccessAdminCommand.tenant_id`，其余字段映射原`AccessAdminMutation::UpdateTenant`，复用原mutation_response。合法真实租户由Core Enabled校验；`0`、空、超长、非法字符拒绝。现有Core更新允许平台按原权限处理非active租户，不新增“归档不可恢复”规则或租户删除含义。

成功必须有原目标tenant_id、有效正整数version、目标状态及audit_id；新client应核对返回版本为原expected_version加一、name/status/allow_registration与本次提交一致。expected_version来自本次确认展示的记录，不取提交时任意新版本。版本不匹配409，状态与审计均不落库；有效更新按原next_version递增并原子写入审计。字段、状态、影响提示与UI-A保持一致，不修改管理员保护或创建初始管理员事务。

### 4.4 鉴权、错误与敏感数据

- 客户端新GET在Enabled/Disabled都只允许当前域0管理身份及`idp.platform/clients.manage`；租户PATCH仅Enabled平台身份及`idp.platform/tenants.manage`。非0租户管理员即使传`tenant_id=.`、目标头0或拥有其他业务授权也不能越权。
- 两个入口均禁止业务头；目标头必须缺省或恰好一个`0`。重复头、非0头都拒绝。被编辑租户来自body，不改变actor、管理登录入口、token用途、当前会话或目标工作区。
- 普通受保护API仍用管理Bearer，Cookie本身、业务Bearer、TenantSelection票据、开发subject头不能认证管理操作。Cookie恢复/轮换及开发登录期限仍沿原合同；不新增CORS或无锁降级。
- 正常管理401清理本地身份，403保留仍有效会话但拒绝操作；Core事务中权限/账号/会话失效也可能表现为403，不能把所有403当成身份仍可继续写。由现有client/session机制裁决，不静默重发旧操作。
- Core非法输入400、缺资源404、并发/状态冲突409、存储异常5xx沿原映射；Disabled租户router仍为空，404不变。DTO/query解析按现有Axum提取器约定（query错误400；JSON语法/数据/Content-Type分别可为400/422/415），不得为统一文案伪装为对象不存在。请求鉴权与解析失败先后沿原中间件，不规定恶意请求一定先返回某一种状态。
- 新GET的有效不存在特例仅为§4.2的200/null；新PATCH错误不转null、不转成功。敏感参数仍不得进入URL、日志、storage、截图或审计；query仅承载非凭据ID，Secret仍只在原upsert JSON中短暂传递并由服务端处理。

## 5 ManagementClient与界面合同（建议）

### 5.1 查询与公共方法

保留构造参数、认证、会话和已导出方法签名。建议增加`lookupClient(id): Promise<ManagedClient | null>`，调用新GET并严格验证envelope；由`authenticated`统一等待access/refresh和校验revision，不引入第二套fetch、身份缓存或transport。

**补齐响应元数据边界**：当前`request`在`response.ok`后只返回JSON/undefined，`authenticated`也只传业务值；单在lookupClient里验证envelope不能证明HTTP状态恰好为200。未来须在现有request/authenticated链上增加仅用于新lookup与集合PATCH的可选内部成功响应约束，先验证状态200和JSON媒体类型（`application/json`，允许charset参数），再解析/校验业务值。保持同一fetch、鉴权、revision、mutation计数与错误通路；不新增公共transport、不改变其他调用默认成功状态。201/202/206等即使携带貌似有效envelope也不接受，204、非JSON媒体类型或无效JSON同样报未确认/响应无效。PATCH已发出后违反成功响应契约按未知结果冻结，不根据状态属于2xx就宣布成功或自动重发。

**补齐公共错误边界**：lookupClient将新GET实际返回的404/405转换为`ManagementError`，使用现有`status=0`约定及稳定`code="client_lookup_unconfirmed"`，提示精确查询未确认、需核对版本与挂载；不返回null、不保留为对象不存在404。仅这个新方法做局部映射，其他4xx/5xx沿原规则，401仍先由authenticated清理会话，403不被改成null或清空身份。实际HTTP404也可能来自服务端其他NotFound，故文案不能断言一定是端点未挂载。

`getClient(id): Promise<ManagedClient>`继续保留签名，内部复用lookupClient；仅合法200/null才合成对象缺失`ManagementError(404, code="client_not_found")`，其余已分类错误继续抛出。这样旧调用方升级client后即使只按status===404判断，也不会因新GET路由404进入误登记。新client仍需要具备新协议的服务端，版本兼容见§7；旧UI使用旧client二进制的既有404推断能力不会被反向修复。UI登记判断必须直接使用lookupClient返回值，不恢复catch getClient的404作为本期登记入口。

新ClientEditor对**所有ID**使用lookupClient；null才显示“此ID尚未登记”的原确认流程。删除当前dot-only预拒绝及旧“详情404后listClients探测”的登记分支，不以列表可读证明新查询已挂载。原getClient直接调用者的404语义不是给UI恢复自动登记的授权。

### 5.2 租户设置

`getManagedTenant`保留现有dot-only精确列表读取及校验，普通ID沿旧详情读取；不改变列表过滤、sort_order、游标和hash语法。`updateTenant`保持现有方法签名，**所有ID**统一发集合PATCH，并显式从已确认TenantDetail取tenant_id与expected_version；请求不附被编辑租户的目标头。

集合PATCH沿§5.1的内部约束验证200及JSON媒体类型；客户端本地校验ID和可安全表示的正整数版本、返回ID/版本/状态、audit_id，防止非法调用或畸形响应变成已确认成功；服务端Core仍为最终权威。TenantEditor在新client/服务端合同具备后移除dot-only阻止，复用现有SafeConfirm、原值→新值与版本、状态后果提示、useWriteFeedback及刷新回焦；不新增页面或改造后台视觉。

### 5.3 写入结果、草稿与迟到响应

客户端upsert仍保存完整回调列表；公开客户端强制PKCE且不收Secret，机密客户端保留/设置/轮换沿原合同。查询和回读只显示client_secret_configured，不能证明具体新Secret内容；成功回读不新增CAS或撤销现有会话的承诺。

两个页面都保留：草稿/确认/未知结果离页提示、写意图等待refresh即计入忙碌、提交期间禁重复写、卸载/切目标/身份变化丢弃旧响应、清除敏感字段、取消和成功回焦。寻址函数不得绕过authenticated的revision或将旧目标响应写入新页。

以下null状态表只适用于客户端lookup。租户getManagedTenant始终返回有效详情或错误；精确列表空页转404，不能进入创建或解锁未知创建。

| 读取所处阶段 | 返回null或其他读取失败时的页面约束 |
| --- | --- |
| 初次精确查询，尚未发出该编辑流程的写请求 | 仅有效200/null可进入原登记确认流程；HTTP错误或畸形响应不能进入 |
| 已明确写入成功后的回读 | 保留写入成功证据；合法200/null、404或挂载/解析错误都表示当前记录未能确认，禁止转为未登记、开放新建或再次POST；取得合法非null记录后才恢复编辑并重新确认新的写意图 |
| 写结果未知后的回读 | null、404、持续失败都不证明原请求未执行，保留blocked及原ID；不自动进入登记。合法非null回读按原恢复流程核对可见状态，再经重新确认产生新的写意图，不宣称已证明原Secret或请求归因 |

客户端编辑器须保留本轮是否已发写请求及其saved/unknown/rejected阶段，不能只把当前snapshot设为null后统一清blocked、清dirty并生成登记表单。明确拒绝后的回读也不自动转登记或重放：合法非null记录可按原流程恢复编辑；null维持读取未确认，若确需登记应明确结束当前编辑再从初次查询重新核对。租户编辑器保留原originalId、记录与write反馈，继续区分创建与设置，不能根据单次404改变任务类型。

“已确认写入成功”依据原写响应与audit_id；回读失败只表示未刷新展示，不能抹掉已确认写入。丢响应/超时/解析错误按原未知写入处理，保留原ID、冻结再次提交并要求明确回读或放弃离开；不因查询null、404、同名对象出现或版本变化认定原写未发生，也不自动重试。客户端回读最多确认可见配置及密钥存在性；租户回读最多确认目标当前记录/版本，不能独自证明请求归因。重新读取并重新确认后才允许新的写意图，未知状态的恢复和放弃提示不因支持dot-only弱化。

## 6 能力复用与未来实现边界

| 层 | 未来最小变动建议 | 必须复用 / 保持 |
| --- | --- | --- |
| Core | 先核对合同，无计划新增业务能力或trait | ClientAdminService.get_client/upsert_client；TenantAdminService精确读取及AccessAdminService.execute；现有权限、版本、锁、审计、管理员保护 |
| Axum | client_admin新增两段GET/严格query/envelope；tenant_management_admin增加集合PATCH/独立DTO，公共处理逻辑小范围复用 | 原router函数签名、模式门禁、platform_context、call、no_store、body limit与错误投影；旧路由保持 |
| 存储与安全 | 不计划改schema、SQL、加密、签名或环境配置 | 原事务和存储trait；无ID映射表、迁移、启动修复或新Secret |
| 管理Web | client新增lookup、局部响应元数据约束/错误映射与集合PATCH；客户端编辑器分阶段处理null，两个编辑器移除已被安全入口替代的限制 | ManagementClient会话隔离、SafeConfirm、草稿/未知写保护、工作区及hash导航、现有字段与操作范围 |
| 直接嵌入与参考宿主 | 原管理router自然带新入口，参考宿主重编译后验证；已有宿主需核对新路径/方法转发白名单 | 无UI/仅API仍可用，不要求后台壳层、前端依赖或browser；旧参考补建与新模式只读启动保持 |
| 文档与验收 | 更新实际管理接口说明，新增N1报告/独立证据，修改在维护的测试脚本预期 | UI-A–F原报告/JSON/截图和N0修订2不回写；通用旧AdminService/admin_router保持原合同 |

本设计中的接口名、返回结构及目标方法是建议合同，不是现有API说明。未来主实现不得在handler复制权限检查或直接执行SQL，也不因统一两个JSON DTO而引入通用命令框架、新依赖或路由库。若仅有少量共享字段，使用清晰局部映射即可。

## 7 兼容、版本配对与回退

| 组合 / 影响 | 预期与限制 |
| --- | --- |
| 旧UI/client＋新服务端 | 原路径、列表、POST及原body保留，原有普通ID流程应回归；旧UI仍可能主动拒绝dot-only，不宣称自动获得新能力 |
| 新UI/client＋新服务端 | 使用新查询与集合PATCH，达到N1验收后才说明相应dot-only管理可用 |
| 新UI/client＋旧/未挂载服务端 | 新GET的404/405由lookupClient归类为status=0的client_lookup_unconfirmed，不得解释为对象缺失；PATCH的404可能是目标缺失或入口缺失，不能仅凭状态码断定原因，405按协议不可用处理。页面提示核对目标、版本与挂载，禁止回退到dot路径、列表扫描、重复POST或自动登记；这是明确的版本配对要求，不承诺所有新旧组合互通 |
| 公共ManagementClient错误语义 | 方法签名与明确对象缺失404保留；升级后精确查询的原始404/405不再透传，改为status=0及client_lookup_unconfirmed。仅依赖status的调用方也不会误认为对象缺失；按code/状态诊断的消费者须知晓此收紧，禁止全局重写其他端点错误 |
| 部分代理只放行旧路径/方法 | 必须放行新的固定GET和集合PATCH，保留query/body及外层前缀；缺失时拒绝操作，不自动绕过。N1不部署代理；生产TLS/代理与N2目标环境仍单独待定 |
| 同步Web与编译资源 | 先构建Web，再编译嵌入资源的Rust宿主；记录同批源码/制品。独立分发Web或管理子包时明确所需服务端协议，不能假定仅替换静态文件就完成兼容 |
| 直接Core或自定义HTTP宿主 | 既有Core方法和ID不变，不必使用新HTTP；只使用通用admin_router的宿主不会自动获得独立管理新入口，也不能让管理Web冒用其认证模型 |
| 回退旧版本 | 原数据库/schema和存量ID不变，无本专项数据迁移；回退到旧UI/服务端将恢复已披露的dot-only管理限制，不能为回退改ID或放宽授权 |

未来实现需在独立交付记录中说明HTTP增量及导出ManagementClient的兼容要求；版本号、发布和分发由该任务确认，本设计不提升3.0.0、不预选发布方案。N0 D02–D07仍不因本专项冻结。新端点功能验收是N1范围，商用浏览器、真实读屏/设备、代表宿主与生产拓扑证据仍属N2或后续。

## 8 验收断言（设计要求，全部待执行）

下表是未来实施的退出要求，不是本轮验收结果。适用ID至少为`.`、`..`、`...`、`.a`、`a..`、`-`、`lookup`、`upsert`、普通大小写ID及128字节边界；租户`0`专列拒绝，客户端`0`按原语法处理。外层前缀至少覆盖默认`/api`与非默认`/identity`。无关阶段既有回归可以按实际差异复用，但新协议断言必须有新证据。

### 8.1 HTTP、Core复用与寻址

| ID | 必须断言 | 建议证据层 |
| --- | --- | --- |
| ID01 | ID语法未改，dot-only、点混合及边界合法值通过N1 query/集合PATCH适配器精确到达既有Core service；旧动态路径不据此承诺dot-only可达；非法空/超长/空白/控制符/斜线/反斜线/Unicode拒绝，不trim或二次解码 | Core既有断言＋Axum适配器测试 |
| ID02 | 新客户端query只有一个client_id；重复同值/异值、未知参数、缺失、错误编码拒绝；`%2E`按一次解码为点，`%252e`不冒充点；JSON `%2e`非法 | Axum提取器/真实HTTP负例 |
| ID03 | 新lookup对存在对象200且外层及内部ID均精确；有效缺失200/null；仅NotFound("client")可投影null；其他NotFound/Forbidden/Store/畸形service响应不能变为有效缺失 | service替身＋真实宿主 |
| ID04 | 新PATCH无query定位，重复/未知/缺少字段、创建字段/actor伪造拒绝；旧path PATCH仍拒绝body tenant_id；失败不写状态或审计 | Axum与真实DB |
| ID05 | tenant读取继续原精确过滤：空、错ID、重复、has_more、畸形version不可当详情；不扫描下一页，不因空页自动创建/重放 | client单测＋真实宿主 |
| ID06 | `/-/lookup`与原单段`-`/lookup详情共存，无路由注册panic；upsert ID经新查询可读，原POST不变；GET/POST/PATCH集合方法分派无交叉调用 | router组合＋真实HTTP |
| ID07 | 通过真实fetch/URL链发送dot-only时ID仅在query/body，不出现危险dot pathname；默认与非默认外层前缀路径、方法、请求体精确，无跳转依赖 | client请求捕获＋隔离真实宿主/浏览器 |
| ID08 | 原dot路径及百分号点路径仅作为负面/兼容记录；不能要求已在客户端归一化的请求一定由某handler拒绝；旧路径原body即使被归一化到集合地址，也因缺少新必填tenant_id而不得写入；不得从path/query/header补出它；以无意外写入/创建、无错误身份及新入口精确寻址为断言 | URL层与真实HTTP分别登记 |

### 8.2 权限、租户及事务

| ID | 必须断言 | 建议证据层 |
| --- | --- | --- |
| ID09 | 无管理Bearer、业务Bearer、Cookie单独认证、TenantSelection、伪造subject均不能通过；非0管理员不能管理全局客户端/租户；仅有业务权限不能替代平台权限 | 真实宿主负例 |
| ID10 | 平台目标头缺省/唯一0合法；非0/重复头、业务头拒绝；body/query的ID不替换actor，无法跨用途或假冒目标身份 | Axum＋真实宿主 |
| ID11 | Enabled可读取/更新真实dot-only租户；Disabled无租户管理路由且无写入；两模式客户端均保持平台权限；四管理登录策略的身份边界不变 | 参考宿主及模式回归 |
| ID12 | dot-only租户新PATCH与原普通ID path PATCH效果等价：期望版本成功递增一次，旧版本409不写；两请求同版本并发最多一次成功；审计与状态原子提交，注入失败全回滚 | 隔离真实PostgreSQL |
| ID13 | 新lookup/tenant更新遇当前账号、会话或权限已失效应拒绝；等待锁后失效也不凭旧权限写；暂停/归档租户的可操作性沿原平台规则，不扩租户管理员权限 | Core既有规则＋定向真实DB |
| ID14 | 新查询无Secret/哈希，新写返回metadata/audit_id；日志/storage/URL/只读DOM/审计不泄漏凭据，原Secret输入用后清除；客户端public/机密、PKCE、回调与保留/轮换Secret规则不变 | 适配器、client与浏览器 |

### 8.3 UI任务与恢复

| ID | 必须断言 | 建议证据层 |
| --- | --- | --- |
| ID15 | 已有`.`/`..`客户端可从列表及输入精确ID打开、显示编辑已有对象、确认并保存、回读同一ID；缺失ID只有经过200/null才显示登记，取消不写 | 隔离真实宿主/浏览器 |
| ID16 | 新GET缺失/405/HTML/204/200缺字段或错ID，即使旧列表200也不能显示未登记、开放保存或发POST；getClient兼容签名不被UI用作HTTP404登记回退 | client负例＋浏览器注入 |
| ID17 | dot-only租户设置显示本次确认版本与原/新值，经新PATCH成功回读；取消零写入；冲突保留/提示重新核对，不能自动换新版本重提；普通ID流程等价 | client＋真实宿主/浏览器 |
| ID18 | dot-only两类页面草稿、确认与未知结果下，跨页/目标/hash刷新/前进后退、关闭及浏览器离开维持既有保护；写意图等待refresh期间已busy | 原导航/任务断言扩展 |
| ID19 | 新查询、保存、回读延迟期间logout、跨标签替换、会话撤销或切目标：旧响应不能恢复身份/草稿或覆盖新页，旧写不自动重放；普通401/403按原合同处理 | client＋浏览器，注入点明确 |
| ID20 | 写响应明确成功后回读合法200/null、404、挂载失败或畸形结果，保留已确认成功与当前读取未确认，不显示未登记、不开放新建、不追加POST；合法非null回读才能恢复编辑；真实写后丢响应需服务端/DB证明确已写入并标未知，不自动重发；回读同配置/Secret已配置不能证明具体密钥或原请求归因 | 真实DB＋明确丢响应注入 |
| ID21 | 未知/成功/明确拒绝后的回读阶段不得因null/404自动再登记/创建；未知状态持续读取失败可明确放弃离开但不声称服务端未执行；合法非null回读后重新确认才发新写意图。初次未发写请求的200/null仍可进入登记，两个阶段须成对断言；租户空页404不改变创建/设置任务 | 浏览器负例 |
| ID22 | 新成功/失败/取消/关闭流程保留焦点、键盘、标签和敏感字段清除，不修改UI-A业务字段/危险后果/保护管理员规则 | UI-F相关专项回归 |

### 8.4 旧参考、嵌入与证据边界

| ID | 必须断言 | 建议证据层 |
| --- | --- | --- |
| ID23 | 旧client调用普通安全ID的客户端动态GET、租户动态path PATCH、客户端JSON upsert、列表sort/filter/cursor及租户创建保持语义；两套管理router公开签名和通用admin_router原行为保留，同宿主两类重叠路由须隔离外层前缀 | Axum/client与旧参考回归 |
| ID24 | 新client对旧/部分挂载服务明确失败，无不安全回退或误写；外层前缀由宿主决定，代理未放行集合PATCH/新GET时也不能形成null证据 | 版本/挂载负例 |
| ID25 | 宿主可直接调用原Core或选装独立管理router，无管理UI/browser依赖；主React入口、admin子入口会话边界及公开导出保持；管理与旧业务凭证双向隔离 | 编译/嵌入及既有定向回归 |
| ID26 | M1-02旧参考只补缺不覆盖；新模式只读启动、仅管理及可选browser/UI保持；不因新HTTP入口修改配置、seed、启动写入或业务入口装配 | 参考宿主相关既有验收 |
| ID27 | N1证据另存，列源码/制品SHA、实际环境/挂载、用例和注入、审计/DB回读及未覆盖；旧UI-C fail-closed结果继续保留为历史，不改成新功能成功证据 | 静态证据清单审查 |

### 8.5 响应元数据与公共错误专项

| ID | 必须断言 | 建议证据层 |
| --- | --- | --- |
| ID28 | 新lookup与集合PATCH只有200及JSON媒体类型可进入业务投影；201/202/206携带完全有效业务体、204、错误Content-Type及无效JSON均拒绝，lookup不变null、PATCH不变已确认成功且已发写按未知锁定；其他旧调用默认行为和401清理/revision计数不变 | request/authenticated/client负例＋浏览器注入，记录实际状态与媒体类型 |
| ID29 | 对同一ID，合法200/null使lookupClient返回null并使getClient合成404/client_not_found；实际HTTP404/405使二者抛status=0/client_lookup_unconfirmed，不能落入旧调用方status===404登记分支；401/403、网络和5xx均不返回null，UI仍只使用lookupClient | 公共方法/旧调用方兼容单测＋缺路由/错误挂载负例 |

## 9 后续实施顺序与退出条件

本轮止于设计。若后续明确授权实施，建议按以下顺序完成同一个N1任务，不借此启动N2或原M1工作包：

1. 先独立审阅本协议：两处HTTP增量、响应元数据验证、200/null与公共404错误区分、集合PATCH字段/鉴权、ManagementClient版本配对及兼容矩阵；有变动先修订本文。
2. 实现Axum最小适配器及新旧路由/DTO断言，复用Core业务合同；确认不更改schema、旧API和通用router职责。
3. 更新ManagementClient的局部响应验证与错误映射，以及两个既有编辑器的分阶段回读状态，保留导航、确认和未知写入机制；同步新的请求与响应负例，旧fail-closed保护应在安全替代可用后移除。
4. 先运行窄范围Web/Axum检查，再按变更范围构建Web并重编译宿主，执行dot-only真实HTTP/DB/浏览器流程及必要的旧参考/嵌入/管理会话回归。live数据库仍需显式隔离配置，不使普通离线测试依赖live DB。
5. 形成N1实施验收报告及独立证据，逐项记录ID01–ID29的实际结果/复用理由/不适用；不得将核心寻址或误登记防护列为不适用。审查通过后才在交付总结追加K01/K02的已解决状态与版本，原报告保持。

退出至少要求：两类dot-only成功与拒绝路径、新旧接口/ID、挂载失败不误登记、权限隔离与事务版本、未知写入及迟到响应保护均有证据，公共合同说明同步。局部A1通过不代表N0目标矩阵A2或试点/部署A3；N2准备/执行仍需独立授权。未来实施结果的提交和推送需后续明确授权；本次文档归档见§13。

## 10 待审阅项与未决边界

| 项目 | 当前处理 |
| --- | --- |
| N1协议审阅 | 本文建议固定`/-/lookup`、显式200/null、集合PATCH及新client/服务端配对；完整设计复审及提交前核对已完成，不视为实现授权；后续若变更协议先修订设计 |
| 外部消费者清单 | 本仓库管理Web及admin子入口、参考宿主调用链已静态盘点；实际外部宿主是否占用新路径、代理方法白名单及客户端升级窗口未确认，进入其接入前需确认；不阻止本轮形成设计 |
| 发布与版本 | 不决定新的软件版本、npm分发或升级排期；未来实现须披露配对要求，不暗示已发布 |
| 其他合法ID路径限制 | `upsert`静态冲突作为本专项避免新保留词、统一查询的兼容样本；旧GET仍保持。其他实体及任意外部代理不在已解决范围 |
| N0决定 | R01浏览器家族保持；D02–D07全部继续待决，不将N1协议选择当目标环境、设备、宿主或视觉范围确认 |
| 后续能力与运行 | N2–N5和M1-03–06未启动，试点、部署、生产就绪继续待定；本设计不配置域名/数据库/Secret/代理或选硬件 |

## 11 修订1形成时的设计核对记录

本稿对照Core ID/权限/事务、两个独立管理router、通用旧router、ManagementClient、编辑器、hash导航、专项脚本及历史报告完成静态追踪。确定问题为既有K01/K02寻址限制；额外记录了由路由规则推断的`upsert`旧GET冲突及未来单段别名风险，未把它表述为本轮运行发现。

修订1形成时只新增本文和更新文档入口，未运行产品构建、测试、浏览器、数据库或部署验收，未提交、未推送；以下修订2保留原方案与本条历史语境，补齐完整复审发现的契约缺口。

## 12 修订2完整复审记录

2026-10-23，对照实际代码、N0修订2、交付总结修订2及原设计依据完成全文复审。原建议的query/JSON寻址、两段固定地址、旧路由保留及Core复用仍可行；发现并完善以下四项设计遗漏/表述偏差，不将它们当成本轮已发现并修复的产品回归：

| 编号 | 修订1遗漏 / 偏差 | 修订2处理及依据 |
| --- | --- | --- |
| N1R01 | 规定只接受200，却未交代现有请求层只返回JSON，丢失成功状态/媒体类型后的验证位置 | §4.2、§5.1/5.2、§6/9及ID28明确在原request/authenticated内部增加局部成功响应约束；依据[request实现](../web/management/client.ts)，不另起fetch，不改变旧调用默认合同 |
| N1R02 | getClient“仅null合成404”与“其他错误原样抛出”并存，使路由404仍可被旧调用方判为对象缺失 | §5.1/7及ID29明确lookup局部转换实际404/405为现有status=0＋client_lookup_unconfirmed，确认null才合成404/client_not_found；沿原[ManagementError与认证链](../web/management/client.ts)，401清理与403处理不变 |
| N1R03 | 状态表要求成功后null不能登记，但ID20只笼统写回读失败；未明确编辑器如何区别初读与写后阶段，且null表未限于客户端 | §5.3、ID20/21明确初读、saved、unknown、rejected的分阶段结果；成功后合法200/null也必须保持读取未确认。依据[客户端编辑器](../web/management/clients.tsx)当前读完成统一清blocked逻辑及[租户编辑器](../web/management/tenants.tsx)的详情/原ID恢复；属于未来N1必要状态增量，不能只替换URL |
| N1R04 | 部分断言笼统说合法ID到达“原服务”、旧“client path PATCH”，易混淆新寻址与旧路径及租户/客户端操作；原dot请求被规范到新集合入口的兼容负例不够具体 | ID01/08/23限定N1适配器、旧租户PATCH与客户端GET/upsert，补旧body缺tenant_id零写；§2.1和ID23明确通用router与独立管理router同宿主须隔离前缀。原ID及旧API不变，不宣称旧dot路径也修复 |

本轮静态复审后未发现所选方案在当前范围内仍有确定的HTTP/权限/兼容矛盾；ID01–ID29都是未来验收要求，未运行、更未通过。N0修订2和UI-A–F历史报告/JSON/截图、产品及验收代码不变；原无关工作区改动保留。文档入口同步到本修订，相对链接、范围与历史文件保全另作静态检查；复审阶段未提交、未推送，本次本地归档见§13。D02–D07继续待决，N2–N5和M1-03–06未启动，试点和部署继续待定。

## 13 提交前核对与本地归档

2026-10-23，对照实际产品基线`d4be6a5`、N0修订2（归档`b3bf292`）、交付总结修订2（原归档`d4b318e`）及既有设计/验收依据完成提交前核对。未发现阻断本次文档归档的事实偏差或契约矛盾；既有实现限制与未来HTTP/client/UI增量保持区分，K01/K02尚未通过代码实施解决。

核对覆盖query/JSON精确寻址、旧路径/方法与ID兼容、平台权限及租户目标、明确不存在与入口错误、响应状态/媒体类型、分阶段回读与未知写入，以及ID01–ID29验收要求。所有N1断言仍为待执行；未重新运行构建、产品测试、浏览器或数据库验收。文档链接、断言编号、源码/历史文件保全及暂存范围另作静态检查。

本批只归档本文和README、详细设计、交付总结的N1入口/进展更新；N0修订2、UI-A–F历史报告/JSON/截图、产品及验收源码保持原样。原有无关`docs/m1-02-code-review.md`改动不暂存、不提交，内容对象保持`4ef4907646970f1cd06ec80cf51a9516497244d6`。

本批随N1设计文档本地提交归档，不推送，不代表已实施或验收通过。D02–D07继续待决，N2–N5和M1-03–06未启动，试点和部署继续待定。
