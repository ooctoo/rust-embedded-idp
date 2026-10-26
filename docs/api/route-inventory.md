# 当前 HTTP 路由清单（A03 第二批基线）

核对范围：修订4技术设计 §6、实施方案 §4.4；Axum crate 的公开 router、reference app 的条件装配、no-tenant-host 示例。路径均为模块/应用内路径。Axum crate 导出的 router 不添加外层前缀；嵌入方负责 mount/nest 和反向代理前缀。`RouteMountPlan`用于生成外部路径，不会自动改写已返回 router。Reference app 直接装配时采用下表实际路径；管理 API 可按配置前缀 nest，管理 UI 使用独立配置前缀。

这是路由清单，不是 OpenAPI/schema 全集。响应常见为 JSON；流式、静态字节和重定向另行标明。状态码列为源码可观察的主要结果，不穷举所有 service error、extractor rejection、method-not-allowed 和中间件错误。JSON body 的字段/schema 尚未完整盘点。

## 装配与条件

| Router / 所有者 | 装配条件与组合 | 源码 |
| --- | --- | --- |
| `embedded-idp-axum::router` | 合并 public、subject、token、client-authenticated、admin API；是通用组合 router，不包含 tenant 专用 router、management auth、browser session、scan router 或静态 UI | [`lib.rs`](../../crates/embedded-idp-axum/src/lib.rs) |
| 按认证用途导出的 `public_router`、`subject_router`、`token_router`、`client_authenticated_router`、`admin_router` | 嵌入方可单独装配；其边界由函数名/服务认证逻辑表达，不自动套参考宿主的管理认证 | [`lib.rs`](../../crates/embedded-idp-axum/src/lib.rs) |
| 租户路由族 | 由宿主显式 merge。LegacyReference 配置 `reference_business` 时装配完整业务协议；v1 `business_entries` 按入口前缀装配普通认证/refresh/logout/self-roles、可选browser及显式注册，不暴露OIDC/device/scan。`Enabled` tenancy 还受各 service / `TenancyMode` 策略约束 | [`bootstrap.rs`](../../crates/embedded-idp-app/src/bootstrap.rs) |
| Management auth/API | Reference app 根据管理配置装配；API 在 auth middleware 下。启用 tenancy 且策略为 `ChooseAfterAuthentication` 时才加租户选择三路由。管理 API 可嵌套至配置 `mount_prefix` | [`management_auth.rs`](../../crates/embedded-idp-axum/src/management_auth.rs), [`bootstrap.rs`](../../crates/embedded-idp-app/src/bootstrap.rs) |
| Management UI | 有 UI base path 且编译嵌入资源时装配；独立前缀，根页、带斜杠页、重定向和带hash的资产路径 | [`admin_ui.rs`](../../crates/embedded-idp-app/src/admin_ui.rs), [`build.rs`](../../crates/embedded-idp-app/build.rs) |
| Scan login | Reference app 设置 scan_login 时才 nest browser、UI、device 三组路由；service/host context 缺失不挂载 | [`bootstrap.rs`](../../crates/embedded-idp-app/src/bootstrap.rs), [`device_scan_login.rs`](../../crates/embedded-idp-axum/src/device_scan_login.rs), [`scan_ui.rs`](../../crates/embedded-idp-app/src/scan_ui.rs) |
| Health | Reference app always；no-tenant-host 自行提供 `/healthz` | [`bootstrap.rs`](../../crates/embedded-idp-app/src/bootstrap.rs), [example main.rs](../../examples/no-tenant-host/src/main.rs) |

## Axum core router

公共路径的 body limit 由 `AUTH_DEVICE_BODY_LIMIT_BYTES`（16 KiB）设定；subject/token子router也使用该上限；旧单域client-authenticated router未设置该layer，Form沿Axum默认限制及宿主层配置。受限请求超限由 Axum 以 413 拒绝。Json/Form extractor 按 handler 声明工作；以响应投影为准，不能据此认定已有完整 schema。

| 方法与路径 | 用途 / 凭证 | Body / 主要状态 | 来源 |
| --- | --- | --- | --- |
| POST `/auth/register` | 注册；公开，registration service/policy 可拒绝 | JSON；202/服务错误 | [`lib.rs`](../../crates/embedded-idp-axum/src/lib.rs) |
| POST `/auth/verify-email` | 邮箱验证；公开 | JSON；200/验证错误 | 同上 |
| POST `/auth/resend-verification` | 重发验证；公开 | JSON；202/服务错误 | 同上 |
| POST `/auth/login` | 单域登录；公开凭证交换 | JSON；200 或认证错误 | 同上 |
| POST `/devices/provision`, `/device-proof/challenges`, `/devices/complete`, `/devices/heartbeat` | 单域设备配置/证明挑战/完成/心跳；proof/device 身份按流程校验，proof headers/body签名规则见 `proof_http.rs`；不是无认证写入 | JSON，受16 KiB限制；201/200/认证或状态错误 | [`lib.rs`](../../crates/embedded-idp-axum/src/lib.rs), [`proof_http.rs`](../../crates/embedded-idp-axum/src/proof_http.rs) |
| POST `/oidc/token` | 单域 OIDC token exchange；客户端认证按 grant/client 类型 | Form（application/x-www-form-urlencoded）；200/协议错误 | [`lib.rs`](../../crates/embedded-idp-axum/src/lib.rs) |
| GET `/.well-known/openid-configuration`, `/oidc/jwks` | discovery/JWKS；公开 | JSON；200；reference app 在 JWKS 返回 ETag 与 `Cache-Control: public, max-age=300` | [`lib.rs`](../../crates/embedded-idp-axum/src/lib.rs), [`bootstrap.rs`](../../crates/embedded-idp-app/src/bootstrap.rs) |
| GET `/devices`, `/devices/:device_id` | 单域设备读取；subject router，需认证主体 | JSON；200/401/403/404 | [`lib.rs`](../../crates/embedded-idp-axum/src/lib.rs) |
| POST `/devices/bind`, `/devices/unbind`, `/devices/rotate-key` | 单域设备账号绑定/解绑/密钥轮换；需认证主体及服务端授权 | JSON；200/状态错误 | 同上 |
| GET `/oidc/authorize` | 单域 OIDC authorize；须宿主注入AuthenticatedSubject，客户端/redirect/PKCE 由服务验证，成功时重定向至登记的 redirect URI | query；307/协议错误 | 同上 |
| POST `/auth/refresh`, `/auth/logout` | 刷新与退出；refresh/logout token；proof-bound 配置可要求设备证明 | JSON；200/认证错误 | 同上 |
| GET/POST `/oidc/userinfo` | Bearer userinfo；GET与POST均注册 | 仅读取Bearer，不提取query/body；200/401/403 | 同上 |
| POST `/oidc/revoke`, `/oidc/introspect` | OIDC client-authenticated revoke/introspection | Form（application/x-www-form-urlencoded）；200 或客户端认证错误 | 同上 |

## 租户认证、注册与用户自助

| 方法与路径 | 装配/认证 | Body、结果与来源 |
| --- | --- | --- |
| POST `/auth/login` | `tenant_auth_router`；匿名凭证登录，proof要求由 entry policy决定 | JSON；200/认证拒绝；[`tenant_auth.rs`](../../crates/embedded-idp-axum/src/tenant_auth.rs) |
| GET `/auth/access/capabilities`, `/auth/session` | tenant auth router；capabilities公开，session需Bearer access token | JSON；200/401；同上 |
| GET `/auth/tenant-selection/tenants`, POST `/auth/me/tenant-selection` | 仅Enabled + `ChooseAfterAuthentication`；列表使用selection ticket，切换使用Bearer session | GET无body，切换POST不提取body；200/认证错误；同上 |
| POST `/auth/tenant-selection/complete` | 普通tenant_auth在Enabled + Choose时注册；tenant_device_auth替代普通router并提供proof-aware完成，配置只绑定外部签名路径，不控制是否挂载 | JSON，设备分支按会话策略要求proof；200/拒绝；[`tenant_device_auth.rs`](../../crates/embedded-idp-axum/src/tenant_device_auth.rs) |
| POST `/auth/register`, `/auth/verify-email`, `/auth/resend-verification` | `tenant_registration_router`显式装配；公开，受租户注册策略限制 | JSON；注册/重发202，验证200；拒绝按错误映射；[`tenant_registration.rs`](../../crates/embedded-idp-axum/src/tenant_registration.rs) |
| GET `/auth/me/roles` | `tenant_self_router`；需认证subject和access service | JSON；200/401/拒绝；[`tenant_self.rs`](../../crates/embedded-idp-axum/src/tenant_self.rs) |

## Tenant devices 与 device-auth

`tenant_device_router` 和 `tenant_device_auth_router` 是不同 router；业务自助路由不会自动获得 proof challenge。Reference app 提供二者并以 service/config决定能力；示例宿主单独 merge device-auth router。设备写入需可信 admission/provider及适用的证明流程，列表/详情/operation读取须当前租户主体授权。

| 方法与路径 | 用途 | 来源 |
| --- | --- | --- |
| POST `/auth/login`, `/auth/refresh`, `/devices/proof/challenges` | tenant device-auth登录、普通及设备绑定刷新、challenge；同时复用capabilities/session/Choose列表与切换路由，不可再整体merge tenant_auth_router | [`tenant_device_auth.rs`](../../crates/embedded-idp-axum/src/tenant_device_auth.rs) |
| POST `/auth/tenant-selection/complete` | 仅Enabled + Choose时注册；proof-aware选择完成 | 同上 |
| POST `/devices/provision`, `/devices/registration-result`, `/devices/complete`, `/devices/rotate-key`, `/devices/unbind`, `/devices/heartbeat` | 租户设备注册/回执/完成/轮换/解绑/心跳；JSON；provision/result需可信admission；complete需登记公钥proof；rotate需本人身份和双签；unbind需本人身份/版本；heartbeat按设备proof合同 | [`tenant_devices.rs`](../../crates/embedded-idp-axum/src/tenant_devices.rs) |
| GET `/devices`, `/devices/:device_id`, `/devices/:device_id/keys/:key_id`, `/devices/operations/:operation_id` | 本租户设备、密钥元数据与操作结果读取；Bearer subject及租户范围 | 同上 |

第四批 B2 JSON v2 device-enabled entry有独立[设备合同](device-openapi.json)，不扩大原17项普通合同：host以显式device配置选择该路由族，device-auth替代同一入口普通`/auth/login`和`/auth/refresh`，不得同时merge以免路由冲突；Choose选择路由由Tenancy配置决定。设备proof头可选或按entry/session策略要求，存在时以原始请求字节、HTTP method、含嵌入host prefix的外部path、tenant和audience做proof校验；合同profile为现有`EMBEDDED-IDP-DEVICE-AUTH-V2`及`EMBEDDED-IDP-DEVICE-REQUEST-V2`。共享OIDC仍按B1全局只装配一次；只有显式启用device-bound OIDC的entry才向exchange启用真实proof能力。`x-embedded-idp-device-admission`为宿主签发的短期私有grant，仅provision/registration-result使用，不作为业务token或URL参数；host每次请求重新校验，服务端registration记录按tenant/client/scope/request_id寻址。registration scope必须保持稳定；entry_id不在B2 grant或Core admission上下文中，当前只可用于SDK本地target/journal隔离。完全相同的provision请求在相同scope/request_id下幂等，改动字段会冲突；registration-result须用同scope重新授权读取。`/devices/complete`不使用admission或Bearer，原子消费一次性challenge并完成登记，重复提交旧signature不幂等，未知响应后重新授权查询registration-result。`/devices/proof/challenges`返回HTTP 200不证明challenge已存入，也不证明登记可以完成。 `/devices/rotate-key`要求当前人员及active本人binding；旧/新key共同签署`DEVICE-KEY-ROTATION-V2`规范消息，expected key id/version执行CAS，单次rotation challenge、密钥切换及审计在Core事务内完成。没有idempotency key或操作receipt；未知结果结合相同binding、设备当前proof-key指针和key元数据恢复，不能把单个历史metadata当回执。

## 租户 OIDC

| 方法与路径 | 用途 / 认证 | Body / 响应 / 来源 |
| --- | --- | --- |
| GET `/oidc/authorize` | authorization endpoint；必须恰有一个 Authorization Bearer access token，且租户上下文需匹配；service校验client/redirect/PKCE | query；成功307；[`tenant_oidc_authorization.rs`](../../crates/embedded-idp-axum/src/tenant_oidc_authorization.rs) |
| POST `/oidc/token` | token endpoint；Form body，client认证可Basic或form字段；设备绑定code按策略校验proof，非绑定code不强制proof | `application/x-www-form-urlencoded`；200/协议错误；同上 |
| GET `/oidc/userinfo` | Bearer access token | 无body；JSON或协议错误；[`tenant_oidc_resource.rs`](../../crates/embedded-idp-axum/src/tenant_oidc_resource.rs) |
| POST `/oidc/introspect`, `/oidc/revoke` | client-authenticated；Form body，凭证可Basic或form字段 | `application/x-www-form-urlencoded`；协议响应；同上 |
| POST `/auth/logout` | Form body；client/session认证及精确撤销 | `application/x-www-form-urlencoded`；200/协议错误；同上 |

## Management auth 与管理 API

以下`admin_api.rs`四类旧单域路由本身不验证管理Bearer，也没有自动租户/purpose隔离；必须由宿主提供管理鉴权边界。它们不用于当前reference host。其余细粒度租户管理router要求宿主注入受信`AccessAdminContext`，reference host通过`management_router`验证Bearer后注入；不能把单独merge这些router当作已接通JWT认证。

`management_router` 把已装好的管理 API 套 `authenticate_management` Bearer middleware 后 merge 登录面；management auth自身端点不受该保护路由层约束。auth响应加 no-store。细粒度管理API body使用JSON，列表参数使用query；management auth为16 KiB；role/permission admin为64 KiB，account/security-admin/client/tenant/device/session/binding admin及access diagnostic为16 KiB；无本地layer的读取路由沿宿主限制。主要输出JSON，成功常见200，创建201，错误由service映射。

| 路由族及路径 | 方法 | 认证 / 主要语义 | 来源 |
| --- | --- | --- | --- |
| `/admin/auth/capabilities`, `/admin/auth/session` | GET | capabilities公开；session需已有管理认证凭证 | [`management_auth.rs`](../../crates/embedded-idp-axum/src/management_auth.rs) |
| `/admin/auth/login`, `/admin/auth/refresh`, `/admin/auth/logout` | POST | 登录匿名；refresh/logout使用管理凭证/refresh凭证 | 同上 |
| `/admin/auth/tenant-selection/tenants` GET；`/admin/auth/tenant-selection/complete`, `/admin/auth/me/tenant-selection` POST | 如左列 | 仅Enabled + ChooseAfterAuthentication | 同上 |
| `/admin/accounts`, `/admin/accounts/:account_id` | GET；collection另有POST创建 | 旧单域：宿主负责管理鉴权 | [`admin_api.rs`](../../crates/embedded-idp-axum/src/admin_api.rs) |
| `/admin/accounts/activate`, `/admin/accounts/disable`, `/admin/accounts/set-password`, `/admin/accounts/revoke-sessions` | POST | 旧单域：宿主负责管理鉴权 | 同上 |
| `/admin/sessions`, `/admin/sessions/:session_id` | GET；`/admin/sessions/revoke` POST | 旧单域：宿主负责管理鉴权 | 同上 |
| `/admin/clients`, `/admin/clients/:client_id` | GET；`/admin/clients/upsert` POST | 旧单域：宿主负责管理鉴权；路径来自`http_paths.rs` | 同上 |
| `/admin/devices`, `/admin/devices/:device_id` | GET；`/admin/devices/unbind`, `/admin/devices/disable`, `/admin/devices/revoke` POST | 旧单域：宿主负责管理鉴权 | 同上 |
| `/admin/access/roles` | GET, POST；`/admin/access/roles/:role_id` GET, PATCH, DELETE；`/admin/access/roles/:role_id/permissions` GET, PUT；`/admin/access/business-admin` GET, POST | 管理Bearer；body JSON；主要200/201/错误 | [`role_admin.rs`](../../crates/embedded-idp-axum/src/role_admin.rs) |
| `/admin/access/permissions` GET, POST；`/admin/access/permissions/:resource_type/:action` GET, PATCH, DELETE；`/admin/access/permissions/:resource_type/:action/enabled` POST；`/admin/platform/permissions` GET | 如左列 | 管理Bearer；body JSON | [`permission_admin.rs`](../../crates/embedded-idp-axum/src/permission_admin.rs) |
| `/admin/access/subjects/:subject_id/role-bindings` | GET, POST；`/admin/access/role-bindings/:binding_id` DELETE | 管理Bearer；body JSON | [`role_binding_admin.rs`](../../crates/embedded-idp-axum/src/role_binding_admin.rs) |
| `/admin/access/audit-events`, `/admin/platform/audit-events` | GET；详情为`/admin/access/audit-events/:id`及`/admin/platform/audit-events/:id` | 管理Bearer | [`audit_admin.rs`](../../crates/embedded-idp-axum/src/audit_admin.rs) |
| `/admin/access/check` | POST | 管理Bearer；权限诊断 | [`access_diagnostic.rs`](../../crates/embedded-idp-axum/src/access_diagnostic.rs) |
| `/admin/access/security-admins/:subject_id` | GET, POST, DELETE；`/admin/platform/security-admins/:subject_id` GET, POST, DELETE | 管理Bearer；tenant/platform安全管理员关系 | [`security_admin.rs`](../../crates/embedded-idp-axum/src/security_admin.rs) |
| `/admin/platform/accounts` | POST；`/admin/platform/accounts/:account_id/status` POST；`/admin/platform/accounts/:account_id/password` POST | 管理Bearer；平台账户管理 | [`account_security_admin.rs`](../../crates/embedded-idp-axum/src/account_security_admin.rs) |
| `/admin/tenants` | GET, POST, PATCH；`/admin/tenants/:tenant_id` GET, PATCH | 管理Bearer；仅Enabled装配；collection PATCH通过body tenant_id定位更新 | [`tenant_management_admin.rs`](../../crates/embedded-idp-axum/src/tenant_management_admin.rs) |
| `/admin/members/:account_id/status`, `/admin/members/:account_id/bind` POST；`/admin/platform/accounts`, `/admin/platform/accounts/:account_id` GET | 如左列 | 管理Bearer；members写入仅Enabled | [`account_admin.rs`](../../crates/embedded-idp-axum/src/account_admin.rs), [`account_security_admin.rs`](../../crates/embedded-idp-axum/src/account_security_admin.rs) |
| `/admin/devices` GET；`/admin/devices/:device_id` GET；`/admin/devices/:device_id/keys/:key_id` GET；`/admin/devices/:device_id/operations/:operation_id` GET；`/admin/devices/:device_id/bindings/:binding_id` GET；`/admin/devices/:device_id/enable` POST；`/admin/devices/:device_id/disable` POST；`/admin/devices/:device_id/revoke` POST；`/admin/devices/:device_id/bindings` GET；`/admin/devices/:device_id/bindings/:binding_id/unbind` POST | 如左列 | 管理Bearer；租户设备管理 | [`tenant_device_admin.rs`](../../crates/embedded-idp-axum/src/tenant_device_admin.rs) |
| `/admin/sessions`, `/admin/sessions/:session_id` | GET；`/admin/sessions/:session_id/revoke` POST；`/admin/accounts/:account_id/sessions/revoke` POST | 管理Bearer | [`tenant_session_admin.rs`](../../crates/embedded-idp-axum/src/tenant_session_admin.rs) |
| `/admin/clients` GET; `/admin/clients/-/lookup` GET; `/admin/clients/:client_id` GET; `/admin/clients/upsert` POST | 如左列 | 管理Bearer；另一个 client-admin router，与 core admin-api同前缀，实际 reference host仅在相应管理装配分支选用其一 | [`client_admin.rs`](../../crates/embedded-idp-axum/src/client_admin.rs), [`bootstrap.rs`](../../crates/embedded-idp-app/src/bootstrap.rs) |

> 管理 API 中仍有按tenancy mode生成的条件路由及router替代关系。`bootstrap.rs` 的具体merge选择是运行时依据；`account_admin` 与 `account_security_admin` 在 `/admin/platform/accounts` 分别提供只读与写操作，GET/POST方法互补，参考宿主实际共同合并；client管理实现也有 `admin_api` 与 `client_admin` 两套，不得假定可同时合并。各route模块的 `.route()` 清单已按方法和路径列出；此处不声称 DTO schema 全覆盖。

## Browser session

`browser_session_router`按purpose固定root为`/auth/browser`或`/admin/auth/browser`，宿主可加外层前缀，JSON请求/响应，浏览器cookie承载refresh/session流程；CSRF、来源检查及cookie属性依 `BrowserSessionHttpConfig`。五条均为POST，具体路径为 `{root}/login`, `{root}/tenant-selection/complete`, `{root}/restore`, `{root}/refresh`, `{root}/logout`，见 [`browser_session.rs`](../../crates/embedded-idp-axum/src/browser_session.rs)。租户reference使用 `/auth/browser`，management browser session可在相应配置启用时 merge到management routes。

## Scan login

以下路径在 scan router 自身是相对路径；reference host nest后外部路径如下。协议调用均POST JSON，UI与资产为GET。browser操作由绑定的浏览器session/CSRF与origin规则保护；device操作使用设备凭据/proof/host context。主要返回JSON；exchange/recover/ack/abort的结果与幂等状态按service合同。

| 相对路径 | Reference host路径 | 来源 |
| --- | --- | --- |
| `/context`, `/phone-codes`, `/attach`, `/inspect`, `/approve`, `/deny`, `/cancel`, `/status` | `/auth/browser/device-scan`加左列各完整相对路径 | [`device_scan_login.rs`](../../crates/embedded-idp-axum/src/device_scan_login.rs) |
| `/create`, `/claim`, `/status`, `/lookup`, `/cancel`, `/exchange`, `/recover`, `/acknowledge`, `/abort`, `/close-origin` | `/auth/device-scan`加左列各完整相对路径 | 同上及 [`bootstrap.rs`](../../crates/embedded-idp-app/src/bootstrap.rs) |
| UI `/`, `/assets/:asset` | `/auth/browser/device-scan/ui/`及`/auth/browser/device-scan/ui/assets/:asset` | [`scan_ui.rs`](../../crates/embedded-idp-app/src/scan_ui.rs) |

独立[scan-openapi.json](scan-openapi.json)覆盖以上18个POST JSON操作；`scan_profile(browser_prefix, device_prefix)`为browser和device操作分别设置宿主前缀。DTO为严格字段对象，body上限16 KiB，响应`Cache-Control: no-store`。browser guard联合要求精确Origin、固定`x-embedded-idp-browser: 1`，并拒绝tenant header；device proof使用`EMBEDDED-IDP-DEVICE-SCAN-V2`，签名绑定proof字段、原始body、POST、外部路径、tenant与audience，并追加 unpadded base64url 的`scan-context-sha256`。该值是`EMBEDDED-IDP-SCAN-CONTEXT-V1`域分隔符与长度前缀编码的`purpose_str`、可信`target_client_id`、`entry_id`的SHA-256；后三者来自host路由配置，不是请求值。create/claim遇到未知响应时以原始operation_id和相同请求重试；lookup的`scan_not_found` 404不是终态，客户端保留原始action、operation_id及delivery secret继续恢复。exchange/recover固定issuance_operation_id，响应可为进度或Pending bundle；acknowledge只回进度，`delivery_state=acknowledged`表示目标session已激活。abort返回409 `already_acknowledged`表示ACK已先提交，应保留bundle/session并查询或recover；close-origin的`already_activated`也表示已激活且不执行logout。UI与静态资源不属于JSON API合同。

## 探针、静态资源、redirect与宿主示例

| 方法/路径 | 行为 | 来源 |
| --- | --- | --- |
| GET `/healthz` | JSON `{"status":"ok"}`，活性探针，不代表DB readiness | [`bootstrap.rs`](../../crates/embedded-idp-app/src/bootstrap.rs), [example main.rs](../../examples/no-tenant-host/src/main.rs) |
| GET `/readyz` | Reference app检查数据库/catalog准备情况；失败返回服务不可用 | [`bootstrap.rs`](../../crates/embedded-idp-app/src/bootstrap.rs) |
| GET management UI base及规范末尾斜线路径（根配置仅`/`） | 根路径可能308到规范末尾斜线；提供嵌入管理HTML | [`admin_ui.rs`](../../crates/embedded-idp-app/src/admin_ui.rs) |
| GET management UI `{asset_prefix}/*path` | 仅编译嵌入的静态文件；带hash文件可缓存；缺失404 | 同上 |
| GET scan UI `/`、`/assets/:asset` | 编译嵌入scan UI和manifest资产；缺失404 | [`scan_ui.rs`](../../crates/embedded-idp-app/src/scan_ui.rs) |
| GET `/`、`/assets/:name`, `/api/reports/:id` | no-tenant-host示例页面、静态示例资产和受业务认证保护的报告读取；不是IDP library router | [`main.rs`](../../examples/no-tenant-host/src/main.rs), [`reports.rs`](../../examples/no-tenant-host/src/reports.rs) |

## A01 第一批历史边界

A01 管理 client 显式准备仅涉及现有管理 client API/CLI 的准备流程；第一批当时没有新HTTP endpoint，也没有新增路由族。A03 第一批仅提供路由盘点，未安装 utoipa、未生成OpenAPI；第二批现已增加普通业务合同，见下节及[合同说明](README.md)。后续其他模块schema批次须逐个对照本清单、handler DTO、`Json`/`Form`/query提取器、动态 `json!` 响应和内容类型，再标注已建模/未建模；状态码、鉴权逻辑、proof精确字节、cookie/CSRF语义需人工合同检查。

租户认证/注册/设备、OIDC、browser及scan路由请求上限为16 KiB（`proof_http.rs`常量），本人roles为GET且没有单独body-limit layer。写接口的no-store由相应router/handler添加；分页读取的tenant/client/business与cursor由各service校验，不能由裸资源ID推断授权。本人roles要求business_id；租户管理查询的tenant_id是目标范围，不是认证身份来源。

## 第一批复审更正（2026-10-25）

核实实际常量后，将auth/device/OIDC/browser/scan上限从误写的64 KiB更正为16 KiB；role/permission管理仍为独立64 KiB。明确旧单域admin路由不自带Bearer验证、tenant_device_auth包含公共认证读路由且支持普通刷新、Choose路由按mode/policy而非路径配置启用。设备绑定OIDC code才要求proof；注册/重发成功状态为202，邮箱验证为200。源码路由声明、常量、handler提取器和reference/example装配联合核对；清单不等同完整schema或运行验收。

## A02A 新入口与 A03 合同覆盖

[生成合同](business-openapi.json) 的唯一源码为 `crates/embedded-idp-axum/src/openapi.rs`，通过可选 `openapi` feature 使用 utoipa 生成。该文件覆盖以下 17 项普通业务操作；历史管理、device、OIDC、scan 等仍以以上完整路由清单为准，未声称历史全量 schema 已交付。`business_profile` 过滤 Fixed/Choose、browser、registration 条件，server URL 表示宿主 mount_prefix，模块 path 不硬编码外层前缀。每个入口的 Cookie 名由配置替换合同占位符。

| 方法/路径 | 权威 HTTP 实现 / 条件 |
| --- | --- |
| POST `/auth/refresh` | `tenant_refresh.rs` → 与 device-auth 共用响应映射；普通 refresh，拒绝设备证明/tenant header；raw_json超限为JSON 413，媒体类型不支持为空415 |
| POST `/auth/logout` | `tenant_oidc_resource.rs::tenant_logout_router`；Form/Basic client，复用原 resource logout 实现；空200 |
| POST `/auth/login`, GET `/auth/access/capabilities`, GET `/auth/session` | `tenant_auth.rs`，所有普通入口 |
| GET `/auth/tenant-selection/tenants`, POST `/auth/me/tenant-selection`, POST `/auth/tenant-selection/complete` | `tenant_auth.rs`，仅 Enabled+Choose |
| GET `/auth/me/roles` | `tenant_self.rs`，Bearer，business_id必填，cursor绑定tenant/business/subject；next_cursor始终存在、可null |
| POST `/auth/browser/login`, `/auth/browser/tenant-selection/complete`, `/auth/browser/restore`, `/auth/browser/refresh`, `/auth/browser/logout` | `browser_session.rs`，browser启用时全部挂载；Fixed的browser选择路由存在但服务拒绝选择 |
| POST `/auth/register`, `/auth/verify-email`, `/auth/resend-verification` | `tenant_registration.rs`，显式注册开关、Fixed策略及邮件依赖 |

新router不会隐式提供OIDC资源接口、challenge或设备管理接口。普通refresh的reuse结果在Core提交撤销后映射401；logout只撤销凭证对应会话/refresh family。Browser JSON没有refresh_token；Cookie/Origin/固定请求头是联合要求，Sec-Fetch-Site若出现必须same-origin。

检查命令：`./scripts/check_api_contracts.sh`。它比对确定性生成物，并执行唯一operationId、schema引用、清单覆盖、profile条件及真实Axum响应（状态、Content-Type、no-store、DTO与错误）检查；本批真实宿主生命周期/隔离测试另见第二批实施记录。

A03复审补充：roles/tenant列表的Query提取失败是text/plain 400；登录不允许tenant header。正常browser模式无Cookie退出204，受限development_login模式仍先要求expected_session。合同局部测试覆盖17项成功响应的递归schema、全部有效条件组合的实际挂载及代表提取器/安全失败，不把fixture HTTP投影当作Core事务或真实宿主隔离验收。

## A02B-B1 共享 OIDC 合同

[共享 OIDC 合同](shared-oidc-openapi.json) 与普通入口合同分开：新 v2 `business_entries[].oidc.enabled=true` 至少出现一项时，宿主只装配一次共享 `/oidc/*` 与 `/.well-known/openid-configuration`。authorize/token 复用租户 OIDC 授权处理器，userinfo/introspect/revoke 使用仅三项的 `tenant_oidc_protocol_resource_router`；不合并旧 resource router 所带的 `/auth/logout`。这七项包括 GET authorize（Bearer、S256）、POST token（authorization_code form）、GET userinfo、POST introspect/revoke、GET discovery/JWKS。v1 拒绝 `oidc` 配置字段，普通 `business_document()` 仍仅描述原17项。共享发现元数据不暴露设备端点；legacy/reference OIDC 路由语义仍按前文历史清单保留。

## A04-A 前端消费（2026-10-26）

`EmbeddedDeviceClient`/`DeviceSelfService`消费现有device合同的五个本人操作：GET /devices、GET /devices/:device_id、GET /devices/:device_id/keys/:key_id、POST /devices/unbind、GET /devices/operations/:operation_id。认证和入口沿用同一个EmbeddedIdentityClient的内存Bearer、base、transport及revision；不新增HTTP路由，不改变管理接口。前端intent绑定入口对象和tenant/account/client；现有服务端本人receipt按tenant/account/operation ID查询，不宣称新增client隔离。详见[A04-A设计](../a04-a-technical-design.md)。

## A05 Enabled 示例宿主（非IdP库路由）

`examples/tenant-host` 在 `/fixed` 和 `/choose` 下分别组合普通 Fixed tenant-a 与 Choose auth/refresh/logout/self/browser，固定入口不暴露选租户路由。模块本地根路径未改。每个入口另挂 `GET /api/reports` 和 `GET /api/reports/:id`，由宿主完成真实身份/精确授权和双列资源查询；列表受40候选预算及绑定scope/filter的签名游标约束。详情未授权403，授权后缺失404。示例有 `/`、`/fixed`、`/choose`、`/assets/:name`、`/example-config`、`/healthz`；可选 `/management` UI与 `/control/admin/auth/*`、`/control/admin/access/permissions*`、`/control/admin/platform/permissions`。管理router只组合权限目录，目录使用独立Management Bearer，Cookie仅用于认证生命周期。

独立[示例合同](../../examples/tenant-host/api-contract.json)与 `scripts/check_tenant_host_contract.mjs`核对路由/query/响应字段和预算；已加入check_api_contracts.sh。它不扩充IdP business-openapi.json；真实响应和安全行为由示例限定live测试覆盖。
