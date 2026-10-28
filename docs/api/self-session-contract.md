# S03-A1 本人会话查询 HTTP 合同

此合同对应只读会话查询，不代表宿主已自动挂载。业务两项路由纳入 `business-openapi.json`；management 路由当前没有生成完整OpenAPI schema，仅在本合同和 route inventory 中记录。

## 路由与身份

| 方法 / 路径 | 身份来源 | 请求 |
| --- | --- | --- |
| GET `/auth/security/sessions` | 唯一 `Authorization: Bearer <token>`，由注入的 `TenantAuthenticationService` 验证业务 purpose、entry 与 audience | Query仅接受可选 `limit`、`cursor` |
| GET `/admin/auth/security/sessions` | 唯一 Bearer，由注入的 `ManagementAuthenticationService` 验证management purpose、entry 与 audience | Query仅接受可选 `limit`、`cursor` |
| POST `/auth/browser/security/sessions` | 配置的 HttpOnly refresh Cookie，经专用 `SelfSecurityBrowserIdentityService` 只读验证 | 严格JSON，含必需 `expected` identity |
| POST `/admin/auth/browser/security/sessions` | 配置的management HttpOnly refresh Cookie，经management专用身份服务只读验证 | 严格JSON，含必需 `expected` identity |

Bearer请求拒绝重复Authorization；可选 `x-embedded-idp-tenant-id` 必须与验证actor tenant一致，并拒绝 `x-embedded-idp-business-id`。Browser请求要求精确匹配配置的Origin和唯一 `x-embedded-idp-browser: 1`；若带 `Sec-Fetch-Site`，其值必须为 `same-origin`。Browser请求拒绝tenant/business选择头。

四条路由的 actor 都必须是本人账号当前有效的第一方 session，即数据库中该精确actor session的 `scope IS NULL`。OIDC授权码派生的 `scope=Some` session不能授权全局本人安全查询。结果仍可列出同一账号的委托scope会话。Session只读身份验证不调用refresh/rotate，也不向响应暴露Cookie或token。Browser身份服务的purpose和restricted lifetime必须分别与 `BrowserSessionHttpConfig` 完全相同。

## 分页与响应

GET query和Browser JSON可选 `limit`，范围1..50，默认50。可选 `cursor` 是最多1024字符的base64url无padding JSON，版本为1，字段为 `subject_id`、`tenant_id`、规范小写UUID `session_id`。Cursor绑定当前subject；格式/版本/主体不符返回400。Query和JSON均拒绝未知字段。

成功响应为 `{"items":[...],"next_cursor":...}`。`next_cursor` 始终存在，可为null。每个item严格包含：

- `tenant_id`, `session_id`, `client_id`：字符串。
- `purpose`：`business` 或 `management`。
- `device_id`：字符串或null。
- `created_at`, `expires_at`：非负Unix秒整数。
- `status`：`active` 或 `expired`。仅数据库active会话进入列表；已过期时间投影为`expired`，数据库revoked/pending不列出。
- `current`：布尔值，标记发起此查询的确切会话。

响应不含scope、refresh token/version、账号邮箱或可选的安全秘密。所有成功和失败响应均带 `Cache-Control: no-store`。

## 错误和请求限制

Bearer无效/actor失效为401。Invalid limit、cursor、未知query/JSON字段为400；Browser Origin/固定头/跨站检查失败为403。Browser JSON上限16384 bytes；超限为413，unsupported media type为415，JSON提取错误按Axum extractor返回。服务错误为500。状态码与错误正文中的敏感输入、Bearer和Cookie均不得回显。提取器拒绝响应也应由外层no-store middleware覆盖。

## 实际接线边界

`business_document()`描述业务Bearer与browser两项。management两项不会伪装成已生成schema。库router需要embedding host显式合并到相应业务/management/browser entry；参考宿主接线与真实HTTP验证另行记录。本只读切片不启用session revoke/password change，也不代表安全页UI完成。

会话撤销的Core/PG能力见[独立合同](self-session-revocation-contract.md)，现由显式配置可选挂载独立HTTP路径；本页只读路径不隐含写操作。
