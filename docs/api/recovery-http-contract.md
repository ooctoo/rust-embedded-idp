# 密码恢复 HTTP 合同

此接口是可选的账号全域密码恢复能力。它不按租户、登录入口或 browser purpose 限定账号，不要求现有 Bearer、session、device proof 或管理角色；通过 browser 路由的请求也不读取或写入 refresh Cookie。成功完成恢复会按 Core 合同退役该账号的已有凭据，不自动登录。

## 路由与启用条件

业务入口有三项 POST：

| 路径 | 请求 | 成功响应 |
| --- | --- | --- |
| `/auth/password-recovery/start` | `email`、`operation_id`、`receipt_secret` | 200 `{handle, expires_at_unix_secs}` |
| `/auth/password-recovery/complete` | `handle`、`code`、`new_password`、`operation_id`、`receipt_secret` | 200 `{completed: true}` |
| `/auth/password-recovery/result` | `operation_id`、`receipt_secret` | 200 `{completed: boolean}` |

对应 browser 路径在每项前加 `/auth/browser`。管理路由把根路径改为 `/admin/auth/password-recovery` 或 `/admin/auth/browser/password-recovery`；六项管理路径见[路由清单](route-inventory.md)，当前不属于 business OpenAPI 制品。

只有同时启用 `account_security` 与 `recovery_email` 才挂载恢复路由；旧 `business_profile` 和 `business_profile_with_account_security` 保持默认关闭。Browser 三项另要求该入口启用了 browser。宿主外部 mount prefix 由 profile 提供。

## 请求边界

请求体为严格 JSON，未知字段被拒绝，大小最多 16 KiB，读取最多 5 秒。拒绝 query 参数及 tenant/business selector headers；秘密仅放在 JSON body。`operation_id` 为规范小写非nil UUID；`receipt_secret` 为32随机字节的规范无填充 base64url 编码；handle为48字节对应的64字符无填充 base64url；验证码为6位数字。新密码按已配置账号密码策略校验，既不trim也不返回。

Browser 操作要求精确配置的 Origin 与 `x-embedded-idp-browser: 1`；存在 `Sec-Fetch-Site` 时必须为 `same-origin`。拒绝 tenant header。模块 browser guard 在模块体读取/解析和 Core 调用之前执行。若宿主使用外层匿名 admission，它可能先读取 start 的有界 body 并扣减 shared source/global/email 账号预算，再由模块检查 Origin；因此 Origin 拒绝不保证不消耗外层预算。该公开匿名预算用于防滥用，不证明认证，也不以“邮箱存在”为依据。

## 响应与错误

所有响应 `Cache-Control: no-store`，不发送或清除 `Set-Cookie`。无效 JSON/命令为 400 `invalid_request`；无效恢复凭据为 400 `invalid_recovery`；读取超时为 408 `request_timeout`；超过大小上限为 413 `request_too_large`；同一 operation ID 绑定不同命令为 409 `operation_conflict`；准入或持久恢复预算耗尽为 429 `rate_limited`。Core恢复容量/存储错误返回顶层 `{code: "security_unavailable", message: ...}`。503还可能来自准入：外层host admission沿既有合同返回顶层 `{code: "temporarily_unavailable", message: ...}`；恢复router内匿名并发许可饱和沿用既有兼容体 `{error:{code:"temporarily_unavailable"}}`。这些非正常服务容量状态与准入容量状态均为固定非敏感响应，不透露数据库错误、邮箱、账号/flow是否存在或秘密内容。

Start 对可恢复、未知及无资格邮箱返回同形状结果。成功只确认请求已登记，不代表邮件已发送或账号存在；同一命令可恢复同一有效开始收据。没有独立 start-result。Result 返回 `completed=false` 只表示当前没有可确认的完成收据，不能证明原命令没有提交，也不能作为更换 operation ID 重试的依据。

`business-openapi.json`描述条件 business/browser 操作，不代表任意宿主均已挂载或提供恢复邮件。HTTP局部与profile测试不是完整部署、邮件供应商或生产验收证据。
