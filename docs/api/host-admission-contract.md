# 宿主准入附加合同（S01-B）

`with_abuse_admission`是宿主选装层，参考app和两个嵌入示例当前启用。它在原库router之前处理POST/PUT/PATCH/DELETE；不替代授权、DTO、Origin、proof或CSRF。库OpenAPI描述的基础router成功响应不变；本页列出启用宿主层时附加的拒绝合同，不伪称库默认启用该层。

| 条件 | 状态/顶层code | 响应头 |
| --- | --- | --- |
| 来源/全局/账号预算耗尽 | 429 / rate_limited | Retry-After: 60，Cache-Control: no-store |
| 无可信来源、容量耗尽或adapter不可用 | 503 / temporarily_unavailable | Cache-Control: no-store |
| 指定账号路径body超过16KiB | 413 / request_too_large | Cache-Control: no-store |
| 指定账号路径body未在5秒内读完 | 408 / request_timeout | Cache-Control: no-store |
| 指定账号路径body传输读取失败 | 400 / invalid_request_body | Cache-Control: no-store |

JSON为`{"code":"...","message":"..."}`，message是非敏感说明，不返回账号/来源/剩余预算。不透出内部错误字符串。只有login/register/verify-email/resend-verification及password-recovery/start、verify路径缓冲账号body；原始字节完整交回原handler。其他写路由body限制保持原值。重复email或非法JSON不任选一个email扣额，原handler继续按原合同拒绝。

来源取TCP ConnectInfo中规范化IP，忽略端口、Forwarded和X-Forwarded-For。受信宿主可在外层middleware注入TrustedRequestSource，不能直接从任意Header构造。缺ConnectInfo的内存Router测试应显式注入类型化可信来源，不能为测试默认放行未知来源。

Global/source先扣，account在读取body后再扣；拒绝、取消或后续认证失败不退款。源码测试位于`embedded-idp-axum/src/abuse_admission.rs`，真实参考宿主定向验证位于`live_reference_host.rs::s01_host_shares_account_budget_and_bounds_slow_login_body`。单进程内存预算在重启后清空，不是持久或多副本全局限制。

## 密码工作预算附加合同（S01-A / S01-C）

密码工作预算限制同时执行的密码哈希/验证工作，不是速率窗口。Core服务可使用默认的局部预算；宿主可将同一 `PasswordWorkBudget` 注入多个支持该能力的服务，以共享在途容量。客户端密钥预算需要宿主显式使用 `BudgetedClientSecretCodec`；库默认的 `PhcClientSecretCodec` 不自动套该wrapper。因此下面的503是已启用对应预算时的条件响应，不表示每个嵌入配置都共享同一容量。

| 路由 | 条件 | 状态/响应合同 |
| --- | --- | --- |
| 普通/浏览器 `/auth/login`、`/auth/browser/login`、已启用的 `/auth/register` | 对应Core密码工作预算满载 | 503 / `temporarily_unavailable`，Cache-Control: no-store，通用message |
| Shared OIDC `/oidc/token`、`/oidc/introspect`、`/oidc/revoke` | 宿主注入预算版client-secret codec且哈希/验证预算满载 | 503 / OAuth `server_error`，Cache-Control: no-store；不带 `WWW-Authenticate` |
| Device admission既有端点 | 原有在线设备admission并发容量满载 | 继续使用既有 503 / `device_admission_busy` 合同，不改为上面的marker或错误体 |

容量按预算实例共享，通常在单进程内，不保证跨进程或重启持久。HTTP取消不会中断已经进入同步哈希/验证的工作，许可保留到实际工作退出。`docs/api/shared-oidc-openapi.json` 和普通业务OpenAPI仅描述对应端点的条件503响应；不会改变成功响应、授权规则或既有错误schema。
