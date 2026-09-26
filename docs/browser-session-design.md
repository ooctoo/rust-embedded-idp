# 浏览器会话与 Cookie 恢复设计

日期：2026-09-26。范围：可选浏览器接入；原显式令牌及设备证明接口保留。本文是本期新增能力的契约，实施与验收结果在文末记录。

## 1. 目标与本期范围

登录、完成租户选择及续期成功后，刷新令牌仅通过 HttpOnly Cookie 返回，JSON 不包含 refresh_token。访问令牌仅保存在客户端实例内存。页面重载后显式调用 restore()，使用 Cookie 轮换获得新的访问令牌；不新增独立的服务器浏览器会话表。

支持 disabled（业务域 0）、enabled + fixed、enabled + choose_after_authentication。只有创建正式租户会话后才写 Cookie；选择票据仍是短期、内存中的一次性凭证，不能调用业务 API。平台管理域 0 不是所有租户权限。

本期浏览器接入只支持同源。每个应用入口、每种用途（业务/管理）只有一个当前浏览器会话；支持多个标签页共享该会话，不支持多个标签页同时工作于不同业务租户。此限制属于 Web 接入层，不进入 Core 的会话数量或租户规则。管理和业务可同时登录。不同宿主入口需使用不同 Cookie 名称及相应外部路径，不能仅靠端口隔离 Cookie。

不支持跨站第三方 Cookie、设备绑定浏览器恢复、统一跨应用 SSO、新增长期浏览器会话或放宽刷新重用检测。设备绑定会话必须继续验证原证明，不能降级使用本期无设备证明入口。

## 2. 分层与配置

- Core：新增浏览器会话服务契约，复用登录/选租户、严格刷新轮换、会话撤销事务。刷新与退出支持完整的预期会话断言（tenant_id/account_id/session_id/client_id）；断言不授予权限。用途、入口客户端、固定租户策略、账号/成员/租户/会话有效性仍由服务端验证。
- Axum：独立的 browser 路由、Cookie 读取/写入、同源与 CSRF 请求校验、去掉刷新凭证的响应投影；不访问数据库。构造时确认服务用途与路由用途一致。
- 宿主：注入可信 public_origin、Cookie 名称、含外层前缀的 Cookie Path、Secure 策略。生产必须 HTTPS；仅显式 loopback HTTP 开发配置允许非 Secure。不得根据不可信 Host/X-Forwarded-* 自动放宽来源。
- React：显式 cookie 模式，restore()、同源请求、跨标签页锁与失效通知。默认显式令牌模式保持兼容。独立管理页面与无租户宿主示例接入 cookie 模式。
- PostgreSQL：复用 auth_sessions/refresh_tokens 及现有索引，无新表、迁移和分页变更。

## 3. HTTP 契约

业务路由在 `/auth/browser`，管理路由在 `/admin/auth/browser`；宿主可添加外层前缀。管理参考宿主为 `/api/admin/auth/browser`。原 capabilities、租户列表、begin-switch、session 以及业务/管理 API 仍使用原入口与 Bearer/选择票据。

| 方法与后缀 | 输入 | 成功结果 |
| --- | --- | --- |
| POST `/login` | JSON email/password | authenticated 或 tenant_selection_required；正式会话才设置 Cookie |
| POST `/tenant-selection/complete` | TenantSelection 头 + JSON tenant_id | authenticated + 新租户会话 Cookie |
| POST `/restore` | JSON `{}` 或 `{expected_session: ...}` | 从 Cookie 严格轮换，返回当前会话和访问令牌 |
| POST `/refresh` | JSON `{expected_session: ...}` | 同 restore；客户端续期始终传完整原会话断言 |
| POST `/logout` | JSON `{}` 或 `{expected_session: ...}` | 撤销 Cookie 对应的当前无设备会话及刷新令牌族，204 并清 Cookie |

完整 expected_session 是 tenant_id、account_id、session_id、client_id 四个字符串。无脚本凭证时允许 restore/logout 不带断言；已建立上下文时必须发送断言。原始刷新令牌不允许作为这些 JSON 请求的字段；拒绝未知/重复字段和不支持的 Content-Type。普通 API 不接受 Cookie 作为访问凭证。

成功 JSON 保持现有 `status/session/tokens` 结构，tokens 仅包含 access_token、access_expires_at_unix_secs、refresh_expires_at_unix_secs。租户选择结果保持现有票据结构。所有响应（含提取器错误）禁止缓存。

无 Cookie、过期/撤销/失效凭证：401；已确认刷新重用：401 并保持现有整族撤销；预期会话不匹配：409 `browser_session_changed`，不轮换、不撤销、不清除新 Cookie；来源或 CSRF 拒绝：403 且不设置 Cookie；存储/签名故障：5xx，不伪装为已退出。无 Cookie 或已无效会话退出可幂等成功；无法确认服务端撤销时不能对用户声称退出成功。

登录或租户切换替换浏览器 Cookie，不自动撤销其他既有 Core 会话；原有会话寿命/管理员撤销规则继续适用。失去浏览器引用的旧会话不会由 restore 隐式找回。

## 4. Cookie 与请求安全

Cookie 为 host-only（不设置 Domain），HttpOnly、SameSite=Strict；Secure 由已验证的 HTTPS/loopback 开发配置确定；Path 与该 browser 路由的外部路径一致，不能依赖 Path 作为授权边界。Max-Age 为剩余刷新凭证寿命，且受服务端原始会话期限限制。删除时沿用相同名称与路径，Max-Age=0。Cookie 值严格限于安全的令牌字符，拒绝同名重复 Cookie，避免代理与解析器分歧。

所有 browser POST 要求 Origin 与宿主配置的源精确一致、`X-Embedded-Idp-Browser: 1`、JSON 请求；缺失/null/多个 Origin 拒绝。Sec-Fetch-Site 若存在，只允许 same-origin。不给跨源请求开放这些端点的凭证 CORS。自定义头要求预检，来源校验不能仅由 CORS 或 SameSite 替代。登录同样防 CSRF，避免登录身份替换。HttpOnly 不等于防 XSS；宿主仍需自身内容安全措施。

管理和业务使用不同 Cookie 名称/路径、不同锁与通知命名空间、不同 Core 用途校验。把业务 Cookie 放到管理 Cookie 名称下仍不能恢复管理身份。Cookie、令牌、密码和票据不进入 URL、日志、localStorage、sessionStorage 或跨标签页广播。

## 5. 事务、退出和设备边界

轮换继续在现有事务中锁定状态、租户、账号、会话、刷新记录；核对完整预期会话必须早于轮换及重用撤销。成功提交后才发 Set-Cookie；旧令牌再次使用仍触发严格重用检测，不加宽限期。

Cookie 退出不依赖未过期的访问令牌。Core 通过刷新凭证定位并验证用途/客户端/固定租户及当前刷新版本，撤销精确会话及刷新族；不能借退出操作撤销其他租户或管理会话。无效令牌退出无副作用；存储错误向上传播。设备绑定或强制设备证明入口拒绝本期浏览器操作。

刷新提交与 HTTP 响应交付不可能原子化。响应丢失、网络超时后不重放旧凭证；客户端将该入口标记为需要重新登录，并通知其他标签页。不以无限重试或放松重用检测掩盖不确定状态。

## 6. React 与多标签页协议

提供显式 cookie 模式及 restore()，access token 仅在内存；浏览器请求使用 same-origin。默认令牌模式现有调用保持兼容。cookie 模式要求 Web Locks 和可用的本地非敏感协调存储；不支持时给出明确错误，不退化成无锁 Cookie 刷新。

同源、同入口、同用途的登录/完成选择/恢复/续期/退出通过同一 Web Lock 串行执行。localStorage 只保存随机变更版本和“需要重新登录”等协调状态，不含凭证。storage 事件通知会话替换或退出；每次取访问令牌与操作会话前亦主动检查版本，覆盖后台标签页漏收通知。

成功轮换不更换会话版本标记，各标签页依次使用浏览器最新 Cookie；初次恢复不覆盖已存在的其他标签页上下文。登录、完成选择、退出以及不确定的刷新结果更新标记，其他实例清除内存身份和租户数据，提示重新加载。已登录实例续期带 expected_session，出现 409 时停止旧上下文，不能静默接收其他账号/租户的令牌。已有 revision 保护仍阻止退出后迟到的响应恢复页面身份。

切换期间当前页面暂停业务操作；其他标签页收到变更后暂停旧上下文。SDK 必须向宿主提供状态变化，宿主根据会话标识清除列表、选中项及请求缓存。SDK 无法收回已交给宿主的 Bearer 或已经在服务端执行的业务请求；后端资源授权始终核对可信 tenant 和资源归属。不得宣称前端通知等于服务端撤销旧会话。

## 7. 验证与交付顺序

先完成本文并同步宿主/React/安全文档，再实施 Core 契约、HTTP 适配、客户端协调及参考宿主接入，最后跨文档复核。

必须验证：

- 登录/选租户/恢复/续期 JSON 不暴露刷新令牌，Set-Cookie 属性、期限、路径、清除正确。
- 过期、已撤销、成员移除、租户停用不可恢复；重用仍撤销精确刷新族。
- expected_session 不匹配无轮换/撤销副作用；管理业务互换、错误客户端/固定租户失败。
- 访问令牌过期或页面未恢复时可退出；退出与刷新并发、响应丢失、重复退出行为明确。
- 同一会话多个标签页串行恢复/续期；切租户/换账号使旧标签页失效，不静默串租户；管理业务不互相登出。
- Origin 缺失/错误/null、CSRF 头缺失、错误内容类型、重复 Cookie 被拒绝。
- 设备绑定和 proof-required 不降级；原 token 客户端和设备接口回归通过。
- Web 类型/构建/客户端测试、Rust fmt/check/test；有显式测试数据库连接时运行真实 PostgreSQL 测试。浏览器真实验收与离线模拟测试分别记录，不互相替代。

## 8. 实施与验证记录

已完成 Core、Axum、React、参考管理宿主与无租户业务示例接入；原显式令牌和设备证明入口保留。新分支最初基于 origin/main 的 88aa7cf，推送前已更新到 6873c7f（管理列表排序）；原工作区改动未混入本分支。

验证记录（2026-09-26）：

- `pnpm --dir web test`：77 项客户端协议、并发协调、恢复、退出竞态及路径规范化测试通过。
- `pnpm --dir web build`、`pnpm --dir web test:embedded-bundle`、`./examples/no-tenant-host/run.sh build-web`：类型、构建、嵌入包及示例通过；管理 bundle 仍有现有的大包警告。
- `cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo test --workspace --locked`：通过。
- 使用原工作区的显式 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI`，真实 PostgreSQL 的 7 组存储/认证测试（107 项）及离线管理员初始化测试（2 项）通过；真实参考宿主 3 项测试通过，包括本次新增的 disabled/enabled Cookie 恢复、身份断言409、业务/管理隔离、退出和重用撤销。测试仅创建并清理随机 schema，未修改应用 schema。
- 真实应用内浏览器以合成身份服务运行同源多文档检查：恢复、HttpOnly、并发轮换、租户替换后旧页面失效、退出传播通过。它验证浏览器 Cookie/Web Locks/storage 行为，不等同于真实数据库后端加管理页面的完整多标签页端到端验收。

仍需部署环境验收：实际 HTTPS 反向代理、完整管理/业务页面多标签页操作、各目标浏览器兼容性。Web Locks/存储不可用时 Cookie 模式明确失败；不会自动降级成无锁续期。跨站与多租户同时打开均不在本期范围。
