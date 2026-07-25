# Developer and Integration Guide

本文档面向两类读者：

- 项目开发者：在本地构建、启动、调试和测试 `rust-embedded-idp`。
- 项目使用方：把模块嵌入 Rust/Axum 宿主，或调用 standalone 服务提供的 HTTP API。

本文档以当前代码为准。项目仍处于 `v0.1.0` 阶段，`embedded-idp-app`
是开发和集成参考宿主，不是可直接投入生产的身份平台。

## 1. 项目能力与结构

Cargo workspace 包含五个 crate：

| Crate | 职责 |
| --- | --- |
| `embedded-idp-core` | 账号、密码、Session、Token、OIDC、设备和管理服务的领域模型与业务逻辑 |
| `embedded-idp-email` | 邮件发送抽象和验证码邮件内容组装 |
| `embedded-idp-axum` | HTTP DTO、错误映射和可拆分挂载的 Axum Router |
| `embedded-idp-storage-postgres` | PostgreSQL 存储实现、连接配置和 migration |
| `embedded-idp-app` | 可运行的参考宿主，负责环境变量、服务装配、管理 UI 和开发安全适配器 |

当前提供：

- 本地账号注册、邮箱验证码、密码登录、Refresh Token 轮换和退出登录。
- OAuth/OIDC Authorization Code Flow，支持 PKCE `plain` 和 `S256`。
- Public desktop client 和 confidential web client。
- OIDC Discovery、JWKS、UserInfo、Token Revocation 和 Token Introspection。
- 设备 provision、proof completion、heartbeat、账号绑定、解绑、查询、禁用和撤销。
- 账号、Session、OIDC Client 和设备的管理员 API。
- React 管理后台。
- PostgreSQL migration 和持久化。
- `log`、`sendmail`、`smtp` 三种验证码邮件投递方式。
- 按安全边界拆分的 Axum Router，允许宿主选择性挂载。

## 2. 开发者：本地环境

### 2.1 前置依赖

- Stable Rust toolchain
- Node.js 22 或更高版本
- pnpm 10.30.1
- PostgreSQL
- 可选：Docker，用于快速启动 PostgreSQL
- 可选：`curl`，用于 smoke test 和接口调试

检查版本：

```bash
rustc --version
cargo --version
node --version
pnpm --version
```

### 2.2 安装依赖并构建

在仓库根目录执行：

```bash
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
```

必须先构建 `web`。`embedded-idp-app` 使用 `include_str!` 在 Rust
编译期嵌入 `web/dist` 中的 HTML、CSS 和 JavaScript，而生成文件不提交到 Git。

### 2.3 启动 PostgreSQL

已有 PostgreSQL 时，只需创建一个应用账号可连接的数据库。

使用 Docker 的示例：

```bash
docker run \
  --name embedded-idp-postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  -d postgres:16-alpine
```

应用启动时会：

1. 连接 PostgreSQL。
2. 创建配置的 schema。
3. 执行 migration。
4. 创建或更新默认 public desktop client。
5. 如果配置了 confidential client，则一并创建或更新。

### 2.4 创建本地配置

```bash
cp .env.example .env
```

Docker PostgreSQL 对应的最小配置示例：

```bash
EMBEDDED_IDP_APP_PG_URI=postgres://postgres:postgres@127.0.0.1:5432/postgres
EMBEDDED_IDP_TEST_PG_CONNECTION_URI=postgres://postgres:postgres@127.0.0.1:5432/postgres
EMBEDDED_IDP_APP_ADMIN_API_KEY=dev-admin-key
```

`.env` 会被启动和测试脚本作为 Bash 配置文件加载。包含空格或 shell
特殊字符的值必须正确引用；不要提交 `.env`。

### 2.5 启动 standalone 服务

```bash
./scripts/run_embedded_idp_app.sh
```

默认地址：

| 资源 | 地址 |
| --- | --- |
| 管理后台 | `http://127.0.0.1:9100/` |
| 健康检查 | `http://127.0.0.1:9100/healthz` |
| OIDC Discovery | `http://127.0.0.1:9100/.well-known/openid-configuration` |
| 管理 API | `http://127.0.0.1:9100/api/admin/*` |

验证健康状态：

```bash
curl -fsS http://127.0.0.1:9100/healthz
```

预期响应：

```json
{"status":"ok"}
```

### 2.6 前端开发

生产静态资源构建：

```bash
pnpm --dir web build
```

Vite 开发服务器：

```bash
pnpm --dir web dev
```

Vite 默认监听 `http://127.0.0.1:4178`。当前 Vite 配置没有 `/api`
反向代理，因此完整管理功能联调应优先使用 Rust standalone 服务嵌入的构建产物。

### 2.7 测试

前端类型检查和构建：

```bash
pnpm --dir web build
```

Rust 格式和编译检查：

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
```

不依赖真实数据库的常规测试：

```bash
cargo test --workspace
```

真实 PostgreSQL 集成测试：

```bash
./scripts/run_live_postgres_checks.sh
```

该脚本要求设置 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI`。测试会为每个
harness 创建唯一 schema，并在结束时尝试删除，不应指向缺少建表和删表权限的数据库账号。

服务启动后的 smoke test：

```bash
./scripts/smoke_test_embedded_idp_app.sh
```

它会检查：

- 管理 UI HTML。
- 管理 UI 静态 JavaScript。
- 未携带 Admin Key 时管理 API 返回 `401`。
- 配置 Admin Key 后管理 API 返回 `200`。

## 3. Standalone 配置参考

### 3.1 Server

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `EMBEDDED_IDP_APP_BIND_ADDR` | `127.0.0.1:9100` | Axum 监听地址，格式为 `host:port` |
| `EMBEDDED_IDP_APP_ISSUER` | `http://<bind_addr>` | OIDC issuer 和公开端点基地址 |
| `EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH` | `/` | 管理 UI 基础路径 |
| `EMBEDDED_IDP_APP_ADMIN_API_KEY` | 未设置 | 管理 API Key；未设置时 standalone 不挂载管理 API |

Issuer 必须以 `https://`、`http://localhost` 或 `http://127.0.0.1`
开头。监听地址可以使用 `0.0.0.0`，但 issuer 不能使用
`http://0.0.0.0`。

`EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH=/admin` 时：

- UI：`/admin/`
- 静态文件：`/admin/static/*`
- 管理 API 仍为 `/api/admin/*`

### 3.2 PostgreSQL

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `EMBEDDED_IDP_APP_PG_URI` | `postgres://127.0.0.1:5432/postgres` | PostgreSQL URI，支持 `postgres://` 和 `postgresql://` |
| `EMBEDDED_IDP_APP_PG_SCHEMA` | `embedded_idp` | 模块表所在 schema |
| `EMBEDDED_IDP_APP_PG_TLS_MODE` | `prefer` | `disable`、`prefer` 或 `require` |
| `EMBEDDED_IDP_APP_PG_TLS_CA_CERT_PATH` | 未设置 | `require` 模式下额外信任的 PEM CA 文件 |
| `EMBEDDED_IDP_APP_PG_APP_NAME` | `embedded-idp-app` | PostgreSQL session application name |
| `EMBEDDED_IDP_APP_PG_MAX_CONNECTIONS` | `10` | 最大连接数，必须大于 0 |
| `EMBEDDED_IDP_APP_PG_CONNECT_TIMEOUT_SECS` | `5` | 连接超时秒数，必须大于 0 |

Schema 名只允许 ASCII 小写字母、数字和下划线。当前 `prefer`
行为与 `disable` 相同，不会自动回退到 TLS；生产环境应使用 `require`。

### 3.3 Auth 和密码策略

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `EMBEDDED_IDP_APP_ALLOW_LOCAL_REGISTRATION` | `true` | 是否允许 `/auth/register` |
| `EMBEDDED_IDP_APP_ACCESS_TOKEN_TTL_SECS` | `900` | Access Token TTL |
| `EMBEDDED_IDP_APP_REFRESH_TOKEN_TTL_SECS` | `86400` | Refresh Token TTL |
| `EMBEDDED_IDP_APP_SESSION_TTL_SECS` | `604800` | Session TTL |
| `EMBEDDED_IDP_APP_VERIFICATION_CODE_TTL_SECS` | `900` | 邮箱验证码 TTL，最大 3600 秒 |
| `EMBEDDED_IDP_APP_PASSWORD_MIN_LENGTH` | `8` | 密码最小字符数 |
| `EMBEDDED_IDP_APP_PASSWORD_MAX_LENGTH` | `128` | 密码最大字符数 |

约束：

- Access Token TTL 必须大于 0。
- Refresh Token TTL 必须大于 Access Token TTL。
- Session TTL 必须大于等于 Refresh Token TTL。
- 验证码 TTL 必须为 `1..=3600`。
- 密码最小长度必须大于 0，最大长度不能小于最小长度。
- 密码还必须至少包含一个 ASCII 字母和一个 ASCII 数字；这两项当前不可配置。

Boolean 配置接受：

- 真：`true`、`TRUE`、`1`、`yes`、`YES`
- 假：`false`、`FALSE`、`0`、`no`、`NO`

### 3.4 验证邮件

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `EMBEDDED_IDP_APP_EMAIL_DELIVERY_MODE` | `log` | `log`、`sendmail` 或 `smtp` |
| `EMBEDDED_IDP_APP_EMAIL_SENDMAIL_COMMAND` | `/usr/sbin/sendmail` | sendmail 兼容程序路径 |
| `EMBEDDED_IDP_APP_EMAIL_FROM` | `embedded-idp@localhost.localdomain` | From 邮箱 |
| `EMBEDDED_IDP_APP_EMAIL_FROM_NAME` | 未设置 | From 展示名称 |
| `EMBEDDED_IDP_APP_EMAIL_VERIFICATION_SUBJECT` | `Your embedded IDP verification code` | 验证邮件主题 |
| `EMBEDDED_IDP_APP_EMAIL_SMTP_HOST` | `localhost` | SMTP 主机 |
| `EMBEDDED_IDP_APP_EMAIL_SMTP_PORT` | `587` | SMTP 端口 |
| `EMBEDDED_IDP_APP_EMAIL_SMTP_TLS_MODE` | `starttls` | `starttls`、`implicit_tls` 或 `plain` |
| `EMBEDDED_IDP_APP_EMAIL_SMTP_USERNAME` | 未设置 | SMTP 用户名 |
| `EMBEDDED_IDP_APP_EMAIL_SMTP_PASSWORD` | 未设置 | SMTP 密码 |

SMTP 用户名和密码只有同时存在时才启用认证。只设置其中一个会退化为匿名 SMTP，
因此部署时应把二者作为一组 Secret 管理。

### 3.5 Device 和 OIDC

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `EMBEDDED_IDP_APP_DEVICE_NONCE_TTL_SECS` | `300` | Device registration challenge TTL |
| `EMBEDDED_IDP_APP_DEVICE_PROOF_CLOCK_SKEW_SECS` | `30` | Device Proof 允许的时间偏差 |
| `EMBEDDED_IDP_APP_DEVICE_HEARTBEAT_GRACE_PERIOD_SECS` | `60` | Device heartbeat 宽限时间 |
| `EMBEDDED_IDP_APP_AUTHORIZATION_CODE_TTL_SECS` | `300` | Authorization Code TTL，最大 600 秒 |
| `EMBEDDED_IDP_APP_REQUIRE_PKCE_FOR_PUBLIC_CLIENTS` | `true` | Public client 是否强制 PKCE |

Heartbeat 宽限时间不能小于 Proof 时钟偏差。

### 3.6 启动时预置 Client

Public desktop client：

| 环境变量 | 默认值 |
| --- | --- |
| `EMBEDDED_IDP_APP_PUBLIC_CLIENT_ID` | `desktop-app` |
| `EMBEDDED_IDP_APP_PUBLIC_CLIENT_NAME` | `Embedded IdP Desktop App` |
| `EMBEDDED_IDP_APP_PUBLIC_REDIRECT_URI` | `http://127.0.0.1:43821/callback` |

可选 confidential web client：

| 环境变量 | 默认值 |
| --- | --- |
| `EMBEDDED_IDP_APP_CONFIDENTIAL_CLIENT_ID` | 未设置 |
| `EMBEDDED_IDP_APP_CONFIDENTIAL_CLIENT_NAME` | `Embedded IdP Web App` |
| `EMBEDDED_IDP_APP_CONFIDENTIAL_REDIRECT_URI` | `https://example.com/callback` |
| `EMBEDDED_IDP_APP_CONFIDENTIAL_CLIENT_SECRET` | 未设置 |

`CONFIDENTIAL_CLIENT_ID` 和 `CONFIDENTIAL_CLIENT_SECRET` 必须同时设置。
Raw secret 仅用于 seed，数据库保存 Argon2id PHC hash。

### 3.7 开发和测试

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `EMBEDDED_IDP_APP_DEV_SUBJECT_HEADER` | `x-embedded-idp-account-id` | standalone 将该 Header 转为 `AuthenticatedSubject` |
| `EMBEDDED_IDP_TEST_PG_CONNECTION_URI` | 未设置 | 真实 PostgreSQL 集成测试 URI |

`DEV_SUBJECT_HEADER` 只适用于本地开发。生产宿主必须从可信登录态或 Session
构造 `AuthenticatedSubject`，不能相信调用方提交的账号 Header。

## 4. 使用方：部署和接入模式

### 4.1 Standalone 模式

适合：

- 本地开发。
- 模块验收。
- 受控的内部集成环境。

特点：

- HTTP 服务、PostgreSQL、开发 Token 实现和管理 UI 已装配。
- 管理 API 外部路径为 `/api/admin/*`。
- Subject-bound 路由通过开发 Header 模拟登录用户。

### 4.2 嵌入 Axum 宿主

宿主负责：

1. 构造 `EmbeddedIdpConfig` 和 `PgStorageConfig`。
2. 创建 `PostgresStorageAdapter` 并执行 migration。
3. 组装 Core Service。
4. 实现生产级 Token、ID Token、Access Token 校验和 Device Proof 校验。
5. 为不同 Router 添加对应的安全中间件。
6. 决定模块挂载在根路径、`/api/v1` 或其他前缀。

可拆分 Router：

| Router | 路由类别 |
| --- | --- |
| `public_router` | 注册、验证、登录、设备 provision/completion/heartbeat、Token、JWKS、Discovery |
| `subject_router` | Authorize，以及当前用户的设备查询、绑定和解绑 |
| `token_router` | Refresh、Logout、UserInfo |
| `client_authenticated_router` | Revocation、Introspection |
| `admin_router` | 账号、Session、Client、设备管理员 API |

示意：

```rust
let app = Router::new()
    .merge(public_router(state.clone()))
    .merge(
        subject_router(state.clone())
            .route_layer(middleware::from_fn(inject_authenticated_subject)),
    )
    .merge(token_router(state.clone()))
    .merge(client_authenticated_router(state.clone()))
    .merge(
        admin_router(state)
            .route_layer(middleware::from_fn(require_operator)),
    );
```

宿主必须提供或选择：

- `TokenIssuer`
- `IdTokenIssuer`
- `AccessTokenValidator`
- `ClientSecretVerifier`
- `DeviceProofVerifier`
- `VerificationEmailService`
- `AuthenticatedSubject` 注入中间件
- `OidcMetadataService` 和实际 JWKS

完整装配示例可运行：

```bash
cargo run -p embedded-idp-axum --example host_integration
```

## 5. HTTP 通用约定

以下路径均为模块根路径。Standalone 的管理员路径额外增加 `/api` 前缀。

### 5.1 请求格式

- Auth、Device、Admin 请求：`application/json`
- `/oidc/token`、`/oidc/revoke`、`/oidc/introspect`：
  `application/x-www-form-urlencoded`
- `/oidc/authorize`：URL Query
- 所有 `*_unix_secs` 字段：Unix epoch 秒
- ID 在 HTTP/Rust 边界视为不透明字符串；默认实现生成带前缀的 UUIDv7 风格 ID

### 5.2 鉴权类别

| 类别 | 说明 |
| --- | --- |
| Public | 不需要已登录账号上下文 |
| Subject-bound | 宿主必须注入可信 `AuthenticatedSubject` |
| Token-bound | 请求携带 Refresh Token，或 `Authorization: Bearer <access_token>` |
| Client-authenticated | Confidential client 必须提交并验证 `client_secret` |
| Admin | Standalone 使用 `x-embedded-idp-admin-key`；嵌入模式由宿主保护 |

Standalone Subject-bound 请求示例：

```bash
curl \
  -H 'x-embedded-idp-account-id: <account_id>' \
  http://127.0.0.1:9100/devices
```

Standalone Admin 请求示例：

```bash
curl \
  -H 'x-embedded-idp-admin-key: dev-admin-key' \
  http://127.0.0.1:9100/api/admin/accounts
```

### 5.3 错误响应

服务错误统一返回：

```json
{
  "code": "invalid_contract",
  "message": "Password must include at least one letter."
}
```

常见错误码：

| HTTP | `code` |
| --- | --- |
| 400 | `invalid_contract`、`redirect_uri_mismatch`、`unsupported_response_type`、`unsupported_grant_type`、`pkce_required` |
| 401 | `invalid_credentials`、`invalid_token`、`invalid_verification_code`、`invalid_code_verifier`、`invalid_client_authentication` |
| 403 | `registration_disabled`、`account_pending_verification`、`account_disabled`、`device_disabled` |
| 404 | `account_not_found`、`client_not_found`、`session_not_found`、`device_not_found` |
| 409 | `email_already_exists`、`device_client_mismatch`、`device_registration_state_invalid` |
| 422 | `invalid_client_config` |
| 500 | `internal_error` |

Axum 自身拒绝无法解析的 JSON、Form 或 Query 时，响应不一定使用上述业务错误结构。

## 6. Auth API

### 6.1 注册账号

`POST /auth/register`，Public，JSON。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `email` | 是 | 合法邮箱，必须唯一 |
| `password` | 是 | 满足配置的长度，并包含字母和数字 |
| `display_name` | 否 | 展示名称 |
| `client_id` | 是 | 已配置的 OIDC Client |
| `device_id` | 否 | Active 且属于相同 `client_id` 的设备 |

成功返回 `202 Accepted`：

```json
{
  "account_id": "<account_id>",
  "account_status": "pending_verification",
  "verification_channel": "email",
  "verification_expires_at_unix_secs": 1700000900,
  "delivery_status": "sent"
}
```

`delivery_status=failed` 表示账号和验证码已经创建，但邮件发送失败。

### 6.2 验证邮箱

`POST /auth/verify-email`，Public，JSON。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `email` | 是 | 注册邮箱 |
| `verification_code` | 是 | 最新且未过期的验证码 |
| `client_id` | 是 | 创建 Session 的 Client |
| `device_id` | 否 | 可选关联设备 |

成功返回 `200` 和 Auth 响应。

### 6.3 重发验证码

`POST /auth/resend-verification`，Public，JSON。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `email` | 是 | 处于 `pending_verification` 的账号邮箱 |

成功返回 `202`，响应结构与注册相同。

### 6.4 登录

`POST /auth/login`，Public，JSON。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `email` | 是 | Active 账号邮箱 |
| `password` | 是 | 登录密码 |
| `client_id` | 是 | 已配置 Client |
| `device_id` | 否 | 可选 Active 设备，必须属于相同 Client |

成功返回 `200`：

```json
{
  "account_id": "<account_id>",
  "session_id": "<session_id>",
  "device_id": null,
  "access_token": "<access_token>",
  "refresh_token": "<refresh_token>",
  "refresh_token_version": 0
}
```

### 6.5 Refresh Token 轮换

`POST /auth/refresh`，Token-bound，JSON。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `refresh_token` | 是 | 当前有效 Refresh Token |
| `rotated_at_unix_secs` | 是 | 本次轮换时间 |

成功返回新的 Auth 响应并增加 `refresh_token_version`。旧 Refresh Token
随即失效。

### 6.6 退出登录

`POST /auth/logout`，Token-bound，JSON。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `refresh_token` | 是 | 当前 Session 的 Refresh Token |
| `logged_out_at_unix_secs` | 是 | 退出时间 |

成功返回 `200`。响应沿用 Auth 响应结构，但
`access_token` 和 `refresh_token` 为空字符串；Session 和相关 Refresh Token 已撤销。

## 7. Device API

### 7.1 Provision

`POST /devices/provision`，Public，JSON。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `client_id` | 是 | 设备所属 Client |
| `device_name` | 是 | 设备展示名称 |
| `requested_at_unix_secs` | 是 | 请求时间 |

返回 `201`：

```json
{
  "device": {
    "device_id": "<device_id>",
    "client_id": "desktop-app",
    "status": "pending"
  },
  "challenge": "<nonce>",
  "expires_at_unix_secs": 1700000300
}
```

### 7.2 Complete registration

`POST /devices/complete`，Public，JSON。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `device_id` | 是 | Pending device |
| `proof_key_id` | 是 | Device Proof key 标识 |
| `proof_challenge` | 是 | Provision 返回的 challenge |
| `proof_signature` | 是 | Challenge 签名 |
| `proof_signed_at_unix_secs` | 是 | 签名时间 |
| `completed_at_unix_secs` | 是 | 完成时间 |

成功返回 `200` 和状态为 `active` 的 Device。

### 7.3 Heartbeat

`POST /devices/heartbeat`，Public，JSON。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `device_id` | 是 | Active device |
| `observed_at_unix_secs` | 是 | 服务观察时间 |

成功返回更新后的 Device。

### 7.4 绑定、查询和解绑

这些接口均为 Subject-bound：

| 接口 | 参数 | 返回 |
| --- | --- | --- |
| `POST /devices/bind` | JSON：`device_id`、`bound_at_unix_secs` | Device binding |
| `GET /devices` | 无 | 当前 Subject 的 Device 列表 |
| `GET /devices/:device_id` | Path：`device_id` | Device 和当前 Subject 的 active bindings |
| `POST /devices/unbind` | JSON：`device_id`、`unbound_at_unix_secs` | 更新后的 binding |

调用方不能在 body 中选择 `account_id`；账号范围来自可信
`AuthenticatedSubject`。

设备禁用和撤销只通过 Admin API 提供，不存在 Public 或 Subject-bound
的 `/devices/disable`、`/devices/revoke`。

## 8. OIDC API

### 8.1 Authorization

`GET /oidc/authorize`，Subject-bound，Query。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `response_type` | 是 | 当前只支持 `code` |
| `client_id` | 是 | OIDC Client |
| `redirect_uri` | 是 | 必须与 Client 注册值完全匹配 |
| `scope` | 否 | 空格分隔 scope；包含 `openid` 时交换阶段可返回 ID Token |
| `state` | 否 | 原样返回给 callback |
| `code_challenge` | Public client 通常必填 | PKCE challenge |
| `code_challenge_method` | 与 challenge 配套 | `plain` 或 `S256` |
| `nonce` | 否 | ID Token nonce |

成功返回 `307 Temporary Redirect`：

```text
<redirect_uri>?code=<authorization_code>&state=<state>
```

### 8.2 Token

`POST /oidc/token`，Form。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `grant_type` | 是 | 当前只支持 `authorization_code` |
| `code` | 是 | Authorization Code |
| `redirect_uri` | 是 | 必须与 authorize 请求一致 |
| `client_id` | 是 | Client |
| `client_secret` | Confidential client 必填 | Client Secret |
| `code_verifier` | 使用 PKCE 时必填 | PKCE verifier |

示例：

```bash
curl -X POST http://127.0.0.1:9100/oidc/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'code=<code>' \
  --data-urlencode 'redirect_uri=http://127.0.0.1:43821/callback' \
  --data-urlencode 'client_id=desktop-app' \
  --data-urlencode 'code_verifier=<verifier>'
```

成功响应：

```json
{
  "access_token": "<access_token>",
  "refresh_token": "<refresh_token>",
  "refresh_token_version": 0,
  "token_type": "Bearer",
  "id_token": "<optional_id_token>",
  "scope": "openid profile email",
  "subject_account_id": "<account_id>"
}
```

当前响应没有 `expires_in`；使用方应依据宿主配置管理 TTL。

### 8.3 UserInfo

`GET` 或 `POST /oidc/userinfo`，Token-bound。

```http
Authorization: Bearer <access_token>
```

成功响应：

```json
{
  "sub": "<account_id>",
  "email": "user@example.com",
  "name": "User"
}
```

### 8.4 Revocation

`POST /oidc/revoke`，Client-authenticated，Form。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `token` | 是 | 待撤销 Token |
| `token_type_hint` | 否 | `access_token` 或 `refresh_token` |
| `client_id` | 是 | Token 所属 Client |
| `client_secret` | Confidential client 必填 | Client Secret |
| `revoked_at_unix_secs` | 是 | 撤销时间 |

成功返回 `200`，响应 body 为空。

### 8.5 Introspection

`POST /oidc/introspect`，Client-authenticated，Form。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `token` | 是 | 待检查 Token |
| `token_type_hint` | 否 | `access_token` 或 `refresh_token` |
| `client_id` | 是 | 调用 Client |
| `client_secret` | Confidential client 必填 | Client Secret |

响应字段：

| 字段 | 说明 |
| --- | --- |
| `active` | Token 当前是否有效 |
| `sub` | 账号 ID，inactive 时可能省略 |
| `client_id` | Token Client |
| `scope` | Scope |
| `token_type` | Token 类型 |
| `sid` | Session ID |
| `exp` | 过期 Unix 秒 |
| `iat` | 签发 Unix 秒 |

### 8.6 JWKS 和 Discovery

- `GET /oidc/jwks.json`
- `GET /.well-known/openid-configuration`

Discovery 只公布实际存在的非管理员接口。设备禁用和撤销属于管理员操作，
不会出现在 Discovery 中。

## 9. Admin API

### 9.1 路径和鉴权

模块本地路径为 `/admin/*`。Standalone 将整个 Admin Router nest 到
`/api`，因此外部路径为 `/api/admin/*`。

Standalone 请求必须携带：

```http
x-embedded-idp-admin-key: <EMBEDDED_IDP_APP_ADMIN_API_KEY>
```

未配置 `EMBEDDED_IDP_APP_ADMIN_API_KEY` 时，standalone 不挂载 Admin Router，
请求会得到 `404`，而不是 `401`。

### 9.2 分页

列表默认：

- `limit=50`
- `offset=0`
- 最大 `limit=200`

列表响应中的 `page`：

```json
{
  "limit": 50,
  "offset": 0,
  "returned": 20,
  "total": 120,
  "has_more": true,
  "next_cursor": "1700000000:<entity_id>"
}
```

账号、Session 和设备支持 `cursor=<unix_secs>:<entity_id>`。使用 cursor
时 `offset` 必须为 `0`。Client 列表当前只支持 offset 分页。

### 9.3 账号管理

| 方法和路径 | 参数 | 响应 |
| --- | --- | --- |
| `GET /admin/accounts` | Query：`status`、`email`、`created_after_unix_secs`、`created_before_unix_secs`、`cursor`、`limit`、`offset` | `accounts` + `page` |
| `POST /admin/accounts` | JSON：`email`、`password`、可选 `display_name` | `201` Account |
| `GET /admin/accounts/:account_id` | Path：`account_id` | Account |
| `POST /admin/accounts/activate` | JSON：`account_id` | Account |
| `POST /admin/accounts/disable` | JSON：`account_id` | Account |
| `POST /admin/accounts/set-password` | JSON：`account_id`、`new_password` | Account |
| `POST /admin/accounts/revoke-sessions` | JSON：`account_id`、`revoked_at_unix_secs` | 被撤销的 `sessions` + `page` |

`status` 支持：`pending_verification`、`active`、`disabled`。

### 9.4 Session 管理

| 方法和路径 | 参数 | 响应 |
| --- | --- | --- |
| `GET /admin/sessions` | Query：`account_id`、`status`、`client_id`、`device_id`、`created_after_unix_secs`、`created_before_unix_secs`、`cursor`、`limit`、`offset` | `sessions` + `page` |
| `GET /admin/sessions/:session_id` | Path：`session_id` | Session |
| `POST /admin/sessions/revoke` | JSON：`session_id`、`revoked_at_unix_secs` | Session |

`status` 支持：`pending`、`active`、`revoked`、`expired`。

### 9.5 OIDC Client 管理

| 方法和路径 | 参数 | 响应 |
| --- | --- | --- |
| `GET /admin/clients` | Query：`client_type`、`pkce_required`、`limit`、`offset` | `clients` + `page` |
| `GET /admin/clients/:client_id` | Path：`client_id` | Client |
| `POST /admin/clients/upsert` | JSON：见下表 | Client |

Upsert JSON：

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `client_id` | 是 | Client 唯一 ID |
| `client_name` | 是 | 展示名称 |
| `redirect_uris` | 是 | Redirect URI 数组 |
| `client_type` | 是 | `public_desktop` 或 `confidential_web` |
| `pkce_required` | 是 | 是否强制 PKCE |
| `client_secret` | 否 | Confidential client 的 raw secret；服务端保存 hash |

Public client 不能配置 secret；Confidential client 必须具有 secret hash。
Redirect URI 还会按照 Client 类型执行安全规则校验。

### 9.6 设备管理

| 方法和路径 | 参数 | 响应 |
| --- | --- | --- |
| `GET /admin/devices` | Query：`account_id`、`client_id`、`status`、`registered_after_unix_secs`、`registered_before_unix_secs`、`cursor`、`limit`、`offset` | `devices` + `page` |
| `GET /admin/devices/:device_id` | Path：`device_id` | Device + 全部 bindings |
| `POST /admin/devices/unbind` | JSON：`account_id`、`device_id`、`unbound_at_unix_secs` | Binding |
| `POST /admin/devices/disable` | JSON：`device_id` | Device |
| `POST /admin/devices/revoke` | JSON：`device_id` | Device |

`status` 支持：`pending`、`active`、`disabled`、`revoked`。

Standalone 管理调用示例：

```bash
curl -X POST http://127.0.0.1:9100/api/admin/accounts \
  -H 'content-type: application/json' \
  -H 'x-embedded-idp-admin-key: dev-admin-key' \
  -d '{
    "email": "admin-created@example.com",
    "password": "Password123",
    "display_name": "Admin Created"
  }'
```

## 10. 本地端到端账号流程

### 10.1 注册

```bash
curl -X POST http://127.0.0.1:9100/auth/register \
  -H 'content-type: application/json' \
  -d '{
    "email": "user@example.com",
    "password": "Password123",
    "display_name": "Demo User",
    "client_id": "desktop-app"
  }'
```

默认 `EMAIL_DELIVERY_MODE=log` 时，从运行服务的终端日志读取六位验证码。

### 10.2 验证邮箱

```bash
curl -X POST http://127.0.0.1:9100/auth/verify-email \
  -H 'content-type: application/json' \
  -d '{
    "email": "user@example.com",
    "verification_code": "123456",
    "client_id": "desktop-app"
  }'
```

保存响应中的 Access Token 和 Refresh Token。

### 10.3 调用 UserInfo

```bash
curl \
  -H 'Authorization: Bearer <access_token>' \
  http://127.0.0.1:9100/oidc/userinfo
```

### 10.4 Refresh

```bash
curl -X POST http://127.0.0.1:9100/auth/refresh \
  -H 'content-type: application/json' \
  -d '{
    "refresh_token": "<refresh_token>",
    "rotated_at_unix_secs": 1700000000
  }'
```

每次轮换后必须替换本地保存的 Refresh Token，不能继续使用旧值。

## 11. 生产接入前必须替换的实现

Standalone 当前包含明确的开发实现：

- Access Token 是可读、可伪造的冒号分隔文本。
- ID Token 不是签名 JWT。
- Access Token Validator 只解析文本格式。
- Device Proof 只校验时间新鲜度，不验证签名。
- JWKS 为空。
- `AuthenticatedSubject` 来自调用方可控 Header。
- 管理 API 只使用一个静态 Key。

生产宿主必须：

- 使用签名 Access Token/JWT，并严格验证 issuer、audience、expiry 和签名。
- 使用签名 ID Token，并在 JWKS 发布对应公钥。
- 从可信 Session/SSO 中间件构造 `AuthenticatedSubject`。
- 实现真实 Device Proof 签名验证。
- 使用 Secret Manager 保存数据库、SMTP 和 Client Secret。
- 把 Admin Router 放在强认证和受限网络边界后。
- 使用 PostgreSQL TLS `require`。
- 明确设置 Token、Session 和验证码 TTL。

## 12. 当前范围限制

当前没有提供：

- SAML。
- 社交登录。
- 多租户组织模型。
- 多种存储后端。
- PostgreSQL client certificate authentication。
- 真正的 PostgreSQL `prefer` TLS fallback。
- `/oidc/token` 上的标准 `refresh_token` grant。

管理员设备操作只存在于 `/admin/devices/*`；它们不会作为
`/devices/disable` 或 `/devices/revoke` 暴露，也不会出现在 Discovery 中。
