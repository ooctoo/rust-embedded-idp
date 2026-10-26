# A02A 普通业务入口与 A03 合同：第二批实施

依据：修订4技术设计 §5–6、实施方案 §4.2/4.4。范围为 M1-04A 普通业务组合和 A03 本批合同；不代表 M1-04B、完整 M1-05、M1-06、N2 或部署完成。

## 组合与复用边界

新 JSON v1 配置现在可装配多个普通 `business_entries`：Enabled 使用 Fixed 非0或 Choose，Disabled 使用 Fixed0。每个入口有唯一 `login_entry`、`client_id`；外层前缀与模块根组合后不得冲突（管理与业务可共享外层前缀）；管理入口与业务入口也不能复用 client ID。会话已有 client/purpose/tenant 隔离，不新增 session 数据列。入口重排不改变标识、audience 或 Cookie path。

普通入口合并 `tenant_auth_router`、`tenant_refresh_router`、`tenant_logout_router` 和 `tenant_self_router`，按配置选装 browser 和注册路由。新增可选 Core 窄合同 `TenantRefreshService::refresh_ordinary`、`TenantLogoutService::logout_session`，既有 trait 不新增必需方法。刷新调用现有 `rotate_refresh`；退出复用 `CoreTenantOidcService` 的客户端认证和精确 refresh family 撤销。复用 OIDC 服务不表示开放 OIDC 路由。

普通刷新拒绝设备证明 Header、外部 tenant Header、设备绑定会话及要求 proof 的入口。`ReuseDetected` 仍是先提交家族撤销、再映射 HTTP 401 的事务成功结果。完整设备认证 router 与普通刷新共享响应映射；完整 OIDC resource router 与普通退出共享 form/Basic 解析和响应处理。

退出保持 `application/x-www-form-urlencoded`：PublicDesktop 提交 client_id 和 refresh_token；ConfidentialWeb 由服务端以 Basic 或 form 提交 secret，不能在 query 或浏览器脚本中传递。浏览器登录/恢复/刷新/退出使用 browser-session 接口，只把 refresh 放在 HttpOnly Cookie；返回的短期 access token 仍供资源接口 Bearer 使用。本人角色仍要求显式 business_id。

新配置不会自动挂载 device/proof challenge、scan、OIDC authorize/token/resource、discovery/JWKS。无参数 LegacyReference 保持原装配及历史 browser lifetime 行为。

## 配置与准备

先完成 P1–P3，再用空 `business_entries` 启动管理入口，通过受限 P5 准备租户、client、成员等业务对象，最后加入业务引用。启动在开放监听前核对全部 client 和固定租户，不补缺 seed、不自动迁移。缺失或非法引用拒绝启动。

以下片段替换已有合法 JSON 配置中的 `business_entries`，其他 runtime/management 字段保持原配置。Enabled 模式中应先准备 `tenant-a`、两个 client 和需要的成员关系：

```json
{
  "business_entries": [
    {
      "login_entry": "orders",
      "client_id": "orders-public",
      "tenant_policy": {"kind": "fixed", "tenant_id": "tenant-a"},
      "mount_prefix": "/orders",
      "browser": {"cookie_name": "orders_session"}
    },
    {
      "login_entry": "workspace",
      "client_id": "workspace-public",
      "tenant_policy": {"kind": "choose"},
      "mount_prefix": "/workspace",
      "browser": {"cookie_name": "workspace_session"}
    }
  ]
}
```

Cookie 路径分别为 `/orders/auth/browser` 和 `/workspace/auth/browser`。名称、路径和前端协调键应对应各自入口；同源多入口隔离不是对同源恶意脚本的防护。

`browser.development_session_ttl_secs` 是可选的私网 HTTP 受限会话覆盖值（60–3600秒），未设置时使用 runtime 默认值。每入口独立计算 lifetime；HTTPS/loopback 完整会话不能设置此开发覆盖值，仍使用 runtime.auth 的期限。此设置不改变同入口普通 token 会话，也不改变旧 LegacyReference 共享管理 browser lifetime 的兼容行为。私网 HTTP 还需原有编译特性和显式 transport policy。

注册默认关闭。仅固定域入口可显式设置 `registration_enabled: true`，并提供有效 `runtime.email`；仍须满足存储内租户的 allow_registration 策略。Choose 注册配置直接拒绝。纯登录不要求 SMTP。各入口服务使用独立注册开关，不把全局默认改成允许注册。

## A03 与验证记录

A03 的组件选型、许可证、制品与漂移命令见[本批合同说明](api/README.md)。使用可选 utoipa 5.4.0（锁定 gen 5.5.0），MIT OR Apache-2.0 选择 MIT 分支；不升级 Axum，不给 Core 添加 HTTP/schema 依赖。生成17项普通业务操作的 OpenAPI 3.1.0；全量历史路由清单与本批 schema 的覆盖范围分别记录，不能把清单视为完整 OpenAPI。

2026-10-25 局部验证结果：

| 检查 | 结果及边界 |
| --- | --- |
| `pnpm --dir web build` | 通过；既有bundle大小提示仍存在，未做打包优化 |
| `cargo check --workspace --all-targets --locked --offline` | 通过；验证跨crate编译兼容，不是完整验收 |
| Core authentication 定向suite | 62通过；新增窄trait边界、既有browser/device/OIDC/scan回归；最新logout客户端负例单项再测通过 |
| Axum lib | 102通过；新增普通refresh成功/重用、proof/context/输入拒绝及logout form/Basic测试 |
| App bin（启用development-private-network-http） | 37通过；默认feature配置suite另17通过 |
| A01 CLI回归 | 1通过；准备命令的特殊文件/大小/输入及依赖边界保留 |
| 业务/管理客户端 `node --test` | 110通过；协调、选择切换、迟到结果、Cookie身份隔离等既有合同 |
| A02真实宿主/Postgres | 3通过；其中普通隔离测试遍历Enabled/Disabled；另测Choose/ConfidentialWeb/注册和私网HTTP多入口期限 |
| 旧参考模式真实宿主回归 | 3通过：双模式管理/业务/OIDC、scan proof用途、私网browser期限与过期身份 |
| A03合同及browser schema对照 | 合同5通过、browser_session 10通过；确定性制品、operationId/$ref、条件profile、路由覆盖、状态/内容类型/DTO与错误投影 |
| 格式与补丁检查 | `cargo fmt --all -- --check`、`git diff --check`通过 |

初次宿主测试发现夹具没有保留restore返回的轮换Cookie，已修正；macOS子进程仍存活但未在20秒内启动的夹具超时改为60秒，子进程退出仍立即失败。随后三项全部通过。生产会话恢复和撤销语义没有为测试放宽。

数据库验证使用专用 `postgres:18.6-bookworm` 无持久卷容器和随机schema，测试间串行执行；结束后已删除容器，不连接或修改现有开发/生产数据。未新增数据库迁移。完整验收、生产部署、远端CI、最低Rust版本和跨平台构建未在本批执行；没有执行新的真实设备/SMTP交付验收。历史接口的schema全集仍是A03后续范围。


## 第二批完整复审（2026-10-25）

复审覆盖修订4对应的配置/装配、Core/Axum窄合同、Postgres事务锁序、客户端协调、17项OpenAPI操作和漂移脚本。保留A01及并行N2工作。

发现并修复：

- 新JSON私网HTTP的受限browser Choose票据原本可提交普通token complete取得完整期限。增加可选Core `with_restricted_browser_isolation`，新JSON业务和管理服务显式启用；受限票据有独立用途，普通入口只允许读取租户列表，不能消费。无持久化结构/迁移变更。完整HTTPS/loopback及LegacyReference未启用此新策略。
- 新JSON受限短会话不能经普通切换接口取得更长会话，须重新密码登录再选择租户；完整token会话保留切换。由于既有session未存储通道标记，按持久化会话总期限保守识别：短于当前普通会话配置的既有会话不能升入更长配置，包括重启后降低browser上限或提高普通期限的情况；这也会保守要求此前较短配置签发的普通会话重新登录。该限制属于私网开发模式的期限保护，不是所有Choose入口禁用切换。
- A03纠正普通refresh的JSON 413/空415、Query的text/plain 400、受限logout预期身份及tenant header说明；补全Basic挑战头。漂移检查增加17操作真实成功响应的递归schema对照、六种有效配置组合及提取器负例。
- 增加真实数据库同refresh竞争、refresh/logout两种提交顺序、最后INSERT故障回滚及另一入口不受影响的测试；Core另测reuse撤销写失败必须回滚，成功重试才提交撤销。

兼容性说明：logout仍只接受当前refresh。若refresh先提交，持旧refresh的logout返回幂等200但不撤销新凭证；调用方应串行协调刷新/退出，或用当前凭证退出。未把旧凭证改为永久撤销权限。LegacyReference是开发参考模式，本轮按修订4保留其历史期限/装配，不能据此声称其已有新JSON的跨通道隔离。

升级窗口：旧构建已签发、无source且未区分用途的初始票据无法判断来自browser还是token。严格切换时应在停止旧服务后等待原300秒票据窗口耗尽；不声称本次只读启动已撤销旧票据。旧source-bound切换票据在消费时也检查持久化期限。

本轮局部验证（以上首轮实施记录保留为历史结果）：

| 检查 | 结果 |
| --- | --- |
| Core authentication 定向suite | 65通过；随后新增管理通道测试1通过，最终期限判断收紧后隔离专项3通过 |
| Axum lib / App bin（私网HTTP feature） | 分别102、37通过 |
| A03 `scripts/check_api_contracts.sh` | 最终9通过，包含重新生成制品一致性及真实HTTP schema对照 |
| A02真实宿主/Postgres | 5通过；最终期限判断收紧后受限Choose专项再测1通过 |
| LegacyReference真实宿主 | 3通过 |
| Web构建 / workspace all-targets check | 均通过 |
| 格式与补丁检查 | 通过 |

本轮数据库使用独立无持久卷容器 `idp-a02-review-20261025`，测试完成后已删除；未连接既有数据库。没有新增迁移、执行完整验收或部署。以上局部证据不替代生产环境、跨平台及真实SMTP/设备验收。
