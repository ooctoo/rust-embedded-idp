# A03 普通业务接口合同

修订4第二批（核查日期 2026-10-25）。软件版本 3.0.0；合同是 **OpenAPI 3.1.0**，直接使用 utoipa 的实际序列化版本，没有改写版本字符串。

- 唯一合同源：[openapi.rs](../../crates/embedded-idp-axum/src/openapi.rs)。HTTP本地投影使用ToSchema；操作/条件及安全组合显式维护，再交给utoipa的类型化Paths/OpenApi序列化。没有给Core增加Serde/ToSchema或文档依赖。
- 制品：[business-openapi.json](business-openapi.json)。17项普通业务操作的模块根条件目录；不是任意宿主都暴露全部路径，也不是历史API schema全集。
- `business_profile(mount_prefix, choose, browser, registration, cookie_name)` 根据已验证的宿主配置筛选条件，server URL表示外层prefix，替换Cookie占位名。Fixed最小6项；Choose+browser 14项；Fixed+browser+registration 14项。浏览器选择完成路径始终随browser挂载，Fixed策略下由服务拒绝。
- 浏览器凭证、Origin和固定请求头为联合约束；公开登录仍须Origin+固定头。正常模式缺Cookie退出是幂等204；development_login模式即使缺Cookie也要求expected_session。Confidential client退出为Basic或form认证，不能把secret放query。token入口refresh只接受普通会话，不提供设备proof降级。
- `./scripts/check_api_contracts.sh` 检查确定性制品、唯一operationId、引用、路由清单覆盖、普通router字面路径双向覆盖及真实HTTP行为。源码字面路径检查仅作为补充，不代替动态条件和真实HTTP测试。浏览器成功投影还在既有browser_session局部测试中比对生成schema字段。宿主多入口集成测试另行验证真实装配和生命周期。
- [shared-oidc-openapi.json](shared-oidc-openapi.json) 是独立的 v2 共享 OIDC 合同，包含 authorize/token/userinfo/introspect/revoke 与 discovery/JWKS 七项操作。仅当至少一个 v2 `business_entries[].oidc.enabled` 为 true 时，宿主才挂载一次这些全局路径；它们不属于普通业务 profile，也不包含 `/auth/logout`。新 v2 授权码流程只接受非空 PKCE S256 challenge；未配置 device profile 的 ordinary client 不接设备 proof。显式配置 device profile 的 client 可在共享 token 端点通过五个可选proof请求头兑换设备绑定code，设备绑定code要求匹配proof，ordinary code拒绝附带proof。Discovery 固定声明 authorization_code、RS256、openid/profile/email、S256 和 none/basic/post token auth，不声明设备端点；JWKS 为 RS256，ETag 与 `Cache-Control: public, max-age=300`。
- [device-openapi.json](device-openapi.json) 是独立的 JSON v2 device-enabled entry 合同，覆盖 device-auth 登录/刷新/challenge/条件选择和十项租户设备操作；device-auth替换该入口的普通login/refresh，禁止同入口重复merge两套路由。`device_profile`按host prefix及Choose条件过滤。共享OIDC仅由显式启用设备绑定OIDC的入口贡献真实proof-enabled exchange能力；设备proof头绑定原始body字节、method、外部路径和audience。Admission grant仅用于provision和registration-result：host每次调用都重新验证，grant scope稳定绑定tenant/client/device；scope不是body字段，entry_id目前仅用于SDK本地target/journal隔离，服务端grant不按entry区分。相同scope/request ID下仅完全相同的provision请求幂等；complete会一次性消费challenge并激活登记，不可重放，未知结果通过重新授权后查询registration-result恢复。challenge HTTP 200只代表返回随机challenge，不保证challenge已保存或登记具备完成条件。 `POST /devices/rotate-key`要求当前人员Bearer、active本人binding与旧/新key对同一`DEVICE-KEY-ROTATION-V2`规范字节双签；expected key id/version提供CAS，单次`device_key_rotation` challenge随新key激活、旧key退役和审计在Core事务内提交。该轮换无idempotency key/receipt，旧签名不能重放；未知结果以相同active binding读取设备当前proof-key指针和候选/旧key元数据恢复。单个历史metadata不是原操作回执，设备或binding版本变化需停止自动激活。
- [scan-openapi.json](scan-openapi.json) 是独立的18操作扫码API合同（8 browser、10 device），以Axum请求DTO和响应JSON投影为wire依据；`scan_profile(browser_prefix, device_prefix)`分别给两路由设置前缀。设备proof使用 `EMBEDDED-IDP-DEVICE-SCAN-V2`：签名绑定proof字段、原始body、POST、外部路径、tenant与audience，并追加 unpadded base64url 的 `scan-context-sha256`。该值是 `EMBEDDED-IDP-SCAN-CONTEXT-V1` 域分隔符与长度前缀编码的 `purpose_str`、可信 `target_client_id`、`entry_id` 的 SHA-256；后三者来自host路由配置，不是客户端声明。create/claim未知响应需用原始operation_id和完全相同请求重试；lookup的`scan_not_found` 404不是终态，需保留原始action、operation_id及delivery secret继续恢复。exchange/recover使用固定issuance_operation_id，可能返回进度或Pending bundle；acknowledge响应仅含进度，`delivery_state=acknowledged`表示session已激活。若abort返回409 `already_acknowledged`，ACK已先提交，应保留bundle/session并恢复状态；close-origin的`already_activated`同样表示已激活，绝不代表logout。浏览器Origin/Cookie值由宿主profile提供，文档不虚构全局cookie名。A04-D消费者见[接入说明](../a04-d-integration.md)：设备client与可选UI复用这些18项操作，手机确认继续使用既有H5，不新增HTTP端点。
- 复审补齐17项操作的真实成功响应递归schema比对（包括两种login结果、非空tenant/role列表、可空cursor）、全部有效Fixed/Choose × browser × registration配置的实际路由对照，以及查询/JSON/form提取失败、Origin联合条件和Basic挑战。校验器只实现当前合同使用的schema子集，遇到新增未支持约束会失败，不宣称完整JSON Schema验证器。
- 提取器错误不能统一视为JSON：Query非法参数返回text/plain 400；普通refresh的raw_json超限返回JSON 413，不支持的媒体类型返回空415；其余JSON/form提取失败按各自响应媒体建模。登录禁止tenant header；tenant列表范围由ticket与入口决定，tenant header不参与列表筛选。

重新生成：

```sh
cargo run --locked -p embedded-idp-axum --features openapi --example export_openapi > docs/api/business-openapi.json
cargo run --locked -p embedded-idp-axum --features openapi --example export_device_openapi > docs/api/device-openapi.json
cargo run --locked -p embedded-idp-axum --features openapi --example export_scan_openapi > docs/api/scan-openapi.json
./scripts/check_api_contracts.sh
cargo test --locked -p embedded-idp-axum --features openapi browser_session::tests
```

## OSS-05 / G0 决策和证据

选用发布包 [utoipa 5.4.0](https://docs.rs/crate/utoipa/5.4.0/source/Cargo.toml.orig)，发布于2025-06-16，固定`=5.4.0`、optional、default-features=false，只启用macros。锁定的宏依赖为[utoipa-gen 5.5.0](https://docs.rs/crate/utoipa-gen/5.5.0/source/Cargo.toml.orig)（发布于2026-05-04）。不引入utoipa-axum，不升级Axum 0.7，无git浮动依赖。Cargo.lock校验和：

| 发布包 | crates.io SHA256 |
| --- | --- |
| utoipa 5.4.0 | `2fcc29c80c21c31608227e0912b2d7fddba57ad76b606890627ba8ee7964e993` |
| utoipa-gen 5.5.0 | `6ba0b99ee52df3028635d93840c797102da61f8a7bb3cf751032455895b52ef8` |

已读取本地Cargo下载发布包的Cargo.toml、LICENSE-MIT及LICENSE-APACHE：两者均声明MIT OR Apache-2.0，声明rust-version=1.75；实际本机验证rustc 1.93.0，不宣称在1.75运行通过。宏包为编译期proc-macro；两包无新增原生链接依赖。`cargo tree --locked --offline -p embedded-idp-axum --features openapi -e features -i utoipa`确认只合并macros；gen只默认feature，不启用框架/chrono/yaml等扩展。直接传递依赖indexmap/serde/serde_json和宏链syn/quote/proc-macro2均为仓库已有锁定项；没有替换运行时HTTP框架。

本项目选择MIT许可分支用于该文档工具的分发；[MIT许可文本](licenses/utoipa-MIT.txt)与两包的实际文本一致（Copyright © 2021）。分发包含这两包代码/工具二进制时须保留版权与许可文本；纯生成JSON不会嵌入上游实现，但随仓库保留本notice。生产默认feature不引入utoipa；启用openapi的宿主二进制属于另一分发配置，应保留notice。核查[上游Security页](https://github.com/juhaku/utoipa/security)未列出已发布安全公告（网页查询结果，不是完整依赖数据库证明）。本批未执行漏洞公告数据库审计，G0这里只证明版本、构建/API、feature与许可适配，不宣称无已知漏洞。

剩余范围：当前tenant设备认证与设备自助共14项操作已有独立schema合同；历史管理、legacy设备/扫码及其余OIDC接口仍以路由清单为主，未逐项补齐schema。新 v2 共享 OIDC 七项操作有独立schema合同。完整验收、生产部署、多平台 SDK 生成均未执行。

## A05 示例合同

[Enabled宿主报告合同](../../examples/tenant-host/api-contract.json)独立于IdP模块合同，覆盖Fixed/Choose宿主详情、授权过滤列表与签名游标。`check_api_contracts.sh`同时调用示例静态漂移检查；实际Cookie、成员资格、跨入口和管理用途隔离见[示例局部测试](../../examples/tenant-host/tests/live.mjs)。公开React新增可选`EmbeddedAuth.beforeSessionChange`，返回false取消宿主发起的切租户/退出；不更改HTTP合同或服务端会话失效规则。
