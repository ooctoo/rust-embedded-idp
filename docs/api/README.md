# A03 普通业务接口合同

修订4第二批（核查日期 2026-10-25）。软件版本 3.0.0；合同是 **OpenAPI 3.1.0**，直接使用 utoipa 的实际序列化版本，没有改写版本字符串。

- 唯一合同源：[openapi.rs](../../crates/embedded-idp-axum/src/openapi.rs)。HTTP本地投影使用ToSchema；操作/条件及安全组合显式维护，再交给utoipa的类型化Paths/OpenApi序列化。没有给Core增加Serde/ToSchema或文档依赖。
- 制品：[business-openapi.json](business-openapi.json)。包含27项既有普通业务/安全操作及6项可选密码恢复操作；profile按宿主配置过滤，不是历史API schema全集。
- `business_profile(mount_prefix, choose, browser, registration, cookie_name)` 保持既有默认行为，恢复操作默认排除；`business_profile_with_recovery(..., account_security, recovery_email, cookie_name)` 仅在两项开关都为true时加入恢复路径，browser三项还要求browser启用。server URL表示外层prefix，Cookie占位名由profile替换。
- 浏览器凭证、Origin和固定请求头为联合约束；公开登录仍须Origin+固定头。正常模式缺Cookie退出是幂等204；development_login模式即使缺Cookie也要求expected_session。Confidential client退出为Basic或form认证，不能把secret放query。token入口refresh只接受普通会话，不提供设备proof降级。
- `./scripts/check_api_contracts.sh` 检查确定性制品、唯一operationId、引用、路由清单覆盖、普通router字面路径双向覆盖及真实HTTP行为。源码字面路径检查仅作为补充，不代替动态条件和真实HTTP测试。浏览器成功投影还在既有browser_session局部测试中比对生成schema字段。宿主多入口集成测试另行验证真实装配和生命周期。
- [shared-oidc-openapi.json](shared-oidc-openapi.json) 是独立的 v2 共享 OIDC 合同，包含 authorize/token/userinfo/introspect/revoke 与 discovery/JWKS 七项操作。仅当至少一个 v2 `business_entries[].oidc.enabled` 为 true 时，宿主才挂载一次这些全局路径；它们不属于普通业务 profile，也不包含 `/auth/logout`。新 v2 授权码流程只接受非空 PKCE S256 challenge；未配置 device profile 的 ordinary client 不接设备 proof。显式配置 device profile 的 client 可在共享 token 端点通过五个可选proof请求头兑换设备绑定code，设备绑定code要求匹配proof，ordinary code拒绝附带proof。Discovery 固定声明 authorization_code、RS256、openid/profile/email、S256 和 none/basic/post token auth，不声明设备端点；JWKS 为 RS256，ETag 与 `Cache-Control: public, max-age=300`。
- [device-openapi.json](device-openapi.json) 是独立的 JSON v2 device-enabled entry 合同，覆盖 device-auth 登录/刷新/challenge/条件选择和十项租户设备操作；device-auth替换该入口的普通login/refresh，禁止同入口重复merge两套路由。`device_profile`按host prefix及Choose条件过滤。共享OIDC仅由显式启用设备绑定OIDC的入口贡献真实proof-enabled exchange能力；设备proof头绑定原始body字节、method、外部路径和audience。Admission grant仅用于provision和registration-result：host每次调用都重新验证，grant scope稳定绑定tenant/client/device；scope不是body字段，entry_id目前仅用于SDK本地target/journal隔离，服务端grant不按entry区分。相同scope/request ID下仅完全相同的provision请求幂等；complete会一次性消费challenge并激活登记，不可重放，未知结果通过重新授权后查询registration-result恢复。challenge HTTP 200只代表返回随机challenge，不保证challenge已保存或登记具备完成条件。 `POST /devices/rotate-key`要求当前人员Bearer、active本人binding与旧/新key对同一`DEVICE-KEY-ROTATION-V2`规范字节双签；expected key id/version提供CAS，单次`device_key_rotation` challenge随新key激活、旧key退役和审计在Core事务内提交。该轮换无idempotency key/receipt，旧签名不能重放；未知结果以相同active binding读取设备当前proof-key指针和候选/旧key元数据恢复。单个历史metadata不是原操作回执，设备或binding版本变化需停止自动激活。
- [scan-openapi.json](scan-openapi.json) 是独立的18操作扫码API合同（8 browser、10 device），以Axum请求DTO和响应JSON投影为wire依据；`scan_profile(browser_prefix, device_prefix)`分别给两路由设置前缀。设备proof使用 `EMBEDDED-IDP-DEVICE-SCAN-V2`：签名绑定proof字段、原始body、POST、外部路径、tenant与audience，并追加 unpadded base64url 的 `scan-context-sha256`。该值是 `EMBEDDED-IDP-SCAN-CONTEXT-V1` 域分隔符与长度前缀编码的 `purpose_str`、可信 `target_client_id`、`entry_id` 的 SHA-256；后三者来自host路由配置，不是客户端声明。create/claim未知响应需用原始operation_id和完全相同请求重试；lookup的`scan_not_found` 404不是终态，需保留原始action、operation_id及delivery secret继续恢复。exchange/recover使用固定issuance_operation_id，可能返回进度或Pending bundle；acknowledge响应仅含进度，`delivery_state=acknowledged`表示session已激活。若abort返回409 `already_acknowledged`，ACK已先提交，应保留bundle/session并恢复状态；close-origin的`already_activated`同样表示已激活，绝不代表logout。浏览器Origin/Cookie值由宿主profile提供，文档不虚构全局cookie名。A04-D消费者见[接入说明](../a04-d-integration.md)：设备client与可选UI复用这些18项操作，手机确认继续使用既有H5，不新增HTTP端点。
- 复审补齐既有27项操作的真实成功响应递归schema比对（包括两种login结果、非空tenant/role列表、可空cursor）、全部有效Fixed/Choose × browser × registration配置的实际路由对照，以及查询/JSON/form提取失败、Origin联合条件和Basic挑战。密码恢复附加profile测试覆盖默认关闭、两个开关同时开启、browser条件、严格schema、错误/无缓存合同；schema校验器不宣称是完整JSON Schema验证器。完整恢复HTTP语义见[恢复合同](recovery-http-contract.md)。
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

S01-B启用宿主准入层时附加的429/503及有界body错误见[宿主准入合同](host-admission-contract.md)。基础库router与选装宿主层分开描述，原OpenAPI制品不冒称默认挂载该层。

- [安全基础存储接口](security-foundation-contract.md)：显式plan/apply/check、凭据版本与安全事件基础；不新增HTTP路由。
- [本人会话查询](self-session-contract.md)：业务/管理 Bearer 与 Cookie 的只读会话分页、身份及错误合同。

- [账号安全加密端口](account-security-crypto-contract.md)：版本化密钥、收据与恢复用途、存储元数据和错误边界；无新增HTTP路由。

- [安全运行时存储扩展](security-runtime-contract.md)：成功收据、恢复预算/flow及加密outbox的显式迁移和布局检查；无新增HTTP路由。

- [本人会话撤销合同](self-session-revocation-contract.md)：本人范围、关联凭据退役、持久收据与结果未知；包含显式配置启用的独立HTTP挂载。

- [本人改密Core/PG合同](self-password-change-contract.md)：锁外KDF、凭据版本CAS、全域退役与独立结果收据；S03-A5接入可选HTTP，Web尚待实施。

- [密码恢复开始合同](recovery-start-contract.md)：统一匿名形状、限额、代次取消及事务加密outbox；S03-B1仅Core/PG，未挂载HTTP或发送邮件。

- [密码恢复完成合同](recovery-completion-contract.md)：失败计数原子提交、锁外KDF及二次资格/版本检查、单次消费与匿名完成收据；仅Core/PG，HTTP尚待接线。

- [安全邮件outbox合同](security-outbox-contract.md)：有界领取、租约CAS、Unknown不重发及清理；Core/PG已实现，O01a-B3宿主通过recovery_email显式启用发送循环；恢复HTTP条件挂载见[恢复HTTP合同](recovery-http-contract.md)。

- [密码恢复HTTP合同](recovery-http-contract.md)：六项业务/browser条件路由、严格JSON和错误映射；需同时启用account security与recovery email。管理对应路由列于路由清单，未生成管理OpenAPI。

- [Web自助安全SDK合同](account-security-web-contract.md)：业务与管理客户端共用的本人会话、撤销、改密、匿名恢复和结果收据能力；C2已提供持久日志、可见页面和刷新结果恢复，见[实施记录](../s03-c2-implementation-result.md)。
