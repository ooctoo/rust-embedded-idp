# 第一期安全基础版交付清单

2026-10-26。范围依据用户确认：S01、最小O01a、S03本人会话/撤销/改密/邮件恢复；每批先详细设计、实施计划和double check，再实现和局部/集成测试。A01–A05沿用已完成基线。

本清单描述本地候选软件的实现与分批验证，不表示完整验收、生产上线或已发布版本。工作目录为 `/private/tmp/sut-idp-physical-timeout-20261023`，唯一工作分支 `codex/registration-physical-timeout`；本轮安全增量与2026-10-28复核修正纳入本次本地提交范围，实际提交结果以Git历史为准；未推送、未合回main。

最新复核见[2026-10-28交付前复核](phase-one-delivery-review-2026-10-28.md)：发现并修复3处Web状态问题后重新验证。

## 功能交付

| 能力 | 交付内容 | 证据 |
| --- | --- | --- |
| S01 | 共享密码物理预算、匿名容量、可信来源/账号摘要限流、硬容量与清理、OIDC/client/device KDF统一接线 | [A](s01-a-implementation-result.md)、[B](s01-b-implementation-result.md)、[C](s01-c-implementation-result.md) |
| 最小O01a | 事务安全事件、加密邮件outbox、版本化key provider、claim/lease/CAS/cleanup、类型化发送结果、Unknown不盲重发、宿主启动与退出生命周期 | [基础](security-foundation-implementation-result.md)、[加密](account-security-crypto-implementation-result.md)、[runtime](security-runtime-implementation-result.md)、[邮件](o01a-a-implementation-result.md)、[outbox](o01a-b2-implementation-result.md)、[worker](o01a-b3-implementation-result.md) |
| S03本人会话 | 全域本人列表、精确本人身份检查、目标会话撤销、当前会话退出、匿名收据核对 | [A1](s03-a1-implementation-result.md)、[A2](s03-a2-implementation-result.md)、[A3](s03-a3-implementation-result.md) |
| S03改密 | 旧密码重验、凭据版本/并发屏障、原子全域会话退役、幂等结果恢复；旧密码错误保留当前身份 | [A4](s03-a4-implementation-result.md)、[A5](s03-a5-implementation-result.md) |
| S03恢复 | 普通账号邮件code、匿名外显、累计预算、旧flow失效、单次消费、事务退役、不自动登录；高权限账号不走普通恢复 | [B1](s03-b1-implementation-result.md)、[B2](s03-b2-implementation-result.md)、[B3](s03-b3-implementation-result.md) |
| Web使用路径 | 共用SDK、管理与业务嵌入页面、sessionStorage写前intent/CAS、刷新恢复、未知结果核对、身份切换隔离、中英文/键盘/窄屏 | [C1](s03-c1-implementation-result.md)、[C2](s03-c2-implementation-result.md)、[公开合同/示例](api/account-security-web-contract.md) |
| 接入与接口 | 显式安全配置、foundation/runtime迁移、启动/readiness校验、可选恢复路由、管理UI能力meta、持续合同漂移检查 | [宿主集成](host-integration-v1.md)、[合同索引](api/README.md)、[路由清单](api/route-inventory.md) |

## 验证证据与局限

各切片记录包含Core/HTTP/PG并发、回滚、幂等、取消后的物理预算、发送Unknown与旧凭据退役等定向证据。最终Web回归219项，构建产物10项，管理HTML定向7项通过；格式、工作区all-target编译、20项OpenAPI及4类生成合同/A05漂移检查通过。离线工作区回归结果见下方最终核对。

本批真实浏览器使用一次性Postgres18.6和Enabled模式参考宿主、本地SMTP：管理Cookie改密与刷新结果恢复，业务token邮件恢复/新密码登录/当前会话撤销通过。合成故障浏览器补充丢响应、刷新、同op重试、false收据、存储损坏、身份切换和375px键盘布局。真实多入口、Enabled/Disabled和Cookie/token HTTP矩阵复用前置批次证据，不把浏览器单模式扩称全矩阵。

未执行全套产品断言/完整验收、远端CI、生产环境TLS/SMTP、容量与长窗口、灾备、实体设备、原生WebView或系统读屏验收。离线运行中ignored live测试不计为通过；前置PG及本批fixture显式运行的结果单独记录。

## 接入方仍须完成

- 按宿主配置提供可信subject/token/client-secret、来源信息、生产密钥与邮件供应。参考host不是生产host，测试fixture及其随机账号不得复用部署。
- 按[宿主说明](host-integration-v1.md)执行安全扩展显式准备/迁移并检查schema与key；在线启动只校验，不隐式迁移。迁移真实数据库和上线另行审批安排。
- 依实际安全配置启用Web功能，提供同源/明确Origin边界。sessionStorage只承诺当前标签页刷新；关标签丢记录、XSS防护和宿主原生持久存储不可由此默认解决。
- governor与物理预算是单进程有界控制；多副本全局准入、生产容量参数、密钥保管/轮换运维须目标宿主验证。Unknown投递不自动宣称未送达或重复发送。

## 后置产品范围

MFA/WebAuthn/TOTP、step-up及因子丢失恢复，企业OIDC/LDAP/SCIM，邀请、机器身份、组/委派、外部Webhook、完整运行控制面，以及原生keystore/跨进程锁均不包含在本期交付承诺中。高权限账号不能借普通邮件恢复绕过安全边界。

## 最终核对

- [x] 本期每批设计/计划/复核及实施记录齐备，公开接口与宿主配置已更新。
- [x] 本批浏览器、隔离PG/SMTP链路完成，测试宿主/schema/容器已清理。
- [x] 既有8个未跟踪测试逐项SHA-256与合并前manifest一致；生成dist/依赖目录未纳入Git改动。
- [x] 最终 `cargo test --locked --offline --workspace` 通过：724 passed、0 failed、313 ignored（含doc-test组）；日志 `/private/tmp/idp-phase-one-unit.log`。ignored不计为本次执行。
- [x] 完整验收、部署、提交/推送另行安排，无隐式扩大本次授权。

### 2026-10-28复核后重跑

Rust离线工作区724 passed、0 failed、313 ignored；Web 223/223、构建产物10/10、OpenAPI合同20/20通过，四类制品与A05检查无漂移。格式、workspace all-target与Web构建通过。新增三项Web修复经22项workflow及局部浏览器错误路径验证。现有大chunk与测试helper dead_code提示不影响通过，ignored仍不计为已执行验收。
