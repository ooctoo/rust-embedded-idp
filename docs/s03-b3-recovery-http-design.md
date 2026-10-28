# S03-B3 密码恢复 HTTP 与宿主接线设计

2026-10-26；本批在 B1/B2 Core、PG 与 O01a-B3 物理邮件 runtime 已完成后实施。无新数据库结构、密码学或依赖。复用现有许可证与组件；不部署、不完整验收。

## 边界与合同

恢复为账号全域操作，不要求旧会话、设备 proof 或管理角色。不能用路由前缀把全域账号恢复解释成入口内改密；成功退役整个账号已有凭据，不自动登录。有效安全管理员仍由 Core 排除。可信宿主决定是否公开接口，HTTP 不修改资格规则。

业务根 `/auth/password-recovery`、管理根 `/admin/auth/password-recovery`；browser 根分别 `/auth/browser/password-recovery`、`/admin/auth/browser/password-recovery`。每根 POST `/start`、`/complete`、`/result` 共12条可选路由。外层前缀仍由宿主负责。Body 为严格 JSON，未知字段拒绝，最多16384字节，读取最多5秒。拒绝 query（秘密只在body）及 tenant/business selector header。Bearer/Cookie 不作为身份凭据，不生成或清除 Cookie。

- start: email、operation_id、receipt_secret；200 `{handle,expires_at_unix_secs}`。普通可恢复、未知及无资格邮箱同形；成功只表明已登记请求，不表示邮件发送或账号存在。重试原命令取得同一有效开始收据；不存在独立 start-result。
- complete: handle、code、new_password、operation_id、receipt_secret；200 `{completed:true}`。密码规则、canonical handle/secret/UUID 及验证码校验由 Core 执行。
- result: operation_id、receipt_secret；200 `{completed:boolean}`。查询完成收据；false为未确认，不能证明未提交；不能据此生成新operation重复操作。

所有响应 no-store；无 Set-Cookie。结构400 invalid_request；大body413 request_too_large；读取超时408 request_timeout；无效恢复400 invalid_recovery；recovery.operation_conflict为409 operation_conflict；recovery.rate_limited为429 rate_limited；recovery.capacity、Store及其他基础设施故障503 security_unavailable。数据库 unique 冲突不得转换成客户端可重试的409。响应固定文案，不泄露SQL、邮箱、flow存在性或秘密。端点业务错误为既有 `{code,message}`；宿主source准入503沿用temporarily_unavailable；匿名HTTP许可满载沿用既有嵌套 `{error:{code:"temporarily_unavailable"}}`（无message），OpenAPI 503以oneOf描述两种形状，不为本批改变既有登录容量错误格式。

browser复用当前 BrowserSessionHttpConfig 的 exact Origin、固定 x-embedded-idp-browser:1、Sec-Fetch-Site与tenant header guard，不需要 identity service。模块guard在模块body读取/解析及Core调用前运行；宿主外层S01会先读取有界start body并扣source/global/email账号预算，即使随后Origin拒绝。此预算是公开匿名恢复请求的防滥用门槛，不是认证成功计数，非browser客户端本来也可消耗相同额度；本批保留此行为并测试，不宣称被拒请求零副作用。失效或其他入口的Cookie不得影响匿名恢复。

## 准入和取消安全

复用 AnonymousLoginBudget 的8个默认容量及 task-local physical_holds；扩展识别到三个 recovery 后缀。独立恢复router拥有本地上界，完整宿主仍在合并路由外注入同一共享budget，因此管理/多业务/browser/登录累计。所有同步 Core 调用使用 tenant_auth::call，HTTP取消后许可随物理blocking工作保留。无等待队列。恢复body超时在模块router内实现，独立嵌入也受保护；不能只依赖宿主admission。

宿主复用 S01 source/global admission，start共享email账号准入；complete/result没有email，不伪造账号键，以source/global+持久化flow/subject失败预算保护。密码计算继续复用共享PasswordWorkBudget，所有预算只承诺当前进程。Core成功start的统一形状保留；现有匿名失败最小延时复用，不声称全程恒定时间。

## 宿主与兼容性

只有 account_security 配置且 recovery_email=true 时创建共享 RecoveryStartService/RecoveryCompletionService 并挂载12条对应路由；已有SMTP配置校验、runtime扩展核验和worker是前置。false/未配置404，不生成恢复flow。管理、legacy业务、配置化业务入口（包括设备入口）的恢复行为共用同一服务/crypto/KDFbudget。browser仅随该入口browser开启挂载，不改变普通/device登录选型。保留所有旧router/profile公开签名，新增可选构造器/显式recovery profile；旧profile不得意外暴露恢复。

## 实施顺序与验证

1. 独立审查本设计，对路径、body超时、共享许可、默认关闭及错误映射与现有代码逐项核对，修正后冻结。
2. Axum三个端点及browser guard，窄范围测试：命令转换、严格JSON/大小/query/selectors、错误矩阵、no-store/no-cookie、origin先行、无Cookie可调用；许可饱和跨前缀、取消保留以及body超时测试。
3. Host共用service接线；最小改动传递配置，不增加重复状态机；OpenAPI条件目录、profile和路由清单同步，漂移测试必须覆盖默认关闭、browser及不同prefix。
4. isolated PG真实宿主双模式测试：默认404；dummy同形；SMTP取得code完成及结果；旧密码/会话失效；多入口重放和browser origin拒绝。局部测试不等于完整验收。复查已有改密/邮件runtime回归。
5. 更新实施记录与交付计划，明确Web及交付汇总仍待后续切片。

## Double check

独立复核完成（s01_inventory），主代理核对并修正两项：明确不同Core返回类型分别映射；限定Origin先行保证为模块内部，并明确宿主外层账号准入可先消耗额度。start/result返回AccessError，complete返回RecoveryCompleteError；complete先特判InvalidRecovery，其余交由统一AccessError mapper：InvalidInput→400、已知operation_conflict→409、已知rate_limited→429、其余全部→503（包括未知Conflict/Store/InvalidStoreResponse，不输出底层信息）。上述决定已冻结，可开始实施。
