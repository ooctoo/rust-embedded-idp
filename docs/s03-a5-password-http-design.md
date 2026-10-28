# S03-A5 本人改密 HTTP、宿主与共享密码预算设计

2026-10-26。状态：独立double check完成，两项合同修正已写回，主代理冻结后进入实施。前置S03-A4 Core/PG及15项真实PG合并回归已通过。本批不含密码恢复或Web安全页。

## 复用和范围

直接复用S03-A4 CoreSelfPasswordChangeService、S03-A3显式account_security配置/持久密钥、同一PostgresAccessStore及foundation/runtime检查。新增独立router，不改旧构造器参数，不增加环境变量、DDL或依赖。不复用管理重置接口替代本人当前密码校验。

宿主在account_security存在时构造一份Arc改密service，显式传入现有AuthConfig、SystemClock、UuidV7IdGenerator、同一个crypto和PasswordWorkBudget clone。管理和所有普通业务入口共享该实例。无配置保持旧行为与404；原legacy环境路径仍默认关闭。启用时启动与readyz已有只读runtime检查继续生效。

## HTTP合同

新增四组POST命令/结果，共8路由：

- /auth/security/password、/auth/security/password/result
- /admin/auth/security/password、/admin/auth/security/password/result
- /auth/browser/security/password、/auth/browser/security/password/result
- /admin/auth/browser/security/password、/admin/auth/browser/security/password/result

Bearer命令DTO严格拒绝未知字段：current_password、new_password、operation_id、receipt_secret。browser另外强制expected {tenant_id,account_id,session_id,client_id}。result仅operation_id/receipt_secret，不接收密码或身份。UUID和secret遵循撤销合同；密码不trim、不回显、Debug不打印。认证及selectors直接遵循S03-A3：正确用途的单Authorization、匹配tenant hint可接受、拒绝business selector；browser同一Origin/Fetch/browser header规则和expected校验。结果无需已经失效的Bearer/Cookie，不调用认证；browser结果仍要求Origin/browser头，禁止tenant/business selectors。

三个构造器self_password_change_router(business auth, service)、management_self_password_change_router(management auth, service)、browser_self_password_change_router(identity, service, config)均独立挂载；browser构造时验证purpose和lifetime一致。复用既有call/spawn_blocking与physical_holds，新增SelfPasswordChangeError的From<StoreError>转换为Access包装，以兼容call的错误约束，不扩大AccessError旧enum。

16KiB上限与外层no-store覆盖提取器拒绝。新命令/result handler显式接收Result<Json<DTO>, JsonRejection>，JSON语法错误、未知/缺失字段或错误Content-Type统一400 invalid_request，message固定request is invalid；超过16KiB统一413 request_too_large，message固定request body is too large，不透出Axum反序列化字段/行号。宿主外层既有body transport/timeout拒绝仍沿用宿主准入合同，不改其错误族。成功200 {completed:true}，result未确认200 {completed:false}。不设置或清除Cookie；迟到响应不得清除新登录。新接口失败映射：无效actor及认证InvalidSession/Forbidden为401 invalid_session；其余入口认证错误沿用S03-A3的revocation_auth_error/map_tenant_auth_error（其中InvalidCredentials/InvalidAuthorization/InvalidGrant为401 invalid_credentials），不重新定义旧认证错误族；本人服务旧密码错误为401 invalid_credentials；策略/格式400 invalid_request；快照变化409 credentials_changed；收据重放冲突409 operation_conflict；预算/容量/存储/crypto/布局绑定失效503 security_unavailable；异常存储投影500 server_error。固定非敏感文案，不暴露hash、字段值或底层DB错误。后续Web必须区分invalid_credentials与invalid_session，前者保留当前登录且不自动重试。

所有POST在宿主现有共享准入/anonymous physical wrapper之前组装，可信peer规则不变。第三方宿主需注入同类准入。结果查询不能绕过同层来源限流。

## 既有管理KDF预算收尾

CoreAccountSecurityService新增私有password_work字段及with_password_work_budget(builder)，旧new签名保持兼容并默认bounded budget；参考宿主必须传同一共享预算。三处真实hash：create_account、set_account_password、create_tenant的New administrator分支，在已完成权限验证后、hash调用前用try_login立即取得许可，hash完成后释放。饱和返回既有password.work_unavailable，管理HTTP已映射503 temporarily_unavailable。无等待队列，不持锁等待许可；保留既有管理写的锁内hash及hash后actor重查，不借此改造旧管理事务或合同。Existing administrator建租户、账号状态修改不做KDF，不应占用许可或因KDF预算饱和失败。

新本人改密KDF仍严格在事务外；不得将旧管理路径的锁内行为复制过去。共享预算实现不更改4个总槽与2个registration槽上限，不通过独立预算绕开限制。

## OpenAPI及实施顺序

1. 独立审查路由认证边界、错误语义、Cookie迟到响应、From转换、共享预算及旧签名兼容；主代理修正冻结。
2. 先管理Core预算/局部测试；再Axum独立route与DTO测试；主代理集成Host。分别拥有文件，避免并发改同一bootstrap。
3. business OpenAPI在既有account_security开关下增加4项操作，总27项；management仍精确合同+路由清单。保留business_profile默认关闭与旧接口签名。更新API说明/host集成和漂移测试，不新增未实现Web承诺。
4. 局部测试：管理三处饱和时无hash/写入、无KDF分支不受影响；Axum认证用途/入口/selector、expected及Origin、请求限制与固定错误/no-store/noSetCookie，result不调用认证或写接口。
5. 真实隔离PG+reference host两mode，覆盖管理及至少两个业务入口、Bearer/browser本人改密、错误旧密码无副作用、全域旧登录失效/新密码可重新登录、改密后独立收据、跨入口拒绝、旧响应不清新Cookie（无SetCookie）。一套独立预算饱和Core测试补足真实host难控制的瞬时槽位，不虚称已做真实负载容量验收。
6. 运行相关Core/Axum/App局部测试、工作区all-target编译与合同漂移，记录结果与未执行项。保持8个预存测试不变。不做完整验收、部署、提交或推送。

## Double check与冻结记录

独立复核确认构造点、三个管理KDF入口、call物理许可及OpenAPI条件装配相符；主代理修正两项：明确入口认证沿用S03-A3已有错误映射，以及新JSON提取失败使用固定400/413响应（含未知/缺失字段、Content-Type、过大body测试）。前置S03-A4已闭合，按以上方案实施。

## 局部验证稳定性修正

App全量测试的邮件helper退出码用例在并行编译/宿主测试时偶发Unknown；该用例只验证exit code映射，却额外采用2秒截止时间，把进程调度也混入断言。改为该用例10秒有界截止（仍低于生产15秒上限）；原专门超时/kill/reap测试保持原时间与断言。此修改不增加生产等待时间、不吞失败或重试断言；修正后须重跑全部App测试。
