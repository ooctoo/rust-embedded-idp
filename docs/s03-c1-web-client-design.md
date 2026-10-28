# S03-C1 Web 自助安全 SDK 设计与实施计划

> 后续状态：C2页面与持久日志已完成本批实现及局部验证，见[C2实施记录](s03-c2-implementation-result.md)。下文保留C1批次范围。

2026-10-26；前置S03-A1/A3/A5/B3 HTTP和双模式局部验证已完成。本批实现共用SDK与现有两个身份客户端的窄传输桥，不增加服务端API/依赖，不改变现有管理会话管理接口。随后C2实现可见安全页、登录恢复入口、会话内持久回执及浏览器交互测试；C1本身不是Web交付完成。

## 现有代码约束与复用

embedded/client.ts和management/client.ts分别拥有凭证、revision、transport及browser coordinator。既有authenticated会自动刷新且遇所有401均clear，不能直接用于本人密码变更（invalid_credentials必须保留会话），Cookie本人读取也不能通过refresh后再读取。新桥复用私有request/browserRequest、browserOperation/check及revision，不暴露access/refresh token，不复制认证状态机。普通request补解析固定错误code（顶层code、字符串error、嵌套error.code），browser采用同一识别范围；错误文案继续固定，不显示服务端任意message。

新 `web/embedded/account-security-client.ts` 只依赖已有browser-session secureRandomUuid及标准Web Crypto。React/Ant Design不进入SDK。两身份客户端只type-import新端口类型，避免运行时循环与现有data-URL测试装载器失效。依赖许可仍沿用已有TypeScript/React工具链，不引入新组件。

## 端口及传输

新类型SecurityIdentity含tenant_id/account_id/session_id/client_id四项。AccountSecurityPort结构包含：

- 只读accountSecurityScope：由purpose、token/cookie/development_login模式及规范化base组成，不含身份凭据。
- getSnapshot(): {session?:unknown}，复用现有snapshot；SDK运行时必须校验完整四字段SecurityIdentity。管理端旧Session.client_id可选类型保持兼容，缺字段的旧身份不能执行新安全写。
- requestAccountSecurity(operation, body, expected?): Promise<unknown>。
- forgetAccountSecuritySession(expected): void，仅清除仍与四项expected完全相同的本页身份；不发logout，不修改Cookie，不影响后登录身份。

operation为有限union：sessions、revoke、password、revoke-result、password-result、recovery-start、recovery-complete、recovery-result。不可传任意URL。路径只从该union固定映射到已冻结/auth/security、/auth/password-recovery（管理增加/admin）；browser由模式增加/browser。匿名result/recovery不附Bearer，不要求当前session或expected，不clear身份，也不被另一用户登录阻止查询收据。

JavaScript运行时同样要求操作属于路径表自有属性，constructor/toString等继承键不能触发请求。会话页校验current与本次owner的tenant/session/client匹配，并拒绝同页重复tenant/session；允许真正的跨租户、跨client本人会话。

sessions/revoke/password必须传与当前身份相同的expected；进入时捕获revision，异步操作前后核对。Cookie模式在browserOperation锁内check当前marker、revision和expected，直接browserRequest，不refresh/rotate，body最后设置可信expected，禁止调用者覆盖。仅这三个需身份操作在token模式使用access取得现有/刷新后的token，随后再次核对revision+expected，sessions为GET仅limit/cursor编码，其他为POST。不发送tenant/business selector。development_login沿用既有显式模式，禁止静默降级。

旧密码错误401 invalid_credentials不clear、不标记浏览器blocked；仅明确invalid_session可清除仍为原revision的本页身份。其他失败留给调用者核对收据。迟到的成功/失败均不能覆盖或清除新身份。forget仅处理本页内存；其他标签页依靠既有coordinator和服务端凭据失效校验，不向共享Cookie发送清除命令。

管理桥对revoke/password计入既有mutationActivity，保证导航的进行中写提示；finally归零。匿名恢复不冒充管理写权限，也不按tenant管理会话API操作。

## SDK及校验

AccountSecurityClient接受AccountSecurityPort。公开方法：listSessions(cursor?)；prepareRevocation(targetTenantId,targetSessionId)；revoke(intent)；preparePasswordChange()；changePassword(intent,currentPassword,newPassword)；result(intent)；prepareRecoveryStart(email)；startRecovery(intent)；prepareRecoveryCompletion(handle)；completeRecovery(intent,code,newPassword)。result支持撤销、改密、恢复完成三类intent。

intent是冻结的可序列化记录：version=1、scope、kind、operation_id、receipt_secret；本人写另含四字段owner；撤销另含target_tenant_id/target_session_id；恢复开始另含email；恢复完成另含handle。operation采用secureRandomUuid（非零canonical），receipt_secret用crypto.getRandomValues产生32字节并canonical base64url（非全零）；随机不可用时失败，不用Math.random或时间替代。prepare只生成意图不调用网络；调用者必须先保存原intent再提交，未知响应不得换operation重试。

每次发送再次校验version、scope、kind、canonical UUID/secret、owner和字段形状，防止从错误入口/用途恢复日志。scope限制SDK本地复用，不改变后端跨入口收据能力。恢复email按Core ASCII空格trim、长度<=254做轻校验，资格由服务端判定；handle为64字符canonical48字节；code为6ASCII数字。密码仅作为方法参数发送，不写intent、不保存到SDK字段、日志或snapshot。最终密码强度仍由宿主Core策略决定。

返回数据严格校验：列表<=50条，每项tenant/session/client、purpose、device_id/null、非负安全整数时间、active/expired、current，next_cursor=null或<=1024 base64url；列表不限定当前tenant/client（这是本人全域列表）。start只接受handle及非负安全整数expires_at_unix_secs；completed必须boolean，写成功必须true。畸形成功响应视为结果未知错误，不据此清除原intent。客户端错误不输出输入秘密。

本人成功改密或撤销当前精确会话后，调用port.forgetAccountSecuritySession(owner)；result=true仅对改密或撤销目标tenant/session与owner精确匹配的intent执行受owner约束清理，result=false仅代表未确认。撤销其他会话不clear；匿名恢复成功不猜测email对应哪个当前身份，不clear其他登录，页面提示重新登录。所有result均只读，无自动写重试。

## C2持久与交互依赖（本批不伪称已完成）

SDK不自行挑选宿主存储。C2参考页面会在提交前写入有版本、作用域、容量限制的sessionStorage日志；宿主嵌入可显式提供同合同存储。只保存上述intent和恢复handle/有效期，不保存密码、code、token。存储写/readback失败阻止写请求；损坏记录显式报错，不静默生成新operation。当前页未知结果提供核对，false保留；刷新可用原receipt继续查询。安全页要区分普通管理会话页与本人全域安全页，写/恢复UI按宿主启用配置显示，不能假设可选端点已经开启。

本批UI设计约束沿用现有样式和oiloil的状态覆盖/反馈闭合规则；不重建全站设计系统。C2详细页面、日志状态机及可访问性设计须独立复核后实施。

## 实施顺序及验证

1. 独立double check本设计与两个client/HTTP合同；冻结前不写本批代码。
2. 一个worker负责两个现有client的窄桥和各自测试；另一个worker负责新SDK/测试，接口约定固定，禁止修改对方文件。主代理负责导出、测试脚本、集成与源码复核。
3. 测试桥：两purpose token/cookie/development、正确路径/header、Cookie不refresh、expected/切换/迟到拒绝、invalid_credentials保留、invalid_session只清原身份、匿名result不带凭据、错误code解析、mutation计数恢复。
4. 测试SDK：随机/intent字段及跨scope拒绝、列表跨tenant接受但非法字段拒绝、prepare不网络、result无登录可读/false不清、原operation不变、密码不进入intent、完成成功精确owner清理。
5. pnpm web局部及既有client回归，pnpm web test、build（含嵌入导出/类型），bundle测试。不进行完整验收；Web真实交互/宿主集成属于后续C2退出条件。

## Double check

独立复核（s01_inventory）发现两处表述歧义，冻结规则明确如下：仅sessions/revoke/password三个需要身份的操作允许token模式调用access；所有匿名result和recovery在任何模式均不调用access/refresh。Cookie匿名调用直接browserRequest，不执行要求身份的browserOperation/check。result=true仅对改密或撤销目标tenant/session与owner精确匹配的intent清理匹配owner；其他撤销及匿名恢复绝不清理身份。以上规则优先于前文概括表述，设计已冻结，可开始实施。

### 冻结的TypeScript公共命名

导出SecurityIdentity、AccountSecurityOperation（前述8值）、AccountSecurityPort、SecuritySession、SecuritySessionPage、RevocationIntent、PasswordChangeIntent、RecoveryStartIntent、RecoveryCompletionIntent、SecurityIntent（4者union）、AccountSecurityClient、AccountSecurityError。kind为revoke/password/recovery-start/recovery-complete；receipt字段直接放intent顶层。scope getter为accountSecurityScope；桥方法requestAccountSecurity(operation: AccountSecurityOperation, body: Record<string, unknown>, expected?: SecurityIdentity): Promise<unknown>；清理方法forgetAccountSecuritySession(expected: SecurityIdentity): void。listSessions固定limit50，cursor可选。

SDK本地校验失败抛固定消息AccountSecurityError，status=0，code为invalid_security_intent / invalid_security_response / security_random_unavailable / security_session_changed，不包含输入值。HTTP失败透传现有client error（都有status/code）；C2按结构处理，不能依赖单一client的instanceof。网络/畸形成功为结果未知，SDK不自动retry。普通HTTP请求固定状态消息保持兼容，只额外解析code供安全组件识别。

另导出纯函数parseSecurityIntent(value: unknown, scope: string): SecurityIntent供C2读取日志时校验，不发网络；拒绝多余字段（尤其password/code/token）、错误scope/version/kind及无效字段，返回冻结记录。SDK发送时复用同一校验，避免UI与SDK各写一套日志解析。
