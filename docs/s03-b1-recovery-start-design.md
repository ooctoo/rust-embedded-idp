# S03-B1 密码恢复开始与加密待发记录设计

2026-10-26。第二轮独立复核通过，主代理冻结本合同，按精确端口进入实施。第一轮问题已整合为唯一合同。本批只实现Core/PG开始流程；验证码完成、worker、HTTP、Web分批设计后接入。

## 范围与复用

邮箱六位code，不引入链接登录、MFA豁免或管理身份匿名恢复。复用tenant_v6、foundation/runtime、AccountSecurityCrypto、既有PG池与state安全屏障，无新DDL、依赖或队列。不复用注册表/注册资格，不直接调用邮件sender。

所有合法且未限流的新start都创建一条flow/start receipt/outbox/event；flow初始pending。符合资格者flow保存账号/版本，outbox加密payload且pending；无资格者account/version均NULL，outbox cancelled无payload。后续完成服务必须拒绝NULL账号。外显统一handle和expires_at，不能暴露资格。容量、crypto故障路径一致，但不声称数据库/网络计时恒定。

## 输入与幂等

RecoveryStartCommand {email: SecretString, operation_id: Uuid, receipt_secret: SecretString}。operation非nil；secret43字符canonical base64url非零32bytes。邮箱仅去首尾ASCII空格，非空、UTF-8字节数<=254、无control/CR/LF/NUL、无剩余Unicode whitespace、恰一个@且两端非空，再用既有is_valid_email检查形状。保持大小写精确查询accounts.email，不用注册canonicalizer改变历史身份。subject_digest仅ASCII lowercase归并预算。异常历史地址不在匿名恢复范围，本人改密/管理路径不变。

RecoveryStartResult {handle: SecretString, expires_at: SystemTime}。handle为flow UUID16bytes+随机secret32bytes，经base64url无padding得到64字符；必须校验UUID非nil及secret非零。flow有效900秒、保留86400秒；start receipt最长900秒。所有秘密/邮箱不打印Debug。

state锁和runtime核对后先查operation的start receipt，不先查询账号/扣预算。行存在且now < expires_at并request HMAC匹配时解密返回相同handle/原expires，不新写。行存在但过期或请求不同则operation conflict。幂等只在该行实际存在期间成立：改密可能提前删除，不能承诺固定15分钟保护。行删除后同operation为新start，正常扣预算并失效旧代次；客户端新意图必须新UUID，不增加永久tombstone。返回旧handle不恢复被失效的flow。

## 精确Core端口与类型

所有时间使用SystemTime并在Core每次锁后采样时向下取整到UTC整秒（与既有epoch存储一致，确保首次/重放expires_at完全一致；UNIX_EPOCH之前为错误）、UUID字段用Uuid、计数用u32/u64、摘要/密文复用SecurityDigest/SecurityEnvelope，不把opaque字节放Debug。

- RecoveryStartReceipt：operation_id、flow_id、request_digest、handle_envelope、created_at、expires_at。
- RecoveryBudget：subject_digest [u8;32]、window_start、expires_at、start_count u32、failure_count u32。
- RecoveryAccountSnapshot：account_id Uuid、email SecretString、credential_version u64、active bool、has_active_membership bool、has_effective_security_admin bool。存储提供事实，资格由Core判定active && active_membership && !effective_admin。
- RecoveryStartContext：account Option<RecoveryAccountSnapshot>、budget Option<RecoveryBudget>、flow_count/outbox_count/budget_count u64。
- RecoveryStartFlow：id Uuid、subject_digest、account_id Option<Uuid>、snapshot_credential_version Option<u64>、handle_digest、code_digest、created_at、expires_at、retained_until。仅表示初始pending/failed_attempts=0，不另建未使用的通用状态机。
- RecoveryStartOutbox：id、flow_id、envelope Option<SecurityEnvelope>、created_at、expires_at。Some为pending、attempts=0、next_attempt=created；None为cancelled、last_outcome=not_started，lease为空。
- RecoveryStartBundle：budget、flow、receipt、outbox、event_id Uuid。event固定recovery_started/accepted，账号来自flow可空，operation来自receipt，时间来自flow。

RecoveryStartService::start_recovery(command)->Result<RecoveryStartResult, AccessError>。
CoreRecoveryStartService<S,C,K,I>::new(mode, store, clock, crypto, ids)，不注入KDF预算，因为本批没有密码计算。
RecoveryStartStore用GAT Transaction: RecoveryStartTransaction；recovery_start_transaction(mode, authority, callback FnOnce(&mut Transaction)->Result<R,AccessError>)->Result<R,AccessError>。
Transaction方法：start_receipt(operation)->Result<Option<RecoveryStartReceipt>,StoreError>；lock_start_context(email:&str, subject_digest:&[u8;32])->Result<RecoveryStartContext,StoreError>；close_subject_flows(subject_digest:&[u8;32], now:SystemTime)->Result<(),StoreError>；record_start(bundle:&RecoveryStartBundle)->Result<(),StoreError>。

没有给匿名调用返回AccountSnapshot的服务方法。Store回调是可信宿主/模块边界，SQL不自行裁定配额或生成验证码。

## 锁序与资格事实

runner开READ COMMITTED事务，设statement_timeout/lock_timeout各5秒，state FOR UPDATE→base/runtime布局/mode/authority核对→callback。所有失败回滚。重放只在state锁后取Clock，不进入账号查询。

新start在lock_start_context中先非锁定精确发现email/account和membership tenant（已持全局排他state），再排序锁全部相关tenant、account，锁后重读email/status/member/role/权限，最后锁budget行并计总量。Core在此返回后取Clock，之后的flow/outbox写仍受同state屏障保护。不先锁account再补tenant。新start之间按schema串行，是首版性能边界。

has_active_membership仅在active member+active tenant成立。effective admin按目标账号检查既有has_effective_security_admin完整语义：idp业务/type binding、正确resource/role kind、active role/member/account/tenant、全部受保护action存在且permission enabled未archived并category正确；不能使用域级any-account谓词或简化的account_admin_tenants。Disabled只域0 system_admin；Enabled域0 system_admin和真实域tenant_security_admin；business_admin不排除。SQL可复用现有PermissionCatalog动作集合，必须加target account约束。

Core防御校验：account UUID非nil、email精确等于规范输入、version为正且<=i64::MAX；budget subject相同、计数在0..3/0..10、expires=window_start+3600、window_start<=now；receipt operation匹配、flow非nil、created<=now、TTL在(0,900]；解密handle必须64字符canonical、flow UUID与receipt一致。无效投影为InvalidStoreResponse，不当作无资格。

## 预算、容量、代次

全局未清理flow/outbox各最多10000，budget键最多100000；所有资格分支同样检查。已有budget可在键满时更新，新键不可新增。窗口3600秒，到期从now重开且计数归零；每窗口最多3次新start、累计10次code失败，达到任一拒绝新代次。合法receipt重放不扣预算也不因新的配额拒绝。新start在同事务将start_count加1，不改变未过期failure_count。

新代次将同subject旧pending flow invalidated，并将其相关pending/sending outbox cancelled、清密文/key/lease，分别last_outcome=not_started/unknown；不得覆盖其他终态。旧start receipt仍可在实际保留期重放旧handle，但不恢复flow。保留累计budget。允许全局容量导致统一503，配合外层来源/全局准入和后续有界清理；不宣称恶意流量下永不拒绝正常用户。

预算/flow/startreceipt/outbox/event一次提交，任何容量/crypto/SQL错误无副作用。到期/未来时间通过checked_add/非负时间检查，禁止溢出或倒退窗口绕过配额。

## Crypto与payload

flow、outbox、event ID来自IdGenerator并验证canonical非nil；三个ID互异。无论资格，一律random_token/random_code、三个HMAC和两个seal；无资格也生成临时payload密文然后不持久化，crypto故障均失败。生成token需校验43字符/非零32bytes，code恰6位ASCII数字。

- request HMAC：Command/context(operation, flow)，u32BE长度前缀依次domain embedded-idp/password-recovery-start/v1、精确邮箱UTF8、请求secret32bytes。
- handle HMAC：RecoveryHandle/context(flow,None)，随机secret32bytes。
- code HMAC：RecoveryCode/context(flow,None)，六位code ASCII。
- handle envelope：RecoveryStartReceipt/context(operation,flow)，完整handle UTF8。
- mail envelope：RecoveryEmail/context(outbox,flow)，固定三字段UTF8，以真实LF分隔：recovery-email-v1、email、code。无结尾额外LF。解密者严格验三字段及版本/输入约束。

当前key写，重放用stored key ID验证/解密；未知key/crypto失败为固定Store Backend，不当作错请求。不加serde依赖，不复用可打印正文的OutboundEmail；后续worker构造已存在的脱敏SecurityEmail，模板由宿主负责。

record_start防御校验bundle跨表ID/subject/时间一致、account/version同时存在且有效、outbox payload存在与account存在一致、计数边界及非nil IDs。无效bundle失败而不是修正。SQL负责类型/外键/唯一/字段形状及原子upsert budget、insert四项；event无邮箱/code/handle/digest，仅可空account、operation、时间。

## 错误与验证顺序

非法输入用InvalidInput静态字段；配额Conflict("recovery.rate_limited")；容量Conflict("recovery.capacity")；重放Conflict("recovery.operation_conflict")；存储/crypto固定Backend。未来HTTP分别400/429/503/409，不在本批新增路由。非资格不返回错误或不同有效期。

1. 精确端口独立复核，主代理写回修正并冻结后编码。
2. Core定向测试：资格/非资格相同返回、全crypto路径、邮箱边界、HMAC/旧key/重放/过期/删除后新start、预算窗口/容量/异常store、Debug无秘密、错误回滚调用合同。
3. PG两mode：普通/未知/disabled/closed/缺成员/有效system或tenant admin/business admin事实矩阵、精确大小写账号lookup与共享bucket、单次并发/三次配额、旧代次关闭及终态保留、回滚、实际密文解密context校验、payload不入非资格表、同operation重放无新邮件、改密删除receipt后重放按新代次。
4. 相关Core/PG测试、workspace all-target、fmt/diff、原8测试SHA和API合同/交付清单。无HTTP，不添加未实现OpenAPI路径。未做完整验收、部署、提交、推送。

## 第二轮复核与冻结记录

独立核对确认注册写入也持state SHARE、现有DDL容纳全部投影、改密提前删除receipt的幂等边界已准确表达。主代理补充：未来所有flow/receipt清理（含级联删除）必须持同state屏障；不允许脱离安全事务清理。邮箱查询沿用现有认证email=$1语义而不做lower，Core仍要求返回邮箱与规范输入一致；不声明支持与该身份模型不兼容的数据库非确定性collation。冻结后只实现本批Core/PG和局部测试，不扩张HTTP/worker。
