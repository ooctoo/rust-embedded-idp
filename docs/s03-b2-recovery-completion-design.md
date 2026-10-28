# S03-B2 验证码完成密码恢复：详细设计与实施计划

状态：2026-10-26 已完成两轮独立 double check，修订后冻结，可开始本批编码。本批只实现 Core/PG 和局部测试，不实现 HTTP、投递 worker 或 Web，也不改变已安装 DDL。

## 目标和前置

依赖已实现 S03-B1 的随机 handle、六位 code、账号资格投影、累计预算，以及 security_foundation_v1 的凭据版本屏障和 security_runtime_v1 的收据。复用 S03-A4 的全账号凭据退役逻辑；复用现有 PasswordWorkBudget、密码策略及 Argon2 helper、AccountSecurityCrypto，不增加依赖。许可证沿用现有依赖清单。

成功意味着：以有效 handle/code 为凭证，在同一事务中改密、消费该 flow、退役全账号旧凭据、取消恢复邮件、写安全事件和匿名完成收据。绝不自动登录；客户端须重新登录。账号不存在、无资格、代次过期、已消费及错误 code 不向匿名方区分。有效完成收据允许安全重放和结果查询，不依赖已退役会话。

## 输入与公开端口

`RecoveryCompleteCommand { handle: SecretString, code: SecretString, new_password: SecretString, operation_id: Uuid, receipt_secret: SecretString }`。handle 严格为 canonical base64url 无填充的 48 字节（UUID16 + secret32），UUID 非零；code 恰好六位 ASCII 数字；operation 非零；receipt_secret 沿用 canonical 43 字符/32 非零字节。先验证这些结构和现有密码策略，再进入事务，禁止将秘密写入 Debug/日志。

`RecoveryCompletionService::complete_recovery(command) -> Result<(), RecoveryCompleteError>` 与 `recovery_completion_result(SecurityReceiptQuery) -> Result<bool, AccessError>`。错误类型 `RecoveryCompleteError { InvalidRecovery, Access(AccessError) }`；未知/过期/失效/无资格/失败限额统一 InvalidRecovery。结构错误为 InvalidInput；operation 重放不一致为 Conflict("recovery.operation_conflict")；容量/预算执行器/crypto 基础设施错误使用现有固定错误，不含输入或 SQL。未来 HTTP 分别映射 400（结构错误或统一 invalid_recovery）、409、503；结果查询仅 confirmed 布尔，不返回账号或 flow。

`CoreRecoveryCompletionService::new(mode, store, clock, crypto, ids, config, password_work)` 验证 config。所有时间在锁内采样，截断到 UTC epoch 整秒，拒绝 pre-epoch/溢出。

## 存储端口和投影

`RecoveryCompletionStore` 使用单个 GAT Transaction 和
`recovery_completion_transaction(mode, authority, flow_id: Option<Uuid>, callback)`。
所有阶段包括匿名收据查询使用 READ COMMITTED、access_state FOR UPDATE、5 秒 statement/lock timeout、verify + runtime authority/mode 检查。flow_id 为 Some 时，发现 flow/account，按 C 排序锁相关 tenant SHARE、account UPDATE，再锁 budget/flow；无 flow 不锁账号。所有恢复/会话/权限写与未来 cleanup 必须使用同一 state 屏障，保持现有全局顺序。

事务方法：
- `receipt(operation_id) -> Option<SecurityOperationReceipt>`（限定 PasswordRecovery）；
- `context(flow_id) -> Option<RecoveryCompletionContext>`；
- `record_failure(flow_id, budget: &RecoveryBudget, failed_attempts: u32, now: SystemTime, event_id: Uuid) -> ()`；
- `receipt_count() -> u64`；
- `complete(flow_id, account_id, expected_version, new_hash, now, receipt, event_id) -> ()`。

精确投影：`RecoveryCompletionContext { flow: RecoveryStartFlow, state: RecoveryFlowState, failed_attempts: u32, budget: RecoveryBudget, account: Option<RecoveryAccountSnapshot> }`；`RecoveryFlowState` 为 Pending/Consumed/Invalidated/Expired。复用flow包含id/subject_digest/account_id/snapshot_credential_version/handle_digest/code_digest/created_at/expires_at/retained_until；account/version可空且成对，failed_attempts范围0..5，budget必须存在。不加载旧密码 hash。投影字段/时间/非零 ID/配对和范围由 Core 校验，PG异常返回固定错误。复用 B1 的 per-account 完整 effective security admin 判定，不能只看角色名、只看一个 permission，或把业务 admin 排除。

## 三阶段算法与原子性

1. 第一事务先查完成收据，再查 flow。收据存在时必须目的/op/有效期/secret/command 全匹配才返回成功，完全不需要 flow 仍存在；不匹配或过期 conflict。无收据时校验 flow pending 且未过期、handle HMAC 匹配、失败次数 <5。两个事务都先将已过期预算投影为从now开始的新3600秒窗口、start_count/failure_count=0，再检查有效预算未达到10；未过期则保留计数。正确code不要求单独持久化窗口重置，错误code写入新窗口计数；匹配 handle 才允许增加失败计数，避免仅知道 UUID 即可锁死流程。未知/失效 handle 不写计数。
2. code HMAC 不匹配：在事务中增加 flow.failed_attempts 和 budget.failure_count。budget 已过期时按当前 now 开新3600秒窗口，start_count=0、failure_count 从0开始；未过期保留 start_count/window。第五次 flow 置 invalidated，并取消该flow尚pending/sending的邮件，清payload/key/lease，分别记录not_started/unknown；第十次累计失败阻止这个 subject 的所有完成尝试及新 start（B1既有行为）。返回 callback 的 `Ok(Invalid)`，使失败计数提交；事务外再映射 InvalidRecovery。禁止 callback 直接 Err 导致计数回滚。无资格 dummy flow 仍校验 code 并执行同样计数路径，但即使猜中也不能进入 KDF。每次已提交wrongcode同时写recovery_failed/rejected事件，account来自flow可空、operation_id=NULL、time=now，不存email/code/handle。生成canonical非零evt ID；事件唯一冲突回滚计数并沿用现有适配器的固定access.unique冲突；crypto错误为固定Backend，均不声称计数已保存。后续HTTP须将内部存储冲突映射基础设施失败，不能误当客户端operation重放冲突。
3. code 正确后检查 live account active、至少一个有效 membership、无 effective security admin、ID/凭据版本等于 flow snapshot；任何不满足统一 InvalidRecovery。返回内部 verified snapshot（flow、account、版本、subject），结束事务。取得共享 PasswordWorkBudget permit，调用现有 hash_password 计算新 hash，KDF 期间无 DB 连接/锁。预算饱和不消费 flow，也不增加猜测计数；permit 生命周期覆盖实际 hash。
4. 第二事务重新先查完成收据（处理并发相同操作），再读 flow/预算/账号。重新核验 pending、TTL、handle/code、失败限额、资格和 snapshot；不重复增加失败计数。新 start、改密、管理员停用/权限变更等在 KDF 间发生时必须阻止完成。收据容量总上限100000（含未清理过期行），超限不改密。
5. 生成24小时 PasswordRecovery 收据与 canonical 非零 evt ID。先将当前 flow 从 pending CAS 为 consumed，再执行账号 password UPDATE CAS（active、凭据版本一致）；触发器增加版本。复用 A4 的账户级凭据清理：全会话/refresh/code/租户选择/email verification 退役；scan grants/deliveries清密文及可恢复秘密，保留墓碑/审计；所有同账号 pending recovery 失效、相关邮件清payload/lease、start收据删除，保留budget。当前 flow 已 consumed 不被改成 invalidated。插入 recovery_completed/accepted 安全事件与完成收据。任何 SQL/事件冲突均回滚整个第二事务。

第二事务前的正确 code 检查不是单独消费。并发不同 operation 最多一个成功；同 operation+同 command 可通过完成收据幂等成功。一个请求先正确校验但另一请求耗尽猜测次数时，正确请求第二次检查也失败。失败尝试不能在事务未提交时对外声称已计数。

## 完成收据合同

purpose=PasswordRecovery，TTL86400秒，已有 security_receipts 存储，无新表。secret HMAC 使用 ReceiptSecret，context=(operation,None)，payload=receipt_secret解码32字节。command HMAC 使用 Command，context=(operation,Some(accountUUID))。payload 为逐段 u32 大端长度前缀拼接：domain `embedded-idp/password-recovery-complete/v1`、handle完整UTF8、code六位UTF8、new_password UTF8；各字段独立分帧，避免歧义。正确重放校验secret及整个命令，因此不能用同 operation 改密码/换flow。校验使用crypto adapter常量时间验证，支持存量previous key；未知key/密文问题按既有固定 Backend。

结果查询仅需 operation/receipt_secret；收据缺失/已过期/secret不符统一 false，有效匹配 true。持有secret的结果读取不需现存账号（receipt无FK），不影响后来登录的Cookie。完成收据删除后没有永久幂等保证，但已消费/删除 flow 不能再次恢复。

## 复用边界与实施顺序

1. 独立审查本文件：失败计数提交、预算跨窗口、两阶段CAS、管理员资格、收据上下文及A4清理兼容。修订问题后记录冻结。
2. Core 新 `access/recovery_completion.rs` 与定向测试；仅导出此端口，不引入HTTP/数据库依赖。
3. PG 新 `access/recovery_completion.rs`；将 B1 账号锁定/资格投影与 A4 账号凭据清理提取为 access 内部 helper（不新增公共抽象/存储trait）。A4原调用保持行为。不要复制第二套资格SQL和清理SQL。
4. Core 测试通过后跑两个 tenancy mode 的隔离 PG：有效完成+重新验证新hash、未知/无资格、wrong handle不计数、wrongcode提交、5次flow/10次subject/新代次不能清累计、窗口跨界、有效期边界、并发两完成仅一成功、同operation重放、事件冲突整事务回滚、第一事务提交后至第二事务开始前，改密/新start/停用/升级admin使旧snapshot失败（屏障可放在KDF开始前，不声称在CPU hash执行中注入）、所有凭据退役及收据匿名查询。
5. 回归 A4 全部 PG（含 login races）、B1 PG与相关 Core；fmt、工作区编译、diff检查。更新内部接口合同和交付进度。本批无路由变化，不能把 HTTP/OpenAPI 未实现记为完成。

## 第一轮 double check 修订

独立审查指出：成功事件必须使用已安装CHECK允许的recovery_completed（已修正）；有效失败预算必须先按到期窗口归零再检查阈值，不能让旧的10次计数永久阻止正确code（已修正）；wrongcode明确记录recovery_failed/rejected事件，并与计数原子提交。主代理补齐第五次失败取消outbox，防止失效flow继续投递。第二轮独立复核确认事件、nullable字段、预算到期规则及取消outbox满足既有DDL，无剩余阻断。

## 交付证据与限制

Mock只证明Core规则；真实PG才证明SQL约束/事务。并发测试使用屏障确定交错，不靠sleep猜测；测试注入仅用于暴露真实生产阶段，不能改生产密码策略/资格。无真实SMTP/COMMIT断网/生产环境验收结论；本批邮件仍不发送。
