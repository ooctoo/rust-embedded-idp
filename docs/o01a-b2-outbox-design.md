# O01a-B2 持久恢复邮件投递与清理设计

2026-10-26；已完成两轮独立 double check，修订后冻结，可开始实现。依赖 S03-B1/B2、security_runtime_v1、已有 AccountSecurityCrypto 和物理 SecurityEmailDeliveryService。本批实现 Core/PG claim/finish/cleanup 与局部测试；宿主调度、启停及HTTP在后续批接线。不改变已安装DDL、不引入新依赖或消息中间件。

## 复用和责任

Core拥有资格、解密、重试/状态决策和租约时效；PG拥有有界选择、锁和原子更新；App后续将Core返回的收件邮箱/code构造固定正文并调用现有4槽物理发送器。Email的Accepted/Rejected/NotStarted/Unknown映射到Core独立枚举，Core不依赖Email/HTTP/数据库。沿用现有ring/lettre及许可清单，不另建SMTP栈。

复用access内部recovery_account完整资格及锁序。每次调用READ COMMITTED、access_state UPDATE、5秒statement/lock timeout、base/foundation/runtime/authority检查；锁顺序tenant(C排序)→account→flow→outbox。数据库事务内无SMTP/阻塞KDF。时间在屏障后按UTC整秒采样，负epoch/溢出拒绝。

## 精确 Core 合同

`SecurityOutboxService`：
- `claim() -> Result<Option<SecurityMailClaim>, AccessError>`；单次最多选择并处理1个候选。宿主未来最多4个发送loop，各自claim后立即send，无额外无界队列。
- `finish(completion: SecurityMailCompletion) -> Result<bool, AccessError>`；true表示该租约结果成功落库，false表示行已不存在/已终态/租约已替换。重复finish不产生第二事件。
- `cleanup() -> Result<SecurityCleanupResult, AccessError>`；每调用最多处理100个逻辑记录（跨各类合计），不无限循环。

`SecurityMailClaim { outbox_id: Uuid, flow_id: Uuid, lease_token: Uuid, lease_until: SystemTime, expires_at: SystemTime, recipient: SecretString, code: SecretString }`。手写或安全Debug不输出邮箱/code/token。租约UUID通过现有IdGenerator生成canonical非零ID；token是内部CAS能力，不进入HTTP或日志。
`SecurityMailOutcome::{Accepted,Rejected,NotStarted,Unknown}`。
`SecurityMailCompletion { outbox_id, lease_token: Uuid, outcome: SecurityMailOutcome }`（lease Debug隐藏）。
`SecurityCleanupResult { processed: u32 }`只统计选中逻辑记录，级联附属行不单独算，不暴露主体或payload。
`CoreSecurityOutboxService::new(mode,store,clock,crypto,ids)`。

存储GAT `SecurityOutboxStore::security_outbox_transaction(mode,authority,callback)`，Transaction方法：
- `candidate(now) -> Option<SecurityMailContext>`：pending且next_attempt<=now，按next_attempt,id稳定顺序，最多1；先发现后锁账户、flow/outbox，重读同一投影。
- `current(outbox_id) -> Option<SecurityMailContext>`：用于finish，按同一锁序读取。
- `transition(outbox_id, expected_lease: Option<Uuid>, change: SecurityMailTransition, event_id: Option<Uuid>, now) -> bool`：expected None只允许pending；Some只允许sending且token匹配；CAS状态/token相符才写状态并选装email_delivery事件。不得以None匹配任意状态。
- `cleanup(now, limit: u32, event_ids: &[Uuid]) -> u32`：精确语义见后文，limit必须1..100，event_ids必须恰好limit个互异非零UUID；Core在调用前通过IdGenerator生成并校验，最多100个。

`SecurityMailContext { outbox_id, flow_id:Uuid, state:SecurityMailState, envelope:Option<SecurityEnvelope>, created_at,expires_at,next_attempt_at:SystemTime, attempts:u32, lease_token:Option<Uuid>, lease_until:Option<SystemTime>, flow:RecoveryStartFlow, flow_state:RecoveryFlowState, failed_attempts:u32, account:Option<RecoveryAccountSnapshot> }`。state枚举Pending/Sending/Accepted/Rejected/Unknown/Cancelled/Expired。字段合法性由Core校验，不把损坏投影当无记录；outbox与flow的created_at/expires_at必须分别相等，候选next_attempt_at不得晚于锁后now，finish遇now早于created_at拒绝回退时间。账号/flow版本配对与邮箱来自既有projection，不从payload授权。

`SecurityMailTransition`：`Sending { lease_token, lease_until }`，`Retry { next_attempt_at }`，`Terminal { state:SecurityMailTerminal, outcome:Option<SecurityMailOutcome> }`。Terminal枚举Accepted/Rejected/Unknown/Cancelled/Expired，不允许构造pending。Sending在PG将attempts+1，保留密文；Retry保留attempts与密文并清lease（只允许sending、attempts<3）；Terminal清envelope/key/lease。事件outcome对NotStarted映射schema允许的rejected（表示未获发送接收，本地可重试性质由outbox.last_outcome=not_started表达），其他同名；无实际投递的expire/cancel可不写email_delivery，避免伪造供应商结果。发送claim本身无事件；finish实际结果写事件。

## claim 决策

候选不存在返回None。校验投影后：outbox/flow到期、flow不再pending或已5次失败、当前账号不active/无有效成员/已有有效安全管理员权限、credential version不匹配，则将pending取消（已到期为Expired，否则Cancelled），清payload/lease，last_outcome=NotStarted，返回None。无法撤回已发送邮件，恢复完成仍重新核验code和资格。

资格通过后用RecoveryEmail(context=outboxID+flowID) open；解析恰好三行 `recovery-email-v1\nemail\ncode`（无尾LF），email必须等于当前账号email且没有控制/额外换行，code六位ASCII数字。验证code的RecoveryCode摘要与flow一致。密文无效/格式错误/code不符：原子转Rejected、last_outcome=Rejected并写email_delivery/rejected，不发送。UnknownKey/Unavailable等密钥配置故障返回固定Backend并回滚、不消耗尝试次数；后续宿主固定退避，不紧循环。只允许attempts<3；创建lease=now+30秒，随机token，Sending将attempts+1。提交成功后才返回明文claim；COMMIT错误不能发送。

## finish 决策

检查command ID非零。当前不是sending或token不符返回false，不能覆盖被改密/新代次/清理取消的状态。匹配租约但now>=lease_until：转Unknown、清payload/lease并写email_delivery/unknown，忽略迟到成功报告；不自动重发。

租约有效时重查flow/账号资格/版本；若已失效或到期，转Cancelled（到期Expired）并清payload/lease，last_outcome记录本次真实物理结果，写该结果事件，不再重试。资格仍有效时：Accepted→Accepted，Rejected→Rejected，Unknown→Unknown；均终态清payload。NotStarted且attempts<3且now+1<expires_at→Retry(next=now+1)，last_outcome=NotStarted；否则Cancelled+NotStarted。attempts计数每次claim，包括NotStarted，最多3次。有效SMTP返回Accepted只证明供应商接收，不能叫收件箱送达。

宿主后来必须在send前核对claim还未过本地wall-clock lease/flow expiry，并把绝对物理deadline限制为min(15秒,剩余租约/有效期)。进程暂停与发送之间无法提供跨进程原子性：claim后被撤销仍可能发出已失效code；finish CAS不能重新激活它。SMTP调用完全在DB事务外，未知状态永久禁止自动重发，用户只能按start限额新建代次。

## 有界清理

同一state UPDATE事务，单次总额度100，依次处理以下记录；每类稳定排序并LIMIT剩余额度，使用CTE选ID后UPDATE/DELETE，不先无界加载：
1. sending且lease_until<=now或outbox expires<=now：Unknown、清payload/key/lease、last_outcome=Unknown，写email_delivery/unknown事件。一次选中outbox计1；PG按选中顺序使用Core提供event_ids的前N个，必须在同事务原子转态和插入事件，不在SQL中随机生成ID。
2. pending且expires<=now：Expired、清payload/key/lease，NotStarted，无投递事件。
3. startreceipt expires<=now：删除整行；不依赖flow是否消费。
4. pending flow expires<=now：置Expired（密文由1/2清理；后续claim不会再发送）；
5. flow retained_until<=now：删除（级联outbox/startreceipt）；无凭据或quota变化。
6. 成功receipt expires<=now：删除；
7. budget expires<=now且不存在同subject任何保留flow：删除。S03-B2的context投影对终态/过期flow也要求budget存在，因此保留到最后一条flow被清理；仅保护未到期pending不足以兼容现有读合同。该摘要预算最多随flow额外保留24小时，不含明文邮箱；到期预算仍按新窗口归零，不延长限额封锁。
8. security_events occurred_at<=now-30天：删除；now小于30天时不执行，避免负epoch。

发送终态outbox随flow24小时保留后级联删除。上述时间是逻辑失效/清理资格阈值；物理删除由有界后台批次完成，积压时可能晚于阈值，不能宣称到秒物理删除。逻辑期限在业务和claim中独立强制检查。cleanup不会删除仍在有效期内的成功receipt，也不删access_audit或scan墓碑。无轮询无自动迁移；宿主后续每秒一批清理，不能用while耗尽队列阻塞业务。

## 实施顺序和验证

先独立审查精确端口/DDL枚举/事件生成/清理总额度、state屏障及发送未知边界，修正文档并二次复核后编码。然后Core service+mock，PG事务+真实隔离测试，最后独立审查实现及回归B1/B2/A4必要场景。此切片不改变HTTP合同。

Core测试覆盖payload/AAD/code校验、密钥错误、无资格/到期、租约边界、NotStarted三次、迟到finish和无秘密Debug。双mode PG测试覆盖两worker不双领、发送事务外、claim回滚不返回可发送内容、重复/迟到finish、权限/改密/新代次后不覆盖取消、Unknown不再claim、cleanup总量100及receipt/budget在途保护、事件冲突回滚。清理与恢复并发用state锁确定性屏障，不使用sleep猜测。

证据仅为局部Core/PG；物理发送器已有A测试，宿主worker真正启停/物理deadline/容量将在下一批联合验证。暂不做完整验收、部署或推送。

## Double check修订

第一轮独立审查确认DDL、事件映射、AEAD上下文及物理发送器边界一致。主代理进一步发现cleanup删除budget会破坏B2终态flow的必要budget投影，因此删除条件加强为不存在任何保留flow（非仅在途flow），并要求集成验证清理后旧handle仍统一InvalidRecovery而非存储错误。第二轮复核确认此规则与B1/B2投影及FK/清理顺序兼容，无剩余阻断。
