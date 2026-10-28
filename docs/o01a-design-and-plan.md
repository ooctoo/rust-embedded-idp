# O01a 最小安全事件及邮件投递设计与实施计划

2026-10-26，设计草案，尚未编码。服务于本期 S03 邮箱密码恢复，不引入 Webhook 或消息中间件。

## 已核对的复用边界

Email 的 RegistrationEmailDeliveryService 已定义真实物理返回、绝对 Instant deadline、Sent/Rejected/Unknown 与脱敏 Debug。注册 runtime 包含准备/processing/未知结果恢复，但其资格、字段和数据库表以 pending 注册与账号激活为核心；不能仅换 purpose 用于恢复。保留这些公共注册合同。普通 EmailSenderProvider 只有 Result/message，不能通过错误字符串判断投递是否发生。

复用现有 lettre SMTP、ring AES-256-GCM/HMAC、现有 PostgreSQL 连接池与事务设施。密码恢复的加密上下文、票据和资格独立；安全事件不伪造 AccessAdminContext。无需引入新第三方依赖。原有 MIT/Apache-2.0 项目依赖许可由现有依赖清单维护，新增治理组件 governor 另有 S01 G0 记录。

## O01a-A 投递合同与真实资源边界

先增加独立、可选的通用安全邮件请求与类型化结果：Accepted、Rejected、Unknown。请求不实现明文 Debug；结果不含 provider 原始错误。方法带绝对 deadline，返回意味着实际发送已结束。旧 provider 若无法确定错误阶段，只能映射 Unknown，不能按错误文本猜测。Accepted 只代表供应商接收，不代表收件箱投递。

参考宿主使用一个共享投递容量（4 槽）；许可移动进真实阻塞工作，调用取消不能提前释放。SMTP 配置连接/读写超时，DNS 与底层阻塞仍需明确能力边界；不得声称 tokio timeout 可终止同步发送。首批新安全邮件 worker 仅支持可满足限定契约的 adapter；不能以 detached task 冒充取消。sendmail 必须同时覆盖 stdin 写入与子进程等待、超时 kill/reap、stderr 有界且脱敏；如不能完整实现该资源边界，则新恢复投递明确拒绝该模式，保留旧注册兼容入口并单列限制。

Log 模式不输出地址、正文、验证码或 token；仅输出固定的事件和条数。Log 不能把密码恢复投递标记 Accepted，返回 Rejected。旧注册 Log 的业务返回兼容，但必须说明开发日志不再作为验证码收取渠道。

## O01a-B 最小持久事件/outbox（待详细事务复核）

通过显式可选 security_v1 扩展安装，不能在线启动自动创建，不能修改 tenant_v6 固有迁移版本。事件包含随机 ID、类型、时间、主体可空、关联 operation、有限结果；禁止密码、验证码、token、邮件正文及原始 provider 错误。

恢复 start 在一笔事务中生成 flow、摘要、短期加密 payload 和事件；outbox 只保存加密邮箱/code/expiry、key ID、flow ID、尝试/状态和租约，不存明文 code。AAD 包含部署域、用途、flow 与 delivery ID，拒绝跨 flow/用途替换。密钥由宿主显式提供，缺失或不匹配 fail closed，最多当前与一个退役读取 key；不能每次启动自动随机生成持久加密 key。

worker 有界 claim、租约 token 条件更新；SMTP 不在数据库事务中。Accepted 后 sent；确定 Rejected 可按有限策略重试；Unknown 或物理返回前租约过期不能直接再次发送，进入 unknown，用户只能走受累计限额控制的新代次。旧 worker 完成结果必须匹配租约 token，不能覆盖新状态。过期/消费/失效后清除 payload；审计保留非秘密结果。claim、完成、清理均需有限批次。吞吐与持久数据保留上限在编码前进一步固定。

## 实施与验证门槛

1. 完成 A 合同、同步 adapter deadline/容量细节复核后才编码；局部测试覆盖 redaction、满载、取消后真实许可、Rejected/Unknown、超时。
2. 为 B 补齐精确 schema/锁序/租约/幂等/清理设计，与 S03 flow 事务一起 double check，再写 Core/store/迁移。不能先建缺乏消费者的通用调度平台。
3. 合成邮件 adapter 与独立 PostgreSQL 集成验证回滚、双 worker、租约过期、迟到完成、COMMIT unknown、payload 清理。
4. 宿主显式启用/检查扩展、注入 key、启动/停止 worker，更新配置、合同与交付清单。真实 SMTP 供应验收和部署仍另行安排。

本草案不代表设计已通过；A 的 DNS/同步物理超时和 B 的精确表合同是编码前必须闭合的项目。

## A 物理截止时间细化（待独立复核）

同步 lettre 的 socket timeout 不能证明 DNS/供应商整段执行在绝对 deadline 前结束。因此本期参考宿主新安全邮件使用受控子进程：同一可执行文件的内部 mail-helper 子命令，仅从 stdin 接收有界的完整类型化投递配置和消息；stdout 仅一个固定结果，stderr 丢弃，凭据不经 argv/临时文件/日志。父进程通过 Tokio process/io 写入、等待，统一绝对 deadline；失败/超时 kill 并 reap 后才释放共享 4 槽许可。内部 helper 仅运行 SMTP，sendmail 和 Log 对新安全邮件明确 Rejected；不变更旧注册 sendmail 合同。本设计不新增通用进程管理库。

每次发送的 supervisor task 由 worker 持有；caller 取消不 abort supervisor，许可覆盖 kill/reap。App 关闭需停止领取、等待在途；最迟 deadline 到达后收割 helper。父进程意外退出依赖平台进程生命周期，交付文档不能宣称跨宿主崩溃绝不重复；数据库 lease 过期只转 Unknown，禁止自动重发。helper 内也设置 SMTP socket timeout 作为第二层边界。

A 的失败分类：本地配置/请求非法、明确未启动时 Rejected；helper 明确 SMTP accepted 才 Accepted；helper 启动后的断管、超时、非正常退出、协议结果异常一律 Unknown，不解析 lettre 错误文本推测是否投递。helper 自身只能在建立 SMTP 调用前给出 Rejected；调用后的所有 err 均 Unknown。这比乐观重试保守，但符合密码恢复通知不可确认重复的要求。

请求序列化体上限 16KiB；stdout 协议最多 32 字节，禁止缓冲无限日志。timeout 通过 tokio 的进程 I/O future 管理；不以同步写 stdin 的方式制造超时前置阻塞。新增 tokio process/io-util 是已有依赖的 feature，不引入新的 SMTP 实现。单次 deadline 固定 15 秒，helper socket timeout 5 秒；最大 4 个真实 helper。无容量则 Rejected（未开始）；outbox 稍后重试须区分该本地未开始状态与 SMTP 未知，实施时明确持久状态字段。

## A 独立复核修订与冻结合同

独立复核指出关闭时序与 Rejected 混合分类问题，现冻结如下，A 可进入实现；B 仍需独立细化。

- Email 新增异步 SecurityEmailDeliveryService（标准 Future/Pin，无 async-trait 依赖），SecurityEmail 请求自定义脱敏 Debug，结果四种：Accepted、Rejected（终止性本地无效/不支持）、NotStarted（容量不足、关闭中、spawn 失败，可稍后重试）、Unknown（启动后结果不确定）。旧 EmailSenderProvider 不作隐式转换。
- helper 退出码协议：0=Accepted；2=Rejected（解码/配置/构建消息失败、尚未调用 SMTP）；3=Unknown（SMTP 已调用且失败）。其他退出码、信号、超时、断管均 Unknown。stdout/stderr 全部 null，不再读 stdout；因此不存在无限输出及 pipe 双向死锁。配置与邮件仅走父进程异步有界 stdin。
- 请求包含单一收件邮箱、正文和固定用途；helper 输入连同显式 SMTP 配置最多16KiB。父进程 env_clear，不继承宿主 DB/令牌环境。构建 SMTP message 的错误只用于退出码，不输出原始错误。采用既有 subject/from/TLS/credential 配置，禁止 Debug 输出配置。
- ProcessSecurityEmailSender 持有共享4槽 semaphore 和带 closing 标志的短 Mutex 任务登记表。send 在登记锁内检查关闭、取得许可并启动受控 supervisor，表中清除已完成句柄；结果通过 oneshot 返回。取消 send 只丢弃接收者，不取消登记中的 supervisor。许可移动入任务，物理子进程退出/kill+wait 后才释放。没有无界 waiting queue。
- shutdown 先在登记锁内置 closing 并取出全部在途句柄，然后逐个 await；每个 supervisor 已有最多15秒的绝对截止时间，禁止用5秒 runtime shutdown 替代。A 提供且测试该 shutdown；B 挂载 worker 时必须在 main 的 runtime.block_on 内先停领取并调用此 shutdown，再退出 runtime。A 未挂载消费者时不宣称宿主恢复 worker 已交付。
- 每次 send 的绝对 deadline 取调用方期限与 now+15秒的较早值，过期请求 NotStarted；helper socket timeout5秒。父任务在 stdin 写入/关管与 wait 的整段上使用同一 deadline；超时显式 Child::kill().await（含 wait），kill_on_drop 仅作异常后备。kill/reap 异常不能声称完整清理：该槽应保留隔离，不再派发，结果 Unknown。
- 旧注册 Log 输出改为固定 suppressed 事件与收件人数，兼容旧返回；这属于去除秘密输出，需补脱敏回归。旧 sendmail 并未完成新的安全投递合同，恢复 worker 不调用它。

A 实现复核补充：kill/reap 整段再加2秒清理期限，异常超时则隔离该槽并返回 Unknown，shutdown 返回不代表隔离槽已回收，必须记录该健康限制；正常 supervisor 总耗时最多15秒发送+2秒清理。旧 SMTP transport 在未传新 timeout 时保留 lettre 原有默认值，不能把 None 当作无超时注入而改变旧注册行为。测试除假helper外，增加实际二进制和本地合成SMTP协议的 Accepted/Unknown/非法请求/脱敏验证，不连接真实供应商。
