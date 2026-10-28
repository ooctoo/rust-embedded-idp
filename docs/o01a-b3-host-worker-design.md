# O01a-B3 参考宿主邮件 worker 与安全清理生命周期

2026-10-26；已完成两轮独立 double check，修订后冻结，可开始编码。依赖O01a-B2已验证的Core/PG outbox及O01a-A物理子进程发送器。本批只接宿主运行时，不新增恢复HTTP或Web。没有新增第三方依赖、数据库迁移或通用任务框架。

## 显式配置及装配

`runtime.account_security`新增可选bool `recovery_email`，默认false，兼容现有仅会话撤销/改密配置。true要求同runtime.email存在且mode=smtp；sendmail/log和缺失邮件配置在静态配置校验时拒绝，错误固定且不含秘密。沿用现有SMTP字段、secret_ref和相对路径处理，不另建供应商配置。CLI静态security-plan/apply/check只验证该组合，不读取SMTP或安全密钥；在线启动再解析秘密。validate_for_startup保留非秘密检查（它在email解析前也被调用）；build_composition在已解析配置上另做EmailDeliveryConfig检查，覆盖直接构造路径，不能改变既有secret解析顺序。

只要account_security配置存在，就构造同authority/crypto/store的CoreSecurityOutboxService并启用每秒一次有界cleanup，避免仅使用本人改密时收据无消费者而占满。只有recovery_email=true才构造ProcessSecurityEmailSender（当前可执行文件+固定内部helper子命令）并启动四个发送循环。复用已加载crypto，不重复读key文件；缺配置仍保持现有行为。runtime扩展缺失/漂移仍在启动/readiness fail closed，不自动DDL。

AppComposition增加`security_runtime: Option<SecurityRuntimeJob>`，含`service: Arc<dyn SecurityOutboxService>`和`sender: Option<Arc<ProcessSecurityEmailSender>>`。新App模块`security_runtime.rs`负责调度/时间桥接/关闭。bootstrap两条composition返回路径都携带该job。保持服务和sender的一个clone在Tokio runtime外直到runtime停止后释放，避免同步PG池最后引用在异步上下文销毁。仅在listener绑定成功后spawn任务；build_composition本身不启动后台发送。

## 有界调度

`spawn(job, watch::Receiver<bool>)`返回持有JoinHandle的运行句柄。固定四个发送loop（有sender时）和一个cleanup loop，无待发内存队列。每个loop同时至多一个spawn_blocking DB操作；await物理结果后才开始下一步，不通过timeout+重试制造并发堆积。发送loop每轮结束后等1秒（没有候选、错误或成功均一样），cleanup每轮结束后等1秒，错过tick不补跑。初次可立即执行；关闭watch初值true或通道关闭都不开始新claim/cleanup。

所有同步Core调用使用spawn_blocking并保留JoinHandle直到完成；记录错误只用固定消息，不打印AccessError底层内容、邮箱/code/lease/配置或数据库连接。返回错误下轮重试；claim失败绝不能发送。cleanup每次只调用一次Core.cleanup（100上限），不while耗尽积压。

发送loop：claim提交返回Some后，检查stop；已关闭则不发SMTP，以NotStarted调用finish（允许后续重启有限重试）。否则构造固定PasswordRecovery正文，只有code和提示“如非本人请求请忽略”，不放handle或账号权限。收件地址/正文只能进入受控发送器stdin，不进入日志。

发送绝对Instant deadline计算使用同一时刻采样SystemTime::now和Instant::now：remaining=min(claim.lease_until,claim.expires_at)-wall_now，deadline=instant_now+min(remaining,15秒)。remaining<=0或时钟早于推导的lease创建时间(lease_until-30秒)则不发送，finish NotStarted；不通过重新设置15秒延长旧lease。物理sender仍会用自身now+15s二次收紧，并保留最多2秒kill/reap。wallclock/进程暂停并不支持发送与撤销跨进程原子性，已发旧code依赖恢复事务版本复查失效。

调用SecurityEmailDeliveryService::send后映射四种typed outcome，仅写一次finish。finish失败时不重新发送、不新claim来重试同一邮件；保留sending行，30秒lease后cleanup转Unknown。避免无界结果重试队列；已接受但写回失败的物理结果不可确认，不能伪造Accepted数据库证据。finish false意味着已被并发取消/清理，不报投递成功或错误覆盖。

## 停止与物理资源

main复用已有stop watch，HTTP结束/错误或SIGINT/SIGTERM都会发true。安全runtime关闭与HTTP/scan drain并行，不被HTTP的10秒或scan的5秒超时提前替代。

停止信号后同时：1)发送器shutdown置closing并等待其登记supervisors（最长15秒发送+2秒清理，异常槽保持隔离）；2)所有循环停止领取，等待已开始的DB/send/finish路径完成。正在claim的DB返回后会观察stop并只finish NotStarted，不启动SMTP。sender closing是第二层保护，不能靠轮询stop消除发送竞态。

为避免外部DB/网络异常阻止进程退出，安全loop drain最多35秒；到时abort尚未完成的异步loop并await其取消，记录固定“security runtime database outcome unknown”。禁止把abort称为取消spawn_blocking内部物理DB操作；这些操作最多五个、不会启动新的后继发送，可能继续至数据库/连接超时（现有PG transport每连接/事务有共享10秒绝对物理deadline，不把逐语句5秒当作总时限）。发送器supervisor不由loop abort取消，仍须独立await sender.shutdown后才退出runtime.block_on。现有runtime.shutdown_timeout(5秒)最后处理残余阻塞工作；不宣称总DB物理工作已终止。35秒为发送17秒加后续PG操作10秒及调度余量；停止发生在claim中时，claim最多10秒后只执行NotStarted finish，不再发送。此边界与既有DB连接绝对deadline和逐语句超时一致，不为本批新造通用进程DB执行器。

如果loop panic，其他loop仍可工作，失败以固定日志记录；关闭必须收割全部句柄，无丢失JoinHandle。sender.shutdown重复调用安全，但main只调用一次。关闭返回表明发送器登记任务已等待完成或隔离，不等于SMTP收件箱送达，也不等于未知DB事务未提交。

## 实施计划

1. 独立复核配置静态/在线两路径、pool生命周期、send截止时间与stop竞态、DB超时真实边界；修订后再次确认。
2. 新security_runtime模块，生产只暴露具体job/运行句柄；测试内部可注入trait sender/clock或缩短调度周期，但不公开新的宿主通用调度API。Core/PG端口不改。
3. account_security_config与composition_config增加bool及验证，bootstrap复用crypto装配job，main按上述并行drain保留服务/等待发送器。
4. 局部单元测试：四路上限/不补跑、无sender只cleanup、已关闭不claim、claim后stop不发、send deadline不越lease/flow、发送未知不重发、finish失败不重发、发送中stop仍等待物理sender、超时后loop不再发/不新增DB操作、配置默认兼容及true组合拒绝；不使用sleep猜测竞态，使用Notify/oneshot/barrier。
5. 隔离真实宿主两mode：启动预置pending outbox，合成SMTP接收一封并验证accepted/清payload，Unknown不重发；SIGTERM发送中等待/kill-reap及readyz不受秘密输出影响，重启对expired sending仅Unknown。测试只连临时本地SMTP和一次性PG，不使用真实凭据。配置未开启时不发送，account_security存在时仍cleanup。
6. 工作区编译、App局部测试、必要既有helper/配置回归、接口漂移与宿主配置文档更新。测试证据不外推完整验收或部署。

## 待复核项

35秒安全loop drain只限制宿主等待，不能证明同步DB任务物理终止；文档和日志须保留此限制。若现有main的pool保留或helper任务登记不满足此顺序，应先修设计再改代码，不通过丢弃句柄掩盖关闭失败。

## 第一轮复核修订

静态配置检查留在secret解析前，解析后防御检查移入bootstrap，避免CLI提前读取SMTP秘密。独立审查确认PG transport每连接/事务共享10秒绝对物理deadline；将loop drain从25秒提高为35秒，覆盖在途发送17秒及随后finish10秒，并继续明确async abort不代表取消物理DB执行。第二轮已确认配置顺序、关闭窗口与物理deadline边界无阻断，冻结实施。

实现验证补充：并行App测试中旧helper超时测试的PID握手2.5秒偶发早于shell启动，单独运行3秒deadline通过。本批将该测试的物理deadline改为10秒、PID等待9秒，helper sleep30秒保证仍由deadline终止；生产SEND_LIMIT=15秒和CLEANUP_LIMIT=2秒保持不变，PID消失及许可回收断言保留。
