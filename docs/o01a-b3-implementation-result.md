# O01a-B3 宿主安全邮件运行时实施记录

2026-10-26。先两轮独立设计复核再编码，主代理负责配置/装配/主进程，运行时模块和测试有独立任务分工；最终接线另经独立只读审查。没有恢复HTTP或Web功能接线，也没有部署。

## 已实现

account_security可选recovery_email bool默认false；启用须runtime.email.mode=smtp。静态配置在secret解析前验证组合，准备CLI不读取SMTP/crypto秘密；bootstrap检查解析后配置。复用原邮件配置和已加载crypto，不新增依赖。两个宿主composition分支均携带安全运行时。

account_security存在时总是启动一个每秒有界清理loop；邮件启用才增加四个发送loop。listener成功绑定后才启动，DB调用spawn_blocking且不重叠，无内存待发队列。发送deadline取15秒、剩余lease/flow期限最小值；claim后停机不发邮件，只写NotStarted。finish失败不重发，最终由租约超时转Unknown。

stop watch贯穿HTTP/scan/security三路并行收尾；sender置closing并等待真实supervisor，安全loop最多35秒。超时仅abort/收割剩余async handles，不宣称取消物理DB；PG仍受原10秒绝对deadline约束。保留service/pool引用到Tokio runtime停止后。固定诊断不包含秘密。代码复核修复了超时后重复poll已完成JoinHandle的问题；测试对应修正为单一drainer持有句柄。

## 验证

- 运行时定向6项、配置22项通过；App完整局部套件最终71项通过，最终主代理记录 `/private/tmp/idp-o01b3-final-app.log`。
- 真实参考宿主四个ignored集成用例都覆盖Disabled/Enabled：Accepted落库并清payload，Unknown不再连接SMTP，recovery_email省略时仅cleanup，SMTP已进入DATA时SIGTERM、观察固定drain日志、确认进程仍存活后释放250并完成Accepted收尾。成功/关闭/cleanup证据在 `/private/tmp/idp-o01b3-reviewed-host.log`，Unknown定点修正后通过在 `/private/tmp/idp-o01b3-final-host.log`。
- 同一最终host日志还记录既有S03-A5管理/业务Bearer/Cookie多入口改密回归1项（双mode）通过，验证默认false及cleanup接线兼容。共5个真实host用例已有通过证据，不把早期失败log当绿灯。
- 工作区all-target离线编译通过（`/private/tmp/idp-o01b3-workspace.log`）。本批HTTP路径和DTO未改，接口说明更新outbox/宿主配置文档，未生成候选恢复端点。

## 失败排查和证据限制

首轮host仅cleanup通过：新合成SMTP accept后未切回blocking，macOS继承非阻塞导致协议读取提前退出。修复与既有helper测试相同的阻塞模式后发送/停机路径通过。Unknown观察用例将2500毫秒误写成秒，主代理只连接该临时fake SMTP唤醒断言，使旧测试正常失败并Drop清理；改正单位后单独重跑通过，没有修改生产重试策略。

App整组测试先暴露旧helper PID启动握手2.5秒在并行负载下偶发早于shell启动。该测试物理deadline改为10秒、PID等待9秒、helper sleep30秒，仍验证超时kill/reap后PID不存在及4槽归还；生产15秒发送/2秒清理限额未改。另一个新测试复用了重复await句柄写法，已修正，并整组重跑。

全部SMTP仅本机合成服务器，PostgreSQL为一次性容器，测试账号/密钥为合成材料，容器自动清理。不证明真实供应商TLS、到达收件箱、生产吞吐或完整验收。35秒是宿主等待窗口，不是把所有未知数据库结果断言为未发生。

## 待推进

下一批恢复start/complete/result HTTP及共享准入、浏览器guard、OpenAPI/漂移；其后Web会话管理、本人改密、密码恢复及未知结果交互；最后一期交付清单核对。当前仍未完成一期整体目标，未提交、推送、部署或做完整验收。
