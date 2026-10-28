# S03-B2 密码恢复完成实施记录

2026-10-26。详细设计两轮独立复核后编码；Core与PG实现另经独立源码审查。新增完成恢复及匿名结果端口，没有HTTP/邮件worker/Web接线。

## 实现结果

- 六位code与随机handle验证；错误handle不扣猜测次数；错误code在事务中持久增加flow与subject累计次数、写recovery_failed事件，再返回统一InvalidRecovery。每flow5次、每窗口累计10次，过期窗口先归零；第五次取消该flow邮件并清payload/lease。
- 第一事务验证后释放连接/锁，在共享密码预算内生成hash；第二事务重验flow期限/状态、凭据版本及当前资格。成功CAS改密并消费flow，写完成事件与24小时收据，不自动登录。
- B1的完整账号资格SQL提取为内部recovery_account helper；A4全账号凭据退役SQL提取为内部password_retirement helper。恢复与本人改密复用同一退役行为，未新增数据库结构或依赖。
- 同operation及相同命令可从完成收据重放；结果查询仅operation/secret，过期或不匹配返回false。内部SQL唯一冲突沿用access.unique，不冒充客户端operation冲突。

## 复核修订

设计阶段修正成功事件名为schema允许的recovery_completed；调整预算顺序避免过期10次失败永久锁死；明确wrongcode失败事件与计数原子提交、第五次邮件取消。实现阶段静态复核确认锁序、两阶段重验及清理复用无阻断。

首轮live 4/7通过，3处测试断言/夹具错误已修正：事件唯一冲突实际映射access.unique；预算窗口[0,3600]相对NOW=1000并未过期，改为显式AtClock(10000)创建新flow及校验过期预算，保留全部真实TTL约束。重跑7/7通过。

## 验证和证据边界

- Core定向12项、Core lib全部350项通过（`/private/tmp/idp-s03b2-core.log`）。覆盖收据过期/命令重放、错误handle、无资格不KDF、预算饱和、两个事务间凭据/成员/管理员资格变化；mock只证明Core规则。
- PostgreSQL新增7项通过（`/private/tmp/idp-s03b2-reviewed-live.log`）：双模式成功改密后真实登录验证新hash、旧会话退役与邮件清密文、code计数/5次与10次门槛/过期窗口、失败事件和成功事件碰撞各自整事务回滚、两并发请求至多一次消费、第一事务提交后成员资格撤销导致第二事务拒绝。
- 资格变化的确定性屏障放在第一事务提交后、KDF开始前，覆盖两事务间快照失效窗口，不声称在CPU hash执行中注入。
- 工作区all-target离线编译通过（`/private/tmp/idp-s03b2-workspace.log`）；fmt和diff检查通过。隔离数据库容器使用合成账号并自动清理。原8个未跟踪测试SHA256保持一致。
- 共享helper回归：B1恢复开始4项、A4本人改密及登录交错5项全部通过（同一 reviewed-live 日志），本轮真实PG共16项。没有真实SMTP供应商、COMMIT网络故障或生产环境验证。

接口见 [恢复完成合同](api/recovery-completion-contract.md)。后续仍须持久outbox worker/cleanup、宿主生命周期、恢复HTTP与Web安全交互、一期交付清单；本批不等同一期整体完成，未做完整验收、部署、提交或推送。
