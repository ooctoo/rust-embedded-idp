# S03-A4 本人改密 Core/PG 局部实施结果

2026-10-26。设计先经独立double check，六项修改写回冻结后实施；Core与PG代码分别完成独立只读审查，主代理检查实际变更与集成。设计见s03-a4-password-change-design.md，接口见api/self-password-change-contract.md。

## 实现

新增专用本人改密Core服务、只读/写GAT存储端口及PG适配器，未改变旧AccessError枚举或旧构造器。当前密码验证与新密码hash在共享工作许可内、数据库事务外执行；写事务重查可信actor及快照，以account/status/旧hash/credential version作CAS。凭据版本由既有foundation trigger推进。

密码更新、全账号跨租户/purpose凭据退役、扫码秘密清除/版本推进、恢复flow及outbox取消、start receipt清理、安全事件和24小时成功receipt同事务提交。保留累计邮箱budget、账号/设备/绑定/密钥、扫码历史与tombstone；无关账号保持有效。结果查询无需已撤销actor，仅提供bool确认，不自动登录或自动重试写入。

本批未增加依赖、DDL或迁移，复用既有密码helper、Argon2、Ring加密端口及运行时表。不包含HTTP、宿主改密挂载和Web，不能据此声称用户已能在页面改密。

## 证据

- Core新增9项定向测试通过；全部322项lib测试通过，日志/private/tmp/idp-s03a4-core.log。内存store仅证明Core合同，不作为真实PG回滚证据。
- 工作区all-target locked/offline编译通过，/private/tmp/idp-s03a4-workspace.log。保留尚未接线security_email消费者的unused警告。
- 真实隔离PG已通过：并发双改密只一次版本/事件/收据；事件ID碰撞回滚密码及会话退役；email变化使旧version快照CAS失败且会话不变；实际登录服务两种确定性barrier顺序均正确（旧登录先提交后被撤销、旧hash快照先读而认证事务后执行则拒绝）。后两项覆盖两mode。证据/private/tmp/idp-s03a4-reviewed-live.log（其中全域fixture失败另行修正，不能将该次整体当通过）。
- 修正fixture后，全域退役测试两mode通过，/private/tmp/idp-s03a4-fixture-live.log：覆盖多租户/purpose/session/refresh/code/selection、全部grant状态与三种delivery状态、秘密清理/版本、flow/outbox/startreceipt、邮箱budget保留及无关账号数据保留。
- fixture修正包括设备与proof key在同一事务创建以符合deferred FK、纠正无关交付INSERT列数，并补齐被断言保留的无关账号start receipt。未放宽生产约束或测试断言。

最终合并PG回归15项全部通过（5项改密/CAS/登录竞争、7项撤销及3项列表），日志/private/tmp/idp-s03a4-regression-live.log；以上失败记录保留为夹具修正过程，最终当前状态以该回归为准。格式/diff检查已通过，原8个未跟踪测试SHA保持不变。

## 边界和后续

下一批先复核s03-a5-password-http-design，再接入HTTP/宿主及旧管理KDF共享预算。恢复消费者/outbox worker和Web仍未完成；一期整体未交付。无真实COMMIT网络故障注入，不能声称验证所有网络未知结果。未完整验收、部署、提交或推送。
