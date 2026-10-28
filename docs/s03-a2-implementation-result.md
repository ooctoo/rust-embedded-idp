# S03-A2 本人会话撤销与收据局部实施结果

2026-10-26。先完成详细设计和独立double check，再实现Core/PG并进行独立代码复核、主代理实际变更审查及局部测试。本批尚无HTTP/宿主/UI挂载，不将领域服务完成视为整项产品交付。

## 已完成行为

CoreSelfSessionRevocationService使用可信AccessActor，锁后重新验证第一方会话，按账号及tenant/session复合键限制目标。本人当前、pending、过期、已撤销会话均可撤销，跨账号和不存在目标统一NotFound。delegated scope不得执行全域本人安全写。

撤销目标及其recoverable扫码子会话，关联refresh/code/tenant selection同步退役；清除grant presentation和delivery加密结果/receipt hash。已acknowledged的独立子会话保持有效；显式以其为目标时可正常撤销。保留原扫码操作/审计记录。凭据、成功收据及session_revoked事件一个事务；事件写失败全部回滚。

成功receipt使用客户端预生成的operation/secret与确定性HMAC命令绑定，有效24小时。仍有效的同actor重放验证stored key ID，不重复事件；结果查询无需已经撤销的actor，仅返回bool。false表示未确认而非未发生。旧key支持previous读取，未知key报告固定基础设施错误，不视为secret不匹配。

PG复用本人列表的actor锁定和有效性查询；新写state排他锁、收据读取共享锁，事务内验证foundation/runtime绑定与布局。没有增加在线DDL或自动清理，也没有改旧管理/扫码公开合同。

主审纠正了实现中未经设计的Pending目标拒绝，补充对应Core/PG测试；另补delegated actor拒绝和acknowledged子会话成为显式目标的验证。独立PG源码复核未发现锁序或SQL集合阻塞；所有成员集合在改变delivery状态前完成凭据退役。

## 验证证据

- Core全部313项lib测试通过（新增7项revocation测试），`/private/tmp/idp-s03a2-core.log`。mock回滚仅用于领域调用行为，真实回滚以下列PG证据为准。
- 一次性PostgreSQL容器7项撤销测试和3项共用self-session查询回归全部通过，`/private/tmp/idp-s03a2-reviewed-live.log`。覆盖两mode本人/跨主体/复合tenant隔离、当前/失效/delegated actor、pending/expired/revoked目标、refresh/code/selection、匿名结果确认、重放/冲突/旧key/未知key、并发只一次事件、事件ID冲突导致全部回滚，以及扫码recoverable与acknowledged后果。
- 工作区all-target离线locked编译通过，`/private/tmp/idp-s03a2-workspace-check.log`。仍有原有fixture及尚未装配security_email的unused警告。
- cargo fmt和diff检查通过；原8个未跟踪测试SHA保持一致。临时数据库容器自动清理，无真实库/凭据参与。

没有宣称实际COMMIT网络故障已注入：现有证据确认撤销当前会话后独立查询能读到成功收据，以及未提交事务不留成功receipt；故障注入更广范围后续另列。

## 后续

下一步完成参考宿主显式安全密钥/扩展检查和撤销/结果查询HTTP接线，再实现改密、密码恢复事务/worker及安全页。对应接口见api/self-session-revocation-contract.md，当前路由清单不新增未实现入口。

尚未执行完整验收、部署、提交或推送；第一期整体目标保持未完成。
