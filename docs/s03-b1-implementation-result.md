# S03-B1 恢复开始流程实施记录

2026-10-26；在详细设计两轮独立复核、锁后整秒时间修订后实施。仅完成 Core 和 PostgreSQL 开始恢复事务，不发送邮件、不挂载 HTTP。

## 已实现

RecoveryStartService、typed store/transaction、匿名一致handle及receipt；原样账号查找与ASCII小写预算键分离；当前账号完整安全管理员资格检查；每小时3次start/累计10次失败门槛、硬容量及新代次关闭；真实crypto适配器下的handle/code摘要、加密开始收据和邮件payload。预算/flow/收据/outbox/安全事件在同一state屏障事务内写入，业务管理员不被误当安全管理员排除。

收据仅在行存在且未过期时保证相同请求重放。删除后的新请求正常扣预算并关闭旧代次。无资格账号flow不存account/version、outbox不存密文，但随机和crypto路径仍执行；不宣称数据库/网络恒定时间。

## 验证

- Core定向11项通过；Core lib全部338项通过（`/private/tmp/idp-s03b1-core.log`）。覆盖配额/容量、窗口边界、纳秒时钟归一化、资格、重放与损坏收据、crypto失败无mock提交。mock不代替数据库原子性证据。
- 一次性PostgreSQL 18.6容器真实集成4项通过（`/private/tmp/idp-s03b1-final-live.log`）：Disabled/Enabled资格及真实加密上下文、重放/代次关闭/收据删除、4请求并发只允许3次、事件唯一冲突导致所有写入回滚。容器自动删除。
- 初轮2/4、第二轮3/4，均是新测试夹具错误：过期收据999秒违反900秒约束；business_admin错误配置role_permissions触发category guard。最终夹具只保留合法业务管理员role/binding，并使用900秒收据。这些失败没有通过放宽生产DDL或规则规避。
- 工作区all-target离线编译通过（`/private/tmp/idp-s03b1-workspace.log`）；邮件物理适配器尚无持久消费者，相关dead-code警告仍在，不记为已接线。

接口见 `docs/api/recovery-start-contract.md`。本批无新增HTTP路径，现有OpenAPI制品无变更。后续 B2 已完成设计两轮复核，开始实现code完成恢复；持久邮件worker、恢复HTTP和安全页仍未完成。本项目尚未达到一期整体交付门槛，未做完整验收、部署、推送或提交本批改动。
