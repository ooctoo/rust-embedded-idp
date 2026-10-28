# 安全邮件 outbox Core / PostgreSQL 合同

O01a-B2，2026-10-26。详细设计见 [持久投递与清理](../o01a-b2-outbox-design.md)。O01a-B2提供队列事务能力；O01a-B3已挂载显式可选的宿主发送循环及默认随account_security启用的cleanup，不新增HTTP路由。

`SecurityOutboxService` 提供 `claim()`、`finish(SecurityMailCompletion)`、`cleanup()`。claim单次最多领取一项，返回已提交的outbox/flow/租约标识、有效期及SecretString邮箱/code；调用者只能在成功返回后开始实际发送，不能在事务内发送。租约30秒，每次领取增加attempts，最多3次。

领取前重新检查flow pending、期限、错误次数、账号active/成员关系/有效安全管理员排除及凭据版本；解密严格绑定outbox+flow，邮件邮箱与当前账号一致，code还须通过flow摘要验证。错误密文/内容终止为rejected，缺失密钥等配置故障回滚并返回固定错误。无资格/过期流程取消或过期并清payload。时间投影不一致、未来重试候选及回退到创建前的finish时间拒绝。

| 物理结果 | 有效租约及资格下的行为 |
| --- | --- |
| Accepted | 终态accepted，清密文/租约；仅表示供应商接收 |
| Rejected | 终态rejected，清密文/租约 |
| Unknown | 终态unknown，清密文/租约，禁止自动重发 |
| NotStarted | 尚未开始发送；至少1秒后重试，最多3次领取，耗尽或将过期则cancelled |

finish匹配sending状态和租约token，重复、替换、取消后返回false且不覆盖旧状态。租约已到期时，即使迟到结果为Accepted也转Unknown；资格变化/流程到期时不再重试。事件与状态同事务，NotStarted在outbox保持not_started，在有限事件枚举中记rejected，不能据事件单独推断是否可重试。

cleanup单次跨所有类别合计最多100个根记录操作；sending超时转Unknown并写事件，pending邮件过期清密文，开始收据15分钟、恢复flow/成功收据24小时、安全事件30天后可清理。flow关联outbox/开始收据级联删除不单独计数。预算必须等同subject的所有保留flow都删除后才可清理，保证旧恢复handle的查询合同；到期预算仍按窗口归零，不延长限额。物理删除是有界后台处理，逻辑失效不依赖清理及时完成。

PG所有操作使用同一access_state UPDATE屏障、typed schema/authority校验及5秒事务语句/锁期限；当前账号资格复用既有helper。租约CAS、密文清理和安全事件原子提交。无新增DDL、依赖或随机SQL ID生成；事件与租约ID由Core注入的IdGenerator提供。

O01a-B3宿主复用现有4槽物理发送器，在数据库事务外限制单次发送15秒并兼顾剩余租约/flow期限，关闭时先停领取再收割物理工作。该宿主生命周期与真实本地SMTP测试见O01a-B3实施记录；仍不能把队列落库或claim成功当作邮件已经发送。
