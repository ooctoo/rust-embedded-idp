# O01a-B2 持久恢复邮件队列实施记录

2026-10-26。先完成详细设计及两轮独立复核，再实施Core/PG；实现另经独立源码审查。新增claim/finish/cleanup内部端口，没有宿主发送循环或HTTP挂载。

## 已实现和复核修订

每次最多领取一项、30秒租约、最多3次尝试；领取重新核对恢复流程、账号资格/版本及加密payload/code摘要，提交后才返回明文。finish按状态与租约token CAS，重复/已取消结果不覆盖；迟到结果转Unknown，Unknown不重发；NotStarted至少1秒后有限重试。密文与租约在终态清除，状态和安全事件原子提交。

cleanup每次跨类别合计最多100个根记录：租约超时、过期payload/开始收据、flow/完成收据保留期、预算、安全事件。第二轮设计修订将预算删除条件加强为没有任何保留flow，避免B2读取旧flow时因缺预算变成存储错误。物理删除为后台有界处理，逻辑期限由业务独立强制检查。

实现复核补上outbox/flow创建和过期时间相等校验、未来重试候选拒绝、finish时钟回退拒绝。Core不依赖Email/HTTP/PG；PG不执行SMTP、不生成随机ID。没有新增依赖或迁移。

## 测试证据

- Core定向9项及Core库全部359项通过：`/private/tmp/idp-o01b2-core.log`。Mock证明服务合同和事务回调规则，不证明PG原子性。
- PG首轮在并发测试因lazy iterator先join后spawn而阻塞；精准停止测试进程，外层脚本清理容器，修正为先启动全部线程再join，没有将此问题归为生产锁问题。
- 第二轮10项中9项通过：`/private/tmp/idp-o01b2-reviewed-live.log`。覆盖双模式领取/终态清密文、并发只领取一次、NotStarted三次、迟到Unknown、事件冲突回滚、清理100额度、租约过期事件、清理事件回滚、24小时flow/成功收据/预算清理以及旧handle查询兼容。
- 剩余取消用例曾误把管理员改密当作A4本人改密即时取消。已改为明确验证：新start立即cancel旧邮件、旧finish返回false；管理员改密先失效凭据版本，outbox保持sending，随后有效租约finish因版本失效转cancelled并保存真实物理结果（Accepted），重复finish为false。定向验证通过（`/private/tmp/idp-o01b2-cancellation-live.log`，1/1）；结合上一轮其余9项，10个局部PG用例均已有通过证据。
- 工作区all-target编译通过（`/private/tmp/idp-o01b2-workspace.log`）；接口合同/漂移检查及18项OpenAPI测试通过（`/private/tmp/idp-o01b2-contracts.log`）。参考宿主邮件物理适配器未挂消费者的dead-code警告仍存在，不冒称已接线。

fmt与diff检查通过。当前target符号链接指向工作区外既有缓存，主代理使用授权的缓存访问执行检查；没有改动该链接。普通工作树源码及原8个未跟踪测试保持原有归属，SHA256检查未变。

## 下一步

宿主有界调度/关闭、物理发送截止时间与数据库lease联调、恢复HTTP、Web本人安全与找回密码交互仍待完成。没有真实供应商投递、完整验收、部署、提交或推送。接口见 [outbox合同](api/security-outbox-contract.md)。
