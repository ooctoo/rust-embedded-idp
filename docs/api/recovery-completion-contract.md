# 密码恢复完成 Core / PostgreSQL 合同

S03-B2，2026-10-26。设计见 [详细设计](../s03-b2-recovery-completion-design.md)。实现与验证进度以实施记录/交付计划为准；本合同只定义Core/PG边界；当前HTTP见[恢复HTTP合同](recovery-http-contract.md)，邮件worker见[安全outbox合同](security-outbox-contract.md)，Web仍另批推进。

## 命令与结果

RecoveryCompletionService提供complete_recovery(RecoveryCompleteCommand)与recovery_completion_result(SecurityReceiptQuery)。完成命令包含handle（canonical base64url48字节）、code（6位ASCII数字）、new_password（既有密码策略）、非零operation UUID及canonical32字节receipt_secret。秘密不输出Debug。成功只完成改密，不登录，不返回会话。

非法结构为InvalidInput；未知/过期/失效流程、错误验证码、失败次数超限或当前账号无资格统一InvalidRecovery。错误handle/未知flow不扣猜测次数。crypto、数据库或布局故障不是普通验证码错误。

## 原子性与并发

第一事务在access_state UPDATE屏障后验证收据、flow、handle、code和账号资格。错误code原子增加flow及subject预算，记录recovery_failed/rejected，再在事务外返回InvalidRecovery。每flow最多5次，跨代次subject固定3600秒最多10次；到期窗口先归零再检查阈值。第五次取消该flow尚未终结的邮件并清密文/lease。预算饱和不进入KDF。

正确code及有效普通账号资格通过后释放事务/连接，在宿主共享PasswordWorkBudget内计算Argon2 hash，再进入第二事务重查收据、flow期限/状态、code、预算、账号资格和凭据版本。期间改密、新代次、停用、成员移除或授予有效安全管理员权限都使旧验证结果不能完成恢复。

成功事务把当前flow置consumed，以active+凭据版本CAS改密码，复用本人改密全部凭据退役逻辑，取消相关邮件并删除开始收据，写recovery_completed/accepted事件及24小时完成收据。累计预算保留。任一写失败全部回滚；不同operation并发只允许一个消费，相同命令可由成功收据重放。

## 完成收据

purpose=password_recovery；与其他purpose共用100000行硬上限，未清理过期行也计数。secret摘要绑定operation；命令摘要绑定operation+account及分帧domain/handle/code/new_password。收据重放先于flow查找：即使开始收据或flow已清理，只要完成收据未过期、secret及完整命令匹配，仍可确认同一完成。不匹配或现存已过期收据为recovery.operation_conflict。

匿名result只用operation/receipt_secret，缺失/过期/secret错误为false，有效匹配true；false仅代表未确认。不暴露账号/验证码/hash，不要求旧会话，不执行KDF。依赖当前与最多一个previous key读取历史摘要；不能通过重新生成密钥绕过部署authority。

本批没有HTTP路径变更，OpenAPI不新增候选路由。HTTP错误映射及浏览器请求guard见S03-B3接线合同；Web未知结果交互另批设计和验证。
