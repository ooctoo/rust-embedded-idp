# 密码恢复开始 Core / PostgreSQL 合同

S03-B1，2026-10-26。对应 [详细设计](../s03-b1-recovery-start-design.md)。该Core切片本身不含HTTP；当前HTTP/宿主挂载见[恢复HTTP合同](recovery-http-contract.md)，实际邮件投递见[安全outbox合同](security-outbox-contract.md)。

`RecoveryStartService::start_recovery(RecoveryStartCommand)` 返回 `RecoveryStartResult { handle, expires_at }`。命令为 email、非零 operation_id、canonical base64url32字节且非全零 receipt_secret。email仅trim ASCII空格，保留账号查找大小写；预算subject摘要ASCII小写。handle为64字符canonical base64url（flow UUID16+随机32字节），有效900秒。

已存在完成开始请求收据时，未过期且完全相同email/secret/op才能返回相同handle和原有效期，不加预算、不新发邮件、不恢复旧flow。现存过期或不匹配收据冲突；收据被清理或改密删除后，同operation按新请求处理，没有永久幂等保证。

每subject固定3600秒窗口最多3个新start，累计10次code失败后也禁止start；窗口过期才重开。flow/outbox各10000行，预算100000行，包含尚未清理的过期行；预算容量满只拒绝新subject。有效收据重放先于配额检查。

存在、active且有有效成员关系、无有效系统/租户安全管理员权限的账号才产生可投递邮件。business_admin不因此排除。未知/不合资格账号仍生成相同形状的handle、pending flow、收据和事件，outbox为cancelled且无payload，flow不保存account/version。所有资格分支执行相同次数的随机token/code、HMAC和seal；数据库查询不声称恒定时间。

READ COMMITTED事务先锁access_state UPDATE，核对base/foundation/runtime及authority/mode，再按tenant/account/budget顺序读取当前资格。时间在锁后取整秒。新代次取消同subject的旧pending flow及pending/sending邮件，清密文/key/lease，pending记录not_started、sending记录unknown；终态不恢复。预算、flow、开始收据、outbox及recovery_started/accepted事件原子写入，错误整体回滚。

handle/code分别用RecoveryHandle/RecoveryCode摘要绑定flow；请求摘要绑定operation+flow及分帧domain/email/receipt_secret；开始收据用RecoveryStartReceipt封装并绑定operation+flow。邮件密文使用RecoveryEmail绑定outbox+flow，UTF8明文为 `recovery-email-v1\n<email>\n<code>`（真实LF、无尾LF）。秘密与摘要Debug脱敏。不得把加密投递记录的落库误当作发送成功。

结构错误为InvalidInput；配额、容量和重放分别为recovery.rate_limited、recovery.capacity、recovery.operation_conflict；crypto固定Backend。实际HTTP映射已在[接线合同](recovery-http-contract.md)冻结。后续code验证必须重查flow/有效期/凭据版本和资格，不能仅凭开始收据恢复账号。
