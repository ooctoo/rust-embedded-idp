# AccountSecurityCrypto 嵌入合同

本合同是 Core 端口与 Security adapter 合同，没有新增 HTTP 路由、数据库迁移或自动密钥供应。设计及复核见 [收据与恢复加密设计](../account-security-crypto-design.md)。

Core 导出 `AccountSecurityCrypto`、`SecurityCryptoContext`、`SecurityDigestPurpose`、`SecurityEnvelopePurpose`、`SecurityDigest`、`SecurityEnvelope`、`SecurityCryptoError`。Security 导出 `RingAccountSecurityCrypto`、`AccountSecurityKeySet`。宿主只将已验证配置传入构造器；不得从请求 Host、任意 HTTP header 或启动随机值确定 authority/持久密钥。

| 用途 | 上下文与处理 |
| --- | --- |
| RecoveryHandle | reference=flow UUID；handle为flow UUID原始16bytes + random secret 32bytes的base64url无padding编码（64字符）；先按非秘密 UUID 定位，再验证 handle 中随机 secret；UUID 单独不授权 |
| ReceiptSecret | reference=operation UUID；仅查询既有成功结果，不授权新操作 |
| Command | reference=operation UUID；有主体时 related=subject UUID；领域命令提供确定性长度前缀 payload |
| RecoveryCode | reference=flow UUID；错误次数、TTL 和单次消费由事务领域控制 |
| RecoveryEmail envelope | reference=delivery UUID，related=flow UUID |
| RecoveryStartReceipt envelope | reference=operation UUID，related=flow UUID；重试验证另由领域服务执行 |

`digest`/`seal` 总使用 current；存储记录必须同时保存 key ID。`verify_digest`/`open` 仅按该 ID 选 current 或 previous，不试遍多个 key。`UnknownKey` 是运行配置/轮换错误，不得降级成“错误验证码”并消耗用户猜测预算。摘要不匹配是 `Ok(false)`，不可解密是 `InvalidCiphertext`；所有错误不附带明文或底层错误文本。

配置包含稳定 subject key 和最多两组独立密钥；authority 为1..128、key ID为1..32的ASCII字母数字/点/下划线/短横线。每组有 secret/command/code/envelope 四个32字节 key，全部非零且彼此不重复，包含跨组与 subject key。前一组须保留至旧记录最长有效期后；记录清理、运行时 key rotation 和 readiness 属于后续消费者实现。subject key 日常保持稳定，不能用换 key 绕过累计邮箱预算。

payload 与 UTF-8 明文最多16384 bytes；envelope 为 nonce12 + ciphertext + tag16。context UUID不可nil。`subject_digest`仅对邮箱预算做ASCII空格trim和ASCII小写处理，长度检查基于该结果1..254 bytes；这不是邮箱合法性验证，也不改变账号查找规则。调用方必须先完成业务邮箱验证。token 为32随机bytes的43字符base64url；code为6位十进制。`SecretString` 与输出类型 Debug 脱敏，不承诺底层内存自动清零。

本端口不提供权限判断、恢复资格、持久重试、预算、TTL、事件提交或密文清理。只有后续 Core/PG/HTTP/宿主消费者贯通并验证后，才能将密码恢复标为可用。
