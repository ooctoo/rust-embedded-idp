# O01a / S03 收据与恢复加密合同

2026-10-26。详细设计已完成独立复核并按下述修正，允许本切片编码。为后续会话撤销/改密收据、恢复票据和加密outbox提供共用基础，不提前启用恢复接口。

## 复用与密钥边界

沿用现有ring AES-256-GCM、HMAC-SHA256、SystemRandom与base64ct，不新增依赖、不改变注册专用加密adapter或算法。Core定义AccountSecurityCrypto端口和类型，Security实现RingAccountSecurityCrypto。本地Cargo.lock沿用ring 0.17.14（包声明Apache-2.0 AND ISC）与base64ct 1.8.3（Apache-2.0 OR MIT），已核对已缓存发布包Cargo.toml；分发仍须保留上游适用版权/许可，不把本次复用说成完成全依赖许可证审计。不把通用私有purpose字符串传给注册crypto；新的固定枚举与domain前缀保证用途隔离。

宿主在构造时显式注入authority（1..128 ASCII字母数字._-，与security foundation一致）、稳定subject_key，以及一个current和最多一个previous KeySet。KeySet含key_id（1..32 ASCII字母数字._-）和四个独立32字节key：secret、command、code、envelope。所有key非零且彼此不同（包括subject与current/previous），两个key_id不同。key材料不派生自密码、不存数据库、不自动在进程启动时生成。subject_key稳定用于邮箱累计预算，不参与日常keyset轮换，避免换key重置猜测/重发预算。更换subject_key必须停用恢复并等待窗口/在途flow排空或另作迁移，本期无自动更换。

新写只用current，读取/校验只按存储的key_id精确选current或previous，不遍历历史key。previous重叠至少覆盖现有15分钟flow/payload和24小时receipt最长有效期；删除key意味着无法读取旧记录，服务必须显式处理UnknownKey而非视为错误验证码扣次数。完整key装配/运维CLI随运行时切片实施，不把crypto类型存在当作已配置密钥。

## Core精确合同

SecurityCryptoContext含reference_id:UUID和related_id:Option<UUID>，reference及存在的related不得nil。outbox envelope reference=delivery ID、related=flow ID；start重试收据reference=operation ID、related=flow ID；code reference=flow ID；receipt secret reference=operation ID；command reference=operation ID、related=subject ID。需要绑定的其余字段（例如新密码、目标复合session、预期版本）由后续Core命令的确定性长度前缀编码进入payload，不能拿任意JSON序列化当作相等语义。

SecurityDigestPurpose固定RecoveryHandle、ReceiptSecret、Command、RecoveryCode。前两者用secret key并分别domain隔离，Command和RecoveryCode用各自key。SecurityEnvelopePurpose固定RecoveryEmail、RecoveryStartReceipt。

AccountSecurityCrypto方法：authority()只读；random_token()返回32随机字节的无padding base64url SecretString；random_code()返回无偏6位十进制SecretString；subject_digest(email)生成稳定邮箱预算HMAC；digest(purpose,context,payload)返回SecurityDigest{key_id,bytes[32]}；verify_digest同参数和已存digest返回bool或固定错误；seal/open使用purpose/context和SecretString，封套SecurityEnvelope{key_id,ciphertext}。文本plaintext最大16384 UTF-8字节；digest payload最大16384字节；subject邮箱长度1..254字节，trim ASCII空格后非空，再ASCII小写只用于预算，不改变账号查找相等规则。

错误枚举固定InvalidInput/UnknownKey/InvalidCiphertext/Unavailable，不携带外部错误或秘密。请求、keyset、digest/envelope Debug不输出key、摘要、明文或ciphertext（key_id和长度可见）。复用已有SecretString；不宣称其拥有目前并不存在的zeroize保证。

## 编码/密码学规则

HMAC及AAD用长度前缀字段串接（u32 big-endian长度），包含固定版本domain、authority、key_id、用途、reference UUID原始16bytes、related有无标志及存在的UUID。不允许可歧义拼接。secret/command/code分key且用途入domain。预算subject独立domain含authority和规范预算邮箱。

封套ciphertext格式为随机12字节nonce + AES-GCM密文/tag（16字节），总长最多16412，最短28。每次seal从SystemRandom生成新nonce。AAD绑定部署/key/用途/对象，跨flow、delivery、authority、purpose或篡改均拒绝。open对解密后UTF-8校验，任何异常固定错误，不回显。摘要校验用ring::hmac::verify，禁止普通数组相等作为验证实现。

6位code使用现有注册adapter同类rejection sampling：从u32取样，拒绝大于等于floor(2^32/10^6)*10^6的尾部，再模10^6并补零；最多取样8次，连续拒绝则Unavailable，避免无界循环。token/code随机失败返回Unavailable，不用时间/计数器替代。恢复累计预算、TTL和原子消费由后续领域事务实现，crypto本身不宣称防猜测完成。

## 实施与验证

1. 独立复核用途、key轮换、AAD及稳定subject预算key；冻结后实现Core类型/trait与Security adapter。
2. 局部测试当前/previous精确读取、current写入、unknown key错误、全部purpose/context/authority分离、封套nonce不复用、篡改/截断/超限/无效key拒绝、6位code/token格式、Debug脱敏。用合成固定key，无真实秘密。
3. 编译、格式及diff检查；文档更新实际边界。该切片没有HTTP或DB schema变化，接口合同记录在Core/宿主密钥说明，后续运行时必须通过具体命令编码和事务复核才能接入。

## Double check 记录

独立复核确认算法、用途/部署/对象绑定、轮换与输入界限自洽；发现存储草案漏记digest key_id和start receipt密文位置。已同步补充secret/command/handle的key_id及独立password_recovery_start_receipts（flow关联、15分钟TTL、同事务创建及过期清理）。后续消费者须验证并冻结完整DDL，不能把本切片当作持久化已实现。

主代理补充定位规则：恢复handle外部编码flow UUID 16bytes + random secret 32bytes（base64url固定64字符）；先以UUID定位，再以同UUID context和stored key_id验证secret摘要，避免HMAC需要flow而flow又只能靠HMAC找到的循环依赖。random_token仍返回独立32随机bytes的43字符编码；后续服务负责组合handle，ReceiptSecret仍直接使用43字符token。UUID不是权限凭据。authority语法与foundation保持一致，code最多8次取样。
