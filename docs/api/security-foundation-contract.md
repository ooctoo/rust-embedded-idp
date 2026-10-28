# Security foundation 存储接口合同

本扩展只提供凭据版本与安全事件存储，不暴露HTTP端点，不代表本人改密或恢复路由已经启用。版本为 `security_foundation_v1`，独立于tenant_v6和注册扩展。

## 显式操作顺序

1. 由可信宿主选择既有adapter、TenancyMode和固定authority（1..128位ASCII字母数字/._-），调用 `plan_security_foundation(mode, authority)`。返回 SecurityFoundationPlan 含schema_name/mode/authority/fingerprint；过程只读且要求tenant_v6已bootstrap。
2. 审阅目标与迁移设计后，显式调用 `apply_security_foundation(&plan)`。该操作在state排他锁内重查目标指纹，一笔事务安装列、触发器、表和索引；不会覆盖部分对象，重复执行返回冲突。
3. 正常返回后调用 `check_security_foundation(mode, authority)`。在线宿主后续可调用此只读方法校验绑定和布局，不得在check失败时自动调用apply。

若apply返回无法确认COMMIT的固定存储错误，保留原plan和配置，先调用check：check成功证明该逻辑目标上的扩展已存在且绑定/结构一致；check失败本身不能证明之前未提交（可能连接不可用或结构漂移），继续检查连接和固定目标事实，不盲目重跑DDL。API不自动重试COMMIT，也不把网络异常映射为“肯定未写”。本任务仅在临时数据库验证这些API，没有对用户真实数据库执行迁移。

## 状态和兼容性

账号新增security_credential_version由数据库管理，旧INSERT无需传值。password_hash/status/email/registration_tenant_id变化推进版本；profile变化不推进；业务调用方不能指定新版本。注册专用revision触发器继续独立工作。

security_events只允许固定kind/outcome及UUID关联字段和时间，不容纳邮件、密码、验证码、token或原始provider日志。以后服务必须在原安全事务内写事件；当前扩展安装不会自动产生或投递安全事件。

布局指纹包含实际表列/约束/index、版本列/约束、trigger启用状态和函数定义，忽略其他账号列和注册trigger。它是运维漂移检查，不是抵御数据库所有者篡改的数字签名。目标指纹绑定database/schema目录身份、authority、mode、bootstrap与DDL；克隆数据库应由宿主管理新的authority，不能把目录OID视为跨服务器全球唯一身份。

当前没有破坏性自动down migration。后续功能开始依赖凭据版本后，不能通过删列/删事件“回退”安全状态；回退应用与数据恢复须另行设计和演练。
