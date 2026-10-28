# Security runtime 存储扩展合同

本合同对应 [详细设计及复核](../security-runtime-storage-design.md)。扩展以 `security_runtime_v1` 标识，依赖已安装且布局检查通过的 `security_foundation_v1` 和 tenant_v6；不新增 HTTP 路由。现有账号/session数据仍由原基础表拥有。

PostgresStorageAdapter新增：

- `plan_security_runtime(mode, authority) -> Result<SecurityRuntimePlan, StoreError>`：只读预览，检测部分对象冲突。
- `apply_security_runtime(&plan) -> Result<(), StoreError>`：显式事务迁移，核对目标/指纹、持有access_state排他锁，再检查foundation与对象状态；失败整批回滚。
- `check_security_runtime(mode, authority) -> Result<(), StoreError>`：验证前置、部署绑定与列/约束/索引布局。布局漂移拒绝启动依赖该扩展的功能。

Plan字段为schema_name、mode、authority、fingerprint；必须把完整plan传回同一目标应用。指纹绑定数据库/schema身份、前置布局、模式/authority和DDL。它是误操作与漂移检测，不是授权令牌或抗DB owner篡改机制。应用已安装扩展返回冲突，不将重复apply当在线自动升级。authority与crypto配置应相同，语法1..128 ASCII字母数字._-。参考宿主已通过可选runtime.account_security装配配置与security-plan/apply/check CLI；在线启动和readyz只读核对，未配置时不挂载撤销路由。具体命令与密钥文件要求见../host-integration-v1.md。恢复及outbox消费者尚未接入，不能仅因存储存在就声称密码恢复已可用。

扩展包含六张表：runtime状态、成功安全操作收据、恢复累计预算、恢复flow、恢复开始的加密收据、加密邮件outbox。所有摘要与密文携带key ID，密文/状态/租约字段组合有数据库CHECK约束；plaintext密码、验证码、邮箱、handle和receipt secret不入库。完整字段和有效期见设计；内置约束不能替代服务层资格判断、权限、TTL判断、并发屏障或密码策略。

成功收据只确认已提交操作；密钥/secret验证由Core和crypto消费者承担，operation UUID本身不授权。账号删除后成功收据可保留至24小时清理；与账号关联的flow随删除级联清理其startreceipt/outbox。与账号无关的预算按窗口清理；无资格邮箱的flow没有账号FK，但有效期和容量策略相同。

数据库只约束局部行形状。跨表TTL一致、容量配额、同邮箱新代次失效、错误猜测计数提交、KDF锁外执行、未知SMTP结果不自动重发，以及批量清理，均须由后续事务服务实现和验证。该扩展不产生自动投递或自动安全事件。
