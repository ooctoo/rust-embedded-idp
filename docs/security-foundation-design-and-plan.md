# O01a-B0 / S03 安全基础扩展设计与实施方案

2026-10-26。仅冻结共用的凭据版本和事务安全事件存储；outbox/恢复flow/receipt仍按各自后续扩展实施，不能把本批表存在当作恢复能力已启用。

## 现状与选择

tenant_v6 没有通用 credential version；可选注册扩展的 registration_security_revision 服务于注册资格，不能作为本人改密的强制依赖。账号的所有已有更新路径最终写同一 accounts 表，因此用独立数据库 BEFORE trigger维护 security_credential_version，覆盖旧管理改密、状态、邮箱与注册租户变化，避免漏掉旧写路径。现有 state→tenant→account 锁序保持不变。

本批扩展版本为 security_foundation_v1；后续 security_recovery_v1 显式依赖它，不通过修改已有tenant_v6版本或在线启动DDL启用功能。security_state 保存singleton/version/authority/mode/安装时间及布局指纹，security_events保存固定安全事实。基础扩展不触发邮件或调用外部系统。

## 精确表合同

accounts 新列 security_credential_version bigint NOT NULL DEFAULT 1 CHECK (>0)。现有账号初始1。BEFORE INSERT拒绝显式非1；BEFORE UPDATE拒绝调用方自行修改版本；若(password_hash,status,email,registration_tenant_id)任一实质不同，则new.version=old.version+1，否则保持不变。整数溢出让事务失败，不回绕。触发器覆盖所有UPDATE（而非仅UPDATE OF），防止直接降低版本；其他display_name变化不推进。删除账号不重用旧身份ID；后续flow外键清理必须独立实现。

security_state：singleton布尔PK且只能true；version固定security_foundation_v1；authority为1..128字符ASCII标识（字母数字._-）；mode固定disabled/enabled且与access_state匹配；installed_at_epoch bigint；layout_fingerprint text（64位hex）。无账号、密钥、邮箱或token。

security_events：id uuid PK，kind固定 password_changed/session_revoked/recovery_started/recovery_failed/recovery_completed/email_delivery，outcome固定 accepted/rejected/unknown；account_id uuid可空且不设FK（允许保留删除主体的最小历史标识），operation_id uuid可空，occurred_at_epoch bigint>=0。不提供任意payload字段，不存密码、摘要、邮件或provider错误。建立(occurred_at_epoch,id)清理索引及(account_id,occurred_at_epoch,id)本人/运维定向索引。后续Core服务只在其原事务里append；本批不引入伪造管理员actor的事件接口。

## 显式迁移合同

PG adapter新增只读plan_security_foundation(mode,authority)、apply_security_foundation(plan)、check_security_foundation(mode,authority)。plan包含schema、mode、authority与目标指纹；指纹绑定当前database/schema OID、base module version/mode/bootstrap时间、DDL内容。plan前先验证tenant_v6布局及bootstrap完成；任意同名state/events/trigger/function或已有版本列都视为冲突，不能覆盖或部分接管。

apply先重做plan比较，再使用setup连接、5秒statement/lock timeout，取原access_state FOR UPDATE。锁内重查base版本、mode、bootstrap以及目标指纹和不存在条件，执行完整DDL、插入state、计算布局指纹并保存，最后单次commit。错误回滚，重复apply明确already-installed冲突；COMMIT结果未知时调用check确认，而非盲目重跑。不同schema/authority/mode的plan不能互换。无需访问pg_control_system或超级用户权限，只用普通catalog读取。

check验证base readiness、状态绑定和layout_fingerprint。布局指纹只覆盖本扩展表/索引/约束、账号新增列/约束/trigger、对应函数定义与启用状态，不把其他账号列/注册扩展trigger算入，避免正常注册扩展导致误报；对象缺失、trigger禁用/变更、约束/index漂移都必须失败。布局指纹与state存储只作运维漂移检查，不防范可任意改库的数据库所有者。

## 实施和局部验证

1. 独立复核设计，尤其首次/重复/未知提交、partial对象、版本trigger与注册trigger共存。
2. 实现SQL和adapter显式方法，无启动接线；记录诊断为固定StoreError，不暴露连接或行秘密。保持普通离线测试不依赖数据库。
3. 隔离PostgreSQL集成：两种mode安装/check；plan只读；跨目标/绑定错配；重复和部分对象拒绝；旧账号默认版本、hash/status/email变更推进、profile不推进、手工版本更改拒绝；rollback恢复旧版本；trigger禁用/DDL漂移被check拒绝；事务事件与安全写同提交/回滚。
4. 编译/fmt/diff和相关迁移测试通过后更新交付记录。这里不对真实库迁移，不完整验收/部署/推送。

主代理初审完成，等待独立double check后再编码。

独立复核完成：旧SQL显式列名INSERT与新增default兼容；auth/registration/admin均有state先行锁序；注册revision trigger只更新其专用字段，可并存。布局签名必须包含实际定义而非对象计数，覆盖同名预占/禁用/替换。以上已纳入实施和测试要求，设计冻结进入编码。
