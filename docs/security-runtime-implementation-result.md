# O01a-B1 / S03 安全运行时存储实施结果

2026-10-26。本批详细设计经独立double check后实现，随后复核实际DDL与迁移源码并补充局部测试。新增security_runtime_v1显式存储扩展，不把该基础完成计作改密/恢复已可用。

## 完成内容

六张表覆盖runtime部署绑定、成功收据、恢复累计预算、恢复flow、加密开始收据和加密邮件outbox。摘要携带key ID；UUID、长度、有效期、账号/凭据快照配对、状态/密文及租约组合由SQL约束保护。匿名不合格flow可保留同形状记录；过期、容量和资格的实际业务处理仍由后续消费者负责。

新增SecurityRuntimePlan及plan/apply/check API。只读计划绑定目标身份、foundation布局和DDL；apply在access_state排他锁后再次核对同事务foundation和对象状态；全部DDL与runtime标记一并提交。foundation校验抽出crate-private同事务辅助函数，原对外API保持；基础layout不纳入runtime表，两个扩展可独立检测漂移。复用现有PG设施，无新依赖或在线自动迁移。

独立DDL复核未发现NULL三值逻辑、FK级联、状态/密文组合阻塞；主代理复核实际adapter、helper及测试并补齐缺失用例。未引入通用迁移框架、空HTTP桩或重复领域服务。

## 局部证据

- 一次性PostgreSQL 18.6容器，5项runtime live测试全部通过（主要迁移、并发和数据场景覆盖Disabled/Enabled两种mode）。日志 `/private/tmp/idp-security-runtime-live.log`。
- 测试涵盖基础缺失、只读plan、错误目标/authority/指纹、plan后foundation漂移、部分表/索引冲突、并发apply单赢家、列/索引漂移，以及foundation仍有效。
- 合成记录覆盖多表事务提交/回滚、sending到accepted清除密文/租约、匿名取消outbox、flow/账号删除级联与成功receipt短期保留；无效UUID/key/digest/TTL、账号版本配对、租约、单侧NULL密文和终态payload均被拒绝。不是实际发送或恢复端到端证明。
- foundation共用校验变更后，另一次隔离容器中的5项foundation测试全部通过，包括与注册扩展两个安装顺序共存。日志 `/private/tmp/idp-security-runtime-foundation-regression.log`。
- 工作区 `cargo check --workspace --all-targets --locked --offline`通过；日志 `/private/tmp/idp-security-runtime-check.log`。既有fixture和未接线security_email的unused警告仍存在。普通测试不依赖live PG。
- cargo fmt与diff检查通过；原8个未跟踪测试保持不变。容器均由runner finally清理，未连接真实开发/生产库。

## 后续与边界

下一步按详细合同实现本人安全写：撤销会话、改密、收据查询与全域会话/扫码/恢复票据退役，再接入恢复flow/outbox消费者及宿主、HTTP/Web。当前只有schema与显式迁移API，没有自动事件/投递、容量执行或清理worker。完整验收、部署、推送、提交均未执行；一期目标尚未完成。
