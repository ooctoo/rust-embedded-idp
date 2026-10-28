# O01a-B1 / S03 持久安全运行时存储设计与实施计划

2026-10-26，详细设计已独立复核通过，按本合同进入实现。前置 security_foundation_v1（凭据版本、事件）及 AccountSecurityCrypto 已实现。本批建立会话撤销、改密与恢复需要的持久化形状及显式迁移；领域行为按下述同一合同继续实现，不将建表标为产品可用。

## 所有权与迁移

Core继续拥有事务/服务规则；本批PG仅提供扩展plan/apply/check和约束。新增独立security_runtime_v1，不修改已冻结foundation DDL或tenant_v6。复用PostgresStorageAdapter配置/连接/事务和现有foundation迁移模式；不引入迁移框架或新依赖。

SecurityRuntimePlan包含schema_name、mode、authority、fingerprint。plan_security_runtime(mode,authority)只读，要求foundation完整check成功；指纹绑定数据库名/OID、schemaOID、模式、authority、基础版本、foundation layout_fingerprint及本批完整DDL。检测所有本扩展预占表/索引名字冲突，不覆盖或收养部分既有对象。apply_security_runtime(&plan)先检查目标及plan一致性，再setup连接、5秒statement/lock timeout，access_state FOR UPDATE后在同一事务复核foundation绑定与实际布局、对象冲突和指纹，建表、写runtime_state及layout指纹后提交。并发应用只能一个成功，失败回滚全部对象。check_security_runtime验证foundation、runtime版本/authority/mode以及实际所有新表的列/默认值/notnull/约束/索引，缺失或漂移fail closed。布局指纹是漂移检测，不是抵抗DB owner篡改的签名。

为避免同事务内重开连接/锁反转，将foundation已有base_ready/layout验证收拢为pub(crate)的单事务check辅助函数，外部API保持不变；runtime apply持有access_state后调用该辅助函数。新扩展不向security_state加列，因此foundation已有布局指纹保持不变。在线启动不自动建表，CLI接线在后续宿主批次提供。本批仅在隔离PG执行。

## 精确表合同

所有UUID主键/操作/flow/租约不允许nil（显式CHECK）；epoch为bigint>=0，expires>created/completed。所有key_id为1..32 ASCII字母数字._-；digest bytea固定32bytes。无明文email、密码、code、handle、receipt_secret进入表。account_id仅为内部主体UUID。

1. security_runtime_state：singleton boolean PK CHECK(singleton)，version CHECK='security_runtime_v1'、authority与foundation同语法、tenancy_mode disabled/enabled、installed_at_epoch>=0、layout_fingerprint固定64位小写hex。仅一行。
2. security_receipts：purpose text枚举session_revoke/password_change/password_recovery；operation_id uuid；主键(purpose,operation_id)；account_id uuid非空（不加FK，账号删除后仍可在24小时内确认已发生结果）；secret_key_id/secret_digest；command_key_id/command_digest；completed_at_epoch>=0、expires_at_epoch>completed且差值<=86400。只保存成功结果，同事务与安全写提交。索引(expires_at_epoch,purpose,operation_id)用于清理；(account_id,completed_at_epoch,operation_id)用于定向诊断，不公开查询。
3. password_recovery_budgets：subject_digest bytea PK 32；window_start_epoch>=0、start_count integer 0..3、failure_count integer 0..10、expires_at_epoch>window_start且差值=3600。subject用稳定预算key，不随加密keyset轮换；预算修改必须在全局写屏障内。索引(expires_at_epoch,subject_digest)。
4. password_recovery_flows：id uuid PK；subject_digest bytea32（不FK预算，窗口更换与flow保留独立）；account_id nullable uuid REFERENCES accounts(id) ON DELETE CASCADE；snapshot_credential_version nullable bigint；CHECK account_id/snapshot同空或同非空且snapshot>=1；handle_key_id/handle_digest32；code_key_id/code_digest32；created_at_epoch>=0、expires_at_epoch>created且差值<=900；retained_until_epoch=created+86400；state pending/consumed/invalidated/expired；failed_attempts integer0..5。无额外generation计数，flow UUID就是代次，新start在同一屏障下使同subject旧pending失效。索引(subject_digest,state,created_at_epoch,id)、(account_id,state,id)、(retained_until_epoch,id)、(state,expires_at_epoch,id)。handle格式为flowUUID16+randomsecret32的base64url64字符，先定位再验摘要；不存在/无效/过期统一外显失败。
5. password_recovery_start_receipts：operation_id uuid PK；flow_id uuid NOT NULL UNIQUE REFERENCES flows(id) ON DELETE CASCADE；request_key_id/request_digest32；envelope_key_id/ciphertext bytea长度28..16412；created_at_epoch>=0，expires_at_epoch>created且差值<=900。context=operation_id+flow_id，plaintext只有同一handle；request使用Command purpose，reference=operationID，related=Some(flowID)（S03-B1冻结后的合同），payload确定性分帧编码domain、经业务验证的邮箱、32byte客户端重试secret。operation_id单独不授权取handle，同request验证后方可open。有效期与flow相同，过期删除整个startreceipt行清除密文，不保留空密文假收据。索引(expires_at_epoch,operation_id)。
6. security_email_outbox：id uuid PK；flow_id uuid UNIQUE NOT NULL REFERENCES flows(id) ON DELETE CASCADE；envelope_key_id nullable、ciphertext nullable（成对为空/非空，非空尺寸28..16412及key语法）；state pending/sending/accepted/rejected/unknown/cancelled/expired；created_at_epoch>=0、expires_at_epoch>created且差值<=900；next_attempt_at_epoch>=created；attempts integer0..3；lease_token nullable uuid与lease_until_epoch nullable bigint；last_outcome nullable accepted/rejected/unknown/not_started。CHECK：pending/sending必须payload非空，其他终态payload为空；sending必须lease字段非空、lease_until>created、attempts>=1，其他状态lease字段为空；pending attempts<3。索引(state,next_attempt_at_epoch,id)、(state,lease_until_epoch,id)、(expires_at_epoch,id)。发送有效期与flow一致。

每次新start都创建一行flow和一行outbox；无资格/不存在账号使用account/version NULL，仍有随机不可用code/handle摘要、outbox为cancelled且无payload。这样容量计数和响应结构不取决于账号是否存在。有效账户才创建pending加密邮件。双方都创建同形状startreceipt；真实邮件差异不在HTTP响应公开。语法校验不等于身份资格。

## 后续服务必须遵守的事务不变量

全局写顺序access_state FOR UPDATE → 必要tenant → account → budget/flow/outbox/receipt。事务内取Clock在锁后；网络、KDF不在锁内。所有成功receipt的purpose/operation唯一，actor/目标/新密码等确定性命令摘要必须匹配才能重放；receiptsecret只授权结果查询，不授权新的写。recovery_start的请求摘要明确与其他Command payload用首字段版本/命令名隔离，不能只拼邮箱字符串。

恢复窗口采用固定3600秒窗口：过期后窗口从now重新建立，但任一在途flow验证前也必须重新定位当前窗口并累计错误，不从flow旧计数重置subject累计。每flow最多5错，同subject每窗口10错、3次新start。错误计数事务必须提交，不能以Err回滚已计数写入。新start失效旧pending flow及尚可投递payload。改密/完成恢复全域退役并失效账号其他flow/outbox；unknown SMTP禁止自动重发。

首版容量：flow/outbox各10000，budget100000，startreceipt随flow上限；成功security_receipts最多100000。计数在同全局写屏障内。容量不足统一503且整个命令无副作用，不能只对有效邮箱检查outbox容量。清理每批100，flow24小时、成功receipt24小时、startreceipt/payload15分钟、event30天；处理sending超时为unknown后清密文。租约30秒；claim每批<=4，发送<=15秒+清理<=2秒；NotStarted至少1秒后重试，最多3次。精确claim/verify/retire服务API仍需在各消费者批次复核。

## 实施顺序与局部测试

1. 独立审查DDL字段是否足以承载冻结crypto与receipt/recovery语义、是否有约束矛盾或对非账号差异化容量；主代理修正文档后编码。
2. 新SQL与migration adapter；轻量抽取foundation事务内check复用，无对外API破坏。未实现消费者时不添加空trait/HTTP桩。
3. 隔离PG两种mode验证：要求foundation、plan只读、错误authority/伪造或过期plan/部分对象冲突拒绝、并发apply单赢家、check模式/authority/布局漂移、foundation check仍通过；有效receipt/flow/startreceipt/outbox可事务写入及回滚，异常状态/尺寸/零UUID/超期/租约组合被DB拒绝；删除flow级联清理payload，账号删除行为明确。
4. cargo fmt、相关PG局部测试、工作区all-target检查；更新API合同与交付清单。无新增HTTP故不修改OpenAPI。后续紧接安全写服务及恢复消费者，不把本批建表当作一期完成。

## Double check结论

独立复核未发现阻止编码的矛盾，确认foundation同事务完整复核、独立runtime指纹、receipt key ID/上下文、非账号容量一致、全局锁序及级联边界。SQL约束、迁移竞争和漂移必须由下面局部真实PG测试兑现；未把存储约束说成领域消费者已实现。
