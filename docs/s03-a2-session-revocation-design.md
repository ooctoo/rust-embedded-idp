# S03-A2 本人会话撤销与持久收据设计/实施计划

2026-10-26，独立double check已通过，按本合同实施。前置本人会话读取、独立browser身份、account-security crypto、security runtime schema已完成。此次实现Core与PG真实安全写及收据读取；随后使用同一冻结合同接HTTP/宿主，不以本切片代替最终产品交付。

## 权限及重放

新增SelfSessionRevocationService（revoke_session(actor,command)->Result<(),AccessError>；session_revocation_result(query)->Result<bool,AccessError>）及CoreSelfSessionRevocationService<S,C,K,I>，构造mode/store/clock/crypto/ids。沿用AccessActor和AccessError，不伪装admin。发起actor必须数据库active、有效期/成员/租户/device/currentkey/binding有效且scope=NULL；业务和管理purpose均可本人使用，但HTTP入口各自认证purpose/client。actor subject/session要求canonical nonnil UUID。

SelfSessionRevokeCommand：target_tenant_id:String、target_session_id:String、operation_id:Uuid、receipt_secret:SecretString。目标tenant为现有validate_id128规则，Disabled只能0；target session和operation均canonical非nil UUID。receipt_secret严格43字符无padding base64url，解码32byte且重新编码相等，拒绝32全零，绝不日志。客户端提交前生成operation及secret，保留至结果明确。

目标只允许本人账号，跨租户本人会话可撤销；不存在/他人均NotFound("session")。允许当前、本人pending、expired、已revoked目标；已revoked作为成功确保清理并写本次receipt，但不影响其他已独立建立会话。每个成功操作唯一receipt，24小时有效，repeat只在仍有效actor下校验原actor/目标/secret及命令摘要，匹配返回成功且不重复事件；同operation不同参数Conflict("security.operation_conflict")。已失效actor不得用secret重新授权写，只可走匿名结果查询。

## 确定性加密绑定

ReceiptSecret context.reference=operation，related=None，payload为解码32byte secret。Command context.reference=operation，related=subject UUID；payload为逐字段u32BE长度前缀：固定`embedded-idp/self-session-revoke/v1`、actor tenant UTF8、actor subject UUID16、actor session UUID16、target tenant UTF8、target session UUID16。操作身份由context绑定；purpose枚举还绑定算法domain。不得使用JSON序列化或普通密码SHA。

新写保存current digest；重放须用stored key_id验证（不能用current新算摘要与旧摘要比较）。任何UnknownKey/crypto异常固定Store::Backend("account security crypto unavailable")，不得当成参数不匹配。用户secret错误/命令不匹配是operation_conflict。构造/方法检查crypto.authority和store runtime binding相同，由store按传入authority验证，不从请求头拿authority。

## Core/Store精确接口

SecurityOperationReceipt包含purpose:SecurityReceiptPurpose（SessionRevoke/PasswordChange/PasswordRecovery，映射已冻结schema）、operation_id:Uuid、account_id:String、secret_digest:SecurityDigest、command_digest:SecurityDigest、completed_at/expires_at:SystemTime；Debug继承摘要脱敏。SecurityReceiptQuery {operation_id,receipt_secret}此服务只查询SessionRevoke，其他两purpose待对应服务接入。

SelfSessionMutationTransaction：actor_is_active(actor,now)->bool；receipt(purpose,operation)->Option<SecurityOperationReceipt>；receipt_count()->u64；owned_session(actor,target_tenant,target_session)->Option<TenantSession>；revoke_session_credentials(actor,target_tenant,target_session,now)->()；record_completion(receipt,event_id:Uuid)->()（同事务插入receipt及session_revoked/accepted event）。各方法返回StoreError。Domain必须核对读到receipt的purpose/op/account与合理时间（completed<=now、expires>completed且<=24h）；目标返回身份/复合键完全匹配，拒绝InvalidStoreResponse。

SelfSessionMutationStore GAT transaction及self_session_mutation(mode,authority,actor:Option<&AccessActor>,closure)->Result<R,AccessError>。Some actor取得access_state FOR UPDATE，再锁actor tenant/account/session；None结果查询取得access_state FOR SHARE，无actor锁。Core只在runner完成锁定后读取Clock；事务5秒statement/lock timeout，READ COMMITTED。runner验证tenant_v6/bootstrap与foundation/runtime version/authority/mode状态。完整布局check在宿主装配时执行，本批PG runner也执行check_in_transaction及runtime同事务layout检查以fail closed，后续如优化需另证明等价。Err回滚全部写。

写流程：输入校验→锁→now→active actor→查receipt（过期视冲突，不自动删除/复用同operation）→匹配则成功；不存在则owned_session→receipt_count<100000→计算两个digest、生成非nilUUID event id（IdGenerator）→撤销SQL→写receipt+event→提交。超容量Conflict("security.receipt_capacity")，后续HTTP映射503且不提交副作用。receipt TTL使用checked_add(86400)，越界固定InvalidStoreResponse。

结果查询校验operation和secret语法，锁后now，只查询SessionRevoke；不存在/过期/错误secret返回false，true仅在有效成功receipt且secret验证成功。false仅表示未确认，不证明未提交；不读取账号/session信息，不返回目标、主体或时间。成功receipt不要求账号仍存在，也不改变任何状态。无效格式返回InvalidInput，密钥不可用返回固定基础设施错误。清理后false，前端不得自动重做。

## 关联凭据的精确失效范围

先验证目标owner，全部SQL按subject和target复合键限定，不使用请求提供的account。目标集合R：目标会话，加上以该目标为source的scan grant尚处于recoverable delivery产生的会话（同subject）。已acknowledged且独立激活的其他扫码会话不随source单会话撤销；全域改密将在下一批全部退役。

同事务依次：
1. R中auth_sessions设revoked；关联refresh仅未revoked的设revoked_at=now/reason=administrative，保留历史原因；删除以R为source的authorization_codes；撤销以R为source的tenant selections。
2. 以目标为source的scan grants，或delivery.session是目标的grant：清presentation_key/nonce/ciphertext、delivery_secret_hash；waiting_user/waiting_device/awaiting_approval/approved/issued转invalidated，version+1；保留原其他终态和审计/操作tombstone。
3. 上述grant的deliveries清result_key/nonce/ciphertext和receipt_nonce_hash；recoverable或delivery.session恰为目标的设revoked、revoked_at=now、reason='self_session_revoked'；其他acknowledged会话保持其state。必须先用原recoverable集合完成R的所有凭据退役，再变更delivery状态，避免后续SQL失去集合成员。
4. 写session_revoked accepted event（account/operation，IdGenerator提供独立eventUUID）及成功receipt。唯一/事件插入失败也回滚所有撤销。

锁顺序全局state排他→actor tenant/account/session→目标及关联记录；既有写均先state共享/排他，故无需先持account后升级state。结果读取state共享与提交互斥，可确认COMMIT未知结果。数据清理由后续worker统一实现；本批不匿名删除过期receipt以偷偷重用operation。

## 实施与测试

1. 设计独立复核尤其scan源/已acknowledged边界、原子失败、锁后Clock及stored key_id重放。通过后实现Core类型/服务和PG事务；复用本人查询的actor校验SQL为crate-private helper，旧读取语义不变。
2. Core局部模拟store：外人404、inactive/scope拒绝、current撤销、receipt匹配/冲突/过期/容量、unknown key、事件唯一失败回滚责任、结果false语义、锁后时钟、命令绑定/轮换。真正回滚/并发依赖PG证据，mock不冒充证明。
3. 隔离PG两mode：跨账号无副作用、复合tenant、current/other撤销、refresh/code/selection退役、scan pending delivery退役而acknowledged独立会话保留、事件+receipt原子rollback、并发同operation只有一次事件、同目标不同operation、查询结果及过期、错误密钥。保留旧self-session读取回归。
4. 更新Core/PG合同及交付清单。HTTP后续必须按同receipt能力映射匿名只读结果入口，并保留原认证/Origin/expected identity和16KiB/no-store/共享源预算；完成后再推进改密与恢复，不将Core测试当作HTTP可用证明。

## Double check记录

独立复核确认复合键/owner边界、state先锁、旧key重放及扫码recoverable/acknowledged分界与现代码兼容。须先按原recoverable集合退役凭据，再改delivery；不得误用拒绝acknowledged的单grant helper。具体SQL及原子回滚/并发/密钥轮换由局部真实PG测试兑现。

实现复核裁定：本人pending目标同样允许撤销，不能因列表只显示active而额外限制安全写。已移除实现中未经设计的Pending拒绝，并补充Core测试；actor自身仍必须active且非delegated。
