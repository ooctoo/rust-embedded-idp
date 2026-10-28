# S01-C：昂贵工作边界收尾设计

2026-10-26，设计已复核并进入实施。S01-A/B已接通普通密码并发和HTTP准入；本批补盘点发现的client-secret Argon2绕过入口，明确旧邮件路径后续归O01a。不是新增OIDC协议。

## 现状和决策

`PhcClientSecretCodec`在Core中直接Argon2 hash/verify。参考宿主普通和legacy OIDC以及管理client写入注入该codec，未共享S01-A PasswordWorkBudget。来源速率不替代昂贵工作在途容量；仅保护*/login也不能覆盖/oidc/token、introspect或revoke的client认证。

新增Core薄wrapper `BudgetedClientSecretCodec<V>`，构造参数为既有codec和共享PasswordWorkBudget，实现ClientSecretVerifier/Hasher：调用前try_login，保留RAII permit直到真实同步验证/哈希退出，满载通过既有ClientSecretError::VerifierRejected/HasherRejected携带固定password.work_unavailable标记，不能用false伪装错误密码。不自写哈希算法，不改变PhcClientSecretCodec默认构造或既有泛型服务合同。wrapper可测试底层closure已开始时容量仍被占用；cancel HTTP不能终止该同步闭包。

参考app所有在线OIDC/client-admin的codec均使用同一composition预算。两个示例的OIDC也使用自己的宿主共享预算。离线seed-client哈希无需与未运行的HTTP共享，不扩展为持久预算。显式cookie/scan/device auth仍保留S01-A接线；客户端scope/proof/refresh生命周期不变。

现有client认证error转换会包成StoreError::Backend，HTTP一般投影500；本批为固定budget marker增加503暂不可用映射，其他client验证错误和OAuth invalid_client行为不变。须逐条核对tenant OIDC和legacy OIDC错误投影，避免把业务失败改为成功或暴露错误内部文本。管理client hash预算耗尽也应可重试503，并保证无客户端/审计半写。

## 实施与验证

1. 复核Core client_auth错误转换、tenant OIDC错误映射及client admin hasher路径；先明确全部503目标，再实现wrapper。
2. 以可阻塞fake codec证明共享总4槽、hash/verify同一预算、满载不调用底层、释放恢复；wrapper无额外线程/重试。
3. 参考宿主和示例接线，测试客户端401/400等原行为保持；饱和503不泄漏marker且不签发token。
4. 运行相关Core/Axum局部测试、OIDC真实宿主定向集成及编译。后续O01a补SMTP/邮件投递并发、结果未知和日志秘密边界，不能在S01结论中忽略未完成邮件接线。

## 非目标

不增加client machine principal、client_credentials、MFA；不变更数据库schema/secret生命周期；不修改真实client hash。所有动作仍须原权限/认证，不为避免预算错误放宽安全校验。新wrapper并非可中断KDF；许可覆盖真实工作到退出。

## 复核修订与实施门槛

独立复核已确认需区分各错误协议：legacy service 的精确 Store backend marker 映射顶层 code/message temporarily_unavailable 503；tenant OIDC token、introspect、revoke 精确 marker 映射 OAuth server_error 503，不能添加 WWW-Authenticate；client admin 精确 marker 映射顶层 temporarily_unavailable 503。其他错误投影保持不变。路由原有 no-store 必须继续验证。禁止模糊 contains 匹配，客户端认证失败必须在授权码消耗或令牌签发前返回；管理 hash 失败必须无客户端及审计半写。

补充设备登记：FileAdmission 启动时校验 grant 的离线 KDF 保持原行为；在线 inject 原有独立 static semaphore 替换为 composition 注入的 PasswordWorkBudget。许可必须在 spawn_blocking 前取得，并移动进闭包直至真实计算退出；避免在 authenticate 内再次扣额。FileAdmission 使用 builder 接收预算，默认构造保留测试便利；所有生产组合点显式注入共享实例。保留既有 device_admission_busy 503/no-store 错误合同。这样不把预算耗尽误判为无效凭据，也不改变授权规则。

主代理对照真实 inject、client_auth、client admin 和 HTTP error 路径复核：以上补充后设计可进入实施。实施后增加 wrapper 阻塞与共享预算测试、设备注入饱和回归及各错误投影测试，并复查实际 diff 与接口文档。
