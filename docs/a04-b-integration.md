# A04-B 宿主接入：登记、signer、admission与恢复

对应[详细设计](a04-b-technical-design.md)与[实施方案](a04-b-implementation-plan.md)。包主入口提供独立登记客户端及React组件，不依赖本人登录会话。登记完成只是激活设备证明密钥；本人绑定仍须后续持钥登录。

## 接入职责

宿主创建`DeviceRegistrationClient({target, signer, admission, store, transport?})`并传给`DeviceRegistration`。target固定包含baseUrl、tenant_id、client_id、entry_id、device_id。不同服务端安全域必须使用不同client；entry_id是本地上下文，不是B2 grant额外授权条件。HTTP base仅同源根路径、HTTPS或localhost HTTP。

- signer.prepare({target, registration_request_id})须先持久保存候选密钥再返回handle、Ed25519 public JWK及RFC7638 key_id。宿主通过标准密码库计算thumbprint和签名；SDK不存储私钥。signRegistration仅接受登记语义参数；宿主须核对目标、request与handle关联，并使用REGISTRATION-V2规范字节。`buildDeviceRegistrationProofBytes`供宿主复用。activate和discard都须幂等。
- admission.authorize每次重验目标/action的业务所有权与期限，返回credential、registration_scope和expires_at_unix_secs。当前适配发送B2 `x-embedded-idp-device-admission`。credential可以更新，scope不能改变；原grant到期导致无法读取时，应由宿主恢复相同scope的受信授权能力或人工核对，不能自动换grant冒充原登记。
- store.withLock须跨使用同一候选的实例/标签页串行化；load/save为原子持久化。store不得回退旧版本或吞掉写入错误。记录包含opaque handle及public JWK，宿主应限制访问，但不得记录private key、admission credential或signature。生产平台keystore、durable store及跨进程锁由宿主实现；没有安全adapter时不开放登记按钮。

使用前调用load恢复本地journal。空记录才可prepare(name)。prepared可provision；远端未确认时保留原device/request/handle。recover查结果并协调本地activate；retryProvision先查结果，仅404时用原参数重试。complete会先查结果、获取新challenge、调用宿主signer、先持久化unknown再提交，并重查结果后激活。不要因超时/403/404/nonce已消费生成新request或丢弃key。discard仅允许确定没有远端写入尝试的prepared候选；abandoned记录留存，不自动重新登记。

组件卸载取消订阅，宿主切换流程时调用dispose。dispose不能撤销已经发送的请求，也不能取消持久化journal；新实例通过load/recover继续。取消与网络失败均不表示服务端回滚。store或signer错误对UI只显示固定安全错误码，具体秘密不得包含在诊断日志中。

## 复用与许可证

复用本仓MIT的协议、状态服务及B2 HTTP边界；React19/MIT与现有TypeScript/Vite构建和Playwright测试工具保持原依赖。没有新增运行时包、密码库或数据库迁移。Node `crypto`固定seed signer与本地文件journal仅用于`registration-live-check.mjs`测试，不导出产品bundle、不声称提供平台密钥保护或跨进程持久锁。

局部验证与未验证范围以[实施记录](a04-b-implementation-result.md)为准。A04-C双签轮换、A04-D扫码组件、原生keystore/持久锁、完整验收和部署不属于本批。
