# S01-C 实施结果

2026-10-26。本批补齐在线 client-secret 与设备 admission 的共享昂贵工作边界。详细设计及复核修正见 s01-c-design-and-plan.md。

- Core 新增可选 BudgetedClientSecretCodec，原 PhcClientSecretCodec 兼容；hash/verify 与宿主密码登录共享4槽，许可覆盖同步真实工作。精确预算错误穿透 tenant 与 legacy client admin/client auth，普通 provider 错误保持原投影。
- 参考宿主在线 OIDC/client admin、两个嵌入示例显式注入；设备 admission 替换独立 static semaphore，改共享 composition 预算并在 spawn_blocking 中持许可。离线 seed/grant 文件校验不改变。
- HTTP 新增精确503映射：普通与管理 temporarily_unavailable，tenant OIDC server_error；不错误投影401，不泄漏内部 marker。原 device_admission_busy 合同保留。OpenAPI 和宿主附加合同同步。

## 验证证据

Core wrapper/错误映射/client admin 局部测试通过，包含4槽混合hash/verify阻塞、满载不调用底层、释放恢复、管理无半写及 legacy 精确marker匹配。阻塞测试使用独立条件变量及5秒期限。

Axum lib 172项测试通过；设备 admission 3项通过。工作区 all-targets 编译通过。专用临时PostgreSQL真实宿主的 confidential OIDC资源隔离及设备admission入口/身份绑定2项集成通过。API合同15项及Enabled示例静态合同检查通过。测试日志为 /private/tmp/idp-s01c-{check,axum,device,live}.log；详细测试源码在对应模块。

不把上述证据称为完整验收。旧注册SMTP/sendmail尚未满足新的安全邮件投递合同，归O01a接续；管理员密码创建/改密昂贵工作归S03统一处理，不宣称本批已完成整个安全基础版。

最终复核补证：legacy map_service_error 新增503自身附 no-store，覆盖没有外层middleware的旧公开router。Core实际OIDC内存store新增两项饱和回归：授权码未消费且session未新增，释放预算后同code兑换成功；revoke满载时session/refresh未撤销，释放后同token撤销成功。对应 authentication_tests::oidc 模块6项通过。该证据补齐服务层无副作用验证，不以mapper测试替代业务事务验证。
