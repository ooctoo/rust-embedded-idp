# S03-A0 Cookie 身份前置实施结果

2026-10-26。本批按 s03-a-browser-identity-design.md 先设计、独立复核再实现，并对实际diff再次复核通过。

Core 新增 SelfSecurityBrowserIdentityService，为普通、管理与受限browser服务提供不旋转凭据的本人身份验证。所有调用必填 expected identity；purpose与期限由服务构造绑定。复用现有账号/租户/成员/session/client/refresh/设备/期限验证，返回可信AccessActor。旧Business-only身份接口和扫码调用链保持原有业务限制。

局部验证：browser模块25项通过（新增3项）；scan相关22项通过；工作区all-targets编译、fmt与diff检查通过。本机日志 /private/tmp/idp-s03a0-{browser,scan,check}.log。验证包括management/business隔离、配置client与expected四字段错配、受限期限、被撤销session、proof-required拒绝和不旋转/撤销refresh。

尚未暴露本人HTTP路由、修改数据库或启用安全页；本人会话/改密/恢复仍待后续实施。后续HTTP构造必须核对identity service purpose/lifetime与BrowserSessionHttpConfig一致，复用Origin/CSRF/Cookie边界；本批Core证据不能证明未来HTTP装配已安全完成。
