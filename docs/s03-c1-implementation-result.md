# S03-C1 Web 安全 SDK 实施记录

> 后续状态：C2页面与持久日志已完成本批实现及局部验证，见[C2实施记录](s03-c2-implementation-result.md)。下文保留C1批次范围。

2026-10-26；[设计与独立复核](s03-c1-web-client-design.md)、[接口合同](api/account-security-web-contract.md)。本批范围是SDK及业务/管理身份客户端窄桥，不含C2页面和持久日志。

实现了八种固定操作的传输桥、冻结且可序列化的安全intent、strict恢复解析、全域本人会话校验、撤销/改密/恢复及匿名收据查询。复用既有revision、browser coordinator、transport和安全随机；无新依赖。密码/code/token不进入intent。Cookie本人请求不刷新；旧密码错误保留登录；清理仅在SDK验证成功后针对精确owner进行。

主代理集成审查修正：桥不重复SDK成功清理，避免在响应校验前丢失身份；运行时拒绝路径表继承属性；保留管理Session.client_id可选的旧类型，端口输入通过运行时四字段校验；用原生base64替代手写编码，列表校验current和重复tenant/session。构建产物测试覆盖SDK与两实际client组合的错误密码保留、成功改密清理及退出后匿名核对。

最终验证：`pnpm --dir web test` 201/201通过（`/private/tmp/idp-s03c1-final-tests.log`）；Web完整构建含TypeScript声明与两嵌入入口通过（`/private/tmp/idp-s03c1-final-build.log`，仅既有管理bundle体积提示）；构建产物测试9/9通过（`/private/tmp/idp-s03c1-final-bundle.log`）；git diff --check通过。额外以TypeScript程序确认两个既有client均可作为新端口，SDK缺client_id的runtime拒绝已纳入单测。既有8个未跟踪Rust测试SHA256全部与原清单一致，不在本批修改范围；不提交/推送/部署、不完整验收。下一批必须完成可见自助页面、匿名恢复入口、提交前持久intent及刷新后恢复，才可整理一期交付完成清单。
