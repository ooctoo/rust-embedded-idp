# S01-A 实施记录

2026-10-26。在设计与独立复核完成后实施，见[设计和计划](s01-a-design-and-plan.md)。没有提交、推送、部署或完整验收。

## 已实现

- reference host每次composition创建一个PasswordWorkBudget，覆盖management/browser、legacy/reference scan认证、ordinary/device认证和两处旧租户注册构造点；最终两条router返回路径均包裹同一个匿名登录HTTP预算。
- CoreTenantRegistrationService保留constructor，增加注入builder；旧注册在真实hash前申请注册许可，hash完成即释放，不跨持久化/邮件投递占用。默认独立budget兼容，宿主多入口显式共享。
- 旧租户注册仅对新引入的password.work_unavailable返回503/code=temporarily_unavailable/no-store，不暴露内部marker；其他backend错误仍500。路由清单同步，历史旧注册完整OpenAPI schema仍未纳入本轮生成范围。
- 两个独立service共用预算的Core负例、跨前缀HTTP容量和取消后物理工作保持许可的测试已补齐。实际diff独立复核未发现阻塞项。

## 验证

- `cargo test --locked --offline -p embedded-idp-core registration_`：31通过。
- `cargo test --locked --offline -p embedded-idp-axum --lib`：158通过。
- `cargo check --locked --offline -p embedded-idp-app --all-targets`通过。
- 专用PostgreSQL 18.6容器：ordinary多入口、Choose注册及legacy reference两模式真实宿主回归3项通过；容器结束清理。
- fmt与diff空白检查通过。HTTP新测试曾错误地直接检查无middleware响应的no-store，并误读旧DTO为error.code；已改为真实router请求及既有顶层code断言，最终通过，未为测试改动响应格式。

## 剩余范围

完整S01未完成。来源/账号速率、硬容量与过期清理、typed阈值、故障策略、两个嵌入示例统一接线、后续恢复入口及交付合同仍需S01-B/后续切片。库默认预算不自动跨宿主共享，未宣称分布式一致性或统计抗枚举；已认证管理密码写入不属于本批匿名入口接线。
