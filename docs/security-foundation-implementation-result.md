# O01a-B0 / S03 安全基础扩展实施结果

2026-10-26。先完成详细设计与独立复核，再实现；实际代码再次只读审查，补齐指出的测试遗漏。参考 security-foundation-design-and-plan.md 与 api/security-foundation-contract.md。

已增加可选 security_foundation_v1：accounts凭据版本由trigger维护，security_state保存部署绑定/布局指纹，security_events仅固定类型/结果和非秘密关联字段。PG adapter提供显式plan/apply/check，安装使用state排他锁和单次事务。无在线自动DDL，无新HTTP路由，无真实数据库迁移。

## 已验证

- 离线authority边界单元测试1项通过；工作区all-targets编译、fmt和diff检查通过。
- 独立临时PostgreSQL 5项集成通过，命令为 `cargo test -p embedded-idp-storage-postgres --test live_access_admin security_foundation:: --locked --offline -- --ignored --test-threads=1`（显式测试URI由临时容器runner提供）。
- 两种tenancy mode下plan只读、跨schema/authority/mode绑定拒绝、重复安装拒绝；相同plan并发只有一个成功。
- 新账号省略版本自动为1、显式非1拒绝；四个安全字段改变递增，profile/相同值不递增；版本不可手工降低；安全写与事件提交/回滚一致。
- 部分表/函数/版本列预占拒绝；加列、禁用trigger、同名CHECK改为true被布局检查拒绝；恢复原结构可重新通过。
- 实际注册基础扩展先装/后装两种顺序均通过，密码变化同时推进两个独立revision，健康检查不误报注册trigger。

本机证据日志 /private/tmp/idp-security-foundation-live-reviewed.log 与 idp-security-foundation-check.log；测试使用随机schema且容器自动清理。先前8个未跟踪测试文件保持原字节内容。

本批未交付Core本人安全服务、自动事件记录、outbox、receipt或密码恢复消费者，不能仅凭扩展安装声称这些产品能力已完成。COMMIT未知按合同由check核对，不自动重试；完整验收、生产迁移、部署、提交和推送均未执行。
