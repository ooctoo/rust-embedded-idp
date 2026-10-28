# S03-A3 本人撤销 HTTP 与参考宿主实施结果

2026-10-26。详细设计与实施计划见s03-a3-http-host-design.md；编码前完成独立复核，编码后完成独立审查与主代理集成复核。

## 已完成

可选runtime.account_security显式供应authority、稳定subject key和当前/前一组密钥文件；严格校验文件长度、类型、Unix权限及密钥独立性，不在线生成持久密钥。security-plan/apply/check分别支持foundation与runtime，apply必须提供匹配指纹，安装与检查均由既有存储适配器执行。在线启动及readyz只读核对绑定和布局，不自动修复或迁移。

业务及管理的Bearer/browser均提供撤销和独立结果查询，共8个条件路由。宿主各入口复用同一撤销服务，入口认证仍维持原client/purpose/tenant边界。browser命令要求expected identity和原Origin规则，结果查询无需已撤销Cookie但仍受browser头校验。所有响应no-store，16KiB上限，不发Set-Cookie，防止旧操作迟到响应清除新登录。

主审纠正运行时布局/authority冲突的映射：基础设施失效返回503，仅操作重放内容冲突409；补充单元及真实宿主回归。已有business_profile默认保持不挂载，新条件profile显式声明account_security。

## 局部验证

- Axum lib 183项通过：/private/tmp/idp-s03a3-axum.log。
- App bin 64项通过：/private/tmp/idp-s03a3-app-unsandboxed.log。首次受限执行中2项邮件helper测试失败；允许执行临时脚本后原测试全部通过，未放宽断言或生产超时。
- 工作区all-target locked/offline编译通过：/private/tmp/idp-s03a3-workspace.log。尚未挂载邮件消费者的unused警告保留。
- 合同漂移脚本通过，含17项OpenAPI测试及A05独立合同：/private/tmp/idp-s03a3-contracts.log。
- 一次性PostgreSQL18.6与真实宿主子进程测试通过：/private/tmp/idp-s03a3-host-verified.log。一个测试依次覆盖Disabled与Enabled、显式迁移及错误指纹、缺少扩展时启动拒绝、两业务入口与管理入口的Bearer/Cookie隔离、撤销当前会话后匿名收据查询、同入口新Cookie不受旧请求影响、无配置404、错误authority/缺少密钥拒绝、运行中布局漂移使readyz和收据查询503且不自动修复。

测试夹具修正了重复配置写入、未释放连接导致池耗尽，以及Enabled业务入口不能使用系统域0；Enabled现创建真实业务租户。合成凭据仅用于临时测试，容器由runner清理。

## 未完成边界

本批不含改密、恢复事务及outbox消费者、安全页Web交互，也未注入真实COMMIT网络故障。完整验收、部署、提交和推送均未执行；一期整体目标尚未完成。
