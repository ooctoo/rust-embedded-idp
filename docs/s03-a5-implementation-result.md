# S03-A5 本人改密 HTTP与宿主实施结果

2026-10-26。先详细设计与独立double check，修正认证错误映射和JSON提取拒绝合同后冻结实施。代码又经独立Host/Axum审查及主代理实际变更审查；设计见s03-a5-password-http-design.md。

## 已完成

管理及所有普通业务入口挂载可选Bearer/browser改密及结果查询，共8路由。原配置省略runtime.account_security仍不挂载；不新增密钥配置、环境变量或DDL。宿主只构造一份改密服务，复用同一crypto及共享PasswordWorkBudget；启动和readyz沿用只读runtime布局/authority检查。

本人改密使用当前密码，不借用管理重置权限。browser要求expected身份和原Origin规则；匿名result不要求已经撤销的会话，但browser仍受原guard保护。固定JSON400/413、16KiB、no-store、无Set-Cookie，避免旧操作迟到响应覆盖新登录。主审补齐无效actor的401 invalid_session映射，命令参数仍400；credentials_changed文案不提示直接重试旧密码写。

CoreAccountSecurityService旧new签名兼容，增加共享budget builder。账号创建、管理员改密、新建租户管理员三处hash在权限验证后立即try_login，hash完成释放；无需KDF分支不受预算饱和影响。保留旧管理写的锁内hash与hash后actor复核；新本人改密维持锁外KDF。

business OpenAPI条件profile共27操作，管理路由保持专用合同/路由清单。接口和宿主文档同步，HTTP接线不等于Web安全页完成。

## 局部证据

- Core全部327项lib测试及all-target检查通过，包含三处管理hash饱和无写、Existing管理员创建租户/status修改不受饱和影响，以及新错误转换测试（实施worker执行，主代理复核实际代码）。
- Axum新增6项定向测试通过；主代理全部189项lib通过，/private/tmp/idp-s03a5-axum.log。
- App全部64项bin测试通过，/private/tmp/idp-s03a5-app-reviewed.log。首次退出码用例偶发Unknown，修正该测试的截止时间以避免和进程调度混测；专门的timeout/kill/reap断言保持，生产15秒上限未改。未把首次63/64当通过。
- 两mode真实宿主与隔离PG联调通过，/private/tmp/idp-s03a5-reviewed-host.log。覆盖管理Bearer、业务1 browser、业务2 Bearer、管理browser四轮改密，错误旧密码无hash/version/session/receipt/event变化，正确token跨入口拒绝，旧Bearer/Cookie全域失效，新密码各入口登录成功，撤销actor后的匿名结果确认、旧cookie结果请求不删除新cookie、无配置404。
- 该生命周期测试密集登录同一合成账号，首次触发默认账号429；夹具显式account burst100/period10ms，其余默认配置和所有准入保持，不改生产阈值或限流测试。真实容量与负载验收未执行。
- 工作区all-target locked/offline编译通过，/private/tmp/idp-s03a5-workspace.log；保留尚未装配邮件消费者的unused警告。
- OpenAPI18项及漂移脚本通过，主代理复跑也通过，日志/private/tmp/idp-s03a5-contracts.log。
- 格式/diff检查通过，原8个未跟踪测试SHA保持不变。临时数据库自动清理，无真实库或邮件供应商参与。

## 待推进

S03-B恢复start/complete、O01a持久outbox消费者及清理、HTTP与Web安全页仍未完成。恢复开始详细设计已草拟并进入独立复核，未按草案编码。仍不声明完整验收、生产就绪或一期全部交付；未部署、提交、推送。
