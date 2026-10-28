# S03-B3 密码恢复 HTTP 与宿主接线实施记录

2026-10-26；对应 [详细设计与复核](s03-b3-recovery-http-design.md)。状态：设计、复核、实现与分批局部验证完成；本文件不表示一期整体完成。

## 实现范围

新增独立普通/管理/browser恢复router；严格JSON、16KiB/5秒body限制、query与selector拒绝、browser Origin guard、固定错误和no-store/no-cookie。所有命令依赖既有Core开始/完成/结果服务，HTTP不重复实现资格或密码规则。扩展匿名HTTP许可到恢复start/complete/result，复用取消后仍由物理blocking调用持有的共享许可。

参考宿主只在account_security.recovery_email=true时创建一次共享恢复服务，装配管理、legacy业务及配置化多入口；false或未配置保持404。复用当前持久密钥、SMTP worker、只读runtime检查、同一PasswordWorkBudget。无新依赖/DDL/自动迁移。

保留旧OpenAPI profile签名和默认行为，新增显式recovery profile；条件目录、管理路径清单及恢复HTTP合同同步。修正早期runtime存储设计的request摘要related上下文描述，以已实现的S03-B1 operation+flow合同为准。

## 复核与验证

设计独立复核修正Core错误类型分流及外层准入/Origin顺序说明后冻结。主代理审核宿主各挂载分支、flag前置和共享实例；审核集成fixture时修正显式/identity前缀误用/api的问题。

已通过真实宿主双模式恢复集成1项（37.05秒），包含默认关闭、未知邮箱同形、browser guard/无Cookie调用、真实SMTP获取code、跨入口开始及完成重放、错误收据secret返回false、全域旧会话/密码失效和新密码登录。既有本人改密双模式集成回归1项通过（40.16秒）。日志 `/private/tmp/idp-s03b3-host.log`，一次性PostgreSQL容器已清理。

App all-target及workspace all-target编译通过，日志分别为 `/private/tmp/idp-s03b3-app-check.log`、`/private/tmp/idp-s03b3-workspace.log`；workspace只有既有存储测试警告。Axum全lib 196/196通过（`/private/tmp/idp-b3-axum-lib.log`），包括实际恢复路径取消后持有许可和账号准入顺序。OpenAPI合同20/20、`scripts/check_api_contracts.sh`及cargo fmt/diff检查通过，六条业务/browser路径已对实际router/schema检查，503两个形状已覆盖。

复核发现匿名HTTP预算饱和沿用旧嵌套503 JSON，与业务固定错误形状不同；保留兼容格式并把恢复OpenAPI 503改为oneOf，不改变既有登录错误合同。原8个未跟踪测试SHA256已核对全部不变。

未执行完整验收、部署、推送或提交；原有8个未跟踪测试保持不变。Web安全页、嵌入组件及一期交付汇总仍待后续切片。
