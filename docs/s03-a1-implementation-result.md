# S03-A1 本人会话查询实施结果

2026-10-26；按 s03-a1-session-query-design.md 先设计/独立复核后实现，再审核实际diff。已完成Core、PG、Axum及参考宿主业务/管理/legacy入口的Bearer和Cookie查询链路；安全页UI及撤销/改密仍未完成。

Core规定本人全域active会话的有界分页、cursor主体绑定、过期投影及错误adapter防护。PG按state→tenant→account→session顺序在进入Core闭包前锁定actor，再取Clock，避免锁等待前时间授权已经过期的会话。actor必须第一方scope=NULL；列表仍包含本人委托会话。跨主体行、失效成员/设备/key/binding与已撤销actor均拒绝。

HTTP不接受subject选择；Bearer沿用各入口认证，Cookie复用只读身份和精确Origin/CSRF配置，不旋转凭据；响应仅非秘密会话元数据、no-store。现有browser guard行为保持不变。业务两条路由进入生成OpenAPI，管理两条记录在专用合同/route inventory，不声称已有完整管理OpenAPI。

## 分批验证

- Core定向6项通过，含锁后采样Clock回归；Axum lib 177项通过，含新增Bearer/browser合同测试。
- 独立PG 3项通过，覆盖两mode、多租户/分页/current/expired、委托actor限制、同主体委托会话展示、他人行排除、cursor和设备授权事实。
- 真实参考宿主定向1项（内部两mode）通过：普通双入口、管理Bearer、业务与管理Cookie查询，主体/入口隔离及Cookie不旋转；原重排/恢复/撤销流程回归继续通过。首轮失败来自夹具切换端口后复用旧issuer管理令牌，已改为新宿主重新登录，未放宽认证规则。
- API合同/漂移检查16项及A05静态合同检查通过；工作区all-targets编译、fmt和diff检查通过。

本机证据：/private/tmp/idp-s03a1-core.log、idp-s03a1-axum.log、idp-s03a1-live.log（PG通过，首次host夹具失败保留）、idp-s03a1-host-live.log（修正后host通过）、idp-s03a1-final-check.log。测试使用自动清理的临时PG容器与合成账号。

未进行完整验收、生产迁移、部署、提交或推送。O01a持久outbox、本人撤销/改密、安全页UI和密码恢复仍属一期待推进事项。
