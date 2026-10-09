# 租户、角色与权限：2.0.0 交付记录

更新时间：2026-09-27。本文保留 `2.0.0` 交付时的历史状态；当前 3.0.0 的 tenant_v6 升级见[统一手册](device-scan-login-upgrade.md)，扫码交付与验收见[验证记录](device-scan-login-validation.md)；授权契约见[业务标识设计](business-domain-authorization-design-v1.md)，运行方式见[参考服务说明](standalone-app-v1.md)。

## 已实现

| 边界 | 当前能力 |
| --- | --- |
| Core | 租户成员、业务隔离的角色和权限定义、类型/实例范围绑定、业务管理员；按可信租户、业务和用户查询本人角色及单次/批量授权 |
| PostgreSQL | `tenant_v3` 结构、同租户同业务约束、游标查询、共享有界连接池、管理写事务与审计；两种运行模式使用同一套结构 |
| HTTP | 可选 Axum 业务与管理路由；管理登录令牌与业务令牌用途分离，管理操作在服务端复查身份和权限 |
| 参考服务 | 单进程组合管理 UI 与对外 API；`disabled` 和 `enabled` 使用独立 schema；显式离线建库、签名密钥与管理员初始化，在线启动只读核验身份状态 |
| React | 独立管理后台；本地 `@embedded-idp/react` 登录/选租户/本人角色入口及 `/admin` 权限目录入口 |
| 无租户嵌入宿主示例 | `examples/no-tenant-host` 是单独的 Axum 业务进程；只使用 Disabled 模式，报告表可与 IdP 同库同 schema 或分开放置，读取时执行实例级权限检查 |

`disabled` 仅使用租户域 `0`；`enabled` 的 `0` 是平台域，真实业务权限属于具体租户。权限定义的主键是 `(tenant_id, business_id, resource_type, action)`；普通角色需显式关联权限并按类型/实例分配，业务管理员绑定自动覆盖同业务新增的有效权限。业务管理员不获得 IDP 管理权限。IdP 不判断报告等业务对象是否存在或属于该租户与业务。

同一用户 ID 和登录凭证可加入多个租户，但创建时必须指定首个租户。管理后台可创建租户时新建首位管理员账号，或选择已有用户；之后可显式绑定已有用户。设备、会话、授权码与授权检查均绑定租户。业务登录支持固定租户或认证后选租户；管理登录独立配置。

## 本地验证入口

参考服务的三个模板统一位于仓库根目录：[共享配置](../.env.example)、[无租户模式](../.env.disabled.example)、[带租户模式](../.env.enabled.example)。`./scripts/dev_env.sh <mode> init` 只复制缺失配置，不覆盖本机文件。两模式可共用一个 PostgreSQL 数据库，但必须使用不同 schema 和端口；参考服务默认 schema 为 `embedded_idp_disabled_v2` / `embedded_idp_enabled_v2`。schema 名的 `_v2` 是参考服务开发脚本防误用约束，数据库结构版本写在 `access_state.module_version` 中。不要把旧 schema 的表删除视作自动迁移。无租户嵌入宿主示例使用[自己的配置和启动命令](../examples/no-tenant-host/README.md)，不读取这些根目录配置；带租户嵌入体验留待后续。

先运行 `pnpm --dir web install --frozen-lockfile`，再按[参考服务启动步骤](standalone-app-v1.md)准备密钥、两个 schema 和各自管理员。开发脚本启动前会构建 Web；参考服务的管理页分别位于 `127.0.0.1:9100` 和 `127.0.0.1:9200`。构建与回归命令见 [README](../README.md#验证与文档)。实时 PostgreSQL 测试只使用显式的 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI`，在随机临时 schema 运行，不修改应用 schema。

## 本次验证

本次 2.0 实施已通过：Rust 工作区 359 项离线测试、PostgreSQL 与真实参考服务 113 项实库测试、Web 客户端 79 项测试和 3 项组件包检查；Web 构建、Rust 全目标编译、格式及差异检查均通过。实库检查使用临时 schema。它们不替代下列生产宿主及浏览器验收。

迁移回归通过 [`scripts/test_business_scope_migration.sh`](../scripts/test_business_scope_migration.sh) 实际执行：完整 dry-run 后无变更、v2→v3 保留普通授权和自定义名称、错误映射回滚、重跑无重复审计，以及默认 search_path 下触发器正确执行。

## 仍需完成

- IDP 内部设备身份与生命周期增量见[详细技术设计](device-identity-lifecycle-design-v1.md)和[独立实施计划](device-identity-lifecycle-implementation-plan.md)。本页 2.0 验证结果不覆盖这些增量；该生命周期步骤已纳入 3.0.0；其本机 v4 记录属于历史，当前部署版本和生产验收须另行核对。

- 扩展示例中的报告列表与分页：必须先按业务数据库和授权范围过滤，再分页；当前示例只提供单份报告读取。
- 完成宿主中的设备自助 UI、真实设备证明接入，以及部分管理页面的浏览器交互补验。
- 测量资源授权和管理查询的 SQL 计划、连接池等待、吞吐与 p95/p99，并验证并发撤权边界。现有离线和集成测试不等于生产性能验收。
- 生产宿主仍需按[安全要求](rust-embedded-idp-production-security-delivery-v2.md)负责限流、密钥轮换、设备准入及运维；`embedded-idp-app` 是开发参考宿主。

已交付的 1.0.0 破坏性升级不提供首版之前的结构、令牌、设备证明或管理 API 兼容。2.0 另提供 tenant_v2 → tenant_v3 的显式业务映射迁移，见[变更记录](../CHANGELOG.md)和[业务标识设计](business-domain-authorization-design-v1.md)。
