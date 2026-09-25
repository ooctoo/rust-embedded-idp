# 租户、角色与权限：当前交付与验收

更新时间：2026-09-25。本文记录 `1.0.0` 工作分支的当前状态；详细规则见[模块设计](tenant-role-permission-design-v1.md)，运行方式见[参考服务说明](standalone-app-v1.md)。旧版按开发批次记录的计划已移除，避免把当时的待办误读为当前缺口。

## 已实现

| 边界 | 当前能力 |
| --- | --- |
| Core | 租户成员、角色、业务权限定义、类型/实例范围绑定；按可信租户和用户查询本人角色、所属租户及单次/批量授权 |
| PostgreSQL | `tenant_v2` 结构、同域约束、游标查询、共享有界连接池、管理写事务与审计；两种运行模式使用同一套结构 |
| HTTP | 可选 Axum 业务与管理路由；管理登录令牌与业务令牌用途分离，管理操作在服务端复查身份和权限 |
| 参考服务 | 单进程组合管理 UI 与对外 API；`disabled` 和 `enabled` 使用独立 schema；显式离线建库、签名密钥与管理员初始化，在线启动只读核验身份状态 |
| React | 独立管理后台；本地 `@embedded-idp/react` 登录/选租户/本人角色入口及 `/admin` 权限目录入口 |

`disabled` 仅使用业务域 `0`；`enabled` 的 `0` 是平台域，真实业务权限属于具体租户。权限定义的主键是 `(tenant_id, resource_type, action)`；用户对某个资源 ID 的权限来自同域角色、角色权限和类型/实例范围绑定。IdP 只保存标识与授权，不判断报告等业务对象是否存在或属于该租户。创建权限不会自动授予任何用户。

同一用户 ID 和登录凭证可加入多个租户，但创建时必须指定首个租户。管理后台可创建租户时新建首位管理员账号，或选择已有用户；之后可显式绑定已有用户。设备、会话、授权码与授权检查均绑定租户。业务登录支持固定租户或认证后选租户；管理登录独立配置。

## 本地验证入口

三个模板统一位于仓库根目录：[共享配置](../.env.example)、[无租户模式](../.env.disabled.example)、[带租户模式](../.env.enabled.example)。`./scripts/dev_env.sh <mode> init` 只复制缺失配置，不覆盖本机文件。两模式可共用一个 PostgreSQL 数据库，但必须使用不同 schema 和端口；本地默认 schema 为 `embedded_idp_disabled_v2` / `embedded_idp_enabled_v2`。schema 名的 `_v2` 是开发脚本防误用约束，数据库结构版本写在 `access_state.module_version` 中。不要把旧 schema 的表删除视作自动迁移。

先运行 `pnpm --dir web install --frozen-lockfile`，再按[参考服务启动步骤](standalone-app-v1.md)准备密钥、两个 schema 和各自管理员。开发脚本启动前会构建 Web；参考服务的管理页分别位于 `127.0.0.1:9100` 和 `127.0.0.1:9200`。构建与回归命令见 [README](../README.md#验证与文档)。实时 PostgreSQL 测试只使用显式的 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI`，在随机临时 schema 运行，不修改应用 schema。

## 仍需完成

- 增加可运行的真实业务宿主示例，证明其用可信租户、用户和实际报告 ID 执行授权；报告列表需在分页前结合业务数据库过滤。
- 完成宿主中的设备自助 UI、真实设备证明接入，以及部分管理页面的浏览器交互补验。
- 测量资源授权和管理查询的 SQL 计划、连接池等待、吞吐与 p95/p99，并验证并发撤权边界。现有离线和集成测试不等于生产性能验收。
- 生产宿主仍需按[安全要求](rust-embedded-idp-production-security-delivery-v2.md)负责限流、密钥轮换、设备准入及运维；`embedded-idp-app` 是开发参考宿主。

这次破坏性升级不提供旧结构、旧令牌、旧设备证明或旧管理 API 的兼容与数据迁移。详见[变更记录](../CHANGELOG.md)。
