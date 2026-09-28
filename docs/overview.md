# 项目概览

`rust-embedded-idp` 是可嵌入 Rust 宿主的身份与访问控制模块，不以通用云 IAM 平台为目标。已发布的 2.0.0 基于 `tenant_v3`；本开发分支已实现 `tenant_v4` 并升级本机参考 schema，生产设备生命周期验收尚未完成。Disabled 使用业务域 `0`，Enabled 使用真实业务租户并把 `0` 留给平台管理；租户内授权对象按 `business_id` 隔离。账号创建时必须有初始成员关系；同一用户可凭同一 user ID 和凭证加入多个租户。

模块能力包括账号与会话、租户成员关系、角色及资源类型/实例授权、设备证明、OAuth/OIDC，以及独立的管理认证。管理端和业务接口可在一个参考服务中部署；嵌入时管理服务可独立运行、由宿主挂载或不启用，宿主控制台也可复用 IdP 管理接口。所有启用的 IdP 入口共用同一个 IdP 数据库与 schema；宿主自行管理业务表，可选择与 IdP 共用或分开存放。

## 边界

- `embedded-idp-core`：领域规则、服务/存储契约、权限检查。
- `embedded-idp-axum`：模块本地 HTTP 路由和薄适配器。
- `embedded-idp-storage-postgres`：配置注入的 PostgreSQL 连接池、SQL 与显式 schema 初始化。
- `embedded-idp-security`：生产密码学适配器；`embedded-idp-email`：邮件契约。
- `embedded-idp-app`：开发参考服务、管理后台与本地启动命令，不是生产宿主。

IdP Core 已按租户和业务标识提供业务权限定义的动态创建、读取、修改、启停和归档；同名权限在不同租户或业务是独立记录，可由目标域管理员在 IdP 独立后台或宿主控制台手动维护。管理页面只选择租户，同租户列表默认展示授权范围内的全部业务并支持业务筛选；创建、详情、修改和授权操作使用精确业务域。IdP 保存标识、说明和授权关系，不定义该标识的具体业务含义；宿主决定何处检查，并验证报告等业务资源的存在和租户归属。

## 当前状态与文档入口

设备身份的[详细技术设计](device-identity-lifecycle-design-v1.md)和[实施计划](device-identity-lifecycle-implementation-plan.md)已编写，状态版本、恢复启用、可信准入登记、精确解绑、操作回执、密钥元数据与身份审计已实现；两模式随机 schema 与 v3→v4 迁移实库回归通过，管理浏览器已验证停用/恢复，完整 P0 验收仍待完成。该设计不改变业务授权边界，不把设备、会话绑定到业务标识。

参考服务的两模式、管理后台、宿主嵌入登录/本人角色/权限目录组件已接通；[无租户嵌入宿主示例](../examples/no-tenant-host/README.md)展示了业务数据与 IdP 授权的集成，带租户嵌入体验留待后续。设备自助界面、报告列表授权过滤及性能验收尚未完成；`web/embedded/demo.html` 仍是模拟交互页面。当前操作方式见 [README](../README.md) 和 [参考服务指南](standalone-app-v1.md)。

- [租户/角色/权限设计](tenant-role-permission-design-v1.md)：当前目标与授权语义。
- [执行计划](tenant-access-execution-plan.md)：当前边界及按阶段历史验证记录。
- [宿主集成说明](host-integration-v1.md)：注入、管理认证和 HTTP 边界；旧 v1 示例已标为历史。
- [生产安全要求](rust-embedded-idp-production-security-delivery-v2.md)：上线前的安全边界。

`module-architecture-v1.md`、`service-and-api-surface-v1.md`、`postgres-schema-design-v1.md`、`device-model-v1.md` 和 `implementation-slices-v1.md` 保留早期设计背景，其中无租户、共享设备或旧 API 的描述不是当前运行契约。
