# rust-embedded-idp

可嵌入 Rust 宿主的身份与访问控制模块，提供账号、租户、角色、资源权限、设备证明和 OAuth/OIDC。仓库另有 React 管理后台、宿主可嵌入的 React 登录组件，以及用于开发的独立参考服务。参考服务不是生产宿主。

## 设计目标与边界

授权设计：[租户内业务标识与业务管理员](docs/business-domain-authorization-design-v1.md)，包含业务权限隔离、`business_admin`、IDP 管理角色重命名及 `tenant_v2 → tenant_v3` 显式迁移。这是 2.0.0 的破坏性授权契约升级。

设备升级设计：[设备身份与安全生命周期](docs/device-identity-lifecycle-design-v1.md)及[实施计划](docs/device-identity-lifecycle-implementation-plan.md)。本分支已接通宿主提交设备 ID、固定预期公钥、设备版本与启停/撤销、精确解绑、操作回执、当前/历史密钥元数据和身份操作审计；v3→v4 迁移已在隔离 PostgreSQL schema 回归，并在停机和备份后升级了本机两套参考服务 schema。管理浏览器的停用/恢复已实测，更多浏览器与生产规模性能等完整 P0 发布验收仍未完成，**不能据此作为生产部署**。设备不增加业务归属。

- **按模块接入**：Core 定义身份和授权规则，Axum 提供可组合路由，PostgreSQL 适配器由宿主注入数据库配置。宿主决定外层路由前缀、业务资源归属及运行环境。
- **两种租户模式**：`disabled` 使用单一业务域 `0`；`enabled` 使用真实租户，保留 `0` 作为平台管理域。模式由启动配置固定，不由请求选择。用户创建时必须属于一个域，同一 user ID 和凭证可以加入多个租户。
- **先认证、再授权**：业务会话绑定租户。用户可查看自己的角色；宿主在实际业务接口中以经过认证的用户、租户、资源类型、动作和资源 ID 调用权限检查。IdP 不代替宿主检查报告等业务资源是否存在或属于该租户。
- **租户内业务权限动态管理**：IdP Core 按 `(tenant_id, business_id, resource_type, action)` 管理业务权限定义；Enabled 模式中相同的 `report::read` 在不同租户是独立记录，可有不同的说明和启停状态，Disabled 模式固定在 `0`。具备目标域管理权限的人可手动创建权限、维护角色与分配，既可使用 IdP 独立管理后台，也可使用宿主控制台。IdP 只管理标识与授权，具体业务含义和实际检查位置由宿主决定。
- **管理与业务隔离**：管理登录、令牌用途和路由独立；管理 API 只服务管理端。参考服务使用真实 RS256/Ed25519 适配器，不把开发身份 Header、旧 API key 或空 JWKS 作为生产默认值。

独立部署使用一个 IdP 数据库和一个服务（管理端 + 对外 API）。嵌入部署时，宿主组合 Core、存储和所需的 Axum 路由；IdP 管理端可独立运行、由宿主挂载，或不对外提供。需要在宿主控制台管理权限时，可复用 IdP 的管理接口与前端能力。管理端与宿主中的 IdP 模块始终连接**同一 IdP 数据库和 schema**；宿主自行选择业务表所在数据库和 schema，只要不与 IdP 对象重名，也可与 IdP 共用 schema。见[宿主集成说明](docs/host-integration-v1.md)。

| Crate | 职责 |
| --- | --- |
| `embedded-idp-core` | 模型、服务规则、存储与安全契约 |
| `embedded-idp-security` | 生产密码学适配器 |
| `embedded-idp-email` | 邮件契约 |
| `embedded-idp-axum` | 可组合 HTTP 路由 |
| `embedded-idp-storage-postgres` | PostgreSQL 连接池、SQL 与显式 schema 初始化 |
| `embedded-idp-app` | 开发参考服务、环境加载、管理页面与离线命令 |

## 当前能力与限制

本分支两种模式均使用 `tenant_v6`；已发布的 2.0.0 使用 `tenant_v3`。已接通注册与邮箱验证、登录与选租户、会话/refresh、OIDC、租户设备、角色与资源授权，以及租户/成员/角色/权限目录/设备/会话/客户端/审计管理。业务权限定义可按租户和业务标识创建、读取、修改、启停和归档，并与同租户同业务角色关联。React 管理后台接入真实 API；本地 `@embedded-idp/react` 主入口提供登录、租户选择和本人角色列表，`/admin` 子入口提供权限目录组件，React 19 由宿主提供。

仓库提供[无租户嵌入宿主示例](examples/no-tenant-host/README.md)：另起 Axum 业务进程，复用 IdP 业务路由和 React 登录组件，并在宿主报告接口中检查 `report::read::<id>`。该示例的配置模板和启动命令均在 `examples/no-tenant-host` 内，不依赖根目录的开发环境脚本；带租户的嵌入体验留待后续。`web/embedded/demo.html` 仍只使用模拟响应。设备自助界面、部分管理页面浏览器补验和性能验收仍未完成。

业务权限目录已按租户隔离；内置管理权限受保护。宿主可调用 Core 服务或选装 Axum 管理路由。独立管理应用提供完整页面；本地 `@embedded-idp/react/admin` 入口提供可嵌入的权限目录组件，尚未发布到 npm。组件使用独立的管理会话与管理 API，不使用业务登录令牌；接入方式见 [React 集成说明](docs/react-ui-integration-design.md)。

## 本地开发

需要 Rust stable、Node.js 22、pnpm 10.30.1 和 PostgreSQL。先安装并构建 Web 资源；Rust 参考服务会在编译时嵌入 `web/dist/management`：

```sh
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
```

本地配置分为共享 `.env` 和模式文件 `.env.disabled` / `.env.enabled`。首次创建时运行：

```sh
./scripts/dev_env.sh disabled init
./scripts/dev_env.sh enabled init
```

配置共享 `.env` 中的 `EMBEDDED_IDP_APP_PG_URI`。脚本不会覆盖已有配置。两模式默认使用同一个 PostgreSQL 连接下的 `embedded_idp_disabled_v2` / `embedded_idp_enabled_v2` schema，分别监听 `127.0.0.1:9100` / `127.0.0.1:9200`。模式文件中的值覆盖共享配置；已有 `.env.disabled` / `.env.enabled` 需手动把 schema 名改为 `_v2`，脚本不会覆盖原文件。

首次准备各 schema，并生成一份两模式共用的本地签名私钥：

```sh
./scripts/dev_env.sh disabled key-init
./scripts/dev_env.sh disabled db-init
./scripts/dev_env.sh enabled db-init
```

`key-init` 只在密钥不存在时创建 `.local/idp-signing-key.der`，不会覆盖。`db-init` 在目标 schema 中创建本分支的 `tenant_v6` IdP 对象，允许保留不冲突的宿主对象；重复执行只核对同模式的现有结构和状态，不清除数据，也不创建管理员。对象重名、旧版或不兼容的 IdP 结构会被拒绝；启动不会自动迁移旧 schema。

每个模式需单独执行一次**离线管理员初始化**，邮箱由你指定，密码只能通过标准输入传入，不能放进命令参数或 `.env`。下面是在 zsh/bash 中输入不回显密码的示例：

```sh
read -rs ADMIN_PASSWORD
printf '\n'
printf '%s\n' "$ADMIN_PASSWORD" | ./scripts/dev_env.sh disabled bootstrap-admin --email admin@example.test --password-stdin
printf '%s\n' "$ADMIN_PASSWORD" | ./scripts/dev_env.sh enabled bootstrap-admin --email admin@example.test --password-stdin
unset ADMIN_PASSWORD
```

两模式的账号在不同 schema 中；重复 bootstrap 只检查现有有效管理员，**不会重设密码**。正常启动不传管理员账号或密码：

```sh
./scripts/dev_env.sh disabled start
# 另开终端
./scripts/dev_env.sh enabled start
```

管理页面分别在 [无租户模式](http://127.0.0.1:9100/) 和 [有租户模式](http://127.0.0.1:9200/)；就绪检查在各自的 `/readyz`。Enabled 管理登录默认固定平台 `0`，先创建租户及其管理员；租户管理员登录策略见[参考服务指南](docs/standalone-app-v1.md)。管理 API 在 `/api/admin/*`，业务模块路由保留 `/auth`、`/devices`、`/oidc` 根路径。`start` 先检查已准备的 schema、签名密钥与有效管理员，不运行迁移或修复身份数据；缺失的参考客户端会被创建，已有客户端配置不会被覆盖。

## 权限接入示例

假设宿主有 10 个业务动作，管理员先选择目标租户，在权限目录列表中按需筛选业务标识，并在创建表单填写业务标识，创建对应的 10 个 `resource_type::action` 定义；再在角色与权限中按业务筛选、关联角色，并按资源类型或具体 ID 将角色分配给用户。也可创建该业务唯一的 `business_admin`，直接分配用户后覆盖该业务全部有效权限。宿主仍须以明确的 `business_id` 在对应业务操作中调用 `AuthorizationService::check` 或 `check_many`；IdP 不解释这些标识的业务含义。权限目录以数据库为准，新增业务权限无需在进程内 `PermissionCatalog` 声明；该目录仍用于受保护的内置管理权限。

例如租户 `t1` 创建 `report::read`，租户 `t2` 也可创建同名权限，两者的说明、状态和角色关联互不影响。`t1` 给用户分配 `report` 类型级范围，可覆盖该租户所有报告；分配实例范围 `r001`，只能覆盖 `t1` 中的 `r001`。宿主读取报告时先按 `(tenant_id, report_id)` 查找资源，再检查当前用户对该租户的 `report::read::r001` 授权。新增一份报告不需要新增权限定义。详细契约见[租户/角色/权限设计](docs/tenant-role-permission-design-v1.md)。

## 验证与文档

```sh
node scripts/test_dev_env.mjs
node scripts/test_device_proof_vectors.mjs
pnpm --dir web test
pnpm --dir web build
pnpm --dir web test:embedded-bundle
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
```

管理列表支持 `sort_order=asc|desc`，省略时默认时间倒序。管理页面只选择租户；同租户内权限、角色、绑定列表默认展示全部授权业务，并支持业务标识筛选。权限、角色、绑定的管理游标升级为 v3，并绑定可选业务筛选；本人角色和角色权限游标升级为 v2，绑定必填的精确业务标识。改变业务、过滤条件或排序方向须从第一页开始。权限列表增加 `business_id` 稳定排序键，其他账号、成员、设备、会话列表不增加业务语义。

已有 `tenant_v2` 数据必须停机并按[业务隔离迁移说明](docs/business-domain-authorization-design-v1.md#10-tenant_v2--tenant_v3-显式迁移)提供显式业务映射，通过 `scripts/migrate_business_scope.sh` 执行迁移；不能直接启动新版本或用旧列表排序脚本代替本次迁移。运行时不自动升级。业务标识没有默认值，旧调用方必须更新；现有 schema 名称可保留，数据库内的 `access_state.module_version` 才是结构版本。

本分支的 `tenant_v3 → tenant_v4` 显式升级见[设备生命周期升级手册](docs/device-identity-lifecycle-upgrade.md)。迁移脚本默认预演；正式应用须停写、验证备份并审阅撤销清单。数据库连接通过 libpq 环境变量传递，不放在命令参数中。

内置角色键为 `idp_system_admin`（IDP管理员）、`idp_tenant_security_admin`（IDP租户管理员），其 kind 和职责不变；`business_admin` 只授予所属租户、业务下的业务权限，不授予 IDP 管理能力。

- [参考服务配置与启动](docs/standalone-app-v1.md)
- [开发与嵌入指南](docs/developer-and-integration-guide.md)
- [宿主集成边界](docs/host-integration-v1.md)
- [租户/角色/权限设计](docs/tenant-role-permission-design-v1.md)
- [破坏性升级记录](CHANGELOG.md)
- [当前进度与历史验证记录](docs/tenant-access-execution-plan.md)
- [浏览器 Cookie 会话设计](docs/browser-session-design.md)
- [React 管理与嵌入组件](docs/react-ui-integration-design.md)
- [无租户嵌入宿主示例](examples/no-tenant-host/README.md)
- [生产安全要求](docs/rust-embedded-idp-production-security-delivery-v2.md)
- [通用扫码授权设备登录设计](docs/device-scan-login-design-v1.md)（双向扫码、宿主准入、Pending 交付恢复、ACK 与原操作终止）
- [扫码授权设备登录升级手册](docs/device-scan-login-upgrade.md)
- [扫码授权设备登录验证记录](docs/device-scan-login-validation.md)

`docs/*-v1.md` 中的早期模型和切片文档保留作历史背景；以当前设计、执行计划、代码和测试为准，不把旧开发适配器示例用于生产接入。
