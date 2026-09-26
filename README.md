# rust-embedded-idp

可嵌入 Rust 宿主的身份与访问控制模块，提供账号、租户、角色、资源权限、设备证明和 OAuth/OIDC。仓库另有 React 管理后台、宿主可嵌入的 React 登录组件，以及用于开发的独立参考服务。参考服务不是生产宿主。

## 设计目标与边界

- **按模块接入**：Core 定义身份和授权规则，Axum 提供可组合路由，PostgreSQL 适配器由宿主注入数据库配置。宿主决定外层路由前缀、业务资源归属及运行环境。
- **两种租户模式**：`disabled` 使用单一业务域 `0`；`enabled` 使用真实租户，保留 `0` 作为平台管理域。模式由启动配置固定，不由请求选择。用户创建时必须属于一个域，同一 user ID 和凭证可以加入多个租户。
- **先认证、再授权**：业务会话绑定租户。用户可查看自己的角色；宿主在实际业务接口中以经过认证的用户、租户、资源类型、动作和资源 ID 调用权限检查。IdP 不代替宿主检查报告等业务资源是否存在或属于该租户。
- **租户内业务权限动态管理**：IdP Core 按 `(tenant_id, resource_type, action)` 管理业务权限定义；Enabled 模式中相同的 `report::read` 在不同租户是独立记录，可有不同的说明和启停状态，Disabled 模式固定在 `0`。具备目标域管理权限的人可手动创建权限、维护角色与分配，既可使用 IdP 独立管理后台，也可使用宿主控制台。IdP 只管理标识与授权，具体业务含义和实际检查位置由宿主决定。
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

两种模式均使用 `tenant_v2`。已接通注册与邮箱验证、登录与选租户、会话/refresh、OIDC、租户设备、角色与资源授权，以及租户/成员/角色/权限目录/设备/会话/客户端/审计管理。业务权限定义可按租户创建、读取、修改、启停和归档，并与本租户角色关联。React 管理后台接入真实 API；本地 `@embedded-idp/react` 主入口提供登录、租户选择和本人角色列表，`/admin` 子入口提供权限目录组件，React 19 由宿主提供。

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

`key-init` 只在密钥不存在时创建 `.local/idp-signing-key.der`，不会覆盖。`db-init` 在目标 schema 中创建 `tenant_v2` 的 IdP 对象，允许保留不冲突的宿主对象；重复执行只核对同模式的现有结构和状态，不清除数据，也不创建管理员。对象重名、旧版或不兼容的 IdP 结构会被拒绝；本次不自动迁移旧开发 schema。

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

假设宿主有 10 个业务动作，管理员可在目标租户的「权限目录」创建对应的 10 个 `resource_type::action` 定义，在「角色与权限」中关联角色，再按资源类型或具体 ID 将角色分配给用户。宿主仍须在对应业务操作中调用 `AuthorizationService::check` 或 `check_many`；IdP 不解释这些标识的业务含义。权限目录以数据库为准，新增业务权限无需在进程内 `PermissionCatalog` 声明；该目录仍用于受保护的内置管理权限。

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

管理列表支持 `sort_order=asc|desc`，省略时默认时间倒序；时间相同按唯一标识同向排列。翻页须保持排序方向，切换方向从第一页开始。已有 `tenant_v2` schema 使用本版本前，需由数据库维护者显式执行 `psql -v schema=目标_IdP_schema -f scripts/migrate_list_time_desc.sql`（连接由本地 PostgreSQL 配置提供）。该脚本保留数据、为未知历史权限保留空创建时间，并可重复执行。在线启动不会代为升级；v1 管理分页游标失效，刷新列表从第一页开始；已有 v2 倒序游标仍可使用。新建 schema 无需额外升级。

真实 PostgreSQL 测试必须显式设置 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI`，再运行 `./scripts/run_live_postgres_checks.sh disabled`。测试使用随机临时 schema，不会因为缺少测试连接而改用应用连接。

- [参考服务配置与启动](docs/standalone-app-v1.md)
- [开发与嵌入指南](docs/developer-and-integration-guide.md)
- [宿主集成边界](docs/host-integration-v1.md)
- [租户/角色/权限设计](docs/tenant-role-permission-design-v1.md)
- [1.0.0 破坏性升级记录](CHANGELOG.md)
- [当前进度与历史验证记录](docs/tenant-access-execution-plan.md)
- [浏览器 Cookie 会话设计](docs/browser-session-design.md)
- [React 管理与嵌入组件](docs/react-ui-integration-design.md)
- [无租户嵌入宿主示例](examples/no-tenant-host/README.md)
- [生产安全要求](docs/rust-embedded-idp-production-security-delivery-v2.md)

`docs/*-v1.md` 中的早期模型和切片文档保留作历史背景；以当前设计、执行计划、代码和测试为准，不把旧开发适配器示例用于生产接入。
