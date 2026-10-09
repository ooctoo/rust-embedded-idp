# 无租户嵌入宿主示例

这是一个独立运行的 Axum 业务应用，只演示 `disabled` 无租户模式。它直接装配 `embedded-idp-core`、`embedded-idp-axum`、`embedded-idp-security` 和 PostgreSQL 适配器。管理后台使用仓库中的参考管理应用，但由本示例自己的配置和脚本启动；两个进程连接**同一个 IdP schema**。示例报告默认存入同库的独立业务 schema；也可把 `NO_TENANT_HOST_BUSINESS_SCHEMA` 设为 IdP schema，或通过 `NO_TENANT_HOST_BUSINESS_PG_URI` 放到另一业务数据库。

宿主提供同源 React 页面、IdP 的业务登录/refresh/退出/本人角色路由，以及 `GET /api/reports/:id`。报告接口只接受业务 Bearer 令牌；它从 IdP 认证服务取得实时用户，检查 `report::read::<id>` 授权，再读取宿主报告。内部授权域固定为 `0`，界面不提供租户管理或切换。管理接口和管理令牌没有挂到宿主进程。

## 运行

示例的 Rust 服务、React 页面、构建配置和启动命令都在 `examples/no-tenant-host` 内；页面构建复用仓库 `web` 中已安装的工具和 IdP 组件。不读取仓库根目录的 `.env` 或 `scripts/dev_env.sh`。首次运行先安装 Web 依赖，再复制本示例的配置，修改其中的 PostgreSQL URI，然后创建签名密钥、IdP 与业务表，并离线初始化管理员：

```sh
pnpm --dir web install --frozen-lockfile
./examples/no-tenant-host/run.sh init
# 编辑 examples/no-tenant-host/.env 中的 EMBEDDED_IDP_APP_PG_URI
./examples/no-tenant-host/run.sh key-init
./examples/no-tenant-host/run.sh db-init
./examples/no-tenant-host/run.sh bootstrap-admin \
  --email admin@example.test --password-stdin < /path/to/private/admin-password
```

在一个终端启动管理后台。它会创建缺失的公开客户端 `desktop-app`，供报告宿主登录使用：

```sh
./examples/no-tenant-host/run.sh management
```

在另一个终端准备一份示例报告并启动宿主：

```sh
./examples/no-tenant-host/run.sh seed-report r001 '示例报告'
./examples/no-tenant-host/run.sh serve
```

打开 [宿主页面](http://127.0.0.1:9300/)；管理后台在 [127.0.0.1:9500](http://127.0.0.1:9500/)。本示例仅支持无租户模式；带租户的嵌入体验留待后续示例。IdP 与业务表默认在同一个 PostgreSQL 数据库中，可选择相同或不同 schema；业务数据也可使用另一连接 URI。

在管理后台创建业务权限 `report::read`，把它加入一个角色，并为测试用户分配 `report` 类型级范围或实例 `r001` 范围。用该用户在宿主页面登录并读取 `r001`。撤销角色分配或停用权限后，再次读取会得到 403。创建权限本身不会自动授权。已获授权但业务库中没有该报告时返回 404；未登录或会话失效返回 401。

`init` 只复制本示例的 `.env.example`，不会覆盖现有 `.env`。`db-init` 幂等准备 IdP 和业务表；它不会创建或重设管理员。同 schema 部署时，已有业务表会保留；IdP 对象重名会使 IdP 建表事务整体回滚。宿主报告表由后续独立步骤创建，若该步骤失败，已完成的 IdP 初始化不会回滚。`bootstrap-admin` 从标准输入读取密码，不要把密码放入命令参数或配置。在线启动检查现有 IdP 与业务结构，不执行初始化或修复。`seed-report` 只向业务表写入示例内容。可用 `NO_TENANT_HOST_BIND_ADDR` 覆盖宿主端口，用 `NO_TENANT_HOST_BUSINESS_SCHEMA` 设置业务 schema。默认业务连接使用本地 PostgreSQL 明文连接；生产宿主需自行配置 TLS、连接池、资源生命周期、限流和设备准入。

## 验证边界

`cargo test -p embedded-idp-no-tenant-host` 检查宿主构造的授权查询绑定真实用户和报告 ID；`./examples/no-tenant-host/run.sh build-web` 检查页面并生成 `examples/no-tenant-host/dist`。`serve` 会先执行这一步。示例展示业务资源读取与权限撤销的集成路径，不包含报告列表、写入 API、完整 OIDC 客户端、设备注册界面或带租户嵌入能力。

## 浏览器恢复

示例登录组件使用 Cookie 模式，刷新页面后通过 `/auth/browser/restore` 恢复，访问令牌仍只保存在内存。`NO_TENANT_HOST_BROWSER_ORIGIN` 默认 `http://<NO_TENANT_HOST_BIND_ADDR>`，反向代理部署需设置精确外部源；非 loopback 必须 HTTPS。Cookie 名称为 `idp_<bind-port>_business`，不与参考管理端共用。接口与多标签页规则见[浏览器会话设计](../../docs/browser-session-design.md)。

## 2.0 业务标识

示例配置必须显式提供 `NO_TENANT_HOST_BUSINESS_ID`，模板使用 `reports`。在 IDP 管理端创建权限、角色和用户分配时使用相同业务标识；服务端从配置构造授权查询，不接受前端覆盖该标识。可配置普通 `report/read` 角色范围，也可在该业务创建 `business_admin` 后直接分配用户。

当前示例随 3.0.0 使用 tenant_v6；已有 v3/v4/v5 schema 按[统一升级手册](../../docs/device-scan-login-upgrade.md)升级。已有 IdP v2 schema 需先执行[显式映射迁移](../../docs/business-domain-authorization-design-v1.md)，示例启动不会自动升级或重新授予权限。业务报告表仍由单业务宿主独占，授权隔离不要求为该表增加第二套身份模型。
