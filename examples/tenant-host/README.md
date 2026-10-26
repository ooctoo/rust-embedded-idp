# Enabled 嵌入宿主示例

本示例是独立 Axum 宿主，直接消费本仓公开 Core/Axum/security/Postgres 库，固定 `TenancyMode::Enabled`。不依赖 `embedded-idp-app` 的内部装配，不更改 [Disabled 示例](../no-tenant-host/README.md)。仅绑定 loopback、仅接受显式 loopback PostgreSQL 连接，使用本地 NoTls；不作为生产配置模板。

## 路由与信任边界

| 入口 | 可信策略 | Cookie Path | 会话用途 |
| --- | --- | --- | --- |
| `/fixed` | 固定 tenant-a | `/fixed/auth/browser` | Business，client=tenant-host-fixed |
| `/choose` | 验证账号后选择 active 成员租户 | `/choose/auth/browser` | Business，client=tenant-host-choose |
| `/management` UI、`/control` API | 平台 Fixed0 | `/control/admin/auth/browser` | Management，独立 client/audience |

Cookie 仅供登录、refresh、restore；报告与权限目录 API 使用内存中的对应 Bearer，不能仅靠 Cookie 读取业务。普通业务 token 无法调用管理路由；Fixed 与 Choose 也不能混用 token。选择租户要求独立的 active membership；共享账号密码不自动加入另一租户。管理页面目标选择是固定示例 tenant-a/b，服务端仍对每个目录请求做真实管理授权，未挂完整租户管理后台。

每个业务入口提供本人角色和 `/api/reports/:id`、`/api/reports`。详情先校验当前身份、精确业务权限，再按 `(tenant_id,report_id)` 取宿主报告；未授权的存在/不存在对象均403，仅授权后缺失404。列表逐候选授权过滤，最多检查40条，最多返回20条；空页也可能有继续游标，不提供总数。游标绑定用户、session、tenant、入口、业务、过滤条件及limit，HMAC认证、15分钟有效，服务重启后失效，应重新从首页开始。完整示例合同见 [api-contract.json](api-contract.json)，不改变 IdP API 合同。

身份/授权与业务读取是独立数据库操作，撤销影响之后的请求，不承诺已通过检查的在途读取与撤销线性化。生产更强一致性由宿主事务或版本屏障实现。

## 本地准备与运行

依赖现有 Rust、Node、pnpm 和本地 PostgreSQL。命令只加载本目录 `.env`，不加载根目录 `.env`。配置是可信 shell 文件，不应接受外部上传。所有示例 schema 必须以 `a05_` 开头且 IdP 与业务 schema 不同；仍应使用专用数据库/角色。

```sh
pnpm --dir web install --frozen-lockfile
./examples/tenant-host/run.sh init
# 编辑 examples/tenant-host/.env，设置专用本地 PostgreSQL URI
./examples/tenant-host/run.sh key-init
./examples/tenant-host/run.sh db-init
./examples/tenant-host/run.sh bootstrap-admin admin@example.test < /path/to/private/admin-password
./examples/tenant-host/run.sh prepare-clients
./examples/tenant-host/run.sh seed-fixtures admin@example.test < /path/to/private/fixture-passwords.json
./examples/tenant-host/run.sh serve
```

bootstrap-admin 的stdin是一行管理员密码。seed-fixtures 的stdin是严格 JSON，只有 `admin_password` 和 `fixture_password` 两个字符串字段；fixture密码用于 both@example.test 和 only-a@example.test，须12–128字符且满足现有密码规则。密码文件应权限0600，不提交、打印或放到命令行。这里不提供生产口令或固定默认口令。

默认打开 `http://127.0.0.1:9400/`。both@example.test 分别加入 tenant-a/b；only-a@example.test 只加入A。两租户的 r001 标题/内容不同，用户仅获 r001 与不存在的 missing 的实例读取权。其余 r000–r050用于验证列表过滤；缺失但未授权的 absent 为403，已授权 missing 为404。

管理client通过A01显式preparation；业务clients使用示例离线 insert-if-absent +完整定义比较事务，不覆盖已有冲突。注册元数据中的callback是client的有效配置占位；本示例未挂OIDC授权/code交换，不应把这些callback当作可用OAuth流程。

`db-init` 拒绝接管已有未标记业务schema；marker与报告表在同一业务事务创建，IdP初始化另用既有tenant_v6机制，两库不形成一个事务。bootstrap不重设已有管理员。seed-fixtures会拒绝已存在的目标租户，失败可能保留前面已成功的fixture步骤；请核对专用schema后显式处理，脚本不会自动清空、覆盖或恢复。在线 `serve` 只检查，不迁移或补数据。生产宿主不得调用fixture命令。

可设置 `TENANT_HOST_MANAGEMENT=false` 关闭管理UI/API；离线bootstrap和fixture准备仍使用独立管理身份。完整Web构建可独立运行 `./examples/tenant-host/run.sh build-web`，生成dist不会提交。

## React与无UI接入

示例使用仓库本地 React19 与 `@embedded-idp/react` 构建产物入口、单独 `/admin` 子入口（build-web先构建嵌入包）；包未发布npm。EmbeddedAuth复用原有Cookie协调、租户选择和本人角色；新增可选 `beforeSessionChange: () => boolean | Promise<boolean>`，在切租户/退出前确认宿主草稿，返回false不执行身份操作，默认行为兼容。它不拦截其他标签页或服务端导致的失效；凭据撤销不能被草稿阻止。

业务查询绑定入口/session与递增generation，切换后清除数据/游标，忽略旧响应和旧错误。草稿只在页面内存，不写报告。固定Cookie入口的多标签共享会话，不承诺各标签独立租户。权限目录使用独立管理client；更换目标时卸载旧目录状态。示例CSS使用th-前缀，嵌入组件沿用自己的CSS作用域；无全局管理页面样式导入。

无UI宿主可复用 `src/main.rs` 的普通auth/refresh/logout/self/browser装配与 `src/reports.rs` 的业务校验流程。私钥、生产TLS、连接池、业务写入、设备admission等必须由真实宿主提供；设备/扫码不是本基础示例的退出条件。

## 局部验证

```sh
cargo test --locked --offline -p embedded-idp-tenant-host
./examples/tenant-host/run.sh build-web
node scripts/check_tenant_host_contract.mjs
cargo build --locked --offline -p embedded-idp-tenant-host
# 先确认本机已有 postgres:18.6-bookworm 与 scripts/n2-ci 的锁定Playwright工具
node examples/tenant-host/tests/live.mjs --browser
```

live脚本创建专用Docker容器、随机本地端口和临时密钥，测试后清理，不读取用户.env。它使用合成身份验证真实服务、成员状态变化、列表和浏览器；不是完整验收或部署。macOS使用本机Chrome，其他平台使用已安装的Playwright Chromium；本机结果不代表Linux CI已执行。截图仅含示例公开信息，保存在 `/private/tmp/idp-a05-ui`。

[详细设计](../../docs/a05-technical-design.md) / [实施方案](../../docs/a05-implementation-plan.md) / [局部实施记录](../../docs/a05-implementation-result.md)。
