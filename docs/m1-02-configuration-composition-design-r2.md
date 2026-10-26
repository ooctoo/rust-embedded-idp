# M1-02 配置归一与共同装配契约设计

| 项目 | 内容 |
| --- | --- |
| 文档标识 | UP-M1-02-DESIGN，修订 2，2026 年 10 月 20 日 |
| 状态 | 可行性分析及建议契约，待设计审阅；不是已实现或已发布接口 |
| 主基线 | [M1-01 设计核对结果](m1-01-design-review-result.md)，重点为第 3–5、7 节 |
| 需求依据 | [UP-M1-01 修订 2](m1-01-compatibility-handoff.md)，保留 B01–B12、I01–I10 及 P/S/F/C/D/M 约束 |
| 当前源码 | 本地 `main`，`1835ec35790568fefb9f6792a120b3041cfe77ae`；软件 `3.0.0`，schema `tenant_v6`；本轮未刷新远端 |
| 工作区边界 | 修订前已有 README 修改、三份 M1-01 文档和本文修订 1；本轮仅修订本文，保留其他工作 |
| 执行范围 | 只读调查与设计文档；未改代码、测试、依赖或 schema，未运行构建、验收、数据库命令或部署 |
| 后续边界 | 未启动 M1-03–06；试点、真实域名、基础设施、Secret 供应和发布时间继续待定 |

## 1 可行性结论

**方案在当前架构下可行，建议沿用 M1-01 的 app 内归一与共同装配方向。**没有发现必须重建认证／授权模型、修改 `TenantLoginEntry`、扩展 store trait 或升级 `tenant_v6` 的前置条件。这里的“可行”来自源码与契约核对，不代表新配置或多入口已经能够运行。

支持此结论的事实：

1. Core 已按可信 `client_id`、`login_entry`、policy 和 purpose 构造认证服务，Axum 路由可以独立组合。集合循环应在 app，不进入 Core 的领域模型。
2. 旧 app 配置和 bootstrap 均为二进制内部模块，可以收敛成内部共同参数；下游直接使用 Core/Axum 的宿主不必采用新文件格式。
3. readiness、管理员 bootstrap、client／租户管理均可复用。引用核对还可复用 `TenantAuthStore::auth_transaction`、`TenantAuthTransaction::tenant` 和 `TenantOidcTransaction::oidc_client`，无需先增加查询 trait 或在 app 写新的查询 SQL。
4. BrowserSession 已接受可信外部 origin、Cookie 名和完整外部 Path；Web 已按 origin/path/purpose 协调。管理 Web 已读取 `idp-api-base`，需要补的是 app 随配置注入该值。
5. 仅管理启动的依赖可以闭合：数据库和管理员显式准备 → 管理 client 显式准备 → 空业务列表启动 → 平台 API 创建业务对象 → 配置引用并启用业务。

仍有四项必须区分的缺口：

| 缺口 | 对可行性的影响 | 所属后续工作 |
| --- | --- | --- |
| 当前 app 无新输入、集合校验或空业务装配 | 本文给出建议契约，仍需后续实现 | M1-02 配置实现与共同装配边界；实际多入口组合由 M1-04 承接 |
| 管理 client 尚无受限离线准备入口 | 不阻碍配置设计；阻碍全新实例完成正式 P1–P6 软件闭环 | M1-03；不能以启动 seed 代替 |
| 单 issuer 的 OIDC 与设备／扫码外部路径尚未验证多入口映射 | 普通登录／管理契约可以先审阅；新模式不得默默挂载这些尚未闭合的组合 | M1-04 在启用或影响相应能力前闭合 |
| 普通认证 router 未单独打包业务 token refresh/logout HTTP 面 | 现有 device adapter 支持普通刷新，resource adapter 已有退出；缺口是目标组合与路径的核对，不是领域能力缺失 | 后续业务装配明确复用范围；M1-04 承接组合验证，不能推导出永久拒绝非空集合，见第 5.4 节 |

旧参考模式继续承载原有 OIDC、设备、扫码组合及其兼容门槛。本文定义新配置的管理、普通业务 token／可选 Cookie 与可选既有注册面结构；建议 M1-02 后续实施先交付配置归一和仅管理装配，多入口运行证据由 M1-04 承接。这是实施阶段划分，不是 JSON v1 只能接受空集合的永久规则。具体构建未实现的组合必须明确拒绝，不能通过省掉刷新／退出接口勉强启动，也不能删掉旧模式已有能力或据此宣称整个 M1 可交付。

## 2 上下文、目标与范围

需求方希望多个产品共用账号与凭证，并让各产品成员、权限及会话独立。“一个产品一个租户”是实例配置选择；通用模块继续支持 Enabled + Fixed、Enabled + Choose、Disabled + Fixed 0。共享账号不自动加入产品，不提供跨产品 SSO。

M1-02 的目标是把“如何输入配置”和“如何构造同一组服务”分开，并明确启动时可做什么。本文定义：

- 旧环境变量与显式新输入到共同参数的映射及冲突规则。
- 稳定入口标识、client／用途／策略绑定和引用检查。
- 外部挂载、Cookie、前端 base path 的一致性及冲突处理。
- 空业务列表与仅管理启动。
- 旧参考补建、新模式只读启动、显式准备三者的边界。
- 后续实现需要证明的断言；本轮全部运行状态为未执行。

不建设第二套认证、租户选择、注册、权限目录、浏览器协调或初始化框架。不新增持久入口注册表、配置热更新、自动迁移、跨配置历史对账、匿名安装 API、SSO、MFA、完整托管 UI 或生产部署方案。

crate 边界保持：Core 管规则及服务契约；Axum 管薄 HTTP 适配；Postgres 管 SQL／存储；app 管环境、文件、服务组合和外层挂载。本文不创建新的可导入 app 库或要求其他宿主依赖 app。

## 3 输入契约与共同参数

### 3.1 建议输入方式

以下命令和字段是**拟定接口**，当前二进制尚不支持新命令参数。

| 输入方式 | 选择方式 | 行为 |
| --- | --- | --- |
| 旧参考输入 | 保留无参数启动及现有环境变量 | 原默认、原单业务入口、原管理入口、原补缺 client 行为 |
| 显式新输入 v1 | 建议 `embedded-idp-app --config <path>` | 单个严格 JSON 文件；归一后只读启动 |
| 现有管理员准备 | 保留 `bootstrap-admin` 原有契约 | 独立命令；按第 6.4 节由同一 JSON 映射命令专用临时环境；保留密码 stdin 和重复执行保护 |

不再同时增加 `CONFIG_FILE` 环境变量、多个文件合并、通用 `--set` 覆盖或第三种输入格式。JSON 复用现有 `serde_json`；若类型化反序列化需要 app 显式声明 workspace 已有的 `serde`，在后续实现中列出 manifest 差异，不引入新的配置框架。

输入处理顺序：

1. 解析启动方式，拒绝重复 `--config`、空路径、未知参数，以及 `bootstrap-admin --config ...` 等本阶段未定义组合。
2. 读取并严格解析选定输入的结构，尚不读取 Secret 值。显式文件缺失、不可读或解析失败均退出，**绝不回退旧 env**。文件要求 `version=1`；拒绝未知字段、重复 JSON key、错误类型及不允许的 null。不能先解析成会覆盖重复 key 的通用 map 再声称已拒绝重复字段。
3. 从已通过结构校验的字段收集合法 SecretRef 的来源名称，检查旧／新输入冲突；仅明确引用且满足第 3.2 节白名单的旧变量获得豁免。此时只检查变量是否存在，不读取其内容。
4. 完成策略、标识、路径、Cookie 和所需能力的静态校验，形成挂载计划；再解析所需 Secret、按 JSON 目录解析文件路径并加载密钥，归一为共同参数。
5. 前述检查全部成功后才访问数据库做 readiness 与启动引用核对；最后构造完整路由并监听。任何早期错误均不触发数据库操作，错误不会退回另一种来源。

### 3.2 冲突处理

**旧输入与新输入之间没有优先级。**新文件启用时，若进程中存在任何本阶段已识别的旧 app 配置变量，即使值相同或为空，也返回来源冲突；不按 env、文件或参数加载顺序取胜。

唯一例外是新文件明确指名的 Secret 环境引用。例如 `postgres.connection.uri_ref={"env":"EMBEDDED_IDP_APP_PG_URI"}` 可以消费该变量，此时它仅是这个字段的数据来源，不再执行旧配置解析。允许复用的旧 Secret 名限于 PG URI 和 SMTP password；其他旧变量不能借“引用”绕过排他规则。建议新实例使用独立的 Secret 名。

其他规则：

- 一个 SecretRef 只能指定一个 `env` 或 `file`；不得同时带明文、多个来源或 fallback。空值、缺失、无效编码一律失败，诊断不包含内容。文本文件按 UTF-8 原样读取，不 trim 或静默剥除换行；JSON 配置与文本 Secret 文件建议分别限制为 1 MiB／64 KiB，超限失败。签名密钥仍由原二进制密钥读取器处理，不走文本 SecretRef。
- `file` 相对路径相对于 JSON 所在目录；普通路径字段同样处理。旧环境中的相对路径继续相对于原进程工作目录，不偷偷改解析规则。
- 新模式不自动加载 `.env`，不执行 shell 展开，不插值 `${...}`。未被显式引用的任意环境变量不影响新配置；`EMBEDDED_IDP_APP_*` 的未知项也应报告为不支持的配置，避免拼写错误被吞掉。
- 旧脚本的 `.env` → `.env.<mode>` 覆盖是**既有旧模式内部规则**，继续保留，不属于本次拒绝的混合输入。app 只看到覆盖后的进程环境。
- `EMBEDDED_IDP_APP_ENV_FILE`、`EMBEDDED_IDP_COMMON_ENV_FILE` 是旧 shell loader 的控制项，不是新 JSON 数据源。新启动不能通过会注入旧模式配置的脚本暗中切换；后续若支持脚本新入口，应单独适配且不得自动 source 旧文件。
- 配置错误给出类别、字段路径和有关入口标识。可列冲突变量名，不打印原 JSON、连接串、密码、私钥、Secret 值／hash 或整份内部配置。

### 3.3 内部共同参数

建议在 app 内形成以下概念结构，名称可以在实现时调整；这不是新增公共 Rust struct。

| 内部部分 | 内容与责任 |
| --- | --- |
| `source` | 只由入口解析器产生 `LegacyReference` 或 `ExplicitV1`；配置文件不能自填或修改 |
| `runtime` | mode、监听、issuer、签名材料引用、typed Postgres／email、默认认证参数和 HTTP transport policy |
| `management` | 一个独立管理入口、挂载与可选 UI 配置；显式 v1 本阶段要求管理入口存在 |
| `business_entries` | 业务入口集合；显式 v1 必填，允许 `[]`，省略或 null 均报错；旧适配固定产生一个 |
| 每个入口 | `login_entry`、`client_id`、purpose、policy、证明要求、认证参数、适配器选择、外部挂载和 Cookie 范围 |
| `startup_effects` | 从 source 派生：旧模式携带原参考 client 补缺计划；显式模式固定无写计划 |
| 兼容扩展 | 旧单入口 OIDC、设备、可选 scan 的已有 typed 配置；不作为新模式任意扩展开关 |

共同装配器只消费已归一参数，不再读取环境、解析 JSON 或自行选择 tenant/client。同一逻辑入口的 token/browser 可分别构造原有服务以应用浏览器 TTL 限制，但共用同一可信绑定。路由、Cookie 和 Web 描述从同一个已验证挂载计划导出。

不创建一套“旧 app bootstrap”和另一套“新 app bootstrap”。输入适配和明确的 startup effects 可以不同，安全适配器、管理服务、普通业务服务和路由构造应复用。当前 `AppComposition` 的单个 scan cleanup handle 可留作旧兼容；未来多入口后台任务集合由 M1-04 决定，不在本轮设计通用任务平台。

### 3.4 显式 JSON v1 的建议字段

| 字段 | 必填／默认与校验 |
| --- | --- |
| `version` | 必填，整数 `1` |
| `runtime.tenancy_mode` | 必填，`enabled` 或 `disabled`，无请求级切换 |
| `runtime.bind_addr` | 必填，复用 SocketAddr 校验；不据此生成入口标识 |
| `runtime.issuer` | 必填，沿用 Core 支持与 JWT 配置校验；不从 Host／代理头或业务 mount 推导 |
| `runtime.signing_key_file` | 必填，引用已有密钥；不自动生成；保留既有 RSA 格式、强度和文件权限检查 |
| `runtime.postgres` | 必填；`connection.uri_ref/schema_name/tls_mode` 显式配置；CA 可选；pool 缺省值见附录。TLS 策略不从旧 env 偷渡 |
| `runtime.http` | 必填；`browser_origin` 显式；`transport_policy` 默认 `default`；开发 TTL 默认 900，仍受原有 feature/debug/范围及服务限制 |
| `runtime.auth` | 可省略，TTL／密码长度沿用附录数值；不包含 `allow_local_registration`，注册由入口显式选择 |
| `runtime.email` | 可省略；省略表示未配置发送 provider，若启用注册面则必须提供合法 typed email 配置；不自动选日志发送 |
| `management` | 必填单个对象；含 `login_entry/client_id/tenant_policy/mount_prefix/browser/ui`；管理 browser 必需；`ui` 可为 null，表示不挂页面 |
| `business_entries` | 必填数组，允许空或非空；每项含 `login_entry/client_id/tenant_policy/mount_prefix`；普通 token 路由由该业务入口承载；`browser` 默认 null；配置有效性与构建已支持的运行组合按第 5.4 节区分 |
| `tenant_policy` | 严格联合：`{"kind":"fixed","tenant_id":"..."}` 或 `{"kind":"choose"}`；Choose 不接受 tenant_id，Fixed 不隐式补 0 |
| `require_device_proof` | 默认 false；管理 true 保持既有明确拒绝；新业务 true 在证明适配映射闭合前报不支持，不静默挂普通免证明入口 |
| `browser` | 非空时为 `{"cookie_name":"..."}`；Path 与 purpose 不允许覆盖，由入口位置派生；保留原 BrowserSession 校验 |
| `ui` | 管理入口中可为 `{"base_path":"/..."}`；独立于管理 API mount；复用现有静态资源，不新增 UI 系统 |
| `registration_enabled` | 仅业务，默认 false；true 时需 email 配置及现有注册规则；Fixed 验证目标域匹配，Choose 沿用显式 tenant_id 与原策略校验，不擅自删除其能力；不能凭路由开关放宽数据库租户注册策略 |
| `oidc/device/scan` | 显式 v1 第一阶段不接收配置这些能力的字段；传入即报告不支持，不当作未知可忽略扩展。旧输入仍完整映射已有能力 |

purpose 由 `management`／`business_entries` 的位置分别确定，JSON 不接受另一个可冲突的 purpose 字段。入口中不配置成员、角色、业务权限目录、client_name、redirect URI 或 client secret；这些仍由显式准备／管理 API 和数据库维护。`business_id` 不从入口或 client 推导。

拟定的仅管理配置示意如下，值均为虚构标识；它不创建文件中引用的数据库、密钥、管理员或 client，也不代表当前可执行配置：

```json
{
  "version": 1,
  "runtime": {
    "tenancy_mode": "enabled",
    "bind_addr": "127.0.0.1:9100",
    "issuer": "https://idp.example.test",
    "signing_key_file": "secrets/signing-key.der",
    "postgres": {
      "connection": {
        "uri_ref": {"env": "IDP_DATABASE_URI"},
        "schema_name": "embedded_idp",
        "tls_mode": "require"
      }
    },
    "http": {"browser_origin": "https://idp.example.test"}
  },
  "management": {
    "login_entry": "management",
    "client_id": "idp-management",
    "tenant_policy": {"kind": "fixed", "tenant_id": "0"},
    "mount_prefix": "/api",
    "browser": {"cookie_name": "idp_management"},
    "ui": {"base_path": "/"}
  },
  "business_entries": []
}
```

启用产品 A 的例子是在已通过平台 API 准备对象后加入一项：`login_entry=product-a-web`、`client_id=product-a-web-client`、Fixed `tenant-a`、`mount_prefix=/products/a`、Cookie 名 `idp_product_a_web`。产品 A 的另一个独立客户端用另一项及另一 client；同一项的 token/browser 不另建 client。具体产品标识和部署值不在本文选定。

## 4 稳定绑定与引用核对

### 4.1 标识规则

`login_entry` 直接复用既有入口标识，不再增加平行的 `entry_id` 别名。显式 v1 要求所有管理／业务逻辑入口的 `login_entry` 唯一，沿用 Core 的标识语法和长度限制，不做大小写转换、trim 或自动补名。

以下均不能作为标识来源：数组下标、列表长度、端口、显示名称、tenant_id 的自动拼接、时间、随机数或配置文件路径。旧模式的 `business`、`management` 和已有 scan entry 值原样保留。

不同逻辑入口在显式 v1 中不得复用 client，即使 policy 相同；单个入口的 token/browser 是同一绑定的适配方式。旧 scan 使用同一业务 client 的受控子流程按原契约保留，不因新逻辑入口的唯一性规则破坏旧输入。

该唯一性是**当前 app 配置内的校验**。数据库没有入口注册表，也没有 client→purpose→tenant policy 的持久绑定。不能据此承诺不同进程／其他宿主之间的全局唯一性；共享 schema 的实例必须在运行配置审阅中保持一致绑定。新增注册表或跨进程控制器不属于本方案。

### 4.2 策略矩阵

| mode／purpose | Fixed 0 | Fixed 非 0 | Choose |
| --- | --- | --- | --- |
| Enabled／Business | 拒绝 | 允许；运行时验证租户、账号和成员当前资格 | 允许；列表和完成选择不授予平台 0 |
| Enabled／Management | 允许平台管理身份 | 保留现有管理身份规则 | 允许；不得通过 Choose 进入 0 |
| Disabled／Business | 允许 | 拒绝 | 拒绝 |
| Disabled／Management | 允许独立管理用途 | 拒绝 | 拒绝 |

先确定用途，再构造对应 Core 服务；不能对管理 Fixed 0 直接应用业务校验器。管理认证不等于目标租户授权，管理 API 继续逐操作检查权限。首次准备流程的管理入口采用 Fixed 0；其他合法管理策略继续保留，但不声称它们都能完成平台首次准备。

新模式沿用参考 app 的业务 audience `embedded-idp-business`／scope `openid profile email` 和管理 audience `embedded-idp-management`／scope `management`，由用途派生，不新增每入口可覆盖的 audience／scope DSL。issuer 和密钥是实例级可信参数。不同 client 之间的隔离仍由 Core 及实际资源服务验证，不能只靠共享 audience 的 JWT 签名有效就允许跨入口访问。

### 4.3 数据库引用检查

在监听前执行下列无数据修改的检查：

1. 沿用 mode/schema/version、可信 `PermissionCatalog` 与有效平台管理员 readiness。
2. 对全部引用 client 读取当前对象并运行已有 `OidcClient::validate`。显式 v1 的管理 client 限为已有 PublicDesktop／PKCE 类型，与 M1-03 最小 public 管理准备方向一致；业务 client 不改写既有 public/confidential 模型，使用当前有效对象。
3. 对 Fixed 引用验证 tenant 存在、标识合法且满足 mode/purpose；Choose 不枚举或固化所有业务租户，不要求预先存在至少一个业务租户。
4. 缺失、损坏或不兼容引用拒绝整次启动，不跳过入口、不换默认 client／tenant、不回退 Choose／Disabled。

建议 Fixed 租户的 suspended／archived 等**有效状态值本身不视为配置损坏**：停用是既有在线业务状态，认证由 Core 拒绝；启动不自动恢复状态，也不因停用一个产品而使管理恢复入口无法启动。不存在的引用仍必须拒绝。成员、角色、会话是否有效不预计算为入口 Allow；各请求继续核对当前状态。

只检查当前对象有效性和必要能力，不比较历史准备快照中的名称、回调集合，也不重写在线 client。读取到的 secret hash 只在既有类型校验所需的内存路径使用，不返回、记录或复制到装配摘要。client 类型是否合法不意味着普通密码登录已执行 OAuth client-secret 认证；不同协议继续使用各自既有规则。

最小实现可用既有认证事务：先排序去重锁 Fixed tenant，再读取 tenant，按稳定顺序读取 clients；不用账号／票据锁，不调用写方法，不伪造管理员上下文。现有事务会使用 `SELECT ... FOR SHARE` 并提交，因此本文“只读”指**不修改身份数据**，不承诺适配 PostgreSQL `READ ONLY` 事务或只读副本。

启动检查只证明检查时刻的状态。Read Committed 不构成全生命周期配置快照；之后的撤销／状态变更仍由原请求事务处理，不新增授权缓存。启动引用核对不放入每次 `/readyz`；两者的范围、锁和时限按下节区分，旧模式 readiness 不随新检查静默收紧。

#### 4.3.1 启动检查与运行探针分开

| 项目 | 启动引用核对 | `/readyz` |
| --- | --- | --- |
| 范围 | 原 readiness，加全部配置入口的 client／Fixed tenant 引用和结构合法性 | 沿用 `PostgresAccessStore::check_readiness`：schema、mode、bootstrap、内置管理目录和有效平台管理员 |
| 频率 | 每次启动、监听前执行一次；失败整次退出 | 沿用每请求检查，不按业务入口展开并行任务，不新增后台全量轮询 |
| 数据库行为 | 既有 auth transaction，按前述顺序加共享锁，结束即提交或回滚；只读语义是不改身份数据 | 原 `READ ONLY` 事务；不调用 auth transaction，不新增 tenant/client 的 `FOR SHARE` 行锁或读取 client secret hash |
| 结果含义 | 证明检查时的配置引用可用，不能保证后来没有状态变化 | 只证明基础 Access readiness；不等于每个入口或每个产品当前可以登录 |

保持既有 `200 {"status":"ready"}`／`503 {"status":"not_ready"}` 投影；数据库检查报错不能返回成功，也不能触发修复。启动后若引用缺失或账号／成员／租户状态变化，实际请求继续按原 Core 规则拒绝；下一次启动重新检查引用。若只有某个 client 引用异常，基础 `/readyz` 仍可能成功，不能把它当作逐入口状态检查或授权依据。

时限与并发边界必须如实交付：

- 现有 `connect_timeout_secs` 用于连接建立和池获取等待，**不等于 SQL、锁等待或整个 HTTP 探针的总时限**。当前 store 接口未提供本次调用的 `lock_timeout`／`statement_timeout` 参数，不声称复用现有接口即得到这些保证。
- 原 readiness 没有新增的业务行锁，但普通查询仍可能等待数据库或 schema 锁。不能把 `READ ONLY` 写成“永不阻塞”。本阶段通过不重复全入口引用锁检查避免新增放大，不借此重写库的超时策略。
- 同时持有的连接受既有 pool 上限约束；当前 HTTP 层没有专用探针并发门禁或端到端超时保证。不得把 `spawn_blocking` 外层超时或代理断开等同于底层 SQL 已取消，也不得超时后为同一请求无限重试。
- 真实运行前需按部署条件验证探针频率、并发、数据库语句／锁超时及阻塞任务释放；若要求严格总时限或独立取消，应另行明确最小实现与参数归属。M1-02 不新增探针调度平台，不宣称已有生产时限保障，部署仍待定。

### 4.4 稳定性与变更分类

| 操作 | 契约 |
| --- | --- |
| 入口重排、增删无关入口 | 原入口所有绑定及外部地址不变；不重新生成标识或影响其原有效凭证 |
| 同配置普通重启 | 同 DB／密钥／时钟语义；沿用原 TTL 和当前消费／撤销状态；不延寿、不重灌 |
| 改 login_entry/client/policy/purpose/issuer/密钥策略/mount/Cookie 范围 | 属于绑定或凭证兼容变更，不能伪称重排；需单独变更记录及旧凭证处置 |
| 删除入口或改入口名 | 不能承诺已有离线 JWT、所有 access session 立即失效；必须按原会话撤销与资源验证边界处理 |

M1 不提供原地自动迁移。建议绑定变化采用明确新逻辑入口及独立 client，并登记旧 session／refresh／selection／code／Cookie 的失效或重新登录安排。没有历史配置存储时，app 无法自动发现“这个名字昨天绑定了另一个租户”；当前文件的静态校验不能替代配置版本审阅。迁移到新格式也不自动保证凭证兼容，特别是旧 OIDC／设备／扫码必须先满足对应门槛。

## 5 挂载、Cookie 与前端一致性

### 5.1 路径模型

`mount_prefix` 是 app 可信外层前缀；局部根 `/auth`、`/devices`、`/admin`、`/oidc`、`/.well-known/openid-configuration` 不重写。显式 v1 用空字符串表示根挂载，拒绝 `/` 作为重复表示。非空值以 `/` 开头，每个段只能包含 ASCII 字母、数字、`_`、`-`、`.`；段不能恰为 `.` 或 `..`，无空段或尾斜线。这是本配置格式统一采用的适配器字符交集，token-only 入口也遵循，不因是否启用 Cookie 改变。

不得做 URL decode、trim 或自动修正。空格、非 ASCII、`+`、`%`、反斜线、`?`、`#`、`:`、`*` 等均拒绝；因此 `/team+one`、`/产品`、`/a%2Fb`、`/a//b`、`/a/../b` 非法，`/team_one/v1.2` 合法。最终派生 Path 仍须通过原 BrowserSession／已启用适配器的构造校验。管理前端对根路径使用不同字面表示，按第 5.3 节转换，不反向改变内部 mount。

UI `base_path` 沿用现有规范化和保留前缀限制，可取 `/`；规范化后再检查冲突。旧模式的路径规范化不变。新模式不支持代理剥除后再另填一个不一致的外部路径；如需代理，公开路径须与受信装配计划一致。更复杂 rewrite 拓扑留待另行契约。

| 入口 | 真实外部路径规则 |
| --- | --- |
| 业务 token／本人角色 | `mount_prefix + /auth/...`，本人角色保留显式 business_id |
| 业务 browser | `mount_prefix + /auth/browser/...` |
| 管理登录／管理 API | `management.mount_prefix + /admin/...` |
| 管理 browser | `management.mount_prefix + /admin/auth/browser/...` |
| 管理 UI／资源 | UI base 的精确首页／必要重定向，以及该 base 下 `/assets/*`；根 UI 不是整站兜底 |
| 健康 | 实例级 `/healthz`、`/readyz`，不按入口复制 |
| 旧 OIDC／设备／scan | 保留当前实际路径与 discovery；新前缀启用前由 M1-04 核对完整映射 |

app 在合并 Router 前生成内部“路径归属清单”。这只用于校验既有路由的装配，不建设通用路由 DSL，也不冒充 M1-05 的完整 OpenAPI 制品。

路径冲突规则：

- 按展开后的路由族归属判断，不只比较 mount 字符串是否相等。
- 不同入口的 `/auth` 子树、管理 `/admin` 子树等不能相等或按路径段形成祖先／后代覆盖；拒绝例如一个入口占有 `/products/a/auth`，另一个把前缀放进该子树。
- 健康端点、UI 精确首页／重定向与静态资源通配子树也参与检查。UI `/` 只占首页和 `/assets/*`，可以与 `/api/admin`、`/products/a/auth` 共存。
- 同一逻辑入口内部由既有 router 有意组合的 token/browser/registration 属于同一所有者，不作为跨入口冲突；仍检查最终 method/path 重复及实际 nest/merge 限制。
- 不允许以不同 HTTP method、配置顺序或更具体的路由覆盖来绕过跨入口归属冲突。发生冲突必须在监听前给出两个入口及冲突路径，不等待框架 panic。
- 与禁用能力对应的路径不挂载；向后启用某能力时必须重新展开并检查，不能假定今天无冲突就保证未来可用。

### 5.2 Cookie 与协调范围

Cookie Path 只从真实挂载派生：业务为 `<prefix>/auth/browser`，管理为 `<prefix>/admin/auth/browser`。不提供第二个手填 Path，也不从 `admin_ui_base_path` 推导认证路径。

1. 新模式 Cookie 名必须显式稳定，使用既有 BrowserSession 语法校验；不从端口、数组位置或显示名生成。不同逻辑入口在同一 Cookie 主机范围中不得同名，即使 Path 不同。
2. 不同入口的 Cookie Path 必须不同，且不得形成按路径段匹配的覆盖。不能依赖不同名字为路径重叠解围。
3. 校验 Cookie 主机范围时忽略端口，不能把 `https://host:9100` 与 `https://host:9200` 视为天然隔离。单份配置只能发现自身冲突，同主机上的其他部署须共同审阅命名和路径。
4. 沿用 host-only、HttpOnly、SameSite=Strict 和原 Secure／开发传输策略，不开放 Domain、任意 SameSite 或手动关闭 Secure 的新字段。默认 HTTPS／既有回环 HTTP 规则及显式私网开发门禁保持。
5. Web 的 origin/path/purpose 必须对应真实 browser endpoint。业务 token/custom transport 仍保留；每个 Cookie 入口只有一个当前浏览器会话，同入口多个标签不能各自独立选租户。
6. 退出／清 Cookie 必须使用同一名称和 Path；改变这些值需迁移安排，不能靠新 Cookie 退出清掉旧范围。Cookie Path 不是同源脚本的安全隔离边界。
7. 当前 browser 不支持 proof-required／设备绑定恢复。新模式拒绝 `browser != null` 与 `require_device_proof=true` 的组合，不能降级为免证明。

旧模式继续使用 `idp_{port}_business` 和 `idp_{port}_management`，路径分别为 `/auth/browser` 和 `/api/admin/auth/browser`；转换不重命名。原 HTTP 错误、重复 Cookie 拒绝、未知结果恢复和刷新重用检测保持。

### 5.3 管理页面接线

当前 `web/management/main.tsx` 已读取 `meta[name="idp-api-base"]`，但静态 HTML 中默认 `/api`，app 只动态注入 browser 模式描述。共同装配应从同一管理挂载计划生成两份非敏感页面描述，明确以下规则：

| 内部 `management.mount_prefix` | 页面 `idp-api-base` 的 content | 客户端最终 API／browser 路径 |
| --- | --- | --- |
| `""` | `/` | `/admin/...`、`/admin/auth/browser/...` |
| `/api` | `/api` | `/api/admin/...`、`/api/admin/auth/browser/...` |
| `/identity` | `/identity` | `/identity/admin/...`、`/identity/admin/auth/browser/...` |

`ManagementClient` 的输入要求同源绝对路径：空字符串会被拒绝，而 `/` 会在客户端内部归一为空前缀。因此页面根挂载必须注入 `/`；不能指望 `?? "/api"` 为显式空字符串兜底，也无需修改现有客户端公共构造器。

app 应**替换模板中原有的 `idp-api-base`，保证最终文档恰有一个**；不能仿照当前 browser meta 的追加方式再加第二个 API base。前端 `querySelector` 读取第一个匹配项，重复会继续选中旧 `/api`。受控模板缺失或重复目标 meta 应作为装配／资源错误被发现，不输出歧义页面。`idp-browser-config` 同样保持唯一并使用原安全 HTML 编码。

`BrowserSessionClientConfig` 只有 mode、期限及 restore/refresh 标志，不包含路径、origin 或 purpose，不能靠注入它传播 API mount。页面 API base 与 browser 描述均来自已验证装配；验收检查 DOM 实际选值、客户端实际请求、Cookie Path 和协调键，而不只是 HTML 中包含新字符串。

页面路径、静态资源路径、API base 和 browser Path 是不同用途的值：移动 UI 不自动移动 API；移动 API 必须同时更新页面注入、Cookie 和协调键。向页面只传非敏感配置，不传 Secret、连接串或可信授权决定。

### 5.4 现有业务能力与阶段交付边界

本轮补充核对的事实是：`tenant_auth_router` 提供普通登录、capabilities、session 和条件化选择／切换；`/auth/refresh` 位于 `tenant_device_auth_router`，`/auth/logout` 位于 `tenant_oidc_resource_router`。原 app 正是组合后两个 router，而非只挂普通认证 router。BrowserSession 另有自身的刷新／退出面；不能用它替代显式 token 客户端的契约。

还应同时保留另一半事实：`TenantDeviceAuthenticationService::refresh` 的 `proof=None` 分支直接调用普通 `rotate_refresh`；现有 HTTP adapter 能传入该无证明分支，原 Core 仍会拒绝需要证明的会话降级。resource router 已提供普通 logout。因此不能因源码文件名含 device／OIDC 就判断普通 token 生命周期不存在，或认为只有完整 discovery／授权码协议上线后才能复用这些能力。

契约和实施顺序分开：

- **配置契约：**`business_entries` 是允许非空的集合。解析器和共同参数不能把“非空”判为永久非法，也不增加与工作包编号绑定的配置开关。
- **阶段交付：**M1-02 后续实施可先交付解析、校验、共同装配边界和仅管理路径；具体构建尚未实现业务装配时，在监听及任何写操作前报告明确的不支持组合。此为该构建的暂时能力边界，不能成为 JSON v1 的长期规则或公共 Core 限制。
- **业务启用：**后续先决定既有 router 的完整复用范围。直接复用 device auth／OIDC resource router 会同时带入 challenge／userinfo／introspect／revoke 等路由，必须列明实际暴露面；不能声称只挂 refresh/logout。若确需最小拆分，先评估新公共出口及兼容影响，不复制认证、刷新或撤销逻辑。
- **验证归属：**完整业务组合需覆盖 login/session/refresh/logout、选择／切换、可选 browser，以及实际挂载关联面的外部路径和安全绑定。M1-04 承接多入口组合证据；其未启动不等于这些领域能力缺失，也不要求未来所有业务启用都携带工作包门禁。

新模式暂不接收完整 device／scan／OIDC 配置与是否内部复用已有 adapter 是不同问题。复用时新增的可观察路由不能静默暴露；在组合和验证范围明确前不交付残缺业务入口。本轮不选择拆分方案、不添加端点、不降低证明规则，也不启动 M1-04。

## 6 启动阶段与副作用边界

### 6.1 单套装配的阶段

| 阶段 | 旧参考模式 | 显式新模式 |
| --- | --- | --- |
| 输入归一和静态校验 | 保留旧解析、默认和错误边界；产生原单入口计划 | 严格新契约，完整集合和冲突检查 |
| 密钥及数据库前置 | 原 key、schema、mode、catalog、有效管理员检查 | 复用相同依赖，不初始化或迁移 |
| client 准备 | 按旧规则补缺 public、management 和可选 confidential client | **没有该阶段**；不得调用 seed 或 M1-03 准备能力 |
| 引用核对 | 不把新模式的严格比较偷偷加到旧 client 补缺语义上 | 对所有配置引用执行第 4.3 节检查 |
| 服务／路由构造 | 保留旧业务、管理及原可选能力 | 按当前构建已实现且验证过的组合构造；暂未支持的组合明确失败，不将非空集合写成永久非法 |
| 监听和后台任务 | 保持原有 scan cleanup 行为 | 全部通过后才监听；本阶段没有 scan，不启动其 cleanup |

新模式从入口解析到监听成功均不得新增、修改或删除身份数据，不补 client、tenant、管理员、成员、角色、PermissionCatalog、session、refresh 或初始化审计，不生成密钥。签名配置错误或引用冲突时没有半套已监听的路由。

“只读启动”不表示服务运行期只读：用户登录、刷新、管理 API 的合法操作仍按现有事务写库。未来显式启用的 scan cleanup 属运行期状态处理，不得在 startup 校验中暗中执行；其启用时机由相应工作包给证据。

### 6.2 旧参考补建精确语义

当前 `insert_client_if_missing` 是校验待插入对象后执行 `ON CONFLICT (client_id) DO NOTHING`：

- 缺失时插入参考 client；已有 ID 不覆盖其在线配置。
- **没有读取并比较现有对象**，因此“没有覆盖”不等于“与 seed 完全一致”。
- 多个 client 分开调用，不承诺整体原子：中途失败时前面的补建可能已完成。
- 不据此补管理员、迁移 schema、重设密码或恢复撤销凭证。

上述可观察行为保留在 LegacyReference；不能为了共同装配把它改成 M1-03 的创建／匹配／冲突三态，也不能给显式 JSON 增加 `legacy_seed=true` 来恢复隐式写入。若未来决定改变旧模式，需要单独兼容说明。

### 6.3 仅管理启动

`business_entries=[]` 是明确有效状态，不生成默认 `business`、`desktop-app` 或 Disabled 业务域入口。该状态只构造：

- 独立管理认证 token/browser、受管理身份保护的现有管理 API。
- 配置要求的管理 UI／资源。
- `/healthz` 与沿用基础 Access readiness 的 `/readyz`；管理引用在监听前核对，不随探针反复锁定。

不构造业务登录／本人角色／注册／设备／扫码／业务 OIDC，不发布指向不存在业务端点的 discovery，不自动挂 `/oidc/jwks`。管理 JWT 的签发和验证仍有正确密钥／issuer／audience，但这不要求对外宣告一个未实现的 OIDC provider。

没有业务入口时不额外要求业务 client、email provider、业务 Cookie 或 scan 密钥；管理安全与数据库前置仍必须满足。平台 Fixed 0 的仅管理启动不要求预先创建业务租户；若显式选择管理 Fixed 非 0，则仍须存在它所引用的租户，不能因为业务列表为空跳过引用检查。空列表在 Enabled／Disabled 均合法，管理矩阵保持。

### 6.4 显式准备的衔接

P1/P2 使用已有 Access 初始化及管理员 bootstrap，但**现有命令不会读取新 JSON**。本阶段选择命令专用临时环境映射衔接，不新增配置导出器、准备控制器或 `bootstrap-admin --config`。新模式普通启动也不启动任何准备子进程。下表是后续受控运维的参数契约，本轮不执行、不生成真实环境文件。

以同一版本 JSON 为唯一参数来源，先按第 3 节解释其缺省、SecretRef 和相对路径，再将下列有效值提供给相应命令；不得维护另一份长期 `.env` 作为第二配置源。表内旧变量均省略 `EMBEDDED_IDP_APP_`：

| 新配置有效值 | P1：现有示例的 `--access-schema` 分支 | P2：现有 `bootstrap-admin` |
| --- | --- | --- |
| `runtime.tenancy_mode` | 显式 `TENANCY_MODE` | 显式 `TENANCY_MODE` |
| `runtime.postgres.connection.uri_ref` 解析出的同一连接串 | 仅通过临时环境 `PG_URI`，不放命令参数 | 同左 |
| `runtime.postgres.connection.schema_name` | 显式 `PG_SCHEMA`，不允许 positional 参数另行覆盖 | 显式 `PG_SCHEMA` |
| `runtime.postgres.connection.tls_mode` | 显式规范小写 `PG_TLS_MODE`，不使用其默认 disable | 同值显式 `PG_TLS_MODE`，不使用 app 默认 prefer |
| `runtime.postgres.connection.tls_ca_cert_path` | 有值时转为基于 JSON 目录解析的绝对路径，设置 `PG_TLS_CA_CERT_PATH`；无值时移除继承项 | 同左 |
| `runtime.auth` 六个 TTL／密码长度有效值 | 不消费，不伪称影响 schema 初始化 | 逐项设置 `ACCESS_TOKEN_TTL_SECS`、`REFRESH_TOKEN_TTL_SECS`、`SESSION_TTL_SECS`、`VERIFICATION_CODE_TTL_SECS`、`PASSWORD_MIN_LENGTH`、`PASSWORD_MAX_LENGTH`；省略字段先按附录 A.2 展开 |
| 管理初始化的 AuthConfig 注册标志 | 不消费；不改变 Access 初始化中 Disabled 域 0 的既有默认 | 明确 `ALLOW_LOCAL_REGISTRATION=false`，不继承其他进程值；这不修改租户注册状态 |
| `runtime.postgres.pool` | 示例固定 app name=`embedded-idp-bootstrap`、max=4、connect timeout=5；不能冒称消费在线 pool 字段 | 映射 `PG_APP_NAME`、`PG_MAX_CONNECTIONS`、`PG_CONNECT_TIMEOUT_SECS` |

P1 的固定池参数属于现有离线工具限制，不改变目标或 TLS。若目标必须使用另一连接超时或容量，不能假装设置环境就有效，应停止并另行评审最小工具适配；本轮不改示例。P2 的配置映射仅复用其已有读取入口，不修改 password stdin、有效管理员重复保护及事务语义。

准备与启动的顺序和恢复边界：

1. 从同一 JSON 核对目标连接的主机／端口／database（隐去凭据）、schema、mode、显式 TLS 与 CA，以及 P2 密码策略和共同的可信 catalog。无明确目标、引用解析失败、参数遗漏或两步目标不一致时停止，不调用命令。连接串和 Secret 不打印、不写入报告、命令行或 shell 历史。
2. P1 只使用 `bootstrap_local_postgres --access-schema`，连接与 schema 走上述临时环境；不进入默认 legacy migrations/覆盖式 client seed，也不以 `--schema-only` 冒充 Access 初始化。参考 app 继续使用同一空宿主 PermissionCatalog；自定义目录宿主沿用自己的库接入。
3. P2 单独执行原管理员命令，密码仅走 stdin。P1/P2 不是总事务；中断后只对同一目标复用原重复执行规则，不自动重设密码、迁移或修复未知状态。
4. 临时环境只属于各准备命令的受控子进程；移除继承的无关 `EMBEDDED_IDP_APP_*` 项，不 source 会强制模式 schema 的旧 `load_dev_env.sh`。命令结束后销毁该环境，不向新模式启动进程继承。由此准备阶段使用旧变量与启动阶段拒绝混合输入不矛盾。
5. P4 使用原 JSON 和显式 Secret 来源启动；若仍带入非白名单准备变量，按来源冲突停止。监听前重新核对实际 schema/mode/version、管理员和管理 client；不以“准备命令执行过”代替当前状态检查。管理 client 缺失或不兼容时拒绝，不调用参考 seed 补齐；若引用已合法存在，不额外要求 P3 的历史执行标记。

本段只给出参数与操作衔接契约，不声称当前工具已能自动解析或比较新 JSON。未来若自动化此映射，必须复用同一解析规则、采用进程环境 API 传值，并单独记录交付；不得拼接含 Secret 的 shell 命令或把 JSON 当 shell 执行。

P3 只准备管理 public client，是 M1-03 的独立缺口。本文不定义 P3 命令名、审计新类型、并发写算法或存储 API，也不执行它。

未来 P3 的输入必须与新配置中管理 client_id 对应，但其“创建／相同／冲突”比较包含名称、类型、PKCE、redirect URI 等准备字段，不应把整份准备声明带进正常启动并覆盖数据库。P4 的正常启动只检查当前引用。P5 沿用平台 API 创建业务租户、client、成员和角色；P6 才加入入口引用。流程不要求通过尚不能登录的管理 API 自己创建首次管理 client。

## 7 兼容与交付影响

| 兼容面 | 本文建议 |
| --- | --- |
| 公共 Rust 接口 | 保留 TenantLoginEntry 字面量、Core 构造器、store traits、Axum routers 与自定义 provider 注入；不增加宿主必填配置 |
| app 内部 | 允许调整配置类型、bootstrap helper 和同仓源码包含式测试；不为私有结构建设长期兼容包装 |
| 外部输入 | 旧无参数/env 保留；新 JSON 是显式 opt-in。旧内部 overlay 与新旧混合来源分开 |
| HTTP／Web | 不增加请求可控 client/purpose/policy；保留 DTO、capabilities、错误、缓存头、body limit、租户头和 business_id 语义 |
| 数据与权限 | 保持 tenant_v6、动态业务权限、同 schema 宿主表及可信 PermissionCatalog；不复制目录，不恢复停用或撤销状态 |
| 凭证 | 稳定配置下保留入口绑定、密钥及原 TTL；成功 Choose 切换不自动注销仍有效来源会话 |
| 旧 OIDC／设备／scan | 旧配置路径保持，受共同装配重构影响时仍须回归；新组合待 M1-04 |
| 版本 | 当前无必须破坏公共契约或 schema 的证据；不预定发行版本或 tenant_v7。新增 CLI／文件字段属于可观察新增契约，发布前需记录 |

后续 M1-02 实现的合理文件范围是 app 配置解析、main 输入分派、bootstrap 共同参数与校验、管理 UI 的 base 注入，以及相关 app 测试和文档。引用读取优先使用既有 trait，SQL 仍留在 Postgres 适配器。若实现证明必须新增公共方法或改变 wire，先明确实际调用方和版本影响，不用“内部重构”掩盖。

## 8 验收断言设计

以下均为**待执行**，未写测试、未运行验收。优先使用 M1-01 第 6 节已定位的测试及夹具，不复制已有认证状态机测试；新增断言集中在配置、装配和副作用。

| 编号 | 输入／单一变化 | 必须观察的结果 | 复用及关联 |
| --- | --- | --- | --- |
| Q01 | 旧 env 分别 Enabled/Disabled，含缺省值和显式策略 | 归一后 business/management 名、client、policy、路径、audience、TTL、注册和扩展开关逐字段与旧基线相同 | app config、live_reference_host；B08、D/M |
| Q02 | 新配置与一个旧变量同时存在，含相同值／空值；分别显式引用白名单来源、未引用或引用非白名单旧变量 | 严格结构解析后再判冲突；仅合法显式白名单引用豁免；冲突时不读取 Secret 内容、不加载密钥、不访问 DB、不监听 | 新 app 配置负例；I03 |
| Q03 | 文件缺失、版本错误、重复 key、未知字段、错误类型、缺 business_entries 或 null | 明确失败，无旧模式 fallback；显式 `[]` 可继续 | 新 app 配置负例；P03 |
| Q04 | 缺／空 Secret、同时 env/file、坏密钥、非法 transport | 失败且不输出 Secret；私网 feature/debug/TTL 原门禁保留，不降级 | 既有配置与安全测试；P03 |
| Q05 | 每个 mode/purpose/policy 组合；另管理 proof=true | 符合第 4.2 节；管理 Fixed 0 例外保留，proof 明确拒绝 | Core management、app config；M01–M04、D02 |
| Q06 | 重复 login_entry；不同逻辑入口复用 client；同项 token/browser | 前两项拒绝；同项合法组合保留，不另造 client | 配置／Core 绑定；S01、C04 |
| Q07 | 一个 client 缺失／损坏，或一个 Fixed tenant 缺失 | 整次拒绝，不跳过入口／补建；其余有效记录不变 | 原事务及 app live；P03、P06 |
| Q08 | Fixed tenant 被合法停用；Choose 尚无业务租户 | 停用不被恢复，真实登录仍拒绝；Choose 不因零业务域被错误改成 Fixed；平台管理仍可用于准备 | 原认证状态测试、app；C/F、P01 |
| Q09 | 两个路由族重叠、UI/assets 冲突；逐项输入 `/team+one`、`/产品`、编码分隔符、空段、点段、尾斜线 | 在密钥／DB 操作前拒绝，非框架 panic；以 `""`、`/team_one/v1.2` 为合法对照；token-only 与 browser 使用相同前缀语法，派生 Path 通过原适配器校验 | config、admin_ui、app 路由组合；I05 |
| Q10 | 当前集合中同名异 Path、Path 覆盖；另审阅同主机跨端口部署 | 集合内冲突拒绝；合法名称／Path 成功。跨进程冲突须由运行配置清单发现，不能宣称单文件能自动检测；后续真实组合验证退出 A 不清 B | BrowserSession、Web 协调；S04 |
| Q11 | 管理 mount 分别为 `""`、`/api`、`/identity`，UI 独立移动；另给缺失／重复 API meta 的受控模板 | 根 mount 注入 `/`，其他原值；最终 API/browser meta 各恰一个；检查 querySelector 的实际 content、客户端成功构造、真实请求、Cookie Path、协调键；非默认 mount 不请求旧 `/api`；异常模板明确失败，无追加第二个 meta | management Web、admin_ui；I06 |
| Q12 | 空业务列表，管理前置齐备；分别去掉管理员／管理 client | 齐备时仅第 6.3 节路由存在；缺失时拒绝。无业务对象、discovery、默认业务 Cookie 或后台任务被创建 | app live、readiness；P01/P03 |
| Q13 | 新模式成功／失败启动及 readyz 前后比较数据库 | 身份配置、会话、刷新、目录与审计均无启动／探针写入；宿主表不变；显式准备未被调用；probe 仅检查第 4.3.1 节范围 | live_reference_host、bootstrap；P02/P06/D04 |
| Q14 | 旧模式缺 client、已有同 ID 但在线配置不同 | 只补缺，不覆盖、不要求与 seed 相等；保持原部分补建失败边界，不能误称 P3 匹配 | 原 app client seed；B08/I04 |
| Q15 | 入口重排／增删无关项／同配置重启 | 原有效 token/refresh/selection 及适用 code 依原 TTL 可用；已消费／撤销不复活；旧 scan 标识不变 | 现有 Core／PG + 后续组合；S01/S02 |
| Q16 | client/entry/policy/purpose/issuer/path 单项变化 | 按具体产物断言不匹配拒绝或明确迁移要求；不宣称改名能撤销全部 session/JWT | M1-01 S03、C04 逐字段方法 |
| Q17 | 新模式请求尚未支持的 OIDC/device/scan 或 proof-required；旧模式启用既有组合 | 新模式明确不支持，无静默丢配置；旧组合保持兼容，不能把负例当旧能力删除依据 | 旧 app、device/scan/OIDC；I07 |
| Q18 | 旧独立嵌入宿主，含自定义 provider/token/transport/catalog | 无新配置文件、中央服务或数据库要求；原本人角色与真实资源授权边界保持 | no-tenant-host、Core/Axum/Web；D01/D04/B11/B12 |
| Q19 | 合法非空集合；分别对照尚未实现和已实现相应组合的构建 | 解析／归一不因非空永久失败；不支持的构建在监听和任何写入前明确拒绝，已实现的构建按完整路由与安全校验启用，不再受“只能为空”分支阻挡；组合证据涵盖普通无证明刷新、证明会话不得降级、logout 及实际带入的其他端点 | 原 device service／resource router、后续组合；第 5.4 节 |
| Q20 | 从同一 JSON 投影 P1/P2 参数，含非默认 schema、enabled、TLS=require、自定义 CA、不同密码长度及 env/file SecretRef | 目标、TLS/CA、mode 与密码策略逐项一致；相对 CA 转绝对；缺失／不一致时不调用工具；P1 固定 pool 的限制显式可见，不能依赖不存在的 env 覆盖；无 Secret 输出或命令参数 | 既有 Access 初始化示例、administrator_init；第 6.4 节 |
| Q21 | 准备子进程结束后启动新模式；另注入残留非白名单旧变量、错误 P1 分支或不一致目标 | 干净启动只消费 JSON 与声明的 Secret；残留配置按冲突拒绝；准备流程禁止 legacy seed／schema-only 代替 Access 初始化；P1/P2 重试不重设密码，管理 client 缺失不启动 seed，合法已有 client 不要求 P3 历史标记；全过程不是总事务 | 既有 loader／bootstrap 测试与后续衔接；P02/P03 |
| Q22 | 正常／并发 readyz，另以隔离夹具移除被引用 client、使基础 readiness 失败或模拟数据库等待 | 不按入口扇出，不调用带行锁的引用扫描或读取 client hash；client 缺失时基础 readiness 可成功，但真实认证请求／重启各按原状态与引用规则拒绝；基础失败返回原 503，检查无数据写入；连接占用不突破原 pool，不能把获取超时当成查询取消或以超时后重试放大请求 | 现有 readonly readiness、app HTTP、后续实库故障证据；第 4.3.1 节 |

Q01–Q14 及 Q19–Q22 的纯配置／参数／范围断言属于 M1-02 设计与后续最小实施门槛。Q19 的真实业务生命周期、Q20/Q21 的实际准备重试和完整 P1–P6、Q22 的实库等待及运行容量只在相应阶段执行；既有准备工具的用例可以复用，不因本文而实现新 P3。Q15–Q18 按受影响范围回归，多入口、多标签及协议组合由 M1-04/06 承接。所有行仍为待执行，不因列入本文就启动工作包。纯配置、真实 HTTP、隔离 Postgres、真实浏览器及设备／部署证据分别记录。

本轮设计文档核对仅检查：每项需求有契约位置、来源事实与建议分开、没有引用不存在的“已实现接口”、没有暗中加入后续工作。运行验收结论保持未执行。

## 9 待定项与进入实现的条件

| 项目 | 当前建议／待定内容 | 是否阻碍本轮可行性结论 |
| --- | --- | --- |
| 配置契约审阅 | 审阅 `--config`、JSON v1、互斥输入、SecretRef、默认及支持范围；采纳后再作为实现契约 | 不阻碍；当前仍为建议，不能当作已发布 |
| P1/P2 参数衔接 | 第 6.4 节选用同源 JSON 的命令专用临时环境；现有工具不自动读 JSON，P1 固定 pool 限制明确保留 | 设计参数链路已明确；实际执行和任何自动化另行交付 |
| 新模式引用状态规则 | 建议拒绝不存在／损坏引用，合法停用留给运行时拒绝，保留管理恢复入口 | 不阻碍；这是本文明确的运维行为选择 |
| 管理 client 准备 | M1-03 冻结命令、比较规范、并发、审计和最小存储落点 | 阻碍全新实例闭环，不阻碍 M1-02 设计 |
| OIDC 映射 | M1-04 核对 issuer/discovery/authorize/token/resource/client 分派，及旧 code/refresh | 阻碍新模式 OIDC 启用；不能直接复制全局 discovery |
| 普通业务 token 生命周期 | 普通刷新／退出能力已存在；后续明确完整复用面或最小拆分，公共出口变化另评估 | 未实现组合的构建不能启用；不是 JSON 非空集合永久非法，也不是缺少领域能力 |
| 探针运行保障 | 复用基础 readiness，不重复启动引用扫描；现有池获取超时不保证 SQL／HTTP 总时限，真实运行前验证等待、频率和并发 | M1-02 不新增全入口锁扫描；严格总时限／取消能力不假称已具备，部署继续待定 |
| 设备与 scan | M1-04 核对真实外部 method/path、audience、可信 provider、entry/host_scope、cleanup 归属 | 阻碍对应新组合启用；旧模式契约继续保留 |
| OpenAPI | M1-05 冻结工具、制品与漂移检查；本文件路径归属清单不能代替 | 不阻碍配置设计 |
| 跨进程／历史变更 | 无持久注册表；由版本化配置审阅保证一致性和凭证处置；将来若需要自动化另提需求 | 不阻碍当前静态装配 |
| 版本／公共 API | 如后续出现实际公共接口变化，单独给证据、版本和迁移；当前不预设 | 不阻碍 |
| 试点与部署 | 产品、加入方式、域名、数据库、Secret、代理／副本、SLO/RPO/RTO、发布窗口继续待定 | 不作为本轮设计缺项，不据此承诺上线 |

建议审阅通过后，仅另行授权 M1-02 的配置归一与最小共同装配实现；M1-03–06 依各自范围推进。本文的可行性结论和文档交付不构成代码实施、运行验收或部署授权。

## 10 修订 2 审查闭合与完整核对

“闭合”指设计文本已补正，不表示实现或运行通过。

| 审查项 | 本次修订位置 | 对应断言 |
| --- | --- | --- |
| 新 JSON 与 P1/P2 参数断链 | 第 3.1、6.4 节：单一来源、完整映射、显式 TLS/CA、固定工具限制、命令环境隔离与目标核对 | Q20、Q21，复用 P02/P03 |
| 根挂载与前端空串不兼容 | 第 5.3 节：内部 `""` → 页面 `/`，客户端自行归一 | Q11 |
| API base 重复 meta | 第 5.3 节：替换原项并保证唯一，检查实际 DOM 取值和请求 | Q11 |
| 冲突判断与 SecretRef 例外顺序矛盾 | 第 3.1–3.2 节：先严格解析结构／收集引用，再判冲突，最后读取 Secret | Q02、Q03、Q04 |
| mount 字符范围不完整 | 第 5.1 节：统一 ASCII 段规则、非法实例、最终适配器校验 | Q09 |
| 非空集合阶段限制被当作能力缺口 | 第 1、3.4、5.4、6.1、9 节：普通刷新／退出已有，配置有效性、构建支持与组合证据分开 | Q17、Q19 |
| readyz 重复锁定全入口与时限误解 | 第 4.3.1、6.3、9 节：保持基础只读探针，明确不检查的内容、无新增行锁、现有超时与并发限制 | Q13、Q22 |

完整核对覆盖 M1-01 的 B01–B12／I01–I10、管理策略矩阵和 P/S 边界，及本文输入、字段表、示例、默认映射、装配阶段、验收表和待定项之间的一致性。修订保留旧参考默认／补缺语义、独立嵌入能力、业务权限命名空间及已有 provider 注入；未新增持久入口表、认证模型、schema 或永久业务禁用规则。

本轮只做源码静态对照、修订前后文本差异审阅、文档链接／示例／编号检查。56 项旧变量映射和可观察常量仍完整保留；新增 Q20–Q22，调整 Q02/Q09/Q11/Q13/Q19。全部运行断言保持未执行。P3 准备能力、后续业务路由组合、OpenAPI、真实探针运行预算及部署仍按第 9 节单独交付；它们不由本次文档核对冒充完成。

## 附录 A：旧环境变量的完整映射

本附录依据当前 `crates/embedded-idp-app/src/config.rs`，变量均带 `EMBEDDED_IDP_APP_` 前缀；表内省略该前缀。默认值仅描述旧 parser，不等于 `dev_env.sh` 生成的模式文件取值。新模式的安全标识、路径、数据库连接与 TLS 必须按第 3.4 节显式设置；其余注明沿用的数值才作为新默认。

### A.1 实例与数据库

| 旧变量后缀 | 旧缺省／规则 | 共同参数及新字段 |
| --- | --- | --- |
| `TENANCY_MODE` | `disabled`；仅接受 enabled/disabled | `runtime.tenancy_mode`；新必填 |
| `BIND_ADDR` | `127.0.0.1:9100` | `runtime.bind_addr`；新必填 |
| `BROWSER_ORIGIN` | `http://{bind_addr}`，仍需原校验 | `runtime.http.browser_origin`；新必填，不自动推导 |
| `HTTP_TRANSPORT_POLICY` | `default`；另有显式开发值 | `runtime.http.transport_policy`；新沿用枚举与默认 |
| `DEVELOPMENT_SESSION_TTL_SECS` | `900`，60–3600；仅在受限 browser 生效 | `runtime.http.development_session_ttl_secs` |
| `ISSUER` | `http://{bind_addr}` | `runtime.issuer`；新必填，不能随前缀改值 |
| `SIGNING_KEY_FILE` | `.local/idp-signing-key.der` | `runtime.signing_key_file`；新必填，不生成 |
| `PG_URI` | `postgres://127.0.0.1:5432/postgres` | 旧解析为原 connection_uri；新 `runtime.postgres.connection.uri_ref` |
| `PG_SCHEMA` | `embedded_idp` | `runtime.postgres.connection.schema_name`；新必填 |
| `PG_TLS_MODE` | `prefer`；接受原大小写形式 | `runtime.postgres.connection.tls_mode`；新必填 lower-case enum，不自动降级 |
| `PG_TLS_CA_CERT_PATH` | 无 | `runtime.postgres.connection.tls_ca_cert_path` |
| `PG_APP_NAME` | `embedded-idp-app` | `runtime.postgres.pool.application_name` |
| `PG_MAX_CONNECTIONS` | `10` | `runtime.postgres.pool.max_connections` |
| `PG_CONNECT_TIMEOUT_SECS` | `5` | `runtime.postgres.pool.connect_timeout_secs` |

新 pool 整体或字段省略时沿用上述非敏感数值／名称默认。新枚举使用规范小写值；不修改旧 parser 的 bool／枚举别名或错误行为。

### A.2 认证、策略与旧入口常量

| 旧变量后缀／常量 | 旧缺省／规则 | 归一规则 |
| --- | --- | --- |
| `LOGIN_POLICY` + `LOGIN_TENANT_ID` | Enabled 默认 choose；Disabled 默认 fixed 0；Enabled fixed 非管理必须显式 tenant；choose 不能同时有 tenant | 旧 `business_entries[0].tenant_policy`；新每项必填，无省略策略 |
| `MANAGEMENT_LOGIN_POLICY` + `MANAGEMENT_TENANT_ID` | 默认 fixed 0；保留管理例外 | `management.tenant_policy`；新必填 |
| `ALLOW_LOCAL_REGISTRATION` | `true`；原参考注册 router 仍装配，Core 决定能否注册 | 旧业务 AuthConfig 原样；新业务 `registration_enabled` 默认 false，未启用则不挂面，启用时映射该入口 AuthConfig 且复用原 Core 与租户开关 |
| `ACCESS_TOKEN_TTL_SECS` | `900` | `runtime.auth.access_token_ttl_secs` |
| `REFRESH_TOKEN_TTL_SECS` | `86400` | `runtime.auth.refresh_token_ttl_secs` |
| `SESSION_TTL_SECS` | `604800` | `runtime.auth.session_ttl_secs` |
| `VERIFICATION_CODE_TTL_SECS` | `900` | `runtime.auth.verification_code_ttl_secs` |
| `PASSWORD_MIN_LENGTH` / `PASSWORD_MAX_LENGTH` | `8` / `128` | `runtime.auth.password_min_length/password_max_length` |
| `ADMIN_UI_BASE_PATH` | `/`；现有规范化 | `management.ui.base_path`，只控制 UI |
| 业务 `login_entry` 常量 | `business` | 旧原样；新显式 login_entry |
| 管理 `login_entry/client_id` 常量 | `management` / `idp-management` | 旧原样；新分别显式引用，不强制所有实例使用这些名字 |
| 原挂载常量 | 业务根；管理 `/api` | 旧原样；新显式 mount_prefix |
| 原 Cookie 常量 | `idp_{port}_business/management` | 旧原样；新显式 name + 派生 Path |
| 原 audience／scope | 业务与管理各自常量 | 用途派生，见第 4.2 节；不由 client 或数组位置生成 |
| 原证明要求 | 普通业务/管理 false；scan 目标服务 true | 旧原样；新普通能力按第 3.4 节拒绝尚未支持的证明配置 |

新 `runtime.auth` 的六个 TTL／长度字段省略时采用表中默认，并继续校验 refresh > access、session ≥ refresh 等原有关系。管理 AuthConfig 不通过新配置开启注册。私网 browser 的服务与签发器继续使用独立受限期限，不全局缩短设备／token 服务配置。

### A.3 参考 client 补缺

本表仅描述 app 的旧配置解析与补缺常量，不描述 `bootstrap_local_postgres` 的独立 legacy 分支。该分支另有硬编码回调 `http://127.0.0.1:49152/callback` 和覆盖式 client seed，不能视为本表默认或新 P1；第 6.4 节明确只复用其 `--access-schema` 分支。

| 旧变量后缀／常量 | 旧缺省／规则 | 归一规则 |
| --- | --- | --- |
| `PUBLIC_CLIENT_ID` | `desktop-app` | 旧业务 client 绑定及 startup 补缺对象；新仅有 client_id 引用 |
| `PUBLIC_CLIENT_NAME` | `Embedded IdP Desktop App` | 只进入 LegacyReference 补缺计划 |
| `PUBLIC_REDIRECT_URI` | `http://127.0.0.1:43821/callback` | 同上，PublicDesktop／PKCE=true |
| `CONFIDENTIAL_CLIENT_ID` + `CONFIDENTIAL_CLIENT_SECRET` | 同时有或同时无，半组拒绝 | 原可选 confidential 补缺计划；**不自动形成第二业务登录入口** |
| `CONFIDENTIAL_CLIENT_NAME` | `Embedded IdP Web App` | 旧补缺名称 |
| `CONFIDENTIAL_REDIRECT_URI` | `https://example.com/callback` | 旧补缺回调；ConfidentialWeb／PKCE=false，secret 按原方式 hash |
| 管理 seed 常量 | `idp-management`；`IdP management console`；`http://127.0.0.1/management-callback` | 原 PublicDesktop／PKCE=true 补缺计划 |

新模式没有这些 seed 配置字段，也不接收 confidential secret 来补建对象。当前 OidcClient 类型对 public／confidential 的回调和 PKCE 有既定校验；不得把新 browser_origin 当作新 public redirect URI 自动写入数据库。

### A.4 邮件

旧字段映射到共同 typed `email`；新配置为 `runtime.email`。新模式只有显式配置时才使用该 provider；其中 SMTP password 采用 SecretRef，不能内联明文。

| 旧变量后缀 | 旧缺省 | 新 email 内部字段 |
| --- | --- | --- |
| `EMAIL_DELIVERY_MODE` | `log` | `mode`；新对象出现时必须显式选 log/sendmail/smtp |
| `EMAIL_SENDMAIL_COMMAND` | `/usr/sbin/sendmail` | `sendmail_command` |
| `EMAIL_SMTP_HOST` | `localhost` | `smtp.host` |
| `EMAIL_SMTP_PORT` | `587` | `smtp.port` |
| `EMAIL_SMTP_TLS_MODE` | `starttls` | `smtp.tls_mode` |
| `EMAIL_SMTP_USERNAME` | 无 | `smtp.username` |
| `EMAIL_SMTP_PASSWORD` | 无 | `smtp.password_ref`，旧适配仍接受原 env |
| `EMAIL_FROM` | `embedded-idp@localhost.localdomain` | `from_email` |
| `EMAIL_FROM_NAME` | 无 | `from_name` |
| `EMAIL_VERIFICATION_SUBJECT` | `Your embedded IDP verification code` | `subject` |

新 email 显式选定 mode 后，非 Secret 字段沿用表中缺省并经过已有 provider 校验；选 log 是显式开发选择，不代表生产邮件接入完成。邮件仍是验证码及到期时间，不变为验证链接。

### A.5 OIDC、设备和 scan 兼容扩展

以下值在旧模式中完整保留到共同参数的兼容扩展；显式 v1 第一阶段不开放其配置字段。拒绝新配置启用不代表删除库能力，也不允许旧模式将已启用值忽略。

| 旧变量后缀 | 旧缺省／约束 | 共同参数目的 |
| --- | --- | --- |
| `AUTHORIZATION_CODE_TTL_SECS` | `300` | 原 OidcConfig |
| `REQUIRE_PKCE_FOR_PUBLIC_CLIENTS` | `true` | 原 OidcConfig |
| `DEVICE_NONCE_TTL_SECS` | `300` | 原 DeviceConfig |
| `DEVICE_PROOF_CLOCK_SKEW_SECS` | `30` | 原 DeviceConfig |
| `DEVICE_HEARTBEAT_GRACE_PERIOD_SECS` | `60` | 原 DeviceConfig |
| `ALLOW_DEVICE_PROVISIONING` | `false` | 原参考 DeviceAdmission，不变成生产业务准入 |
| `SCAN_LOGIN_ENABLED` | `false` | 原可选 scan；false 时仍按原逻辑不消费其他 scan 字段 |
| `SCAN_LOGIN_ENTRY_ID` | 启用时必填 | 原 ScanLoginEntryConfig.entry_id，不能改为数组编号 |
| `SCAN_LOGIN_ALLOWED_SOURCE_CLIENT_IDS` | 启用时必填；原逗号拆分；只允许当前 public client | 原来源允许关系，不放宽跨 client |
| `SCAN_LOGIN_MODES` | 启用时必填，原三种合法字串 | 原 modes |
| `SCAN_LOGIN_VERIFICATION_URI` | 启用时必填，同源绝对路径，无 query/fragment | 原扫码页面及 device HTTP binding |
| `SCAN_LOGIN_RESULT_KEY_ID` | 启用时必填 | 原结果加密 key ID |
| `SCAN_LOGIN_RESULT_KEY_BASE64URL` | 启用时必填，规范无填充 base64url 32 字节 | 原结果密钥，不生成、不打印 |
| scan 隐含参数 | target=public client、policy=业务 policy、host_scope=`reference-host`、target_scope=None、默认 limits | 原样保留，新的跨入口值留给 M1-04 |

## 附录 B：本轮源码证据入口

这些链接是只读核对位置，不是运行通过证明：

- [app config](../crates/embedded-idp-app/src/config.rs)：旧变量、默认、策略、Cookie 与 scan 解析。
- [app bootstrap](../crates/embedded-idp-app/src/bootstrap.rs)：固定 entry/client/audience、readiness、参考补缺、单业务装配、discovery 和 cleanup handle。
- [app main](../crates/embedded-idp-app/src/main.rs)、[开发配置 loader](../scripts/load_dev_env.sh)：旧启动／命令分派、环境覆盖和后台任务时机。
- [管理员准备](../crates/embedded-idp-app/src/administrator_init.rs)、[Access 初始化示例](../crates/embedded-idp-storage-postgres/examples/bootstrap_local_postgres.rs)：只消费旧变量的 P1/P2 输入、Access 分支、TLS 默认差异及固定 pool 限制。
- [认证契约](../crates/embedded-idp-core/src/access/authentication.rs)、[管理认证](../crates/embedded-idp-core/src/access/authentication/management.rs)：用途矩阵、稳定绑定和既有 transaction 接口。
- [OIDC transaction](../crates/embedded-idp-core/src/access/authentication/oidc.rs)、[Postgres 实现](../crates/embedded-idp-storage-postgres/src/access/oidc.rs)、[认证事务实现](../crates/embedded-idp-storage-postgres/src/access/authentication.rs)：当前 client／tenant 读取与锁／提交边界。
- [基础 readiness](../crates/embedded-idp-storage-postgres/src/access/admin.rs)、[连接池适配](../crates/embedded-idp-storage-postgres/src/adapter.rs)：只读探针范围与连接获取超时，区别于全入口引用行锁和 SQL 总时限。
- [device transport](../crates/embedded-idp-core/src/access/authentication/device_transport.rs)、[device auth router](../crates/embedded-idp-axum/src/tenant_device_auth.rs)、[OIDC resource router](../crates/embedded-idp-axum/src/tenant_oidc_resource.rs)：已存在的普通无证明刷新、退出及整体 router 附带路由。
- [BrowserSession HTTP](../crates/embedded-idp-axum/src/browser_session.rs)、[浏览器会话设计](browser-session-design.md)、[私网开发契约](development-private-http.md)：Cookie、purpose、外部 Path 与受限服务。
- [管理页面装配](../crates/embedded-idp-app/src/admin_ui.rs)、[管理 Web 入口](../web/management/main.tsx)、[Web 协调](../web/embedded/browser-session.ts)：静态资源、API base 注入缺口及已有协调键。
- [生产安全要求](rust-embedded-idp-production-security-delivery-v2.md)、[当前扫码设计](device-scan-login-design-v1.md)：可信绑定、证明用途与宿主准入边界。
