# 租户内业务标识与业务管理员：技术设计 v1

日期：2026-09-27。状态：**2.0 实施契约**；实现与验证状态见[交付与验收](tenant-access-execution-plan.md)。

代码基线：`origin/main`，`ea719ec0f9cd7024748048ba2a687da02683b658`。工作分支：`codex/business-domain-design`。

本文落实本轮确认的业务标识、业务管理员和 IDP 管理角色命名要求。租户认证背景见[租户权限设计](tenant-role-permission-design-v1.md)。下文列出的授权结构和接口替代旧契约；认证、设备证明等未涉及部分继续执行现有契约。

## 1. 目标与确定的边界

1. 授权层级为 `tenant_id → business_id → resource_type → action / resource_id`。
2. 同一租户下可以存在多个业务标识；同名资源类型和动作在不同业务中完全独立。
3. 每个 `(tenant_id, business_id)` 最多有一个 `key=business_admin`、`kind=business_admin` 的角色。名称由调用方指定，省略时使用“业务管理员”。可以有多个用户持有该角色。
4. 宿主按需要通过经过管理授权的 Core/HTTP 接口创建角色；创建租户或启动服务不自动创建业务管理员，不自动给现有用户授权。
5. 用户直接绑定业务管理员后，拥有该业务所有**已登记、启用、未归档**的业务权限，覆盖全部资源实例及后来新增的资源类型和动作。无需权限关联或逐资源分配。
6. 普通角色仍按权限集和资源范围授权，但角色、权限、分配、查询必须属于同一租户和业务。
7. 业务管理员不获得 IDP 管理权限。账号、租户、成员关系和角色状态仍然参与校验，业务对象状态与实际归属仍由宿主检查。
8. 无租户模式使用 `tenant_id=0`，也支持多个业务；有租户模式业务数据只在真实租户，`0` 仍是平台管理域。
9. 本次只调整 IDP 及仓库自带客户端、参考服务和示例，不修改外部业务系统。

### 1.1 最小设计选择

- `business_id` 是权限命名空间，不是新的组织、租户、工厂实体，也不是 OIDC `client_id`。
- 本期不增加业务注册表、业务审批、业务成员表、业务管理员专属登录、业务令牌或全局“当前业务”会话状态。
- 创建权限或角色即可使用一个业务标识；即使当前没有任何权限，也可以先创建管理员角色，此时不能通过任何业务权限检查。
- 不增加通配符、角色继承、显式 deny、策略语言、授权缓存或额外服务。全权是受保护角色类型的固定规则。
- 业务归属不可在线移动。更换标识需显式重新创建和授权，或另行执行经过审核的数据迁移。

## 2. 实施前基线与调整位置

| 实施前基线 | 代码位置 | 本次变化 |
| --- | --- | --- |
| 权限键为资源类型与动作，外层只有租户 | `access/query.rs`、`access/model.rs` | 权限键和查询增加业务标识 |
| `RoleKind` 仅三种，普通角色创建固定为 Business | `access/model.rs`、`access/admin.rs` | 增加 BusinessAdmin 与专用创建命令 |
| 角色键在租户内唯一 | `sql/tenant_v2.sql` | 改为租户、业务、角色键联合唯一 |
| 所有非 business 类型每租户只能有一个 | `access_protected_role_unique` | IDP 角色按租户唯一，业务管理员按租户和业务唯一 |
| binding 必须具有 resource_type | `RoleBinding`、`access_role_bindings` | 增加明确的业务级分配形态 |
| GrantRole 依赖角色已关联该类型的权限 | `access/admin.rs` | 普通分配保留；业务管理员直接分配 |
| SQL 强制 JOIN role_permissions | `access.rs::check_grants` | 校验有效权限后，在同域内分两种授权分支 |
| 管理诊断复用 tx.check_permission | `access/admin/diagnostic.rs` | 继续复用同一授权 SQL |
| 客户端拒绝未知 kind，列表游标不含业务 | `web/*/client.ts`、Axum DTO | 同步类型、校验、业务作用域和游标 |
| bootstrap 与新租户写入旧 IDP 角色键/名称 | storage `access/admin.rs`、Core `access/admin.rs` | 新建使用新标识，已有记录显式迁移 |

表中 `access/` 指 Core 的 `crates/embedded-idp-core/src/access/`；storage 指 `crates/embedded-idp-storage-postgres/src/`。实施影响清单见第 12 节。

## 3. 标识、管理命名空间与信任来源

### 3.1 业务标识

`business_id` 采用现有 `validate_name` 规则：1–64 字节，`[a-z][a-z0-9_.-]*`，区分大小写但只接受小写，不 trim、不做隐式转换。`f_01` 是合法示例，名称本身不携带额外授权含义。

保留 `idp` 以及 `idp.` 前缀。宿主业务不能使用；没有隐式默认业务、空字符串业务或 `*` 业务。

### 3.2 内置管理权限

为了使现有共表结构继续使用非空复合键，数据库和 Core 中以固定 `business_id=idp` 存放 IDP 管理权限及角色。这是内部保留命名空间，不是宿主业务，也不是跨业务通配符。

| 类别/类型 | business_id | 租户约束 |
| --- | --- | --- |
| platform 权限 / SystemAdmin | idp | 只能在 0 |
| tenant 权限 / TenantSecurityAdmin | idp | 沿用当前租户模式约束 |
| business 权限 / Business / BusinessAdmin | 非保留业务标识 | Disabled 只能 0；Enabled 只能真实租户 |

内置管理授权查询由 Core 固定填入 `idp`，不能复用管理请求选择的目标业务。权限目录的 `idp.platform`、`idp.tenant` 资源根保持不变。业务权限仍禁止使用 `idp.` 资源根。

### 3.3 请求信任边界

- `subject_id` 和当前租户来自已经验证的会话。宿主调用 Core 必须提供可信认证结果。
- 实际业务操作的 `business_id` 由宿主服务端挂载配置、路由或所加载业务对象确定。前端字段只能作为选择输入，必须经服务端核对，不得直接决定管理员匹配域。
- 管理接口允许管理员显式选择目标租户；同租户列表可用 business_id 筛选，但筛选值不产生权限。Core 仍验证管理会话和目标租户权限，写入与详情按目标记录的精确业务域校验。
- 宿主加载资源、查询业务数据和授权检查必须使用一致的租户、业务标识与资源 ID。宿主数据库可以用其既有隔离方式，不要求机械新增同名字段。
- 本期不改变 JWT、refresh、OIDC code、设备证明和 Cookie 协议；业务标识不是身份声明。已有 token audience/client/session 校验保持有效，不承诺跨应用登录隔离由 business_id 自动解决。

## 4. Core 模型与服务契约

以下为目标接口形态，不是已实现的可编译示例。

```rust
struct PermissionKey {
    business_id: String,
    resource_type: String,
    action: String,
}

struct AccessQuery {
    tenant_id: String,
    business_id: String,
    subject_id: AccountId,
    resource_type: String,
    action: String,
    resource_id: Option<String>,
}

enum RoleKind { SystemAdmin, TenantSecurityAdmin, Business, BusinessAdmin }

// Role 增加不可变 business_id；PermissionDefinition 从 key 获取 business_id。
// RolePermission 的 key 自带业务，必须与所属 Role 一致。
enum RoleBindingScope {
    Business,
    Resource { resource_type: String, scope: ResourceScope },
}
// RoleBinding 保留 tenant_id / subject_id / role_id / id / created_at，
// 增加 business_id，以 RoleBindingScope 替代原 resource_type + scope。
```

`ResourceScope::Type | Instance(id)` 的现有语义保持。Business 只能用于 BusinessAdmin；Resource 只能用于普通业务角色或现有 IDP 管理角色。缺失 scope 不自动转换成 Business。

`PermissionKey` 保留在 `PermissionDefinition` 内，不同时增加第二个可分歧的业务字段。角色权限替换命令要求每个 key 的业务都匹配角色；HTTP body 中省略重复业务字段，由适配器从唯一的已校验目标业务构造 key。

存储层将 `PermissionDefinition.key.business_id` 映射到 `access_permissions.business_id` 列，读取时也只由该列构造 key；Core 不另有 `PermissionDefinition.business_id` 字段。HTTP 的扁平 business_id 同样从 key 序列化。RoleBinding/RolePermission 与关联 Role 之间的业务一致性由 Core 校验及复合外键共同保证。

### 4.1 命令与管理权限

在现有管理服务与事务框架扩展，不新增并行的管理服务实现：

| 命令 | 目标业务来源 | 管理授权 |
| --- | --- | --- |
| CreateRole | 新增显式 business_id 参数；固定 Business | roles.manage |
| CreateBusinessAdminRole | business_id + 可选 name；固定 key/kind | roles.manage |
| CreatePermission、SyncPermissions | PermissionKey.business_id；批次只允许一个业务 | permissions.manage；模板同步保持现有受限管理入口 |
| UpdateRole / DeleteRole | role_id 加显式预期 business_id | roles.manage |
| ReplaceRolePermissions | 同上；仅 Business 可操作 | roles.manage |
| GrantRole | 同上，显式 RoleBindingScope | grants.manage |
| RevokeRole | binding_id 加显式预期 business_id | grants.manage |
| 权限、角色及绑定读取 | tenant 必填；business 可选列表筛选 | access.read |
| 业务权限诊断 | 显式 tenant + business | access.read |

平台操作者继续映射 `idp.platform/access.manage` 等现有能力；真实租户管理员使用 `idp.tenant/*`，不能管理其他租户。业务管理员不因此获得任何上表管理权限。无需新增管理权限 key。

对于现有不属于业务的命令（账号、设备、会话、租户、安全管理员任命），不强塞宿主业务标识。新的业务字段放在相应命令或查询参数中，不在整个 AccessAdminContext 中放可变“当前业务”。

所有按 UUID 查找的详情、修改、删除、分配和撤销都重验 `(tenant_id, business_id, id)`。UUID 全局唯一不替代业务隔离。目标存在但不属于指定域时按未找到处理，不泄露其他业务内容。

### 4.2 业务管理员生命周期

- 创建：原子写角色与审计，数据库保证同域唯一；并发重复创建最多一次成功，其余返回 Conflict。需要重试的宿主读取已有角色并核对，不自动改名、启用或重新分配。
- 普通 CreateRole 拒绝 `business_admin` 及所有 IDP 保留键；不接受 kind 参数。专用创建不接受调用方 key/kind/permissions。
- 更新：允许名称、active/disabled，使用 expected_version；禁止改变 key、kind、tenant 或 business。
- 分配：要求目标账号与租户成员有效、角色有效，scope 必须显式为 Business；可以在权限目录为空时分配。
- 同用户重复分配返回 Conflict，不创建多份绑定；读取已有分配可用于重试核对。
- 撤销：删除该 binding 并审计。该用户其他业务的分配不受影响；普通角色仍可独立授予部分权限。
- 删除角色：只有零绑定才允许删除，使用 expected_version；否则 Conflict。管理员可先停用再逐项撤销。无需最后业务管理员保护，因为 IDP 授权管理员可以重新管理。
- 普通角色维持现有删除行为；IDP 安全管理员的专用任命和最后管理员保护继续有效。
- 不允许通过 ReplaceRolePermissions 给业务管理员添加或清空权限关联；始终没有该类关联。

### 4.3 查询与展示描述

- `AuthorizationService::check/check_many` 保持服务入口，新增查询必填 business_id；同一批次要求 tenant、business、subject 全部相同，保留输入顺序和重复项，最多 100 项。
- `list_subject_roles`、`list_role_permissions` 必须指定精确的 business_id；管理角色/权限/绑定列表按租户查询，支持可选 business_id 筛选。结果必须返回可验证的 business_id。详情、修改、删除、分配、撤销仍必须使用对象的精确业务域。
- 角色配置查询仍返回显式关联。业务管理员的 permissions 为空，不将当前全部权限物化成角色配置。有效决策只能调用 check/check_many/诊断。
- `AccessListScope` 中 AdminPermissions、AdminRoles、AdminRoleBindings 的业务筛选可选，SubjectRoles、RolePermissions 的业务标识必填；各自游标绑定租户、对应业务范围、其他过滤条件和方向。权限/角色相关诊断必须包含业务。Web 管理页在同一租户内默认展示当前授权范围内的全部业务，列表提供业务筛选；筛选变化清空游标与选中对象。
- 受影响管理游标升级到 v3，自助角色/角色权限游标升级到 v2。旧游标拒绝；切换租户、业务筛选、其他过滤条件或排序方向必须从第一页开始。权限列表的排序稳定键包含 `business_id`，避免跨业务同 resource/action 时翻页漏项。未涉及业务的列表不强制改游标版本。
- 管理列表仍默认 desc，支持 asc；保留当前时间及稳定 ID 的 keyset 排序。配置读取不等于有效授权，停用角色仍可展示。

新描述语法：`tenant_id/business_id/subject_id::resource_type::action[::resource_id]`。例如 `t1/f_01/u1::report::read::r1`；内置管理为 `0/idp/u1::idp.platform::access.manage`。

保持当前字段字符集、资源 ID 长度和 1024 字节总上限；旧的两段主体前缀不再解析为业务授权。字符串只是描述，不是凭证，不将缺失业务猜成默认值。

## 5. PostgreSQL 目标结构

目标 Access 结构版本为 **tenant_v3**。新建 DDL 使用 `sql/tenant_v3.sql`；本节是结构规范，不是可直接执行的迁移脚本。保留现有表和行 ID，新增字段均在迁移填充后设为 NOT NULL；没有默认宿主业务值。

### 5.1 表和索引

| 表 | 新增/修改 | 约束与索引 |
| --- | --- | --- |
| access_permissions | business_id text NOT NULL | PK `(tenant_id,business_id,resource_type,action)`；检查 category 与 idp 命名空间一致 |
| access_roles | business_id text NOT NULL；kind 增 BusinessAdmin | 保留 PK `(tenant_id,id)`；新增 UNIQUE `(tenant_id,business_id,id)` 供复合 FK 使用；角色键 UNIQUE `(tenant_id,business_id,key)` |
| access_role_permissions | business_id text NOT NULL | PK `(tenant_id,business_id,role_id,resource_type,action)`；角色、权限两侧均使用包含 tenant/business 的 FK |
| access_role_bindings | business_id text NOT NULL；scope_kind；resource_type 改可空 | 角色 FK `(tenant_id,business_id,role_id)`；成员 FK `(tenant_id,account_id)` 保留 |
| access_audit_events | target_business_id text NULL | 新业务授权对象操作/诊断填写业务；IDP 内置角色/权限操作填写 idp；非单一授权域事件及旧事件保持 NULL；JSON change 中新授权对象包含业务 |
| access_state | module_version 更新 tenant_v3 | 在线版本核验、DDL 约束和 guard 一起更新 |

权限和角色仍引用租户。没有业务注册表，因此不增加指向业务表的 FK；业务隔离由各授权对象之间的复合 FK 保证。

角色约束：

- IDP 两种角色：business_id=idp，key 分别固定为 idp_system_admin / idp_tenant_security_admin。
- BusinessAdmin：business_id 非保留，key=business_admin。
- Business：business_id 非保留，key 不得使用任何新旧 IDP 保留键或 business_admin。
- 用局部唯一索引 `(tenant_id,kind) WHERE kind IN ('system_admin','tenant_security_admin')` 保持 IDP 单例。
- 用局部唯一索引 `(tenant_id,business_id) WHERE kind='business_admin'` 明确业务管理员单例。
- 更新时禁止改变 role 的 tenant、business、key、kind；用数据库不可变字段 guard 防止已有 FK/绑定被重解释。

### 5.2 分配形态

```text
scope_kind=business : resource_type IS NULL AND resource_id IS NULL
scope_kind=type     : resource_type IS NOT NULL AND resource_id IS NULL
scope_kind=instance : resource_type IS NOT NULL AND resource_id IS NOT NULL
```

非空资源字段沿用当前格式约束。局部唯一索引分别为：

- Business：`(tenant_id,business_id,account_id,role_id)`。
- Type：`(tenant_id,business_id,account_id,role_id,resource_type)`。
- Instance：`(tenant_id,business_id,account_id,role_id,resource_type,resource_id)`。

CHECK 不能查询另一张表。因此新增窄范围的绑定校验触发器：关联角色为 BusinessAdmin 才允许 business scope；Business 只允许 type/instance；两种 IDP 管理角色只允许其固定资源类型的 type scope。角色类型不可变，避免之后失配。

角色权限关联写入校验禁止 BusinessAdmin 的关联，并验证 role kind 与 permission category 匹配；租户、业务和权限存在性由复合 FK 保证。数据库约束用于防止持久化错误，不替代 Core 对调用者的管理授权。

### 5.3 查询索引和已有副作用

- 普通授权索引加入 business：`(tenant_id,business_id,account_id,resource_type,resource_id,role_id)`，只覆盖 resource scope。
- Business scope 使用前述用户角色唯一索引；角色权限与权限主键支持同域查询。
- 角色、权限、binding 的分页索引在租户后加入 business，保留当前 created_at 与稳定键的排序方式、NULL 历史时间处理及 C 排序规则。
- 新业务审计索引 `(tenant_id,target_business_id,occurred_at_epoch,id)` 仅在对应筛选入口启用；租户审计旧查询继续支持。
- 现有 ReplaceRolePermissions 后删除“已无该资源类型权限”的 binding 清理 SQL，只能作用于普通角色的 resource scope，不能删掉没有权限关联的业务管理员分配。
- 租户成员移除应清除该租户**全部业务**的绑定，不能因为管理 UI 当前业务筛选而漏删；账号/租户停用仍影响该主体的全部相关业务。

## 6. 统一授权算法

对 `Q=(tenant,business,subject,type,action,optional resource)`：

1. 验证输入和运行模式，拒绝非法或缺失业务。内置管理查询必须使用 idp，业务查询不得使用保留域。
2. 在一个数据库快照中验证模块版本、账号 active、租户 active、成员 active。
3. 找到 Q 的完整权限键，要求权限 enabled、未 archived，且类别与业务域一致。未知权限对任何角色都 Deny。
4. 若为 Business 权限，查询同 tenant/business/subject 下的 active BusinessAdmin 和 business-scope binding；存在则 Allow。
5. 否则按当前显式角色权限关联、角色类别、资源类型及 type/instance 覆盖规则匹配，所有 join 同时限定 tenant/business；存在则 Allow。
6. 无匹配则 Deny。数据库/结构错误返回 Error，不能转换为 Allow 或伪装成普通 Deny。

SQL 形态：先将 batch 参数展开，读取共同有效身份和每项权限，再计算 `EXISTS(业务管理员分配) OR EXISTS(普通/IDP角色显式关联)`。不要先将所有绑定 inner join 到权限关联表，否则无关联的业务管理员会被丢弃。批次仍为一次往返、一个快照，不先读角色后用第二次查询做授权。

Core 的 `RoleBinding::grants` 更新为同等语义，权限关联参数允许在业务管理员分支不存在；普通分支仍必须验证关联。Core 内存存储测试、Postgres `check_grants` 和管理诊断使用同一组行为用例。

业务管理员分支只面向 PermissionCategory::Business。管理写操作仍调用固定 idp 权限，不允许以“先看业务管理员”替代管理认证。

### 6.1 并发与撤权

延用现有管理写事务的 state → tenant → account 锁顺序、锁后读取时间和当前管理会话复查；暂不新增 business 锁。角色创建的单例由唯一索引兜底，版本检查及审计与变更同事务提交。

撤权提交后，新开启快照的 check 必须观察到撤权；已经取得旧快照的在途请求可能完成，不声称能取消已开始的业务事务。宿主需要“授权与敏感数据写入原子”时，仍需其现有事务集成。保留不跨请求缓存 Allow 的约束。

## 7. HTTP 契约

保留模块根 `/admin`、`/auth` 等及宿主外层前缀，不新增另一套授权 HTTP 服务。下表均为实施后的目标契约。

### 7.1 业务筛选与请求边界

管理页面只选择目标租户；同一租户内不提供全局业务切换，角色、权限和绑定列表默认查询当前授权范围内的全部业务，并提供业务标识筛选。列表接口的 `X-Embedded-IdP-Business-Id` 为可选筛选 Header：Disabled 的 `0` 域缺失时包含 Platform、Tenant、Business 三类记录，筛选 `idp` 时包含 Platform、Tenant 两类记录；Enabled 的真实租户缺失时包含 Tenant、Business 两类记录。空值、重复值和非法值均 400。租户选择继续使用现有可信上下文和 `X-Embedded-IdP-Tenant-Id` 规则。

创建权限、创建角色、创建业务管理员等需要业务归属的表单必须填写 business_id；详情、修改、删除、角色权限替换、角色分配和撤销从已读取并核验的记录取得精确 business_id，不接受用列表筛选代替目标域。角色绑定抽屉和角色选择器可使用可选业务筛选。账号、成员、设备、会话、客户端和其他不属于业务授权对象的列表不增加业务筛选；审计列表保留独立的可选 business_id 查询参数。

管理角色和权限只读接口可用 `idp` 查看当前目标租户内置记录；业务 CRUD、业务管理员创建和业务分配不接受 idp。原有安全管理员任命路由保持专用入口，由服务端固定 idp，不接受宿主业务 Header。

Enabled 模式的平台 `0` 读取继续走现有专用平台入口；不能为了显示内置角色而放宽普通 `/admin/access` 目标租户检查。业务列表与平台目录分开处理。

租户、成员、账号、客户端、设备、会话与安全管理员接口不增加业务过滤；不相关接口若收到该 Header 应返回 400，避免造成它已经按业务隔离的误解。审计业务筛选使用下文独立 query 参数。

### 7.2 角色与绑定

| 方法与路径 | 变化 |
| --- | --- |
| POST /admin/access/roles | body `{key,name}`，固定 Business；创建表单的业务标识由客户端放入精确业务 Header |
| POST /admin/access/business-admin | 新增；body `{ "name": "业务系统管理员" }`，name 可省略；创建表单的业务标识由客户端放入精确业务 Header |
| GET /admin/access/business-admin | 新增；按精确业务 Header 返回单例角色详情，不存在 404 |
| GET/PATCH/DELETE /admin/access/roles/{role_id} | 必须带精确业务 Header；同域读取；BusinessAdmin 允许名称/状态更新和零绑定删除，expected_version 必需 |
| GET/PUT /admin/access/roles/{role_id}/permissions | 必须带精确业务 Header；GET 返回显式关联；BusinessAdmin 为 []；PUT 对该类型 403 |
| POST /admin/access/subjects/{subject_id}/role-bindings | 必须带精确业务 Header；scope DTO 区分 business / type / instance，见下例 |
| DELETE /admin/access/role-bindings/{binding_id} | 必须带精确业务 Header；重验租户和业务；业务管理员撤销沿用该入口 |

业务管理员分配：

```json
{"role_id":"<业务管理员角色UUID>","scope":{"kind":"business"}}
```

普通分配：

```json
{"role_id":"<普通角色UUID>","resource_type":"report","scope":{"kind":"instance","resource_id":"r001"}}
```

business scope 携带 resource_type/resource_id 即 400；普通角色使用 business scope 或业务管理员使用 resource scope 即 400。适配器从请求的唯一目标业务构造 Core 命令；客户端不能在 body 提供另一套业务选择值。

响应 role/binding 包含 business_id，binding 返回相同 scope 形态。创建/分配沿用现有成功响应封装及 audit_id；新增创建返回 201、读取 200，错误继续使用统一 problem 响应。

### 7.3 权限、自助查询与诊断

- 现有权限目录 CRUD 路径保留；创建表单的业务标识由客户端放入精确业务 Header，body 不重复 business_id。Permission DTO 始终返回 business_id；列表可选业务筛选 Header，详情和写入必须使用精确业务 Header。
- `/auth/me/roles` 增加必填 query `business_id`，只接受非保留业务；tenant/subject 仍只能从认证会话获取，不能通过 query/header 改写。它返回本人指定业务的角色配置，不证明当前有效权限。
- 保留 Core `list_role_permissions` 的同域配置读取能力，不为本设计虚构尚不存在的公共自助权限路由。
- 管理权限诊断表单必须填写目标 business，由客户端放入精确业务 Header，仍走 check_grants；成功的诊断记录含目标业务。
- 审计列表增加可选 `business_id` 筛选，管理权限仍是租户/平台审计权限；带筛选的游标必须绑定该值。省略仍查询有权查看的全部租户审计，而不是隐式选择某个业务。
- 审计业务字段表示**被修改/查询的授权对象**所属域，不是操作者用于授权的 idp 域。例如修改 f_01 权限记录 f_01；任命 IDP 管理员记录 idp；账号安全、创建租户、移除成员等可能影响多个业务的事件记 NULL。这些 NULL 事件仍在全租户审计中可见，不能用单业务筛选声称获得完整的用户安全历史。
- 需要业务归属的创建、详情、写入和诊断接口缺失精确业务 Header 时 400；列表缺失业务筛选时按租户模式返回全部允许记录。旧客户端不得通过自动使用 idp/default 来代替创建、详情或写入目标域。

### 7.4 错误语义

| 情况 | 结果 |
| --- | --- |
| 创建/详情/写入缺失或非法业务、scope 形态不符、跨业务批次、旧游标；列表筛选值非法 | 400 InvalidInput / InvalidCursor |
| 无有效认证 | 401 |
| 无管理能力、尝试写 idp 业务、普通接口创建保留角色 | 403 |
| 指定 tenant/business 下没有对象 | 404 |
| 同域管理员已存在、重复 binding、版本冲突、带绑定删除管理员 | 409 |
| 运行时查询未找到权限、无有效角色分配 | AccessDecision::Deny；由宿主映射业务响应 |
| 存储/结构错误 | Error；不得隐藏为普通无权限 |

复用现有 AccessError 和 HTTP 错误码；精细原因放在稳定的非敏感 detail 中，不为每个失败新增异常层次。

## 8. IDP 管理角色重命名

| kind（保持） | 新 key | 新默认 name |
| --- | --- | --- |
| system_admin | idp_system_admin | IDP管理员 |
| tenant_security_admin | idp_tenant_security_admin | IDP租户管理员 |

bootstrap、新租户创建、管理 UI、保留键检查、fixture、文档一起改。普通角色创建保留新旧四个 IDP key 及 business_admin，避免旧名称被重新用于误导性角色。

迁移只按**受保护 kind**选择要重命名的角色，不按同名普通角色推断权限。保留 role_id、version 历史衔接、关联和用户绑定；角色 version 加一并写迁移记录。仅当名称等于旧默认英文名称时换成新默认中文名称，自定义名称保留。

## 9. Web、参考服务与宿主集成

- Web 管理端先选目标租户；同一租户内的角色、权限和绑定列表默认展示全部授权业务，并提供 business_id 筛选。创建表单必须明确输入或选择 business_id，选择值是筛选或创建归属，不是权限。无业务注册表时，允许输入新标识，不新增“注册业务”前置流程。
- 本期不提供聚合业务发现 API；宿主可提供其业务列表，独立管理端使用明确输入。业务筛选变化取消旧请求或丢弃旧响应、清空游标与选中对象，缓存键加入 tenant/business filter。成员/账号/设备/会话页面不增加业务筛选，审计页面保留独立业务筛选。
- 新增“创建业务管理员”操作，名称可编辑；权限页显示“本业务全部有效权限，含以后新增权限”，不展示空列表为“无权限”。
- 分配业务管理员只选用户和角色，无资源范围表单；普通角色保留现有范围表单。新增 scope 与 kind 要同时更新 UI 和 ManagementClient 前置验证。
- 可嵌入客户端 `listMyRoles` 显式接收 business_id；`EmbeddedAuth` 可选 `businessId` 只控制本人角色查询，省略时提供纯身份界面。登录、选租户组件不新增业务选择登录步骤。
- `PermissionCatalog` 内置管理 key 固定 idp；宿主模板声明显式业务 key。SyncPermissions 要校验单租户单业务，只插入缺失定义，不覆盖现有权限状态。
- 新租户创建目前会复制宿主 catalog 的业务权限模板；继续保留该显式宿主配置行为，每项模板保留其 business_id，仅替换 tenant_id。租户安全管理员的权限关联只包含 idp 命名空间的 Tenant 类别，不把这些业务模板关联给它，也不创建业务管理员。
- 参考服务的结构版本、readiness、离线建库工具升级；新启动不自动迁移、创建业务管理员、恢复角色或绑定。单业务示例给出显式 business_id 配置及请求，拒绝缺失配置，不在库内设置默认值。
- 宿主可直接复用 Core 管理服务；HTTP 调用方用现有管理会话。创建业务管理员不复用首位 IDP 管理员的离线 bootstrap，不提供无认证初始化 HTTP。

## 10. tenant_v2 → tenant_v3 显式迁移

这是授权主键变化，采用停机升级，不支持 v2/v3 混合写入，也不在启动时自动迁移。本期实施必须交付保留已有数据的迁移工具；无需再实施 v1 的历史协议兼容。

### 10.1 映射输入与预检查

迁移的业务标识由操作者提供，不能猜测。支持两种明确输入：

1. 每租户一个目标业务：将该租户所有既有 Business 权限、角色和关联迁入指定 business_id。
2. 同租户拆成多业务：显式提供 `旧权限(tenant,type,action) → business` 与 `旧role_id → business` 映射；每条角色权限边必须映射到同一业务。

空权限集角色也必须映射；binding 从对应 role 得到业务。停用、归档权限也必须映射，不能丢弃历史键。已有普通角色跨多个目标业务时预检查失败，不能自动复制权限或角色；先由操作者明确拆分方案再执行本迁移。全部旧行必须恰好映射一次，无遗漏、无重复、无跨域边。

内置管理数据统一映射 idp，与宿主映射分开。若既有普通角色使用新保留 key（包括 business_admin），操作者须先明确改名并在 v2 中完成修改，再运行迁移；迁移不能根据名字把它变成管理员。

dry-run 报告包含行数、映射覆盖、关联冲突、保留键冲突、受保护角色数量、版本/DDL 指纹以及待修改默认名称，不打印任何凭证。v2 布局检查还应涵盖既有时间分页升级的列与索引。

该原地迁移面向已完成 bootstrap 且管理员不变量有效的 v2。未 bootstrap 的空开发结构直接显式准备新 v3 schema；不完整或受损结构先修复，不能借本迁移自动恢复管理员。

### 10.2 执行顺序

1. 停止旧写入服务，备份并验证可恢复；针对目标 schema 获取迁移 advisory lock 和必要表锁。
2. 一个事务内再次核验 v2、映射和现有管理员不变量，防止 dry-run 后发生变化。
3. 添加可空业务列、scope_kind 和业务审计列；按显式映射填充；现有 binding 的 resource_id 为空映射 type，否则 instance。
4. 将 IDP 管理数据置于 idp 并重命名角色；所有普通角色仍为 Business，不创建 BusinessAdmin，不增加任何绑定。
5. 重建主键、复合 FK、唯一/分页索引和上述 guard/触发器；验证完整性后设置 NOT NULL。
6. 对迁移前后的普通授权按映射做等价性核验，核对账号、成员、角色、绑定等保留行数；将元数据切为 tenant_v3，提交。
7. 启动新版本，验证 readiness、两个租户模式、代表性 Allow/Deny、管理端与宿主示例。完成后才能由管理者显式创建业务管理员。

`access_state_guard` 当前禁止修改 module_version；迁移必须在独占事务内定向替换该 guard/版本约束，更新版本后恢复 v3 guard，不整体关闭所有触发器。版本值、结构与新触发器只能一起提交。失败回滚到完整 v2，不能留下半升级状态。

### 10.3 历史、重跑与回退

- 旧审计 JSON 不重写、不伪造当时的业务归属；target_business_id 保持 NULL，界面显示“历史记录，未区分业务”。
- 迁移用专门离线审计事件 `access.migrate_business_scope` 记录来源/目标版本、映射摘要、变更计数和请求 ID。操作者须显式指定现有有效平台管理员的 account_id 作为归责主体，迁移前核验该账号及其 0 域成员关系，不创建账号；数据库执行权限仍由离线运维控制，这个 ID 不等同于在线认证。事件固定 actor_domain/target_domain=0、target_business_id=NULL、authentication_source=offline_migration、actor_session_id=NULL，保留 actor 外键。审计 CHECK 为这一精确组合增加分支，普通管理事件仍必须有会话；不借用 bootstrap 事件，不伪造会话。
- 重跑已完成的 v3：只核验 v3 完整结构并报告 AlreadyMigrated，不再次映射、重命名或恢复任何授权；v3 不一致则失败。
- 新程序拒绝 v2；旧程序拒绝 v3。参考脚本的 schema 名后缀只是开发目录约定，不代表数据库版本；迁移不通过修改 schema 名伪装升级。
- 不提供有损降级。v3 开始写入后，如需回退必须恢复升级前完整备份并处理期间新增数据；不能直接删除 business_id 列。
- Token/密码/设备密钥格式不变；切换版本时重启连接池和服务。HTTP、Rust API 与客户端是破坏性升级，发布版本必须显式标记，不能宣称旧宿主无需修改。

### 10.4 运行迁移工具

入口是 [`scripts/migrate_business_scope.sh`](../scripts/migrate_business_scope.sh)，依赖 `psql`。先停止旧服务写入、完成数据库备份，并确认旧库已完成管理员初始化和列表时间升级。参数依次为连接 URI、schema、权限映射 TSV、角色映射 TSV、现有有效平台管理员 UUID、审计请求 ID；不带 `--apply` 时执行完整转换后回滚。

两份 TSV 都必须带表头；以下仅是合成格式示例，分隔符为实际制表符：

```text
tenant_id	resource_type	action	business_id
t1	report	read	f_01
```

```text
tenant_id	role_id	business_id
t1	44444444-4444-4444-8444-444444444444	f_01
```

权限文件必须覆盖全部 Business 权限（包括归档及未关联角色的权限），角色文件必须覆盖全部 Business 角色（包括空角色）。IDP 内置对象不写入映射。单租户单业务场景可先导出该租户全部上述对象，再为它们填写相同 business_id；多业务时逐对象分组。一个角色的全部关联权限必须映射到同一业务。普通角色若占用新增保留键，须先按错误提示显式改名，不能靠迁移自动猜名。

```bash
# 以下变量由部署者提供；使用备份后、已停写的目标数据库。
bash scripts/migrate_business_scope.sh "$IDP_MIGRATION_URI" "$IDP_SCHEMA" \
  /private/path/permissions.tsv /private/path/roles.tsv "$IDP_OPERATOR_ID" migration-review

# 核对 dry-run 后再提交同一映射。
bash scripts/migrate_business_scope.sh "$IDP_MIGRATION_URI" "$IDP_SCHEMA" \
  /private/path/permissions.tsv /private/path/roles.tsv "$IDP_OPERATOR_ID" migration-apply --apply
```

映射文件路径当前只接受字母、数字、下划线、点、斜线和连字符。不要直接执行模板 SQL；wrapper 会安全填入本地 COPY 路径。迁移完成后用新版本 readiness 检查结构与管理员状态，核对普通用户代表性 Allow/Deny，再恢复服务。

可重复的迁移回归入口为 [`scripts/test_business_scope_migration.sh`](../scripts/test_business_scope_migration.sh)：显式设置 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI` 后执行，只创建并清理随机测试 schema，不升级应用 schema。

## 11. 验证与验收矩阵

| 维度 | 必须验证 |
| --- | --- |
| 同租户不同业务 | 同名 type/action/角色 key 可并存；f_01 的任何授权不能满足 f_02 |
| 不同租户同业务 | business_id 相同不共享权限、角色或绑定；平台 0 不作为业务回退 |
| 业务管理员 | 无 role_permissions 仍 Allow；以后新增 type/action 自动覆盖；实例级与类型级检查均覆盖 |
| 有效性 | 缺失/停用/归档权限 Deny；账号、成员、租户、角色失效 Deny；撤销下次新快照生效 |
| 普通角色 | type/instance 原规则保持；角色和权限不同业务关联失败；不存在管理员时结果与旧模型映射等价 |
| 管理边界 | BusinessAdmin 不能访问 idp 管理、创建/分配角色；租户管理员仅管理本租户业务；平台显式选择目标租户 |
| 单例/并发 | 同 tenant/business 并发创建最多一个成功；不同业务可各一个；重复绑定和版本冲突正确处理 |
| 分配形态 | 缺 scope、业务级携资源字段、普通角色用业务级、管理员用资源级全部拒绝；数据库直接写非法关系失败 |
| 生命周期 | 更新权限不清理 BusinessAdmin 分配；成员移除清理本租户所有业务；停用再启用按现有绑定恢复 |
| 查找/分页 | 换业务不可复用 cursor；改 Header 不能访问其他业务 UUID；输出业务不符时客户端拒绝；管理列表方向不变 |
| 批量/诊断 | check、check_many、诊断一致；混业务批次拒绝；顺序与重复项保留；存储故障为 Error |
| 迁移 | 单/多业务完整映射、空角色、归档权限、跨业务边、键冲突、事务失败回滚、v3重跑、guard/版本不匹配 |
| 名称迁移 | 新旧默认名正确；自定义名保留；role_id 和用户绑定保持；同名普通角色不升级 |
| 模式/集成 | Disabled 与 Enabled；嵌入客户端、管理客户端、参考服务、仓库示例全部传递一致业务标识 |

实施时先 Core 单元测试和 Web DTO 测试，再 Axum、Postgres 存储和迁移测试；跨边界实现完成后运行仓库规定的 Web build、Rust fmt/check/test。真实 PostgreSQL 验证仍只使用显式 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI` 和临时 schema，不使离线测试依赖数据库。

验证批量授权的 SQL 仍一次往返；用代表性数据检查普通/管理员两个分支的执行计划，不以本设计文档代替性能验收。

## 12. 实施拆分和文件责任

| 顺序 | 范围 | 完成条件 |
| --- | --- | --- |
| 1 | Core `query.rs/model.rs/service.rs/store.rs/admin*.rs` 及 tests | 标识与 scope、单例规则、管理授权映射、普通/管理员统一行为、分页契约先确定 |
| 2 | Postgres `access.rs/access/admin.rs/sql`、结构核验、迁移工具 | v3 DDL、授权 SQL、事务审计和迁移在临时数据库通过同一验收矩阵 |
| 3 | Axum `role_admin/role_binding_admin/permission_admin/access_diagnostic/tenant_self/tenant_admin` 及审计路由 | 唯一业务输入来源、DTO、隔离、HTTP 错误和游标测试通过 |
| 4 | `web/management`、`web/embedded` | 客户端支持新类型/scope，管理操作及空权限集展示正确，同租户业务筛选不串数据 |
| 5 | 参考 app、脚本、`examples/no-tenant-host`、所有当前集成文档 | 显式业务配置、版本发布、迁移与回退说明，两种模式集成验证 |

每一步都不能仅靠全局替换 `system_admin`：key 要改，kind 保留，idp.platform 管理权限和审计历史保留各自语义。实施前再次确认当时主分支变化，本文代码基线不代替实际 diff 审查。

## 13. 跨文档一致性与本轮交付

本轮实现 Core、PostgreSQL、HTTP、Web、参考服务与仓库内示例，并同步当前接口文档。历史协议说明保留其版本背景。

| 现有文档 | 与目标设计的差异 | 本轮/实施时处理 |
| --- | --- | --- |
| README、当前交付状态 | tenant_v2、按租户目录、未有业务管理员 | 更新为 2.0 当前能力和限制 |
| tenant-role-permission-design-v1 | 两段描述语法、无业务域、只有资源 binding、旧角色 key | 标注历史结构，更新当前查询与分页契约，并链接 2.0 完整模型 |
| host-integration-v1、React 集成说明 | 旧参数、DTO、模板和客户端示例 | 更新 business 参数、DTO、scope 和破坏性升级要求 |
| tenant-access-execution-plan | 上一轮升级不支持历史迁移 | 明确其指上一轮；本设计的 v2→v3 显式映射迁移为本轮新增要求 |
| production-security 文档、browser-session、设备证明 | 认证/会话协议 | 保持现有协议；实现中不能以业务管理员跳过这些检查 |
| PostgreSQL 早期设计、CHANGELOG 历史条目 | 历史版本说明 | 不回写历史；实现发布时新增 v3 变更说明与迁移入口 |

评审重点是本设计是否满足“每租户每业务一个可自定义名称的全权角色”，并验证普通授权没有跨业务旁路。业务标识选择、历史数据映射由部署者提供；其具体值不是 IDP 预置产品规则。
