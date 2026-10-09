# 设备身份与安全生命周期：详细技术设计 v1

初版：2026-09-28。本文保留设备生命周期的初始契约与 P0 历史验收，现已纳入 3.0.0；部署当前版本须使用 tenant_v6，按[统一升级手册](device-scan-login-upgrade.md)执行，不能以本机历史 v4 记录判断当前数据库。宿主现场与生产容量验收仍由部署方完成。

代码基线：`b8e5d1648de861b5308ed24b9e7be05fafc15f72`（2.0.0，`tenant_v3`）。实施顺序和交付门槛见[实施计划](device-identity-lifecycle-implementation-plan.md)。本文仅设计 IDP 内部能力，不设计宿主业务、接入项目、终端配对页面或离线同步。

## 1. 目标、范围与权威关系

本轮补齐设备身份的安全恢复、可靠登记、人员设备关系管理、结果查询与审计。复用现有 Core 服务、Postgres 事务、Axum 路由和管理前端，不建设独立设备服务或通用命令平台。

### 1.1 确定的边界

- 设备身份归属 `tenant_id`，保留现有 `client_id` 约束。**登记协议由宿主或其客户端生成设备 ID，宿主确认后提交给 IDP**；IDP 校验、占用并维护其安全生命周期。存储主键要求 canonical UUID；宿主若使用 `device1` 等非 UUID 业务设备号，须在自己的数据中映射到提交给 IDP 的 UUID。设备、人员设备绑定、会话、密钥、挑战均不新增 `business_id`。
- `business_id` 继续只是权限命名空间。角色、权限、资源实例授权以及 `business_admin` 的现有语义不变；本轮不新增任何业务权限定义。
- 设备身份、人员账号、人员设备绑定、会话是独立对象。撤销设备不删除账号；定向解绑不撤销其他人员、其他设备或其他租户的关系。
- IDP 管理操作仍要求管理用途身份和内置管理权限。持有业务管理员角色不获得设备安全管理权。
- 不改变 V2 在线设备证明的签名字节、五个证明头、一次性挑战、refresh 轮换及重用检测规则。不以业务幂等为由接受证明重放。
- 不新增业务成员表、工厂/终端资料、设备业务绑定、配对码平台、业务暂停、历史业务授权、离线证据/许可/补传/校准。

### 1.2 分期

| 层级 | 本设计确定的工作 |
| --- | --- |
| P0 | 设备状态版本与启用；可靠登记与结果恢复；管理员绑定查询/定向解绑；自助解绑精确化；当前密钥查询及轮换恢复；同事务审计、HTTP/客户端/管理端与迁移 |
| P1 | 受控历史公钥列表与详情；在 P0 交付后单独实现，不阻塞 P0 |
| 后置 | 无人员会话的 DEVICE 主体认证。本设计只保留边界，不提供未审定的协议或新增入口 |

本文记录本分支的 P0 契约和待验收项；已发布的 2.0.0 仍使用 `tenant_v3`。安全不变量继续以[生产安全要求](rust-embedded-idp-production-security-delivery-v2.md)、[设备证明设计](rust-embedded-idp-production-security-extension-design-v2.md)、[租户设计及实施补充](tenant-role-permission-design-v1.md)为基线。历史文档中的非租户路径、旧迁移版本或开发适配器不覆盖本分支源码。

## 2. 相对 2.0.0 的源码差异

| 能力 | 2.0.0 基线 | 本分支处理 |
| --- | --- | --- |
| 登记 | `provision_device` 通过准入后每次生成新 device ID；HTTP body 为 tenant/device_name；没有登记请求结果记录 | 改为接收可信准入审核过的宿主设备 UUID，新增请求关联、准入范围和预期公钥绑定；同请求返回同设备 |
| 激活 | `complete_registration` 原子消费挑战、插入版本 1 公钥并激活设备 | 保留原子性与 V2 字节；增加登记预期公钥/期限核对和完成结果记录 |
| 设备管理 | 管理接口有列表、详情、disable/revoke；Core 只接受 disabled/revoked；比较 `expected_status` | 增加 enable 和单调递增 version，替换只有状态的并发检查 |
| 安全停用 | 撤销该设备关联 session/refresh，清除来源授权码、切租户票据与 nonce；保留密钥和人员绑定 | 保留副作用，明确哪些路径能恢复 |
| 撤销 | 在停用副作用之上退役 active key，将非 unbound 绑定改为 unbound | 保留终态，不删除历史 |
| 首次绑定/重绑 | 证明登录读取非 unbound 绑定；不存在时创建新 binding。部分唯一索引只约束非 unbound 行 | 保留“解绑后合法登录新建关系”，绝不重新激活旧 binding ID |
| suspended 绑定 | 证明校验拒绝，不能首次绑定覆盖；当前无完整的管理员绑定操作面 | P0 不新增 suspend/resume 功能；读取时明确展示，不承诺其等同解绑 |
| 自助解绑 | 按本人 tenant/account/device 解绑并撤销相关 session/refresh；未显式清理其来源 code/selection | 按 binding ID/version 定位，并补齐派生凭证清理及审计 |
| 管理员定向解绑 | 设备管理服务没有人员绑定列表/详情/定向解绑方法 | 增加上述能力，沿用 ManageDevices 管理边界 |
| 密钥轮换 | 双签名、active 绑定、一次性挑战，原子退役旧 key/插入下一版本；历史公钥保留 | 增加明确预期 key/version 和受控当前/指定 key 元数据查询，支持响应丢失后核对 |
| 审计 | 管理状态变化进入 `access_audit_events`；认证侧登记/轮换/解绑不能假定已有等价管理审计 | 按第 7 节补齐；匿名登记不伪造账号/管理操作者 |
| Web | `devices.tsx` 有列表、详情、停用/撤销与“结果未知请重新加载”；当前没有恢复或绑定管理 | 原页面增量完善，不新建监控看板 |

主要核查文件：

- Core：[device_proof.rs](../crates/embedded-idp-core/src/access/device_proof.rs)、[lifecycle.rs](../crates/embedded-idp-core/src/access/device_proof/lifecycle.rs)、[management.rs](../crates/embedded-idp-core/src/access/device_proof/management.rs)、[device_login.rs](../crates/embedded-idp-core/src/access/authentication/device_login.rs)、[admin.rs](../crates/embedded-idp-core/src/access/admin.rs)、[admin/devices.rs](../crates/embedded-idp-core/src/access/admin/devices.rs)。
- 存储：[device_proof.rs](../crates/embedded-idp-storage-postgres/src/access/device_proof.rs)、[device_management.rs](../crates/embedded-idp-storage-postgres/src/access/device_management.rs)、[admin.rs](../crates/embedded-idp-storage-postgres/src/access/admin.rs)、[tenant_v3.sql](../crates/embedded-idp-storage-postgres/src/sql/tenant_v3.sql)。
- HTTP：[tenant_devices.rs](../crates/embedded-idp-axum/src/tenant_devices.rs)、[tenant_device_admin.rs](../crates/embedded-idp-axum/src/tenant_device_admin.rs)；Web：[devices.tsx](../web/management/devices.tsx)、[client.ts](../web/management/client.ts)。

## 3. 领域模型与状态规则

### 3.1 设备版本

`TenantProofDevice` 和所有设备详情投影增加 `version: u64`，映射 `devices.version bigint CHECK(version > 0)`。新设备从 1 开始，激活、实际启停/撤销、密钥轮换每次恰好增加 1；心跳、nonce、人员登录/绑定变化不增加设备版本。

设备版本与密钥版本不同。密钥版本只在注册和轮换时从 1 递增；设备经历 disable→enable 后，即使 status 回到 active，version 也不同。所有版本越界必须失败，不允许回绕。

### 3.2 状态机

| 原状态 | 操作 | 目标状态 | 条件与副作用 |
| --- | --- | --- | --- |
| 无 | provision | pending | 准入授权、有效且未占用的预期公钥、登记请求关联同事务完成 |
| pending | complete | active | 未过登记期限；公钥与预登记一致；有效持钥证明；插入 key v1、记录完成时间、设备 version+1 |
| active | disable | disabled | 管理授权及 expected_version；撤销设备范围凭证，清 nonce；保留 key/binding |
| pending | disable | disabled | 保留现有能力；无 key 的 disabled 只能后续撤销，不允许 enable 或 complete |
| disabled | enable | active | 管理授权、租户/client 有效、expected_version、存在匹配且唯一的 active key；不恢复旧凭证，不改变绑定状态 |
| pending/active/disabled | revoke | revoked | 管理授权、expected_version；清理凭证/nonce、退役 key、解绑关系、version+1 |
| active | rotate-key | active | 有效人员会话/绑定、预期 key/version、双签名、新挑战；key version+1、device version+1 |
| revoked | 任意激活/轮换 | 拒绝 | 不可逆终态 |

新 operation ID 对“已在目标状态”的启停/撤销返回 `device_state_conflict`，不再次清理凭证、不增长版本；同 operation ID 的已提交操作按第 6 节返回原结果。这区分重复投递与新的状态操作。

enable 保留原 active 公钥；之后必须重新登录并使用新挑战。已退役公钥始终不能用于新在线请求；疑似泄漏、密钥丢失不得以 enable/公钥覆盖恢复，应撤销原身份。服务端无法识别“同一物理硬件”，本轮不承诺硬件唯一性。

现有 `SetDeviceStatus` 存储分支会对所有状态变更执行撤销。实现时必须显式分支 enable 与 disable/revoke，不能机械放开 enum 后意外删除新会话或恢复旧凭证。enable 也不是“inactive tenant 清理例外”，只有租户有效时允许；平台在停用租户内仍可做 disable/revoke 等清理。

### 3.3 人员设备关系

- 每次首次/再次合法证明登录生成新 binding ID；历史 unbound 行保留。非 unbound 的 `(tenant, account, device)` 继续最多一行。
- 绑定投影增加 `binding_id`、`version`、`bound_at`、`unbound_at`；表增加 `version bigint > 0`，新行为 1，解绑增加 1。心跳/最近认证时间不改变 version。
- 定向解绑必须传 `binding_id + expected_version`，再核对 tenant/device/account。不能仅以 account/device 找“当前那行”执行旧请求。
- 自助解绑只允许本人 active 绑定；不能自助把 suspended 变成 unbound 来解除限制。管理员可明确解绑 active 或 suspended 关系，后者意味着解除这条限制，之后新登录仍需满足全部认证条件。
- P0 不新增手工创建 active 绑定、suspend/resume、人员设备白名单或黑名单。所有新增 active 关系仍经密码/选租户凭证与设备证明登录事务产生。
- 设备 revoke、租户成员移除等已有批量解绑路径也增加受影响 binding version，并保留精确的凭证范围；不能只修改新接口。
- 解绑不删除账号、不移除租户成员关系、不修改角色。会话撤销只覆盖目标 `(tenant, account, device)`；设备停用/撤销覆盖 `(tenant, device)` 全部人员。

## 4. 可靠登记

### 4.1 契约

现有创建 pending 设备的步骤增加以下输入（拟定 Rust 形态）：

```rust
struct ProvisionTenantDevice {
    tenant_id: String,
    device_id: String,               // 宿主生成并提交的 canonical UUID
    registration_request_id: String, // canonical UUID，关联键，不是凭据
    device_name: String,
    public_jwk: String,              // 预登记公钥；不得含私钥
}

struct TrustedDeviceAdmission {
    registration_scope: String,      // 可信准入适配器确定，禁止取自 JSON/Header 原值
    valid_until: SystemTime,          // 不能超过本次准入凭据的有效期
}
```

`TenantDeviceAdmission` 从“只接受 tenant/client 并返回 ()”改为对包含宿主设备 ID 的登记动作及可信准入上下文授权；稳定的 `TrustedDeviceAdmission` 由宿主在验证调用者后提供。准入方须确认该设备 ID 属于当前可登记的宿主设备；IDP 不从裸 JSON 字段推断所有权。动作区分 `Provision`（完整登记请求）与 `ReadResult`（tenant/device/request ID）；读取动作无需提交公钥，也不得先读取结果再据此确定调用者 scope。两个动作的 scope 都由同一个可信准入身份/授权引用确定。Axum 不在共享 `Arc` 中保存请求可变状态：通过可信请求扩展传入上下文；缺失上下文或准入拒绝即失败。客户端 ID 仍由服务配置确定。

`registration_scope` 只用来隔离登记结果查找，1–128 字节、使用现有 ID 字符集，不是业务 ID、租户、权限或登录主体；必须由认证后的准入方身份/登记授权引用稳定导出。不得把所有生产调用者放进默认 scope，不接受请求方自称 scope。Core 接口文档明确它是可信输入。本项目参考服务只在既有显式开发准入开关下提供固定开发 scope；默认拒绝策略不变。

每次创建、重试、查询均重新通过准入校验并检查租户/client 状态；等待事务锁后还须用服务时间复核 grant 的 valid_until。准入校验不负责在 IDP 事务外消费登记请求；单请求执行结果由登记事务保证。知道 request ID、公钥或 device ID 不产生读取/注册权限。

### 4.2 持久记录

新增 `device_registrations`，不是通用任务表：

| 字段 | 约束/含义 |
| --- | --- |
| tenant_id、client_id、registration_scope、registration_request_id | 联合主键；request ID 为 UUID |
| device_id | `(tenant_id, device_id)` 唯一并引用 devices；client 一致性由复合外键兜底 |
| expected_key_id、public_jwk | 验证后的 thumbprint 与规范公钥；expected_key_id 全局唯一，禁止同一密钥登记多个设备 |
| device_name | 原始合法名称，作为请求内容比较的一部分，不随展示名称变化 |
| created_at_epoch、expires_at_epoch | 注入时钟，expires > created；登记窗口最多 24 小时，且不超过本次准入有效期 |
| completed_at_epoch | 未完成为 NULL；完成后不可改写 |

请求内容通过规范 public JWK、名称、可信 tenant/client/scope 精确比较，禁止依赖任意 JSON 字段顺序。此表就是登记结果与无人员会话登记的安全来源记录；不生成虚假的 account ID 或管理会话。

密钥唯一性须同时检查历史 `device_proof_keys` 与登记预约，保留现有全局 key ID 唯一语义。实现统一先取得该 key ID 的事务级 advisory lock，再按固定顺序检查两表；登记、complete 和 rotate 所有新增 key 的入口都遵循同一规则。使用确定性的带命名空间锁键，哈希碰撞只降低并发，不能跳过唯一性检查。

### 4.3 创建、重试、完成与查询

1. 验证输入/public JWK、租户和配置 client；执行准入，取得可信 scope。
2. 开启既有身份事务，持有 state/tenant 锁并读取服务时间；该租户锁串行化同租户登记请求，新增登记在插入设备后取得 key ID 预约锁。
3. 若已有同请求，设备 ID 或其他内容不同则冲突；内容一致则返回同一个 device ID、登记完成时间及当前安全状态，不再次延长期限、不创建第二台设备、不重新激活。
4. 若不存在，检查设备 ID 和 key 均未被占用/预约，同事务写 pending 设备和登记记录。并发唯一性冲突不能回报为成功的新设备。
5. complete 使用现有注册 V2 证明，先锁设备，再锁登记、key 预约与 nonce；核对 pinned 公钥、登记期限及 pending 状态；完成、key 插入、nonce 消费、版本增加同事务提交。预登记公钥不代表已经持钥或激活。
6. 激活响应丢失时，通过受准入保护的登记结果查询，或同请求 provision，读取 `completed_at` 与当前状态。不得重放已消费挑战来查询结果。pending 且未过期时可申请新挑战继续；disabled/revoked/expired 不自动修复。

同请求完成后又被停用，结果必须同时表达“曾完成登记”和“当前 disabled”，不能只返回缓存的 active。登记已过期、尚未完成时不能延长期限或复用 request ID 开始新身份；新登记使用新 request ID 和新密钥。登记 challenge 的可授权资格也核对未过期登记记录，过期/不存在仍返回同形的不授权挑战。P0 不增加后台清理服务：过期记录保留，complete 按期限拒绝；管理员可撤销遗留 pending 身份。

登记结果只包含 tenant/client/device、登记及当前设备状态、key ID/版本、时间和版本，不返回 scope、准入凭据、签名或挑战。所有返回 `no-store`。

## 5. 密钥轮换与结果恢复

### 5.1 P0 当前及指定密钥元数据

设备详情增加 `key_version`；增加受控的指定 key 元数据查询，字段为 tenant/device/key ID、algorithm、version、status、registered_at、retired_at，**不返回 public JWK**。

- 管理入口沿用 ManageDevices。
- 自助入口要求有效人员会话、同 tenant/client、本人当前 active 绑定；不接受仅凭 key ID 查询。不要求查询一定使用旧 key 证明：人员身份验证与设备关系复查已经建立读取资格。
- 有效会话仍必须经过当前 device/key/binding 状态检查；设备被停用、撤销或本人已解绑时，自助查询拒绝，由有权管理员查询。
- 返回存储记录必须再次校验 tenant/device/key，其他设备或租户的 key 按未找到处理。

### 5.2 轮换流程

`RotateTenantDeviceKey` 增加 `expected_key_id`、`expected_key_version`，HTTP 同名字段。Core 从锁定当前 key 推导下一版本；客户端预期值只能用于断言，不能决定存储版本。继续使用当前 V2 双签名字节，其中已包含 old key ID、new key ID 与 next version；不新增签名协议。

在事务中重新验证会话、绑定、预期 key、目标 key 从未被其他设备使用/预约、双签名及 nonce。插入新 key、退役旧 key、device version+1、nonce 消费和 `device.key.rotate` 审计同事务完成。登记预约中的本设备初始 key 允许 complete 使用；轮换不得复用任意已使用或已预约 key。同设备的登录/refresh 与轮换保留现有锁序，轮换不撤销有效人员会话，但后续证明必须使用新 active key。

响应丢失后查询 proposed key 的元数据：

| 结果 | 解释与下一步 |
| --- | --- |
| proposed key 已属于目标设备 | 此 key 曾成功安装；若 retired，说明之后又轮换/撤销，不得当成当前可用 |
| proposed key 不存在，旧 key 仍 active | 尚未观察到成功提交；原请求可能仍在处理。只在重新核对后用新挑战及同一预期 old key 重试；锁和唯一性保证不会重复安装 |
| 设备或绑定不可用、当前 key 非预期 | 停止自动重试，返回明确拒绝或交管理员核对 |

密钥安装元数据与已有审计足够恢复轮换，不增加轮换任务表或复用旧签名的幂等缓存。管理员不能上传新公钥覆盖 active key。

## 6. 管理操作与自助解绑的并发、幂等

### 6.1 操作标识与版本

enable/disable/revoke、管理员解绑、自助解绑均要求 `operation_id`（canonical UUID）和目标 `expected_version`；管理操作另要求非空原因（1–512 字节，拒绝控制字符）。自助解绑可使用固定的 `self_service` 原因，不要求新的人机流程。

`operation_id` 与现有 `AccessAdminContext.request_id` 分开：前者是一次用户意图的稳定关联键，后者是每次传输的审计追踪 ID。二者都不是凭据。

复用 `access_audit_events` 的事务日志作为这些操作的成功回执，新增 nullable `device_operation_id uuid`、`device_command_sha256 bytea`；两字段同空或同非空，摘要 32 字节；唯一索引为 `(actor_domain, actor_id, target_domain, device_operation_id) WHERE device_operation_id IS NOT NULL`。只有本节列出的设备命令填写，其他管理操作保持 NULL。

摘要由 Core 使用现有 SHA-256 对固定版本标识及长度前缀字段编码生成：操作种类、目标租户/device/binding/account、expected_version、原因；不包含会话 ID、传输 request ID、时间或 JSON 格式。规范化规则及固定向量必须进入测试，禁止拼接有歧义的分隔字符串。

### 6.2 事务顺序

1. 锁既有管理作用域或自助账号作用域，按当前时间重新认证、授权。
2. 在当前 actor/目标域内读取 operation ID；已有相同摘要时返回原审计回执，不再检查旧版本并重做动作；不同摘要返回 `device_operation_conflict`。
3. 新请求读取准确目标，核对 tenant/device/binding、expected_version 和合法状态。
4. 更新状态/版本、撤销指定范围凭证、写审计及操作关联，同事务提交；失败全部回滚。

操作回执含 operation ID、audit ID、对象 ID、执行时间和**提交当时**的结果版本/状态；它不是当前状态，界面仍需重新加载详情。同一意图只能有一次状态变化与成功审计。

每次重试或查回执都重新认证授权。原管理会话或自助会话若因本次操作失效，不得凭 operation ID 绕过认证；可在取得新的合格会话后核对。同一个账号新会话可以查自己的回执。普通设备管理者不因此获得完整审计读取权；专用回执返回最小字段，完整审计仍要求 ReadAudit。

成功回执随安全审计保留，P0 不增加 TTL 清理。若未来有审计归档，须保留唯一键/摘要的防重墓碑，否则不能声称原幂等保证继续成立。

查询不到回执只表示当前快照未见已提交结果，不证明请求没有在途。使用原 operation ID 重试；不能换 ID 无条件再执行。自助解绑即使后来重新登录生成新 binding，也只能返回旧操作结果，不能解绑新的 binding。

## 7. 会话失效与审计

### 7.1 凭证清理范围

| 操作 | 凭证范围 | 其他效果 |
| --- | --- | --- |
| disable/revoke | 目标 tenant/device 的所有人员、所有相关会话 | session active/pending→revoked；相关 refresh 标记撤销；删除 source_session 授权码；撤销相应来源的选择票据；删除该设备 nonce |
| 管理员/自助解绑 | 目标 tenant/account/device 的相关会话 | 同样清理对应 refresh、source code 和 source selection；不删除设备级 nonce，以免影响其他用户 |
| enable | 不恢复任何凭证 | 清理残余 nonce，保留当前 key 和各 binding 状态；要求之后新登录 |
| rotate-key | 不撤销人员会话 | 旧 key retired；旧 key 的在线证明拒绝；其他设备不受影响 |

事务必须显式清除/撤销关联的 source code/selection，不只依赖之后的 session 检查。禁止只清 refresh、不清 session。已有全账号、租户成员移除和全设备撤销路径都要纳入副作用审查。

### 7.2 审计写入

- 管理启停/撤销/解绑沿用 `AccessAuditEvent`，新增 `device.enable`、`device.binding.unbind`，已有 disable/revoke 名称保留。`target_business_id` 为 NULL，不填宿主业务。
- 人员证明登录创建绑定、密钥轮换、自助解绑通过身份事务追加同一张审计表，使用真实 account/session、固定 `authentication_source=device_session`，不得构造 management 身份或调用管理 execute 绕过授权。新增 typed secret-free 事件投影和事务方法；管理读取规则保持。
- 登录审计使用本次新建会话 ID，绑定、会话与审计同事务；恢复/重试不能生成假登录记录。轮换和自助解绑使用已验证的当前会话，即使随后撤销仍保留历史引用。
- 无账号的 provision/complete 使用 `device_registrations` 的可信准入范围、不可变公钥引用、创建/到期/完成时间作来源记录。P0 不放宽现有管理审计 actor 非空约束，也不引入伪造机器账号。登记结果仅供同一可信准入范围查询；管理详情只显示设备登记时间。
- before/after 仅含标识、状态、版本、时间和原因；不得把整个 domain record 自动序列化为审计。私钥、证明、挑战、token、refresh 摘要、准入凭据、公钥原文均不进入普通日志和审计。
- 认证失败仍使用安全错误与现有诊断路径，不为每个失败创建持久“失败任务”；审计写失败必须使对应成功变更回滚。

## 8. Core 与存储契约

在既有 `CoreTenantDeviceProofService`、`CoreTenantDeviceAuthenticationService`、`CoreAccessAdminService` 上增加方法/命令，不平行实现第二套规则。

| 位置 | 增量 |
| --- | --- |
| `TenantProofDevice` / 管理与自助投影 | device version、当前 key version；自助投影增加 binding ID/version |
| `TenantDeviceAdmission` | 接受完整登记请求和可信上下文，验证其中的登记 scope；无隐式默认准入 |
| `TenantDeviceLifecycleTransaction` | 登记查找/锁/插入/完成、key 预约互斥、元数据读取、同事务身份审计；激活/轮换更新 device version |
| `TenantDeviceManagementTransaction` | 按 binding ID/version 定向解绑和完整凭证清理；本人操作回执读取 |
| `TenantDeviceService` | 可靠 provision、registration_result、key_metadata、精确 unbind、self_operation_result |
| `TenantDeviceAdminService` | binding 列表/详情、key 元数据、device_operation_result |
| `AccessAdminMutation` | `SetDeviceStatus` 替换 expected_status 为 expected_version 并增加 operation_id/reason；新增定向解绑命令 |
| `AccessChange` / `AccessAuditEvent` | 增加 typed binding/key 变更与可选设备操作关联；secret-free 投影保持 |

表结构除第 4、6 节外：`devices.version`、`account_device_bindings.version`；`devices` 增加 `(tenant_id,id,client_id)` 唯一约束以支持登记复合 FK；保留 key 全局唯一、设备最多一个 active key、绑定非 unbound 部分唯一索引。身份 key 的 retired 不等于设备 revoked，读取要同时返回两个事实。

### 8.1 锁顺序与时间

保留当前管理员 state 锁（按现有 `exclusive_state` 选择 share/update）→排序后的 tenant 排他锁→排序后的 account 锁。Postgres 身份事务入口持 state 共享锁，服务按操作需要取得 tenant 共享锁和 account 锁，再沿该路径取得 device/key/binding/challenge 等锁；这里不是要求所有认证操作锁同一组行。会话读取及跨租户 source-device 快照保留现有实现，不能机械增加反向行锁。不得为了新功能减少现有租户锁范围。

- 管理端先授权再修改，租户排他锁与认证事务的共享锁互斥。定向解绑的目标 account 加入现有排序 subject_ids。
- 自助解绑与同账号登录/refresh 共用账号锁，再锁精确 binding；批量设备撤销只经管理锁路径，不在普通认证事务中反向取得所有用户账号锁。
- 登记首次创建：tenant→新设备插入→key advisory lock→登记插入；已存在请求只读其结果并锁定本设备。complete：tenant→device→registration 读取→nonce→key advisory lock；当前轮换路径为 account/device→current key→binding→challenge→proposed key advisory lock。占用检查只在 advisory lock 下读取其他设备 key/预约是否存在，发现即冲突，禁止 `FOR UPDATE` 锁另一个设备的 key。首次创建持 key 锁期间不得尝试锁已有 device，避免与 complete/rotation 倒序。必须以当前 `access/*` 路径并发测试证明锁序，不能引用 legacy 单域实现代替验证。
- 设备安全版本只在设备锁/条件更新内增加；binding 版本在精确绑定行更新。SQL 除版本条件外继续包含租户与对象 ID。
- 所有可能等待的锁取得后，读取注入 `Clock`；据同一 now 重验会话、挑战、登记有效期并写时间。等待锁前的时间不能用于通过过期验证。
- PostgreSQL DB 时间不是第二个授权时钟；所有写入/审计/回执以服务时间为准。保持“除已确认 refresh reuse 外，安全错误回滚”的现有原则。

## 9. HTTP 契约

以下为本分支模块本地路由，保留既有根路径。管理目标租户沿现有可信管理选择契约；自助租户来自认证会话。Body 中 tenant 只用于登记/现有完成协议且须经过准入与策略校验，不能选择管理权限域。

| 路径 | 请求/结果 |
| --- | --- |
| POST `/devices/provision` | tenant_id、device_id（canonical UUID）、registration_request_id、device_name、public_jwk；可信准入上下文由扩展注入；返回登记结果，重复返回同身份 |
| POST `/devices/registration-result` | tenant_id、device_id、registration_request_id；同准入校验与 scope，设备 ID 必须与登记记录一致；返回完成事实和当前状态；不接受 public key 替代准入 |
| POST `/devices/complete` | 保持现有字段；新增 pinned key/登记有效期检查，成功返回 key 元数据及 device version |
| POST `/devices/rotate-key` | 原字段 + expected_key_id、expected_key_version；成功返回安装 key 和 device version |
| GET `/devices`、`/devices/:device_id` | 原有本人列表/详情，增加 device/binding version、binding_id、key_version；本人列表原分页不顺带改造 |
| GET `/devices/:device_id/keys/:key_id` | 本人 active 绑定范围内 key 元数据，不含 JWK |
| POST `/devices/unbind` | device_id、binding_id、expected_version、operation_id；返回最小回执，替代原 204 |
| GET `/devices/operations/:operation_id` | 当前有效人员在当前租户内自己的自助操作回执；不需目标绑定仍 active，不允许读取他人或管理操作回执 |
| GET `/admin/devices`、`/admin/devices/:device_id` | 原列表/详情，增加版本和当前 key 元数据；保留设备登记时间 |
| POST `/admin/devices/:device_id/enable`、`/disable`、`/revoke` | expected_version、operation_id、reason；返回最小回执 |
| GET `/admin/devices/:device_id/bindings` | 状态筛选、limit/cursor/sort_order；返回绑定元数据，无账户凭证 |
| GET `/admin/devices/:device_id/bindings/:binding_id` | 绑定详情，所有状态均可读，含历史 unbound |
| POST `/admin/devices/:device_id/bindings/:binding_id/unbind` | expected_version、operation_id、reason；目标账号由绑定记录取得，不接受另一个 account 覆盖 |
| GET `/admin/devices/:device_id/keys/:key_id` | ManageDevices 范围内 key 元数据，不含 JWK |
| GET `/admin/devices/:device_id/operations/:operation_id` | 当前管理操作者自己的精确目标操作回执；他人操作使用现有受 ReadAudit 保护的审计入口 |

设备管理权限仍为 Enabled 的 `idp.tenant::devices.manage`；平台显式目标沿现有 `idp.platform::access.manage` 映射。Disabled 使用 0；Enabled 设备不在平台 0 注册。ReadAudit 仍独立，不因 ManageDevices 自动开放整份审计。

管理绑定列表默认 50、上限 200，默认 desc，支持 asc；稳定键 `(bound_at_epoch,id)`，游标绑定 tenant/device/status/sort_order。换条件或方向必须重新分页。不增加总数扫描或心跳排序；现有设备管理列表继续现行时间/ID 排序。

HTTP 继续 16 KiB 上限、拒绝重复/未知字段、单个合法认证头、no-store。新响应数值沿已有客户端安全整数校验；bigint 超 JS 安全整数不能静默截断。静态 `/devices/operations` 与参数路由须有明确路由测试，不依赖声明顺序猜测。

### 9.1 错误与披露

| 条件 | 已建立合法访问上下文后的结果 |
| --- | --- |
| 非法 UUID/JWK/字段/版本 | 400，稳定输入错误，不返回原始值 |
| 无有效认证/缺准入 | 401 或现有安全拒绝；缺少可信准入扩展不得默认放行 |
| 无管理权限/跨租户/会话或绑定无效 | 沿现有 401/403 与安全证明错误映射；授权前不泄露目标存在性 |
| 授权范围内目标不存在 | 404 |
| expected_version / expected_key 不匹配 | 409 `device_version_conflict` / `device_key_conflict` |
| 同操作或登记 ID 内容不同 | 409 `device_operation_conflict` / `device_registration_conflict` |
| 非法状态转换 | 409 `device_state_conflict` |
| 登记超过有效期 | 合法登记查询返回登记到期时间与当前状态；持钥完成以安全证明拒绝映射，不向无权调用者透露状态 |
| key 已占用 | 409 通用登记/密钥冲突，不返回其他 tenant/device |
| 存储/内部故障 | 现有可用性错误，不伪装成权限不足 |

公开 challenge 接口保持已知/未知/不合格设备同形响应；同请求关联不会放宽挑战重放和 refresh reuse 策略。特定错误只在允许披露的上下文中返回，不能把上表全部公开给匿名调用者。

## 10. IDP 管理端及 TypeScript

在现有 `web/management/devices.tsx` 列表/详情内增量增加：

- 有 active key 的 disabled 设备显示“重新启用”；没有 key 明确显示不能启用、可撤销原因；revoked 保持终态说明。
- 状态操作显示影响范围、填写原因，产生一次 operation ID 并保存至该操作完成/明确取消核对；网络失败先查询结果及刷新详情，不能自动换 operation ID。
- 详情展示 device version、当前 key 版本和设备登记时间；人员绑定区分页展示 active/suspended/unbound，解绑以 binding ID/version 提交。
- 客户端核对操作回执后重新读取详情；页面展示当前状态，不用旧回执覆盖后续管理结果。
- 保留焦点恢复、键盘操作、文字状态和错误提示；提交中防重复操作；不增加图表、设备在线判断或后台定时轮询。

管理客户端严格校验 tenant/device/binding/key/版本及分页作用域；遇到不符返回协议错误。设备登记与签名证明由宿主接入现有 HTTP 契约；本轮没有扩展 `web/embedded/client.ts`，也不在浏览器保存私钥。参考 app 只负责装配及已有开发准入。

## 11. P1 历史公钥

在 P0 元数据读取基础上增加管理端 `GET /admin/devices/:device_id/keys` 分页列表，以及 `GET /admin/devices/:device_id/keys/:key_id/public-jwk`。要求 ManageDevices，同事务核对目标域和设备；分页按 `(version,key_id)`，支持方向并绑定游标。JWK 只在专用端点输出、no-store，不进入普通列表/日志/审计。

返回历史公钥及 recorded lifecycle（注册/退役时间、key status、device status）；这些时间表示 IDP 的状态变更时间，不证明某条离线内容在何时签名。本期不新增 `valid_at` 查询或 `historically_authorized=true`。保留现有 `DeviceSignatureVerifier` 作为密码学原语，不增加接受任意大载荷的公共验签服务。

P1 不新增表、不修改管理角色默认分配。若将来要求更细的公钥读取管理权限，需独立需求，不在本期预置。

## 12. 后置 DEVICE 主体

不在 P0/P1 实现独立机器认证。后续必须单独确定：主体类型、无需人员的信任来源、用途/audience、重放防护、密钥和撤销检查、结果类型、错误披露、是否需要令牌以及资源上限。

任何后续方案不得把 DEVICE 伪装为 account、不得给其人员角色、不得复用人员 refresh 绕过账号状态；设备结果不携带 business_id。P0 的登记结果查询不是机器会话，也不能用作资源请求认证。仅在独立协议和验收设计完成后才可排实现。

## 13. 数据迁移与兼容

本方案新增必填登记/版本字段并改变解绑响应，是破坏性设备接口及 Core 契约变更；正式里程碑版本为 3.0.0。该生命周期步骤引入 `tenant_v4`，当前版本另包含扫码 v5/v6，运行要求 `tenant_v6`；保留旧 SQL 的历史含义，完整升级见[统一手册](device-scan-login-upgrade.md)，v3→v4 撤销规则见[生命周期步骤](device-identity-lifecycle-upgrade.md)。

### 13.1 显式 v3→v4 迁移

迁移只通过离线命令执行，不由 app 启动自动升级：停写所有身份入口→验证备份→验证 v3 布局和模式→dry-run→显式 apply→只读结构与代表性身份检查；升级 3.0.0 时继续统一手册的 v5/v6 步骤和启动验收后才恢复服务。

1. 新增设备/绑定版本，现有行设为 1，作为新版本起点，不伪造既往修改次数。
2. 建立登记表及约束、设备复合唯一约束、审计操作关联列和索引；旧审计操作关联为 NULL。
3. 旧 active/disabled/revoked 设备保持密钥、绑定、会话及状态，不伪造登记 request ID 或准入来源；旧设备不能通过登记结果接口取得不存在的登记记录。
4. 旧 pending 和无 key 的 disabled 设备无法满足 pinned 登记公钥契约，只在 apply 事务中明确撤销，列入 dry-run 数量及 ID 清单；dry-run 不修改状态。按设备 revoke 的完整范围清 session/refresh/source code/source selection/nonce 和非 unbound 绑定，增加设备/受影响绑定版本；即使理论上不应有凭证，也不省略清理。不从未知值推导预期公钥。若查出 pending 已有 key 等非法状态，阻断而非强行处理。
5. 校验 active 设备恰有一个匹配 active key、revoked 没有 active key/有效绑定、跨租户外键成立。异常数据阻断迁移，不自动修复或提升身份。
6. 保留现有 unbound 历史、suspended 绑定；不重新绑定账号，不改变角色/业务权限、token/JWT/proof 格式。
7. 校验完成后在同一迁移事务写 `tenant_v4` 标记，使用迁移锁；重跑只验证已完成结构，不重复撤销/审计。

迁移审计沿既有 offline_migration 机制增加专用操作 `access.migrate_device_lifecycle`，需同步审计 CHECK 约束。组合固定为：有效平台管理员的真实 `actor_id`、`actor_domain=0`、`actor_session_id=NULL`、`authentication_source=offline_migration`、`target_domain=0`、`target_business_id=NULL`。迁移命令验证账号及平台成员/管理权限，不创建操作者。每个受影响设备独立一条变更记录，change 内含其真实 target tenant/device、前后版本/状态和各凭证清理数量；另记 schema 升级汇总，避免把无限设备清单塞入单个事件。它们与 DDL、撤销及版本标记同事务提交；失败无部分清理，重跑无重复审计，不借用旧业务迁移 operation 名称。

### 13.2 切换与回退

- 新二进制只接受目标 schema；旧二进制拒绝 v4。更新 schema 检查、所有 SQL 版本字面量、初始化脚本、测试数据和 readiness；不能只改一个常量。
- 旧 provision、仅 expected_status 的管理写入、旧自助解绑 body 明确拒绝，不提供降级写路径；其他未涉及的登录/OIDC/业务授权协议保持原语义。
- 迁移提交前可事务回滚。提交后禁止直接启动旧二进制；正常采用向前修复。恢复备份必须停机，并说明会丢失备份后的状态及可能复活已撤销凭证；不能将其宣传为无损回滚。
- P0/P1 分开验收；P1 只增加受控读接口，不再次迁移 schema。新字段/新路由在文档、客户端、管理端全部同步后才算交付。

## 14. 验收矩阵

| 编号 | 必须证明 |
| --- | --- |
| D01 | Enabled/Disabled 均通过；跨 tenant/client 的登记、读取、绑定、操作结果、key 查询被拒绝 |
| D02 | 同登记请求并发/响应丢失/重启返回同 device；同 ID 不同内容冲突；无准入或伪造 scope 无读取权 |
| D03 | 预登记 key 与 complete key 不同拒绝；无效签名不消费 nonce；过期登记不能激活；预约/历史 key 不可跨设备复用 |
| D04 | disable→enable 后旧版本请求失败；同 operation ID 返回旧结果但不重复变更；新 ID 重做同目标状态明确冲突 |
| D05 | enable 仅允许有合法 active key 的 disabled；旧 session/refresh/code/selection 不复活；旧 nonce 无效 |
| D06 | revoked 永不可恢复；旧 active/retired key 与其他租户 key 不能绕过；无 key 的 disabled 不能 enable |
| D07 | A/B 共用设备，只解绑 A 的精确 binding；B、其他设备与其他租户保持有效；A 原凭证全部失效 |
| D08 | A 解绑后新登录生成新 binding；旧 operation/旧 binding ID 重试不触及新绑定；suspended 无法自助绕过 |
| D09 | 解绑/撤销与并发 login/refresh/OIDC exchange/tenant selection 有确定序列，不产生撤销前凭证的复活 |
| D10 | 轮换双签名/版本/key 预约/nonce 一起校验；并发轮换至多一个成功；旧 key 不再发起请求 |
| D11 | 轮换响应丢失可查询 proposed key；后来再轮换或撤销仍可区分曾安装与当前可用；查询不到不自动认定未执行 |
| D12 | 操作回执须重新授权；不同 actor/tenant/对象不能读；原会话已失效不凭 operation ID 越权 |
| D13 | 审计/回执写失败，状态/版本/凭证/nonce 全回滚；同 ID 不同摘要不产生副作用 |
| D14 | 管理权限、普通业务权限、ReadAudit 独立；business_admin 不获得设备身份管理权 |
| D15 | HTTP 重复/未知字段、超大 body、非法版本、旧 DTO、错误路径/证明头均拒绝；错误不枚举设备或泄露密钥/令牌 |
| D16 | 新分页游标绑定筛选/方向/目标，无重复漏项；Web 拒绝串域 DTO；未知结果可恢复并正确展示版本 |
| D17 | v3→v4 dry-run 不写；apply 撤销明确列出的 legacy pending/no-key disabled 并清全部关联凭证；真实迁移 actor/domain/session 组合与逐设备审计可落库；既有有效身份保留；错误布局/约束阻断；DDL/清理/审计失败整体回滚，重跑一致 |
| D18 | 原 refresh reuse、Cookie 与显式令牌、OIDC、租户授权和九组设备证明向量保持通过；无业务维度协议扩展 |
| H01 | P1 历史 JWK 精确归属、权限及分页；retired key 可读取但不能认证；不返回“历史业务有效”结论 |

单元/HTTP/实库/管理页面验证分别在[实施计划](device-identity-lifecycle-implementation-plan.md)归档。源码审查不代替上述运行证据。

## 15. 初始实施时的跨文档审查记录

| 文档/契约 | 本轮关系 |
| --- | --- |
| README、overview | 当时标明 tenant_v4 切片及 2.0.0 的 tenant_v3；当前已更新为 3.0.0 / tenant_v6 与统一升级入口 |
| business-domain-authorization-design-v1 | 保持“设备/会话不强加业务标识”及业务管理员不获得 IDP 管理权，无冲突 |
| tenant-role-permission-design-v1 的设备实施补充 | `expected_status` 仅是 2.0.0 历史契约；本分支使用版本与回执契约 |
| production-security 两份文档 | 保留密码学、fresh proof、nonce、refresh 安全要求；新登记 pinned key 和版本控制是增量，不恢复旧证明格式 |
| host-integration-v1 / developer-and-integration-guide | 宿主集成文档已同步 IDP 接口、结构版本及参考准入契约；历史章节仍以原版本为背景 |
| react-ui-integration-design / 管理端 | 已同步管理客户端及状态说明；浏览器验收的剩余场景见实施计划 |
| tenant-access-execution-plan | 新计划单独标记分段实施；既有测试数字和发布记录不作为本轮验收 |
| 历史 device-model-v1 / schema 草图 | 不回写历史，不以旧模型决定新实现 |

本设计尚无依赖业务产品选择的阻塞项。发布版本号、代码基线与 schema 编号需在开始实施时复核；这不代表可以跳过迁移、协议回归或独立 DEVICE 主体设计。
