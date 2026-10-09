# 设备身份与安全生命周期：实施计划

初版：2026-09-28。本文保留生命周期 P0 的阶段计划和历史验证；3.0.0 已纳入该增量及后续扫码能力，当前要求 tenant_v6，升级与验收入口见[统一手册](device-scan-login-upgrade.md)。下文 v4 初始化、本机升级和测试数字仅对应当时切片，不作为当前部署状态。

设计依据：[详细技术设计 v1](device-identity-lifecycle-design-v1.md)。基线为 `b8e5d1648de861b5308ed24b9e7be05fafc15f72`。本文件只安排 IDP 仓库内工作，不包含宿主接入、终端应用、业务授权配置或现场验收。

## 1. 交付原则

- 主代理负责边界、公共契约、迁移和锁序决策；实现工作只能在契约明确后按非重叠模块拆分。每个候选变更都必须复核实际 diff。
- 先 Core 契约和最小规则测试，再存储、HTTP、客户端与管理 UI；不能先露出 HTTP 功能再补领域规则。
- 依赖最少：复用现有 UUID、SHA-256、Ed25519、事务、审计、分页和 Ant Design，不新增消息队列、后台任务框架或通用幂等服务。
- 所有阶段默认未完成。文档审查、测试编译、离线测试、真实 Postgres、真实管理页面分别记录，不相互替代。
- P0 可拆多个审阅提交，但整体迁移、协议、客户端与验证未完成前，不发布任何要求用户升级的中间版本。

## 2. 阶段与依赖

```text
S0 契约冻结
  → S1 Core 状态、版本与回执规则
  → S2 存储、锁、审计与迁移
  → S3 登记/轮换/绑定身份链路
  → S4 Axum、参考服务与客户端
  → S5 IDP 管理端
  → S6 集成验证、文档和发布准备

P0 验收完成 → H1 历史公钥受控读取（P1）
独立需求确认 → M0 DEVICE 主体协议设计（不属于 P0/P1 实现）
```

S1–S3 可以通过小范围纵向切片迭代，但不得把未实现的 store trait 临时实现为放行或默认空数据。独立的 Web DTO 测试准备和迁移测试数据准备可并行；同一 `admin.rs`、DDL 或认证事务不要并行修改。

## 3. 各阶段任务与出口

### S0：契约冻结与基线复核

**产物**：设计与实施分工确认、当前源码差异清单、固定 JSON/回执/错误案例。

1. 复核 HEAD、工作区变更、AGENTS 和当前安全文档；确认拟用 `tenant_v4` 未被占用。
2. 固定宿主提交 canonical 设备 UUID 的准入审核、register scope 的可信来源契约、注册请求关联规则、设备 ID/key 预约唯一性和锁次序。
3. 固定 enable 条件、pending 被停用后的处理、operation ID 与传输 request ID 区分、精确 binding ID/version 语义。
4. 固定管理授权、匿名登记记录、身份事务审计的差异；确认不会伪造管理会话。
5. 固定破坏性接口变更及迁移时 legacy pending/no-key disabled 的撤销清单规则。

**出口**：技术设计第 3–9、13 节没有互相矛盾的输入、状态或授权规则；所有新必填字段有来源、校验和恢复办法。这里只解决 IDP 技术契约，不添加业务字段。

### S1：Core 契约与领域规则

**主要文件**：

- `crates/embedded-idp-core/src/access/device_proof.rs`
- `crates/embedded-idp-core/src/access/device_proof/{lifecycle,management}.rs`
- `crates/embedded-idp-core/src/access/authentication/{device_login,device_transport}.rs`
- `crates/embedded-idp-core/src/access/admin.rs`、`access/admin/{devices,audit}.rs`
- `crates/embedded-idp-core/src/access/{query,authentication_tests,admin_tests}.rs`

**任务**：

- 增加 device/binding 版本、绑定详情和 key 元数据投影；定义登记请求与准入结果。
- enable/disable/revoke 的转换表和版本检查；typed mutation receipt、设备操作摘要与重复请求规则。
- 精确解绑及自助/管理权限区分；保持 unbound 后新 binding、suspended 不自动重绑。
- 增加存储 trait 所需的精确读写方法、同事务审计和回执查找，不实现数据库或 HTTP 规则。
- 身份事务内记录首次绑定、轮换、自助解绑；保持真实 actor/session 和 secret-free 审计。

**验证**：Core 窄测试覆盖 D02–D08、D10–D14 的领域部分；固定摘要向量、overflow、invalid store response 与回滚错误分类。

**出口**：内存测试能证明状态转换和副作用计划，现有认证/授权测试继续通过；没有 `business_id` 扩散到设备/会话契约。

### S2：Postgres、锁和迁移

**主要文件**：

- `crates/embedded-idp-storage-postgres/src/access.rs`
- `crates/embedded-idp-storage-postgres/src/access/{admin,authentication,device_proof,device_management}.rs`
- `crates/embedded-idp-storage-postgres/src/sql/tenant_v4.sql`
- `scripts/migrate_device_lifecycle.sh`、`scripts/migrate_device_lifecycle.sql`、`scripts/test_device_lifecycle_migration.sh`
- `crates/embedded-idp-storage-postgres/tests/access_admin/{devices,audit}.rs`
- `crates/embedded-idp-storage-postgres/tests/authentication/device_proofs.rs` 及其子模块

**任务**：

- 增加设计规定的列、登记记录、复合约束与部分唯一索引；保留 v3 历史 DDL。
- 登记请求及 key 预约事务锁；覆盖登记/complete/rotate 全部 key 写入入口，不出现只改一个 caller 的旁路。
- 所有设备状态/密钥变化更新 device version，所有绑定生命周期变化更新 binding version；包括已有批量撤销、成员移除路径。
- 区分 enable 与清理操作；定向解绑增加 source code/selection 清理。
- 审计操作字段与唯一回执、设备身份审计；对应写失败整体回滚。
- 更新 schema 版本常量、SQL 内嵌版本、布局检查、对象清单及 readiness。
- 显式迁移脚本提供 dry-run/apply、模式/指纹检查、备份与停写前置说明、失败回滚及重跑验证；迁移只操作指定 schema。

**验证**：D01–D13、D17 的真实数据库部分；两个独立连接制造并发，屏障协调，不依赖任意 sleep；注入审计失败和中途 SQL 错误验证原子性。

**出口**：空库 v4 初始化和 v3 升级都通过；原角色、权限和有效设备身份保持；新旧二进制 schema 不兼容被明确拒绝。没有实库环境时标记未验证，不能以编译通过结项。

### S3：身份链路纵向完成

**主要范围**：S1/S2 的登记、证明登录、rotate、unbind、refresh、OIDC source-session 检查相关真实路径。

**任务**：

- provision→complete→首次证明登录→会话/刷新→定向解绑完整跑通。
- 登记丢响应后查询/原请求重试；登记期限、pinned key 和相同 key 跨入口预约互斥。
- 轮换丢响应后通过 proposed key 元数据恢复；安装后又轮换/撤销，仍可区分历史结果与当前身份。
- 停用→恢复→新登录，新凭证有效且所有旧凭证/nonce 继续失效。
- 解绑 A→A 重新登录生成新 binding→旧请求重试，不影响新绑定；B 的凭证保持有效。
- 检查选择租户、OIDC 换码、浏览器 optional-device 与显式 proof 路径，没有旧凭证旁路。

**出口**：D03、D05–D11、D18；租户身份链路是主要验收路径，不能只测试遗留单域 `service/device_security.rs` 后宣称完成。

### S4：HTTP、参考服务与 TypeScript

**主要文件**：

- `crates/embedded-idp-axum/src/{tenant_devices,tenant_device_admin,tenant_device_auth,tenant_admin,audit_admin}.rs`
- `crates/embedded-idp-app/src/bootstrap.rs` 及装配/配置文件
- `web/management/client.ts`、`web/management/client.test.mjs`
- 设备登记与证明的宿主 HTTP 接入

**任务**：

- 按技术设计第 9 节增加/修改路由和 DTO；参数解析保持薄层，业务规则仍在 Core。
- 可信准入上下文注入、公开请求字段与可信 actor 的分离；请求扩展缺失拒绝，不用共享可变状态保存调用者。
- 新错误映射、16 KiB、unknown/duplicate 拒绝、no-store、路由冲突测试。
- 管理 Web 响应严格解析版本及 ID、作用域；操作 ID 跨网络重试保持不变；不自动重放 refresh 或旧证明。
- 参考服务保持生产准入默认拒绝，只同步开发开关和显式配置校验；不建设新的生产部署功能。

**出口**：D01、D12、D14–D16；旧写入 DTO 明确失败，管理/自助权限互不冒用；所有跨语言类型同步。

### S5：IDP 管理页面

**主要文件**：`web/management/devices.tsx` 及必要的现有客户端/样式文件。

**任务**：增加恢复操作、原因、版本、绑定列表/详情与定向解绑、当前 key 元数据和操作结果恢复。沿用原列表/Drawer/分页，不新增设计系统、图表、设备自助门户或硬件工具。

**验证**：真实参考服务的以下场景：

1. active→disabled→enabled 后，管理页面正确刷新并说明必须重新登录。
2. revoked、无 key disabled、无权限分别显示正确状态和不可执行原因。
3. 双管理员编辑、过期版本冲突，旧页面不能覆盖新状态。
4. 服务端已提交但响应断开，查询原 operation ID 后展示原结果和当前状态。
5. 两个人共享设备，仅解绑指定绑定；历史与当前绑定不混淆。
6. 键盘操作、焦点返回、文字状态、错误恢复、切租户/筛选后清分页及选择。

**出口**：记录实际浏览器验证及局限。DTO 单测/Web build 不替代页面验证；不要求本轮验证宿主 UI。

### S6：整体验收与发布准备

**任务**：

- 跑完整验收矩阵及必要性能检查：新增查询走相应索引，列表仍 limit+1，无全表 COUNT；确认新增锁没有反向获取造成死锁。
- 实际审查 diff：删去仅服务假想未来的抽象、可变全局状态、兼容层、配置与依赖；保留必要的安全与恢复逻辑。
- 同步 README、overview、当前设备接口文档、管理客户端说明、安全文档实施补充、CHANGELOG 和执行计划；新设计入口从“计划”改为真实状态。
- 记录最终版本、迁移命令、停写要求、旧 pending 处理、向前恢复及回退风险。具体命令以已实现且验证过的脚本为准。
- 代码提交和推送按实际任务执行；正式发布仍须完成生产验收。

**出口**：P0 的 D01–D18 全部有证据或明确未完成项；任何安全/迁移必测项缺失都不能标记 P0 完成。

### H1：P1 历史公钥

**依赖**：P0 已完成并稳定。

**范围**：Core 管理读取→Postgres 历史 key 查询→Axum 专用 public-jwk 路由→客户端/管理页受控展开。复用现有表；不建历史业务授权模型或在线任意载荷验签服务。

**出口**：H01 及相关 D01/D14–D16；旧 key 可读取但不能认证，公钥不泄漏进普通日志/审计；生命周期时间没有被解释成签名时间。

## 4. 验证命令与证据规则

先运行对应范围的窄测试，变更跨边界后再运行完整基线。以下是当前仓库可用入口；新增测试名在实施时补充，不在设计中虚构已运行结果。

```sh
cargo test -p embedded-idp-core --locked
pnpm --dir web test
node scripts/test_device_proof_vectors.mjs
cargo test -p embedded-idp-security --test tenant_device_proof_v2 --locked
```

完整离线基线（先 Web 后 Rust 参考服务）：

```sh
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
pnpm --dir web test:embedded-bundle
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
git diff --check
```

真实 Postgres 只在显式配置 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI` 时运行；使用临时 schema，不读取应用 URI 代替测试 URI：

```sh
./scripts/run_live_postgres_checks.sh disabled
./scripts/run_live_postgres_checks.sh enabled
```

`scripts/test_device_lifecycle_migration.sh` 使用临时 v3 schema 回归 dry-run、apply、重跑、异常数据阻断和审计失败回滚。现有设备管理 tests 嵌入 `live_access_admin`，设备身份 tests 嵌入 `live_tenant_registration` 的认证模块；许多实库测试带 `#[ignore]`，普通 `cargo test` 或 `--no-run` 不能证明它们实际运行。两模式脚本选择的是本地配置；测试内部也覆盖 Enabled/Disabled。

每个阶段记录 commit、检查命令、运行环境、通过/失败/未运行，以及与验收编号的对应关系。文件中不记录真实连接串、令牌、私钥或登记凭据。

## 5. 风险和停止条件

| 风险 | 处置/停止条件 |
| --- | --- |
| 可靠登记重试泄露别人登记结果 | scope 来自可信准入且每次重验；若当前 HTTP 注入无法保证这一点，先完成该契约，不用公共 request ID 顶替授权 |
| enable 导致旧凭证复活 | 保持撤销记录，不反转 session/refresh 状态；D05/D09 不通过则禁止交付 |
| 旧解绑误伤后来新绑定 | 精确 binding ID/version，操作回执去重；不得回退为只按 account/device 更新 |
| key 预约/轮换锁互相等待 | 明确共同锁序，真实并发回归；不能靠超时后重试掩盖死锁 |
| 匿名登记强塞账号审计 | 使用登记来源记录，不扩造用户；身份操作审计必须记录真实会话 |
| 迁移丢失历史或自动赋权 | dry-run、备份、停写、明确撤销清单；不自动修复孤立 key 或授权关系 |
| 为兼容旧 DTO 绕过版本检查 | 破坏性升级时明确拒绝；不增加隐式默认版本或 expected_status 降级 |
| 审计归档破坏操作去重 | P0 保留操作记录；归档另行设计防重保留，不静默缩短保证 |
| 范围重新扩展至业务/机器平台 | 本轮不增加 business_id/业务设备表；DEVICE 主体回到独立 M0 设计 |

## 6. 当前分支实施状态

- P0 代码已实现：可信准入登记与结果恢复、设备和绑定版本、恢复/停用/撤销、精确解绑、操作回执、密钥元数据、身份事务审计及认证路径复查。设备和人员关系仍只有租户与客户端边界；不引入业务设备表。
- 离线验证：Web 构建、83 项 Web 测试、Rust 工作区检查和测试、设备证明向量通过。两种租户模式的随机隔离 PostgreSQL schema 各通过 122 项实库测试；迁移回归覆盖 dry-run、apply、重跑、异常数据阻断及审计失败全回滚。代表性并发测试覆盖轮换、撤销与登录/refresh/OIDC 换码、解绑与切租户；这些不是全部可能交错的穷举证明。
- 管理浏览器已在隔离 schema 验证停用/恢复、无密钥设备和已撤销设备提示、版本冲突、指定人员绑定解绑。未完成断响应恢复、完整无权限场景及 Enabled 管理页面的浏览器验证。20,000 台合成设备的本地单次分页查询抽样不能作为生产性能承诺。
- 2026-09-28 本机维护窗口已停止 9100/9200 参考服务，将 `embedded_idp_disabled_v2` 与 `embedded_idp_enabled_v2` 各自备份并验证 archive 可完整解码、记录 SHA-256；停写后 dry-run 均无待撤销设备，再分别执行显式 apply。两套 schema 均为 `tenant_v4`，身份/权限/会话等行数保持，迁移审计各有汇总记录。新参考服务的 `/readyz` 为 ready、OIDC discovery 为 200、匿名管理设备请求为 401。由于没有现有管理员密码，这两套原有数据尚未完成带账号的真实登录及授权允许/拒绝验收；隔离实库参考服务已有相应测试。
- 生产交付仍需完成管理浏览器剩余场景、真实宿主接入及生产规模验收。P1 历史 JWK 和独立 DEVICE 主体不属于本轮。当前正式升级按[统一手册](device-scan-login-upgrade.md)执行；已完成 v3→v4 的 schema 不重跑该步骤，但仍须核对并完成后续 v5/v6。

## 7. D01–D18 证据索引

以下用例均在随机隔离的真实 PostgreSQL schema 中运行；`access_admin/devices.rs` 属于 `live_access_admin`，`authentication/device_proofs*` 属于 `live_tenant_registration`。HTTP/客户端/迁移测试各证明自己的边界，不以单元测试代替浏览器或生产负载。

| 项 | 证据与结论 |
| --- | --- |
| D01 | `http_device_queries_enforce_actor_client_tenant_cursor_and_admission`、`device_operation_receipt_replays_once_and_is_scoped_to_target`；两租户模式与跨域拒绝通过。 |
| D02 | `provision_and_registration_enforce_admission_and_activate_atomically_in_both_modes`、`concurrent_completion_has_one_winner_and_global_key_reuse_is_rejected_at_provision`、管理 HTTP 登记重试/查询；通过。 |
| D03 | 同一登记/完成实库用例及 `rotation_verifies_both_keys_preserves_old_authority_on_failure_and_retires_on_success`；无效证明、过期和 key 预约通过。 |
| D04 | `disabled_device_can_be_enabled_without_restoring_old_credentials`、`device_operation_receipt_replays_once_and_is_scoped_to_target`；通过。 |
| D05 | 同上及 `device_admin_http_is_scoped_and_disable_revoke_cleanup_is_atomic_in_both_modes`；旧凭证清理和新挑战要求通过。 |
| D06 | `device_admin_http_is_scoped_and_disable_revoke_cleanup_is_atomic_in_both_modes`、`revoked_device_cannot_complete_proof_login_in_both_modes`、`revoked_device_cannot_refresh_a_proof_bound_session_in_both_modes`；通过。 |
| D07 | `admin_unbind_cleans_only_the_exact_binding_and_rolls_back_with_audit`、`http_device_unbind_rolls_back_and_revokes_only_own_device_sessions_in_both_modes`；通过。 |
| D08 | 同一精确解绑用例和 `proof_login_binds_and_issues_atomically_in_both_modes_and_rechecks_device_authority`；历史/新绑定与 suspended 拒绝通过。 |
| D09 | `device_revocation_serializes_with_waiting_authentication`、撤销后登录/refresh、`device_revocation_committed_while_oidc_exchange_waits_prevents_issuance`、`source_unbind_committed_while_tenant_switch_waits_prevents_issuance`；代表性等待序列通过，未枚举所有交错。 |
| D10 | `concurrent_rotations_install_only_one_key_and_audit_once_in_both_modes`、轮换双签名与失败回滚测试；通过。 |
| D11 | 连续轮换/已退役 key 元数据与管理 HTTP 查询，客户端丢响应回执单测；通过，现场断线未模拟。 |
| D12 | `device_operation_receipt_replays_once_and_is_scoped_to_target`、管理 HTTP 实时授权测试；通过。 |
| D13 | 管理/自助解绑审计失败回滚、轮换及 refresh/OIDC 插入失败回滚、摘要冲突测试；通过。 |
| D14 | `device_admin_rechecks_tenant_grants_and_actor_device_authority`、管理/审计权限测试；通过。 |
| D15 | `tenant_devices`、`tenant_device_admin` 的 HTTP 拒绝用例和真实管理 HTTP 实库用例；通过。 |
| D16 | 设备/绑定分页实库测试、`web/management/client.test.mjs` 中跨域 DTO 与丢响应回执用例通过；管理页面已实测版本冲突及定向解绑，断响应浏览器场景待补。 |
| D17 | `scripts/test_device_lifecycle_migration.sh` 两模式临时 v3 schema 的 dry-run/apply/重跑/异常与失败回滚通过；本机两套原有 schema 停机备份后正式升级并保留数量、审计和 readiness 验证通过。 |
| D18 | `cargo test --workspace --locked`、两模式 `run_live_postgres_checks.sh`、Web 测试、九组设备证明向量通过；业务维度未进入设备契约。 |
