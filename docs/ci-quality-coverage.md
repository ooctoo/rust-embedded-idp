# CI目标与现有测试覆盖盘点

> 本文件保留P1接入前盘点。后续普通CI已接入独立integration/e2e入口，具体实现、本地结果和未验证项以[实施记录](ci-quality-implementation-result.md)为准；下文“未接入”指盘点时状态。E06已纳入固定首批六组，不再作为后续候选。

日期：2026-10-25。状态：按当前工作树只读盘点，未执行 live PostgreSQL 或浏览器验收。本文映射[CI质量设计](ci-quality-design.md)中的 I01–I06 和 E01–E06；它描述代码里已有的测试，不表示这些测试当前都已接入普通 CI。

## 当前执行入口

| 层 | 当前命令/入口 | 现状与边界 |
| --- | --- | --- |
| 构建与UT | [`ci.yml`](../.github/workflows/ci.yml#L14-L44)：`pnpm --dir web test`、`pnpm --dir web build`、`cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo test --workspace --locked`，另有 development-private-network-http 与 release HTTP transport 测试 | PR、main 和 `v*` tag 自动执行。Rust `#[ignore]` 的真实数据库集成不被 `cargo test --workspace` 执行。Web test 是 Node `node:test` 单元测试，不启动浏览器。 |
| PostgreSQL/HTTP集成 | [`run_live_postgres_checks.sh`](../scripts/run_live_postgres_checks.sh#L10-L27)：先检查显式 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI`，构建 Web，再以 `--ignored --nocapture` 运行 storage 和 app live 测试 | 脚本可复用，但当前普通 CI workflow 没有调用它，也没有配置 CI 专用 PostgreSQL 服务或 URI。缺变量会直接失败；不得把未运行或 ignored 测试算成通过。 |
| 浏览器E2E | [`n2-functional.yml`](../.github/workflows/n2-functional.yml#L87-L108) 的手动 N2 工作流执行离线工具检查、安装 Playwright/Chromium、准备隔离fixture并运行八套检查器；[`run_management_n2_ci.py`](../scripts/run_management_n2_ci.py) 管理 prepare/run/finalize | 这是手动专项，不是普通CI。下列浏览器检查器有可复用的真实页面操作和回归断言，但依赖私有 fixture 与 Playwright 环境，目前没有被 `.github/workflows/ci.yml` 调用。 |

Web 本地UT命令定义在 [`web/package.json`](../web/package.json#L7-L12)：`pnpm --dir web test` 覆盖 `management/client.test.mjs`、`management/navigation.test.mjs`、`embedded/client.test.mjs`；`pnpm --dir web test:embedded-bundle` 另测 bundle。它们是 API/client/navigation 逻辑测试，不是 UI 浏览器测试。普通CI中可复用的 Node/Rust现有检查仍按原入口运行。

## 集成场景 I01–I06

下面命令使用同一个显式脚本入口。指定某个 Rust 集成测试时，命令形式为 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI=<隔离测试URI> cargo test -p <crate> --test <target> <test_name> -- --ignored --exact --nocapture`；完整既有集合由 `./scripts/run_live_postgres_checks.sh disabled` 运行（脚本会加载开发环境文件，因此自动CI接入前须确认该加载行为适用于隔离runner）。本轮不运行这些命令。

| 设计项 | 已有真实测试与代码位置 | 层/命令 | 覆盖结论与缺口 |
| --- | --- | --- | --- |
| I01 初始化幂等、结构拒绝、保留宿主对象/配置 | `live_access.rs::access_initialization_is_atomic_idempotent_and_allows_host_tables`（`:172`）；`live_access.rs::device_credentials_stay_in_their_tenant_and_layout_damage_is_rejected`（`:588`）；`live_access_bootstrap.rs::bootstrap_initializes_both_modes_and_is_idempotent`（`:171`） | Postgres集成；完整脚本运行 storage `live_access`、`live_access_bootstrap` | 覆盖存储schema初始化、重复调用、宿主表保留、损坏布局拒绝和bootstrap幂等。没有证据表明这些 live 用例当前处置了所有配置/凭证覆盖组合；新入口应从这些场景里选最小合同集。 |
| I02 身份/租户/业务/用途隔离及 HTTP 拒绝 | `live_access.rs::access_sql_checks_exact_scopes_status_revocation_and_batch_order_in_both_modes`（`:281`）、`access_lists_page_without_cross_tenant_or_subject_data`（`:383`）；`live_access_tenants.rs::business_permissions_are_independent_per_tenant_and_archive_denies`（`:572`）；`live_reference_host.rs::reference_host_runs_management_and_business_flows_in_both_modes`（`:355`）、`browser_cookie_restore_logout_and_purpose_isolation_in_both_modes`（`:865`） | 存储+参考宿主真实HTTP集成；完整脚本运行 `live_reference_host` | 核心隔离和参考宿主用途隔离已有真实Postgres/HTTP测试。普通CI只运行非ignored工作区测试，不会运行以上用例。 |
| I03 会话创建、刷新、撤销、过期与并发 | `live_tenant_registration.rs::fixed_login_creates_bound_session_and_rechecks_current_state_in_both_modes`（`:487`）、`selection_rollback_and_concurrent_different_tenants_allow_one_session`（`:672`）、`http_login_selection_authentication_and_switch_use_real_postgres_and_rs256`（`:783`）；`live_reference_host.rs::browser_cookie_restore_logout_and_purpose_isolation_in_both_modes`（`:865`） | Postgres/HTTP集成；完整脚本分别运行 `live_tenant_registration` 和 `live_reference_host` | 覆盖真实数据库登录/选租户/session及Cookie恢复/退出。真实跨标签 refresh-lock 尚由浏览器专项验证（E06）；不是普通CI UT或当前工作区测试。 |
| I04 关键写入审计原子性、回滚与并发 | `live_access.rs::access_registration_and_database_constraints_keep_membership_atomic`（`:500`）、`database_serializes_concurrent_last_membership_removals`（`:549`）；`live_access_tenants.rs::tenant_state_version_cleanup_restore_and_audit_rollback`（`:336`）；`live_access_bootstrap.rs::bootstrap_rolls_back_directory_and_audit_failures`（`:257`）；`live_access_admin.rs::concurrent_last_tenant_security_admin_revocation_keeps_one_effective_admin`（`:718`） | Postgres集成；完整脚本运行相应 `live_access*` targets | 已有多项真实事务/并发/回滚合同；逐个写操作全覆盖不在本文声称范围。当前自动CI不执行这些ignored测试。 |
| I05 typed配置、管理资源开关、模块路由与参考宿主装配 | `composition_config.rs` UT（如 `policy_matrix_and_entry_collisions`（`:1508`）、`rejects_policy_paths_cookie_and_secrets`（`:1492`））由workspace测试执行；live宿主有 `explicit_management_only_is_read_only_at_startup_in_both_modes_and_mounts`（`live_reference_host.rs:1593`）、`explicit_optional_management_surfaces_respect_mount_and_authorization`（`:1644`）、`reference_host_refuses_uninitialized_or_wrong_mode_without_mutating_schema`（`:717`）；无租户消费者入口见 [`examples/no-tenant-host/run.sh`](../examples/no-tenant-host/run.sh) | 配置UT随 `cargo test --workspace --locked`；真实参考宿主集成通过live脚本；consumer build当前由 `.github/workflows/ci.yml:36` 执行 `./examples/no-tenant-host/run.sh build-web` | 配置解析/校验UT和consumer编译已经接入普通CI；真实模式、挂载、可选管理资源及启动读写边界测试仍ignored。consumer build只证明编译，不是运行集成。 |
| I06 migration/preparation工具输入、预检、保护与退出状态 | CI执行 `bash scripts/test_scan_login_migration_wrapper.sh`（`ci.yml:29`）、`bash scripts/test_scan_login_origin_closure_migration_wrapper.sh`（`:30`）；另有 `scripts/test_device_lifecycle_migration.sh`、`scripts/test_business_scope_migration.sh` | 离线shell/Node检查；可按 CI 命令执行前两项 | 已接入CI的migration wrapper测试是离线测试，不能证明真实PG迁移工具在隔离数据库上的全生命周期、备份/数据保护或错误清理。其余脚本不因此算作CI覆盖；首次接入前需逐个核查实际内容。 |

## 浏览器场景 E01–E06

检查器共享若干实现方式：Playwright `chromium.launch`、`browser.newContext`、角色/标签定位、API调用和网络路由拦截；测试通常从fixture中的 `hosts`、合成管理员密码和作用域数据启动。示例：[`check_management_clients.mjs`](../scripts/check_management_clients.mjs#L10-L33) 校验fixture schema并定义 `open`、`locate`、`save`；[`check_management_console.mjs`](../scripts/check_management_console.mjs#L16-L54) 还验证fixture目录及容器标签。它们要求 `IDP_UI_TEST_FIXTURE` 与锁定的Playwright路径；console/security也要求 `IDP_UI_BROWSER_EXECUTABLE`。这些fixture/helper不是通用E2E入口，尚未从N2 harness提取到日常CI job。

| 设计项 | 可复用检查器/具体断言 | 当前运行方式 | 覆盖结论与缺口 |
| --- | --- | --- | --- |
| E01 登录、错误凭证、身份恢复、退出失效 | `check_management_console.mjs:195-209` 验证错误密码、清空密码且不显示工作区；`check_management_navigation.mjs:32-62` 的 `open` 执行浏览器登录，`:117-124` 验证Cookie reload恢复，`:378-390` 验证另一标签退出清理旧工作区并重载回登录；真实Cookie恢复/退出/用途隔离另由 `live_reference_host.rs:865` 覆盖 | 浏览器脚本需N2 fixture；HTTP层由 live Postgres脚本显式运行 | 登录、Cookie刷新和跨标签退出组成部分已存在，且有真实HTTP层测试。缺口是这些脚本未接入普通CI，也没有单独针对“退出后重放旧Cookie/API访问必拒绝”的浏览器断言。 |
| E02 enabled/disabled与作用域配置查看 | `check_management_console.mjs:211-235` 用编译后的Rust资源走 `enabled`、`disabled`、`fixed`、`choose`；`check_management_navigation.mjs:307-331` 覆盖Disabled入口及Fixed/Choose目标边界；`check_management_clients.mjs:142-150` 覆盖模式列表和固定租户拒绝 | N2检查器，需fixture中的多个host和真实参考服务 | 代表性模式及作用域浏览器路径已存在。复杂排列/全配置组合不适合作为首批CI E2E；上述脚本未由普通CI调用。 |
| E03 代表性读取、写入和服务端回读 | `check_management_clients.mjs:142,192,211` 覆盖客户端列表、公开/机密客户端写入、重读；`check_management_authorization.mjs:262-299` 覆盖租户管理员、权限/角色和成员创建回读 | N2检查器连接真实参考服务；写操作前有确认UI，数据使用随机后缀/合成值 | 已有高质量真实服务写入及回读可复用。当前用例量明显大于“一个代表性客户端或权限”；CI应挑选最小正向路径而非整套授权检查。 |
| E04 危险操作取消/确认 | `check_management_clients.mjs:358-365` 检查取消脏状态、关闭确认与焦点恢复；`check_management_console.mjs:374-388` 检查创建权限确认取消且无写入；授权脚本 `check_management_authorization.mjs:262-291` 有确认后真实创建/保存 | N2检查器 | 取消无写与确认后真实写均有现成片段，但并非一个专门的“危险操作”最小场景；还需选定一个具有不可逆/高影响后果的具体UI动作，并明确一次写入和最终回读。目前不能声称E04整体已满足。 |
| E05 401/403/服务错误/未知写入恢复，不重放 | `check_management_clients.mjs:270-296,311-358` 覆盖注入403/500、畸形响应、真实POST后丢弃响应及禁止重放；`check_management_navigation.mjs:228-230,415` 覆盖丢失响应和401/403页面状态；`check_management_authorization.mjs:606-627,816` 覆盖错误状态及提交POST后注入响应丢失 | N2 Playwright检查器；部分网络失败通过 `page.route` 注入。不是实际网络故障或外部服务可用性验证 | 客户端错误态及unknown-write恢复很充分，可择一个最小高价值断言。注入的断线只模拟浏览器观察到的响应丢失；服务端真正提交与回读要依赖所选案例的代码，不能概括为真实网络故障演练。 |
| E06 双标签刷新协调和独立退出 | `check_management_n2_mac.mjs:70-96` 验证多个入口Cookie会话隔离及退出；`:140-156` 用两个真实标签、实际服务端refresh并发计数验证Web Locks最多一个并发refresh；`check_management_navigation.mjs:390` 有跨标签退出清工作区 | 现有浏览器专项；N2执行器通过`run`阶段调度，并非普通web测试命令 | 有真实浏览器/参考服务的高价值回归，可直接复用。需fixture多入口/短时钟控制等准备，不属于单页面轻量E2E；普通CI当前未运行。 |

## 最小接入建议（供实施阶段确认）

1. 先接入I01–I05中最能代表真实PG/HTTP合同的既有ignored用例，优先复用 [`run_live_postgres_checks.sh`](../scripts/run_live_postgres_checks.sh) 的命令集合；把自动runner与开发`.env`加载彻底隔离后再接workflow。I06先保持已存在的离线wrapper检查，若仍需真实数据库验证再单独挑选，不复制全套迁移回归。
2. 浏览器E2E优先组合E01、E02一条作用域路径、E03一个写入回读、E04一条取消/确认、E05一条unknown-write恢复。E06成本更高，已有专项场景可后续纳入最小E2E job；具体实现前检查fixture能否单独建立/清理，不把八套N2整套搬进日常CI。
3. 新workflow接入前，补齐每个选中案例的固定测试名、独立命令、fixture所有权/清理及“未执行不得通过”结果；目前没有环境变量就能安全独立启动上述浏览器检查器的公开CI命令。

本盘点没有运行测试，也没有证明当前任何live或浏览器专项在本工作树通过。实际CI应以执行SHA、job日志和清理结果记录为准。

## 本轮接入映射

- I01–I05：`scripts/run_ci_integration.sh` 在专属 PG 容器中，通过私有合成配置调用既有 live 入口；十个目标必须全部实际执行。I01新增 `schema_inspection_ignores_unrelated_concurrent_ddl`，验证其他schema并发DDL不破坏本目标结构检查及v6迁移重入。
- I06：保留两个离线迁移wrapper检查；`live_access`内的 `scan_login_migration`、`scan_login_origin_closure_migration` 实际验证历史版本迁移、幂等和失败回滚，初始化/preparation安全合同由live bootstrap/host测试覆盖。不声称所有独立迁移脚本、生产升级或备份恢复已验证。
- E01–E06：`scripts/check_ci_e2e.mjs` 为独立固定选集，分别覆盖身份、作用域、写入回读、撤销取消/确认、未知结果恢复、双标签刷新/退出隔离；由 `scripts/run_ci_e2e.py` 管理隔离资源。
- 当前结果与环境差异见[实施记录](ci-quality-implementation-result.md)；上述代码接入不等于远端job已通过。
