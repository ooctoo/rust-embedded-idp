# 管理员预建 schema 的表结构初始化设计与实施方案

日期：2026-10-29。状态：修订 2 已实施并完成本地验证及最终复审；实际结果和验证范围见[实施与验证记录](precreated-schema-initialization-result.md)。下文保留设计基线及验收要求。

目标是在数据库管理员已经创建、并授权给初始化账号的 PostgreSQL schema 中，初始化当前 `tenant_v6` 的完整 IdP 对象和必要的初始状态。初始化账号无需数据库级 `CREATE` 权限，也无需成为 schema 所有者。这里的管理员指数据库管理员，与后续离线创建的 IdP 系统管理员不同。

建议沿用 `PostgresStorageAdapter::initialize_access_schema`：目标 schema 已存在时跳过创建 schema；目标不存在时保留现有创建行为。这样可以支持受限账号部署，同时兼容现有开发环境和宿主调用，不增加配置开关或改变存储 API 签名。若后续要求“schema 必须预先存在，任何情况下均不得自动创建”，需要另行确定这一行为变更；它不是本提案的默认行为。

## 当前实现与问题

本次工作分支为 `codex/precreated-schema-init`，从同步后的 `main` 创建，基线为 `d19f93b`。以下分析以该基线为准。

当前调用路径：

1. `scripts/dev_env.sh <mode> db-init` 加载开发配置。
2. `bootstrap_local_postgres --access-schema` 读取连接、schema 和租户模式。
3. `PostgresStorageAdapter::initialize_access_schema` 开启事务并获取按 schema 隔离的迁移锁。
4. 若已有 `access_state`，校验结构、版本及模式后返回；否则先检查 IdP 表名冲突。
5. 执行 `CREATE SCHEMA IF NOT EXISTS`，执行 `tenant_v6.sql`，写入状态、系统域及传入的权限目录，然后提交。

主要实现位于 [access.rs](../crates/embedded-idp-storage-postgres/src/access.rs)，命令入口位于 [bootstrap_local_postgres.rs](../crates/embedded-idp-storage-postgres/examples/bootstrap_local_postgres.rs)。

当前代码已经允许同一 schema 中保留不冲突的宿主表，已有 [live_access.rs](../crates/embedded-idp-storage-postgres/tests/live_access.rs) 用例覆盖业务表保留、对象冲突和失败回滚。但这些用例没有证明“schema 由其他角色所有、初始化账号没有数据库级 CREATE”可以成功。

关键问题是 `CREATE SCHEMA IF NOT EXISTS` 仍然先检查数据库级 `CREATE` 权限，之后才判断 schema 是否存在。因此即使目标已存在，只有 schema 内授权的账号仍会失败。这一检查顺序见 [PostgreSQL 18 源码](https://raw.githubusercontent.com/postgres/postgres/REL_18_STABLE/src/backend/commands/schemacmds.c) 中的 `CreateSchemaCommand`；权限定义见 [CREATE SCHEMA 文档](https://www.postgresql.org/docs/18/sql-createschema.html)。

`tenant_v6.sql` 本身不创建 schema。表和函数的创建目标、表引用及触发器调用的函数均限定目标 schema；显式索引和约束使用 PostgreSQL 在关联表所在 schema 中创建的规则。修正集中在初始化编排，不需要重写建表 SQL。类型、内置函数和运算符仍有未限定名称，不能据此声称整个过程独立于宿主的名称解析及信任配置。

当前还有两项与预建共享 schema 直接相关的风险：首次初始化只读取 `schema_facts`，未运行重复调用所用的 `validate_layout`；事务使用 `client.transaction()`，未显式选择隔离级别。本提案把提交前结构校验及初始化事务的 `READ COMMITTED` 一并列入最小实施范围，理由见后文。

## 目标行为

| 目标状态 | 建议行为 |
| --- | --- |
| 管理员已建空 schema，账号有 schema 内初始化权限 | 直接创建完整 IdP 对象和初始状态 |
| 已有 schema 含不冲突的宿主对象 | 保留宿主对象和数据，创建 IdP 对象 |
| 已有通过现有结构校验、同模式及版本的 IdP 结构，调用者有读取权限 | 只校验并返回，不重建、不覆盖权限目录或管理员状态 |
| 已有旧版本、不同模式，或现有校验能识别的不完整 IdP 结构 | 沿用拒绝行为，按已有显式升级或处置流程处理 |
| 存在阻止创建或使现有结构校验失败的对象冲突 | 预检拒绝，或在提交前失败并回滚；不接管或替换已有对象 |
| schema 不存在，账号有数据库级 CREATE | 保留现有自动创建后初始化的行为 |
| schema 不存在，账号没有数据库级 CREATE | 失败，不创建半套对象；由管理员先准备 schema |
| 已有 schema，但缺少必要权限 | 失败，不尝试提权、修改授权或转移所有权 |
| 目标名称以 PostgreSQL 保留前缀 `pg_` 开头 | 初始化入口拒绝，不因跳过 CREATE SCHEMA 而放开系统或临时命名空间 |

首次成功后仍是 `tenant_v6`，`bootstrap_completed` 为 `false`。表结构初始化包含既有的系统域和权限初始数据，不等于管理员初始化。随后继续使用既有离线 bootstrap 和在线就绪检查。

## 权限和所有权

管理员先准备数据库、角色、schema 和授权。模块只消费宿主提供的连接配置，不持有管理员连接，也不创建角色、变更所有者或自动执行 `GRANT`。

| 操作主体 | 所需条件 |
| --- | --- |
| 数据库管理员 | 创建目标 schema，并向初始化角色授予所需权限 |
| 初始化角色 | 可连接目标数据库；对目标 schema 有 `USAGE`、`CREATE`；可使用现有可信 `plpgsql` 语言 |
| 在线角色 | 可使用目标 schema，并具有实际业务所需的表和函数权限；由部署方管理 |

在已有 schema 中首次创建对象，不要求初始化角色具有数据库级 `CREATE`、`CREATEDB`、超级用户权限或 schema 所有权。可信语言权限若被部署方撤销，应由管理员按当前 DDL 恢复必要授权；模块不安装扩展或语言。权限语义参考 [PostgreSQL 权限文档](https://www.postgresql.org/docs/18/ddl-priv.html)。

新 IdP 对象归执行初始化的有效数据库角色所有，schema 原所有者保持不变。schema 所有者与对象所有者不同，不代表 schema 所有者无法干预其中对象；该所有者、可在其中创建对象的角色及连接的名称解析设置都必须属于可信部署边界。共享 schema 不是对不可信业务角色的安全隔离机制。相关行为见 [PostgreSQL schema 与搜索路径说明](https://www.postgresql.org/docs/18/ddl-schemas.html)。

初始化与在线运行可使用同一个角色，但撤销其 schema `CREATE` 并不会撤销它对已拥有 IdP 对象的修改或删除能力。需要严格分离 DDL 与在线权限时，应由部署方使用不同角色。模块不自动切换角色，也不持有管理员连接。

角色分离时，schema 的 `USAGE` 不等于表的读写权限。部署方应按实际使用的 IdP 对象授予在线角色权限，并验证读取、写入和触发器内访问；不能仅凭 readiness 的只读校验断言全部运行权限齐备。为避免触及宿主业务对象，不建议在共享 schema 中直接使用 `GRANT ... ON ALL TABLES` 作为本功能的接入步骤。

新对象的 ACL 会受实际创建角色的默认权限影响，而不是自动继承 schema 所有者的默认权限。已有对象授权和后续新增对象的默认授权是两件事，见 [ALTER DEFAULT PRIVILEGES](https://www.postgresql.org/docs/18/sql-alterdefaultprivileges.html)。本期不修改任何默认 ACL，也不新增运行角色自动授权或通用权限管理系统。现有 DDL 不创建序列，不应额外要求本功能的序列授权。

重复初始化只承诺不需要新 DDL：调用者仍须有 schema `USAGE`、现有查询所需的读取权限及必要的系统目录可见性。`information_schema.columns` 受当前角色权限影响，权限不足也可能表现为结构校验失败；不得据此补建表或改授权。更换初始化角色后，同样需要先由管理员授予既有对象读取权限。

## 初始化流程设计

在现有事务和迁移锁内增加 schema 存在性判断，以 `pg_catalog.pg_namespace` 和参数绑定查询目标名称。该判断不依赖当前默认 schema，也不把“当前账号没有权限”解释为“schema 不存在”。

1. 在初始化入口拒绝 `pg_` 保留前缀；保持现有单段标识符校验。不改变其他存储 API 的配置接受范围。
2. 使用原连接池，为本次初始化显式开启 `READ COMMITTED` 事务，再获取原 `{schema}:embedded-idp-migration` 事务锁；不更改连接的会话级隔离设置。
3. 获得锁后查询 schema 是否存在。已有 schema 的路径不执行任何 `CREATE SCHEMA`，也不事先要求数据库级 `CREATE`。
4. 保留已有 `access_state` 分支：按当前结构校验检查其必须为普通表及其他必需对象，再检查版本和模式并返回。名称解析、权限或校验失败直接返回错误，不能降级为首次初始化。
5. 首次初始化仍执行已有 IdP 关系对象冲突预检。预检不是对全部对象定义的穷尽扫描。
6. 只有 schema 不存在时，才在原事务中执行现有创建语句；保留其数据库权限要求，不自动授权。
7. 执行原 `tenant_v6.sql`，写入当前状态、系统域及权限目录。
8. 在同一事务内复用 `validate_layout`，随后读取 `schema_facts`；全部通过才提交并返回成功。不得以 DDL 未报错代替提交前校验。
9. 提交前的可确认失败按原事务回滚；提交确认丢失按下述结果未知流程处理，不承诺所有 `Err` 均意味着已回滚。

现有 `PgStorageConfig` 仅做词法校验，允许 `pg_` 前缀。跳过创建语句后，不能再依靠 PostgreSQL 的 `CREATE SCHEMA` 来拒绝这些名称，因此需要上述入口级拒绝。该拒绝使用现有 `StoreError`，不新增公共错误变体。`public` 不属于该保留前缀，不额外禁止；只有宿主明确选择、完成授权并接受共享信任边界时才使用。不扩大到引号、大小写、多段名称或 SQL 关键字支持，不引入全局 `search_path` 修改。

现有错误映射继续使用 `StoreError`。本期优先通过文档说明所需权限，避免在所有存储操作中引入新错误分类。初始化失败不得输出数据库连接串、凭据或完整私有配置。

### 并发可见性

锁后的存在性、结构和状态检查必须使用获得锁之后的可见状态。`REPEATABLE READ` 会保留事务首条非事务控制语句的快照；仅有 advisory lock 不能保证等待者读到前一初始化者刚提交的状态，见 [PostgreSQL 事务隔离说明](https://www.postgresql.org/docs/18/transaction-iso.html)。因此本次初始化显式选择 `READ COMMITTED`，与现有 bootstrap、管理事务的选择一致；测试还应覆盖会话默认隔离级别为 `repeatable read` 的情况。该选择只作用于初始化事务。

迁移锁只协调同一数据库中使用相同锁键的调用，不能阻止管理员或其他工具并发删除、改名或重建 schema、修改授权及对象。方案以初始化期间无外部目标 DDL 为前提，不宣称能识别同名 schema 被替换或抵御恶意 DDL。运行时检查失败应保留原错误并退出；模块不自动重试、换 schema 或清理目标。不同 schema 的锁键哈希碰撞最多增加等待，不赋予跨 schema 写入权限。

### 冲突判定与校验范围

| 对象情况 | 判定和处理 |
| --- | --- |
| 与 IdP 表同名的表、视图、物化视图、序列、索引等关系对象 | 原 `pg_class` 预检拒绝；名为 access_state 的非普通表在现有结构检查中拒绝 |
| 与显式 IdP 索引同名的关系对象 | 原 DDL 报错，沿用冲突映射并回滚 |
| 与新表同名的独立类型或 domain | 可能不在 pg_class 预检中；CREATE TABLE 的隐式行类型创建会发生冲突，DDL 失败后回滚 |
| 与 IdP 函数名称及输入签名相同的函数 | CREATE FUNCTION 失败后回滚；不使用 CREATE OR REPLACE |
| 同名但输入签名不同的函数、其他 schema 的同名对象、其他表上的同名触发器 | 不仅凭名称视为冲突，按 PostgreSQL 命名空间与签名规则处理 |
| PostgreSQL 为约束或索引自动选择不同名称 | 若因此不满足现有 validate_layout，必须在提交前失败并回滚；不修改宿主对象腾出名称 |

关系命名空间、表的隐式行类型和函数重载分别参考 [schema 说明](https://www.postgresql.org/docs/18/ddl-schemas.html)、[CREATE TABLE](https://www.postgresql.org/docs/18/sql-createtable.html) 和 [CREATE FUNCTION](https://www.postgresql.org/docs/18/sql-createfunction.html)。不能把宿主的所有同名对象一律列为冲突。

一个具体的晚期失败夹具是在宿主表上建立名为 `devices_tenant_id_id_client_id_key` 的普通索引，而不是同名约束：该名称被现有 `validate_layout` 作为约束名检查，但不在表名预检中。PostgreSQL 的自动命名会寻找可用名称，见 [ChooseRelationName 与 ChooseIndexName](https://doxygen.postgresql.org/indexcmds_8c_source.html)。原实现的复现需使用可通过 CREATE SCHEMA 检查的测试角色，避免受限角色的权限失败遮蔽命名偏差；修正后的回归再使用受限角色。实施时应在真实数据库确认该夹具触发预期偏差，再证明提交前校验拒绝且全部新对象和初始数据回滚；不能只断言 DDL 抛错。

`validate_layout` 只检查当前列出的表、部分列、约束、索引和触发器等条件，并不逐项核对所有列、函数体、触发器归属、所有者、ACL 或恶意附加对象。因此“校验成功”等同于现有检查通过，不能表述为完整数据库一致性审计。对已存在结构沿用该能力，不增加通用 schema 差异引擎或宣称覆盖任意损坏。

### 失败回滚和结果未知

| 失败位置 | 数据和恢复语义 |
| --- | --- |
| 连接、保留名称或锁前失败 | 本次没有创建对象；不改变已有 schema |
| 冲突、权限、DDL、初始数据或提交前结构校验失败，回滚可确认 | 本次新建 IdP 对象和初始数据全部撤销；预建 schema、宿主对象、所有者及 ACL 保持原状；本次自动新建的 schema 也撤销 |
| COMMIT 明确被数据库拒绝且事务已终止 | 不返回成功；以确认的服务端事务状态为准 |
| COMMIT 发送后断连、超时、进程退出或成功响应未到达操作者 | 可能已经完整提交，也可能没有提交；结果未知，不能声称已回滚或删除重建 |

结果未知时，恢复数据库连接并等待原事务结束，以原数据库、schema、模式和可信权限目录重新执行同一初始化。迁移锁协调仍在执行的原调用：完整提交后走原校验返回分支，未提交则重新初始化；遇到不一致或权限失败则停止并核对。此重试由操作者明确执行，模块不自动循环重试，也不把 bootstrap 标记重置。对提交期间断连的谨慎恢复要求可参考 [PostgreSQL 运维说明](https://wiki.postgresql.org/wiki/Operations_cheat_sheet)。

现有 `StoreError` 不提供结构化的提交阶段信息，不能仅凭 `Backend` 或命令非零退出断言服务端已回滚。遇到未获确认的连接故障，接入文档应保守按结果未知说明；本期不为此增加公共结果类型或伪造精确的阶段诊断。

Access 初始化依赖 Rust 事务退出时回滚。必须验证错误返回后连接池可继续使用、未遗留失败事务和事务锁；不能用已有 legacy cutover 专用连接测试代替。用池上限为 1 的夹具覆盖可复用连接的正常错误回滚，再由独立连接确认迁移锁可获取；坏连接应被丢弃或重建，不能要求断线后仍复用同一 backend。

上述事务保证只覆盖本次数据库事务内的对象和数据。管理员先前执行的建 schema、授权、默认 ACL，以及之后单独执行的管理员 bootstrap、客户端准备和宿主业务表初始化，都不参与同一原子事务。数据库审计日志、非事务序列推进或管理员事件触发器的外部副作用也不能承诺被回滚；部署方拥有这些控制。

## 修改范围

| 文件或区域 | 实施内容 |
| --- | --- |
| `crates/embedded-idp-storage-postgres/src/access.rs` | 入口拒绝 pg_ 保留名称，显式初始化事务隔离，判断 schema 存在性，仅在缺失时创建，并在提交前复用结构校验；更新注释 |
| `crates/embedded-idp-storage-postgres/tests/live_access.rs` | 受限角色、对象冲突、晚期校验回滚、并发可见性与池恢复；使用现有 live target 中的局部夹具 |
| `crates/embedded-idp-storage-postgres/tests/schema_initialization/mod.rs` | 上述局部夹具和回归的实际实现，由 live_access 引入，不新增 CI target |
| `README.md` | 简述两种 schema 准备方式及权限要求，链接详细接入说明 |
| `CONTRIBUTING.md` | 说明新增角色夹具要求一次性数据库及测试连接的管理权限 |
| `docs/standalone-app-v1.md` | 区分固定开发脚本与自定义 schema 的直接初始化命令 |
| `docs/host-integration-v1.md` | 补充宿主预建 schema、初始化和在线角色权限边界 |
| 本设计文档 | 实施后补充结果及实际验证范围 |

现有入口通常只需更新说明：`bootstrap_local_postgres --access-schema`、宿主直接调用以及 `scripts/dev_env.sh db-init` 最终均调用同一方法。没有新增参数的必要，也不需要修改 Core、Axum、管理 Web、HTTP/OpenAPI 或嵌套数据库配置结构。

对象定义和数据契约不变，沿用 `tenant_v6`，不新增数据库版本或升级脚本。首次初始化新增提交前校验，可能使过去“创建成功但后续无法通过相同校验”的目标提前失败；这是本次对成功语义的必要收紧，需在文档说明。已有结构的检查内容和重复调用不覆盖目录的行为保持不变，不增加首次初始化权限对重复调用的限制。

## 入口差异与边界

### 自定义 schema 的推荐入口

嵌入宿主继续注入 `PgStorageConfig.connection.schema_name` 并调用原方法。参考工具可使用已有环境配置直接执行：

```sh
# 先由可信配置提供 EMBEDDED_IDP_APP_PG_URI 及 TLS 配置，不把连接串放入参数。
EMBEDDED_IDP_APP_PG_SCHEMA=idp_identity \
EMBEDDED_IDP_APP_TENANCY_MODE=enabled \
cargo run --locked -p embedded-idp-storage-postgres \
  --example bootstrap_local_postgres -- --access-schema
```

这是实施后的使用示例。直接入口读取进程环境，不自动加载开发 `.env` 文件。初始化、bootstrap 和在线进程必须使用相同的数据库、schema 和模式。

### 固定本地开发脚本

`scripts/load_dev_env.sh` 要求 `embedded_idp_disabled_v2` 或 `embedded_idp_enabled_v2`，并拒绝其他 schema；[test_dev_env.mjs](../scripts/test_dev_env.mjs) 将此视为明确的保护契约。本期保持该限制。管理员可以预建这两个开发 schema；使用任意自定义名称时走上述直接入口或宿主配置。

因此不能把本次能力描述为“修改模式文件后即可让开发脚本操作任意 schema”。若确有该需求，应单独设计替代现有防误操作校验的办法。

### 历史初始化和宿主示例

- `apply_migrations` 使用旧 `0001/0002/0003` 链，初始 SQL 也包含创建 schema；这是历史结构，不能替代当前 `tenant_v6`。本期不改历史初始化契约。
- `bootstrap_local_postgres --schema-only` 明确负责创建 schema，不用于在已有 schema 中建表；不作为受限账号推荐入口。
- `examples/no-tenant-host` 的 `db-init` 在 IdP 初始化之后，另行准备业务报告 schema；该步骤仍含创建 schema 语句。因此 IdP 模块修正不等于整个示例命令已经支持受限数据库账号。
- `examples/tenant-host` 的 fixture 命令带专用前缀和 marker，可能拒绝已有未标记的 IdP schema。这是示例资源保护，不能为本需求直接移除。
- `prepare_management_client_audit_schema` 是独立的可选增量准备，不创建 schema；其权限由执行该命令的部署角色保证，本期不并入首次初始化。

上述示例的业务表和 fixture 生命周期不属于本次 IdP 表结构初始化改动。文档应明确推荐入口，避免把示例命令的额外职责误当成模块限制。

## 实施顺序

| 阶段 | 工作 | 完成条件 |
| --- | --- | --- |
| P1 受限角色回归 | 在现有 `live_access` target 中准备隔离角色、管理员所有的 schema 及保留数据；先建立权限及自动命名偏差的可复现用例 | 原实现因数据库 CREATE 权限失败；自动命名夹具确认首次返回与随后校验的偏差；夹具确认实际执行角色受限 |
| P2 最小实现 | 在 `access.rs` 中增加保留名称拒绝、显式 READ COMMITTED、schema 存在性分支和提交前结构校验 | 受限角色初始化及重复校验成功；晚期校验失败保持原对象并回滚；不更改 DDL 和公共配置结构 |
| P3 直接风险验证 | 执行下面的验收矩阵，覆盖权限、两种模式、命名空间、回滚、并发和池恢复；验证结果未知后的同参数恢复 | 明确区分确认回滚、确认提交和未获确认；没有把只读 readiness 当成完整运行权限证明 |
| P4 文档与最终审查 | 更新既有接入指南，审查实际 diff，并完成相关构建检查 | 文档准确区分直接入口、开发脚本、历史链及示例限制；无无关改动 |

新测试优先放入现有 live target，不新增 CI lane、数据库框架或依赖。需要管理角色的夹具应在专用测试 PostgreSQL 中运行；普通离线测试继续不依赖数据库。

## 验收矩阵

以下首次初始化及模式相关用例覆盖 `disabled` 和 `enabled`。

| 编号 | 场景 | 可观察结果 |
| --- | --- | --- |
| A01 | 非超级用户、非数据库所有者、无数据库 CREATE，管理员预建空 schema，并授予 schema USAGE/CREATE | 初始化及随后 inspect 均成功；版本为 tenant_v6，bootstrap 未完成；schema 所有者和 ACL 不变，新对象归初始化角色 |
| A02 | 同样角色，预建 schema 含管理员所有的业务表和数据 | IdP 初始化成功；业务对象的 OID、定义、所有者、ACL 和数据不变，初始化角色未被附带授予业务表权限 |
| A03 | 已有结构重复执行；撤销初始化角色的 schema CREATE，保留 USAGE 和所需读取权限后复验 | 返回原事实；目录、模式、bootstrap、对象 OID 和定义不变；无新 DDL，也不要求数据库 CREATE；包含 bootstrap 前后两种状态 |
| A04 | 已有 schema 缺少 USAGE，或首次初始化缺少 CREATE | 明确失败；没有残留的新 IdP 对象；schema 和宿主数据保留 |
| A05 | schema 不存在，角色有数据库 CREATE | 兼容原路径，创建 schema 和完整结构 |
| A06 | schema 不存在，角色无数据库 CREATE | 失败；目标 schema 及 IdP 对象均未创建 |
| A07 | 同名 IdP 表、名为 access_state 的非普通表、显式索引冲突、同名独立类型及同输入签名函数 | 拒绝或 DDL 失败并整体回滚；原对象及数据不被替换；按各分支断言现有 Conflict 或 Backend，不强求同一个错误文本 |
| A08 | 旧版、不同模式，以及缺表、被禁用的必需触发器等现有检查可识别的结构缺陷 | 拒绝；不迁移、不补建、不修复；不宣称覆盖任意损坏或恶意伪造 |
| A09 | 两个遵守迁移锁的调用进入同一预建 schema | 默认配置下一个创建、另一个校验；无重复初始数据和部分结构；同步控制确保实际出现锁等待，不靠固定睡眠 |
| A10 | 晚期函数创建冲突，或初始数据写入之后的结构校验失败 | 管理连接对比 pg_class、pg_proc、pg_type 及 ACL 基线，本次新对象及初始数据无残留，预建冲突对象不计为残留；预建 schema 与业务对象保留；不只检查 access_state 是否消失 |
| A11 | 自定义 schema 初始化后执行真实 Core bootstrap、构造 store 和 readiness | 原接入流程可继续使用；不通过测试 seed 直接设置 bootstrap 标记替代真实初始化；重复初始化不改变已生成的管理员与目录 |
| A12 | 宿主对象占用 devices_tenant_id_id_client_id_key 等现有校验依赖的自动名称 | 先确认 DDL 自动命名偏差；提交前结构校验拒绝，DDL 和初始数据全部回滚，不留下“首次成功、下次失败”的结构 |
| A13 | 目标为 pg_catalog、pg_temp 或其他 pg_ 名称 | 初始化入口安全拒绝；不尝试对系统或临时 schema 执行 DDL，不通过建真实系统对象制造夹具 |
| A14 | 同 A09，但连接默认隔离级别设置为 repeatable read | 初始化事务显式使用 READ COMMITTED，等待者读取前一调用提交的状态；会话默认设置在调用前后不变 |
| A15 | 当前 search_path 指向其他可信 schema；其他 schema 中有同名 IdP 对象，目标中有可共存的函数重载和业务触发器 | 存在性与对象操作仍落在明确的目标；允许合法共存；无跨 schema 写入，不测试或承诺抵御恶意搜索路径 |
| A16 | 在线角色与初始化角色不同；仅授予明确 IdP 对象访问权限，不授予 schema CREATE | readiness 及代表性的真实管理读写、触发器内访问可用；宿主业务表授权不变；只读权限不足以执行写入时必须失败 |
| A17 | 初始化错误后从 max_connections=1 的同一适配器重新取连接 | 无遗留失败事务，正常连接可继续查询；独立连接可获取原事务锁，修复夹具冲突后同参数重试成功 |
| A18 | 成功提交后，测试调用方丢弃成功结果，再以相同参数复核；另测已确认回滚后的重试 | 分别进入原校验分支或重新初始化，不重建、不重复种子、不删除目标；验证恢复协议，不把此模拟当成真实 COMMIT 断网测试 |
| A19 | 保留 schema USAGE，但换用无 IdP 表读取权限的角色调用重复初始化 | 返回读取或结构校验错误；不把不可见当成不存在，不创建或授权任何对象 |

### 夹具权限和清理

现有 `Db::new` 会先用传入连接初始化 schema，不能直接用它证明“首次建表由受限角色完成”。新增局部夹具应分离管理连接与受限适配器：管理连接只建 schema、角色及精确授权、检查原对象和清理；受限适配器实际执行初始化与重复验证。不能在多个并发测试间修改进程全局 URI 或角色配置。

受限角色必须非超级用户、非数据库/schema 所有者、无 CREATEDB/CREATEROLE/BYPASSRLS，也不继承或切换到所有者及高权限角色。检查实际执行连接的 `current_user`、必要的 `session_user`、`has_database_privilege(current_user, current_database(), 'CREATE') = false`、schema USAGE/CREATE 以及目标所有者。限制必须作用于适配器使用的每条连接，不能只在辅助连接上执行一次 `SET ROLE`，再让适配器继续以管理员身份运行。缺 USAGE 与缺 CREATE 的用例分别测试，检查有效权限而非仅检查某条 GRANT 是否存在。

角色属于 PostgreSQL 集群而非单个 schema，测试必须使用专用一次性实例和随机资源名。保持现有显式 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI` 入口；新夹具需要建角色权限，必须在接触资源前说明并验证这一前提。现有 CI 隔离 PostgreSQL 可提供管理角色，本需求不要求普通应用账号具有该能力。连接条件不满足应明确失败，不能忽略新增用例后声称通过。

不得为制造无权限场景而撤销共享数据库的 PUBLIC 权限、修改开发角色或触碰应用 schema。若公共或继承授权使无权限前提不成立，应拒绝使用该夹具环境。生成的角色凭据只放私有内存或受限配置，不输出到参数、日志、断言错误或 CI 附件。

清理必须关闭受限连接及池的全部持有者，以原管理连接删除自身随机 schema、撤销自身创建的精确授权和默认权限依赖，再删除随机角色，最后确认 schema 和角色均不存在。清理失败使测试失败并保留不含凭据的资源定位信息，不能沿用现有 Db::drop 中忽略清理错误的做法。禁止用未限定资源的 DROP OWNED 或 REASSIGN OWNED 清理共享对象；紧急清理也只能处理已核对的本测试资源。

真实 COMMIT 断连场景未由现有工具提供确定性的故障注入。本期用 A18 验证恢复语义，不新增通用网络代理或故障框架；若另做真实断连专项，应单独记录其环境和实际覆盖，不能将模拟结果等同于驱动在提交瞬间断网的实测结论。

## 复审结论与修订对应

| 发现 | 修订 |
| --- | --- |
| 首次 DDL 成功不保证符合后续校验，自动命名可能造成晚期不兼容 | 增加同事务提交前 validate_layout，并用 A12 验证 |
| 单有迁移锁不足以约束等待者的事务快照 | 初始化显式 READ COMMITTED，并覆盖会话默认不同的情况 |
| 跳过 CREATE SCHEMA 同时跳过了其保留名称检查 | 入口拒绝 pg_；不全局收紧其他存储 API 的词法配置 |
| schema 授权、对象所有权、默认 ACL 与运行权限被过度合并 | 分别说明初始化、重复校验、在线角色及共享信任边界；增加 A16/A19 |
| “任意同名对象冲突”和“完整损坏校验”表述过强 | 按命名空间和签名细化处理，限定现有 validate_layout 的实际保证 |
| 所有失败均已回滚的承诺不成立 | 区分提交前失败和提交结果未知，明确同参数恢复及事务外边界 |
| 现有 legacy 池测试和忽略错误的 Drop 不能证明新增路径正确清理 | 增加 Access 错误后的池/锁恢复和显式角色清理验收 |

主设计方向保持不变：支持管理员预建 schema，保留缺失 schema 的兼容路径，复用现有结构和 API。实现范围在同一个初始化函数内补齐上述直接风险，不扩展到历史迁移、示例业务表、通用权限系统或完整结构审计。

## 验证安排与本轮交付

实施后先执行定向 storage 检查和上述真实 PostgreSQL 回归，再运行现有 `scripts/run_ci_integration.sh --output-dir <全新目录>`，核对现有十个 live targets 实际执行及资源清理。该入口会准备 Web 资源以满足 Rust 参考宿主的编译依赖；本任务不新增 Web 行为测试。

最终按仓库基线执行 Web 构建、`cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked` 和 `cargo test --workspace --locked`。依赖缺失时先按锁文件安装。未配置显式测试数据库时，普通测试中被忽略的 live 用例不能计为数据库验收通过。范围内新增的只读检查、隔离及回滚用例应记录实际结果；角色分离、清理或真实断连专项未执行时如实列出，不将计划项目计为通过。

设计及修订 2 复审阶段只交付工作分支、修改范围分析和方案，未修改代码或操作数据库。静态复审对照了初始化、DDL、错误映射、结构校验、bootstrap/readiness、连接池和夹具，并核对 PostgreSQL 官方语义。后续已按用户授权实施，自动命名偏差等实际结果以[实施与验证记录](precreated-schema-initialization-result.md)为准。工作区原有 `crates/embedded-idp-axum/tests/openapi_contract.rs` 修改继续保留，不纳入本需求提交。
