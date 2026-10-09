# 3.0.0 设备与扫码登录升级手册

本手册是设备生命周期、双向扫码、断网恢复和私网 HTTP 开发模式的统一升级入口。3.0.0 在两种 tenancy mode 下均要求 `tenant_v6`；软件版本、schema 名称、数据库结构版本和证明协议版本是不同概念，不能相互替代。

## 选择升级路径

先读取真实目标 schema 的 `access_state.tenancy_mode` 和 `module_version`，核对宿主配置及备份。保留既有 schema 名称，不因版本号变化重命名或初始化已有库。

| 当前状态 | 升级路径 |
| --- | --- |
| 全新 schema，没有 IDP 对象 | 使用 3.0.0 初始化 `tenant_v6`，单独离线初始化管理员；不运行旧迁移 |
| 已发布 2.0.0 / `tenant_v3` | `migrate_device_lifecycle`：v3→v4；`migrate_scan_login`：v4→v5；`migrate_scan_login_origin_closures`：v5→v6 |
| `tenant_v4` | 仅 v4→v5→v6 |
| `tenant_v5` | 仅 v5→v6 |
| `tenant_v6` | 无结构迁移；核对 readiness、宿主接口、证明用途和配套 Web 版本 |
| `tenant_v2` | 先按[业务隔离迁移](business-domain-authorization-design-v1.md#10-tenant_v2--tenant_v3-显式迁移)核对历史时间元数据、提供显式业务映射并升级到 v3，再执行本手册 |
| 其他版本、缺少版本行或不兼容布局 | 停止升级，调查结构和历史；不修改版本标记或用初始化覆盖 |

从 v3 到 v6 是三个分别提交的事务，整条链没有一个跨步骤事务。中途失败时保持停写，核对实际已提交版本，修复后从对应步骤继续；不要从第一步盲目重放。

## 准备与停写

1. 固定 3.0.0 源码提交、匹配 Web 归档及 SHA-256，准备新的二进制和宿主适配。扫码功能默认关闭；升级 schema 不要求立即启用扫码。
2. 停止所有写目标 schema 的 IDP 实例、嵌入宿主及 cleanup 任务，在整个迁移链和启动验证完成前保持停写。
3. 核对已登记设备、当前密钥、人员绑定及 Pending 交付。若从 v3 升级，准备该 schema 的有效平台管理员 UUID，审阅[生命周期迁移撤销规则](device-identity-lifecycle-upgrade.md)。
4. 备份并验证可读取；生产恢复演练由宿主完成。连接信息通过受保护的 libpq 变量或 `PGPASSFILE` 提供，不写入参数或仓库。

以下 schema 和 UUID 为示例。每个 schema 分别核对连接并执行；必须设置 `PGDATABASE`，按部署需要设置 `PGHOST`、`PGPORT`、`PGUSER` 和受限 `PGPASSFILE`（或短期 `PGPASSWORD`）。迁移包装器不使用 `EMBEDDED_IDP_APP_PG_URI`。schema 名来自可信配置，不拼接用户输入。

```sh
schema=embedded_idp_disabled_v2
actor_id='<effective-platform-admin-uuid>' # 仅 v3→v4 使用
backup_dir='<private-backup-directory>'

psql -X -v ON_ERROR_STOP=1 -c "select tenancy_mode,module_version from ${schema}.access_state"
pg_dump -Fc -n "$schema" -f "$backup_dir/$schema.dump"
pg_restore -l "$backup_dir/$schema.dump" > "$backup_dir/$schema.toc"
pg_restore -f /dev/null "$backup_dir/$schema.dump"
shasum -a 256 "$backup_dir/$schema.dump" > "$backup_dir/$schema.dump.sha256"
```

不要复制 SQL 手工执行、直接修改 `access_state`，也不要把含密码的 URI 记录在 shell history、CI 输出或工单中。

## Rust 与客户端接入变更

- 自定义 `TenantScanLoginTransaction` 增加 closure 查询／插入实现；使用 Postgres 适配器的宿主直接升级依赖。关闭与原请求最终提交必须共用设备行锁和事务，不能在宿主另一个数据库里代替此记录。
- 自定义 `TenantDeviceScanLoginService` 实现增加 `close_origin`。`LookupDeviceScan` 的 Rust 构造增加 `origin_action: Some(Create/Claim)`，旧代码可明确填 `None`；HTTP 字段仍可省略，保持无歧义旧查询的兼容。
- 设备证明配置添加 `ScanLoginAction::CloseOrigin.purpose()`（`scan_login_close_origin`）。路由固定实际外部路径 `/auth/device-scan/close-origin` 加宿主前缀；签名绑定实际 body，不能复用 create／claim 的证明。
- 宿主升级原生恢复状态机：先保存原请求，NotFound 保持未决；成功关闭后禁止重用原 ID，清除被撤销的 Pending bundle；`already_activated` 保留当前会话凭据。关闭新登录准入时仍保持终止、查询、清理与补偿服务运行，不以移除整个模块实现登录方式开关。

## 应用和切换

只执行当前版本需要的步骤，每步先预演、审阅后再应用。v3→v4 会清理列出的旧 pending／无密钥 disabled 身份及关联凭据、写入迁移审计；另外两步增加扫码表及持久原操作终止记录。每一步的结构、数据、审计和版本标记在自己的事务内整体提交或回滚。

```sh
# 仅当前 tenant_v3：先审阅预演的撤销清单
./scripts/migrate_device_lifecycle.sh "$schema" "$actor_id" "device-v4-dry-$schema"
./scripts/migrate_device_lifecycle.sh "$schema" "$actor_id" "device-v4-apply-$schema" --apply
psql -X -v ON_ERROR_STOP=1 -c "select module_version from ${schema}.access_state"
# 必须为 tenant_v4

# 仅当前 tenant_v4
./scripts/migrate_scan_login.sh "$schema"
./scripts/migrate_scan_login.sh "$schema" --apply
psql -X -v ON_ERROR_STOP=1 -c "select module_version from ${schema}.access_state"
# 必须为 tenant_v5

# 仅当前 tenant_v5
./scripts/migrate_scan_login_origin_closures.sh "$schema"
./scripts/migrate_scan_login_origin_closures.sh "$schema" --apply
psql -X -v ON_ERROR_STOP=1 -c "select module_version from ${schema}.access_state"
# 必须为 tenant_v6
```

省略 `--apply` 只预演并回滚，不写数据库。历史脚本只识别自己的源／目标版本，不接受后续 v6；不要对 v6 重新运行 v3→v4 或 v4→v5。最后一步重复 apply 验证已有 v6 关键布局；dry-run 只确认版本适用，不能替代当前二进制 readiness 的完整结构校验。

切换检查顺序：

1. 核对最终 `module_version=tenant_v6`、迁移审计、未列入撤销清单的账号/权限/有效设备/绑定/会话，以及保留的 closure 记录。
2. 安装匹配的 Rust 依赖、原生状态机和 Web 制品。启动 3.0.0，检查 `/readyz`、普通密码登录、既有 refresh、严格设备会话认证和业务授权允许/拒绝。
3. 配置扫码 entry、显式 source-client allowlist、可信 host context、`ScanLoginAdmission`、真实目标资料、全部十种扫码证明用途、结果加密适配器和有界 cleanup，保持新登录入口关闭。
4. 加载结果密钥并检查可用性，再显式启用扫码准入；使用已登记测试设备和普通业务测试人员分别走两种方向，覆盖批准、拒绝、取消、兑换响应丢失、恢复、ACK 和 close-origin 迟到请求拒绝。
5. 检查宿主最终准入失败的精确补偿、Active 状态校验及设备本地原子保存。完成部署环境验收后恢复正常业务写入。

Core 的结果加密接口由宿主管理密钥轮换。旧密钥需覆盖仍可解密的展示码和交付结果，直到两者均到期并清理。参考应用目前只配置一个结果密钥，不是多 key 的生产轮换系统；更换它之前应关闭新登录、处置／排空旧展示和 Pending 交付，不能直接替换后尝试重建原会话。

启用私网 HTTP 还需遵循[开发模式接入](development-private-http.md)：feature、开发构建及显式策略同时满足，并单独构造受限浏览器服务与匹配签发器。传给 H5 的模式描述来自服务端 `client_config()`，不能让 H5 自行降级。开发浏览器期限不影响设备会话和恢复窗口，数据库无需再迁移。

## 回退边界

关闭入口会阻止新授权请求，但已签发会话按既有会话规则继续有效。先让未完成授权到期或用精确 abort/compensate 处置，再停止 cleanup，才可切换到兼容 `tenant_v6` 的回退二进制。

不能直接把数据库版本降回 `tenant_v4` 或 `tenant_v5`、删除扫码表或丢弃仍可能解密交付结果的 key。需要恢复旧备份时，先停写并评估备份后的账号、设备、会话和审计变化；恢复会丢失这些变化，也可能恢复已撤销的凭据。

## 恢复故障处置

- 未收到创建或关联响应：原设备使用已保存的 origin action、operation ID 和 delivery secret 调用 lookup。`scan_not_found` 是非终态，不能据此丢弃请求、换 ID 或开始另一次登录。
- 确认放弃原创建／关联：用相同 origin action、operation ID、delivery secret、新 challenge 调用 close-origin；不依赖原手机码仍有效。只有收到 `closed` 或 lookup 的 `origin_operation_closed` 才能把该操作标为终止。终止响应再次丢失时保留原上下文并重复 close-origin／lookup；`already_activated` 保留已激活凭据，正常精确注销另走原接口。
- 关闭的原操作 ID 永不重用。开始用户明确发起的新流程时生成全新 ID 和 delivery secret；不要修改旧请求内容来绕过未知结果。
- 未收到兑换／恢复响应：使用原 issuance operation ID、新 challenge 和同一 delivery secret 重试；先查询状态，不能把超时判断为未签发。
- 收到 bundle：原生层原子保存 session、tokens 和 receipt nonce 后 ACK。ACK 响应丢失时保留 receipt 与 ACK operation ID 重试；已经 acknowledged 的恢复只返回元数据。
- 宿主最终拒绝：可信服务端调用 compensate，原设备可调用 abort；二者只撤销本 grant 的未确认 Pending 会话，不能代替 Active 会话注销。
- 结果密钥丢失或密文无法解密：保持 Pending 禁止使用，由可信宿主按 grant／issuance 精确补偿；不要重建同一 grant 的会话。修复 keyring 前关闭新创建／签发准入，并保留 cleanup。
- cleanup 失败：参考宿主每 30 秒重试、每批最多 100 个，失败输出不含身份或秘密的告警。生产宿主应监控积压；恢复窗口到期后 ACK 仍拒绝并撤销，不能通过停摆任务放行业务。

只归档已无秘密的历史记录。操作记录至少保留 7 天，issued grant 不可重发标记覆盖关联会话生命周期加 90 天；模块 cleanup 不自动删除审计或幂等记录。

原操作终止记录 `scan_login_origin_closures` 不含原始 delivery secret，只有摘要；cleanup 不删除它。其保存期限与短期恢复密文不同：同一 scoped operation ID 的迟到提交必须永久被拒绝。宿主归档必须保留等价的拒绝索引，禁止删除 tombstone 后重新开放旧 ID；备份和灾备恢复须同时包含该表。关闭入口后应继续保留 lookup、close-origin、abort 和可信服务端补偿能力。

交付范围与验收结果见[CHANGELOG](../CHANGELOG.md)、[扫码验收记录](device-scan-login-validation.md)和[HTTP 开发模式验收记录](development-private-http-validation.md)。
