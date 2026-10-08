# 扫码授权设备登录 `tenant_v4 → tenant_v5` 升级手册

本手册适用于已有 `tenant_v4` Access schema 的宿主。扫码授权设备登录引入授权请求、幂等操作和加密交付结果的持久化记录；新二进制要求 `tenant_v5`。新建空库应直接执行当前 schema 初始化，运行时不会自动迁移。

## 准备

1. 准备包含扫码登录迁移的二进制，并核对宿主已实现 `ScanLoginAdmission`、目标展示资料提供者、显式入口配置和结果 keyring。参考服务只在明确配置后启用；默认关闭。
2. 停止所有写目标 schema 的 IDP 实例、嵌入宿主及 cleanup 任务。扫码交付的状态转换需要一致事务，迁移期间不得与旧版本并发写入。
3. 备份目标 schema，并验证备份可读取。连接信息通过受保护的 libpq 环境变量或 `PGPASSFILE` 提供，不能把密码写入命令参数或提交到仓库。

```sh
schema=embedded_idp_disabled_v2
backup_dir='<private-backup-directory>'

psql -X -v ON_ERROR_STOP=1 -c "select tenancy_mode,module_version from ${schema}.access_state"
pg_dump -Fc -n "$schema" -f "$backup_dir/$schema.dump"
pg_restore -l "$backup_dir/$schema.dump" > "$backup_dir/$schema.toc"
pg_restore -f /dev/null "$backup_dir/$schema.dump"
shasum -a 256 "$backup_dir/$schema.dump" > "$backup_dir/$schema.dump.sha256"
```

确认 `module_version` 为 `tenant_v4`。迁移包装器使用现有 libpq 变量：必须设置 `PGDATABASE`，并按部署需要设置 `PGHOST`、`PGPORT`、`PGUSER` 及受保护的 `PGPASSFILE`（或短期 `PGPASSWORD`）。不要使用参考服务的 `EMBEDDED_IDP_APP_PG_URI`，也不要把连接 URI 或密码记录在 shell history、CI 输出或工单中。不得手工复制 SQL 或直接修改 `access_state`。

## 应用和切换

迁移工具必须先预演，再在停写窗口显式应用。它应在单事务中创建 `tenant_v5` 表、约束和索引，更新版本标记；失败必须整体回滚。启动服务只核对 schema，不修复或升级数据。

```sh
scripts/migrate_scan_login.sh "$schema"
scripts/migrate_scan_login.sh "$schema" --apply
```

省略 `--apply` 时只执行预演；脚本拒绝非 `tenant_v4`／`tenant_v5` 版本及不合法 schema 名称；`tenant_v5` 仅用于重复执行时核对已有布局。

完成后检查版本、服务 `/readyz`、普通账号密码登录、既有 refresh 和设备认证。先配置但保持扫码入口关闭，再加载结果 keyring 和宿主准入适配器，最后显式启用入口。首次上线应使用测试人员和已登记测试设备分别走 `device_display` 与 `phone_display`，覆盖批准、取消、重复兑换和恢复响应丢失。

结果加密 keyring 属于运行所需秘密。迁移不生成 key；缺失、格式错误或当前 key ID 不存在时，参考宿主必须拒绝启用扫码能力。保留旧 key 直到所有仍可恢复的交付记录已过期并完成清理。

## 回退边界

关闭入口会阻止新授权请求，但已签发会话按既有会话规则继续有效。先让未完成授权到期或用精确 abort/compensate 处置，再停止 cleanup，才可切换到兼容 `tenant_v5` 的回退二进制。

不能直接把数据库版本降回 `tenant_v4`、删除扫码表或丢弃仍可能解密交付结果的 key。需要恢复旧备份时，先停写并评估备份后的账号、设备、会话和审计变化；恢复会丢失这些变化，也可能恢复已撤销的凭据。

## 恢复故障处置

- 未收到创建或关联响应：原设备使用已保存的 origin operation ID 和 delivery secret 调用 lookup；不要替换 operation ID 或丢弃秘密。
- 未收到兑换／恢复响应：使用原 issuance operation ID、新 challenge 和同一 delivery secret 重试；先查询状态，不能把超时判断为未签发。
- 收到 bundle：原生层原子保存 session、tokens 和 receipt nonce 后 ACK。ACK 响应丢失时保留 receipt 与 ACK operation ID 重试；已经 acknowledged 的恢复只返回元数据。
- 宿主最终拒绝：可信服务端调用 compensate，原设备可调用 abort；二者只撤销本 grant 的未确认 Pending 会话，不能代替 Active 会话注销。
- 结果密钥丢失或密文无法解密：保持 Pending 禁止使用，由可信宿主按 grant／issuance 精确补偿；不要重建同一 grant 的会话。修复 keyring 前关闭新创建／签发准入，并保留 cleanup。
- cleanup 失败：参考宿主每 30 秒重试、每批最多 100 个，失败输出不含身份或秘密的告警。生产宿主应监控积压；恢复窗口到期后 ACK 仍拒绝并撤销，不能通过停摆任务放行业务。

只归档已无秘密的历史记录。操作记录至少保留 7 天，issued grant 不可重发标记覆盖关联会话生命周期加 90 天；模块 cleanup 不自动删除审计或幂等记录。
