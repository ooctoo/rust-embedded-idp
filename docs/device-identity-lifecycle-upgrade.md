# 设备生命周期 `tenant_v3 → tenant_v4` 升级手册

本手册适用于本分支的新二进制及已有 `tenant_v3` Access schema。升级是破坏性接口和数据库变更：旧二进制不能连接 `tenant_v4`，旧设备写入请求不能继续使用。新建空库直接初始化 `tenant_v4`，不运行此迁移。迁移不会在服务启动时自动执行。

## 准备与停写

1. 更新宿主对设备登记、状态操作、自助解绑的请求字段和响应处理；准备与本分支匹配的新二进制和 Web 构建。确认每个目标 schema 的有效平台管理员 UUID，供迁移审计使用。
2. 停止所有连接目标 schema 的 IDP 写入者，包括参考服务、嵌入宿主和后台任务。切换期间保持停写。核对数据库连接和已运行服务，不能只停止管理页面。
3. 使用 `pg_dump`、`pg_restore`、`psql` 可访问目标 PostgreSQL 的账号。通过 libpq 的 `PGHOST`、`PGPORT`、`PGUSER`、`PGDATABASE` 和权限受限的 `PGPASSFILE` 等环境变量配置连接。`PGDATABASE` 必须已设置；不要把含密码的 URI 放在命令参数、文档或日志中。

以下命令中的 schema 名和 UUID 仅为示例；每个 schema 分别执行。备份目录应在仓库外，限制访问权限并保留至验收结束。

```sh
schema=embedded_idp_disabled_v2
actor_id='<effective-platform-admin-uuid>'
backup_dir='<private-backup-directory>'

psql -X -v ON_ERROR_STOP=1 -c "select tenancy_mode,module_version from ${schema}.access_state"
pg_dump -Fc -n "$schema" -f "$backup_dir/$schema.dump"
pg_restore -l "$backup_dir/$schema.dump" > "$backup_dir/$schema.toc"
pg_restore -f /dev/null "$backup_dir/$schema.dump"
shasum -a 256 "$backup_dir/$schema.dump" > "$backup_dir/$schema.dump.sha256"
```

确认版本为 `tenant_v3`、备份可完整解码，并记录升级前的账号、角色、权限、设备、绑定和会话数量。备份验证不等于已演练恢复；生产环境应按自己的恢复策略完成恢复验证。

## 预演与应用

```sh
./scripts/migrate_device_lifecycle.sh "$schema" "$actor_id" "device-v4-dry-$schema"
```

预演使用一致性快照并回滚，不加独占表锁。审阅输出中的设备 ID、待撤销数量及受影响的 session、refresh、授权码、租户选择、nonce 和绑定。旧 `pending` 或无密钥 `disabled` 设备会被撤销；非法旧状态会使迁移失败，须先调查，不能跳过检查或让脚本自动修复。即使预演为零，正式应用前仍须确认所有写入者已停止、备份有效。

```sh
./scripts/migrate_device_lifecycle.sh "$schema" "$actor_id" "device-v4-apply-$schema" --apply
psql -X -v ON_ERROR_STOP=1 -c "select tenancy_mode,module_version from ${schema}.access_state"
psql -X -v ON_ERROR_STOP=1 -c "select operation,count(*) from ${schema}.access_audit_events where operation='access.migrate_device_lifecycle' group by operation"
```

`--apply` 在单个事务中加锁、清理列出的旧身份、写审计并标记 `tenant_v4`。失败时事务回滚；不要以命令退出前的部分输出判断成功。重复执行已升级的 schema 仅检查关键布局并退出，不重复清理或写审计。对第二个 schema 重新核对连接、备份、预演并使用独立 request ID。

## 切换与回退边界

核对升级前后未列入撤销清单的账号、权限、有效设备和会话数量与状态；逐条核对预演中列出的撤销结果及审计。启动新二进制，检查 `/readyz`、OIDC discovery，并用真实测试账号验证代表性的登录、授权允许和拒绝。只有这些检查通过后才恢复写入。参考服务的本机 `embedded_idp_disabled_v2` 和 `embedded_idp_enabled_v2` 已于 2026-09-28 升到 v4；无需再次应用。

迁移提交后不能直接启动旧二进制。优先向前修复。若必须恢复备份，先再次停写并评估备份之后的身份变化；恢复会丢失这些变化，且可能复活已撤销的凭证，因此不能视作无损回滚。
