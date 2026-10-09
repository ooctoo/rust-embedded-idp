# 设备生命周期 v3→v4 迁移步骤

本文件描述历史迁移链中的 tenant_v3→tenant_v4 步骤及撤销规则。当前 3.0.0 使用 tenant_v6，新库直接初始化 v6；已有 v3 完成本步骤后继续 v4→v5→v6，全部流程见[统一升级手册](device-scan-login-upgrade.md)。旧设备写入 DTO 不兼容，启动不自动迁移。

## 准备与停写

1. 更新宿主对设备登记、状态操作、自助解绑的请求字段和响应处理；准备与目标版本匹配的新二进制和 Web 构建。确认每个目标 schema 的有效平台管理员 UUID，供迁移审计使用。
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

核对升级前后未列入撤销清单的账号、权限、有效设备和会话数量与状态；逐条核对预演中列出的撤销结果及审计。v4 是本步骤的中间结果；升级 3.0.0 时继续完成统一手册中的 v5/v6 步骤，再启动当前二进制并验收后恢复写入。参考服务在 2026-09-28 的本机 v4 升级属于历史记录，不能代替当前目标 schema 的版本核对。

迁移提交后不能直接启动旧二进制。优先向前修复。若必须恢复备份，先再次停写并评估备份之后的身份变化；恢复会丢失这些变化，且可能复活已撤销的凭证，因此不能视作无损回滚。
