# 通用扫码授权设备登录验证记录

日期：2026-10-09。分支：`codex/device-scan-login`。

以下两节保留 PR #16（主干 `33c4aa8`）的交付基线；本次 v6 增量与验证列在后面。

## 主干交付基线

- 双向扫码都固定具体目标设备，并由来源手机业务会话确认；传统登录继续走既有接口。
- Core 提供入口配置、显式来源客户端关系、可信身份与宿主上下文、分阶段准入、真实目标资料、授权状态机和事务契约。
- 九种设备证明绑定实际外部路径、原始 body、用途、目标客户端和入口；一次性挑战在最终事务消费。
- 兑换原子创建 Pending 人员设备会话、refresh、加密结果、幂等记录和审计；原设备恢复同一结果，持久化后 ACK 激活。
- ReleaseResult／ActivateSession 拒绝时精确补偿；abort、compensate、恢复期到期和 cleanup 不删除共享绑定，不撤销其他会话。
- Postgres `tenant_v5` 新表与显式 v4→v5 迁移；参考宿主 H5、QR／Code 128、原生持久化示例与升级运行手册。

## 主干基线验证

| 层级 | 命令／方法 | 证据 |
| --- | --- | --- |
| Web | 冻结依赖安装、`pnpm --dir web test`、`build`、`test:embedded-bundle` | 83 项客户端测试、3 项嵌入包测试通过；类型检查和管理／扫码／嵌入包构建通过 |
| Rust | `cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo test --workspace --locked` | 406 项通过、129 项显式 live 测试保持 ignored，不引入普通离线测试的数据库依赖 |
| Core 扫码 | `cargo test -p embedded-idp-core scan_login --lib` | 13 项通过；双向服务、源会话注销边界、幂等、错误秘密与回执、取消、最终拒绝、精确撤销、提前到期清理、审计回滚 |
| Axum 扫码 | `cargo test -p embedded-idp-axum device_scan_login` | 8 项通过；真实嵌套路由路径／body 摘要、业务 Cookie 限制、Origin、可信上下文、重复／未知／超限请求、读取 DTO、串会话与存储故障分类 |
| 加密与协议 | Security 的 `device_scan_login_v1`、Node 共享向量校验器 | 6 项 Rust 测试、9 个 Ed25519 向量、135 个签名篡改校验通过；AAD 篡改、旧 key 解密、nonce 和 keyring 边界覆盖 |
| Postgres 扫码 | 显式测试连接上的 `live_tenant_registration scan_login -- --ignored` | 4 项通过；真实 Ed25519／AES、双向流程、Pending 门禁与恢复／激活、两线程不同兑换操作只签发一次、审计 trigger 故障整体回滚及同操作重试 |
| Postgres 迁移 | `live_access scan_login_migration -- --ignored` | 实际迁移 DO 块升级、重复执行及版本写入故障完整回滚通过 |
| 迁移包装器 | 静态脚本检查；已有本地 pg 容器 psql 执行实际包装器 | 随机隔离 v4 schema 的 dry-run 不修改、apply 升级、重复 apply 和 v5 dry-run 全部通过；测试 schema 已删除 |
| 数据库回归 | `scripts/run_live_postgres_checks.sh disabled` | 128 项 live 测试通过；内部同时覆盖 Enabled／Disabled，包含管理、业务认证、设备、refresh、OIDC、Cookie 与参考宿主 |
| 参考 H5 | 本地合成 API mock + 实际浏览器 | Cookie 恢复、可见 QR SVG／Code 128 SVG、当前人员／目标工位／设备识别展示及带 revision／expected_session 的批准请求通过；无应用 JS 错误 |
| 原生示例 | Node 语法检查、协议向量及代码审查 | 请求前保存固定操作；创建／关联响应丢失用 lookup；兑换／恢复前后原子文件写、fsync、rename，先保存 bundle 再 ACK；已确认后丢弃迟到 bundle |

所有 live 测试使用显式配置的测试连接，并且每例创建、使用和删除自己命名的随机 schema；没有升级、重置或清理任何现存应用 schema。连接参数和秘密不写入版本文件。

## 本次 v6 增量与验证

- Pending refresh 撤销使用类型化 `ClientRevocation`（SQL 值 `client_revocation`），修正非法原因值导致撤销回滚的问题。
- 新增 `close_origin`／`/auth/device-scan/close-origin` 和持久化 closure；原 create／claim 的最终事务与关闭共享设备锁。未知原请求、过期手机码和响应再次丢失均可收敛；关闭成功不再执行原操作。
- 已签发未 ACK 的结果原子撤销；已 ACK 返回 `already_activated`，不隐式注销 Active。关闭不依赖来源会话、账号或宿主新登录资格继续有效。
- lookup NotFound 明确非终态；关闭确认需要明确 origin_action，不能将另一种未提交动作误判为终结。新 purpose 与全部十个跨语言向量固定。
- 参考宿主启用扫码时正确配置全部十种 proof purpose。原生例子保持原操作上下文、关闭响应丢失重试、关闭后清除 Pending 凭据及新流程使用新 ID；同流程重试保留 bundle。
- 显式 v5→v6 迁移与 v4→v5→v6 链路、损坏 closure PK 的 readiness 拒绝已验证；启动不迁移已有应用 schema。

| 层级 | 已通过结果 |
| --- | --- |
| Web | 冻结依赖安装、构建、83 项客户端测试和 3 项嵌入包测试 |
| Rust | fmt、workspace all-targets check；workspace 416 项通过、141 项 opt-in live 测试 ignored；最新 Core 扫码 20 项通过 |
| HTTP／协议 | Axum 扫码 11 项通过；Security 6 项；Node 10 向量与 150 篡改案例；新原生 helper 与实际 Node 子进程的合成 HTTP 执行测试通过 |
| 完整 PostgreSQL | `scripts/run_live_postgres_checks.sh disabled`：139 项通过，覆盖本次的两个方向 close-first 与 ACK／close 竞争 |
| Pending 撤销与回滚 | ReleaseResult／ActivateSession 拒绝、abort、cleanup、host compensate；SQL 核对 session／refresh／密文／receipt，来源会话及共享 binding 保持；关闭审计末端失败不写终止记录且 Pending 数据整体恢复 |
| 迁移工具 | 实际 psql 包装器隔离 schema 的 v4→v5→v6 dry-run／apply／repeat apply／target dry-run 全部通过，测试 schema 删除 |
| 参考宿主 | 实际参考二进制 + 隔离 PostgreSQL：十种扫码动作均可取得相应用途的设备挑战；不将挑战测试视为完整手机／设备现场链路 |

新迁移包装器及原生恢复测试已加入 CI。测试凭据为公开合成或临时生成材料；真实连接配置未写入仓库、输出或命令参数。

## 宿主接入条件与验收边界

资源服务器必须执行有状态会话校验，拒绝 Pending；JWT 签名校验不能单独满足本协议。生产宿主实现业务准入与目标资料提供者、每请求可信上下文、共享入口限流、cleanup 调度与告警，以及原生安全存储的单一凭据所有者。

SMT 的工厂归属、终端作业状态、人员业务资格和 `device.login` 权限由 SMT 在相应阶段检查；本模块不读取 SMT 表。已有 Active 会话的退出码牌继续使用精确会话注销。

上述结果证明 IDP 服务、传输、持久化、失败恢复及参考交互的已测路径通过。H5 浏览器验证使用合成接口，不能替代真实宿主联调；真实扫码枪、码牌打印、Windows／目标平台安全存储、生产业务最终准入及现场网络故障验收由 SMT 完成。

结果密钥故障、补偿重试、cleanup 停摆、保留期限和回退顺序见[升级手册](device-scan-login-upgrade.md)；完整 Rust／HTTP 契约见[技术设计](device-scan-login-design-v1.md)。
