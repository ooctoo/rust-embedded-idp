# A04-D 局部实施记录

2026-10-26。先完成[详细技术设计](a04-d-technical-design.md)和[实施方案](a04-d-implementation-plan.md)，独立 double check 后编码，并对实现作二次复核。本批只完成可选扫码嵌入交互；未执行完整验收、部署、Git 提交或推送。

## 实施内容

- `DeviceScanClient` / `DeviceScanLogin`：设备展示 D1、设备认领手机 P1 两方向；手机仍通过已有 H5 的 attach/inspect/approve 明确批准具体目标。
- SCAN-V2 proof builder、固定目标/外部路径/原始 body 校验、每动作独立 challenge、无 Bearer/Cookie 的设备请求。独立于本人会话 client，不将来源凭据交给设备。
- 宿主显式 signer、受保护 journal、同设备锁和 session sink；原发起、发行、ACK/abort 的写前记录与同 ID 恢复。Pending bundle 先持久化，确认 ACK 后才调用宿主激活；宿主仍须 stateful 验证。
- `ScanSourceEntry` 固定 H5 链接及可选 renderer 注入；复用现有 QR/CODE128 资产，不新建批准服务、Core 规则、SQL 表、HTTP 端点或运行时依赖。
- 18 项扫码接口合同维持既有路由范围，补恢复、ACK/abort 竞态说明和来源 DTO 字段断言；接入见[说明](a04-d-integration.md)。

## 复核修正

1. 区分 create 包装响应与 claim 裸 progress；统一传输错误类型，避免 404 和 already_acknowledged 分支被绕过。
2. 先持久化再发布交付状态；终态删除可选字段而非保存 undefined；冻结快照并隔离 store/sink 持有的对象引用。已保存 bundle 的 session、tokens、期限和 nonce 必须完全一致。
3. 修正 ACK 先完成的取消竞态：abort 的 already_acknowledged 与 close-origin 的 already_activated 都恢复精确会话，不清理 active 凭据。
4. exchange 未到服务器时，即使本地已有发行 ID，abort 仍可能返回 scan_not_approved/409；这与 scan_not_found/404 一样只能触发继续 close-origin，不能直接视为取消成功。普通失败保留 closing。
5. UI 补 closing 重试、origin-unknown 在 lookup 404 后按原材料重试、空状态读取本地记录、closed 隐藏无效操作；批准/交付后隐藏已用显示码，撤销交付不能再次 ACK。
6. 按真实 Core 修正测试：recover 在尚无交付时不会成功返回 approved；必须查询 status 确认 approved，再用原发行 ID 显式重试 exchange。

## 本地验证证据

| 检查 | 结果与范围 |
| --- | --- |
| `pnpm --dir web test` | 185/185 通过，包含本批 16 项 controller 与 4 项 protocol 测试 |
| 独立 proof 向量 | 同一 protocol 测试覆盖既有 10 个动作，规范字节与 Ed25519 签名完全一致 |
| Web build / embedded TypeScript | 通过；主包不引入管理界面、antd、Node signer 或测试私钥 |
| `node --test web/embedded/bundle.test.mjs` | 7/7 通过，新增公开 exports、SSR 缺适配器与安全来源链接检查 |
| `./scripts/check_api_contracts.sh` | 四份生成合同无漂移，15/15 合同测试通过 |
| Rust 指定 live test 编译 | `cargo test --locked --offline -p embedded-idp-app --features development-private-network-http --test live_reference_host --no-run` 通过 |
| 指定隔离实测 | `a04d_scan_client_both_modes_recover_delivery_and_close_origin` 1/1 通过；专用 PostgreSQL 18.6 容器、随机 schema/端口、真实 Rust host、编译后 JS client 与合成 Ed25519 signer |
| 浏览器局部 fixture | Chromium 通过：StrictMode、缺 client、原发起404恢复、取消丢回应重试、Pending/Active、终态隐藏码、320px无水平溢出；复用现有 QR renderer 的生成和清理 |
| 格式与变更检查 | `cargo fmt --all -- --check`、`git diff --check` 通过 |

真实宿主测试直接通过来源浏览器 API（Cookie + Origin + 固定 browser header + expected_session）完成两方向明确批准。分别丢弃已提交的 create/claim、exchange、ACK 响应，重建 client 从临时 0600 文件恢复：origin/issuance ID 不变、不重复 exchange，Pending token 访问 `/auth/session` 为 401，ACK 后同 token 为 200。还覆盖 ACK 后取消触发恢复、close-origin 响应丢失后确认关闭、Pending abort、发起/发行请求未发送时的重试及取消。它证明局部真实协议/数据库事务集成，不代表真实手机已完成全链路验收。

浏览器 fixture 的 signer/store/transport 是 mock，另测现有 renderer 的实际 SVG 生成；没有验证摄像头、扫码枪、真实手机或原生 WebView。真实 host 测试使用合成密钥及进程内互斥，不能证明生产 keystore、跨进程锁、业务 admission 或硬件安全边界。

本次专用 Postgres 容器及数据卷、Vite 进程已清理；未触碰其他服务。

## 剩余范围

A04-D 本批实现和局部验证完成；A04 整体持钥端交付仍需宿主接入/平台与硬件验证。后续按修订4推进 A05 等尚未完成项，继续先设计及复核。完整验收与部署保持未执行，不以本批证据关闭这些门槛。
