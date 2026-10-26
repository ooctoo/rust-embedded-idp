# A04-D 可选扫码组件接入

本页描述设备侧的可选嵌入组件；手机侧继续使用参考宿主已有 `/auth/browser/device-scan/ui`。两种方向都要求手机核对并明确批准目标设备。客户端不能代替服务端 B3 admission 或设备 proof。

## 组件与依赖

从 `@embedded-idp/react` 导入 `DeviceScanClient`、`DeviceScanLogin`、`ScanSourceEntry`、`buildDeviceScanProofBytes` 及相关类型，载入包的 CSS。复用宿主 React 19；扫码入口不导入管理子包、antd 或 Node 密钥代码。已有二维码/CODE128 renderer 通过 `renderer` 属性显式注入；没有 renderer 时展示短码和手机入口，不要求浏览器摄像头。宿主扫码枪可将 P1 原始短码交给 `client.claim(code)`。

本批无新增依赖。仓库代码 MIT；React MIT；参考宿主已有 antd 与 JsBarcode 资产均 MIT，继续保留现有许可证/第三方告知。平台密钥、原生桥接、受保护存储由宿主选型，不能把本仓测试 signer 当生产实现。

## 必须提供的安全适配器

- `target` 固定 `baseUrl/tenant_id/client_id/entry_id/device_id/audience/verification_uri`；audience、entry、外层路径前缀必须与宿主路由配置一致。确认地址必须等于同源同 base 的 `/auth/browser/device-scan/ui`。生产使用 HTTPS。
- `signer.signRequest(input)`：核对固定目标、动作、purpose、原始 body、外部路径与挑战，在设备持钥边界内签名，返回 canonical base64url `key_id/signature`。可用 `buildDeviceScanProofBytes({...input,key_id})` 构造 SCAN-V2 字节；私钥不返回浏览器。每次请求重新获取 challenge；不能缓存并复用签名。
- `store.withLock/load/save`：同设备跨实例、跨进程互斥，与登记/轮换共用设备锁，扫码 journal 使用独立命名空间。`save` 必须原子且安全持久化。journal 包含 delivery secret、P1/D1 和 Pending tokens，不能存入普通 localStorage、诊断日志或 URL。不能把进程内 Promise 锁当成原生跨进程锁。
- `sessions.activate({target,issuance_operation_id,bundle})`：以发行 ID 幂等安装精确会话，并在开放业务前检查服务端当前 session 状态。SDK 只在核对 ACK 后调用；仅验 JWT 签名不够。
- `sessions.discard({target,issuance_operation_id?})`：只清除此扫码流的 Pending 缓存，不能退出已有普通会话。SDK 不会自动把令牌导入 `EmbeddedIdentityClient`。

没有适配器时不应构造 client；`<DeviceScanLogin />` 呈现不可用说明。不要提供“临时无签名/内存存储”的生产降级。

## 使用与恢复

宿主创建长期 client 实例，把它交给 `<DeviceScanLogin client={client} renderer={renderer} />`。挂载仅 `load()`，不会自动发起扫码。销毁宿主流程时调用 `dispose()`，已经提交的网络写入不会被回滚。组件卸载不销毁宿主持有的 client。

设备展示方向 `create()` 返回 D1；手机使用固定 H5 的入口扫描/输入，`attach/inspect/approve` 后设备查询状态。手机展示方向由 H5 发 P1，设备 `claim(P1)` 后手机必须再次检查具体目标并批准。两者都在 approved 后执行 `exchange()`，先安全保存 Pending bundle，再显式 `acknowledge()`，确认后才激活。

`lookup()` 恢复原发起结果；`retryOrigin()` 在 origin-unknown 下先 lookup，仅 `scan_not_found` 时复用原 action、operation ID、secret 和 P1 重发。404 不意味着原操作失败，禁止换 ID 或丢弃 journal。`recover()` 始终使用原 issuance；ACK 后服务端不再返回 token，本地 bundle 丢失不能通过重新 exchange 补造。

取消调用 `cancel()`：先持久化 closing，必要时 abort Pending 交付，再 close-origin。失败后继续用同一方法重试；不能先删 journal。exchange 尚未抵达时的 abort 409 scan_not_approved/404 scan_not_found 会继续 close-origin，由服务端事务阻止迟到写入。若 ACK 已先完成，服务端返回 already_acknowledged/already_activated，客户端转入确认和激活，不能显示取消成功或删已激活凭据；退出该会话须走普通精确 logout。

Snapshot 仅供 UI：不包含 token、delivery secret、receipt nonce 或签名。显示码本身仍是短期敏感材料，不应被分析埋点采集。禁止使用 response.next_action 拼接 URL。UI 手动查询尊重 poll_after_ms/本地退避，直接调用 client 的宿主也应限频。

已有 journal 阻止开始第二个流程。完成/关闭后的归档由宿主在核对服务器状态后显式处理；SDK 不自动归档或创建新 operation ID。关闭记录保留原 ID/secret 用于确认，宿主需制定保护存储的保留与清理策略。

## 验证边界

[详细设计](a04-d-technical-design.md)、[实施方案](a04-d-implementation-plan.md)、[局部实施记录](a04-d-implementation-result.md)。`scan-demo.html` / `scan-browser-check.mjs` 是 mock UI fixture；`scan-live-check.mjs` 只由指定隔离参考宿主测试调用，使用合成测试私钥和临时受限文件。它们都不等于真实手机摄像头、扫码枪、原生 keystore、跨进程锁或生产验收。
