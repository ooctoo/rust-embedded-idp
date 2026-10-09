# 扫码授权设备登录参考接入

本目录展示通用参考宿主的接入材料。它不包含业务表、工位模型或扫码枪驱动；生产宿主应实现自身的业务准入和真实终端资料展示。

`native-client.mjs` 是原生层流程的可运行结构示例：它生成 Ed25519 设备证明、在权限受限文件中保存操作与 `delivery_secret`，并在兑换或恢复后先保存 bundle 和 receipt nonce，再 ack。它演示 create/claim/lookup/close-origin/exchange/recover/ack/status/cancel/abort。原始 create 或 claim 请求结果未知时，`close-origin` 使用已保存的原动作和 operation ID 关闭它，不需要手机码、显示码或来源会话。关闭请求响应丢失时保留原状态并以相同数据重试；收到 `closed` 后原子替换状态，清除待交付 bundle、receipt nonce 与 ack 操作，只保留该原动作、operation ID、secret 与摘要供 lookup 或重复 close 核对，不能再作为 create/claim 重用。新建 create/claim 会重置旧生命周期并生成新的 operation ID 和 secret。`already_activated` 保留已激活 bundle，应由宿主正常精确会话注销路径处理。`native-client-state.test.mjs` 检查状态规则，`native-client-execution.test.mjs` 以 mocked HTTP 和临时状态文件执行实际客户端流程。运行前需要一个已登记测试设备的私钥 JWK、设备 ID、租户和已启用的参考服务。示例只使用 Node 内建 API，不输出 `delivery_secret`、令牌、receipt nonce 或私钥；生产原生应用应改用平台安全存储。

```sh
IDP_ORIGIN=http://127.0.0.1:9100 \
SCAN_ENTRY_ID=reference-device-scan \
SCAN_TENANT_ID=0 \
SCAN_DEVICE_ID='<registered-device-uuid>' \
SCAN_DEVICE_PRIVATE_JWK_FILE='<owner-only-private-jwk.json>' \
node docs/examples/device-scan-login/native-client.mjs create
```

参考服务只有在以下配置都存在时才挂载这些路由：

- `EMBEDDED_IDP_APP_SCAN_LOGIN_ENABLED=true`
- `EMBEDDED_IDP_APP_SCAN_LOGIN_ENTRY_ID`、`EMBEDDED_IDP_APP_SCAN_LOGIN_ALLOWED_SOURCE_CLIENT_IDS` 与 `EMBEDDED_IDP_APP_SCAN_LOGIN_MODES`
- `EMBEDDED_IDP_APP_SCAN_LOGIN_VERIFICATION_URI`
- `EMBEDDED_IDP_APP_SCAN_LOGIN_RESULT_KEY_ID` 与恰好 32 字节、无填充 base64url 编码的 `EMBEDDED_IDP_APP_SCAN_LOGIN_RESULT_KEY_BASE64URL`

结果 key 必须由部署者生成并保存在受保护的密钥系统中；参考应用不生成或记录它。`ALLOWED_SOURCE_CLIENT_IDS` 是逗号分隔的明确来源客户端列表，目标客户端始终是参考服务已配置的 public client。

参考 H5 位于参考宿主同源 `/auth/browser/device-scan/ui`。它使用普通业务 Cookie，读取当前人员身份、显示目标设备的服务端资料，并以明确按钮批准或拒绝。手机出示码同时使用本地嵌入的 QR 和 Code 128 SVG 资产；扫描设备显示码仍可粘贴到输入框中模拟相机输入。它不宣称完成真实扫码硬件或平台验收。

`web` 将已有的 Ant Design `QRCode` 用于 SVG QR，并新增直接依赖 `jsbarcode` 3.11.6 生成 Code 128。两者都由 Vite 打入参考宿主的本地 `scan-code.js`，不加载 CDN、远程脚本或扫描数据服务。

详见[技术设计](../../device-scan-login-design-v1.md)、[升级手册](../../device-scan-login-upgrade.md)。
