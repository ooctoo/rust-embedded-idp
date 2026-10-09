# 局域网 HTTP 开发模式验收记录

日期：2026-10-09。源码交付以对应提交及 Web 归档内 manifest.json 为准。本记录不包含凭据、数据库连接或设备私钥。

## 自动验证

- `cargo check --workspace --all-targets --locked`：通过。
- `cargo test --workspace --locked`：425 passed，141 ignored；忽略项主要是需要显式数据库的测试，并非已验收。
- Axum 开发 feature 测试：96 passed；Core 的受限浏览器测试包含实际持久化到期、过长期限/签名声明回滚、选租户回滚、预期身份和管理用途隔离、旧长期 Cookie 拒绝。
- 参考应用开发 feature 单元测试：16 passed。
- `cargo test -p embedded-idp-axum --release --features development-private-network-http http_transport::tests --locked`：2 passed，实际 Release 构建确认开发策略拒绝启用。
- Web 客户端测试：93 passed；embedded 制品测试：3 passed；完整 Web 构建通过。
- 格式检查与 diff 空白检查通过。

## 隔离 PostgreSQL 与实际参考进程

使用显式本机测试数据库连接，每次创建和删除随机 schema，未修改已有宿主/参考应用 schema。

新增私网 Origin 测试直接运行实际参考二进制：验证 120 秒配置写入 session 与 refresh 的实际有效期、禁止 restore/refresh 不轮换、不撤销、默认 token 会话期限不变、错误 Origin/缺失断言拒绝、Alice/Bob 旧身份断言拒绝且不覆盖 Cookie、扫码 context 与 phone code、HTML 模式描述以及服务端到期拒绝。已有回环 Cookie 恢复/退出/用途隔离测试在 enabled/disabled 两种租户模式通过。以上使用回环 TCP 配私网 Origin，单独不算非安全浏览器验收。

## 真实非安全上下文浏览器

使用 Playwright CLI 控制实际 Chromium，通过本机 RFC1918 地址访问临时参考服务，后端使用独立 PostgreSQL schema。未使用 insecure-origin-as-secure 类浏览器开关。观测为：

```json
{"isSecureContext":false,"navigator.locks":"undefined","crypto.randomUUID":"undefined","crypto.getRandomValues":"function"}
```

完成以下检查：

- 普通业务人员登录及 management 管理员登录均通过；页面重载要求重新登录。
- 设备显示码：Node 原生参考客户端使用真实 Ed25519 签名创建请求，浏览器展示当前人员和目标设备并批准；设备兑换、恢复同一结果、ACK 成功。
- 手机显示码：浏览器生成 QR/Code128，Node 参考客户端读取码并使用真实签名关联设备，浏览器核对目标并批准，设备兑换和 ACK 成功。
- 设备实际会话保留原 604800 秒期限，恢复窗口保留 120 秒；受限浏览器上限为 900 秒。
- 最终制品重复执行“显示码 → 取消 → 再显示码”，QR 和 Code128 均重新渲染，清理后的 React 根不会留下空白结果。
- 双标签：Alice 已核对目标后，另一标签登录 Bob；Alice 批准返回 409 browser_session_changed，确认界面清除。Alice 退出也返回同一错误，Bob 仍可出码。

临时设备使用测试生成的密钥并在独立 schema 中准备，不代表此次重新验收了首次设备登记流程。二维码数据通过 DOM/输入传递来模拟扫码器，未使用实体扫码枪或手机摄像头。

## 尚需宿主验收

SMT 固定 Rust 提交和对应 Web 归档，接入其 Debug 私网 URL 策略、H5 配置及 UUID 工具后，还需验证手机系统扫码器打开 HTTP 链接、目标手机浏览器、实体扫码枪和桌面目标平台。HTTPS 的完整会话协调由默认模式及既有回环真实服务/SDK 回归覆盖，本轮未重新搭建真实 HTTPS 反向代理环境。HTTP H5 内摄像头能力仍受浏览器限制。

Web 归档只包含 embedded 包、management 静态制品和 scan-code 制品，以及提交/文件 SHA-256 清单；不包含环境文件、原生设备状态或测试密钥。生成文件不进入 Git。
