# 局域网 HTTP 开发接入

状态：实施契约。适用于通用嵌入宿主和 IDP 参考应用，不依赖 SMT 数据或配置。

## 模式与启用条件

默认行为保持 HTTPS 和现有显式回环 HTTP。新增 `HttpTransportPolicy::DevelopmentPrivateNetworkHttp`，只有 `embedded-idp-axum/development-private-network-http` feature、`debug_assertions` 构建和宿主显式选择三者同时满足才可构造；不满足立即返回配置错误，即使配置的是 HTTPS。标准 release 构建拒绝启用。Cargo profile 可以自行覆盖 debug assertions，这是一项开发构建护栏，并非可信部署环境证明。

策略只由可信启动配置产生，不从请求参数、Host、Forwarded 或 X-Forwarded-* 推断。新增 HTTP 地址只接受规范 RFC1918 IPv4 字面地址：10/8、172.16/12、192.168/16。任意域名、公网、CGNAT、链路本地、IPv6 ULA、数值缩写均不接受。0.0.0.0 是监听地址，不能作为外部 Origin。默认 localhost、127.0.0.1、[::1] 保持兼容。

HTTPS 和现有回环 HTTP 仍使用完整 Cookie 模式。实际私网 HTTP 强制受限浏览器模式，不会因为浏览器缺少 API 而自动降级。H5 与浏览器 API 必须同源；跨端口开发通过宿主同源反向代理接入。私网 HTTP 明文传输密码和凭据，仅用于隔离开发环境和测试账号。

## Rust 接入与有效期

原 `BrowserSessionHttpConfig::new`、`ScanDeviceHttpConfig::new` 签名和默认行为保留；新构造入口在原参数后接受 `&HttpTransportPolicy`。统一校验浏览器 Origin 和扫码 verification URI。

受限浏览器会话默认上限 **900 秒（15 分钟）**，允许 **60–3600 秒（含端点）**。私网配置可调用 `.with_development_session_ttl_secs(seconds)`；其他模式拒绝此设置。有效期从会话实际创建时刻计算，不滑动续期。实际会话及刷新凭证的有效期为原配置与该上限的较小值；原更严格配置不会被延长。访问令牌有效期必须短于刷新凭证，界面按返回的访问到期时间要求重新登录，可能早于上限。

宿主应为浏览器单独构造认证服务和兼容的令牌签发器：

1. 令牌签发器 refresh TTL 取 `min(original_refresh_ttl, development_ttl)`，access TTL 不大于 `min(original_access_ttl, refresh_ttl - 1)`。
2. 对 Core 业务或管理认证服务调用 `.into_restricted_browser(development_ttl)`，得到只暴露浏览器服务契约的 `RestrictedBrowserSessionService`。Core 在原签发事务中限制实际 session/refresh 到期；签名声明或凭据期限超出限制则整个签发失败，不用 HTTP 响应裁剪掩盖错误配置。
3. 将受限服务用于 `browser_session_router`，以及业务扫码的 `try_scan_browser_router`。它们核对 HTTP 配置与服务期限声明，不接受未限制的普通服务。
4. 设备登录、设备扫码签发、显式令牌接口和 OIDC 继续使用独立的原服务。不能全局修改宿主 AuthConfig 来实现浏览器限制。

Core 验证 Cookie 背后保存的会话时，受限入口还拒绝期限超出上限的旧长期会话。数据库结构不变。首次设备登记、设备证明、一次性消费、Pending/release/ACK、设备撤销、兑换结果恢复和原操作终结完整保留；设备会话期限及设备恢复窗口不缩短。

## 服务端决定模式，宿主传给 Web

`BrowserSessionHttpConfig::client_config()` 返回可序列化的非敏感描述：

```json
{"mode":"development_login","session_ttl_secs":900,"restore":false,"refresh":false}
```

完整模式为 `{"mode":"cookie","session_ttl_secs":null,"restore":true,"refresh":true}`。

宿主从已经成功构造的服务端配置取得描述，安全编码进页面启动数据，或通过同源宿主启动配置接口交付。不能让页面 query/localStorage 自行启用。参考应用把描述 HTML 转义后写入 `meta[name="idp-browser-config"]`；management 和扫码页面读取同一配置。描述无凭据、无身份，不参与授权；服务端独立检查。

```ts
const client = new EmbeddedIdentityClient('/idp', undefined, {
  mode: browserConfig.mode,
  browserConfig,
});
```

`ManagementClient` 接收相同 options。开发模式缺失描述或模式冲突直接失败。宿主自有 H5 可复用导出的 `secureRandomUuid()`；使用原生 randomUUID 或 getRandomValues 生成 UUID v4，无 Math.random 回退。

## 浏览器生命周期和身份断言

开发模式支持密码登录、选租户、退出和两种扫码授权。页面重载无自动恢复，访问到期重新登录；调用 restore 明确失败，取访问凭据时不自动 refresh。访问凭据只在内存。Cookie 仍是 HttpOnly、SameSite=Strict、原路径和用途隔离，仅私网 HTTP 不设置 Secure。

扫码身份从本页成功登录/选租户响应取得。context 及所有扫码动作携带 tenant_id/account_id/session_id/client_id 四字段 expected_session；服务端与当前 Cookie 的真实身份核对。旧标签页不能把新 Cookie 身份自动接纳为原操作的操作者。身份变化或失效后清理工位确认和显示码，并要求重新登录。

开发模式退出必须带预期身份，无本页身份的 SDK 只清本页状态，不发起无断言退出。不同标签页并发登录/退出允许导致 Cookie 被覆盖或清除及重新登录；不保证完整模式的跨标签串行语义。正确性由服务端身份断言保障，不能用每标签内存锁替代 Web Locks。SDK revision 仍拒绝迟到响应重新建立旧页面状态。已发出的请求按服务端验明的身份执行，前端不能收回已经提交的授权。

## 稳定错误

| 场景 | HTTP | 错误码 | 宿主处理 |
| --- | --- | --- | --- |
| 开发入口请求 Cookie restore | 403 | browser_restore_disabled | 不重试恢复，显示登录 |
| 开发入口请求 Cookie refresh | 403 | browser_refresh_disabled | 不重试续期，显示登录 |
| Cookie 与预期人员/租户/会话/客户端不一致 | 409 | browser_session_changed | 清确认上下文，重新登录，不能改用新身份继续 |
| 受限 Cookie 会话失效或到期 | 401 | browser_session_expired | 清本页身份，重新登录 |
| 受限 context/退出缺少预期身份 | 400 | browser_expected_session_required | 修复调用方，不进行无断言重试 |
| Origin/CSRF 检查失败 | 403 | browser_origin_rejected | 修复可信同源配置 |

`browser_session_expired` 包含无法再使用的无效/撤销会话，不通过错误细分泄漏认证事实。浏览器认证路由沿用 `code` 字段，扫码路由沿用 `error` 字段；不改变既有响应外形。SDK 错误公开 `code`。其他已有字段校验、存储故障和设备证明错误沿用原契约，不伪装成成功退出或登录到期。禁用 restore/refresh 在调用服务前拒绝，没有轮换/撤销副作用。

## 参考应用启动

参考应用 feature 转发至 Axum。示例配置（替换为本机真实私网地址；保留现有数据库及密钥配置）：

```sh
EMBEDDED_IDP_APP_HTTP_TRANSPORT_POLICY=development-private-network-http
EMBEDDED_IDP_APP_DEVELOPMENT_SESSION_TTL_SECS=900
EMBEDDED_IDP_APP_BIND_ADDR=0.0.0.0:9100
EMBEDDED_IDP_APP_BROWSER_ORIGIN=http://192.168.31.159:9100
EMBEDDED_IDP_APP_SCAN_LOGIN_VERIFICATION_URI=http://192.168.31.159:9100/auth/browser/device-scan/ui
```

显式设置 `EMBEDDED_IDP_APP_ISSUER`，不能从 0.0.0.0 推导。既有回环 issuer 可以用于本次密码/扫码联调的固定令牌标识；远端 OAuth/OIDC discovery 仍应使用现有可访问 HTTPS issuer，本次不放宽 OIDC 地址规则。扫码启用、结果加密密钥、来源客户端允许关系继续按原扫码接入文档配置。

```sh
./scripts/run_embedded_idp_app.sh disabled --features development-private-network-http
```

脚本先构建 Web。开关不自动启用设备登记、不初始化或迁移 schema。原有 HTTPS 联调入口可继续使用。

## 浏览器能力与验收边界

手机系统相机/原生扫码器可读取设备链接，再打开 HTTP 授权页（实际扫码器及浏览器需验收）；手机 HTTP 页面可以展示二维码/Code128，由设备扫码枪读取。网页内 getUserMedia、WebCrypto subtle 和 Web Locks 的安全上下文要求不会被本功能解除。HTTP H5 内直接调用摄像头需要 HTTPS 或原生桥接。

验证矩阵必须包含默认/feature/debug/release 构建、URL 边界、两种会话模式、业务/管理用途、设备恢复回归和真实非安全上下文浏览器。仅回环页面或把 HTTP 标记为安全来源的浏览器启动参数不构成本次浏览器验收。真实数据库隔离测试、浏览器模拟后端检查、真实前后端浏览器联调及手机/扫码枪现场验收分别记录。

交付应固定 Git 提交，构建 embedded/management/scan-code Web 归档并附 SHA-256 和文件清单。生成的 dist 不提交 Git；宿主固定源码依赖与对应 Web 制品，更新自身 H5、桌面 Debug URL 放行后再做目标平台验收。

实际验证结果见[验收记录](development-private-http-validation.md)。
