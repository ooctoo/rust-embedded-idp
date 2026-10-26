# A04-A 宿主接入

2026-10-26。本地包未发布npm。使用现有业务身份客户端和同一入口：

```tsx
import { EmbeddedIdentityClient, EmbeddedDeviceClient, EmbeddedAuth, DeviceSelfService } from '@embedded-idp/react';
import '@embedded-idp/react/style.css';

// 在组件外或useMemo内创建稳定实例；不要每次render重建。
const identity = new EmbeddedIdentityClient('/identity');
const devices = new EmbeddedDeviceClient(identity);
// Cookie模式沿用现有browserConfig；组件自身不读Cookie或保存token。
export function AccountDevices() {
  return <><EmbeddedAuth client={identity} /><DeviceSelfService client={devices} /></>;
}
```

宿主挂载对应业务entry的`tenant_device_router`；本人接口只使用内存Bearer与服务端当前业务身份，不接管理端token。请求桥限制到本人device路径，复用identity的请求前后revision校验。组件props为client、language（zh-CN/en-US）、className、style，主题沿用`--embedded-idp-*`变量，不导入AntD或全局CSS。

列表、详情和keyMetadata仅公开当前本人绑定的元数据。解绑只移除本人绑定并撤销相关设备会话，不是删除或撤销设备。发送前保存同一UnbindIntent；无法确认响应时只查询原operationResult，不生成新命令。若解绑导致当前设备会话失效，需重新登录同一tenant/account/client再读回执。intent仅在当前组件/client内存保留，刷新页面或销毁client后本批不提供恢复；没有持久化凭据。服务端本人receipt现有语义是tenant/account/operation ID范围，前端的client实例绑定不构成新增服务端隔离。

A04-A不提供登记/密钥轮换。后续必须先设计用途受限signer、安全候选handle与有期限的宿主admission；不能把设备UUID/public JWK当作所有权，也不能以WebAuthn凭据替代Ed25519密钥。rotate当前没有operation receipt，不能套用解绑回读语义。

局部交互夹具：`pnpm --dir web exec vite --host 127.0.0.1 --port 4187`后打开`/embedded/device-demo.html`。固定合成数据，首个解绑模拟提交成功但丢失响应，不代表真实准入或平台持钥。复用仓库已安装的`scripts/n2-ci` Playwright，可运行`node web/embedded/device-browser-check.mjs`；输出默认`/private/tmp/idp-a04a-ui`，可通过IDP_A04_UI_ORIGIN/IDP_A04_UI_OUTPUT覆盖。

真实客户端局部测试由app的`a04a_device_self_client_reads_and_recovers_unbind_against_reference_host`驱动，需要先Web build与显式隔离Postgres URI；测试调用`device-live-check.mjs`加载实际构建包并请求真实宿主。普通离线UT不依赖数据库或浏览器。完整验收、原生持钥与部署另行安排。
