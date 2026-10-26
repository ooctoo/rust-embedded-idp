# A04-C 双签轮换局部实施记录

2026-10-26。按修订4，先完成[详细设计](a04-c-technical-design.md)和[实施方案](a04-c-implementation-plan.md)，独立核对Core/SQL/Axum合同与恢复边界后实现，并复审实际代码。接入方式见[宿主指南](a04-c-integration.md)。

## 交付

新增DeviceKeyRotationClient、DeviceKeyRotation与宿主signer/store类型，复用A04-A身份和本人设备读取。身份桥仅增加轮换challenge与rotate-key两个POST，challenge限定精确轮换purpose与当前tenant，不开放任意路由或准入接口。无Core/SQL行为变更、迁移、新运行时依赖或私钥导出。

旧/新密钥签署同一ROTATION-V2字节，wire公钥带kid，expected key/version由服务端CAS核对和推进。持久记录绑定原owner、入口、设备、binding与版本；提交前保存rotate-unknown。完成后按detail→当前指针对应metadata→detail核对，再幂等激活宿主候选并保留旧key。没有新增轮换receipt，也不把历史元数据称为原操作回执。

同一候选可在原owner重新登录后恢复。unknown读取到旧key仍有效时保持unknown，不能丢弃候选，仅允许显式新challenge重试。轮换journal与登记journal分开命名，但必须共享同设备锁。终态不自动开始下一轮，归档与旧key清理由宿主明确处理。

复审修复：状态通知不得清空成功/未知阶段；unknown不能降为prepared；同一新旧handle不能交给discard；保存结果不确定保留key；root入口与路径穿越校验；执行中账号切换及同步订阅回调后须重新检查再发送；组件初次读取失败可重试，StrictMode复用加载，身份切换隐藏旧记录。界面将原expected key明确标为“轮换前密钥”，避免完成后误称当前key。

## 局部验证

| 检查 | 结果 |
| --- | --- |
| Web测试 | 165通过；新增轮换controller 19项、身份桥1项。覆盖规范字节、真实Node Ed25519双签、journal与scope/owner、写前失败/提交结果不确定、激活/保存失败、challenge过期、会话切走再切回、dispose、并发锁、未知结果不清理 |
| Web build | 通过，含TypeScript、独立bundle及声明生成 |
| 组件包测试 | 6通过，轮换公开导出/无adapter挂载/测试密钥不进产品bundle |
| Chromium局部夹具 | 通过：StrictMode、一次load失败重试、成功提交后丢响应、重建恢复不重复写、owner切换隐藏、unknown无discard、缺client与320px布局；截图已查看 |
| 真实参考宿主指定测试 | `a04c_rotation_client_dual_signs_and_recovers_against_reference_host`通过。专用隔离PostgreSQL与构建后的JS包，固定测试key由Rust验证双签；错旧签名、错新签名均拒绝且原key不变；正确提交丢响应，同owner重登录+磁盘journal新实例恢复；key/device版本仅加1，原key retired；原请求重放实际收到409 |
| A03合同/漂移 | 四份OpenAPI无漂移，15项合同测试通过；说明双签、CAS、nonce、原子审计和无receipt恢复边界 |
| Rust/格式 | 指定app测试目标编译、workspace all-targets check、fmt check和git diff --check通过 |

首次真实测试发现错误签名返回401使现有身份客户端清空会话；修正测试为同owner重新登录继续，未放宽服务端验签或会话校验。浏览器夹具修复了错误地从rotate DTO读取tenant_id的问题（此字段由Bearer上下文承载），必须验签成功后才模拟丢响应。

日志在`/private/tmp/idp-a04c-*.log`，截图`/private/tmp/idp-a04c-ui/320.png`，均为临时局部证据，后续CI/验收应重跑。

## 范围

没有提交、推送、完整验收或部署。真实测试使用disabled租户模式，不代表所有租户/目标平台/生产容量验证。测试文件journal与进程内mutex不证明跨进程互斥、断电恢复或原生keystore安全。宿主额外设备proof transport策略、下一轮记录归档、原生持钥/共享锁仍需接入验证；A04-D可选扫码和A05继续按设计先行推进。所有测试私钥均为固定合成fixture，不导出产品包。

专用`idp-a04c-20261026`容器与卷已删除，本机4187 Vite服务已停止。
