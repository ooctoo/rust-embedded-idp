# A04-B 登记与宿主恢复：局部实施记录

2026-10-26。先完成[详细技术设计](a04-b-technical-design.md)和[实施方案](a04-b-implementation-plan.md)，对照Core生命周期、Rust JWK解析器、Axum DTO、B2 admission交叉复核，再实现并复审代码。未提交、推送、完整验收或部署。

## 已完成

主入口新增DeviceRegistrationClient、DeviceRegistration及宿主契约类型/规范字节builder。独立于登录会话，显式注入signer、admission、持久store与锁；只消费既有provision、registration-result、proof/challenges和complete四接口。没有新增Core/SQL规则、迁移或运行时依赖，原A04-A本人Bearer请求桥未扩权。

登记与完成写入前先保存unknown状态；网络响应丢失后保留原device/request/key引用，新实例加载原记录并重新授权查询。完成请求使用新challenge和真实REGISTRATION-V2签名，结果再次核对后才调用宿主幂等activate。404不等于远端未写入；查后重试仅复用原provision参数。停用/撤销/轮换后的结果、scope改变、期限失效、错误DTO均拒绝继续激活。

实现复审修正了：wire公钥必须带kid；32/64字节Base64URL尾位规则不同；challenge期限可能晚于登记期限，两者须分别检查；持久化期间过期/取消不能继续发送；prepare保存结果不确定时不得删除key；dispose与prepare并发时清理确定未发送候选；StrictMode加载重复与旧客户端迟到请求不得污染新界面。候选清理失败或结果不确定不声称回滚。

API合同修复Registration.pending的proof_key_id/key_version nullable，并说明同scope原请求幂等、每次重授权、complete非幂等及challenge成功不能证明登记可完成。entry_id只参与本地上下文，B2服务端隔离按tenant/client/device/scope，不能将本地入口标识当新增授权。

## 验证

| 检查 | 结果与范围 |
| --- | --- |
| `pnpm --dir web test` | 145通过，其中A04-B controller 23项；覆盖真实Ed25519本地验签、恢复、写前日志失败/提交结果不确定、scope/期限/DTO/target、并发锁、迟到dispose和后续轮换/撤销 |
| `pnpm --dir web build` | 通过，含Web类型检查、独立bundle和声明生成 |
| `pnpm --dir web test:embedded-bundle` | 5通过，含公开导出、缺adapter可挂载、无测试私钥/测试adapter进入产品bundle |
| `node web/embedded/registration-browser-check.mjs` | Chromium局部夹具通过：StrictMode、两种响应丢失、新实例恢复、迟到错误隔离、缺client及320px无横向溢出；窄屏截图人工查看 |
| A04-B `live_reference_host`指定测试 | 独立PostgreSQL schema与本机参考宿主通过；运行实际构建后的JS client，Node标准crypto固定测试key由Rust真实验签。provision与complete各丢一次已成功响应，用磁盘journal、新实例恢复；只发生两次远端写入、一次密钥准备，scope变化拒绝恢复 |
| A03合同/漂移 | 四份OpenAPI无漂移，15项合同测试通过 |
| Rust局部编译/格式 | app live测试目标编译、workspace all-targets check、fmt check通过；未跑workspace完整测试/完整验收 |
| `git diff --check` | 通过 |

局部输出保存在`/private/tmp/idp-a04b-*.log`，截图在`/private/tmp/idp-a04b-ui/`。临时文件不是长期发布证据，CI/后续验收应按仓库脚本重跑。

## 边界与后续

真实宿主测试为disabled租户模式的专用隔离环境，不代表所有租户模式、原生设备或生产容量验收。测试文件journal只证明本次流程持久化与新实例恢复；测试内存mutex不是跨进程锁验收，也没有模拟断电/fsync/文件系统损坏。没有提供默认浏览器私钥存储或动态业务grant服务。包仍为仓库本地组件，未发布npm。

A04-C双签轮换、A04-D可选扫码交互及A05仍待后续按设计/复核/实施推进；原生持钥与安全持久store按[接入说明](a04-b-integration.md)由宿主落实。本次未触及并行CI/N2/PG修改，没有提交或推送。专用`idp-a04b-20261026`容器及卷已删除，4187本地Vite服务已停止。
