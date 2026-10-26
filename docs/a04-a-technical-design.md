# A04-A 本人设备与解绑回执技术设计

2026-10-26；修订4 A04 的第一子批。先设计并复核，再编码。B2/B3已提供设备路由与本地协议验证，本批不改变Core、SQL或HTTP wire。A04整体仍分本人设备、登记、双签轮换与可选扫码；本批不声称完成持钥端体验。

## 现有路径与边界

`tenant_devices.rs` 已提供 GET /devices、/devices/:id、/devices/:id/keys/:key、POST /devices/unbind、GET /devices/operations/:operation。列表/详情仅本人绑定；Bearer认证取得当前业务AccessActor，租户/client/成员和版本由Core重验。UI不得调用管理绑定接口。解绑是移除本人绑定，不是删除设备、吊销设备公钥或代替管理员撤销设备。

EmbeddedIdentityClient已有内存access token、refresh single-flight和私有revision，但外部客户端直接取token后fetch无法复核返回时的身份代际。本批在该类增加受限设备请求桥：仅允许现有本人GET路径及POST /devices/unbind；统一复用相同base、transport、credentials:omit、no-store、redirect:error、15秒超时与revision，返回请求起点session副本及未知JSON。不接受任意URL或自报tenant；不向组件暴露token。已有authenticated私有方法仅增加可选JSON body，旧调用不变。

## 薄客户端

新增EmbeddedDeviceClient(identity)，绑定一个已有EmbeddedIdentityClient，无第二个base/transport。提供list(cursor)、detail(deviceId)、keyMetadata(deviceId,keyId)、prepareUnbind(device)、unbind(intent)、operationResult(intent)。请求与校验对照实际Axum投影：

- 设备：tenant_id/device_id/client_id/proof_key_id/status/version/key_version；本人投影另含binding_id/binding_version/device_name/registered_at_unix_secs/last_seen_at_unix_secs/binding_status。
- 状态只接受已有枚举；设备/绑定/非空key版本是正安全整数（proof_key_id/key_version可为null），标识符合现有ID/UUID或key指纹约束，时间为非负安全整数或明确null；拒绝错tenant/client/device、重复列表设备、>50条、无后续游标却has_more。游标只作不透明值传输，最多2048字符。
- key metadata只展示公开算法/状态/版本/时间，不含密钥。
- 解绑intent在发送前固定operation_id、device_id、binding_id、expected_version、tenant/account/client及入口client对象；采用现有secureRandomUuid。不得由UI自行指定result_version。不自动重试写请求。
- 回执校验 operation_id/device_id/binding_id 与原intent一致，operation=`device.binding.unbind.self`、result_status=`unbound`按Core实际固定值，result_version及audit/time类型正确；result_version须为原expected_version+1，不使用当前列表版本推断历史命令成功。

请求期间logout/切租户/重新登录，旧revision结果必须拒绝。intent允许同一identity客户端内同tenant/account/client重新登录后回读（session可更新），但跨入口客户端或不同身份不允许重放/读取。该client/入口约束是前端intent保护，不是服务端回执的新增隔离保证。现有Core/store按tenant/account/operation ID读取本人回执，并校验当前client会话；同账号同tenant在另一client知道operation ID时可读取该最小回执。本批保留该语义，不修改SQL或把UI约束误称服务端边界。服务器仍是最终授权方。组件不持久化凭据或intent；页面重载后仅提供手工宿主恢复能力的后续扩展，本批不承诺跨重载恢复。

## 组件状态与交互

新增公开DeviceSelfService({client: EmbeddedDeviceClient, language?, className?, style?})，复用现有CSS module主题变量与宿主React，不引入AntD/全局store。显示当前tenant/client、本人设备分页、详情/公钥元数据、设备与本人绑定的独立状态。默认中文并提供英文。无session时提示先登录；loading、空列表、失败均明确显示。

解绑采用行内确认，展示设备名/ID、本人绑定与后果。确认前prepare intent；发送期间禁用重复操作。收到合法回执才显示成功；超时、网络失败、5xx或响应不合法保留原intent并显示“结果未确认”，提供只读“查询原操作结果”。404不是未执行的证明，不自动生成新operation id。恢复成功后可重新加载列表；重新加载失败不得覆盖已经确认的成功回执。401可触发登录失效，当前UI敏感数据随身份变化隐藏；同身份重新登录可重新查询原操作，但不得把旧数据呈现在另一身份下。

组件以client+当前身份为状态隔离边界，清理订阅/丢弃过期异步结果；身份切换即时隐藏旧列表/详情，不能等effect后才隐藏。同一身份并行读取采用最新请求序号防止旧页覆盖新页。错误用role=alert并聚焦可读容器，状态用role=status；原生button/label和可见焦点支持键盘，窄屏不截断设备ID。不展示尚未实现的登记/轮换按钮。

## 复用与后续依赖

复用本仓MIT客户端、React19(MIT)、TypeScript/Vite现有构建和测试、现有Core/HTTP/PG能力；无新增运行时依赖或迁移。A04-B再细化用途受限signer/admission合同、固定测试密钥adapter和登记恢复；A04-C再接双签与当前active key核实（rotate无receipt）；A04-D扫码可选。没有真实平台指定前不引入原生keychain或浏览器私钥存储实现。

## 验证范围

客户端测试实际序列化请求/响应、同identity认证、错域/非法DTO、分页、解绑原intent回执、未知结果恢复、401、logout和切换后的迟到响应。组件build/exports/SSR与真实浏览器夹具验证键盘确认、未知结果回读、身份切换隐藏和样式隔离。真实API局部测试复用已登记设备的宿主，确认本人列表/详情/解绑/回执路径，与浏览器夹具区别记录。不做完整验收、部署、提交或推送。
