# A04-D 可选扫码交互技术设计

2026-10-26。修订4设备第四子批，先设计/double check后编码。复用已实现双向扫码Core/Axum/B3路由、手机端H5与QR/CODE128 renderer，补可嵌入设备端client/UI和手机来源入口；不重写授权/准入/持久事务，不增Core/SQL/wire，不做完整验收和部署。

## 1 固定范围与复用

设备展示码(device_display)：create→手机在既有H5登录、attach/inspect并明确approve→设备status→exchange→安全保存Pending bundle→acknowledge→确认后宿主activate。手机展示码(phone_display)：既有H5签发P1短码→设备claim→手机再次inspect/明确批准具体目标→同样交付链。扫描/认领本身不等于批准。

新增DeviceScanClient和DeviceScanLogin组件；来源端新增ScanSourceEntry，只链接宿主固定的同一来源H5 canonical URI，可带D1短码fragment，继续使用既有Cookie/CSRF/expected-session/可信设备资料/confirmation_revision；不把来源token发给设备，不实现第二套approve UI。renderer通过显式`{render(element,value,kind),clear(element)}`注入，直接可用现有window.EmbeddedIdpScanCode；主包不引入antd/jsbarcode。没有renderer仍显示短码和安全来源链接，不伪装为已渲染二维码。未接signer/store/session sink时不开放设备登录。

复用本仓MIT协议/示例状态规则，React19/MIT及既有antd/MIT、JsBarcode/MIT的现有渲染资产；标准WebCrypto SHA256/random和宿主标准Ed25519，无新增运行时依赖。CLI示例仍为示例，不作为生产私钥存储默认。

## 2 公共接口与宿主边界

`new DeviceScanClient({target,signer,store,sessions,transport?})`。target固定baseUrl、tenant_id、client_id(目标client)、entry_id、device_id、audience、verification_uri。base仅同源绝对路径、HTTPS或localhost HTTP，拒绝userinfo/query/fragment/traversal。verification_uri为宿主明确配置的同源同base下既有H5路径；服务端create返回URI必须匹配它，禁止任意远端返回URL跳转。target自身不是授权，业务准入仍由B3 TrustedScanHostContext/ScanLoginAdmission负责。

所有请求无Bearer/Cookie，credentials omit、redirect error、no-store、15秒；独立于本人identity client。设备请求每次取新purpose challenge，由`signer.signRequest({target,action,purpose,external_path,body,challenge,signed_at})`返回{key_id,signature}；body为SDK一次JSON.stringify的原始字符串，外部path包含base前缀，SDK发送完全相同body。purpose映射固定scan_login_create/claim/status/lookup/cancel/exchange/recover/ack/abort/close_origin；实际route acknowledge对应purpose scan_login_ack，close-origin对应scan_login_close_origin。宿主只能签此固定动作/目标/路径，不提供任意HTTP签名器。导出`buildDeviceScanProofBytes(input)`异步纯builder：WebCrypto SHA256原始UTF8 body；SCAN-CONTEXT-V1按purpose/client/entry的8字节big-endian长度与UTF8串哈希；SCAN-V2字段顺序严格复用Core/CLI。签名只返回key id和64字节canonical base64url，五个x-device headers由SDK构造，不允许host覆盖URL/凭据header。每await和发送前检查dispose代际/挑战期限。

store.withLock(target,fn)/load(target)/save(record)必须同设备跨实例互斥、原子且安全持久化；扫码journal独立命名，与登记/轮换共享设备锁。**它包含delivery secret、可能的短码和Pending tokens，必须用受保护宿主存储，禁止localStorage/URL/log。** SDK无默认adapter。sessions.activate({target,issuance_operation_id,bundle})须幂等且只安装确认active的精确session，调用前由SDK核对acknowledged并匹配issuance；宿主还须stateful验证服务端session当前有效，不能只验JWT。sessions.discard({target,issuance_operation_id?})只能清理本流Pending缓存，不能退出任意既有active会话。默认不向EmbeddedIdentityClient导入token。

公开load、create、claim(code)、retryOrigin、lookup、status、exchange、recover、acknowledge、cancel、dispose、getSnapshot/subscribe。方法Promise<void>，无自动后台轮询；UI提供手动查询并尊重服务端poll_after_ms，失败/429采用本地有限退避，不忙轮询。snapshot仅target、phase、公开progress、display_code/verification_url和安全error/busy；绝不含secret/token/receipt_nonce/signature或host handle。显示码是短期秘密，仅明确用于展示/扫码，关闭或到期立即隐藏。

## 3 Journal与状态机

record schema_version1，固定target，origin_action(create/claim)、origin_operation_id、delivery_secret(32byte强随机)、claim_code可选、grant_id/progress可选、display_code可选；exchange_operation_id/ack_operation_id/abort_operation_id首次生成后保存复用；bundle可选含session/tokens/receipt_nonce。phase为origin-unknown、waiting、exchange-unknown、pending、ack-unknown、active、closing、closed。空journal允许新流；已有记录禁止新create/claim切流，终态须宿主核对归档后再开始，不隐式换operation id。

create/claim：先生成origin id/secret并保存origin-unknown，后发原DTO。重试保持原id/secret/claim code；无法确认先lookup；404 scan_not_found仅暂未找到，不能新建流/丢弃secret；显式retryOrigin先lookup，仅该404可重发原材料。lookup携带原action/id/secret和entry/tenant；恢复create显示码时使用固定verification_uri，不依赖lookup不存在的URI字段。状态/交付都校验grant一致、mode一致、合法state与版本/期限/nullable字段；不接受任意response next_action作为可执行路径。

exchange：先持久化固定exchange_operation_id和exchange-unknown，再发送。exchange/recover返回只有progress时不伪造bundle；返回bundle必须匹配tenant/client、grant与原issuance id、session/expiry/token形状。首次bundle保存为pending后才允许ACK；已保存bundle不得被不同session/token/nonce的迟到结果覆盖。recover始终使用原issuance id；无issuance时走lookup/status，不自动开始exchange。exchange写前保存但未到服务端时，recover可能返回409 scan_not_approved；查询status确认仍approved后可显式exchange，复用已有issuance ID。

acknowledge：只对已安全保存bundle，先保存固定ack_operation_id和ack-unknown，再发送；ack失败/丢回应保留bundle及同ack id。返回acknowledged且issuance匹配才调用sessions.activate，然后保存active。激活/save失败可新实例恢复，绝不再创建会话。recover在acknowledged只返回progress时，必须已有本地bundle才可activate，否则提示缺本地交付材料，不能用空token或重新exchange补造。Pending不开放业务能力。

cancel：用户明确取消，先save closing；已知exchange id先发送固定abort_operation_id与原issuance的abort，随后close-origin封闭原create/claim，阻止迟到请求。尚无issuance直接close-origin；其Core也处理已存在未激活交付的撤销。只有outcome closed且原action/id匹配后可sessions.discard本流Pending并保存closed、移除bundle/显示码/claim code，保留原secret/id供关闭结果重查；普通错误保留closing继续原操作，UI保留显式重试关闭按钮；已保存exchange ID但实际尚未发行时，abort可能返回409 scan_not_approved或404 scan_not_found，只对这些确定错误继续close-origin，由其事务封闭迟到写入，不能据此直接清理本地材料；abort返回409 already_acknowledged必须转status/recover核对acknowledged，不再循环abort；本地bundle匹配则恢复activate，否则保留材料提示人工核对。already_activated不能显示已取消或删除active凭据，回到确认恢复，需普通精确logout退出。未知ACK和取消竞态由服务端事务裁决。dispose只终止后续动作，已发写入不回滚。

## 4 UI/合同/验证

DeviceScanLogin提供两方向入口、短码输入/展示、等待手机确认、查询、兑换、安全保存Pending后明确确认接收、原操作恢复与取消确认；busy/loaded gate、StrictMode、卸载/切client代际、zh/en、键盘标签及320px。支持短期码原串（D1.+32字节canonical base64url用于设备展示；P1.+16字节canonical base64url用于手机展示/claim），拒绝把任意URL当claim code；来源链接只用固定URI+fragment，不把delivery secret放URL。不要求浏览器摄像头，宿主扫码器可提供短码文本。既有H5显示可信目标资料并明确approve，不增加自动批准。

局部测试：SCAN-V2独立向量与真实Rust验签；两方向实际JS client与来源H5 API批准组合；create/claim丢响应lookup；exchange丢回应recover同Pending；ACK丢回应status/recover+同bundle激活；取消close-origin及abort拒迟到请求；wrong scope/DTO/version/expiry、写前保存失败、dispose、两实例锁、Pending不activate、秘密不进快照；浏览器StrictMode/缺adapter/renderer复用/错误恢复/窄屏。A03保持18项扫码合同、补消费者/恢复说明和必要schema断言，不虚称端到端平台验收。

## Double check

编码前已独立核对Core/service/proof、Axum DTO与CLI/H5，修正ACK先提交导致abort 409的竞态分支，明确D1/P1长度。实现复审又补原发起404的同ID重试、关闭丢回应重试、exchange未到服务端时的abort 409/404处理、快照与适配器对象隔离，以及撤销交付不可再次ACK。界面恢复不允许将ACK与取消同时视为成功。
