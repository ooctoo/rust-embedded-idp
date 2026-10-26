# A04-C 双签轮换技术设计

2026-10-26，修订4第三设备子批。先设计并double check，再编码。复用Core rotate_key事务、现有本人设备详情/密钥元数据和challenge/rotate-key HTTP接口；不新增operation receipt、数据库表、Core规则或密码学算法。完整验收、部署、原生keystore与A04-D扫码不在本批。

## 1 协议与授权

rotate-key需有效人员Bearer、当前tenant/client及active本人绑定，旧/新Ed25519密钥共同签署同一份ROTATION-V2规范字节。purpose精确为device_key_rotation。规范字节为`EMBEDDED-IDP-DEVICE-KEY-ROTATION-V2\ntenant-id:{tenant}\ndevice-id:{device}\nold-key-id:{old}\nnew-key-id:{new}\nnew-key-version:{expected+1}\nchallenge:{challenge}\n`。客户端为签名计算expected+1并检查safe integer，wire只提交expected_key_id/expected_key_version，不提交new version；服务端锁内推进版本、验证双签、消费nonce、退役旧key、激活新key和追加audit原子完成。proposed_public_jwk必须带kid，与RFC7638 SHA256一致。无admission grant参与轮换。

原EmbeddedIdentityClient的device bridge只增加POST proof/challenges（限定轮换purpose）和rotate-key；保留原Bearer transport和revision检查。新增只读deviceBaseUrl供轮换client校验目标与实际身份入口一致，不另注入任意token或另建登录实现。普通有效人员session可执行轮换，不要求该session本身为持钥登录；私钥与双签仍必需。Cookie模式未提供此Bearer桥能力时失败关闭，不做隐式降级。

## 2 宿主契约与持久状态

新增DeviceKeyRotationClient({devices: EmbeddedDeviceClient, target:{baseUrl,tenant_id,client_id,entry_id,device_id}, signer, store})。base须与devices.identity.deviceBaseUrl规范化后完全一致；不同entry的服务端隔离仍靠client，entry只参与本地上下文。所有动作需当前session匹配target。record额外绑定owner.account_id（tenant/client也核对），允许同owner重登录恢复；执行中任何session切换或dispose使代际失效，切走再切回也不能续发旧动作。

公开方法getSnapshot/subscribe、load、prepare、rotate、recover、discard、dispose，异步动作Promise<void>。snapshot仅target、phase(empty/prepared/rotate-unknown/active/abandoned)、busy、安全error code、公开old/new key ID和版本；不含私钥、opaque handle、完整JWK、signature或token。

必需store.withLock(target,operation)、load(target)、save(record)：跨实例/标签页/进程串行化同一设备候选的所有登记/轮换操作，原子持久存储；锁键不因账号切换绕过同设备互斥。轮换journal与登记journal使用不同命名空间，但共享同设备锁。SDK每操作锁内reload，不覆盖错target/schema/owner记录。record version1包括target、owner、本地rotation_id、原binding_id/binding_version/device_version、expected_key_id/version、current_handle、handle、三字段public_jwk/key_id及phase。rotation_id仅供宿主候选幂等与诊断，不是服务端receipt。记录终态保留；新一轮轮换须宿主明确归档旧记录后再开放，不自动循环。

signer.prepare({target,owner,rotation_id,expected_key_id,expected_key_version})必须确认旧handle归属且可签，持久创建不同候选key后返回{current_handle,handle,public_jwk:{kty,crv,x},key_id}。SDK用标准WebCrypto核对thumbprint，拒绝相同key、私钥或额外JWK字段。signRotation(context+challenge+new_key_version)返回两签名，仅接受轮换语义上下文，不签任意消息。activate(context)幂等切换候选为本地active并保留旧key，不自动删除旧key；discard(context)幂等清理确定未发送轮换的候选，不得删除current_handle。候选prepare失败/保存结果未知时按A04-B原则保留可能已记入journal的key，确定未发送且无journal才best-effort清理。宿主throw不原样进入UI。

## 3 操作与恢复

prepare：验证当前owner→读本人detail与当前key metadata→再次detail比对稳定binding/device/key版本→宿主prepare→保存prepared。任何候选创建前失败不改变远端；创建后取消要处理确定未发送候选；save抛错且load失败时不能删除候选。

rotate：锁内读原record并核对owner→重新读取detail/key/detail。若当前已为候选key、版本expected+1，转恢复activate；若仍旧key及原版本/绑定则取新challenge→检查期限→宿主双签→检查session/期限→先保存rotate-unknown→再次检查session/期限→POST rotate-key。成功key DTO必须匹配tenant/device/newkey/expected+1，随后重新detail/key/detail确认再activate并保存active。旧签名不重放；服务端nonce失败/409/网络超时均保留记录与两把key。

recover：先查询本人detail，指针是原key或候选key时读取该指针对应metadata并再读detail，避免候选尚未存在的404误阻原key恢复；其他指针直接拒绝。当前active指针=候选、metadata active且版本expected+1、device version=原+1、binding ID/version未变才activate；原key分支须device version仍等于原值。若仍旧key/原版本/原绑定，显示prepared或原unknown并允许用户显式rotate重试（新challenge、相同候选和expected）。一次读取旧key不证明在途请求没提交，故unknown不能discard；并发重试由服务端expected CAS/nonce裁决。候选已再次轮换/退役、设备停用/撤销、绑定失效、owner变化均失败关闭，保留候选与旧key。单个历史metadata不是原轮换归因证据，不能宣称收到原请求回执；detail/key/detail仍非远端与keystore分布式事务，检查后远端可再变化。

discard仅prepared，先保存abandoned再清候选；unknown/active绝不自动清理。load仅本地历史阶段，不声称实时远端状态。session切换时UI立即隐藏旧状态并使在途动作失效，journal留给原owner恢复。持久化/激活失败可由新实例load/recover继续；回读权限因旧session失效可要求同owner重新登录，不用管理员身份代签。

## 4 UI、复用与验证

新增可选DeviceKeyRotation组件，不塞入A04-A列表流程。无client/signer显示不可用；prepare与实际提交明确确认，unknown区分查询与显式新challenge重试，展示旧/新公开key与阶段；active说明仅当前核对成功、旧key保留。zh/en、键盘标签、错误焦点、320px、StrictMode与迟到响应隔离。组件卸载退订，宿主切换流程dispose。

复用本仓MIT协议、A04-A身份/设备读取、React19/MIT及现有TypeScript/Vite/Playwright。标准WebCrypto SHA256与宿主标准crypto Ed25519，无新增运行时依赖。固定seed signer只在测试，不导出产品包。

局部测试覆盖规范向量、wire kid/expected版本、真实Rust双签验签、错签/错owner/跨入口/旧版本/nonce重放、提交响应丢失与新实例恢复、current metadata不能作为receipt、轮换后再次变化拒绝activate、store/activate失败、保存期间过期/session切换/dispose、双实例互斥、unknown不销毁、StrictMode/UI无秘密。A03同步rotate非幂等/恢复说明和必要schema测试，四合同漂移检查；Web局部测试/build/bundle、指定隔离PG宿主测试，不做完整验收和部署。

## Double check结论

独立核对Core/SQL/Axum/现有client后通过，编码前已澄清双签规范字节和先按当前指针读取metadata。challenge成功可能不入库；只校验canonical challenge和自身期限，不能把HTTP成功当轮换成功。实现与测试仍须核对wire kid、会话代际、保存结果不确定及激活失败恢复。
