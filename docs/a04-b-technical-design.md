# A04-B 登记、宿主持钥与恢复技术设计

2026-10-26，修订4 A04第二子批。先设计与double check，再编码。复用现有四个HTTP操作：provision、registration-result、complete、proof/challenges；不改Core、SQL、wire或A04-A本人Bearer请求桥。登记不要求尚未存在的本人session，完成登记也不意味着已登录或已建立本人绑定。A04-C双签轮换、原生keychain、完整验收/部署不在本批。

## 1 固定宿主边界

新增独立DeviceRegistrationClient，immutable目标包含baseUrl、tenant_id、client_id、entry_id、device_id。device UUID由宿主提供，兼容预批准B2 grant；registration_request_id由现有secureRandomUuid产生。base仅同源绝对路径或HTTPS/localhost HTTP，不接受userinfo/query/fragment/路径穿越；真实私网HTTP需后续明确transport policy，不能默认放宽。所有请求credentials:omit、no-store、redirect:error、15秒超时，不读取全局登录状态，不借用管理员token。

entry_id只参与宿主本地上下文/日志隔离，现有B2准入服务端只绑定tenant/client/device/scope/期限，不校验entry_id；需要服务端隔离的入口必须使用不同client。宿主须统一同一物理候选的锁与持钥策略，不能靠别名entry绕过互斥。

三个必需宿主能力通过显式接口注入：

1. signer：prepare(target+registration_request_id)持久保存候选私钥，返回opaque handle、仅含kty/crv/x的Ed25519 public JWK和RFC7638 key_id；signRegistration(语义target、request id、handle/key_id、challenge)只允许登记用途，由宿主构造现有REGISTRATION-V2规范字节；activate必须幂等，核对handle所属目标与key；discard仅清理已知未发送远端写入的候选。私钥不返回SDK/React、不进localStorage/URL/log；SDK快照不含handle/JWK/准入credential。缺少能力时UI禁用登记。
2. admission：每次provision和registration-result调用authorize，宿主重验业务所有权、tenant/client/device/action及期限，返回短期credential、稳定registration_scope和expires_at_unix_secs。当前HTTP适配明确采用B2 reference的`x-embedded-idp-device-admission`，只把credential作为这一header发送，scope不进JSON也不是客户端自报授权。新scope必须拒绝恢复旧请求，credential不入journal/快照。生产宿主可通过受信transport适配同样的HTTP边界，但不能用未验证subject替代TrustedDeviceAdmission。B2预批准grant不是动态业务审批服务。
3. store：withLock(target, async operation)、load(target)、save(record)。宿主必须按完整入口/tenant/client/device跨实例/跨标签页互斥，并提供原子持久化；每次操作在锁内重新load。不能仅靠组件busy或某个SDK对象的Promise锁。测试adapter用内存mutex，只证明单进程流程，不作生产持久性证明。record只含版本、固定target、request ID、device_name、候选handle/public JWK/key ID、phase和首次准入scope；无private key、token、credential、challenge或signature。store与signer是受信宿主实现。

SDK可导出登记规范字节builder供宿主复用，但signer接口不接受任意待签字节。builder严格校验tenant、UUID、32字节canonical base64url key/challenge，输出与Core `build_device_registration_proof_bytes`完全一致。签名/随机密钥和SHA256均复用宿主标准库/WebCrypto，SDK不实现Ed25519或自造密码协议。候选key_id由宿主生成，SDK用WebCrypto SHA-256核对RFC7638 thumbprint，并与服务端expected_key_id比对，不能将自报key_id当服务端认证。

## 2 持久状态与请求顺序

记录schema_version=1，phase为prepared、provision-unknown、pending、complete-unknown、active、abandoned。unknown既包含未确认网络结果，也包含跨进程中断；调用开始先锁并load，不盲信内存。

- prepare(name)：确认无现存record→生成request ID→signer.prepare已保存候选→严格校验公开描述→store.save(prepared)→发布快照。保存失败不得发HTTP；允许best-effort清理刚创建且确定未发送的候选，清理失败保留可诊断状态，不报告远端失败。
- provision：prepared→每次重新authorize→锁定首次scope→**先持久化provision-unknown**→发送完全相同的provision DTO→校验身份、expected key、version/nullable/timestamp→持久化pending。返回completed状态也必须核对active/key/version=1，再走本地activate。任何错误保留原record和handle，不自动生成新request/device。
- recover：重新authorize读取registration-result，不要求本人Bearer；404只表示当前未查到，不能证明先前写没有在途，不清理key。provision-unknown可显式“查询并重试原登记”：先lookup，只有404才用同一request/device/JWK/name及稳定scope再次provision（服务端幂等）。其他错误不能转新登记。
- complete：先重新read result，若已完成则核对并恢复本地activate；若仍pending且未过期，取purpose=`device_registration`的新challenge，校验有效截止→signRegistration→复核challenge与登记期限→**先save complete-unknown**→POST complete。合法成功响应仍再read result核对当前active/key/version=1后才activate。unknown恢复不把nonce已消费当失败证据；可以从pending状态再次获取新challenge完成同一登记，不重发旧signature。
- activate：只有最新result为completed、device active、proof_key_id=候选key_id、key_version=1时调用宿主幂等activate，然后save active。本地activate/save失败保留可恢复record；下次仍重新查远端。若后来被轮换/停用/撤销，拒绝激活或删除候选，不宣称当前key安全可用。检查后服务端仍可变化，不承诺跨宿主/远端线性化。
- discard：仅prepared（没有任何远端write attempt）可操作，先持久化abandoned再调用幂等discard；abandoned保留审计/恢复信息，不自动重新开始同一device。任何曾进入unknown/pending/active的record都不自动删除key，即使过期、403或404。显式人工后续核对另行处理。

所有动作single-flight（重复点击拒绝），且经宿主lock跨实例串行。load失败或record与immutable target/版本不匹配失败关闭，不覆盖存储。dispose使客户端代际失效，await返回后不继续新的HTTP/sign/activate；已发出的远端请求可能提交，journal中的unknown供新实例恢复。组件卸载只取消订阅，宿主在切换登记流程时负责dispose；不得把UI取消误称远端事务回滚。

## 3 校验与界面

DTO严格对照tenant_devices.rs：provision 201/result 200返回device投影+expected_key_id/created/expires/completed；pending的proof_key_id/key_version为null；complete返回tenant/device/key/version。设备/请求UUID规范、name按UTF8≤256且无control，初次登记投影限定pending device version=1、completed device version=2/key_version=1，后续设备版本变化保守拒绝本地激活；版本正safe integer，时间非负safe integer，可空值显式校验。宿主public JWK只含kty/crv/x，wire请求按Rust解析器补入kid=已校验key_id；禁止d或额外秘密字段；base64url检查canonical长度。响应错tenant/client/device/expected key、状态组合或时间关系拒绝。

新增DeviceRegistration组件独立于A04-A列表，可在未登录设备端使用。显示固定tenant/client/device与公开key ID、持久阶段和可执行动作；中文/英文、标签、键盘、错误焦点、role=status/alert、窄屏。恢复只读与显式重试分开；失败不显示“已撤销/已回滚”。只有active表示服务端登记和本地activate核对通过，并说明尚需持钥登录建立本人关系。组件不展示handle、JWK、credential、signature或private key。无client/adapters显示明确不可用提示；不做原生持钥模拟承诺。

## 4 复用、合同与测试

复用本仓MIT协议、B2 grant adapter、React19/MIT与既有CSS/TypeScript/Vite/Playwright工具。固定测试seed的Node crypto Ed25519适配器仅在测试文件，不导出到产品包；测试store/admission也不作为默认生产能力。无新运行时依赖、无数据库迁移。

A03复核四个既有登记接口的DTO、nullable、challenge purpose/期限、admission header、registration-result每次重授权和complete非幂等边界，补SDK消费者与恢复语义说明；任何发现的schema漂移直接修正并再生成。

局部测试：协议builder独立向量/Rust真实验签；缺adapter/错scope/过期admission/错owner、错误DTO、非法私钥JWK、save失败无网络、同目标两实例锁、provision/complete响应丢失与新实例load恢复、challenge过期/重放、返回但未入库challenge不能误判成功、重复complete、后续轮换或撤销不激活、dispose迟到、未发送候选清理。真实隔离宿主使用构建后的JS client+固定测试signer，预批准grant精确到tenant/client/device，分别丢弃provision和complete响应再恢复。浏览器夹具仅证明交互/隐藏秘密，不替代真实密码学/持久性/平台安全。完整验收和部署暂缓。

## 5 Double check与固定公共API

已交叉核对Core lifecycle/security、Axum DTO及B2 admission：无协议阻断；修正entry_id仅本地隔离的边界。challenge HTTP成功不代表nonce入库，完成后结果复查是唯一激活依据。继续采用karpathy-guidelines的最小改动与可验证退出条件。

客户端文件`device-registration-client.ts`：`new DeviceRegistrationClient({target, signer, admission, store, transport?})`。公开`getSnapshot`/`subscribe`（箭头函数）、`load()`（仅加载journal）、`prepare(deviceName)`、`provision()`、`recover()`（查远端并恢复本地activate）、`retryProvision()`（先查，仅404重试原provision）、`complete()`、`discard()`、`dispose()`。所有异步动作Promise<void>。

Snapshot包含target、phase（empty或持久phase）、key_id可选、busy、error可选；error采用固定安全错误码，不暴露宿主throw内容或服务端原始正文。UI只按这些公开值呈现。导出target/record/signer/admission/store/options/snapshot类型；signer参数统一为record上下文，prepare参数为target与registration_request_id，signRegistration另加challenge；返回signature为64字节canonical base64url。纯函数`buildDeviceRegistrationProofBytes({tenant_id,device_id,key_id,challenge})`输出Uint8Array。

实现复审补充：wire JWK必须带kid；challenge TTL不截断到登记期限，客户端分别校验两者；prepare清理必须区分保存确定失败与结果不确定，后者保留候选；取消期间prepare成功返回也须处理未发送候选，避免无记录孤儿。

本地load只恢复上次持久阶段，不代表实时读取远端状态；需要当前状态时调用recover。原生keystore、跨进程互斥/崩溃恢复与动态业务准入仍是宿主责任，本批测试不替代这些平台验证。
