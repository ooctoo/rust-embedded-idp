# A04-C 宿主接入：双签轮换

对应[技术设计](a04-c-technical-design.md)、[实施方案](a04-c-implementation-plan.md)和[局部记录](a04-c-implementation-result.md)。主入口导出DeviceKeyRotationClient、DeviceKeyRotation、规范字节builder及宿主接口类型。

## 接线

使用已经登录的EmbeddedDeviceClient创建`new DeviceKeyRotationClient({devices, target, signer, store})`。target包含baseUrl、tenant_id、client_id、entry_id、device_id；base必须等于身份客户端实际入口。组件可用`<DeviceKeyRotation client={client} />`，缺安全适配器或人员会话时禁用，不提供私钥输入框。Bearer会话与请求重试仍由现有身份客户端管理，不向轮换组件暴露token。Cookie模式没有此Bearer能力，不能隐式转管理员或普通token模式。

store契约为withLock(target,operation)、load(target)、save(record)。轮换journal与A04-B登记journal须使用不同记录命名空间，**同一设备的登记/轮换仍须共用宿主互斥锁**，不得因账号或别名入口绕过锁。目标/owner/schema不一致时停止，不覆盖已有记录。终态记录保留，下一次轮换由宿主核对、归档后显式开放；SDK不自动启动下一次轮换。

signer.prepare接收target、owner、rotation_id、expected_key_id/version，核对当前持钥归属并持久创建候选后返回current_handle、handle、三字段public_jwk及key_id。signRotation接收保存的上下文、challenge和new_key_version=expected+1，返回current_key_signature/proposed_key_signature；两把key签署完全相同的ROTATION-V2 bytes。wire中proposed_public_jwk由SDK补入kid，new_key_version不出现在请求DTO中。宿主可以复用buildDeviceKeyRotationProofBytes，但必须独立核对语义上下文，不能开放任意字节签名能力。

activate必须幂等，只切换确认后的候选为本地active，保留旧key。discard只能清理确定没有远端轮换尝试的候选，不能删除current_handle。宿主需保证prepare抛错前的私钥清理或以rotation_id查找候选；SDK无法清理未返回的handle。私钥不进入SDK/React/journal/日志。标准WebCrypto用于thumbprint，实际Ed25519签名由平台安全设施或成熟标准crypto实现，不复制密码算法。

## 恢复

load读取本地历史状态；prepare读取本人detail/key/detail并记录原binding及版本；rotate重新检查后取新challenge双签，先保存rotate-unknown再发送。查询到旧key仍有效不能证明原请求没有在途，因此unknown保持不可丢弃，只有显式rotate可用同一候选、新challenge重试。recover只读当前指针对应key元数据并再读detail，确认候选仍active、原绑定不变、key/device版本均只推进一次后才activate。

没有rotation operation receipt；历史key metadata不能证明某次请求的归因。设备被再次轮换、停用/撤销、绑定改变、owner切换均停止激活，保留两把key供宿主核对。错误设备签名返回401时现有身份client会清空会话；同owner重新登录后可用新实例load/recover。切换身份/dispose不能撤销已发请求；UI取消不等于远端回滚。详情两次回读不能提供远端与keystore的分布式原子性，宿主仍须处理检查后的远端变化。

本批不实现自动归档/多次轮换队列、旧key垃圾回收、原生keystore/跨进程锁或新的device-proof transport。若宿主额外要求元数据请求持设备证明，必须提供可恢复的受信transport策略，不应把旧key已失效的证明当成唯一恢复路径。

## 复用和许可证

无新增运行时依赖或迁移。复用本仓MIT协议、A04-A设备读取与身份请求桥、React19/MIT以及既有TypeScript/Vite/Playwright。测试固定seed Node crypto signer与文件journal仅属于隔离测试，不进入产品bundle，也不表示已验证平台密钥保护、断电恢复或跨进程锁。
