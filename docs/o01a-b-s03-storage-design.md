# O01a-B / S03 安全存储与恢复事务设计（草案）

2026-10-26，总设计按切片冻结与实施；foundation和crypto已实现，运行时存储精确合同见security-runtime-storage-design.md，服务消费者仍待冻结。该文档共同冻结安全事件、outbox、本人改密 receipt 与恢复生命周期，避免先建无法满足消费者的通用平台。O01a-A 物理邮件 adapter 单独验收，不代表本文件功能已实现。

## 扩展与所有权

新扩展 security_foundation_v1/security_runtime_v1 与既有 tenant_v6、可选 registration_email_v1/runtime_v1 分开标记。Host显式 plan/apply/check；在线启动仅检查，不自动创建表或加列。迁移先验证 tenant_v6 readiness、模式及目标schema，锁 access_state FOR UPDATE，在同一事务加扩展；已装但布局不符 fail closed。生产迁移不在当前任务执行，局部使用全新隔离schema。

Core 定义安全事件、flow/outbox/receipt领域状态、store事务端口及服务；PG 实现SQL/锁与迁移；Security 实现随机token、HMAC、AEAD；Email与app负责物理发送，HTTP保持薄adapter。复用现有连接池、UUID、ring、SecretString、PasswordWorkBudget、token认证和Web会话设施，不引入消息中间件或新的密码算法。

## 存储精确合同

此前候选表已由[安全运行时存储设计](security-runtime-storage-design.md)替代，不再保留第二套字段定义。foundation使用独立security_foundation_v1；六张runtime表使用security_runtime_v1，包含成功receipt、预算、flow、startreceipt与outbox及独立状态表。后续服务必须以该文件及实际SQL为准。

成功receipt保存各digest key ID；恢复开始的handle独立加密保存15分钟，同operation重试须验证Command用途请求摘要及客户端随机secret。flow UUID是代次，不再额外维护generation计数。外部handle为flow UUID16bytes + random secret32bytes的base64url无padding64字符，先定位flow，再按stored key ID验证随机secret；UUID本身不授权。所有开始请求（含不存在/无资格邮箱）都创建flow/startreceipt/outbox，无资格者outbox取消且无payload，容量计数规则一致。

## 锁序与原子性

安全写统一先 access_state FOR UPDATE，再按现有顺序锁必要tenant、account，最后budget/flow/outbox/receipt；不能先取flow或account行锁后再取state。首版低频全局安全写采用现有粗粒度安全屏障，后续只有测出瓶颈并重新证明并发规则才拆锁。普通认证/refresh持共享state，与改密排他state互斥。

KDF快照在事务外；进入改密事务后重查actor及credential_version/hash，防止管理员改密/禁用与旧快照竞争。hash更新、所有tenant/purpose会话退役、refresh撤销、授权码删除、selection撤销、恢复flow失效、事件与receipt一个提交。scan物理数据处理应复用其可退役状态规则；不能仅凭删除一个session断言所有历史ciphertext已清除，最终SQL需核对scan表FK与状态。

outbox claim也先state屏障，校验flow pending/未过期、账号仍active/版本匹配、恢复资格仍成立；更新sending并生成唯一lease_token。领取每批最多4，lease30秒，真正发送最多15秒+2秒清理。网络不在事务内。完成必须同时匹配id/state= sending/lease_token，迟到旧worker不能覆盖cancelled/expired状态。

Accepted=>accepted且立即清除payload；Rejected=>rejected并清除；Unknown=>unknown并清除，不自动重发；NotStarted=>pending，至少1秒后再领取，最多3次，之后rejected。sending租约过期=>unknown并清除，不能用“进程没返回”推定没发。flow消费/版本变化/失效可将尚未发出的pending取消；已发送邮件即使迟到，其中code也必须在验证时被新代次/凭据版本拒绝。

## 密码恢复生命周期候选

start要求有效邮箱语法、客户端新operation_id及重复请求标识；返回固定202及opaque flow handle。存在、无账号、disabled/closed、不允许恢复的管理身份，响应结构一致。查资格失败也不能把不存在作为404/不同响应。数据库基础设施失败统一503，不以成功202掩盖未处理的可恢复系统错误。

同邮箱每小时最多3个新代次，累计错误code最多10次；每flow最多5次，TTL15分钟；新start不能重置subject窗口。每次新代次失效旧flow/code与待发payload；重复同operation按同请求摘要恢复同flow，不能重复计数/发信。为能恢复同flow，opaque handle应加密保存在短期receipt而非存明文；已裁定使用独立password_recovery_start_receipts（见上），避免把开始状态当作成功改密收据；精确DDL/输入仍须冻结再编码。

verify输入handle、code、新密码、operation_id/receipt_secret；成功验证code之后在共享预算下生成密码hash，然后事务内重查flow/version/状态并单次消费、全域退役、写事件和receipt。错误code必须提交失败计数事件，不通过返回Err导致事务回滚计数。两阶段hash前后必须用快照/版本与flow状态重查，预算不足不能消耗有效code。完成后不自动登录。仅邮件code，本期不提供fragment链接。

普通邮箱恢复不恢复管理身份全因子丢失；具有有效系统/租户安全管理员身份的账号默认不开放匿名邮箱重置，资格谓词需复用现有effective-admin判断并在提交时重查。本人持当前密码改密仍允许。没有MFA实现不等于未来可跳过因子政策；未来启用时恢复必须显式扩展。

## 有界存储与清理（待压测外的局部核对）

首版每部署最多10000个未清理flow/outbox，budget键最多100000；新增时在同state屏障下检查总量，容量错误响应不能只对存在账号出现。清理每批100，按expires/id稳定索引；payload到15分钟无条件删除，flow/receipt24小时，event30天，budget过窗口且无在途flow后可删。精确容量外显和事件删除保留策略需要实现前复核，不能以每次扫描全表冒充有界清理。

## 编码前复核清单

确认start幂等恢复opaque handle的加密receipt模型、scan退役SQL、管理员恢复资格与模式、自助browser认证边界、容量外显及清理索引。随后才冻结精确Rust traits/DTO/SQL，依次Core+crypto、PG扩展+失败测试、host worker、HTTP/Web；每一层补事务回滚/并发/结果未知/迟到完成测试。真实SMTP供应商、容量压测、生产迁移及完整验收不在本轮范围。
