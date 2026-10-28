# S01-B：有界来源与账号准入

2026-10-26；独立double check完成并已回写下列修正，允许开始本切片编码。依赖[S01-A](s01-a-implementation-result.md)，属于[一期安全基础版](phase-one-delivery-plan.md)。

## 冻结目标

为宿主提供可注入的共享准入合同、单进程成熟限流adapter、明确的可信来源边界和HTTP接线。保护会产生工作/状态的POST/PUT/PATCH/DELETE，不影响健康会话GET读取、静态资产、health与discovery。密码/email匿名入口追加账号预算；新恢复入口必须显式加入该分类。保留现有HTTP并发许可与KDF预算，不把速率预算当并发限制或认证。

## 分层与公开类型

Core新增独立admission模块：`AdmissionPolicy`包含global/source/account三个`AdmissionQuota { replenish_every: Duration, burst: u32（validate拒绝0） }`及max_keys；验证周期、burst和最大保留时间有界，不读取网络或环境。原始source/account仅作为借用参数在调用栈存活，禁止Debug输出敏感值。`AdmissionDecision`区分allowed/rate-limited/unavailable；`AbuseAdmission: Send + Sync`提供`admit_source(&[u8])`（原子执行global+source顺序消耗）和`admit_account(&str)`（账号预算）两个方法。共享store适配者保证每次方法调用原子，不能宣称跨body读取两阶段是同一事务；本地顺序消耗规则在下节明确，不提供自动退款。

Security实现`InMemoryAbuseAdmission`，复用governor 0.10.4和现有ring HMAC-SHA256。每个实例由宿主注入独立32字节key或显式随机生成；不使用JWT/设备key，不输出原始来源/邮箱或摘要。Core仅接业务无关准入判定，不依赖governor/HTTP/DB。不得将该适配器宣称为跨进程共享实现；多副本宿主必须注入共享原子端口或明确接受每副本预算之和。

Axum提供`with_abuse_admission(router, Arc<dyn AbuseAdmission>)`。来源只取可信ConnectInfo<SocketAddr>的IP（不含端口，IPv4-mapped IPv6规范化，以带地址族前缀的二进制IP作为摘要输入）；可由宿主在外部可信middleware放入类型化TrustedRequestSource覆盖。不会解析Forwarded/X-Forwarded-For等Header；缺少可信来源在受保护写请求上503，不按未知来源降级放行。提供显式构造的host source接口用于非TCP/可信代理宿主；客户端不能从Header创建该类型。

## 本地预算与容量算法

整个调用用一个短Mutex保护global limiter及有界HashMap，锁内无I/O、KDF或await。先消耗global预算，再source，最后（有账号时）account；任一拒绝不退款，前面预算仍被消耗，防止大量变化账号绕过入口总预算。来源/账号键分别用HMAC(domain || canonical input)，两个命名空间不可混用；账号统一trim ASCII空格并ASCII小写用于预算，不改变身份系统实际邮箱相等规则。账号预算跨登录/注册/恢复和入口共享，切换client/tenant/flow不能拿新账号预算。

每个键保存governor direct limiter及最近一次允许的单调时间。最多保留max_keys个source+account键；新键达到上限时只清理已至少经过burst*replenish_every且此间无成功消费的键（此时预算已完全补满）。拒绝不延长保留；活跃桶绝不驱逐/重建以重置预算。仍满返回unavailable，不放宽为无上限。清理仅在插入或周期触发，受max_keys硬上限约束；global预算在其前进一步限制攻击引起的扫描频率。毒化锁返回unavailable，不panic放行。过期判断与governor使用同一显式单调clock；测试使用其FakeRelativeClock，不用墙钟sleep模拟预算。

参考默认策略先以明确开发值交付：global每10ms补1、burst200；source每200ms补1、burst60；account每2s补1、burst10；max_keys=16384。这些参数可由typed构造器替换，不写成生产容量承诺。账号耗尽不会修改账号status；攻击者可能造成有限临时拒绝，必须结合来源预算并在交付说明披露NAT和账号拒绝风险，不能宣称不存在定向DoS。

## HTTP账号提取与失败合同

所有其他写路由仅source/global准入，wrapper不读取或替换body，不改变其64KiB等原限制。对最后路径段login/register/verify-email/resend-verification及后续password-recovery start/verify分类，读取原始body上限沿现有16KiB；额外body读取deadline 5秒。先source/global准入，再缓冲有界body，解析JSON仅提取字符串email用于账号预算，随后把原始bytes完整还给原handler，不重新序列化、不修改proof绑定字节或替代DTO校验。使用派生struct提取email并拒绝重复email；提取失败只扣source/global并把原bytes交回原handler。重复/unknown字段仍由原handler拒绝；无email/非法JSON走更严格的source预算后原有错误路径。两个阶段必须避免重复扣global/source，Core端口因此需明确分为`admit_source`及`admit_account`两个方法，每个方法内部原子；文档不宣称跨HTTP body读取的一次事务原子性。account阶段不暴露独立HTTP路由；这由可信Axum wrapper先执行source阶段保证，不把该Core预算端口当作能约束任意宿主代码的认证凭据。

返回429顶层`code=rate_limited`和固定粗粒度Retry-After=60/no-store；配置/容量/来源/adapter失败503 `temporarily_unavailable`/no-store。仅上述账号body路径新增过大413、读取deadline408，不泄漏来源/账号/预算剩余。新拒绝状态是宿主选装层的附加合同，更新路由清单与HTTP合同文档；无新的业务成功DTO。

## 宿主接线与兼容

参考宿主最终router同时包裹S01-A并发层和本层，outer abuse先于高成本工作，监听使用into_make_service_with_connect_info。显式配置新增可选typed abuse policy，旧输入缺省使用上述开发默认值，不解释任意代理Header。两个嵌入示例也共享password预算、anonymous HTTP预算，并注入各自独立abuse adapter；各自只绑定loopback。库调用方不被隐式强制新Header/来源，使用新的wrapper时才启用附加状态；文档给出接入代码。

本批不自动挂载新注册邮件runtime，不新增schema/迁移，不改旧验证代码的领域尝试合同；该旧匿名验证路径仅有累计来源/邮箱预算，后续O01a/S03不得复用为密码恢复票据。已有信任/Origin/device proof guard继续生效，来源准入不证明设备可信。

## G0与实施顺序

1. 核对governor 0.10.4发布包MIT许可、源码摘要、features及传递依赖；`default-features=false, features=[std]`，不启dashmap/quanta/jitter；隔离探针验证burst/补充与单调时钟。主机Rust1.93编译证据；目标Linux/MSRV未验证时如实列出，不默认升级工具链。
2. 独立设计复核后，先Core端口/typed policy和Security adapter（clock/容量/故障负例），再HTTP wrapper/来源/body保护和状态合同，再参考宿主及两个示例。
3. 测试跨入口同账号、可信peer与伪造代理头、源端口不能重置、无peer fail closed、容量满不重置活跃预算、拒绝不滑动冷却、并发预算、读取timeout/大body和取消；不使用真实用户邮箱或可追踪指标。
4. 真实隔离host测试限额拒绝和恢复、现有登录/设备/browser兼容；A03漂移检查和嵌入示例局部测试。
5. 完成记录说明单进程/代理/生产阈值边界后进入O01a详细设计。任何为通过测试而放宽预算的改动必须回写设计，不能只改测试期望。

## 独立复核修正

复核已修正两阶段端口与HTTP调用约束的混淆、所有写方法与仅账号路径buffer的区别、重复email不错误扣某一账号、原bytes保留、无ConnectInfo拒绝，以及IPv4映射/端口规范化。TrustedRequestSource只由可信宿主代码构造（1–256字节opaque），在abuse层外注入后再调用next，测试用request.extensions_mut直接注入，不支持Header自动转换。Core端口定义admit_source(&[u8])/admit_account(&str)，结果为Result<(), AdmissionRejection>（RateLimited/Unavailable）；参数不创建身份或权限。

quota校验：补充周期1ms–1h、burst 1–1000、完全补满期不超过24h、max_keys 1–65536；零值/溢出拒绝。显式参考JSON可选abuse对象以period_ms/burst/max_keys表示，与库Duration转换，缺省开发值，未知字段拒绝。测试增加source/account共享容量、边界时刻清理、不退款、原始proof bytes，以及其他写路由body不变。

governor G0实际证据见[s01-governor-g0.md](s01-governor-g0.md)，产品features及锁文件在落地后复核。密码预算/高成本client-secret及旧邮件发送的并发边界在后续安全整合盘点中继续核对，本批不把速率限制冒称所有昂贵操作均已并发有界。

补充HTTP读取错误复核：复用已在锁文件中的http-body-util类型区分LengthLimitError（413）与传输读取失败（400）；测试使用现有http-body trait模拟pending/失败body，不自写buffer算法。timeout仍408。两依赖沿现有版本和MIT许可，不升级版本或引入网络栈。

实际实现复核补充：账号输入可包含UTF-8，预算只做ASCII空格裁剪/ASCII大小写归并，不擅自把非ASCII字符串改成503；实际邮箱合法性仍由原DTO/Core验证。已有client secret验证的物理并发、邮件发送有界性与上线旧验证路径还需后续收尾，不在S01-B记录中略过。
