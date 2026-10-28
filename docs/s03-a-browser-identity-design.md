# S03-A0 本人安全页的 Cookie 身份前置

2026-10-26；本切片只实现 Core 认证接点，不提前暴露本人路由或修改数据库。S03-A 主设计的其余事务前置仍待冻结。

## 问题与边界

当前 BrowserSessionIdentityService 明确仅返回业务会话身份，扫码等调用者依赖该限制；management 登录/刷新虽然存在，但不具有本人安全页需要的不旋转 Cookie 身份验证接点。不能直接删除业务限制并使扫码接受管理会话，也不能通过刷新 Cookie 来实现身份查询。

新增独立 SelfSecurityBrowserIdentityService，方法为配置绑定的 purpose、可选 restricted lifetime，以及 authenticate_self_security_browser(cookie, expected: BrowserSessionIdentity) -> AccessActor。expected 对全部本人操作必填，防止旧标签页在 Cookie 切换后操作另一个主体。Actor 只由认证结果构造，后续本人安全事务仍需重查其活跃状态。

实现复用现有 authenticate_browser_impl 的事务校验：把实际 refresh/account/session/client/tenant/设备/有效期检查提为私有共享 helper；旧 authenticate_browser_impl 保留 Business 检查再调用该 helper。新服务调用私有 helper并立即转换AccessActor，不向扫码公开management身份。purpose由Core构造时注入，helper内现有 require_session_identity 校验 session.purpose==self.purpose，不使用请求字段选择purpose。

为 CoreTenantAuthenticationService、CoreManagementAuthenticationService、RestrictedBrowserSessionService 实现新trait。restricted必须沿用其lifetime上界，管理实例委托内部已绑定purpose的auth。新trait不更改旧trait方法签名/默认行为，不改变令牌/refresh状态，不签发凭据、不迁移schema。

## 实施计划与 double check

1. 核对 require_session_identity 的 purpose 检查和 management/restricted 持有关系；新helper仅放宽私有接点，旧business入口保持原拒绝。
2. 提取私有共用校验，追加独立trait与三种实现；避免复制安全校验SQL/算法。
3. 使用现有内存fixture验证management与business成功、跨purpose/跨client拒绝、expected不符拒绝、restricted超长session拒绝、无refresh旋转/签发/撤销。保留原扫码身份回归。
4. 跑 browser/authentication 相关局部测试、Core编译、格式及diff检查。HTTP合同本切片不变，后续路由必须显式复用Origin/CSRF guard，不能依赖merge继承。

主代理初审：新增独立接点优于扩大旧扫码身份合同；必填expected和配置purpose保留多入口隔离。待独立复核后编码。

独立复核通过条件已落实：新trait提供 self_security_browser_purpose() 与 self_security_browser_lifetime_secs()；后续HTTP router构造必须验证两者与BrowserSessionHttpConfig严格相等，不匹配立即拒绝装配。不得把management身份adapter放到business Cookie路径。私有helper保留全部已有校验，包括entry.require_device_proof和session.device_id拒绝；旧scan输入/trait及调用链不改。本切片设计已通过，开始实施。
