# S03-A1 本人会话查询纵向切片

2026-10-26；范围是只读本人会话查询（Core→Postgres→HTTP/宿主），不提前开放撤销或改密。安全页最终UI与写操作仍在S03待办，本批不改其退出门槛。

## 领域合同

Core 新增 SelfSessionService::list_sessions(actor: AccessActor, page: SelfSessionPageRequest) -> Result<SelfSessionPage,AccessError>，由 CoreSelfSessionService<S,C> 实现，构造时绑定TenancyMode/store/Clock。请求含limit（1..50）与可空SelfSessionCursor{subject_id,tenant_id,session_id}；cursor的subject必须等于actor.subject，tenant满足现有id规则，session为规范UUID。不能从JSON选择查询subject。返回items与可空next_cursor，每项仅tenant_id/session_id/client_id/purpose/device_id/created_at/expires_at/status(active或expired)/current。不返回scope、refresh version/token或账号邮箱。数据域为本人账号全局，数据库status=active的会话，已过期的投影expired，撤销项不列出。

分页按tenant_id(C collation)/id(UUID)升序，limit+1前瞻；next_cursor只在有下一页时生成。Core验证store返回数量上限、subject一致、顺序严格递增、会话status/时间合理，防止错误adapter泄漏其他主体；只在Core投影非敏感DTO。

新SelfSessionReadStore GAT事务方法 self_session_read(mode, closure)，事务端口有actor_is_active(actor,now)及sessions_for_subject(subject,after,limit)。服务先验证actor/page，再在同一事务中重查actor活跃，并在持有actor相关锁期间查询，随后读取并校验/投影。无管理权限复用、无伪造管理actor。

## PostgreSQL 一致性

复用PostgresAccessStore。事务用READ COMMITTED、5秒statement/lock timeout，先access_state FOR SHARE并验证mode/bootstrap。actor检查依次锁tenant、account、session（共享行锁），再核对account/member/tenant active、session account和复合key、active/创建及认证时间/expiry；device session另外要求device/current key/binding有效。该顺序与已有安全写/登录/注销一致，避免检查通过后actor在读取期间被撤销。session purpose来自已认证入口，数据库检查只接受既有business/management，不额外赋予管理权限。

sessions查询固定account_id与status=active；after是参数化tenant/id元组，不拼接用户SQL。使用现有sessions_account_scope索引，不新增迁移。直接查询base tenant_v6能力，查询不要求security_foundation已安装（只读能力无需凭据版本）。

## HTTP 与宿主

新增业务Bearer GET `/auth/security/sessions`，managementBearer GET `/admin/auth/security/sessions`，query只接受limit/cursor。两个构造分别接收原TenantAuthenticationService或ManagementAuthenticationService及同一个SelfSessionService，严格单Authorization、既有tenant header匹配检查、拒绝business header；管理认证按原service校验purpose/audience/entry，提取其可信actor。新router不修改现有构造参数。cursor用有界base64url JSON，携带version=1及Core三个字段，最大1024字节；错误cursor400，失效/跨主体cursor拒绝；所有响应no-store。

随后browser同能力为POST `/auth/browser/security/sessions` 或 `/admin/auth/browser/security/sessions`，严格JSON含expected identity/limit/cursor，复用S03-A0专用身份trait。构造时purpose/lifetime与BrowserSessionHttpConfig严格相等，复用既有Origin/固定browser头/sec-fetch-site/Cookie解析，16KiB限制，no-store。不得用refresh接口代替只读身份查询。

参考宿主每个普通入口与独立management挂载相应router；legacy业务入口也需核对接线，库router仍由embedding host显式选择。没有新增对外账户选择参数。OpenAPI/route inventory记录两类Bearer与browser能力、分页和错误；新增局部合同/漂移断言。

## 验证与实施顺序

1. 独立复核设计及字段/锁序，冻结Core trait后实现Core和PG；测试本人两租户、多purpose、多page/current/expired、他人行排除、伪造cursor、已撤销actor、失效成员/设备、adapter错误及状态不变。
2. HTTP和host接线：测试真实Authorization、重头/跨purpose、未知query、cursor错误、browser Origin/expected与配置绑定，no-store及无token输出。
3. 隔离PG及真实host定向集成验证；同步合同。Web安全页随撤销/改密统一接入，避免构建只有链接而无最终操作的临时页面，本批不能称UI已完成。

主代理已检查现有tenant_self、browser helper和sessions索引，待独立复核后进入编码。

主代理补充凭据边界：本人安全操作仅允许原生登录/管理登录生成的第一方session（scope=None）。OIDC授权码派生的scope=Some会话即使主体相同，也不得借openid/profile/email授权查询或修改全局安全状态；数据库actor检查必须同时要求scope IS NULL。列表仍可展示属于本人的委托会话，便于后续本人撤销。此限制不修改原OIDC协议行为，不新增OAuth scope。Core store端口文档和PG/HTTP负例必须覆盖该边界。

独立复核通过后已澄清：READ COMMITTED为逐语句快照，本批保证同一事务中锁定actor后查询，不承诺跨页一致快照。scope限制必须复查actor的确切session行；不能在全局列表过滤scope Some。补测委托actor被拒而本人委托会话仍可列出。设计冻结进入实现。

实现复核修正：self_session_read明确接收actor，在调用Core闭包前依次取得state/tenant/account/session锁；Core在闭包开始后才读取Clock并验证当前资格，避免把锁等待前的时间用于判断已经过期的actor。actor_is_active只在已锁行上读取状态，不再等待新的行锁。保持原锁序与可注入Clock，不改为数据库真实时钟绕过测试/宿主合同。
