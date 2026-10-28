# S03-A 本人会话与改密详细设计（草案）

2026-10-26。用户已选定一期安全基础版；本文件待独立复核，未授权按未冻结条款编码。前置 S01 与 O01a 最小事务事件，不包含 MFA。

## 范围与现有实现

AccessActor 含 tenant/subject/session 三元组，仅由可信宿主认证后构造。现有 admin actor_is_active 明确要求 management purpose，不能直接用于本人业务会话，也不能伪造管理员上下文调用改密。TenantSession 已包含 purpose/client/device/创建/认证/到期/status，无需建立平行 session 表。

现有 admin update_account_security 已全域撤销 session/refresh、删除授权码及旧验证代码、撤销 tenant-selection；它不物理删除 scan grants/delivery，但 scan 读取会校验源/待交付 session。新增安全状态需使用同一个全局 access_state 安全屏障，不能单独在账号行锁后补取 tenant 锁。普通登录先快照 KDF 后锁内重查，可与相同屏障兼容。

## 本人合同

新增 Core SelfSecurityService 和 SelfSecurityStore/Transaction；不扩展管理权限。服务接收 trusted AccessActor，事务内重新验证账号、成员、租户及 session 活跃、有效期、设备/key/binding 有效；认证和改密不得相信请求体 subject。业务和管理 purpose 均可本人使用，但前置 token/cookie 解析仍由各原入口执行，不能跨 audience/client/entry 借用。

本人会话列表以账号全局为范围，仅返回该账号已建立的会话：tenant_id、session_id、client_id、purpose、可空 device_id、创建/到期、状态和 current 标志。不得返回 token/digest/IP/raw UA 或其他账号资料。每页最多50，cursor 是经过验证的 tenant/session 排序键，不将 offset 作为分页；读操作仍重查当前 actor。列出 active 状态（过期在响应中标为 expired）和有限最近已撤销会话，具体筛选须在合同冻结时二选一避免全历史泄露。

撤销命令包含目标 tenant/session 复合键与随机 operation_id。锁内确认其 account_id==actor.subject_id；不存在或不属于本人均404。目标为当前会话也允许，成功后前端清空本地认证。原子撤销该 session 和关联 refresh，消费/退役其授权码、selection source 及 scan 相关可用授权；同 operation 重放可返回非秘密 receipt，改变目标参数冲突409。撤销其他会话不退役当前会话。

## 改密与版本

新增 security_v1 可选扩展的 accounts.security_credential_version bigint>=1，与可选注册 registration_security_revision 独立。数据库 trigger 在 password_hash、status、email、registration_tenant_id 变化时推进版本；所有历史管理/注册路径自动维护，不靠逐一追改调用点。触发器不能悄悄更改现有注册 trigger 语义。

命令包含 current_password、新密码、operation_id；采用现有 AuthConfig 密码策略并拒绝超长，SecretString 脱敏。先用已验证 actor 读取凭据快照（hash+version+status），在共享 PasswordWorkBudget 许可中验证当前密码、生成新 hash，不持数据库锁等待 KDF；无匹配返回统一 credentials_invalid。随后新事务先取 access_state FOR UPDATE，再按现有序锁租户/账号，重查 actor 和 snapshot version/hash/status。一致才变更 hash、推进 trigger 版本、退役账号全部 tenant/purpose 会话与 refresh、authorization_code/selection/恢复 flow；事件与 receipt 同事务提交。

不自动登录、不延长会话，不删除未来 MFA 因子。全域注销是用户界面提交前的明确提示。状态变化与并发第二次改密只有一个提交；版本冲突返回409，禁止自动重试旧密码写。

## 结果未知与幂等

改密会撤销发起会话，不能要求已撤销 cookie 才能恢复成功结果。准备阶段需一个短期随机 receipt secret（只返回一次、服务端只存摘要）或等价请求凭据，绑定操作/账号/新密码请求摘要，结果查询仅返回 completed/unknown，不能登录、读账号或放大匿名枚举。具体 HTTP 两阶段或单次返回前失败的恢复合同尚须与 O01a-B 共同冻结；不能把普通 operation_id 当公共可猜的授权凭据，也不能因超时直接再次改密。

## 路由与界面待冻结

候选 bearer `/auth/security/sessions`、`/auth/security/sessions/revoke`、`/auth/security/password`；browser 同能力在原 browser session adapter 下，以原 Origin/CSRF/Cookie policy 保护。主代理需核对实际 browser/router 组合再定最终路径。所有响应 no-store，body上限16KiB，固定非敏感错误；共享源准入对写操作生效。Web 增加本人安全页：分页会话、当前标志、撤销确认、旧密码/新密码输入、全域退出提示、结果未知恢复；迟到响应不得覆盖新登录主体。

## 实施顺序与局部验证

1. 和 O01a-B 一起冻结 security_v1 schema、事件、receipt及精确 session/scan 退役SQL；独立审查锁序及所有旧写路径。
2. Core/store/迁移优先，覆盖无管理员权限本人操作、跨主体404、复合键、回滚、重复operation冲突、当前会话撤销、密码策略、预算饱和、并发改密和旧登录快照竞争。
3. Axum bearer/browser adapters，覆盖来源/Origin/CSRF/client/tenant/purpose边界、no-store、请求体和异常脱敏；更新OpenAPI/漂移测试。
4. Web 与参考宿主显式配置、security扩展检查；真实独立PostgreSQL/HTTP/浏览器局部测试验证旧会话跨租户不可继续，COMMIT未知能恢复。
5. 文档列明迁移预览/显式应用、可回退代码与不可丢失凭据版本数据的边界。本期不对真实库运行迁移，不完整验收/部署/推送。

未冻结项（会话历史筛选、receipt恢复方式、browser路径）不是实现者自由裁量；编码前由主代理补齐并 double check。

## 主代理后续裁定：会话筛选与改密 receipt

会话列表首批仅列数据库 status=active 的会话，按当前时间投影 active/expired；不提供历史撤销列表。稳定排序 tenant_id/id，cursor精确两字段，页长50（请求可1..50）；响应 last cursor 从最后一条返回记录生成。减少历史保留与跨产品展示耦合，注销其他会话后刷新即可消失。

改密采用单次命令与客户端预生成 receipt secret，不新增准备接口。浏览器在提交前用 Web Crypto 生成32字节随机 receipt_secret 和UUID operation_id，并保存为仅当前页/会话关联的敏感恢复状态。请求同时携带两者；Core只存 purpose域隔离HMAC摘要，绝不把secret当作操作ID或写入日志。凭据更新、非秘密event和成功receipt在同一事务写入；失败无成功receipt。

独立 POST `/auth/security/password/result` 只收 operation_id/receipt_secret，不要求已撤销session；只返回 completed:true 或 completed:false，不返回账号、tenant、密码资料、版本或登录能力。缺失/无效secret/未知operation对外同一false响应；语法无效可400。强随机secret使其成为短期只读收据能力，不是重置密码票据。读请求同样受来源限流与16KiB限制。成功receipt保留24小时，清理后返回false（不能解释为写入未发生）。UI文案必须明确false表示尚未确认，不能自动再次改密。

原操作重试只在仍有效认证下执行；如果receipt已完成且secret与命令摘要匹配，返回同一成功结果而不再写。命令摘要使用独立key HMAC绑定新密码、原actor/account及operation，避免存可离线猜测的新密码SHA。不同payload同operation409；不得通过receipt secret授权新改密。验证密码前可检查成功receipt，但只有相同actor和摘要时短路；不能让receipt查询路径执行领域写。

本裁定解决前述receipt/会话筛选待定项；browser认证装配及security_v1精确schema仍待复核，S03-A尚不进入编码。

## Cookie 接点复核结果与路由实施裁定

S03-A0已补齐独立 SelfSecurityBrowserIdentityService，见配套设计和implementation-result。旧业务扫码身份合同未扩大。后续browser本人路由放在 browser_session 的子模块中，直接复用父模块私有配置与credential解析；将现有guard的header判定抽为内部共享函数供两种state调用，不能复制一套逐渐分叉的CSRF规则。

新增独立router构造，不修改现有 browser_session_router 的参数签名。构造时校验self-security identity service purpose/lifetime与HTTP配置严格相等；路由根沿用原purpose对应 `/auth/browser` 或 `/admin/auth/browser`，其下 `/security/sessions`、`/security/sessions/revoke`、`/security/password`。读取也用POST+必填expected identity JSON，保证旧标签页拒绝、Origin/固定browser头校验及16KiB body上限；这些候选读取路径与此前Bearer GET列表不混淆。Host外层prefix保持不变，Cookie仍由旧登录/恢复模块管理。API DTO及schema须随S03后续合同一起冻结并更新OpenAPI。
