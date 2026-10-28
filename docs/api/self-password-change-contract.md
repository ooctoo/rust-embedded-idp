# 本人改密 Core / PostgreSQL 合同

2026-10-26。对应设计：../s03-a4-password-change-design.md。S03-A4提供Core/PG能力；S03-A5已挂载可选HTTP与参考宿主，见本文后半部分。Web仍待实施。

## 端口与认证

SelfPasswordChangeService提供change_password(AccessActor, SelfPasswordChangeCommand)与password_change_result(SecurityReceiptQuery)。命令包含current_password、new_password、非nil UUID operation_id及32字节canonical base64url receipt_secret（43字符，拒绝全零）。密码/secret均为SecretString，不能写日志。

CoreSelfPasswordChangeService构造器必须显式注入mode、store、clock、crypto、ids、有效AuthConfig及宿主共享PasswordWorkBudget。新密码复用现有注册策略（字符数量上下限、ASCII字母及数字，不trim）；当前密码非空且不超配置上限。错误类型SelfPasswordChangeError::{InvalidCredentials, Access(AccessError)}独立包装，不扩大旧AccessError枚举。

Actor必须由宿主可信认证，Core在每个事务中重查第一方session、账号/成员/租户、时效及device/key/binding。scope非NULL拒绝本人全域安全操作。业务与管理均可使用，入口client/purpose绑定仍由原认证服务保证。

## 锁外KDF与提交

SelfPasswordChangeStore分离ReadTransaction和WriteTransaction GAT。password_change_read读取凭据/收据，actor=None仅用于结果查询；password_change_write必需actor。Read接口只暴露actor_is_active、credential_snapshot、receipt；Write扩展receipt_count、replace_password_and_retire、record_completion。

PG先取得state SHARE（读）或UPDATE（写），核对base/foundation/runtime布局及mode/authority，再按tenant/account/session锁序执行闭包。服务锁后取Clock。读事务结束并释放连接、锁后，才在共享PasswordWorkBudget许可内验证旧密码及生成新Argon2 hash。写事务重新验证actor与快照；CAS同时匹配account、active状态、旧hash和credential version，恰更新一行。foundation trigger唯一负责版本推进。email/status/registration tenant变化也可使快照失效。任何失败均不部分提交。

同事务退役该账号全租户/purpose的session、refresh、authorization code、tenant selection和email verification code；扫码grant匹配source account或交付session account，可用状态失效、所有匹配grant增版本并清秘密，交付转revoked并清加密结果及收据hash。保留设备/绑定/密钥、扫码操作与tombstone/audit记录。

恢复pending flow失效；相关outbox pending/sending取消并清密文/key/lease，分别记录not_started/unknown，原终态保留结果。删除该账号所有flow的start receipt，保留累计邮箱budget。已发SMTP不能召回，未来worker须以lease/state CAS防止覆盖取消结果；恢复验证必须检查flow与凭据版本。

## 结果未知与容量

password_changed accepted事件与purpose=password_change成功receipt同事务提交。receipt TTL24小时，总容量100000（全部purpose、未清理过期行也计数）。容量满拒绝写入；不存在自动登录、自动重试改密或自动清理。

receipt secret用独立密钥HMAC，context绑定operation；命令HMAC绑定专用domain、actor tenant/subject/session及新密码，context绑定operation+subject。当前密码只用于认证，不保存到命令摘要。重放验证stored key ID，未知key为固定基础设施错误。仍有效actor才能写入/重放；成功改密已撤销其actor，通常应查询result而非再次写入。

result无需已撤销会话，仅由operation和secret授权读取bool：true为已提交；缺失、过期、secret错误为false。false表示尚未确认，不是未发生证明。语法无效返回InvalidInput。结果不返回账号、版本、密码或登录能力，不执行KDF和状态变更。已有收据操作号不可更换payload或在过期后重用。

存储/crypto故障不可当普通错误凭据或未知收据吞掉。security.credentials_changed与security.operation_conflict区分并发变化/重放冲突；security.receipt_capacity及password.work_unavailable是容量故障。HTTP映射已在S03-A5接线批冻结，见下文。

## S03-A5 HTTP与宿主接线

显式runtime.account_security启用时，参考宿主挂载以下POST命令及对应`/result`；未配置时404。模块根保持不变，宿主拥有外层prefix：

| 场景 | 命令路径 |
| --- | --- |
| 业务Bearer | /auth/security/password |
| 管理Bearer | /admin/auth/security/password |
| 业务Cookie | /auth/browser/security/password |
| 管理Cookie | /admin/auth/browser/security/password |

命令JSON为current_password、new_password、operation_id、receipt_secret；Cookie另必填expected的tenant_id/account_id/session_id/client_id。result仅operation_id与receipt_secret。所有DTO拒绝未知字段；固定16KiB上限，JSON提取失败400 invalid_request，过大413 request_too_large。所有响应no-store，无Set-Cookie。结果查询不调用认证，Cookie结果仍须原Origin/browser guard；禁止tenant/business selectors，不能用body身份授权写入。

成功200 {completed:true}；结果未确认200 {completed:false}。本人服务错误：旧密码错误401 invalid_credentials，失效actor401 invalid_session，策略/格式400 invalid_request，快照变化409 credentials_changed，重放冲突409 operation_conflict，预算/收据容量/存储/crypto/布局故障503 security_unavailable，无效存储投影500 server_error。入口认证沿用既有S03-A3映射。客户端不能把所有401当作清登录指令：错误旧密码不改变会话；迟到响应只有expected仍匹配时才可清本地状态。

构造器self_password_change_router、management_self_password_change_router、browser_self_password_change_router独立组合，不改变原router签名。宿主只构造一份改密service，注入与登录、注册、client secret、管理账号哈希共用的PasswordWorkBudget，以及同一authority与crypto。同步服务通过既有阻塞执行helper运行，调用者取消不提前释放物理工作许可。

CoreAccountSecurityService新增可选builder with_password_work_budget，旧new仍兼容且使用bounded默认预算；参考宿主显式共享。create_account、set_account_password、New administrator建租户三处hash在权限通过后立即try_login，饱和不写数据，管理HTTP沿用503 temporarily_unavailable。Existing administrator建租户及status变更无KDF，不占预算。此补丁保留旧管理写锁内hash；本人改密仍严格锁外hash。

本接线的测试与交付状态以S03-A5实施记录为准；不代表安全页和密码恢复已完成。
