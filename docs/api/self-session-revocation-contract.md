# 本人会话撤销与收据：Core/PG合同

S03-A2 实现 `SelfSessionRevocationService` 与 `CoreSelfSessionRevocationService`，详见[设计及复核](../s03-a2-session-revocation-design.md)。S03-A3新增独立HTTP路由和可选参考宿主挂载，读取列表与撤销路径分开。

`revoke_session(AccessActor, SelfSessionRevokeCommand) -> Result<(), AccessError>`：目标由target_tenant_id/target_session_id复合键指定，必须属于actor账号。请求另含非nil operation UUID及提交前由客户端生成的32随机bytes receipt_secret（43字符base64url，无padding、非全零）。actor必须仍为有效的第一方会话，delegated OAuth scope不允许全域本人安全写。目标可为当前、pending、过期或已撤销的本人会话。

成功时原子提交目标及未交付扫码子会话的凭据失效、加密扫码结果清理、安全事件和24小时成功receipt。已acknowledged的独立扫码子会话不随源会话单次撤销；显式以该子会话为目标仍可撤销。receipt与event插入失败则所有撤销回滚。无需赋予管理员角色，不影响其他账号或相同UUID的其他tenant会话。

仍有效的同actor可重放同operation/secret/目标；Core按receipt内的key ID验证摘要，不重复事件。变更参数或复用已过期operation返回`Conflict("security.operation_conflict")`。目标不存在/不属于本人均`NotFound("session")`；actor失效返回Forbidden；非法格式InvalidInput；receipt全局容量100000满返回`Conflict("security.receipt_capacity")`，未来HTTP必须映射503而非当作成功。加密配置/未知key固定Backend错误，不返回秘密或底层错误。

`session_revocation_result(SecurityReceiptQuery) -> Result<bool, AccessError>`：仅operation_id/receipt_secret，无actor，返回当前有效成功收据是否可验证。不存在、过期或错误secret统一false；非法格式可拒绝。true不授予会话/登录/新修改能力，不返回账号或目标信息。false是“未确认”，不等于“写入未发生”，前端不得因此自动生成新operation重做。当前会话被撤销后也可用该只读能力核对结果。

PG实现`SelfSessionMutationStore`：先锁access_state（写FOR UPDATE、结果读FOR SHARE），同事务检查基础/runtime部署绑定与布局，再按tenant/account/session锁定actor；Core在锁后取Clock。共享actor有效性SQL与只读列表保持一致。构造服务前宿主仍应显式check扩展；不提供在线DDL、清理worker或浏览器secret保存策略；S03-A3的HTTP认证装配见下。


## S03-A3 HTTP合同

业务Bearer POST `/auth/security/sessions/revoke`，Cookie POST `/auth/browser/security/sessions/revoke`；管理对应`/admin/auth/security/sessions/revoke`和`/admin/auth/browser/security/sessions/revoke`。各路径加`/result`是独立只读收据能力入口。外层prefix由宿主控制，只有显式account_security配置启用才挂载。

撤销JSON：target_tenant_id、target_session_id、operation_id、receipt_secret；browser另必需expected（tenant_id/account_id/session_id/client_id）。结果JSON仅operation_id、receipt_secret，不要求已撤销Cookie/Bearer；browser结果仍必须通过Origin、固定browser头和Fetch-site策略。所有对象拒绝未知字段，结果禁止tenant/business选择头。Bearer撤销可带与actor匹配的tenant头，不能用其切目标身份。

成功撤销200 `{completed:true}`；查询200 `{completed:true|false}`。401 invalid_session、404 session_not_found、409 operation_conflict、400 invalid_request、容量/基础设施503 security_unavailable、无效store500 server_error。JSON提取器413/415/422按Axum原行为；所有响应no-store、16KiB body限制、无Set-Cookie。撤销结果不清除另一标签页的新Cookie，旧会话在数据库中已经失效。

business OpenAPI为包含4项增量的条件目录。旧business_profile保持默认关闭该可选能力；business_profile_with_account_security显式设置启用，并与browser配置交集筛选Cookie路径。管理路径仍以本合同和路由清单为准，未声称有完整management OpenAPI。
