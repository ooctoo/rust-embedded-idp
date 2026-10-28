# Web 自助安全 SDK 合同

S03-C1，2026-10-26。对应[设计与复核](../s03-c1-web-client-design.md)。本合同覆盖SDK与现有身份客户端传输桥；可见页面和会话内持久化日志已由C2实现，见[实施记录](../s03-c2-implementation-result.md)。

`@embedded-idp/react`导出AccountSecurityClient、AccountSecurityError、parseSecurityIntent及端口/会话/四类intent类型。AccountSecurityClient接受EmbeddedIdentityClient或ManagementClient；后者仍从/admin子入口导入。业务bundle不因此引入管理路由或Ant Design。

## 本人能力

listSessions(cursor?)读取本人全域会话，固定每页50条，next_cursor为null或下一页游标。可列出其他租户/client/purpose会话；current只对应发起查询的精确身份。客户端校验响应字段、分页边界、current和重复键。它与管理端按租户管理他人会话的API不同。

prepareRevocation(targetTenantId,targetSessionId)与preparePasswordChange()生成冻结intent，不发网络。revoke(intent)、changePassword(intent,currentPassword,newPassword)发送已冻结HTTP命令。只有仍匹配owner四字段的第一方身份可以提交。Cookie模式直接使用本人browser接口，不refresh/rotate；token模式可在提交前依既有策略取得token。明确的invalid_credentials不会清除当前登录。

成功改密或撤销当前确切会话后清除仍匹配owner的本页凭证，不发送logout、不清共享Cookie。迟到响应不能清理后来登录的身份。

## 匿名恢复与收据

prepareRecoveryStart(email)生成开始intent，startRecovery(intent)返回handle及expires_at_unix_secs。prepareRecoveryCompletion(handle)生成完成intent，completeRecovery(intent,code,newPassword)只改密不登录。密码/code只作为参数发送，不在intent或SDK状态中保存。

result(intent)接受撤销、改密或恢复完成intent，只发送原operation_id/receipt_secret。无需当前登录、Bearer、token刷新或Cookie身份；browser仍发送固定header并受Origin限制。completed=false只表示未确认。true只对改密或当前会话撤销清理仍匹配的原owner；恢复完成不猜测当前身份是否对应恢复邮箱。

scope包含purpose、模式与规范化入口base，只限制本地intent误复用，不更改服务端跨入口收据能力。不同入口scope的intent会在发请求前拒绝。

## 宿主必须完成的持久和交互责任

intent包含version/scope/kind/随机operation_id及32字节随机receipt_secret；本人写含owner，撤销另含目标tenant/session，恢复开始含email，恢复完成含handle。prepare使用安全随机源，不可用则拒绝。parseSecurityIntent用于从宿主日志读取时验证版本、scope、字段和canonical格式，拒绝额外密码/code/token字段并返回冻结记录。

调用者应先可靠保存intent，再提交。结果未知时保留同一intent并查询result，不自动换operation重做。开始请求无独立result，可用原开始intent重试取得未过期收据。SDK不选择宿主存储、不自动保存、不自动重试或轮询。C2参考页面已实现sessionStorage日志、恢复状态和显式放弃本地记录；第一期原生安全存储仍不包含在内。

所有本地SDK错误使用固定非敏感文案，status=0，code为invalid_security_intent、invalid_security_response、security_random_unavailable或security_session_changed。HTTP错误保留原client error的status/code；不同身份客户端的错误class不同，宿主不能只依赖一种instanceof。网络或畸形成功响应可能代表结果未知，必须结合保存的intent核对。

## C2 页面与持久流程

新增 `AccountSecurityPanel`、`PasswordRecovery`、`AccountSecurityWorkflow`、`createSessionSecurityJournal`、`validateAccountSecurityFeatures` 与对应 props/store/record 类型。两个 React 组件接受 `identity`（上述端口加 subscribe）、`features?`、`store?`、`language?`、`onClose?`。默认写与恢复关闭；显式 `{enabled:true,recovery:true}` 才开放恢复，recovery=true 且 enabled=false 拒绝。只读列表由宿主挂载的本人 API 提供，不要求 enabled=true。

默认日志位于当前标签页 sessionStorage，按 origin 与 client scope 隔离，一条记录上限16KiB；刷新可恢复，关闭标签页后不保证保留。日志包括 intent、pending/ready/completed 状态和可选恢复 flow，不含密码、验证码、access/refresh token。receipt_secret 是结果查询凭据，不得输出到日志/遥测、URL或复制到localStorage。独立组件与 EmbeddedAuth 同入口共享这条记录；不自动覆盖另一未关闭操作。

`SecurityJournalStore.read()` 返回原始文本或null；`compareAndSet(expectedRaw,nextRaw)` 必须原子比较并同步写入/删除，写后可读到相同值。默认实现满足单页同步执行范围，不保证跨进程锁。自定义store不满足合同会令写流程失败关闭。存储损坏/拒绝写不阻止只读会话查询；用户可明确确认移除损坏记录。

workflow 先保存pending并readback再发送HTTP。明确可修正错误才成为ready；网络失败、5xx、冲突、无效成功响应保持pending。完成类pending只能核对结果，false仍保持；开始类pending只允许原请求重试或明确放弃。completed保留到用户关闭本地记录。放弃/关闭不取消服务器操作，busy时不能删除记录。所有写与删除检查原始记录CAS，迟到响应不能覆盖另一个视图的新记录。

组件对身份切换隔离表单、列表与异步响应，但保留原intent供匿名核对。操作成功后仍显示结果面板；不会因为SDK清理当前会话而自动跳走。输入的密码/code在请求结束后清空。没有自动轮询、自动重新发起写操作或后台发送验证码。

```tsx
import { EmbeddedAuth, EmbeddedIdentityClient, PasswordRecovery } from "@embedded-idp/react";
import "@embedded-idp/react/style.css";

// client须稳定持有；base由宿主选择，不能取不可信URL参数。
const client = new EmbeddedIdentityClient("/identity");
const features = { enabled: true, recovery: true };
<EmbeddedAuth client={client} accountSecurity={features} />;
<PasswordRecovery identity={client} features={features} language="zh-CN" />;
```

上例两种入口通常择一挂载；如同时展示，独立视图需“重新读取”同步另一视图写入的记录。功能标志是展示配置，不能替代服务端权限与路由装配。参考宿主从typed account_security配置生成 `idp-account-security` meta；第三方宿主须按实际能力传入，不通过404猜测开启。

2026-10-28复核补充：只读列表错误不修改安全写journal；分页成功后才提交游标位置。恢复验证码格式错误在ready转pending之前拒绝，保留原记录供修正；服务端仍负责验证码正确性及密码政策。
