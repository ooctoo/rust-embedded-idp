# S03-C2 Web 安全页与持久流程实施记录

2026-10-26，工作分支 `codex/registration-physical-timeout`，未提交候选。
先完成[详细设计及实施计划](s03-c2-web-ui-design.md)，独立复核后实施；实现审查再修正状态机和身份隔离。

## 已实现

- 共用 AccountSecurityPanel、PasswordRecovery 与 AccountSecurityWorkflow；管理端、EmbeddedAuth 与独立嵌入均可用。本人全域会话、撤销、改密、邮件恢复和匿名收据核对形成可见路径。
- typed features默认关闭写与恢复；参考宿主安全配置生成转义的meta；只读查询不绑写开关。旧EmbeddedAuth省略配置时保持原界面。
- 标签页sessionStorage一条scope日志，先保存pending/readback再发请求，CAS防覆盖；unknown只核对，恢复开始只用原intent重试，完成记录显式关闭。密码/code/token不入日志。
- 四字段身份及scope隔离内层页面状态，保留外层唯一workflow；切换身份不显示旧列表/密码，迟到请求不能污染新页面。改密/撤销当前会话后仍保留结果页。
- 局部浏览器测试夹具仅显式开关+显式PG URI可运行；随机账号、私有临时文件、本地SMTP及独立schema，stop文件/20分钟截止/RAII退出。未向真实邮箱发送邮件。

## 审查修正

完成类pending禁止再次提交；只有精确HTTP status/code组合可进入ready。成功后的存储错误不再经通用catch覆盖其他视图记录。CAS冲突重新读取仍保持busy，避免订阅者重入。损坏记录仍能查本人会话且有明确移除入口。已完成记录使用“关闭记录”而非“放弃”；所有关闭仅删除本地凭据，不取消服务器操作。最终页面检查补齐首次列表读取失败时的重新读取入口，并通过浏览器失败→重试→显示会话验证。

## 本批验证

| 检查 | 结果及范围 |
| --- | --- |
| Web Node回归 | 219/219，包括18项workflow测试；旧client及SDK回归保持 |
| TypeScript及Web构建 | 通过；管理端现有大chunk提示仍存在，不影响构建 |
| 构建产物测试 | 10/10，含两个实际client、公开组件、默认关闭、独立label及业务bundle不含管理路径 |
| App管理HTML局部测试 | 7/7，含安全meta默认关闭、明确开启、非法组合/重复拒绝 |
| fmt / workspace all-target | 通过；既有测试helper dead_code提示不当作失败 |
| 接口合同及漂移脚本 | 20项OpenAPI测试通过，4类制品与A05示例检查无漂移；本批不新增身份HTTP路由 |
| Playwright合成故障 | 错误旧密码可修正且清空输入；丢响应后刷新保持op，false不重发，true完成；恢复开始同op重试，pending complete不可重发；敏感字段不入日志；身份切换清空旧值；损坏日志仍可读列表；键盘label/顺序与375px无横向溢出 |
| 真实参考宿主/PG/SMTP浏览器 | Enabled模式，一次性Postgres18.6容器；管理Cookie登录→本人列表→错误旧密码→正确改密退出→刷新结果恢复；业务token嵌入恢复开始→刷新保留flow→本地SMTP code→恢复完成→新密码登录→本人列表→关闭记录→撤销当前会话退出。fixture测试1/1，通过后宿主/schema/容器清理 |

浏览器通过同源本地代理访问真实宿主，不引入生产CORS配置。真实HTTP的Enabled/Disabled、Cookie/token和多入口矩阵已在B3等前置批次验证；本批新增真实页面链路只声明Enabled。恢复完成脚本末尾曾因期待另一文案超时，实际恢复与登录已成功；按实际公开文案重新断言并继续撤销链路通过，未掩盖失败重跑整个业务操作。

本地证据：`/private/tmp/idp-s03c2-{tests,build,bundle,meta,fmt,check,contracts}.log`及最终Web/嵌入资源复跑的`*-final.log`，`/private/tmp/idp-c2-live.log`，浏览器截图/临时脚本在 `/private/tmp/idp-c2-browser/`。最终全工作区离线回归结果记录于[一期交付清单](phase-one-delivery-checklist.md)。这些是本地证据，不是远端CI或完整验收。

## 交付边界

[接口/组件合同](api/account-security-web-contract.md)和[宿主集成说明](host-integration-v1.md)已同步。无新增Web依赖。没有部署、推送、合回main或提交本轮改动；sessionStorage不提供关标签后的恢复、原生安全存储或跨进程锁。完整验收、目标环境邮件/TLS/容量/灾备/实体设备验收另行安排。
