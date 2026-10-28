# S01-A：共享工作预算接线设计与实施计划

2026-10-26，基线`7b981a6`。状态：独立复核完成，以下两项修正已回写，允许开始本切片编码。属于[第一期安全基础版](phase-one-delivery-plan.md)的首批；不等同完整S01。

## 现状与问题

Core已有PasswordWorkBudget（全部密码工作4个，其中注册最多2个），各认证service默认创建自己的Arc。Axum已有AnonymousLoginBudget（8个并发POST */login），每个router独立创建，提供with_anonymous_login_budget供宿主在最终router外共享。tenant_auth::call与通用run_service_call将HTTP许可传入实际spawn_blocking，取消等待不应提前还许可。

参考宿主bootstrap.rs创建management、browser、普通多入口、device及legacy reference认证service，没有注入共同PasswordWorkBudget，也没有在最后合并router上共享AnonymousLoginBudget；入口增加会乘大预算。旧CoreTenantRegistrationService直接hash_password，缺少已有注册预算。注册邮件新runtime已要求service与runtime共享预算，但尚未挂参考宿主，不能把它当作旧注册已保护。

## 范围和合同

1. 不增加依赖或新算法，复用现有PasswordWorkBudget、AnonymousLoginBudget。保持默认构造器兼容；CoreTenantRegistrationService新增可选builder `with_password_work_budget`，默认独立预算，文档要求多入口宿主显式共享。
2. Core旧租户注册在输入/密码策略校验后、真实hash前申请`try_registration`，许可仅覆盖实际哈希。满载沿既有Store错误返回，不能写账号/验证码，不能改变registration_disabled或invalid-input优先级。哈希成功/失败/取消外层等待后真实工作退出才释放。注册预留两槽语义不改变。
3. 参考宿主build_composition每次创建一个预算对象，显式传给management_auth、legacy auth、独立scan_auth、ordinary_business_routes所有auth_for以及旧租户registration。browser/restricted配置与token用途不变。匿名HTTP预算同样每个composition一个，包裹两条return路径的最终router。各库router现有局部预算保留，兼容独立消费者；嵌套许可继续通过task-local传递。
4. 本批不把预算保存为进程全局或环境变量，不改变数据库事务、schema、DTO或路由集合。不更改reference/bootstrap离线命令、admin改密/创建等已认证写操作；S03阶段再统一新增密码写路径的预算策略。
5. 两个嵌入示例和其他宿主必须在S01后续接线批核对；本子批仅reference host及Core缺口，不据此宣称整个仓库所有宿主共享。S01-B会补阈值typed policy、来源/账号键和状态错误；当前沿现有固定4/2及8的兼容参数，不伪称配置化已完成。

## 安全与失败语义

登录沿既有503暂不可用/no-store映射；旧租户注册原先将Store错误统一映为500，本次仅新增password.work_unavailable专门映射为503 temporarily_unavailable/no-store，其他Store错误不改。预算不是认证，不能改变tenant、purpose、proof/admission或授权。默认构造不同composition互不共享。Core哈希预算与HTTP容量独立，任务取消后HTTP持有链和实际KDF许可均必须覆盖工作真实结束。不持数据库锁等待预算，不排队等待KDF许可。该批不承诺速率窗口、IP/账号限流、分布式一致性或统计抗枚举。

## 实施步骤

1. 复核现有run_service_call/tenant_auth::call取消路径及bootstrap所有认证/注册创建点，写复核结论。
2. Core注册添加builder和哈希许可；测试共享预算耗尽时无写入、释放后恢复、注册占用不超过2且保留登录槽。
3. bootstrap创建/传递一个预算，覆盖显式ordinary和LegacyReference两条组装路径；外层包裹共享HTTP预算。
4. 以确定性阻塞服务验证多个router共享HTTP上限、取消后物理任务未结束仍占容量、释放后恢复。共享Core预算用真实service或可注入夹具验证，不仅比较实现字段。
5. 局部Core/Axum单测、参考宿主编译及定向集成；同步旧注册503错误投影及路由清单；未建模旧注册schema时明确记录范围，不伪称全API schema已齐。更新实施记录/进度后进入S01-B。

## double check检查表

- [x] 注册许可不会跨持久化/投递无谓占用；失败无持久副作用。
- [x] management与所有browser/device/legacy/ordinary创建点均共享，两个return分支均有HTTP外层。
- [x] task-local持有链覆盖spawn_blocking取消，未引入提前释放或等待死锁。
- [x] 兼容constructor/default、proof和token生命周期不变。
- [x] 子批边界、后续示例接线/阈值配置及匿名安全缺口未被标成完成。

## 独立复核记录

只读复核对照了Core注册执行顺序、bootstrap六类构造点与两个返回分支，以及http_support::run_service_call/tenant_auth::call的task-local持有链。修正遗漏的legacy scan_auth接线和旧注册500/新增503映射差异。主代理确认仅对新引入的预算耗尽分支增加503，并补HTTP负例；其他错误不改。以上是设计复核结果，实际代码与验证证据在实施后另记。
