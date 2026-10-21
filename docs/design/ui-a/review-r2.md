# UI-A 修订 2 再审记录

| 项目 | 记录 |
| --- | --- |
| 日期 / 对象 | 2026-10-20；UI-A 修订1静态业务稿及交互说明 |
| 依据 | [详细设计修订2](../../management-console-capability-design.md)、实际提交`6bed928964c67fa08d73ea61175e14bf3db7e65c`、既有管理Web/Core/Axum/Postgres代码 |
| 结果 | 发现7组设计偏差/覆盖缺口，已落实到[UI-A修订2说明](README.md)和[画板迭代2](ui-a-business-mockups.html)；未发现需在本轮修改产品代码的依据 |
| 判定 | 无P0；P1为实现前应修正的契约/恢复误导，P2为任务完整性缺口。均是设计发现，不认定为同名产品故障 |
| 边界 | 只修改设计资产/说明；无产品代码、提交、产品测试或验收；UI-B与M1-03–06未启动，试点/部署待定 |

## 1 发现与修订

| ID / 级别 | 修订1的问题与影响 | 当前代码依据 | 修订2处理 |
| --- | --- | --- | --- |
| UA01 / P1 | §5.1称撤销绑定沿用role版本，并笼统称所有写入检查版本，易误建CAS或声称预览动作已锁定 | [client分配/撤销](../../../web/management/client.ts#L1150)、[Axum Grant正文](../../../crates/embedded-idp-axum/src/role_binding_admin.rs#L85)、[Core当前角色检查](../../../crates/embedded-idp-core/src/access/admin.rs#L1561)；没有expected_role_version | §4.2/5.1逐接口区分版本、原状态与当前权限检查；预览为快照；C02增加binding ID |
| UA02 / P1 | 画板仅凭会话域0显示“平台管理员”，容易把认证范围当成受保护角色与动作授权；成员空状态未注明平台范围 | [Capabilities/Session](../../../web/management/client.ts#L1)无管理员角色声明；[管理authenticate](../../../crates/embedded-idp-core/src/access/authentication/management.rs#L107)产可信上下文，管理服务另查权限 | 顶栏/侧板显示已确认会话范围和账号ID，加“当前会话”入口；空状态标平台范围；原模式矩阵保留 |
| UA03 / P1 | 成员危险操作说明遗漏暂停/恢复完整后果；“最后有效成员关系”不精确，可能误判必须剩一个active关系 | [成员状态UI](../../../web/management/members.tsx#L164)、[Postgres清理](../../../crates/embedded-idp-storage-postgres/src/access/admin.rs#L1181)、[最后非removed关系检查](../../../crates/embedded-idp-core/src/access/admin.rs#L1918) | §5.1明确session/refresh/授权码/验证码/选择票据清理，暂停保留授权与绑定、移除清理绑定；C02.1–2样张；最后一个未removed关系与最后有效管理员分开 |
| UA04 / P1 | C05把401/跨标签变化合并为重新登录；未区分写成功后回读失败与未知写入，409提示似能识别具体领域原因 | [普通错误映射](../../../web/management/client.ts#L409)只保HTTP状态，[browserFailure](../../../web/management/client.ts#L527)、[原sessionChanged提示](../../../web/management/app.tsx#L119)、[logout](../../../web/management/client.ts#L1305)另有状态语义 | C05和§5.2分开401登录、sessionChanged重新加载、成功后读取失败、未知/解析失败、通用409、429/5xx/404与退出未知；密码/Secret回读不能证明新值 |
| UA05 / P2 | A01只有登记按钮，无ID输入画面；B02看起来可随意改business/在全量下拉中换角色，真实分页选择未画出 | [ID读取入口](../../../web/management/clients.tsx#L112)、[RoleChoice/重新选择](../../../web/management/members.tsx#L14)及角色详情读取 | A01.1定位层、B01.1游标角色列表、B02只读已选摘要+重新选择；切换清理草稿；角色/绑定稳定ID参与核对 |
| UA06 / P2 | Choose样张仅有下一页与泛化取消，少停用项；少量样例记录却统一启用下一页；零可用/过期只有概述 | [TenantPicker](../../../web/management/app.tsx#L20)和[选择状态机](../../../web/management/client.ts#L1232) | 首次取消“返回登录”、切换取消另述；租户/成员active双检查，不可用项禁选；少量记录按has_more=false；§6.1补过期/零可用/失败分支 |
| UA07 / P2 | 字段上限列了32×2048回调，却漏总JSON16 KiB；资源ID有效格式未在样稿旁说明 | [client总请求限制](../../../web/management/client.ts#L745)、[Axum上限](../../../crates/embedded-idp-axum/src/client_admin.rs#L26)、[resource ID检查](../../../web/management/client.ts#L1159) | §3.2/画板补总量及资源ID限制；本地未发送校验失败不标为未知写入 |

问题对应的主要交互风险：UA01/02/03会形成错误的权限或影响范围模型；UA04会诱发重复提交或错误恢复；UA05–07会让用户找不到下一步、使用无效选择或到提交时才得知限制。

## 2 已确认并保留的边界

- client仍是部署级list/get/upsert；回调完整替换、Secret留空保留/显式替换、公开客户端PKCE要求、无删除/停用、无CAS、不自动撤销既有session均有代码依据。
- 全局账号改密/状态变更退役所有域凭证，自己的账号处置沿原client清理；closed只读。没有自助恢复、MFA或step-up新能力。
- Enabled平台会话管理目标与非0会话/Choose范围分离；Disabled无租户CRUD/关联/移除入口。管理员任命仍要求原平台/系统会话并走专用接口，不从普通业务角色操作保护角色。
- 普通业务角色type/instance与business_admin的business范围保留；后者覆盖未来有效业务权限且不授予IDP管理权；业务资源存在和归属仍由宿主负责。
- 403、读取失败、未筛选空与筛选无匹配分开；不补未经授权资料、不伪造统计、全量分页导出或通用幂等写入。
- API/UI mount、meta、Cookie及Coordinator均复用M1-02；UI-A不挂新业务router，不改变可选browser/UI或只读启动契约。

## 3 设计复核断言

以下仅核对设计表达是否完整，不是产品运行验收：

| 编号 | 复核要求 | 本次处理 |
| --- | --- | --- |
| UA-D01 | 每个提交动作的身份、target、business、subject及原对象ID明确；只有真实接口声明版本才写CAS | 已修订；分配/撤销不再宣称role版本锁 |
| UA-D02 | 身份标签不能从域推断管理员角色；模式矩阵不扩大任命、全局改密或关联权限 | 已修订；保留平台/非0/Disabled边界 |
| UA-D03 | 暂停、恢复、移除、全局改密/停用、撤角色、撤管理员、撤会话的后果分别说明 | 已补暂停/移除样张与准确清理边界；其余保留原矩阵 |
| UA-D04 | 成功、成功后读失败、未确认写入、本地校验失败和冲突有不同后续；不盲重放 | 已拆分C05及说明；未知改密/换Secret不承诺GET可确认 |
| UA-D05 | 角色分页、ID定位、资源范围必选、Choose资格/取消/过期及无数据均有明确下一步 | 已补画板与说明；分页不伪造has_more |
| UA-D06 | HTML/说明/PNG同为修订2，主要变更在桌面与窄屏均不裁切；静态示例不连接服务 | 已核对22张PNG及HTML；五种视口无页面整体横向溢出，文件链接/重复ID/外部请求检查通过；不代表产品交互通过 |

## 4 核对证据与限制

本次阅读了上位详细设计、UI-A完整HTML与说明、相关管理页面和client方法，并追踪Core与Postgres中的成员处置、管理员保护、全域凭证退役及客户端写入。复用现有本地Playwright/浏览器只渲染静态稿，阻断外部请求；更新PNG并检查320/390/768/1024/1440视口。无Web/Rust产品测试、产品构建、真实API、数据库或部署验收。

视觉与交互仍为候选。真实键盘焦点、屏幕阅读器、触屏横滚、会话/并发/失败因果以及各模式运行证据留在后续获准的实施和验收阶段；本记录不把静态稿评为生产或无障碍合规。
