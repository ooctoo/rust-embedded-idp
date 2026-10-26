# N1 既有 ID 兼容专项最小实现与验收回传

| 项目 | 内容 |
| --- | --- |
| 版本 / 日期 | 修订2，2026-10-23；补齐两类非阻断验收缺口 |
| 状态 | N1最小实现、本地相关验收及修订2提交前核对完成，随本批本地提交归档；未推送，不是目标环境或生产验收 |
| 设计基线 | [N1修订2](management-console-n1-id-compatibility-design.md)，归档`6853be0b0ab0baa46d45f478531080e78497365c`；[N0修订2](management-console-n0-support-baseline-design.md)、[交付总结修订2](management-console-delivery-summary-and-plan.md) |
| 代码定位 | 分支`codex/management-console-ui-b`；实现与验收以设计提交`6853be0`为父基线，本批提交归档相同产品/验收源码及证据；精确文件摘要见下；3.0.0 / `tenant_v6`未变 |
| 源码与制品 | [摘要](design/n1/source-manifest.json)：5个产品文件、7个验收文件、17个未改边界及构建制品摘要；四个临时宿主实际提供的Web资源与本次构建匹配 |
| 本轮边界 | 复用Core、存储、管理认证、会话与原UI任务；无schema、依赖、配置或启动装配增量。D02–D07继续待决；N2–N5与M1-03–06未启动，试点和部署继续待定 |

## 1 交付结论与剩余兼容边界

新管理UI与新服务端配对时，精确`.`/`..`租户可沿既有精确查询读取并通过集合PATCH保存，客户端可按固定query地址读取、登记/编辑及回读；路径不再承载这些动态ID。客户端初读只有明确的200/null才开放登记，挂载错误、畸形响应及写后缺失都不能自动转为登记或重放。

交付总结K01/K02在本次新协议及新UI的本地验收范围内闭合，**旧动态路径仍有归一化/静态动作名限制**。旧UI保留其原预拒绝，旧client不会自动获得新查询能力；新client需要新服务端，不向旧路径或列表扫描自动降级。没有改变合法ID语法、存量ID、公共方法签名、业务用途、平台身份或目标租户权限；没有新增客户端CAS、删除或幂等写入协议。

宿主直接调用Core或选装独立管理router的方式保持；仅API/无UI或无browser不要求后台壳层。通用旧AdminService/admin_router保持原合同，不因本次而自动获得独立管理新入口；同宿主的两组重叠路由仍需隔离前缀和认证。

## 2 实际实现

| 落点 | 实际变化 / 复用 |
| --- | --- |
| [client_admin.rs](../crates/embedded-idp-axum/src/client_admin.rs) | 新增GET `/admin/clients/-/lookup?client_id=...`。类型化query拒绝缺失/重复/未知字段，原Core完成ID语法与权限校验；精确NotFound("client")才投影200/null，错ID和其他错误保持失败。旧列表/动态详情/upsert保留，不新增保留ID |
| [tenant_management_admin.rs](../crates/embedded-idp-axum/src/tenant_management_admin.rs) | 新增PATCH `/admin/tenants`，独立JSON DTO含tenant_id与原字段；拒绝非空query及缺失/重复/未知字段。与旧路径PATCH共用原platform_context、UpdateTenant、mutation_response、版本和审计事务；旧DTO仍拒绝body tenant_id，Disabled仍为空router |
| [ManagementClient](../web/management/client.ts) | 原request/authenticated链局部增加200与JSON媒体类型约束，仅新lookup和集合PATCH使用。lookup验证外层/内部ID及metadata；实际404/405映射status=0/client_lookup_unconfirmed，getClient仅在合法null时合成404/client_not_found。updateTenant统一集合PATCH并核对ID、audit_id、原版本+1及提交字段；普通旧请求默认行为和认证/revision/mutation机制保持 |
| [客户端编辑器](../web/management/clients.tsx) | 移除dot-only预拒绝及404后列表探测登记；使用lookupClient。以本轮written标记保留已发写历史，saved/unknown/rejected后null或读取错误保持未确认/锁定；合法非null回读后重新确认新意图。原成功反馈、密钥清理、危险确认、草稿和离页守卫复用 |
| [租户编辑器](../web/management/tenants.tsx) | 只移除dot-only禁止PATCH，沿原originalId、SafeConfirm、write反馈与详情回读；创建/设置任务、初始管理员事务、确认版本、焦点和离页保护不变 |
| [宿主说明](host-integration-v1.md) | 补新路径、错误与版本配对、两类router边界及恢复合同；不新增宿主平台、发布、部署或前端分发承诺 |

HTTP地址中的`/-/lookup`是固定两段，单段ID `-`、`lookup`仍能走旧详情；`upsert`经新查询可读，旧GET `/clients/upsert`仍为405。query只解码一次；JSON不解码ID，不trim或转换。实现复用类型化提取器及原Core校验，没有额外编码解析框架、ID映射表或启动修复。

## 3 验收环境、结果及分层

本轮使用已有PostgreSQL18.6镜像新建带所有权标记的临时容器，随机schema；参考宿主仅监听loopback，使用Enabled平台、Fixed非0、Choose、Disabled四策略与非默认API/UI挂载。真实宿主测试另建随机schema，包含默认`/api`及原配置/旧参考回归；不读项目`.env`，不使用项目现存数据库。

本机为macOS/Darwin arm64；Node24.19.0、pnpm10.28.2、Cargo1.93.0。浏览器是Chromium headless shell1243 / Google Chrome for Testing153.0.8010.12，**不是已确认商用浏览器矩阵的桌面A2验收**。工具版本是实际记录，不重写仓库Node22/pnpm10.30.1/Rust stable前提。环境细项见[检查记录](design/n1/checks.json)。

本报告区分初次实现验收与修订2补验。修订2扩展N1浏览器脚本，并补充B脚本会话按钮就绪等待，更新报告与证据；5个产品文件及编译制品均与初次验收摘要一致。另建同版本隔离夹具，重跑Web、嵌入bundle和B/C/D相关回归；最终B使用另一全新夹具，避免N1真实修改dot租户名称影响B的初始夹具断言。Axum、workspace、真实宿主52项及F96沿用初次记录，未在补验中重复执行。初次11组及全部失败尝试保持原样，补验另存[followup](design/n1/followup/README.md)。

| 检查 | 最终结果 | 证据 / 范围 |
| --- | --- | --- |
| Web全量单测 | 111通过、0失败，其中管理client86项；补验重跑 | [补验检查](design/n1/followup/checks.json)；精确query、错误分类、两操作完整非200/媒体类型/JSON负例、版本与返回投影；含原身份/会话/导航单测 |
| Web与嵌入 | 初次完整构建及宿主/示例重编译通过；补验嵌入bundle3项通过 | [初次检查](design/n1/checks.json)、[补验检查](design/n1/followup/checks.json)、[制品摘要](design/n1/source-manifest.json)；补验复用一致制品，无生成bundle入库 |
| Axum | 98通过、0失败 | [检查](design/n1/checks.json)；新router/query/DTO断言是服务替身，不单独证明真实权限/事务 |
| Rust workspace | all-targets检查通过；448通过、152显式ignored | [检查](design/n1/checks.json)；ignored不是通过，不代表所有live项目已执行 |
| 真实参考宿主全项 | 52通过、0失败、0 ignored：33单元+2CLI+2bootstrap+15真实宿主 | [记录](design/n1/host-run.json)；原13真实宿主＋2项N1专项，真实认证/DB/事务与错误注入 |
| UI-B回归 | 19组、页面脚本错误0；补验重跑 | [结果](design/n1/followup/b/ui-b-results.json)、[执行](design/n1/followup/b/execution.json)；导航、hash、会话及原任务入口 |
| N1专项 | 26组、页面脚本错误0；原11组＋新增15组 | [结果](design/n1/followup/n1/n1-browser-results.json)、[执行](design/n1/followup/n1/execution.json)；每组含多个断言，见§4、§7 |
| UI-C回归 | 27组、页面脚本错误0；补验重跑 | [结果](design/n1/followup/c/ui-c-results.json)、[执行](design/n1/followup/c/execution.json)；dot-only成功流程及原确认、未知写、跨页、迟到响应 |
| UI-D回归 | 42组、页面脚本错误0；补验重跑 | [结果](design/n1/followup/d/ui-d-results.json)、[执行](design/n1/followup/d/execution.json)；集合PATCH、管理员保护、授权、恢复与目标隔离 |
| UI-F回归 | 初次96组、页面脚本错误0；补验未重跑 | [结果](design/n1/f/results.json)、[执行](design/n1/f/execution.json)；含133次布局、8项对比度与28次标签样本检查，保持原证据口径 |
| 静态检查 | Rust fmt、5个改动脚本语法、diff检查通过 | [检查](design/n1/checks.json)；未做提交/推送 |

各层存在重叠，不累计为唯一用例总数。UI-E47组和其他定向live项目未在本轮独立重跑，历史报告继续保持其原范围；本轮UI-F与Web/宿主结果不冒称替代所有安全生命周期、外部宿主或目标环境验收。

## 4 N1修订2断言映射

以下“完成”指本地相应证据层完成；不是全部环境组合或所有实现路径均由真实DB测试。替身、故障注入与原逻辑复用分别注明。

| 断言 | 本轮证据与结论 |
| --- | --- |
| ID01 | Axum新查询与Web测试覆盖dot-only、点混合、静态名及长度边界；真实宿主查询多种合法ID。Core语法未改；旧dot路径没有被宣称修复 |
| ID02 | Axum及真实宿主拒绝重复同/异值query、未知、空、双重编码和坏编码；一次`%2E`解码读取精确ID；JSON `%2e`拒绝 |
| ID03 | Axum替身区分精确NotFound/client、其他NotFound、Forbidden及错ID；真实存在/不存在精确投影验证。Core存储错误映射与权限事务复用，未把服务错误改为null |
| ID04 | 真实宿主原始JSON重复、未知、缺ID、query冲突、保留域及旧path/body冲突均失败，tenant.update审计不增加 |
| ID05 | 原精确租户过滤回读及单条/错ID/多条/后页/畸形拒绝单测通过；dot-only UI及HTTP回读实际成功，空页不解锁重建 |
| ID06 | router替身及真实宿主验证单段`-`/lookup与新地址共存、upsert经新查询可读、旧GET upsert405、原POST保留；集合方法分派通过 |
| ID07 | N1浏览器捕获真实请求，新GET的ID仅在query，新PATCH的ID/版本仅在JSON，无目标/业务头；与默认`/api`真实宿主及非默认挂载回归相互补充 |
| ID08 | 新集合入口缺tenant_id的旧body失败零审计；不以原dot路径被某URL处理层改写后得到的响应证明寻址安全。浏览器只向新固定路径发送，不使用旧dot路径或重定向回退 |
| ID09 | 新真实宿主用例验证无凭据、Cookie/开发subject伪造、业务Bearer、TenantSelection均拒绝；非0租户管理身份对两新入口及缺省/0目标头均403且无写入 |
| ID10 | 两新入口缺省/唯一0允许，非0/重复目标头、业务头拒绝；旧平台身份、被编辑资源ID与管理目标分开，真实HTTP/浏览器均有断言 |
| ID11 | 真实两模式客户端查询、Disabled租户404通过；浏览器B及原宿主四策略边界回归通过，不增加登录策略 |
| ID12 | 同一目标新集合/旧path并发同版本，恰好一200一409、版本只增一次、审计只增一；注入审计P0001触发器得到500，完整记录与审计计数不变，移除后同版本更新恢复成功 |
| ID13 | workspace重跑原Core锁后取时钟、事务内撤权、Secret哈希后会话到期等断言；新端点复用原服务。实际失效/隔离由宿主、C/D/F回归补充；真实PG“锁等待期间权限恰好失效”未新增专项，不将Core替身时钟推进说成该实测 |
| ID14 | 原客户端类型/PKCE/Secret规则及脱敏投影、密钥清理、确认摘要回归通过；新增HTTP查询不输出Secret/哈希，写仍走原upsert |
| ID15 | N1与C实际准备`.`/`..`客户端，输入ID及列表打开、编辑/保存/回读同一ID；真实缺失200/null才进登记，取消不写 |
| ID16 | 注入404/405/204/201/202/206/HTML/坏JSON/缺字段/错ID不显示未登记、不开放保存、不POST；原列表可读不能代替新lookup |
| ID17 | N1真实dot-only租户确认显示原/新值和版本，取消零PATCH；确认后body精确、版本递增；旧版本冲突由宿主验证，普通租户由D回归 |
| ID18 | 原客户端专项保留；补验对`.`/`..`租户分别覆盖草稿/确认/未知写：取消hash跨页、前进后退、目标及菜单跳转均保留原状态，取消关闭保留、确认关闭无重放；合成beforeunload事件证明处理器阻止标志，不当作真实刷新或原生提示实测。B/C导航、Web refresh等待busy继续通过 |
| ID19 | 补验对`.`/`..`租户各覆盖初读、集合PATCH及写后回读的真实响应延迟；同会话另一标签真实退出后释放并确认响应送达，旧响应不能恢复身份、编辑器或成功提示，零/一次写入不重放。C新lookup/POST迟到退出回归、Web revision和D目标隔离通过；不扩称覆盖所有身份替换/失效方式 |
| ID20 | saved后注入200/null及404保持成功与读取未确认，不开放新建/再次POST；真实合法非null回读恢复。unknown先完成真实POST并独立GET确认可见结果，再注入abort，不冒称真实丢包 |
| ID21 | saved/unknown/rejected后null/404不重新登记及合法非null恢复保留；补验增加null→404→503持续失败下的关闭：unknown/rejected取消关闭仍锁定，确认放弃后才关闭；saved保留成功证据并可直接关闭。失败路由未移除前完成关闭，独立读确认原记录与预期写结果，无追加POST；初次200/null仍允许登记。租户仍使用详情/错误流程 |
| ID22 | C/D/F危险确认、成功/失败回焦、取消、窄屏、Select/textarea标签及敏感字段清理回归通过；无新视觉改造或可访问性认证 |
| ID23 | 真实宿主旧客户端动态GET、租户path PATCH、JSON upsert及创建保留；B/C/D/F分页/过滤/排序回归通过；通用旧router和公开签名未改 |
| ID24 | Web/浏览器缺lookup、405和坏响应全部保守失败，集合PATCH非200不确认为成功；没有生产代理验收，未自动绕过缺路径/方法 |
| ID25 | all-targets覆盖宿主示例编译，嵌入bundle3项通过；Core/主入口/管理子入口/会话边界文件未改；原真实宿主双向用途隔离回归通过，不扩任意外部宿主组合 |
| ID26 | 52项宿主回归包含旧参考补缺不覆盖、新模式只读启动、仅管理及可选browser/UI；配置、seed、schema和装配代码未改 |
| ID27 | N1全部结果与失败尝试另存，源码/制品/实际环境和清理均登记；N0、UI-A–F原报告/JSON/截图未回写 |
| ID28 | 两新调用单测分别覆盖201/202/206/204、错误媒体类型/无效JSON、charset正例，拒绝后pending归零且无自动重试；lookup浏览器误登记负例及集合PATCH的未知结果分类复用原write机制 |
| ID29 | Web断言确认null时lookup返回null/getClient合成404/client_not_found；实际404/405两方法均status0/client_lookup_unconfirmed；401清理、403保留、网络/5xx不返回null，UI只用lookup |

## 5 失败尝试、修正与证据边界

1. 真实宿主首次51通过/1失败：新public_desktop夹具误用HTTPS回调，被原规则正确400拒绝。修正为原规则允许的loopback回调，补强非0管理员和审计故障断言后完整52项通过。[首次记录](design/n1/attempts/host-initial.json)保留，不改产品规则来迎合用例。
2. B前两次在会话抽屉重复校验时未取得预期HTTP响应而超时。验收脚本补抽屉绘制稳定等待，仍要求真实GET `/auth/session`及相同session_id；没有退回读取缓存比较。[尝试1](design/n1/b/attempts/attempt-1-execution.json)、[尝试2](design/n1/b/attempts/attempt-2-execution.json)保留。
3. N1前两次在租户确认的“取消”按钮定位失败，已完成前10组。脚本按现有中文两字间距规则修正定位，实际取消零PATCH断言不变；最终11组完整通过。[尝试1](design/n1/n1/attempts/attempt-1-execution.json)、[部分结果1](design/n1/n1/attempts/attempt-1-results.json)、[尝试2](design/n1/n1/attempts/attempt-2-execution.json)、[部分结果2](design/n1/n1/attempts/attempt-2-results.json)保留。

HTTP/界面故障、200/null、错误媒体类型及abort是明确注入。真实审计故障仅在临时schema注入触发器，已移除并验证恢复；不修改产品SQL。浏览器列表/分页的其他夹具按原脚本边界，截图均为合成数据实际运行，不能扩大为实体设备、真实网络事故、全部读屏或生产证据。

修订2补验的N1扩展26组首次完整通过，C27和D42通过。B先有两次等待校验HTTP响应超时，第三次在校验按钮定位超时；增补非loading就绪检查并允许loading图标形成的可访问名称前缀。诊断副本在原夹具通过前4组后，因N1已实际修改dot租户名称而不满足B的初始名称断言；最终原维护脚本在全新隔离夹具19组通过。前两次具体点击时序原因未被独立证实，不把等待改动说成产品缺陷修复；四次失败/诊断记录见[补验入口](design/n1/followup/README.md)，不计通过、不丢弃。HTTP200和相同session_id校验均保留，诊断副本不作为最终验收脚本。

失败截图和原始日志仅留本机临时目录；公开附件只保存安全JSON和合成运行图片，不包含state、配置、URI、token、密码或宿主日志。

## 6 清理、最终核对与未覆盖项

已验证临时容器所有权标记；真实宿主测试随机schema残留0。四个配置宿主进程已退出、临时容器及卷已移除，私有state/配置目录已删除，见[清理记录](design/n1/cleanup-checks.json)。

以上为初次验收清理。修订2的两个新增隔离夹具分别核对所有权、退出各自四个宿主、移除容器及卷并删除私有配置/state，见[补验清理记录](design/n1/followup/cleanup-checks.json)；不把初次清理记录当作补验清理证据。

最终核对范围包括N1修订2、5个产品文件、7个验收文件、真实结果及29项断言映射；没有新增Core/存储/认证接口、依赖、迁移或不必要框架。旧动态路径、旧UI和版本混用限制继续披露。合法ID功能闭合限于本次客户端及租户职责，不宣称其他实体所有HTTP寻址均已解决。

N0 D02–D07、真实商用浏览器/设备/读屏、代表外部嵌入消费者、所有代理/系统/部署组合、性能与长时运行、剩余ignored live测试继续未覆盖或待决定；实际PG锁等待时点失权未新增端到端专项。现有局部A1结果不能作为A2/A3通过或试点/部署授权。

本轮实现和补验执行时未提交、未推送；修订2提交前核对完成后随本批本地提交归档，仍未推送。原有无关`docs/m1-02-code-review.md`工作区改动保持，未纳入本任务；N2–N5和M1-03–06未启动，试点和部署继续待定。

## 7 修订2补验与完整复核

此前只读审查没有发现阻断性产品错误，但指出ID21持续读取失败后放弃关闭，以及ID18/ID19中dot-only租户专项证据不足。本次保持产品代码、Core、认证、存储、宿主装配和旧接口不变，扩展[专项脚本](../scripts/check_management_n1.mjs)并完善[B会话按钮等待](../scripts/check_management_navigation.mjs)。

| 新增组 | 实际断言 |
| --- | --- |
| 客户端3组 | saved/unknown/rejected各一次真实或明确拒绝的写入后，连续注入200/null、404、503；始终不变登记或追加写。unknown/rejected取消关闭仍保留页面及锁，确认放弃才关闭；saved可关闭且不撤销已确认成功。关闭期间失败注入仍有效，独立真实查询核对持久结果，重开须重新查询 |
| dot-only租户6组 | `.`和`..`各覆盖草稿、确认、真实已写入但响应被abort的未知状态；取消后退/前进/hash跨页/目标切换/菜单/关闭后保留原ID和草稿或锁定，最终明确关闭，无额外PATCH；独立回读名称和版本、会话仍为平台0 |
| dot-only租户6组 | `.`和`..`各覆盖初读、集合PATCH、成功写后回读延迟；取得真实200响应后暂缓投递，PATCH/回读阶段独立查询验证实际写入。另一标签验证相同session后真实logout，当前页清空，再释放并确认迟到响应完整送达，身份/编辑器/确认层/成功提示均不恢复，初读零写、其余一次写 |

上述15组与原11组一起完整执行。未知结果为“真实写入＋明确abort注入”，延迟为“真实响应＋投递门控”，不冒称真实网络事故。beforeunload仅合成事件检查；本次失效触发为同一会话跨标签logout，不声称覆盖全部会话撤销、身份替换、真实刷新提示或目标环境组合。已有其他机制的证据仍按其原层级复用。

完整复核对照N1修订2、实际实现、最新脚本与安全结果，逐项核对ID01–ID29及版本配对限制；上述两类缺口已在相应本地专项范围闭合，未发现新的实现偏差或回归。产品/边界/制品摘要一致、历史附件保持，相关回归及隔离夹具清理见[补验证据入口](design/n1/followup/README.md)。本结论不改变§6和N0的待决及未覆盖范围。

## 8 提交前核对与归档

2026-10-23，核对N1设计修订2、5个产品文件、7个验收文件及报告修订2，未发现阻断本次提交的偏差。产品/验收源码与当前摘要一致，17个Core、存储、装配、会话及嵌入边界摘要保持；设计修订2与N0修订2保持已归档原文。复核初次及补验机器结果、两类缺口专项、版本配对限制和清理记录，确认报告没有扩大验收层级。

本次运行Rust格式、两个增量脚本语法和diff检查，并检查文档链接、JSON、文件摘要及提交清单；产品/验收源码没有变动，不重复运行已通过的整套验收。Web111、bundle3、N1 26组、B19/C27/D42以修订2补验记录为准；Axum98、workspace448/152 ignored、真实宿主52、F96继续按初次记录使用。

提交范围限于N1实现、相关验收、宿主说明、报告/证据与文档入口；不纳入无关`docs/m1-02-code-review.md`、生成bundle、依赖目录或私有夹具/日志。既有身份与租户隔离、宿主直接嵌入、旧参考及兼容限制保持；仅本地提交，不推送、不发布、不启动后续阶段，D02–D07和试点/部署仍待定。
