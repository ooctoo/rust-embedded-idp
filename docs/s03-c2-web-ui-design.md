# S03-C2 自助安全页面、恢复交互及持久记录设计

2026-10-26；前置C1 SDK、201项Web单测和9项构建产物检查已通过。本批闭合Web产品使用路径，不新增身份HTTP业务合同，不实现原生存储/MFA。沿用既有管理样式和embedded CSS变量，按oiloil状态覆盖、反馈闭合及可恢复操作规则设计。

## 页面与启用方式

增加可复用 AccountSecurityPanel（本人全域会话/撤销/改密/结果核对）和 PasswordRecovery（邮箱→验证码及新密码→完成/结果核对）两个React组件，业务主入口导出，不导入管理路由或Ant Design。props含identity（AccountSecurityPort加subscribe）、features、可选store、language默认zh-CN、onClose。中英文文案、每实例useId关联label、role=alert/status、busy禁用重复动作。CSS复用既有字体/颜色变量，响应式列表避免横向滚动；按钮显示动作文字。

features为 `{enabled:boolean,recovery:boolean}`，enabled表示可选安全写已开启，recovery要求enabled同时为true。只读本人列表不由该写开关隐含关闭。未传features默认两个false；不能从404、URL或浏览器能力猜测启用。管理HTML新增宿主生成的 `idp-account-security` JSON meta，内容仅两个布尔值。main解析并传ManagementApp；旧router/render签名保留默认关闭，新可选构造器接入typed config。bootstrap从account_security/recovery_email派生，与实际路由一致；不新增HTTP能力探测或环境变量。

管理壳header加“我的安全”，先走已有canLeave检查，和“账号安全”（管理员管理他人）区分。打开后由ManagementApp稳定持有该页面，SDK改密清除登录也不卸载结果面板；关闭返回原壳或登录。登录页在enabled时提供“核对安全操作结果”，recovery时提供“找回密码”。登录恢复始终可匿名操作，不要求管理角色；页面说明具备安全管理权限的账号须联系管理员，不能承诺它会收到邮件。

EmbeddedAuth增加可选accountSecurity配置，原默认UI保持不变；明确启用时提供登录后的“我的安全”和登录前找回/核对入口。切换视图仍调用既有beforeSessionChange（若宿主提供），组件不自行改变宿主路由。独立组件也可由宿主直接挂载。SDK和组件通过传入identity的scope使用同一入口地址，不接收任意网络URL。

## 会话与改密交互

列表显示租户、client、purpose、创建/到期时间、状态及“当前会话”，支持下一页与返回上一页；初始loading、empty、error retry、失效身份均明确。跨租户会话可见，不绑定管理目标。enabled=false时只读，不显示可执行撤销/改密。

撤销必须明确确认目标；当前会话额外提示将退出本页。改密表含当前、新密码和确认新密码，autoComplete正确，提交前匹配确认。密码政策由服务器最终判断，页面不硬编码一套更强策略。密码/code在请求settle后清空，不进入任何journal。身份切换或组件卸载清空表单、列表和迟到请求显示；保留作用域内持久intent供匿名核对，禁止把旧owner写操作改投新身份。

成功改密/当前撤销后仍显示“已完成，请重新登录”；撤销他人会话后刷新列表。错误旧密码可保留当前身份并编辑重试。只读查询不会占用写journal，也不改变Cookie。

## 最小持久日志与状态机

新增纯TS account-security-workflow.ts，复用C1 SDK及parseSecurityIntent，不再实现HTTP或凭据状态机。导出SecurityJournalStore（read(): string|null；compareAndSet(expectedRaw:string|null,nextRaw:string|null):void）、createSessionSecurityJournal(scope,storage?)、AccountSecurityWorkflow、AccountSecurityFeatures及validateAccountSecurityFeatures。

默认store使用sessionStorage，key包含当前origin与opaque scope；绝不存localStorage秘密。一个scope只有一条有界记录（最多16KiB），便于避免同入口多个不确定安全写互相覆盖。记录严格形状 `{version:1,scope,intent,stage,flow?}`；stage仅pending/ready/completed。intent用C1解析并deep freeze；flow严格为 `{handle,expires_at_unix_secs}`，只允许恢复记录。ready恢复开始必须有flow；恢复完成记录保留flow且handle必须等于intent.handle。completed只允许本人写或恢复完成，不允许开始操作伪造完成。

store每次写/删除先比对原始raw，写后readback必须完全一致；异常或配额拒绝抛固定存储错误，不能继续网络写。真正sessionStorage同步操作在单页JS内不跨await，支持两个组件竞争时CAS拒绝覆盖；不宣称多进程或原生持久锁。自定义store须满足同合同。sessionStorage只承诺当前浏览器标签页刷新恢复，关闭标签页后不保证记录保留。

流程：
1. 新写无现存记录时prepare intent；先CAS保存pending并readback，再调用SDK。已有未关闭记录不生成另一个operation覆盖。
2. 开始恢复200将同一start intent记为ready并保存flow；后续验证码提交先替换为新的complete intent+同flow、pending，再发请求。
3. 本人写/恢复完成200或result=true将记录标记completed。保留到用户点击完成/关闭记录，不自动删除；成功后持久写失败仍保留原pending，提示核对，绝不重新生成operation。
4. 网络、5xx、无效响应、409、401 invalid_session等结果未知保持pending。只允许“核对结果”；start pending没有result，提供“用原请求重试”，始终同email/op/secret。result=false保持pending并显示未确认，不自动重试写、不自动换operation。
5. 明确的400 invalid_request/invalid_recovery、401 invalid_credentials、403 browser_origin_rejected、404 session_not_found、429 rate_limited可记ready供用户修正后重试，沿用原intent。ready本人写只允许相同owner/目标；ready恢复完成可重新填code/password但不改handle。其他未识别错误仍pending。404端点不可用不重试，提示宿主未开启，可显式放弃记录。
6. 用户明确“放弃本地记录”需确认：这不会撤销服务端操作；删除也做CAS/readback，不隐式取消在途网络。busy时禁止放弃。损坏/未知版本/超大记录失败关闭写入口，可显式确认移除损坏raw；读会话仍可用。

workflow snapshot包含record/busy/error/storageError，不含密码/code/token。workflow持有SDK及store，提供subscribe/getSnapshot、listSessions、revoke(targetTenant,targetSession)、changePassword(current,new)、startRecovery(email)、retryStart、completeRecovery(code,new)、checkResult、discard。每次动作先读取当前raw，发现其他视图已改写则刷新snapshot并拒绝本次旧动作；不覆盖。busy覆盖从保存pending到结果落盘。只读listSessions不改变日志。methods不自动poll。flow时间过期时禁止UI发送验证码，但pending完成仍可查24小时收据；不得以客户端时间替代服务器资格或过期校验。

## 恢复页状态

无记录：邮箱输入和提交，统一提示“如果账号符合恢复条件，将发送验证码”。ready start或ready complete：显示验证码、新密码、确认密码及有效期；默认不显示handle/receipt/op。pending start：原请求重试；pending complete：核对结果。completed：成功并返回登录，不自动登录。其他类型的已有记录显示安全结果核对，不覆盖为恢复。明确重新开始需先确认放弃本地记录，再提交新email请求；只有服务器新start会使旧流程失效，不把本地删除说成服务器撤销。

## 实施及验证顺序

1. 独立复核上述日志状态、CAS、功能开关与UI身份边界，修正冻结后编码。
2. worker A仅workflow/store及纯TS测试；worker B仅两个React组件/CSS及EmbeddedAuth嵌入；primary负责管理App/Shell/main、Rust typed meta/接线、导出/文档/集成。公共命名按本设计，组件尽量共用结果面板但不建通用表单框架。
3. 单测覆盖write-before-network、storage拒绝/readback丢失/损坏/CAS、unknown刷新恢复、false保持、同op重试、成功落盘失败恢复、密码不入journal、错误retry与新身份禁止写；SDK及既有client回归保持。
4. Web test/build/bundle、App meta局部测试；Playwright局部页面交互（合成API故障/切换/刷新、键盘label、窄屏）、隔离PG真实管理安全页及业务嵌入恢复的关键链路验证。明确区分浏览器fixture证据与真实HTTP/PG证据，不扩大为完整验收。
5. 更新C2实施结果、API/宿主配置文档、组件使用示例和一期交付清单。没有完整验收/部署/推送授权。

## Double check

独立复核完成。主代理核对当前bootstrap确认本人只读路由无条件挂载（写路由另受account_security开关），所以参考宿主enabled=false仍提供只读；第三方宿主直接挂载组件时须先挂载只读API，不将模块合同误解为自动装配。404仅当固定code=session_not_found才允许ready，其他404一律pending并提示端点不可用。CAS冲突必须在任何网络调用前中止并重新读取当前raw；不得解释成写成功。上述澄清后冻结，可开始实施。

### 冻结实现接口

workflow构造器为new AccountSecurityWorkflow(identity: AccountSecurityPort, features: AccountSecurityFeatures, store?: SecurityJournalStore)，默认store由当前scope构造；features只含enabled/recovery布尔值，recovery要求enabled，缺省由validateAccountSecurityFeatures(undefined)返回两个false，非法显式对象拒绝。Snapshot为稳定不可变对象：record可选、busy布尔、error可选固定code字符串、storageError可选固定code字符串。错误code只取白名单或通用固定值，不存服务端任意文案。方法失败更新snapshot后reject，UI捕获以防未处理promise。getSnapshot/subscribe使用绑定函数，适用于useSyncExternalStore。

组件props统一为identity、features?、store?、language?、onClose?，identity类型为AccountSecurityPort加subscribe(listener:()=>void):()=>void；既有两个client均满足。AccountSecurityPanel和PasswordRecovery分别导出。公共store/Workflow/Features/validate函数同时从主入口导出，管理页面可复用但业务bundle不得出现管理路径。初版不增加自动后台轮询或跨组件事件总线；每次动作前读当前raw、CAS拒绝陈旧视图，提供重新读取按钮。flow的安全整数时间需以可表示日期显示，否则固定“时间不可用”，不能因异常服务响应崩溃。

### 身份切换首帧与完成记录收尾补充

2026-10-26 独立实现复核补充并冻结：面板/恢复入口必须在身份变化后的首个render就隔离旧表单和会话列表，不依赖useEffect稍后清理。外层组件持有每个入口唯一的AccountSecurityWorkflow与snapshot；内层纯UI按完整身份key设React key，身份变化卸载旧本地状态并重建新视图，但不清除该scope的journal。旧异步列表响应不得更新新视图；workflow仍按单实例与既有CAS/snapshot合同工作，不增加跨组件总线。

EmbeddedAuth默认UI只在显式传入accountSecurity配置时显示登录后“我的安全”；此时即使enabled=false也允许进入只读安全页。完全省略配置时保持既有登录界面。登录前结果核对/恢复入口仍按enabled/recovery能力显式展示。安全面板正在处理时，返回按钮禁用。

完成记录的操作按钮显示“关闭记录”，说明删除的是本地凭据记录，不会取消服务端操作；未完成记录仍称“放弃本地记录”。关闭均需确认、CAS删除并readback，不改变服务端状态。

实现前接口复核补充：开始请求失败且没有flow时始终pending（包括400/429），仅原intent重试或显式放弃后重新填写；不能构造没有flow的ready start。另导出SecurityJournalRecord，workflow增加refresh():void只读当前raw并更新snapshot，供陈旧视图显式刷新。两个组件各自仅创建一个workflow，子结果面板复用父实例/snapshot，避免同页两实例造成busy或结果显示不同步。

### 2026-10-28 交付前复核修正

发现并复核两处只读状态问题：listSessions失败不能发布到写journal的共享error，否则重试成功/身份切换后仍显示旧错误；翻页游标只能在请求成功且generation/身份仍匹配时与page一起更新，不能在发请求前push/pop。实施顺序：先把列表错误限制到Panel局部错误状态（workflow仅分类后reject），再让load接受候选cursorStack并在成功时提交page+stack。失败保留原page和原stack，下一次重试只请求一次候选页。已有写操作busy/record/error不受只读请求成功或失败影响。验证覆盖迟到列表失败不污染完成记录/新身份，以及下一页失败→重试成功→上一页返回首页；无需修改HTTP合同或增加依赖。已核对组件已有身份key/generation与SDK身份检查，采用这一最小修正后再实施。

同轮恢复输入复核：验证码格式错误目前在保存pending后才由SDK拒绝，实际没有请求但日志无法再编辑。冻结修正为workflow在ready记录转pending前检查6位ASCII数字code及string密码，非法输入保留原ready记录并返回固定invalid_request；UI补pattern/minLength，服务端仍负责正确性和密码策略。不得把所有invalid_security_intent泛化成可重试。测试须同时覆盖ready-start与ready-complete，短码/字母码不发网络、不改原intent，随后合法码可继续。
