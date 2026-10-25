# N2剩余功能缺口与GitHub Actions最小执行方案

N2远端就绪与workflow同步进展（2026-10-25）：截至`8fd9f46`的验收内容已按前序授权推送；main仅纳入N2 workflow并修正上下文。本轮将main `4ce8adec`的workflow精确同步到验收分支，完整复审及124项离线工具检查通过；[同步报告](n2-ci-workflow-sync-result.md)记录证据和新执行SHA的冻结规则。本轮仅相关同步、测试和文档/证据提交并推送，264项功能断言组尚未在CI实际执行。下文原阶段记录保留；本轮不触发实际补验、不部署，不测缩放/旁白，M1-03–06未启动。

后续工具实施进展（2026-10-25）：需求方已另行授权功能选集、CI驱动和workflow适配及离线工具验证，结果见[实施回传](n2-functional-ci-tooling-result.md)和[证据](design/n2/ci-functional-tooling-20261025/README.md)。已实现工具并完成122项离线检查；264项功能断言只登记未实跑，仍未执行实际CI补验或改产品。下文保留本方案归档时的阶段边界；当前实现完成复审后仅本地提交归档，实际SHA以包含本文的Git记录为准；未推送/部署，缩放与旁白不测，M1-03–06未启动。

日期：2026-10-25。编写基线为本地`cc0456118a5c795347cf1d6eb142392df570fe7a`，当前分支`codex/management-console-ui-b`。依据[R02运行拓扑](validation-runtime-topology.md)、[Linux Docker补验报告](n2-linux-docker-execution-result.md)、[Mac报告](n2-mac-execution-result.md)及需求方随后“先关注功能”“不再测试缩放和旁白”的范围调整。

**本文件是方案，未实施或执行。** 本轮只新增本方案并维护README、拓扑和交付汇总入口；完整复审修正后仅四份相关文档随本地提交归档，实际SHA以包含本文的Git记录为准。不改产品、测试驱动、依赖锁文件或workflow，不准备环境、不运行补验、不推送、不部署，不启动M1-03–06。无关`docs/m1-02-code-review.md`修改保留。

## 1 当前结论与剩余功能缺口

Mac H01和Linux arm64 H01的限定组合已有实际通过证据；Linux子批包含八阶段完整复验、SafeConfirm产品修复、工具错误路径加固和清理。历史用例数及失败保持在原报告，不重新写成当前CI通过结果。现阶段没有已确认未关闭的H01功能阻断缺陷；首次客户端拒绝原因未能从原证据追溯，继续保留限制，后续如再现须用已补强的诊断定位，不追认根因。

| 项目 | 当前事实 | 剩余工作与优先级 |
| --- | --- | --- |
| H01既有功能 | 四登录策略、管理会话、导航、客户端、授权、安全处置、N1及异常恢复已在已记录组合通过 | P0：把这些断言变为可重复的CI功能回归，覆盖新Linux浏览器组合，不能仅复制旧结果 |
| CI执行环境 | [现有CI](../.github/workflows/ci.yml)仅有构建、离线测试及已有专项；没有N2临时PG、浏览器和容器会话回归 | P0：补原生arm64 runner、浏览器安装、版本冻结、启动/失败诊断及最终判定 |
| 工具可移植性 | 现有Linux驱动限定Mac Chrome/headed和Docker Desktop context；各套混有布局检查，F还无条件执行CSS zoom | P0：工具层显式支持CI配置和功能子集；不能原样整套调用后宣称已排除缩放 |
| 证据与故障收尾 | 本地已有16项Linux工具、5项Mac工具离线检查，及所有权/部分创建/失败清理逻辑 | P0：补CI信号、超时、artifact白名单、取消/清理未知状态和失败退出码映射 |
| H02–H05真实消费者 | H01参考宿主不代签真实同源宿主、Rust消费者、业务React或管理目录消费者 | P1：消费者明确后逐行补验；目前延期，不用仓库示例补写A2通过 |
| 生产CPU与浏览器 | 生产Rust方向为Linux Docker；具体CPU、宿主和使用者浏览器尚未冻结 | 条件项：目标明确后再新增必要矩阵行；本批arm64 CI不决定生产架构或浏览器支持 |

本方案承接[原N2的28项断言](management-console-n2-target-validation-design.md#6-补验范围与验收断言)：N2-02–19中的适用功能、H01资源合同及N2-28继续核对；N2-01在CI行只证明实际runner/浏览器/制品，不冒充桌面终端验收。N2-05的H01拒绝及用途边界照测，真实业务消费者的双用途生命周期仍按其原证据或后续消费者行登记。N2-24–27的真实H02–H05仍待消费者指定。

范围调整：N2-20旁白和N2-21缩放/重排测试移出当前待办；历史证据不删除。实体移动端、额外浏览器、其他输入法、对比度/像素比较、独立视觉签认不作为本批功能门槛。保留正常桌面视口下的键盘操作、弹层取消/提交、busy保护和关闭后回焦等功能可操作性检查，不开展缩放或150px短视口专项。原生中文IME的9组历史记录保持，本批不派发合成composition来冒充系统输入法。

D02–D07按环境行理解：此前Mac/Linux子批已采用的选择继续有效；本文件给出CI行的明确推荐，属于待实施方案。真实消费者、生产支持范围与正式签收未决项继续单列，不把六项全部重新标成“尚未选择”，也不宣称整体N2已完成。

## 2 推荐的唯一首批组合

首批只增加一个独立job和一个环境行`CI-FUNC-ARM64-01`，串行执行各套，暂不分片、矩阵扩张、定时运行、缓存共享或使用self-hosted runner。

该CI环境只用于H01，不向纯Core/无Web消费者增加Node、浏览器或PG必选依赖；H03按其实际接入合同和适配器另验。

| 层次 | 推荐选择与校验 |
| --- | --- |
| GitHub runner | 标准托管`ubuntu-24.04-arm`，job直接运行在VM上；不使用job container、Docker-in-Docker或QEMU。检查实际OS、`runner.arch`、`uname`及Docker daemon均为原生arm64 |
| Rust制品 | `linux/arm64` / `aarch64-unknown-linux-gnu`，Rust1.93.0，`--release --locked`，默认features；不启用development-private-network-http或新增business装配 |
| 镜像基础 | 沿用下表四个已记录官方digest，分别构建runtime/prepare并仅`--load`到本job；不得依赖Mac本地镜像tag或镜像ID在云端已经存在 |
| 宿主工具 | Node22.23.4、pnpm10.30.1；runner自带Python3，要求>=3.9并记录完整版本；不新增Python第三方包。记录Docker/Buildx/BuildKit实际版本和Ubuntu runner ImageVersion |
| 浏览器 | 工具专用依赖`playwright=1.64.1`，配套完整Chromium revision1248 / 156.0.8078.4，`channel: 'chromium'`、`headless: true`。安装完整浏览器而不装headless shell；不使用本机`_npx`缓存或alpha包 |
| 浏览器运行位置 | Ubuntu runner，访问本job Docker中的Linux app；实际浏览器OS、发行物/版本、二进制SHA256、channel及headless模式全部登记。这是独立CI功能工程证据，不继承Mac桌面Chrome结论 |
| 显示/输入 | 固定1440×1000 CSS px、100%基准；合成数据上的点击、键盘、刷新、两标签与请求回读。无Xvfb、无系统缩放/读屏或物理输入法任务 |
| PG | PostgreSQL18.6，专用数据卷挂`/var/lib/postgresql`，核对实际PGDATA；本地socket与TCP均SCRAM，PG不向宿主发布端口 |

截至2026-10-25，[GitHub官方runner表](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)列出公有和私有仓库的`ubuntu-24.04-arm`。这支持本方案的推荐，不证明当前账号的Actions策略、额度或实际runner已经就绪；获准实施时先核对可用性。不可用时记录准备阻塞，不静默切换amd64或Mac runner；若另选架构，建立独立行和制品校验。

Playwright1.64.1来自[官方稳定发布](https://github.com/microsoft/playwright/releases/tag/v1.64.1)，浏览器版本来自该tag的[browsers.json](https://raw.githubusercontent.com/microsoft/playwright/v1.64.1/packages/playwright-core/browsers.json)。[系统要求](https://playwright.dev/docs/intro#system-requirements)覆盖Ubuntu24.04 arm64；[浏览器文档](https://playwright.dev/docs/browsers)说明配套版本和`chromium`新headless模式。实施时核对安装后的实际版本和包完整性，不将这些推荐值填成已安装记录；升级另立变更评估，不自动跟随latest。

| 用途 | 冻结镜像输入 |
| --- | --- |
| Web构建 | `node@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d` |
| Rust构建 | `rust@sha256:d0a4aa3ca2e1088ac0c81690914a0d810f2eee188197034edf366ed010a2b382` |
| runtime/prepare基础 | `debian@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8` |
| PG | `postgres@sha256:bbf83594798e144bff365a9c191c5d779f181fb3135902064ab8ff11918020fc` |

digest及arm64子manifest的原记录见[镜像输入](design/n2/linux-docker-20261025/images/frozen.json)。后续预拉取并验证平台，再由现有构建入口使用digest；本轮不拉取。托管VM软件和Dockerfile中的apt仓库会变化，因此还要记录实际系统/动态库/包清单，不承诺仅凭镜像基础digest实现位级重现。

## 3 工作流、构建与最小工具适配

建议后续新增`.github/workflows/n2-functional.yml`，首阶段仅`workflow_dispatch`；首次真实通过并复审后，再另行决定接入`pull_request`。不改变现有CI的检查范围或分支保护，不设置push/tag发布、cron、部署environment或镜像推送。

首次手动触发还有仓库级前提：该workflow文件须先存在于远端默认分支，之后才能选择包含所审阅实现的分支/ref运行；仅在开发分支新增并推送文件仍不足以启用dispatch，见[GitHub手动运行说明](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)。推荐后续先完成工具/workflow实现与静态复审，再另行取得推送、默认分支纳入及首次执行授权；不通过临时push触发器绕过此前提。本轮本地文档提交不授予这些远端动作。

- 使用`contents: read`，checkout不持久化凭据，不取仓库/组织/生产Secret。新增Actions须固定经核对的完整commit SHA，沿现有checkout/setup-node固定版本策略；具体新增action SHA在实施时核对，不将浮动tag当冻结输入。执行未受信代码不使用`pull_request_target`；见[GitHub安全说明](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)。
- 一个job、各套串行。初始`concurrency`按workflow/ref分组，`cancel-in-progress: false`，减少新运行打断旧清理；手工取消和runner丢失仍须处理。首批不接fork PR、不增写权限或常驻执行器。
- 建议job总上限120分钟：预检5分钟、构建30分钟、八套各最多8分钟（含本套准备/执行/清理），另留15分钟作总清理、脱敏汇总与上传，共114分钟、余量6分钟。这些是待首跑校准的建议上限，不是已测CI耗时。各阶段均有有限等待，不让网络安装或Docker子命令无限挂住；总截止前停止启动新套，缺失项记未执行且本批失败。
- 远端执行的ref必须实际包含获审阅的产品基线和后续工具改动，记录真实checkout SHA与tree。不能把本地`cc04561`直接视为远端已可执行；本轮不查询或更新远端ref，也不dispatch。

构建顺序：冻结checkout/工具输入 → 检查本机Unix Docker endpoint及原生arm64 daemon、可用CPU/内存/磁盘 → 预拉取上述基础镜像 → 干净白名单上下文 → Web测试/构建/bundle → release app及bootstrap → 本地runtime/prepare → 实际ELF/链接/嵌入资源核对。复用[现有Dockerfile](../scripts/n2-linux/Dockerfile)和[构建器](../scripts/build_management_n2_linux.py)，不复制`.env`、`.local`、`.git`、旧dist/target、证据或无关文档；不从缓存凭空宣称测试已执行，构建步骤若命中缓存须记录复用来源或强制执行本次要求的测试层。

标准runner并不保证与本地构建资源相同。首批建议以`CARGO_BUILD_JOBS=2`限制构建并发，传入构建阶段并记录；跟踪浏览器、基础镜像、BuildKit中间层和证据的峰值空间，不能只用[既有镜像摘要](design/n2/linux-docker-20261025/review-closure/build-focus-fix/image-summary.json)中约123/126MB的最终runtime/prepare大小估算。预检或运行中资源不足时，记录准备阻塞或构建失败并有界收尾，不自动改架构、换更大付费runner或全局删除预装软件/缓存；实际耗时和峰值用于首跑后调整预算。

后续获准实施时，最小改动限定为以下工具面，本轮均不修改：

| 文件/责任 | 需要的适配 |
| --- | --- |
| `scripts/n2-ci/package.json`及其pnpm锁文件（拟新增） | 私有工具包，仅固定Playwright1.64.1及完整依赖；避免引入产品运行依赖。用frozen lock安装，再通过该包的本地CLI安装配套完整Chromium及系统依赖；不引入新的测试框架 |
| `build_management_n2_linux.py`与`n2-linux/Dockerfile` | 显式传入并登记CI构建并发限制，沿用同一默认features及release制品合同；构建子进程也有截止时间和进程收尾。未建立跨run缓存时仍核对本job内runtime/prepare两次构建的实际复用与测试执行日志 |
| `run_management_n2_linux.py` | 明确CI profile、Linux browser channel/headless及功能套件选择和源case映射；输出真实模式，不再固定Mac路径或强开`IDP_UI_N2_LAYOUT=1`。现有子命令1800秒超时不能直接沿用为CI时限：按套件总截止时间分配准备/执行/清理预算，并预留收尾时间。保留原Mac入口行为和历史证据 |
| `prepare_management_n2_linux.py`及Docker调用辅助模块 | CI允许经核对的本机Unix endpoint/context（一般为`default`），Python、Node及其子进程始终使用同一显式选择；不修改全局Docker设置或切换用户context。仍验证Linux arm64、镜像平台和所有权，不直接删除`desktop-linux`校验后接受任意远端Docker。保留私有状态原子写入、验证ID执行及依赖安全清理 |
| B/C/D/E/F检查器 | 提供显式`functional-only`选择，分离混合块；保留产品请求、拒绝、状态和恢复断言。源码应能核对本批不会调用CSS zoom、宽度循环、shortConfirmation、对比度或像素比较，不能仅把旧输出改名 |
| `check_management_n2_mac.mjs`与L05检查器 | 用显式CI browser配置替代固定Mac/headed路径，仍运行持久化profile、真实会话/refresh/退出；CI报告名称和平台不沿用Mac验收措辞 |
| `management_console_states/tenant/pagination/focus.mjs` | 优先复用已有功能模块；focus模块保留真实权限写入后的焦点恢复、防重放和身份不变。标签模块仅在必要功能选择器语义范围使用，不纳入独立无障碍/视觉评级 |
| workflow及离线工具检查 | 覆盖配置分支、选集完整性、缩放入口未调用、signal/timeout、准备失败、所有权不符、profile/目录清理失败、artifact白名单及非零失败状态；普通离线检查不依赖实库 |

八套选集必须先冻结语义case ID与源用例映射；CI选择校验同时检查“所有预期功能均执行”和“所有排除项均未执行”。原脚本19/27/42/47/26/98组是混合套历史计数，删去视觉段后不得照抄整套计数。N1未发现缩放段，可保留现有功能主干；其他套即使没有CSS zoom也有多宽度/视觉段，需要明确处理。

## 4 最小功能验收清单与执行顺序

以下全部为**计划，未在GitHub Actions执行**。不创建空的通过JSON。先CI-F01，再CI-F02–08；同一镜像在各套全新夹具上运行。

| ID / 套 | 必须保留的功能与独立判断 | 主要复用依据 |
| --- | --- | --- |
| CI-F01 运行门槛及重建 | 原生AArch64 app/bootstrap、动态库、非root/只读挂载、PG无发布端口及SCRAM；默认与非默认管理资源/唯一可信meta；缺schema/admin/client、坏key/权限、配置冲突和非法business明确拒绝且不补数据。重建同一app后origin、key、client、数据库、会话ID和截止时间保持，配置哨兵不被覆盖；两种管理登录独立退出，旧Cookie拒绝 | L01–L05；采样表计数/公开配置不扩大为全量写审计；SIGTERM143允许，强杀/OOM不记正常停止 |
| CI-F02 会话安全 | 四入口同一持久profile共存，精确Cookie/协调键及用途，单入口退出不串身份；伪造subject/平台目标拒绝；缺锁、存储读/写失败及静默丢失在登录前失败关闭；真实两标签refresh串行并回读session | 既有会话8组，注入能力/客户端时间与真实HTTP分别标记；不宣称企业策略/无痕/桌面Chrome均已验证 |
| CI-F03 导航与身份 | Enabled平台、Fixed非0、Choose、Disabled的登录、取消/切换、hash/刷新/前进后退、未知/越界入口；目标变化不替换身份；草稿/确认/写意图等待refresh时阻离页/重提；401清理、403及跨标签退出按合同处理 | B功能段；浏览器离开提示的合成事件与真实reload分列，不承诺强制unload提示 |
| CI-F04 客户端与N1 | lookup已存在/初次合法null/非法响应区分；普通与`.`/`..` ID在query/body正确寻址、集合PATCH、版本核对；public/confidential转换、PKCE和秘密隐藏；明确POST2xx才正向回读，saved回读失败仍保留成功，unknown/写后null不得误登记或重放，迟到响应被丢弃 | C功能段及独立N1套；两套各新数据；明文Secret/改密值不因状态回读被视为已核验 |
| CI-F05 租户与授权 | 租户/初始管理员准备、成员、权限目录、角色及业务/资源授权；平台、目标租户和business作用域精确；最后管理员/最后关系/内置保护规则真实拒绝；未知结果按实体恢复，无虚假整批回滚或自动补写 | D功能段；真实请求/拒绝、公开配置/版本及适用审计回读 |
| CI-F06 安全处置 | 全局账号改密/状态、自身会话失效、目标域设备/绑定/终态、会话撤销、诊断和审计；Busy/取消/未知结果、迟到响应和安全保护仍有效 | E功能段及其设备/会话模块；合成设备不证明实体持钥、扫码或生产撤销传播 |
| CI-F07 读取与恢复流程 | 真实cursor前后页及筛选重置；加载、空、无匹配、401/403/503分别处理；平台目录只读无写；租户创建响应丢失后分别回读租户/成员/admin，后续角色失败不回滚既有成功；权限真实写后回焦、回读失败/卸载不抢焦，单次写入及会话不变 | F的states/tenant/pagination/focus模块和必要主文件功能段；固定正常视口，无CSS zoom/断点/短屏/像素门槛 |
| CI-F08 工具与最终门槛 | 本批所有预期功能case均有结果，无未解释跳过/未执行；脚本错误为失败。公开证据完整、秘密扫描通过；profile、容器、卷、网络及私有目录清理可回读，任一清理失败使suite和job失败 | 既有16/5工具检查按适用复用，加CI特有故障注入；数字只在实际运行后报告 |

执行单元仍采用八套独立fixture：gates（含L05）、session、navigation、clients、authorization、security、N1、workflow-functional；CI-F04跨clients/N1，CI-F08贯穿各套。功能case可跨组覆盖同一不变量，不累计为唯一用例总数。

功能选集须显式保留N2-17–19在正常桌面视口的可操作性：导航及跳过链接、筛选Select、只读会话Drawer、客户端编辑和嵌套确认的Enter/方向键/Tab/Shift+Tab/Esc、取消优先、关闭回焦、busy时拒绝退出或重提，以及必要控件名称和错误关联。它们主要来自F主文件与B/C，不能仅运行F的四个辅助模块。原390px移动菜单、短屏和视觉断言不执行，也不把桌面侧栏结果代填为移动菜单通过。

构建/制品/运行门槛失败时，下游依赖组记阻塞/未执行，本批失败；其他独立套可在确认隔离条件后继续收集诊断。安全越权或凭据泄露类问题停止后续业务写入，仅取证和清理。默认不自动重试；修复后使用新的run attempt和新数据完整重跑受影响组，保留第一次失败，不把“重跑通过”抹成从未失败。

## 5 隔离数据、认证与网络

1. 每套重新创建专用bridge网络、Postgres及明确命名的数据/秘密卷、两个随机schema和四个app，沿现有夹具合同。初始账号/租户/client/权限均为合成数据，包含tenant-a、tenant-b、`.`、`..`及不同管理身份；不用现有`.env`、日常DB或真实用户。
2. N1会修改dot实体，B依赖初始seed，C/D/E/F各有后置写入，禁止串用前一套数据库。L05只在自己的gate夹具内保留PG卷、key和端口重建app；整套结束再删除。
3. `business_entries: []`始终成立；非法非空配置只作拒绝负例，不启动新业务入口。四登录策略是现有管理合同，不在N2实现M1-03–06。
4. 每次生成随机测试密码、PG密码及RSA3072 PKCS8 DER；通过标准输入/私有env文件/秘密文件引用传入。私有根0700、状态与秘密0600，runtime UID/GID10001，根文件系统和秘密挂载只读、`--init`、cap-drop ALL/no-new-privileges。
5. app仅发布runner的`127.0.0.1`随机端口，issuer/browser_origin与实际映射严格一致；PG不发布宿主端口。重建必须沿原origin，不得换端口后仍声称恢复原会话。loopback HTTP与隔离PG非TLS只证明本测试组合，不替生产HTTPS或数据库决策。
6. 资源名称保留现有正则兼容的随机nonce；标签另加GitHub run ID、attempt、job和源码SHA，并保留fixture目录/nonce所有权。执行和删除使用验证后的对象ID，不凭名称前缀扫描删除。
7. 推荐私有根位于本job `RUNNER_TEMP`下并设置一致的`TMPDIR`；Python和Node子进程共同继承，`idp-ui-b-*`仍是该临时根直系目录，满足现有load校验。公开输出另放独立的`n2-public/<run-id>/<attempt>/<suite>`，不把private目录作为其子目录。
8. 普通套使用新隔离browser contexts；session/L05使用本套新建的临时持久化user-data-dir，记录关闭/删除结果。它们是Linux headless Chromium配置，不借用用户profile、不冒充Mac普通桌面profile验收。冻结的Web/镜像可以共用，身份和数据库后置状态不能共用。

## 6 证据、归档与失败状态

公开artifact只从白名单目录上传，建议名为`n2-functional-<sha12>-<run-id>-<attempt>-arm64`。建议`retention-days: 30`，先核对组织/仓库实际允许值并记录到期时间；GitHub支持自定义artifact保留期，见[官方artifact说明](https://docs.github.com/en/actions/tutorials/store-and-share-data)。CI不得自动提交证据或上传镜像；正式接受的脱敏摘要/manifest/关键失败与截图应在到期前另获归档授权，artifact过期不等于永久证据已经保全。

| 公开材料 | 必须包含 |
| --- | --- |
| 输入与环境 | 实际SHA/tree及产品/工具lockfile、workflow、检查器和所有导入辅助模块的哈希；不能仅用旧文件名glob漏掉`management_console_*`模块。记录runner OS/arch/ImageVersion、Python/Node/pnpm/Rust/Docker/Buildx、浏览器版本/revision/channel/headless与二进制hash；索引/arm64子manifest及实际镜像ID |
| 制品 | Web与bundle真实测试日志，release构建状态，app/bootstrap ELF/sha256、动态库及运行包清单；实际served JS/CSS哈希和内嵌制品匹配。基础镜像有digest、本地构建无RepoDigest时明确记空，不虚构registry发布 |
| 功能覆盖 | 选择清单、源case映射、执行case ID/结果、明确排除/未执行及理由；请求方法/合成ID/状态、会话相等与期限、写次数和适用独立回读。真实事故与响应/能力/时间注入分别标记 |
| 失败 | 首次错误/阶段/非零退出、脱敏诊断、必要的失败截图，重跑run/attempt关系；截图仅用于解释功能失败，不做视觉验收或缩放检查 |
| 收尾 | 浏览器profile关闭/删除、逐对象owner/ID、停止退出/OOM、移除/不存在回读、私有目录去向、最后label查询与清理错误；最终成功/失败/取消/证据不完整的独立状态 |

禁止上传密码、token/Cookie值、数据库URI、私钥、原始env/inspect、DB dump、profile、storageState、原始HAR/trace/video和完整私密stdout。测试秘密生成后尽早登记日志mask，但artifact不能依赖终端mask代替脱敏：上传前按已知本套秘密及JWT/URI/私钥等模式检查文本，截图遮住输入/textarea及任何秘密显示区域。检查器直接写出的JSON/诊断也在扫描范围内；清理fixture前完成必要脱敏，无法安全处理的附件不上传，并将证据缺口记为本批失败。

证据目录先创建，逐case/阶段增量落盘。构建失败也应有最小输入/失败摘要，不能因为没有浏览器结果而上传空“通过”包。upload缺失或失败不能输出证据齐备的通过结论。机器构建日志保留原貌及hash，若含尾空白，与源码/文档格式检查分开，不为过空白检查改写原失败内容。

## 7 清理与取消要求

正常与失败路径均按以下顺序：尽力退出仍可操作的本批会话 → 关闭context/浏览器并处理profile → 停止/移除app及prepare容器 → PG → 所有权核对后的数据/秘密卷 → 无端点网络 → 确认可删除的profile/私有文件。逐对象记录，不运行全局prune、rm通配符或按全仓库标签删除其他run对象。

- app停止等待有限，退出143可作为SIGTERM结果；137/OOM或停止未确认不能计正常成功。任一DB使用容器未确认停止，则保留其依赖的PG/卷/秘密与私有恢复状态，继续处理其他独立对象。
- Docker不可达/inspect失败不等于不存在；需健康列表及owner/ID核对。目录删除失败仍写execution结果，suite与job均非零。profile关闭失败先保留profile及私有定位，不在浏览器可能存活时删除。
- 套件超时或收到SIGINT/SIGTERM时，停止启动新套并记录中断；先请求关闭本套浏览器，再对已登记且确认归本套所有的进程组及Chromium子进程有限等待、终止并回读，不能只结束Node父进程便开始删除profile或fixture。不能按进程名批量终止其他进程；无法确认退出时保留依赖和私有定位并记清理失败。中断不能像普通业务异常一样继续下一套。
- workflow还要有有界`if: always()`清理、脱敏汇总和上传步骤，不用`continue-on-error`或`|| true`掩盖验收退出码。
- `always()`不是runner失联、VM销毁、强制终止后的清理保证；GitHub有独立取消流程，见[取消参考](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-cancellation)。无法回读时记`cleanup_unknown`/证据不完整，不能记通过。首批仅使用托管临时VM，不留下外部DB、常驻runner或云资源需要事后猜测删除。
- runner仍存活时，私有恢复材料保留至清理确认并只在本job受限目录使用；不得上传含秘密的“恢复包”。runner销毁后该现场不再可恢复，仅能保留已脱敏诊断；不承诺失联场景的完整私有现场保全。
- 无秘密的本地验收镜像可保留到本job结束并登记；如主动删除，只删除本job创建且未被引用的精确ID。基础镜像或共享缓存不做全局清理；首批不配置跨run写入缓存。

## 8 后续实施、执行和完成门槛

1. **先实施工具适配与离线故障验证。** 冻结case选集、稳定Playwright锁文件和Action SHA；确认无缩放/旁白调用，同时保留功能断言。需另获实施授权，本轮不写这些文件。
2. **再准备首个CI环境。** 后续另获远端动作与执行授权后，核对workflow在默认分支的可触发性和获审阅ref，验证账号/runner/本机Docker、镜像输入、浏览器与网络依赖，实际版本不符即停止相应行。准备受阻不写成产品失败或跳过后通过。
3. **执行唯一首批组合。** build → gates/L05 → session → navigation → clients → authorization → security → N1 → workflow-functional；每套新夹具，按§4映射保留全部结果。
4. **失败先修复再复验。** 记录环境/工具/产品归属；产品或公开合同需新增能力时单独列依赖，不借CI功能补验启动M1-03–06。修复后更新源码/制品，完整重跑受影响套；失败和注入都保留。
5. **复审并限定签收。** 必验功能全执行、无未关闭安全/任务阻断问题、清理有回读、artifact完整且秘密扫描通过，才声明`CI-FUNC-ARM64-01`功能回归通过。只有明确选择的行可完成，不宣布Mac/Windows/真实消费者或生产通过；缩放、旁白及视觉签认不作为本批门槛。
6. **再决定自动触发与其余行。** 首次手动真实通过后，评估PR触发及维护责任；真实H02–H05消费者、实际生产CPU/浏览器明确后另批补验。H05尤其需要核对当前无完整草稿/未知状态公共回调时的宿主保守协调，不能在方案里假定新API已存在。

## 9 文档复审与本地归档范围

2026-10-25完整复审包含本文、README新增入口、R02拓扑及交付汇总新增说明，共四份文档。对照原N2断言、Linux实际报告和现有CI/构建/夹具/浏览器检查器，核对八套映射、默认features、空business装配、功能与视觉混合块、隔离数据及证据/清理边界。补齐默认分支dispatch前提、构建资源与并发控制，以及桌面键盘功能不能随视觉块一并删去的要求；同时将方案阶段的“不提交”改为本轮获授权的仅相关文档本地归档。

本轮只做源码/历史结果/官方资料核对、功能缺口分析和文档静态检查。归档前核对相对链接/锚点、冻结镜像引用、时间预算、空白和暂存文件范围；无关审查文档保持原样，不纳入提交。没有安装Playwright、生成锁文件、构建镜像、查询Docker运行态、运行产品或工具测试、调用GitHub workflow、推送或部署；没有新的CI环境或功能通过结论，M1-03–06未启动。
