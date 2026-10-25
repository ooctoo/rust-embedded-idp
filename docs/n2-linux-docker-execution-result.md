# N2 Linux Docker 子批执行与补验报告

日期：2026-10-25。执行依据为[最小执行方案](management-console-n2-linux-docker-execution-plan.md)和需求方随后明确的实际执行授权。本轮采用Linux arm64、Debian/glibc、release默认features、Mac Chrome组合；证据位于[独立目录](design/n2/linux-docker-20261025/README.md)。

当前状态：提交前完整复审及修正已完成，修复后Linux arm64 / Debian-glibc / release默认features镜像 + Mac Chrome + H01组合的八阶段完整复验全部通过，L01–L09适用项与清理回读齐备。历史失败保留，不扩大为整体N2或生产验收。本轮相关改动随本地提交归档，实际SHA以包含本文的Git记录为准；未推送、未部署，M1-03–06未启动。

## 范围与环境

- 产品/设计起点为当前分支`71fc6261a4b6362e3e0181c4414a874f33b4cfd1`，包含此前N2 Mac产品修复。Rust源码未改；本轮新增容器构建/夹具/验收工具、调整测试并整理证据；提交前复审另修复Web共享SafeConfirm的短屏焦点可见性，并重建Linux制品。
- Docker context为本机`desktop-linux`，Docker Desktop 4.94.0 / Engine 29.8.2，daemon为Linux arm64；实际制品为`aarch64-unknown-linux-gnu`的ELF64 AArch64。完整版本和制品哈希见[环境](design/n2/linux-docker-20261025/environment.json)、[构建工具](design/n2/linux-docker-20261025/build-tools.json)、[ELF制品](design/n2/linux-docker-20261025/review-closure/linux-artifacts.json)。
- 冻结官方Node 22-bookworm-slim、Rust 1.93.0-bookworm、Debian bookworm-slim和Postgres 18.6-bookworm的索引、arm64子manifest和镜像ID，见[镜像输入](design/n2/linux-docker-20261025/images/frozen.json)。实测构建Node为22.23.4、pnpm10.30.1、Rust1.93.0；宿主自动化Node24.19.0与构建环境分列。
- Mac为macOS26.6.2/25G83 arm64，安装Chrome155.0.8059.85，headed；普通七套中六套使用隔离off-the-record contexts，N2共存专项和L05使用新建普通持久化profile，全部仅含合成数据。
- 每套独立网络、PG/数据卷/秘密卷、两个随机schema及四个app；非root UID10001、只读根和秘密挂载、`--init`、cap-drop/no-new-privileges。app仅向Mac loopback发布随机端口，PG无宿主发布端口。新配置始终`business_entries: []`，非法非空配置只作拒绝负例。
- 最终整批明确使用本地socket及TCP均为SCRAM密码认证；早期过渡夹具使用官方默认local trust，应用TCP已使用密码认证。这一准备差异保留在历史诊断中，不把早期结果冒充最终认证组合。

这是H01参考宿主的Linux运行工程证据。参考app不是生产宿主，loopback HTTP与测试DB非TLS不证明生产HTTPS、证书或生产DB；不扩展生产架构/浏览器支持、真实H02–H05消费者、GitHub Actions、旁白、实体设备或A3验收。Mac历史原生IME/菜单缩放记录没有在本轮重新执行，F中的CSS zoom和视口采样也不能替代原生操作。

## 构建、工具与实际发现

构建从经白名单筛选的干净临时上下文开始，未复制项目`.env`、`.local`、旧dist/target、依赖目录、证据原件或无关文档修改。Web单测及构建先于Linux Rust编译，management和scan-code资源同时嵌入。runtime仅包含app与运行依赖；prepare另带同次构建的bootstrap与临时准备工具，均只构建并加载到本地。

[构建记录](design/n2/linux-docker-20261025/build-attempt1/image-summary.json)与日志保留Web115项、bundle3项通过、两个release制品构建结果。已有大chunk提示、CA rehash提示，以及Dockerfile必传镜像ARG导致的默认FROM lint提示均保留；实际构建参数经digest校验，不使用空FROM或latest回退。

| 事项 | 发现、修正与证据边界 |
| --- | --- |
| 构建输入复核 | 运行构建前修正Docker全局ARG作用域及workspace示例源码输入；未据此声称实际编译失败或产品修复 |
| L05 Cookie查询 | 首轮助手以根URL筛选Cookie，遗漏认证Path限定Cookie；修正为读取测试profile Cookie集合后匹配准确名称/Path。原失败、后续会话/期限/独立退出/旧Cookie拒绝均留档 |
| 客户端正向保存与定位 | 原助手对所有保存先等待回读，遇到明确拒绝只表现为GET超时；改为正向任务必须先有2xx POST，再有精确GET。定位提交核对输入ID并等待精确lookup请求；负例只拦截目标lookup，增加无秘密的请求/表单诊断。首次未保存POST内容，不能补称具体拒绝原因或断言Linux产品缺陷；独立重跑曾确认同一类型转换POST200，最终结果按整套复验计 |
| F Cookie名称 | 原F断言固定`idp_ui_b`，与本批四个不同Cookie名不符；改读fixture的实际cookie_name，旧夹具保留原名兼容，Path/HttpOnly/SameSite断言不放宽 |
| 首轮F短屏焦点采样 | `confirmed/console`即时几何断言失败；增加最多3秒等待并记录矩形，随后`confirmed-tools`完整98组未复现。该阶段未据此改产品；后续复审再次自然失败，产品修复与新制品结果见下节，不把首轮通过当最终关闭 |
| 新工具离线测试记录 | 首轮14项通过；扩充测试时一次PG mock名称与状态不一致导致测试本身失败，修正mock后通过，原日志保留。复审后增至16项，另跑既有Mac工具5项，均通过 |
| 新工具所有权与恢复 | 写入卷之前立即核对owner/run标签，防止`volume create`返回已有异主卷；状态原子写入且权限受限，准备CLI退出码严格核对，重建移除旧ID后登记新ID；超时强杀/OOM不冒充正常停止，清理失败保留依赖资源和私有恢复状态 |
| 诊断助手语法错误 | 一次新增表单诊断的括号错误导致Node语法失败，已修正并静态校验；该次没有执行客户端业务任务，未删除记录 |
| 工具限制 | Playwright CLI wrapper因npm网络解析失败，未安装全局包；改用已存在的Playwright库和仓库脚本。Python缓存目录限制通过`-B`和AST检查避开，不更改系统权限 |

前述首轮工具调整不等于修复新的产品合同；后续SafeConfirm产品修复另列，不能继续沿用“产品源码未改”的阶段性结论。第一轮客户端拒绝没有完整请求证据，不能以猜测填写原因，也不能仅凭单次重跑宣称全部N2通过；以最终逐套完整结果及未覆盖说明为准。

## 提交前复审

[完整复审记录](design/n2/linux-docker-20261025/review-closure/README.md)补齐两处工具错误路径：SQL拒绝已不存在的容器，并按验证后的ID执行；私有目录删除异常转换为清理错误，runner仍记录执行结果。新增两项针对性回归，修复前行为在完全mock的复现实验中被拒绝，修复后Linux工具16项及既有Mac工具5项通过。R02/交付汇总也明确方案归档时的历史语境。

随后在真实F复验中再次观察到确认按钮y118–158、视口150，持续3秒仍裁切8px。保留该失败及后续一次未复现的完整通过记录，按间歇性问题处理，不再归因为瞬时采样。SafeConfirm的按钮onFocus在完整矩形越视口时调用原生scrollIntoView nearest，并保留调用者onFocus；说明区120px最低阅读高度、后果内容、取消优先和既有权限/确认流程保持。新制品重新执行Web115/bundle3及release编译，再完整运行八阶段；F增加真实Tab和十轮SafeConfirm短屏回归。显式8px滚动位置注入仅为边界探针，旧制品也可通过，不把它当作旧版必失败证据。最终结果按下表和汇总映射。

## 最终结果与清理

最终选择由[汇总JSON](design/n2/linux-docker-20261025/summary.json)明确映射至`review-closure/final/`：八阶段均在修复后同一产品制品上，以独立新夹具及SCRAM配置完整执行通过。另有`focus-fix-check`独立F98组和`final-tools-check`当前驱动会话8组通过。旧制品结果与`actual/console`失败不混入新制品通过声明，也不改写退出状态。组间与重复短屏采样有重叠，不累计为唯一用例数。

| 验收 | 最终结果 / 证据 |
| --- | --- |
| L01–L04 构建/运行门槛 | [运行结果](design/n2/linux-docker-20261025/review-closure/final/gates/runtime/results.json)：AArch64、4宿主非root/只读/隔离PG、5入口10个嵌入资源、7个启动拒绝负例通过；数据库核对为表计数和公开客户端配置，不声称全量写审计 |
| L05 容器重建 | [6组](design/n2/linux-docker-20261025/review-closure/final/gates/l05-restart-results.json)通过：同origin、同会话ID/截止时间、配置哨兵保持；独立退出204、旧Cookie401。SIGTERM退出143、无OOM，不声称优雅排空或零中断 |
| L06 普通profile会话安全 | [8组](design/n2/linux-docker-20261025/review-closure/final/n2_mac/results.json)通过：四入口共存、拒绝伪造、单入口退出、锁/存储失败关闭、两标签真实refresh串行；6个测试profile删除、cleanupErrors为空 |
| L07 既有任务/恢复 | [navigation19](design/n2/linux-docker-20261025/review-closure/final/navigation/ui-b-results.json)、[clients27](design/n2/linux-docker-20261025/review-closure/final/clients/ui-c-results.json)、[authorization42](design/n2/linux-docker-20261025/review-closure/final/authorization/ui-d-results.json)、[security47](design/n2/linux-docker-20261025/review-closure/final/security/ui-e-results.json)、[N1 26](design/n2/linux-docker-20261025/review-closure/final/n1/n1-browser-results.json)、[F98](design/n2/linux-docker-20261025/review-closure/final/console/results.json)均整套通过；pageErrors为空 |
| F布局与视觉 | 196项布局采样（原187项加9次SafeConfirm重复）、8项对比度、28项标签；22次按钮焦点、11次真实Tab及10个显式边界探针可见，键盘/危险预览写入均0。[新制品视觉复核](design/n2/linux-docker-20261025/review-closure/visual-review.json)再次抽查3张桌面/窄屏截图，无新增阻断问题；需求方签认待定 |
| L08 工具/静态回归 | [Linux工具16项](design/n2/linux-docker-20261025/review-closure/linux-tools-offline.txt)、[既有Mac工具5项](design/n2/linux-docker-20261025/review-closure/mac-tools-offline.txt)通过；Web115/bundle3在修复后Linux镜像构建中重新通过。Python AST、Node语法、Rustfmt及源码/文档diff空白检查通过；机器构建日志保留原有尾空白；未声称运行全量Rust workspace测试 |
| L09 清理 | [41套执行夹具及3组元数据夹具](design/n2/linux-docker-20261025/cleanup.json)清理无错误，私有目录移除；[最终Docker回读](design/n2/linux-docker-20261025/review-closure/final-environment-readback.json)本轮标签下容器/网络/卷均为空 |

修复后259项构建输入哈希匹配当前文件，与首轮相比只有`web/management/workflow.tsx`改变，Rust源码未改。新运行镜像ID为`sha256:52b7b51438b4c94f61be3794dbd8db8f115f0c2db365c5d026c289f5ab17a718`，实际app SHA256为`06758e33881d1ac1f015ff7b959869e85602c22f2a3a8b4f7a477ee14fe463e3`。[新构建](design/n2/linux-docker-20261025/review-closure/build-focus-fix/image-summary.json)、[ELF制品](design/n2/linux-docker-20261025/review-closure/linux-artifacts.json)和[最终源码清单](design/n2/linux-docker-20261025/source-manifest-final.json)对应本轮修复；原制品也保留。每次运行保留当次工具清单；最后的清理失败exitCode报告加固以离线故障注入及当前驱动真实专项验证，不追认成先前运行版本。

复现入口为`scripts/build_management_n2_linux.py --help`与`scripts/run_management_n2_linux.py --help`；镜像输入取`images/frozen.json`的digest，运行使用`review-closure/build-focus-fix/image-summary.json`中的runtime/prepare标签及冻结PG引用，传入本机已安装Playwright库路径，输出须用新的目录。先`--suites gates`，再`--suites n2_mac navigation clients authorization security n1 console`，浏览器使用已安装Mac Chrome headed。入口会创建并销毁独立合成数据夹具；不会推送镜像或部署。

## 保留边界

公开材料仅含合成数据、必要状态/路径/错误、源码/制品哈希和已脱敏的运行诊断。密码、token/Cookie值、数据库URI、私钥、完整inspect/env、原始HAR/trace及profile不归档；清理只处理本轮所有权匹配的对象，不做全局prune。基础镜像、本轮无秘密的验收镜像及本地构建缓存保留供复现，和临时运行夹具分别登记。

本轮没有执行生产迁移或重启共享服务，没有修改CI；按后续授权仅本轮Web局部修复、工具、测试、文档和证据随本地提交归档，未推送或部署；无关`docs/m1-02-code-review.md`修改保留。需求方最终视觉签认仍单列。
