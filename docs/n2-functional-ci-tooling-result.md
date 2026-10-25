# N2功能选集、CI驱动与workflow适配回传

后续状态（2026-10-25）：此前验收内容已按授权推送，main仅纳入并修正N2 workflow；[本轮同步报告](n2-ci-workflow-sync-result.md)记录验收分支同步、124项离线复验及新执行SHA冻结。下文122项结果及“尚未推送”等均为工具实施阶段的历史记录，原证据不改写；实际N2 CI补验仍未执行。

日期：2026-10-25。实施依据为已提交的[最小执行方案](management-console-n2-github-actions-functional-plan.md)，起点`52ee553a8c8d0481a25c68bee96b38205d19a276`。需求方随后授权工具实现及离线验证，仍禁止实际补验、产品改动、推送、部署及M1-03–06。

工具实施阶段状态：功能选集、驱动、依赖冻结和独立workflow完成全面复审、问题修复和最终整合复验；122项离线工具检查及静态检查通过。[证据目录](design/n2/ci-functional-tooling-20261025/README.md)保留最终结果、初次失败和修正说明。本轮仅相关工具、测试、文档和证据随本地签名提交归档，实际SHA以包含本文的Git记录为准；基线为上述方案提交。没有运行任何实际浏览器、Docker、PG、HTTP产品验收或GitHub Actions，不能宣布CI环境或264项功能断言已通过。无关`docs/m1-02-code-review.md`保持原样。

## 实现范围

| 范围 | 已实现内容 |
| --- | --- |
| 功能选集 | `scripts/n2-ci/functional-cases.json`冻结六套246项选中、13项排除；另以`runtime-cases.json`登记gates10项、session8项。共264项计划功能断言，逐项含语义ID、原名称和源码映射，不沿用旧混合套计数 |
| 明确排除 | 仅`IDP_UI_PROFILE=ci-functional`启用；固定1440×1000、full Chromium channel/headless，不调用CSS zoom、宽度循环、短屏、对比度、旁白或截图。F主文件桌面键盘、Select、弹层/嵌套确认和回焦，以及四个功能模块保留；传递的设备/会话模块也隔离视觉分支 |
| 覆盖结果 | 每套增量记录selected/executed/excluded/missing，未知、重复、遗漏和排除项执行均失败；驱动独立核对结果名称、源映射、排除项及完成状态，页面错误或context/browser关闭失败不能通过。gates/session中途失败也保留已完成项，余下套明确记未执行 |
| CI驱动 | 新入口`run_management_n2_ci.py`的prepare/run/finalize/verify四阶段；原Linux入口增加显式CI转接，默认Mac入口保留。核对本机Unix endpoint/default context、原生arm64、实际checkout SHA/tree、工具/完整浏览器版本与归属哈希、冻结镜像及实际构建版本日志 |
| 构建与夹具 | release/locked/default features及空business装配保持；通过构建参数把Cargo并发限制为2。每套仍独立PG/网络/卷、两schema和四app，run/attempt/job/source SHA加入原所有权标签；跨run加载与清理被拒绝 |
| 截止与进程 | 每套八分钟含45秒收尾；收到中断、超时或检查失败停止启动后续套。总体按job起点预留18分钟（有界清理、上传、最终门槛和余量），不是实测耗时。子进程独立session并跟踪已观察到的detached后代，按PID/startTicks核对后终止，拒绝PID复用；读取身份不确定时失败关闭，spawn后身份读取失败仍进入清理 |
| 失败和清理 | DB使用容器未停、profile残留、Docker不可达、对象仍在或目录删除失败均非零；保留依赖和私有恢复材料，不把inspect失败当不存在。最终按真实标签回读容器/网络/卷，秘密、profile、夹具和临时输出删除完成后才写成功摘要；无秘密job-state/start元数据留给最后verify |
| 证据发布 | 私有根与公开根独立且0700；驱动及workflow初始化均在写目录前验证run/attempt派生路径、固定私有路径和符号链接。只发布显式白名单、UTF-8解码和秘密扫描后的附件；已知测试秘密替换，JWT/私钥/URI/凭据字段拒绝。原始checker stdout/stderr只在私有夹具中，公开诊断限源码位置和状态；不上传profile、env、dump、HAR或截图 |
| workflow | `.github/workflows/n2-functional.yml`仅手动触发，单`ubuntu-24.04-arm` job、120分钟；contents:read、无持久checkout凭据、无发布/部署/cache/PR触发。使用经核对完整SHA的Node24 Actions runtime，shell仍Node22.23.4；既有`ci.yml`保持 |
| 依赖与artifact | 私有工具包只直接依赖Playwright1.64.1，完整pnpm锁已生成并离线frozen校验。`always()`收尾非零时，验证publication清单、完整文件集合和哈希后保留已脱敏失败证据，并保留原非零；清单缺失/不符或出现错误的通过摘要时才回退为常量失败包。最终门槛再次校验publication精确集合和哈希、八套execution/coverage/raw结果、准备附件及源码身份；缺证据、重封后结果不全、上传失败或缺artifact ID均失败。请求保留30天，实际expires_at保持未核对，不虚构到期时间 |

源断言映射表示断言组，不把组内多次采样或mock分支累加成唯一产品用例总数。CI准备中的Chromium `--version`、镜像预拉取和构建仅写入未来执行路径，本轮未调用。

## 离线验证与修正

以下都是工具离线验证，Docker、浏览器、PG及HTTP操作均为mock或只检查源码分支；不是新的H01功能运行证据。

| 检查 | 最终结果 |
| --- | --- |
| 既有Mac工具回归 | 5项通过，包含持久profile清理错误处理 |
| Linux夹具/构建工具回归 | 28项通过，包含Unix端点、原生架构、run所有权、构建参数、超时日志及清理失败 |
| CI驱动 | 36项通过；含完整mock准备成功及21类准备不匹配/超时，八套精确覆盖核对、秘密扫描、预算、profile保留、私有删除失败、workflow安全fallback和artifact门槛 |
| 进程收尾 | 21项mock检查通过；包含detached后代、PID复用、Z/X退出状态、无/proc库存、中断/超时及部分日志 |
| 功能选集/浏览器配置 | 32项离线检查通过；包含逐项映射、缺失/重复/未知/排除拒绝、视觉分支不进入和CI配置冲突拒绝 |
| 静态与依赖 | Python内存语法、Node语法、YAML结构与全部shell块`bash -n`、frozen/offline锁一致性、文档链接及源码/文档diff空白检查通过；原始修前复现日志有一处EOF空行，按证据保留要求原样归档。仅工具锁解析，没有安装依赖或浏览器 |

合计122项离线工具检查；subTest和各断言组内部子断言另含多分支，不扩大为产品通过计数。五组均在本次整合后重新运行，未复用旧通过日志；最终日志及对应完整工具输入哈希见[结果索引](design/n2/ci-functional-tooling-20261025/review-closure/final/offline-results.json)。

发现并处置的主要问题：

- 驱动预算不足分支未落最终summary，已补齐所有未开套及理由，再验通过；真实初败日志保留。
- 原型在私有目录删除前写成功摘要，已改为全部清理结果收集后判定；通过故障注入证明删除失败不能通过。
- 原型finalize只处理driver不存在，已补任意非零/导入异常的安全fallback；路径或symlink校验失败时不提供upload路径。随后复审发现一律清空public会丢失安全失败日志，已补publication逐文件校验，保留完整安全失败证据并维持非零；十类清单/文件/状态分支已离线复验。
- 所有权label前缀按实际fixture统一；发现profile无法确认退出时不删除其依赖。进程组之外的已观察到detached后代也纳入核对。
- dot/dot-dot语义ID冲突、设备残留窄屏几何断言和混合行取消/等待边界已修正；选集及源分支检查通过。
- 主集成第一次失败源于测试夹具根目录仍为0755，被新增0700守卫正确拒绝；修正mock并新增权限拒绝测试。第二次失败为新增阶段诊断字段后测试精确对象断言过时，调整后复验；两次完整日志保留，不宣称产品缺陷。
- 本机pnpm默认外置store登记受沙箱EPERM限制；改用本轮临时store离线校验，不改全局配置。本机Node24.19.0与工具包要求22.23.4的engine警告保留，不冒充目标Node已验证。

## 提交前完整复审

本轮复审修正及复验详见[复审闭环证据](design/n2/ci-functional-tooling-20261025/review-closure/README.md)。原105项实现阶段证据、失败记录和原始输入快照保留；最终122项结果优先。

- 修复N1在`finally`内误标通过，以及部分检查器吞掉关闭异常的问题。六套共用小型finalizer，逐context关闭并继续到browser；业务异常、清理失败及关闭期间晚到的pageErrors均写失败状态和异常类名，完整结果才标通过，不记录异常消息中的秘密。
- `/proc`读取权限或格式错误不再等同进程已退出；已跟踪PID无法读身份必须失败。根进程spawn后初次身份读取也已纳入清理边界。对应mock覆盖读取失败、已消失、僵尸、PID复用及清理继续执行。
- 拒绝仅有通过摘要的证据包：最终验证要求schema正确、文件集合精确、哈希一致、八套真实结果和准备附件完整，源码身份与当前工具哈希一致。准备镜像、四份运行时清单和served-assets附件均纳入缺失门槛；重封残缺包仍失败。
- 浏览器版本改为精确token匹配，拒绝`156.0.8078.40`冒充`156.0.8078.4`。驱动与workflow初始化在创建或更改目录前拒绝错误归属路径及符号链接；离线sentinel验证外部目标未被修改。
- PASS源映射核对具体字面串、模板固定文本或明确字面分支，并更新实际PASS行；错误名称映射被拒绝。动态模板的参数取值仍只由未来真实运行确认，静态映射和mock不证明UI流程通过。
- 输入清单从33份变更文件扩展为完整保守工具闭包，包含实际调用的未修改脚本、传递模块、Dockerfile ignore、依赖锁和冻结镜像输入；旧清单原样存入复审目录。附件清单和最终工具源码哈希全部复核。
- 无关`docs/m1-02-code-review.md`保持原blob；产品源码、既有workflow与历史实际补验证据未改。暂存范围经显式路径清单核对，只有本轮N2相关改动。

## 尚待授权的真实执行

1. 工具本轮仅本地签名提交归档，尚未推送；手动dispatch还要求workflow先纳入远端默认分支。远端操作和实际补验仍需后续授权，不在本轮执行。
2. 单原生arm64 runner的账号可用性、磁盘/内存峰值、构建/八套耗时及Linux headless行为尚未实际证明；截止值是上限，可能令剩余套未执行并失败，需要首跑后据实校准。
3. /proc跟踪只能证明已观察到的子树；极短瞬间脱离的后代不作无条件回收保证。profile残留、组仍存活或身份无法确认时保留依赖，记清理失败/未知；托管VM失联不宣称完整现场可恢复。
4. artifact实际ID/URL/digest由未来upload输出到step summary；有权限的首次审阅者还须核对实际expires_at并归档只读元数据，之后才正式签收证据保全。当前未增加actions权限或调用artifact API。
5. 真实H02–H05消费者、生产CPU/浏览器及正式签认继续单列；当前实现不增加产品公共协议或M1-03–06能力。缩放和旁白不再安排。
