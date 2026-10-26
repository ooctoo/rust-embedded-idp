# N2 GitHub Actions首次功能补验

> 附件清理（2026-10-26）：按后续授权移除旧N2大体积附件，验收结论保留为历史记录；附件请通过[Git历史检索](n2-evidence-archive.md)追溯。下文附件链接指向检索说明。

日期：2026-10-25。执行依据为[已提交的最小方案](management-console-n2-github-actions-functional-plan.md)和需求方本轮明确授权。首次从冻结SHA `c304310d146ae916cbd89bad6168b96d3052db53`手动执行；只覆盖`CI-FUNC-ARM64-01`和八套功能选集，不部署、不测缩放/旁白，不启动M1-03–06。H02–H05真实消费者和生产支持范围继续单列。

**限定范围补验通过，独立复核完成。** [独立证据目录（历史附件）](n2-evidence-archive.md)保留首次失败、修复、离线复验和后续真实复验，最终执行SHA为`14dd9199094464a1f7368e9c95f5c29e7a5354c7`，以下按实际终态登记。

## 执行与修复关系

| 运行 | checkout SHA | 当前结论 |
| --- | --- | --- |
| [首次运行 40183166070](https://github.com/ooctoo/rust-embedded-idp/actions/runs/40183166070)，attempt 1 | `c304310d146ae916cbd89bad6168b96d3052db53` | 环境准备失败；八套均未执行，不能记功能通过 |
| [修复后运行 40183858494](https://github.com/ooctoo/rust-embedded-idp/actions/runs/40183858494)，attempt 1 | `d7214815dd168c97532495b884fea8f4fedfac7d` | 构建和gates通过；会话套在双标签刷新等待竞态处失败，后六套未执行 |
| [再次复验 40185099189](https://github.com/ooctoo/rust-embedded-idp/actions/runs/40185099189)，attempt 1 | `de50eb9d02fe977ec60932c0e7072aba514c6f69` | gates、会话、导航、客户端通过；权限套完成25组后在创建权限“核对”按钮点击超时，后面三套未执行 |
| [诊断复验 40186939525](https://github.com/ooctoo/rust-embedded-idp/actions/runs/40186939525)，attempt 1 | `64425832dfb59f5469f530cbf42f030a21314a8a` | 相同位置失败；按钮可见、未禁用、未遮挡、位于视口内，累计85/264组完成 |
| [定位诊断 40188254095](https://github.com/ooctoo/rust-embedded-idp/actions/runs/40188254095)，attempt 1 | `da88ba78eef94c77207a8b82fded8a7455927ae9` | 相同位置失败；弹窗匹配1、精确按钮匹配0，非loading按钮仍含loading图标，点击尚未发生；累计85/264组完成 |
| [产品修复后复验 40189371589](https://github.com/ooctoo/rust-embedded-idp/actions/runs/40189371589)，attempt 1 | `4afc9724ba757a22e8cbf4558c7c66a8666e7e96` | 前七套完整通过，console已记录91组，但最终落盘因变量作用域错误失败；264组选中断言均有记录，整批仍失败 |
| [收尾修复后复验 40191248439](https://github.com/ooctoo/rust-embedded-idp/actions/runs/40191248439)，attempt 1 | `14dd9199094464a1f7368e9c95f5c29e7a5354c7` | 成功；全新数据重新执行八套264组，缺失0，清理和artifact独立核对通过 |

首次run已实际分配`ubuntu-24.04-arm`，日志记录Ubuntu24.04.5、runner2.338.0、runner image20261012.149.1，实际token只有Contents/Metadata read。Node/pnpm选择、124项离线检查及完整Chromium安装成功；prepare在`owned-full-chromium`阶段以`CalledProcessError`失败，构建和功能套未启动。对应失败摘要明确`actualExecution: false`、`evidenceComplete: false`。

根因由源码定位及真实Node的合成pnpm非提升布局复现确认：CI工具只直接依赖`playwright`，从工具包根目录解析间接依赖`playwright-core/package.json`得到`MODULE_NOT_FOUND`。修复为从已安装的`playwright/package.json`建立`createRequire`，解析该包自己的依赖；未新增依赖、变更版本、workflow或产品行为。永久回归执行prepare所用的真实元数据脚本，先证明根目录不能解析core，再验证正确包内解析和版本/浏览器信息。

修复后五组离线检查为5＋28＋39＋21＋32＝125项，全部通过；Python语法及相关源码空白检查通过。首次真实失败和修前Node复现均保留。机器日志14处行尾空白按原始字节保留，与源码格式检查分列。仅该驱动修复、回归和对应证据签名提交并推送至验收分支，修复提交为`d7214815dd168c97532495b884fea8f4fedfac7d`；原冻结SHA的失败结论不改写。

第二次真实运行完成gates的10组断言和会话套前7组；双标签刷新在仅观察到1次响应时提前断言应为2次。源码以“页面没有spinner”判断完成，存在异步请求尚未结束的窗口；延迟响应离线回归在旧逻辑上复现提前断言。修复为先确认按钮可操作，在点击前注册各标签真实GET列表响应等待，两个200响应完成后再执行原有“两次刷新、最大并发1、两次200、session不变”断言。仅同步PASS源行号，八套264项不变；修后126项离线检查全部通过。修复签名提交`de50eb9d02fe977ec60932c0e7072aba514c6f69`已推送验收分支。

证据复核发现通用`.log`忽略规则会漏收公开构建日志，已对publication封存且秘密扫描通过的9份公开日志显式纳入提交；前次完整artifact文件均已与Git对象逐项核对，没有私有日志混入。

第三次实际运行证实双标签刷新修复有效：两次刷新、最大并发1、authoritative session不变全部通过。前四套累计完成60组，权限套再完成25组后发生按钮点击超时，合计85/264组完成。页错误和清理错误均为空，不能仅凭`TimeoutError`确认按钮被禁用、遮挡或超出视口。为保留定位依据，诊断提交只输出固定布尔原因、白名单按钮名、几何位置及中心命中关系；不输出原始异常消息、表单值或任意DOM文本。真实映射代码的两项离线隐私检查以及33项功能工具、39项CI驱动检查通过。该提交`64425832dfb59f5469f530cbf42f030a21314a8a`经本地签名核对后推送，继续同一八套功能完整复验。

第四次几何诊断排除禁用、遮挡和视口位置后，第五次增加的安全角色匹配诊断确认：`创建权限`弹窗匹配1，`核对`按钮匹配0，按钮没有`aria-hidden`/`inert`祖先、loading class为false，但仍含loading图标；Playwright尚在等待定位器，未执行点击。没有以绕过角色、force click、加大超时或删断言解决。

根因由本机真实`PermissionDirectory`组件与合成client的“未知写入—原范围回读—结束核对—重新创建”探针交叉确认：初次3/3复现；补充名称检查的另3次中2次出现`loading`参与按钮可访问名称，精确`核对`匹配失败。单独AntD基础弹窗的6种时序未复现，也保留为阴性结果；它不能否定真实组件和CI中的复现。本机探针使用Chrome155，未连接Rust或数据库，不充作Linux CI通过。

产品修复仅给权限编辑器主按钮增加与可见文案一致的`aria-label: 核对`，不改变权限、busy/未知写入保护、原对象回读或提交逻辑。相同真实组件流程修后3/3精确名称匹配通过，即使折叠图标仍在DOM。现有权限功能用例将继续实际点击、真实POST与写后读取；不以探针替代最终整套复验。另将关闭页面时的诊断计数失败转为null，避免覆盖原始异常。115项Web测试、四类Web构建、33项功能工具、39项CI驱动及3项隐私/关闭页面离线检查通过。修复签名提交为`4afc9724ba757a22e8cbf4558c7c66a8666e7e96`，后续须在该SHA上重新构建并完整执行八套。

随后本机相同真实组件流程额外3次实际点击重新创建后的“核对”和嵌套“确认”均通过。第六次真实CI也完整通过权限41组、安全46组及N1 26组，确认产品修复在目标组合有效。但console的91组PASS后，最终结果对象在`finally`读取`try`内部的`const t/fixed`，触发`ReferenceError`，没有生成`console/results.json`，也可能覆盖原始异常；不能以264组计数代替整批成功或补造结果文件。

工具修复将两个目标引用提升到`try/finally`共有作用域，目标尚未创建时计数为0，已创建目标仍读取实际writes数组。新增永久离线回归执行真实声明、目标建立语句和catch/finally源码：修前复现同一`ReferenceError`；修后同时验证正常完成、启动失败、部分目标建立失败的原始错误身份、非零计数保留、结果落盘及context/browser关闭。五组离线工具检查增至5＋28＋39＋21＋34＝127项，全部通过；选集、PASS源行号、断言、超时及workflow未变，产品源码没有再次修改。修复签名提交为`14dd9199094464a1f7368e9c95f5c29e7a5354c7`，已以该新SHA和全新数据重跑全部八套，最终通过。

执行控制曾发生GitHub TLS握手超时；每次均先连续核对未出现相应run，才重发一次请求，没有盲目重复dispatch。传输失败与实际job失败分别保存。没有变更Actions策略、token权限、分支保护或main。

## 实际环境与功能结果

最终第七次运行八套全部通过，264组选中断言、0缺失、13组按计划排除。127项离线工具检查与实际264组功能断言分别核对；后者不是离线mock。

最终实际环境为Linux aarch64/ARM64（runner image `20261023.149.3`）、Node22.23.4、pnpm10.30.1、Python3.12.3，工具Playwright1.64.1、完整Chromium revision1248/156.0.8078.4、headless、1440×1000。原生arm64 Docker构建Debian12/bookworm、glibc2.36、release默认features制品；gates核对UID10001、只读运行、PG无宿主发布端口及SCRAM。259份构建输入与43份工具输入均与实际checkout `14dd919`逐项哈希核对一致；使用该SHA的验证器复核，不引用并行工作区改动。宿主glibc2.39与产品容器glibc2.36分别登记；这些事实不代签生产支持。

| 执行套 | 结果 |
| --- | --- |
| gates（含L05） | 最终10组通过；清理确认 |
| n2_mac（CI会话8组，名称沿用脚本；不是Mac运行） | 最终8组通过；清理确认 |
| navigation | 最终18组通过；清理确认 |
| clients | 最终24组通过；清理确认 |
| authorization | 最终41组通过；清理确认 |
| security | 最终46组通过；清理确认 |
| n1 | 最终26组通过；清理确认 |
| console（正常桌面功能） | 最终91组通过，results.json完整落盘；页错误/清理错误为空，键盘及危险预览写计数均为0 |

## 清理与artifact保全

首次失败artifact `12594633237`已下载，下载ZIP的SHA256与GitHub digest一致：`7a54f31f161c5819d95cc8a5f54002723ee783bfe658fd4ac5579425f3c58320`。完整公开附件、publication精确文件集合/哈希和秘密模式扫描通过；日志及全部解压附件已归档。API实际`expires_at`为`2026-11-24T10:03:45Z`，不是按30天请求推算的日期。摘要报告清理confirmed、errors为空；该次尚未创建功能fixture，只能证明失败准备阶段收尾，不能代替八套清理。

第二次失败artifact `12595486707`也完成下载ZIP digest、publication精确文件集合/哈希及秘密扫描核对；SHA256为`2520d81c8474a00b795bd2384b28a5749941777847e387c23fdfb006b770815a`，实际`expires_at`为`2026-11-24T10:21:04Z`。已启动的两套fixture均清理完成、私有目录删除、错误为空，6个浏览器profile删除成功，最终所有权回读通过；后六套未创建数据。完整批次仍失败。

第三次失败artifact `12595952792`完成相同的ZIP digest、publication及秘密扫描核对；SHA256为`79c522e41599168844b61e9b898a2a91fef271b33777ea8b30bb8b7161701278`，实际`expires_at`为`2026-11-24T10:42:32Z`。已启动的五套fixture清理完成、私有目录删除、错误为空，6个浏览器profile删除成功，最终所有权回读通过；后面三套未创建数据。259份构建输入和43份工具输入均与该run实际SHA逐项核对一致。

第四次失败artifact `12596735850`的SHA256为`3d5629fb63ca4bab800b9a224123cec9ce0b7113b9b7e5c853cdac7ea3321789`，实际到期`2026-11-24T11:09:26Z`。第五次失败artifact `12597168351`的SHA256为`83d6e84773eda945e2c078bf6cc17d68c3bcf5a4f13f62e3f1d71fa3ff1582e3`，实际到期`2026-11-24T11:29:06Z`。两次均完成ZIP digest、publication、秘密扫描及259份构建/43份工具输入与实际SHA核对；五套已启动fixture、私有目录和6个浏览器profile清理确认，最终所有权回读无错误。

第六次失败artifact `12596699761`的SHA256为`f62e55fa566cff559baeb35e741d1750a9497388810fe3651b628d86484682db`，实际到期`2026-11-24T11:51:40Z`。ZIP digest、publication、秘密扫描及259份构建/43份工具输入与实际SHA核对通过；八套fixture及私有目录、6个持久化浏览器profile清理确认，最终所有权回读无错误。console最终结果缺失仍阻止签收。

最终成功artifact `12598502265`的SHA256为`279bb5b5ae7f3e559f0b0b98810512cd38a5bc109a00524782b48ffc734e3ef4`，API实际到期`2026-11-24T12:19:13Z`。八套fixture及私有目录、6个持久化浏览器profile清理确认，最终所有权回读无错误。全部七次原始公开artifact ZIP及完整解压文件已归档，逐一验证ZIP哈希、精确文件集合和publication哈希；最终八套的覆盖、结果落盘和清理由冻结SHA验证器及独立核对共同确认。artifact中的待审阅expiry字段保持原样，外部核对单独写入`artifact-verification.json`，不篡改已封存附件。

本轮保留无关文档及执行中出现的A01/A02等Rust和接口工作；实际CI从冻结Git提交构建，不含这些工作区改动。六个修复/诊断提交已签名推送验收分支；远端只读回读确认验收分支为`14dd9199094464a1f7368e9c95f5c29e7a5354c7`，main仍为`4ce8adec3c5f501be75e31d0c0df779d76016713`，没有活动N2运行。收尾报告和最终证据随本轮相关本地提交归档，实际归档SHA见Git记录；未新增推送。归档提交不是新的被测SHA，后续其他任务代码不套用本次通过结论。限定通过只覆盖H01及本CI组合，不代表整体N2、生产或真实消费者通过。


## CI耗时梳理（范围澄清前的分析记录）

最终成功job历时18分34秒：镜像准备/构建4分58秒，八套功能（含各套准备与清理）12分43秒，工具与Chromium安装36秒，离线工具检查3秒，上传约1秒。此前完整但收尾失败的job为18分04秒，分布一致。普通CI最近五个成功样本的workflow总历时约3.5–5.5分钟；这些样本来自此前main/PR提交，包含调度与收尾，不作为未来代码的性能承诺。详见[计时记录（历史附件）](n2-evidence-archive.md)。

普通CI与N2是两条独立workflow，N2当前只有手动触发。镜像每批只构建一次供八套使用；各套独立新建数据是隔离要求。当前没有跨运行构建缓存。建议先评估依赖与Docker层缓存，保持来源SHA/镜像输入核对且不缓存fixture、秘密或浏览器profile；再形成按变更影响选择功能套的规则，安全/会话/核心/驱动跨面变更及发布前仍跑全量；最后才评估分为独立job并行的收益与镜像传输成本。

Web构建与no-tenant-host消费者构建、Rust all-targets检查与默认/开发HTTP feature/release专项分别有不同覆盖面，尚不能认定为可直接删除的重复。不优先删除只占数秒的离线检查、清理或证据门槛。未来可按需求方偏好用`release/x.y.z` tag作为发布验收入口，具体与普通CI现有`v*`触发策略一并设计。本次没有修改workflow、测试选集、触发器或缓存配置。


开源范围澄清后的当前建议见[CI边界复审与提速最小方案](ci-speed-minimal-implementation-plan.md)：前述为一次专项后的初步提速分析，不再建议把H01八套、固定64组保底或复杂自动选套设为所有PR/版本默认门槛。上游模块、适配器、UI契约和参考应用仍须正确；生产单体配置、宿主集成、镜像与部署验收由下游仓库负责。N2保留手动专项，release/x.y.z只作未来上游版本质量检查入口，Docker专项缓存降为低优先级。本轮没有实施这些调整；相关材料本地归档后CI/CD暂停。
