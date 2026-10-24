# N2 Mac 提交前复审与收尾

日期：2026-10-24。用户授权完整复审代码、测试与证据，发现问题先修复再复验，仅提交本轮相关改动到当前`codex/management-console-ui-b`分支；不推送、不部署，不启动M1-03–06。原无关`docs/m1-02-code-review.md`单行修改保留。

复审修复和最终验证已完成，限定范围内未发现剩余确定性问题；本轮相关改动随本地提交归档。提交基线与文件快照独立登记，最终提交SHA以Git记录为准。

## 复审发现与处置

### N2-MAC-03：协调预检失败留下拒绝的刷新Promise

复审追踪两种client的完整Cookie续期路径发现：`refreshing`的清理原本在Web Lock操作回调内。若请求在锁队列中等待时协调存储变得不可读，`BrowserSessionCoordinator.run`在回调执行前拒绝，回调内的`finally`不会执行；存储恢复后仍复用已拒绝的Promise，无法正常续期。

管理端与业务端新增两项真实客户端回归：登录短期限合成会话→等待锁队列→拒绝存储读→确认零refresh HTTP→恢复存储→同一client再次续期应成功。修复前两项均失败，修复后两项通过。现在将清理放在等待整个`run`的外层`finally`，并比较Promise身份，防止旧轮次清理新轮次。不自动重放已发送的未知结果，不增加无锁降级、认证状态机、公开API或依赖；token/development路径保持。

[修复前失败](refresh-regression-before.txt)、[修复后通过](refresh-regression-after.txt)。完整Web从113项增加到115项，包含首轮两项存储回归和本次两项排队恢复回归。

### 验收与清理工具收尾

- 准备失败：逐个尝试停止所有已创建子进程，记录部分`state.json`以便恢复；进程未退出或Docker删除失败时保留容器/私有文件。仅在确认停止、Docker删除成功后删除私有目录。标准`--cleanup`可在Docker正常且确认容器不存在时清理已核对的本地夹具；Docker故障/现有容器所有权不能确认时保留现场。
- Chrome profile：每个profile独立尝试关闭和删除；关闭失败时保留该profile，继续其他清理，仍写`results.json`。记录实际删除数量及`cleanupErrors`；任何清理失败不能输出整套通过。
- 存储断言：四入口分别要求精确的管理协调键存在，再核对全部键属于该origin；空列表不再误判通过。
- 执行器：拒绝覆盖既有suite证据目录；诊断脱敏覆盖测试凭据、home/repo/tmp路径和内联data模块源码。

新增[离线工具测试](../../../../../scripts/test_management_n2_tools.py)5项，执行实际Python函数/异常处理块及JS最终清理块，使用假子进程/profile/Docker，不启动服务或删除真实profile。覆盖子进程超时仍处理后续进程、Docker删除失败/成功、容器不存在/daemon故障/所有权不明的恢复、脱敏及profile关闭/删除失败后继续取证。[测试日志](tool-failure-tests.txt)。

### 证据与简洁性复核

修正一处失败栈中的本机缓存路径，并对安全文本日志统一去除home/repo/tmp前缀及inline data源码；[脱敏登记](redactions.json)保留原始与公开哈希，失败类型、断言、行号及结果不变。未把原exit1改为exit0，未删除失败尝试。首轮与IME目录的源码/制品摘要是复审前快照，当前构建另立清单；不覆盖历史哈希。

原生IME的9组观察、20张截图、手动切换输入源和候选窗/DOM事件未捕获边界均复核；执行者视觉审阅保持。此次仅调整client的异常清理和工具，UI结构、输入处理、样式及两类确认区修复没有变化，沿用该原生记录；不声称重新执行系统IME/200%/400%全过程。另打开本次F截图复核正常/窄屏确认样本。

实际diff复核未引入额外包装层、通用框架、依赖、公开契约或数据模型变化。分工的只读审查结果由主代理核对源码并执行验证，不直接作为接受结论。

## 最终验证

| 检查 | 结果与证据 |
| --- | --- |
| Web | 115通过、0失败；[日志](web-tests.txt) |
| 嵌入bundle | 3通过、0失败；[日志](bundle-tests.txt) |
| 工具离线异常 | 5通过；[日志](tool-failure-tests.txt) |
| 构建 | Web先构建，再编译Rust参考宿主；均通过。既有大chunk提示保留；[Web](web-build.txt)、[宿主](rust-host-build.txt) |
| B/C/D/E | 当前桌面Chrome headed各19/27/42/47组、0页面脚本错误；`browser/`各独立夹具 |
| F扩展 | 98组，187次布局、8项对比度、28次标签检查，纯键盘/危险预览零写；[记录](browser/console/results.json) |
| N1 | 26组、0页面脚本错误；[记录](browser/n1/n1-browser-results.json) |
| N2专项 | 普通持久化profile 8组完整通过，精确协调键、四Cookie隔离、能力失败及双标签真实refresh并发1；6个profile删除；[最终工具复跑](confirmed-tools/n2_mac/results.json) |
| 静态 | Rust fmt、Node语法、Python AST、diff与JSON/链接/证据哈希核对；Rust源码未变，不冒称全workspace/live数据库测试 |
| 实际资源 | [四入口JS/CSS](served-assets.json)与本次重建磁盘制品一致 |

各套存在回归重叠，不累加为唯一用例总数。七套主批各新建独立PG与四宿主；N2专项在最终清理工具版本上另跑一次。[最终源码/制品快照](source-manifest.json)、[验证汇总](validation.json)、[清理记录](cleanup.json)在全部运行结束后冻结。

需求方最终视觉签认单列。Windows Chrome/Edge、真实外部嵌入消费者、其他输入法及生产/试点没有在本批取得通过结论；旁白按用户决定不测。
