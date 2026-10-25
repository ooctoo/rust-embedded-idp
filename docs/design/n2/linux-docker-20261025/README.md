# N2 Linux Docker 2026-10-25 执行证据

依据[最小方案](../../../management-console-n2-linux-docker-execution-plan.md)和后续实际执行授权，完整说明见[执行报告](../../../n2-linux-docker-execution-result.md)。所列单架构H01组合的适用补验已完成，最终逐套映射见`summary.json`；不扩大为整体N2或生产验收。

- `review-closure/`：完整复审的SQL所有权/清理落盘修正、SafeConfirm短屏产品修复、旧行为失败演示、Linux16项和Mac5项离线检查。`build-focus-fix`为新制品，`final`八阶段完整通过；另有独立F和当前驱动会话专项通过。最终复核及限定提交范围一并保留。
- `scope.json`、`environment.json`、`images/frozen.json`：起点、范围、实际环境和镜像输入。
- `build-attempt1/`、`build-tools.json`、`linux-artifacts.json`：干净上下文、Web/编译日志、构建工具、镜像ID及AArch64 ELF。
- `confirmed/`：首轮SCRAM配置下gates、N2和五套任务通过，console短屏几何采样失败。每个`execution.json`含结果及清理回读，均作为旧制品历史保留。
- `confirmed-tools/`：首轮F采样/恢复工具补强后F98组及会话8组通过；随后复审再次自然失败，最终新制品结论以`review-closure/final`为准，不覆盖先前结果。
- `summary.json`、`cleanup.json`、`source-manifest-final.json`、`evidence-manifest.json`：当前最终逐套映射、汇总清理、制品源码及公开证据哈希。
- 根目录`final-environment-readback.json`、`visual-review.json`、`static-review.json`保留初次收尾快照；复审后的回读、视觉及静态/最终复核分别为`review-closure/final-environment-readback.json`、`review-closure/visual-review.json`和`review-closure/final-review.json`。
- `gates-attempt1/`、`gates-attempt2/`、`gates-final/`：运行门槛、L05失败与补强重跑，历史记录不覆盖。
- `browser/`、`clients-diagnostic/`、`clients-diagnostic2/`、`browser-followup/`：首次浏览器批次及诊断/助手修正/过渡复验；保留失败截图、结果和工具manifest，不选择性删除失败。
- `mac-tools-offline.txt`、`linux-tools-offline-final.txt`、`tool-limitations.json`：工具异常分支、静态/工具边界。

旧阶段的PG容器内local socket默认trust，与最终两类连接均SCRAM分开登记；产品连接均为本批私有PG。六套off-the-record上下文、N2普通持久化profile和L05普通持久化profile分别取证；没有本轮原生IME/菜单缩放、读屏、Windows、真实消费者、CI或生产通过声明。

所有临时夹具和私有恢复材料的去向以逐次清理结果为准。脱敏文本不是原始凭据/inspect/HAR；不公开密码、连接URI、token、Cookie值、私钥、真实profile或原始私密日志。镜像/构建缓存允许保留，与运行夹具分开。本轮相关改动在完整复审后随本地提交归档，实际SHA以Git记录为准；未推送、未部署，M1-03–06未启动。
