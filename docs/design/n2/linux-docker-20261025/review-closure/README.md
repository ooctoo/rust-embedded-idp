# N2 Linux Docker 提交前完整复审

日期：2026-10-25。起点为`71fc6261a4b6362e3e0181c4414a874f33b4cfd1`及本轮未提交的Linux工具、测试、文档和证据。复审与本地提交由需求方明确授权；不推送、不部署，不启动M1-03–06。

## 发现与修正

1. SQL助手忽略所有权检查返回的“容器不存在”，仍可能按名称执行。修正为明确拒绝缺失，并只使用检查后的容器ID执行；离线测试断言拒绝时无Docker exec，正常时只用已验证ID。
2. 私有目录删除异常会穿透cleanup，导致runner无法保存execution.json。修正为捕获文件系统异常、登记清理错误并返回；离线测试真实调用runner finally，核对失败退出、结果落盘及私有状态保留；清理错误同时把suite的exitCode置1，不能只令总进程失败而在套件JSON中保留0。该最后的错误路径报告调整另有final-tools-check正常路径实际专项，且离线16项再次通过。部分删除失败只能保证记录失败，不能承诺已删除的私有文件可恢复；该阶段已确认容器/卷/网络清理完成。
3. 真实F复验重现SafeConfirm确认按钮持续裁切8px，见`actual/console/short-confirmation-failure.json/png`；3秒等待也未恢复。后续`focus-diagnostic`整套通过，说明有间歇性，不能归为纯采样问题。SafeConfirm追加局部原生焦点可见性处理，保留按钮回调和说明区；`build-focus-fix`重新构建，`final`在新制品上完整执行八阶段。F增加真实Tab及十轮短屏检查。`focus-probe-before`的显式滚动位置注入在旧制品上也能恢复，不作为旧版必失败证据。
4. R02拓扑与交付汇总的“未执行”段落时间语境不明确。补充方案归档时的历史限定及后续实际结果入口，不回写历史验收记录。

`regression-before.txt/json`在内存重建修复前两个方法、Docker完全mock时运行新增测试；预期的两项失败/异常证明测试能识别旧行为，不是伪造历史容器失败。`linux-tools-offline.txt`为修复后16项全部通过，`mac-tools-offline.txt`为既有5项全部通过，`rustfmt.txt`记录本轮静态格式复核。

## 实际复验与证据

`actual/`是工具修复阶段对旧制品的实际复验：全新SCRAM隔离夹具与Mac headed Chrome，重跑gates、N2普通profile专项、clients完整套和console完整套；其中F再次失败，不能用其余套通过抵消该失败。随后产品修复的新制品以`final/`八阶段完整复验为准；逐次结果/清理以各execution.json及结果文件为准。

`prior-*`保存复审前汇总及清单快照；其中的路径与哈希均相对于上一级证据根目录，描述当时快照。原执行结果、失败截图、工具manifest不覆盖。最终索引以根目录summary、cleanup及evidence-manifest为准。

新制品`final/`八阶段完整通过：L01–L05门槛、会话8组、navigation19、clients27、authorization42、security47、N1 26及F98；F有196项布局采样（含9次重复）、22次焦点、11次真实Tab及10次显式边界探针，pageErrors为空、键盘/危险预览写入为0。`focus-fix-check`另一次完整F98组通过，`final-tools-check`当前驱动会话8组通过。结果不累计为唯一用例数。

`final-review.json`记录主审与检查结论，`final-environment-readback.json`确认本轮标签下容器/网络/卷均为空。累计41套执行夹具及3组元数据夹具清理无错误，私有目录均移除；无秘密的旧/新验收镜像与共享缓存保留。新制品实际截图再次复核见`visual-review.json`；需求方签认和未覆盖环境仍单列。原始失败与各次工具manifest保持。

本轮只提交相关Web修复、工具、测试、文档和证据；无关`docs/m1-02-code-review.md`内容对象保持`4ef4907646970f1cd06ec80cf51a9516497244d6`。本地提交SHA以包含本记录的Git提交为准，不推送、不部署，不启动M1-03–06。
