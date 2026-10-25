# N2 CI工具提交前复审闭环

日期：2026-10-25。基线`52ee553a8c8d0481a25c68bee96b38205d19a276`；最终修订随包含本文的本地签名提交归档，不推送或部署。

本轮只审查和修正N2工具、离线mock、CI workflow、文档与证据。实际浏览器、Docker、PG、HTTP产品验收和GitHub Actions运行均为0；264项计划功能断言未实跑。缩放、旁白及M1-03–06不在执行范围。

## 复审与修正

1. `selection/`：旧N1在异常路径误标通过的源码顺序/mock重现、修复前检查及最终结果。六套使用共用finalizer，业务异常、关闭期间晚到的pageErrors或任何context/browser关闭失败均失败；原异常保留，结果仅记录异常类名。具体PASS名称和源行映射检查增强，模板的动态值不等于真实UI证明。
2. `processes/`：读取进程身份失败被误判退出的修前mock重现，修后进程与Linux工具49项结果（28 Linux＋21进程），语法检查。CI身份读取不确定时失败；根进程spawn后读取失败仍进入清理。只有可证明直接子进程归属时才能终止其新建进程组。
3. `driver/before-fix.txt`：旧verify接受只有通过摘要、没有publication或任何suite结果的mock重现。其余driver日志记录逐步整合；最终门槛要求精确附件集合/哈希、八套结果、排除项、清理和准备附件完整，绑定源码身份。路径校验先于mkdir，workflow初始化也拒绝symlink；外部sentinel保持。
4. `gate-review/`：独立只读聚焦复审及36项驱动mock结果。核对准备/结果输出路径、成功和失败收尾合同；结论不覆盖真实runner行为。
5. `original-input-snapshot/`：原实现阶段source-inputs（仅33份变更文件）及evidence-manifest原样保留。当前顶层source-inputs扩展为保守工具闭包，补齐未修改的实际入口、传递模块、Docker ignore、产品锁和冻结镜像输入；它与旧快照的范围和时间不同。

## 最终验证

[最终离线结果](final/offline-results.json)记录五组全部重新执行：5＋28＋36＋21＋32＝122项。subTest、多次循环、case内子断言不另扩成产品通过计数。`tested-tool-inputs.json`绑定该轮工具源码；静态结果另列语法、workflow shell/YAML、文档链接、锁解析、范围与哈希校验。本机Python3.9.6、Node24.19.0；22.23.4仅未来CI目标，pnpm的engine警告保留。

完整失败和中间日志均保留，没有将mock故障说成产品缺陷。原实现阶段105项结果仍在父目录`final/`，复审后结果以本目录`final/`为准。runner强制终止或失联、极短脱离且未被观察的后代、实际artifact有效到期时间仍须按报告边界处理，不作无条件清理或验收保证。

产品源码、既有CI workflow和历史实际补验证据不变；无关`docs/m1-02-code-review.md`的blob为`4ef4907646970f1cd06ec80cf51a9516497244d6`。本轮显式暂存与提交清单排除该文件。

暂存复核：114份相关文件逐文件校验哈希，排除无关修改。`git diff --cached --check`仅报告`selection/pre-fix-coverage-repro.log.txt`原始控制台日志末尾空行（第29行）；保留日志原字节。排除此机器日志后，全部源码、文档和其他证据的暂存空白检查通过，无产品源码或既有CI变更。
