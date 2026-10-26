# N1 修订2补验

2026-10-23。对应[实施报告修订2](../../../n1-implementation-result.md)及[N1设计修订2](../../../management-console-n1-id-compatibility-design.md)。本批只扩展N1专项及B会话校验就绪等待，没有改动产品代码。

| 检查 | 结果 | 记录 |
| --- | --- | --- |
| N1 | 26组、页面脚本错误0；原11＋新增15 | [结果](n1/n1-browser-results.json)、[执行](n1/execution.json) |
| UI-B | 19组、页面脚本错误0 | [结果](b/ui-b-results.json)、[执行](b/execution.json) |
| UI-C | 27组、页面脚本错误0 | [结果](c/ui-c-results.json)、[执行](c/execution.json) |
| UI-D | 42组、页面脚本错误0 | [结果](d/ui-d-results.json)、[执行](d/execution.json) |
| Web / bundle | 111项 / 3项通过 | [检查与环境](checks.json) |

新增15组分别是客户端saved/unknown/rejected持续null、404、503后关闭3组，两个dot-only租户三种状态离页6组，以及两个ID初读、PATCH、写后回读的迟到响应6组。每组包含多个断言，不与回归组数相加为唯一用例数。

初读、PATCH、写后回读使用真实HTTP200响应，再门控投递；另一标签核对同一管理session并真实退出后才释放响应，验证旧页不恢复且不重放。未知写入为真实写成功后明确abort注入，独立查询核对持久结果。beforeunload仅合成事件阻止标志，未证明原生提示策略；没有扩称所有身份替换、失效触发或浏览器环境。

N1/C/D使用一套新增的临时PostgreSQL18.6夹具，最终B另用全新夹具，避免N1修改的dot租户名称破坏B初始seed预期。两套均为loopback四宿主、随机schema；不读项目`.env`、不使用现存数据库。[N1/C/D夹具记录](fixture-n1-c-d.json)、[B夹具记录](fixture-b.json)、[源码与实际资源](source-manifest.json)、[清理](cleanup-checks.json)不含凭据或私有state。

本批B失败证据保留：[尝试1](b/attempts/attempt-1-execution.json)、[尝试2](b/attempts/attempt-2-execution.json)为真实session响应等待超时；[尝试3](b/attempts/attempt-3-execution.json)为按钮定位超时；[诊断4](b/attempts/attempt-4-diagnostic-execution.json)通过前4组后，因N1已经真实修改dot租户名称而不满足B初始名称断言。诊断只增加读取DOM状态，未改变产品；最终验收使用维护脚本及全新夹具，保留GET200与同一session_id要求。原始日志、诊断副本和失败截图留私有临时目录，不公开归档。

初次N1 11组、B/C/D/F、宿主52及失败记录仍在[原入口](../README.md)。[初次源码摘要](../attempts/source-manifest-revision1.json)保存原脚本版本；[当前摘要](../source-manifest.json)刷新两个验收脚本hash，产品/边界/制品摘要保持。Axum/workspace/宿主52、UI-F96及构建未在本批重跑；已有证据继续按原层级使用。

本批只是本机Chromium headless A1补验，执行时未提交、未推送；报告修订2及提交前核对完成后随本批本地提交归档，仍未推送。N0 D02–D07继续待决，N2–N5、M1-03–06未启动，试点和部署继续待定。
