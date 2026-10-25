# N2 workflow同步、离线复验与执行版本冻结

日期：2026-10-25。验收分支为`codex/management-console-ui-b`，本轮起点为`8fd9f46da55eaa6fa47b5247b9ddd7a71e1d9606`。需求方授权将已合入main的workflow修正同步到验收分支，完整复审、离线复验后，仅提交并推送相关改动并冻结新的执行SHA。实际N2补验未获本轮授权。

本轮已完成同步和离线复验：workflow与main的`4ce8adec3c5f501be75e31d0c0df779d76016713`逐字节一致；124项离线工具检查、actionlint语义检查及相关静态检查通过。[独立证据](design/n2/ci-workflow-sync-20261025/README.md)保留修前失败、整合失败及修后结果。没有运行实际浏览器、Docker、PG、HTTP产品验收或N2 job；264项功能断言组仍仅为计划选集，不能宣布CI功能验收通过。

## 来源与最小同步范围

前序授权A已将截至`8fd9f46`的18个提交推送到验收分支，且只把N2 workflow纳入main：

| main记录 | 结果 |
| --- | --- |
| [bootstrap PR #20](https://github.com/ooctoo/rust-embedded-idp/pull/20) | squash提交`cfca218045270ccd97747f65d577ea924f62ceaf`；未合并整个验收分支 |
| [修正 PR #21](https://github.com/ooctoo/rust-embedded-idp/pull/21) | squash提交`4ce8adec3c5f501be75e31d0c0df779d76016713`；修复不合法的job级`runner.temp`上下文 |
| main既有CI | [4ce8adec检查通过](https://github.com/ooctoo/rust-embedded-idp/actions/runs/40181095564)；这是既有CI结果，不是N2实际补验 |
| N2注册 | workflow ID `395805707`，路径`.github/workflows/n2-functional.yml`，状态active；同步前只读快照见证据 |

原workflow在job级env中引用`runner.temp`，GitHub拒绝解析；普通YAML和shell语法检查不能发现这一上下文问题。历史三条push失败记录保留，不能作N2功能执行证据；前序已核实它们没有job，本轮未发起dispatch。

本轮采用单文件精确同步，不merge或cherry-pick main历史。四个路径变量移到初始化step的env；初始化先验证run/attempt、目录归属、权限和符号链接，再通过`GITHUB_ENV`传给后续步骤。保持仅`workflow_dispatch`、单原生arm64 job、120分钟、`contents: read`、固定Action SHA及既有清理/证据门槛。既有`ci.yml`、产品源码、依赖版本和功能选集不变；未新增release/tag触发器。未来`release/x.y.z`发布触发偏好单独处理，本轮不创建tag。

同步后workflow Git blob为`a5c8b310c5742ca256faa57066f1042e00ae1676`，SHA256为`90f3937d257f9fbcbd46706eb0a60fa18bf7b2a697f4434833010316b9947ebf`。

## 复审与离线复验

新增两个永久离线回归：检查runner路径只在初始化step解析；执行提取出的初始化脚本，以合成目录验证四个路径的准确导出、保留既有环境行，以及错误路径/符号链接拒绝后不导出、不修改外部sentinel。外部驱动与夹具调用继续由mock守卫阻止。

| 检查 | 最终结果 |
| --- | --- |
| Mac工具 | 5项通过 |
| Linux工具 | 28项通过 |
| CI驱动（含两个新回归） | 38项通过 |
| 进程收尾 | 21项通过 |
| 功能选集 | 32项通过 |
| actionlint 1.7.12 | 通过；验证GitHub表达式上下文，未调用外部shellcheck/pyflakes |
| 静态检查 | 12份Python内存编译、20份Node语法、YAML结构、8段shell语法、2段内嵌Python编译、文档链接/锚点及相关diff检查通过 |
| 依赖锁 | frozen/offline、lockfile-only通过，未安装依赖或浏览器；本机Node24.19.0与目标22.23.4的engine警告原样保留 |

总计124项离线工具检查；子断言和subTest不累加成产品用例。新增两个回归在旧workflow上分别复现上下文错误和未导出环境；actionlint也复现原四处错误。第一次unittest调用因缺`PYTHONPATH=scripts`导入失败，纠正调用后才得到有效修前复现；随后首次整合复验发现新测试的变量名正则漏掉数字，修正为包含数字后38项通过。这两类测试调用/匹配问题与workflow缺陷分开记录，全部失败日志原样保留。

复审确认本轮只涉及workflow同步、离线回归和对应文档/证据，无新增产品行为、依赖、抽象层或执行矩阵。旧122项工具证据、Mac/Linux实际证据均保留，不改写为新CI结果；本轮工具输入及证据各有完整哈希清单。

## 提交、推送与冻结规则

本轮只提交并推送相关文件到当前验收分支；无关`docs/m1-02-code-review.md`保留且不暂存，其blob仍为`4ef4907646970f1cd06ec80cf51a9516497244d6`。不创建PR、不再合并main，也不合并整个验收分支。

**新的唯一执行SHA为包含本报告和本轮证据的签名提交的完整Git SHA**，最终交付消息记录该值。正文不嵌入自身SHA；可用`git log -1 --format=%H -- docs/n2-ci-workflow-sync-result.md`定位归档提交，结合该提交中的`source-inputs.json`核对工作树。推送使用明确完整SHA及单一验收分支ref、不推tag；随后只读复核远端ref等于该SHA。再次修改工具或workflow后须重新复审、离线复验并冻结新SHA，不能沿用本次身份。

未来首次实际补验仍需单独执行授权。执行前须确认远端验收ref仍指向冻结SHA、workflow注册有效、账号/runner前置条件未变；实际运行后据实核对runner、八套264项断言组、清理、artifact ID/digest/URL及实际expires_at。离线mock不证明runner分配、真实构建耗时、浏览器行为或证据上传保留成功。

不触发N2实际补验、不部署，不测试缩放和旁白，不启动M1-03–06；H02–H05真实消费者、生产CPU/浏览器及正式签认继续单列。
