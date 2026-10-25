# N2 workflow同步离线证据

本目录对应[同步报告](../../../n2-ci-workflow-sync-result.md)，起点为验收分支`8fd9f46da55eaa6fa47b5247b9ddd7a71e1d9606`，workflow精确来源为main `4ce8adec3c5f501be75e31d0c0df779d76016713`。执行SHA取包含本目录的签名提交，远端核对结果及完整SHA见最终交付消息。没有实际N2 job、浏览器、Docker、PG或HTTP产品验收。

| 文件 | 含义 |
| --- | --- |
| `sync-inputs.json` | 基线、workflow来源、修前/修后身份及同步方式 |
| `remote-before.json` | 同步阶段只读核对的远端ref、注册和历史运行记录；不是实际补验 |
| `before-actionlint.txt` | 旧workflow四处不合法runner上下文的真实复现 |
| `before-driver-regression.txt` | 初次unittest调用的导入失败；不是有效回归结果 |
| `before-driver-regression-corrected-invocation.txt` | 纠正PYTHONPATH后，两项新测试在旧workflow上的有效失败 |
| `integration-first-failure.txt` | 首次整合38项中的测试正则漏数字失败；随后修正测试 |
| `*-offline.txt` | 五组最终离线结果，合计124项；lockfile文件仅做冻结锁解析 |
| `actionlint-final.txt` | 修后exit 0的原始空输出，语义检查配置见static-checks |
| `offline-results.json` / `static-checks.json` | 最终命令、结果、环境、语义/语法/锁及边界 |
| `source-inputs.json` | 最终完整工具输入闭包及本轮相关文档哈希，不含无关修改 |
| `evidence-manifest.json` | 本目录精确文件集合及SHA256（不含自身）；source-inputs只含本目录README，不含其他附件或清单，避免循环 |

日志保持原始字节。124项表示工具离线检查，不等于264项计划功能断言组已执行；实际选集、隔离运行、资源收尾、artifact保全都等待后续授权的真实运行。旧证据目录保留不动。
