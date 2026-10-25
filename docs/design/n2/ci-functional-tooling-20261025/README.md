# N2 CI工具实现离线证据

日期：2026-10-25。对应[实现回传](../../../n2-functional-ci-tooling-result.md)。起点HEAD为`52ee553a8c8d0481a25c68bee96b38205d19a276`；本轮相关工具、测试、文档和证据完成复审后随本地签名提交归档，实际SHA以包含本文的Git记录为准；未推送。

本目录只含离线工具检查和静态证据，实际浏览器、Docker、PG、HTTP产品验收及GitHub Actions执行均为0。264项登记功能断言没有实跑通过结论，缩放和旁白未测试。

- [复审后最终结果](review-closure/final/offline-results.json)：Mac5、Linux28、CI驱动36、进程21、功能选集32，共122项通过；五组在整合后重新运行，源码输入完整绑定。[复审说明](review-closure/README.md)保留修复前mock重现及各轮日志。
- [最初实现阶段结果](final/offline-results.json)：Mac5、Linux28、CI驱动30、进程16、功能选集26，共105项通过。除驱动和进程最后定向复验外，其余组复用integration-attempt-2中已通过且相关源码未改变的日志，索引逐项说明。
- [静态检查](final/static-checks.json)、[锁文件校验](final/lockfile-validation.json)：仅锁解析，无依赖/浏览器安装。本机Node版本警告及外置store沙箱限制明确记录。
- `integration-attempt-1/`：主集成0700守卫拒绝旧mock夹具的真实失败及同批其他组结果。
- `integration-attempt-2/`：诊断stage字段导致测试对象断言过时的真实失败及同批其他组结果。
- `driver-budget-first-failure.txt`保留原型预算分支缺summary的真实初败；其他扩展验证、workflow mock路径调整及功能选集修正摘要保留原记录，不冒充产品/CI事故。
- `source-inputs.json`绑定复审后的完整工具输入闭包及本轮文档哈希；原33份变更文件快照保存在`review-closure/original-input-snapshot/`，最初清单与当前闭包不可混用。`evidence-manifest.json`绑定本目录附件（不包含自身）。

离线mock只使用不可连接实际系统的占位数据；没有真实认证材料、profile、.env或完整inspect。失败重跑记录保留，机器日志不为过空白检查改写。原始工具控制台中曾出现的环境路径属于本机测试路径，不是生产或共享系统证据。不得据此推断实际CI、生产、实体设备或真实嵌入消费者已验收。
