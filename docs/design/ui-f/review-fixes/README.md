# UI-F 审查修正证据（修订2）

2026-10-23。基于UI-A修订2与UI-F首轮审查，仅修复权限写入成功回焦、补过滤参数/排除项与Select/textarea标签断言。完整范围、复用能力和未覆盖项见[报告§9](../../../ui-f-implementation-result.md#9-审查修正与复验修订2)。修订2审查及提交前核对完成，随本批UI-F提交归档、未推送；M1-03–06未启动，试点和部署待定。

- [UI-F96组](results.json)与[命令记录](ui-f-run.json)：包括两mode真实权限写入回焦12组、Select/textarea正反标签2组及加强的真实分页筛选。脚本错误0，键盘取消及危险预览零写请求；133次布局、8项对比度、28次标签范围检查（83条控件记录，含19条combobox与1条textarea，并非唯一控件数）。
- 原[UI-D42组](ui-d-results.json)与[命令](ui-d-run.json)：未改原脚本，双模式授权、管理员保护及未知结果/迟到响应回归。
- [参考宿主50项](host-run.json)：33单元、2CLI、2bootstrap、13真实宿主，全部通过且无ignored。
- [检查清单](checks.json)：本次Web106、嵌入3、Web/宿主构建、fmt、六个脚本语法及diff；首轮其他检查明确复用，未宣称重跑。
- [源码摘要](source-manifest.json)：最终9个产品文件、6个验收脚本及未改边界源码SHA256；无Rust或示例源码差异。
- [清理回查](cleanup-checks.json)：本次独立两夹具、8个已记录宿主PID，以及目录、容器标签、原配置进程均不存在。

四图来自本次完整96组执行的最终编译资源，已逐张核对，非静态画板或单独前缀运行：

| 登录320px | 菜单390px | 确认320px | 客户端1440px |
| --- | --- | --- | --- |
| [图片](assets/ui-f-login-320.png) | [图片](assets/ui-f-menu-390.png) | [图片](assets/ui-f-confirm-320.png) | [图片](assets/ui-f-clients-1440.png) |

仅使用两mode随机schema、合成账号、PostgreSQL18.6及四策略loopback编译后宿主。混合状态设备为临时SQL列表种子，不作为设备登记或证明验收。迟延/503/空/401/403明确注入；200%仍为CSS zoom。只归档上述白名单JSON和合成截图，不包含私有state、凭据、URI、token/Cookie值、密钥、宿主日志或失败图片。首轮82组与其他阶段证据在[上层目录](../README.md)保留，不能用于冒称新断言已在首轮运行。
