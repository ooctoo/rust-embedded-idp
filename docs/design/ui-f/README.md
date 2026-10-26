# UI-F 本地运行证据

2026-10-23，基于UI-A修订2与已提交UI-E。首轮与修订2验收时未提交；本批随UI-F提交归档、未推送；范围、问题修正、UX01–19映射、复跑和限制见[实施验收报告](../../ui-f-implementation-result.md)。M1-03–06未启动，试点与部署待定。

当前修订2新增专项及完整复验：[UI-F96 / UI-D42 / 宿主50与清理](review-fixes/README.md)。下方82组及原构建/运行记录保留为首轮证据，当前源码摘要见修订2目录。

## 首轮完整记录（审查修正前）

- [UI-F 82组](results.json)：四策略真实挂载/会话、键盘/焦点、26页面五宽度、200% CSS zoom、8项实际对比度样本、租户创建未知结果和后续独立失败、4类列表真实游标、12列表逐页加载/空/503/403/401与平台权限只读。页面脚本错误0；键盘取消与危险预览分别直接断言零写请求。完整命令结果见[UI-F运行汇总](ui-f-run.json)。四张图片在完整业务运行后按最终源码的等待/裁取要求单独补验，见[无业务写入截图补验](screenshot-checks.json)，不冒称另一次82组全量。
- 原脚本完整复跑：[UI-B 19组](ui-b-results.json)、[UI-C 27组](ui-c-results.json)、[UI-D 42组](ui-d-results.json)、[UI-E 47组](ui-e-results.json)，均页面脚本错误0。不是复制旧阶段结果，见[各阶段命令汇总](browser-runs.json)。
- [Rust定向运行](rust-checks.json)：本轮参考宿主50项（含13项真实宿主）、设备6项、账号安全3项、会话3项均通过，failed=0、ignored=0；不把它们合计成独立于workspace的全量唯一用例数。
- [构建与常规检查](checks.json)：Web106、嵌入bundle3、Web/Rust构建、fmt/workspace check；常规workspace测试444通过、150显式ignored，ignored不算通过。真实宿主及上述12项Postgres另列，不代表其余live项目均已执行。
- [源码摘要](source-manifest.json)：本批产品与验收源码的SHA256，用于核对未提交工作区，不含私有状态或生成资源。
- [临时资源清理回查](cleanup-checks.json)：本轮全部自建夹具目录、容器标签、原配置进程，以及最后五组20个已记录宿主PID的最终检查。

## 运行图片

下列四张是最终编译资源和合成数据的实际Chromium截图，非UI-A静态画板；不含密码、token、Cookie值或密钥。

| 图片 | 实测内容 |
| --- | --- |
| [320px登录失败](assets/ui-f-login-320.png) | 连接失败后重连、登录失败保留邮箱和清空密码；唯一登录标题、局部错误 |
| [390px移动菜单](assets/ui-f-menu-390.png) | 命名导航抽屉、当前页、键盘焦点及减少动态 |
| [320px客户端确认](assets/ui-f-confirm-320.png) | 原完整配置、影响范围、无CAS、取消在前；不显示Secret |
| [1440px客户端页](assets/ui-f-clients-1440.png) | 原任务壳层、筛选、真实列表/游标、较清晰控件边界 |

两mode隔离随机schema，PostgreSQL18.6，四个loopback编译后参考宿主；无Vite开发服务器、无仓库`.env`或已有数据库访问。UI-F分页设备是临时SQL种子，正常操作/游标走真实API；空、403、401、503、迟延和丢响应按报告明确注入，不作为生产事故或实体设备证明。200%是CSS zoom；DOM阅读顺序不代表真实读屏或浏览器/OS缩放验收。

只保留上述白名单JSON和四张合成截图。失败尝试、部分运行记录、诊断副本、私有state/URI/凭证、宿主日志和失败截图不复制。源码与报告的最终核对见[报告§8](../../ui-f-implementation-result.md#8-复跑清理与最终核对)。
