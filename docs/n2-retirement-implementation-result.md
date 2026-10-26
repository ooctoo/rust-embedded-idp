# N2必要断言迁移与旧编排退役

> 后续附件清理（2026-10-26）：旧N2大体积附件已按用户授权移除，原材料通过[Git历史](n2-evidence-archive.md)追溯。本文保留退役实施时的结果；共享工具和未提交产品工作仍有用途。

日期：2026-10-26。依据[N2退役范围与覆盖映射](n2-retirement-plan-and-mapping.md)。本轮授权实现、本地复验、范围内本地提交；不推送、不触发远端Actions、不部署，不测试缩放和旁白，不启动M1-03–06。

## 变更

- 旧N2 workflow、CI/Mac/Linux调度、Docker构建/准备器、八套检查器及专属模块/manifest/测试退出。删除前本地源备份位于`/private/tmp/idp-n2-retirement-sources`；已提交版本可由`a3fcd72`追溯，历史报告与附件保持原样。
- 普通CI保留check、integration、e2e三层；必要浏览器合同放进原六组，不新增workflow、组别、动态选套、平台矩阵或测试依赖。
- E01保留认证恢复/退出，并补真实浏览器协调存储失败时拒绝发起登录、保留邮箱和清密码。E02补Choose取消/完成、旧target迟到响应、草稿离开取消和pending写入不改目标。
- E03的客户端代表写入改为机密客户端，确认框/URL/storage无明文、取消与提交后清密钥；分页只以真实投影注入两个游标页验证共享UI翻页/重置，不大批造数。授权仅建立最低前置数据，UI一次实例授权与独立回读。
- E04保留取消不写/确认一次及独立会话不受影响，用键盘执行取消。E05补已确认写入后GET失败、未知写入后null/404禁止误登记、授权原scope恢复、创建租户后的局部成功。E06保留真实两标签刷新与跨入口隔离，补退出后迟到响应不能恢复工作区。
- `checked`直接记录实际子断言结果，runner拒绝空组、未完成/失败、重复ID或错组结果，不新增全量case清单协议。仅发布常量阶段/受限源码位置和数值断言诊断。
- 共享进程工具、fixture和Playwright锁文件保留。混合fixture测试保留四项，删除只服务旧Mac编排的两个测试。未改产品源码，A02B/A04/A05等并行修改不纳入本轮提交。

## 覆盖边界

迁移不宣称与旧264组等价。Core/Web规则与真实SQL/HTTP已覆盖的安全合同继续由原测试承担；完整页面目录、多模式排列、每页分页/错误/焦点矩阵以及固定arm64生产式容器门槛退出常驻CI。保留一个代表性键盘确认与游标UI路径。真实IME历史证据仅归档，不用合成事件冒充。

## 本地验证

本轮证据根为`/private/tmp/idp-n2-retirement-20261026-4pmyn0as`，记录各次失败和复验，原始日志不写Git。执行基线HEAD为`a3fcd729a10d65da8d7e988b71e4d80fd436c418`，另含本轮及并行工作区修改，不能视为纯提交树或目标Linux runner的证明。

完整PG/HTTP集成十目标169通过、0失败、0 ignored，清理确认。上轮A04-B注册not_found失败用例本次已通过，A02B-B3也通过；其并行产品修复未混入CI提交。Web单测185通过，Web/Rust宿主及fixture工具构建通过。

初次迁移浏览器复验发现新角色创建应为201，原测试误写200；已依据Axum合同修正。诊断同时扩展为安全的module行号和数值actual/expected，避免为定位而公开原始Playwright输出。失败历史保留，各次清理状态独立记录。


复审修正：Ant Select采用真实键盘展开/选择；客户端lookup的404按现有合同归为“精确查询未确认”，与200/null一样呈现读取失败，不将它误当对象不存在。未知写入及已确认写入的POST计数覆盖整个回读过程；授权恢复同时核对原binding/role/resource/scope和UI原绑定提示；租户补偿检测包含collection与兼容detail PATCH/DELETE，并在最终独立回读后再次核对完整租户记录及写入计数。

最终离线检查通过：集成驱动8、E2E runner7、checker2、共享fixture4、进程清理21；不存在活动代码引用已删除旧N2入口。`cargo test --workspace --locked`通过（483 passed/0 failed/171 ignored）；ignored保留显式live策略，不能计作已执行通过，完整集成169通过单独记录。未改Rust产品源码，因此本轮没有重跑其他feature/release专项矩阵。

实际本机为Mac arm64、Node24.19.0、pnpm10.28.2、Rust1.93.0、PG18.6 Debian、Playwright1.64.1/Chromium156.0.8078.4。目标Ubuntu x64 runner、artifact上传及远端注册状态均未执行，不能由本地结果代替。


最终六组E2E通过：19个实际子场景全部通过、0 page errors、browser closed及fixture cleanup通过；最终运行46.26秒（含准备/清理），上一轮完整通过43.49秒。本轮失败历史、最终JSON与离线检查摘要见[最小复验证据](design/ci-quality/n2-retirement-20261026/README.md)。旧N2已不再执行；删除旧入口后新入口独立运行，结果没有依赖旧manifest或检查器。活动文档链接已核对；历史说明中的两处已删除源码链接改为`git show a3fcd72:<path>`追溯方式，封存附件不改写。

本地提交仅包含本轮脚本/测试/旧workflow删除与文档；README只暂存CI条目，无关产品/API、Cargo和示例工作保留。完成这轮后CI/CD先暂停，后续按产品功能需求推进，不继续扩建N2或发布编排。
