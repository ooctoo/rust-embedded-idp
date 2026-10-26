# N2退役本地复验证据

2026-10-26。执行基线`a3fcd729a10d65da8d7e988b71e4d80fd436c418`，包含本轮及并行未提交改动；不能当作纯提交树或远端Linux runner通过。完整说明见[实施记录](../../../n2-retirement-implementation-result.md)。

- `integration-result.json`与`integration-cases.json`：十目标169通过，含A02B-B3和A04-B原失败用例；清理确认。
- `e2e-execution.json`与`e2e-results.json`：最终六组共19个已执行子场景通过，页面错误为零，浏览器与fixture清理通过，46.26秒含准备/清理。
- `checks.json`：离线、Web、工作区单测结果与本地日志哈希；ignored未冒充通过。
- `attempts.json`：此前失败/复验阶段、脱敏源码/数值诊断与每次清理状态；原始输出保留在本机私有临时目录，不写Git。

证据根：`/private/tmp/idp-n2-retirement-20261026-4pmyn0as`。它是本地临时保全，不是永久artifact。JSON仅含结果白名单，无数据库凭证、令牌、原始Playwright错误或profile。历史N2封存证据未修改。没有执行旧N2全套、远端Actions、推送、部署、缩放/旁白或M1-03–06。
