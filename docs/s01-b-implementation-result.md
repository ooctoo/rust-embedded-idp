# S01-B 实施结果

2026-10-26；详细设计与独立复核见 s01-b-design-and-plan.md，选型/许可证见 s01-governor-g0.md。本批完成有界、单进程来源与账号速率准入，接入参考宿主和两种嵌入示例。原成功 DTO、权限及设备 proof 不变。

## 已验证

- Security 准入适配器 6 个局部测试通过：容量、恢复、独立摘要键、单调时钟及损坏锁 fail-closed。
- Axum 准入 10 个局部测试通过：可信来源、忽略伪造代理头、共享账号键、16KiB body、5 秒慢 body、传输错误、原始字节保留和 IPv4-mapped 规范化。
- 参考宿主配置测试通过；工作区 all-targets 编译通过。
- 专用临时 PostgreSQL/参考宿主 4 个定向集成测试通过：普通入口隔离、confidential/可选注册、双 tenancy mode，以及新增跨入口限流和慢 body 超时。
- API 合同 15 个测试与 A05 静态合同检查通过。
- Enabled 示例真实本地 HTTP/浏览器测试通过：Fixed/Choose、Cookie reload、权限/租户边界、撤销、迟到响应隔离、管理独立及 320px 展示。
- Web 及示例构建通过。浏览器依赖首次缺失，离线安装后重试成功；本机 Node25/pnpm10，不作为目标 Node22 CI 的证明。

本地证据日志为 /private/tmp/idp-s01b-{security,http,config,check,live,contracts}.log 及 idp-s01b-example-live.log。临时日志不作为仓库长久测试工件，复跑入口以源码测试为准。

## 明确边界

来源/global 与账号扣额分阶段，不承诺跨请求体原子扣额；重启会清空预算；没有共享多副本预算。可信代理地址映射由宿主提供。新 wrapper 是可选宿主组合，不改变未包装库 router。OIDC/client-admin 和设备登记的昂贵工作共享预算由 S01-C 接续收尾。完整验收、目标环境、部署、推送均未执行。
