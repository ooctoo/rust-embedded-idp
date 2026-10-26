# A02B-B3 实施记录

日期：2026-10-25。依据修订4与[B3详细技术设计](a02b-b3-technical-design.md)、[实施方案及复核](a02b-b3-implementation-plan.md)。本批仅配置组合、参考扫码页面、清理生命周期和接口合同，不改Core事务状态机或数据库结构。完整验收、部署、提交和推送未执行；并行CI/N2工作不属于本批。

## 实现

- JSON v2可选scan入口，同client普通browser来源与独立proof-required设备目标；要求已有browser和device配置。显式reference-identity-only/registered-device provider不代表生产业务准入。
- 每入口固定scope、audience、外部路径，复用Core十类proof purpose、既有8个browser/10个device路由、Pending交付与ack/recover/abort协议。每请求注入短期可信host context。
- 独立32字节私有结果密钥文件，1–4把key，启动时加载；active加密，旧key恢复；缺失或不合法拒绝启动，不生成替代key。新旧key重叠责任、参考provider边界见设计。
- 多入口页面使用自身认证与资产路径。局部测试发现Axum nest规范页面地址为不带尾斜杠的`/ui`；设计、配置和测试均修正，与Legacy一致。
- 一个顺序cleanup调度器处理有界入口列表，不补发错过的interval。listener绑定后才启动；SIGINT/SIGTERM触发HTTP和cleanup并行有界drain。修复初版误将drain计时包住整个服务生命周期的问题，并覆盖正常HTTP退出通知cleanup、初始stop与false通知、多任务公平推进。
- A03独立18操作扫码合同与生成器、漂移检查。复核修正两侧同名status/cancel路径覆盖、security数组结构、可空响应字段；扫码profile使用Core既有`EMBEDDED-IDP-DEVICE-SCAN-V2`，不另创协议。
- 依赖仅Tokio启用signal/sync及锁定signal-hook-registry 1.4.8（MIT OR Apache-2.0）；沿用现有ring/Axum/Core实现。

## 局部验证状态

- `pnpm --dir web build`：通过，先构建嵌入资产再编译Rust宿主。
- app二进制单测：50项通过，包含配置、keyring新旧重叠/跨entry AAD/重复材料/文件权限、两入口页面、顺序cleanup与停止边界。
- Axum `device_scan_login`（openapi feature）：12项通过，包含真实HTTP响应对schema的投影检查。
- Core `access::authentication_tests::scan_login`：15项通过，包含取消、投递过期、恢复、清理和回滚。
- 真实Postgres `authentication::device_proofs::scan_login`：12项通过，包含并发exchange、ack/close竞争、清理/补偿及审计失败回滚。
- 新B3真实宿主测试：1项通过。两个entry不同scope/audience/key，UI与资产实际HTTP 200；准入登记、browser隔离、跨entry proof拒绝、phone代码路由、device_display批准/交付、Pending不可认证、重启密钥重叠recover保持同一token/session/receipt、ack后认证以及SIGTERM正常退出。缺key启动失败前后DB快照一致。
- B2真实宿主回归2项通过；Legacy扫码challenge、受限browser及Enabled/Disabled管理/业务链路3项通过。
- `CARGO_NET_OFFLINE=true ./scripts/check_api_contracts.sh`：四份制品漂移检查和15项合同测试通过。
- `cargo check --locked --offline --workspace --all-targets`、`cargo fmt --all -- --check`、`git diff --check`：通过。

数据库使用专用Postgres18.6容器`idp-b3-20261025`与随机schema，显式传入测试URI；没有使用既有开发或生产数据库。真实测试先以`--features development-private-network-http --test live_reference_host --no-run`编译，再指定过滤器、`--ignored --test-threads=1`运行。

局部验证曾发现并修复：测试签名器漏用scan专用上下文（改复用Core builder，未改wire）；OpenAPI空required数组被序列化器省略的断言；正常SIGTERM时同步PG池在异步上下文最后析构导致panic。最后一项已先更新设计/方案并独立复核，保留Router服务树引用至runtime退出后同步释放，再以真实SIGTERM成功退出验证。超过drain期限的慢DB/已脱离blocking任务最终释放尚未故障注入，不把正常退出通过当作超时路径的完整证明。

## 后续边界

A04按修订4拆分设备列表/本人回执、登记、双签轮换及可选扫码子批；每项仍先细化设计和实施方案并double check，再写代码。A05 Enabled宿主示例为独立批次。实体设备、原生持钥、真实代理/TLS、多副本与完整故障注入未在本批验收。

清理：本轮专用Postgres容器及匿名数据卷已删除。B3按本文局部退出条件完成，A04/A05尚未编码；不把本轮局部证据扩大为完整产品验收。
