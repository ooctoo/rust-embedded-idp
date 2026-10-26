# A05 Enabled 嵌入示例局部实施记录

2026-10-26。已先完成[详细设计](a05-technical-design.md)与[实施方案](a05-implementation-plan.md)，经独立 double check 修正客户端准备边界后实施。产物为独立 [tenant-host 示例](../examples/tenant-host/README.md)，未执行完整验收、部署、提交或推送。

## 实施与复核

- 新增独立 workspace binary，固定 Enabled，直接复用公开 Core/Axum/security/Postgres API。Fixed tenant-a 与 Choose 两入口分别绑定 client、audience、login entry 和 Cookie Path；保留 Disabled 示例原实现。
- 管理组件独立 Fixed0 management 会话，明确装配权限目录 router，Cookie用于认证生命周期，目录仍使用管理 Bearer。可配置关闭管理UI/API。
- 报告详情坚持认证→精确权限→双列资源查询；列表最多检查40候选、最多返回20项，空页可以继续，HMAC游标绑定用户/session/租户/业务/入口/过滤条件/limit与期限。所有报告结果 no-store；后台同步存储和权限调用放入阻塞线程。
- 初始化仅接收 loopback 数据库与不同 a05_ schema。业务marker绑定IdP schema；拒绝接管已有未标记业务schema，以及以新业务marker接管既有IdP schema。客户端显式准备、冲突不覆盖；seed仅创建隔离演示数据，已有fixture拒绝重复，不隐式恢复部分失败。
- React复用原登录、选租户、本人角色、Cookie协调和独立权限目录。增加可选 `EmbeddedAuth.beforeSessionChange` 草稿确认钩子，默认兼容；取消确认不执行身份变化。业务请求绑定当前scope和递增generation，切换后清缓存、丢弃迟到结果及错误。
- 示例独立接口合同与静态漂移检查加入A03入口，未改变IdP HTTP DTO或Core/库迁移。未添加新的第三方版本；依赖复用现有锁定包。新增workspace成员在Cargo.lock中登记。

实现复核修正了：误用A01准备业务client的设计、初始化marker接管边界、空列表对空授权批次调用、阻塞线程内执行授权、未装配管理租户列表API调用、跨入口复用陈旧Web产物、嵌入CSS遗漏，以及异步查询的旧错误/忙状态覆盖。局部测试的PostgreSQL就绪探测改为TCP连接，避免把初始化阶段的临时Unix socket服务误认为最终服务已就绪。构建现在先更新嵌入包，再构建示例，避免类型已更新而运行时仍读取旧dist。

## 局部验证

| 检查 | 结果 |
| --- | --- |
| `cargo test --locked --offline -p embedded-idp-tenant-host -p embedded-idp-no-tenant-host` | Enabled 5项、Disabled 4项通过 |
| `pnpm --dir web test` | 185/185通过 |
| `pnpm --dir web test:embedded-bundle` | 7/7通过 |
| `./examples/tenant-host/run.sh build-web` | Web主包、管理子包、示例TypeScript及Vite构建通过 |
| `./scripts/check_api_contracts.sh` | 四份IdP生成合同无漂移，15/15合同测试；A05宿主独立合同的路由、query、响应字段和边界检查通过 |
| `node examples/tenant-host/tests/live.mjs --browser` | 专用PostgreSQL 18.6、真实新宿主、合成身份、真实浏览器局部流程通过 |
| 格式和变更检查 | `cargo fmt --all -- --check`、`git diff --check`通过 |

真实HTTP覆盖：重复初始化与准备、未标记schema拒绝接管、client冲突不覆盖、Fixed与Choose登录、A/B同报告ID内容隔离、入口token互拒、caller租户header拒绝、only-a不能选B、未授权对象存在/不存在均403、授权缺失404、列表过滤及空页继续、篡改/跨用户/跨租户入口/改变limit或prefix的cursor拒绝、Cookie restore及Cookie不能直接读报告、管理/业务purpose隔离。直接在专用fixture数据库改变成员为suspended/removed、账号为disabled，后续请求拒绝，另一仍active成员域不受单域停用影响。此状态变更测试验证宿主消费当前身份，不替代管理写事务自身的验收。

浏览器覆盖：真实Cookie刷新恢复、Fixed/Choose、入口和租户切换草稿取消、延迟交付旧租户报告后不覆盖新租户、列表读取及空页完成、独立管理登录和权限目录目标切换、320px页面无水平溢出。复用包实际CSS；未使用mock身份服务器代替真实宿主。截图只含合成公开信息，保存在 `/private/tmp/idp-a05-ui`。

补充验证管理关闭后 `/management` 和 `/control/admin/auth/capabilities` 均404，配置返回关闭；同一服务重启后旧游标签名失效并返回400。测试脚本清理本次专用容器、进程、临时密钥；中间一次浏览器测试拦截时序异常遗留的专用资源已单独核对并清理。

## 限制与后续

本批基础Enabled示例完成，不能视为完整产品验收。生产TLS/池、第三方嵌入宿主全部组合、Linux CI、跨库在途撤销线性化、性能和真实设备/扫码均未验证。示例仅loopback/NoTls，fixture不是生产迁移；跨库seed失败可能部分提交，必须显式核查，不能自动覆盖恢复。示例包含管理组件的bundle会触发Vite大chunk提示，当前未做体积优化或性能宣称。

后续按修订4处理S01等后续切片并保持设计先行；完整验收与部署仍保持未执行。
