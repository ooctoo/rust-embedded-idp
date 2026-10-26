# A04-A 实施记录

2026-10-26。依据修订4 A04与[细化技术设计](a04-a-technical-design.md)、[实施方案及复核](a04-a-implementation-plan.md)。本批完成不依赖设备持钥的本人设备与解绑回执子集；登记/轮换/扫码组件、A05和完整验收不包含在本次完成口径。

## 实现与复用

- `EmbeddedIdentityClient.requestDevice`限制本人设备路由，复用原有base、transport、内存Bearer、超时、refresh single-flight和revision；不允许任意URL、管理路由或其他设备写路径。
- `EmbeddedDeviceClient`提供list/detail/keyMetadata、prepareUnbind/unbind/operationResult。按实际HTTP投影校验scope、正整数版本、nullable key、时间、分页及解绑回执；opaque intent冻结并绑定client实例和owner，回执必须匹配原操作/绑定及版本+1。同一owner重新登录可回读，跨owner或实例不能复用该intent。
- `DeviceSelfService`提供中英文、分页/详情/公开密钥状态、行内解绑确认、未知结果回读、焦点与状态反馈。设备状态与本人绑定状态分开显示；只有active设备+active绑定提供key metadata操作。身份代际变更即时隐藏旧数据，迟到响应不能覆盖当前界面；未知解绑不能被新操作覆盖，成功回执不被随后列表刷新失败抹除。
- 包主入口导出client/DTO/组件/props，仍使用宿主React19和独立CSS module，没有引入AntD或新运行时依赖。复用现有React/TypeScript/Vite/Playwright（MIT）和本仓MIT服务，无Core、SQL、HTTP wire或迁移变更。
- A03五个本人接口沿用现有device合同，只补路由消费说明。[宿主接入说明](a04-a-integration.md)明确认证、内存恢复、client和服务端receipt范围的区别。

## 先设计与double check发现

方案复核发现现有receipt是tenant/account/operation ID范围，不能把前端intent的入口约束描述成新增服务端client隔离，已修正文档。实现复核修正了同账号重新登录的数据代际、分页cursor残留、未知intent覆盖、迟到回写、多实例heading ID及操作后详情清理。真实宿主测试发现algorithm是小写`ed25519`，已对照存储投影修正，未改变服务端协议。独立审查发现key metadata的active状态前提，已同步UI并加入浏览器负例。

## 局部证据

- `pnpm --dir web test`：122项通过（含新增设备client 7项）。请求/DTO、scope、分页、原intent回执、同owner重新登录、跨实例/owner拒绝、非法URL/写路径及logout迟到响应均有覆盖。
- `pnpm --dir web build`：通过；`pnpm --dir web test:embedded-bundle`：4项通过，包含公开导出、宿主React、无管理依赖、无全局CSS和中英文组件SSR。
- `node web/embedded/device-browser-check.mjs`：使用仓库已有Playwright本地Chromium通过。详情/key、旧用户延迟列表、新用户隐藏旧数据、键盘确认、unknown阻止再次解绑、切换owner/重新登录恢复、停用设备隐藏不可用key查询、320px无横向溢出。截图经主代理查看。夹具是合成响应，不作真实协议证据。
- app真实宿主 `a04a_device_self_client_reads_and_recovers_unbind_against_reference_host`：通过。复用B3真实登记/证明/扫码激活设备夹具，再以实际构建的JS客户端请求真实本人API；在服务端解绑成功后丢弃响应，随后GET原回执；重新登录同owner仍可回读，写入仅一次。
- 真实Postgres本人解绑/查询两项回归通过，覆盖Enabled/Disabled、本人会话撤销、事务回滚、actor/client/tenant/cursor与admission边界。
- `CARGO_NET_OFFLINE=true ./scripts/check_api_contracts.sh`：四份制品无漂移、15项合同测试通过。
- `cargo check --locked --offline --workspace --all-targets`、`cargo fmt --all -- --check`和`git diff --check`：通过。

真实测试仅用专用容器`idp-a04a-20261026`、Postgres18.6和随机schema，不访问既有数据库。真实宿主用`--features development-private-network-http --test live_reference_host --no-run`编译，再传显式`EMBEDDED_IDP_TEST_PG_CONNECTION_URI`并以`a04a_device_self_client --ignored --test-threads=1`运行；普通离线测试不依赖PG。

## 剩余边界

A04-B登记/signing/admission、A04-C双签轮换及其未知结果恢复、A04-D可选扫码和原生平台持钥仍未实施。intent仅保留本页内存，重新加载页面不承诺恢复。实际JS宿主链路本批验证Disabled；Enabled服务端本人授权由既有PG两模式回归验证，不冒称覆盖所有浏览器/租户/设备组合。未做完整验收、部署、提交或推送；并行CI/N2/PG工作保持原样。

专用测试Postgres容器及匿名卷已清理。A04-A局部退出条件完成，A04整体仍保留后续子批。
