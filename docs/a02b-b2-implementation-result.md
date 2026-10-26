# 第四批 A02B-B2 实施记录

## 范围与前置依赖

基线为本地提交`241672b`。A01显式准备、A02A普通多入口和A02B-B1共享OIDC已具备局部验证，B2按修订4继续接入设备proof/admission；B3扫码provider/keyring/cleanup、完整验收和部署不在本批。保留工作区并行N2材料。

复用Core设备登记/结果查询/激活/轮换/解绑/心跳、单次challenge、已有Ed25519与RS256适配器及Postgres事务。新增改动归app配置/装配/受限参考准入适配器、Axum共享OIDC按client查找可信HTTP proof profile、相关HTTP合同和局部测试；Core既有业务规则与数据库结构不变。不新增生产依赖或数据库迁移；测试复用已锁定的 ring 0.17.14（crate 声明 `Apache-2.0 AND ISC`；复用仓库现有锁定版本，不新增运行时包）生成真实 Ed25519 签名。

前置缺口：TrustedDeviceAdmission只有scope与expiry，不能从请求JSON声明；旧reference_dev一年期限的准入不用于新配置。现有设备HTTP配置已固定POST和协议profile，但共享OIDC此前只有一份token路径配置。B2须冻结client→proof配置注册表，保留原始请求体摘要，绝不从未验证的JWT或caller header取可信audience/path。

本批范围决策：JSONv2 entry显式device配置，包含admission_provider、profile_provider、audience及各外部path；profile_provider只支持现有ed25519-v2。runtime中的admission provider引用宿主私有文件，文件存放预先批准的有期限登记grant（精确tenant/client/device、稳定scope及凭据hash）。请求须提供grant凭据，host验证后才构造请求级TrustedDeviceAdmission；Core再次验证范围与期限。它是参考host的有限授权适配示例，不把普通Business Bearer等同设备所有权，不提供生产设备审批平台。provider缺失、路径歧义和不支持组合必须在监听/身份写入前拒绝。

支持可选proof和强制proof入口；强制proof不允许browser会话以免绕过，不改变普通入口和LegacyReference。设备仍由已有生命周期接口操作，扫码配置仍拒绝。固定外部路径须与本host真实挂载一致，真实反向代理重写规则由后续宿主单独接线验收。

局部退出：两入口设备登记/回读/证明登录/刷新/OIDC兑换隔离、期限/错误credential/错误scope与重复header拒绝、路径/audience/body签名绑定和禁止proof降级；静态配置拒绝用例、已有Core/HTTP回归，以及设备合同生成与漂移检查。不执行实体设备/真实代理/TLS、完整产品验收或部署。

## 配置与验证结果

### 显式配置

配置版本为 `2`。在现有 `runtime` 中加入：

```json
"device_admission_providers": [
  { "id": "enrollment", "grants_file": "device-grants.json" }
]
```

业务 entry 示例（与现有 management/runtime 配置合并，非完整配置文件）：

```json
{
  "login_entry": "desktop",
  "client_id": "desktop",
  "tenant_policy": { "kind": "fixed", "tenant_id": "0" },
  "mount_prefix": "/desktop",
  "require_device_proof": true,
  "oidc": { "enabled": true },
  "device": {
    "admission_provider": "enrollment",
    "profile_provider": "ed25519-v2",
    "audience": "desktop-device-api",
    "paths": {
      "login": "/desktop/auth/login",
      "selection": "/desktop/auth/tenant-selection/complete",
      "refresh": "/desktop/auth/refresh",
      "heartbeat": "/desktop/devices/heartbeat",
      "oidc_token": "/oidc/token"
    }
  }
}
```

五条路径均必填，即使当前 fixed policy 不挂载 selection 或未开启 OIDC；固定 POST，由已有协议常量定义 AUTH-V2/REQUEST-V2。audience 是设备 proof 的 audience，不改变业务 JWT audience。共享 OIDC token 通过已登记 client 查静态 profile，Core 继续验证 client/授权码/session/tenant；客户端字段不能自定义 profile。配置 v1 不接受 device/provider 字段；v2 不配置 device 则仍为普通入口。`require_device_proof=true` 与 browser 组合在启动前拒绝。scan 仍不支持。

### 准入材料及边界

`grants_file` 相对于主配置文件目录解析，文件须为普通文件、Unix 权限仅属主可读写（如 `0600`），最大 64 KiB，内容为 1–128 项 JSON 数组。每项字段如下（占位符不可直接作为运行凭据）：

```json
[
  {
    "grant_id": "enroll-001",
    "tenant_id": "0",
    "client_id": "desktop",
    "device_id": "11111111-1111-4111-8111-111111111111",
    "credential_hash": "<由 PhcClientSecretCodec.hash_client_secret 生成的 PHC>",
    "issued_at_unix_secs": 0,
    "expires_at_unix_secs": 1
  }
]
```

宿主可信的预批准流程生成高熵随机凭据，保留已有 Argon2id 默认参数的 hash，通过安全通道交付原文；本批不提供审批平台或凭据生成命令。原文长度 32–256 ASCII 字节、无空白，不能用示例常量作为生产 secret。请求登记或读取登记结果时发送 `x-embedded-idp-device-admission: enroll-001.<原文>`，重复 header、错误凭据或期限均拒绝。任何普通 bearer 均不能替代该授权。

grant 的期限为绝对时间，最长一小时。宿主构造 `registration_scope=provider_id.grant_id`，请求上下文期限取 grant 到期时间与当前时间加 300 秒的较早者；Core 在事务锁内重验范围和期限。因登记结果截止时间还受第一次 provision 上下文限制，完成登记应在该固定短窗口内进行；重启或回读不会延长已有登记窗口。grant 的设备 UUID 和请求的 registration_request_id 均使用规范 UUID。Core 保持登记幂等、结果按稳定 scope 隔离以及单次 challenge 事务消费语义。

文件只在启动时加载，撤销或替换需重启，不能宣称即时撤销；稳定 scope 需保持同一 grant_id 的授权含义，禁止将其重新分配到另一个身份。跨宿主即时撤销、真实设备归属审批、代理路径映射及 TLS 验收属于生产宿主后续责任。参考适配器的授权对象是指定 tenant/client/device 的登记能力，不是任意人员账号所有权声明。

全进程最多四个准入 hash 校验并行，超额返回 `503 device_admission_busy`，不建立无限排队；鉴权失败返回 `401 device_admission_required`，均 no-store。此上限不代替生产边界的来源限流。provider 文件格式或依赖无效在数据库初始化和监听之前失败。

### 局部验证

以下检查均限本批及直接受影响兼容路径，不代表完整产品验收：

- `pnpm --dir web build`：通过（先构建嵌入资产，再编译参考宿主）。
- `cargo test --locked --offline -p embedded-idp-app --bin embedded-idp-app`：41 项通过。包括配置 v1/v2、依赖缺失、路径冲突、browser/proof 非法组合、准入身份/期限/重复头、hash参数/文件权限及并发容量拒绝。
- `cargo test --locked --offline -p embedded-idp-axum --lib`：103 项通过。新增共享 token client→profile 检查，证明原始 form 摘要、外部路径、method、tenant及两client不同audience正确传递；未知client、query与重复tenant头不能到达service。
- `cargo test --locked --offline -p embedded-idp-core access::authentication_tests`：67 项通过。复用的设备登记/事务激活、nonce/会话/绑定回滚、选择完成与刷新期限复核等测试均在此范围；未改 Core 规则。
- `CARGO_NET_OFFLINE=true ./scripts/check_api_contracts.sh`：14 项合同测试及三份制品漂移检查通过。新增设备14操作合同、条件选择、共享OIDC proof说明和schema引用循环检查；普通17操作目录保持独立。设备合同是设备差异面，入口公共capabilities/session/选择列表/本人等沿用普通合同对应操作，不声称14项就是该entry的全部路由。
- `cargo check --locked --offline --workspace --all-targets`、`cargo fmt --all -- --check`、`git diff --check`：通过。
- 真实宿主局部测试：专用 PostgreSQL 18.6 容器 `idp-b2-20261025`，仅使用自动生成的隔离schema。B1共享OIDC、confidential client资源隔离、受限browser不能升级OIDC、LegacyReference两模式共4项回归通过。B2两项新增测试全部通过：`a02b_b2_device_admission_is_bound_to_entry_and_registration_identity` 和 `a02b_b2_device_proofs_bind_registration_auth_refresh_and_shared_oidc_exchange`，覆盖双入口grant/设备隔离、重验结果、真实登记/完成、两audience证明登录、刷新降级拒绝、heartbeat/replay及共享token原始form proof。

测试编译命令为 `cargo test --locked --offline -p embedded-idp-app --features development-private-network-http --test live_reference_host --no-run`；随后仅以显式测试数据库变量运行指定过滤器，`--ignored --test-threads=1` 串行执行。没有访问已有开发/生产数据库。

新增宿主签名用例通过真实Ed25519证明验证两入口不同client/audience；负例使用尚未消费的nonce，最终有效请求成功以排除nonce已消费造成的假阳性。原始JSON空白和form字段顺序变化保留相同业务语义，用于验证签名确实绑定字节。登记结果读取仍重新验证准入，不以先前成功登记免除授权。

本批未执行完整验收、部署或远程推送；实体设备、真实反向代理/TLS、平台SDK、多租户设备入口所有组合与长时间故障注入仍未验收。B3 provider/结果密钥/cleanup仍按后续批次推进。

清理：专用测试容器及匿名数据卷已删除；工作区并行N2文档/暂存状态保持原样，本批未提交。
