# M1-02 配置归一与最小共同装配实施结果

| 项目 | 记录 |
| --- | --- |
| 日期／设计基线 | 2026-10-20；[M1-02 设计修订 2 固定快照](m1-02-configuration-composition-design-r2.md) |
| 源码起点 | `1835ec35790568fefb9f6792a120b3041cfe77ae`；3.0.0／`tenant_v6`；本次工作区改动尚未提交 |
| 交付范围 | 旧输入归一、显式 JSON 输入、最小共同管理装配、仅管理启动及相关验证 |
| 能力边界 | 显式配置可静态解析合法非空业务集合；本构建尚未装配其运行路径，在监听／密钥加载／数据库访问前明确拒绝，不自动回退旧参考输入 |
| 后续边界 | 未实现管理 client 准备命令、未启动 M1-03–06；试点、部署、完整多入口业务协议和探针生产时限继续待定 |

本文 §1–5 保留修订 2 原实施与验收记录。后续修订 3 的收尾改动、管理完整生命周期和新增运行证据见[收尾实施与验收回传](m1-02-closure-result.md)；不能把本表中的历史“通过”直接扩展为修订 3 全量通过。

## 1 实际改动

| 文件 | 改动 |
| --- | --- |
| [composition_config.rs](../crates/embedded-idp-app/src/composition_config.rs) | app 内共同参数；旧配置原值转换；严格 JSON v1；重复 key／未知字段／类型／null／版本检查；惰性 SecretRef；文件大小和常规文件检查；策略、稳定标识、路径归属和 Cookie 校验 |
| [main.rs](../crates/embedded-idp-app/src/main.rs) | 新增 `--config <path>`；保留无参数旧参考与独立 `bootstrap-admin` 分派；按实际装配打印入口信息 |
| [bootstrap.rs](../crates/embedded-idp-app/src/bootstrap.rs) | 单个共同装配入口，复用原管理服务／受保护 API／Cookie／健康路由；新输入只核对已准备引用，旧输入才执行原参考补缺及完整旧业务装配 |
| [admin_ui.rs](../crates/embedded-idp-app/src/admin_ui.rs) | 根 mount `""` 映射页面 `/`；替换唯一 API meta，插入唯一 browser meta；构造阶段拒绝歧义模板；UI／assets 与 API mount 分开 |
| [config.rs](../crates/embedded-idp-app/src/config.rs) | 旧 env parser、默认及类型保留；原 browser helper 留作 test-only 的归一对照 |
| [explicit_config_cli.rs](../crates/embedded-idp-app/tests/explicit_config_cli.rs) | 真实二进制离线错误用例：缺参数、重复来源参数、坏文件、非法命令组合，不回退、不输出 Secret |
| [live_reference_host.rs](../crates/embedded-idp-app/tests/live_reference_host.rs) | 新增隔离数据库／真实进程验收，保留原参考行为用例 |
| app Cargo.toml／Cargo.lock | 显式使用已在锁文件中的 `serde` derive 与 `serde_path_to_error`；没有新增配置框架或更新依赖版本 |

未修改 Core、Axum、Postgres 的公共契约、SQL 或 schema，也未修改 Web client 的公共构造器。旧参考 seed 仍是缺失插入、已有不覆盖，不升级为 M1-03 的匹配／冲突准备协议。旧业务 JWT/JWKS 和 browser 配置仍在参考 seed 前完成原有安全配置检查。

## 2 使用与前置条件

示例：[仅管理 JSON](examples/m1-02-management.json)。其中域名、路径、Secret 名和 schema 均为示意值；需先按实际目标修改。

```sh
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
cargo run -p embedded-idp-app -- --config /absolute/path/management.json
```

JSON 相对文件路径以 JSON 所在目录为基准。普通启动必须已经具备同 mode 的 Access schema、有效平台管理员、符合配置的 public／PKCE 管理 client 和既有签名密钥。新模式不准备这些对象，不补缺 client，不生成密钥，不写身份数据。

不要使用会 source `.env`／模式文件的旧开发脚本启动显式模式；旧 app 变量与 JSON 混合会拒绝，只有 JSON 明确指名的合法 PG URI／SMTP password 旧 Secret 来源例外。新实例宜使用独立命名的 Secret。`bootstrap-admin --config` 仍不支持；P1/P2 的同源参数投影继续按设计第 6.4 节使用命令专用临时环境，不新增自动准备编排器。

当前显式模式只挂管理认证、受保护管理 API、可选管理页面／assets 及健康路由；`ui:null` 可以禁用页面。业务登录、注册、设备、扫码、discovery、JWKS 均不会因默认值而出现。合法非空集合在本构建报 `business entries are not supported by this build`；这是运行装配未交付的说明，不是配置格式永久禁止非空集合。

管理 Fixed 0 例外、Enabled 的管理 Choose／Fixed 非 0、Disabled 限 Fixed 0 继续依赖原 Core 规则。基础 `/readyz` 保持原 schema／mode／bootstrap／管理目录／有效平台管理员检查，不反复扫描或锁定全部入口引用；client 运行中被移除时，它仍可返回基础 ready，而实际认证和下一次启动拒绝。

## 3 已运行验证与证据层级

所有数据库执行均指向为本次任务新建的临时 PostgreSQL 18.3 容器；未使用已有 `pg` 容器或业务数据库。测试各自创建／清理随机 schema，并保留同 schema 宿主 sentinel。数据库中插入管理 client 只属于隔离测试夹具，没有转化为软件准备命令或匿名 API。

| 检查 | 结果／边界 |
| --- | --- |
| `pnpm --dir web install --frozen-lockfile`、`pnpm --dir web build` | 通过；嵌入资源先于 Rust 编译；原有 chunk size 提示保留，没有改打包策略 |
| `pnpm --dir web test` | 93 项通过 |
| `pnpm --dir web test:embedded-bundle` | 3 项通过 |
| `cargo fmt --all -- --check` | 通过 |
| `cargo check --workspace --all-targets --locked --offline` | 通过 |
| `cargo test --workspace --locked --offline` | 通过；未启用的实库用例明确 ignored，不计实库通过 |
| app 默认构建、显式测试 PG、`--include-ignored --test-threads=1` | 30 项 app 单元用例、2 项管理员 CLI 实库用例、9 项真实参考／仅管理进程用例通过 |
| 新增独立 CLI 离线集成 target | 1 项通过，包含 6 组错误输入 |
| app 私网开发 feature 构建及相关实库回归 | 通过：30 项单元、1 项独立 CLI、2 项管理员 CLI 实库、10 项真实进程用例；额外覆盖既有受限 browser 期限与过时身份拒绝，不称为真实手机／私网现场验收 |
| 真实浏览器 | 在独立合成 fixture 上验证根管理 mount 与 `/identity`，UI 均独立位于 `/console/`；API/browser meta 各唯一，DOM content 分别为 `/`、`/identity`；真实登录、平台页面、客户端列表读取及刷新恢复成功 |

真实进程用例覆盖 Enabled／Disabled × `""`／`/api`／`/identity`，以及 `ui:null`。启动与 `/readyz` 前后比较全部表行的有序 JSON 快照；缺管理员、错 mode、缺 client、错误密钥、不兼容 public PKCE 配置均拒绝，且不补建或修复。仅有管理 client 即可启动，无业务 client／租户／email provider 要求。

重启用例保持同端口／issuer／key／DB，核对 token 与 Cookie 恢复、原 session 到期时间不延长、在线修改回调不被旧 seed 覆盖。运行中移除管理 client 的隔离负例证明基础 `/readyz` 与实际入口认证的范围不同。它不表示新增 client 删除 API。

真实浏览器检查通过内置浏览器完成：外部 Playwright CLI 因当前 registry 无法解析且无缓存，未作为浏览器证据来源。没有绕过浏览器安全警告或修改信任设置。真实浏览器检查是本地回环、合成身份和单入口管理操作，不能推导同源 A/B 多入口多标签、私网手机／设备或生产部署通过。

复现相关实库回归时，显式向进程注入仅属于隔离测试库的 `EMBEDDED_IDP_TEST_PG_CONNECTION_URI`，分别运行：

```sh
cargo test -p embedded-idp-app --locked --offline -- --include-ignored --test-threads=1
cargo test -p embedded-idp-app --features development-private-network-http --locked --offline -- --include-ignored --test-threads=1
```

前一命令在独立 CLI target 加入前已完成 app 30+2+9 项，新增 target 随后单独通过；后一命令包含最终全部 app target。运行证据来自这些显式实库命令，不来自 workspace 离线命令中被 ignored 的条目。临时浏览器进程和验收数据库在检查结束后清理，不留下试点或部署实例。

### 3.1 首次失败与处理

首次默认 app 实库验收并行运行时，新仅管理用例在管理员 fixture bootstrap 失败；临时数据库日志包含 `could not open relation with OID ...`，发生于其他随机 schema 被并发创建／删除时的既有 `information_schema.columns` 检查。单独重跑该用例通过；随后相关实库 target 以 `--test-threads=1` 串行通过。

没有为此修改库 SQL、取消状态校验或把失败改为跳过。本次结果只说明串行隔离验收通过，不宣称已解决并发 schema DDL 的 catalog 查询问题，也不把它当作业务认证并发或部署容量证据。

## 4 Q01–Q22 回传

“部分通过”表示本阶段子断言已有运行证据，整组后续组合尚未执行；不能折算为整个 M1 通过。

| 编号 | 本次结果 | 已有证据／未执行边界 |
| --- | --- | --- |
| Q01 | 通过：本阶段旧输入／归一 | 原 env 单元用例、逐字段归一与 browser 配置对照、旧两模式真实参考流程 |
| Q02 | 通过 | 合法白名单、未知旧变量、混合来源、惰性 lookup 计数；静态失败不读取 Secret |
| Q03 | 通过 | 版本／重复 key／未知字段／类型／null／缺字段及 CLI 文件错误；无旧输入 fallback |
| Q04 | 部分通过 | 文件 Secret 的空值／编码／大小／双来源、常规 FIFO、坏签名密钥和既有传输门禁；真实 TLS／私网环境未验收 |
| Q05 | 部分通过 | 静态 mode/purpose/policy 矩阵、管理 proof 明确拒绝；真实新模式两种 mode 的 Fixed 0；新管理 Choose／Fixed 非 0 的完整 HTTP/DB 组合未额外执行 |
| Q06 | 通过：静态部分 | login_entry/client/Cookie 唯一性及 family 冲突；未启用新业务集合运行 |
| Q07 | 部分通过 | 缺 client／损坏 PKCE、错 mode／缺管理员的启动无写；业务 Fixed 引用的多入口组合未执行 |
| Q08 | 未执行完整组合 | 原 Core 当前状态用例回归与策略静态检查；新业务停用／Choose 零业务域组合仍归后续装配 |
| Q09 | 通过：本阶段路径校验 | 非法字符、段、UI／API／assets 归属及根挂载；实际已挂管理路由正常运行 |
| Q10 | 部分通过 | 静态 Cookie 名／路径冲突与真实单管理入口 Cookie；跨入口多标签验证未执行 |
| Q11 | 通过：本阶段管理 UI | HTTP 三种 mount、模板缺失／重复负例，真实浏览器根与 `/identity` 的 DOM 和实际登录／读取 |
| Q12 | 通过 | 两 mode 的空列表仅管理启动，零业务对象及缺管理依赖负例，`ui:null` |
| Q13 | 通过：本阶段启动／probe | 成功／失败启动与基础 `/readyz` 全表行快照、宿主 sentinel 保留，未调用准备／seed |
| Q14 | 部分通过 | 旧参考流程及原 `ON CONFLICT DO NOTHING` 代码保留；新模式已有在线回调修改后重启保留。旧模式部分补建失败组合未新增故障注入 |
| Q15 | 部分通过 | 新管理同配置重启 token／Cookie／原期限，旧参考回归；业务重排、selection／OIDC code 的新多入口组合未执行 |
| Q16 | 未执行完整组合 | 保留原 Core 绑定与票据回归；不提供绑定原地迁移，不声称改名会撤销全部 JWT/session |
| Q17 | 部分通过 | 新格式拒绝不支持扩展／proof 配置；旧参考业务与扫码回归。完整新协议组合未启动 |
| Q18 | 部分通过 | workspace 的独立无租户宿主和 Core/Axum/Web 离线回归；未另跑完整独立宿主浏览器链路 |
| Q19 | 通过：当前构建边界 | 合法非空集合解析成功，启动前明确拒绝；未实现“支持业务运行的构建”对照，不承诺业务生命周期完成 |
| Q20 | 部分通过 | JSON/Secret 路径与默认解析、fixture 中已有 Access 初始化／管理员命令的同目标临时参数。未新增投影工具，真实 TLS/CA 非默认工具限制未执行 |
| Q21 | 部分通过 | 真实 CLI 拒绝未定义组合、干净临时环境启动、缺 client 不 seed、既有管理员重复执行保护；没有执行完整 P1–P6 或新 P3 |
| Q22 | 部分通过 | 基础 probe 无写、缺 client 后基础 ready／认证拒绝、下一次启动拒绝；未运行高并发 probe、锁等待／严格取消与容量验收 |

## 5 最终边界

本次实现未新增公开 Rust/Web API、schema 或认证规则；app 内增加配置格式和 CLI 属可观察新增接口。设计修订 2 作为固定基线保留，本报告单独记录实现及运行层级，不把设计中的历史“未执行”改成全量通过。

M1-03 的管理 client 显式准备、新业务多入口及协议组合、M1-05 OpenAPI、M1-06 总体验收均未启动。现有事务／签名／设备用例的回归不代表启动这些工作包。真实探针时限、试点与部署继续待定；未提交、推送或发布。

## 6 修订 3 收尾增量

后续已按代码审查 F01–F06 与 A01–A05 实施收尾：提前构建能力门禁、保留共同 typed email、按需装配 browser/UI，并补齐管理 token/Cookie 生命周期、用途隔离及受影响的旧参考回归。具体命令、结果、Q01–Q22 增量状态和剩余阶段边界统一记录在[收尾回传](m1-02-closure-result.md)。本节不改写前述历史失败、串行重跑或 ignored 记录。
