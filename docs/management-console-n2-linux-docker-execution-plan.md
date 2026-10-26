# N2 Linux Docker 补验最小执行方案

2026-10-25执行更新：需求方在方案本地提交后明确授权采用推荐组合准备环境并实际补验、发现问题先修复再复验。[执行报告](n2-linux-docker-execution-result.md)记录已完成的限定组合补验与证据；以下表格及§9–§10保留文档归档阶段的未执行语境，不能解读为撤销后续执行授权。生产/真实消费者/CI等范围不扩展，不推送、不部署，不启动M1-03–06。

| 项目 | 内容 |
| --- | --- |
| 版本 / 日期 | 修订1，2026-10-25 |
| 状态 | 完整复审及提交前静态核对完成，仅相关文档随本轮本地提交归档、未推送；推荐组合待后续执行批次确认，未准备环境、未构建镜像、未执行补验 |
| 编写与复审起点 | `codex/management-console-ui-b`，`8527b67ae9c1b32b6372f5bf5592bd16e6d606eb`；N2 Mac产品及证据提交 `e2c997524a1b8d516894591a3f6aeb54d4d93f9c`；本文最终归档提交以Git记录为准 |
| 依据 | [R02运行拓扑](validation-runtime-topology.md)、[N2设计](management-console-n2-target-validation-design.md)、[Mac报告](n2-mac-execution-result.md)与[最终复审（历史附件）](n2-evidence-archive.md) |
| 本轮边界 | 按最新授权仅完整复审、修正文档及本地提交；不改产品、工具、Dockerfile或CI，不安装、不拉取镜像、不启动容器/服务/浏览器、不运行补验、不推送、不部署，不启动N3–N5及M1-03–06 |

## 1 目标与结论范围

下一批以服务端运行组合变化为主：自动化和桌面Chrome留在Mac，Rust参考宿主由Mac进程改为Linux容器。先证明实际Linux制品、动态库、只读配置、内嵌资源、数据库连接和既有管理任务在该组合下成立，再安排GitHub Actions适配。工具链和浏览器版本变化须同时单列，不能假设此次只有服务端OS一个变量。

`embedded-idp-app`仍是开发/参考宿主。将其容器化只能取得H01的Linux运行工程证据，不能据此交付生产宿主、冻结生产架构，或代签H02外部同源宿主、H03真实Rust消费者、H04/H05真实React消费者。生产部署、TLS终止、生产数据库、容量、运维及A3验收另行安排。

本批不增加新业务入口，显式配置始终使用`business_entries: []`。旁白按需求方决定不测；Windows/Edge、Safari/Firefox、实体移动设备、系统高对比度、其他输入法及全站WCAG一致性均不自动加入。Mac原生IME/菜单缩放记录保留原证据范围，不写成Linux容器下已重新执行。需求方最终视觉签认单列。

## 2 未明确项与推荐选择

以下是供选择的执行建议，不是已确认的生产参数；本轮不要求先取得全部生产信息才能完成方案。

| 项目 | 首批推荐 | 选择理由与替代条件 |
| --- | --- | --- |
| 服务CPU架构 | **`linux/arm64`，Rust target `aarch64-unknown-linux-gnu`** | 沿已验证的Apple Silicon Mac架构，减少首批模拟变量。执行前核对Docker daemon/目标平台。若先明确生产为x86-64，则改为`linux/amd64` / `x86_64-unknown-linux-gnu`独立批次；Mac模拟运行须明记，不能算原生amd64验收 |
| 镜像系统 | **Debian bookworm / glibc** | 当前Postgres适配器依赖`native-tls`和OpenSSL，优先匹配构建与运行的发行版。首批不改成musl/Alpine、不替换TLS依赖、不追求最小静态镜像 |
| 构建镜像 | Web候选`node:22-bookworm-slim`；Rust候选`rust:1.93.0-bookworm` | Node主版本/pnpm遵循仓库声明；Rust先对齐Mac已验证的1.93.0，避免同时升级编译器。具体Node补丁、标签可取得性、平台manifest和digest在准备时核对并冻结；候选Rust标签不可取得时登记阻塞并提出替代，不静默换成latest |
| 运行镜像 | `debian:bookworm-slim`，补齐`libssl3`、`ca-certificates`及实际链接依赖 | 构建阶段配置`pkg-config`、`libssl-dev`及必要编译工具；运行镜像不保留Node、pnpm、Cargo或编译器。最终以Linux ELF及动态链接检查核定依赖，不从Cargo构建成功推导可运行 |
| 数据库镜像 | 候选`postgres:18.6-bookworm`，单独容器 | 与Mac补验18.6版本对照；准备时冻结平台及digest，不选择生产DB拓扑 |
| 构建模式 | **release、默认features** | 不启用`development-private-network-http`，不因容器网络使用受限开发登录替代完整Cookie会话 |
| 浏览器 | Mac已安装Chrome、headed；七套现有检查按原profile性质复用 | 执行前重新登记OS/build、架构和真实完整浏览器版本；若已升级，建立新环境行，不能沿用155版本的通过声明 |
| 网络/TLS | 首批仅Mac `http://127.0.0.1:<随机端口>` → 容器；PG仅专用Docker网络，测试库`tls_mode: disable` | 属本机隔离工程测试。非loopback入口须另备有效HTTPS；本批不引入反向代理，不放松生产TLS，不验证生产证书链 |
| CI | 本批不修改workflow；通过后优先评估复用现有Ubuntu CI | runner架构、浏览器及headless/headed另选，不能从当前`ubuntu-latest`推导N2已接入或CPU已选定 |

推荐先做单架构、单浏览器、单发行版，不一开始增加arm64/amd64双矩阵。若生产架构此时仍未知，可接受首批仅作为Linux arm64工程结果；amd64仍为未执行，不能作为已覆盖的生产目标。

## 3 最小运行拓扑与配置

### 3.1 夹具结构

每套独立测试夹具包含：1个专用Docker网络、1个PostgreSQL容器及其专属卷、2个随机schema、4个Rust app容器、专属只读配置/秘密挂载，以及Mac上的新建测试profile。各套串行执行、各自重建，四个app可在本套内同时存在。

Mac浏览器和API驱动只访问`127.0.0.1`的外部端口；app在容器内监听`0.0.0.0:8080`，发布为`127.0.0.1:<随机端口>:8080`。数据库不发布宿主端口，app使用专用网络内的PG服务名和5432端口；Mac侧独立数据库回读通过已核对所有权的`docker exec ... psql`完成。`0.0.0.0`、PG服务名、容器IP都不是浏览器origin。

驱动先选择外部端口并生成对应issuer/browser_origin，启动后核对Docker实际映射与二者完全一致；不从容器内8080端口推导外部origin。并发占用导致端口冲突时保留准备失败，清理本次部分夹具后重新生成；L05重建期间必须保持原端口，不能静默换端口后仍宣称原会话恢复通过。

| 夹具键 | 租户模式 / 登录策略 | schema | API外层前缀 / UI路径 | Cookie名建议 |
| --- | --- | --- | --- | --- |
| enabled | Enabled / Fixed `0` | 本套`uib_enabled_<随机hex>` | `/identity` / `/console` | `idp_ui_b_enabled` |
| disabled | Disabled / Fixed `0` | 本套`uib_disabled_<随机hex>` | `/gateway` / `/manage` | `idp_ui_b_disabled` |
| fixed | Enabled / Fixed `tenant-a` | 同本套enabled | `/identity` / `/console` | `idp_ui_b_fixed` |
| choose | Enabled / Choose | 同本套enabled | `/identity` / `/console` | `idp_ui_b_choose` |

每个app有独立外部端口和明确origin；同一hostname的Cookie不按端口隔离，必须保留上述不同名称及准确外部Path。N2共存专项使用同一普通持久化profile；其余套件保留原off-the-record上下文，不把两种profile结论合并。

另在启动冒烟中，以独立配置验证默认挂载`/api` + UI `/`，结束后移除；不要求第五个app贯穿七套浏览器检查。

### 3.2 配置生成合同

在线容器直接执行`embedded-idp-app --config /run/idp/config.json`，不通过仓库`dev_env.sh`或无参数legacy入口。下例仅展示enabled行的字段；占位符须由未来夹具生成器替换，app不会展开这些字符串，本轮不生成可运行配置。

```json
{
  "version": 1,
  "runtime": {
    "tenancy_mode": "enabled",
    "bind_addr": "0.0.0.0:8080",
    "issuer": "http://127.0.0.1:<外部端口>",
    "signing_key_file": "/run/idp/secrets/key.der",
    "postgres": {
      "connection": {
        "uri_ref": { "file": "/run/idp/secrets/database-uri" },
        "schema_name": "uib_enabled_<随机hex>",
        "tls_mode": "disable"
      },
      "pool": {
        "application_name": "idp-n2-linux",
        "max_connections": 4,
        "connect_timeout_secs": 5
      }
    },
    "http": {
      "browser_origin": "http://127.0.0.1:<外部端口>",
      "transport_policy": "default"
    }
  },
  "management": {
    "login_entry": "enabled",
    "client_id": "management-ui-b",
    "tenant_policy": { "kind": "fixed", "tenant_id": "0" },
    "mount_prefix": "/identity",
    "browser": { "cookie_name": "idp_ui_b_enabled" },
    "ui": { "base_path": "/console" }
  },
  "business_entries": []
}
```

其余三行只按表改变模式、schema、entry、策略、prefix、UI、origin及Cookie名称；不引入不存在的配置字段。在线环境不继承`EMBEDDED_IDP_APP_*`或`EMBEDDED_IDP_COMMON_ENV_FILE`等旧来源，以免显式配置冲突。URI文件无末尾换行；密钥为本套新生成的RSA至少3072位、PKCS#8 DER，不能读取项目`.local`或真实签名密钥。

app建议固定非root UID/GID `10001:10001`，根文件系统只读，配置与秘密只读挂载，必要`/tmp`用tmpfs；去掉额外capabilities并启用no-new-privileges，不挂Docker socket或整个仓库。启动使用exec形式直接运行app，不用shell包裹或无参数回退；建议启用Docker的`--init`转发信号和回收子进程，并记录有限停止超时。健康探测由本批驱动读取`/readyz`，不为此给运行镜像加入完整工具链。秘密可由一次性准备容器写入本套专属卷，目录0700、文件0400或0600、属主10001；在线只读挂载。须在实际Linux容器内核对可读性和权限，不能为解决Mac bind-mount属主问题放宽为0644。PG初始化使用官方镜像的既有用户流程，不照搬app的UID/只读根设置。

## 4 构建与夹具准备顺序（后续执行）

1. **冻结源码与制品输入。** 记录提交SHA、相关未提交差异及哈希、Cargo/pnpm锁文件、工具链和镜像输入。只将本批核对过的源码送入构建上下文，排除`.git`、`.env*`、`.local`、`target`、`node_modules`、旧dist、浏览器profile、历史运行秘密和证据原件；不上传无关工作区修改。生成资源必须在构建阶段从源码产生。
2. **核对并固定镜像。** 记录候选标签、索引与所选架构manifest digest、Docker/BuildKit版本及daemon平台；冻结后运行使用本地已取得镜像，不在测试过程中自动拉取更新。缺镜像或平台不可用记环境问题，禁止伪造digest。
3. **Web构建阶段。** Node 22，pnpm 10.30.1；先`pnpm --dir web install --frozen-lockfile`，再Web单测和`pnpm --dir web build`、`test:embedded-bundle`。Mac证据实际使用Node 24.19.0/pnpm 10.28.2，本方案对齐仓库声明，工具版本差异与资源新哈希须登记；失败不能直接归因为Linux运行问题。保留完整management和scan-code dist，Rust `build.rs`会同时读取二者；不能只复制management或复用Mac旧dist。
4. **Linux Rust构建阶段。** 在所选Linux平台的Rust镜像中构建，Web资源先复制到仓库对应目录。依次构建`cargo build -p embedded-idp-app --release --locked`及`cargo build -p embedded-idp-storage-postgres --example bootstrap_local_postgres --release --locked`；默认features。首批采用目标平台内原生编译，不只在Mac加一个`--target`后复制制品。记录`rustc -Vv`、ELF架构、动态链接及二进制哈希。
5. **分离运行与准备制品。** 最终app运行镜像只复制参考宿主及必要运行库/CA；另一个仅供本批使用的准备镜像带同次构建的bootstrap示例和app离线CLI。准备镜像不冒充生产镜像；两个制品都只保留本地，不推送registry。
6. **准备全新数据。** 创建本套网络/PG/卷，等待最终TCP就绪；一次性准备容器用明确env调用`bootstrap_local_postgres --access-schema`，分别初始化Enabled/Disabled当前`tenant_v6`结构。再用app的`bootstrap-admin --email ... --password-stdin`初始化合成管理员，密码通过私有输入流。离线CLI仍使用其现有env合同，与在线JSON进程严格分开；URI不放命令参数。不能误用示例的无参数legacy迁移/seed路径。
7. **按依赖建立客户端、启动宿主及准备测试关系。** 先通过本套PG的合成SQL在两个schema建立合法`management-ui-b`客户端，再启动enabled/disabled容器并等待readiness。随后使用enabled平台管理员真实登录所得凭据，通过受认证API建立`tenant-a`/`tenant-b`/`.`/`..`及成员/管理员关系，最后启动依赖这些租户的fixed/choose容器。准备成功后先通过API退出用于准备的临时管理会话，再结束准备容器；设备/分页等专项SQL seed另按各套脚本登记。写入只限当前随机schema；在线app启动只校验，不创建schema、补管理员或隐式补client，不用伪造身份头完成准备。
8. **运行、复验、清理。** 先完成下节L01–L05门槛，再跑七套用例。失败先保存证据并判断环境/工具/产品归属，修复后按受影响面复验，最后核对资源清理。若修复越出本批既有合同或涉及M1-03–06，记录阻塞和增量建议，不自行扩展。

不把基础镜像digest等同于完全可重现构建：APT安装的包版本也要登记，最终保留运行镜像ID、可取得的digest、包清单及ELF哈希。纯本地构建没有RepoDigest时如实记录，不虚构registry digest。

## 5 最小验收清单

所有行当前均为**未执行**。以下用例名与通过标准是计划，不创建空的“通过JSON”。历史用例组数量仅作对照，不能代替新运行结果或累计为唯一用例数。

| 编号 / 阶段 | 本批必须证明 | 证据与失败处置 |
| --- | --- | --- |
| L01 构建/架构 | Web先构建；app与bootstrap为所选Linux ELF；实际运行镜像架构匹配；动态库完整；最终镜像无编译工具、项目秘密和旧制品 | 构建日志、输入清单、ELF/链接/包清单、镜像ID和二进制/资源哈希；失败不进入功能补验 |
| L02 非root/挂载 | 10001运行、只读根/秘密、key权限正确；从容器内连接本套PG；外部只发布Mac loopback端口 | 脱敏用户/权限/挂载/网络元数据，不公开完整`docker inspect`或容器env |
| L03 四策略与默认挂载 | 四app readiness及登录成功；默认`/api` + `/`冒烟；非默认路径与实际JS/CSS、唯一可信meta、API地址一致；未挂业务入口 | HTTP状态、真实会话/目标回读、实际served assets哈希；资源能加载不等于会话通过 |
| L04 启动失败且不自修复 | 缺schema、缺管理员/管理client、坏key或key权限错误、配置来源冲突时明确失败且不监听、不补数据；非法非空business配置仍拒绝 | 使用独立破坏性夹具，前后数据库事实/计数及哨兵、端口探测和脱敏错误；不向本批加入业务装配能力 |
| L05 app容器重建 | 保持同一外部端口、issuer、entry/client、key和PG卷，停止并重建app后仍readiness；显式token与Cookie分别核对各自原有有效会话，原session截止时间不因启动重置；客户端配置和哨兵不被覆盖 | 前后会话相等/期限、DB与配置哈希、停止超时及退出结果。有限等待退出，不把SIGTERM退出码强制要求为0；若超时强杀/OOM等须单列并诊断，不能计作正常停止通过。即使恢复成功，也不据此宣称优雅排空、零中断或生产重启通过 |
| L06 会话安全专项 | `n2_mac`在Mac Chrome访问Linux app：四Cookie同profile共存，准确Path/host，单入口退出不串会话，伪造身份/目标拒绝；缺锁及存储读写/静默丢失失败关闭；双标签真实refresh串行 | 复用8组专项及普通持久化profile；真实与注入分别标注。生产HTTPS Secure Cookie与证书链不在loopback证据中 |
| L07 既有任务与恢复 | navigation、clients、authorization、security、n1、console六套完整运行；console显式设置`IDP_UI_N2_LAYOUT=1`，含七宽度/600高和两类320×150确认；登录/授权/保护规则、dot寻址、写后回读、未知结果、迟到响应、键盘、布局与确认恢复不回退 | 历史19/27/42/47/26/98组作基线；每套全新夹具。执行摘要回读布局开关；CSS zoom/视口采样与原生菜单缩放分别记录。关键安全失败不因其他套通过而豁免 |
| L08 修复与离线回归 | 如仅工具适配，检查工具失败/清理路径并跑既有5项离线检查；如有client或UI修复，增加能复现问题的回归，跑受影响Web/bundle/浏览器套件 | 修复前失败、修复后结果、源码/制品更新及复验映射。现有Web115/bundle3是Mac基线，不能记为本批已跑；Rust源码或跨层构建变化按风险扩大到仓库要求的检查 |
| L09 清理与汇总 | 每次失败/重跑均保留；本批profile、容器、卷、网络及私有文件有明确去向；实际资源匹配最终制品 | 逐对象清理回读；清理失败不记整套通过，保留恢复所需私有状态和安全说明 |

推荐顺序：L01–L05 → L06安全专项 → L07六套 → 必要修复/复验L08 → L09汇总。各次失败的现场先取证，再结束该套；禁止让失败夹具被后续用例复用或修改，掩盖原始原因。

L05只重建明确归属本批的app，不重启现有开发服务或共享数据库。PG卷贯穿本套app重建，整套结束删除；不把此测试扩展为生产备份恢复、数据库升级或运维演练。

## 6 工具适配范围与现有缺口

源码核对确认：当前`prepare_management_navigation.py`通过`target/debug/embedded-idp-app`启动Mac子进程，容器只承载PG；清理按PID/命令/config核对。`run_management_n2_mac.py`固定Mac Chrome和headed；`check_management_n2_mac.mjs`也直接使用该Chrome路径。这些都不是现成的Linux app容器执行器。

后续最小实施建议：

- 增加独立Linux Docker构建/运行/清理入口，复用现有fixture数据合同和浏览器断言，不改已归档的Mac运行事实；不要让旧的PID清理器处理app容器。
- 保留浏览器脚本依赖的`hosts`四键、`schemas`两键、`password`、`dir`、PG `container`等语义。PG继续兼容`idp-ui-b-<hex>`名称、`uib_<mode>_<hex>` schema及`idp.ui-b.fixture`所有权标记；全部新资源另加本批run/suite标记和精确ID。容器内部URI与任何Mac侧地址分开，不能把旧`db_uri`的loopback字符串照搬进app容器。
- Mac浏览器部分可复用当前七套检查；新增app容器ID、卷、网络、镜像与端口映射的私有登记。app启动/停止改走容器ID及所有权核对，失败和部分创建状态同样可恢复。
- 除既有5项工具离线检查外，新增Linux夹具的部分创建、端口冲突、容器/卷所有权不符、Docker不可达及停止/删除失败分支须有针对性的离线检查；不得用旧PID夹具的通过结果代替新容器清理逻辑的验证。本轮不编写或运行这些检查。
- 后续候选文件只限本批Dockerfile、严格构建上下文排除规则、Linux夹具/执行器和必要工具测试；本轮均不创建。优先扩展现有断言入口，不为N2建立通用部署框架、改变公共API或引入新的业务协议。
- GitHub Actions的浏览器路径、headless策略、工具版本和artifact处理另设下一批。本地Linux app + Mac浏览器通过，仍不等于Linux CI浏览器通过；当前workflow保持。

## 7 隔离数据与秘密

每套独立PG容器和命名卷，仅存合成账号/租户/client/授权/设备数据；两个schema随机生成。PG数据卷显式挂载`/var/lib/postgresql`，准备时回读实际PGDATA；不能照用17及以前的路径而遗留匿名卷。数据库用户/库可沿现有`uib`测试合同，密码每套随机，使用密码认证，不选择`trust`。

准备阶段先核对Docker context/daemon，拒绝把未知远程daemon当作本机隔离运行；网络、容器、卷、秘密卷/临时文件和profile均写入私有所有权清单。专用网络无共享生产容器，不使用host network；app能访问的PG身份只用于本套一次性库，不作为生产最小权限示例。

不读取项目现存`.env`、不连接日常或生产数据库、不复用真实账号/浏览器profile。私有目录0700、文件0600或更严；密码不进命令参数/构建ARG/镜像层/公开日志。bootstrap所需URI通过专属受限env文件或准备进程私有env提供，其inspect/log均视为秘密。线上app使用文件SecretRef；未约定的真实邮件、设备扫码和外部回调不调用。

每套初始数据必须相同且独立：B/navigation依赖初始dot名称，N1会修改对应实体，不能顺着复用同一后置数据库。准备失败时也立即登记已创建对象，不能因state未完整输出而遗失清理入口。

## 8 证据、清理与通过门槛

后续执行时才建立`docs/design/n2/linux-docker-<实际日期>/`，本轮不创建证据目录。建议归档：

| 记录 | 公开内容 |
| --- | --- |
| 范围/环境 | 实际Mac/Chrome/驱动版本、Docker daemon OS/CPU、容器发行版、Rust target/features、PG版本、浏览器profile/headed性质；生产与CI未选项 |
| 输入/构建 | 提交及相关差异哈希、lockfile、Dockerfile/排除规则、基础镜像平台/digest、包版本、二进制和内嵌/实际服务资源哈希 |
| 执行 | 按suite和attempt独立目录；开始结束时间、脱敏命令、exit code、每项结果、真实/合成/注入标记及安全回读 |
| 问题/复验 | 首次失败、归因、修复diff/哈希、复验范围与结果；历史失败不覆盖，不将失败exit改成0 |
| 清理/结论 | 对象别名与所有权核对、停止/删除/不存在的回读、私有现场是否保留、残留及恢复责任；逐环境通过和未覆盖 |

原始HAR/trace、完整headers、Cookie/token、密码、数据库URI、私钥、原始宿主日志、浏览器profile、含env的完整inspect和秘密卷均留在私有受限区，不直接归档。数据库回读只公开必要业务字段、状态或相等性，不公开凭据/refresh摘要。截图使用合成页面，公开前扫描秘密及home/repo/tmp等私有路径；源码/公开制品哈希可保留，秘密文件不进入公开摘要。

清理顺序：浏览器/会话仍可操作时先退出本批测试会话，再关闭context/profile → 停止/移除四app及准备容器 → 移除本批PG → 删除精确记录且所有权匹配的数据/秘密卷 → 删除无端点的本批网络 → 确认profile已关闭后删除 → 最后删除不再需要的私有目录。故障场景退出失败须记录，不因此放弃后续可独立完成的清理。逐对象使用ID和label核对，不能只凭名称前缀或做全局prune；若任何数据库使用容器未确认停止，保留其依赖的PG/卷/秘密及恢复状态，不沿依赖链继续删除。失败时继续处理其他独立对象。Docker不可达不等于对象不存在。

本批构建缓存默认保留并明确登记，不计作运行夹具；无秘密的本地验收镜像可保留用于复现，记录ID及用途。若删除，仅处理本批创建且未被其他容器使用的精确ID，不清除共享基础镜像或共享缓存。公开证据及历史失败永久保留于版本化目录，不能随私有夹具删除。

只有推荐组合在后续明确采用、L01–L09适用项有证据、安全/任务阻断问题关闭且清理回读完整，才可声明“所列Linux架构运行镜像 + Mac Chrome + H01通过”。缺镜像/权限属于准备阻塞；产品失败、工具失败和未执行分别登记，不能互相覆盖。非安全差异须记录影响和接受依据；旁白不重新成为完成条件。整体N2、真实消费者、另一CPU架构、生产浏览器、GitHub Actions及生产上线继续单列。

## 9 本轮静态核对与后续入口

本方案对照了README/CONTRIBUTING、app配置/CLI/build.rs、PG适配器依赖与bootstrap示例、Mac夹具/执行器/浏览器专项、N2设计/最终收尾及现有CI。核对发现的是容器执行入口、平台/镜像冻结和容器所有权清理的工程缺口，没有据此宣称产品缺陷或新增验收通过。

编写阶段已完成JSON示例语法/关键字段、L01–L09编号、四份本轮文档的相对链接及diff空白静态检查。本次按新增授权完整复审、修正并本地提交，仅限本文、README、R02拓扑及交付总结四份文档；不执行文中命令，不盘点Docker运行态、不准备或启动补验。无关`docs/m1-02-code-review.md`修改保留。后续推荐先确认§2的单架构组合，再准备最小构建/容器工具，依§4–§5执行；本次文档提交授权不延伸为环境准备或产品修复授权。

镜像技术依据于2026-10-25查阅官方资料：[Docker多平台构建](https://docs.docker.com/build/building/multi-platform/)说明目标架构与模拟/原生执行的差异；[多阶段构建](https://docs.docker.com/build/building/multi-stage/)和[构建最佳实践](https://docs.docker.com/build/building/best-practices/)支持分离构建/运行及固定digest。[Rust](https://hub.docker.com/_/rust)、[Node](https://hub.docker.com/_/node)、[Postgres](https://hub.docker.com/_/postgres)官方镜像页供候选标签和准备时的平台核对；[Debian bookworm libssl3](https://packages.debian.org/bookworm/libssl3)供运行依赖核对。本文未查询registry manifest或实际拉取，候选与digest待准备阶段实证。

## 10 完整复审与本地归档

2026-10-25，对照R02、Mac最终收尾、README/CONTRIBUTING、配置/CLI/启动校验/资源构建、PG依赖与bootstrap、现有夹具和七套脚本及CI完成全文复审。修正：

| 事项 | 文档修正 |
| --- | --- |
| 准备依赖次序 | 明确先SQL建立管理client，再启动平台/Disabled宿主，通过真实平台API准备租户，最后启动Fixed/Choose；准备会话退出单列 |
| 布局复用前提 | 明确`IDP_UI_N2_LAYOUT=1`及七宽度/短确认采样；自动CSS zoom不冒充原生缩放 |
| 容器重建边界 | 增加实际端口映射核对、建议`--init`与有限停止超时；token/Cookie按各自会话核对，强杀不冒充正常停止 |
| 清理依赖 | 先退出会话再关闭浏览器；未确认停止时保留依赖的PG/卷/秘密；新增容器工具不能仅继承旧PID工具测试结论 |
| 版本与归档状态 | 明确Node/pnpm对照差异、编写基线与最终归档的区别；四份本轮文档同步最新本地提交授权，其他推荐和生产待定项保持 |

`--init`用途对照[Docker run官方参考](https://docs.docker.com/reference/cli/docker/container/run/#specify-an-init-process)：仅用于信号转发和子进程回收，不等于app已实现优雅停机；源码当前直接调用`axum::serve`，本轮不新增信号处理。

提交前重新核对JSON示例字段、编号、相对链接、diff空白及实际暂存清单。没有运行构建、测试、容器或浏览器，没有新增产品验收证据；本轮未发现阻断文档归档的剩余确定性偏差。只提交上述四份文档；无关审查文件内容对象保持`4ef4907646970f1cd06ec80cf51a9516497244d6`。不推送、不部署，不启动N3–N5及M1-03–06。
