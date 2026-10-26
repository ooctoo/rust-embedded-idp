# A02B-B3 实施方案与方案复核

日期：2026-10-25。技术权威：[详细技术设计](a02b-b3-technical-design.md)。先设计、double check、再编码；2026-10-25已由独立审查者逐项对照Core构造器、source_current、HTTP配置、result AAD/keyring及cleanup源码，再由主代理复核；未发现未解决阻断，允许进入编码。不以方案通过代表实现完成。

## 实施顺序

1. 对现有B2增量独立审查并追踪真实调用链，记录确认的问题/已排除的误报；不为假设性风险改协议。
2. 主代理完成B3配置、同client来源/目标模型、provider边界、keyring、任务停止和合同设计；独立审查者按源码复核，主代理处理结论；未解决阻断项前不编码。
3. 配置及keyring加载：scan typed对象、严格静态检查、相对路径、私有32字节key读取、已有cipher；新增针对性测试。只在v2开启。
4. 装配及UI：普通source browser与proof-required target分开构造，增加scan purposes、两个router族、每请求短期hostcontext，参考页面参数化。保留Legacy行为和范围说明。
5. 清理生命周期：有界job列表、顺序到期执行、失败重试、启动顺序、SIGINT/SIGTERM、停止/drain超时，补取消和无重叠测试。
6. A03同步独立18操作合同及制品生成器/漂移检查，复核真实DTO/headers/错误状态/条件挂载；不改Core wire。
7. 先局部单测/build，再隔离数据库的B3宿主流与直接受影响Legacy/B2回归；修复后再次核对实际diff及简洁性，记录未覆盖项。删除仅本轮创建的测试容器/卷。
8. B3完成后才细化下一项A04的详细设计和实施方案；A04通过double check再编码；A05同样处理。候选安全/联邦增强在对应阶段先固定消费者和范围，不自动一次引入所有库。

## 文件责任

- 主代理：composition_config.rs、bootstrap.rs、scan组合模块及架构/安全/最终集成；不改变Core事务算法和DB结构。
- 有界任务可委派：main生命周期及独立cleanup模块、scan_ui.rs参数化、openapi.rs/合同测试/导出脚本、独立宿主测试。派工前给出本文固定决策；多人不得覆盖同一文件，所有候选结果由主代理实审。
- 不改并行CI/N2文档或脚本，不自动提交、推送、部署或全量产品验收。

## Double check清单

| 项目 | 检查方法 | 状态 |
|---|---|---|
| source与target职责 | 对照Core构造器、source_current、B2 refresh与browser TTL | 双重源码复核通过 |
| provider与proof | 对照ScanLoginAdmission、presentation、十个purpose和raw-body配置 | 双重源码复核通过 |
| 持久隔离及keyring | host_scope+entry+tenant/client、AAD、旧key恢复与无随机fallback | 双重源码复核通过 |
| 后台生命周期 | 顺序有界工作，取消不得谎称停止blocking SQL | 双重复核通过；HTTP/cleanup并行drain，总等待为较长者加runtime 5秒 |
| 路由及UI | 实际mount/Cookie path、verification URI、脚本安全编码 | 方案双重复核通过；两入口实际HTTP页面与资产测试通过 |
| 兼容和许可证 | v1拒绝scan、Legacy保留、当前依赖/feature实际许可 | 方案复核通过；signal-hook-registry 1.4.8已锁定并核对MIT OR Apache-2.0 |

## 测试与退出

采用仓库现有命令：Web build先于Rust host；cargo fmt/check；app/axum/core目标单测；合同脚本；真实测试仅显式专用PG URI、随机schema、串行运行指定用例。新配置成功和失败两侧均验证。每项记录真实结果，不以编译或静态schema替代协议成功链路。未完成项保留明确状态。

退出须同时满足：上述设计复核无未解决阻断；所选B3配置真正可运行；两入口隔离及Pending交付/恢复/取消、密钥重叠和cleanup停止有局部证据；合同无漂移；实施记录与剩余边界一致。

局部实现复核修正：Axum现有nest挂载的UI规范地址是不带尾斜杠的`/ui`，与Legacy一致；配置、设计与测试已统一该地址。扫码proof profile直接复用Core `SCAN_LOGIN_PROOF_PROFILE`（`EMBEDDED-IDP-DEVICE-SCAN-V2`），不另定义V1协议。

停止路径实现复核：真实SIGTERM链路发现同步Postgres连接析构在Tokio上下文调用内部runtime，导致exit 101。对照postgres connection/drop与app Router生命周期确认；修复采用在主线程保留Router clone，runtime.shutdown_timeout之后释放服务树，避免改动数据库适配器或另建池。复核后实施，并用同一真实信号测试回归。

实施收口：配置/组合/生命周期/合同及所选局部测试完成，结果见[B3实施记录](a02b-b3-implementation-result.md)。正常SIGTERM通过；超时慢DB故障注入、实体设备及完整验收仍未执行。A04/A05下一批继续先细化设计与double check，本批未编码。
