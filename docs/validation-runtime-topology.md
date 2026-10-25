# 开发、自动化与生产运行拓扑

日期：2026-10-24。决策R02，依据需求方对执行位置的最新说明。本文确认各层的位置与当前验收范围；N0/N2修订2中的执行矩阵保留为历史设计，当前安排按本记录及[N2 Mac执行报告](n2-mac-execution-result.md)理解。

R02优先说明执行位置、当前Mac批次和生产运行方向；原有产品/安全合同、N2适用断言、证据分级及未覆盖项继续有效。R01浏览器目标保留为历史记录，生产支持范围待明确，不把整份N0/N2设计或安全要求一并作废。

## 已确认的位置

| 层次 | 当前开发/测试 | 后续安排与边界 |
| --- | --- | --- |
| 自动化工具 | 本机Mac | 未来将本套自动化接入GitHub Actions；N2所用runner的OS、架构、浏览器和图形会话方式尚未指定 |
| Rust服务 | 开发阶段直接运行在Mac | 生产目标为Docker镜像，在Linux上运行；镜像基础、CPU架构和部署参数另定，不据此宣称生产容器已验收 |
| 被测浏览器 | 当前测试阶段在Mac；已完成的具体组合为本机桌面Chrome，见Mac报告 | 生产使用者的OS和浏览器尚不确定，不能从当前测试环境推导生产浏览器支持列表 |
| 测试数据库 | 本次Mac补验采用本机Docker中的隔离PostgreSQL夹具 | 这是测试夹具的选择，不替生产数据库位置或其他嵌入宿主作决定 |

仓库现有[CI](../.github/workflows/ci.yml)使用`ubuntu-latest`；这不等于本套N2浏览器自动化已经接入，也不预先确定未来N2 job必须使用哪种runner。本次不修改workflow或准备CI运行环境。

## 对N0/N2执行计划的影响

1. **当前围绕Mac完成浏览器验收。** 自动化及Rust开发服务均可在Mac执行，不要求先准备Windows自动化工具、Windows Rust服务或跨机器Windows测试入口。
2. **GitHub Actions作为后续工程自动化环境单列。** 复用功能/安全用例时登记实际runner、Rust target、容器、浏览器和headless/headed模式。CI中的自动检查不能代替Mac系统拼音、真实菜单缩放等原生操作证据；若浏览器在Linux runner运行，所得是该Linux浏览器组合的证据。
3. **生产Linux Docker运行验证单列。** Mac开发进程与Linux镜像是两个服务端运行组合；镜像中的Rust制品须匹配Linux及目标CPU架构，后续以实际镜像、配置及服务运行取得对应证据。本文只固定目标方向，不启动打包、部署或生产验收。
4. **生产浏览器矩阵待确定。** R01中的Windows Chrome/Edge和Mac Chrome目标记录保留；本次执行位置说明不将它们直接视为已冻结的生产支持清单，也不宣称取消或已经通过Windows支持。Windows相关准备不阻塞当前Mac批次，后续是否必验、版本和优先级随实际支持范围明确。服务端运行在Linux也不自动增加Linux桌面浏览器支持。

功能和安全合同跨环境保持统一；差异记录用于说明证据在哪个组合上成立，而不是另做Windows/Mac两套业务实现。Rust服务OS、自动化运行机OS、被测浏览器OS分别登记，三者不要求相同。

2026-10-25后续方案：[N2 Linux Docker最小执行方案](management-console-n2-linux-docker-execution-plan.md)提出先以Linux arm64、Debian/glibc及Mac Chrome验证H01参考宿主的容器运行链路。完整复审修正准备依赖、布局开关、容器重建及清理边界，按新增授权仅四份相关文档本地归档、不推送。架构/镜像为下一批推荐，未冻结生产参数；未准备环境、打包或执行，不改产品/工具/CI、不部署、不启动M1-03–06，不改变本文R02的证据边界。

## 当前交付边界

N2 Mac代码、复验及证据已在本地提交`e2c997524a1b8d516894591a3f6aeb54d4d93f9c`归档。当前生产浏览器范围、未来N2 CI组合、Linux镜像的具体运行验收及真实嵌入消费者仍单列；不能把这些待定项改成失败或通过，也不据此否定已完成的Mac限定结果。

旁白仍按需求方决定不测。本次仅补充拓扑决策和文档入口，不改产品、测试脚本、CI或既有证据。按最新授权，完整复审与提交前静态核对后，仅本轮相关文档随本地提交归档；不推送、不部署，不启动M1-03–06。

## 2026-10-24拓扑文档复审范围（历史批次）

复审包含本文、[README入口](../README.md)、[交付总结](management-console-delivery-summary-and-plan.md)、[N0支持基线](management-console-n0-support-baseline-design.md)、[N2补验设计](management-console-n2-target-validation-design.md)及[首批计划](management-console-n2-options-and-first-batch-plan.md)的新增说明，共六份相关文档。核对最新范围、R01/R02关系、现有CI配置、相对链接及差异/提交范围；原修订2正文和N2 Mac运行证据保留，不把静态文档复审记为新产品验收。无关的`docs/m1-02-code-review.md`工作区修改不纳入本次提交。
