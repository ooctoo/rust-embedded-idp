# N1 本地实现验收证据

2026-10-23。完整范围、失败尝试和未覆盖项见[实施回传](../../n1-implementation-result.md)，设计基线见[N1修订2](../../management-console-n1-id-compatibility-design.md)。

- [源码/制品与边界摘要](source-manifest.json)、[检查与环境](checks.json)、[真实宿主52项](host-run.json)、[夹具清理](cleanup-checks.json)。
- [B19](b/ui-b-results.json)、[N1专项11](n1/n1-browser-results.json)、[C27](c/ui-c-results.json)、[D42](d/ui-d-results.json)、[F96](f/results.json)，各目录的execution.json为对应命令记录；组数存在回归重叠，不合计为唯一总数。
- 首次宿主失败保存在[attempts](attempts/host-initial.json)；B与N1尝试保存在各自attempts目录，N1保留两份部分结果，不作为最终通过。
- [修订2补验](followup/README.md)：N1扩展26组、B19/C27/D42及Web111/bundle3；持续失败放弃关闭、dot-only租户离页和迟到响应专项，原记录保持不变。[初次源码摘要](attempts/source-manifest-revision1.json)保留历史hash，根目录摘要对应当前脚本。

全部来自隔离PostgreSQL18.6与编译后参考宿主、本机Chromium headless shell1243；本轮没有N2目标环境或部署验收。图片为合成数据实际运行样本，不是视觉最终签认或完整无障碍认证。私有凭据、夹具state/配置、URI、原始宿主日志与失败截图不公开归档。

报告修订2及提交前核对完成，随本批本地提交归档、未推送；归档范围与核对方式见[报告§8](../../n1-implementation-result.md#8-提交前核对与归档)。机器记录保留各自执行时状态。
