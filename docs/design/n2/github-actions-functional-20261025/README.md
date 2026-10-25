# N2 GitHub Actions实际功能补验证据

本批由需求方授权从冻结SHA `c304310d146ae916cbd89bad6168b96d3052db53`首次执行，限`CI-FUNC-ARM64-01`、八套功能选集及清理/证据门槛；不部署、不测缩放或旁白，不启动M1-03–06。无关修改保留。

最终run `40191248439`、SHA `14dd9199094464a1f7368e9c95f5c29e7a5354c7`在限定H01/CI组合通过：八套264组、0缺失，清理、下载artifact哈希、publication及有效到期时间均完成独立核对。前六次失败原样保留，排队和离线检查均不代签实际验收。完整过程见[执行报告](../../../n2-github-actions-functional-execution-result.md)。

- `summary.json` / `evidence-manifest.json`：最终限定结论、运行历史和本目录精确文件哈希（含原始ZIP及通用规则忽略的公开日志）。
- `remote-final-readback.json` / `private-cleanup-review.json`：远端终态与本机私有临时材料清理。
- `ci-timing-review.json`：实测耗时和分层建议，仅分析，未改CI。
- `remote-preflight.json`：执行前只读策略、ref与workflow注册。
- `transport-1-dispatch.json`：TLS握手失败及未出现对应运行的核查；不是实际产品补验失败。
- `first-dispatch.json` / `first-run-initial.json`：首次被GitHub接收的dispatch与实际run身份。
- `frozen-source-inputs.json`：与冻结提交逐文件核对的输入，不含本轮无关修改。
- `runs/<run-id>/`：各运行的API元数据、终态步骤及状态变化；首次失败与后续复验分别保留。
- `runs/<run-id>/artifact-original.zip`：从GitHub下载的原始公开附件；SHA256与API digest一致。
- `runs/<run-id>/artifact/`：完整解压的公开payload，保留publication封存的原始字节，包含被通用Git规则忽略的构建日志。
- `runs/<run-id>/artifact-verification.json`：下载digest、精确文件集合/哈希、秘密扫描和API实际到期时间；不改写封存附件中的待审阅expiry字段。
- `runs/<run-id>/independent-review.json` / `frozen-validator-review.json`：执行SHA、259份构建输入、43份工具输入及覆盖/清理核对；prepare失败尚未构建时明确不适用。
- `permission-label-fix-review.json` / `final-source-review.json`：产品单属性修复、工具错误路径及完整源码差异复审。
- `signed-repair-commits.json`：修复/诊断提交的本地签名及路径范围核对。
- `probes/`及`*-browser-probe*.json` / `*-click-probe*.json`：本机合成DOM、基础AntD弹窗和真实权限目录组件的定位证据；含阴性结果及修复前后源码哈希，不代替CI真实宿主结果。
- `review-scripts/`：执行/复审工具的脱敏源码快照及可离线重放的冻结版本校验器；不执行浏览器、Docker或数据库。

原冻结SHA的首次失败、驱动解析修复、刷新等待修复、两次按钮诊断、产品修复及控制台收尾修复后的完整复验分别保留。八套固定为264组选中功能断言、13组明确排除；历史重复运行不能相加成唯一覆盖数。

可在仓库根目录离线重放某个完整运行的校验：

```sh
python3 -B docs/design/n2/github-actions-functional-20261025/review-scripts/verify-frozen-evidence.py \
  docs/design/n2/github-actions-functional-20261025/runs/<run-id>
```

校验器从该run的Git SHA构建临时验证上下文，检查43份工具输入、publication及完整八套证据；已生成工具清单的失败run输出`not_complete`。首次prepare失败未生成工具清单，见其独立核对记录。它只更新封存payload之外的`frozen-validator-review.json`，不改artifact，不引用工作区中的并行改动。

原始日志与下载包先置于本机0700受限临时目录；只归档已核对的公开metadata、脱敏证据和哈希，不复制私有夹具、env、profile、dump或认证信息。

最终收尾报告和本目录新增证据随本轮相关本地提交归档，实际归档SHA见Git记录，未新增推送；六个修复提交已按此前授权签名推送。归档提交不改变实际执行SHA。私有临时目录只在全部公开ZIP及payload复核后清理，结果见`private-cleanup-review.json`。

开源仓库/参考应用与下游生产集成职责、CI提速方案及暂停边界见[当前复审](../../../ci-speed-minimal-implementation-plan.md)。既有运行payload与原始ZIP不因后续职责澄清而改写；原closing-document-review记录此前尚未提交的审阅时点，最终归档范围另见本轮方案复审记录。
