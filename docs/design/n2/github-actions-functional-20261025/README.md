# N2 GitHub Actions实际功能补验证据

本批由需求方授权从冻结SHA `c304310d146ae916cbd89bad6168b96d3052db53`首次执行，限`CI-FUNC-ARM64-01`、八套功能选集及清理/证据门槛；不部署、不测缩放或旁白，不启动M1-03–06。无关修改保留。

当前为执行中的证据目录，任何queued/in_progress记录均不表示验收通过。实际环境、套件结果、清理、artifact哈希与有效到期时间须在终态后逐项核对。

- `remote-preflight.json`：执行前只读策略、ref与workflow注册。
- `transport-1-dispatch.json`：TLS握手失败及未出现对应运行的核查；不是实际产品补验失败。
- `first-dispatch.json` / `first-run-initial.json`：首次被GitHub接收的dispatch与实际run身份。
- `frozen-source-inputs.json`：与冻结提交逐文件核对的输入，不含本轮无关修改。
- `runs/<run-id>/`：各运行的API元数据、终态步骤及状态变化；首次失败与后续复验分别保留。

原始日志与下载包先置于本机0700受限临时目录；只归档已核对的公开metadata、脱敏证据和哈希，不复制私有夹具、env、profile、dump或认证信息。
