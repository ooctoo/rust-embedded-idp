# N2 Mac 子批证据（2026-10-24）

范围和判定以[执行报告](../../../n2-mac-execution-result.md)为准。仅B03/H01当前组合；旁白由用户移出，追加真实中文IME组合及执行者视觉复核已完成，需求方最终签认单列。不把控制的Chrome profile、原生菜单缩放、合成响应注入或历史实库结果混为同一层证据。

- [review-closure/](review-closure/README.md)：提交前完整复审、第三项刷新恢复修复、异常清理及断言/脱敏收尾、最终复验和提交范围。当前最终源码/制品以此目录为准，原首轮/IME摘要是复审前快照。诊断脱敏保留变更前后哈希，不更改失败原因或通过结论。

- [ime-visual-followup/](ime-visual-followup/README.md)：9组真实简体拼音补验、20张新页面截图、上一轮截图复核、独立中文回读与新增夹具清理；没有产品代码变更。原始失败/运行记录保持，机器汇总另指向本次追加结果。

- `initial/`：修复前六套19/27/42/47/96/26组完整结果与截图。
- `supplement-attempt1/`、`supplement-attempt2/`：Close助手定位失败及storage-get产品问题，均保留不完整结果与诊断。
- `final/`：重建后的B/C/D/E/N1完整结果，以及两个未完成的专项/F尝试，不能将其总进程exit1改称全批通过。
- `final-followup/`：修正初次restore=401处理后N2专项8组；修正滚动观测后F98组完整执行。
- `persistent-profile/n2_mac/`：专项在普通持久化profile中再次8组完整通过，并删除6个自建profile。与其他off-the-record上下文分列。
- `native-before-fix.json`、`native-final.json`：真实Chrome菜单百分比、CSS视口/DPR、键盘与刷新记录；`assets/`为实际合成数据页面截图。
- `source-manifest-initial.json`、`source-manifest-final.json`：源码、锁文件、Web/嵌入包和宿主制品摘要，最终为本地未提交快照。
- `native-readback-and-served-assets.json`：原生操作后独立客户端回读及四入口实际JS/CSS摘要。
- `build-and-unit-checks.json`、`build-attempt1.json`、`storage-regression-before.json`和安全文本日志：构建、113项Web、3项bundle、修复前两项真实负例失败及命令归属失败。
- `cleanup.json`、`summary.json`：执行汇总、所有权清理与复核。

主批可复跑：

```sh
IDP_UI_N2_LAYOUT=1 python3 scripts/run_management_n2_mac.py \
  --image postgres:18.6 --playwright /absolute/path/to/playwright/index.mjs \
  --output /new/evidence/directory \
  --suites n2_mac console navigation clients authorization security n1
```

须先构建Web和Rust参考宿主及storage crate的bootstrap示例，使用已安装的桌面Chrome、已安装的PG镜像与Playwright模块。脚本不拉取镜像、不读取项目.env；每套新建隔离夹具并核对所有权清理。不能覆盖本目录的失败/历史证据。真实菜单缩放/原生刷新由CUA单独操作；此命令不宣称自动完成中文IME、人工视觉或其他OS/宿主验收。

公开附件没有Cookie/token值、密码、私钥、连接URI、HAR/trace、真实用户profile或宿主原始日志；仅合成数据与必要脱敏错误。生成bundle和依赖目录不入库。
