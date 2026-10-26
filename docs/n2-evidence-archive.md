# 旧N2附件的Git历史追溯

2026-10-26：N2独立编排已退役。用户进一步要求删除无继续使用价值的保留项，因此旧截图、日志、构建输入快照、重复结果和原始/解压ZIP不再随当前工作树保存。移除前共有1055个已提交文件，文件内容合计21,457,368字节（目录磁盘占用约23 MB）。没有改写Git历史。

## 仍有用途的内容

- 普通CI继续使用Playwright锁文件、共享进程清理与管理页面fixture；它们不是闲置N2工具。
- Mac、Linux Docker、GitHub Actions的验收结论保留在原报告中，只适用于其记录的SHA和环境。历史链接现在指向本说明，不能把它当作当前附件或新验收通过。
- 当前CI分层与N2退役的最小结果摘要仍保留，供追溯必要回归和最近修复；不再逐轮保存大批截图和ZIP到Git。
- A02B/A04/A05等未提交产品修改不属于旧N2垃圾文件，不在本次删除范围。

## 查找原始材料

删除前的完整文件树位于本地提交`1a23b715f666aad53e8dc7f6eb6428bd3ca22714`。先列出历史路径，再读取需要的单个材料；原报告的历史版本也保留了精确附件链接。

```sh
git ls-tree -r --name-only 1a23b71 -- docs/design/n2
git show 1a23b71:docs/design/n2/github-actions-functional-20261025/summary.json
git show 1a23b71:docs/n2-github-actions-functional-execution-result.md
```

这只是已有Git记录的检索方式，不增加下载、远端Actions或测试步骤。当前执行范围见[CI设计](ci-quality-design.md)、[覆盖映射](ci-quality-coverage.md)与[N2退役记录](n2-retirement-implementation-result.md)。
