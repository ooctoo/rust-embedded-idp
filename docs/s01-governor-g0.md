# S01 governor G0 复用核查

2026-10-26。选定已发布`governor = 0.10.4`，MIT，`default-features=false, features=[std]`；不启dashmap、quanta、jitter。尚未加入产品依赖时先在`/private/tmp/idp-governor-g0`完成独立编译和FakeRelativeClock burst/补充探针，Rust1.93/macOS arm64通过。最终产品Cargo.lock/feature合并图仍须在接线后再次核对。

发布包SHA-256：`9efcab3c1958580ff1f25a2a41be1668f7603d849bb63af523b208a3cc1223b8`。包内`.cargo_vcs_info.json`对应上游commit `9f3a79dd47dd32acd589c562b8d4fefe99b93372`，路径`governor`。API与释放语义参考[官方文档](https://docs.rs/governor/0.10.4/governor/struct.RateLimiter.html)和发布包源码；仅复用其速率算法，容量/来源可信性/多维策略仍由本项目负责。

std-only的DefaultClock为MonotonicClock；适配器使用显式clock类型，避免未来features统一启用quanta改变内部假设。探针验证2 burst耗尽拒绝及单调时间推进后恢复，不把纯算法测试当网络保护验收。包未声明rust-version，不能据此给出MSRV兼容承诺；未运行目标Linux交叉构建。

发布crate未携带独立LICENSE文件，必须依据同commit的[上游LICENSE](https://github.com/boinkor-net/governor/blob/9f3a79dd47dd32acd589c562b8d4fefe99b93372/LICENSE)补发行归属，不能只保留SPDX一句。源码不复制/fork。

## 临时探针依赖许可证

实际`cargo metadata --filter-platform aarch64-apple-darwin`：governor/slab为MIT；nonzero_ext为Apache-2.0；foldhash为Zlib；其余allocator-api2、cfg-if、equivalent、futures系列、hashbrown、libc、lock_api、parking_lot/core、pin-project-lite、portable-atomic、scopeguard、smallvec、spinning_top、web-time均为MIT或Apache-2.0选择许可（旧字符串MIT/Apache-2.0按上游原文记录）。未新增原生TLS库。

该列表是隔离探针解析结果，不是最终产品依赖版本清单。发布前仍需保留所选许可文本和NOTICE并依据最终锁文件更新发行清单；本次不做软件发布。

上游同commit MIT许可文本已按官方原文保存至[发行归属副本](third-party/governor-LICENSE.txt)。HTTP错误分类直接复用锁文件已有http-body-util 0.1和测试http-body 1，不复制HTTP body实现。
