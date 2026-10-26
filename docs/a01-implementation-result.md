# A01 / A03 第一批实施记录

日期：2026-10-25。依据产品能力设计/方案修订4；本次未提交，收尾HEAD为`da88ba7`（并行N2工作仍在推进）。本记录只覆盖本批代码和局部验证，不覆盖并行验收结论。

## 交付

- A01：新增可选Core管理client准备合同、Postgres原子创建/匹配/冲突与独立系统审计；配置摘要为版本化SHA256，不保存原始秘密。
- `prepare-management-client --config <path> --definition <path>`：唯一client_id来自配置；定义仅允许名称/回调集合；PublicDesktop、PKCE、无secret；冲突不更新。
- `prepare-management-client-audit --config <path>`：显式附加审计表准备，保持tenant_v6。P3及在线启动不运行DDL；旧参考seed保留。
- 准备模式只解析必要连接材料，保留完整结构校验；P4沿已有readiness后引用检查，补拒绝空字符串secret记录。
- [操作说明](a01-management-client-preparation.md)、[A03路由清单](api/route-inventory.md)。A03本批不生成OpenAPI或引入utoipa；已区分单域/租户router、动态装配、认证、Form/JSON及静态资源。

## 局部验证

| 检查 | 结果 |
| --- | --- |
| `pnpm --dir web build` | 通过；既有chunk大小警告，不提交生成物 |
| `cargo check --workspace --all-targets --locked` | 通过 |
| `cargo fmt --all -- --check` / `git diff --check` | 通过 |
| `cargo test --workspace --locked` | 通过：451 passed、0 failed、155 ignored；ignored不计验证通过 |
| App定向测试 | 35单元+2 CLI测试通过；无DB环境的17项显式数据库测试ignored，不计通过 |
| Core management_preparation | 1项通过：输入校验、模拟COMMIT已完成但回执丢失、重复匹配/异义冲突不覆盖 |
| Postgres live_access_bootstrap | 专用临时PG上8项通过，含3组新增A01测试；同/异定义并发、字段冲突、P2/有效管理员、审计失败回滚和错误布局 |
| 隔离宿主CLI与HTTP | P1 schema准备→P2夹具管理员→显式审计准备→P3 Created→重复AlreadyMatches→P4管理登录200→P5创建测试租户201（公开注册关闭） |

实库检查使用本任务独立PostgreSQL 18.6容器、回环端口、无数据卷及专用测试schema，没有使用既有项目数据库。测试宿主已停止，临时容器已删除。不同测试并发销毁schema曾触发现有catalog反射查询OID竞态；改为`--test-threads=1`串行schema生命周期后8项通过，单项内部的并发创建仍保留。不据此声称修复全仓catalog竞态。

## 边界

COMMIT-unknown证据是存储模拟，不是真实网络提交故障注入。此次P4/P5只覆盖Enabled Fixed0和token登录的一次受限准备，不代表完整P1–P6、浏览器组合或真实TLS验收。非默认schema/连接参数与SecretRef读取由配置测试及临时环境验证，真实CA/TLS服务器组合仍待相应验收。

未部署、未推送、未运行完整N2/M1-06；A02及其他产品能力仍未实施。既有README、M1-02复审及并行N2证据/permission-directory标签修改保留，不归入本次代码交付。

## 第一批完整复审（2026-10-25）

对照修订4与实际Core→Postgres、CLI→配置→启动引用检查链路复审。保留其他任务的N2脚本、前端及证据变更。本轮未扩大到A02、完整验收或部署。

| 问题 | 修复与补测 |
| --- | --- |
| 审计表自定义trigger/rule可吞掉INSERT，使client创建缺审计 | 事务内锁定审计表并拒绝改变插入语义的布局，核查审计插入恰一行；补吞写trigger/rule拒绝、真实审计PK失败全事务回滚 |
| 定义文件可为FIFO而阻塞 | 复用已有有界普通文件读取；真实CLI验证FIFO、超限、未知/重复字段、秘密不回显、退出2/4 |
| 原先只覆盖P3之间并发 | 新增实际在线ClientAdminService upsert与P3竞争；重跑原定义不能覆盖在线修改；COMMIT-unknown仍为明确的存储模拟 |
| P4/P5此前只有一次手工验证 | 新增Disabled/Enabled双模式自动化：缺client启动拒绝、无隐式审计DDL、Created/Matches/Conflict、P4只读启动、管理登录、无Bearer拒绝及P5受限业务client/租户准备 |
| A03上限、认证、条件与状态描述不准确 | 修正公共上限16 KiB、旧单域管理鉴权由宿主承担、Choose条件、设备router复用面、条件proof、注册/重发202；逐项核对实际handler与装配 |
| 方案引用不存在的trait简称 | 两份方案更正为现有TenantDeviceAuthenticationService，不改变A02设计方向 |

附加审计表不改变tenant_v6或强制旧宿主实现新trait；旧无参数seed、已有在线upsert语义保留。完整源文件、差异、路由字面量及本地链接/表格已核查；字面量检查仅用于发现遗漏，条件装配与安全语义仍按源码人工复核。

本轮验证：App 35项单元测试通过；Web build、workspace all-targets check、fmt/diff检查通过；Core定向1项、A01实库4项、在线upsert/P3竞争1项、离线真实CLI1项、双模式P3/P4/P5自动化1项均通过。实库用例内部保留并发，schema生命周期串行；仅使用本次专用临时PG，测试结束已删除容器。上文451项workspace结果属于第一批实施时记录，本轮未据此重复宣称全套测试重跑。真实网络COMMIT故障、完整N2/M1-06与部署仍未执行。
