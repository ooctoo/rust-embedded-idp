# A01 管理 client 显式准备

本文说明修订4 A01 的局部准备流程。后续 A02A 已接通普通业务入口，见[第二批实施记录](a02a-implementation-result.md)；完整验收和部署仍独立。`embedded-idp-app` 是参考宿主，生产宿主可直接调用 Core 准备合同与 Postgres adapter。

## 准备顺序

1. P1：在目标模式下显式准备 `tenant_v6` schema。既有数据库按其升级说明迁移，不能通过本命令修复或清空。
2. 显式添加准备审计表：`embedded-idp-app prepare-management-client-audit --config /absolute/path/config.json`。这一步验证 schema/mode，不自动初始化管理员，也不修改在线 readiness 的版本要求；可在 P2 前执行。
3. P2：使用已有 `bootstrap-admin` 流程初始化管理员。该命令仍使用显式环境输入；按 [M1-02 §6.4](m1-02-configuration-composition-design-r2.md#64-显式准备的衔接) 从同一 JSON 的有效值映射命令专用临时环境，不维护第二份长期配置。必须指向相同数据库、schema、TLS/CA 和模式，结束后移除临时环境再执行新 JSON 命令。
4. P3：`embedded-idp-app prepare-management-client --config /absolute/path/config.json --definition /absolute/path/management-client.json`。
5. P4：配置 `business_entries: []`，运行 `embedded-idp-app --config /absolute/path/config.json`。启动在 readiness 后、开放监听前只读核对管理 client 与租户策略引用，缺失时拒绝启动。登录后进行受限 P5 业务对象准备，并显式选择注册开关。
6. P6：P5 准备完成后，加入普通 `business_entries` 并重启。A02A 支持普通 token/browser 入口；新配置的设备 proof、扫码及 OIDC 扩展仍待 A02B。

定义文件只包含：

```json
{
  "client_name": "IdP management console",
  "redirect_uris": ["http://127.0.0.1/management-callback"]
}
```

client ID 唯一来源是运行配置的 `management.client_id`。未知字段、重复字段、额外 client ID、secret 输入均拒绝；文件必须为普通文件且最多64 KiB，目录/FIFO等特殊文件拒绝。类型固定 PublicDesktop，PKCE 固定开启，无 secret。回调仅排序/去重，不自动改写 URI。

准备命令复用严格 JSON 配置结构、SecretRef、路径与数据库 TLS/CA 校验，但不打开签名密钥、不读取 SMTP 密码、不启动邮件或监听。准备时允许普通业务引用尚未存在；真实启动则核对全部入口引用。未知/重复字段和结构错误不会因准备模式放宽。

## 结果与恢复

| 退出码 | 含义 | 后续动作 |
| --- | --- | --- |
| 0 | `Created` 或 `AlreadyMatches`；审计 schema 命令成功 | 可继续下一独立步骤 |
| 2 | 参数、配置或定义不合法 | 修正输入；不输出秘密值 |
| 3 | `Conflict` | 现有记录不同，不覆盖、不删除；由管理员核查 |
| 4 | 数据库/准备状态失败或结果不明 | 核对连接、schema/mode、P2 和审计准备；以完全相同定义重试 |

创建与离线系统审计同事务提交；已匹配不重复审计。COMMIT 回执丢失后重试可能返回 `AlreadyMatches`，只说明当前匹配，不证明归因于上一次调用。P1/P2/P3 不是跨命令事务，失败不自动回滚此前成功步骤。

旧的无参数 LegacyReference 启动路径保留补缺 seed 行为；新 JSON 配置路径不运行该 seed。命令不提供匿名安装 HTTP API，不把普通运行时会话伪装为离线管理员。

## 局部验证范围

相关离线测试覆盖参数/定义拒绝、配置解析与启动能力分离、SMTP SecretRef 不解析、Core 合法性与创建/匹配/冲突；隔离 Postgres 测试另覆盖原子事务及并发。只有在明确提供隔离测试连接时才执行数据库验证，普通离线测试不连接数据库。P4 登录和 P5 对象准备的实际执行证据应单独记录，不能以单元测试替代，更不能据此宣称完整验收完成。

附加审计表必须保留本模块定义的普通持久表结构，禁止自定义trigger/rule等改变审计写入语义；不兼容时准备事务拒绝，不自动删除或修复用户对象。完整实施与复审证据见[第一批实施记录](a01-implementation-result.md)。
