# 账号安全收据与恢复加密：局部实施结果

2026-10-26。在唯一工作分支继续实现；先完成详细设计与独立复核，修正存储key ID遗漏、start receipt位置及handle定位循环后编码。该切片仅提供加密端口与适配器，不代表撤销/改密/密码恢复已经贯通。

## 已完成

- Core `AccountSecurityCrypto`、固定purpose/context、版本化digest/envelope、固定错误与脱敏Debug。
- Security `RingAccountSecurityCrypto` 和 `AccountSecurityKeySet`；复用已有ring/base64ct，无新依赖。独立密钥、部署/用途/对象绑定、精确current/previous选钥、有界输入、随机token/code、稳定邮箱预算摘要。
- API嵌入合同、存储草案中各digest key ID与独立start receipt的生命周期补充。
- 独立代码复核未发现阻塞；主代理实际源码/变更复核修正trim后长度检查与多余key副本，补齐已知错误key ID、related UUID具体字节和边界测试。没有新增通用加密框架或替换注册专用adapter。

## 验证

- Security crate全部31项lib测试通过，含新增8项安全crypto测试；Core新增1项脱敏测试通过。日志 `/private/tmp/idp-account-security-crypto-tests.log`。
- 最后补充related UUID变化测试后，8项crypto测试重新通过；日志 `/private/tmp/idp-account-security-crypto-reviewed.log`。过滤掉的集成测试不计为执行通过。
- `cargo check --workspace --all-targets --locked --offline`通过，日志 `/private/tmp/idp-account-security-crypto-check.log`。仍有既有注册测试夹具的2条unused警告和尚未接入持久消费者的security_email的10条unused警告，未隐藏。
- `cargo fmt --all -- --check`、`git diff --check`通过。此前8个未跟踪测试文件SHA-256与保全manifest完全一致。

## 待推进

消费者的确定性command编码、持久收据/恢复flow/outbox、资格判断、猜测预算、单次消费、TTL清理、宿主密钥供应/轮换检查及HTTP/Web仍需各自设计复核后实现。当前不新增HTTP路由，故本切片无OpenAPI制品变化。下一批优先冻结安全写和receipt精确存储合同，再实现会话撤销与改密；随后恢复outbox/worker和邮箱恢复及安全页。

没有执行完整验收、真实库迁移、生产SMTP、部署、提交或推送。当前一期总体退出门槛尚未完成。
