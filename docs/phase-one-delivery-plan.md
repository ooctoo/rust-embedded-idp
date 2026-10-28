# 第一期安全基础版交付计划

2026-10-26；用户已明确选择安全基础版及分批局部/集成测试。工作基线为唯一工作分支`codex/registration-physical-timeout`的`7b981a6`，不在main开发。

## 已冻结范围

交付A01–A05现有能力，加S01防滥用、最小O01a安全事件/邮件outbox、S03本人会话查询与撤销、改密及密码恢复。MFA/WebAuthn/TOTP、企业身份联邦、邀请/机器身份/组、外部Webhook、原生设备安全存储及跨进程锁不进入第一期。本期仍不代表生产宿主已经部署。

每个切片必须先完成详细设计、实施计划、独立复核并记录修正，再开始对应代码。跨切片共用已有合同和事务；注册邮件runtime已在分支中，先审查复用，不能另建重复投递栈，也不能把注册专用表直接当作通用密码恢复表。保持tenant_v6兼容，新增安全状态使用显式可选扩展及迁移，不在在线启动自动创建。

## 实施顺序和退出门槛

| 顺序 | 切片 | 第一期间必须闭合的结果 |
| --- | --- | --- |
| 1 | S01-A 共享工作预算接线 | 参考宿主的多业务入口、管理与browser共用密码预算和匿名登录HTTP容量；旧租户注册哈希接同一预算；取消不能提前释放物理工作许可 |
| 2 | S01-B 有界来源/账号准入 | governor G0版本/许可/feature核查；可信peer、摘要键、单调时间、多入口累计、硬容量、过期清理、错误合同与宿主接线；单进程范围明确，不宣称多副本全局预算 |
| 2.1 | S01-C KDF 接线收尾 | 在线 OIDC/client admin/device admission 共享同一密码预算；精确503及兼容合同；离线seed边界明确 |
| 3 | O01a最小安全事件和恢复邮件投递 | 盘点注册runtime可复用部分，类型化投递结果、加密payload、事务事件、租约/重复与未知结果处理、显式key供应、可追踪状态；局部失败恢复可用 |
| 4 | S03-A 本人会话/改密 | 独立本人API与React入口；会话只能本人查询/撤销；当前密码重验证；全域会话退役与凭据版本/并发屏障；结果未知可核对 |
| 5 | S03-B 密码恢复 | 邮件code为首批；匿名外显、累计猜测/重发预算、单次消费、旧代次失效、并发及失败恢复、改密后不自动登录；复用O01a投递，不复用注册资格 |
| 6 | 一期交付清单 | 更新API/漂移检查、宿主配置/迁移/示例、已实现与限制；所有前述分批局部与集成测试通过，未执行项显式列出 |

S01-B为后续匿名入口提供准入；O01a为S03-B前置。S03-A可在相关安全合同冻结后独立开发，但不通过并发修改同一安全事务模块抢工。配置阈值和恢复方式在各详细设计中固定；第一期不新增密码无因子登录方式，不默认为历史账号强制MFA。

## 验证及操作边界

使用合成账号和专用PostgreSQL容器/schema；真实开发/生产库、用户凭据不是测试夹具。验证覆盖事务回滚、幂等/重放、并发撤销、结果未知、入口隔离与Web迟到响应；普通离线测试不依赖DB。必要时跑工作区检查，ignored单列。

不运行完整验收、部署、推送；没有自动合回main的授权。先前8个未跟踪live测试文件保留原样，不当作本任务新产物或私自提交。生产TLS/邮件供应、容量/长窗口/灾备/实体设备和目标环境验收后续单列。第一期“可交付”在本任务中指功能实现及约定分批验证和交付说明完成，不写成生产就绪。

## 当前进度

S01、最小O01a、S03一期子集已实现并完成分批局部/集成验证；最终离线回归及交付说明见[一期交付清单](phase-one-delivery-checklist.md)。一期范围不包含MFA/因子管理、企业身份集成、原生平台持钥或完整验收/部署。

| 切片 | 结果与证据 |
| --- | --- |
| S01-A/B/C | 共享物理预算、来源/账号有界准入、OIDC/client/device KDF接线；[A](s01-a-implementation-result.md)、[B](s01-b-implementation-result.md)、[C](s01-c-implementation-result.md) |
| O01a-A/B0与共用基础 | 类型化邮件投递、事务事件、版本化加密、foundation/runtime扩展；[邮件](o01a-a-implementation-result.md)、[foundation](security-foundation-implementation-result.md)、[加密](account-security-crypto-implementation-result.md)、[runtime](security-runtime-implementation-result.md) |
| O01a-B2/B3 | 持久邮件claim/finish/cleanup、物理sender和宿主生命周期；[B2](o01a-b2-implementation-result.md)、[B3](o01a-b3-implementation-result.md) |
| S03-A0/A1 | Cookie本人身份和全域会话列表；[A0](s03-a0-implementation-result.md)、[A1](s03-a1-implementation-result.md) |
| S03-A2/A3 | 本人撤销/匿名收据、PG/HTTP及宿主配置；[A2](s03-a2-implementation-result.md)、[A3](s03-a3-implementation-result.md) |
| S03-A4/A5 | 重验旧密码、全域会话退役、并发屏障、HTTP及宿主预算；[A4](s03-a4-implementation-result.md)、[A5](s03-a5-implementation-result.md) |
| S03-B1/B2/B3 | 匿名恢复开始、累计尝试、单次完成、PG事务、邮件/HTTP/多入口接线；[B1](s03-b1-implementation-result.md)、[B2](s03-b2-implementation-result.md)、[B3](s03-b3-implementation-result.md) |
| S03-C1/C2 | SDK、管理及业务页面、写前持久intent、刷新和结果恢复；[C1](s03-c1-implementation-result.md)、[C2](s03-c2-implementation-result.md) |

完整目标环境验收、部署、提交/推送安排与后置产品增强单列于交付清单；本任务的分批验证完成不替代它们。
