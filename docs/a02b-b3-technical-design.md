# A02B-B3 扫码组合技术设计

日期：2026-10-25。依据修订4 §5.5 与实施方案 §4.3。本文先于B3代码编写；审查结论另见实施方案。完整验收、部署、npm发布及候选S/X/O/U能力不在本批。

## 1 现状及范围

B2当前增量已完成独立只读复审和主代理调用链核对：未确认新的安全/事务/兼容缺陷；optional Fixed无proof会经proof helper返回None调用普通login，已有真实宿主测试覆盖；grant读取经read_limited两次核对普通文件。不能仅凭局部函数推断这两项存在缺陷。仍保留真实代理与期限边界竞态未完整验收的说明。

现有LegacyReference可选扫码已复用Core的两种码模式、阶段admission、设备资料投影、Pending结果、ack/recover/abort与scope内cleanup；JSON v2未接线。B3只增加该配置面的组合及受控生命周期，不重写状态机、不迁移数据库。

参考宿主本批支持**每个业务entry内同client的普通浏览器来源与设备目标**，显式开关，不自动配置跨client信任。Core仍可由嵌入宿主注入跨client来源策略。源码构造器要求scan target auth使用proof-required配置；普通browser auth仍是独立实例，require_device_proof=false。本批scan要求已有device配置和browser配置，因此entry不能为require_device_proof=true；这不降低target会话约束：scan专用auth强制true，device-bound refresh不允许无proof。

## 2 配置和支持门禁

在JSON v2 business entry下增加可选scan对象（缺省不挂载），deny_unknown_fields、null/重复key规则与现有配置一致：

```json
"scan": {
  "admission_provider": "reference-identity-only",
  "presentation_provider": "registered-device",
  "host_scope": "example-host",
  "modes": ["device_display", "phone_display"],
  "audience": "desktop-scan",
  "device_prefix": "/desktop/auth/device-scan",
  "verification_uri": "https://identity.example.test/desktop/auth/browser/device-scan/ui",
  "result_keyring": {
    "active_key_id": "result-v2",
    "keys": [
      {"key_id": "result-v2", "key_file": "private/result-v2.key"},
      {"key_id": "result-v1", "key_file": "private/result-v1.key"}
    ]
  },
  "cleanup": {"interval_secs": 30, "batch_size": 100}
}
```

- scan的entry_id直接取稳定login_entry，target_client_id与唯一允许source client均取当前entry.client_id；这些派生值必须在记录和客户端context中明确可见。host_scope为显式稳定配置，变更即新隔离域，不借重排或重启更名。target policy复用entry policy。target_scope=None（现有默认）；limits复用Core已校验默认值，不暴露未验收的自由调参。
- admission仅支持显式`reference-identity-only`，presentation仅支持`registered-device`。不是JSON声明准入成功，也不是生产业务审批：Core先验证当前来源账号/成员/普通Business session、目标设备/key及单次证明，固定宿主provider只作身份范围的阶段许可；显示资料源于登记设备ID和安全版本，不接受请求自报名称。生产业务资格/场所须自定义Core provider，不能宣称此参考实现已提供。
- device_prefix必须等于mount_prefix+`/auth/device-scan`；browser根固定mount_prefix+`/auth/browser/device-scan`；verification_uri必须精确为配置browser origin+browser根+`/ui`，不能query、fragment或跨origin。POST/profile/audience由可信HTTP配置生成；不信任转发头；部署重写需另验。
- 必须已有device与browser，provider必须已编译支持。最多16个scan入口，cleanup interval为1..3600秒，batch为1..100；普通无scan入口不受新增上限影响。modes非空、不重复、仅两种已支持值。v1出现scan即拒绝。附带路由落在已保留的/auth族内，仍受现有前缀冲突检查。
- key_file相对主配置目录解析；仅属主可读的普通文件，保存32个原始随机字节（非base64/密码），最大32字节。每ring1..4把key，active必须存在、key_id唯一、密钥材料不重复。复用现成ScanResultKeyring的最终约束。所有key在监听及DB初始化之前加载，异常不得生成替代密钥或输出材料。

## 3 服务与HTTP组合

每entry复用既有CoreTenantDeviceScanLoginService和数据库适配器：独立构造target auth（当前login_entry/client/policy，require proof=true）及相同client的proof service，添加现有十个scan purpose。来源identity只从该entry的普通browser会话获得，正确继承受限私网HTTP browser lifetime及Origin/Cookie规则；不把管理Cookie、其他entry的Cookie或target设备session当source。按照development-private-http.md既有合同，target扫码设备会话使用独立普通期限；browser受限期限仅约束来源会话及批准资格，不能全局截短设备auth。

scan service同时供8个browser操作和10个device操作使用。每个请求由host中间件重新注入TrustedScanHostContext（固定scope、当前时间+60秒），覆盖任何预存extension；阶段admission仍由Core限制到≤5秒并在事务内复核。该host context不是登记grant、不是认证凭据。LegacyReference原有路径/配置保持，生命周期清理改为共同列表管理。

参考扫码UI复用scan_ui.rs及本地QR/Code128资产，只参数化browser根、设备入口entry_id与嵌入auth根；动态值以JSON/HTML安全编码进入页面，不拼接任意脚本。默认Legacy入口不改；v2两入口不再硬编码根路径，页面通过固定entry配置而非可编辑输入决定entry。完整UI/原生持钥功能仍由A04承担。

每次grant定位仍受Core tenant/host_scope/entry/client与proof约束。approve不能激活session；exchange/recover返回同一Pending bundle，只有ack成功激活；abort/超时/cleanup按现有事务精确撤销。禁止为了多入口简化这些步骤。

## 4 密钥轮换与恢复

复用RingScanResultCipher AES-256-GCM及绑定tenant/scope/entry/grant/expiry的AAD，结果keyring与JWT签名keyring独立。active加密新结果，列表中的旧key用于恢复尚未过期delivery。配置重启加载，无自动reload或随机fallback。新key+旧key共同部署后才切active；旧key至少保留到该入口最长恢复窗口及在途请求排空完成，不能据一次重启即移除。配置不能证明DB没有旧Pending，因此删除旧key是宿主操作责任；缺key恢复必须失败关闭，不重新签发第二会话。

## 5 清理和停止

AppComposition由Option cleanup改为有界Vec，每项固定scope/service/interval/batch。采用一个轮询调度任务顺序运行到期entry，每entry每轮最多一批，不并发积压，失败下轮再试；使用单调Instant安排下轮，错过间隔不补发风暴。blocking DB工作交给spawn_blocking且等待返回后再处理下一项。

显式停止信号使用Tokio现有runtime的signal feature（SIGINT、Unix SIGTERM）；停止HTTP接收，通知调度任务停止新批次，HTTP drain与cleanup drain并行开始，分别最多10秒和5秒，二者全部结束/超时后进入runtime最终等待。不能取消已运行的同步DB调用，因此最后runtime shutdown_timeout为5秒，超期日志明确结果未知而非声称回滚。后续启动复用幂等/事务清理恢复。listener bind成功后才启动调度，避免启动失败仍启动后台工作。运行期持有一份Router服务树的外部保活引用，待runtime退出后再同步释放：Postgres同步连接池的最后一次drop会执行内部runtime，不能发生在Tokio异步上下文中。该约束由真实SIGTERM测试发现并对照postgres/r2d2析构路径复核；不改变store所有权或引入新的池。测试用可控制closure验证无重叠/停止/失败重试，不创建通用任务平台。

## 6 复用与许可证

无新增OAuth/扫码/密码实现。复用本仓MIT Core、Axum薄适配器、Postgres store、scan UI；沿用已锁定ring 0.17.14（Apache-2.0 AND ISC）、Axum/Tokio（MIT）、现有QR/Code128资产。新增的仅Tokio signal feature及其必要传递依赖；缓存signal-hook-registry 1.4.8声明MIT OR Apache-2.0，实施时锁定核对；不得替换整个runtime或加入调度框架。前端既有依赖不升级。

## 7 合同与验证边界

A03新增独立scan合同（18操作），明确browser Cookie+Origin+固定头联合约束、device proof raw bytes/外部路径、分离的两类响应、Pending与激活语义、模式/配置条件及恢复错误；现有ordinary/device/shared OIDC合同不混在一个profile。以源码路由覆盖、制品再生成、引用校验及代表性真实HTTP响应比对检查漂移。历史全量schema不因此宣称完成。

静态测试覆盖版本/provider/device/browser/路径/URI/mode/key/cleanup约束，启动前key读取和无secret报错；局部服务测试复用Core/PG已有取消、delivery超时、清理竞争和结果轮换用例。真实宿主验证至少两个entry、不同scope/audience/key，browser来源隔离、完整device_display交付恢复/ack与Pending不可用、重放/跨入口拒绝、phone_display路由接线、关闭信号退出。实体设备、真实代理/TLS、多副本、故障注入全集不在本批。
