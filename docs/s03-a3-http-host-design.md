# S03-A3 会话撤销HTTP与参考宿主实施设计

2026-10-26，独立double check已通过，进入实施。目标让已完成的本人撤销/收据Core与PG能够由参考宿主真实调用。完整安全页、改密/恢复及worker仍属后续批次；不做完整验收、部署或推送。

## 显式持久配置与复用

JSON v1/v2新增可选runtime.account_security；缺省None保留既有启动兼容，不挂载新的安全写/收据路由。启用须提供authority、subject_key_file、current:{key_id,key_file}及可选previous:{key_id,key_file}。subject文件恰32 raw bytes；每个keyset文件恰128 raw bytes，按顺序切四个32bytes secret/command/code/envelope。key ID、authority、非零/各用途独立校验直接复用RingAccountSecurityCrypto构造器。无新依赖、不通过环境变量传原始密钥、不启动随机生成持久key。

路径沿用配置文件相对路径解析为绝对路径。AccountSecurityConfig/KeyFileReference均deny_unknown_fields，仅含路径和非秘密ID。validate_static检查authority/keyid语法、current/previous不同ID及非空路径，不读取密钥；load_crypto打开每个文件后对同handle做metadata，要求regular file、准确长度，Unix权限无group/other位，再有界读取33/129bytes检查实际长度，固定非敏感错误，不回显路径/材料或底层错误。不抽象改造旧signing/scan文件读逻辑；新loader小且用途固定。继承SecretString/nozeroize实际限制。

subject key稳定不可日常轮换。keyset轮换保留previous至少覆盖旧记录24小时最长TTL；配置只支持current+previous，不声称自动轮换/旧记录重加密/密钥删除安全检查。未知旧key依旧显式基础设施失败。无参数legacy环境模式不启用此可选能力，需迁移到--config显式配置；不改变旧env字段。AppConfig.from_legacy account_security=None。

## 显式迁移CLI

新增security-plan/security-apply/security-check三个子命令，参数--config <path> --extension foundation|runtime；apply额外必需--fingerprint <64lowerhex>，其他命令不接受该参数。拒绝重复/未知/缺参。复用AppConfig::for_preparation，要求account_security配置，使用其authority及mode/PG配置；迁移命令不读原始key文件，不要求签名key或在线登录。bootstrap仍按已有流程完成，runtime要求foundation已安装。

plan只读，输出单个JSON {extension,schema_name,mode,authority,fingerprint}，不输出连接URI/密钥。apply按相同配置重新生成计划，比对用户明确提供的fingerprint后调用现有adapter apply（其中再锁内校验）；不同指纹退出3且无写；配置/用法错误2、数据库失败或提交结果未知4。check调用相应check API，成功只输出非敏感ready信息。重复apply已安装失败，操作员用check核对，不自动补迁移、不自动覆盖。CLI输出/错误固定，无真实库操作在本任务执行。

## HTTP合同

新增独立构造器self_session_revocation_router(business auth,service)、management_self_session_revocation_router(management auth,service)、browser_self_session_revocation_router(identity,service,http_config)。不改变原列表/登录构造签名。service为Arc<dyn SelfSessionRevocationService>。

每个purpose有以下POST路径，host仍拥有外层prefix：

| 入口 | 业务路径 | 管理路径 |
| --- | --- | --- |
| Bearer撤销 | /auth/security/sessions/revoke | /admin/auth/security/sessions/revoke |
| capability结果查询 | /auth/security/sessions/revoke/result | /admin/auth/security/sessions/revoke/result |
| Cookie撤销 | /auth/browser/security/sessions/revoke | /admin/auth/browser/security/sessions/revoke |
| browser capability结果 | /auth/browser/security/sessions/revoke/result | /admin/auth/browser/security/sessions/revoke/result |

撤销JSON严格字段：target_tenant_id,target_session_id,operation_id,receipt_secret；browser另必需expected:{tenant_id,account_id,session_id,client_id}。结果JSON仅operation_id,receipt_secret，不允许account/tenant/target/expected选择器。operation文本必须canonical非nilUUID，secret由Core严格验证43字符/32byte格式。16KiB DefaultBodyLimit，所有成功/错误no-store，原Axum提取器413/415/422等保持如实合同。

Bearer撤销复用现有单Authorization、长度限制、purpose对应认证和tenant_header_matches；拒绝business selector。结果查询不验证token/cookie（撤销当前会话后它们可能失效），拒绝tenant/business选择header，不调用认证服务。结果能力按部署全局operation+secret验证，跨入口持有同secret可查询同一boolean；不返回主体/目标。Cookie撤销沿用共享browser_headers_valid和credential，强制expected身份，构造时purpose/lifetime相等；browser结果只检查相同Origin/browser header/Fetch-site和禁止selectors，不需要Cookie/expected。

撤销成功及已确认结果均200 {completed:true}，未确认结果200 {completed:false}。无Set-Cookie：不能让旧撤销请求的迟到响应删除另一标签页新登录的cookie；UI后续仅在expected仍匹配时清本地认证，旧Cookie服务端已失效。401 invalid_session；404 session_not_found；409 operation_conflict；400 invalid_request（参数/mode）；容量503 security_unavailable；存储/crypto503 security_unavailable；无效store返回500 server_error。错误不回显字段值/秘密。HTTP层只认证/映射/DTO，事务规则保留Core。

所有挂载通过参考宿主既有shared abuse admission（POST来源/全局配额，可信peer），call阻塞预算仍由原helper持有；结果读取不能绕过该层。第三方嵌入宿主须自行注入同类准入，库router不虚构默认全局限流。

## Host接线

build_composition只加载一次crypto；在任何reference seed/online写之前，启用配置就check_security_runtime(mode,authority)，失败中止启动且不修复schema。构造一个Arc撤销service（同PostgresAccessStore/SystemClock/UuidV7IdGenerator），传给management和所有ordinary business entry；不在每entry重读key或建独立域。

management Bearer/router合并；browser身份实例与现列表一致clone，撤销router使用同配置/expected规则。ordinary_business_routes增加内部可选service参数，共享注入；business auth在移动给self-router前clone以挂载撤销。无account_security时现行为不变。legacy reference分支None不挂载，但内部代码如已有显式optionalservice仍按相同auth identity分支组装，不能扩大旧scan身份trait。

## 实施与局部验证

1. 设计独立复核配置/迁移权限、结果查询无需已撤销cookie、跨entry能力边界和late-response cookie策略，纠正后编码。
2. 配置loader/CLI与Axum adapter并行非重叠实现；主代理集成bootstrap。单元测试：key权限/长度/重复/轮换、CLI参数/指纹、DTO/认证/Origin/expected/selector/body/no-store/无SetCookie/失效cookie仍查询result；test double断言result不会调用auth或写方法。
3. 本地一次性PG真实reference host：启用前缺扩展/错key配置拒绝启动无DDL；使用CLI plan/apply/check基础+runtime；至少两mode验证管理与普通business Bearer/Cookie撤销和结果、跨entry拒绝、操作重复和新cookie不被旧请求清除（无SetCookie）。受保护准备及既有preexisting测试不改。
4. business OpenAPI增加4项操作（management仍专用合同+清单），新增schema/error/expected/receipt能力说明；更新路由清单与漂移检查，通过相关Axum/App测试和check_api_contracts。Web资源如需编译host先沿用已build产物，不提交生成dist。
5. 更新交付清单实际证据及限制，不把后台加密outbox表存在当邮件恢复已可用。

## Double check与实施裁定

独立复核未发现阻塞，要求新路由在现shared admission包装前合并，迁移/密钥错误不回显底层值，外层no-store覆盖提取器拒绝。主代理补充：启用后/readyz也执行只读security runtime检查，运行中布局漂移不得仍报告ready；此检查不加载/轮换密钥、不写库。
