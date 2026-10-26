# 第三批 A02B-B1 实施记录

## 范围与依赖

2026-10-25 开始基线 HEAD `14dd9199094464a1f7368e9c95f5c29e7a5354c7`，工作区保留未提交的 A01/A02A/A03 与并行 N2 结果。按修订4顺序：A01 → A02A/A03初版已具备局部证据；本批只实施 A02B-B1（配置v2与单issuer共享OIDC），然后才是B2设备proof/admission、B3扫码provider/keyring/cleanup。A04/A05及安全增强不在本批。

拥有文件：app composition_config/bootstrap/oidc_dispatch、Core authentication/oidc及专项测试、Axum OIDC resource的协议路由拆分、OpenAPI及合同测试、真实宿主定向测试和本记录。复用既有Core OIDC授权码/资源事务、RS256验证、client secret验证、Axum表单和错误投影，不复制密码学或创建第二套领域算法。既有依赖及许可证保持；本批不引入新开源组件，无新增G0选型或数据库迁移。

公共合同：新增可选Core普通OIDC transport实现（拒绝device proof）、S256严格策略builder；新增Axum不含logout的协议resource router。旧trait签名、旧router和LegacyReference保留。

支持组合：JSON v2中每个业务入口可选 `"oidc":{"enabled":true}`，支持已有Fixed/Choose与public/confidential客户端。v1拒绝oidc字段；v2未启用时无共享协议/discovery/JWKS。管理client不进入业务注册表。device/scan仍拒绝，不以占位配置开放。配置必须显式准备引用的client/tenant，启动不创建身份数据。

故障恢复：继续现有授权码消费与会话创建同事务、一次性授权码和精确family撤销；注册表只在启动时构建。更改入口绑定应显式处理旧凭据；移除OIDC配置仅关闭此服务分派，不承诺全域或离线JWT吊销。

局部验证目标：配置版本/未知字段/路径冲突、两入口及禁用入口隔离、跨client code/actor、redirect/PKCE负例且不消费、伪JWT与管理purpose、真实授权码生命周期及metadata/路由一致性、短会话不升级、旧参考兼容。完整验收、真实代理/TLS/设备、生产部署均不执行。

## 接入合同

共享顶层路径：`/oidc/authorize`、`/oidc/token`、`/oidc/userinfo`、`/oidc/introspect`、`/oidc/revoke`、`/oidc/jwks`及`/.well-known/openid-configuration`。每入口普通认证和logout仍位于自己的mount prefix；共享resource不另挂根`/auth/logout`。

authorize继续Bearer调用并返回307，不是读取入口Cookie的SSO页面；浏览器先在自己的入口恢复access token。所有新协议client必须使用PKCE S256，授权码发放与消费都检查，旧plain码不能在切换新策略后换取token。token endpoint只支持authorization_code，不宣告refresh/password/implicit grant。B1拒绝设备proof且不会挂载device challenge。userinfo在验证签名/issuer/audience/purpose后才选择入口，选中服务再次检查当前session；client_id表单仅是查找线索，不替代client认证。introspection仅允许confidential client；revoke保留public client提交client_id、confidential client验证secret的既有规则，只处理本client的当前token family。

新JSON受限私网browser短会话不能通过OIDC授权/换码获得长期限；需重新完成普通认证。已有session没有通道标记，沿用A02A保守期限规则（短于当前普通session配置即拒绝升级）。LegacyReference未启用该隔离策略，保持既有行为。

## 配置示例

以已有效的v1文档为基础，把顶层`version`改为`2`，并只在需要OIDC的业务入口增加以下字段；runtime、管理入口及SecretRef格式不变：

```json
{
  "login_entry": "orders",
  "client_id": "orders-client",
  "tenant_policy": { "kind": "choose" },
  "mount_prefix": "/orders",
  "oidc": { "enabled": true }
}
```

在Disabled模式使用`{"kind":"fixed","tenant_id":"0"}`；Enabled Fixed须使用已存在的非0租户。client和回调地址经已有管理API显式准备，授权请求的redirect_uri须精确匹配；confidential secret只由服务端调用方持有。`oidc.enabled=false`或省略整个oidc对象关闭此入口的协议接入，不关闭其普通登录。所有入口关闭时共享七项路由一起移除。

API清单与独立七操作合同见[合同说明](api/README.md)。普通17操作profile保持独立，不把共享OIDC重复挂到每个入口。

## 验证结果

本批局部证据（2026-10-25）：

| 检查 | 结果及范围 |
| --- | --- |
| Web构建 | `pnpm --dir web build`通过；未提交生成资源 |
| Core认证定向suite | 67通过，含授权码失败回滚及新S256/短源会话检查；补充普通transport拒绝proof后专项1通过 |
| Axum lib | 102通过，覆盖原OIDC/browser等HTTP回归 |
| App bin | 默认feature 37通过；私网HTTP feature 38通过，含v1/v2显式配置与共享路径冲突 |
| 新B1真实宿主/Postgres | 3通过：Disabled多入口、Enabled confidential client、私网browser；之后将Enabled入口改为Choose并单项通过，补充metadata/全部关闭条件后共享入口单项通过 |
| LegacyReference真实宿主 | 3通过：双模式管理/业务/OIDC、扫码proof用途、私网browser期限与过期身份 |
| workspace all-targets | 默认feature、locked/offline编译检查通过；新OpenAPI导出example有required-features门禁 |
| A03合同与漂移 | 11通过；普通17操作和新增共享7操作制品一致，协议成功/错误HTTP投影、内容类型与挂载清单对照 |
| 格式与补丁 | `cargo fmt --all -- --check`与`git diff --check`通过 |

真实数据库仅使用本轮专用无持久卷容器`idp-b1-20261025`与随机schema，结束后已删除；不连接既有开发/生产数据库。首次局部失败包括测试夹具的错误PKCE向量、已存在logout路径的状态预期及重排后禁用索引，均已修正并重跑；同时把未启用入口的有效签名令牌在authorize中统一映射为401身份拒绝，保持未知请求client为400协议错误。

Core/存储事务算法继续复用，没有新增锁序、表或迁移。移除入口配置不删除session；普通入口仍可按原合同验证既有会话。未执行完整验收、远端CI、跨平台/MSRV、真实设备/代理/TLS、生产部署或提交推送。B2/B3尚未启动；其provider/admission/keyring/cleanup依赖不能视为已完成。
