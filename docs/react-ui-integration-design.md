# React 管理后台与宿主嵌入组件

> 2.0 客户端契约见[租户内业务标识与业务管理员设计](business-domain-authorization-design-v1.md)：租户内业务筛选、`business_admin`、业务级分配和游标隔离。本文示例对应 2.0。

> 浏览器 Cookie 接入的新增契约见[浏览器会话设计](browser-session-design.md)。原显式令牌与设备证明接口继续适用；本期不支持跨标签页同时使用不同业务租户。

更新时间：2026-09-25。Web 工程有两个交付面：参考服务使用的独立管理后台，以及宿主可本地导入的 `@embedded-idp/react` 组件包。源码和构建产物在同一工程，均未发布到 npm。

| 入口 | 内容 | 主要依赖 |
| --- | --- | --- |
| `web/management` | 管理登录、租户目标选择、租户/成员/角色/权限、账号、设备、会话、客户端、审计与权限诊断 | React 19、Ant Design 5 |
| `@embedded-idp/react` | 业务登录、固定/选择租户、当前身份与本人角色 | 宿主 React 19；局部 CSS，无 Ant Design |
| `@embedded-idp/react/admin` | 可嵌入的权限目录组件及管理客户端 | 宿主 React 19、Ant Design 5、React 19 兼容补丁 |

## 身份和安全边界

管理后台先读取 `/admin/auth/capabilities`，再使用独立管理登录与管理用途 JWT；业务组件只调用公开 `/auth` 和本人接口。两种凭证不能互换。当前管理客户端只接受同源绝对 API 前缀，默认显式令牌模式的凭证和选择票据保存在客户端实例内存。可选 Cookie 模式仅把访问令牌与选择票据留在内存，刷新凭证由 HttpOnly Cookie 保存；本地存储只保存跨标签页协调标记，不保存凭证。参考管理页面使用 Cookie 模式，启动时先读取 capabilities 再 restore()。业务组件的请求适配器可由宿主提供，以承载其设备证明；真实签名和业务资源授权始终由宿主服务端负责。

Disabled 模式固定域 `0`，不展示租户管理或切换。Enabled 模式的业务登录遵循服务端 Fixed/Choose 策略；管理平台 `0` 选择业务租户时，目标域通过专用管理 Header 传递，管理身份并不变成目标租户的业务身份。界面隐藏或显示操作只是交互提示，Core 与管理服务每次写入仍复查实时权限。管理写入遇到冲突或结果不确定时不自动重放，需重新读取核对。

权限目录定义 `(tenant_id, business_id, resource_type, action)`。管理页面只选择租户；同一租户内角色、权限和绑定列表默认显示当前授权范围内的全部业务，并提供业务标识筛选。创建权限、角色和业务管理员时在表单填写业务标识；普通角色需显式关联权限，业务管理员自动覆盖同业务新增的有效权限。成员页面的角色绑定抽屉和角色选择器可按业务筛选，按类型或实例分配普通角色，按整个业务分配业务管理员。筛选变化后重置列表游标和选中项；账号、成员、设备、会话页面不增加业务筛选，审计使用可选业务筛选，留空查询目标租户全部记录。诊断表单必须填写业务标识；宿主仍须核对业务对象归属并调用权限检查。

## 构建与本地使用

`pnpm --dir web build` 生成管理应用 `web/dist/management`、业务组件 `web/embedded/dist/embedded-idp.*` 和管理组件 `web/embedded/dist/admin.*`。Rust 参考服务编译时嵌入管理应用；先构建 Web，再编译 Rust。`pnpm --dir web dev` 在 `127.0.0.1:4179` 预览管理源码，需要同源管理 API；真实本地体验使用[参考服务的两种模式](standalone-app-v1.md)。`web/embedded/demo.html` 仅用模拟响应验证组件交互；[无租户嵌入宿主](../examples/no-tenant-host/README.md)的页面源码和构建配置位于示例目录，通过 `./examples/no-tenant-host/run.sh build-web` 构建。

宿主完成本地包构建/安装后导入业务组件：

```tsx
import { EmbeddedAuth, EmbeddedIdentityClient } from "@embedded-idp/react";
import "@embedded-idp/react/style.css";

const identity = new EmbeddedIdentityClient("/api");
export function Login() { return <EmbeddedAuth client={identity} language="zh-CN" />; }
```

`EmbeddedAuth` 可选传入 `businessId="f_01"` 显示该业务的本人角色；省略时仅显示身份与登录操作，不查询角色。自行调用客户端时使用 `listMyRoles("f_01", cursor?)`，业务 ID 不参与登录或选租户。

管理控制台如需嵌入权限目录，使用独立入口：

```tsx
import { PermissionDirectory, type PermissionDirectoryClient } from "@embedded-idp/react/admin";
import "@embedded-idp/react/admin/style.css";

export function PermissionSettings({ client, tenantId, businessId }: {
  client: PermissionDirectoryClient; tenantId: string; businessId: string;
}) {
  return <PermissionDirectory key={`${tenantId}:${businessId}`} client={client} tenant={tenantId} business={businessId} />;
}
```

`PermissionDirectoryClient` 可由导出的 `ManagementClient` 实现，也可由宿主实现同一组管理 API 方法。使用 `ManagementClient` 时，先调用 `loadCapabilities()` 并完成管理登录/选租户。组件不代办管理登录，不接受业务 access token；Enabled 平台 `0` 仅显示受保护权限，业务权限必须在真实目标租户创建。角色关联仍通过角色管理界面或 API。管理组件使用 Ant Design 默认弹层 portal，嵌入宿主需验证遮罩层级和焦点行为；CSS 不导入旧后台全局样式或 Tailwind。

## 验证边界

`pnpm --dir web test` 覆盖管理和业务客户端协议；`pnpm --dir web build` 检查类型与产物；`pnpm --dir web test:embedded-bundle` 验证组件包入口、样式边界和宿主 React 复用。参考服务和 PostgreSQL 的实际接口另由 Rust 集成测试覆盖。这些检查不替代真实业务宿主中的设备证明、报告资源授权或全部管理页面的浏览器验收；剩余工作见[当前交付与验收](tenant-access-execution-plan.md)。

## Cookie 模式接入

业务端使用 `new EmbeddedIdentityClient("/idp", undefined, { mode: "cookie" })`；管理端使用 `new ManagementClient("/api", { mode: "cookie" })`。默认不传选项时仍使用显式令牌模式。Cookie 模式只能连接同源端点，路径会规范化以避免同一接口使用不同跨标签页锁。

`EmbeddedAuth` 和管理 Console 在读取 capabilities 后调用一次 `restore()`。自行构建界面的宿主应先 `loadCapabilities()` 再 `restore()`；401 表示未登录，其他错误应显示给用户，不能无限重试。已登录实例调用 restore 会发送完整预期身份；并发 restore 在实例内合并。订阅快照的 `sessionChanged` 时停止旧操作、清除业务数据并提示重新加载；`selecting` 期间不得继续操作旧业务上下文。设备证明宿主继续使用原显式令牌模式及自定义 transport。
