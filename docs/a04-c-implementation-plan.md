# A04-C 实施方案

2026-10-26。依据[技术设计](a04-c-technical-design.md)，当前阶段：double check通过，已修正文档的签名字节与恢复查询顺序，代码与局部验证完成，见[实施记录](a04-c-implementation-result.md)。

1. 核对Core双签/nonce/expected CAS、Axum DTO与本人读取权限，独立double check；修正阻断后才编码。
2. 主代理负责架构、identity bridge扩展、集成与最终安全审查；有界worker实现controller与局部测试、UI和夹具。保留已有未提交A01–A04-B及其他工作，不改变Core/SQL/wire。
3. 接入export、实际构建包的Node测试signer与Rust隔离宿主双签/丢回应恢复，更新合同与制品。
4. 局部UT→Web build/bundle→真实宿主指定测试与浏览器→合同漂移及Rust编译/格式；修复实际失败，不弱化断言。
5. 更新实施记录与总计划，清理专用测试资源；不提交、推送、部署或完整验收。

退出条件：双签由真实Rust验证，write-ahead journal与同owner重登录/新实例恢复不重复创建候选，scope/期限/并发/错误DTO及清理边界有负例；UI公开字段与合同一致。原生keystore/跨进程锁由宿主实现，局部测试不作为平台验收。

实施复审修正了unknown恢复旧指针不得降prepared、会话切换/同步订阅回调后的发送保护、同handle不能清理旧key、初始加载失败的UI重试和轮换前密钥标签；401沿用身份client清会话语义，通过同owner重登录恢复。
