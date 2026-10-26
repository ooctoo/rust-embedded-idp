# A04-B 实施方案与复核

2026-10-26。依据[A04-B详细设计](a04-b-technical-design.md)。状态：double check通过，已修正文档中的entry隔离表述与未落库challenge负例；代码与相关局部测试完成，见[实施记录](a04-b-implementation-result.md)。

1. 核对Core登记/结果/complete事务和canonical bytes、B2 grant scope/期限、公开组件边界；独立复核重点持久化写前顺序、跨实例锁、404未知、重授权及清理安全，修正文档后才编码。
2. 主代理固定公共合同和协议/目标/DTO校验；有界worker分别负责controller+UT、UI、HTTP合同复核。多人保留现有A01–A04-A及并行CI/PG改动，不修改生产Core/store。
3. 接入公开exports、测试专用signer/store、隔离宿主JS验签与恢复测试、浏览器夹具。无默认浏览器私钥存储，无动态grant签发服务。
4. 局部UT→Web build/类型/包检查→真实PG宿主登记+恢复→浏览器交互→A03漂移和相关Rust编译/格式。实际失败先定位再修复，不能降低断言绕过。
5. 主代理审查实际diff及不必要抽象、独立安全复核；更新实施记录与总计划，清理专用资源。不提交、推送、完整验收或部署。

退出：四接口真正可调用，固定测试signer由真实Core验签；两个未知写入均以原record跨实例恢复；scope/期限/DTO/journal/锁负例通过；UI无秘密展示，API制品无漂移。原生持久store/跨标签页锁依宿主合同，测试adapter不作为生产验证；A04-C轮换、A04-D扫码、A05仍后续。

执行复核已补齐wire JWK kid、独立challenge/registration期限、持久化结果不确定保留key、迟到dispose、React StrictMode与缺adapter边界。无新增依赖或迁移；保持先设计/复核再编码的顺序。
