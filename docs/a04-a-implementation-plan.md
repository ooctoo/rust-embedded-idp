# A04-A 实施方案与复核

2026-10-26。依据[A04-A技术设计](a04-a-technical-design.md)。当前状态：详细设计经独立源码double check与主代理裁决后通过，可进入编码。复核发现服务端本人回执按tenant/account/operation ID共享，文档已区分前端intent入口保护与现有服务端授权语义；不扩大本批改Core/SQL。DTO的可空key指针与正整数版本、解绑固定operation/result_status及版本+1已同步。

1. 对照Axum DTO、Core解绑receipt和现有client revision，复核请求桥边界、intent身份绑定、错误恢复及组件状态切换；先修文档阻断项。
2. 主代理负责认证请求桥/公共API与集成；薄client与DTO局部测试为独立文件责任；组件/CSS与浏览器夹具分配独立文件责任。并行工作不得覆盖既有CI/N2与PG修改。
3. 实现后先跑client目标测试，再Web build、bundle测试及局部浏览器交互；真实宿主用显式专用PG和随机schema验证本人API，不操作现有数据库。
4. A03不新增HTTP路由，核对并复用device合同五个本人操作；更新路由消费与公开exports说明，执行既有合同漂移检查。
5. 主代理审查实际diff/安全边界和不必要抽象，修复确定问题，记录真实测试证据、剩余A04-B/C/D与A05状态；删除本轮专用测试资源。

退出：本人设备分页/详情/key metadata可用，解绑及未知结果回读使用同一intent，无跨身份迟到回写，包导出/主题隔离/局部浏览器证据通过。登记、signer、admission及真实轮换不在此子批退出条件，A04整体不得标为完成。

## 实现复核

主代理实审修正：展示scope纳入session_id而恢复intent只按owner绑定；分页cursor随身份代际重置；unknown intent禁止被下一次解绑覆盖；所有异步读/写/刷新由当前scope与请求序号复核；成功receipt与列表刷新错误分离；多组件heading使用useId。独立实现复审发现key metadata仅对active设备和active本人绑定开放，UI已同步限制并补浏览器负例。真实宿主发现algorithm wire为小写`ed25519`，已对照存储投影修正客户端与夹具。

本子批先行原因：本人列表/解绑只依赖现有业务Bearer与五个本人API，无持钥/admission调用；不为它预建尚未接线的signer抽象。下一子批A04-B再冻结用途受限signer、admission与登记恢复的详细合同，并通过double check后编码。

收口：A04-A设计/实现复核与所选局部检查完成，详见[实施记录](a04-a-implementation-result.md)。本批无新增HTTP协议或数据迁移。
