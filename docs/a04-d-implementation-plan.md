# A04-D 实施方案

2026-10-26，依据[技术设计](a04-d-technical-design.md)。状态：编码前double check通过；实施后复核已补ACK/abort竞态、未提交exchange的取消、原发起与关闭重试、快照隔离。代码及相关局部测试已完成，见[实施记录](a04-d-implementation-result.md)。

1. 核对Core scan_login/service/proof、Axum DTO、既有native示例及来源H5。独立复核Pending/ACK、close-origin和无秘密UI边界，先修正文档。
2. 主代理负责协议/架构、公开接口、实际宿主联调和最终复审；有界worker实现client+UT、UI/夹具、A03合同说明，互不重叠。保留现有未提交变更，不改Core/SQL。
3. 补产品exports、宿主接入说明、实际固定测试signer与隔离PG宿主测试；复用既有H5和renderer。
4. 局部UT、Web build/bundle、真实双方向指定测试、浏览器检查、合同漂移、Rust编译/格式；修复失败并补回归。
5. 更新总计划/实施记录，清理专用资源；不提交、推送、完整验收或部署。

退出：两方向需要手机明确确认，Pending不能用于业务；原操作/发行/ACK id在失败与重建中不变；激活须ACK确认且本地bundle完备；取消不能误销毁active session。原生存储/平台锁/真实扫码硬件仍由宿主验证。
