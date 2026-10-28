# O01a-A 安全邮件物理适配器实施结果

2026-10-26。详细设计及两轮复核修订见 o01a-design-and-plan.md。本批只交付邮件合同和受控物理发送适配器；持久outbox、恢复业务消费者及main关闭时序装配仍属于O01a-B/S03，尚未完成。

## 实现与复核

Email新增SecurityEmail（Debug脱敏）、用途、Accepted/Rejected/NotStarted/Unknown四种结果及标准Future异步合同。App使用同一二进制内部helper从stdin读取最多16KiB JSON，env_clear，stdout/stderr关闭，SMTP采用已有lettre，socket timeout5秒；父supervisor绝对发送期限最多15秒，共享4槽，无无界排队。调用方取消不取消已登记supervisor；物理退出/kill+reap后释放许可，清理最多2秒，未确认清理则隔离容量。

父进程正常shutdown停止新发送并等待已登记任务；O01a-B必须在runtime销毁前调用该方法。父进程意外崩溃可能遗留helper，不能声称跨宿主崩溃物理无重叠；后续outbox租约到期必须Unknown而非直接重发。

旧Log发送不再打印地址/正文/验证码，仅固定 suppressed 事件与人数，旧返回值兼容；新安全邮件不支持Log/sendmail。复用SMTP构建器时保留旧letter默认timeout，只对新helper显式5秒，不改变旧注册邮件运行合同。

## 局部验证

- 适配器4项：退出码分类、关闭拒绝新任务、超时kill/reap并以PID退出核对、调用取消后容量保持、无效/超限/过期/不支持模式/启动失败。
- Log固定输出1项；Email请求Debug脱敏1项。
- 实际二进制+临时loopback SMTP 3项：接受exit0、DATA后451=>Unknown/exit3、非法和超限JSON=>Rejected/exit2，stdout/stderr不含合成地址/code。命令 `cargo test -p embedded-idp-app --test security_email_helper --locked --offline`；普通沙箱禁止loopback bind，工具授权后使用本机临时监听通过，没有使用真实SMTP。
- 格式、diff检查及工作区all-targets编译通过。未接入持久消费者的sender有dead_code警告，属于当前切片未装配状态，不能隐藏成已运行worker。

未执行真实供应商投递验收、完整验收、部署、提交或推送。所有测试仅使用合成材料。
