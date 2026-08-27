# FreqErr.md — 常见错误类型记录

格式：`[错误类型] 错误描述（技术上和现象上） → 正确做法`

- [sqlite3.Row 无 get 方法] sqlite3.Row 对象不支持 dict 的 `.get()` 方法，调用会抛出 `AttributeError: 'sqlite3.Row' object has no attribute 'get'`，在生产环境中被中间件捕获后返回 500。 → 使用 `row["key"]` 访问字段；如需默认值，先用 `dict(row)` 转换或捕获 KeyError。
- [未导入的常量/配置] 代码中引用 `ROOT_EMAIL` 等模块级常量但未从 `..config` 导入，运行时抛出 `NameError`，被中间件捕获后返回 500。 → 每次使用跨模块常量前检查导入语句；提交前跑一遍全量测试覆盖相关分支。
- [SID 轮换后心跳端点未返回 4034] `handshake_heartbeat` 仅调用 `update_handshake(sid)` 更新活跃时间，未检测 sid 是否已被标记为 `rotated`，导致攻击者可对已吊销 sid 持续发送心跳维持会话。 → 心跳端点必须先原子校验 sid 归属+轮换状态再更新，使用 `update_handshake_checked(sid, user_id)` 返回的 status 决定响应（rotated→4034, mismatch→4033, ok→更新）。
- [配置项 DoS：阈值设为 0 导致全站瘫痪] `threshold_handshake_timeout=0` 会使 `now - last <= 0` 恒为 False，所有非 root 用户每次写请求都判定握手失败 → 失败计数达阈值 → 轮换全部 sid → 全站无法发言；`threshold_handshake_fail_limit=0` 会使首次失败即轮换。 → 阈值必须有硬下限：`THRESHOLD_MIN_VALUES` 字典定义最小值，`update_thresholds` 校验，`_get_timeout`/`_get_fail_limit` 强制 `max(val, hard_min)` 兜底。
- [测试未携带 X-SID 头被握手守卫拦截] `require_handshake` 依赖要求有效 sid + 近期鼠标活动，测试中 POST `/api/tasks` 等发言类端点未携带 `X-SID` 头且未发送握手心跳，会收到 4033。 → 测试辅助函数 `headers(tokens)` 应附加 `X-SID`，发言前调用 `handshake(client, tokens)` 发送一次心跳。
- [旧 sid 复用窗口] login/refresh 签发新 sid 后，旧 sid 仍留在 `_sessions` 中且 `rotated=False`，直到 `_maybe_cleanup` 在 3 倍超时后回收（约 180s），期间旧 sid 仍可被 `require_handshake` 接受。 → `_issue_session` 签发新 sid 前调用 `invalidate_user_sids(user_id)` 静默失效旧 sid。
