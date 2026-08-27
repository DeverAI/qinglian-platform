# 2026-07-31 BUG 与逻辑复检收尾轮

## 本轮目标
响应用户“检查有没有什么遗漏的 BUG 或者逻辑问题”的要求，在已完成数据层与权限层的基础上，对签到奖励、AI Agent 配置读取、Root 服务开关、论坛/私信/群聊积分门槛豁免、管理员自审自利等高风险点进行复检与修复。

## 已修复问题

### 1. 签到连续奖励逻辑修正
- **文件**：`app/routers/points.py`
- **问题**：原代码 `extra = 5 if streak >= 7 else 0` 会在第 7 天及以后每天都额外奖励 5 积分，与设计“连续签到奖励（+5/周）”矛盾。
- **修复**：改为 `extra = 5 if streak == 7 else 0`，仅在连续签到满 7 天时一次性奖励。

### 2. AI Agent 配置读取修正
- **文件**：`app/routers/agent.py`
- **问题**：`/chat` 入口直接用模块常量 `AI_API_URL` / `AI_MODEL` 判断是否可用，未考虑管理员后台通过 `admin_settings` 配置的 API 地址/密钥/模型。
- **修复**：改为先调用 `_ai_config()`（优先后台设置，其次环境变量），再判断是否降级为静态导览。

### 3. Root 动态服务开关补全 chat
- **文件**：`app/routers/root.py`
- **问题**：`SERVICE_NAMES` 集合缺少 `chat`，导致 Root 无法在后台开关私信/群聊服务；`ban_admin()` 仅更新 `users.is_banned`，未同步 `bans` 表。
- **修复**：`SERVICE_NAMES` 加入 `chat`；`ban_admin()` 同步插入 `ban_type='account'` 记录，保持与 `admin.py` 封禁路径一致。

### 4. 论坛发帖/回复积分门槛豁免管理员
- **文件**：`app/routers/forum.py`
- **问题**：`create_post` / `create_reply` 在事务内对所有用户调用 `ensure_points_in_tx`，导致 0 积分管理员无法发帖/回复。
- **修复**：导入 `SPEAK_BYPASS_ROLES`，事务内二次校验仅对非豁免角色执行。

### 5. 私信/群聊发言积分门槛豁免管理员
- **文件**：`app/routers/chat.py`
- **问题**：`send_pm` / `send_group_msg` 使用 `require_threshold` 做前置拦截，不区分角色，低积分管理员无法发私信/群聊。
- **修复**：改用 `require_speak()` 并在事务内对 `SPEAK_BYPASS_ROLES` 豁免积分校验。

### 6. 举报处理自审拦截
- **文件**：`app/routers/admin.py`
- **问题**：`handle_report()` 未检查处理者是否为自己提交的举报。
- **修复**：增加 `report["reporter_id"] == user["id"]` 判断，禁止处理自己的举报。

## 全局复检
- 调用上下文故障检测专员对 `points.py`、`agent.py`、`root.py`、`forum.py`、`chat.py`、`admin.py`、`security.py`、`auth.py`、`database.py`、`main.py` 进行审查。
- 结论：无阻塞级（Critical）缺陷；按建议完成 H1/H2/M2 三项立即修复。

## 测试结果
- 命令：`python -m pytest tests/test_api.py -v`
- 结果：31 个测试全部通过，1 个 deprecation warning（Starlette/TestClient 提示安装 httpx2）。
- `Err.log` 为空。

## 备份与归档
- 关键修改文件备份至 `backups/20260731_220000/app/routers/`（points.py、agent.py、root.py、forum.py、chat.py、admin.py）。
- `done.md` 归档为 `updates/20260731_BUG与逻辑复检收尾.md`。
