# done.md — 本轮已完成任务

> 归档时将按日期重命名移入 updates/。

## 2026-07-30 项目初始化轮

- [完成] T0 阶段0文档初始化：Design.md / Techniques.md / Fact.md / Future.md / Err.log 建立；冲突（Prisma vs FastAPI）经用户裁决为 FastAPI+SQLite 并记录；全局 AI Agent 经用户许可引入（AI 导游定位）。

## 2026-07-31 合规护栏与任务模块轮

- [完成] 设计文档更新：将任务审核脱敏护栏、AI 导游边界、积分反刷、注册设备指纹等合规/反刷设计决策写入 Design.md / Future.md / Techniques.md。
- [完成] 数据库结构更新：users 表新增 device_fingerprint / is_suspicious；tasks 表新增 is_mosaicked；建立设备指纹索引。
- [完成] 注册接入设备指纹：同一指纹超过 3 个账号自动标记为可疑账号。
- [完成] T1 数据库层与安全基础验收：config / errlog / database / security / main 骨架可正常运行。
- [完成] T2 用户认证系统验收：注册 / 登录 / JWT 访问令牌 7 天 / refresh 续期 / me / 登出。
- [完成] T3 任务上传与审核 API：multipart 图片上传（扩展名+魔数+大小校验）、任务状态机、审核联动创建论坛板块、积分奖励；新增管理端打码接口 `/api/admin/tasks/{id}/mosaic`，实现"原始图不落地"脱敏护栏，审核通过前强制确认或打码，操作写入 AdminLog。
- [完成] T4 论坛 CRUD API：板块树形查询、发帖（自动解析 #tag）、帖子详情与浏览量、回复与引用、点赞/点踩（禁止自赞/自踩）、收藏、举报、标签列表与按标签筛选。
- [完成] T5 积分系统 API：每日签到（含连续签到额外奖励）、积分流水、我的积分总览、周/月/总排行榜。
- [完成] T6 管理后台 API：帖子加精/取消加精（禁止给自己加精，+3 积分仅一次）、举报列表与处理、用户列表/角色修改/封禁、AdminLog 查询、蜜罐日志查询、知识库管理 CRUD；蜜罐诱饵接口 `/api/honeypot/login` 与 `/api/honeypot/panel` 实现。
- [完成] T7 全局 AI 导游 Agent：`/api/agent/chat` 基于 Design.md 原文回答，未配置 API 时降级为静态导览，越界需求自动记录 Future.md；`/api/agent/future` 支持显式记录未来需求。

## 2026-07-31 前端页面、集成测试与初始内容轮

- [完成] T8 前端全部页面：补齐 forum.html、post.html、knowledge.html、rankings.html、agent.html、disclaimer.html、profile.html、admin.html、panel.html（蜜罐诱饵页），并更新 common.js / common.css 提供分页、PUT/DELETE、样式支持。
- [完成] 管理后台脱敏护栏 UI：admin.html 支持 Canvas 拖拽打码、提交打码替换原图、审核确认、分类浏览、举报处理、用户管理、知识库 CRUD、日志与蜜罐日志查看。
- [完成] 根路径静态托管：在 main.py 增加 `/` StaticFiles 挂载，使 `/login.html` 等页面可直接访问。
- [完成] T9 集成测试：新增 tests/conftest.py 与 tests/test_api.py，覆盖注册/登录/me/续期、任务提交/审核/打码、论坛发帖/点赞/回复/举报/收藏、签到与排行榜、用户管理/封禁、知识库 CRUD、蜜罐记录、静态页面与模块开关；12 个测试全部通过。
- [完成] T10 知识库与论坛初始内容：seed.py 写入 6 条知识库条目（法律/案例/指南/Qoder），首个注册用户注册时自动在社区公告板块发布欢迎帖。
- [完成] 配置可测试化：config.py 支持 `QLKIMI_DB`、`QLKIMI_UPLOADS`、`QLKIMI_ERR_LOG` 环境变量，便于隔离测试环境。

## 2026-07-31 测试修复与全局复检轮

- [完成] 修复 `app/routers/knowledge.py`：`_entry_out` 中 `sqlite3.Row` 不支持 `.get()` 导致的每日一法 500 错误；增强每日一法对条目删除和并发首次请求的健壮性。
- [完成] 修复 `app/routers/emails.py`：SMTP 发送失败时改为返回 `fail()` 确保邮件状态更新事务提交；邮件复核限制为 `sent`/`self_sent` 状态；SMTP 端口合法性校验；异常时关闭连接；邮件创建时 DB 异常清理附件文件。
- [完成] 修复 `app/routers/tasks.py`：任务提交时 DB 异常清理已保存图片，避免孤立文件。
- [完成] 修复 `app/routers/points.py`：签到返回真实积分（从 DB 重新查询），并发重复签到捕获 `IntegrityError` 返回业务错误。
- [完成] 修复 `app/routers/forum.py`：点赞/点踩并发时捕获 `IntegrityError`，避免 500。
- [完成] 修复 `app/security.py`：`get_current_user` 返回白名单字段，排除 `password_hash`。
- [完成] 修复 `app/routers/admin.py`：最后一名 `sysadmin` 不可被降级或封禁；POP3/SMTP 测试接口增加端口合法性校验。
- [完成] 更新 `tests/test_api.py`：邮件发送测试接受 `5002`/`5003`，仅真正发送成功时才复核加分。
- [完成] 更新 `tests/conftest.py`：Windows 下测试临时目录清理 `PermissionError` 时使用 `shutil.rmtree(..., ignore_errors=True)` 兜底。
- [完成] 新增 `pyproject.toml`：配置 `pythonpath = ["."]`，使 `pytest` 裸命令可直接运行。
- [完成] 集成测试：`python -m pytest tests/test_api.py -v` 18 个测试全部通过。
- [完成] 子 AGENT 全面查错与全局复检：根据反馈修复并发、事务、文件一致性、权限、端口校验等问题；复检通过，无阻塞级缺陷。

## 2026-07-31 POP3 收件箱补全轮

- [完成] 设计文档更新：在 Design.md / Techniques.md 中补充 POP3 收件箱设计（后台收取平台统一邮箱邮件、管理员查看与标记已读）。
- [完成] 数据库新增 `email_inbox` 表：存储 `message_id`（去重）、主题、发件人、收件人、正文、原始大小、已读状态、接收时间，并建立索引。
- [完成] 实现 POP3 收件箱 API（`app/routers/emails.py`）：
  - `POST /api/emails/admin/emails/fetch-inbox` 手动触发收取；
  - `GET /api/emails/admin/emails/inbox` 列表查询；
  - `GET /api/emails/admin/emails/inbox/{id}` 查看单封邮件并自动标记已读；
  - `POST /api/emails/admin/emails/inbox/{id}/read` 手动标记已读。
- [完成] 邮件解析健壮性：使用标准库 `poplib` + `email.parser.BytesParser`，支持 MIME 编码头解码、text/plain 正文提取、text/html 极简标签剥离、日期解析；按 `message_id` 去重避免重复入库。
- [完成] 管理后台收件箱页面（`static/admin.html`）：新增"收件箱"tab，支持一键收取、列表浏览、查看详情、显示收取统计。
- [完成] 集成测试新增 `TestInbox`：mock `poplib` 验证收取、去重、列表、查看、未配置报错等场景。
- [完成] 集成测试：`python -m pytest tests/test_api.py -v` 20 个测试全部通过。
- [完成] 子 AGENT 故障检测：无阻塞级缺陷。

## 2026-07-31 Root 账号、封禁体系、私信群聊与收件箱公开轮

- [完成] 设计文档更新：在 Design.md / Techniques.md 中补充 Root 账号双因素登录、多维度封禁（账号/邮箱/设备）、管理员权限自保护、Root 动态服务开关、私信与群聊、官方收件箱一键关联公开、邮箱注册上限（2 个/邮箱）等设计决策与技术实现。
- [完成] 数据库结构更新：
  - 新增 `root_login_codes` 表保存 Root 登录验证码与临时令牌；
  - 新增 `bans` 表支持账号/邮箱/设备三级封禁；
  - 新增 `messages`、`conversations`、`groups`、`group_members`、`group_messages` 表实现私信与群聊；
  - `email_inbox` 新增 `post_id`、`is_public` 字段用于关联主题并公开；
  - 移除 `users.email` 唯一约束，通过应用层限制同一邮箱最多 2 个账号，并保留迁移脚本兼容旧库。
- [完成] Root 账号体系：
  - `app/main.py` 启动时依据 `QLKIMI_ROOT_PASSWORD` 自动初始化 root 账号；
  - `app/routers/auth.py` 实现 `/root/step1`、`/root/step2` 双因素登录，生成 6 位验证码并调用后台 SMTP 发送至 `ROOT_EMAIL`（默认 `13965124556@163.com`），验证码有效期 10 分钟且完全不暴露给前端；
  - `app/security.py` 新增 `require_root` 依赖，`app/routers/root.py` 实现服务开关、管理员列表、授予/撤销 admin/sysadmin、封禁管理员等接口。
- [完成] 多维度封禁体系：
  - `app/security.py` 中 `_check_bans` 在登录、续期、`get_current_user` 时联动校验账号/邮箱/设备封禁；
  - `app/routers/auth.py` 注册前校验邮箱/设备是否被封禁；
  - `app/routers/admin.py` 实现账号封禁、邮箱封禁、设备封禁（仅 root）、解封，设备封禁同时标记对应指纹用户为可疑；
  - 管理员不可封禁/降级自己，最后一名 `sysadmin` 不可被降级或封禁，低权重管理员不可操作高权重账号。
- [完成] Root 动态服务开关：
  - `app/main.py` 中 `service_switch_guard` 中间件根据 `admin_settings` 中 `svc_*` 配置实时拦截已关闭服务请求，返回 `code=5030`；认证、Root、配置接口不受影响；
  - `app/routers/root.py` 提供 `/services` 列表与 `/services/{name}` 切换接口。
- [完成] 私信与群聊：
  - `app/routers/chat.py` 实现私信发送/会话列表/消息记录（自动标记已读）与群聊创建/成员校验/消息收发；
  - 私信禁止发给自己，群聊仅成员可读写；
  - `static/disclaimer.html` 已补充私信与群聊免责条款。
- [完成] 官方收件箱公开关联：
  - `app/routers/emails.py` 新增 `POST /api/emails/admin/emails/inbox/{id}/publish` 关联论坛主题并公开；
  - 新增 `GET /api/emails/inbox/public` 公开列表；
  - `static/admin.html` 收件箱详情页增加"关联主题并公开"功能。
- [完成] 邮箱注册上限：
  - `app/routers/auth.py` 同一邮箱已有 2 个账号时拒绝注册（`code=4003`）；
  - 登录时同一邮箱多账号需提供昵称区分（`code=4007`）。
- [完成] 集成测试扩展：`tests/test_api.py` 新增 `TestAuthLimitsAndBans`、`TestRoot`、`TestChat`、`TestInboxPublish`，覆盖邮箱注册限制、Root 双因素登录、服务开关、设备封禁、管理员封禁、私信群聊、收件箱公开关联等场景。

## 2026-07-31 数据层与权限层收尾轮（复检修复）

- [完成] 修正 `debug_reg.py`：使用 `TestClient` 上下文管理器触发 `lifespan`，避免测试环境数据库表未初始化。
- [完成] 清空历史 `Err.log` 并建立 `FreqErr.md`，记录 `sqlite3.Row` 无 `.get()` 方法与未导入常量两类常见错误。
- [完成] 修复 `app/security.py`：`_check_bans` 中 `row.get("role")` 改为 `row["role"]`，解决登录/认证 500 错误。
- [完成] 修复 `app/routers/admin.py`：补充导入 `ROOT_EMAIL`，解决邮箱封禁 500 错误；调整任务打码接口文件删除时机，改为 DB 提交成功后再删除原图，避免事务回滚导致图片引用断裂；增加空 `images` 列表校验。
- [完成] 修复 `app/main.py`：Root 自动初始化账号使用 `config.ROOT_EMAIL`，与 `auth.py` Root 双因素登录保持一致。
- [完成] 修复 `app/routers/forum.py`：`create_post` 增加板块状态（仅 `open`）、禁止向根分类发帖、标题/内容去空校验；`create_reply` 增加回复内容去空校验。
- [完成] 修复 `app/database.py` 与 `app/common.py`：`point_logs` 增加 `UNIQUE(user_id, ref_type, ref_id, reason)` 约束与对应唯一索引，`add_points` 对 `IntegrityError` 静默跳过，保证积分并发发放幂等。
- [完成] 集成测试回归：`python -m pytest tests/test_api.py -v` 31 个测试全部通过。
- [完成] 子 AGENT 最终复检：修复发现的 Critical/High 问题，剩余中低风险项按业务优先级后续处理。

## 2026-07-31 社区治理设计文档更新轮

- [完成] 明确平台核心价值定位：将"降低举报门槛、众包举证、AI 整理、平台代发代收"的叙事写入 [Design.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Design.md) 项目定位与核心模块。
- [完成] 群聊治理规范进文档：在 [Design.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Design.md) 中完整补充 200 积分信用准入、群主负责制、平台被动响应、四类硬红线 AI 处理、举报与处理流程、积分奖惩、用户权益保护、免责声明等群聊设计规范。
- [完成] 积分分层与社区行为门槛进文档：0-3 分禁言、10 分发起讨论版、30 分接管板块、200 分建群，以及新用户仅靠签到需 4 天才能发言的机制，写入 [Design.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Design.md)。
- [完成] 讨论版生命周期进文档：查重、证据限额封存、3 天后召集写邮件、证据包 AI 整理、认领代发规则、未允许代发板块归档等，写入 [Design.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Design.md)。
- [完成] 邮件代发 AI 多模型辩论审核进文档：AI 初审、24 小时人工窗口、Deepseek/Qwen/MiniMax 找茬攻击、KIMI/Qwen 搜索验证、最高五轮投票、root 可配置模型职责，写入 [Design.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Design.md)。
- [完成] 反刷与内容治理进文档：频率限制、字数门槛、长文本转 txt、图片压缩、每日 10k/4M 上限、每日 AI 巡查、危险关键词即时审核、攻击性内容独立检测，写入 [Design.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Design.md)。
- [完成] Root 可配置阈值进文档：所有治理数字由 root 在后台配置、管理员不可修改，写入 [Design.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Design.md)。
- [完成] 数据模型与安全设计扩展：在 [Design.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Design.md) 中补充 `group_reports`、`board_claims`、categories 生命周期字段、posts/replies AI 审核字段、admin_settings 阈值存储等数据模型说明，以及积分分层安全、讨论版反刷、邮件代发安全、群聊红线拦截、攻击性内容检测等安全设计。
- [完成] 技术方案更新：在 [Techniques.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Techniques.md) 中补充群聊治理表结构、AI被动审核、积分分层校验、讨论版生命周期、多模型辩论审核编排、反刷治理、攻击检测、证据包整理、每日巡查、Root 可配置阈值等技术实现，并新增 `ai_review.py`、`attack_detector.py` 模块规划。
- [完成] 集成测试回归：`python -m pytest tests/test_api.py -v` 31 个测试全部通过。

## 2026-07-31 BUG 与逻辑复检收尾轮

- [完成] 修复 `app/routers/points.py`：签到连续奖励改为仅在 `streak == 7` 时一次性额外 +5 积分，第 8 天起不再重复奖励，符合“+5/周”设计。
- [完成] 修复 `app/routers/agent.py`：`/chat` 入口改为先调用 `_ai_config()` 读取配置（优先后台 `admin_settings`，其次环境变量），避免后台已配置但模块常量为空时错误降级为静态导览。
- [完成] 修复 `app/routers/root.py`：`SERVICE_NAMES` 补全 `chat`，使 Root 可通过后台动态开关私信/群聊服务；`ban_admin()` 同步向 `bans` 表写入账号级封禁记录，与 `admin.py` 封禁路径保持一致。
- [完成] 修复 `app/routers/forum.py`：`create_post` / `create_reply` 在事务内使用 `ensure_points_in_tx` 进行二次原子校验时，对 `SPEAK_BYPASS_ROLES`（moderator/admin/sysadmin/root）豁免，避免低积分管理员无法发帖/回复。
- [完成] 修复 `app/routers/chat.py`：`send_pm` / `send_group_msg` 改为依赖 `require_speak()`，并在事务内对 `SPEAK_BYPASS_ROLES` 豁免积分门槛校验，确保管理员低积分时仍可正常发私信/群聊。
- [完成] 修复 `app/routers/admin.py`：`handle_report()` 增加自审拦截，管理员不能处理自己提交的举报。
- [完成] 调用上下文故障检测专员进行全局复检：无阻塞级缺陷；按建议完成 H1/H2/M2 三项立即修复。
- [完成] 集成测试回归：`python -m pytest tests/test_api.py -v` 31 个测试全部通过，`Err.log` 为空。

## 2026-07-31 首页通知与每日简报轮

- [完成] 设计文档更新：在 [Design.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Design.md) / [Techniques.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Techniques.md) 中补充首页每日简报（AI 联网搜索近 7 日合规/未成年人保护/数据安全新法规政策摘要，无新内容降级为"历史上的今天"）与系统通知列表设计决策与技术实现。
- [完成] 后端 `app/routers/notify.py`：新建路由模块，实现：
  - `GET /api/notify/briefing` 获取今日简报（优先读缓存，缓存不存在则现场生成）；
  - `GET /api/notify/messages` 返回最近 N 条系统通知（按 id 倒序，含 unread 未读计数）；
  - `POST /api/notify/messages/read` 全部标记已读；
  - `DELETE /api/notify/messages/{id}` 单条删除；
  - `DELETE /api/notify/messages` 清空全部；
  - `add_system_message` 工具函数供其他模块写入通知；
  - `_generate_daily_briefing` 调用 AI 联网搜索生成简报，解析 JSON 输出，失败降级为静态兜底，落盘缓存到 `storage/briefings/briefing_YYYY-MM-DD.json`，并同步写入 `system_messages` 表。
- [完成] 后端 `app/main.py`：挂载 notify 路由（`prefix=/api/notify`），lifespan 启动时同步触发一次简报生成（AI 未配置时走静态兜底，失败仅写 `Err.log`）。
- [完成] 后端 `app/routers/root.py`：`SERVICE_NAMES` 增加 `notify`，Root 可通过后台动态开关通知服务。
- [完成] 后端 `app/database.py`：新增 `system_messages` 表（id/type/title/content/ref_type/ref_id/is_read/created_at）及 created_at、is_read 索引。
- [完成] 后端 `app/config.py`：新增 `BRIEFING_DIR` 路径配置，支持 `QLKIMI_BRIEFING_DIR` 环境变量便于测试隔离。
- [完成] 前端 `static/index.html`：重新设计首页，包含自绘 SVG Logo（盾牌+朝霞光+联结节点三角，寓意合规监督/青年希望/联盟）、Hero 区（渐变背景+品牌标题+CTA 按钮）、每日简报卡片（quote-card + 引号装饰 + AI 图标 + 来源展示 + anim-fade 动画）、系统通知列表（支持未读 badge、已读、删除）。
- [完成] 前端 `static/common.css`：新增渐变主色变量、hero/quote-card/quote-mark/anim-fade/notifyList 等样式，实现符合"青联"立意的亮丽设计与响应式布局。
- [完成] 前端 `static/common.js`：新增 `loadBriefing`、`loadNotifyMessages` 函数，处理 API 请求与动态渲染。
- [完成] 测试 `tests/test_api.py`：新增 `TestNotify` 类，覆盖简报生成与字段校验、通知列表、标记已读、单条删除（含非法 id 与不存在 id）、清空全部等场景。
- [完成] 测试 `tests/conftest.py`：测试环境设置 `QLKIMI_BRIEFING_DIR` 隔离简报缓存目录，避免历史缓存污染测试。
- [完成] 修复关键问题：排查并修复 notify 路由未注册问题（根因：磁盘 main.py 不含 notify 挂载代码，通过 Python 脚本直接修改磁盘文件修复）；修复 `_generate_daily_briefing` AI 未配置分支不调用 `_notify_briefing` 导致通知列表为空的问题。
- [完成] 集成测试回归：`python -m pytest tests/test_api.py -v` 33 个测试全部通过，`Err.log` 为空。
- [完成] 备份修改文件至 `backups/20260731_232430_notify/`（app/main.py、config.py、database.py、routers/notify.py、routers/root.py、static/index.html、common.css、common.js、tests/conftest.py、test_api.py）。

## 2026-08-01 首页消息流、新闻栏与条文背诵游戏轮

- [完成] 设计文档更新：在 [Design.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Design.md) / [Techniques.md](file:///c:/Users/Amily/Desktop/最近科创/青联KIMI/Techniques.md) 中补充首页消息流与板块订阅、新闻栏与夜间审核联动、条文背诵游戏（积分激励）、移动端优化等设计决策与技术实现。
- [完成] 后端 `app/routers/feed.py`：新建首页消息流路由，提供 `GET /api/feed?tab=all|mine|subscriptions|news&limit=20`，按 Tab 聚合多源动态（任务进度/帖子更新/关注板块新帖/新闻），统一按时间倒序，未登录仅可看 all/news。
- [完成] 后端 `app/routers/news.py`：新建新闻栏路由，提供 `GET /api/news` 列表与 `POST /api/news/admin/collect` 管理员手动采集；`_collect_news()` 调用 AI 联网搜索当日合规/未成年人保护/数据安全新闻，输出 JSON 数组并落库 `news` 表，7 天后自动置 is_active=0；同日按 (title, source_url) 去重；明确禁止编造链接。
- [完成] 后端 `app/routers/quiz.py`：新建条文背诵游戏路由，提供：
  - `GET /api/quiz/question`：从 `knowledge_entries`（category=law）随机抽取条目，按句号/分号切分选 20-80 字句子，挖空 2-4 字实词生成 4 选 1 选择题，落库 `quiz_questions`；校验今日已答题数 < 5，达上限返回 4032。
  - `POST /api/quiz/answer`：提交答案，校验未答过本题；正确则 `add_points(user, 1, '条文背诵答对', 'quiz', question_id)`，错误仅写记录不扣分；返回 `{is_correct, answer_index, points_delta}`。
  - `GET /api/quiz/today`：返回今日已答/已对/上限/剩余。
- [完成] 后端 `app/routers/forum.py`：新增 `POST /api/forum/categories/{id}/subscribe`、`DELETE /api/forum/categories/{id}/subscribe`、`GET /api/forum/my/subscriptions` 板块订阅接口，写 `board_subscriptions` 表（UNIQUE(user_id, category_id)）。
- [完成] 后端 `app/database.py`：新增 `board_subscriptions`、`news`、`quiz_questions`、`quiz_records` 四张表及对应索引。
- [完成] 后端 `app/main.py`：挂载 feed/news/quiz 路由（`prefix=/api/feed|/api/news|/api/quiz`）；`SERVICE_PATH_PREFIXES` 补全 notify/feed/news/quiz，使 Root 动态服务开关可拦截；lifespan 启动时同步触发一次 `_collect_news()`（AI 未配置时直接返回）。
- [完成] 后端 `app/routers/root.py`：`SERVICE_NAMES` 增加 `feed`/`news`/`quiz`，Root 可通过后台动态开关。
- [完成] 前端 `static/index.html`：新增首页消息流区（Tab 筛选：全部/我的动态/关注板块/新闻）、右侧新闻栏卡片、系统通知卡片、底部"条文背诵挑战"游戏入口；优化 Hero 与卡片布局。
- [完成] 前端 `static/quiz.html`：新建条文背诵游戏页面，含题目区、4 选项卡片、正误反馈、今日状态、移动端导航折叠。
- [完成] 前端 `static/common.css`：新增 `.feed-card`/`.feed-tabs`/`.feed-list`/`.news-card`/`.quiz-entry`/`.quiz-page-card`/`.quiz-blank`/`.quiz-options`/`.quiz-option`/`.quiz-feedback` 等样式；移动端响应式：768px 导航折叠为汉堡菜单、640px 卡片单列堆叠、触控目标 ≥44px。
- [完成] 前端 `static/common.js`：新增 `loadFeed`/`switchFeedTab`/`loadNews`/`loadQuizQuestion`/`submitQuizAnswer`/`loadQuizToday` 函数，处理 API 请求与动态渲染；所有图标使用内联 SVG，禁止 emoji。
- [完成] 测试 `tests/test_api.py`：新增 `TestFeed`（3 项：公开 Tab、我的动态含任务、关注板块订阅流程）、`TestNews`（5 项：列表、直接写入、7 天过期、管理员采集 AI 未配置降级、非管理员拒绝）、`TestQuiz`（5 项：未登录拒绝、答对加分、答错不加分且不可重复作答、今日状态、每日上限 5 题）共 13 项测试。
- [完成] 修复关键问题：`app/main.py` 未挂载 feed/news/quiz 路由且 `SERVICE_PATH_PREFIXES` 未包含这三项（根因：上轮 Write/Edit 工具缓存未落盘），用 Write 工具整体重写 main.py 后用 MCP Read 验证磁盘文件已正确写入。
- [完成] 集成测试回归：`python -m pytest tests/test_api.py -v` 46 个测试全部通过（原 33 + 新增 13），`Err.log` 为空。
- [完成] SVG 与 emoji 复检：所有新增页面图标均为内联自绘 SVG，无 emoji；无需按 `参考/README.md` 写 SVG 需求清单。

## 2026-08-01 全量检修轮

- [完成] T1 核校 main.py 磁盘文件与路由挂载完整性（feed/news/quiz/notify 与 SERVICE_PATH_PREFIXES）：main.py 路由挂载完整，SERVICE_PATH_PREFIXES 包含所有模块。
- [完成] T2 检查新路由代码健壮性：审查 feed/news/quiz/notify/forum 订阅代码，异常处理、并发安全、边界条件基本到位。Err.log 为空。
- [完成] T3 检查根目录冗余文件：生成清单提示用户，含 debug_*/fix_*/patch_*/tmp_edit*/test_write.txt 等。
- [完成] T4 检查文档与代码一致性：Design.md/Techniques.md 与 app/routers/ 实际路由对齐。
- [完成] T5 调用故障检测专员做健壮性复检：发现 1 项 Critical、3 项 High、4 项 Medium、4 项 Low 缺陷。
- [完成] 修复 C1: news.py _call_ai_plain() 添加 try/except 异常处理，防止裸异常导致 500。
- [完成] 修复 H1: quiz.py submit_answer() 添加 BEGIN IMMEDIATE 获取写锁，防止并发请求同时通过日答题数校验。
- [完成] 修复 H2: notify.py clear_all_messages() 改为 require_roles("admin", "sysadmin", "root", mutating=True)，防止普通用户清空系统通知。
- [完成] 修复 H3: forum.py favorite_post() 添加 try/except sqlite3.IntegrityError，防止并发收藏导致 500。
- [完成] 故障检测专员全局复检（阶段3）：确认 4 项修复均正确、完整，无遗漏异常路径，无新引入的副作用。
- [完成] 集成测试回归：`python -m pytest tests/test_api.py -v` 46 个测试全部通过，Err.log 为空。

## 2026-08-01 反刷治理、讨论版生命周期、AI多模型辩论、Root阈值API集成收尾轮

- [完成] T1 反刷与内容治理补全：字数门槛（check_word_count）、频率限制（check_rate_limit）、查重（check_duplicate）、每日文字总量上限（check_daily_text_bytes/add_daily_text_bytes）、每日图片总量上限（check_daily_image_bytes/add_daily_image_bytes）、长文本自动转 txt（auto_long_text_to_txt），全部实现在 `app/content_guard.py`，集成到 `app/routers/forum.py` 的 create_post/create_reply 和 `app/routers/emails.py` 的 create_email。
- [完成] T1.7 每日 AI 巡查：`app/board_lifecycle.py` 的 `run_daily_patrol()` 扫描未巡查帖子/回复并标记，`app/main.py` lifespan 中调用。
- [完成] T2.1+T2.2 讨论版生命周期自动化：`app/board_lifecycle.py` 的 `run_daily_lifecycle()` 检查 evidence_count 自动封存，closed 超过配置天数后自动归档，写入系统通知。
- [完成] T2.3 板块认领 CRUD：`app/routers/forum.py` 实现 `POST /board-claims`（认领）、`GET /board-claims/my`（列表）、`PUT /{claim_id}`（更新草稿）、`POST /{claim_id}/submit`（提交审核）、`POST /{claim_id}/abandon`（放弃），含积分门槛校验、同时认领上限、截止时间。
- [完成] T2.4 证据包整理：`app/board_lifecycle.py` 的 `generate_evidence_package()` 收集板块内帖子/回复/图片生成 txt 证据包，写入 `categories.evidence_package`，封存时自动调用。
- [完成] T3.1 AI 多模型辩论审核模块：`app/routers/ai_review.py` 实现 `run_ai_initial_review()`（AI 初审）和 `run_ai_debate()`（多模型辩论），支持 Deepseek/Qwen/MiniMax 攻击方 + KIMI/Qwen 验证方，默认 1-3 轮，最多 5 轮，模型列表由 root 配置。
- [完成] T3.2 AI 审核集成到邮件流程：`app/routers/emails.py` 新增 `submit-review` 端点（draft→ai_pending→human_pending/rejected），扩展 `admin_review_email` 支持 ai_pending/human_pending/ai_debate 状态，修改 `send_email` 草稿状态先走 AI 审核再发送，`app/main.py` 中 `_check_expired_email_reviews()` 检查超时 human_pending 邮件自动触发 AI 辩论。
- [完成] T4 Root 可配置阈值 API：`app/routers/root.py` 实现 `GET /api/root/thresholds`（读取所有阈值含默认值兜底）和 `PUT /api/root/thresholds`（批量更新，含值有效性校验：必须为非负整数）。
- [完成] 修复 `app/routers/forum.py` 缺失 `get_current_user` 导入（`my_claims` 函数中使用 `Depends(get_current_user)` 但未导入）。
- [完成] 修复 `app/routers/root.py` 阈值更新缺少值有效性校验（添加非负整数校验）。
- [完成] 清理临时测试脚本 `_run_tests.py`。
- [完成] 子 AGENT 全局故障检测复检：无明显阻塞级缺陷，误报已核实排除，仅修复真实问题（阈值校验）。
- [完成] Err.log 为空，无残留错误。
