# Techniques.md — 技术方案文档

> 记录实现方法与技术选型。更新于 2026-07-31。

## 一、技术栈

- 后端：Python 3 + FastAPI（仅依赖 fastapi / uvicorn / python-multipart；测试另需 httpx）
- 数据库：SQLite（标准库 sqlite3，参数化查询，每请求新建连接）
- 前端：静态 HTML + 原生 JS（Fetch API），由 FastAPI StaticFiles 托管
- 认证：自实现 HS256 JWT（标准库 hmac/hashlib/base64），密码 PBKDF2-HMAC-SHA256（10 万次迭代，16 字节随机盐）

## 二、目录结构

```
app/
  main.py        # 应用装配、全局异常中间件(写Err.log)、静态托管、模块开关挂载
  config.py      # 模块开关 ENABLE_XXX、密钥、路径、AI 配置(环境变量)
  database.py    # 连接工厂 + 全量建表 + 种子触发
  security.py    # JWT/密码哈希/转义/CSRF/权限依赖
  errlog.py      # Err.log 写入工具(线程锁)
  seed.py        # 知识库与论坛初始内容
  routers/
    auth.py      # 注册/登录/刷新/登出/me
    tasks.py     # 任务提交(multipart)、我的任务、公开列表、平台列表
    forum.py     # 板块/帖子/回复/点赞/收藏/举报/标签
    points.py    # 签到/积分流水/排行榜(周月总)
    knowledge.py # 知识库公开查询
    admin.py     # 审核/加精/举报处理/用户管理/知识库管理/日志/蜜罐/封禁
    root.py      # Root 专属：服务开关、管理员管理
    agent.py     # AI 导游(urllib 调用 OpenAI 兼容接口) + Future.md 记录
    chat.py      # 私信与群聊
    notify.py    # 首页每日简报 + 系统通知（system_messages 表）
    ai_review.py # AI 多模型辩论审核编排（邮件/证据包）
app/
    attack_detector.py # 攻击性内容/越狱攻击检测模块（规则引擎）
static/          # 全部前端页面 + css/js
uploads/         # 上传图片(随机文件名)
data/            # SQLite 数据库文件
storage/briefings/  # 每日简报 JSON 缓存（briefing_YYYY-MM-DD.json）
tests/           # 集成测试(TestClient)
```

## 三、关键实现方案

1. **统一响应**：工具函数 ok(data)/fail(code,message)，全局异常中间件兜底 `{code:500}` 并写 Err.log。
2. **JWT**：header/payload base64url 编码 + HMAC-SHA256 签名；payload 含 sub/role/type/exp；access 7 天、refresh 30 天；前端 401 且 code=4010 时用 refresh 自动续期并重放原请求。
3. **CSRF**：登录/刷新时签发随机 csrf_token 存于用户行；变更类请求依赖校验 `X-CSRF-Token` 头匹配。
4. **XSS**：`escape_html` 服务端转义入库前不改原文、输出时由前端统一 `textContent`/转义；自研 mini Markdown：先整体转义，再按 代码块→行内码→粗斜体→链接(白名单协议)→标题→引用→列表 顺序正则替换。
5. **上传**：扩展名白名单 + 魔数校验(jpg FFD8FF / png 89504E47 / webp RIFF+WEBP)，单张 5MB、单次 5 张，`uuid` 文件名存 uploads/，Task.images 存 JSON 数组。
6. **审核联动**：任务通过 → 事务内创建/复用平台一级分类 + `[平台]-[类型]` 二级板块、任务状态置 approved、+5 积分(优秀再 +5)、写 AdminLog。
7. **积分**：PointLog 流水 + User.points 冗余缓存；签到判重按日期、连续签到比对昨天；回复点赞达 10 次触发 +1（用流水去重保证仅一次）；排行榜按 PointLog 时间窗聚合（周=近7天，月=近30天，总=全部）。
8. **蜜罐**：静态页 `panel.html` 含明文"前端验证"注释与 Cookie 判断诱饵；`/api/honeypot/login` 记录 IP+Cookie+payload 入 honeypot_logs 并返回伪造数据；真实后台 admin.html 走 JWT。
9. **AI 导游**：标准库 urllib 调 OpenAI 兼容 /chat/completions（AI_API_URL/AI_API_KEY/AI_MODEL 环境变量），system 注入 Design.md 摘要；未配置时返回静态导览文案；`/api/agent/future` 将需求追加到 Future.md。
10. **模块开关**：config.py 中 ENABLE_XXX；main.py 按开关条件 include_router；`/api/config/modules` 下发开关，前端据此隐藏入口。
11. **测试**：FastAPI TestClient 端到端覆盖 注册/登录/续期、任务提交审核联动、论坛 CRUD/点赞/收藏/举报、签到与积分、排行榜、蜜罐记录、统一响应与分页、上传校验。测试通过 `QLKIMI_DB` / `QLKIMI_UPLOADS` / `QLKIMI_ERR_LOG` 环境变量隔离数据库与上传目录。
12. **任务审核脱敏护栏**：管理员审核任务截图时，前端在预览区顶部显示显式合规提示；提供极简 Canvas 打码工具（拖拽绘制黑色矩形马赛克）。审核提交时前端将打码后的图片 Base64 回传，后端解码覆盖原文件并删除原始上传文件；`AdminLog` 记录"对任务 X 的图片 Y 执行脱敏打码"。
13. **AI 导游边界**：调用 AI 前将 Design.md 摘要作为 system prompt；用户问题若明显超出 Design.md 范围，不调用 AI，直接追加到 Future.md 并返回固定话术"这个提议很好，已记录至 Future.md，将由管理员评估。"
14. **积分反刷**：点赞/点踩前校验 `target.user_id != current_user.id`；加精前校验 `post.user_id != current_user.id` 且当前用户角色为 moderator/admin/sysadmin。
15. **注册设备指纹**：前端在注册表单中附加 `device_fingerprint`（Canvas 指纹 + 屏幕分辨率 + 色深 + 时区拼接后 SHA256）。后端写入 `users.device_fingerprint`，并在同一指纹已存在 ≥3 个账号时将新账号 `is_suspicious` 标记为 1。sysadmin 可在管理后台查看可疑账号列表并人工处理。
16. **初始内容种子**：`seed.py` 在数据库为空时创建「社区公告」板块与 6 条知识库条目（法律/案例/指南/Qoder）；首个注册用户注册时自动在该板块发布欢迎帖。
17. **管理员可配置项**：`admin_settings` 表以 key-value 形式存储 POP3/SMTP 与 AI API 参数；`agent.py` 与邮件发送模块优先读取库内配置，其次环境变量，实现后台即时生效。
18. **邮件代发**：用户提交表单后由 `emails.py` 生成标准邮件正文，状态 `draft` → `pending`（待管理员复核）→ `sent`；使用标准库 `smtplib` 通过后台配置的 SMTP 发送，发件人固定为 `noreply@` 统一邮箱；发送原文备份存入 `emails.backup_copy`；同时支持 `send_method='self'`，返回可复制模板。
19. **POP3 收件箱**：后台提供 `POST /api/admin/emails/fetch-inbox` 手动触发收取，使用标准库 `poplib` 连接管理员配置的 POP3 服务器，拉取邮件后用 `email.parser.BytesParser` 解析主题、发件人、收件人、正文与日期，存入 `email_inbox` 表；`message_id` 用于去重。管理员可在后台查看列表、读单封邮件、标记已读。
20. **法律知识库**：`knowledge_entries` 新增 `source_url` 与 `is_official`；`knowledge_keywords` 建立关键词到条目/条款的索引；`/api/knowledge/daily` 按日期轮转返回官方法律条目并写入 `daily_law` 去重。
21. **积分用途**：`users.nickname_color` 记录荣誉颜色；`applications` 表处理志愿者/管理员权限申请；积分规则通过 `add_points` 统一写入，无货币价值。
22. **上传合规检测**：任务提交时后端校验 `no_sensitive_declared` 字段；保存图片后调用 `ai_check.py` 中多模态 AI 检测接口（OpenAI 兼容 /chat/completions，支持 image_url），若判定含第三方个人信息，立即删除该图片文件并将任务状态置为 `returned`、标记 `admin_label='needs_supplement'`。
23. **Root 双因素登录**：`app/routers/auth.py` 提供 `/root/step1` 与 `/root/step2`；step1 校验 root 账号密码后生成 6 位数字验证码与临时令牌，存入 `root_login_codes`；通过 `_send_root_code` 使用后台 SMTP 配置将验证码发送至 `ROOT_EMAIL`（默认 `13965124556@163.com`）；step2 校验临时令牌+验证码后签发正式会话。验证码有效期与目标邮箱仅后端配置，不暴露给前端。
24. **多维度封禁**：`bans` 表记录 `account`/`email`/`device` 三类封禁；`security._check_bans` 在登录、续期、`get_current_user` 时联动校验账号状态、邮箱封禁、设备封禁；`auth.register` 在写入前校验邮箱/设备是否被封禁；设备封禁同时将对应指纹用户标记为可疑。
25. **管理员权限自保护**：`admin.py` 中角色变更与封禁接口拒绝 `target_user_id == current_user.id`；拒绝将角色改为 `root`；通过 `ROLE_WEIGHT` 限制低权重管理员无法操作高权重账号；最后一名 `sysadmin` 不可降级或封禁。root 相关操作走独立的 `root.py`。
26. **动态服务开关**：`main.py` 中 `service_switch_guard` 中间件拦截 `/api/*` 请求，根据 `admin_settings` 中 `svc_{name}` 的值判断服务是否关闭；关闭时返回 `code=5030`。认证、Root、配置模块接口不受拦截。root 通过 `/api/root/services/{name}` 读写开关。
27. **私信与群聊**：私信表 `messages` + 会话表 `conversations`（`user_a`/`user_b` 唯一索引，发送时维护 `last_message_at`）；群聊表 `groups`/`group_members`/`group_messages`。私信禁止发给自己，列表时自动将对方发来的消息标记已读；群聊发送与查看均校验成员身份。
28. **官方收件箱一键公开**：`email_inbox` 表新增 `post_id` 与 `is_public`；管理员调用 `POST /api/emails/admin/emails/inbox/{id}/publish` 关联帖子后，`GET /api/emails/inbox/public` 可公开列出已关联邮件，便于在论坛主题侧展示平台回复。
29. **邮箱注册上限**：`users.email` 移除唯一约束；注册时查询同一邮箱已有账号数，≥2 时返回 `code=4003`；登录时若同一邮箱密码匹配多个账号且未提供昵称，返回 `code=4007` 要求补充昵称。
30. **Root 账号初始化**：`main.py` 启动时检查环境变量 `QLKIMI_ROOT_PASSWORD`，若存在且长度≥8、且数据库中尚无 root 账号，则自动创建 `root@qlkimi.local` 的 root 用户，避免通过注册产生高权限账号。
31. **群聊治理表结构**：`groups` 增加 `owner_id`、`announcement`、`join_type`（open/approval）、`created_at`；`group_members` 增加 `role`（member/admin）、`joined_at`；`group_messages` 增加 `is_redline`、`is_deleted`、`ai_scan_at`、`deleted_at`；新增 `group_reports` 表记录举报人、被举报消息、理由、AI 判断结果、处理动作。硬红线消息单独长期保留。
32. **群聊 AI 被动审核**：举报提交后调用后台配置的视觉/文本模型扫描被举报聊天记录，30 秒内返回分类（硬红线/非红线不当/无违规/恶意举报）；硬红线立即删除消息、封禁发布者、可解散群聊；非红线不当生成提醒给群主；恶意举报反噬举报者积分。复杂情况 24 小时内转人工，逾期再次 AI 全量扫描。
33. **积分分层权限校验**：在 `forum.py`（发帖/回复/发起讨论版/接管板块）、`chat.py`（建群/群聊发言）、`emails.py`（认领代发）等入口前置 `require_points(min_points)` 依赖；`users.points` 实时缓存，`PointLog` 流水保证可追溯；0-3 分用户所有发言入口返回 `code=4031`。
34. **讨论版生命周期**：`categories` 增加 `status`（open/closed/archived）、`allow_email`（默认 false）、`evidence_count`、自动统计的 `post_count`、`closed_at`、`archived_at`、`claim_user_id`、`claim_deadline`；定时任务（或每次写入时检查）在 `evidence_count >= root 阈值` 时自动将板块置为 `closed`；closed 3 天后触发召集邮件；未允许代发的板块 closed 3 周后置为 `archived`。新增 `board_claims` 表记录认领人、认领时间、截止时间、共享草稿、状态（claimed/draft/submitted/abandoned）。
35. **邮件代发 AI 多模型辩论**：`emails.py` 中邮件状态扩展为 `draft` → `ai_pending`（AI 初审）→ `human_pending`（24 小时人工窗口）→ `ai_debate`（人工未审）→ `approved`/`rejected`/`sent`。初审不合格直接退回并记录原因；明显刷 token 直接封禁。人工窗口超时后调用 `ai_review.py` 编排多模型：Deepseek/Qwen/MiniMax 负责攻击性质疑，KIMI/Qwen 负责搜索验证，最终投票；默认 1-3 轮即可判定，争议大时最高 5 轮。模型职责列表存于 `admin_settings`，root 可配置，修改前测试 API 稳定性。
36. **反刷与内容治理**：
    - **查重**：写入 `posts`/`replies` 时计算文本指纹（如 simhash 或简单 n-gram），24 小时内相似度超阈值则拒绝并记录 `similar_to_id`；
    - **频率限制**：按用户 ID + 操作类型在 Redis/内存/数据库记录最近 N 次，超限则 `code=4290`；
    - **字数门槛**：发帖/回复 `word_count < threshold` 直接退回；
    - **长文本转 txt**：超过一定长度时后端将文本内容写入 uploads/ 下 txt 文件，正文存文件路径；
    - **图片压缩**：上传后使用 Pillow（若允许引入）或保持现有尺寸限制，确保单用户每日图片总量 ≤ 4M；
    - **每日上限**：单用户每日文字总量 ≤ 10k，由 root 配置。
37. **攻击性内容检测**：`app/attack_detector.py` 模块实现独立规则引擎，两级规则（硬性攻击关键词命中即封禁 + 可疑模式标记记录）。`detect(text)` 返回 `AttackResult`；`handle_attack(conn, user_id, reason)` 执行封禁+AdminLog+系统通知。已集成到以下入口：`agent.py` 的 `/api/agent/chat`（AI 导游输入前检测）、`emails.py` 的 `POST /api/emails`（邮件代发提交前检测）、`tasks.py` 的 `POST /api/tasks`（任务提交前检测）。命中硬性规则立即封禁账号并返回 `code=4030`；可疑模式仅记录 AdminLog 不封禁，继续正常流程。
38. **证据包最终整理**：封存板块进入邮件撰写阶段前，由 AI 对板块内所有证据进行最终审核整理：删除重复/无关图片、补充说明、合并为一份图片证据集与一个 txt 文字证据集；整理结果写入 `categories.evidence_package`（JSON 记录图片列表 + txt 路径）。
39. **每日 AI 巡查与关键词即时审核**：定时任务每天扫描一次全量新增/待审内容；内容写入时若命中危险关键词库（涉政/涉黄/暴力/恐怖/攻击指令等）则立即触发 AI 审核，不再等待定时任务。
40. **Root 可配置阈值**：所有治理数字（0/3/10/30/200 积分门槛、证据限额 40、封存 3 天、等待 24 小时、辩论轮数 5、每日 10k/4M 上限、查重时间窗、恶意举报扣分区间等）均存于 `admin_settings`，key 形如 `threshold_points_speak`、`threshold_evidence_close`、`threshold_debate_rounds` 等；root 通过 `/api/root/thresholds` 读写，其他角色只读或不可见。
41. **首页每日简报**：`app/routers/notify.py` 提供 `GET /api/notify/briefing`；后端先读 `storage/briefings/briefing_YYYY-MM-DD.json` 当日缓存，命中则直接返回；未命中时调用后台配置的 AI 接口（`agent.py` 的 `_ai_config()` 复用），prompt 要求模型联网搜索近 7 日国家/行业层面与互联网平台合规、未成年人保护、个人信息保护相关的新法规/政策/监管动态，输出 JSON `{summary, source, source_url, kind}`，`kind=policy` 表示有新政策，`kind=history` 表示降级为"历史上的今天"。生成结果落盘缓存并写入 `system_messages` 表（type=`daily_briefing`）便于在通知列表中回看。AI 未配置或调用失败时返回静态兜底文案。应用启动时 `main.py` lifespan 中触发一次 `_generate_daily_briefing()` 保证首日有内容。
42. **首页系统通知**：`system_messages` 表字段 `id/type/title/content/ref_type/ref_id/is_read/created_at`；`add_system_message()` 工具函数供审核流程、root 公告、讨论版生命周期、邮件代发进度等事件调用；`GET /api/notify/messages?limit=20` 返回最近通知（按 id 倒序），`POST /api/notify/messages/read` 全部已读，`DELETE /api/notify/messages/{id}` 单条删除，`DELETE /api/notify/messages` 清空。前端首页右侧/底部展示未读计数与列表。
43. **首页视觉与品牌**：`static/index.html` 顶部为带渐变背景的 Hero 区，左侧自绘 SVG Logo（盾牌 + 朝霞 + 联结节点，对应"青联合规监督社区"），右侧展示项目立意与快捷 CTA；其下为"每日简报"卡片（quote-card 样式，含 quote-mark 装饰 SVG 与 anim-fade 入场动画）；再下为系统通知列表 + 最新举报/帖子 + 快捷入口。所有图标使用内联 SVG，禁止 emoji。`common.css` 新增 `.hero`、`.brand-logo`、`.quote-card`、`.quote-mark`、`.anim-fade`、`.notify-list`、`.notify-item` 等样式；移动端通过媒体查询自适应单列布局。
44. **首页消息流与板块订阅**：新增 `app/routers/feed.py`，提供 `GET /api/feed?tab=all|mine|subscriptions|news&limit=20`，按 Tab 聚合多源动态：`mine` 取当前用户的任务进度+自己发过/回复过的帖子更新；`subscriptions` 取 `board_subscriptions` 关联的板块新帖；`news` 取 `news` 表最近 7 天；`all` 合并以上并按时间倒序。`board_subscriptions` 表 `(user_id, category_id, created_at)` 唯一索引，`POST /api/forum/categories/{id}/subscribe` 与 `DELETE` 走 upsert/删除。未登录用户仅可看 `all`/`news` Tab。
45. **新闻栏与夜间审核联动**：新增 `app/routers/news.py`，提供 `GET /api/news?limit=20` 展示最近 7 天新闻。新闻生成由 `news.py` 内 `_collect_news()` 完成：调用后台配置的 AI 接口（复用 `agent._ai_config()`），prompt 要求模型联网搜索当日与互联网合规、未成年人保护、个人信息保护、数据安全相关的权威新闻，输出 JSON 数组 `[{title, abstract, source_name, source_url, published_at}]`，并明确禁止编造链接。生成结果写入 `news` 表。`main.py` lifespan 中在每日简报生成后触发一次 `_collect_news()`；同时 `news.py` 暴露 `POST /api/news/admin/collect` 供管理员手动触发。`news` 表 `(id, title, abstract, source_name, source_url, published_at, collected_at, is_active)`，查询时自动将 7 天前的记录置 `is_active=0`。
46. **条文背诵游戏**：新增 `app/routers/quiz.py`，提供：
    - `GET /api/quiz/question`：从 `knowledge_entries`（category=law）中随机抽取一条，对其 content 挖空 1-2 个关键词生成 4 选 1 选择题；题目与选项落库 `quiz_questions`（避免重复生成），返回 `{question_id, blank_text, options, knowledge_id}`；同时校验今日已答题数 < 5，达上限返回 `code=4032`。
    - `POST /api/quiz/answer`：提交 `{question_id, option_index}`，校验 `quiz_records` 未答过本题；正确则 `add_points(conn, user_id, 1, '条文背诵答对', 'quiz', question_id)` 并写 `quiz_records`（INSERT 包裹 try/except IntegrityError 防并发双答 500）；错误仅写记录不扣分。返回 `{is_correct, answer_index, points_delta}`。
    - `GET /api/quiz/today`：返回今日已答题数、已得分、上限。
    - 题目生成算法：对法律条款按句号/分号切分，选长度 20-80 字的句子，随机挖空 1-2 个 2-4 字的实词，干扰项从同法其他条款抽取相近词或同义词。
47. **移动端优化**：`common.css` 全站媒体查询断点 640px；导航在移动端折叠为汉堡菜单（纯 CSS + 少量 JS toggle）；卡片单列堆叠；字号最小 14px，触控目标最小 44×44px；表格横向滚动容器 `.table-scroll{overflow-x:auto}`；首页消息流在移动端单列，桌面端 `.home-grid` 双栏。
48. **全量检修（2026-08-01）**：本轮不引入新功能，仅做完整性与兼容性复检。复检手段：①核对 `app/main.py` 磁盘文件已正确挂载 feed/news/quiz/notify 路由，且 `SERVICE_PATH_PREFIXES` 已补全这四项（上轮已用 Write 整体重写修复 Read/Edit 工具缓存未落盘问题）；②运行 `python -m pytest tests/test_api.py -v` 46 项全通过；③`Err.log` 已为空；④文档与代码状态一致（Design.md 决策记录、Techniques.md 实现方案与 `app/routers/` 实际路由对齐）。已知技术债：根目录残留历史调试脚本（`debug_*.py`/`fix_*.py`/`patch_*.py`/`tmp_edit*.py`/`test_write.txt`），按文件操作红线规则不自行删除，提示用户手动清理。
49. **AI 多模型辩论审核集成到邮件代发流程（2026-08-01）**：
    - `emails.py` 新增 `POST /api/emails/{id}/submit-review` 端点：用户提交草稿邮件进入 AI 审核流程；状态机 `draft → ai_pending → human_pending（初审通过）/ rejected（初审退回）`；初审通过后加激励积分（+2）。
    - `send_email` 端点重构：`draft`/`failed` 状态不再直接发送，而是先进入 AI 审核流程；`approved` 状态可直接发送；其他状态返回错误提示。
    - `admin_review_email` 扩展支持 `ai_pending`/`human_pending`/`ai_debate` 三种状态：管理员选择 `effective` → `approved`，`needs_supplement` → `rejected`；操作写入系统通知。
    - `main.py lifespan` 新增 `_check_expired_email_reviews()`：定时检查 `human_pending` 超过 `threshold_human_pending_hours`（默认 24h）的邮件，自动触发 `ai_review.run_ai_debate()` 多模型辩论。
    - 积分规则：AI 初审通过 +2 分（`邮件代发通过初审`）；管理员审核有效 +3 分（`代发邮件审核有效`）。
50. **证据包生成集成到讨论版生命周期（2026-08-01）**：`board_lifecycle.run_daily_lifecycle()` 在封存板块（`evidence_count >= threshold` 时）自动调用 `generate_evidence_package()` 生成证据包（图片证据集 + txt 文字证据集），写入 `categories.evidence_package`。
51. **鼠标握手机制（2026-08-08）**：新增 `app/handshake.py` 模块，使用 `threading.Lock` 保护的内存字典 `_sessions: dict[str, dict]` 记录 sid → {user_id, last_mouse_active, last_request_at, fail_count, created_at, rotated}。`issue_sid(user_id)` 生成 32 字节 URL-safe 随机令牌并存入字典；`update_handshake(sid)` 更新鼠标活跃时间戳；`is_handshake_active(sid)` 检查 `now - last_mouse_active <= timeout`（timeout 从 `admin_settings` 读取 `threshold_handshake_timeout`，默认 60 秒）；`require_handshake` 为 FastAPI 依赖，从 `X-SID` 头提取 sid 并校验：sid 不存在/已轮换/不匹配用户 → 记录 fail_count，达阈值（`threshold_handshake_fail_limit`，默认 3）时调用 `rotate_user_sids(user_id, reason)` 轮换该用户全部 sid 并写系统通知，返回 `code=4034`；sid 有效但无鼠标活动 → 返回 `code=4033`。root 账号豁免握手校验。`auth.py` 在 `_issue_session()` 中调用 `issue_sid(user_id)` 并将 sid 返回给前端；`POST /api/auth/handshake` 从 X-SID 头读取 sid 更新心跳；`GET /api/auth/handshake/status` 返回当前 sid 状态。前端 `common.js` 新增 `HandshakeManager`：监听 `document` 的 `mousemove/touchmove/pointermove` 事件（节流），每 15 秒发送一次心跳（携带 X-SID 头）；收到 4033 时显示全屏遮罩 `#handshake-overlay`，用户移动鼠标后自动发送心跳恢复；收到 4034 时弹出安全提醒模态框并清除认证状态、跳转登录页。握手依赖应用到所有发言/内容创建端点（forum 发帖/回复、chat 私信/群聊、agent 对话、emails 代发、tasks 提交、quiz 答题）。
52. **全站前端美化（2026-08-08）**：`common.css` 新增组件级样式：`.page-header`（页面标题区）、`.form-card`（表单卡片）、`.list-item`（列表项卡片化）、`.empty-state`（空状态）、`.skeleton`（骨架屏）、`.modal-overlay`/`.modal-box`（模态框）、`.btn-group`（按钮组）、`.stat-grid`/`.stat-card`（统计卡片）、`.action-bar`（操作栏）、`.handshake-overlay`（握手遮罩）；`common.js` 新增 `showModal(title, body, actions)` 替代 `alert/confirm/prompt`、`confirmDialog(msg)` 返回 Promise、`promptDialog(msg, defaultVal)` 返回 Promise。所有页面统一导航栏结构（SVG Logo + nav-links + nav-toggle + nav-user + themeToggle），通过 `normalizeNavigation()` 自动补全。
53. **SID 安全升级与全站前端统一（2026-08-08）**：在 51/52 基础上完成两项升级：①**SID 会话密钥轮换**——`handshake.py` 从 user_id 键升级为 per-session sid 键，新增 `issue_sid/rotate_user_sids/record_handshake_failure`，`require_handshake` 从 `X-SID` 头校验 sid 有效性+鼠标活跃+fail_count 阈值触发轮换；`auth.py` 的 `_issue_session` 签发 sid 并返回；`common.js` 的 `authHeaders()` 自动附加 `X-SID` 头，`HandshakeManager` 心跳携带 sid，4034 时弹安全提醒并清除认证。②**全站 11 个旧页面统一**——tasks/register/post/profile/knowledge/rankings/agent/admin/emails/disclaimer/panel 全部升级为新导航栏（SVG Logo + nav-toggle + nav-links + 完整链接）+ 组件化内容（page-header/form-card/list-item/stat-grid）+ 替换 alert/prompt/confirm 为 showToast/confirmDialog/promptDialog + 清理内联样式 + 添加 anim-in 入场动画。
54. **SID 握手安全漏洞修复与健壮性升级（2026-08-08 第二轮）**：故障检测审查后修复多项隐患：
    - **心跳端点 sid 轮换检测**：`handshake.py` 新增 `update_handshake_checked(sid, user_id) -> (status, now)`，原子地校验 sid 归属当前用户 + 轮换状态 + 更新活跃时间戳（避免 `is_sid_rotated` + `update_handshake` 间的 TOCTOU）。`auth.py` `handshake_heartbeat` 改用该函数：sid 已轮换 → 4034，sid 不属于当前用户 → 4033，校验通过 → 更新心跳。
    - **配置项 DoS 防护**：`database.py` 将 `threshold_handshake_timeout`/`threshold_handshake_fail_limit` 纳入 `DEFAULT_THRESHOLDS`（默认 60/3），新增 `THRESHOLD_MIN_VALUES` 字典定义硬下限（timeout≥10、fail_limit≥1 等）；`root.py` `update_thresholds` 在非负整数校验后追加硬下限校验；`handshake.py` `_get_timeout`/`_get_fail_limit` 强制 `max(val, hard_min)` 兜底，三重防护防止 root 误配 0/负值导致全站 DoS 或首次失败即轮换。
    - **sid 归属校验三件套**：`handshake.py` 新增 `update_handshake_checked`（心跳）、`get_handshake_status_for_user(sid, user_id)`（状态查询，不匹配返回空状态防信息泄露）、`clear_handshake_for_user(sid, user_id)`（登出，仅清除属于当前用户的 sid，同时清 `_user_fails`）。`auth.py` 三个对应端点全部改用归属感知版本，防跨用户保活/清除会话 DoS。
    - **旧 sid 即时失效**：`handshake.py` 新增 `invalidate_user_sids(user_id)` 静默失效该用户所有旧 sid（标记 `rotated=True` 但不写系统通知，避免登录轰炸）；`auth.py` `_issue_session` 签发新 sid 前调用该函数，消除旧 sid 在 `_maybe_cleanup` 回收前（约 180s）仍可被 `require_handshake` 接受的复用窗口。
    - **失败计数器内存上限**：`handshake.py` `_record_user_fail` 增加单用户失败记录上限 `_FAIL_LIST_MAX=200`，超过则保留最近记录（足够触发轮换判定）；同时在失败路径调用 `_maybe_cleanup` 触发周期性清理，防高频失败请求导致内存放大。
    - **前端后台标签心跳恢复**：`common.js` `HandshakeManager.init` 新增 `document.visibilitychange`（切回前台立即补发心跳）与 `window.focus`（窗口获焦补发心跳）监听，避免浏览器后台节流导致 sid 超时后用户切回需等待下个定时周期或移动鼠标。
55. **风控监控后台（2026-08-08）**：服务器后台监控工具，实现操作审计、异常 IP 检测、双因素验证、IP 封禁管理：
    - **审计日志三处冗余**：`risk_control.py` `log_action` 每次后台操作同时写入 DB `risk_audit_logs` 表 + 文件 `storage/risk_audit/YYYYMM.log` + 高危操作（danger/critical）额外写 `Err.log`，三处冗余防删除。文件写入使用 `threading.Lock` 防并发冲突，DB 写失败时仍写文件保证审计不丢。
    - **风险分级引擎**：`classify_risk(method, path, action)` 基于方法/路径/action 评估为 info/warn/danger/critical 四级。DELETE→danger（单条删除）；路径含 batch/bulk→critical（批量操作）；路径含 /role、/ban、/services/、/thresholds→critical（角色变更/封禁/服务开关/阈值修改）；/settings + PUT/POST→danger（敏感配置）；其他后台写操作→warn；后台读操作→info。
    - **异常 IP 检测**：`is_ip_suspicious(ip, actor_id)` 判定条件：不在白名单 + 近 7 天未在 `risk_audit_logs` 出现过（新 IP）+ 与该用户历史常用 IP 不同（账号异地登录）。本地 IP（127.0.0.1/::1/testclient 等）和白名单 IP 豁免。
    - **2FA 挑战与校验**：`issue_2fa_challenge` 生成 6 位验证码，PBKDF2 哈希存储（不存明文），32 字节 URL-safe challenge_token。配置 `RISK_2FA_EMAIL` 或 `ROOT_EMAIL` 时发邮件不返回明文（防中间人），否则本地返回（仅服务器本地访问场景）。`verify_2fa` 校验验证码，失败累计 `fail_count`，达阈值（`RISK_2FA_MAX_FAILS=3`）自动封禁 IP + 封禁用户账号 + 标记挑战 `resolved=-1`。
    - **2FA 令牌复用**：`is_2fa_verified(challenge_token, actor_id, max_age=300)` 检查令牌是否已通过验证（`resolved=1`）且在 5 分钟窗口内，且 `actor_id` 与当前请求操作者一致（防 A 的令牌授权 B 的操作）。中间件校验 `X-2FA-Token` 头，已验证令牌 5 分钟内可复用，避免每个高危操作都重验。
    - **风控边界中间件**：`main.py` `risk_control_boundary` 拦截后台路径（/api/admin、/api/root、/api/risk）所有访问：①封禁 IP 直接阻断（4036）；②轻量解析 JWT 获取 actor_id 用于日志；③critical 级操作或异常 IP 触发 2FA（4035），异常 IP 且未配置邮件直接拦截（4037）不暴露验证码；④2FA 接口自身（/api/risk/2fa/*）豁免 2FA 校验；⑤每次操作记录到审计日志。
    - **前端全局 2FA 拦截**：`common.js` 新增 `TwoFaManager` 类，`api()` 函数拦截 4035 响应自动弹出验证码模态框——服务器本地访问时自动填入验证码（`sent_via=local`），邮箱模式用户手动输入；验证通过后存储令牌到 `sessionStorage`（5 分钟复用窗口），`authHeaders()` 自动附加 `X-2FA-Token` 头，并自动重试原请求（`_retry2fa` 标志防无限重试）。4036/4037 显示拦截 toast 提示。



## 四、环境变量

| 变量 | 用途 | 默认 |
|------|------|------|
| QLKIMI_SECRET | JWT/CSRF 签名密钥 | dev 默认值(生产必须更换) |
| AI_API_URL / AI_API_KEY / AI_MODEL | AI 导游接口配置 | 空(降级静态导览) |
| QLKIMI_DB | SQLite 数据库路径 | `data/qlkimi.db` |
| QLKIMI_UPLOADS | 上传图片目录 | `uploads/` |
| QLKIMI_ERR_LOG | 运行时错误日志路径 | `Err.log` |
| QLKIMI_ROOT_PASSWORD | Root 账号初始化密码（长度≥8时生效） | 空（不自动创建 root） |
| QLKIMI_ROOT_EMAIL | Root 登录验证码接收邮箱 | `13965124556@163.com` |
| QLKIMI_RISK_2FA_EMAIL | 风控 2FA 验证码接收邮箱（空则复用 ROOT_EMAIL，均空则本地返回明文） | 空 |

## 五、交付顺序（与用户要求一致）

数据库 → 认证 → 任务上传与审核 API → 论坛 CRUD API → 积分 API → 管理面板 API → AI 导游 → 前端全部页面 → 集成测试 → 知识库与论坛内容生成。
