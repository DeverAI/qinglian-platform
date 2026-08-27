"""SQLite 数据层：连接工厂 + 全量建表。

约定：所有查询一律使用参数化占位符，禁止字符串拼接 SQL（防注入）。
时间戳统一 TEXT，默认 datetime('now','localtime')。
"""
import sqlite3
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    nickname TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','moderator','admin','sysadmin','root')),
    points INTEGER NOT NULL DEFAULT 0,
    guardian_declared INTEGER NOT NULL DEFAULT 0,
    is_banned INTEGER NOT NULL DEFAULT 0,
    is_suspicious INTEGER NOT NULL DEFAULT 0,
    device_fingerprint TEXT NOT NULL DEFAULT '',
    nickname_color TEXT NOT NULL DEFAULT '',
    csrf_token TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_users_fingerprint ON users(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    platform_name TEXT NOT NULL,
    issue_type TEXT NOT NULL CHECK(issue_type IN ('隐私条款不合理','霸王条款','数据滥用','未成年人保护缺失','其他')),
    clause_text TEXT NOT NULL,
    description TEXT NOT NULL,
    law_reference TEXT NOT NULL DEFAULT '',
    images TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','reviewing','approved','rejected','returned')),
    review_note TEXT NOT NULL DEFAULT '',
    reviewer_id INTEGER REFERENCES users(id),
    is_excellent INTEGER NOT NULL DEFAULT 0,
    is_mosaicked INTEGER NOT NULL DEFAULT 0,
    admin_label TEXT NOT NULL DEFAULT '' CHECK(admin_label IN ('','effective','needs_supplement')),
    category_id INTEGER REFERENCES categories(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_user ON tasks(user_id);

CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    parent_id INTEGER REFERENCES categories(id),
    platform_name TEXT NOT NULL DEFAULT '',
    issue_type TEXT NOT NULL DEFAULT '',
    task_id INTEGER REFERENCES tasks(id),
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed','archived')),
    allow_email INTEGER NOT NULL DEFAULT 0,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    post_count INTEGER NOT NULL DEFAULT 0,
    closed_at TEXT,
    archived_at TEXT,
    claim_user_id INTEGER REFERENCES users(id),
    claim_deadline TEXT,
    evidence_package TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_categories_parent ON categories(parent_id);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER NOT NULL REFERENCES categories(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    is_essence INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'normal' CHECK(status IN ('normal','hidden')),
    is_ai_reviewed INTEGER NOT NULL DEFAULT 0,
    similar_to_id INTEGER REFERENCES posts(id),
    word_count INTEGER NOT NULL DEFAULT 0,
    views INTEGER NOT NULL DEFAULT 0,
    likes INTEGER NOT NULL DEFAULT 0,
    dislikes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_posts_category ON posts(category_id);
CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id);

CREATE TABLE IF NOT EXISTS replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL REFERENCES posts(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    quote_reply_id INTEGER REFERENCES replies(id),
    status TEXT NOT NULL DEFAULT 'normal' CHECK(status IN ('normal','hidden')),
    is_ai_reviewed INTEGER NOT NULL DEFAULT 0,
    similar_to_id INTEGER REFERENCES replies(id),
    word_count INTEGER NOT NULL DEFAULT 0,
    likes INTEGER NOT NULL DEFAULT 0,
    dislikes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_replies_post ON replies(post_id);

CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    target_type TEXT NOT NULL CHECK(target_type IN ('post','reply')),
    target_id INTEGER NOT NULL,
    value INTEGER NOT NULL CHECK(value IN (1,-1)),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(user_id, target_type, target_id)
);

CREATE TABLE IF NOT EXISTS favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    post_id INTEGER NOT NULL REFERENCES posts(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(user_id, post_id)
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER NOT NULL REFERENCES users(id),
    target_type TEXT NOT NULL CHECK(target_type IN ('post','reply','task')),
    target_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','resolved','dismissed')),
    handled_by INTEGER REFERENCES users(id),
    handled_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS post_tags (
    post_id INTEGER NOT NULL REFERENCES posts(id),
    tag_id INTEGER NOT NULL REFERENCES tags(id),
    PRIMARY KEY (post_id, tag_id)
);

CREATE TABLE IF NOT EXISTS point_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    delta INTEGER NOT NULL,
    reason TEXT NOT NULL,
    ref_type TEXT NOT NULL DEFAULT '',
    ref_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(user_id, ref_type, ref_id, reason)
);
CREATE INDEX IF NOT EXISTS idx_point_logs_user ON point_logs(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_point_logs_time ON point_logs(created_at);

CREATE TABLE IF NOT EXISTS sign_ins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    sign_date TEXT NOT NULL,
    streak INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(user_id, sign_date)
);

CREATE TABLE IF NOT EXISTS knowledge_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL CHECK(category IN ('law','case','guide','qoder')),
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    source_url TEXT NOT NULL DEFAULT '',
    is_official INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_knowledge_category ON knowledge_entries(category);

CREATE TABLE IF NOT EXISTS knowledge_keywords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL REFERENCES knowledge_entries(id),
    keyword TEXT NOT NULL,
    clause TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_knowledge_keywords ON knowledge_keywords(keyword);

CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS honeypot_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    cookie_data TEXT NOT NULL DEFAULT '',
    payload TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    platform_name TEXT NOT NULL,
    issue_type TEXT NOT NULL,
    clause_text TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL,
    law_reference TEXT NOT NULL DEFAULT '',
    attachments TEXT NOT NULL DEFAULT '[]',
    recipient TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    send_method TEXT NOT NULL DEFAULT 'proxy' CHECK(send_method IN ('proxy','self')),
    status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','pending','ai_pending','human_pending','ai_debate','approved','rejected','sent','failed','self_sent')),
    admin_label TEXT NOT NULL DEFAULT '' CHECK(admin_label IN ('','effective','needs_supplement')),
    backup_copy TEXT NOT NULL DEFAULT '',
    reviewed_by INTEGER REFERENCES users(id),
    reviewed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_emails_user ON emails(user_id);
CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status);

CREATE TABLE IF NOT EXISTS email_inbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    sender TEXT NOT NULL DEFAULT '',
    recipient TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    raw_size INTEGER NOT NULL DEFAULT 0,
    is_read INTEGER NOT NULL DEFAULT 0,
    is_public INTEGER NOT NULL DEFAULT 0,
    post_id INTEGER REFERENCES posts(id),
    received_at TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_email_inbox_message_id ON email_inbox(message_id);
CREATE INDEX IF NOT EXISTS idx_email_inbox_received ON email_inbox(received_at);

CREATE TABLE IF NOT EXISTS root_login_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    code TEXT NOT NULL,
    temp_token TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_root_codes_token ON root_login_codes(temp_token);

CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ban_type TEXT NOT NULL CHECK(ban_type IN ('account','email','device')),
    target TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    banned_by INTEGER REFERENCES users(id),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_bans_type_target ON bans(ban_type, target);
CREATE INDEX IF NOT EXISTS idx_bans_active ON bans(is_active);

CREATE TABLE IF NOT EXISTS ip_access_controls (
    ip TEXT PRIMARY KEY,
    request_count INTEGER NOT NULL DEFAULT 0,
    window_started_at REAL NOT NULL DEFAULT 0,
    limit_per_minute INTEGER NOT NULL DEFAULT 0,
    strike_count INTEGER NOT NULL DEFAULT 0,
    banned_until REAL NOT NULL DEFAULT 0,
    degraded_until REAL NOT NULL DEFAULT 0,
    last_seen REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_ip_access_controls_banned_until ON ip_access_controls(banned_until);

CREATE TABLE IF NOT EXISTS ip_security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    event_type TEXT NOT NULL,
    path TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    actor_id INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_ip_security_events_ip_created ON ip_security_events(ip, created_at DESC);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    receiver_id INTEGER NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id, created_at);

CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_a INTEGER NOT NULL REFERENCES users(id),
    user_b INTEGER NOT NULL REFERENCES users(id),
    last_message_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(user_a, user_b)
);
CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_a, user_b);

CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    owner_id INTEGER NOT NULL REFERENCES users(id),
    announcement TEXT NOT NULL DEFAULT '',
    join_type TEXT NOT NULL DEFAULT 'open' CHECK(join_type IN ('open','approval')),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','readonly','dissolved')),
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL REFERENCES groups(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('member','admin')),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','left','kicked')),
    joined_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    left_at TEXT,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_groups_owner ON groups(owner_id);
CREATE INDEX IF NOT EXISTS idx_groups_status ON groups(status);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id, status);

CREATE TABLE IF NOT EXISTS group_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL REFERENCES groups(id),
    sender_id INTEGER NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    is_redline INTEGER NOT NULL DEFAULT 0,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    ai_scan_at TEXT,
    deleted_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_id, created_at);

CREATE TABLE IF NOT EXISTS group_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL REFERENCES groups(id),
    reporter_id INTEGER NOT NULL REFERENCES users(id),
    message_id INTEGER REFERENCES group_messages(id),
    reason TEXT NOT NULL DEFAULT '',
    ai_result TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','resolved','dismissed')),
    handled_by INTEGER REFERENCES users(id),
    handled_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_group_reports_group ON group_reports(group_id, status);

CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    type TEXT NOT NULL CHECK(type IN ('volunteer','admin')),
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
    reviewed_by INTEGER REFERENCES users(id),
    reviewed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_applications_user ON applications(user_id);

CREATE TABLE IF NOT EXISTS board_claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER NOT NULL REFERENCES categories(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    draft_body TEXT NOT NULL DEFAULT '',
    shared_notes TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'claimed' CHECK(status IN ('claimed','draft','submitted','abandoned')),
    claimed_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    deadline TEXT NOT NULL,
    last_activity_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(category_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_board_claims_user ON board_claims(user_id, status);
CREATE INDEX IF NOT EXISTS idx_board_claims_deadline ON board_claims(deadline, status);

CREATE TABLE IF NOT EXISTS user_daily_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    usage_date TEXT NOT NULL,
    text_bytes INTEGER NOT NULL DEFAULT 0,
    image_bytes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(user_id, usage_date)
);
CREATE INDEX IF NOT EXISTS idx_user_daily_usage ON user_daily_usage(user_id, usage_date);

CREATE TABLE IF NOT EXISTS admin_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_by INTEGER REFERENCES users(id),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS daily_law (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL REFERENCES knowledge_entries(id),
    push_date TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS system_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL DEFAULT 'system' CHECK(type IN ('system','daily_briefing','task','post','email','board','root','point')),
    title TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    ref_type TEXT NOT NULL DEFAULT '',
    ref_id INTEGER,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_system_messages_created ON system_messages(created_at);
CREATE INDEX IF NOT EXISTS idx_system_messages_read ON system_messages(is_read);

-- 板块订阅（首页消息流用）
CREATE TABLE IF NOT EXISTS board_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    category_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(user_id, category_id)
);
CREATE INDEX IF NOT EXISTS idx_board_subs_user ON board_subscriptions(user_id);

-- 新闻栏（AI 夜间审核时联网搜索生成）
CREATE TABLE IF NOT EXISTS news (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    abstract TEXT NOT NULL DEFAULT '',
    source_name TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    published_at TEXT,
    collected_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    is_active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_news_collected ON news(collected_at);
CREATE INDEX IF NOT EXISTS idx_news_active ON news(is_active);

-- 条文背诵游戏：题目
CREATE TABLE IF NOT EXISTS quiz_questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    knowledge_id INTEGER NOT NULL,
    blank_text TEXT NOT NULL,
    options_json TEXT NOT NULL,
    answer_index INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_quiz_q_knowledge ON quiz_questions(knowledge_id);

-- 条文背诵游戏：作答记录
CREATE TABLE IF NOT EXISTS quiz_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    question_id INTEGER NOT NULL,
    is_correct INTEGER NOT NULL DEFAULT 0,
    answered_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(user_id, question_id)
);
CREATE INDEX IF NOT EXISTS idx_quiz_r_user_date ON quiz_records(user_id, answered_at);

-- 风控审计日志（root 专属监控工具）：每次后台/敏感操作都记录 actor/IP/UA/操作/详情/风险等级
-- 多处备份：主表 risk_audit_logs + 文件日志 storage/risk_audit/YYYYMM.log + Err.log（高危）
CREATE TABLE IF NOT EXISTS risk_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,                      -- 操作者 user_id（未登录为 NULL）
    actor_role TEXT NOT NULL DEFAULT '',   -- 操作者角色
    actor_ip TEXT NOT NULL DEFAULT '',     -- 来源 IP
    actor_ua TEXT NOT NULL DEFAULT '',     -- User-Agent（截断）
    method TEXT NOT NULL DEFAULT '',       -- HTTP 方法
    path TEXT NOT NULL DEFAULT '',         -- 请求路径
    action TEXT NOT NULL DEFAULT '',       -- 操作分类（如 delete_knowledge/ban_user）
    detail TEXT NOT NULL DEFAULT '',       -- 操作详情（JSON 字符串）
    risk_level TEXT NOT NULL DEFAULT 'info' CHECK(risk_level IN ('info','warn','danger','critical')),
    triggered_2fa INTEGER NOT NULL DEFAULT 0,  -- 是否触发 2FA 挑战
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_risk_audit_actor ON risk_audit_logs(actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_audit_ip ON risk_audit_logs(actor_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_audit_level ON risk_audit_logs(risk_level, created_at DESC);

-- 2FA 挑战记录：风控触发后给当前会话发验证码，3 次失败封禁
CREATE TABLE IF NOT EXISTS risk_2fa_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    actor_ip TEXT NOT NULL DEFAULT '',
    challenge_token TEXT NOT NULL,         -- 临时令牌（前端持有）
    code_hash TEXT NOT NULL,               -- 验证码哈希（不存明文）
    fail_count INTEGER NOT NULL DEFAULT 0,
    resolved INTEGER NOT NULL DEFAULT 0,   -- 1=通过 -1=封禁 0=进行中
    reason TEXT NOT NULL DEFAULT '',       -- 触发原因
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_risk_2fa_token ON risk_2fa_challenges(challenge_token);
CREATE INDEX IF NOT EXISTS idx_risk_2fa_ip ON risk_2fa_challenges(actor_ip, created_at DESC);

-- 风控 IP 封禁表：3 次 2FA 失败后封禁该 IP 访问后台
-- 与 ip_access_controls 区别：本表仅针对后台管理台访问，永久封禁需 root 手动解封
CREATE TABLE IF NOT EXISTS risk_ip_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    user_id INTEGER,                       -- 关联的用户（若可识别）
    reason TEXT NOT NULL DEFAULT '',
    fail_count INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    banned_by INTEGER,                     -- NULL=自动封禁
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    lifted_at TEXT,
    UNIQUE(ip)
);
CREATE INDEX IF NOT EXISTS idx_risk_ip_bans_active ON risk_ip_bans(is_active);

-- 风控 IP 白名单：root 信任的 IP（如服务器管理员常驻地），跳过异常检测
CREATE TABLE IF NOT EXISTS risk_ip_whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
"""


def _connect() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(config.DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def db():
    """每请求一个连接：正常结束 commit，异常 rollback 并向上抛出（由中间件记录 Err.log）。"""
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    return column in cols


def _has_unique_email(conn: sqlite3.Connection) -> bool:
    """检测旧版 users 表是否对 email 有 UNIQUE 约束。"""
    for row in conn.execute("PRAGMA index_list(users)"):
        name = row[1]
        is_unique = row[2]
        if is_unique:
            cols = [r[2] for r in conn.execute(f"PRAGMA index_info({name})")]
            if cols == ["email"]:
                return True
    return False


def _migrate_users_remove_email_unique(conn: sqlite3.Connection) -> None:
    """移除 users.email 的 UNIQUE 约束并保留数据（SQLite 需重建表）。

    重建 users 表前临时关闭外键检查，避免其他表的外键引用阻止 DROP TABLE。
    """
    conn.executescript("""
    PRAGMA foreign_keys=OFF;
    DROP TABLE IF EXISTS users_new;
    CREATE TABLE users_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        nickname TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','moderator','admin','sysadmin','root')),
        points INTEGER NOT NULL DEFAULT 0,
        guardian_declared INTEGER NOT NULL DEFAULT 0,
        is_banned INTEGER NOT NULL DEFAULT 0,
        is_suspicious INTEGER NOT NULL DEFAULT 0,
        device_fingerprint TEXT NOT NULL DEFAULT '',
        nickname_color TEXT NOT NULL DEFAULT '',
        csrf_token TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
    );
    INSERT INTO users_new SELECT * FROM users;
    DROP TABLE IF EXISTS users;
    ALTER TABLE users_new RENAME TO users;
    CREATE INDEX IF NOT EXISTS idx_users_fingerprint ON users(device_fingerprint);
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    PRAGMA foreign_keys=ON;
    """)


def _add_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    """安全地添加列（若不存在）。"""
    if not _column_exists(conn, table, column):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


DEFAULT_THRESHOLDS = {
    "threshold_points_speak": "4",
    "threshold_points_create_board": "10",
    "threshold_points_moderate_board": "30",
    "threshold_points_create_group": "200",
    "threshold_points_apply_volunteer": "100",
    "threshold_points_apply_admin": "500",
    "threshold_points_nickname_color": "50",
    "threshold_evidence_close": "40",
    "threshold_close_to_archive_days": "21",
    "threshold_claim_deadline_hours": "24",
    "threshold_activity_deadline_hours": "72",
    "threshold_human_pending_hours": "24",
    "threshold_debate_rounds": "5",
    "threshold_daily_text_bytes": "10240",
    "threshold_daily_image_bytes": "4194304",
    "threshold_upload_source_max_bytes": "10485760",
    "threshold_upload_min_target_bytes": "65536",
    "threshold_upload_default_target_bytes": "524288",
    "threshold_upload_selectable_max_bytes": "2097152",
    "threshold_upload_original_max_bytes": "5242880",
    "threshold_upload_max_dimension": "1920",
    "threshold_upload_max_pixels": "24000000",
    "threshold_upload_max_count": "5",
    "threshold_points_upload_quality_choice": "100",
    "threshold_points_upload_original": "500",
    "threshold_reward_signin_base": "1",
    "threshold_reward_signin_streak7_bonus": "5",
    "threshold_reward_task_upload_approved": "2",
    "threshold_reward_task_evidence_valid": "3",
    "threshold_reward_task_excellent": "5",
    "threshold_reward_post_featured": "3",
    "threshold_reward_email_initial_approved": "2",
    "threshold_reward_email_valid": "3",
    "threshold_reward_reply_ten_likes": "1",
    "threshold_reward_board_claim": "2",
    "threshold_cost_board_claim_abandon": "2",
    "threshold_reward_knowledge_share": "1",
    "threshold_reward_quiz_correct": "1",
    "threshold_quiz_daily_limit": "5",
    # 两字是基础完整性门槛；更严格的社区可由 root 动态调高。
    "threshold_min_word_count": "2",
    "threshold_duplicate_window_hours": "24",
    "threshold_redline_report_deduction_min": "10",
    "threshold_redline_report_deduction_max": "50",
    "threshold_ip_protection_enabled": "1",
    "threshold_ip_window_seconds": "60",
    "threshold_ip_default_limit": "60",
    "threshold_ip_min_limit": "20",
    "threshold_ip_degrade_percent": "25",
    "threshold_ip_degrade_minutes": "20",
    "threshold_ip_ban_minutes": "30",
    "threshold_ip_ban_max_minutes": "1440",
    "threshold_ip_ban_escalation_percent": "50",
    "threshold_ip_recovery_percent": "20",
    # SID 会话密钥握手安全（root 可配，但服务端硬下限保护，见 handshake.py）
    "threshold_handshake_timeout": "60",
    "threshold_handshake_fail_limit": "3",
}

# 阈值最小值硬下限：防止 root 误配 0/负值导致 DoS 或逻辑崩溃。
# update_thresholds 会校验，handshake.py 也会兜底 max()。
THRESHOLD_MIN_VALUES = {
    "threshold_handshake_timeout": 10,    # 秒：过小会使正常用户频繁掉线
    "threshold_handshake_fail_limit": 1,  # 次：0 会使首次失败即轮换
    "threshold_ip_default_limit": 1,
    "threshold_ip_min_limit": 1,
    "threshold_quiz_daily_limit": 1,
    "threshold_min_word_count": 1,
}


def _ensure_default_settings(conn: sqlite3.Connection) -> None:
    """预置 root 可配置阈值默认值；已存在则不覆盖。"""
    for key, value in DEFAULT_THRESHOLDS.items():
        conn.execute(
            "INSERT OR IGNORE INTO admin_settings(key, value) VALUES (?, ?)",
            (key, value),
        )


def _migrate(conn: sqlite3.Connection) -> None:
    """对已有数据库追加新增字段/表（CREATE IF NOT EXISTS 已处理表）。"""
    if _has_unique_email(conn):
        _migrate_users_remove_email_unique(conn)
    if not _column_exists(conn, "users", "nickname_color"):
        conn.execute("ALTER TABLE users ADD COLUMN nickname_color TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "ip_access_controls", "request_count", "request_count INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "ip_access_controls", "window_started_at", "window_started_at REAL NOT NULL DEFAULT 0")
    _add_column(conn, "ip_access_controls", "limit_per_minute", "limit_per_minute INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "ip_access_controls", "strike_count", "strike_count INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "ip_access_controls", "banned_until", "banned_until REAL NOT NULL DEFAULT 0")
    _add_column(conn, "ip_access_controls", "degraded_until", "degraded_until REAL NOT NULL DEFAULT 0")
    _add_column(conn, "ip_access_controls", "last_seen", "last_seen REAL NOT NULL DEFAULT 0")
    if not _column_exists(conn, "tasks", "admin_label"):
        conn.execute("ALTER TABLE tasks ADD COLUMN admin_label TEXT NOT NULL DEFAULT '' CHECK(admin_label IN ('','effective','needs_supplement'))")
    if not _column_exists(conn, "knowledge_entries", "source_url"):
        conn.execute("ALTER TABLE knowledge_entries ADD COLUMN source_url TEXT NOT NULL DEFAULT ''")
    if not _column_exists(conn, "knowledge_entries", "is_official"):
        conn.execute("ALTER TABLE knowledge_entries ADD COLUMN is_official INTEGER NOT NULL DEFAULT 0")
    if not _column_exists(conn, "email_inbox", "is_public"):
        conn.execute("ALTER TABLE email_inbox ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0")
    if not _column_exists(conn, "email_inbox", "post_id"):
        conn.execute("ALTER TABLE email_inbox ADD COLUMN post_id INTEGER REFERENCES posts(id)")

    # 社区治理相关字段迁移
    _add_column(conn, "categories", "status", "status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed','archived'))")
    _add_column(conn, "categories", "allow_email", "allow_email INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "categories", "evidence_count", "evidence_count INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "categories", "post_count", "post_count INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "categories", "closed_at", "closed_at TEXT")
    _add_column(conn, "categories", "archived_at", "archived_at TEXT")
    _add_column(conn, "categories", "claim_user_id", "claim_user_id INTEGER REFERENCES users(id)")
    _add_column(conn, "categories", "claim_deadline", "claim_deadline TEXT")
    _add_column(conn, "categories", "evidence_package", "evidence_package TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "categories", "updated_at", "updated_at TEXT NOT NULL DEFAULT ''")
    conn.execute("UPDATE categories SET updated_at=datetime('now','localtime') WHERE updated_at IS NULL OR updated_at=''")
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS trg_categories_set_updated_at_after_insert
        AFTER INSERT ON categories
        FOR EACH ROW
        WHEN NEW.updated_at IS NULL OR NEW.updated_at = ''
        BEGIN
            UPDATE categories SET updated_at=datetime('now','localtime') WHERE id=NEW.id;
        END;
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_categories_status ON categories(status)")

    _add_column(conn, "posts", "is_ai_reviewed", "is_ai_reviewed INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "posts", "similar_to_id", "similar_to_id INTEGER REFERENCES posts(id)")
    _add_column(conn, "posts", "word_count", "word_count INTEGER NOT NULL DEFAULT 0")

    _add_column(conn, "replies", "is_ai_reviewed", "is_ai_reviewed INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "replies", "similar_to_id", "similar_to_id INTEGER REFERENCES replies(id)")
    _add_column(conn, "replies", "word_count", "word_count INTEGER NOT NULL DEFAULT 0")

    # SQLite 不允许 ALTER TABLE 添加带非 NULL 默认值的 REFERENCES 列，
    # 旧库先以无 FK 形式加列，回填后再由应用层保证后续写入合法性。
    _add_column(conn, "groups", "owner_id", "owner_id INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "groups", "announcement", "announcement TEXT NOT NULL DEFAULT ''")
    _add_column(conn, "groups", "join_type", "join_type TEXT NOT NULL DEFAULT 'open' CHECK(join_type IN ('open','approval'))")
    _add_column(conn, "groups", "status", "status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','readonly','dissolved'))")

    _add_column(conn, "group_members", "role", "role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('member','admin'))")
    _add_column(conn, "group_members", "status", "status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','left','kicked'))")
    _add_column(conn, "group_members", "left_at", "left_at TEXT")

    _add_column(conn, "group_messages", "is_redline", "is_redline INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "group_messages", "is_deleted", "is_deleted INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "group_messages", "ai_scan_at", "ai_scan_at TEXT")
    _add_column(conn, "group_messages", "deleted_at", "deleted_at TEXT")

    # 旧群聊数据的 owner_id 回填为 created_by，仅当 created_by 仍存在于 users 时
    conn.execute(
        "UPDATE groups SET owner_id = created_by "
        "WHERE (owner_id = 0 OR owner_id IS NULL) AND created_by IN (SELECT id FROM users)"
    )

    # 创建者已不存在的旧群聊无法保证后续外键一致性，作为孤儿数据清理
    orphan_groups = [r["id"] for r in conn.execute(
        "SELECT id FROM groups WHERE owner_id = 0 OR owner_id IS NULL"
    ).fetchall()]
    for gid in orphan_groups:
        conn.execute("DELETE FROM group_reports WHERE group_id=?", (gid,))
        conn.execute("DELETE FROM group_messages WHERE group_id=?", (gid,))
        conn.execute("DELETE FROM group_members WHERE group_id=?", (gid,))
        conn.execute("DELETE FROM groups WHERE id=?", (gid,))

    # 确保新增索引对旧库也生效
    conn.execute("CREATE INDEX IF NOT EXISTS idx_groups_owner ON groups(owner_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_groups_status ON groups(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id, status)")

    # 积分发放幂等性：旧库可能缺少该唯一索引
    conn.execute(
        """
        DELETE FROM point_logs
        WHERE rowid NOT IN (
            SELECT MIN(rowid)
            FROM point_logs
            GROUP BY user_id, ref_type, ref_id, reason
        )
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_point_logs_unique "
        "ON point_logs(user_id, ref_type, ref_id, reason)"
    )

    _ensure_default_settings(conn)


def init_db() -> None:
    with db() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)
