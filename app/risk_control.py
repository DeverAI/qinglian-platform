"""风控核心模块：服务器后台监控工具专用。

设计目标（用户需求）：
- 仅在服务器上修改/使用的监控工具，记录操作和 IP。
- 日志多处备份（DB 主表 + 文件日志），尽可能不被删除。
- 检测异常/不常见 IP、危险操作（如大量删除）时自动启动双因素认证。
- 3 次验证码内无法通过 → 封禁该 IP 对应用户 + 封禁此 IP 对后台管理台的访问。
- 前后端验证防护可直接加强。

核心能力：
1. `log_action`：记录每次后台/敏感操作到 DB risk_audit_logs + 文件 storage/risk_audit/YYYYMM.log。
   高危（danger/critical）额外写入 Err.log，三处冗余防删除。
2. `classify_risk`：基于方法/路径/action 评估风险等级。
   - DELETE / 批量操作 / 角色变更 / 封禁 / 服务开关 / 阈值修改 → danger/critical。
3. `is_ip_suspicious`：检测不常见 IP（不在白名单 + 近 N 天未出现过 + 非 RFC1918 私网）。
4. `should_trigger_2fa`：危险操作 OR 异常 IP → 触发 2FA。
5. `issue_2fa_challenge`：签发 2FA 挑战（验证码哈希存库，明文仅返回给前端或邮件）。
6. `verify_2fa`：校验验证码，失败累计 fail_count，达阈值（3）→ ban_ip + ban_user。
7. `ban_ip` / `unban_ip` / `is_ip_banned`：后台访问封禁（永久，需 root 手动解封）。
8. `add_whitelist` / `remove_whitelist` / `is_whitelisted`：IP 白名单管理。

安全：
- 验证码使用 PBKDF2 哈希存储，不存明文。
- 验证码仅在服务器本地访问时返回明文（RISK_2FA_EMAIL 未配置时），
  配置邮箱则发送邮件、不返回明文（防中间人）。
- challenge_token 为 32 字节 URL-safe 随机令牌。
- fail_count 达阈值后 challenge 立即 resolved=-1，IP 进入 risk_ip_bans。
"""
import datetime
import json
import secrets
import threading
from pathlib import Path

from . import config
from .common import BizError
from .database import db
from .errlog import log_error
from .security import hash_password, verify_password

_lock = threading.Lock()

# 后台管理台访问路径前缀（这些路径受风控中间件保护）
BACKEND_PATH_PREFIXES = ("/api/admin", "/api/root", "/api/risk")

# 危险操作分类（action → risk_level）
# 注：path-based 检测在 classify_risk 中按方法+路径判定，这里仅记录典型 action 名。
DANGER_ACTIONS = {
    "delete": "danger",
    "delete_knowledge": "danger",
    "delete_post": "danger",
    "ban_user": "danger",
    "ban_email": "danger",
    "ban_device": "critical",
    "ban_ip": "critical",
    "change_role": "critical",      # 角色提权/降权
    "promote_admin": "critical",
    "toggle_service": "critical",   # 服务开关
    "update_thresholds": "critical",
    "update_setting": "danger",     # SMTP/AI 等敏感配置
    "lift_ban": "warn",
    "review_task": "info",
    "mosaic_task": "info",
    "essence_post": "info",
}


def _now_iso() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def _file_log_path() -> Path:
    """当月文件日志路径：storage/risk_audit/YYYYMM.log"""
    config.RISK_AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    return config.RISK_AUDIT_DIR / f"{datetime.datetime.now().strftime('%Y%m')}.log"


def _write_file_log(entry: dict) -> None:
    """追加一条审计日志到文件（防 DB 被删后仍可追溯）。"""
    try:
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        with _lock:
            with open(_file_log_path(), "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        # 文件日志失败不应影响主流程
        pass


def classify_risk(method: str, path: str, action: str = "") -> str:
    """根据方法/路径/action 评估风险等级。

    返回 'info' / 'warn' / 'danger' / 'critical'。
    """
    method = (method or "").upper()
    path = path or ""
    action = action or ""

    # 1. 按 action 直接查表
    if action in DANGER_ACTIONS:
        return DANGER_ACTIONS[action]

    # 2. DELETE 方法 → danger（单条删除；批量删除见下一条 → critical）
    if method == "DELETE":
        return "danger"

    # 3. 批量操作（路径含 batch/bulk）→ critical（大量删除/批量变更，强制 2FA）
    if "batch" in path.lower() or "bulk" in path.lower():
        return "critical"

    # 4. 角色变更 / 封禁 / 服务开关 / 阈值修改 → critical
    if "/role" in path or "/ban" in path or "/services/" in path or "/thresholds" in path:
        return "critical"

    # 5. 设置修改（SMTP/AI 等敏感配置）→ danger
    if "/settings" in path and method in ("PUT", "POST"):
        return "danger"

    # 6. 后台写操作（POST/PUT 到 /api/admin|root|risk）→ warn
    if method in ("POST", "PUT", "PATCH") and any(path.startswith(p) for p in BACKEND_PATH_PREFIXES):
        return "warn"

    # 7. 后台读操作 → info
    return "info"


def log_action(
    actor_id: int | None,
    actor_role: str,
    actor_ip: str,
    actor_ua: str,
    method: str,
    path: str,
    action: str = "",
    detail: str = "",
    risk_level: str | None = None,
    triggered_2fa: bool = False,
) -> dict:
    """记录一次审计日志（DB + 文件双写，高危再加 Err.log）。

    返回写入的日志条目（供调用方使用）。
    """
    if risk_level is None:
        risk_level = classify_risk(method, path, action)

    entry = {
        "actor_id": actor_id,
        "actor_role": actor_role,
        "actor_ip": (actor_ip or "")[:64],
        "actor_ua": (actor_ua or "")[:300],
        "method": (method or "")[:10],
        "path": (path or "")[:500],
        "action": (action or "")[:64],
        "detail": (detail or "")[:2000],
        "risk_level": risk_level,
        "triggered_2fa": 1 if triggered_2fa else 0,
        "created_at": _now_iso(),
    }

    # 1. 写 DB 主表
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO risk_audit_logs "
                "(actor_id, actor_role, actor_ip, actor_ua, method, path, action, detail, risk_level, triggered_2fa) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    entry["actor_id"], entry["actor_role"], entry["actor_ip"], entry["actor_ua"],
                    entry["method"], entry["path"], entry["action"], entry["detail"],
                    entry["risk_level"], entry["triggered_2fa"],
                ),
            )
    except Exception as exc:
        # DB 写失败也继续写文件，保证审计不丢
        log_error("risk_control.log_action.db", repr(exc))

    # 2. 写文件日志（冗余备份）
    _write_file_log(entry)

    # 3. 高危额外写 Err.log（第三处备份）
    if risk_level in ("danger", "critical"):
        log_error(
            "risk_audit",
            f"level={risk_level} actor={actor_id}({actor_role}) ip={actor_ip} {method} {path} action={action} detail={detail[:200]}",
        )

    return entry


def is_whitelisted(ip: str) -> bool:
    """IP 是否在白名单（信任 IP，跳过异常检测）。"""
    if not ip:
        return False
    with db() as conn:
        row = conn.execute("SELECT 1 FROM risk_ip_whitelist WHERE ip=? LIMIT 1", (ip,)).fetchone()
    return row is not None


def add_whitelist(ip: str, label: str = "") -> None:
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO risk_ip_whitelist (ip, label) VALUES (?,?)",
            (ip[:64], label[:100]),
        )


def remove_whitelist(ip: str) -> None:
    with db() as conn:
        conn.execute("DELETE FROM risk_ip_whitelist WHERE ip=?", (ip[:64],))


def is_ip_banned(ip: str) -> bool:
    """IP 是否已被风控封禁（禁止访问后台管理台）。"""
    if not ip:
        return False
    with db() as conn:
        row = conn.execute(
            "SELECT 1 FROM risk_ip_bans WHERE ip=? AND is_active=1 LIMIT 1", (ip,)
        ).fetchone()
    return row is not None


def ban_ip(ip: str, reason: str, user_id: int | None = None, fail_count: int = 0, banned_by: int | None = None) -> None:
    """封禁 IP 访问后台管理台（永久，需 root 手动解封）。"""
    if not ip:
        return
    with db() as conn:
        conn.execute(
            "INSERT INTO risk_ip_bans (ip, user_id, reason, fail_count, is_active, banned_by) "
            "VALUES (?,?,?,?,1,?) "
            "ON CONFLICT(ip) DO UPDATE SET is_active=1, reason=excluded.reason, fail_count=excluded.fail_count, "
            "banned_by=excluded.banned_by, lifted_at=NULL",
            (ip[:64], user_id, reason[:500], fail_count, banned_by),
        )
    # 同步写审计日志 + Err.log
    log_action(
        actor_id=banned_by, actor_role="system", actor_ip=ip, actor_ua="",
        method="", path="", action="ban_ip",
        detail=f"reason={reason}, fail_count={fail_count}, user_id={user_id}",
        risk_level="critical",
    )


def unban_ip(ip: str, banned_by: int) -> None:
    """解封 IP（仅 root 可调用，路由层校验）。"""
    with db() as conn:
        conn.execute(
            "UPDATE risk_ip_bans SET is_active=0, lifted_at=datetime('now','localtime') WHERE ip=?",
            (ip[:64],),
        )
    log_action(
        actor_id=banned_by, actor_role="root", actor_ip="", actor_ua="",
        method="", path="", action="unban_ip", detail=f"ip={ip}",
        risk_level="warn",
    )


def is_ip_suspicious(ip: str, actor_id: int | None = None) -> tuple[bool, str]:
    """检测不常见 IP。

    判定条件（任一满足即可疑）：
    1. IP 不在白名单。
    2. 该 IP 近 N 天（默认 7）未在 risk_audit_logs 出现过（新 IP）。
    3. 该 IP 与该用户历史常用 IP 不同（账号异地登录）。

    返回 (is_suspicious, reason)。
    """
    if not ip or ip in {"127.0.0.1", "::1", "localhost", "testserver", "testclient"}:
        return False, ""

    if is_whitelisted(ip):
        return False, ""

    # 1. 近 7 天是否出现过
    with db() as conn:
        row = conn.execute(
            "SELECT 1 FROM risk_audit_logs WHERE actor_ip=? "
            "AND created_at >= datetime('now','localtime','-7 days') LIMIT 1",
            (ip,),
        ).fetchone()
        if row is None:
            return True, "近 7 天首次出现的 IP"

    # 2. 账号异地登录：该用户历史常用 IP 与当前不同
    if actor_id:
        with db() as conn:
            # 取该用户历史最近 10 条记录的 IP
            rows = conn.execute(
                "SELECT actor_ip, COUNT(*) AS c FROM risk_audit_logs "
                "WHERE actor_id=? AND actor_ip!='' AND actor_ip IS NOT NULL "
                "GROUP BY actor_ip ORDER BY c DESC LIMIT 10",
                (actor_id,),
            ).fetchall()
            if rows:
                known_ips = {r["actor_ip"] for r in rows}
                if ip not in known_ips:
                    return True, f"账号异地登录：常用 IP 为 {', '.join(list(known_ips)[:3])}"

    return False, ""


def should_trigger_2fa(method: str, path: str, action: str, ip: str, actor_id: int | None) -> tuple[bool, str]:
    """判断是否需要触发 2FA。

    触发条件：
    1. critical 级操作（批量删除/角色变更/封禁/服务开关/阈值修改）—— 始终触发，即使来自信任 IP。
    2. 异常 IP（is_ip_suspicious 返回 True）—— 任意变更类操作触发。
    注：danger 级（单条删除/设置修改）仅在异常 IP 时触发，信任 IP 下的日常单条操作不打扰。

    返回 (should_trigger, reason)。
    """
    # 白名单 IP 跳过异常检测，但 critical 操作仍需 2FA
    risk = classify_risk(method, path, action)
    if risk == "critical":
        return True, f"高危操作（{risk}）：{method} {path} {action}"

    suspicious, reason = is_ip_suspicious(ip, actor_id)
    if suspicious:
        return True, reason

    return False, ""


def issue_2fa_challenge(actor_id: int | None, actor_ip: str, reason: str) -> dict:
    """签发 2FA 挑战：生成验证码、哈希存库、返回挑战信息。

    返回：
    - challenge_token: 前端持有，用于提交验证码
    - code: 明文验证码（仅当 RISK_2FA_EMAIL 未配置时返回；配置邮箱则发送邮件不返回明文）
    - expires_at: 过期时间
    - sent_via: 'local'（本地返回）或 'email'（已发邮件）
    """
    code = "".join(secrets.choice("0123456789") for _ in range(6))
    challenge_token = secrets.token_urlsafe(32)
    expires_at = (
        datetime.datetime.now() + datetime.timedelta(minutes=config.RISK_2FA_TTL_MINUTES)
    ).strftime("%Y-%m-%d %H:%M:%S")
    code_hash = hash_password(code)

    with db() as conn:
        conn.execute(
            "INSERT INTO risk_2fa_challenges "
            "(actor_id, actor_ip, challenge_token, code_hash, fail_count, resolved, reason, expires_at) "
            "VALUES (?,?,?,?,0,0,?,?)",
            (actor_id, (actor_ip or "")[:64], challenge_token, code_hash, reason[:500], expires_at),
        )

    # 记录审计日志
    log_action(
        actor_id=actor_id, actor_role="", actor_ip=actor_ip, actor_ua="",
        method="", path="", action="trigger_2fa",
        detail=f"reason={reason}", risk_level="warn", triggered_2fa=True,
    )

    # 发送验证码：配置邮箱则发邮件，否则本地返回明文（仅服务器本地访问场景）
    sent_via = "local"
    target_email = config.RISK_2FA_EMAIL or config.ROOT_EMAIL
    if target_email:
        try:
            _send_2fa_email(target_email, code, reason)
            sent_via = "email"
            code = ""  # 已发邮件，不返回明文
        except Exception as exc:
            # 邮件发送失败：降级为本地返回明文（仍保证可用性），并记录错误
            log_error("risk_control.2fa.email", repr(exc))
            sent_via = "local_email_failed"

    return {
        "challenge_token": challenge_token,
        "code": code,
        "expires_at": expires_at,
        "sent_via": sent_via,
        "reason": reason,
    }


def _send_2fa_email(to_email: str, code: str, reason: str) -> None:
    """发送 2FA 验证码邮件（复用后台 SMTP 配置）。"""
    import smtplib
    from email.message import EmailMessage

    def _smtp_setting(key: str, default: str = "") -> str:
        with db() as conn:
            row = conn.execute("SELECT value FROM admin_settings WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    host = _smtp_setting("smtp_host")
    if not host:
        raise RuntimeError("SMTP 未配置")
    try:
        port = int(_smtp_setting("smtp_port") or 465)
    except ValueError:
        raise RuntimeError("SMTP 端口配置错误")
    username = _smtp_setting("smtp_user")
    password = _smtp_setting("smtp_pass")
    use_ssl = _smtp_setting("smtp_use_ssl", "1") in ("1", "true", "True")
    mail_from = _smtp_setting("mail_from") or username or "noreply@qlkimi.local"
    if not username or not password:
        raise RuntimeError("SMTP 账号密码未配置")

    msg = EmailMessage()
    msg["Subject"] = "青联合规监督社区 风控二次验证码"
    msg["From"] = mail_from
    msg["To"] = to_email
    msg.set_content(
        f"系统检测到一次需要二次验证的后台操作：\n"
        f"触发原因：{reason}\n"
        f"验证码：{code}\n"
        f"有效期 {config.RISK_2FA_TTL_MINUTES} 分钟。\n"
        f"如非本人操作，请立即检查账号安全并修改密码，该 IP 可能正在尝试越权操作。"
    )
    server = None
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            server = smtplib.SMTP(host, port, timeout=15)
            server.starttls()
        server.login(username, password)
        server.send_message(msg)
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


def verify_2fa(challenge_token: str, code: str, actor_ip: str) -> dict:
    """校验 2FA 验证码。

    返回 {verified: bool, message: str, remaining_attempts: int}。

    失败累计 fail_count，达阈值（RISK_2FA_MAX_FAILS=3）→ 封禁 IP + 封禁用户。
    """
    if not challenge_token or not code:
        raise BizError(4001, "验证参数缺失")

    with db() as conn:
        row = conn.execute(
            "SELECT * FROM risk_2fa_challenges WHERE challenge_token=? ORDER BY id DESC LIMIT 1",
            (challenge_token,),
        ).fetchone()
        if row is None:
            raise BizError(4040, "验证挑战不存在或已失效")

        if row["resolved"] != 0:
            raise BizError(4030, "该验证挑战已结束")

        # 过期校验
        if row["expires_at"] < datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"):
            conn.execute("UPDATE risk_2fa_challenges SET resolved=-1 WHERE id=?", (row["id"],))
            raise BizError(4040, "验证码已过期，请重新触发")

        # 校验验证码
        if verify_password(code.strip(), row["code_hash"]):
            conn.execute("UPDATE risk_2fa_challenges SET resolved=1 WHERE id=?", (row["id"],))
            return {"verified": True, "message": "验证通过", "remaining_attempts": 0}

        # 失败累计
        new_fail = int(row["fail_count"]) + 1
        remaining = max(0, config.RISK_2FA_MAX_FAILS - new_fail)
        if new_fail >= config.RISK_2FA_MAX_FAILS:
            # 达阈值：封禁 IP + 封禁用户 + 标记挑战失败
            conn.execute("UPDATE risk_2fa_challenges SET fail_count=?, resolved=-1 WHERE id=?", (new_fail, row["id"]))
            user_id = row["actor_id"]
            conn.execute(
                "INSERT INTO risk_ip_bans (ip, user_id, reason, fail_count, is_active, banned_by) "
                "VALUES (?,?,?,?,1,NULL) "
                "ON CONFLICT(ip) DO UPDATE SET is_active=1, reason=excluded.reason, "
                "fail_count=excluded.fail_count, lifted_at=NULL",
                ((row["actor_ip"] or "")[:64], user_id, f"2FA 连续 {new_fail} 次失败", new_fail),
            )
            # 封禁对应用户账号（若可识别）
            if user_id:
                conn.execute("UPDATE users SET is_banned=1 WHERE id=?", (user_id,))
            return {
                "verified": False,
                "message": f"验证失败次数过多（{new_fail} 次），IP 已被封禁" + ("，账号已被封禁" if user_id else ""),
                "remaining_attempts": 0,
                "banned": True,
            }
        else:
            conn.execute("UPDATE risk_2fa_challenges SET fail_count=? WHERE id=?", (new_fail, row["id"]))
            return {
                "verified": False,
                "message": f"验证码错误，剩余 {remaining} 次尝试机会",
                "remaining_attempts": remaining,
            }


def is_2fa_verified(challenge_token: str, actor_id: int | None, max_age_seconds: int = 300) -> bool:
    """检查 challenge_token 是否已通过 2FA 验证且在有效窗口内。

    供中间件校验 X-2FA-Token 头：
    - resolved=1（已通过验证码校验）
    - 创建时间在 max_age_seconds 内（默认 5 分钟，可复用，避免每个高危操作都重验）
    - actor_id 与当前请求操作者一致（防 A 的令牌授权 B 的操作）

    resolved 状态约定：0=进行中，1=已通过，-1=已封禁/失败。
    """
    if not challenge_token:
        return False
    with db() as conn:
        row = conn.execute(
            "SELECT actor_id, resolved, created_at FROM risk_2fa_challenges "
            "WHERE challenge_token=? ORDER BY id DESC LIMIT 1",
            (challenge_token,),
        ).fetchone()
        if row is None:
            return False
        if int(row["resolved"]) != 1:
            return False
        # actor_id 绑定：未登录挑战（actor_id IS NULL）不授权任何已登录操作
        stored_actor = row["actor_id"]
        if stored_actor is None or actor_id is None or int(stored_actor) != int(actor_id):
            return False
        try:
            created = datetime.datetime.fromisoformat(row["created_at"])
        except (ValueError, TypeError):
            return False
        age = (datetime.datetime.now() - created).total_seconds()
        return 0 <= age <= max_age_seconds


def get_audit_logs(
    page: int = 1,
    limit: int = 50,
    risk_level: str = "",
    actor_ip: str = "",
    action: str = "",
) -> dict:
    """查询审计日志（分页）。"""
    page = max(1, int(page or 1))
    limit = min(200, max(1, int(limit or 50)))
    offset = (page - 1) * limit
    where = "1=1"
    params: list = []
    if risk_level:
        where += " AND risk_level=?"
        params.append(risk_level)
    if actor_ip:
        where += " AND actor_ip=?"
        params.append(actor_ip)
    if action:
        where += " AND action=?"
        params.append(action)
    with db() as conn:
        rows = conn.execute(
            f"SELECT * FROM risk_audit_logs WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) AS c FROM risk_audit_logs WHERE {where}", params
        ).fetchone()["c"]
    return {
        "items": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "limit": limit,
    }


def get_ip_bans(page: int = 1, limit: int = 50) -> dict:
    page = max(1, int(page or 1))
    limit = min(200, max(1, int(limit or 50)))
    offset = (page - 1) * limit
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM risk_ip_bans ORDER BY is_active DESC, id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS c FROM risk_ip_bans").fetchone()["c"]
    return {"items": [dict(r) for r in rows], "total": total, "page": page, "limit": limit}


def get_whitelist() -> list:
    with db() as conn:
        rows = conn.execute("SELECT * FROM risk_ip_whitelist ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    """风控仪表盘统计数据。"""
    with db() as conn:
        total_logs = conn.execute("SELECT COUNT(*) AS c FROM risk_audit_logs").fetchone()["c"]
        danger_logs = conn.execute(
            "SELECT COUNT(*) AS c FROM risk_audit_logs WHERE risk_level IN ('danger','critical')"
        ).fetchone()["c"]
        active_bans = conn.execute(
            "SELECT COUNT(*) AS c FROM risk_ip_bans WHERE is_active=1"
        ).fetchone()["c"]
        pending_2fa = conn.execute(
            "SELECT COUNT(*) AS c FROM risk_2fa_challenges WHERE resolved=0 AND expires_at > datetime('now','localtime')"
        ).fetchone()["c"]
        # 今日操作数
        today_logs = conn.execute(
            "SELECT COUNT(*) AS c FROM risk_audit_logs WHERE created_at >= datetime('now','localtime','start of day')"
        ).fetchone()["c"]
        # 近 24 小时高危操作
        recent_danger = conn.execute(
            "SELECT COUNT(*) AS c FROM risk_audit_logs WHERE risk_level IN ('danger','critical') "
            "AND created_at >= datetime('now','localtime','-1 day')"
        ).fetchone()["c"]
        # 近 7 天活跃 IP 数
        active_ips = conn.execute(
            "SELECT COUNT(DISTINCT actor_ip) AS c FROM risk_audit_logs "
            "WHERE actor_ip!='' AND created_at >= datetime('now','localtime','-7 days')"
        ).fetchone()["c"]
    return {
        "total_logs": total_logs,
        "danger_logs": danger_logs,
        "active_bans": active_bans,
        "pending_2fa": pending_2fa,
        "today_logs": today_logs,
        "recent_danger": recent_danger,
        "active_ips": active_ips,
    }
