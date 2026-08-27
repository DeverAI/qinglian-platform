"""用户认证：注册 / 登录 / 刷新续期 / 登出 / 当前用户 / Root 双因素登录。

约定：access token 7 天、refresh token 30 天；每次登录/刷新轮换 CSRF Token。
Root 账号登录需额外邮箱验证码，验证码仅发送至后端配置的 ROOT_EMAIL。
"""
import re
import secrets
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

from fastapi import APIRouter, Depends, Header
from pydantic import BaseModel, Field

from ..common import BizError, ok
from ..config import ROOT_CODE_TTL_MINUTES, ROOT_EMAIL
from ..database import db
from ..handshake import (
    clear_handshake,
    clear_handshake_by_user,
    get_handshake_status,
    get_handshake_status_by_user,
    invalidate_user_sids,
    issue_sid,
    update_handshake_by_user,
    update_handshake_checked,
)
from ..security import (
    _check_bans,
    csrf_check,
    decode_token,
    get_current_user,
    hash_password,
    issue_token_pair,
    new_csrf_token,
    verify_password,
)

router = APIRouter()

EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+(\.[\w-]+)+$")


class RegisterIn(BaseModel):
    email: str = Field(min_length=5, max_length=120)
    password: str = Field(min_length=8, max_length=72)
    nickname: str = Field(min_length=2, max_length=24)
    guardian_declared: bool
    device_fingerprint: str = Field(default="", max_length=128)


class LoginIn(BaseModel):
    email: str = Field(min_length=5, max_length=120)
    password: str = Field(min_length=1, max_length=72)
    nickname: str = Field(default="", max_length=24)


class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=10)


class RootStep1In(BaseModel):
    email: str = Field(min_length=5, max_length=120)
    password: str = Field(min_length=1, max_length=72)


class RootStep2In(BaseModel):
    temp_token: str = Field(min_length=10)
    code: str = Field(min_length=4, max_length=10)


def _public_user(u) -> dict:
    ud = dict(u)
    return {
        "id": ud["id"],
        "email": ud["email"],
        "nickname": ud["nickname"],
        "role": ud["role"],
        "points": ud["points"],
        "nickname_color": ud.get("nickname_color", ""),
        "created_at": ud["created_at"],
    }


def _issue_session(conn, user) -> dict:
    """签发令牌对并轮换 CSRF Token + 会话 SID，返回给前端。

    安全：签发新 sid 前静默失效该用户所有旧 sid，避免旧 sid 在 _maybe_cleanup
    回收前仍可被 require_handshake 接受的复用窗口（防令牌窃取后旧 sid 复用）。
    """
    invalidate_user_sids(user["id"])  # 静默失效旧 sid（不写通知，避免登录轰炸）
    csrf = new_csrf_token()
    conn.execute("UPDATE users SET csrf_token = ? WHERE id = ?", (csrf, user["id"]))
    tokens = issue_token_pair(user["id"], user["role"])
    sid = issue_sid(user["id"])
    return {**tokens, "csrf_token": csrf, "sid": sid, "user": _public_user(user)}


def _check_register_bans(conn, email: str, fp: str) -> None:
    """注册前校验邮箱/设备是否已被封禁。"""
    if conn.execute(
        "SELECT 1 FROM bans WHERE ban_type='email' AND target=? AND is_active=1 LIMIT 1", (email,)
    ).fetchone():
        raise BizError(4030, "该邮箱已被封禁，无法注册")
    if fp and conn.execute(
        "SELECT 1 FROM bans WHERE ban_type='device' AND target=? AND is_active=1 LIMIT 1", (fp,)
    ).fetchone():
        raise BizError(4030, "当前设备已被封禁，无法注册")


@router.post("/register")
def register(body: RegisterIn):
    email = body.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise BizError(4001, "邮箱格式不正确")
    if not body.guardian_declared:
        raise BizError(4002, "请确认：如未满 18 岁，注册使用须已获监护人知情同意")
    nickname = body.nickname.strip()
    if len(nickname) < 2:
        raise BizError(4005, "昵称至少 2 个字符")
    with db() as conn:
        # 同一邮箱最多 2 个账号
        email_count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE email = ?", (email,)).fetchone()["c"]
        if email_count >= 2:
            raise BizError(4003, "同一邮箱最多注册 2 个账号")
        if conn.execute("SELECT id FROM users WHERE nickname = ?", (nickname,)).fetchone():
            raise BizError(4006, "该昵称已被使用")
        existing_sysadmin = conn.execute("SELECT id FROM users WHERE role='sysadmin' LIMIT 1").fetchone()
        role = "sysadmin" if existing_sysadmin is None else "user"  # 首个注册用户为系统管理员
        fp = (body.device_fingerprint or "").strip()[:128]
        _check_register_bans(conn, email, fp)
        is_suspicious = 0
        if fp and role != "sysadmin":
            fp_count = conn.execute(
                "SELECT COUNT(*) AS c FROM users WHERE device_fingerprint = ?", (fp,)
            ).fetchone()["c"]
            is_suspicious = 1 if fp_count >= 3 else 0
        cur = conn.execute(
            "INSERT INTO users (email, password_hash, nickname, role, guardian_declared, device_fingerprint, is_suspicious) "
            "VALUES (?,?,?,?,?,?,?)",
            (email, hash_password(body.password), nickname, role, 1, fp, is_suspicious),
        )
        user = conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()

        # 首个注册用户的欢迎帖（论坛种子内容）
        if role == "sysadmin":
            post_count = conn.execute("SELECT COUNT(*) AS c FROM posts").fetchone()["c"]
            if post_count == 0:
                cat = conn.execute(
                    "SELECT id FROM categories WHERE parent_id IS NULL AND name = ?", ("社区公告",)
                ).fetchone()
                if cat:
                    conn.execute(
                        "INSERT INTO posts (category_id, user_id, title, content) VALUES (?,?,?,?)",
                        (
                            cat["id"],
                            user["id"],
                            "欢迎来到青联合规监督社区",
                            "## 社区宗旨\n\n"
                            "这里是一个面向青少年的互联网平台合规监督社区。\n\n"
                            "你可以：\n"
                            "- 提交你发现的不合理条款、霸王条款、数据滥用、未成年人保护缺失等举报任务。\n"
                            "- 在论坛参与讨论、发帖、回复、点赞、收藏。\n"
                            "- 每日签到获取积分，查看排行榜。\n"
                            "- 浏览知识库，学习法律法规与维权指南。\n\n"
                            "## 发帖规范\n\n"
                            "- 尊重他人，禁止人身攻击与恶意造谣。\n"
                            "- 上传截图时注意脱敏，避免泄露第三方个人信息。\n"
                            "- 社区内容仅供交流，不构成法律意见。\n\n"
                            "让我们一起维护更健康的互联网环境！",
                        ),
                    )

        data = _issue_session(conn, user)
    return ok(data, "注册成功")


def _pick_user_by_login(conn, email: str, password: str, nickname_hint: str):
    """根据邮箱+密码定位用户；同一邮箱多账号时需用昵称区分。"""
    rows = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchall()
    matched = [r for r in rows if verify_password(password, r["password_hash"])]
    if not matched:
        return None
    if len(matched) == 1:
        return matched[0]
    if nickname_hint:
        for r in matched:
            if r["nickname"] == nickname_hint.strip():
                return r
        raise BizError(4004, "昵称与邮箱密码组合不匹配")
    raise BizError(4007, "该邮箱关联多个账号，请提供昵称以选择登录账号")


@router.post("/login")
def login(body: LoginIn):
    email = body.email.strip().lower()
    with db() as conn:
        user = _pick_user_by_login(conn, email, body.password, body.nickname)
        if user is None:
            raise BizError(4004, "邮箱或密码错误")
        _check_bans(conn, user)
        data = _issue_session(conn, user)
    return ok(data, "登录成功")


@router.post("/refresh")
def refresh(body: RefreshIn):
    payload = decode_token(body.refresh_token, "refresh")
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (payload["sub"],)).fetchone()
        if user is None:
            raise BizError(4010, "用户不存在或已注销")
        _check_bans(conn, user)
        data = _issue_session(conn, user)
    return ok(data, "续期成功")


@router.post("/logout")
def logout(user: dict = Depends(csrf_check), x_sid: str = Header(default="", alias="X-SID")):
    """登出：清除当前 sid（校验归属，防跨用户清除 DoS）并清空 CSRF。"""
    sid = (x_sid or "").strip()
    if sid:
        # 仅当 sid 属于当前用户时清除；不匹配时静默忽略（不泄露 sid 存在性）
        from ..handshake import clear_handshake_for_user
        clear_handshake_for_user(sid, user["id"])
    else:
        clear_handshake_by_user(user["id"])
    with db() as conn:
        conn.execute("UPDATE users SET csrf_token = '' WHERE id = ?", (user["id"],))
    return ok(None, "已退出登录")


@router.get("/me")
def me(user: dict = Depends(get_current_user)):
    return ok(_public_user(user))


# ---------- 鼠标握手机制（SID 会话密钥反爬虫） ----------

@router.post("/handshake")
def handshake_heartbeat(user: dict = Depends(get_current_user), x_sid: str = Header(default="", alias="X-SID")):
    """接收前端鼠标活动心跳，更新会话活跃时间戳。

    安全：
    - 原子校验 sid 归属当前用户 + 轮换状态，避免 TOCTOU。
    - sid 不属于当前用户 → 4033（防跨用户保活会话）。
    - sid 已被轮换 → 4034（防攻击者维持已吊销会话）。
    """
    sid = (x_sid or "").strip()
    if sid:
        status, now = update_handshake_checked(sid, user["id"])
        if status == "rotated":
            raise BizError(4034, "会话密钥已因安全原因轮换，请重新登录")
        if status == "mismatch":
            raise BizError(4033, "会话验证失败，请重新登录")
    else:
        now = update_handshake_by_user(user["id"])
    return ok({"last_active_at": now}, "心跳已接收")


@router.get("/handshake/status")
def handshake_status(user: dict = Depends(get_current_user), x_sid: str = Header(default="", alias="X-SID")):
    """查询当前握手状态（活跃/剩余时间等）。

    安全：校验 sid 归属当前用户，不属于时返回空状态（防信息泄露）。
    """
    sid = (x_sid or "").strip()
    if sid:
        from ..handshake import get_handshake_status_for_user
        return ok(get_handshake_status_for_user(sid, user["id"]))
    return ok(get_handshake_status_by_user(user["id"]))


# ---------- Root 双因素登录（邮箱验证码仅发送至后端配置的 ROOT_EMAIL） ----------

def _smtp_setting(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM admin_settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def _send_root_code(code: str) -> None:
    """将 Root 登录验证码发送到后端配置的 ROOT_EMAIL。"""
    host = _smtp_setting("smtp_host")
    try:
        port = int(_smtp_setting("smtp_port") or 465)
    except ValueError:
        raise BizError(5002, "SMTP 端口配置错误")
    username = _smtp_setting("smtp_user")
    password = _smtp_setting("smtp_pass")
    use_ssl = _smtp_setting("smtp_use_ssl", "1") in ("1", "true", "True")
    mail_from = _smtp_setting("mail_from") or username or "noreply@compliance.local"
    if not host or not username or not password:
        raise BizError(5003, "Root 登录邮件验证码：SMTP 未配置")

    msg = EmailMessage()
    msg["Subject"] = "青联合规监督社区 Root 后台登录验证码"
    msg["From"] = mail_from
    msg["To"] = ROOT_EMAIL
    msg.set_content(
        f"您的 Root 后台登录验证码为：{code}\n"
        f"有效期 {ROOT_CODE_TTL_MINUTES} 分钟，请勿泄露给他人。\n"
        f"如非本人操作，请立即检查系统安全。"
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
    except Exception as e:
        raise BizError(5002, f"Root 验证码邮件发送失败：{e}")
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


@router.post("/root/step1")
def root_login_step1(body: RootStep1In):
    """Root 登录第一步：校验账号密码，发送邮箱验证码。"""
    email = body.email.strip().lower()
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ? AND role = 'root'", (email,)).fetchone()
        if user is None or not verify_password(body.password, user["password_hash"]):
            raise BizError(4004, "邮箱或密码错误")
        _check_bans(conn, user)

    code = "".join(secrets.choice("0123456789") for _ in range(6))
    temp_token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(minutes=ROOT_CODE_TTL_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    with db() as conn:
        conn.execute(
            "INSERT INTO root_login_codes (user_id, code, temp_token, expires_at) VALUES (?,?,?,?)",
            (user["id"], code, temp_token, expires),
        )
    _send_root_code(code)
    return ok({"temp_token": temp_token}, "验证码已发送，请查收邮箱")


@router.post("/root/step2")
def root_login_step2(body: RootStep2In):
    """Root 登录第二步：校验邮箱验证码，签发正式会话。"""
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM root_login_codes WHERE temp_token = ? AND used = 0 ORDER BY id DESC LIMIT 1",
            (body.temp_token,),
        ).fetchone()
        if row is None:
            raise BizError(4004, "验证码无效或已过期")
        if row["expires_at"] < datetime.now().strftime("%Y-%m-%d %H:%M:%S"):
            raise BizError(4004, "验证码已过期")
        if row["code"] != body.code.strip():
            raise BizError(4004, "验证码错误")
        conn.execute("UPDATE root_login_codes SET used = 1 WHERE id = ?", (row["id"],))
        user = conn.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
        if user is None:
            raise BizError(4040, "Root 账号不存在")
        _check_bans(conn, user)
        data = _issue_session(conn, user)
    return ok(data, "Root 登录成功")
