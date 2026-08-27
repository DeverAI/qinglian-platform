"""安全模块：密码哈希、HS256 JWT（标准库自实现）、认证/权限/CSRF 依赖。

轻量化原则：不引入 PyJWT / passlib，全部基于 hashlib/hmac/secrets。
"""
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time

from fastapi import Depends, Header

from . import config
from .common import BizError
from .database import db

# ---------------- 密码 ----------------

PBKDF2_ROUNDS = 100_000
MAX_TOKEN_LENGTH = 4096


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ROUNDS)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, expected = stored.split("$", 1)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ROUNDS)
    return hmac.compare_digest(dk.hex(), expected)


# ---------------- JWT（HS256） ----------------

def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def create_token(user_id: int, role: str, kind: str, days: int) -> str:
    now = int(time.time())
    header = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64e(json.dumps(
        {"sub": user_id, "role": role, "type": kind, "iat": now, "exp": now + days * 86400},
        separators=(",", ":"),
    ).encode())
    signing_input = f"{header}.{payload}"
    sig = hmac.new(config.SECRET_KEY.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64e(sig)}"


def decode_token(token: str, expect_type: str) -> dict:
    if not token or len(token) > MAX_TOKEN_LENGTH:
        raise BizError(4010, "令牌格式无效")
    try:
        header, payload, sig = token.split(".")
    except ValueError:
        raise BizError(4010, "令牌格式无效")
    try:
        header_data = json.loads(_b64d(header))
    except Exception:
        raise BizError(4010, "令牌头损坏")
    if header_data != {"alg": "HS256", "typ": "JWT"}:
        raise BizError(4010, "令牌算法无效")
    signing_input = f"{header}.{payload}"
    expected = hmac.new(config.SECRET_KEY.encode(), signing_input.encode(), hashlib.sha256).digest()
    try:
        actual = _b64d(sig)
    except Exception:
        raise BizError(4010, "令牌签名无效")
    if not hmac.compare_digest(actual, expected):
        raise BizError(4010, "令牌签名不匹配")
    try:
        data = json.loads(_b64d(payload))
    except Exception:
        raise BizError(4010, "令牌载荷损坏")
    if data.get("type") != expect_type:
        raise BizError(4010, "令牌类型错误")
    now = int(time.time())
    try:
        subject = int(data["sub"])
        issued_at = int(data["iat"])
        expires_at = int(data["exp"])
    except (KeyError, TypeError, ValueError):
        raise BizError(4010, "令牌载荷无效")
    if subject <= 0 or issued_at > now + 60 or expires_at <= issued_at:
        raise BizError(4010, "令牌载荷无效")
    if expires_at < now:
        raise BizError(4010, "令牌已过期")
    data["sub"] = subject
    return data


def issue_token_pair(user_id: int, role: str) -> dict:
    return {
        "access_token": create_token(user_id, role, "access", config.ACCESS_TOKEN_DAYS),
        "refresh_token": create_token(user_id, role, "refresh", config.REFRESH_TOKEN_DAYS),
    }


# ---------------- 依赖注入 ----------------

def _check_bans(conn: sqlite3.Connection, row) -> None:
    """校验账号、邮箱、设备是否被封禁。root 账号豁免邮箱/设备维度封禁，防止被恶意锁定。"""
    if row["is_banned"]:
        raise BizError(4030, "账号已被封禁，请联系管理员")
    # 统一校验 bans 表中的账号级封禁（兼容以 user_id 或 email 为 target 的记录）
    for account_target in (str(row["id"]), row["email"]):
        if conn.execute(
            "SELECT 1 FROM bans WHERE ban_type='account' AND target=? AND is_active=1 LIMIT 1",
            (account_target,),
        ).fetchone():
            raise BizError(4030, "该账号已被封禁，请联系管理员")
    if row["role"] == "root":
        return
    email = row["email"]
    fp = row["device_fingerprint"] or ""
    if conn.execute(
        "SELECT 1 FROM bans WHERE ban_type='email' AND target=? AND is_active=1 LIMIT 1", (email,)
    ).fetchone():
        raise BizError(4030, "该邮箱已被封禁，请联系管理员")
    if fp and conn.execute(
        "SELECT 1 FROM bans WHERE ban_type='device' AND target=? AND is_active=1 LIMIT 1", (fp,)
    ).fetchone():
        raise BizError(4030, "当前设备已被封禁，请联系管理员")


def get_current_user(authorization: str = Header(default="")) -> dict:
    if not authorization.startswith("Bearer "):
        raise BizError(4010, "未登录或令牌缺失")
    payload = decode_token(authorization[7:].strip(), "access")
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (payload["sub"],)).fetchone()
        if row is None:
            raise BizError(4010, "用户不存在或已注销")
        _check_bans(conn, row)
    return {
        "id": row["id"],
        "email": row["email"],
        "nickname": row["nickname"],
        "role": row["role"],
        "points": row["points"],
        "is_banned": row["is_banned"],
        "is_suspicious": row["is_suspicious"],
        "nickname_color": row["nickname_color"],
        "csrf_token": row["csrf_token"],
        "created_at": row["created_at"],
    }


def get_optional_user(authorization: str = Header(default="")) -> dict | None:
    if not authorization.startswith("Bearer "):
        return None
    try:
        return get_current_user(authorization)
    except BizError:
        return None


def csrf_check(
    x_csrf_token: str = Header(default=""),
    user: dict = Depends(get_current_user),
) -> dict:
    """变更类请求必须携带与账号绑定的 CSRF Token。"""
    stored = user.get("csrf_token") or ""
    if not x_csrf_token or not stored or not hmac.compare_digest(x_csrf_token, stored):
        raise BizError(4030, "CSRF 校验失败，请重新登录")
    return user


def require_roles(*roles: str, mutating: bool = False):
    """角色守卫。mutating=True 时同时强制 CSRF 校验（用于变更类管理操作）。"""
    base = csrf_check if mutating else get_current_user

    def dep(user: dict = Depends(base)) -> dict:
        # root 可访问任何管理员接口
        if user["role"] == "root":
            return user
        if user["role"] not in roles:
            raise BizError(4030, "权限不足")
        return user

    return dep


def require_root(mutating: bool = False):
    """仅 root 账号可访问。"""
    base = csrf_check if mutating else get_current_user

    def dep(user: dict = Depends(base)) -> dict:
        if user["role"] != "root":
            raise BizError(4030, "权限不足")
        return user

    return dep


def get_user_points(user_id: int) -> int:
    """查询用户当前积分（points 冗余字段）。"""
    with db() as conn:
        row = conn.execute("SELECT points FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            return 0
        return int(row["points"] or 0)


def has_points(user_id: int, min_points: int) -> bool:
    """判断用户积分是否达到门槛。"""
    return get_user_points(user_id) >= min_points


def get_threshold(key: str, default: int) -> int:
    """从 admin_settings 读取 root 可配置阈值，失败时返回默认值。"""
    try:
        with db() as conn:
            row = conn.execute("SELECT value FROM admin_settings WHERE key=?", (key,)).fetchone()
            if row and row["value"]:
                return int(row["value"])
    except Exception:
        pass
    return default


def ensure_points_in_tx(conn: sqlite3.Connection, user_id: int, min_points: int) -> bool:
    """在业务事务内原子校验积分，防止 TOCTOU 绕过门槛。"""
    row = conn.execute("SELECT points FROM users WHERE id=?", (user_id,)).fetchone()
    if row is None:
        return False
    return int(row["points"] or 0) >= min_points


def require_points(min_points: int, mutating: bool = False):
    """积分门槛守卫（预检查）；mutating=True 时同时强制 CSRF 校验。

    注意：本依赖只做快速失败，涉及消耗积分权益的写操作仍需在事务内调用
    ensure_points_in_tx 做原子校验，避免并发窗口被绕过。
    """
    base = csrf_check if mutating else get_current_user

    def dep(user: dict = Depends(base)) -> dict:
        if (user.get("points") or 0) < min_points:
            raise BizError(4031, f"积分不足，需要至少 {min_points} 积分")
        return user

    return dep


def require_threshold(key: str, default: int, mutating: bool = False):
    """root 可配置积分门槛守卫；每次请求动态读取 admin_settings，捕获闭包值。"""
    base = csrf_check if mutating else get_current_user

    def dep(user: dict = Depends(base)) -> dict:
        min_points = get_threshold(key, default)
        if (user.get("points") or 0) < min_points:
            raise BizError(4031, f"积分不足，需要至少 {min_points} 积分")
        return user

    return dep


SPEAK_BYPASS_ROLES = {"moderator", "admin", "sysadmin", "root"}


def require_speak(mutating: bool = True):
    """发言积分门槛守卫：版主/管理员/root 不受 0-3 分禁言限制；其余用户需 >= threshold_points_speak。"""
    base = csrf_check if mutating else get_current_user

    def dep(user: dict = Depends(base)) -> dict:
        if user["role"] in SPEAK_BYPASS_ROLES:
            return user
        min_points = get_threshold("threshold_points_speak", 4)
        if (user.get("points") or 0) < min_points:
            raise BizError(4031, f"积分不足，需要至少 {min_points} 积分才能发言")
        return user

    return dep


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)
