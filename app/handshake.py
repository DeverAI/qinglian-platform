"""SID 会话密钥握手安全模块：per-session SID + 鼠标活动追踪 + 异常轮换。

反爬虫/反盗号设计：
- 每次登录签发唯一 sid（32 字节随机令牌），前端通过 X-SID 头发送。
- 前端追踪鼠标移动并周期性发送心跳，后端记录每个 sid 的最后鼠标活跃时间。
- 发言类端点校验 X-SID 有效且 sid 有近期鼠标活动。
- 若请求缺少有效 sid 或 sid 无鼠标活动，记录失败时间戳；
  短时间窗口内失败达阈值时判定为自动化访问，轮换该用户全部 sid 并通知。

特性：
- 线程安全（threading.Lock 保护字典读写）。
- 轻量化：纯内存，不持久化，服务重启自动清零。
- 超时与失败阈值由 root 通过 admin_settings 配置。
- 自动清理过期会话，防止内存无限增长。
- root 账号豁免握手校验（双因素登录已保障安全）。
"""
import threading
import time
import secrets

from fastapi import Depends, Header

from .common import BizError
from .security import get_current_user, get_threshold

# 内存会话存储：sid -> {user_id, last_mouse_active, last_request_at, fail_count, created_at, rotated}
_sessions: dict[str, dict] = {}
# 每用户失败时间戳列表（滑动窗口异常检测）
_user_fails: dict[int, list[float]] = {}
_lock = threading.Lock()

# 默认超时秒数（可被 root 配置覆盖）
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_FAIL_LIMIT = 3
# 硬下限：防止 root 误配 0/负值导致 DoS（_get_timeout / _get_fail_limit 强制 max()）
_TIMEOUT_HARD_MIN = 10
_FAIL_LIMIT_HARD_MIN = 1
# 失败计数滑动窗口（秒）
_FAIL_WINDOW_SECONDS = 300
# 单用户失败记录上限（防内存放大攻击）
_FAIL_LIST_MAX = 200

# 清理间隔
_CLEANUP_INTERVAL_SECONDS = 300
_last_cleanup = 0.0


def _get_timeout() -> int:
    """从 admin_settings 读取超时阈值，强制不低于硬下限，防止误配 DoS。"""
    return max(get_threshold("threshold_handshake_timeout", DEFAULT_TIMEOUT_SECONDS), _TIMEOUT_HARD_MIN)


def _get_fail_limit() -> int:
    """从 admin_settings 读取失败阈值，强制不低于硬下限，防止误配 0 致首次失败即轮换。"""
    return max(get_threshold("threshold_handshake_fail_limit", DEFAULT_FAIL_LIMIT), _FAIL_LIMIT_HARD_MIN)


def _maybe_cleanup(now: float) -> None:
    """周期性清理过期会话与失败记录，防止内存无限增长。"""
    global _last_cleanup
    if now - _last_cleanup < _CLEANUP_INTERVAL_SECONDS:
        return
    _last_cleanup = now
    timeout = _get_timeout()
    cutoff = now - timeout * 3
    # 清理过期 sid（鼠标和请求都超时）
    expired_sids = [
        sid for sid, s in _sessions.items()
        if s.get("last_mouse_active", 0) < cutoff and s.get("last_request_at", 0) < cutoff
    ]
    for sid in expired_sids:
        _sessions.pop(sid, None)
    # 清理过期的失败记录
    fail_cutoff = now - _FAIL_WINDOW_SECONDS
    for uid in list(_user_fails.keys()):
        _user_fails[uid] = [t for t in _user_fails[uid] if t > fail_cutoff]
        if not _user_fails[uid]:
            _user_fails.pop(uid, None)


def issue_sid(user_id: int) -> str:
    """为用户签发一个新的会话 SID，返回 sid 字符串。"""
    sid = secrets.token_urlsafe(32)
    now = time.time()
    with _lock:
        _sessions[sid] = {
            "user_id": user_id,
            "last_mouse_active": now,
            "last_request_at": now,
            "fail_count": 0,
            "created_at": now,
            "rotated": False,
        }
        _maybe_cleanup(now)
    return sid


def is_sid_rotated(sid: str) -> bool:
    """检查 sid 是否已被标记为轮换（失效）。"""
    with _lock:
        s = _sessions.get(sid)
        return s is not None and bool(s.get("rotated"))


def _sid_belongs_to(sid: str, user_id: int) -> bool:
    """检查 sid 是否属于指定用户（sid 不存在亦返回 False）。"""
    with _lock:
        s = _sessions.get(sid)
        return s is not None and s.get("user_id") == user_id


def update_handshake(sid: str) -> float:
    """更新 sid 的最后鼠标活跃时间戳，返回当前时间戳。

    鼠标活动会重置该 sid 的失败计数。
    若 sid 已被轮换则不做任何更新（调用方应自行检测并返回 4034）。
    """
    now = time.time()
    with _lock:
        s = _sessions.get(sid)
        if s is not None and not s.get("rotated"):
            s["last_mouse_active"] = now
            s["last_request_at"] = now
            s["fail_count"] = 0
        _maybe_cleanup(now)
    return now


def update_handshake_checked(sid: str, user_id: int) -> tuple[str, float]:
    """原子地校验 sid 归属与轮换状态，并更新活跃时间戳。

    返回 (status, now)：
    - "ok"         : 校验通过且已更新
    - "rotated"    : sid 已被轮换（调用方应返回 4034）
    - "mismatch"   : sid 不属于该用户或不存在（调用方应返回 4033）
    原子操作避免 is_sid_rotated + update_handshake 间的 TOCTOU。
    """
    now = time.time()
    with _lock:
        s = _sessions.get(sid)
        if s is None or s.get("user_id") != user_id:
            return "mismatch", now
        if s.get("rotated"):
            return "rotated", now
        s["last_mouse_active"] = now
        s["last_request_at"] = now
        s["fail_count"] = 0
        _maybe_cleanup(now)
    return "ok", now


def get_handshake_status_for_user(sid: str, user_id: int) -> dict:
    """查询 sid 状态并校验归属：sid 不属于该用户时返回空状态（防信息泄露）。"""
    with _lock:
        s = _sessions.get(sid)
        if s is None or s.get("user_id") != user_id:
            timeout = _get_timeout()
            return {
                "active": False,
                "timeout_seconds": timeout,
                "remaining_seconds": 0,
                "last_active_at": 0,
                "rotated": False,
            }
        last = s.get("last_mouse_active", 0.0)
        rotated = s.get("rotated", False)
        timeout = _get_timeout()
    now = time.time()
    active = last > 0 and (now - last) <= timeout and not rotated
    remaining = max(0, int(timeout - (now - last))) if last > 0 else 0
    return {
        "active": active,
        "timeout_seconds": timeout,
        "remaining_seconds": remaining,
        "last_active_at": last,
        "rotated": rotated,
    }


def invalidate_user_sids(user_id: int) -> None:
    """静默失效该用户的所有旧 sid（不写系统通知）。

    用于 login/register/refresh 签发新 sid 前清理旧会话，
    避免旧 sid 在 _maybe_cleanup 回收前仍可被 require_handshake 接受的复用窗口。
    与 rotate_user_sids 不同：不写通知、不设置 rotated_reason，
    但仍标记 rotated=True 以让旧 sid 立即失效。
    """
    with _lock:
        for s in _sessions.values():
            if s.get("user_id") == user_id and not s.get("rotated"):
                s["rotated"] = True
                s["rotated_at"] = time.time()
                s["rotated_reason"] = "用户重新登录，旧会话密钥已失效"
        _user_fails.pop(user_id, None)


def clear_handshake_for_user(sid: str, user_id: int) -> bool:
    """仅当 sid 属于该用户时清除，返回是否清除成功。

    防止攻击者用自身令牌 + 受害者 sid 调用 logout 清除受害者会话（DoS）。
    同时清理该用户的失败计数（_user_fails）。
    """
    with _lock:
        s = _sessions.get(sid)
        if s is None or s.get("user_id") != user_id:
            return False
        _sessions.pop(sid, None)
        _user_fails.pop(user_id, None)
        return True


def update_handshake_by_user(user_id: int) -> float:
    """向后兼容：以 user_id 更新握手（更新该用户所有活跃 sid）。"""
    now = time.time()
    with _lock:
        for s in _sessions.values():
            if s.get("user_id") == user_id and not s.get("rotated"):
                s["last_mouse_active"] = now
                s["last_request_at"] = now
                s["fail_count"] = 0
        _maybe_cleanup(now)
    return now


def is_handshake_active(sid: str) -> bool:
    """检查 sid 是否在超时阈值内有过鼠标活动。"""
    timeout = _get_timeout()
    now = time.time()
    with _lock:
        s = _sessions.get(sid)
        if s is None or s.get("rotated"):
            return False
        last = s.get("last_mouse_active", 0.0)
    if last == 0.0:
        return False
    return (now - last) <= timeout


def is_handshake_active_by_user(user_id: int) -> bool:
    """向后兼容：以 user_id 检查握手活跃（任一 sid 活跃即视为活跃）。"""
    timeout = _get_timeout()
    now = time.time()
    with _lock:
        for s in _sessions.values():
            if s.get("user_id") == user_id and not s.get("rotated"):
                last = s.get("last_mouse_active", 0.0)
                if last > 0 and (now - last) <= timeout:
                    return True
    return False


def get_handshake_status(sid: str) -> dict:
    """返回握手状态详情（供前端展示剩余时间等）。"""
    timeout = _get_timeout()
    now = time.time()
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return {
                "active": False,
                "timeout_seconds": timeout,
                "remaining_seconds": 0,
                "last_active_at": 0,
                "rotated": False,
            }
        last = s.get("last_mouse_active", 0.0)
        rotated = s.get("rotated", False)
    active = last > 0 and (now - last) <= timeout and not rotated
    remaining = max(0, int(timeout - (now - last))) if last > 0 else 0
    return {
        "active": active,
        "timeout_seconds": timeout,
        "remaining_seconds": remaining,
        "last_active_at": last,
        "rotated": rotated,
    }


def get_handshake_status_by_user(user_id: int) -> dict:
    """向后兼容：以 user_id 查询握手状态（取该用户任一未轮换 sid）。"""
    sid = None
    with _lock:
        for s_id, s in _sessions.items():
            if s.get("user_id") == user_id and not s.get("rotated"):
                sid = s_id
                break
    if sid:
        return get_handshake_status(sid)
    timeout = _get_timeout()
    return {
        "active": False,
        "timeout_seconds": timeout,
        "remaining_seconds": 0,
        "last_active_at": 0,
        "rotated": False,
    }


def clear_handshake(sid: str) -> None:
    """清除指定 sid（登出时调用）。"""
    with _lock:
        _sessions.pop(sid, None)


def clear_handshake_by_user(user_id: int) -> None:
    """向后兼容：清除用户的所有 sid。"""
    with _lock:
        to_remove = [sid for sid, s in _sessions.items() if s.get("user_id") == user_id]
        for sid in to_remove:
            _sessions.pop(sid, None)
        _user_fails.pop(user_id, None)


def _record_user_fail(user_id: int) -> int:
    """记录一次用户握手失败，返回滑动窗口内的失败次数。

    单用户失败记录上限 _FAIL_LIST_MAX，防止高频失败请求导致内存放大。
    """
    now = time.time()
    cutoff = now - _FAIL_WINDOW_SECONDS
    with _lock:
        fails = [t for t in _user_fails.get(user_id, []) if t > cutoff]
        fails.append(now)
        if len(fails) > _FAIL_LIST_MAX:
            # 保留最近的记录（足够触发轮换判定）
            fails = fails[-_FAIL_LIST_MAX:]
        _user_fails[user_id] = fails
        _maybe_cleanup(now)
    return len(fails)


def rotate_user_sids(user_id: int, reason: str = "") -> None:
    """轮换指定用户的所有 SID：将旧 sid 标记为已轮换（失效），并写系统通知。

    通知用户：可能是账号被盗或有人在进行爬虫操作。
    注意：不自动签发新 sid——客户端需重新登录获取新 sid。
    """
    with _lock:
        for s in _sessions.values():
            if s.get("user_id") == user_id and not s.get("rotated"):
                s["rotated"] = True
                s["rotated_at"] = time.time()
                s["rotated_reason"] = reason
        _user_fails.pop(user_id, None)
    # 写系统通知（延迟导入避免循环依赖）
    try:
        from .routers.notify import add_system_message
        add_system_message(
            "system",
            "安全提醒：会话密钥已自动轮换",
            "系统检测到您的账号存在异常会话活动（"
            + (reason or "自动化访问")
            + "），已自动轮换全部会话密钥以保护账号安全。"
            "这可能是由于账号被盗用或有人在使用爬虫程序访问。"
            "请检查账号安全设置并重新登录。如非本人操作，请立即修改密码。",
        )
    except Exception:
        pass  # 通知写入失败不影响安全逻辑


def require_handshake(
    user: dict = Depends(get_current_user),
    x_sid: str = Header(default="", alias="X-SID"),
) -> dict:
    """发言类操作的握手守卫。

    校验逻辑：
    1. root 账号豁免（双因素登录已保障安全）。
    2. 从 X-SID 头提取 sid，校验 sid 存在、未轮换、匹配当前用户。
    3. 校验 sid 有近期鼠标活动。
    4. 若校验失败，记录失败时间戳；滑动窗口内失败达阈值时轮换该用户全部
       sid 并返回 code=4034。
    5. 临时性无活动返回 code=4033（请移动鼠标）。
    6. sid 已被轮换返回 code=4034（需重新登录）。
    """
    # root 豁免
    if user.get("role") == "root":
        return user

    sid = (x_sid or "").strip()

    # 校验 sid 有效性 + 鼠标活跃
    sid_valid = False
    sid_active = False
    sid_rotated = False
    now = time.time()
    timeout = _get_timeout()
    with _lock:
        s = _sessions.get(sid)
        if s is not None:
            if s.get("user_id") == user["id"]:
                if s.get("rotated"):
                    sid_rotated = True
                else:
                    sid_valid = True
                    s["last_request_at"] = now
                    last = s.get("last_mouse_active", 0.0)
                    sid_active = last > 0 and (now - last) <= timeout

    # sid 已被轮换 → 直接告知需重新登录
    if sid_rotated:
        raise BizError(4034, "会话密钥已因安全原因轮换，请重新登录")

    # 校验通过
    if sid_valid and sid_active:
        return user

    # 校验失败：记录失败时间戳
    fail_count = _record_user_fail(user["id"])

    # 检查是否达阈值 → 轮换
    fail_limit = _get_fail_limit()
    if fail_count >= fail_limit:
        rotate_user_sids(user["id"], f"连续 {fail_count} 次握手失败")
        raise BizError(4034, "检测到异常会话活动，会话密钥已自动轮换，请重新登录")

    # 临时性失败
    if not sid_valid:
        raise BizError(4033, "会话验证失败，请移动鼠标或重新登录")
    raise BizError(4033, "请移动鼠标验证真人身份后再发言")
