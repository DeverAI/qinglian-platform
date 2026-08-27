"""IP access protection: configurable adaptive rate limiting and audit events."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from .common import BizError
from .database import DEFAULT_THRESHOLDS, db


SECURITY_SETTING_KEYS = {
    "threshold_ip_protection_enabled",
    "threshold_ip_window_seconds",
    "threshold_ip_default_limit",
    "threshold_ip_min_limit",
    "threshold_ip_degrade_percent",
    "threshold_ip_degrade_minutes",
    "threshold_ip_ban_minutes",
    "threshold_ip_ban_max_minutes",
    "threshold_ip_ban_escalation_percent",
    "threshold_ip_recovery_percent",
}


def validate_security_changes(conn, changes: dict[str, str]) -> None:
    """Validate a partial root update against the complete persisted policy."""
    rows = conn.execute(
        "SELECT key, value FROM admin_settings WHERE key IN (" + ",".join("?" * len(SECURITY_SETTING_KEYS)) + ")",
        tuple(SECURITY_SETTING_KEYS),
    ).fetchall()
    merged = {key: DEFAULT_THRESHOLDS[key] for key in SECURITY_SETTING_KEYS}
    merged.update({row["key"]: row["value"] for row in rows})
    merged.update({key: str(value).strip() for key, value in changes.items() if key in SECURITY_SETTING_KEYS})
    try:
        parsed = {key: int(merged[key]) for key in SECURITY_SETTING_KEYS}
    except (TypeError, ValueError) as exc:
        raise BizError(4001, "安全防护参数必须为整数") from exc
    if parsed["threshold_ip_protection_enabled"] not in (0, 1):
        raise BizError(4001, "IP 防护开关只能为 0 或 1")
    positive = SECURITY_SETTING_KEYS - {"threshold_ip_protection_enabled", "threshold_ip_ban_escalation_percent"}
    if any(parsed[key] < 1 for key in positive) or parsed["threshold_ip_ban_escalation_percent"] < 0:
        raise BizError(4001, "安全防护阈值必须为正整数（封禁递增比例可为 0）")
    for key in ("threshold_ip_degrade_percent", "threshold_ip_recovery_percent"):
        if parsed[key] > 100:
            raise BizError(4001, f"{key} 必须在 1-100 之间")
    if parsed["threshold_ip_min_limit"] > parsed["threshold_ip_default_limit"]:
        raise BizError(4001, "IP 最低访问上限不能高于默认访问上限")
    if parsed["threshold_ip_ban_minutes"] > parsed["threshold_ip_ban_max_minutes"]:
        raise BizError(4001, "默认封禁时长不能高于最大封禁时长")


@dataclass(frozen=True)
class ProtectionConfig:
    enabled: bool
    window_seconds: int
    default_limit: int
    min_limit: int
    degrade_percent: int
    degrade_minutes: int
    ban_minutes: int
    ban_max_minutes: int
    ban_escalation_percent: int
    recovery_percent: int


@dataclass
class IpPolicy:
    ip: str
    request_count: int
    window_started_at: float
    limit_per_minute: int
    strike_count: int
    banned_until: float
    degraded_until: float
    last_seen: float


_LOCK = threading.Lock()


def _now() -> float:
    return time.time()


def _read_config(conn) -> ProtectionConfig:
    placeholders = ",".join("?" * len(SECURITY_SETTING_KEYS))
    rows = conn.execute(
        f"SELECT key, value FROM admin_settings WHERE key IN ({placeholders})",
        tuple(SECURITY_SETTING_KEYS),
    ).fetchall()
    values = {row["key"]: row["value"] for row in rows}

    def value(key: str) -> int:
        raw = values.get(key, DEFAULT_THRESHOLDS[key])
        try:
            return int(raw)
        except (TypeError, ValueError):
            return int(DEFAULT_THRESHOLDS[key])

    default_limit = max(1, value("threshold_ip_default_limit"))
    min_limit = max(1, min(value("threshold_ip_min_limit"), default_limit))
    ban_minutes = max(1, value("threshold_ip_ban_minutes"))
    return ProtectionConfig(
        enabled=value("threshold_ip_protection_enabled") == 1,
        window_seconds=max(1, value("threshold_ip_window_seconds")),
        default_limit=default_limit,
        min_limit=min_limit,
        degrade_percent=max(1, min(value("threshold_ip_degrade_percent"), 100)),
        degrade_minutes=max(1, value("threshold_ip_degrade_minutes")),
        ban_minutes=ban_minutes,
        ban_max_minutes=max(ban_minutes, value("threshold_ip_ban_max_minutes")),
        ban_escalation_percent=max(0, value("threshold_ip_ban_escalation_percent")),
        recovery_percent=max(1, min(value("threshold_ip_recovery_percent"), 100)),
    )


def get_ip_ban_minutes() -> int:
    with db() as conn:
        return _read_config(conn).ban_minutes


def _load_policy(conn, ip: str, default_limit: int) -> IpPolicy:
    row = conn.execute(
        "SELECT ip, request_count, window_started_at, limit_per_minute, strike_count, "
        "banned_until, degraded_until, last_seen FROM ip_access_controls WHERE ip=?",
        (ip,),
    ).fetchone()
    now = _now()
    if row:
        return IpPolicy(
            ip=row["ip"], request_count=int(row["request_count"] or 0),
            window_started_at=float(row["window_started_at"] or now),
            limit_per_minute=int(row["limit_per_minute"] or default_limit),
            strike_count=int(row["strike_count"] or 0),
            banned_until=float(row["banned_until"] or 0),
            degraded_until=float(row["degraded_until"] or 0),
            last_seen=float(row["last_seen"] or now),
        )
    return IpPolicy(ip, 0, now, default_limit, 0, 0, 0, now)


def _save_policy(conn, policy: IpPolicy) -> None:
    conn.execute(
        """
        INSERT INTO ip_access_controls
            (ip, request_count, window_started_at, limit_per_minute, strike_count, banned_until, degraded_until, last_seen)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
            request_count=excluded.request_count, window_started_at=excluded.window_started_at,
            limit_per_minute=excluded.limit_per_minute, strike_count=excluded.strike_count,
            banned_until=excluded.banned_until, degraded_until=excluded.degraded_until,
            last_seen=excluded.last_seen
        """,
        (policy.ip, policy.request_count, policy.window_started_at, policy.limit_per_minute,
         policy.strike_count, policy.banned_until, policy.degraded_until, policy.last_seen),
    )


def _log_event(conn, ip: str, event_type: str, path: str = "", detail: str = "", actor_id: int | None = None) -> None:
    conn.execute(
        "INSERT INTO ip_security_events (ip, event_type, path, detail, actor_id) VALUES (?,?,?,?,?)",
        (ip[:64], event_type[:64], path[:500], detail[:1000], actor_id),
    )


def inspect_request(ip: str, path: str = "") -> None:
    if not ip or ip in {"127.0.0.1", "::1", "localhost", "testserver", "testclient"}:
        return
    now = _now()
    with _LOCK:
        with db() as conn:
            cfg = _read_config(conn)
            if not cfg.enabled:
                return
            policy = _load_policy(conn, ip, cfg.default_limit)
            policy.last_seen = now
            if policy.banned_until > now:
                _save_policy(conn, policy)
                raise BizError(4290, "当前 IP 已被临时封禁，请稍后再试")

            # 配置修改对新策略立即生效；降级到期后按 root 配置逐步恢复，避免瞬时流量反弹。
            if policy.strike_count == 0:
                policy.limit_per_minute = cfg.default_limit
            elif policy.degraded_until and policy.degraded_until <= now and policy.limit_per_minute < cfg.default_limit:
                old_limit = policy.limit_per_minute
                recovery = max(1, cfg.default_limit * cfg.recovery_percent // 100)
                policy.limit_per_minute = min(cfg.default_limit, old_limit + recovery)
                policy.degraded_until = now + cfg.degrade_minutes * 60 if policy.limit_per_minute < cfg.default_limit else 0
                _log_event(conn, ip, "limit_recovered", path, f"old_limit={old_limit}, new_limit={policy.limit_per_minute}")
            policy.limit_per_minute = max(cfg.min_limit, min(policy.limit_per_minute, cfg.default_limit))

            if now - policy.window_started_at >= cfg.window_seconds:
                policy.window_started_at = now
                policy.request_count = 0
            policy.request_count += 1
            if policy.request_count > policy.limit_per_minute:
                old_limit = policy.limit_per_minute
                policy.strike_count += 1
                policy.degraded_until = now + cfg.degrade_minutes * 60
                ban_minutes = min(
                    cfg.ban_max_minutes,
                    cfg.ban_minutes * (100 + cfg.ban_escalation_percent * (policy.strike_count - 1)) // 100,
                )
                policy.banned_until = now + ban_minutes * 60
                reduction = max(1, old_limit * cfg.degrade_percent // 100)
                policy.limit_per_minute = max(cfg.min_limit, old_limit - reduction)
                policy.request_count = 0
                _save_policy(conn, policy)
                _log_event(
                    conn, ip, "auto_ban", path,
                    f"strike={policy.strike_count}, ban_minutes={ban_minutes}, old_limit={old_limit}, new_limit={policy.limit_per_minute}",
                )
                # BizError 会使 db() 回滚；先原子持久化封禁和事件，再向请求返回 429。
                conn.commit()
                raise BizError(4290, "访问频率过高，已触发临时封禁")
            _save_policy(conn, policy)


def lift_ip_ban(ip: str, actor_id: int | None = None) -> None:
    with _LOCK:
        with db() as conn:
            cfg = _read_config(conn)
            policy = _load_policy(conn, ip, cfg.default_limit)
            policy.banned_until = 0
            policy.request_count = 0
            _save_policy(conn, policy)
            _log_event(conn, ip, "manual_lift", actor_id=actor_id)


def set_ip_ban(ip: str, minutes: int, reason: str = "", actor_id: int | None = None) -> int:
    now = _now()
    with _LOCK:
        with db() as conn:
            cfg = _read_config(conn)
            minutes = max(1, min(int(minutes), cfg.ban_max_minutes))
            policy = _load_policy(conn, ip, cfg.default_limit)
            old_limit = policy.limit_per_minute
            policy.banned_until = now + minutes * 60
            policy.degraded_until = max(policy.degraded_until, now + cfg.degrade_minutes * 60)
            policy.strike_count += 1
            reduction = max(1, old_limit * cfg.degrade_percent // 100)
            policy.limit_per_minute = max(cfg.min_limit, old_limit - reduction)
            policy.request_count = 0
            _save_policy(conn, policy)
            _log_event(conn, ip, "manual_ban", detail=f"minutes={minutes}, reason={reason}", actor_id=actor_id)
            return minutes


def policy_snapshot(ip: str) -> dict:
    with _LOCK:
        with db() as conn:
            cfg = _read_config(conn)
            policy = _load_policy(conn, ip, cfg.default_limit)
    return {
        "ip": policy.ip, "request_count": policy.request_count,
        "window_started_at": policy.window_started_at, "limit_per_minute": policy.limit_per_minute,
        "strike_count": policy.strike_count, "banned_until": policy.banned_until,
        "degraded_until": policy.degraded_until, "last_seen": policy.last_seen,
    }
