"""反刷与内容治理模块：字数门槛、频率限制、查重、每日上限、长文本自动转txt。

所有阈值通过 `admin_settings` 动态读取（get_threshold），由 root 在后台配置。
"""
import threading
import time
import uuid
from pathlib import Path

from .common import BizError


# 频率限制：内存 dict + 线程锁
_rate_limit_store: dict[tuple[int, str], float] = {}
_rate_limit_lock = threading.Lock()


def check_word_count(content: str, min_words: int) -> None:
    """T1.1: 字数门槛校验。content 长度（字符数）必须 >= min_words。"""
    if len(content) < min_words:
        raise BizError(4001, f"内容过短，至少需要 {min_words} 个字")


def check_rate_limit(user_id: int, operation: str, window: int = 5) -> None:
    """T1.2: 频率限制。同一用户同一操作 N 秒内禁止重复提交。

    Args:
        window: 时间窗口（秒），默认 5 秒。
    """
    key = (user_id, operation)
    now = time.time()
    with _rate_limit_lock:
        last = _rate_limit_store.get(key)
        if last is not None and now - last < window:
            raise BizError(4290, f"操作过于频繁，请 {window} 秒后再试")
        _rate_limit_store[key] = now
        # 懒清理：全清旧条目，避免内存泄漏
        if len(_rate_limit_store) > 2000:
            cutoff = now - 60
            stale_keys = [k for k, t in _rate_limit_store.items() if t < cutoff]
            for k in stale_keys:
                del _rate_limit_store[k]


# 允许的查重表名白名单，防止 SQL 注入
_DUPLICATE_TABLES = frozenset({"posts", "replies"})


def check_duplicate(
    conn, user_id: int, content: str, table: str, window_hours: int = 24
) -> int | None:
    """T1.3: 查重。返回 similar_to_id 或 None。

    基于 content 前缀匹配（前 50 字）在指定时间窗口内检测。
    仅检测同一用户的重复提交，避免误伤正常讨论。
    table 仅允许白名单内的值，防止 SQL 注入。
    """
    if table not in _DUPLICATE_TABLES:
        raise ValueError(f"非法表名：{table}")
    prefix = content[:50].strip()
    if not prefix:
        return None
    row = conn.execute(
        f"SELECT id FROM {table} WHERE user_id=? AND substr(content,1,50)=? "
        f"AND created_at > datetime('now','-{window_hours} hours','localtime') LIMIT 1",
        (user_id, prefix),
    ).fetchone()
    return row["id"] if row else None


def check_daily_text_bytes(conn, user_id: int, content_length: int, max_bytes: int) -> None:
    """T1.4: 校验每日文字总量上限。超过时抛出 BizError。"""
    today = time.strftime("%Y-%m-%d")
    row = conn.execute(
        "SELECT text_bytes FROM user_daily_usage WHERE user_id=? AND usage_date=?",
        (user_id, today),
    ).fetchone()
    used = row["text_bytes"] if row else 0
    if used + content_length > max_bytes:
        raise BizError(
            4291,
            f"今日文字总量已达上限（{max_bytes} 字节 ≈ {max_bytes // 1024}KB），请明日再试",
        )


def add_daily_text_bytes(conn, user_id: int, content_length: int) -> None:
    """T1.4: 累加当日已发文字量（upsert）。"""
    today = time.strftime("%Y-%m-%d")
    conn.execute(
        "INSERT INTO user_daily_usage (user_id, usage_date, text_bytes) VALUES (?,?,?) "
        "ON CONFLICT(user_id, usage_date) DO UPDATE SET "
        "text_bytes=text_bytes+?, updated_at=datetime('now','localtime')",
        (user_id, today, content_length, content_length),
    )


def check_daily_image_bytes(conn, user_id: int, image_size: int, max_bytes: int) -> None:
    """T1.5: 校验每日图片总量上限。超过时抛出 BizError。"""
    today = time.strftime("%Y-%m-%d")
    row = conn.execute(
        "SELECT image_bytes FROM user_daily_usage WHERE user_id=? AND usage_date=?",
        (user_id, today),
    ).fetchone()
    used = row["image_bytes"] if row else 0
    if used + image_size > max_bytes:
        raise BizError(
            4292,
            f"今日图片总量已达上限（约 {max_bytes // 1024 // 1024}MB），请明日再试",
        )


def add_daily_image_bytes(conn, user_id: int, image_size: int) -> None:
    """T1.5: 累加当日已上传图片字节数（upsert）。"""
    today = time.strftime("%Y-%m-%d")
    conn.execute(
        "INSERT INTO user_daily_usage (user_id, usage_date, image_bytes) VALUES (?,?,?) "
        "ON CONFLICT(user_id, usage_date) DO UPDATE SET "
        "image_bytes=image_bytes+?, updated_at=datetime('now','localtime')",
        (user_id, today, image_size, image_size),
    )


def auto_long_text_to_txt(
    content: str, upload_dir: Path, max_length: int = 2000
) -> tuple[str, bool]:
    """T1.6: 长文本自动转 txt 文件。返回 (content_or_path, is_file)。

    当 len(content) > max_length 时，写入 uploads/ 下 txt 文件，
    正文存文件路径，原字段替换为 `[长文本已转存] {filename}`。
    """
    if len(content) <= max_length:
        return content, False
    filename = f"longtext_{uuid.uuid4().hex}.txt"
    path = (upload_dir / filename).resolve()
    # 防止路径穿越：确保生成的文件在 upload_dir 内
    if not str(path).startswith(str(upload_dir.resolve())):
        raise ValueError("路径穿越检测失败")
    path.write_text(content, encoding="utf-8")
    return f"[长文本已转存] {filename}", True