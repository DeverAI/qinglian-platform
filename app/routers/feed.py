"""首页消息流 API：聚合多源动态（我的动态 / 关注板块 / 新闻 / 综合）。

数据源：
- mine：当前用户的任务进度 + 自己发过/回复过的帖子更新
- subscriptions：board_subscriptions 关联的板块新帖
- news：news 表最近 7 天
- all：合并以上并按时间倒序

设计原则：轻量化，单次查询限制，未登录仅可看 all/news。
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query

from ..common import ok
from ..database import db
from ..security import get_optional_user

router = APIRouter()

FEED_LIMIT = 30

# 过期新闻清理的内存缓存：1 小时内不重复执行 UPDATE
import time as _time

_last_expire_ts: float = 0.0
_EXPIRE_INTERVAL = 3600  # 秒


def _fmt(ts: str | None) -> str:
    return ts or ""


def _task_item(r) -> dict:
    return {
        "source": "task",
        "id": r["id"],
        "title": f"{r['platform_name']} · {r['issue_type']}",
        "status": r["status"],
        "user_id": r["user_id"],
        "created_at": _fmt(r["created_at"]),
        "updated_at": _fmt(r["updated_at"]),
    }


def _post_item(r) -> dict:
    return {
        "source": "post",
        "id": r["id"],
        "title": r["title"],
        "category_id": r["category_id"],
        "user_id": r["user_id"],
        "nickname": r["nickname"] if "nickname" in r.keys() else "",
        "created_at": _fmt(r["created_at"]),
    }


def _news_item(r) -> dict:
    return {
        "source": "news",
        "id": r["id"],
        "title": r["title"],
        "abstract": r["abstract"],
        "source_name": r["source_name"],
        "source_url": r["source_url"],
        "published_at": _fmt(r["published_at"]),
        "collected_at": _fmt(r["collected_at"]),
    }


def _expire_news(conn) -> None:
    """将 7 天前的新闻置为 is_active=0（1 小时内仅执行一次，减少高频写操作）。"""
    global _last_expire_ts
    now = _time.time()
    if now - _last_expire_ts < _EXPIRE_INTERVAL:
        return
    _last_expire_ts = now
    cutoff = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("UPDATE news SET is_active=0 WHERE is_active=1 AND collected_at < ?", (cutoff,))


@router.get("")
def get_feed(
    tab: str = Query("all", pattern="^(all|mine|subscriptions|news)$"),
    limit: int = Query(20, ge=1, le=FEED_LIMIT),
    user: dict | None = Depends(get_optional_user),
):
    """首页消息流：按 Tab 聚合多源动态。"""
    items: list[dict] = []
    with db() as conn:
        _expire_news(conn)

        if tab in ("all", "news"):
            rows = conn.execute(
                "SELECT * FROM news WHERE is_active=1 ORDER BY collected_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            items.extend(_news_item(r) for r in rows)

        if user is not None and tab in ("all", "mine"):
            # 我的任务
            rows = conn.execute(
                "SELECT * FROM tasks WHERE user_id=? ORDER BY updated_at DESC LIMIT ?",
                (user["id"], limit),
            ).fetchall()
            items.extend(_task_item(r) for r in rows)
            # 我发过/回复过的帖子
            rows = conn.execute(
                "SELECT DISTINCT p.* FROM posts p "
                "LEFT JOIN replies r ON r.post_id = p.id "
                "WHERE p.user_id=? OR r.user_id=? "
                "ORDER BY p.created_at DESC LIMIT ?",
                (user["id"], user["id"], limit),
            ).fetchall()
            items.extend(_post_item(r) for r in rows)

        if user is not None and tab in ("all", "subscriptions"):
            # 关注板块的新帖
            rows = conn.execute(
                "SELECT p.*, u.nickname FROM posts p "
                "JOIN board_subscriptions bs ON bs.category_id = p.category_id AND bs.user_id=? "
                "LEFT JOIN users u ON u.id = p.user_id "
                "WHERE p.status='normal' "
                "ORDER BY p.created_at DESC LIMIT ?",
                (user["id"], limit),
            ).fetchall()
            items.extend(_post_item(r) for r in rows)

    # 统一按时间倒序（取各源 created_at/collected_at/updated_at 中最靠后的）
    def _key(it: dict) -> str:
        return it.get("updated_at") or it.get("created_at") or it.get("collected_at") or ""

    items.sort(key=_key, reverse=True)
    items = items[:limit]
    return ok({"items": items, "tab": tab})
