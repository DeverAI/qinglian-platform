"""知识库公开查询 API。管理端 CRUD 位于 admin.py。"""
import datetime

from fastapi import APIRouter, Depends

from ..common import BizError, add_points, ok, page_args
from ..database import db
from ..security import csrf_check, get_threshold

router = APIRouter()


def _keywords(conn, entry_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT keyword, clause FROM knowledge_keywords WHERE entry_id=? ORDER BY keyword",
        (entry_id,),
    ).fetchall()
    return [{"keyword": r["keyword"], "clause": r["clause"]} for r in rows]


def _entry_out(row, conn=None) -> dict:
    keys = row.keys()
    data = {
        "id": row["id"],
        "category": row["category"],
        "title": row["title"],
        "content": row["content"],
        "source_url": row["source_url"] if "source_url" in keys else "",
        "is_official": bool(row["is_official"] if "is_official" in keys else 0),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    if conn is not None:
        data["keywords"] = _keywords(conn, row["id"])
    return data


@router.get("")
def list_knowledge(category: str = "", q: str = "", page: int = 1, limit: int = 20):
    page, limit, offset = page_args(page, limit)
    where = "1=1"
    params = []
    if category and category in ("law", "case", "guide", "qoder"):
        where += " AND category=?"
        params.append(category)
    if q:
        where += " AND (title LIKE ? OR content LIKE ?)"
        params.append(f"%{q}%")
        params.append(f"%{q}%")
    sql = f"SELECT id,category,title,content,source_url,is_official,created_at,updated_at FROM knowledge_entries WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    with db() as conn:
        rows = conn.execute(sql, (*params, limit, offset)).fetchall()
        total = conn.execute(f"SELECT COUNT(*) AS c FROM knowledge_entries WHERE {where}", params).fetchone()["c"]
        items = [
            {
                "id": r["id"],
                "category": r["category"],
                "title": r["title"],
                "summary": r["content"][:200],
                "source_url": r["source_url"],
                "is_official": bool(r["is_official"]),
                "keywords": _keywords(conn, r["id"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]
    return ok({"items": items, "total": total, "page": page, "limit": limit})


@router.get("/{entry_id}")
def get_knowledge(entry_id: int):
    with db() as conn:
        row = conn.execute(
            "SELECT id,category,title,content,source_url,is_official,created_at,updated_at FROM knowledge_entries WHERE id=?",
            (entry_id,),
        ).fetchone()
        if row is None:
            raise BizError(4040, "条目不存在")
        return ok(_entry_out(row, conn))


@router.get("/keywords/{keyword}")
def by_keyword(keyword: str):
    with db() as conn:
        rows = conn.execute(
            "SELECT k.id, k.category, k.title, k.source_url, kw.clause "
            "FROM knowledge_keywords kw JOIN knowledge_entries k ON kw.entry_id=k.id "
            "WHERE kw.keyword=? ORDER BY k.title",
            (keyword,),
        ).fetchall()
    return ok({
        "items": [
            {"id": r["id"], "category": r["category"], "title": r["title"], "source_url": r["source_url"], "clause": r["clause"]}
            for r in rows
        ]
    })


@router.post("/{entry_id}/share")
def share_knowledge(entry_id: int, user: dict = Depends(csrf_check)):
    """用户转发法律知识条文，+1 积分（每天对同一条目仅一次）。"""
    today = datetime.date.today().isoformat()
    with db() as conn:
        row = conn.execute("SELECT id FROM knowledge_entries WHERE id=?", (entry_id,)).fetchone()
        if row is None:
            raise BizError(4040, "条目不存在")
        already = conn.execute(
            "SELECT id FROM point_logs WHERE user_id=? AND ref_type='knowledge' AND ref_id=? AND reason LIKE ? AND created_at>=? AND created_at<?",
            (user["id"], entry_id, "转发法律知识条文%", f"{today} 00:00:00", f"{today} 23:59:59"),
        ).fetchone()
        if already:
            raise BizError(4001, "今日已转发过该条目")
        reward = get_threshold("threshold_reward_knowledge_share", 1)
        if reward > 0:
            add_points(conn, user["id"], reward, "转发法律知识条文", "knowledge", entry_id)
    return ok(None, "转发成功，积分 +1")


@router.get("/daily/today")
def daily_law():
    """每日一法：按日期轮转返回一部官方法律条目。"""
    today = datetime.date.today().isoformat()
    with db() as conn:
        pushed = conn.execute("SELECT entry_id FROM daily_law WHERE push_date=?", (today,)).fetchone()
        if pushed:
            row = conn.execute(
                "SELECT id,category,title,content,source_url,is_official,created_at,updated_at FROM knowledge_entries WHERE id=?",
                (pushed["entry_id"],),
            ).fetchone()
            if row is None:
                # 条目已被删除，清理当天记录并重新选择
                conn.execute("DELETE FROM daily_law WHERE push_date=?", (today,))
            else:
                return ok(_entry_out(row, conn))

        # 取官方法律类条目，按已推送次数最少、id 最小轮转
        row = conn.execute(
            "SELECT id,category,title,content,source_url,is_official,created_at,updated_at FROM knowledge_entries "
            "WHERE category='law' AND is_official=1 "
            "ORDER BY (SELECT COUNT(*) FROM daily_law WHERE daily_law.entry_id=knowledge_entries.id) ASC, id ASC LIMIT 1"
        ).fetchone()
        if row is None:
            raise BizError(4040, "暂无官方法律条目")
        # INSERT OR IGNORE 避免并发首次请求时触发唯一约束
        conn.execute(
            "INSERT OR IGNORE INTO daily_law (entry_id, push_date) VALUES (?,?)",
            (row["id"], today),
        )
        # 重新读取当天记录，若并发写入的是其他条目则使用该条目
        pushed = conn.execute("SELECT entry_id FROM daily_law WHERE push_date=?", (today,)).fetchone()
        if pushed:
            row = conn.execute(
                "SELECT id,category,title,content,source_url,is_official,created_at,updated_at FROM knowledge_entries WHERE id=?",
                (pushed["entry_id"],),
            ).fetchone()
        if row is None:
            raise BizError(4040, "暂无官方法律条目")
        return ok(_entry_out(row, conn))
