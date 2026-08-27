"""论坛 CRUD API：板块、帖子、回复、点赞/点踩、收藏、举报、标签。"""
import re
import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..common import BizError, add_points, ok, page_args
from ..config import UPLOAD_DIR
from ..content_guard import (
    add_daily_text_bytes,
    auto_long_text_to_txt,
    check_daily_text_bytes,
    check_duplicate,
    check_rate_limit,
    check_word_count,
)
from ..database import db
from ..handshake import require_handshake
from ..security import csrf_check, ensure_points_in_tx, get_current_user, get_optional_user, get_threshold, require_speak, SPEAK_BYPASS_ROLES

router = APIRouter()

TAG_RE = re.compile(r"#([^#\s,.;:!?<>\"'()]{2,30})")


class PostIn(BaseModel):
    category_id: int
    title: str = Field(min_length=2, max_length=120)
    content: str = Field(min_length=2, max_length=30000)
    tags: list[str] = Field(default_factory=list)


class ReplyIn(BaseModel):
    content: str = Field(min_length=1, max_length=20000)
    quote_reply_id: int | None = None


class LikeIn(BaseModel):
    value: Literal[1, -1]


class ReportIn(BaseModel):
    target_type: Literal["post", "reply", "task"]
    target_id: int
    reason: str = Field(min_length=1, max_length=2000)


def _ensure_tags(conn, names: list[str]) -> list[int]:
    ids = []
    for name in names:
        name = name.strip().lower()
        if not name or len(name) > 30:
            continue
        row = conn.execute("SELECT id FROM tags WHERE name = ?", (name,)).fetchone()
        if row:
            ids.append(row["id"])
        else:
            cur = conn.execute("INSERT INTO tags (name) VALUES (?)", (name,))
            ids.append(cur.lastrowid)
    return ids


def _set_post_tags(conn, post_id: int, tag_ids: list[int]) -> None:
    conn.execute("DELETE FROM post_tags WHERE post_id = ?", (post_id,))
    for tid in tag_ids:
        conn.execute(
            "INSERT OR IGNORE INTO post_tags (post_id, tag_id) VALUES (?,?)",
            (post_id, tid),
        )


def _public_user(row) -> dict:
    return {"id": row["id"], "nickname": row["nickname"], "role": row["role"]}


def _post_out(conn, row, current_user_id: int | None = None) -> dict:
    author = conn.execute("SELECT id,nickname,role FROM users WHERE id=?", (row["user_id"],)).fetchone()
    tags = conn.execute(
        "SELECT t.name FROM tags t JOIN post_tags pt ON pt.tag_id=t.id WHERE pt.post_id=? ORDER BY t.name",
        (row["id"],),
    ).fetchall()
    liked = None
    favorited = False
    if current_user_id:
        l = conn.execute(
            "SELECT value FROM likes WHERE user_id=? AND target_type='post' AND target_id=?",
            (current_user_id, row["id"]),
        ).fetchone()
        liked = l["value"] if l else None
        f = conn.execute(
            "SELECT id FROM favorites WHERE user_id=? AND post_id=?", (current_user_id, row["id"])
        ).fetchone()
        favorited = f is not None
    return {
        "id": row["id"],
        "category_id": row["category_id"],
        "user": _public_user(author),
        "title": row["title"],
        "content": row["content"],
        "is_essence": row["is_essence"],
        "status": row["status"],
        "views": row["views"],
        "likes": row["likes"],
        "dislikes": row["dislikes"],
        "my_like": liked,
        "is_favorite": favorited,
        "tags": [t["name"] for t in tags],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _reply_out(conn, row, current_user_id: int | None = None) -> dict:
    author = conn.execute("SELECT id,nickname,role FROM users WHERE id=?", (row["user_id"],)).fetchone()
    liked = None
    if current_user_id:
        l = conn.execute(
            "SELECT value FROM likes WHERE user_id=? AND target_type='reply' AND target_id=?",
            (current_user_id, row["id"]),
        ).fetchone()
        liked = l["value"] if l else None
    quote = None
    if row["quote_reply_id"]:
        q = conn.execute("SELECT id,content,user_id FROM replies WHERE id=?", (row["quote_reply_id"],)).fetchone()
        if q:
            qu = conn.execute("SELECT id,nickname,role FROM users WHERE id=?", (q["user_id"],)).fetchone()
            quote = {"id": q["id"], "content": q["content"][:200], "user": _public_user(qu)}
    return {
        "id": row["id"],
        "post_id": row["post_id"],
        "user": _public_user(author),
        "content": row["content"],
        "quote": quote,
        "status": row["status"],
        "likes": row["likes"],
        "dislikes": row["dislikes"],
        "my_like": liked,
        "created_at": row["created_at"],
    }


@router.get("/categories")
def list_categories():
    with db() as conn:
        rows = conn.execute("SELECT * FROM categories ORDER BY id").fetchall()
    # 手动分离根节点与子节点
    roots = [r for r in rows if r["parent_id"] is None]
    children = {}
    for r in rows:
        if r["parent_id"] is not None:
            children.setdefault(r["parent_id"], []).append(r)

    def build(row):
        return {
            "id": row["id"],
            "name": row["name"],
            "platform_name": row["platform_name"],
            "issue_type": row["issue_type"],
            "children": [build(c) for c in children.get(row["id"], [])],
        }

    return ok([build(r) for r in roots])


@router.get("/categories/{category_id}")
def category_detail(category_id: int, page: int = 1, limit: int = 20):
    page, limit, offset = page_args(page, limit)
    with db() as conn:
        cat = conn.execute("SELECT * FROM categories WHERE id=?", (category_id,)).fetchone()
        if cat is None:
            raise BizError(4040, "板块不存在")
        rows = conn.execute(
            "SELECT * FROM posts WHERE category_id=? AND status='normal' ORDER BY is_essence DESC, created_at DESC LIMIT ? OFFSET ?",
            (category_id, limit, offset),
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) AS c FROM posts WHERE category_id=? AND status='normal'", (category_id,)
        ).fetchone()["c"]
        items = [_post_out(conn, r) for r in rows]
        result = {"category": {"id": cat["id"], "name": cat["name"]}, "items": items, "total": total, "page": page, "limit": limit}
    return ok(result)


@router.post("/categories/{category_id}/subscribe")
def subscribe_category(category_id: int, user: dict = Depends(csrf_check)):
    """关注板块：关注后该板块新帖会进入首页消息流。"""
    with db() as conn:
        cat = conn.execute("SELECT id FROM categories WHERE id=?", (category_id,)).fetchone()
        if cat is None:
            raise BizError(4040, "板块不存在")
        conn.execute(
            "INSERT OR IGNORE INTO board_subscriptions (user_id, category_id) VALUES (?,?)",
            (user["id"], category_id),
        )
    return ok(None, "已关注")


@router.delete("/categories/{category_id}/subscribe")
def unsubscribe_category(category_id: int, user: dict = Depends(csrf_check)):
    """取消关注板块。"""
    with db() as conn:
        conn.execute(
            "DELETE FROM board_subscriptions WHERE user_id=? AND category_id=?",
            (user["id"], category_id),
        )
    return ok(None, "已取消关注")


@router.get("/my/subscriptions")
def my_subscriptions(user: dict = Depends(get_optional_user)):
    """我关注的板块列表（用于首页"关注板块" Tab 状态展示）。"""
    if user is None:
        return ok({"items": []})
    with db() as conn:
        rows = conn.execute(
            "SELECT c.id, c.name FROM board_subscriptions bs "
            "JOIN categories c ON c.id = bs.category_id "
            "WHERE bs.user_id=? ORDER BY bs.created_at DESC",
            (user["id"],),
        ).fetchall()
    return ok({"items": [{"id": r["id"], "name": r["name"]} for r in rows]})


@router.post("/posts")
def create_post(body: PostIn, user: dict = Depends(require_speak()), _: dict = Depends(require_handshake)):
    title = body.title.strip()
    content = body.content.strip()
    if len(title) < 2:
        raise BizError(4001, "标题不能为空")
    if len(content) < 2:
        raise BizError(4001, "内容不能为空")

    # 反刷治理：字数门槛 + 频率限制
    min_words = get_threshold("threshold_min_word_count", 2)
    check_word_count(content, min_words)
    check_rate_limit(user["id"], "create_post")

    # 长文本自动转 txt
    text_content, is_file = auto_long_text_to_txt(content, UPLOAD_DIR)

    with db() as conn:
        cat = conn.execute("SELECT id, parent_id, status FROM categories WHERE id=?", (body.category_id,)).fetchone()
        if cat is None:
            raise BizError(4040, "板块不存在")
        if cat["parent_id"] is None:
            raise BizError(4001, "不能直接向根分类发帖")
        if cat["status"] != "open":
            raise BizError(4030, "该板块当前已关闭或封存，无法发帖")
        # 事务内原子校验发言积分（版主/管理员/root 豁免），防止并发 TOCTOU 绕过门槛
        if user["role"] not in SPEAK_BYPASS_ROLES:
            threshold = get_threshold("threshold_points_speak", 4)
            if not ensure_points_in_tx(conn, user["id"], threshold):
                raise BizError(4031, f"积分不足，需要至少 {threshold} 积分才能发言")

        # 查重：24小时内同一用户相似内容
        dup_id = check_duplicate(conn, user["id"], content, "posts")
        if dup_id is not None:
            raise BizError(4003, "检测到相似内容已存在，请勿重复发帖")

        # 每日文字总量上限
        max_text = get_threshold("threshold_daily_text_bytes", 10240)
        check_daily_text_bytes(conn, user["id"], len(content), max_text)

        cur = conn.execute(
            "INSERT INTO posts (category_id, user_id, title, content, word_count) VALUES (?,?,?,?,?)",
            (body.category_id, user["id"], title, text_content if is_file else content, len(content)),
        )
        post_id = cur.lastrowid

        # 累加每日文字量
        add_daily_text_bytes(conn, user["id"], len(content))

        # 合并传入标签与内容中 #tag
        tag_names = {t.strip().lower()[:30] for t in body.tags if t.strip()}
        for m in TAG_RE.finditer(body.content):
            tag_names.add(m.group(1).lower()[:30])
        tag_ids = _ensure_tags(conn, list(tag_names))
        _set_post_tags(conn, post_id, tag_ids)
        post = conn.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
        result = _post_out(conn, post, user["id"])
    return ok(result, "发帖成功")


@router.get("/posts")
def list_posts(
    category_id: int = 0,
    tag: str = "",
    essence: bool = False,
    page: int = 1,
    limit: int = 20,
    user: dict | None = Depends(get_optional_user),
):
    page, limit, offset = page_args(page, limit)
    where = "p.status='normal'"
    params = []
    if category_id:
        where += " AND p.category_id=?"
        params.append(category_id)
    if tag:
        where += " AND p.id IN (SELECT post_id FROM post_tags pt JOIN tags t ON pt.tag_id=t.id WHERE t.name=?)"
        params.append(tag.strip().lower())
    if essence:
        where += " AND p.is_essence=1"
    sql = (
        f"SELECT p.* FROM posts p WHERE {where} ORDER BY p.is_essence DESC, p.created_at DESC LIMIT ? OFFSET ?"
    )
    with db() as conn:
        rows = conn.execute(sql, (*params, limit, offset)).fetchall()
        total = conn.execute(f"SELECT COUNT(*) AS c FROM posts p WHERE {where}", params).fetchone()["c"]
        items = [_post_out(conn, r, user["id"] if user else None) for r in rows]
        result = {"items": items, "total": total, "page": page, "limit": limit}
    return ok(result)


@router.get("/posts/{post_id}")
def get_post(post_id: int, user: dict | None = Depends(get_optional_user)):
    with db() as conn:
        post = conn.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
        if post is None or post["status"] != "normal":
            raise BizError(4040, "帖子不存在")
        conn.execute("UPDATE posts SET views = views + 1 WHERE id=?", (post_id,))
        post = conn.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
        replies = conn.execute(
            "SELECT * FROM replies WHERE post_id=? AND status='normal' ORDER BY created_at ASC",
            (post_id,),
        ).fetchall()
        reply_list = [_reply_out(conn, r, user["id"] if user else None) for r in replies]
        data = _post_out(conn, post, user["id"] if user else None)
        data["replies"] = reply_list
    return ok(data)


@router.post("/posts/{post_id}/replies")
def create_reply(post_id: int, body: ReplyIn, user: dict = Depends(require_speak()), _: dict = Depends(require_handshake)):
    content = body.content.strip()
    if not content:
        raise BizError(4001, "回复内容不能为空")

    # 反刷治理：字数门槛 + 频率限制
    min_words = get_threshold("threshold_min_word_count", 2)
    check_word_count(content, min_words)
    check_rate_limit(user["id"], "create_reply")

    with db() as conn:
        post = conn.execute("SELECT id, category_id FROM posts WHERE id=? AND status='normal'", (post_id,)).fetchone()
        if post is None:
            raise BizError(4040, "帖子不存在")
        cat = conn.execute("SELECT status FROM categories WHERE id=?", (post["category_id"],)).fetchone()
        if cat is None or cat["status"] != "open":
            raise BizError(4030, "该板块当前已关闭或封存，无法回复")
        # 事务内原子校验发言积分（版主/管理员/root 豁免）
        if user["role"] not in SPEAK_BYPASS_ROLES:
            threshold = get_threshold("threshold_points_speak", 4)
            if not ensure_points_in_tx(conn, user["id"], threshold):
                raise BizError(4031, f"积分不足，需要至少 {threshold} 积分才能发言")

        # 查重：24小时内同一用户相似回复
        dup_id = check_duplicate(conn, user["id"], content, "replies")
        if dup_id is not None:
            raise BizError(4003, "检测到相似回复已存在，请勿重复回复")

        # 每日文字总量上限
        max_text = get_threshold("threshold_daily_text_bytes", 10240)
        check_daily_text_bytes(conn, user["id"], len(content), max_text)

        if body.quote_reply_id:
            q = conn.execute("SELECT id FROM replies WHERE id=? AND post_id=?", (body.quote_reply_id, post_id)).fetchone()
            if q is None:
                raise BizError(4040, "引用的回复不存在")
        cur = conn.execute(
            "INSERT INTO replies (post_id, user_id, content, quote_reply_id, word_count) VALUES (?,?,?,?,?)",
            (post_id, user["id"], content, body.quote_reply_id, len(content)),
        )

        # 累加每日文字量
        add_daily_text_bytes(conn, user["id"], len(content))

        reply = conn.execute("SELECT * FROM replies WHERE id=?", (cur.lastrowid,)).fetchone()
        result = _reply_out(conn, reply, user["id"])
    return ok(result, "回复成功")


@router.post("/posts/{post_id}/like")
def like_post(post_id: int, body: LikeIn, user: dict = Depends(csrf_check)):
    try:
        with db() as conn:
            post = conn.execute("SELECT id,user_id,likes,dislikes FROM posts WHERE id=? AND status='normal'", (post_id,)).fetchone()
            if post is None:
                raise BizError(4040, "帖子不存在")
            if post["user_id"] == user["id"]:
                raise BizError(4001, "不能给自己的帖子点赞或点踩")
            existing = conn.execute(
                "SELECT id,value FROM likes WHERE user_id=? AND target_type='post' AND target_id=?",
                (user["id"], post_id),
            ).fetchone()
            if existing:
                if existing["value"] == body.value:
                    raise BizError(4002, "已表达过相同态度")
                conn.execute("UPDATE likes SET value=?, created_at=datetime('now','localtime') WHERE id=?", (body.value, existing["id"]))
                if body.value == 1:
                    conn.execute("UPDATE posts SET likes=likes+1, dislikes=dislikes-1 WHERE id=?", (post_id,))
                else:
                    conn.execute("UPDATE posts SET likes=likes-1, dislikes=dislikes+1 WHERE id=?", (post_id,))
            else:
                conn.execute(
                    "INSERT INTO likes (user_id, target_type, target_id, value) VALUES (?,?,?,?)",
                    (user["id"], "post", post_id, body.value),
                )
                if body.value == 1:
                    conn.execute("UPDATE posts SET likes=likes+1 WHERE id=?", (post_id,))
                else:
                    conn.execute("UPDATE posts SET dislikes=dislikes+1 WHERE id=?", (post_id,))
        return ok(None, "操作成功")
    except sqlite3.IntegrityError:
        return ok(None, "操作已处理，请勿重复提交")


@router.post("/replies/{reply_id}/like")
def like_reply(reply_id: int, body: LikeIn, user: dict = Depends(csrf_check)):
    try:
        with db() as conn:
            reply = conn.execute("SELECT id,user_id,post_id,likes,dislikes FROM replies WHERE id=? AND status='normal'", (reply_id,)).fetchone()
            if reply is None:
                raise BizError(4040, "回复不存在")
            if reply["user_id"] == user["id"]:
                raise BizError(4001, "不能给自己的回复点赞或点踩")
            existing = conn.execute(
                "SELECT id,value FROM likes WHERE user_id=? AND target_type='reply' AND target_id=?",
                (user["id"], reply_id),
            ).fetchone()
            # 回复点赞达 10 次且未奖励过时，给回复作者 +1 积分
            def maybe_award_reply_likes():
                if body.value != 1:
                    return
                count = conn.execute("SELECT likes FROM replies WHERE id=?", (reply_id,)).fetchone()["likes"]
                if count >= 10:
                    already = conn.execute(
                        "SELECT id FROM point_logs WHERE user_id=? AND ref_type='reply' AND ref_id=? AND reason LIKE '回复获赞%'",
                        (reply["user_id"], reply_id),
                    ).fetchone()
                    if not already:
                        reward = get_threshold("threshold_reward_reply_ten_likes", 1)
                        if reward > 0:
                            add_points(conn, reply["user_id"], reward, "回复获赞达到 10 次", "reply", reply_id)

            if existing:
                if existing["value"] == body.value:
                    raise BizError(4002, "已表达过相同态度")
                conn.execute("UPDATE likes SET value=?, created_at=datetime('now','localtime') WHERE id=?", (body.value, existing["id"]))
                if body.value == 1:
                    conn.execute("UPDATE replies SET likes=likes+1, dislikes=dislikes-1 WHERE id=?", (reply_id,))
                else:
                    conn.execute("UPDATE replies SET likes=likes-1, dislikes=dislikes+1 WHERE id=?", (reply_id,))
            else:
                conn.execute(
                    "INSERT INTO likes (user_id, target_type, target_id, value) VALUES (?,?,?,?)",
                    (user["id"], "reply", reply_id, body.value),
                )
                if body.value == 1:
                    conn.execute("UPDATE replies SET likes=likes+1 WHERE id=?", (reply_id,))
                else:
                    conn.execute("UPDATE replies SET dislikes=dislikes+1 WHERE id=?", (reply_id,))
            maybe_award_reply_likes()
        return ok(None, "操作成功")
    except sqlite3.IntegrityError:
        return ok(None, "操作已处理，请勿重复提交")


@router.post("/posts/{post_id}/favorite")
def favorite_post(post_id: int, user: dict = Depends(csrf_check)):
    with db() as conn:
        post = conn.execute("SELECT id FROM posts WHERE id=? AND status='normal'", (post_id,)).fetchone()
        if post is None:
            raise BizError(4040, "帖子不存在")
        existing = conn.execute(
            "SELECT id FROM favorites WHERE user_id=? AND post_id=?", (user["id"], post_id)
        ).fetchone()
        if existing:
            conn.execute("DELETE FROM favorites WHERE id=?", (existing["id"],))
            return ok(False, "已取消收藏")
        try:
            conn.execute("INSERT INTO favorites (user_id, post_id) VALUES (?,?)", (user["id"], post_id))
        except sqlite3.IntegrityError:
            raise BizError(4009, "已收藏，请勿重复操作")
    return ok(True, "收藏成功")


@router.get("/tags")
def list_tags():
    with db() as conn:
        rows = conn.execute(
            "SELECT t.name, COUNT(pt.post_id) AS post_count FROM tags t LEFT JOIN post_tags pt ON t.id=pt.tag_id "
            "GROUP BY t.id ORDER BY post_count DESC, t.name LIMIT 100"
        ).fetchall()
    return ok([{"name": r["name"], "post_count": r["post_count"]} for r in rows])


@router.get("/tags/{tag_name}/posts")
def posts_by_tag(tag_name: str, page: int = 1, limit: int = 20, user: dict | None = Depends(get_optional_user)):
    page, limit, offset = page_args(page, limit)
    tag = tag_name.strip().lower()
    with db() as conn:
        rows = conn.execute(
            "SELECT p.* FROM posts p JOIN post_tags pt ON p.id=pt.post_id JOIN tags t ON pt.tag_id=t.id "
            "WHERE t.name=? AND p.status='normal' ORDER BY p.created_at DESC LIMIT ? OFFSET ?",
            (tag, limit, offset),
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) AS c FROM posts p JOIN post_tags pt ON p.id=pt.post_id JOIN tags t ON pt.tag_id=t.id "
            "WHERE t.name=? AND p.status='normal'",
            (tag,),
        ).fetchone()["c"]
        items = [_post_out(conn, r, user["id"] if user else None) for r in rows]
        result = {"items": items, "total": total, "page": page, "limit": limit}
    return ok(result)


@router.post("/reports")
def create_report(body: ReportIn, user: dict = Depends(csrf_check)):
    with db() as conn:
        # 简单校验目标存在
        if body.target_type == "post":
            target = conn.execute("SELECT id FROM posts WHERE id=?", (body.target_id,)).fetchone()
        elif body.target_type == "reply":
            target = conn.execute("SELECT id FROM replies WHERE id=?", (body.target_id,)).fetchone()
        else:
            target = conn.execute("SELECT id FROM tasks WHERE id=?", (body.target_id,)).fetchone()
        if target is None:
            raise BizError(4040, "举报目标不存在")
        # 防重复提交
        dup = conn.execute(
            "SELECT id FROM reports WHERE reporter_id=? AND target_type=? AND target_id=? AND status='pending'",
            (user["id"], body.target_type, body.target_id),
        ).fetchone()
        if dup:
            raise BizError(4003, "您已提交过对此目标的待处理举报")
        cur = conn.execute(
            "INSERT INTO reports (reporter_id, target_type, target_id, reason) VALUES (?,?,?,?)",
            (user["id"], body.target_type, body.target_id, body.reason.strip()),
        )
    return ok({"id": cur.lastrowid}, "举报已提交，等待处理")


# ---------- T2.3: 板块认领（board_claims） ----------

class BoardClaimIn(BaseModel):
    category_id: int


class BoardClaimDraftIn(BaseModel):
    draft_body: str = Field(default="", max_length=50000)
    shared_notes: str = Field(default="", max_length=2000)


@router.post("/board-claims")
def claim_board(body: BoardClaimIn, user: dict = Depends(csrf_check)):
    """认领已封存板块，准备代发邮件。"""
    with db() as conn:
        # BEGIN IMMEDIATE 获取写锁，防止并发抢领
        conn.execute("BEGIN IMMEDIATE")
        cat = conn.execute(
            "SELECT id, status, claim_user_id FROM categories WHERE id=?", (body.category_id,)
        ).fetchone()
        if cat is None:
            raise BizError(4040, "板块不存在")
        if cat["status"] != "closed":
            raise BizError(4001, "仅已封存的板块可认领")
        if cat["claim_user_id"] is not None:
            raise BizError(4002, "该板块已被他人认领")

        # 校验积分门槛
        threshold = get_threshold("threshold_points_moderate_board", 30)
        if (user.get("points") or 0) < threshold:
            raise BizError(4031, f"积分不足，需要至少 {threshold} 积分才能认领板块")

        # 检查同一用户同时认领数
        active = conn.execute(
            "SELECT COUNT(*) AS c FROM board_claims WHERE user_id=? AND status IN ('claimed','draft')",
            (user["id"],),
        ).fetchone()["c"]
        if active >= 2:
            raise BizError(4003, "同时最多认领 2 个板块")

        # 同一板块只能认领一次
        existing = conn.execute(
            "SELECT id FROM board_claims WHERE category_id=? AND user_id=?",
            (body.category_id, user["id"]),
        ).fetchone()
        if existing:
            raise BizError(4002, "您已认领过该板块")

        deadline_hours = get_threshold("threshold_claim_deadline_hours", 24)
        cur = conn.execute(
            "INSERT INTO board_claims (category_id, user_id, deadline, status) VALUES (?,?,datetime('now','localtime','+? hours'),'claimed')",
            (body.category_id, user["id"], deadline_hours),
        )
        conn.execute(
            "UPDATE categories SET claim_user_id=?, claim_deadline=datetime('now','localtime','+? hours'), "
            "updated_at=datetime('now','localtime') WHERE id=?",
            (user["id"], deadline_hours, body.category_id),
        )
        claim = conn.execute("SELECT * FROM board_claims WHERE id=?", (cur.lastrowid,)).fetchone()
    return ok({
        "id": claim["id"],
        "category_id": claim["category_id"],
        "status": claim["status"],
        "deadline": claim["deadline"],
    }, "认领成功，请在截止时间前产出邮件草稿")


@router.get("/board-claims/my")
def my_claims(user: dict = Depends(get_current_user)):
    """我认领的板块列表。"""
    with db() as conn:
        rows = conn.execute(
            "SELECT bc.*, c.name AS category_name FROM board_claims bc "
            "JOIN categories c ON c.id=bc.category_id WHERE bc.user_id=? ORDER BY bc.created_at DESC",
            (user["id"],),
        ).fetchall()
    return ok({
        "items": [
            {
                "id": r["id"],
                "category_id": r["category_id"],
                "category_name": r["category_name"],
                "draft_body": r["draft_body"],
                "shared_notes": r["shared_notes"],
                "status": r["status"],
                "deadline": r["deadline"],
                "last_activity_at": r["last_activity_at"],
                "claimed_at": r["claimed_at"],
            }
            for r in rows
        ]
    })


@router.put("/board-claims/{claim_id}")
def update_claim_draft(claim_id: int, body: BoardClaimDraftIn, user: dict = Depends(csrf_check)):
    """更新认领板块的草稿内容。"""
    with db() as conn:
        claim = conn.execute(
            "SELECT * FROM board_claims WHERE id=? AND user_id=?", (claim_id, user["id"])
        ).fetchone()
        if claim is None:
            raise BizError(4040, "认领记录不存在")
        if claim["status"] not in ("claimed", "draft"):
            raise BizError(4002, f"当前状态（{claim['status']}）不可编辑草稿")
        new_status = "draft" if body.draft_body else "claimed"
        conn.execute(
            "UPDATE board_claims SET draft_body=?, shared_notes=?, status=?, "
            "last_activity_at=datetime('now','localtime') WHERE id=?",
            (body.draft_body, body.shared_notes, new_status, claim_id),
        )
    return ok(None, "草稿已更新")


@router.post("/board-claims/{claim_id}/submit")
def submit_claim(claim_id: int, user: dict = Depends(csrf_check)):
    """提交认领板块的邮件草稿供审核。"""
    with db() as conn:
        claim = conn.execute(
            "SELECT * FROM board_claims WHERE id=? AND user_id=?", (claim_id, user["id"])
        ).fetchone()
        if claim is None:
            raise BizError(4040, "认领记录不存在")
        if claim["status"] not in ("claimed", "draft"):
            raise BizError(4002, f"当前状态（{claim['status']}）不可提交")
        if not claim["draft_body"]:
            raise BizError(4001, "请先填写邮件草稿再提交")
        conn.execute(
            "UPDATE board_claims SET status='submitted', last_activity_at=datetime('now','localtime') WHERE id=?",
            (claim_id,),
        )
    # 提交后加激励积分（只要通过初审阶段即加）
    with db() as conn:
        already = conn.execute(
            "SELECT id FROM point_logs WHERE user_id=? AND ref_type='board_claim' AND ref_id=?",
            (user["id"], claim_id),
        ).fetchone()
        if not already:
            from ..common import add_points
            reward = get_threshold("threshold_reward_board_claim", 2)
            if reward > 0:
                add_points(conn, user["id"], reward, "板块认领邮件提交", "board_claim", claim_id)
    return ok(None, "已提交，等待审核")


@router.post("/board-claims/{claim_id}/abandon")
def abandon_claim(claim_id: int, user: dict = Depends(csrf_check)):
    """放弃认领。"""
    with db() as conn:
        claim = conn.execute(
            "SELECT * FROM board_claims WHERE id=? AND user_id=?", (claim_id, user["id"])
        ).fetchone()
        if claim is None:
            raise BizError(4040, "认领记录不存在")
        if claim["status"] == "abandoned":
            raise BizError(4002, "已放弃，请勿重复操作")
        conn.execute(
            "UPDATE board_claims SET status='abandoned', last_activity_at=datetime('now','localtime') WHERE id=?",
            (claim_id,),
        )
        conn.execute(
            "UPDATE categories SET claim_user_id=NULL, claim_deadline=NULL, updated_at=datetime('now','localtime') WHERE id=?",
            (claim["category_id"],),
        )
        # 扣分（认领后未完成）
        from ..common import spend_points
        cost = get_threshold("threshold_cost_board_claim_abandon", 2)
        if cost > 0:
            spend_points(conn, user["id"], cost, "放弃板块认领扣除", "board_claim", claim_id, min_balance=0)
    return ok(None, "已放弃认领")
