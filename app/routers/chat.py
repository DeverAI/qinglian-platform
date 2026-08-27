"""私信与群聊 API。

内容免责声明：私信/群聊内容由用户自行产生，平台仅提供传输与临时存储，不审核、不担保真实性，
用户应遵守法律法规与社区规范，禁止传播违法、侵权或侵害未成年人权益的内容。
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..common import BizError, ok, page_args, spend_points
from ..database import db
from ..handshake import require_handshake
from ..security import csrf_check, ensure_points_in_tx, get_current_user, get_threshold, require_speak, require_threshold, SPEAK_BYPASS_ROLES

router = APIRouter()

MAX_GROUP_MEMBERS = 200


class PmIn(BaseModel):
    receiver_id: int
    content: str = Field(min_length=1, max_length=5000)


class GroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    member_ids: list[int] = Field(default_factory=list, max_length=MAX_GROUP_MEMBERS)


class GroupMsgIn(BaseModel):
    content: str = Field(min_length=1, max_length=5000)


def _check_content(content: str) -> str:
    """校验并返回清理后的内容，防止全空白消息绕过 Pydantic min_length。"""
    text = content.strip()
    if not text:
        raise BizError(4001, "内容不能为空")
    return text


@router.post("/pm")
def send_pm(
    body: PmIn,
    user: dict = Depends(require_speak()),
    _: dict = Depends(require_handshake),
):
    """发送私信。"""
    if body.receiver_id == user["id"]:
        raise BizError(4001, "不能给自己发私信")
    content = _check_content(body.content)
    with db() as conn:
        # 版主/管理员/root 不受 0-3 分禁言限制
        if user["role"] not in SPEAK_BYPASS_ROLES:
            threshold = get_threshold("threshold_points_speak", 4)
            if not ensure_points_in_tx(conn, user["id"], threshold):
                raise BizError(4031, f"积分不足，需要至少 {threshold} 积分")
        receiver = conn.execute("SELECT id FROM users WHERE id=?", (body.receiver_id,)).fetchone()
        if receiver is None:
            raise BizError(4040, "收件人不存在")
        cur = conn.execute(
            "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?,?,?)",
            (user["id"], body.receiver_id, content),
        )
        msg_id = cur.lastrowid
        # 维护会话时间
        a, b = sorted([user["id"], body.receiver_id])
        conn.execute(
            "INSERT INTO conversations (user_a, user_b, last_message_at) VALUES (?,?,datetime('now','localtime')) "
            "ON CONFLICT(user_a, user_b) DO UPDATE SET last_message_at=excluded.last_message_at",
            (a, b),
        )
        msg = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    return ok({
        "id": msg["id"],
        "sender_id": msg["sender_id"],
        "receiver_id": msg["receiver_id"],
        "content": msg["content"],
        "is_read": bool(msg["is_read"]),
        "created_at": msg["created_at"],
    }, "发送成功")


@router.get("/pm/conversations")
def list_conversations(user: dict = Depends(get_current_user)):
    """我的私信会话列表。"""
    with db() as conn:
        rows = conn.execute(
            "SELECT c.*, ua.nickname AS nickname_a, ub.nickname AS nickname_b "
            "FROM conversations c "
            "JOIN users ua ON c.user_a=ua.id JOIN users ub ON c.user_b=ub.id "
            "WHERE c.user_a=? OR c.user_b=? ORDER BY c.last_message_at DESC",
            (user["id"], user["id"]),
        ).fetchall()
        # 未读数
        unread = {}
        for r in conn.execute(
            "SELECT sender_id, COUNT(*) AS c FROM messages WHERE receiver_id=? AND is_read=0 GROUP BY sender_id",
            (user["id"],),
        ).fetchall():
            unread[r["sender_id"]] = r["c"]
    items = []
    for r in rows:
        partner_id = r["user_b"] if r["user_a"] == user["id"] else r["user_a"]
        partner_nick = r["nickname_b"] if r["user_a"] == user["id"] else r["nickname_a"]
        items.append({
            "partner_id": partner_id,
            "partner_nickname": partner_nick,
            "last_message_at": r["last_message_at"],
            "unread_count": unread.get(partner_id, 0),
        })
    return ok({"items": items})


@router.get("/pm/{partner_id}")
def list_pm(partner_id: int, page: int = 1, limit: int = 20, user: dict = Depends(get_current_user)):
    """与某用户的私信记录。"""
    page, limit, offset = page_args(page, limit)
    with db() as conn:
        # 先标记对方发来的消息为已读，再查询，确保返回状态一致
        conn.execute(
            "UPDATE messages SET is_read=1 WHERE sender_id=? AND receiver_id=? AND is_read=0",
            (partner_id, user["id"]),
        )
        rows = conn.execute(
            "SELECT * FROM messages WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (user["id"], partner_id, partner_id, user["id"], limit, offset),
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) AS c FROM messages WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)",
            (user["id"], partner_id, partner_id, user["id"]),
        ).fetchone()["c"]
    return ok({
        "items": [
            {
                "id": r["id"],
                "sender_id": r["sender_id"],
                "receiver_id": r["receiver_id"],
                "content": r["content"],
                "is_read": bool(r["is_read"]),
                "created_at": r["created_at"],
            }
            for r in reversed(rows)
        ],
        "total": total, "page": page, "limit": limit,
    })


@router.post("/groups")
def create_group(
    body: GroupIn,
    user: dict = Depends(require_threshold("threshold_points_create_group", 200, mutating=True)),
    _: dict = Depends(require_handshake),
):
    """创建群聊并添加成员（自动包含创建者）；建群一次性扣除 200 积分。"""
    name = body.name.strip()
    if not name:
        raise BizError(4001, "群聊名称不能为空")
    member_ids = set(body.member_ids) | {user["id"]}
    if len(member_ids) < 2:
        raise BizError(4001, "群聊至少需要 2 名成员")
    if len(member_ids) > MAX_GROUP_MEMBERS:
        raise BizError(4001, f"群聊成员最多 {MAX_GROUP_MEMBERS} 人")

    cost = get_threshold("threshold_points_create_group", 200)
    with db() as conn:
        # 原子扣减积分
        new_points = spend_points(conn, user["id"], cost, "创建群聊", "group", min_balance=cost)
        if new_points is None:
            raise BizError(4031, f"积分不足，需要至少 {cost} 积分")

        # 校验成员存在
        existing = {
            r["id"] for r in conn.execute(
                f"SELECT id FROM users WHERE id IN ({','.join('?' * len(member_ids))})", tuple(member_ids)
            ).fetchall()
        }
        if existing != member_ids:
            raise BizError(4040, "部分成员不存在")
        cur = conn.execute(
            "INSERT INTO groups (name, created_by, owner_id) VALUES (?,?,?)",
            (name, user["id"], user["id"]),
        )
        group_id = cur.lastrowid
        for uid in member_ids:
            role = "admin" if uid == user["id"] else "member"
            conn.execute(
                "INSERT INTO group_members (group_id, user_id, role, status) VALUES (?,?,?,'active')",
                (group_id, uid, role),
            )
    return ok({"id": group_id, "name": name}, "群聊创建成功")


@router.get("/groups")
def my_groups(user: dict = Depends(get_current_user)):
    """我加入的群聊列表（已解散群不显示）。"""
    with db() as conn:
        rows = conn.execute(
            "SELECT g.*, gm.role AS my_role FROM groups g "
            "JOIN group_members gm ON g.id=gm.group_id "
            "WHERE gm.user_id=? AND gm.status='active' AND g.status!='dissolved' "
            "ORDER BY g.created_at DESC",
            (user["id"],),
        ).fetchall()
    return ok({
        "items": [
            {
                "id": r["id"],
                "name": r["name"],
                "owner_id": r["owner_id"],
                "created_by": r["created_by"],
                "status": r["status"],
                "join_type": r["join_type"],
                "my_role": r["my_role"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]
    })


@router.post("/groups/{group_id}/messages")
def send_group_msg(
    group_id: int,
    body: GroupMsgIn,
    user: dict = Depends(require_speak()),
    _: dict = Depends(require_handshake),
):
    """在群聊中发送消息。"""
    content = _check_content(body.content)
    with db() as conn:
        # 版主/管理员/root 不受 0-3 分禁言限制
        if user["role"] not in SPEAK_BYPASS_ROLES:
            threshold = get_threshold("threshold_points_speak", 4)
            if not ensure_points_in_tx(conn, user["id"], threshold):
                raise BizError(4031, f"积分不足，需要至少 {threshold} 积分")
        group = conn.execute("SELECT status, owner_id FROM groups WHERE id=?", (group_id,)).fetchone()
        if group is None:
            raise BizError(4040, "群聊不存在")
        if group["status"] == "dissolved":
            raise BizError(4030, "该群聊已解散")

        member = conn.execute(
            "SELECT role FROM group_members WHERE group_id=? AND user_id=? AND status='active'",
            (group_id, user["id"]),
        ).fetchone()
        if member is None:
            raise BizError(4030, "你不是该群成员")
        if group["status"] == "readonly" and member["role"] != "admin" and group["owner_id"] != user["id"]:
            raise BizError(4030, "群聊当前仅管理员可发言")

        cur = conn.execute(
            "INSERT INTO group_messages (group_id, sender_id, content) VALUES (?,?,?)",
            (group_id, user["id"], content),
        )
        msg = conn.execute("SELECT * FROM group_messages WHERE id=?", (cur.lastrowid,)).fetchone()
    return ok({
        "id": msg["id"],
        "group_id": msg["group_id"],
        "sender_id": msg["sender_id"],
        "content": msg["content"],
        "created_at": msg["created_at"],
    }, "发送成功")


@router.get("/groups/{group_id}/messages")
def list_group_msgs(group_id: int, page: int = 1, limit: int = 20, user: dict = Depends(get_current_user)):
    """群聊消息记录（不显示已删除消息）。"""
    page, limit, offset = page_args(page, limit)
    with db() as conn:
        group = conn.execute("SELECT status FROM groups WHERE id=?", (group_id,)).fetchone()
        if group is None:
            raise BizError(4040, "群聊不存在")
        if group["status"] == "dissolved":
            raise BizError(4030, "该群聊已解散")
        member = conn.execute(
            "SELECT 1 FROM group_members WHERE group_id=? AND user_id=? AND status='active'",
            (group_id, user["id"]),
        ).fetchone()
        if member is None:
            raise BizError(4030, "你不是该群成员")
        rows = conn.execute(
            "SELECT gm.*, u.nickname AS sender_nickname FROM group_messages gm JOIN users u ON gm.sender_id=u.id "
            "WHERE gm.group_id=? AND gm.is_deleted=0 ORDER BY gm.created_at DESC LIMIT ? OFFSET ?",
            (group_id, limit, offset),
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) AS c FROM group_messages WHERE group_id=? AND is_deleted=0", (group_id,)
        ).fetchone()["c"]
    return ok({
        "items": [
            {
                "id": r["id"],
                "sender_id": r["sender_id"],
                "sender_nickname": r["sender_nickname"],
                "content": r["content"],
                "created_at": r["created_at"],
            }
            for r in reversed(rows)
        ],
        "total": total, "page": page, "limit": limit,
    })
