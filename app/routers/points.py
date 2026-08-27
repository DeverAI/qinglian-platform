"""积分系统 API：签到、积分流水、排行榜、积分用途。"""
import datetime
import sqlite3

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..common import BizError, add_points, ok, page_args, spend_points
from ..database import db
from ..security import csrf_check, get_current_user, get_threshold

router = APIRouter()

# 积分用途阈值（root 可在后台通过 admin_settings 动态调整）
def _nickname_color_cost() -> int:
    return get_threshold("threshold_points_nickname_color", 50)


def _apply_threshold(app_type: str) -> int:
    key = "threshold_points_apply_admin" if app_type == "admin" else "threshold_points_apply_volunteer"
    return get_threshold(key, 500 if app_type == "admin" else 100)

_ALLOWED_COLORS = {
    "#2563eb", "#16a34a", "#dc2626", "#9333ea", "#ea580c",
    "#0891b2", "#db2777", "#65a30d", "#4f46e5", "#0f172a",
}


def _today() -> str:
    return datetime.date.today().isoformat()


def _yesterday() -> str:
    return (datetime.date.today() - datetime.timedelta(days=1)).isoformat()


@router.post("/sign-in")
def sign_in(user: dict = Depends(csrf_check)):
    today = _today()
    try:
        with db() as conn:
            yesterday = _yesterday()
            yest = conn.execute(
                "SELECT streak FROM sign_ins WHERE user_id=? AND sign_date=?", (user["id"], yesterday)
            ).fetchone()
            streak = (yest["streak"] + 1) if yest else 1

            base = get_threshold("threshold_reward_signin_base", 1)
            # 连续签到满 7 天一次性额外奖励 5 积分，不是第 7 天之后每天都奖励
            extra = get_threshold("threshold_reward_signin_streak7_bonus", 5) if streak == 7 else 0
            delta = base + extra
            conn.execute(
                "INSERT INTO sign_ins (user_id, sign_date, streak) VALUES (?,?,?)",
                (user["id"], today, streak),
            )
            if delta > 0:
                add_points(conn, user["id"], delta, f"每日签到（连续{streak}天）", "sign_in")
            total = conn.execute("SELECT points FROM users WHERE id=?", (user["id"],)).fetchone()["points"]
            result = {"delta": delta, "streak": streak, "points": total}
        return ok(result, "签到成功")
    except sqlite3.IntegrityError:
        raise BizError(4001, "今日已签到")


@router.get("/me")
def my_points(user: dict = Depends(get_current_user)):
    with db() as conn:
        total = conn.execute("SELECT points FROM users WHERE id=?", (user["id"],)).fetchone()["points"]
        today = conn.execute(
            "SELECT id FROM sign_ins WHERE user_id=? AND sign_date=?", (user["id"], _today())
        ).fetchone()
        week = conn.execute(
            "SELECT COALESCE(SUM(delta),0) AS s FROM point_logs WHERE user_id=? AND created_at>=datetime('now','-7 days')",
            (user["id"],),
        ).fetchone()["s"]
        month = conn.execute(
            "SELECT COALESCE(SUM(delta),0) AS s FROM point_logs WHERE user_id=? AND created_at>=datetime('now','-30 days')",
            (user["id"],),
        ).fetchone()["s"]
    return ok({"total": total, "signed_today": today is not None, "week": week, "month": month})


@router.get("/rules")
def point_rules():
    """Public, Root-configured point rules used by the homepage and profile UI."""
    earn = [
        ("每日签到", "threshold_reward_signin_base", 1, "每日一次"),
        ("连续签到第 7 天额外奖励", "threshold_reward_signin_streak7_bonus", 5, "仅第 7 天发放一次"),
        ("举报证据审核通过", "threshold_reward_task_upload_approved", 2, "同一任务仅一次"),
        ("举报证据被标注有效", "threshold_reward_task_evidence_valid", 3, "在审核通过奖励之外追加"),
        ("优秀举报案例", "threshold_reward_task_excellent", 5, "在其他任务奖励之外追加"),
        ("邮件代发通过 AI 初审", "threshold_reward_email_initial_approved", 2, "同一邮件仅一次"),
        ("代发邮件被确认有效", "threshold_reward_email_valid", 3, "同一邮件仅一次"),
        ("帖子被加精", "threshold_reward_post_featured", 3, "同一帖子仅一次"),
        ("回复累计获得 10 个赞", "threshold_reward_reply_ten_likes", 1, "达到节点时发放"),
        ("提交板块认领邮件", "threshold_reward_board_claim", 2, "提交成功后发放"),
        ("转发法律知识条文", "threshold_reward_knowledge_share", 1, "同一条文每日一次"),
        ("条文背诵答对", "threshold_reward_quiz_correct", 1, f"每日最多 {_daily_quiz_limit()} 题计分"),
    ]
    unlock = [
        ("论坛/聊天发言", "threshold_points_speak", 4),
        ("创建板块", "threshold_points_create_board", 10),
        ("管理板块", "threshold_points_moderate_board", 30),
        ("自选图片压缩体积", "threshold_points_upload_quality_choice", 100),
        ("申请志愿者", "threshold_points_apply_volunteer", 100),
        ("创建群聊（会扣除）", "threshold_points_create_group", 200),
        ("上传原图", "threshold_points_upload_original", 500),
        ("申请管理员", "threshold_points_apply_admin", 500),
        ("兑换昵称颜色（会扣除）", "threshold_points_nickname_color", 50),
        ("放弃板块认领（会扣除）", "threshold_cost_board_claim_abandon", 2),
    ]
    return ok({
        "earn": [{"name": name, "points": get_threshold(key, default), "note": note} for name, key, default, note in earn],
        "unlock": [{"name": name, "points": get_threshold(key, default)} for name, key, default in unlock],
        "note": "奖励为 0 表示 Root 已关闭该项；所有数值以当前后台配置为准。违规、刷分或重复操作不会获得积分。",
    })


def _daily_quiz_limit() -> int:
    return get_threshold("threshold_quiz_daily_limit", 5)


@router.get("/logs")
def point_logs(
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(get_current_user),
):
    page, limit, offset = page_args(page, limit)
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM point_logs WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (user["id"], limit, offset),
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) AS c FROM point_logs WHERE user_id=?", (user["id"],)
        ).fetchone()["c"]
    return ok({
        "items": [
            {"id": r["id"], "delta": r["delta"], "reason": r["reason"], "ref_type": r["ref_type"], "ref_id": r["ref_id"], "created_at": r["created_at"]}
            for r in rows
        ],
        "total": total,
        "page": page,
        "limit": limit,
    })


@router.get("/rankings")
def rankings(type: str = "week", page: int = 1, limit: int = 20):
    if type not in ("week", "month", "total"):
        raise BizError(4001, "排行榜类型错误")
    page, limit, offset = page_args(page, limit)
    with db() as conn:
        if type == "week":
            rows = conn.execute(
                "SELECT user_id, COALESCE(SUM(delta),0) AS score FROM point_logs WHERE created_at>=datetime('now','-7 days') "
                "GROUP BY user_id ORDER BY score DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            total = conn.execute(
                "SELECT COUNT(DISTINCT user_id) AS c FROM point_logs WHERE created_at>=datetime('now','-7 days')"
            ).fetchone()["c"]
        elif type == "month":
            rows = conn.execute(
                "SELECT user_id, COALESCE(SUM(delta),0) AS score FROM point_logs WHERE created_at>=datetime('now','-30 days') "
                "GROUP BY user_id ORDER BY score DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            total = conn.execute(
                "SELECT COUNT(DISTINCT user_id) AS c FROM point_logs WHERE created_at>=datetime('now','-30 days')"
            ).fetchone()["c"]
        else:
            rows = conn.execute(
                "SELECT id AS user_id, points AS score FROM users ORDER BY points DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        user_ids = [r["user_id"] for r in rows]
        names = {}
        if user_ids:
            placeholders = ",".join("?" * len(user_ids))
            for u in conn.execute(f"SELECT id,nickname FROM users WHERE id IN ({placeholders})", user_ids).fetchall():
                names[u["id"]] = u["nickname"]
    items = [{"user_id": r["user_id"], "nickname": names.get(r["user_id"], ""), "score": r["score"]} for r in rows]
    return ok({"items": items, "total": total, "page": page, "limit": limit, "type": type})


# ---------- 积分用途 ----------

class NicknameColorIn(BaseModel):
    color: str = Field(pattern=r"^#[0-9a-fA-F]{6}$")


class ApplicationIn(BaseModel):
    type: str = Field(pattern="^(volunteer|admin)$")
    reason: str = Field(default="", max_length=1000)


@router.post("/nickname-color")
def set_nickname_color(body: NicknameColorIn, user: dict = Depends(csrf_check)):
    color = body.color.lower()
    if color not in _ALLOWED_COLORS:
        raise BizError(4001, "暂不支持该颜色，请从预设颜色中选择")
    cost = _nickname_color_cost()
    with db() as conn:
        current = conn.execute("SELECT points, nickname_color FROM users WHERE id=?", (user["id"],)).fetchone()
        if current["nickname_color"] == color:
            raise BizError(4003, "已是该颜色，无需重复兑换")
        # 原子扣减积分，余额不足直接失败
        total = spend_points(
            conn, user["id"], cost, "兑换昵称颜色（荣誉）", "nickname_color", min_balance=cost
        )
        if total is None:
            raise BizError(4002, f"积分不足，需要 {cost} 积分")
        conn.execute("UPDATE users SET nickname_color=? WHERE id=?", (color, user["id"]))
    return ok({"color": color, "points": total}, "昵称颜色已更新")


@router.get("/nickname-color/options")
def nickname_color_options(user: dict = Depends(get_current_user)):
    return ok({"cost": _nickname_color_cost(), "colors": sorted(_ALLOWED_COLORS)})


@router.post("/applications")
def create_application(body: ApplicationIn, user: dict = Depends(csrf_check)):
    threshold = _apply_threshold(body.type)
    with db() as conn:
        current = conn.execute("SELECT points, role FROM users WHERE id=?", (user["id"],)).fetchone()
        if current["points"] < threshold:
            raise BizError(4002, f"积分不足，申请{body.type}需要 {threshold} 积分")
        if body.type == "volunteer" and current["role"] in ("moderator", "admin", "sysadmin"):
            raise BizError(4003, "你已是版主或管理员，无需申请志愿者")
        if body.type == "admin" and current["role"] in ("admin", "sysadmin"):
            raise BizError(4003, "你已是管理员，无需重复申请")
        pending = conn.execute(
            "SELECT id FROM applications WHERE user_id=? AND type=? AND status='pending'",
            (user["id"], body.type),
        ).fetchone()
        if pending:
            raise BizError(4004, "你已有一个待处理的同类申请")
        cur = conn.execute(
            "INSERT INTO applications (user_id, type, reason) VALUES (?,?,?)",
            (user["id"], body.type, body.reason.strip()),
        )
    return ok({"id": cur.lastrowid}, "申请已提交，等待管理员审核")


@router.get("/applications/my")
def my_applications(user: dict = Depends(get_current_user)):
    with db() as conn:
        rows = conn.execute(
            "SELECT id, type, reason, status, reviewed_by, reviewed_at, created_at "
            "FROM applications WHERE user_id=? ORDER BY created_at DESC",
            (user["id"],),
        ).fetchall()
    return ok({
        "items": [
            {
                "id": r["id"],
                "type": r["type"],
                "reason": r["reason"],
                "status": r["status"],
                "reviewed_by": r["reviewed_by"],
                "reviewed_at": r["reviewed_at"],
                "created_at": r["created_at"],
            }
            for r in rows
        ],
    })
