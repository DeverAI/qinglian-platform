"""任务上传与审核 API（用户侧）。"""
import json

from fastapi import APIRouter, Depends, Form, Header, UploadFile

from .. import ai_check
from ..attack_detector import detect, handle_attack
from ..common import BizError, ok, page_args
from ..config import ISSUE_TYPES, PRESET_PLATFORMS, UPLOAD_DIR
from ..content_guard import add_daily_image_bytes, check_daily_image_bytes
from ..database import db
from ..handshake import require_handshake
from ..image_upload import image_policy, store_upload_image
from ..security import csrf_check, get_current_user, get_threshold

router = APIRouter()


@router.get("/meta/image-policy")
def get_image_policy(user: dict = Depends(get_current_user)):
    return ok(image_policy(int(user.get("points") or 0)))


def get_optional_user_or_none(authorization: str = Header(default="")) -> dict | None:
    if not authorization.startswith("Bearer "):
        return None
    try:
        return get_current_user(authorization)
    except BizError:
        return None

def _task_out(row) -> dict:
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "platform_name": row["platform_name"],
        "issue_type": row["issue_type"],
        "clause_text": row["clause_text"],
        "description": row["description"],
        "law_reference": row["law_reference"],
        "images": json.loads(row["images"]),
        "status": row["status"],
        "review_note": row["review_note"],
        "reviewer_id": row["reviewer_id"],
        "is_excellent": row["is_excellent"],
        "is_mosaicked": row["is_mosaicked"],
        "admin_label": row["admin_label"],
        "category_id": row["category_id"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


@router.post("")
def create_task(
    platform_name: str = Form(min_length=1, max_length=60),
    issue_type: str = Form(min_length=1, max_length=30),
    clause_text: str = Form(min_length=1, max_length=20000),
    description: str = Form(min_length=1, max_length=10000),
    law_reference: str = Form(default="", max_length=1000),
    no_sensitive_declared: str = Form(default=""),
    image_target_bytes: str = Form(default="auto"),
    images: list[UploadFile] | None = None,
    user: dict = Depends(csrf_check),
    _: dict = Depends(require_handshake),
):
    if issue_type not in ISSUE_TYPES:
        raise BizError(4006, f"无效的问题类型，可选：{', '.join(ISSUE_TYPES)}")
    if no_sensitive_declared.lower() not in ("on", "true", "1"):
        raise BizError(
            4005,
            "请先勾选“我已确认截图中不包含第三方真实姓名、手机号、人脸、家庭住址等个人信息”，并自行备份原始图片",
        )
    platform_name = platform_name.strip()

    # 攻击检测
    combined = f"{platform_name} {clause_text} {description} {law_reference}"
    attack_result = detect(combined)
    if attack_result.is_attack:
        with db() as conn:
            handle_attack(conn, user["id"], attack_result.reason)
        raise BizError(4030, "检测到攻击性内容，账号已被封禁")
    if attack_result.is_suspicious:
        with db() as conn:
            from ..common import log_admin
            log_admin(conn, 0, "可疑任务内容", f"user_id={user['id']}, {attack_result.reason[:200]}")

    images = images or []
    upload_policy = image_policy(int(user.get("points") or 0))
    if len(images) > upload_policy["max_count"]:
        raise BizError(4007, f"单次最多上传 {upload_policy['max_count']} 张图片")
    stored = []
    stored_bytes = 0
    source_bytes = 0
    try:
        for img in images:
            result = store_upload_image(img, int(user.get("points") or 0), image_target_bytes)
            stored.append(result.filename)
            stored_bytes += result.stored_bytes
            source_bytes += result.source_bytes
        if stored_bytes:
            max_image = get_threshold("threshold_daily_image_bytes", 4194304)
            with db() as conn:
                check_daily_image_bytes(conn, user["id"], stored_bytes, max_image)
                add_daily_image_bytes(conn, user["id"], stored_bytes)
    except BizError:
        for name in stored:
            try:
                (UPLOAD_DIR / name).unlink()
            except OSError:
                pass
        raise

    try:
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO tasks (user_id, platform_name, issue_type, clause_text, description, law_reference, images, status) "
                "VALUES (?,?,?,?,?,?,?,'pending')",
                (user["id"], platform_name, issue_type, clause_text, description, law_reference, json.dumps(stored)),
            )
            task_id = cur.lastrowid

            # AI 多模态合规检测：发现违规图片立即删除并打回
            violations = []
            if stored:
                violations = ai_check.check_images([UPLOAD_DIR / n for n in stored])
            if violations:
                remaining = []
                for idx, name in enumerate(stored):
                    if idx in violations:
                        try:
                            (UPLOAD_DIR / name).unlink()
                        except OSError:
                            pass
                    else:
                        remaining.append(name)
                conn.execute(
                    "UPDATE tasks SET status='returned', admin_label='needs_supplement', "
                    "review_note=?, images=?, updated_at=datetime('now','localtime') WHERE id=?",
                    (
                        "AI 多模态检测发现部分截图可能包含第三方个人信息，已自动删除不合规图片，请补充或脱敏后重新提交。",
                        json.dumps(remaining),
                        task_id,
                    ),
                )

            task = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        msg = "提交成功，等待审核"
        if violations:
            msg = "AI 检测到部分图片可能包含第三方个人信息，已自动删除并打回，请补充或脱敏后重新提交"
        output = _task_out(task)
        output["upload_summary"] = {"source_bytes": source_bytes, "stored_bytes": stored_bytes}
        return ok(output, msg)
    except Exception:
        # DB 或未知异常导致事务回滚，清理已保存的图片避免孤立文件
        for name in stored:
            try:
                (UPLOAD_DIR / name).unlink()
            except OSError:
                pass
        raise


@router.get("/my")
def my_tasks(
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(get_current_user),
):
    page, limit, offset = page_args(page, limit)
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (user["id"], limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS c FROM tasks WHERE user_id = ?", (user["id"],)).fetchone()["c"]
    return ok({"items": [_task_out(r) for r in rows], "total": total, "page": page, "limit": limit})


@router.get("/{task_id}")
def get_task(task_id: int, user: dict | None = Depends(get_optional_user_or_none)):
    with db() as conn:
        task = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if task is None:
        raise BizError(4040, "任务不存在")
    # 非本人/非管理员只能看已通过
    is_owner = user and user["id"] == task["user_id"]
    is_admin = user and user["role"] in ("admin", "sysadmin")
    if task["status"] != "approved" and not (is_owner or is_admin):
        raise BizError(4040, "任务不存在")
    return ok(_task_out(task))


@router.get("")
def public_tasks(
    platform_name: str = "",
    issue_type: str = "",
    page: int = 1,
    limit: int = 20,
):
    page, limit, offset = page_args(page, limit)
    where = "status = 'approved'"
    params = []
    if platform_name:
        where += " AND platform_name = ?"
        params.append(platform_name)
    if issue_type and issue_type in ISSUE_TYPES:
        where += " AND issue_type = ?"
        params.append(issue_type)
    sql = f"SELECT * FROM tasks WHERE {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?"
    with db() as conn:
        rows = conn.execute(sql, (*params, limit, offset)).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) AS c FROM tasks WHERE {where}", params
        ).fetchone()["c"]
    return ok({"items": [_task_out(r) for r in rows], "total": total, "page": page, "limit": limit})


@router.get("/meta/platforms")
def platform_list():
    with db() as conn:
        rows = conn.execute(
            "SELECT DISTINCT platform_name FROM tasks WHERE status = 'approved' ORDER BY platform_name"
        ).fetchall()
    used = [r["platform_name"] for r in rows]
    merged = list(dict.fromkeys(PRESET_PLATFORMS + used))
    return ok({"preset": PRESET_PLATFORMS, "used": used, "all": merged})
