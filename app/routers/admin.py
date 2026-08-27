"""管理后台 API（任务审核与脱敏护栏优先实现，T6 后续补齐用户/知识库/日志等）。"""
import base64
import ipaddress
import json
import re
from pathlib import Path

import poplib
import smtplib
from email.utils import parseaddr

from fastapi import APIRouter, Body, Depends
from pydantic import BaseModel, Field

from ..common import BizError, add_points, log_admin, ok, page_args, spend_points
from ..config import ISSUE_TYPES, ROOT_EMAIL, UPLOAD_DIR
from ..database import db
from ..ip_protection import (
    SECURITY_SETTING_KEYS, lift_ip_ban, policy_snapshot, set_ip_ban,
    validate_security_changes,
)
from ..security import get_threshold, require_roles

router = APIRouter()

REVIEW_ROLES = ("admin", "sysadmin")


class ReviewIn(BaseModel):
    action: str = Field(pattern="^(approve|reject|return)$")
    review_note: str = Field(default="", max_length=2000)
    is_excellent: bool = False
    confirm_no_sensitive: bool = False
    admin_label: str = Field(default="effective", pattern="^(effective|needs_supplement)$")


class MosaicIn(BaseModel):
    images: list[dict] = Field(default_factory=list)  # [{index:int, data:base64}]


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


def _ensure_category(conn, platform_name: str, issue_type: str, task_id: int) -> int:
    """创建或复用平台一级分类 + [平台]-[类型] 二级板块，返回二级 category_id。"""
    platform_row = conn.execute(
        "SELECT id FROM categories WHERE parent_id IS NULL AND platform_name = ?", (platform_name,)
    ).fetchone()
    if platform_row is None:
        cur = conn.execute(
            "INSERT INTO categories (name, parent_id, platform_name, issue_type) VALUES (?, NULL, ?, '')",
            (platform_name, platform_name),
        )
        platform_id = cur.lastrowid
    else:
        platform_id = platform_row["id"]

    cat_name = f"{platform_name} - {issue_type}"
    cat_row = conn.execute(
        "SELECT id FROM categories WHERE parent_id = ? AND name = ?", (platform_id, cat_name)
    ).fetchone()
    if cat_row is None:
        cur = conn.execute(
            "INSERT INTO categories (name, parent_id, platform_name, issue_type, task_id) VALUES (?,?,?,?,?)",
            (cat_name, platform_id, platform_name, issue_type, task_id),
        )
        return cur.lastrowid
    return cat_row["id"]


@router.get("/tasks")
def list_review_tasks(
    status: str = "",
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(require_roles(*REVIEW_ROLES)),
):
    page, limit, offset = page_args(page, limit)
    where = "1=1"
    params = []
    if status and status in ("pending", "reviewing", "approved", "rejected", "returned"):
        where += " AND status = ?"
        params.append(status)
    sql = f"SELECT * FROM tasks WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    with db() as conn:
        rows = conn.execute(sql, (*params, limit, offset)).fetchall()
        total = conn.execute(f"SELECT COUNT(*) AS c FROM tasks WHERE {where}", params).fetchone()["c"]
    return ok({"items": [_task_out(r) for r in rows], "total": total, "page": page, "limit": limit})


@router.post("/tasks/{task_id}/review")
def review_task(task_id: int, body: ReviewIn, user: dict = Depends(require_roles(*REVIEW_ROLES, mutating=True))):
    if body.action not in ("approve", "reject", "return"):
        raise BizError(4001, "非法审核动作")

    with db() as conn:
        task = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if task is None:
            raise BizError(4040, "任务不存在")
        if task["user_id"] == user["id"]:
            raise BizError(4001, "不能审核自己提交的任务")

        if task["status"] in ("approved", "rejected") and body.action != task["status"]:
            raise BizError(4002, "任务已处于终态，无法变更审核结果")
        if task["status"] == "approved" and body.action == "approve":
            raise BizError(4002, "任务已通过，请勿重复审核")

        images = json.loads(task["images"])
        if body.action == "approve":
            # 脱敏护栏：有图片且未打码时，必须显式确认无第三方敏感信息
            if images and not task["is_mosaicked"] and not body.confirm_no_sensitive:
                raise BizError(
                    4005,
                    "该任务包含截图，请先使用打码工具脱敏，或确认截图中无第三方真实姓名、手机号、人脸、家庭住址等敏感信息",
                )

            category_id = _ensure_category(conn, task["platform_name"], task["issue_type"], task_id)
            conn.execute(
                "UPDATE tasks SET status='approved', reviewer_id=?, review_note=?, is_excellent=?, "
                "admin_label=?, category_id=?, updated_at=datetime('now','localtime') WHERE id=?",
                (user["id"], body.review_note, 1 if body.is_excellent else 0, body.admin_label, category_id, task_id),
            )
            # 积分奖励：上传证据 +2；有效 +3（幂等：仅首次通过发放）
            already_upload = conn.execute(
                "SELECT id FROM point_logs WHERE user_id=? AND ref_type='task' AND ref_id=? AND reason='上传证据审核通过'",
                (task["user_id"], task_id),
            ).fetchone()
            if not already_upload:
                reward = get_threshold("threshold_reward_task_upload_approved", 2)
                if reward > 0:
                    add_points(conn, task["user_id"], reward, "上传证据审核通过", "task", task_id)
            if body.admin_label == "effective":
                already_effective = conn.execute(
                    "SELECT id FROM point_logs WHERE user_id=? AND ref_type='task' AND ref_id=? AND reason='证据被标注有效'",
                    (task["user_id"], task_id),
                ).fetchone()
                if not already_effective:
                    reward = get_threshold("threshold_reward_task_evidence_valid", 3)
                    if reward > 0:
                        add_points(conn, task["user_id"], reward, "证据被标注有效", "task", task_id)
            if body.is_excellent:
                already_excellent = conn.execute(
                    "SELECT id FROM point_logs WHERE user_id=? AND ref_type='task' AND ref_id=? AND reason='优秀举报案例'",
                    (task["user_id"], task_id),
                ).fetchone()
                if not already_excellent:
                    reward = get_threshold("threshold_reward_task_excellent", 5)
                    if reward > 0:
                        add_points(conn, task["user_id"], reward, "优秀举报案例", "task", task_id)
            log_admin(conn, user["id"], "审核通过任务", f"task_id={task_id}, label={body.admin_label}, excellent={body.is_excellent}")
        elif body.action == "reject":
            conn.execute(
                "UPDATE tasks SET status='rejected', reviewer_id=?, review_note=?, admin_label='needs_supplement', "
                "updated_at=datetime('now','localtime') WHERE id=?",
                (user["id"], body.review_note, task_id),
            )
            log_admin(conn, user["id"], "审核驳回任务", f"task_id={task_id}")
        else:  # return
            conn.execute(
                "UPDATE tasks SET status='returned', reviewer_id=?, review_note=?, admin_label='needs_supplement', "
                "updated_at=datetime('now','localtime') WHERE id=?",
                (user["id"], body.review_note, task_id),
            )
            log_admin(conn, user["id"], "审核打回任务", f"task_id={task_id}")

        task = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    return ok(_task_out(task), "审核操作已执行")


@router.post("/tasks/{task_id}/mosaic")
def mosaic_task(task_id: int, body: MosaicIn, user: dict = Depends(require_roles(*REVIEW_ROLES, mutating=True))):
    data_url_re = re.compile(r"^data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)$")
    if not body.images:
        raise BizError(4001, "请至少选择一张图片进行打码")
    with db() as conn:
        task = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if task is None:
            raise BizError(4040, "任务不存在")
        images = json.loads(task["images"])
        replaced = []
        old_paths = []
        for item in body.images:
            idx = item.get("index")
            if idx is None or idx < 0 or idx >= len(images):
                raise BizError(4001, f"无效的图片索引：{idx}")
            data_url = item.get("data", "")
            m = data_url_re.match(data_url)
            if not m:
                raise BizError(4002, "图片数据格式错误，仅支持 data:image/png;base64,... 或 jpeg/webp")
            ext = ".png" if m.group(1) == "png" else ".jpg" if m.group(1) == "jpeg" else ".webp"
            try:
                raw = base64.b64decode(m.group(2))
            except Exception:
                raise BizError(4003, "Base64 解码失败")
            old_name = images[idx]
            old_path = UPLOAD_DIR / old_name
            new_name = f"{Path(old_name).stem}_m{ext}"
            new_path = UPLOAD_DIR / new_name
            # 先写入新文件，旧文件待 DB 提交成功后再删除，避免事务回滚导致引用断裂
            new_path.write_bytes(raw)
            images[idx] = new_name
            old_paths.append(old_path)
            replaced.append(idx)

        conn.execute(
            "UPDATE tasks SET images=?, is_mosaicked=1, updated_at=datetime('now','localtime') WHERE id=?",
            (json.dumps(images), task_id),
        )
        log_admin(
            conn,
            user["id"],
            "任务截图脱敏打码",
            f"task_id={task_id}, replaced_indices={replaced}",
        )
        task = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    # 事务提交成功后，再删除原始图片
    for old_path in old_paths:
        if old_path.exists():
            old_path.unlink()
    return ok(_task_out(task), "打码完成，原始图片已替换")


MOD_ROLES = ("moderator", "admin", "sysadmin", "root")
ADMIN_ROLES = ("admin", "sysadmin", "root")
SYSADMIN_ROLES = ("sysadmin", "root")
ROOT_ROLES = ("root",)

ROLE_WEIGHT = {"user": 0, "moderator": 1, "admin": 2, "sysadmin": 3, "root": 4}


def _application_cost(app_type: str) -> int:
    key = "threshold_points_apply_admin" if app_type == "admin" else "threshold_points_apply_volunteer"
    return get_threshold(key, 500 if app_type == "admin" else 100)


class EssenceIn(BaseModel):
    is_essence: bool


class ReportHandleIn(BaseModel):
    action: str = Field(pattern="^(resolve|dismiss)$")


class RoleChangeIn(BaseModel):
    role: str = Field(pattern="^(user|moderator|admin|sysadmin|root)$")


class BanIn(BaseModel):
    is_banned: bool


class BanEmailIn(BaseModel):
    email: str = Field(min_length=5, max_length=120)
    reason: str = Field(default="", max_length=500)


class BanDeviceIn(BaseModel):
    fingerprint: str = Field(min_length=1, max_length=128)
    reason: str = Field(default="", max_length=500)


class KeywordIn(BaseModel):
    keyword: str = Field(min_length=1, max_length=60)
    clause: str = Field(default="", max_length=1000)


class KnowledgeIn(BaseModel):
    category: str = Field(pattern="^(law|case|guide|qoder)$")
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=50000)
    source_url: str = Field(default="", max_length=500, pattern=r"^(|https?://[^\s]+)$")
    is_official: bool = False
    keywords: list[KeywordIn] = Field(default_factory=list)


@router.post("/posts/{post_id}/essence")
def essence_post(post_id: int, body: EssenceIn, user: dict = Depends(require_roles(*MOD_ROLES, mutating=True))):
    with db() as conn:
        post = conn.execute("SELECT id,user_id,is_essence FROM posts WHERE id=?", (post_id,)).fetchone()
        if post is None:
            raise BizError(4040, "帖子不存在")
        if post["user_id"] == user["id"]:
            raise BizError(4001, "不能给自己的帖子加精")
        conn.execute("UPDATE posts SET is_essence=? WHERE id=?", (1 if body.is_essence else 0, post_id))
        action = "帖子加精" if body.is_essence else "取消帖子加精"
        log_admin(conn, user["id"], action, f"post_id={post_id}")
        # 加精时给作者 +3 积分（仅一次）
        if body.is_essence:
            already = conn.execute(
                "SELECT id FROM point_logs WHERE user_id=? AND ref_type='post' AND ref_id=? AND reason='帖子被加精'",
                (post["user_id"], post_id),
            ).fetchone()
            if not already:
                reward = get_threshold("threshold_reward_post_featured", 3)
                if reward > 0:
                    add_points(conn, post["user_id"], reward, "帖子被加精", "post", post_id)
    return ok(None, "操作成功")


@router.get("/reports")
def list_reports(
    status: str = "",
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(require_roles(*MOD_ROLES)),
):
    page, limit, offset = page_args(page, limit)
    where = "1=1"
    params = []
    if status and status in ("pending", "resolved", "dismissed"):
        where += " AND r.status=?"
        params.append(status)
    sql = (
        f"SELECT r.*, u.nickname AS reporter_nickname FROM reports r JOIN users u ON r.reporter_id=u.id "
        f"WHERE {where} ORDER BY r.created_at DESC LIMIT ? OFFSET ?"
    )
    count_sql = f"SELECT COUNT(*) AS c FROM reports r WHERE {where}"
    with db() as conn:
        rows = conn.execute(sql, (*params, limit, offset)).fetchall()
        total = conn.execute(count_sql, params).fetchone()["c"]
    return ok({
        "items": [
            {
                "id": r["id"],
                "reporter_id": r["reporter_id"],
                "reporter_nickname": r["reporter_nickname"],
                "target_type": r["target_type"],
                "target_id": r["target_id"],
                "reason": r["reason"],
                "status": r["status"],
                "handled_by": r["handled_by"],
                "handled_at": r["handled_at"],
                "created_at": r["created_at"],
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "limit": limit,
    })


@router.post("/reports/{report_id}/handle")
def handle_report(report_id: int, body: ReportHandleIn, user: dict = Depends(require_roles(*MOD_ROLES, mutating=True))):
    status = "resolved" if body.action == "resolve" else "dismissed"
    with db() as conn:
        report = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if report is None:
            raise BizError(4040, "举报不存在")
        if report["reporter_id"] == user["id"]:
            raise BizError(4001, "不能处理自己提交的举报")
        if report["status"] != "pending":
            raise BizError(4002, "该举报已处理")
        conn.execute(
            "UPDATE reports SET status=?, handled_by=?, handled_at=datetime('now','localtime') WHERE id=?",
            (status, user["id"], report_id),
        )
        log_admin(conn, user["id"], f"举报{status}", f"report_id={report_id}, target={report['target_type']}:{report['target_id']}")
    return ok(None, "处理成功")


@router.get("/users")
def list_users(
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(require_roles(*SYSADMIN_ROLES)),
):
    page, limit, offset = page_args(page, limit)
    with db() as conn:
        rows = conn.execute(
            "SELECT id,email,nickname,role,points,is_banned,is_suspicious,device_fingerprint,created_at FROM users "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    return ok({
        "items": [
            {
                "id": r["id"],
                "email": r["email"],
                "nickname": r["nickname"],
                "role": r["role"],
                "points": r["points"],
                "is_banned": r["is_banned"],
                "is_suspicious": r["is_suspicious"],
                "device_fingerprint": r["device_fingerprint"],
                "created_at": r["created_at"],
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "limit": limit,
    })


def _can_manage_role(operator_role: str, target_role: str, new_role: str) -> bool:
    """操作者只能将目标角色调整为自己权重以下的角色（不含同级），且不能操作更高权限账号。"""
    op_w = ROLE_WEIGHT.get(operator_role, -1)
    target_w = ROLE_WEIGHT.get(target_role, -1)
    new_w = ROLE_WEIGHT.get(new_role, -1)
    # 新角色必须严格低于操作者；目标角色不得高于操作者（root 除外已在依赖中放行）
    return op_w > new_w and op_w >= target_w


@router.post("/users/{target_user_id}/role")
def change_role(target_user_id: int, body: RoleChangeIn, user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    if target_user_id == user["id"]:
        raise BizError(4001, "不能修改自己的角色")
    if body.role == "root":
        raise BizError(4003, "root 角色不可通过此接口分配")
    with db() as conn:
        target = conn.execute("SELECT id,role,email FROM users WHERE id=?", (target_user_id,)).fetchone()
        if target is None:
            raise BizError(4040, "用户不存在")
        if not _can_manage_role(user["role"], target["role"], body.role):
            raise BizError(4030, "权限不足：无法调整该用户角色")
        # 保护最后一名 sysadmin
        if target["role"] == "sysadmin" and body.role != "sysadmin":
            count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role='sysadmin'").fetchone()["c"]
            if count <= 1:
                raise BizError(4002, "不能降级唯一的系统管理员")
        conn.execute("UPDATE users SET role=? WHERE id=?", (body.role, target_user_id))
        log_admin(conn, user["id"], "修改用户角色", f"user_id={target_user_id}, old={target['role']}, new={body.role}")
    return ok(None, "角色已更新")


@router.post("/users/{target_user_id}/ban")
def ban_user(target_user_id: int, body: BanIn, user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    if target_user_id == user["id"]:
        raise BizError(4001, "不能封禁自己")
    with db() as conn:
        target = conn.execute("SELECT id,role,email FROM users WHERE id=?", (target_user_id,)).fetchone()
        if target is None:
            raise BizError(4040, "用户不存在")
        if ROLE_WEIGHT.get(user["role"], -1) < ROLE_WEIGHT.get(target["role"], -1):
            raise BizError(4030, "权限不足：无法封禁更高权限账号")
        if body.is_banned and target["role"] == "sysadmin":
            count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role='sysadmin'").fetchone()["c"]
            if count <= 1:
                raise BizError(4002, "不能封禁唯一的系统管理员")
        conn.execute("UPDATE users SET is_banned=? WHERE id=?", (1 if body.is_banned else 0, target_user_id))
        # 同步写入/解除 bans 表的账号级封禁记录，确保 _check_bans 统一校验
        if body.is_banned:
            conn.execute(
                "INSERT INTO bans (ban_type, target, reason, banned_by) VALUES (?,?,?,?)",
                ("account", str(target["id"]), f"管理员封禁用户 {target['id']}", user["id"]),
            )
        else:
            conn.execute(
                "UPDATE bans SET is_active=0 WHERE ban_type='account' AND target=?",
                (str(target["id"]),),
            )
        action = "封禁用户" if body.is_banned else "解封用户"
        log_admin(conn, user["id"], action, f"user_id={target_user_id}, role={target['role']}")
    return ok(None, "操作成功")


@router.get("/bans")
def list_bans(
    ban_type: str = "",
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(require_roles(*ADMIN_ROLES)),
):
    page, limit, offset = page_args(page, limit)
    where = "1=1"
    params = []
    if ban_type and ban_type in ("account", "email", "device"):
        where += " AND ban_type=?"
        params.append(ban_type)
    sql = f"SELECT * FROM bans WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    with db() as conn:
        rows = conn.execute(sql, (*params, limit, offset)).fetchall()
        total = conn.execute(f"SELECT COUNT(*) AS c FROM bans WHERE {where}", params).fetchone()["c"]
    return ok({
        "items": [
            {
                "id": r["id"],
                "ban_type": r["ban_type"],
                "target": r["target"],
                "reason": r["reason"],
                "banned_by": r["banned_by"],
                "is_active": bool(r["is_active"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ],
        "total": total, "page": page, "limit": limit,
    })


@router.post("/bans/email")
def ban_email(body: BanEmailIn, user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    email = body.email.strip().lower()
    if email == ROOT_EMAIL.lower():
        raise BizError(4001, "禁止封禁 Root 登录邮箱")
    with db() as conn:
        # 如果该邮箱存在更高权限账号，禁止封禁
        higher = conn.execute(
            "SELECT role FROM users WHERE email=? ORDER BY CASE role WHEN 'root' THEN 4 WHEN 'sysadmin' THEN 3 WHEN 'admin' THEN 2 WHEN 'moderator' THEN 1 ELSE 0 END DESC LIMIT 1", (email,)
        ).fetchone()
        if higher and ROLE_WEIGHT.get(higher["role"], -1) > ROLE_WEIGHT.get(user["role"], -1):
            raise BizError(4030, "权限不足：无法封禁该邮箱下的高权限账号")
        conn.execute(
            "INSERT INTO bans (ban_type, target, reason, banned_by) VALUES (?,?,?,?)",
            ("email", email, body.reason, user["id"]),
        )
        log_admin(conn, user["id"], "封禁邮箱", f"email={email}, reason={body.reason}")
    return ok(None, "邮箱已封禁")


@router.post("/bans/device")
def ban_device(body: BanDeviceIn, user: dict = Depends(require_roles(*ROOT_ROLES, mutating=True))):
    fp = body.fingerprint.strip()[:128]
    with db() as conn:
        conn.execute(
            "INSERT INTO bans (ban_type, target, reason, banned_by) VALUES (?,?,?,?)",
            ("device", fp, body.reason, user["id"]),
        )
        # 同时标记使用该指纹的用户为可疑
        conn.execute("UPDATE users SET is_suspicious=1 WHERE device_fingerprint=?", (fp,))
        log_admin(conn, user["id"], "封禁设备", f"fingerprint={fp}, reason={body.reason}")
    return ok(None, "设备已封禁")


@router.post("/bans/{ban_id}/lift")
def lift_ban(ban_id: int, user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    with db() as conn:
        ban = conn.execute("SELECT * FROM bans WHERE id=?", (ban_id,)).fetchone()
        if ban is None:
            raise BizError(4040, "封禁记录不存在")
        if ban["ban_type"] == "device" and user["role"] != "root":
            raise BizError(4030, "仅 root 可解除设备封禁")
        # 解封需同等或更高权限：低权重管理员不可解封高权重管理员创建的封禁
        if ban["banned_by"]:
            banner = conn.execute("SELECT role FROM users WHERE id=?", (ban["banned_by"],)).fetchone()
            if banner and ROLE_WEIGHT.get(user["role"], -1) < ROLE_WEIGHT.get(banner["role"], -1):
                raise BizError(4030, "权限不足：无法解封该封禁记录")
        conn.execute("UPDATE bans SET is_active=0 WHERE id=?", (ban_id,))
        log_admin(conn, user["id"], "解除封禁", f"ban_id={ban_id}, type={ban['ban_type']}, target={ban['target']}")
    return ok(None, "封禁已解除")


@router.get("/logs")
def admin_logs(
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(require_roles(*ADMIN_ROLES)),
):
    page, limit, offset = page_args(page, limit)
    with db() as conn:
        rows = conn.execute(
            "SELECT al.*, u.nickname AS admin_nickname FROM admin_logs al JOIN users u ON al.admin_id=u.id "
            "ORDER BY al.created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS c FROM admin_logs").fetchone()["c"]
    return ok({
        "items": [
            {
                "id": r["id"],
                "admin_id": r["admin_id"],
                "admin_nickname": r["admin_nickname"],
                "action": r["action"],
                "detail": r["detail"],
                "created_at": r["created_at"],
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "limit": limit,
    })


@router.get("/honeypot")
def honeypot_logs(
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(require_roles(*ADMIN_ROLES)),
):
    page, limit, offset = page_args(page, limit)
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM honeypot_logs ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS c FROM honeypot_logs").fetchone()["c"]
    return ok({
        "items": [
            {"id": r["id"], "ip": r["ip"], "path": r["path"], "cookie_data": r["cookie_data"], "payload": r["payload"], "detail": r["detail"], "created_at": r["created_at"]}
            for r in rows
        ],
        "total": total,
        "page": page,
        "limit": limit,
    })


@router.post("/knowledge")
def create_knowledge(body: KnowledgeIn, user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO knowledge_entries (category, title, content, source_url, is_official, created_by) VALUES (?,?,?,?,?,?)",
            (body.category, body.title.strip(), body.content.strip(), body.source_url.strip(), 1 if body.is_official else 0, user["id"]),
        )
        entry_id = cur.lastrowid
        for kw in body.keywords:
            keyword = kw.keyword.strip()
            clause = kw.clause.strip()
            if keyword:
                conn.execute(
                    "INSERT INTO knowledge_keywords (entry_id, keyword, clause) VALUES (?,?,?)",
                    (entry_id, keyword, clause),
                )
        entry = conn.execute("SELECT * FROM knowledge_entries WHERE id=?", (entry_id,)).fetchone()
        log_admin(conn, user["id"], "创建知识库条目", f"entry_id={entry_id}, category={body.category}, official={body.is_official}")
    return ok({"id": entry["id"], "category": entry["category"], "title": entry["title"], "created_at": entry["created_at"]}, "创建成功")


@router.put("/knowledge/{entry_id}")
def update_knowledge(entry_id: int, body: KnowledgeIn, user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    with db() as conn:
        entry = conn.execute("SELECT id FROM knowledge_entries WHERE id=?", (entry_id,)).fetchone()
        if entry is None:
            raise BizError(4040, "条目不存在")
        conn.execute(
            "UPDATE knowledge_entries SET category=?, title=?, content=?, source_url=?, is_official=?, "
            "updated_at=datetime('now','localtime') WHERE id=?",
            (body.category, body.title.strip(), body.content.strip(), body.source_url.strip(), 1 if body.is_official else 0, entry_id),
        )
        conn.execute("DELETE FROM knowledge_keywords WHERE entry_id=?", (entry_id,))
        for kw in body.keywords:
            keyword = kw.keyword.strip()
            clause = kw.clause.strip()
            if keyword:
                conn.execute(
                    "INSERT INTO knowledge_keywords (entry_id, keyword, clause) VALUES (?,?,?)",
                    (entry_id, keyword, clause),
                )
        log_admin(conn, user["id"], "更新知识库", f"entry_id={entry_id}, category={body.category}, official={body.is_official}")
    return ok(None, "更新成功")


@router.delete("/knowledge/{entry_id}")
def delete_knowledge(entry_id: int, user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    with db() as conn:
        entry = conn.execute("SELECT id FROM knowledge_entries WHERE id=?", (entry_id,)).fetchone()
        if entry is None:
            raise BizError(4040, "条目不存在")
        conn.execute("DELETE FROM daily_law WHERE entry_id=?", (entry_id,))
        conn.execute("DELETE FROM knowledge_keywords WHERE entry_id=?", (entry_id,))
        conn.execute("DELETE FROM knowledge_entries WHERE id=?", (entry_id,))
        log_admin(conn, user["id"], "删除知识库", f"entry_id={entry_id}")
    return ok(None, "删除成功")


# ---------- 管理员设置：POP3/SMTP、AI API ----------

MAIL_KEYS = {
    "smtp_host", "smtp_port", "smtp_user", "smtp_pass", "smtp_use_ssl",
    "pop3_host", "pop3_port", "pop3_user", "pop3_pass", "pop3_use_ssl", "mail_from",
}
AI_KEYS = {"ai_api_url", "ai_api_key", "ai_model", "ai_vision_model", "ai_search_model", "ai_review_model"}
AI_MODEL_SPECS = {
    "ai_model": {
        "name": "AI 导游 / 通用对话模型",
        "uses": ["社区导游问答", "普通文本生成"],
        "requirements": ["OpenAI Chat Completions 兼容", "支持中文", "建议支持至少 16K 上下文"],
    },
    "ai_vision_model": {
        "name": "图片合规检测模型",
        "uses": ["识别截图中的人脸、姓名、手机号等第三方隐私"],
        "requirements": ["必须支持 image_url 多模态输入", "必须可靠输出 JSON 数组"],
    },
    "ai_search_model": {
        "name": "联网搜索 / 新闻与简报模型",
        "uses": ["新闻采集", "每日政策简报与来源核验"],
        "requirements": ["必须支持 web_search 工具调用", "必须返回真实可访问来源链接", "不支持工具时任务会失败，不降级为无来源生成"],
    },
    "ai_review_model": {
        "name": "审核与结构化判断模型",
        "uses": ["邮件初审", "争议内容审核"],
        "requirements": ["支持较长中文上下文", "稳定输出指定 JSON", "建议低幻觉模型"],
    },
}
SECURITY_KEYS = SECURITY_SETTING_KEYS
ALL_SETTING_KEYS = MAIL_KEYS | AI_KEYS | SECURITY_KEYS
SENSITIVE_KEYS = {"smtp_pass", "pop3_pass", "ai_api_key"}


class SettingIn(BaseModel):
    key: str = Field(min_length=1)
    value: str


class SettingsGroupIn(BaseModel):
    group: str = Field(pattern="^(mail|ai|security|all)$", default="all")


def _load_settings(conn) -> dict:
    rows = conn.execute("SELECT key, value FROM admin_settings WHERE key IN (" + ",".join("?" * len(ALL_SETTING_KEYS)) + ")", tuple(ALL_SETTING_KEYS)).fetchall()
    return {r["key"]: r["value"] for r in rows}


def get_setting(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM admin_settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def _mask_settings(settings: dict) -> dict:
    return {k: ("******" if k in SENSITIVE_KEYS and v else v) for k, v in settings.items()}


@router.get("/settings")
def list_settings(group: str = "all", user: dict = Depends(require_roles(*ADMIN_ROLES))):
    with db() as conn:
        settings = _load_settings(conn)
    if group == "mail":
        settings = {k: v for k, v in settings.items() if k in MAIL_KEYS}
    elif group == "ai":
        settings = {k: v for k, v in settings.items() if k in AI_KEYS}
    elif group == "security":
        settings = {k: v for k, v in settings.items() if k in SECURITY_KEYS}
    else:
        # 补齐默认值，避免前端 undefined
        for k in ALL_SETTING_KEYS:
            settings.setdefault(k, "")
    return ok(_mask_settings(settings))


@router.get("/settings/ai-specs")
def ai_model_specs(user: dict = Depends(require_roles(*ADMIN_ROLES))):
    return ok(AI_MODEL_SPECS)


@router.put("/settings")
def update_setting(body: SettingIn, user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    if body.key not in ALL_SETTING_KEYS:
        raise BizError(4001, "非法配置项")
    if body.key in SECURITY_KEYS and user["role"] != "root":
        raise BizError(4030, "安全防护参数仅 root 可修改")
    with db() as conn:
        if body.key in SECURITY_KEYS:
            validate_security_changes(conn, {body.key: body.value})
        old = conn.execute("SELECT value FROM admin_settings WHERE key=?", (body.key,)).fetchone()
        conn.execute(
            "INSERT INTO admin_settings (key, value, updated_by, updated_at) VALUES (?,?,?,datetime('now','localtime')) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
            (body.key, body.value, user["id"]),
        )
        detail = f"key={body.key}"
        if body.key in SECURITY_KEYS:
            detail += f", old={old['value'] if old else '<unset>'}, new={body.value}"
        log_admin(conn, user["id"], "更新设置", detail)
    return ok(None, "设置已更新")


class IpBanIn(BaseModel):
    ip: str = Field(min_length=1, max_length=64)
    minutes: int = Field(ge=1)
    reason: str = Field(default="", max_length=500)


def _validated_ip(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError as exc:
        raise BizError(4001, "IP 地址格式无效") from exc


@router.get("/ip-controls")
def list_ip_controls(page: int = 1, limit: int = 20, user: dict = Depends(require_roles(*ADMIN_ROLES))):
    page, limit, offset = page_args(page, limit)
    with db() as conn:
        rows = conn.execute(
            "SELECT ip FROM ip_access_controls ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS c FROM ip_access_controls").fetchone()["c"]
    return ok({
        "items": [policy_snapshot(r["ip"]) for r in rows],
        "total": total,
        "page": page,
        "limit": limit,
    })


@router.post("/ip-controls/ban")
def ban_ip(body: IpBanIn, user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    ip = _validated_ip(body.ip)
    effective_minutes = set_ip_ban(ip, body.minutes, body.reason, actor_id=user["id"])
    with db() as conn:
        log_admin(conn, user["id"], "封禁IP", f"ip={ip}, minutes={effective_minutes}, reason={body.reason}")
    return ok({"minutes": effective_minutes}, "IP 已封禁")


@router.post("/ip-controls/{ip}/lift")
def lift_ip_control(ip: str, user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    ip = _validated_ip(ip)
    lift_ip_ban(ip, actor_id=user["id"])
    with db() as conn:
        log_admin(conn, user["id"], "解除IP封禁", f"ip={ip}")
    return ok(None, "IP 已解除封禁")


@router.get("/ip-controls/events")
def list_ip_security_events(
    ip: str = "", page: int = 1, limit: int = 20,
    user: dict = Depends(require_roles(*ADMIN_ROLES)),
):
    page, limit, offset = page_args(page, limit)
    where = "WHERE e.ip=?" if ip else ""
    params = (ip, limit, offset) if ip else (limit, offset)
    count_params = (ip,) if ip else ()
    with db() as conn:
        rows = conn.execute(
            "SELECT e.*, u.nickname AS actor_nickname FROM ip_security_events e "
            "LEFT JOIN users u ON e.actor_id=u.id " + where + " ORDER BY e.id DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS c FROM ip_security_events e " + where, count_params).fetchone()["c"]
    return ok({"items": [dict(row) for row in rows], "total": total, "page": page, "limit": limit})


def _parse_port(raw: str, default: int) -> int:
    try:
        port = int(raw or default)
        if not 1 <= port <= 65535:
            raise ValueError
        return port
    except ValueError:
        raise BizError(4001, "端口必须是 1-65535 之间的数字")


@router.post("/settings/test-pop3")
def test_pop3(user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    with db() as conn:
        s = _load_settings(conn)
    host = s.get("pop3_host", "")
    port = _parse_port(s.get("pop3_port", ""), 995)
    username = s.get("pop3_user", "")
    password = s.get("pop3_pass", "")
    use_ssl = s.get("pop3_use_ssl", "1") in ("1", "true", "True")
    if not host or not username:
        raise BizError(4001, "POP3 服务器地址和用户名不能为空")
    try:
        if use_ssl:
            server = poplib.POP3_SSL(host, port, timeout=10)
        else:
            server = poplib.POP3(host, port, timeout=10)
        server.user(username)
        server.pass_(password)
        count, _ = server.stat()
        server.quit()
        return ok({"ok": True, "messages": count})
    except Exception as e:
        raise BizError(5002, f"POP3 连接失败：{e}")


@router.post("/settings/test-smtp")
def test_smtp(user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    with db() as conn:
        s = _load_settings(conn)
    host = s.get("smtp_host", "")
    port = _parse_port(s.get("smtp_port", ""), 465)
    username = s.get("smtp_user", "")
    password = s.get("smtp_pass", "")
    use_ssl = s.get("smtp_use_ssl", "1") in ("1", "true", "True")
    if not host or not username:
        raise BizError(4001, "SMTP 服务器地址和用户名不能为空")
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls()
        server.login(username, password)
        server.quit()
        return ok({"ok": True})
    except Exception as e:
        raise BizError(5002, f"SMTP 连接失败：{e}")


# ---------- 权限申请 ----------

class ApplicationIn(BaseModel):
    type: str = Field(pattern="^(volunteer|admin)$")
    reason: str = Field(default="", max_length=1000)


class ApplicationReviewIn(BaseModel):
    status: str = Field(pattern="^(approved|rejected)$")
    note: str = Field(default="", max_length=500)


@router.get("/applications")
def list_applications(
    status: str = "",
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(require_roles(*ADMIN_ROLES)),
):
    page, limit, offset = page_args(page, limit)
    where = "1=1"
    params = []
    if status and status in ("pending", "approved", "rejected"):
        where += " AND a.status=?"
        params.append(status)
    sql = (
        "SELECT a.*, u.nickname, u.email FROM applications a JOIN users u ON a.user_id=u.id "
        f"WHERE {where} ORDER BY a.created_at DESC LIMIT ? OFFSET ?"
    )
    with db() as conn:
        rows = conn.execute(sql, (*params, limit, offset)).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) AS c FROM applications a WHERE {where}", params
        ).fetchone()["c"]
    return ok({
        "items": [
            {
                "id": r["id"], "user_id": r["user_id"], "nickname": r["nickname"], "email": r["email"],
                "type": r["type"], "reason": r["reason"], "status": r["status"],
                "reviewed_by": r["reviewed_by"], "reviewed_at": r["reviewed_at"], "created_at": r["created_at"],
            }
            for r in rows
        ],
        "total": total, "page": page, "limit": limit,
    })


@router.post("/applications/{app_id}/review")
def review_application(app_id: int, body: ApplicationReviewIn, user: dict = Depends(require_roles(*ADMIN_ROLES, mutating=True))):
    with db() as conn:
        app = conn.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
        if app is None:
            raise BizError(4040, "申请不存在")
        if app["status"] != "pending":
            raise BizError(4002, "该申请已处理")

        if body.status == "approved":
            target_role = "moderator" if app["type"] == "volunteer" else "admin"
            applicant = conn.execute("SELECT role, points FROM users WHERE id=?", (app["user_id"],)).fetchone()
            if applicant is None:
                raise BizError(4040, "申请人不存在")
            if ROLE_WEIGHT.get(applicant["role"], 0) >= ROLE_WEIGHT[target_role]:
                raise BizError(4003, f"申请人当前角色为 {applicant['role']}，无需或无法降级审批")
            cost = _application_cost(app["type"])
            if cost:
                total = spend_points(
                    conn, app["user_id"], cost, f"权限申请通过：{app['type']}", "application", app_id, min_balance=cost
                )
                if total is None:
                    raise BizError(4002, "申请人当前积分不足，无法通过")
            conn.execute("UPDATE users SET role=? WHERE id=?", (target_role, app["user_id"]))

        conn.execute(
            "UPDATE applications SET status=?, reviewed_by=?, reviewed_at=datetime('now','localtime') WHERE id=?",
            (body.status, user["id"], app_id),
        )
        log_admin(conn, user["id"], f"申请{body.status}", f"application_id={app_id}, type={app['type']}, note={body.note}")
    return ok(None, "处理成功")
