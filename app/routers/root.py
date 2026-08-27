"""Root 专属接口：服务开关、管理员管理、Root 操作留痕。

Root 拥有最高权限，可开关普通服务、封禁管理员/设备、查看管理日志。
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..common import BizError, log_admin, ok
from ..database import db, DEFAULT_THRESHOLDS, THRESHOLD_MIN_VALUES
from ..ip_protection import SECURITY_SETTING_KEYS, validate_security_changes
from ..security import require_root

router = APIRouter()

SERVICE_NAMES = {"tasks", "forum", "points", "knowledge", "ai_agent", "emails", "honeypot", "chat", "notify", "feed", "news", "quiz"}


class ServiceToggleIn(BaseModel):
    enabled: bool


class PromoteIn(BaseModel):
    user_id: int
    role: str = Field(pattern="^(admin|sysadmin)$")


@router.get("/services")
def list_services(user: dict = Depends(require_root())):
    """读取当前各普通服务的运行开关状态（默认全部开启）。"""
    with db() as conn:
        rows = conn.execute(
            "SELECT key, value FROM admin_settings WHERE key IN (" + ",".join("?" * len(SERVICE_NAMES)) + ")",
            tuple(f"svc_{n}" for n in SERVICE_NAMES),
        ).fetchall()
    settings = {r["key"]: r["value"] for r in rows}
    data = {name: settings.get(f"svc_{name}", "1") == "1" for name in SERVICE_NAMES}
    return ok(data)


@router.put("/services/{name}")
def toggle_service(name: str, body: ServiceToggleIn, user: dict = Depends(require_root(mutating=True))):
    if name not in SERVICE_NAMES:
        raise BizError(4001, "非法服务名")
    with db() as conn:
        conn.execute(
            "INSERT INTO admin_settings (key, value, updated_by, updated_at) VALUES (?,?,?,datetime('now','localtime')) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
            (f"svc_{name}", "1" if body.enabled else "0", user["id"]),
        )
        log_admin(conn, user["id"], "切换服务开关", f"service={name}, enabled={body.enabled}")
    return ok(None, "服务状态已更新")


@router.get("/admins")
def list_admins(user: dict = Depends(require_root())):
    """列出所有管理员/sysadmin（不含 root）。"""
    with db() as conn:
        rows = conn.execute(
            "SELECT id, email, nickname, role, is_banned, created_at FROM users "
            "WHERE role IN ('admin','sysadmin') ORDER BY role DESC, created_at DESC"
        ).fetchall()
    return ok({
        "items": [
            {
                "id": r["id"], "email": r["email"], "nickname": r["nickname"],
                "role": r["role"], "is_banned": bool(r["is_banned"]), "created_at": r["created_at"],
            }
            for r in rows
        ]
    })


@router.post("/admins/{target_user_id}/role")
def set_admin_role(target_user_id: int, body: PromoteIn, user: dict = Depends(require_root(mutating=True))):
    """root 直接分配/撤销管理员权限。"""
    if target_user_id == user["id"]:
        raise BizError(4001, "不能修改自己的角色")
    with db() as conn:
        target = conn.execute("SELECT id, role FROM users WHERE id=?", (target_user_id,)).fetchone()
        if target is None:
            raise BizError(4040, "用户不存在")
        old_role = target["role"]
        # 保护最后一名 sysadmin，防止管理真空
        if old_role == "sysadmin" and body.role != "sysadmin":
            count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role='sysadmin'").fetchone()["c"]
            if count <= 1:
                raise BizError(4002, "不能降级唯一的系统管理员")
        conn.execute("UPDATE users SET role=? WHERE id=?", (body.role, target_user_id))
        log_admin(conn, user["id"], "Root 调整管理员权限", f"user_id={target_user_id}, old={old_role}, new={body.role}")
    return ok(None, "角色已更新")


@router.post("/admins/{target_user_id}/ban")
def ban_admin(target_user_id: int, user: dict = Depends(require_root(mutating=True))):
    if target_user_id == user["id"]:
        raise BizError(4001, "不能封禁自己")
    with db() as conn:
        target = conn.execute("SELECT id, role FROM users WHERE id=?", (target_user_id,)).fetchone()
        if target is None:
            raise BizError(4040, "用户不存在")
        if target["role"] not in ("admin", "sysadmin"):
            raise BizError(4002, "目标用户不是管理员")
        # 保护最后一名 sysadmin
        if target["role"] == "sysadmin":
            count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role='sysadmin'").fetchone()["c"]
            if count <= 1:
                raise BizError(4002, "不能封禁唯一的系统管理员")
        conn.execute("UPDATE users SET is_banned=1 WHERE id=?", (target_user_id,))
        conn.execute(
            "INSERT INTO bans (ban_type, target, reason, banned_by) VALUES (?,?,?,?)",
            ("account", str(target_user_id), f"Root 封禁管理员 {target_user_id}", user["id"]),
        )
        log_admin(conn, user["id"], "Root 封禁管理员", f"user_id={target_user_id}, role={target['role']}")
    return ok(None, "已封禁")


class ThresholdsIn(BaseModel):
    values: dict[str, str]


UPLOAD_THRESHOLD_KEYS = {
    "threshold_daily_image_bytes", "threshold_upload_source_max_bytes",
    "threshold_upload_min_target_bytes", "threshold_upload_default_target_bytes",
    "threshold_upload_selectable_max_bytes", "threshold_upload_original_max_bytes",
    "threshold_upload_max_dimension", "threshold_upload_max_pixels", "threshold_upload_max_count",
    "threshold_points_upload_quality_choice", "threshold_points_upload_original",
}


def _validate_upload_changes(conn, changes: dict[str, str]) -> None:
    rows = conn.execute(
        "SELECT key, value FROM admin_settings WHERE key IN (" + ",".join("?" * len(UPLOAD_THRESHOLD_KEYS)) + ")",
        tuple(UPLOAD_THRESHOLD_KEYS),
    ).fetchall()
    merged = {key: DEFAULT_THRESHOLDS[key] for key in UPLOAD_THRESHOLD_KEYS}
    merged.update({row["key"]: row["value"] for row in rows})
    merged.update({key: str(value).strip() for key, value in changes.items() if key in UPLOAD_THRESHOLD_KEYS})
    try:
        values = {key: int(merged[key]) for key in UPLOAD_THRESHOLD_KEYS}
    except ValueError as exc:
        raise BizError(4001, "图片上传参数必须为整数") from exc
    point_gate_keys = {"threshold_points_upload_quality_choice", "threshold_points_upload_original"}
    if any(values[key] < 1 for key in UPLOAD_THRESHOLD_KEYS - point_gate_keys) or any(values[key] < 0 for key in point_gate_keys):
        raise BizError(4001, "图片容量参数必须为正整数，积分门槛可为 0")
    if not (
        values["threshold_upload_min_target_bytes"]
        <= values["threshold_upload_default_target_bytes"]
        <= values["threshold_upload_selectable_max_bytes"]
        <= values["threshold_upload_source_max_bytes"]
    ):
        raise BizError(4001, "压缩体积须满足：最小 ≤ 默认 ≤ 可选最大 ≤ 源文件上限")
    if values["threshold_upload_original_max_bytes"] > values["threshold_upload_source_max_bytes"]:
        raise BizError(4001, "原图保留上限不能高于源文件上传上限")
    if values["threshold_points_upload_quality_choice"] > values["threshold_points_upload_original"]:
        raise BizError(4001, "原图积分门槛不能低于自选压缩体积门槛")


@router.get("/thresholds")
def list_thresholds(user: dict = Depends(require_root())):
    """读取所有 root 可配置阈值（含默认值兜底）。"""
    with db() as conn:
        rows = conn.execute(
            "SELECT key, value FROM admin_settings WHERE key LIKE 'threshold\\_%' ESCAPE '\\'"
        ).fetchall()
    db_values = {r["key"]: r["value"] for r in rows}
    data = {key: db_values.get(key, default) for key, default in DEFAULT_THRESHOLDS.items()}
    return ok(data)


@router.put("/thresholds")
def update_thresholds(body: ThresholdsIn, user: dict = Depends(require_root(mutating=True))):
    """批量更新阈值。只更新有效的 threshold_ 前缀键。对值做基本有效性校验。"""
    # 校验值有效性：所有阈值默认值都是数字字符串，值必须为非负整数
    for key, value in body.values.items():
        if not key.startswith("threshold_") or key not in DEFAULT_THRESHOLDS:
            continue
        raw = str(value).strip()
        if not raw:
            raise BizError(4001, f"阈值 {key} 的值不能为空")
        try:
            num = int(raw)
            if num < 0:
                raise ValueError
        except ValueError:
            raise BizError(4001, f"阈值 {key} 的值必须是非负整数，收到：{raw}")
        # 硬下限校验：防止 root 误配 0/过小值导致 DoS 或逻辑崩溃
        min_val = THRESHOLD_MIN_VALUES.get(key)
        if min_val is not None and num < min_val:
            raise BizError(4001, f"阈值 {key} 不能小于 {min_val}（防止服务拒绝/逻辑异常）")
    with db() as conn:
        security_changes = {k: v for k, v in body.values.items() if k in SECURITY_SETTING_KEYS}
        if security_changes:
            validate_security_changes(conn, security_changes)
        upload_changes = {k: v for k, v in body.values.items() if k in UPLOAD_THRESHOLD_KEYS}
        if upload_changes:
            _validate_upload_changes(conn, upload_changes)
        changed = []
        for key, value in body.values.items():
            if not key.startswith("threshold_"):
                continue
            if key not in DEFAULT_THRESHOLDS:
                continue
            old = conn.execute("SELECT value FROM admin_settings WHERE key=?", (key,)).fetchone()
            conn.execute(
                "INSERT INTO admin_settings (key, value, updated_by, updated_at) VALUES (?,?,?,datetime('now','localtime')) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
                (key, str(value), user["id"]),
            )
            changed.append(f"{key}:{old['value'] if old else '<unset>'}->{value}")
        log_admin(conn, user["id"], "Root 更新阈值", "; ".join(changed))
    return ok(None, "阈值已更新")
