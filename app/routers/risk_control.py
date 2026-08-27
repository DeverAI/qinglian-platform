"""风控监控后台 API（root 专属）。

仅 root 账号可访问。提供：
- 仪表盘统计 / 审计日志查询 / IP 封禁列表 / IP 白名单管理
- 2FA 触发与校验（供前端在危险操作前调用）
- IP 解封 / 白名单增删

注：后台访问拦截与操作自动记录由 main.py 的 risk_control_boundary 中间件完成，
本路由仅提供查询与管理能力。
"""
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from ..common import BizError, ok
from ..risk_control import (
    add_whitelist,
    ban_ip,
    get_audit_logs,
    get_ip_bans,
    get_stats,
    get_whitelist,
    issue_2fa_challenge,
    remove_whitelist,
    unban_ip,
    verify_2fa,
)
from ..security import get_current_user, require_root

router = APIRouter()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


class Verify2faIn(BaseModel):
    challenge_token: str = Field(min_length=10)
    code: str = Field(min_length=4, max_length=10)


class WhitelistIn(BaseModel):
    ip: str = Field(min_length=3, max_length=64)
    label: str = Field(default="", max_length=100)


class UnbanIn(BaseModel):
    ip: str = Field(min_length=3, max_length=64)


class Trigger2faIn(BaseModel):
    method: str = Field(default="", max_length=10)
    path: str = Field(default="", max_length=500)
    action: str = Field(default="", max_length=64)


@router.get("/stats")
def stats(user: dict = Depends(require_root())):
    """风控仪表盘统计。"""
    return ok(get_stats())


@router.get("/logs")
def logs(
    page: int = 1,
    limit: int = 50,
    risk_level: str = "",
    actor_ip: str = "",
    action: str = "",
    user: dict = Depends(require_root()),
):
    """查询审计日志（支持按风险等级/IP/操作筛选）。"""
    return ok(get_audit_logs(page=page, limit=limit, risk_level=risk_level, actor_ip=actor_ip, action=action))


@router.get("/ip-bans")
def ip_bans(page: int = 1, limit: int = 50, user: dict = Depends(require_root())):
    """查询 IP 封禁列表。"""
    return ok(get_ip_bans(page=page, limit=limit))


@router.post("/ip-bans/{ip}/lift")
def lift_ip_ban(ip: str, user: dict = Depends(require_root(mutating=True))):
    """解封 IP（仅 root）。"""
    unban_ip(ip, user["id"])
    return ok(None, "IP 已解封")


@router.post("/ip-bans/manual")
def manual_ban_ip(body: UnbanIn, user: dict = Depends(require_root(mutating=True))):
    """手动封禁 IP（仅 root）。"""
    ban_ip(body.ip, f"root 手动封禁", banned_by=user["id"])
    return ok(None, "IP 已封禁")


@router.get("/whitelist")
def whitelist(user: dict = Depends(require_root())):
    """查询 IP 白名单。"""
    return ok(get_whitelist())


@router.post("/whitelist")
def add_to_whitelist(body: WhitelistIn, user: dict = Depends(require_root(mutating=True))):
    """添加 IP 到白名单。"""
    add_whitelist(body.ip, body.label)
    return ok(None, "已添加到白名单")


@router.delete("/whitelist/{ip}")
def remove_from_whitelist(ip: str, user: dict = Depends(require_root(mutating=True))):
    """从白名单移除 IP。"""
    remove_whitelist(ip)
    return ok(None, "已从白名单移除")


@router.post("/2fa/trigger")
def trigger_2fa(body: Trigger2faIn, request: Request, user: dict = Depends(get_current_user)):
    """触发 2FA 挑战（任意已登录管理员可触发，用于危险操作前的二次验证）。

    返回 challenge_token + 验证码（sent_via=local 时明文返回，email 时不返回）。
    """
    # 仅管理员/root 可触发（普通用户不需要 2FA，他们的敏感操作由 CSRF+握手守卫保护）
    if user["role"] not in ("admin", "sysadmin", "root"):
        raise BizError(4030, "权限不足")
    reason = f"{body.method} {body.path} {body.action}".strip() or "手动触发"
    result = issue_2fa_challenge(user["id"], _client_ip(request), reason)
    return ok(result, "2FA 挑战已签发")


@router.post("/2fa/verify")
def verify_2fa_code(body: Verify2faIn, request: Request, user: dict = Depends(get_current_user)):
    """校验 2FA 验证码。"""
    result = verify_2fa(body.challenge_token, body.code, _client_ip(request))
    return ok(result, result["message"])
