"""蜜罐诱饵 API：记录伪造 Cookie / 前端验证的访问尝试。"""
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from ..common import ok
from ..database import db

router = APIRouter()


class HoneypotLoginIn(BaseModel):
    username: str = Field(default="", max_length=100)
    password: str = Field(default="", max_length=100)
    role: str = Field(default="", max_length=50)


@router.post("/login")
def honeypot_login(request: Request, body: HoneypotLoginIn):
    """伪造的诱饵登录接口：记录攻击者 IP、Cookie、payload，返回虚假数据。"""
    ip = request.client.host if request.client else ""
    cookie = str(request.headers.get("cookie", ""))
    payload = body.model_dump_json()
    with db() as conn:
        conn.execute(
            "INSERT INTO honeypot_logs (ip, path, cookie_data, payload, detail) VALUES (?,?,?,?,?)",
            (ip, "/api/honeypot/login", cookie, payload, f"role={body.role}"),
        )
    # 返回虚假成功，诱导攻击者继续
    return ok({"token": "fake-admin-token-0000", "role": "admin"}, "登录成功")


@router.get("/panel")
def honeypot_panel(request: Request):
    """伪造的管理面板数据接口。"""
    ip = request.client.host if request.client else ""
    cookie = str(request.headers.get("cookie", ""))
    with db() as conn:
        conn.execute(
            "INSERT INTO honeypot_logs (ip, path, cookie_data, payload, detail) VALUES (?,?,?,?,?)",
            (ip, "/api/honeypot/panel", cookie, "", "访问伪造管理面板"),
        )
    return ok({"users": 9999, "reports": 0, "suspicious": 0}, "面板数据加载成功")
