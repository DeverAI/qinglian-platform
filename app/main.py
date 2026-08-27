"""应用装配：全局异常兜底（写 Err.log）、按模块开关挂载路由、静态资源托管、Root 账号初始化、服务开关中间件。"""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import config
from .common import BizError
from .ip_protection import inspect_request
from .database import db, init_db
from .errlog import log_exception


SERVICE_PATH_PREFIXES = {
    "/api/tasks": "tasks",
    "/api/forum": "forum",
    "/api/points": "points",
    "/api/knowledge": "knowledge",
    "/api/agent": "ai_agent",
    "/api/emails": "emails",
    "/api/honeypot": "honeypot",
    "/api/chat": "chat",
    "/api/notify": "notify",
    "/api/feed": "feed",
    "/api/news": "news",
    "/api/quiz": "quiz",
}


def _ensure_root_user() -> None:
    """若不存在 root 账号，则根据环境变量 QLKIMI_ROOT_PASSWORD 创建一个（默认密码不可用时跳过）。"""
    from .security import hash_password

    password = os.environ.get("QLKIMI_ROOT_PASSWORD", "").strip()
    if not password or len(password) < 8:
        return
    with db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE role='root' LIMIT 1").fetchone()
        if existing:
            return
        conn.execute(
            "INSERT INTO users (email, password_hash, nickname, role, guardian_declared) VALUES (?,?,?,?,?)",
            ("root@qlkimi.local", hash_password(password), "Root", "root", 1),
        )


def _check_expired_email_reviews() -> None:
    """检查超时 human_pending 邮件，自动触发 AI 多模型辩论。"""
    from .database import db
    from .routers.ai_review import run_ai_debate
    from .security import get_threshold

    hours = get_threshold("threshold_human_pending_hours", 24)
    with db() as conn:
        rows = conn.execute(
            "SELECT id FROM emails WHERE status='human_pending' AND "
            f"updated_at <= datetime('now','localtime','-{hours} hours')"
        ).fetchall()
    for row in rows:
        try:
            run_ai_debate(row["id"])
        except Exception as exc:
            from .errlog import log_error
            log_error("email_review.debate", f"email_id={row['id']}: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if config.ENVIRONMENT == "production" and config.SECRET_KEY == "dev-secret-please-change-in-production":
        raise RuntimeError("生产环境必须通过 QLKIMI_SECRET 配置高强度随机密钥")
    init_db()
    _ensure_root_user()
    from . import seed

    seed.seed_if_empty()

    # 首页每日简报 + 新闻栏：丢到后台线程异步生成，不阻塞服务启动。
    # AI 未配置时很快完成；AI 已配置但不可达时，后台线程最长阻塞 ~90s 自行超时退出。
    import threading

    def _bg_init():
        try:
            from .routers.notify import _generate_daily_briefing
            _generate_daily_briefing()
        except Exception as exc:
            from .errlog import log_error
            log_error("lifespan.briefing", repr(exc))
        try:
            from .routers.news import _collect_news
            _collect_news()
        except Exception as exc:
            from .errlog import log_error
            log_error("lifespan.news", repr(exc))
        # T1.7: 每日 AI 巡查
        try:
            from .board_lifecycle import run_daily_patrol
            run_daily_patrol()
        except Exception as exc:
            from .errlog import log_error
            log_error("lifespan.patrol", repr(exc))
        # T2.1+T2.2: 讨论版生命周期检查
        try:
            from .board_lifecycle import run_daily_lifecycle
            run_daily_lifecycle()
        except Exception as exc:
            from .errlog import log_error
            log_error("lifespan.lifecycle", repr(exc))
        # T3.2d: 检查超时 human_pending 邮件，自动触发 AI 辩论
        try:
            _check_expired_email_reviews()
        except Exception as exc:
            from .errlog import log_error
            log_error("lifespan.email_review", repr(exc))

    threading.Thread(target=_bg_init, daemon=True, name="bg-init").start()
    yield


app = FastAPI(title="青联合规监督社区", docs_url=None, redoc_url=None, lifespan=lifespan)

if config.TRUSTED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(config.TRUSTED_HOSTS))


@app.middleware("http")
async def security_boundary(request: Request, call_next):
    """限制请求体，并为 API 与静态页面补齐浏览器安全边界。"""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > config.MAX_REQUEST_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={"code": 4130, "message": "请求内容过大", "data": None},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"code": 4000, "message": "Content-Length 无效", "data": None},
            )
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
        "img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.middleware("http")
async def ip_protection_boundary(request: Request, call_next):
    client = request.client.host if request.client else ""
    if client:
        inspect_request(client, request.url.path)
    return await call_next(request)


@app.middleware("http")
async def risk_control_boundary(request: Request, call_next):
    """风控边界中间件：服务器后台监控工具的统一入口。

    职责（用户需求）：
    1. 拦截后台管理台路径（/api/admin、/api/root、/api/risk）的所有访问。
    2. 封禁 IP 直接阻断访问（4036），并记录拦截事件。
    3. 每次操作都记录 actor/IP/UA/方法/路径/风险等级到审计日志（DB+文件+Err.log 三处冗余）。
    4. 高危操作（批量删除/角色变更/封禁/服务开关/阈值修改）或异常 IP 自动触发 2FA（4035）：
       - 前端需先调 /api/risk/2fa/verify 通过验证，再携带 X-2FA-Token 头重试原请求。
       - 已验证令牌绑定 actor_id，5 分钟内可复用（避免每个高危操作都重验）。
       - danger 级（单条删除/设置修改）在信任 IP 下不触发，仅异常 IP 时触发。
       - 异常 IP 场景验证码不得本地返回（防中间人），邮件未配置则直接拦截（4037）。
    5. 2FA 自身接口（/api/risk/2fa/*）豁免 2FA 校验，但仍受封禁 IP 阻断与日志记录约束。
    """
    from .risk_control import (
        BACKEND_PATH_PREFIXES,
        classify_risk,
        is_2fa_verified,
        is_ip_banned,
        is_ip_suspicious,
        issue_2fa_challenge,
        log_action,
    )
    from .security import decode_token

    path = request.url.path
    method = request.method
    client_ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")[:300]
    is_backend = any(path.startswith(p) for p in BACKEND_PATH_PREFIXES)
    two_fa_exempt = path.startswith("/api/risk/2fa/")

    # 1. 封禁 IP 直接阻断后台访问
    if is_backend and client_ip and is_ip_banned(client_ip):
        try:
            log_action(
                None, "banned", client_ip, ua, method, path,
                action="blocked_banned_ip", risk_level="critical",
                detail=f"已封禁IP尝试访问 {method} {path}",
            )
        except Exception as exc:
            log_exception("risk_control.middleware.ban_log", exc)
        return JSONResponse(
            status_code=403,
            content={"code": 4036, "message": "该 IP 已被风控封禁，禁止访问后台管理台", "data": None},
        )

    # 2. 轻量解析当前用户（仅用于日志记录，真实鉴权由路由依赖完成）
    actor_id = None
    actor_role = ""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        try:
            payload = decode_token(auth[7:].strip(), "access")
            actor_id = payload.get("sub")
            actor_role = payload.get("role", "")
        except Exception:
            pass

    # 3. 2FA 校验：仅后台变更类请求（2FA 接口自身豁免）
    #    触发条件：critical 级操作（批量删除/角色变更/封禁/服务开关/阈值修改）或异常 IP。
    #    danger 级（单条删除/设置修改）在信任 IP 下不触发，避免日常操作频繁打扰。
    mutating = method in ("POST", "PUT", "PATCH", "DELETE")
    if is_backend and mutating and not two_fa_exempt:
        risk = classify_risk(method, path, "")
        suspicious, sip_reason = is_ip_suspicious(client_ip, actor_id)
        need_2fa = risk == "critical" or suspicious
        if need_2fa:
            two_fa_token = request.headers.get("x-2fa-token", "")
            if not is_2fa_verified(two_fa_token, actor_id):
                # 触发新挑战
                reason = f"高危操作（{risk}）：{method} {path}" if risk == "critical" else sip_reason
                challenge = issue_2fa_challenge(actor_id, client_ip, reason)
                # 安全策略：异常 IP 场景验证码不得本地返回（防中间人）
                # issue_2fa_challenge 已配置邮箱则发邮件不返回明文；未配置则本地返回。
                # 异常 IP 且未走邮件 → 直接拦截，不把验证码暴露给可疑来源。
                if suspicious and challenge.get("sent_via") != "email":
                    try:
                        log_action(
                            actor_id, actor_role, client_ip, ua, method, path,
                            action="blocked_suspicious_no_email",
                            detail=f"异常IP且未配置2FA邮件，操作已拦截：{sip_reason}",
                            risk_level="critical",
                        )
                    except Exception as exc:
                        log_exception("risk_control.middleware.susp_log", exc)
                    return JSONResponse(
                        status_code=403,
                        content={
                            "code": 4037,
                            "message": "异常 IP 操作已拦截：检测到不常见 IP，且系统未配置 2FA 邮件，无法安全送达验证码。请联系管理员在服务器本地处理。",
                            "data": {"reason": sip_reason, "ip": client_ip},
                        },
                    )
                try:
                    log_action(
                        actor_id, actor_role, client_ip, ua, method, path,
                        action="2fa_required", detail=reason,
                        risk_level="warn", triggered_2fa=True,
                    )
                except Exception as exc:
                    log_exception("risk_control.middleware.trigger_log", exc)
                return JSONResponse(
                    status_code=403,
                    content={
                        "code": 4035,
                        "message": "该操作需要二次验证：" + reason,
                        "data": {
                            "challenge_token": challenge["challenge_token"],
                            "code": challenge.get("code", ""),
                            "expires_at": challenge["expires_at"],
                            "sent_via": challenge["sent_via"],
                            "reason": reason,
                        },
                    },
                )

    # 4. 执行请求
    response = await call_next(request)

    # 5. 记录操作（后台路径与 2FA 接口均记录）
    if is_backend or two_fa_exempt:
        try:
            log_action(
                actor_id, actor_role, client_ip, ua, method, path,
                detail=request.url.query or "",
            )
        except Exception as exc:
            log_exception("risk_control.middleware.log", exc)

    return response


@app.middleware("http")
async def catch_all(request: Request, call_next):
    """运行时错误兜底：一律记录 Err.log，不得吞没。"""
    try:
        return await call_next(request)
    except BizError:
        raise
    except Exception as exc:
        log_exception("http", exc)
        return JSONResponse(
            status_code=500,
            content={"code": 500, "message": "服务器内部错误", "data": None},
        )


@app.exception_handler(BizError)
async def biz_error_handler(request: Request, exc: BizError):
    return JSONResponse(content={"code": exc.code, "message": exc.message, "data": None})


@app.middleware("http")
async def service_switch_guard(request: Request, call_next):
    """Root 动态服务开关：关闭时拦截对应前缀请求（认证/管理/配置接口除外）。"""
    path = request.url.path
    if path.startswith("/api/") and not any(
        path.startswith(p) for p in ("/api/auth", "/api/admin", "/api/root", "/api/config/modules")
    ):
        service = None
        for prefix, name in SERVICE_PATH_PREFIXES.items():
            if path.startswith(prefix):
                service = name
                break
        if service:
            with db() as conn:
                row = conn.execute("SELECT value FROM admin_settings WHERE key=?", (f"svc_{service}",)).fetchone()
            if row and row["value"] == "0":
                return JSONResponse(
                    status_code=503,
                    content={"code": 5030, "message": "该服务当前已关闭", "data": None},
                )
    return await call_next(request)


# ---------------- 路由（按模块开关挂载，关闭即隐藏接口） ----------------
from .routers import auth  # noqa: E402

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])

if config.ENABLE_TASKS:
    from .routers import tasks

    app.include_router(tasks.router, prefix="/api/tasks", tags=["tasks"])

if config.ENABLE_FORUM:
    from .routers import forum

    app.include_router(forum.router, prefix="/api/forum", tags=["forum"])

if config.ENABLE_POINTS:
    from .routers import points

    app.include_router(points.router, prefix="/api/points", tags=["points"])

if config.ENABLE_KNOWLEDGE:
    from .routers import knowledge

    app.include_router(knowledge.router, prefix="/api/knowledge", tags=["knowledge"])

from .routers import admin  # noqa: E402

app.include_router(admin.router, prefix="/api/admin", tags=["admin"])

# Root 专属接口始终挂载
from .routers import root  # noqa: E402

app.include_router(root.router, prefix="/api/root", tags=["root"])

# 风控监控后台（root 专属）：仪表盘/审计日志/IP 封禁与白名单/2FA 校验
from .routers import risk_control  # noqa: E402

app.include_router(risk_control.router, prefix="/api/risk", tags=["risk"])

if config.ENABLE_HONEYPOT:
    from .routers import honeypot

    app.include_router(honeypot.router, prefix="/api/honeypot", tags=["honeypot"])

if config.ENABLE_AI_AGENT:
    from .routers import agent

    app.include_router(agent.router, prefix="/api/agent", tags=["agent"])

if config.ENABLE_EMAILS:
    from .routers import emails

    app.include_router(emails.router, prefix="/api/emails", tags=["emails"])

# 私信/群聊默认开启，不受静态模块开关限制（但受 root 动态服务开关影响）
from .routers import chat  # noqa: E402

app.include_router(chat.router, prefix="/api/chat", tags=["chat"])

# 首页每日简报 + 系统通知：默认开启，受 root 动态服务开关影响
from .routers import notify  # noqa: E402

app.include_router(notify.router, prefix="/api/notify", tags=["notify"])

# 首页消息流 + 新闻栏 + 条文背诵游戏：默认开启，受 root 动态服务开关影响
from .routers import feed, news, quiz  # noqa: E402

app.include_router(feed.router, prefix="/api/feed", tags=["feed"])
app.include_router(news.router, prefix="/api/news", tags=["news"])
app.include_router(quiz.router, prefix="/api/quiz", tags=["quiz"])


@app.get("/api/config/modules")
def module_switches():
    """下发模块开关，前端据此隐藏入口。"""
    return {
        "code": 0,
        "message": "success",
        "data": {
            "tasks": config.ENABLE_TASKS,
            "forum": config.ENABLE_FORUM,
            "points": config.ENABLE_POINTS,
            "knowledge": config.ENABLE_KNOWLEDGE,
            "ai_agent": config.ENABLE_AI_AGENT,
            "emails": config.ENABLE_EMAILS,
        },
    }


# ---------------- 静态资源 ----------------
config.STATIC_DIR.mkdir(parents=True, exist_ok=True)
config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(config.STATIC_DIR / "index.html")


app.mount("/uploads", StaticFiles(directory=config.UPLOAD_DIR), name="uploads")
app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")
# 根路径静态托管：/login.html /forum.html 等页面直接访问
app.mount("/", StaticFiles(directory=config.STATIC_DIR, html=True), name="root")
