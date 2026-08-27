import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from jinja2 import Environment, FileSystemLoader, select_autoescape
from models.database import init_db
from routers import ocr, questions, papers, prompts, settings, profile, knowledge_base, diagnose, sessions, banks
from routers.notes import router as notes_router
from routers.gallery import router as gallery_router
from routers.configs import router as configs_router
from config import STORAGE_DIR, load_settings, ENABLE_SEARCH, ENABLE_CORRECT, CORS_ALLOWED_ORIGINS
from logger import get_logger, log_error
from services.diagram_service import _is_valid_question_id as _is_valid_diagram_qid, diagram_service
import os
import re
import json

logger = get_logger()

CSP_HEADER = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: blob:; "
    "font-src 'self' data: https://cdn.jsdelivr.net; "
    "connect-src 'self'; "
    "frame-src 'self'"
)

env = Environment(
    loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")),
    autoescape=select_autoescape(['html', 'xml']),
    auto_reload=True,
    cache_size=0,
)


def render_template(name: str, **ctx) -> HTMLResponse:
    tmpl = env.get_template(name)
    ctx.setdefault("enable_search", ENABLE_SEARCH)
    ctx.setdefault("enable_correct", ENABLE_CORRECT)
    return HTMLResponse(tmpl.render(ctx))


async def _night_note_patrol_loop():
    """夜间自动笔记巡逻：在配置的时间窗口内自动执行笔记去重整合 + 题库经典模型收集 + 题库巡检"""
    import asyncio
    from datetime import datetime, timedelta
    from config import load_settings
    _last_patrol_date = None
    while True:
        try:
            await asyncio.sleep(60)  # 每分钟检查一次
            s = load_settings()
            if not s.get("night_patrol_enabled", True):
                continue
            now = datetime.utcnow() + timedelta(hours=8)  # UTC+8
            today_str = now.strftime("%Y-%m-%d")
            patrol_start = s.get("night_patrol_start", "01:00")
            patrol_end = s.get("night_patrol_end", "05:00")
            now_time = now.strftime("%H:%M")
            # Handle overnight range (e.g., 22:00-06:00)
            in_window = False
            if patrol_start <= patrol_end:
                in_window = patrol_start <= now_time <= patrol_end
            else:
                in_window = now_time >= patrol_start or now_time <= patrol_end
            if not in_window:
                continue
            if _last_patrol_date == today_str:
                continue  # 今天已执行过
            _last_patrol_date = today_str
            logger.info("Nightly note patrol: auto-organize + classic model collection started")
            # 1. 收集题库中的经典模型标签（如一线三等角、手拉手模型等）
            classic_models = await _collect_classic_models()
            # 保存到缓存供笔记分类AI使用
            try:
                from services.note_service import _save_classic_models_cache
                _save_classic_models_cache(classic_models)
            except Exception:
                pass
            # 2. 笔记自动整理（注入经典模型上下文）
            from routers.notes import _do_auto_organize
            result = await _do_auto_organize(classic_models_context=classic_models)
            logger.info("Nightly note patrol: %s", result.get("message", "done"))
            # 3. 发送系统消息
            try:
                from services.audit_service import add_system_message
                model_hint = f"（含 {len(classic_models)} 个经典模型）" if classic_models else ""
                add_system_message("system", "夜间笔记整理完成",
                                 f"笔记去重整合已完成{model_hint}。")
            except Exception:
                pass
        except asyncio.CancelledError:
            logger.info("Nightly note patrol scheduler cancelled")
            break
        except Exception as e:
            logger.warning("Nightly note patrol error: %s", str(e)[:200])


async def _collect_classic_models() -> list[str]:
    """从题库中收集经典数学模型/物理模型标签"""
    try:
        from models.database import async_session as _db_s
        from models.models import Question
        from sqlalchemy import select
        CLASSIC_KEYWORDS = [
            "一线三等角", "手拉手模型", "将军饮马", "胡不归", "阿氏圆",
            "瓜豆原理", "K型图", "等积变换", "截长补短", "倍长中线",
            "旋转模型", "翻折模型", "中点模型", "角平分线模型", "弦图",
            "半角模型", "三线合一", "十字模型", "费马点", "托勒密",
        ]
        found = set()
        async with _db_s() as db:
            r = await db.execute(select(Question.knowledge_tags).where(Question.status == "done"))
            rows = r.fetchall()
            for row in rows:
                tags = row[0] if row[0] else []
                if isinstance(tags, list):
                    for tag in tags:
                        tag_lower = tag.strip().lower()
                        for kw in CLASSIC_KEYWORDS:
                            if kw in tag or kw in tag_lower:
                                found.add(kw)
        return list(found)[:20]
    except Exception as e:
        logger.warning("Classic model collection failed: %s", e)
        return []


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    try:
        from routers.prompts import init_default_prompts
        from models.database import async_session
        async with async_session() as db:
            await init_default_prompts(db)
    except Exception as e:
        logger.warning("Prompt init skipped: %s", e)
    try:
        from routers.ocr import resume_pending_tasks
        await resume_pending_tasks()
    except Exception as e:
        log_error("lifespan", f"Failed to resume pending tasks: {e}")
        logger.warning("Failed to resume pending tasks, continuing...", exc_info=True)
    # Auto-generate daily quote at startup
    try:
        from services.audit_service import _generate_daily_quote
        await _generate_daily_quote()
    except Exception as e:
        logger.warning("Daily quote startup generation failed: %s", e)

    # Start nightly audit scheduler
    try:
        from services.audit_service import start_nightly_scheduler
        import asyncio
        asyncio.create_task(start_nightly_scheduler())
        logger.info("Nightly audit scheduler started")
    except Exception as e:
        logger.warning("Failed to start nightly audit scheduler: %s", e)

    # Start nightly note patrol scheduler
    try:
        import asyncio
        asyncio.create_task(_night_note_patrol_loop())
        logger.info("Nightly note patrol scheduler started")
    except Exception as e:
        logger.warning("Failed to start nightly note patrol: %s", e)
    yield


app = FastAPI(title="学习搭子 - 题目本Agent", version="2.0.0", lifespan=lifespan)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """捕获未处理异常并写入 Err.log，避免前端收到 HTML/纯文本 Internal Server Error。"""
    from fastapi.responses import JSONResponse
    log_error("unhandled_exception", f"{request.method} {request.url.path}: {exc}")
    return JSONResponse(status_code=500, content={"detail": "服务器内部错误，请查看 Err.log"})

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)


@app.middleware("http")
async def add_csp_header(request: Request, call_next):
    response = await call_next(request)
    ct = response.headers.get("content-type", "")
    if "text/html" in ct:
        response.headers["Content-Security-Policy"] = CSP_HEADER
    return response

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/storage", StaticFiles(directory=STORAGE_DIR), name="storage")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

app.include_router(ocr.router)
app.include_router(questions.router)
app.include_router(papers.router)
app.include_router(prompts.router)
app.include_router(settings.router)
app.include_router(profile.router)
app.include_router(knowledge_base.router)
app.include_router(diagnose.router)
app.include_router(diagnose.diag_router)
app.include_router(sessions.router)
app.include_router(banks.router)
if ENABLE_SEARCH:
    from routers import search
    app.include_router(search.router)
if ENABLE_CORRECT:
    from routers.correction import router as correction_router
    app.include_router(correction_router)
app.include_router(notes_router)
app.include_router(gallery_router)
app.include_router(configs_router)



@app.get("/api/system-messages")
async def get_system_messages(limit: int = 20):
    from services.audit_service import get_system_messages
    return {"messages": get_system_messages(limit)}


@app.post("/api/system-messages/read")
async def mark_messages_read():
    from services.audit_service import mark_messages_read
    mark_messages_read()
    return {"message": "已标记已读"}


@app.delete("/api/system-messages/{index:path}")
async def delete_system_message(index: str):
    """手动删除指定系统消息；index为'all'时清空全部"""
    from services.audit_service import _load_system_messages, _save_system_messages
    msgs = _load_system_messages()
    if index == "all":
        _save_system_messages([])
        return {"message": "已清空所有系统消息"}
    idx = int(index)
    if 0 <= idx < len(msgs):
        msgs.pop(idx)
        _save_system_messages(msgs)
        return {"message": "已删除"}
    return {"message": "索引无效"}, 404


# --- Manual trigger for audit/rewrite ---
@app.post("/api/audit/trigger")
async def trigger_audit():
    """手动触发全库巡检"""
    from services.audit_service import run_full_audit
    try:
        count = await run_full_audit()
        return {"message": f"巡检完成，发现 {count} 项问题"}
    except Exception as e:
        return {"message": f"巡检失败: {str(e)[:200]}"}


@app.post("/api/audit/rewrite")
async def trigger_rewrite():
    """手动触发自动重写"""
    from services.audit_service import run_auto_rewrite
    try:
        await run_auto_rewrite()
        return {"message": "重写任务已执行"}
    except Exception as e:
        return {"message": f"重写失败: {str(e)[:200]}"}


# --- Page Routes ---
from datetime import date, datetime

_quote_cache = {"quote": "Hello World —— 学习搭子，今日启航。", "has_api": False}

QUOTE_DIR = os.path.join(STORAGE_DIR, "quotes")
os.makedirs(QUOTE_DIR, exist_ok=True)


def _get_quote_filepath() -> str:
    today_str = date.today().strftime("%Y-%m-%d")
    return os.path.join(QUOTE_DIR, f"quote_{today_str}.json")


def _load_quote_from_file() -> dict | None:
    path = _get_quote_filepath()
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("quote"):
                return data
    except (json.JSONDecodeError, IOError, OSError):
        pass
    return None


def _save_quote_to_file(data: dict):
    path = _get_quote_filepath()
    try:
        data["date"] = date.today().strftime("%Y-%m-%d")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
    except (IOError, OSError) as e:
        logger.warning("Failed to save daily quote: %s", e)


async def _gen_quote() -> dict:
    """Generate a daily quote with web search, using system time."""
    s = load_settings()
    zp_key = s.get("zhipuai_api_key", "")
    if not zp_key:
        logger.warning("GLM key not configured for daily quote")
        return {"quote": "Hello World —— 学习搭子，今日启航。", "source": "", "font": ""}
    zp_base = s.get("zhipuai_base_url", "https://open.bigmodel.cn/api/paas/v4").rstrip('/')
    if not zp_base.endswith('/chat/completions'):
        zp_base += '/chat/completions'
    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    weekday = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"][now.weekday()]
    month_day = f"{now.month}月{now.day}日"
    topic = s.get("quote_topic", "").strip()
    topic_hint = ""
    if topic:
        topic_hint = f"主题偏好：{topic}。优先搜索该领域历史上的今天重大事件或人物。"
    prompt = (
        f"当前系统时间：{today} {now.strftime('%H:%M')}，{weekday}，{month_day}。\n"
        f"请联网搜索{today}这一天（历史上的今天）发生的重要事件、诞生或逝世的名人。"
        f"{topic_hint}\n"
        f"如果这天是某位名人（如孔子、爱因斯坦、苏轼、鲁迅等）的诞辰或逝世日，请选取该人物本人的一句与教育、学习、成长相关的名言。\n"
        f"如果不是名人纪念日，则选取历史上今天发生的、与学习和成长有关的重大事件，用一句话概括其精神（50字以内）。\n\n"
        f"请输出一个JSON对象（不要markdown代码块），有三个字段：\n"
        f"\"quote\": 名言/精神概括（纯文本，50字以内），\n"
        f"\"source\": 出处。人名只写名字（如'鲁迅'、'爱因斯坦'，不要加'诞辰''逝世'等后缀）；事件只写事件名（如'五四运动'）。15字以内。\n"
        f"\"font\": CSS字体名。古文/诗词→KaiTi；现代文→留空；外国文→FangSong。\n"
        f"只输出JSON，不要任何额外文字。"
    )
    payload = {
        "model": "glm-4-flash",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.9,
        "max_tokens": 300,
        "tools": [{"type": "web_search", "web_search": {"enable": True}}]
    }
    try:
        import httpx as _h
        async with _h.AsyncClient(timeout=_h.Timeout(60)) as c:
            resp = await c.post(
                zp_base,
                json=payload,
                headers={"Authorization": f"Bearer {zp_key}", "Content-Type": "application/json"}
            )
            if resp.status_code == 200:
                body = resp.json()
                choice = body["choices"][0]
                raw = choice["message"]["content"].strip()
                # Strip markdown code fences robustly
                if raw.startswith('```'):
                    raw = raw.split('\n', 1)[-1] if '\n' in raw else raw[3:]
                if raw.endswith('```'):
                    raw = raw.rsplit('\n', 1)[0] if '\n' in raw else raw[:-3]
                raw = raw.strip()
                try:
                    data = json.loads(raw)
                    q = str(data.get("quote", "")).strip('"').strip("'")[:120]
                    src = str(data.get("source", ""))[:20]
                    font = str(data.get("font", ""))[:30]
                    if q:
                        _save_quote_to_file({"quote": q, "source": src, "font": font})
                        return {"quote": q, "source": src, "font": font}
                except json.JSONDecodeError:
                    q = raw.strip('"').strip("'")[:120]
                    if q:
                        _save_quote_to_file({"quote": q, "source": "", "font": ""})
                        return {"quote": q, "source": "", "font": ""}
    except Exception as e:
        logger.warning("GLM daily quote failed: %s", e)
    return {"quote": "Hello World —— 学习搭子，今日启航。", "source": "", "font": ""}


@app.get("/api/daily-quote")
async def daily_quote():
    global _quote_cache
    # Check if today's quote exists on disk
    cached = _load_quote_from_file()
    if cached and cached.get("quote"):
        _quote_cache = {"quote": cached["quote"], "source": cached.get("source", ""), "font": cached.get("font", ""), "has_api": True}
        return _quote_cache

    # Generate new quote
    s = load_settings()
    if s.get("zhipuai_api_key"):
        data = await _gen_quote()
        _quote_cache = {"quote": data["quote"], "source": data.get("source", ""), "font": data.get("font", ""), "has_api": True}
    else:
        _quote_cache = {"quote": "Hello World —— 学习搭子，今日启航。", "source": "", "font": "", "has_api": False}
    
    # Broadcast as system message
    try:
        from services.audit_service import add_system_message
        add_system_message("daily_quote", "每日一言", _quote_cache["quote"])
    except Exception:
        pass
    
    return _quote_cache

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "学习搭子Agent v2"}


@app.post("/api/diagram/generate")
async def api_generate_diagram(data: dict):
    """生成新图。若请求包含 spec_override（来自编辑器手动摆放），优先按该 spec 渲染保存。"""
    from services.diagram_service import diagram_service
    question_id = data.get("question_id", "")
    prompt = data.get("prompt", "")
    index = data.get("index", 0)
    spec_override = data.get("spec_override")
    if not question_id or not prompt:
        raise HTTPException(400, "需要 question_id 和 prompt")
    if not _is_valid_diagram_qid(question_id):
        raise HTTPException(400, f"非法的 question_id: {question_id}")
    path = await diagram_service.generate_diagram(question_id, prompt, index, spec_override=spec_override)
    if path:
        return {"path": path}
    raise HTTPException(500, "生成图失败")


@app.post("/api/diagram/insert")
async def api_insert_diagram(data: dict):
    """在已有图上插入新组件"""
    from services.diagram_service import diagram_service
    question_id = data.get("question_id", "")
    prompt = data.get("prompt", "")
    index = data.get("index", 0)
    if not question_id or not prompt:
        raise HTTPException(400, "需要 question_id 和 prompt")
    if not _is_valid_diagram_qid(question_id):
        raise HTTPException(400, f"非法的 question_id: {question_id}")
    path = await diagram_service.insert_diagram(question_id, prompt, index)
    if path:
        return {"path": path}
    raise HTTPException(500, "插入图失败")


@app.get("/api/diagram/check/{question_id}/{index}")
async def api_check_diagram_freshness(question_id: str, index: int):
    """检查图是否最新（时间戳校验）"""
    from services.diagram_service import diagram_service
    if not _is_valid_diagram_qid(question_id):
        raise HTTPException(400, f"非法的 question_id: {question_id}")
    fresh = await diagram_service.check_diagram_freshness(question_id, index)
    return {"fresh": fresh}


@app.post("/api/diagram/calibrate")
async def api_calibrate(data: dict):
    """记录一次手动调整样本，返回校准结果"""
    from services.calibration_service import record_adjustment
    components = data.get("components", [])
    if not components:
        raise HTTPException(400, "需要 components 列表")
    result = record_adjustment(components)
    return result


@app.post("/api/diagram/calibration-check")
async def api_calibration_check(data: dict):
    """查询某组合的校准状态"""
    from services.calibration_service import get_calibration
    components = data.get("components", [])
    return get_calibration(components)


@app.post("/api/diagram/render-svg")
async def api_render_svg(data: dict):
    """根据spec实时渲染SVG（用于编辑器导出真实SVG）"""
    from services.diagram_components import assemble
    try:
        spec = data.get("spec", {})
        svg = diagram_service._sanitize_svg(assemble(spec))
        return {"svg": svg}
    except Exception as e:
        raise HTTPException(500, f"SVG渲染失败: {str(e)}")


@app.post("/api/gallery/render-previews")
async def api_render_previews():
    """批量渲染所有组件的真实SVG预览（不含坐标偏移，供编辑器画布直接嵌入）"""
    from services.diagram_components.assembler import _render_component, get_component
    from services.diagram_components import COMPONENT_DB
    previews = {}
    for ctype, cdef in COMPONENT_DB.items():
        comp = {
            "type": ctype,
            "x": 0, "y": 0,
            "w": cdef["default_w"],
            "h": cdef["default_h"],
            "label": "",
        }
        try:
            svg_fragment = _render_component(comp)
            if svg_fragment:
                # Wrap in proper SVG so frontend can innerHTML it
                w, h = cdef["default_w"], cdef["default_h"]
                previews[ctype] = diagram_service._sanitize_svg(
                    f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}">'
                    f'{svg_fragment}</svg>'
                )
        except Exception as e:
            pass
    return {"previews": previews}


@app.post("/api/gallery/render-component")
async def api_render_single_component(data: dict):
    """渲染单个组件（可带实例级渲染参数，供编辑器摆法预览刷新）

    请求: {"type": "iron_stand", "w": 40, "h": 80, "has_ring": true, "clamp_y": 42, ...}
    返回: {"svg": "<svg ...>fragment</svg>"}
    """
    from services.diagram_components.assembler import _render_component, get_component
    raw_type = data.get("type")
    ctype = raw_type.strip() if isinstance(raw_type, str) else ""
    cdef = get_component(ctype) if ctype else None
    if not cdef:
        raise HTTPException(400, f"未知组件类型: {ctype or '(空)'}")
    try:
        w = float(data.get("w") or cdef["default_w"])
        h = float(data.get("h") or cdef["default_h"])
    except (TypeError, ValueError):
        w, h = cdef["default_w"], cdef["default_h"]
    w = max(1.0, min(2000.0, w))
    h = max(1.0, min(2000.0, h))
    # 透传实例级渲染参数（白名单，与 _render_component 合并键一致）
    comp = {"type": ctype, "x": 0, "y": 0, "w": w, "h": h, "label": data.get("label", "")}
    for k in ("liquid", "filled", "water_level", "angle", "clamp_y", "clamp_w",
              "a", "b", "c", "k"):
        if k in data:
            comp[k] = data[k]
    # 布尔键显式归一（防字符串 "false" 被当作真值）
    for k in ("has_ring", "has_clamp"):
        if k in data:
            comp[k] = data[k] in (True, 1, "1", "true", "True")
    fragment = _render_component(comp)
    if not fragment:
        raise HTTPException(500, f"组件 {ctype} 渲染失败")
    return {"svg": diagram_service._sanitize_svg(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}">{fragment}</svg>'
    )}


@app.get("/api/diagram/calibration-summary")
async def api_calibration_summary():
    """获取所有组合的校准摘要"""
    from services.calibration_service import get_calibration_summary
    return get_calibration_summary()


# ═══ 语义连接引擎 API ═══

@app.get("/api/diagram/semantic-scenes")
async def api_list_semantic_scenes():
    """列出所有可用语义场景"""
    from services.diagram_components.semantic_rules import list_all_scenes
    return {"scenes": list_all_scenes()}


@app.post("/api/diagram/semantic-match")
async def api_match_semantic_scene(data: dict):
    """根据已放置的组件集合匹配适用语义场景

    请求: {"component_types": ["beaker", "alcohol_lamp", "tripod", ...]}
    返回: 匹配的场景列表（含configs供选择）
    """
    from services.diagram_components.semantic_rules import match_scene
    types = set(data.get("component_types") or [])
    if not types:
        return {"scenes": []}
    scenes = match_scene(types)
    return {"scenes": scenes}


@app.post("/api/diagram/semantic-resolve")
async def api_resolve_semantic_scene(data: dict):
    """解析特定场景配置，返回端口绑定

    请求: {"scene_id": "heating_beaker", "config_label": "烧杯加热...",
           "components": [{"type":"beaker",...}]}
    返回: {"label":"...", "port_bindings":[...], "params":{...}, "valid":true}
    """
    from services.diagram_components.semantic_rules import resolve_port_bindings
    scene_id = data.get("scene_id", "")
    config_label = data.get("config_label", "")
    components = data.get("components", [])
    result = resolve_port_bindings(scene_id, config_label, components)
    return result


@app.get("/api/diagram/semantic-search")
async def api_search_semantic_scenes(q: str = ""):
    """按关键词搜索语义场景（供AI使用）"""
    from services.diagram_components.semantic_rules import get_scene_by_keyword
    if not q:
        return {"scenes": []}
    return {"scenes": get_scene_by_keyword(q)}


@app.post("/api/diagram/check-safety")
async def api_check_connection_safety(data: dict):
    """检查连接是否安全

    请求: {"src_type": "alcohol_lamp", "dst_type": "beaker"}
    返回: {"safe": false, "reason": "酒精灯不可直接加热烧杯，需通过三脚架+石棉网"}
    """
    from services.diagram_components.semantic_rules import check_connection_safety
    src = data.get("src_type", "").strip()
    dst = data.get("dst_type", "").strip()
    if not src or not dst:
        raise HTTPException(400, "需要 src_type 和 dst_type")
    return check_connection_safety(src, dst)


# ═══ 液面系统 API ═══

@app.get("/api/diagram/liquid-containers")
async def api_liquid_containers():
    """返回支持液面的容器类型列表"""
    from services.diagram_components.liquid_render import LIQUID_CONTAINERS, LIQUID_PRESETS
    return {"containers": list(LIQUID_CONTAINERS.keys()), "presets": list(LIQUID_PRESETS.keys())}


# ═══ Page Routes ═══

class ChatMsg(BaseModel):
    message: str
    session_id: str = ""


class LogPaperError(BaseModel):
    action: str  # "init" / "load_answer_card" / "render"
    paper_id: str
    error: str
    detail: str = ""

@app.post("/api/chat")
async def global_chat(req: ChatMsg):
    from services.ai_service import ai_service
    from services.user_profile import load_profile
    p = load_profile()
    style = p.get("style_notes", "") or p.get("notation_preferences", "")
    from config import load_settings as _load_settings
    _s = _load_settings()
    _classify_model = _s.get("deepseek_model", "deepseek-chat")

    # Phase 1: cheap classifier
    classify_prompt = (
        "分析用户意图，返回JSON。\n"
        "type: chat(闲聊)/solve(解题需要AI推理)/search(搜索题库)/"
        "solve_q(从题库找题并解题写回)/"
        "paper(组卷跳转)/auto_paper(直接生成试卷)/"
        "add_question(新增题目到题库)/edit_question(修改题库题目)/"
        "style(改偏好)/profile(存个人信息)/need(要没有的功能，仅当以上类型都不匹配时才用)/"
        "error_info(查看题目错误信息)\\n"
        "data: 相关参数。search时data含keyword/subject/grade。"
        f"add_question时data含subject/grade/content(题目内容)/answer(答案)。"
        f"edit_question时data含keyword(找题关键词)/field(要改的字段)/value(新值)。"
        f"auto_paper时data含subject/grade/type/topic(专题)。"
        f"error_info时data含question_id(可选,无则列所有错误题目)。"
        f"用户消息: {req.message}"
    )
    try:
        raw = await ai_service._call(
            ai_service.ds_url, ai_service.ds_key,
            {"model": _classify_model, "messages": [{"role": "user", "content": classify_prompt}],
             "temperature": 0, "max_tokens": 256}
        )
        intent = ai_service._extract_json(raw)
    except Exception as e:
        logger.warning("Intent classification failed: %s, falling back to chat", e)
        intent = {"type": "chat"}

    itype = intent.get("type", "chat")
    idata = intent.get("data", {})

    # ====== 组卷 ======
    if itype == "paper":
        from services.config_service import config_service
        from models.database import async_session
        from models.models import Question
        from sqlalchemy import select
        cid = ""
        if idata:
            try:
                cid = await config_service.save_paper_config(idata)
            except Exception as e:
                logger.warning("chat save_paper_config failed: %s", e)
        async with async_session() as db:
            r = await db.execute(select(Question.id).where(Question.status == "done").limit(5))
            qids = [row[0] for row in r.fetchall()]
        hint = f"（题库中已有{len(qids)}道可用题目）" if qids else ""
        jump = f"/papers/generate?saved_config={cid}" if cid else "/papers/generate"
        return {"reply": f"组卷参数已就绪{hint}，已保存（#{cid[:6] if cid else '...'}）。点击下方卡片跳转组卷。",
                "action": {"type": "jump_paper", "data": idata, "saved_config": cid}}

    # ====== 排版偏好 ======
    if itype == "style":
        new_style = idata.get("style_notes", req.message)
        from services.user_profile import save_profile
        p["style_notes"] = new_style
        save_profile(p)
        return {"reply": f"排版偏好已更新为：{new_style[:200]}",
                "action": {"type": "set_style", "data": {"style_notes": new_style}}}

    # ====== 用户画像 ======
    if itype == "profile":
        from services.user_profile import save_profile
        updated = []
        for k, v in idata.items():
            if k in p and v:
                p[k] = v
                updated.append(k)
        if updated:
            save_profile(p)
            return {"reply": f"已记录：{', '.join(updated)}。后续对话将基于这些信息为你服务。",
                    "action": {"type": "set_style", "data": {"updated": updated}}}
        return {"reply": "收到！但请告诉我更具体的信息，比如学校、年级、排名等。"}

    # ====== 需求记录 ======
    if itype == "need":
        from services.diagram_service import diagram_service
        need_desc = idata.get("need", req.message[:60])
        diagram_service._note_agent_need(f"用户需求: {need_desc}")
        return {"reply": f"需求「{need_desc}」已记录到需求池。",
                "action": {"type": "tool_need", "data": {"need": need_desc}}}

    # ====== 查看题目错误信息 ======
    if itype == "error_info":
        from models.database import async_session as _db_s
        from models.models import Question as _Q
        from sqlalchemy import select as _sel
        qid = idata.get("question_id", "")
        async with _db_s() as _db:
            if qid:
                q = await _db.get(_Q, qid)
                if not q:
                    return {"reply": f"未找到题目 #{qid[:8]}"}
                flags = q.audit_flags if hasattr(q, 'audit_flags') and q.audit_flags else []
                err_msg = q.error_message or "无错误记录"
                flag_str = ""
                if isinstance(flags, list) and flags:
                    flag_items = [f"{f.get('type','')}: {f.get('reason','')}" for f in flags]
                    flag_str = "\n审计标记: " + "; ".join(flag_items)
                prev = (q.ocr_text or q.question_html or "")[:80]
                return {"reply": f"题目 #{qid[:8]} [{q.subject}][{q.grade}]\n{prev}...\n状态: {q.status}\n错误: {err_msg}{flag_str}"}
            else:
                r = await _db.execute(_sel(_Q).where(_Q.status == "error").order_by(_Q.created_at.desc()).limit(10))
                errors = r.scalars().all()
                if not errors:
                    return {"reply": "当前没有错误题目。"}
                lines = [f"共 {len(errors)} 道错误题目："]
                for i, eq in enumerate(errors, 1):
                    prev = (eq.ocr_text or eq.question_html or "")[:50].replace("\n", " ")
                    lines.append(f"{i}. #{eq.id[:8]} [{eq.subject}][{eq.grade}] {prev}... - {eq.error_message or '未知错误'}")
                return {"reply": "\n".join(lines)}

    # ====== 新增题目到题库 ======
    if itype == "add_question":
        from models.database import async_session as _db_s
        from models.models import Question as _Q
        content = idata.get("content", req.message)
        answer = idata.get("answer", "")
        subject = idata.get("subject", "")
        grade = idata.get("grade", "")
        # Use AI to generate formatted question HTML
        gen_prompt = (
            f"根据描述生成一道题目。\n"
            f"学科: {subject or '通用'}\n年级: {grade or '通用'}\n"
            f"题目内容: {content}\n答案: {answer or '请推导'}\n"
            "返回JSON: {{\"question_html\":\"题目HTML(含数学公式用$...$)\","
            "\"answer_html\":\"答案HTML\"}}"
        )
        try:
            raw = await ai_service.deepseek_chat([{"role": "user", "content": gen_prompt}], temperature=0.7, max_tokens=32768)
            gen = ai_service._extract_json(raw)
            q_html = gen.get("question_html", content)
            a_html = gen.get("answer_html", answer)
        except Exception:
            q_html = f"<p>{content}</p>"
            a_html = f"<p>{answer}</p>" if answer else ""
        new_id = ''.join(__import__('random').choices('0123456789abcdef', k=12))
        folder = os.path.join(STORAGE_DIR, "questions", new_id)
        os.makedirs(folder, exist_ok=True)
        async with _db_s() as _db:
            q = _Q(id=new_id, folder_path=folder, subject=subject, grade=grade,
                   ocr_text=content, question_html=q_html, answer_html=a_html,
                   standard_answer=answer, status="done", source_type="ai_generated")
            _db.add(q)
            await _db.commit()
        tags_info = f"（{subject} {grade}）" if subject or grade else ""
        return {"reply": f"题目已保存到题库{tags_info}，共1题。可在题库页查看。",
                "action": {"type": "jump_question", "data": {"id": new_id, "subject": subject, "grade": grade}}}

    # ====== 修改题库题目 ======
    if itype == "edit_question":
        from models.database import async_session as _db_s
        from models.models import Question as _Q
        from sqlalchemy import select as _sel
        from datetime import datetime as _dt
        keyword = idata.get("keyword", "")
        field = idata.get("field", "")  # answer / tags / subject / grade / content
        value = idata.get("value", "")
        if not keyword:
            return {"reply": "请告诉我你要修改哪道题？可以给题目的关键词或编号。"}
        async with _db_s() as _db:
            r = await _db.execute(_sel(_Q).where(_Q.ocr_text.contains(keyword)).limit(1))
            q = r.scalars().first()
            if not q:
                return {"reply": f"未找到包含「{keyword}」的题目。请提供更精确的关键词。"}
            if field == "answer" or field == "答案":
                q.standard_answer = value
                q.answer_html = f"<p>{value}</p>"
            elif field == "tags" or field == "标签":
                q.knowledge_tags = [t.strip() for t in value.split(",") if t.strip()]
            elif field == "subject" or field == "学科":
                q.subject = value
            elif field == "grade" or field == "年级":
                q.grade = value
            elif field == "content" or field == "内容":
                q.ocr_text = value
                q.question_html = f"<p>{value}</p>"
            else:
                return {"reply": f"不支持的修改字段: {field}。支持的字段: answer/tags/subject/grade/content"}
            q.updated_at = _dt.utcnow()
            await _db.commit()
            prev = q.ocr_text[:30] if q.ocr_text else ""
        return {"reply": f"题目「{prev}...」的 **{field}** 已更新。",
                "action": {"type": "set_style", "data": {"updated": [field]}}}

    # ====== 直接生成试卷 ======
    if itype == "auto_paper":
        subject = idata.get("subject", "")
        grade = idata.get("grade", "")
        ptype = idata.get("type", "custom")
        topic = idata.get("topic", "")
        # Save config first
        from services.config_service import config_service
        from models.database import async_session as _db_s
        from models.models import Question as _Q
        from sqlalchemy import select as _sel
        cfg = {"subject": subject, "grade": grade, "paper_type": ptype, "question_count": 5}
        if topic:
            cfg["topic"] = topic
            cfg["knowledge_tags"] = [topic]
        cid = ""
        try:
            cid = await config_service.save_paper_config(cfg)
        except Exception as e:
            logger.warning("auto_paper save config failed: %s", e)
        # Try to generate immediately
        async with _db_s() as _db:
            r = await _db.execute(_sel(_Q.id).where(_Q.status == "done").limit(1))
            has_q = len(r.fetchall()) > 0
        if has_q:
            from services.paper_service import paper_service as _ps
            try:
                paper = await _ps.generate_paper(cfg)
                pid = paper.id
                return {"reply": f"试卷已经生成：**{subject} {grade} {ptype}**。",
                        "action": {"type": "jump_paper", "data": cfg, "saved_config": cid, "paper_id": pid}}
            except Exception as e:
                logger.warning("auto_paper generation failed: %s", e)
                hint = f"参数已就绪（{subject} {grade} {ptype}）。"
                return {"reply": f"自动生成暂未成功，请手动跳转组卷页。{hint}",
                        "action": {"type": "jump_paper", "data": cfg, "saved_config": cid}}
        else:
            return {"reply": f"题库暂无可用的题目。请先用OCR导入题目或让我出新题，再生成试卷。",
                    "action": {"type": "jump_paper", "data": cfg, "saved_config": cid}}

    # ====== 题库搜索 ======
    if itype == "search":
        from models.database import async_session as _db_session
        from models.models import Question as _Q
        from sqlalchemy import select as _select
        keyword = idata.get("keyword", "")
        subject = idata.get("subject", "")
        grade = idata.get("grade", "")
        async with _db_session() as _db:
            q = _select(_Q).where(_Q.status == "done").order_by(_Q.created_at.desc()).limit(5)
            if keyword:
                q = q.where(_Q.ocr_text.contains(keyword))
            if subject:
                q = q.where(_Q.subject == subject)
            if grade:
                q = q.where(_Q.grade == grade)
            r = await _db.execute(q)
            found = r.scalars().all()
        if not found:
            return {"reply": f"题库中未找到相关题目{'（' + subject + ' ' + grade + '）' if subject or grade else ''}。试试换关键词？"}
        lines = [f"找到 {len(found)} 道题："]
        for i, fq in enumerate(found, 1):
            tags = ", ".join(fq.knowledge_tags or [])
            prev = (fq.ocr_text or fq.question_html or "")[:60]
            lines.append(f"{i}. [{fq.subject}][{fq.grade}] {prev}...（标签: {tags}）")
        return {"reply": "\n".join(lines)}

    # ====== 从题库解题并写回（含自检）======
    if itype == "solve_q":
        from models.database import async_session as _db_session
        from models.models import Question as _Q
        from sqlalchemy import select as _select
        keyword = idata.get("keyword", "") or idata.get("subject", "")
        subject = idata.get("subject", "")
        grade = idata.get("grade", "")
        async with _db_session() as _db:
            q = _select(_Q).where(_Q.status == "done").order_by(_Q.created_at.desc()).limit(3)
            if keyword:
                q = q.where(_Q.ocr_text.contains(keyword))
            if subject:
                q = q.where(_Q.subject == subject)
            if grade:
                q = q.where(_Q.grade == grade)
            r = await _db.execute(q)
            found = r.scalars().all()
        if not found:
            return {"reply": "题库中未找到匹配的题目，请用 search 先搜索或提供更具体的学科/年级。"}
        from services.ai_service import ai_service as _ai
        from services.diagram_service import diagram_service as _ds
        replies = []
        for fq in found:
            info = json.dumps({"id": fq.id, "subject": fq.subject, "grade": fq.grade,
                               "ocr_text": fq.ocr_text, "question_html": fq.question_html,
                               "knowledge_tags": fq.knowledge_tags}, ensure_ascii=False)
            # solve_q: solve mode
            ans = await _ai.deepseek_solve(
                subject=fq.subject or "", grade=fq.grade or "", ocr_text=fq.ocr_text or "",
                knowledge_tags=fq.knowledge_tags or [], style_notes=style
            )
            answer_html = ans.get("answer_html", "")
            # 自检
            try:
                review = await _ai.deepseek_self_review(
                    ans.get("question_html", ""), answer_html,
                    ans.get("standard_answer", ""), fq.subject or "", fq.grade or ""
                )
                answer_html = review.get("answer_html", answer_html)
                q_html = review.get("question_html", ans.get("question_html", ""))
            except Exception:
                q_html = ans.get("question_html", "")
            # 处理示意图
            diagram_prompts = ans.get("diagram_prompts", [])
            new_diagrams = list(fq.diagrams or [])
            if diagram_prompts:
                places = ans.get("diagram_places") or (["question"] + ["answer"] * max(0, len(diagram_prompts) - 1))
                for i, dp in enumerate(diagram_prompts):
                    try:
                        path = await _ds.generate_diagram(fq.id, dp, len(new_diagrams))
                        if path:
                            place = places[i] if i < len(places) else "question"
                            new_diagrams.append({"path": path, "place": place})
                            svg_tag = f'<div class="diagram"><img src="{path}" style="max-width:80%;height:auto"></div>'
                            answer_html = answer_html.replace(f"[[DIAGRAM:{i}]]", svg_tag, 1)
                            q_html = q_html.replace(f"[[DIAGRAM:{i}]]", svg_tag, 1)
                    except Exception:
                        answer_html = answer_html.replace(f"[[DIAGRAM:{i}]]", "", 1)
                        q_html = q_html.replace(f"[[DIAGRAM:{i}]]", "", 1)
            fq.diagrams = new_diagrams
            fq.question_html = q_html
            if "<!-- SCORE_SPLIT -->" in answer_html:
                parts = answer_html.split("<!-- SCORE_SPLIT -->", 1)
                fq.score_points_html = parts[0].strip()
                fq.answer_html = parts[1].strip()
            else:
                fq.answer_html = answer_html
            fq.standard_answer = ans.get("standard_answer", fq.standard_answer)
            fq.question_type = ans.get("question_type", fq.question_type)
            fq.status = "done"
            async with _db_session() as _db2:
                _db2.add(fq)
                await _db2.commit()
            replies.append(f"**{fq.subject}{fq.grade} - {fq.id[:8]}** 已解答并保存。\n\n" + answer_html)
        return {"reply": "\n\n---\n\n".join(replies)}

    # ====== 解题 ======
    if itype == "solve":
        reply = await ai_service.deepseek_chat([
            {"role": "system", "content": (
                "你是学习搭子AI解题助手。能力：1.详细解题 2.出变式题 3.解释概念 4.画图。\n"
                "遇到几何题、函数图像、物理化学装置等需要图示的内容，请在解答中插入 [[DIAGRAM:详细中文描述图形]] 自动生成示意图。\n"
                "示意图描述要具体：例如 [[DIAGRAM:直角三角形ABC，∠C=90°，AC=3 BC=4 标注顶点]]。\n"
                "【输出格式】使用Markdown：## 标题 / **粗体** / 有序列表1. 2. 3. / 数学用$...$包裹。不得使用emoji和彩色文字。\n"
                f"排版偏好：{style}"
            )},
            {"role": "user", "content": req.message}
        ], max_tokens=32768)
        # 自动生成示意图
        reply = await _render_diagrams_in_reply(reply)
        return {"reply": reply}

    # ====== 默认：智能对话（含多轮能力） ======
    system_prompt = (
        f"你是学习搭子AI助手。你有以下能力：\n"
        f"1. 搜索题库 2. 从题库找题解题并写回 3. 修改/重写题目答案 "
        f"4. 出变式题 5. 解释概念 6. 画几何图（遇到几何/函数/装置题时插入 [[DIAGRAM:详细中文描述图形]] 自动生成示意图。例如 [[DIAGRAM:直角三角形ABC ∠C=90° AC=3 BC=4]]）\n"
        f"7. 评估答案正确性 8. 推荐组卷参数 9. 查看错误信息(error_info)\n"
        f"【输出格式】使用Markdown格式回答：用 ## 表示小标题，用 **粗体** 强调重点，有序列表用 1. 2. 3.，数学公式用 $...$ 包裹。\n"
        f"禁止使用emoji、禁止使用彩色HTML、禁止使用代码块标记（除非展示代码）。\n"
        f"排版偏好：{style}\n"
        f"如果需要多步完成，输出JSON格式: {{\"reply\":\"当前回复\",\"done\":true/false}}"
    )
    reply = await ai_service.deepseek_chat([
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": req.message}
    ], max_tokens=32768)
    # 自动生成示意图
    reply = await _render_diagrams_in_reply(reply)
    return {"reply": reply}


@app.post("/api/log-paper-error")
async def log_paper_error(req: LogPaperError):
    """客户端上报试卷展示错误"""
    from logger import log_error
    if req.detail:
        msg = "paper_id=%s action=%s error=%s detail=%s" % (req.paper_id, req.action, req.error, req.detail[:300])
    else:
        msg = "paper_id=%s action=%s error=%s" % (req.paper_id, req.action, req.error)
    log_error("paper_frontend", msg)
    return {"message": "logged"}


class LogFrontendError(BaseModel):
    error: str
    stack: str = ""
    kind: str = "error"
    page: str = ""


@app.post("/api/log-frontend-error")
async def log_frontend_error(req: LogFrontendError):
    """全局前端JS错误自动上报 —— 类似自动记录需求"""
    msg = "[%s][%s] %s" % (req.kind, req.page, req.error[:200])
    if req.stack:
        msg += " | stack=%s" % req.stack[:300]
    log_error("frontend_js", msg)
    return {"message": "logged"}


async def _render_diagrams_in_reply(reply: str) -> str:
    """替换回复中的 [[DIAGRAM:...]] 标记为实际SVG，含显式宽度防组卷压缩"""
    if '[[DIAGRAM:' not in reply:
        return reply
    from services.diagram_service import diagram_service as _ds
    import re as _re
    diag_idx = 0
    base_name = f"chat_{int(__import__('time').time())}"
    for m in _re.finditer(r'\[\[DIAGRAM:([^\]]+)\]\]', reply):
        desc = m.group(1)
        try:
            path = await _ds.generate_diagram(base_name, desc, diag_idx)
            diag_idx += 1
            if path:
                disk_path = os.path.join(STORAGE_DIR, path.lstrip("/"))
                w, h = _ds._get_svg_size(disk_path)
                size_attr = f' width="{w}"' if w else ""
                svg_tag = f'<div class="diagram"><img src="{path}" style="max-width:80%;height:auto"{size_attr} alt="示意图" onerror="this.style.display=\'none\'"></div>'
                reply = reply.replace(m.group(0), svg_tag, 1)
            else:
                log_error("diagram_gen", f"empty_path base={base_name} idx={diag_idx-1} desc={desc[:60]}")
                reply = reply.replace(m.group(0), '', 1)
        except Exception as e:
            log_error("diagram_gen", f"base={base_name} idx={diag_idx} desc={desc[:60]} error={e}")
            reply = reply.replace(m.group(0), '', 1)
    return reply





@app.get("/favicon.ico")
async def favicon():
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
           '<rect width="32" height="32" rx="6" fill="#333"/>'
           '<text x="16" y="23" text-anchor="middle" font-size="20" fill="#fff">S</text></svg>')
    return Response(content=svg, media_type="image/svg+xml")


# ===================== HTML 页面路由 =====================

@app.get("/", response_class=HTMLResponse)
async def page_dashboard(request: Request):
    return render_template("dashboard.html", page="dashboard")


@app.get("/questions", response_class=HTMLResponse)
async def page_questions(request: Request):
    from config import ENABLE_STRUCTURE_GRAPH, ENABLE_COMPARISON_MODE
    return render_template("questions.html", page="questions",
                           enable_structure_graph=ENABLE_STRUCTURE_GRAPH,
                           enable_comparison_mode=ENABLE_COMPARISON_MODE)


@app.get("/papers", response_class=HTMLResponse)
async def page_papers(request: Request):
    return render_template("papers.html", page="papers")


@app.get("/papers/generate", response_class=HTMLResponse)
async def page_paper_generate(request: Request):
    return render_template("paper_generate.html", page="generate")


if ENABLE_CORRECT:
    @app.get("/correct", response_class=HTMLResponse)
    async def page_correct():
        return render_template("correct.html", page="correct")

    @app.get("/correctCenter", response_class=HTMLResponse)
    async def page_correct_center():
        return render_template("correct_center.html", page="correct")

    @app.get("/correction/history", response_class=HTMLResponse)
    async def page_correction_history():
        return render_template("correction_history.html", page="correct")

    @app.get("/papers/{paper_id}/correct", response_class=HTMLResponse)
    async def page_paper_correct(request: Request, paper_id: str):
        return render_template("paper_correct.html", page="correct", paper_id=paper_id)


@app.get("/papers/{paper_id}", response_class=HTMLResponse)
async def page_paper_detail(request: Request, paper_id: str):
    return render_template("paper_detail.html", page="papers", paper_id=paper_id)


@app.get("/prompts", response_class=HTMLResponse)
async def page_prompts(request: Request):
    return render_template("prompts.html", page="prompts")


@app.get("/settings", response_class=HTMLResponse)
async def page_settings(request: Request):
    return render_template("settings.html", page="settings")


@app.get("/qa", response_class=HTMLResponse)
async def page_qa(request: Request):
    return render_template("qa.html", page="qa")

@app.get("/notes", response_class=HTMLResponse)
async def page_notes(request: Request):
    return render_template("notes.html", page="notes")


@app.get("/batch-upload", response_class=HTMLResponse)
async def page_batch_upload(request: Request):
    return render_template("batch_upload.html", page="batch")


@app.get("/diagnose", response_class=HTMLResponse)
async def page_diagnose(request: Request):
    return render_template("diagnose.html", page="diagnose")


@app.get("/agent", response_class=HTMLResponse)
async def page_agent(request: Request):
    return render_template("agent.html", page="agent")

@app.get("/editor", response_class=HTMLResponse)
async def page_editor(request: Request):
    return render_template("editor.html", page="editor")

@app.get("/banks")
async def page_banks():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/questions")


if ENABLE_SEARCH:
    @app.get("/search", response_class=HTMLResponse)
    async def page_search():
        return render_template("search.html", page="search")
