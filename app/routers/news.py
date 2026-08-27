"""新闻栏 API：AI 联网搜索生成当日合规/未成年人保护/数据安全新闻摘要。

新闻来源限定为政府/官方媒体/权威门户，AI 提示词中明确禁止编造链接。
每条新闻保留 7 天后自动置 is_active=0（由 feed.py 查询时触发）。
"""
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query

from ..common import BizError, ok
from ..database import db
from ..errlog import log_error
from ..routers.admin import get_setting
from ..security import require_roles

router = APIRouter()

DAILY_LIMIT = 8


def _ai_config() -> tuple[str, str, str]:
    """复用 agent.py 的配置优先级：admin_settings → 环境变量。"""
    from .. import config
    url = get_setting("ai_api_url") or config.AI_API_URL
    key = get_setting("ai_api_key") or config.AI_API_KEY
    model = get_setting("ai_search_model") or get_setting("ai_model") or config.AI_MODEL
    return url, key, model


def _call_ai_with_search(messages: list[dict], max_tokens: int = 1000) -> str:
    url, key, model = _ai_config()
    if not url or not model:
        return ""
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.4,
        "max_tokens": max_tokens,
    }
    payload["tools"] = [{"type": "web_search", "web_search": {"enable": True}}]
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["choices"][0]["message"]["content"].strip()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        raise BizError(5001, f"联网搜索模型调用失败，请确认模型支持 web_search：{e.code} {body[:200]}")
    except BizError:
        raise
    except Exception as e:
        raise BizError(5002, f"AI 调用失败：{e}")


def _call_ai_plain(messages: list[dict], max_tokens: int = 1000) -> str:
    url, key, model = _ai_config()
    if not url or not model:
        return ""
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.4,
        "max_tokens": max_tokens,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["choices"][0]["message"]["content"].strip()
    except Exception as e:
        raise BizError(5002, f"AI 调用失败（plain）：{e}")


def _build_news_prompt() -> list[dict]:
    today = datetime.now().strftime("%Y年%m月%d日")
    return [
        {
            "role": "system",
            "content": (
                "你是互联网合规与未成年人保护领域的新闻编辑。请联网搜索今日（"
                + today
                + "）中国境内与以下主题相关的权威新闻：互联网平台合规、未成年人保护、"
                "个人信息保护、数据安全、平台经济监管。"
                "要求：1) 仅引用政府网站、官方媒体、权威门户（如网信办、工信部、新华社、人民日报、央视、"
                "法治日报、中国新闻网等）的真实新闻；2) 严禁编造链接与来源；3) 每条新闻输出标题、不超过150字的摘要、"
                "来源媒体名称、原文链接、发布日期；4) 若今日确无相关新闻，返回空数组 []。"
            ),
        },
        {
            "role": "user",
            "content": "请搜索今日相关新闻，严格按 JSON 数组格式输出，每项字段：title, abstract, source_name, source_url, published_at。不要输出任何额外文字。",
        },
    ]


def _parse_news(raw: str) -> list[dict]:
    """从 AI 输出中解析 JSON 新闻数组。"""
    if not raw:
        return []
    raw = raw.strip()
    # 优先尝试直接解析
    try:
        arr = json.loads(raw)
        if not isinstance(arr, list):
            return []
    except json.JSONDecodeError:
        # 从首个 [ 开始用 raw_decode 解析一个完整 JSON 数组
        idx = raw.find("[")
        if idx < 0:
            return []
        try:
            arr, _end = json.JSONDecoder().raw_decode(raw[idx:])
        except json.JSONDecodeError:
            return []
    result = []
    for item in arr:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()
        url = str(item.get("source_url", "")).strip()
        if not title or not url:
            continue
        # 基础 URL 合法性校验
        if not re.match(r"^https?://", url):
            continue
        result.append({
            "title": title[:200],
            "abstract": str(item.get("abstract", "")).strip()[:400],
            "source_name": str(item.get("source_name", "")).strip()[:100],
            "source_url": url[:500],
            "published_at": str(item.get("published_at", "")).strip()[:30] or None,
        })
    return result


def _collect_news() -> dict:
    """AI 联网搜索生成新闻并落库。返回 {collected, skipped}。"""
    url, _key, model = _ai_config()
    if not url or not model:
        return {"collected": 0, "skipped": 0, "reason": "AI 未配置"}
    try:
        raw = _call_ai_with_search(_build_news_prompt(), max_tokens=1000)
    except BizError as exc:
        log_error("news._collect_news", repr(exc))
        return {"collected": 0, "skipped": 0, "reason": exc.message}

    items = _parse_news(raw)
    if not items:
        return {"collected": 0, "skipped": 0, "reason": "今日无新内容或解析失败"}

    today = datetime.now().strftime("%Y-%m-%d")
    inserted = 0
    with db() as conn:
        # 防止同日重复写入：按 (title, source_url) 去重
        existing = {
            (r["title"], r["source_url"])
            for r in conn.execute(
                "SELECT title, source_url FROM news WHERE date(collected_at)=?", (today,)
            ).fetchall()
        }
        for it in items:
            if (it["title"], it["source_url"]) in existing:
                continue
            conn.execute(
                "INSERT INTO news (title, abstract, source_name, source_url, published_at) "
                "VALUES (?,?,?,?,?)",
                (it["title"], it["abstract"], it["source_name"], it["source_url"], it["published_at"]),
            )
            inserted += 1
    return {"collected": inserted, "skipped": len(items) - inserted}


@router.get("")
def list_news(limit: int = Query(20, ge=1, le=DAILY_LIMIT * 4)):
    """首页新闻栏：返回最近 7 天新闻。"""
    cutoff = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    with db() as conn:
        # 顺手清理过期
        conn.execute("UPDATE news SET is_active=0 WHERE is_active=1 AND collected_at < ?", (cutoff,))
        rows = conn.execute(
            "SELECT * FROM news WHERE is_active=1 ORDER BY collected_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    items = [
        {
            "id": r["id"],
            "title": r["title"],
            "abstract": r["abstract"],
            "source_name": r["source_name"],
            "source_url": r["source_url"],
            "published_at": r["published_at"],
            "collected_at": r["collected_at"],
        }
        for r in rows
    ]
    return ok({"items": items})


@router.post("/admin/collect")
def admin_collect_news(user: dict = Depends(require_roles("admin", "sysadmin", "root", mutating=True))):
    """管理员手动触发新闻采集（需登录 + CSRF）。"""
    result = _collect_news()
    return ok(result, "新闻采集完成")
