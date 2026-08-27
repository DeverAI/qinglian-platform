"""首页通知与每日简报。

提供两类能力：
1. 每日简报（briefing）：AI 联网搜索近 7 日与互联网平台合规、未成年人保护、
   个人信息保护相关的新法规/政策/监管动态，生成 200 字以内摘要；无新内容时
   降级为"历史上的今天"。当日结果落盘缓存到 storage/briefings/，避免重复
   消耗 token。
2. 系统通知（system_messages）：审核结果、板块封存、邮件代发进度、root 公告
   等事件统一写入 system_messages 表，首页拉取最近 20 条展示。

设计原则：轻量化，复用 agent.py 的 _ai_config；不引入新的第三方依赖。
"""
import json
import urllib.error
import urllib.request
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pathlib import Path

from ..common import BizError, ok
from ..config import BRIEFING_DIR
from ..database import db
from ..errlog import log_error
from ..routers.admin import get_setting
from ..security import csrf_check, get_optional_user, require_roles

router = APIRouter()

# ---------------- 系统通知工具 ----------------

VALID_MSG_TYPES = {
    "system", "daily_briefing", "task", "post",
    "email", "board", "root", "point",
}


def add_system_message(
    msg_type: str,
    title: str,
    content: str = "",
    ref_type: str = "",
    ref_id: Optional[int] = None,
) -> int:
    """供其他模块调用的工具函数：写入一条系统通知，返回 id。

    类型不合法时降级为 'system'，避免上游传错导致接口报错。
    """
    if msg_type not in VALID_MSG_TYPES:
        msg_type = "system"
    try:
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO system_messages (type, title, content, ref_type, ref_id) "
                "VALUES (?,?,?,?,?)",
                (msg_type, title[:120], content[:2000], ref_type[:32], ref_id),
            )
            return int(cur.lastrowid)
    except Exception as exc:
        log_error("notify.add_system_message", repr(exc))
        return 0


def _msg_out(row) -> dict:
    return {
        "id": row["id"],
        "type": row["type"],
        "title": row["title"],
        "content": row["content"],
        "ref_type": row["ref_type"],
        "ref_id": row["ref_id"],
        "is_read": row["is_read"],
        "created_at": row["created_at"],
    }


@router.get("/messages")
def list_messages(limit: int = Query(20, ge=1, le=50)):
    """返回最近 N 条系统通知（按 id 倒序）。"""
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM system_messages ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        # 真实未读总数（不受 limit 影响）
        row = conn.execute("SELECT COUNT(*) AS c FROM system_messages WHERE is_read=0").fetchone()
        unread = int(row["c"])
    msgs = [_msg_out(r) for r in rows]
    return ok({"items": msgs, "unread": unread})


@router.post("/messages/read")
def mark_all_read(user: dict = Depends(csrf_check)):
    """将全部通知标记为已读（需登录 + CSRF）。"""
    with db() as conn:
        conn.execute("UPDATE system_messages SET is_read=1 WHERE is_read=0")
    return ok(None, "已全部标记已读")


@router.delete("/messages/{msg_id}")
def delete_message(msg_id: int, user: dict = Depends(csrf_check)):
    """单条删除（需登录 + CSRF）。msg_id<=0 视为非法。"""
    if msg_id <= 0:
        raise BizError(4001, "非法消息 id")
    with db() as conn:
        cur = conn.execute("DELETE FROM system_messages WHERE id=?", (msg_id,))
        if cur.rowcount == 0:
            raise BizError(4040, "消息不存在或已删除")
    return ok(None, "已删除")


@router.delete("/messages")
def clear_all_messages(user: dict = Depends(require_roles("admin", "sysadmin", "root", mutating=True))):
    """清空全部系统通知（需管理员权限 + CSRF）。"""
    with db() as conn:
        conn.execute("DELETE FROM system_messages")
    return ok(None, "已清空")


# ---------------- 每日简报 ----------------

STATIC_FALLBACK = {
    "summary": "欢迎使用青联合规监督社区。这里汇聚青少年力量，监督互联网平台的不合理条款、数据滥用与未成年人保护缺失。请在「任务」中提交举报，在「知识库」学习法律原文。",
    "source": "青联合规监督社区",
    "source_url": "",
    "kind": "fallback",
}


def _briefing_path(date_str: str) -> Path:
    return BRIEFING_DIR / f"briefing_{date_str}.json"


def _load_cached_briefing(date_str: str) -> Optional[dict]:
    path = _briefing_path(date_str)
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("summary"):
                # 兼容旧缓存，避免历史品牌名继续出现在前台。
                for field in ("summary", "source"):
                    if isinstance(data.get(field), str):
                        data[field] = data[field].replace("青联KIMI", "青联合规监督社区")
                return data
    except Exception as exc:
        log_error("notify._load_cached_briefing", repr(exc))
    return None


def _save_cached_briefing(date_str: str, data: dict) -> None:
    try:
        BRIEFING_DIR.mkdir(parents=True, exist_ok=True)
        data["date"] = date_str
        path = _briefing_path(date_str)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        log_error("notify._save_cached_briefing", repr(exc))


def _notify_briefing(data: dict) -> None:
    """将简报写入 system_messages 表，供首页通知列表展示。"""
    kind = data.get("kind", "fallback")
    title = "每日简报 · " + (
        "新政策动态" if kind == "policy"
        else ("历史上的今天" if kind == "history" else "社区导览")
    )
    try:
        add_system_message("daily_briefing", title, data.get("summary", ""))
    except Exception:
        pass


def _ai_config() -> tuple[str, str, str]:
    """复用 agent.py 的配置优先级：admin_settings → 环境变量。"""
    from .. import config
    url = get_setting("ai_api_url") or config.AI_API_URL
    key = get_setting("ai_api_key") or config.AI_API_KEY
    model = get_setting("ai_search_model") or get_setting("ai_model") or config.AI_MODEL
    return url, key, model


def _call_ai_with_search(messages: list[dict], max_tokens: int = 600) -> str:
    """调用 OpenAI 兼容接口；若模型支持 web_search 工具则启用。"""
    url, key, model = _ai_config()
    if not url or not model:
        return ""
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.4,
        "max_tokens": max_tokens,
    }
    # 智谱 / 部分兼容接口支持 tools.web_search；忽略不支持时的报错
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


def _call_ai_plain(messages: list[dict], max_tokens: int = 600) -> str:
    url, key, model = _ai_config()
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
    with urllib.request.urlopen(req, timeout=45) as resp:
        result = json.loads(resp.read().decode("utf-8"))
        return result["choices"][0]["message"]["content"].strip()


def _strip_code_fence(raw: str) -> str:
    """去掉模型常见的 ```json ... ``` 包裹。"""
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1] if "\n" in raw else raw[3:]
    if raw.endswith("```"):
        raw = raw.rsplit("\n", 1)[0] if "\n" in raw else raw[:-3]
    return raw.strip()


def _build_briefing_prompt() -> list[dict]:
    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    weekday = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"][now.weekday()]
    system_prompt = (
        "你是「青联合规监督社区」的简报编辑。社区面向青少年，监督互联网平台的不合理条款、霸王条款、数据滥用、未成年人保护缺失等问题。\n"
        "请联网搜索近 7 日国家或行业层面与以下主题相关的新法规、新政策、监管动态、典型案例：\n"
        "  - 个人信息保护 / 数据安全 / 网络安全\n"
        "  - 未成年人网络保护 / 青少年权益\n"
        "  - 互联网平台合规 / 平台治理 / 反霸王条款\n"
        "输出要求：\n"
        "1. 若找到新政策/法规/动态：summary 字段写不超过 200 字的中文摘要；source 写文件或机构名称（20 字内）；source_url 写可访问的官方或权威媒体链接；kind 写 'policy'。\n"
        "2. 若近 7 日无明显新内容：summary 写一条与青少年维权、法治、互联网治理相关的'历史上的今天'事件概括（不超过 200 字）；source 写事件名（20 字内）；source_url 留空；kind 写 'history'。\n"
        "3. 只输出一个 JSON 对象，字段：summary、source、source_url、kind。不要任何额外文字、不要 markdown 代码块。\n"
        f"当前系统时间：{today} {weekday}。"
    )
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"请生成 {today} 的青联简报。"},
    ]


def _parse_briefing(raw: str) -> dict:
    raw = _strip_code_fence(raw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # 模型偶尔会输出纯文本，兜底作为 summary
        text = raw.strip().strip('"').strip("'")[:200]
        if not text:
            raise
        return {
            "summary": text, "source": "", "source_url": "", "kind": "fallback",
        }
    summary = str(data.get("summary", "")).strip().strip('"').strip("'")[:200]
    if not summary:
        raise ValueError("empty summary")
    return {
        "summary": summary,
        "source": str(data.get("source", "")).strip()[:40],
        "source_url": str(data.get("source_url", "")).strip()[:300],
        "kind": "history" if str(data.get("kind", "")).strip() == "history" else "policy",
    }


def _generate_daily_briefing() -> dict:
    """生成当日简报（幂等：当天已缓存则直接返回缓存）。

    供 main.py 启动时与 /api/notify/briefing 接口共同调用。
    """
    today = datetime.now().strftime("%Y-%m-%d")
    cached = _load_cached_briefing(today)
    if cached:
        return cached

    url, _key, model = _ai_config()
    if not url or not model:
        # AI 未配置：写一条静态兜底并落盘，避免每次请求都走 AI 分支
        _save_cached_briefing(today, STATIC_FALLBACK)
        _notify_briefing(STATIC_FALLBACK)
        return STATIC_FALLBACK

    try:
        raw = _call_ai_with_search(_build_briefing_prompt(), max_tokens=600)
        data = _parse_briefing(raw)
    except BizError as exc:
        log_error("notify._generate_daily_briefing", f"BizError {exc.code}: {exc.message}")
        data = dict(STATIC_FALLBACK)
        data["kind"] = "fallback"
    except Exception as exc:
        log_error("notify._generate_daily_briefing", repr(exc))
        data = dict(STATIC_FALLBACK)
        data["kind"] = "fallback"

    # 仅当 AI 成功生成时才落盘缓存；fallback 不落盘，允许后续请求重试 AI
    if data.get("kind") != "fallback":
        _save_cached_briefing(today, data)
    _notify_briefing(data)
    return data


@router.get("/briefing")
def get_briefing(user: dict = Depends(get_optional_user)):
    """获取今日简报。优先读缓存；缓存不存在则现场生成（首次访问或跨日时）。"""
    today = datetime.now().strftime("%Y-%m-%d")
    cached = _load_cached_briefing(today)
    if cached:
        return ok(cached)
    data = _generate_daily_briefing()
    return ok(data)
