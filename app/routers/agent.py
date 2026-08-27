"""全局 AI 导游 Agent：基于 Design.md 答疑；越界需求记录 Future.md。"""
import json
import urllib.error
import urllib.request
from datetime import datetime
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..attack_detector import detect, handle_attack
from ..common import BizError, ok
from ..config import AI_API_KEY, AI_API_URL, AI_MODEL, DESIGN_MD, FUTURE_MD
from ..database import db
from ..handshake import is_handshake_active
from ..routers.admin import get_setting
from ..security import get_optional_user

router = APIRouter()

OUT_OF_SCOPE_REPLY = "这个提议很好，已记录至 Future.md，将由管理员评估。"


def _read_design() -> str:
    try:
        return DESIGN_MD.read_text(encoding="utf-8")
    except Exception:
        return ""


def _system_prompt() -> str:
    return (
        "你是“青联合规监督社区”的 AI 导游，只根据下面提供的《Design.md》原文回答用户问题。\n"
        "规则：\n"
        "1. 只回答 Design.md 中明确涉及的内容，不得编造文档外信息。\n"
        "2. 如果用户问题超出 Design.md 范围，或文档中无明确依据，请只回复：\n"
        f"   “{OUT_OF_SCOPE_REPLY}”\n"
        "3. 回复保持简洁、友好，不超过 300 字。\n\n"
        "《Design.md》原文如下：\n"
        "---\n"
        f"{_read_design()}\n"
        "---"
    )


def _ai_config() -> tuple[str, str, str]:
    """优先使用管理员后台设置，其次环境变量。"""
    url = get_setting("ai_api_url") or AI_API_URL
    key = get_setting("ai_api_key") or AI_API_KEY
    model = get_setting("ai_model") or AI_MODEL
    return url, key, model


def _call_ai(messages: list[dict]) -> str:
    url, key, model = _ai_config()
    if not url or not model:
        return ""
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 500,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["choices"][0]["message"]["content"].strip()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        raise BizError(5001, f"AI 接口错误：{e.code} {body[:200]}")
    except Exception as e:
        raise BizError(5002, f"AI 调用失败：{e}")


def _record_future(text: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"\n- [{ts} AI 导游收集] {text}"
    try:
        with open(FUTURE_MD, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def _static_tour() -> str:
    return (
        "欢迎来到青联合规监督社区！\n"
        "这里是一个面向青少年的互联网平台合规监督社区。你可以：\n"
        "1. 注册登录后提交举报任务（平台名称、问题类型、条款原文与截图）。\n"
        "2. 在论坛参与讨论、发帖、回复、点赞、收藏。\n"
        "3. 每日签到获取积分，查看周/月/总排行榜。\n"
        "4. 浏览知识库，了解法律法规与维权指南。\n"
        "当前 AI 导游未配置 API，管理员可在后台「设置」中配置 AI API URL/Key/Model，或设置 AI_API_URL / AI_API_KEY / AI_MODEL 环境变量。"
    )


class ChatIn(BaseModel):
    question: str = Field(min_length=1, max_length=1000)


class FutureIn(BaseModel):
    content: str = Field(min_length=1, max_length=2000)


@router.post("/chat")
def chat(body: ChatIn, user: dict | None = Depends(get_optional_user)):
    question = body.question.strip()

    # 鼠标握手机制：已登录用户需在超时阈值内有鼠标活动才能进行 AI 对话
    if user and not is_handshake_active(user["id"]):
        raise BizError(4033, "请移动鼠标验证真人身份后再发言")

    # 攻击检测：任何输入均经过检测
    attack_result = detect(question)
    if attack_result.is_attack:
        if user:
            with db() as conn:
                handle_attack(conn, user["id"], attack_result.reason)
            raise BizError(4030, "检测到攻击性内容，账号已被封禁")
        raise BizError(4031, "检测到攻击性内容，请求被拒绝")
    if attack_result.is_suspicious:
        # 可疑输入：记录日志但不封禁，继续正常处理
        from ..common import log_admin
        with db() as conn:
            log_admin(conn, 0, "可疑AI输入", f"user_id={user.get('id', 'anonymous')}, {attack_result.reason[:200]}")

    url, key, model = _ai_config()
    if not url or not model:
        return ok({"reply": _static_tour(), "recorded": False})

    messages = [
        {"role": "system", "content": _system_prompt()},
        {"role": "user", "content": question},
    ]
    reply = _call_ai(messages)
    recorded = False
    if OUT_OF_SCOPE_REPLY in reply:
        _record_future(question)
        recorded = True
    return ok({"reply": reply, "recorded": recorded})


@router.post("/future")
def record_future(body: FutureIn, user: dict | None = Depends(get_optional_user)):
    _record_future(body.content.strip())
    return ok(None, "已记录至 Future.md")
