"""多模态 AI 合规检测：检测截图中是否包含第三方个人信息。"""
import base64
import json
import urllib.error
import urllib.request
from pathlib import Path

from .config import AI_API_KEY, AI_API_URL, AI_MODEL
from .errlog import log_error
from .routers.admin import get_setting


PROMPT = (
    "你是一台严格的内容合规检测器。请检查以下图片，判断每张图片是否包含"
    "第三方的真实姓名、手机号、身份证号、人脸、家庭住址、聊天记录中的他人信息等"
    "可能导致平台传播个人隐私的敏感内容。\n"
    "规则：\n"
    "1. 只返回一个 JSON 数组，例如 [0,2] 表示第 0、2 张图片违规；[] 表示全部合规。\n"
    "2. 不要返回任何解释、markdown 或其他文字。\n"
    "3. 若图片完全不含上述第三方敏感信息，返回 []。"
)


def _ai_config() -> tuple[str, str, str]:
    url = get_setting("ai_api_url") or AI_API_URL
    key = get_setting("ai_api_key") or AI_API_KEY
    model = get_setting("ai_vision_model") or get_setting("ai_model") or AI_MODEL
    return url, key, model


def _image_data_url(path: Path) -> str:
    ext = path.suffix.lower()
    mime = "image/png" if ext == ".png" else "image/jpeg" if ext in (".jpg", ".jpeg") else "image/webp"
    data = path.read_bytes()
    return f"data:{mime};base64," + base64.b64encode(data).decode()


def check_images(image_paths: list[Path]) -> list[int]:
    """返回违规图片的索引列表；未配置 AI 或调用失败时返回空列表（不阻塞流程）。"""
    url, key, model = _ai_config()
    if not url or not model or not image_paths:
        return []

    messages = [
        {"role": "system", "content": PROMPT},
        {
            "role": "user",
            "content": [
                {"type": "text", "text": f"请检测以下 {len(image_paths)} 张图片，返回违规索引数组。"},
                *[
                    {"type": "image_url", "image_url": {"url": _image_data_url(p)}}
                    for p in image_paths
                ],
            ],
        },
    ]

    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
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
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            text = result["choices"][0]["message"]["content"].strip()
            # 尝试提取 JSON 数组
            text = text.strip("`")
            if text.startswith("json"):
                text = text[4:].strip()
            arr = json.loads(text)
            if isinstance(arr, list):
                return [int(i) for i in arr if isinstance(i, int) and 0 <= i < len(image_paths)]
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        log_error("ai_check", f"AI 检测 HTTP 错误: {e.code} {body[:200]}")
    except Exception as e:
        log_error("ai_check", f"AI 检测异常: {e}")
    return []
