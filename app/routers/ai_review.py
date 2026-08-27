"""AI 多模型辩论审核编排：邮件代发审核。

状态机：
  draft → ai_pending（AI 初审）→ approved（通过） / rejected（直接退回）
         → human_pending（24 小时人工窗口）→ approved / rejected
         → ai_debate（人工未审，触发多模型辩论）→ approved / rejected

模型职责：
  - Deepseek/Qwen/MiniMax：攻击性质疑
  - 具备联网检索能力的模型：搜索验证
  - 默认 1-3 轮即可判定，争议大时最高 5 轮
"""
import json
import time
import urllib.request
from urllib.error import URLError

from ..common import BizError, ok
from ..database import db
from ..errlog import log_error
from ..routers.admin import get_setting

# 默认模型列表（root 可在后台通过 admin_settings 覆盖）
DEFAULT_DEBATE_MODELS = {
    "attacker": ["deepseek-chat", "qwen-max", "minimax-abab6.5"],
    "verifier": ["qwen-max"],
}

DEBATE_MAX_ROUNDS = 5  # 最高辩论轮数


def _call_ai_api(prompt: str, model: str = "") -> str:
    """调用后台配置的 AI API 接口，返回响应文本。"""
    url = get_setting("ai_api_url", "")
    key = get_setting("ai_api_key", "")
    model = model or get_setting("ai_review_model") or get_setting("ai_model", "gpt-4o-mini")
    if not url or not key:
        raise BizError(5005, "AI API 未配置")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
    }
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 2000,
    }).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode())
        return result.get("choices", [{}])[0].get("message", {}).get("content", "")
    except URLError as e:
        log_error("ai_review.api", f"model={model}: {e}")
        raise BizError(5006, f"AI 调用失败：{e.reason}")
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        log_error("ai_review.parse", str(e))
        raise BizError(5007, f"AI 响应解析失败：{e}")


def _ai_review_prompt(email_content: str) -> str:
    """AI 初审 Prompt：检查邮件内容是否合规。"""
    return (
        "你是一个邮件审核助手。请审核以下代发邮件内容，判断其是否适合通过平台发送。\n\n"
        "审核标准：\n"
        "1. 内容是否涉及真实、合理的投诉或维权诉求\n"
        "2. 是否存在明显的攻击性、侮辱性、诽谤性语言\n"
        "3. 是否包含要求平台忽略法律/政策的内容\n"
        "4. 是否明显属于刷 token 或恶意提交\n\n"
        "请回复以下 JSON 格式（不要包含其他内容）：\n"
        '{"verdict": "pass|reject", "reason": "简短理由"}'
        "\n\n邮件内容：\n" + email_content
    )


def _debate_attacker_prompt(email_content: str, round_num: int, history: str) -> str:
    """攻击性质疑 Prompt。"""
    return (
        f"你是一个严格的邮件审核员（第 {round_num} 轮）。请从以下角度攻击性地质疑这封代发邮件：\n"
        "1. 邮件诉求是否真实可信？\n"
        "2. 是否存在夸大或虚假陈述？\n"
        "3. 法律依据是否准确？\n"
        "4. 证据是否充分？\n\n"
        f"历史讨论：\n{history}\n\n"
        "请输出 JSON 格式：\n"
        '{"issues": ["问题1", "问题2"], "risk_level": "low|medium|high", "should_block": true|false}'
        "\n\n邮件内容：\n" + email_content
    )


def _debate_verifier_prompt(email_content: str, round_num: int, history: str) -> str:
    """搜索验证 Prompt。"""
    return (
        f"你是一个信息验证员（第 {round_num} 轮）。请评估以下邮件中提到的平台和问题是否真实存在：\n"
        "1. 邮件中提到的平台是否存在？\n"
        "2. 描述的条款/问题类型是否合理？\n"
        "3. 是否有已知的类似案例或新闻报道？\n\n"
        f"历史讨论：\n{history}\n\n"
        "请输出 JSON 格式：\n"
        '{"verification": "可信|存疑|不可信", "details": "具体说明", "should_block": true|false}'
        "\n\n邮件内容：\n" + email_content
    )


def _parse_json_response(text: str) -> dict:
    """从 AI 响应中解析 JSON。"""
    text = text.strip()
    # 尝试提取 JSON 块
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError) as e:
        log_error("ai_review.json_parse", f"text={text[:200]}: {e}")
        raise BizError(5007, f"AI 响应 JSON 解析失败：{e}")


def run_ai_initial_review(email_id: int) -> dict:
    """T3: AI 初审。返回 {'verdict': 'pass'|'reject', 'reason': '...'}。"""
    with db() as conn:
        row = conn.execute("SELECT id, body, description FROM emails WHERE id=?", (email_id,)).fetchone()
        if row is None:
            raise BizError(4040, "邮件不存在")
        email_content = row["body"] or row["description"]

    try:
        response = _call_ai_api(_ai_review_prompt(email_content))
        result = _parse_json_response(response)
        verdict = result.get("verdict", "reject")
        reason = result.get("reason", "AI 初审通过")
    except BizError as e:
        log_error("ai_review.initial", f"email_id={email_id}: {e}")
        verdict = "error"
        reason = "AI 审核服务未配置或暂不可用"
    except Exception as e:
        log_error("ai_review.initial", f"email_id={email_id}: {e}")
        verdict = "error"
        reason = "AI 初审异常，请稍后重试"

    # 更新邮件状态
    with db() as conn:
        if verdict == "error":
            conn.execute(
                "UPDATE emails SET status='failed', updated_at=datetime('now','localtime') WHERE id=?",
                (email_id,),
            )
        elif verdict == "reject":
            conn.execute(
                "UPDATE emails SET status='rejected', admin_label='needs_supplement', "
                "updated_at=datetime('now','localtime') WHERE id=?",
                (email_id,),
            )
            # 写入系统通知
            conn.execute(
                "INSERT INTO system_messages (type, title, content, ref_type, ref_id) "
                "VALUES ('email','邮件代发审核未通过',?,?,?)",
                (f"AI 初审未通过：{reason}", "email", email_id),
            )
        else:
            # 进入人工审核等待队列
            conn.execute(
                "UPDATE emails SET status='human_pending', "
                "updated_at=datetime('now','localtime') WHERE id=?",
                (email_id,),
            )

    return {"verdict": verdict, "reason": reason}


def run_ai_debate(email_id: int) -> dict:
    """T3: 多模型辩论审核。默认 1-3 轮，争议大时最高 5 轮。

    返回 {'verdict': 'approved'|'rejected', 'reason': '...', 'rounds': int}。
    """
    with db() as conn:
        row = conn.execute("SELECT id, body, description FROM emails WHERE id=?", (email_id,)).fetchone()
        if row is None:
            raise BizError(4040, "邮件不存在")
        email_content = row["body"] or row["description"]

    # 读取辩论轮数配置
    from ..security import get_threshold
    max_rounds = min(get_threshold("threshold_debate_rounds", 5), DEBATE_MAX_ROUNDS)

    attacker_models = get_setting("debate_attacker_models", json.dumps(DEFAULT_DEBATE_MODELS["attacker"]))
    verifier_models = get_setting("debate_verifier_models", json.dumps(DEFAULT_DEBATE_MODELS["verifier"]))
    try:
        attackers = json.loads(attacker_models) if isinstance(attacker_models, str) else DEFAULT_DEBATE_MODELS["attacker"]
        verifiers = json.loads(verifier_models) if isinstance(verifier_models, str) else DEFAULT_DEBATE_MODELS["verifier"]
    except (json.JSONDecodeError, TypeError):
        attackers = DEFAULT_DEBATE_MODELS["attacker"]
        verifiers = DEFAULT_DEBATE_MODELS["verifier"]

    history = "（初始审核）"
    attack_votes = 0
    verify_votes = 0
    total_votes = 0
    final_verdict = "approved"
    final_reason = ""

    for round_num in range(1, max_rounds + 1):
        round_issues = []
        round_should_block = []

        # 攻击方发言
        for model in attackers:
            try:
                prompt = _debate_attacker_prompt(email_content, round_num, history)
                response = _call_ai_api(prompt, model)
                result = _parse_json_response(response)
                if result.get("should_block"):
                    attack_votes += 1
                round_should_block.append(result.get("should_block", False))
                round_issues.append(result.get("issues", []))
                total_votes += 1
            except Exception as e:
                log_error(f"ai_review.debate_attacker", f"model={model}, round={round_num}: {e}")
                continue

        # 验证方发言
        for model in verifiers:
            try:
                prompt = _debate_verifier_prompt(email_content, round_num, history)
                response = _call_ai_api(prompt, model)
                result = _parse_json_response(response)
                if result.get("should_block"):
                    verify_votes += 1
                round_should_block.append(result.get("should_block", False))
                total_votes += 1
            except Exception as e:
                log_error(f"ai_review.debate_verifier", f"model={model}, round={round_num}: {e}")
                continue

        # 更新历史
        issues_text = "; ".join([str(i) for sub in round_issues for i in (sub if isinstance(sub, list) else [sub])])
        history = f"第 {round_num} 轮讨论：\n问题：{issues_text}\n"

        # 判断是否可提前结束
        if total_votes >= 3:
            block_ratio = (attack_votes + verify_votes) / total_votes
            if block_ratio >= 0.6:  # 60% 以上认为应阻止
                final_verdict = "rejected"
                final_reason = f"多模型辩论后判定：{int(block_ratio * 100)}% 模型认为应阻止"
                break
            elif block_ratio <= 0.2 and round_num >= 2:  # 20% 以下认为应阻止且已至少 2 轮
                final_verdict = "approved"
                final_reason = "多模型辩论后判定：风险较低，审核通过"
                break

    # 如果所有轮次结束仍未明确判定，根据投票结果决定
    if final_verdict == "approved" and total_votes > 0:
        block_ratio = (attack_votes + verify_votes) / total_votes
        if block_ratio >= 0.5:
            final_verdict = "rejected"
            final_reason = f"多模型辩论后判定：{int(block_ratio * 100)}% 模型认为应阻止"

    # 更新邮件状态
    with db() as conn:
        new_status = "approved" if final_verdict == "approved" else "rejected"
        conn.execute(
            "UPDATE emails SET status=?, updated_at=datetime('now','localtime') WHERE id=?",
            (new_status, email_id),
        )
        conn.execute(
            "INSERT INTO system_messages (type, title, content, ref_type, ref_id) "
            "VALUES ('email',?,?,?,?)",
            (
                f"邮件代发{new_status}" if new_status == "approved" else "邮件代发未通过",
                f"AI 多模型辩论结束：{final_reason}",
                "email",
                email_id,
            ),
        )

    return {"verdict": final_verdict, "reason": final_reason, "rounds": round_num}
