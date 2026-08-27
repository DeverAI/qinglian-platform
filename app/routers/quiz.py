"""条文背诵游戏 API：从法律知识库挖空生成 4 选 1 选择题，答对加积分。

题目生成算法：对法律条款按句号/分号切分，选长度 20-80 字的句子，
随机挖空 1-2 个 2-4 字的实词，干扰项从同法其他条款抽取相近词。
每日每用户最多 5 题计分，答错不扣分但本题不再计分。
"""
import json
import random
import re
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..common import BizError, add_points, ok
from ..database import db
from ..handshake import require_handshake
from ..security import csrf_check, get_current_user, get_threshold

router = APIRouter()

def _daily_limit() -> int:
    return get_threshold("threshold_quiz_daily_limit", 5)


def _points_per_correct() -> int:
    return get_threshold("threshold_reward_quiz_correct", 1)


class AnswerIn(BaseModel):
    question_id: int
    option_index: int = Field(ge=0, le=3)


def _today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _today_answered(conn, user_id: int) -> int:
    """今日已答题数。"""
    today = _today_str() + "%"
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM quiz_records WHERE user_id=? AND answered_at LIKE ?",
        (user_id, today),
    ).fetchone()
    return int(row["c"])


def _today_correct(conn, user_id: int) -> int:
    """今日答对数。"""
    today = _today_str() + "%"
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM quiz_records WHERE user_id=? AND is_correct=1 AND answered_at LIKE ?",
        (user_id, today),
    ).fetchone()
    return int(row["c"])


def _pick_sentence(content: str) -> tuple[str, str] | None:
    """从法律条款中选一句适合挖空的句子，返回 (sentence, blank_word)。"""
    # 按句号/分号切分
    sentences = [s.strip() for s in re.split(r"[。；]", content) if s.strip()]
    # 筛选长度 20-80 字的句子
    candidates = [s for s in sentences if 20 <= len(s) <= 80]
    if not candidates:
        return None
    sentence = random.choice(candidates)
    # 从句子中找 2-4 字的实词候选（中文连续汉字）
    words = re.findall(r"[\u4e00-\u9fa5]{2,4}", sentence)
    if not words:
        return None
    # 优先选不靠近句首的词（避免挖空主语导致题目过难）
    mid_words = [w for w in words if sentence.find(w) >= 4]
    blank = random.choice(mid_words if mid_words else words)
    return sentence, blank


def _make_distractors(blank: str, all_content: str, count: int = 3) -> list[str]:
    """从同法其他条款抽取相近长度的词作为干扰项。"""
    words = list(set(re.findall(r"[\u4e00-\u9fa5]{2,4}", all_content)))
    # 排除与答案相同的词
    words = [w for w in words if w != blank]
    # 优先选长度相近的
    random.shuffle(words)
    # 取前 count 个，不足则用占位
    result = words[:count]
    while len(result) < count:
        result.append("其他条款")
    return result


@router.get("/question")
def get_question(user: dict = Depends(get_current_user)):
    """获取一道条文背诵选择题。"""
    with db() as conn:
        # 校验今日上限
        answered = _today_answered(conn, user["id"])
        daily_limit = _daily_limit()
        if answered >= daily_limit:
            raise BizError(4032, f"今日已达上限（{daily_limit} 题）")

        # 从知识库法律类条目中随机抽取
        entries = conn.execute(
            "SELECT id, content FROM knowledge_entries WHERE category='law' AND content IS NOT NULL AND length(content) > 40 "
            "ORDER BY RANDOM() LIMIT 10"
        ).fetchall()
        if not entries:
            raise BizError(4040, "暂无可用的法律条文题目")

        # 尝试从这些条目中生成一道未答过的题
        for entry in entries:
            picked = _pick_sentence(entry["content"])
            if not picked:
                continue
            sentence, blank = picked
            # 挖空文本：将 blank 替换为 ____
            blank_text = sentence.replace(blank, "____", 1)
            # 检查当前用户是否已答过相同题目（用 knowledge_id + blank_text 精确匹配）
            existing = conn.execute(
                "SELECT 1 FROM quiz_records qr "
                "JOIN quiz_questions qq ON qq.id = qr.question_id "
                "WHERE qr.user_id=? AND qq.knowledge_id=? AND qq.blank_text=?",
                (user["id"], entry["id"], blank_text),
            ).fetchone()
            if existing:
                continue

            # 生成选项
            distractors = _make_distractors(blank, entry["content"], 3)
            options = distractors + [blank]
            random.shuffle(options)
            answer_index = options.index(blank)

            # 落库题目
            cur = conn.execute(
                "INSERT INTO quiz_questions (knowledge_id, blank_text, options_json, answer_index) "
                "VALUES (?,?,?,?)",
                (entry["id"], blank_text, json.dumps(options, ensure_ascii=False), answer_index),
            )
            question_id = cur.lastrowid
            return ok({
                "question_id": question_id,
                "blank_text": blank_text,
                "options": options,
                "knowledge_id": entry["id"],
                "today_answered": answered,
                "today_correct": _today_correct(conn, user["id"]),
                "daily_limit": _daily_limit(),
            })

    raise BizError(4040, "暂无新题目，请稍后再试")


@router.post("/answer")
def submit_answer(body: AnswerIn, user: dict = Depends(csrf_check), _: dict = Depends(require_handshake)):
    """提交答案。答对 +1 积分，答错不扣分但本题不再计分。"""
    import sqlite3

    with db() as conn:
        # BEGIN IMMEDIATE 获取写锁，防止并发请求同时通过日答题数校验
        conn.execute("BEGIN IMMEDIATE")

        q = conn.execute(
            "SELECT * FROM quiz_questions WHERE id=?", (body.question_id,)
        ).fetchone()
        if q is None:
            raise BizError(4040, "题目不存在")

        is_correct = body.option_index == q["answer_index"]
        points_delta = 0
        # 校验今日上限（已获取写锁，串行安全）
        if is_correct:
            answered = _today_answered(conn, user["id"])
            daily_limit = _daily_limit()
            if answered >= daily_limit:
                # 超上限：仍记录作答（写真实 is_correct）但不加分
                try:
                    conn.execute(
                        "INSERT INTO quiz_records (user_id, question_id, is_correct) VALUES (?,?,?)",
                        (user["id"], body.question_id, 1 if is_correct else 0),
                    )
                except sqlite3.IntegrityError:
                    raise BizError(4009, "本题已作答")
                return ok({
                    "is_correct": True,
                    "answer_index": q["answer_index"],
                    "points_delta": 0,
                    "message": f"今日已达上限（{daily_limit} 题），不再加分",
                })
            reward = _points_per_correct()
            if reward > 0:
                added = add_points(conn, user["id"], reward, "条文背诵答对", "quiz", body.question_id)
                if added:
                    points_delta = reward

        # 写作答记录（UNIQUE(user_id, question_id) 防并发双答）
        try:
            conn.execute(
                "INSERT INTO quiz_records (user_id, question_id, is_correct) VALUES (?,?,?)",
                (user["id"], body.question_id, 1 if is_correct else 0),
            )
        except sqlite3.IntegrityError:
            raise BizError(4009, "本题已作答")
    return ok({
        "is_correct": is_correct,
        "answer_index": q["answer_index"],
        "points_delta": points_delta,
    })


@router.get("/today")
def today_status(user: dict = Depends(get_current_user)):
    """返回今日答题状态。"""
    with db() as conn:
        answered = _today_answered(conn, user["id"])
        correct = _today_correct(conn, user["id"])
    return ok({
        "today_answered": answered,
        "today_correct": correct,
        "daily_limit": _daily_limit(),
        "points_per_correct": _points_per_correct(),
        "remaining": max(0, _daily_limit() - answered),
    })
