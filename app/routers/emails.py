"""邮件代发系统：模板生成、预览、平台统一邮箱代发/自行发送、管理员复核、POP3 收件箱。"""
import json
import poplib
import smtplib
from datetime import datetime
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Form, UploadFile
from pydantic import BaseModel, Field

from ..attack_detector import detect, handle_attack
from ..common import BizError, add_points, fail, log_admin, ok, page_args
from ..config import ISSUE_TYPES, UPLOAD_DIR
from ..content_guard import add_daily_image_bytes, check_daily_image_bytes
from ..database import db
from ..errlog import log_error
from ..handshake import require_handshake
from ..image_upload import image_policy, store_upload_image
from ..routers.admin import get_setting
from ..security import csrf_check, get_current_user, get_threshold, require_roles

router = APIRouter()

def _build_email(
    platform_name: str,
    issue_type: str,
    description: str,
    law_reference: str,
    clause_text: str,
    attachments: list[str],
    sender_name: str,
) -> tuple[str, str]:
    subject = f"关于{platform_name}{issue_type}问题的合规提醒"
    attachment_lines = "\n".join(f"- {a}" for a in attachments) or "（无附件）"
    body = (
        f"尊敬的 {platform_name} 法务部/数据保护官：\n\n"
        "本人注意到贵司在处理用户数据方面存在以下情况，可能与相关法律规定不完全一致：\n\n"
        "【问题描述】\n"
        f"{description}\n\n"
        "【涉及法律条款】\n"
        f"{law_reference or '（用户未填写）'}\n\n"
        "【条款原文】\n"
        f"{clause_text or '（用户未提供）'}\n\n"
        "【相关证据】\n"
        f"{attachment_lines}\n\n"
        "本人希望通过此邮件提醒贵司关注此问题，并期待贵司在合理期限内作出回应。\n\n"
        "此致\n"
        f"{sender_name or '匿名用户'}\n"
        f"发送时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    return subject, body


def _email_out(row) -> dict:
    return {
        "id": row["id"],
        "platform_name": row["platform_name"],
        "issue_type": row["issue_type"],
        "description": row["description"],
        "law_reference": row["law_reference"],
        "clause_text": row["clause_text"],
        "attachments": json.loads(row["attachments"]),
        "recipient": row["recipient"],
        "subject": row["subject"],
        "body": row["body"],
        "send_method": row["send_method"],
        "status": row["status"],
        "admin_label": row["admin_label"],
        "backup_copy": row["backup_copy"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


class ReviewIn(BaseModel):
    admin_label: str = Field(pattern="^(effective|needs_supplement)$")


def _send_smtp(recipient: str, subject: str, body: str, attachments: list[str]) -> None:
    host = get_setting("smtp_host")
    try:
        port = int(get_setting("smtp_port") or 465)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise BizError(5002, "邮件发送失败：SMTP 端口必须是 1-65535 之间的数字")
    username = get_setting("smtp_user")
    password = get_setting("smtp_pass")
    use_ssl = get_setting("smtp_use_ssl", "1") in ("1", "true", "True")
    mail_from = get_setting("mail_from") or username or "noreply@compliance.local"
    if not host or not username:
        raise BizError(5003, "邮件服务器（SMTP）未配置")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = recipient
    msg.set_content(body)
    for name in attachments:
        path = UPLOAD_DIR / name
        if path.exists():
            msg.add_attachment(path.read_bytes(), maintype="image", subtype=Path(name).suffix.lstrip("."), filename=name)

    server = None
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            server = smtplib.SMTP(host, port, timeout=15)
            server.starttls()
        server.login(username, password)
        server.send_message(msg)
    except Exception as e:
        log_error("email_smtp", str(e))
        raise BizError(5002, f"邮件发送失败：{e}")
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


@router.post("")
def create_email(
    platform_name: str = Form(min_length=1, max_length=60),
    issue_type: str = Form(min_length=1, max_length=30),
    description: str = Form(min_length=1, max_length=10000),
    law_reference: str = Form(default="", max_length=1000),
    clause_text: str = Form(default="", max_length=20000),
    recipient: str = Form(min_length=1, max_length=200),
    sender_name: str = Form(default="", max_length=60),
    send_method: str = Form(default="proxy"),
    image_target_bytes: str = Form(default="auto"),
    images: list[UploadFile] | None = None,
    user: dict = Depends(csrf_check),
    _: dict = Depends(require_handshake),
):
    if issue_type not in ISSUE_TYPES:
        raise BizError(4006, f"无效的问题类型，可选：{', '.join(ISSUE_TYPES)}")
    if send_method not in ("proxy", "self"):
        raise BizError(4001, "发送方式只能是 proxy 或 self")

    # 攻击检测
    combined = f"{platform_name} {description} {law_reference} {clause_text} {sender_name}"
    attack_result = detect(combined)
    if attack_result.is_attack:
        with db() as conn:
            handle_attack(conn, user["id"], attack_result.reason)
        raise BizError(4030, "检测到攻击性内容，账号已被封禁")
    if attack_result.is_suspicious:
        with db() as conn:
            log_admin(conn, 0, "可疑邮件内容", f"user_id={user['id']}, {attack_result.reason[:200]}")

    images = images or []
    upload_policy = image_policy(int(user.get("points") or 0))
    if len(images) > upload_policy["max_count"]:
        raise BizError(4007, f"单次最多上传 {upload_policy['max_count']} 张图片")
    stored = []
    stored_bytes = 0
    try:
        for img in images:
            result = store_upload_image(img, int(user.get("points") or 0), image_target_bytes)
            stored.append(result.filename)
            stored_bytes += result.stored_bytes
        if stored_bytes:
            max_image = get_threshold("threshold_daily_image_bytes", 4194304)
            with db() as conn:
                check_daily_image_bytes(conn, user["id"], stored_bytes, max_image)
                add_daily_image_bytes(conn, user["id"], stored_bytes)
    except BizError:
        for name in stored:
            try:
                (UPLOAD_DIR / name).unlink()
            except OSError:
                pass
        raise

    platform_name = platform_name.strip()
    subject, body = _build_email(platform_name, issue_type, description, law_reference, clause_text, stored, sender_name)
    status = "draft"
    backup_copy = body
    try:
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO emails (user_id, platform_name, issue_type, description, law_reference, clause_text, "
                "attachments, recipient, subject, body, send_method, status, backup_copy) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    user["id"], platform_name, issue_type, description, law_reference, clause_text,
                    json.dumps(stored), recipient, subject, body, send_method, status, backup_copy,
                ),
            )
            row = conn.execute("SELECT * FROM emails WHERE id=?", (cur.lastrowid,)).fetchone()
        return ok(_email_out(row), "邮件草稿已生成，请预览后确认发送")
    except Exception:
        # DB 或未知异常导致事务回滚，清理已保存的附件避免孤立文件
        for name in stored:
            try:
                (UPLOAD_DIR / name).unlink()
            except OSError:
                pass
        raise


@router.get("/my")
def my_emails(
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(get_current_user),
):
    page, limit, offset = page_args(page, limit)
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM emails WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (user["id"], limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS c FROM emails WHERE user_id=?", (user["id"],)).fetchone()["c"]
    return ok({"items": [_email_out(r) for r in rows], "total": total, "page": page, "limit": limit})


@router.get("/{email_id}")
def get_email(email_id: int, user: dict = Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT * FROM emails WHERE id=?", (email_id,)).fetchone()
    if row is None or row["user_id"] != user["id"]:
        raise BizError(4040, "邮件不存在")
    return ok(_email_out(row))


@router.post("/{email_id}/send")
def send_email(email_id: int, user: dict = Depends(csrf_check)):
    with db() as conn:
        row = conn.execute("SELECT * FROM emails WHERE id=?", (email_id,)).fetchone()
        if row is None or row["user_id"] != user["id"]:
            raise BizError(4040, "邮件不存在")

        # 自行发送只生成模板，不使用平台发信能力，也无需将内容提交给外部 AI。
        # 这既符合用户选择，也避免在未配置 AI 时错误阻断本地导出流程。
        if row["send_method"] == "self" and row["status"] in ("draft", "failed"):
            conn.execute(
                "UPDATE emails SET status='self_sent', updated_at=datetime('now','localtime') WHERE id=?",
                (email_id,),
            )
            updated = conn.execute("SELECT * FROM emails WHERE id=?", (email_id,)).fetchone()
            return ok(_email_out(updated), "模板已生成，请使用你自己的邮箱发送")

        # 草稿状态 → 先进入 AI 审核流程
        if row["status"] in ("draft", "failed"):
            conn.execute(
                "UPDATE emails SET status='ai_pending', updated_at=datetime('now','localtime') WHERE id=?",
                (email_id,),
            )
        # 已通过审核 → 直接发送
        elif row["status"] == "approved":
            attachments = json.loads(row["attachments"])
            if row["send_method"] == "proxy":
                try:
                    _send_smtp(row["recipient"], row["subject"], row["body"], attachments)
                    status = "sent"
                    msg = "邮件已通过平台统一邮箱发送"
                except BizError as e:
                    status = "failed"
                    conn.execute(
                        "UPDATE emails SET status=?, updated_at=datetime('now','localtime') WHERE id=?",
                        (status, email_id),
                    )
                    updated = conn.execute("SELECT * FROM emails WHERE id=?", (email_id,)).fetchone()
                    return fail(e.code, e.message)
            else:
                status = "self_sent"
                msg = "请复制下方模板与收件人地址，使用你自己的邮箱发送"

            conn.execute(
                "UPDATE emails SET status=?, updated_at=datetime('now','localtime') WHERE id=?",
                (status, email_id),
            )
            updated = conn.execute("SELECT * FROM emails WHERE id=?", (email_id,)).fetchone()
            return ok(_email_out(updated), msg)
        else:
            raise BizError(4002, f"当前状态（{row['status']}）不可发送，请先提交审核")

    # 草稿状态：提交后调用 AI 初审
    from ..routers.ai_review import run_ai_initial_review
    result = run_ai_initial_review(email_id)

    if result["verdict"] == "error":
        return fail(5003, result.get("reason", "AI 审核服务暂不可用"))
    if result["verdict"] == "pass":
        with db() as conn:
            already = conn.execute(
                "SELECT id FROM point_logs WHERE user_id=? AND ref_type='email' AND ref_id=? AND reason='邮件代发通过初审'",
                (user["id"], email_id),
            ).fetchone()
            if not already:
                from ..common import add_points
                reward = get_threshold("threshold_reward_email_initial_approved", 2)
                if reward > 0:
                    add_points(conn, user["id"], reward, "邮件代发通过初审", "email", email_id)
        return ok({"status": "human_pending", "review_result": result}, "邮件已提交审核，等待管理员复核")
    else:
        # 审核拒绝不是“发送成功”。返回非零业务码，避免调用方继续进入人工复核。
        return fail(4002, f"AI 初审未通过：{result.get('reason', '')}")


# ---------- T3.2: AI 审核集成 ----------

@router.post("/{email_id}/submit-review")
def submit_email_review(email_id: int, user: dict = Depends(csrf_check)):
    """提交邮件进入 AI 审核流程。draft → ai_pending → human_pending / rejected。"""
    with db() as conn:
        row = conn.execute("SELECT * FROM emails WHERE id=?", (email_id,)).fetchone()
        if row is None or row["user_id"] != user["id"]:
            raise BizError(4040, "邮件不存在")
        if row["status"] not in ("draft", "failed"):
            raise BizError(4002, f"当前状态（{row['status']}）不可提交审核")

        # 先更新状态为 ai_pending（仅当仍为 draft/failed 时），防止并发重复提交
        conn.execute(
            "UPDATE emails SET status='ai_pending', updated_at=datetime('now','localtime') "
            "WHERE id=? AND status IN ('draft','failed')",
            (email_id,),
        )
        # 校验是否成功更新（如果已被其他请求抢先处理，affected=0）
        if conn.execute("SELECT changes() AS c").fetchone()["c"] == 0:
            raise BizError(4002, "邮件已被其他请求提交审核，请刷新后重试")

    # 调用 AI 初审（在独立连接中执行，不影响已有事务）
    from ..routers.ai_review import run_ai_initial_review
    result = run_ai_initial_review(email_id)

    # 初审通过后，加激励积分
    if result["verdict"] == "pass":
        with db() as conn:
            already = conn.execute(
                "SELECT id FROM point_logs WHERE user_id=? AND ref_type='email' AND ref_id=? AND reason='邮件代发通过初审'",
                (user["id"], email_id),
            ).fetchone()
            if not already:
                from ..common import add_points
                reward = get_threshold("threshold_reward_email_initial_approved", 2)
                if reward > 0:
                    add_points(conn, user["id"], reward, "邮件代发通过初审", "email", email_id)

    return ok(result, "AI 初审完成")


# ---------- 管理员复核 ----------

@router.get("/admin/emails")
def admin_list_emails(
    status: str = "",
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(require_roles("admin", "sysadmin")),
):
    page, limit, offset = page_args(page, limit)
    where = "1=1"
    params = []
    if status and status in ("draft", "pending", "sent", "failed", "self_sent"):
        where += " AND e.status=?"
        params.append(status)
    sql = (
        "SELECT e.*, u.nickname, u.email FROM emails e JOIN users u ON e.user_id=u.id "
        f"WHERE {where} ORDER BY e.created_at DESC LIMIT ? OFFSET ?"
    )
    with db() as conn:
        rows = conn.execute(sql, (*params, limit, offset)).fetchall()
        total = conn.execute(f"SELECT COUNT(*) AS c FROM emails e WHERE {where}", params).fetchone()["c"]
    return ok({
        "items": [
            {
                "id": r["id"], "user_id": r["user_id"], "nickname": r["nickname"], "email": r["email"],
                "platform_name": r["platform_name"], "issue_type": r["issue_type"], "recipient": r["recipient"],
                "subject": r["subject"], "send_method": r["send_method"], "status": r["status"],
                "admin_label": r["admin_label"], "created_at": r["created_at"],
            }
            for r in rows
        ],
        "total": total, "page": page, "limit": limit,
    })


@router.post("/admin/emails/{email_id}/review")
def admin_review_email(email_id: int, body: ReviewIn, user: dict = Depends(require_roles("admin", "sysadmin", mutating=True))):
    with db() as conn:
        row = conn.execute("SELECT * FROM emails WHERE id=?", (email_id,)).fetchone()
        if row is None:
            raise BizError(4040, "邮件不存在")
        if row["user_id"] == user["id"]:
            raise BizError(4001, "不能复核自己发送的邮件")

        # 处理 AI 审核流程中的邮件（ai_pending/human_pending/ai_debate）
        if row["status"] in ("ai_pending", "human_pending", "ai_debate"):
            new_status = "approved" if body.admin_label == "effective" else "rejected"
            conn.execute(
                "UPDATE emails SET status=?, admin_label=?, reviewed_by=?, reviewed_at=datetime('now','localtime'), "
                "updated_at=datetime('now','localtime') WHERE id=?",
                (new_status, body.admin_label, user["id"], email_id),
            )
            # 写入系统通知
            conn.execute(
                "INSERT INTO system_messages (type, title, content, ref_type, ref_id) "
                "VALUES ('email',?,?,?,?)",
                (
                    f"邮件代发审核{'通过' if new_status == 'approved' else '未通过'}",
                    f"管理员审核：{body.admin_label}",
                    "email",
                    email_id,
                ),
            )
            if body.admin_label == "effective":
                already = conn.execute(
                    "SELECT id FROM point_logs WHERE user_id=? AND ref_type='email' AND ref_id=? AND reason='代发邮件审核有效'",
                    (row["user_id"], email_id),
                ).fetchone()
                if not already:
                    reward = get_threshold("threshold_reward_email_valid", 3)
                    if reward > 0:
                        add_points(conn, row["user_id"], reward, "代发邮件审核有效", "email", email_id)
            log_admin(conn, user["id"], "审核邮件代发", f"email_id={email_id}, status={new_status}")
            return ok(None, "审核完成")

        if row["status"] != "sent":
            raise BizError(4002, f"当前状态（{row['status']}）不可复核")

        conn.execute(
            "UPDATE emails SET admin_label=?, reviewed_by=?, reviewed_at=datetime('now','localtime'), "
            "updated_at=datetime('now','localtime') WHERE id=?",
            (body.admin_label, user["id"], email_id),
        )
        if body.admin_label == "effective":
            already = conn.execute(
                "SELECT id FROM point_logs WHERE user_id=? AND ref_type='email' AND ref_id=? AND reason='代发邮件审核有效'",
                (row["user_id"], email_id),
            ).fetchone()
            if not already:
                reward = get_threshold("threshold_reward_email_valid", 3)
                if reward > 0:
                    add_points(conn, row["user_id"], reward, "代发邮件审核有效", "email", email_id)
        log_admin(conn, user["id"], "复核邮件", f"email_id={email_id}, label={body.admin_label}")
    return ok(None, "复核完成")


# ---------- POP3 收件箱 ----------

def _decode_str(value: str) -> str:
    """解码 MIME 编码的邮件头；非标准原始 UTF-8 做兼容兜底。"""
    if not value:
        return ""
    try:
        h = make_header(decode_header(value))
        return str(h)
    except Exception:
        pass
    # 兼容部分邮件服务器直接返回 UTF-8 原始字节被解析为 latin-1
    try:
        if any(ord(c) > 127 for c in value):
            return value.encode("latin-1").decode("utf-8")
    except Exception:
        pass
    return value


def _get_text_body(msg) -> str:
    """优先提取 text/plain 正文，否则从 text/html 中剥离标签返回纯文本。"""
    if msg.is_multipart():
        plain_parts = []
        html_parts = []
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or "utf-8"
                    plain_parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    pass
            elif ctype == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or "utf-8"
                    html_parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    pass
        if plain_parts:
            return "\n".join(plain_parts)
        if html_parts:
            return _html_to_text("\n".join(html_parts))
        return ""
    ctype = msg.get_content_type()
    try:
        payload = msg.get_payload(decode=True)
        charset = msg.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")
        if ctype == "text/html":
            return _html_to_text(text)
        return text
    except Exception:
        return ""


def _html_to_text(html: str) -> str:
    """极简 HTML 标签剥离，保留换行。"""
    import re
    text = re.sub(r"<br\s*/?>", "\n", html, flags=re.I)
    text = re.sub(r"</p>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&amp;", "&", text)
    return text.strip()


def _parse_received_date(msg) -> str:
    date_str = msg.get("Date", "")
    try:
        dt = parsedate_to_datetime(date_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _load_pop3_settings() -> dict:
    with db() as conn:
        rows = conn.execute(
            "SELECT key, value FROM admin_settings WHERE key IN (?, ?, ?, ?, ?)",
            ("pop3_host", "pop3_port", "pop3_user", "pop3_pass", "pop3_use_ssl"),
        ).fetchall()
    settings = {r["key"]: r["value"] for r in rows}
    try:
        port = int(settings.get("pop3_port") or 995)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise BizError(4001, "POP3 端口必须是 1-65535 之间的数字")
    settings["pop3_port"] = port
    settings["pop3_use_ssl"] = settings.get("pop3_use_ssl", "1") in ("1", "true", "True")
    return settings


@router.post("/admin/emails/fetch-inbox")
def fetch_inbox(user: dict = Depends(require_roles("admin", "sysadmin", mutating=True))):
    settings = _load_pop3_settings()
    host = settings.get("pop3_host", "")
    port = settings.get("pop3_port", 995)
    username = settings.get("pop3_user", "")
    password = settings.get("pop3_pass", "")
    use_ssl = settings.get("pop3_use_ssl", True)
    if not host or not username:
        raise BizError(4001, "POP3 服务器地址和用户名不能为空")

    server = None
    fetched = 0
    skipped = 0
    try:
        if use_ssl:
            server = poplib.POP3_SSL(host, port, timeout=15)
        else:
            server = poplib.POP3(host, port, timeout=15)
        server.user(username)
        server.pass_(password)
        count, _ = server.stat()
        with db() as conn:
            existing_ids = {
                r["message_id"] for r in conn.execute("SELECT message_id FROM email_inbox WHERE message_id != ''").fetchall()
            }
            parser = BytesParser()
            for i in range(1, count + 1):
                try:
                    response = server.retr(i)
                    raw = b"\n".join(response[1])
                    msg = parser.parsebytes(raw)
                    message_id = msg.get("Message-ID", "") or msg.get("Message-Id", "")
                    if message_id and message_id in existing_ids:
                        skipped += 1
                        continue
                    subject = _decode_str(msg.get("Subject", ""))
                    sender = _decode_str(msg.get("From", ""))
                    recipient = _decode_str(msg.get("To", ""))
                    body = _get_text_body(msg)
                    received_at = _parse_received_date(msg)
                    conn.execute(
                        "INSERT INTO email_inbox (message_id, subject, sender, recipient, body, raw_size, received_at) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (message_id, subject, sender, recipient, body, len(raw), received_at),
                    )
                    if message_id:
                        existing_ids.add(message_id)
                    fetched += 1
                except Exception as e:
                    log_error("pop3_parse", f"msg {i}: {e}")
                    continue
            log_admin(conn, user["id"], "收取 POP3 收件箱", f"host={host}, fetched={fetched}, skipped={skipped}, total={count}")
    except BizError:
        raise
    except Exception as e:
        log_error("pop3_fetch", str(e))
        raise BizError(5002, f"POP3 收取失败：{e}")
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass
    return ok({"fetched": fetched, "skipped": skipped, "total": count}, "收件箱收取完成")


@router.get("/admin/emails/inbox")
def list_inbox(
    is_read: int = -1,
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(require_roles("admin", "sysadmin")),
):
    page, limit, offset = page_args(page, limit)
    where = "1=1"
    params = []
    if is_read in (0, 1):
        where += " AND is_read=?"
        params.append(is_read)
    sql = f"SELECT id, message_id, subject, sender, recipient, raw_size, is_read, is_public, post_id, received_at, created_at FROM email_inbox WHERE {where} ORDER BY received_at DESC LIMIT ? OFFSET ?"
    with db() as conn:
        rows = conn.execute(sql, (*params, limit, offset)).fetchall()
        total = conn.execute(f"SELECT COUNT(*) AS c FROM email_inbox WHERE {where}", params).fetchone()["c"]
    return ok({
        "items": [
            {
                "id": r["id"],
                "message_id": r["message_id"],
                "subject": r["subject"],
                "sender": r["sender"],
                "recipient": r["recipient"],
                "raw_size": r["raw_size"],
                "is_read": bool(r["is_read"]),
                "is_public": bool(r["is_public"]),
                "post_id": r["post_id"],
                "received_at": r["received_at"],
                "created_at": r["created_at"],
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "limit": limit,
    })


@router.get("/admin/emails/inbox/{inbox_id}")
def get_inbox_email(inbox_id: int, user: dict = Depends(require_roles("admin", "sysadmin"))):
    with db() as conn:
        row = conn.execute("SELECT * FROM email_inbox WHERE id=?", (inbox_id,)).fetchone()
        if row is None:
            raise BizError(4040, "邮件不存在")
        conn.execute("UPDATE email_inbox SET is_read=1 WHERE id=?", (inbox_id,))
    return ok({
        "id": row["id"],
        "message_id": row["message_id"],
        "subject": row["subject"],
        "sender": row["sender"],
        "recipient": row["recipient"],
        "body": row["body"],
        "raw_size": row["raw_size"],
        "is_read": True,
        "received_at": row["received_at"],
        "created_at": row["created_at"],
    })


@router.post("/admin/emails/inbox/{inbox_id}/read")
def mark_inbox_read(inbox_id: int, user: dict = Depends(require_roles("admin", "sysadmin", mutating=True))):
    with db() as conn:
        row = conn.execute("SELECT id FROM email_inbox WHERE id=?", (inbox_id,)).fetchone()
        if row is None:
            raise BizError(4040, "邮件不存在")
        conn.execute("UPDATE email_inbox SET is_read=1 WHERE id=?", (inbox_id,))
    return ok(None, "已标记为已读")


class InboxPublishIn(BaseModel):
    post_id: int


@router.post("/admin/emails/inbox/{inbox_id}/publish")
def publish_inbox_email(inbox_id: int, body: InboxPublishIn, user: dict = Depends(require_roles("admin", "sysadmin", mutating=True))):
    """将收件箱邮件关联到论坛主题并公开。"""
    with db() as conn:
        email = conn.execute("SELECT id FROM email_inbox WHERE id=?", (inbox_id,)).fetchone()
        if email is None:
            raise BizError(4040, "邮件不存在")
        post = conn.execute("SELECT id FROM posts WHERE id=?", (body.post_id,)).fetchone()
        if post is None:
            raise BizError(4040, "帖子不存在")
        conn.execute(
            "UPDATE email_inbox SET post_id=?, is_public=1, is_read=1 WHERE id=?",
            (body.post_id, inbox_id),
        )
        log_admin(conn, user["id"], "公开收件箱邮件", f"inbox_id={inbox_id}, post_id={body.post_id}")
    return ok(None, "已关联并公开")


@router.get("/inbox/public")
def list_public_inbox_emails(page: int = 1, limit: int = 20):
    """公开关联到主题的收件箱邮件列表。"""
    page, limit, offset = page_args(page, limit)
    sql = (
        "SELECT ei.id, ei.subject, ei.sender, ei.recipient, ei.body, ei.received_at, ei.post_id, p.title AS post_title "
        "FROM email_inbox ei LEFT JOIN posts p ON ei.post_id=p.id "
        "WHERE ei.is_public=1 ORDER BY ei.received_at DESC LIMIT ? OFFSET ?"
    )
    count_sql = "SELECT COUNT(*) AS c FROM email_inbox WHERE is_public=1"
    with db() as conn:
        rows = conn.execute(sql, (limit, offset)).fetchall()
        total = conn.execute(count_sql).fetchone()["c"]
    return ok({
        "items": [
            {
                "id": r["id"],
                "subject": r["subject"],
                "sender": r["sender"],
                "recipient": r["recipient"],
                "body": r["body"],
                "received_at": r["received_at"],
                "post_id": r["post_id"],
                "post_title": r["post_title"],
            }
            for r in rows
        ],
        "total": total, "page": page, "limit": limit,
    })
