"""讨论版生命周期管理：AI 巡查、自动封存/归档、证据包整理。

所有阈值通过 `admin_settings` 动态读取，由 root 在后台配置。
"""
from .database import db
from .errlog import log_error
from .security import get_threshold


def run_daily_lifecycle() -> None:
    """T2.1+T2.2: 每日运行，检查所有板块的封存/归档状态。"""
    closed_ids = []
    try:
        with db() as conn:
            rows = conn.execute(
                "SELECT id, status, evidence_count, closed_at, name FROM categories"
            ).fetchall()
            for row in rows:
                try:
                    if row["status"] == "open":
                        threshold = get_threshold("threshold_evidence_close", 40)
                        if (row["evidence_count"] or 0) >= threshold:
                            conn.execute(
                                "UPDATE categories SET status='closed', closed_at=datetime('now','localtime'), "
                                "updated_at=datetime('now','localtime') WHERE id=?",
                                (row["id"],),
                            )
                            _add_notification(
                                conn, "board",
                                f"板块「{row['name']}」因证据数达到上限已自动封存",
                                "",
                            )
                            closed_ids.append(row["id"])
                    elif row["status"] == "closed" and row["closed_at"]:
                        days = get_threshold("threshold_close_to_archive_days", 21)
                        # 检查是否已关闭超过指定天数
                        expired = conn.execute(
                            "SELECT 1 FROM categories WHERE id=? AND "
                            f"closed_at <= datetime('now','localtime','-{days} days') LIMIT 1",
                            (row["id"],),
                        ).fetchone()
                        if expired:
                            conn.execute(
                                "UPDATE categories SET status='archived', archived_at=datetime('now','localtime'), "
                                "updated_at=datetime('now','localtime') WHERE id=?",
                                (row["id"],),
                            )
                            _add_notification(
                                conn, "board",
                                f"板块「{row['name']}」因长期未活动已自动归档",
                                "",
                            )
                except Exception as e:
                    log_error("lifecycle.check", f"category {row['id']}: {e}")
                    continue
    except Exception as e:
        log_error("lifecycle.run", str(e))

    # T2.4: 在事务外生成证据包，避免嵌套事务死锁
    for cid in closed_ids:
        try:
            generate_evidence_package(cid)
        except Exception as e:
            log_error("lifecycle.evidence", f"category {cid}: {e}")


def run_daily_patrol() -> None:
    """T1.7: 每日 AI 巡查。扫描新增/待审内容，触发危险关键词审核。

    当前实现为轻量版：扫描待审帖子/回复，标记为已巡查。
    完整版需集成 AI 审核接口，这里先做基础框架。
    """
    try:
        with db() as conn:
            # 标记未 AI 巡查的帖子
            unpatrolled_posts = conn.execute(
                "SELECT id, user_id, content FROM posts WHERE is_ai_reviewed=0 AND status='normal'"
            ).fetchall()
            for post in unpatrolled_posts:
                # 基础巡查：标记为已巡查（后续可扩展为 AI 审核）
                conn.execute(
                    "UPDATE posts SET is_ai_reviewed=1 WHERE id=?",
                    (post["id"],),
                )

            # 标记未 AI 巡查的回复
            unpatrolled_replies = conn.execute(
                "SELECT id, user_id, content FROM replies WHERE is_ai_reviewed=0 AND status='normal'"
            ).fetchall()
            for reply in unpatrolled_replies:
                conn.execute(
                    "UPDATE replies SET is_ai_reviewed=1 WHERE id=?",
                    (reply["id"],),
                )
    except Exception as e:
        log_error("daily_patrol", str(e))


def _add_notification(conn, ref_type: str, title: str, content: str) -> None:
    """写入系统通知。"""
    conn.execute(
        "INSERT INTO system_messages (type, title, content, ref_type) VALUES ('system',?,?,?)",
        (title, content, ref_type),
    )


def generate_evidence_package(category_id: int) -> str:
    """T2.4: 证据包整理。AI 最终整理板块内证据，写入 categories.evidence_package。

    当前实现为轻量版：收集板块内所有帖子的标题和内容，合并为 txt 证据包。
    完整版需集成 AI 审核，这里先做基础框架。
    """
    from pathlib import Path
    from ..config import UPLOAD_DIR
    import uuid
    import json

    with db() as conn:
        cat = conn.execute("SELECT id, name FROM categories WHERE id=?", (category_id,)).fetchone()
        if cat is None:
            return ""

        posts = conn.execute(
            "SELECT id, title, content, created_at FROM posts WHERE category_id=? AND status='normal' ORDER BY created_at",
            (category_id,),
        ).fetchall()
        replies = conn.execute(
            "SELECT r.content, r.created_at, u.nickname FROM replies r "
            "JOIN posts p ON r.post_id=p.id JOIN users u ON r.user_id=u.id "
            "WHERE p.category_id=? AND r.status='normal' ORDER BY r.created_at",
            (category_id,),
        ).fetchall()

    # 生成文字证据集 txt
    filename = f"evidence_{uuid.uuid4().hex}.txt"
    path = UPLOAD_DIR / filename
    lines = [f"板块：{cat['name']}", f"生成时间：{__import__('time').strftime('%Y-%m-%d %H:%M:%S')}", "", "--- 帖子 ---"]
    for p in posts:
        lines.append(f"\n标题：{p['title']}")
        lines.append(f"内容：{p['content']}")
        lines.append(f"时间：{p['created_at']}")
        lines.append("")
    lines.append("--- 回复 ---")
    for r in replies:
        lines.append(f"\n{r['nickname']}：{r['content']}（{r['created_at']}）")
    lines.append("")
    lines.append("--- 证据图片 ---")
    # 收集板块内所有帖子的图片
    with db() as conn:
        image_posts = conn.execute(
            "SELECT images FROM tasks WHERE category_id=? AND status='approved'",
            (category_id,),
        ).fetchall()
    all_images = []
    for ip in image_posts:
        imgs = json.loads(ip["images"])
        all_images.extend(imgs)
    if all_images:
        for img in all_images:
            lines.append(f"- {img}")
    else:
        lines.append("（无图片证据）")

    path.write_text("\n".join(lines), encoding="utf-8")

    package = json.dumps({"txt": filename, "images": all_images}, ensure_ascii=False)
    with db() as conn:
        conn.execute(
            "UPDATE categories SET evidence_package=?, updated_at=datetime('now','localtime') WHERE id=?",
            (package, category_id),
        )

    return package