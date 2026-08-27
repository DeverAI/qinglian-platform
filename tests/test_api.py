"""端到端集成测试。"""
import base64
import io
import os
import sqlite3
from datetime import datetime, timezone
from email.header import Header

import pytest


def _db_conn():
    return sqlite3.connect(os.environ["QLKIMI_DB"])


def add_user_points(user_id: int, points: int):
    """测试辅助：直接给用户加积分。"""
    with _db_conn() as conn:
        conn.execute("UPDATE users SET points = points + ? WHERE id = ?", (points, user_id))
        conn.execute(
            "INSERT INTO point_logs (user_id, delta, reason, ref_type) VALUES (?, ?, ?, ?)",
            (user_id, points, "测试辅助加积分", "test"),
        )
        conn.commit()

SMALL_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="
)


def register(client, email, password, nickname):
    r = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
            "nickname": nickname,
            "guardian_declared": True,
            "device_fingerprint": "fp-" + email,
        },
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["code"] == 0
    return data["data"]


def login(client, email, password):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["data"]


def headers(tokens, two_fa=None):
    """构造认证头：Bearer token + CSRF + X-SID（握手安全）。two_fa 为已验证的 2FA 令牌。"""
    h = {
        "Authorization": "Bearer " + tokens["access_token"],
        "X-CSRF-Token": tokens["csrf_token"],
    }
    sid = tokens.get("sid", "")
    if sid:
        h["X-SID"] = sid
    if two_fa:
        h["X-2FA-Token"] = two_fa
    return h


def handshake(client, tokens):
    """发送一次鼠标握手心跳，更新 sid 活跃时间戳。"""
    return client.post("/api/auth/handshake", headers=headers(tokens))


def j(r):
    return r.json()


class TestAuth:
    def test_register_first_sysadmin(self, client):
        data = register(client, "sys@t.com", "password123", "Sys")
        assert data["user"]["role"] == "sysadmin"
        assert "access_token" in data

    def test_me_and_refresh(self, client):
        tokens = login(client, "sys@t.com", "password123")
        r = client.get("/api/auth/me", headers={"Authorization": "Bearer " + tokens["access_token"]})
        assert r.status_code == 200
        assert j(r)["data"]["email"] == "sys@t.com"

        r = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert r.status_code == 200
        d = j(r)
        assert d["code"] == 0
        assert "access_token" in d["data"]

    def test_logout(self, client):
        tokens = login(client, "sys@t.com", "password123")
        r = client.post("/api/auth/logout", headers=headers(tokens))
        assert r.status_code == 200
        assert j(r)["code"] == 0


class TestTasks:
    def test_task_review_workflow(self, client):
        admin = login(client, "sys@t.com", "password123")
        user = register(client, "u1@t.com", "password123", "User1")

        f = io.BytesIO(SMALL_PNG)
        r = client.post(
            "/api/tasks",
            data={
                "platform_name": " 测试平台 ",
                "issue_type": "霸王条款",
                "clause_text": " unfair clause ",
                "description": "说明",
                "law_reference": " law ",
                "no_sensitive_declared": "on",
            },
            files={"images": ("test.png", f, "image/png")},
            headers=headers(user),
        )
        assert r.status_code == 200, r.text
        task = j(r)["data"]
        assert task["status"] == "pending"
        assert task["platform_name"] == "测试平台"

        # 普通用户不能审核
        r = client.post(
            "/api/admin/tasks/" + str(task["id"]) + "/review",
            json={"action": "approve", "confirm_no_sensitive": True},
            headers=headers(user),
        )
        assert j(r)["code"] != 0

        # 管理员通过（带确认）
        r = client.post(
            "/api/admin/tasks/" + str(task["id"]) + "/review",
            json={"action": "approve", "confirm_no_sensitive": True, "is_excellent": True},
            headers=headers(admin),
        )
        assert r.status_code == 200, r.text
        d = j(r)
        assert d["code"] == 0
        assert d["data"]["status"] == "approved"

        # 用户积分应为 5+5=10
        r = client.get("/api/auth/me", headers={"Authorization": "Bearer " + user["access_token"]})
        assert j(r)["data"]["points"] == 10

        # 公开列表包含
        r = client.get("/api/tasks")
        assert any(i["id"] == task["id"] for i in j(r)["data"]["items"])

        # 分类已创建
        r = client.get("/api/forum/categories")
        cats = j(r)["data"]
        assert any(c["name"] == "测试平台" for c in cats)

    def test_mosaic_replaces_original(self, client):
        admin = login(client, "sys@t.com", "password123")
        user = register(client, "u2@t.com", "password123", "User2")
        f = io.BytesIO(SMALL_PNG)
        r = client.post(
            "/api/tasks",
            data={"platform_name": "平台B", "issue_type": "数据滥用", "clause_text": "x", "description": "y", "no_sensitive_declared": "on"},
            files={"images": ("b.png", f, "image/png")},
            headers=headers(user),
        )
        task = j(r)["data"]
        old_name = task["images"][0]

        mosaic_data = "data:image/png;base64," + base64.b64encode(SMALL_PNG).decode()
        r = client.post(
            "/api/admin/tasks/" + str(task["id"]) + "/mosaic",
            json={"images": [{"index": 0, "data": mosaic_data}]},
            headers=headers(admin),
        )
        assert j(r)["code"] == 0
        new_name = j(r)["data"]["images"][0]
        assert new_name != old_name
        assert new_name.endswith("_m.png")


class TestForum:
    def test_post_like_reply_report(self, client):
        admin = login(client, "sys@t.com", "password123")
        user = register(client, "u3@t.com", "password123", "User3")

        # 利用审核通过的任务自动创建板块
        f = io.BytesIO(SMALL_PNG)
        r = client.post(
            "/api/tasks",
            data={"platform_name": "论坛平台", "issue_type": "隐私条款不合理", "clause_text": "c", "description": "d", "no_sensitive_declared": "on"},
            files={"images": ("c.png", f, "image/png")},
            headers=headers(user),
        )
        task = j(r)["data"]
        client.post(
            "/api/admin/tasks/" + str(task["id"]) + "/review",
            json={"action": "approve", "confirm_no_sensitive": True},
            headers=headers(admin),
        )

        cats = j(client.get("/api/forum/categories"))["data"]
        platform = next(c for c in cats if c["name"] == "论坛平台")
        board = platform["children"][0]

        # 用户发帖
        r = client.post(
            "/api/forum/posts",
            json={"category_id": board["id"], "title": "测试帖", "content": "正文 #测试", "tags": []},
            headers=headers(user),
        )
        assert j(r)["code"] == 0
        post = j(r)["data"]
        assert post["tags"] == ["测试"]

        # 管理员点赞
        r = client.post("/api/forum/posts/" + str(post["id"]) + "/like", json={"value": 1}, headers=headers(admin))
        assert j(r)["code"] == 0

        # 用户不能自赞
        r = client.post("/api/forum/posts/" + str(post["id"]) + "/like", json={"value": 1}, headers=headers(user))
        assert j(r)["code"] != 0

        # 管理员回复
        r = client.post(
            "/api/forum/posts/" + str(post["id"]) + "/replies",
            json={"content": "回复内容", "quote_reply_id": None},
            headers=headers(admin),
        )
        assert j(r)["code"] == 0
        reply = j(r)["data"]

        # 用户举报回复
        r = client.post(
            "/api/forum/reports",
            json={"target_type": "reply", "target_id": reply["id"], "reason": "不良回复"},
            headers=headers(user),
        )
        assert j(r)["code"] == 0

        # 管理员收藏帖子
        r = client.post("/api/forum/posts/" + str(post["id"]) + "/favorite", json={}, headers=headers(admin))
        assert j(r)["code"] == 0


class TestPoints:
    def test_sign_in_and_rankings(self, client):
        user = register(client, "u4@t.com", "password123", "User4")
        r = client.post("/api/points/sign-in", headers=headers(user))
        assert j(r)["code"] == 0
        assert j(r)["data"]["delta"] == 1

        # 重复签到失败
        r = client.post("/api/points/sign-in", headers=headers(user))
        assert j(r)["code"] != 0

        # 排行榜
        r = client.get("/api/points/rankings?type=total")
        assert j(r)["code"] == 0
        assert any(i["user_id"] == user["user"]["id"] for i in j(r)["data"]["items"])


class TestAdmin:
    def test_user_role_and_ban(self, client, risk_2fa):
        admin = login(client, "sys@t.com", "password123")
        user = register(client, "u5@t.com", "password123", "User5")
        uid = user["user"]["id"]
        # 角色变更/封禁为 critical 级操作，需先完成 2FA（令牌 5 分钟内可复用）
        tfa = risk_2fa(admin, "POST", "/api/admin/users")

        r = client.post("/api/admin/users/" + str(uid) + "/role", json={"role": "moderator"}, headers=headers(admin, tfa))
        assert j(r)["code"] == 0

        r = client.post("/api/admin/users/" + str(uid) + "/ban", json={"is_banned": True}, headers=headers(admin, tfa))
        assert j(r)["code"] == 0

        r = client.post("/api/auth/login", json={"email": "u5@t.com", "password": "password123"})
        assert j(r)["code"] == 4030

        r = client.post("/api/admin/users/" + str(uid) + "/ban", json={"is_banned": False}, headers=headers(admin, tfa))
        assert j(r)["code"] == 0

    def test_knowledge_crud(self, client):
        admin = login(client, "sys@t.com", "password123")
        r = client.post(
            "/api/admin/knowledge",
            json={"category": "law", "title": "测试法律", "content": "内容"},
            headers=headers(admin),
        )
        assert j(r)["code"] == 0
        kid = j(r)["data"]["id"]

        r = client.get("/api/knowledge")
        assert any(i["id"] == kid for i in j(r)["data"]["items"])

        r = client.put("/api/admin/knowledge/" + str(kid), json={"category": "guide", "title": "已更新", "content": "新内容"}, headers=headers(admin))
        assert j(r)["code"] == 0

        r = client.delete("/api/admin/knowledge/" + str(kid), headers=headers(admin))
        assert j(r)["code"] == 0


class TestHoneypot:
    def test_honeypot_records(self, client):
        admin = login(client, "sys@t.com", "password123")
        r = client.post("/api/honeypot/login", json={"username": "admin", "password": "admin", "role": "admin"})
        assert j(r)["code"] == 0
        assert "fake-admin-token" in j(r)["data"]["token"]

        r = client.get("/api/admin/honeypot", headers=headers(admin))
        assert j(r)["code"] == 0
        assert len(j(r)["data"]["items"]) >= 1


class TestStaticAndConfig:
    def test_static_pages(self, client):
        for path in ["/", "/login.html", "/register.html", "/tasks.html", "/forum.html", "/post.html", "/knowledge.html", "/rankings.html", "/agent.html", "/disclaimer.html", "/profile.html", "/admin.html", "/panel.html", "/emails.html", "/risk_control.html"]:
            r = client.get(path)
            assert r.status_code == 200, path

    def test_module_switches(self, client):
        r = client.get("/api/config/modules")
        assert r.status_code == 200
        d = j(r)["data"]
        for k in ["tasks", "forum", "points", "knowledge", "ai_agent"]:
            assert isinstance(d[k], bool)


class TestEmails:
    def test_email_proxy_and_review(self, client):
        admin = login(client, "sys@t.com", "password123")
        user = register(client, "u6@t.com", "password123", "User6")
        uid = user["user"]["id"]

        f = io.BytesIO(SMALL_PNG)
        r = client.post(
            "/api/emails",
            data={
                "platform_name": "测试平台",
                "issue_type": "霸王条款",
                "description": "测试问题描述",
                "law_reference": "个保法第X条",
                "clause_text": "测试条款原文",
                "recipient": "legal@example.com",
                "sender_name": "匿名用户",
                "send_method": "proxy",
            },
            files={"images": ("e.png", f, "image/png")},
            headers=headers(user),
        )
        assert r.status_code == 200, r.text
        email = j(r)["data"]
        assert email["status"] == "draft"
        assert "测试平台" in email["body"]
        assert "legal@example.com" in email["recipient"]

        # 自行发送方式不应真正发邮件
        r2 = client.post(
            "/api/emails",
            data={
                "platform_name": "测试平台2",
                "issue_type": "数据滥用",
                "description": "描述2",
                "recipient": "dpo@example.com",
                "send_method": "self",
            },
            headers=headers(user),
        )
        email2 = j(r2)["data"]
        r_send = client.post("/api/emails/" + str(email2["id"]) + "/send", headers=headers(user))
        assert j(r_send)["data"]["status"] == "self_sent"

        # 管理员复核有效后用户 +3 积分（仅对真正发送成功的邮件复核）
        r_send = client.post("/api/emails/" + str(email["id"]) + "/send", headers=headers(user))
        # 未配置 SMTP 会失败（5002 发送失败 / 5003 未配置），失败邮件不可复核
        assert j(r_send)["code"] in (0, 5002, 5003)
        if j(r_send)["code"] == 0:
            r_review = client.post(
                "/api/emails/admin/emails/" + str(email["id"]) + "/review",
                json={"admin_label": "effective"},
                headers=headers(admin),
            )
            assert j(r_review)["code"] == 0
            r_me = client.get("/api/auth/me", headers={"Authorization": "Bearer " + user["access_token"]})
            assert j(r_me)["data"]["points"] == 3


class TestInbox:
    def _make_mock_pop(self, monkeypatch, raw_messages):
        encoded = [m.encode("utf-8") for m in raw_messages]

        class MockServer:
            def __init__(self, host, port, timeout=10):
                self.host = host
            def user(self, username):
                pass
            def pass_(self, password):
                pass
            def stat(self):
                return len(encoded), sum(len(m) for m in encoded)
            def retr(self, i):
                lines = encoded[i - 1].splitlines()
                return ("ok", lines)
            def quit(self):
                pass

        monkeypatch.setattr("app.routers.emails.poplib.POP3_SSL", MockServer)
        monkeypatch.setattr("app.routers.emails.poplib.POP3", MockServer)

    def _build_raw_email(self, msg_id, subject, body):
        date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        encoded_subject = Header(subject, "utf-8").encode()
        return (
            f"Message-ID: {msg_id}\r\n"
            f"From: sender@example.com\r\n"
            f"To: noreply@qlkimi.local\r\n"
            f"Subject: {encoded_subject}\r\n"
            f"Date: {date}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"\r\n"
            f"{body}"
        )

    def _admin(self, client):
        r = client.post("/api/auth/login", json={"email": "sys@t.com", "password": "password123"})
        if r.status_code == 200 and j(r)["code"] == 0:
            return j(r)["data"]
        return register(client, "sys@t.com", "password123", "Sys")

    def test_pop3_fetch_and_view(self, client, monkeypatch):
        admin = self._admin(client)

        # 配置 POP3
        for key, value in {
            "pop3_host": "pop.example.com",
            "pop3_port": "995",
            "pop3_user": "noreply@qlkimi.local",
            "pop3_pass": "secret",
            "pop3_use_ssl": "1",
        }.items():
            r = client.put("/api/admin/settings", json={"key": key, "value": value}, headers=headers(admin))
            assert j(r)["code"] == 0

        raw = [
            self._build_raw_email("<msg-1@example.com>", "回复：测试平台", "这是第一封回复"),
            self._build_raw_email("<msg-2@example.com>", "回复：数据滥用", "这是第二封回复"),
        ]
        self._make_mock_pop(monkeypatch, raw)

        r = client.post("/api/emails/admin/emails/fetch-inbox", headers=headers(admin))
        assert r.status_code == 200, r.text
        assert j(r)["code"] == 0
        assert j(r)["data"]["fetched"] == 2

        # 列表
        r = client.get("/api/emails/admin/emails/inbox", headers={"Authorization": "Bearer " + admin["access_token"]})
        assert j(r)["code"] == 0
        assert len(j(r)["data"]["items"]) == 2
        inbox_id = j(r)["data"]["items"][0]["id"]

        # 查看并标记已读
        r = client.get(f"/api/emails/admin/emails/inbox/{inbox_id}", headers={"Authorization": "Bearer " + admin["access_token"]})
        assert j(r)["code"] == 0
        assert j(r)["data"]["is_read"] is True
        assert "回复" in j(r)["data"]["subject"]

        # 重复收取应跳过
        r = client.post("/api/emails/admin/emails/fetch-inbox", headers=headers(admin))
        assert j(r)["data"]["skipped"] == 2
        assert j(r)["data"]["fetched"] == 0

    def test_pop3_unconfigured(self, client):
        admin = self._admin(client)
        # 确保 POP3 未配置
        client.put("/api/admin/settings", json={"key": "pop3_host", "value": ""}, headers=headers(admin))
        client.put("/api/admin/settings", json={"key": "pop3_user", "value": ""}, headers=headers(admin))
        r = client.post("/api/emails/admin/emails/fetch-inbox", headers=headers(admin))
        assert j(r)["code"] == 4001


class TestKnowledgeAdvanced:
    def test_daily_law_and_share(self, client):
        admin = login(client, "sys@t.com", "password123")
        user = register(client, "u7@t.com", "password123", "User7")

        # 每日一法
        r = client.get("/api/knowledge/daily/today")
        assert r.status_code == 200
        d = j(r)
        assert d["code"] == 0
        assert d["data"]["category"] == "law"

        # 转发积分
        entry_id = d["data"]["id"]
        r = client.post("/api/knowledge/" + str(entry_id) + "/share", headers=headers(user))
        assert j(r)["code"] == 0
        r_me = client.get("/api/auth/me", headers={"Authorization": "Bearer " + user["access_token"]})
        assert j(r_me)["data"]["points"] == 1

    def test_keyword_index(self, client):
        admin = login(client, "sys@t.com", "password123")
        r = client.post(
            "/api/admin/knowledge",
            json={
                "category": "law",
                "title": "关键词测试法律",
                "content": "测试内容",
                "source_url": "http://example.com/law",
                "is_official": True,
                "keywords": [{"keyword": "测试关键词", "clause": "第1条：测试条款"}],
            },
            headers=headers(admin),
        )
        assert j(r)["code"] == 0
        r2 = client.get("/api/knowledge/keywords/%E6%B5%8B%E8%AF%95%E5%85%B3%E9%94%AE%E8%AF%8D")
        assert j(r2)["code"] == 0
        assert any("关键词测试法律" in i["title"] for i in j(r2)["data"]["items"])


class TestPointsUses:
    def test_nickname_color_and_applications(self, client):
        admin = login(client, "sys@t.com", "password123")
        user = register(client, "u8@t.com", "password123", "User8")
        uid = user["user"]["id"]

        # 积分不足无法兑换颜色
        r = client.post("/api/points/nickname-color", json={"color": "#2563eb"}, headers=headers(user))
        assert j(r)["code"] == 4002

        # 积分不足无法申请志愿者
        r = client.post("/api/points/applications", json={"type": "volunteer"}, headers=headers(user))
        assert j(r)["code"] == 4002

        # 加积分后兑换颜色
        add_user_points(uid, 60)
        r = client.post("/api/points/nickname-color", json={"color": "#2563eb"}, headers=headers(user))
        assert j(r)["code"] == 0
        assert j(r)["data"]["color"] == "#2563eb"
        r_me = client.get("/api/auth/me", headers={"Authorization": "Bearer " + user["access_token"]})
        assert j(r_me)["data"]["nickname_color"] == "#2563eb"
        assert j(r_me)["data"]["points"] == 10

        # 申请志愿者
        add_user_points(uid, 90)  # 10 + 90 = 100
        r = client.post("/api/points/applications", json={"type": "volunteer", "reason": "我愿意参与内容审核"}, headers=headers(user))
        assert j(r)["code"] == 0
        app_id = j(r)["data"]["id"]

        # 重复申请失败
        r = client.post("/api/points/applications", json={"type": "volunteer"}, headers=headers(user))
        assert j(r)["code"] == 4004

        # 管理员审批通过
        r = client.post(
            "/api/admin/applications/" + str(app_id) + "/review",
            json={"status": "approved", "note": "测试通过"},
            headers=headers(admin),
        )
        assert j(r)["code"] == 0
        r_me = client.get("/api/auth/me", headers={"Authorization": "Bearer " + user["access_token"]})
        assert j(r_me)["data"]["role"] == "moderator"
        assert j(r_me)["data"]["points"] == 0

    def test_my_applications(self, client):
        user = register(client, "u9@t.com", "password123", "User9")
        r = client.get("/api/points/applications/my", headers=headers(user))
        assert j(r)["code"] == 0
        assert j(r)["data"]["items"] == []


class TestAdminSettings:
    def test_settings_crud_and_mask(self, client):
        admin = login(client, "sys@t.com", "password123")
        r = client.put("/api/admin/settings", json={"key": "smtp_host", "value": "smtp.example.com"}, headers=headers(admin))
        assert j(r)["code"] == 0
        r = client.get("/api/admin/settings?group=mail", headers=headers(admin))
        assert j(r)["data"]["smtp_host"] == "smtp.example.com"

        r = client.put("/api/admin/settings", json={"key": "ai_api_key", "value": "sk-secret"}, headers=headers(admin))
        assert j(r)["code"] == 0
        r = client.get("/api/admin/settings?group=ai", headers=headers(admin))
        assert j(r)["data"]["ai_api_key"] == "******"


class TestAuthLimitsAndBans:
    def test_email_register_limit(self, client):
        base = "limit@t.com"
        register(client, base, "password123", "Limit1")
        register(client, base, "password123", "Limit2")
        # 同一邮箱第 3 个账号应失败
        r = client.post(
            "/api/auth/register",
            json={"email": base, "password": "password123", "nickname": "Limit3", "guardian_declared": True},
        )
        assert j(r)["code"] == 4003

    def test_banned_email_cannot_register(self, client, risk_2fa):
        admin = login(client, "sys@t.com", "password123")
        email = "bannedemail@t.com"
        tfa = risk_2fa(admin, "POST", "/api/admin/bans")
        r = client.post("/api/admin/bans/email", json={"email": email, "reason": "测试封禁"}, headers=headers(admin, tfa))
        assert j(r)["code"] == 0

        r = client.post(
            "/api/auth/register",
            json={"email": email, "password": "password123", "nickname": "BannedEmail", "guardian_declared": True},
        )
        assert j(r)["code"] == 4030

    def test_banned_user_cannot_login(self, client, risk_2fa):
        admin = login(client, "sys@t.com", "password123")
        user = register(client, "banme@t.com", "password123", "BanMe")
        uid = user["user"]["id"]
        tfa = risk_2fa(admin, "POST", "/api/admin/users")
        r = client.post("/api/admin/users/" + str(uid) + "/ban", json={"is_banned": True}, headers=headers(admin, tfa))
        assert j(r)["code"] == 0

        r = client.post("/api/auth/login", json={"email": "banme@t.com", "password": "password123"})
        assert j(r)["code"] == 4030

    def test_admin_cannot_ban_or_demote_self(self, client):
        admin = login(client, "sys@t.com", "password123")
        uid = admin["user"]["id"]
        r = client.post("/api/admin/users/" + str(uid) + "/ban", json={"is_banned": True}, headers=headers(admin))
        assert j(r)["code"] != 0
        r = client.post("/api/admin/users/" + str(uid) + "/role", json={"role": "user"}, headers=headers(admin))
        assert j(r)["code"] != 0


class TestRoot:
    def _patch_root_code(self, monkeypatch):
        """拦截 Root 验证码邮件发送，返回最新验证码。"""
        captured = {"code": None}

        def fake_send(code):
            captured["code"] = code

        monkeypatch.setattr("app.routers.auth._send_root_code", fake_send)
        return captured

    def _root_login(self, client, monkeypatch):
        captured = self._patch_root_code(monkeypatch)
        r = client.post("/api/auth/root/step1", json={"email": "root@qlkimi.local", "password": "rootpass123"})
        assert r.status_code == 200, r.text
        data = j(r)
        assert data["code"] == 0
        return data["data"]["temp_token"], captured["code"]

    def test_root_2fa_login(self, client, monkeypatch):
        token, code = self._root_login(client, monkeypatch)
        assert code and len(code) == 6
        r = client.post("/api/auth/root/step2", json={"temp_token": token, "code": code})
        assert r.status_code == 200, r.text
        data = j(r)
        assert data["code"] == 0
        assert data["data"]["user"]["role"] == "root"

    def test_root_service_toggle(self, client, monkeypatch, risk_2fa):
        token, code = self._root_login(client, monkeypatch)
        root = j(client.post("/api/auth/root/step2", json={"temp_token": token, "code": code}))["data"]
        # 服务开关为 critical 级操作（路径含 /services/），需先完成 2FA（令牌 5 分钟内可复用）
        tfa = risk_2fa(root, "PUT", "/api/root/services/forum")

        # 默认开启
        r = client.get("/api/root/services", headers=headers(root))
        assert j(r)["code"] == 0
        assert j(r)["data"]["forum"] is True

        # 关闭 forum
        r = client.put("/api/root/services/forum", json={"enabled": False}, headers=headers(root, tfa))
        assert j(r)["code"] == 0
        r = client.get("/api/forum/categories")
        assert r.status_code == 503
        assert j(r)["code"] == 5030

        # 重新开启
        r = client.put("/api/root/services/forum", json={"enabled": True}, headers=headers(root, tfa))
        assert j(r)["code"] == 0
        r = client.get("/api/forum/categories")
        assert j(r)["code"] == 0

    def test_root_ban_device(self, client, monkeypatch, risk_2fa):
        # 先用被封设备注册一个普通账号
        r = client.post(
            "/api/auth/register",
            json={
                "email": "deviceuser@t.com",
                "password": "password123",
                "nickname": "DeviceUser",
                "guardian_declared": True,
                "device_fingerprint": "fp-banned-device",
            },
        )
        assert j(r)["code"] == 0

        token, code = self._root_login(client, monkeypatch)
        root = j(client.post("/api/auth/root/step2", json={"temp_token": token, "code": code}))["data"]
        # 设备封禁为 critical 级操作（路径含 /ban），需先完成 2FA
        tfa = risk_2fa(root, "POST", "/api/admin/bans/device")
        r = client.post(
            "/api/admin/bans/device",
            json={"fingerprint": "fp-banned-device", "reason": "测试设备封禁"},
            headers=headers(root, tfa),
        )
        assert j(r)["code"] == 0

        # 新账号使用被封设备应无法注册
        r = client.post(
            "/api/auth/register",
            json={
                "email": "deviceuser2@t.com",
                "password": "password123",
                "nickname": "DeviceUser2",
                "guardian_declared": True,
                "device_fingerprint": "fp-banned-device",
            },
        )
        assert j(r)["code"] == 4030

    def test_root_ban_admin(self, client, monkeypatch, risk_2fa):
        # 创建一个 admin
        admin = login(client, "sys@t.com", "password123")
        user = register(client, "promote@t.com", "password123", "PromoteMe")
        uid = user["user"]["id"]
        # 角色变更 critical，admin 需先 2FA
        admin_tfa = risk_2fa(admin, "POST", "/api/admin/users")
        r = client.post("/api/admin/users/" + str(uid) + "/role", json={"role": "admin"}, headers=headers(admin, admin_tfa))
        assert j(r)["code"] == 0

        token, code = self._root_login(client, monkeypatch)
        root = j(client.post("/api/auth/root/step2", json={"temp_token": token, "code": code}))["data"]
        # root 封禁管理员 critical（路径含 /ban），需 2FA
        root_tfa = risk_2fa(root, "POST", "/api/root/admins")
        r = client.post("/api/root/admins/" + str(uid) + "/ban", json={}, headers=headers(root, root_tfa))
        assert j(r)["code"] == 0

        # 被 root 封禁的管理员无法登录
        r = client.post("/api/auth/login", json={"email": "promote@t.com", "password": "password123"})
        assert j(r)["code"] == 4030


class TestChat:
    def test_pm_between_users(self, client):
        u1 = register(client, "chat1@t.com", "password123", "Chat1")
        u2 = register(client, "chat2@t.com", "password123", "Chat2")
        uid2 = u2["user"]["id"]

        # 0 积分用户全局禁言，不能发私信
        r = client.post("/api/chat/pm", json={"receiver_id": uid2, "content": "你好"}, headers=headers(u1))
        assert j(r)["code"] == 4031

        # 赋予发言积分后发送成功
        add_user_points(u1["user"]["id"], 4)
        r = client.post("/api/chat/pm", json={"receiver_id": uid2, "content": " 你好 "}, headers=headers(u1))
        assert j(r)["code"] == 0

        # 不能给自己发
        r = client.post(
            "/api/chat/pm",
            json={"receiver_id": u1["user"]["id"], "content": "x"},
            headers=headers(u1),
        )
        assert j(r)["code"] != 0

        # 全空白内容应被拒绝
        r = client.post("/api/chat/pm", json={"receiver_id": uid2, "content": "   "}, headers=headers(u1))
        assert j(r)["code"] != 0

        # 会话列表
        r = client.get("/api/chat/pm/conversations", headers=headers(u2))
        assert j(r)["code"] == 0
        assert any(c["partner_id"] == u1["user"]["id"] for c in j(r)["data"]["items"])

        # 私信记录
        r = client.get("/api/chat/pm/" + str(u1["user"]["id"]), headers=headers(u2))
        assert j(r)["code"] == 0
        assert len(j(r)["data"]["items"]) == 1
        assert j(r)["data"]["items"][0]["content"] == "你好"

    def test_group_chat(self, client):
        u1 = register(client, "g1@t.com", "password123", "G1")
        u2 = register(client, "g2@t.com", "password123", "G2")
        uid1 = u1["user"]["id"]
        uid2 = u2["user"]["id"]

        # 未达 200 积分不能建群
        r = client.post("/api/chat/groups", json={"name": "测试群", "member_ids": [uid2]}, headers=headers(u1))
        assert j(r)["code"] == 4031

        # 赋予建群积分
        add_user_points(uid1, 200)
        add_user_points(uid2, 4)  # 群成员也需要发言积分才能发消息
        r = client.post("/api/chat/groups", json={"name": "测试群", "member_ids": [uid2]}, headers=headers(u1))
        assert j(r)["code"] == 0
        gid = j(r)["data"]["id"]

        # 创建者积分已扣除
        r = client.get("/api/auth/me", headers={"Authorization": "Bearer " + u1["access_token"]})
        assert j(r)["data"]["points"] == 0

        # 非成员不能发消息
        u3 = register(client, "g3@t.com", "password123", "G3")
        add_user_points(u3["user"]["id"], 4)
        r = client.post("/api/chat/groups/" + str(gid) + "/messages", json={"content": "x"}, headers=headers(u3))
        assert j(r)["code"] != 0

        # 无积分成员不能发消息
        u4 = register(client, "g4@t.com", "password123", "G4")
        r = client.post("/api/chat/groups/" + str(gid) + "/messages", json={"content": "x"}, headers=headers(u4))
        assert j(r)["code"] == 4031

        # 成员可发
        r = client.post(
            "/api/chat/groups/" + str(gid) + "/messages",
            json={"content": "群消息"},
            headers=headers(u2),
        )
        assert j(r)["code"] == 0

        r = client.get("/api/chat/groups/" + str(gid) + "/messages", headers=headers(u1))
        assert j(r)["code"] == 0
        assert any(m["content"] == "群消息" for m in j(r)["data"]["items"])

        # 群列表包含创建者角色
        r = client.get("/api/chat/groups", headers=headers(u1))
        assert j(r)["code"] == 0
        group = next(g for g in j(r)["data"]["items"] if g["id"] == gid)
        assert group["owner_id"] == uid1
        assert group["my_role"] == "admin"


class TestInboxPublish:
    def _make_mock_pop(self, monkeypatch, raw_messages):
        encoded = [m.encode("utf-8") for m in raw_messages]

        class MockServer:
            def __init__(self, host, port, timeout=10):
                self.host = host
            def user(self, username):
                pass
            def pass_(self, password):
                pass
            def stat(self):
                return len(encoded), sum(len(m) for m in encoded)
            def retr(self, i):
                lines = encoded[i - 1].splitlines()
                return ("ok", lines)
            def quit(self):
                pass

        monkeypatch.setattr("app.routers.emails.poplib.POP3_SSL", MockServer)
        monkeypatch.setattr("app.routers.emails.poplib.POP3", MockServer)

    def _build_raw_email(self, msg_id, subject, body):
        date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        encoded_subject = Header(subject, "utf-8").encode()
        return (
            f"Message-ID: {msg_id}\r\n"
            f"From: sender@example.com\r\n"
            f"To: noreply@qlkimi.local\r\n"
            f"Subject: {encoded_subject}\r\n"
            f"Date: {date}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"\r\n"
            f"{body}"
        )

    def test_publish_inbox_email(self, client, monkeypatch):
        admin = login(client, "sys@t.com", "password123")
        user = register(client, "inboxpub@t.com", "password123", "InboxPub")

        # 配置 POP3
        for key, value in {
            "pop3_host": "pop.example.com",
            "pop3_port": "995",
            "pop3_user": "noreply@qlkimi.local",
            "pop3_pass": "secret",
            "pop3_use_ssl": "1",
        }.items():
            r = client.put("/api/admin/settings", json={"key": key, "value": value}, headers=headers(admin))
            assert j(r)["code"] == 0

        raw = [self._build_raw_email("<pub-1@example.com>", "公开邮件测试", "这是公开邮件正文")]
        self._make_mock_pop(monkeypatch, raw)
        r = client.post("/api/emails/admin/emails/fetch-inbox", headers=headers(admin))
        assert j(r)["code"] == 0
        inbox_id = j(client.get("/api/emails/admin/emails/inbox", headers=headers(admin)))["data"]["items"][0]["id"]

        # 创建一个帖子用于关联
        f = io.BytesIO(SMALL_PNG)
        r = client.post(
            "/api/tasks",
            data={"platform_name": "公开平台", "issue_type": "霸王条款", "clause_text": "c", "description": "d", "no_sensitive_declared": "on"},
            files={"images": ("c.png", f, "image/png")},
            headers=headers(user),
        )
        task = j(r)["data"]
        client.post(
            "/api/admin/tasks/" + str(task["id"]) + "/review",
            json={"action": "approve", "confirm_no_sensitive": True},
            headers=headers(admin),
        )
        cats = j(client.get("/api/forum/categories"))["data"]
        platform = next(c for c in cats if c["name"] == "公开平台")
        board = platform["children"][0]
        r = client.post(
            "/api/forum/posts",
            json={"category_id": board["id"], "title": "关联主题", "content": "主题内容", "tags": []},
            headers=headers(user),
        )
        post_id = j(r)["data"]["id"]

        # 关联并公开
        r = client.post(
            "/api/emails/admin/emails/inbox/" + str(inbox_id) + "/publish",
            json={"post_id": post_id},
            headers=headers(admin),
        )
        assert j(r)["code"] == 0

        # 公开列表可见
        r = client.get("/api/emails/inbox/public")
        assert j(r)["code"] == 0
        assert any(m["post_id"] == post_id for m in j(r)["data"]["items"])


class TestNotify:
    """首页每日简报与系统通知。"""

    def test_briefing_and_messages(self, client):
        # 简报：未配置 AI 时应返回静态兜底文案，且落盘缓存
        r = client.get("/api/notify/briefing")
        data = j(r)
        assert data["code"] == 0
        briefing = data["data"]
        assert "summary" in briefing and briefing["summary"]
        assert briefing["kind"] in ("policy", "history", "fallback")
        assert "source" in briefing and "source_url" in briefing

        # 通知列表：lifespan 启动时已写入一条 daily_briefing 通知
        r = client.get("/api/notify/messages?limit=20")
        data = j(r)
        assert data["code"] == 0
        assert "items" in data["data"] and "unread" in data["data"]
        items = data["data"]["items"]
        assert isinstance(items, list)
        # 启动时通过 add_system_message 写入的简报通知应至少有一条
        assert len(items) >= 1
        assert any(m["type"] == "daily_briefing" for m in items)

    def test_messages_read_clear_delete(self, client):
        # 变更接口需登录 + CSRF
        tokens = login(client, "sys@t.com", "password123")
        h = headers(tokens)

        # 未登录调用变更接口应被拒
        assert j(client.post("/api/notify/messages/read"))["code"] == 4010

        # 标记全部已读
        r = client.post("/api/notify/messages/read", headers=h)
        assert j(r)["code"] == 0
        r = client.get("/api/notify/messages")
        assert j(r)["data"]["unread"] == 0

        # 单条删除（取第一条）
        first_id = j(client.get("/api/notify/messages"))["data"]["items"][0]["id"]
        r = client.delete(f"/api/notify/messages/{first_id}", headers=h)
        assert j(r)["code"] == 0
        # 删除不存在的消息应返回 4040
        r = client.delete(f"/api/notify/messages/{first_id}", headers=h)
        assert j(r)["code"] == 4040
        # 非法 id
        r = client.delete("/api/notify/messages/0", headers=h)
        assert j(r)["code"] == 4001

        # 清空全部
        r = client.delete("/api/notify/messages", headers=h)
        assert j(r)["code"] == 0
        assert j(client.get("/api/notify/messages"))["data"]["items"] == []


class TestFeed:
    """首页消息流：聚合我的动态 / 关注板块 / 新闻。"""

    def test_feed_public_tabs(self, client):
        # 未登录可访问 all 与 news
        r = client.get("/api/feed?tab=all")
        assert j(r)["code"] == 0
        assert "items" in j(r)["data"]
        r = client.get("/api/feed?tab=news")
        assert j(r)["code"] == 0

    def test_feed_mine_shows_my_task(self, client):
        admin = login(client, "sys@t.com", "password123")
        user = register(client, "feed1@t.com", "password123", "Feed1")
        f = io.BytesIO(SMALL_PNG)
        r = client.post(
            "/api/tasks",
            data={"platform_name": "Feed平台", "issue_type": "霸王条款", "clause_text": "x", "description": "y", "no_sensitive_declared": "on"},
            files={"images": ("f.png", f, "image/png")},
            headers=headers(user),
        )
        task = j(r)["data"]
        # mine Tab 应包含我的任务
        r = client.get("/api/feed?tab=mine", headers={"Authorization": "Bearer " + user["access_token"]})
        assert j(r)["code"] == 0
        assert any(it["source"] == "task" and it["id"] == task["id"] for it in j(r)["data"]["items"])

    def test_feed_subscriptions(self, client):
        admin = login(client, "sys@t.com", "password123")
        user = register(client, "feed2@t.com", "password123", "Feed2")
        # 通过审核任务创建板块
        f = io.BytesIO(SMALL_PNG)
        r = client.post(
            "/api/tasks",
            data={"platform_name": "FeedSub平台", "issue_type": "隐私条款不合理", "clause_text": "c", "description": "d", "no_sensitive_declared": "on"},
            files={"images": ("s.png", f, "image/png")},
            headers=headers(user),
        )
        task = j(r)["data"]
        client.post(
            "/api/admin/tasks/" + str(task["id"]) + "/review",
            json={"action": "approve", "confirm_no_sensitive": True},
            headers=headers(admin),
        )
        cats = j(client.get("/api/forum/categories"))["data"]
        platform = next(c for c in cats if c["name"] == "FeedSub平台")
        board = platform["children"][0]

        # 关注该板块
        r = client.post("/api/forum/categories/" + str(board["id"]) + "/subscribe", headers=headers(user))
        assert j(r)["code"] == 0
        # 我的订阅列表应包含该板块
        r = client.get("/api/forum/my/subscriptions", headers={"Authorization": "Bearer " + user["access_token"]})
        assert any(c["id"] == board["id"] for c in j(r)["data"]["items"])

        # 管理员在该板块发帖
        r = client.post(
            "/api/forum/posts",
            json={"category_id": board["id"], "title": "订阅测试帖", "content": "内容足够长用于测试", "tags": []},
            headers=headers(admin),
        )
        post = j(r)["data"]

        # subscriptions Tab 应包含该帖
        r = client.get("/api/feed?tab=subscriptions", headers={"Authorization": "Bearer " + user["access_token"]})
        assert j(r)["code"] == 0
        assert any(it["source"] == "post" and it["id"] == post["id"] for it in j(r)["data"]["items"])

        # 取消关注
        r = client.delete("/api/forum/categories/" + str(board["id"]) + "/subscribe", headers=headers(user))
        assert j(r)["code"] == 0
        r = client.get("/api/forum/my/subscriptions", headers={"Authorization": "Bearer " + user["access_token"]})
        assert not any(c["id"] == board["id"] for c in j(r)["data"]["items"])


class TestNews:
    """新闻栏：列表展示、过期清理、管理员采集（AI 未配置时降级）。"""

    def test_news_list_empty_or_items(self, client):
        r = client.get("/api/news")
        assert j(r)["code"] == 0
        assert "items" in j(r)["data"]

    def test_news_direct_insert_and_list(self, client):
        # 直接写库插入一条新闻，验证列表返回
        with _db_conn() as conn:
            conn.execute(
                "INSERT INTO news (title, abstract, source_name, source_url, published_at) VALUES (?,?,?,?,?)",
                ("测试新闻标题", "测试摘要内容", "测试来源", "https://example.com/news/1", "2026-08-01"),
            )
            conn.commit()
        r = client.get("/api/news")
        data = j(r)
        assert data["code"] == 0
        items = data["data"]["items"]
        assert any(n["title"] == "测试新闻标题" and n["source_url"] == "https://example.com/news/1" for n in items)

    def test_news_expire_after_7_days(self, client):
        # 写入一条 8 天前的新闻，验证列表不会返回（被置为 is_active=0）
        with _db_conn() as conn:
            conn.execute(
                "INSERT INTO news (title, abstract, source_name, source_url, collected_at, is_active) "
                "VALUES (?,?,?,?,?,1)",
                ("过期新闻", "", "旧来源", "https://example.com/old", "2026-07-01 10:00:00"),
            )
            conn.commit()
        r = client.get("/api/news")
        items = j(r)["data"]["items"]
        assert not any(n["title"] == "过期新闻" for n in items)
        # 确认库内已置为 is_active=0
        with _db_conn() as conn:
            row = conn.execute("SELECT is_active FROM news WHERE title='过期新闻'").fetchone()
            assert row and row[0] == 0

    def test_news_admin_collect_ai_unconfigured(self, client):
        # AI 未配置时，管理员手动采集应返回 reason 而非报错
        admin = login(client, "sys@t.com", "password123")
        r = client.post("/api/news/admin/collect", headers=headers(admin))
        data = j(r)
        assert data["code"] == 0
        assert "reason" in data["data"]

    def test_news_admin_collect_requires_admin(self, client):
        user = register(client, "news1@t.com", "password123", "News1")
        r = client.post("/api/news/admin/collect", headers=headers(user))
        assert j(r)["code"] != 0


class TestQuiz:
    """条文背诵游戏：出题、答题、积分、每日上限。"""

    def _get_question(self, client, tokens):
        r = client.get("/api/quiz/question", headers={"Authorization": "Bearer " + tokens["access_token"]})
        return r

    def _answer_index(self, question_id):
        with _db_conn() as conn:
            row = conn.execute("SELECT answer_index FROM quiz_questions WHERE id=?", (question_id,)).fetchone()
            return int(row[0]) if row else None

    def test_quiz_requires_auth(self, client):
        r = client.get("/api/quiz/question")
        assert j(r)["code"] == 4010

    def test_quiz_question_and_correct_answer(self, client):
        user = register(client, "quiz1@t.com", "password123", "Quiz1")
        uid = user["user"]["id"]
        tokens = login(client, "quiz1@t.com", "password123")
        r = self._get_question(client, tokens)
        data = j(r)
        assert data["code"] == 0
        q = data["data"]
        assert "question_id" in q and "blank_text" in q and "options" in q
        assert len(q["options"]) == 4

        # 查 DB 取正确答案索引并提交
        correct_idx = self._answer_index(q["question_id"])
        r = client.post(
            "/api/quiz/answer",
            json={"question_id": q["question_id"], "option_index": correct_idx},
            headers=headers(tokens),
        )
        data = j(r)
        assert data["code"] == 0
        assert data["data"]["is_correct"] is True
        assert data["data"]["points_delta"] == 1

        # 积分应为 1
        r = client.get("/api/auth/me", headers={"Authorization": "Bearer " + tokens["access_token"]})
        assert j(r)["data"]["points"] == 1

    def test_quiz_wrong_answer_no_points(self, client):
        user = register(client, "quiz2@t.com", "password123", "Quiz2")
        tokens = login(client, "quiz2@t.com", "password123")
        r = self._get_question(client, tokens)
        q = j(r)["data"]
        correct_idx = self._answer_index(q["question_id"])
        wrong_idx = (correct_idx + 1) % 4
        r = client.post(
            "/api/quiz/answer",
            json={"question_id": q["question_id"], "option_index": wrong_idx},
            headers=headers(tokens),
        )
        data = j(r)
        assert data["code"] == 0
        assert data["data"]["is_correct"] is False
        assert data["data"]["points_delta"] == 0

        # 重复作答同一题应被拒
        r = client.post(
            "/api/quiz/answer",
            json={"question_id": q["question_id"], "option_index": wrong_idx},
            headers=headers(tokens),
        )
        assert j(r)["code"] == 4009

    def test_quiz_today_status(self, client):
        user = register(client, "quiz3@t.com", "password123", "Quiz3")
        tokens = login(client, "quiz3@t.com", "password123")
        r = client.get("/api/quiz/today", headers={"Authorization": "Bearer " + tokens["access_token"]})
        data = j(r)
        assert data["code"] == 0
        d = data["data"]
        assert d["today_answered"] == 0
        assert d["daily_limit"] == 5
        assert d["remaining"] == 5

    def test_quiz_daily_limit(self, client):
        user = register(client, "quiz4@t.com", "password123", "Quiz4")
        tokens = login(client, "quiz4@t.com", "password123")
        answered = 0
        # 最多尝试取 10 次题目，凑满 5 次正确作答
        for _ in range(12):
            if answered >= 5:
                break
            r = self._get_question(client, tokens)
            data = j(r)
            if data["code"] != 0:
                break
            q = data["data"]
            correct_idx = self._answer_index(q["question_id"])
            r = client.post(
                "/api/quiz/answer",
                json={"question_id": q["question_id"], "option_index": correct_idx},
                headers=headers(tokens),
            )
            if j(r)["code"] == 0 and j(r)["data"]["is_correct"]:
                answered += 1
        assert answered == 5, f"应能答对 5 题，实际 {answered}"

        # 第 6 次取题应返回 4032（达上限）
        r = self._get_question(client, tokens)
        assert j(r)["code"] == 4032

        # today 状态：已答 5，剩余 0
        r = client.get("/api/quiz/today", headers={"Authorization": "Bearer " + tokens["access_token"]})
        d = j(r)["data"]
        assert d["today_answered"] == 5
        assert d["remaining"] == 0
        assert d["today_correct"] == 5


class TestHandshake:
    """SID 会话密钥握手安全：签发、心跳、异常轮换、root 豁免。"""

    def test_sid_issued_on_login(self, client):
        """登录/注册应签发 sid。"""
        data = register(client, "sid1@t.com", "password123", "Sid1")
        assert "sid" in data and data["sid"]
        tokens = login(client, "sid1@t.com", "password123")
        assert "sid" in tokens and tokens["sid"]
        # 每次登录签发不同 sid
        assert data["sid"] != tokens["sid"]

    def test_handshake_heartbeat(self, client):
        """心跳端点应返回 last_active_at。"""
        tokens = login(client, "sid1@t.com", "password123")
        r = handshake(client, tokens)
        assert j(r)["code"] == 0
        assert "last_active_at" in j(r)["data"]

    def test_handshake_status(self, client):
        """握手状态查询应返回 active=True。"""
        tokens = login(client, "sid1@t.com", "password123")
        r = client.get("/api/auth/handshake/status", headers=headers(tokens))
        assert j(r)["code"] == 0
        assert j(r)["data"]["active"] is True
        assert j(r)["data"]["rotated"] is False

    def test_missing_sid_blocked(self, client):
        """发言类操作缺少 X-SID 应返回 4033（请移动鼠标）。

        使用 /quiz/answer 端点：仅需 csrf_check + require_handshake，
        不需要 require_speak 积分门槛，可直接到达握手校验。
        """
        tokens = register(client, "sid2@t.com", "password123", "Sid2")
        h = {
            "Authorization": "Bearer " + tokens["access_token"],
            "X-CSRF-Token": tokens["csrf_token"],
        }
        r = client.post("/api/quiz/answer", json={"question_id": 1, "option_index": 0}, headers=h)
        assert j(r)["code"] == 4033

    def test_wrong_sid_blocked(self, client):
        """X-SID 不匹配当前用户应返回 4033。"""
        tokens = register(client, "sid3@t.com", "password123", "Sid3")
        h = {
            "Authorization": "Bearer " + tokens["access_token"],
            "X-CSRF-Token": tokens["csrf_token"],
            "X-SID": "invalid-sid-token",
        }
        r = client.post("/api/quiz/answer", json={"question_id": 1, "option_index": 0}, headers=h)
        assert j(r)["code"] == 4033

    def test_repeated_failures_trigger_rotation(self, client):
        """连续失败达阈值应轮换 sid 并返回 4034。"""
        tokens = register(client, "sid4@t.com", "password123", "Sid4")
        h_no_sid = {
            "Authorization": "Bearer " + tokens["access_token"],
            "X-CSRF-Token": tokens["csrf_token"],
        }
        # DEFAULT_FAIL_LIMIT=3，前 2 次返回 4033，第 3 次触发轮换返回 4034
        codes = []
        for _ in range(3):
            r = client.post("/api/quiz/answer", json={"question_id": 1, "option_index": 0}, headers=h_no_sid)
            codes.append(j(r)["code"])
        assert 4033 in codes
        assert 4034 in codes
        # 轮换后旧 sid 失效，心跳端点也返回 4034
        r = handshake(client, tokens)
        assert j(r)["code"] == 4034

    def test_root_exempt_from_handshake(self, client, monkeypatch):
        """Root 账号豁免握手校验。"""
        from tests.test_api import TestRoot

        captured = TestRoot._patch_root_code(TestRoot(), monkeypatch)
        r = client.post("/api/auth/root/step1", json={"email": "root@qlkimi.local", "password": "rootpass123"})
        token = j(r)["data"]["temp_token"]
        code = captured["code"]
        root = j(client.post("/api/auth/root/step2", json={"temp_token": token, "code": code}))["data"]
        # Root 不带 X-SID 也能通过握手（forum 发帖需板块+积分，这里用 quiz/answer 更简单）
        # 直接验证 root 的 handshake status 返回 active（即使不带 sid）
        r = client.get("/api/auth/handshake/status", headers={
            "Authorization": "Bearer " + root["access_token"],
            "X-CSRF-Token": root["csrf_token"],
        })
        assert j(r)["code"] == 0

    def test_logout_clears_sid(self, client):
        """登出后旧 sid 从内存清除，握手状态变为 inactive。"""
        tokens = register(client, "sid5@t.com", "password123", "Sid5")
        r = client.post("/api/auth/logout", headers=headers(tokens))
        assert j(r)["code"] == 0
        # 登出后 sid 已从内存清除，握手状态应为 inactive（JWT 仍有效，用 status 查询）
        r = client.get("/api/auth/handshake/status", headers={
            "Authorization": "Bearer " + tokens["access_token"],
            "X-SID": tokens.get("sid", ""),
        })
        assert j(r)["code"] == 0
        assert j(r)["data"]["active"] is False
