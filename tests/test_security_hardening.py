"""全局安全边界回归测试。"""
import base64
import asyncio
import io
import json
import os
import time

import pytest
from PIL import Image


def _segment(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_security_headers_and_api_cache(client):
    page = client.get("/")
    assert page.status_code == 200
    assert page.headers["x-content-type-options"] == "nosniff"
    assert page.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]

    api = client.get("/api/config/modules")
    assert api.headers["cache-control"] == "no-store"


def test_oversized_request_rejected_before_parsing(client):
    response = client.post(
        "/api/auth/login",
        content=b"{}",
        headers={"content-length": str(31 * 1024 * 1024), "content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["code"] == 4130


def test_jwt_algorithm_confusion_is_rejected():
    from app.common import BizError
    from app.security import decode_token

    forged = ".".join((
        _segment({"alg": "none", "typ": "JWT"}),
        _segment({"sub": 1, "type": "access", "iat": 1, "exp": 9999999999}),
        "x",
    ))
    with pytest.raises(BizError):
        decode_token(forged, "access")


def test_production_rejects_default_secret(monkeypatch):
    from app import config
    from app.main import app, lifespan

    monkeypatch.setattr(config, "ENVIRONMENT", "production")
    monkeypatch.setattr(config, "SECRET_KEY", "dev-secret-please-change-in-production")
    context = lifespan(app)
    with pytest.raises(RuntimeError, match="QLKIMI_SECRET"):
        asyncio.run(context.__aenter__())


def test_ip_protection_triggers_ban_and_softens_limit(client):
    from app.database import db
    from app.common import BizError
    from app.ip_protection import inspect_request, policy_snapshot, lift_ip_ban

    ip = "203.0.113.77"
    for _ in range(60):
        inspect_request(ip, "/api/forum")
    with pytest.raises(BizError) as exc:
        inspect_request(ip, "/api/forum")
    assert exc.value.code == 4290

    snapshot = policy_snapshot(ip)
    assert snapshot["banned_until"] > time.time()
    assert snapshot["limit_per_minute"] < 60
    with db() as conn:
        event = conn.execute(
            "SELECT event_type, path, detail FROM ip_security_events WHERE ip=? ORDER BY id DESC",
            (ip,),
        ).fetchone()
    assert event["event_type"] == "auto_ban"
    assert event["path"] == "/api/forum"
    assert "new_limit=" in event["detail"]

    lift_ip_ban(ip)
    snapshot2 = policy_snapshot(ip)
    assert snapshot2["banned_until"] == 0


def test_root_can_change_ip_ban_minutes(client, risk_2fa):
    def login_local(email, password):
        response = client.post("/api/auth/login", json={"email": email, "password": password})
        assert response.status_code == 200
        return response.json()["data"]

    def headers_local(tokens, two_fa=None):
        h = {"Authorization": "Bearer " + tokens["access_token"], "X-CSRF-Token": tokens["csrf_token"]}
        if two_fa:
            h["X-2FA-Token"] = two_fa
        return h

    root = login_local("root@qlkimi.local", "rootpass123")
    # IP 手动封禁与阈值修改均为 critical 级操作，需先完成 2FA（令牌 5 分钟内可复用）
    root_tfa = risk_2fa(root, "POST", "/api/admin/ip-controls/ban")
    manual_ip = "198.51.100.24"
    banned = client.post(
        "/api/admin/ip-controls/ban",
        json={"ip": manual_ip, "minutes": 5, "reason": "security regression"},
        headers=headers_local(root, root_tfa),
    )
    assert banned.json()["data"]["minutes"] == 5
    events = client.get(
        f"/api/admin/ip-controls/events?ip={manual_ip}", headers=headers_local(root),
    ).json()["data"]["items"]
    assert events[0]["event_type"] == "manual_ban"
    assert events[0]["actor_nickname"]
    lifted = client.post(
        f"/api/admin/ip-controls/{manual_ip}/lift", json={}, headers=headers_local(root),
    )
    assert lifted.json()["code"] == 0

    response = client.put(
        "/api/admin/settings",
        json={"key": "threshold_ip_ban_minutes", "value": "12"},
        headers=headers_local(root),
    )
    assert response.status_code == 200
    data = client.get("/api/admin/settings?group=security", headers=headers_local(root)).json()["data"]
    assert data["threshold_ip_ban_minutes"] == "12"
    assert data["threshold_ip_default_limit"] == "60"
    assert data["threshold_ip_min_limit"] == "20"
    specs = client.get("/api/admin/settings/ai-specs", headers=headers_local(root)).json()["data"]
    assert "web_search" in " ".join(specs["ai_search_model"]["requirements"])
    assert "image_url" in " ".join(specs["ai_vision_model"]["requirements"])

    # 阈值校验为 critical 级操作，复用已验证的 2FA 令牌
    invalid = client.put(
        "/api/root/thresholds",
        json={"values": {"threshold_ip_min_limit": "100", "threshold_ip_default_limit": "50"}},
        headers=headers_local(root, root_tfa),
    )
    assert invalid.json()["code"] == 4001

    sys_response = client.post("/api/auth/login", json={"email": "sys@t.com", "password": "password123"})
    if sys_response.json()["code"] != 0:
        sys_response = client.post("/api/auth/register", json={
            "email": "security-sys@t.com", "password": "password123", "nickname": "SecuritySys",
            "guardian_declared": True, "device_fingerprint": "fp-security-sys",
        })
    sysadmin = sys_response.json()["data"]
    denied = client.put(
        "/api/admin/settings",
        json={"key": "threshold_ip_default_limit", "value": "80"},
        headers=headers_local(sysadmin),
    )
    assert denied.json()["code"] == 4030


def test_image_compression_and_original_point_gate(client):
    from app.database import db

    registered = client.post("/api/auth/register", json={
        "email": "image-policy@t.com", "password": "password123", "nickname": "ImagePolicy",
        "guardian_declared": True, "device_fingerprint": "fp-image-policy",
    }).json()["data"]
    auth = {
        "Authorization": "Bearer " + registered["access_token"],
        "X-CSRF-Token": registered["csrf_token"],
        "X-SID": registered["sid"],
    }
    # 触发一次鼠标握手心跳，确保 sid 处于活跃状态以便通过 require_handshake 守卫
    assert client.post("/api/auth/handshake", headers=auth).json()["code"] == 0

    image = Image.effect_noise((1200, 900), 80).convert("RGB")
    source = io.BytesIO()
    image.save(source, format="PNG")
    source_data = source.getvalue()
    fields = {
        "platform_name": "图片压缩测试平台", "issue_type": "数据滥用",
        "clause_text": "用于回归测试的条款原文", "description": "用于验证服务端图片自动压缩",
        "no_sensitive_declared": "on",
    }
    response = client.post(
        "/api/tasks", data={**fields, "image_target_bytes": "auto"},
        files={"images": ("large.png", io.BytesIO(source_data), "image/png")}, headers=auth,
    ).json()
    assert response["code"] == 0
    saved_name = response["data"]["images"][0]
    assert saved_name.endswith(".webp")
    assert response["data"]["upload_summary"]["stored_bytes"] < len(source_data)
    assert os.path.getsize(os.path.join(os.environ["QLKIMI_UPLOADS"], saved_name)) == response["data"]["upload_summary"]["stored_bytes"]

    denied = client.post(
        "/api/tasks", data={**fields, "image_target_bytes": "original"},
        files={"images": ("original.png", io.BytesIO(source_data), "image/png")}, headers=auth,
    ).json()
    assert denied["code"] == 4031

    with db() as conn:
        conn.execute("UPDATE users SET points=1000 WHERE id=?", (registered["user"]["id"],))
    original = client.post(
        "/api/tasks", data={**fields, "image_target_bytes": "original"},
        files={"images": ("original.png", io.BytesIO(source_data), "image/png")}, headers=auth,
    ).json()
    assert original["code"] == 0
    assert original["data"]["upload_summary"]["stored_bytes"] == len(source_data)

    rules = client.get("/api/points/rules").json()["data"]
    assert any(item["name"] == "上传原图" and item["points"] == 500 for item in rules["unlock"])
