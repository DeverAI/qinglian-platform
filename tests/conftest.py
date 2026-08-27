"""测试配置：隔离数据库与上传目录。"""
import gc
import os
import shutil
import tempfile

import pytest


@pytest.fixture(scope="session")
def client():
    tmp = tempfile.TemporaryDirectory()
    db_path = os.path.join(tmp.name, "test.db")
    uploads_path = os.path.join(tmp.name, "uploads")
    err_log_path = os.path.join(tmp.name, "Err.log")
    os.makedirs(uploads_path, exist_ok=True)
    os.environ["QLKIMI_DB"] = db_path
    os.environ["QLKIMI_UPLOADS"] = uploads_path
    os.environ["QLKIMI_ERR_LOG"] = err_log_path
    os.environ["QLKIMI_ROOT_PASSWORD"] = "rootpass123"
    # 风控 2FA：测试环境清空 ROOT_EMAIL，使验证码本地返回（sent_via=local），
    # 避免 issue_2fa_challenge 尝试 SMTP 连接拖慢测试；root 登录测试已 monkeypatch 邮件发送。
    os.environ["QLKIMI_ROOT_EMAIL"] = ""
    briefing_path = os.path.join(tmp.name, "briefings")
    os.makedirs(briefing_path, exist_ok=True)
    os.environ["QLKIMI_BRIEFING_DIR"] = briefing_path
    # 必须在设置环境变量后导入应用
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        yield c
    # 强制垃圾回收，尽量释放 SQLite 连接句柄（Windows 下避免清理临时目录时报 PermissionError）
    gc.collect()
    try:
        tmp.cleanup()
    except PermissionError:
        # SQLite WAL 文件可能仍被占用，使用 ignore_errors 清理
        shutil.rmtree(tmp.name, ignore_errors=True)
    # 清理 pycache 中可能残留的临时路径（避免后续运行问题）
    for root, dirs, files in os.walk("app/__pycache__"):
        for f in files:
            if f.endswith(".pyc"):
                try:
                    os.remove(os.path.join(root, f))
                except OSError:
                    pass


@pytest.fixture
def risk_2fa(client):
    """返回 2FA 完成辅助函数：对指定用户签发并校验 2FA 挑战，返回可复用的 X-2FA-Token。

    供 critical 级操作（角色变更/封禁/服务开关/阈值修改/批量删除）测试使用。
    已验证令牌绑定 actor_id，5 分钟内对同一用户可复用，因此每个测试完成一次即可。
    """
    def _do(tokens, method="POST", path="/api/admin"):
        h = {
            "Authorization": "Bearer " + tokens["access_token"],
            "X-CSRF-Token": tokens.get("csrf_token", ""),
        }
        sid = tokens.get("sid", "")
        if sid:
            h["X-SID"] = sid
        r = client.post(
            "/api/risk/2fa/trigger",
            json={"method": method, "path": path, "action": ""},
            headers=h,
        )
        assert r.status_code == 200, r.text
        data = r.json()["data"]
        r = client.post(
            "/api/risk/2fa/verify",
            json={"challenge_token": data["challenge_token"], "code": data["code"]},
            headers=h,
        )
        assert r.json()["code"] == 0, r.text
        return data["challenge_token"]

    return _do
