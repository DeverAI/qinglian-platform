# qinglian-platform v0.1.0

青少年互联网平台合规监测系统 - 首公开版

## 项目简介

面向青少年用户的互联网平台合规监测平台。青少年用户可举报互联网平台的不合理条款（隐蔽条款不合理 / 霸王条款 / 数据滥用 / 未成年人保护缺失等），经管理员审核后形成公开案例并在论坛展开讨论，配套积分激励、法律知识库与维权指引。

## 技术栈

- **后端**: FastAPI + Uvicorn + SQLAlchemy
- **前端**: 静态 HTML / CSS / JS（无 SPA 框架，stdlib-first）
- **AI**: 集成 AI 内容审核
- **数据库**: SQLite（用户举报 / 案例 / 简报 / 论坛）

## 快速开始

```bash
pip install -r requirements.txt
python run.py
```

## 主要功能模块

- `app/main.py` - FastAPI 应用入口
- `app/ai_check.py` - AI 内容审核
- `app/attack_detector.py` - 攻击检测
- `app/risk_control.py` - 风控
- `app/content_guard.py` - 内容保护
- `app/ip_protection.py` - IP 保护
- `app/board_lifecycle.py` - 版块生命周期
- `app/image_upload.py` - 图片上传
- `app/security.py` - 安全
- `app/routers/` - 模块化路由（admin / agent / auth / chat / forum / knowledge 等）
- `参考/` - 管理后台参考实现

## 文档

- `docs/admin/Design.md` - 核心设计
- `docs/admin/Fact.md` - 关键事实
- `docs/admin/FreqErr.md` - 常见错误
- `docs/admin/Techniques.md` - 技术方案
- `docs/admin/done.md` - 历届完成记录
- `docs/admin/Future.md` - 未来规划

## License

GPL-3.0 — 详见 [LICENSE](LICENSE) 文件
