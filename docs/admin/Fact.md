# Fact.md — 用户偏好约束与冲突记录

## 用户偏好约束

- 沟通与代码中均不使用 EMOJI（除非用户明确要求）。
- 文件操作一律使用内置工具，禁止命令行改/删/拷项目文件（备份除外，备份须注意安全）。
- 不到迫不得已不删除文件，优先修改；冗余内容由用户自行删除。
- Design.md 不写具体代码实现（独门技巧除外）。
- 全局 AI Agent：用户**已许可引入**（2026-07-30），定位为 AI 导游/介绍，后续将扩展 AI 设计、AI 审核功能。配置走环境变量，带模块开关 ENABLE_AI_AGENT。
- 技术栈：FastAPI + SQLite + HTML + 原生 JS，最小依赖（fastapi/uvicorn/python-multipart/httpx）。
- 运行时错误必须写入 Err.log，不得吞没；修复前先读 Err.log，修复后清空。

## 冲突记录

- [冲突记录] 用户请求"数据模型（Prisma Schema）"与核心原则"轻量化优先/优先 FastAPI"冲突（Prisma 属 Node.js 生态，二者不可共存）→ 经请示用户，采用 FastAPI + SQLite，九个模型以 SQL 建表实现，Prisma 仅视为模型清单语义。2026-07-30
