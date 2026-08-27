"""启动入口：python run.py（可通过 APP_PORT 修改端口）。"""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=os.environ.get("APP_HOST", "127.0.0.1"),
        port=int(os.environ.get("APP_PORT", "8001")),
        reload=False,
    )
