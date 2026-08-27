"""自动存错机制：任何运行时错误都必须写入根目录 Err.log，不得吞没。

修复流程约定：修复前先读取 Err.log，修复完成后清空该文件内容（不删除文件）。
"""
import datetime
import threading
import traceback

from . import config

_lock = threading.Lock()


def log_error(source: str, detail: str) -> None:
    """追加一条错误记录。日志系统自身故障时静默，避免级联崩溃。"""
    try:
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        with _lock:
            with open(config.ERR_LOG, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] [{source}] {detail}\n{'-' * 60}\n")
    except Exception:
        pass


def log_exception(source: str, exc: BaseException) -> None:
    """在 except 块中调用，记录异常对象与完整堆栈。"""
    log_error(source, f"{exc!r}\n{traceback.format_exc()}")
