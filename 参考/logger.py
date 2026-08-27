import logging
import logging.handlers
import os
import sys

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "storage", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

_logger = logging.getLogger("learning_agent")
_logger.setLevel(logging.INFO)
_logger.handlers.clear()

_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

_stream_handler = logging.StreamHandler(sys.stdout)
_stream_handler.setLevel(logging.INFO)
_stream_handler.setFormatter(_formatter)
_logger.addHandler(_stream_handler)

_file_handler = logging.handlers.RotatingFileHandler(
    os.path.join(LOG_DIR, "app.log"), encoding="utf-8",
    maxBytes=10 * 1024 * 1024, backupCount=3
)
_file_handler.setLevel(logging.DEBUG)
_file_handler.setFormatter(_formatter)
_logger.addHandler(_file_handler)

ERROR_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ERRORLOG.md")
ERR_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Err.log")


def log_error(module: str, message: str):
    _logger.error("[%s] %s", module, message)
    try:
        from datetime import datetime
        ts = datetime.now().strftime('%m-%d %H:%M')
        line = f"- [{ts}] `{module}`: {message[:300]}\n"
        with open(ERROR_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
        # Also write to Err.log (appends; cleared manually after fix)
        with open(ERR_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] [{module}] {message[:500]}\n")
    except Exception:
        pass


def get_logger() -> logging.Logger:
    return _logger
