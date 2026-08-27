"""全局配置与模块开关。

模块开关约定：置 False 时 main.py 不注册对应路由，前端依据
/api/config/modules 隐藏所有入口与调用，便于 demo、演示与排错。
"""
import os
import sys
from pathlib import Path

# 将工作区根目录加入 path，以便导入统一 api_keys 模块
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from api_keys import get_api_key

# ---------- 模块开关 ----------
ENABLE_TASKS = True
ENABLE_FORUM = True
ENABLE_POINTS = True
ENABLE_KNOWLEDGE = True
ENABLE_AI_AGENT = True  # 全局 AI 导游（用户已许可，见 Fact.md）
ENABLE_HONEYPOT = True  # 蜜罐（诱饵面板 + 日志）
ENABLE_EMAILS = True      # 邮件代发系统

# ---------- 路径 ----------
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("QLKIMI_DB", str(BASE_DIR / "data" / "qlkimi.db")))
UPLOAD_DIR = Path(os.environ.get("QLKIMI_UPLOADS", str(BASE_DIR / "uploads")))
STATIC_DIR = BASE_DIR / "static"
ERR_LOG = Path(os.environ.get("QLKIMI_ERR_LOG", str(BASE_DIR / "Err.log")))
DESIGN_MD = BASE_DIR / "Design.md"
FUTURE_MD = BASE_DIR / "Future.md"
# 首页每日简报 JSON 缓存目录（briefing_YYYY-MM-DD.json）
BRIEFING_DIR = Path(os.environ.get("QLKIMI_BRIEFING_DIR", str(BASE_DIR / "storage" / "briefings")))
# 风控审计日志文件备份目录（YYYYMM.log，与 DB risk_audit_logs 表互为冗余，防删除）
RISK_AUDIT_DIR = Path(os.environ.get("QLKIMI_RISK_AUDIT_DIR", str(BASE_DIR / "storage" / "risk_audit")))
# 风控 2FA 验证码发送邮箱（默认复用 ROOT_EMAIL）；留空则不发送邮件，仅返回 temp_token+code（仅服务器本地访问时可用）
RISK_2FA_EMAIL = os.environ.get("QLKIMI_RISK_2FA_EMAIL", "")
# 2FA 验证码有效期（分钟）
RISK_2FA_TTL_MINUTES = 5
# 2FA 最大失败次数（超过则封禁 IP）
RISK_2FA_MAX_FAILS = 3

# ---------- 安全 ----------
SECRET_KEY = os.environ.get("QLKIMI_SECRET", "dev-secret-please-change-in-production")
ENVIRONMENT = os.environ.get("QLKIMI_ENV", "development").strip().lower()
ACCESS_TOKEN_DAYS = 7   # 访问令牌 7 天过期（需求规格）
REFRESH_TOKEN_DAYS = 30  # 刷新令牌 30 天，前端自动续期
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 单张图片 <= 5MB
MAX_UPLOAD_COUNT = 5               # 单次最多 5 张
ALLOWED_IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp"}
MAX_REQUEST_SIZE = int(os.environ.get("QLKIMI_MAX_REQUEST_SIZE", str(30 * 1024 * 1024)))
TRUSTED_HOSTS = tuple(
    host.strip()
    for host in os.environ.get("QLKIMI_TRUSTED_HOSTS", "localhost,127.0.0.1,testserver").split(",")
    if host.strip()
)

# ---------- AI 导游（OpenAI 兼容接口，未配置则降级静态导览） ----------
AI_API_URL = os.environ.get("AI_API_URL", "")
AI_API_KEY = os.environ.get("AI_API_KEY", "") or get_api_key("qinglian_ai_api_key", fallback="")
AI_MODEL = os.environ.get("AI_MODEL", "")
AI_TIMEOUT = 30

# ---------- Root 账号安全（仅后端配置，不暴露给前端） ----------
ROOT_EMAIL = os.environ.get("QLKIMI_ROOT_EMAIL", "13965124556@163.com")
ROOT_CODE_TTL_MINUTES = 10

# ---------- 预设平台（下拉选择，允许自定义输入） ----------
PRESET_PLATFORMS = [
    "微信", "QQ", "抖音", "快手", "哔哩哔哩", "小红书", "微博",
    "淘宝", "拼多多", "京东", "美团", "饿了么", "网易云音乐", "Qoder",
]

ISSUE_TYPES = ["隐私条款不合理", "霸王条款", "数据滥用", "未成年人保护缺失", "其他"]
