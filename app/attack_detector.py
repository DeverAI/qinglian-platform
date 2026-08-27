"""攻击性内容检测模块：检测 prompt 注入、越狱、要求忽略先前指示等攻击。

设计原则：
- 本地规则引擎，无外部依赖，启动即用。
- 规则分两级：一级规则（硬性关键词）命中即封禁；二级规则（模式匹配）命中标记可疑。
- 检测结果返回 is_attack（是否确认为攻击）和 reason 原因。
- 外部调用 attack_detector.detect(text) 获得检测结果，再决定是否封禁。
"""
import re
from typing import Optional

# 一级规则：硬性攻击关键词——命中即视为攻击，立即封禁
_HARD_ATTACK_PATTERNS: list[tuple[str, str]] = [
    # ---- 越狱 / 角色扮演 ----
    (r"(?i)(忽略|忘记|无视|跳过)\s*(所有|全部|以上|之前|先前|前面的)?\s*(指令|指示|规则|限制|约束|设定|prompt|system)", "试图绕过系统指令"),
    (r"(?i)你(现在|接下来)?\s*(是|扮演|假装|成为|cos)", "角色扮演越狱尝试"),
    (r"(?i)DAN\s*(模式|激活|开启|mode)", "DAN 越狱模式"),
    (r"(?i)do\s*anything\s*now|jail\s*(free|break)|越狱|破解", "越狱关键词"),
    (r"(?i)你是\s*(GPT|AI|机器人|助手).*?(不是|不再|不需要)", "身份否认越狱"),
    (r"(?i)解锁\s*(限制|全部|所有)?\s*(能力|功能|模式)", "试图解锁限制"),
    (r"(?i)突破\s*(限制|约束|规则|边界)", "试图突破限制"),

    # ---- 指令注入 / 提示注入 ----
    (r"(?i)重复\s*(上面|以上|之前|我)?\s*(说的|的话|内容|文本|文字)", "试图让 AI 回吐提示词"),
    (r"(?i)输出\s*(上面|以上|之前|我)?\s*(的|的完整)?\s*(提示词|prompt|指令|system)", "试图获取系统提示词"),
    (r"(?i)告诉我\s*(你的|系统的)?\s*(提示词|prompt|指令|规则)", "试图获取系统提示词"),
    (r"(?i)翻译\s*(上面|以下|这个)?\s*(内容|文本|文字)\s*(成|到|为)", "试图绕过内容限制"),
    (r"(?i)忽略\s*(安全|审查|审核|过滤|限制|规则)", "试图绕过安全审查"),
    (r"(?i)不要\s*(遵守|遵循|执行|按照)\s*(规则|限制|指令|约束)", "试图取消遵守规则"),

    # ---- 攻击性 / 恶意指令 ----
    (r"(?i)如何\s*(攻击|入侵|破解|黑掉|hack|入侵)", "攻击性指令"),
    (r"(?i)生成\s*(恶意|有害|危险|违法|非法)\s*(代码|软件|脚本|程序)", "生成恶意代码"),
    (r"(?i)教我\s*(制作|制造|合成|生产)\s*(毒品|毒药|炸弹|武器|枪支)", "危险品制作"),
    (r"(?i)自杀|自残|自\s*(杀|残|虐)", "自残/自杀内容"),
    (r"(?i)色情|情色|成人\s*(内容|视频|电影|网站)|淫秽|裸聊|裸照", "色情内容"),

    # ---- 欺骗 / 钓鱼 ----
    (r"(?i)我\s*是\s*(管理员|admin|root|开发者|开发人员|程序员)", "冒充管理员"),
    (r"(?i)我\s*(授权|允许|批准)\s*你", "冒充授权"),
    (r"(?i)测试\s*(模式|环境|阶段|场景)", "试图切换测试模式"),
]

# 二级规则：可疑模式——命中标记但不直接封禁
_SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(请|帮我|麻烦你)\s*(用|以)\s*(英文|中文|法语|日语|韩语)\s*(回复|回答|输出)", "语言切换请求"),
    (r"(?i)我们\s*在\s*(进行|做|执行)\s*(一个|一项)?\s*(测试|实验|演练)", "声称测试/演练"),
    (r"(?i)这\s*是\s*(一个|一项)?\s*(安全|渗透|压力)\s*测试", "声称安全测试"),
    (r"(?i)如果你\s*(理解|明白|知道|清楚)\s*(了|的话)?", "试探性确认"),
    (r"(?i)逐字|逐句|一字不差|原封不动", "试图逐字复述"),
]


def _merge_patterns() -> list[tuple[re.Pattern, str, bool]]:
    """编译规则为 Pattern 对象。"""
    result = []
    for pat, reason in _HARD_ATTACK_PATTERNS:
        result.append((re.compile(pat), reason, True))
    for pat, reason in _SUSPICIOUS_PATTERNS:
        result.append((re.compile(pat), reason, False))
    return result


_COMPILED = _merge_patterns()


class AttackResult:
    """攻击检测结果。"""

    def __init__(self, is_attack: bool, reason: str = "", is_suspicious: bool = False):
        self.is_attack = is_attack
        self.reason = reason
        self.is_suspicious = is_suspicious

    def __bool__(self) -> bool:
        return self.is_attack or self.is_suspicious

    def __repr__(self) -> str:
        return f"AttackResult(is_attack={self.is_attack}, is_suspicious={self.is_suspicious}, reason={self.reason!r})"


def detect(text: str) -> AttackResult:
    """检测输入文本是否包含攻击性内容。

    返回 AttackResult：
    - is_attack=True：确认为攻击，应立即封禁。
    - is_suspicious=True：可疑，应记录日志但不自动封禁。
    - 两者均为 False：安全。
    """
    if not text or not isinstance(text, str):
        return AttackResult(False)

    text = text.strip()
    if not text:
        return AttackResult(False)

    for pattern, reason, is_hard in _COMPILED:
        match = pattern.search(text)
        if match:
            if is_hard:
                return AttackResult(True, f"攻击检测命中：{reason}（匹配：{match.group()[:50]}）")
            else:
                return AttackResult(False, f"可疑模式：{reason}", is_suspicious=True)

    return AttackResult(False)


def handle_attack(conn, user_id: int, reason: str, admin_id: Optional[int] = None) -> None:
    """攻击命中处理：封禁账号 + 写 AdminLog + 写系统通知。

    参数：
        conn: 数据库连接（已打开事务）
        user_id: 攻击者用户 ID
        reason: 攻击原因描述
        admin_id: 操作者 ID（攻击检测场景传 None，系统自动封禁）
    """
    # 封禁账号
    conn.execute(
        "UPDATE users SET is_banned=1, role='banned' WHERE id=?",
        (user_id,),
    )
    # 写入 bans 表
    conn.execute(
        "INSERT INTO bans (target_type, target_value, reason, banned_by) VALUES (?,?,?,?)",
        ("user_id", str(user_id), reason[:200], admin_id or 0),
    )
    # AdminLog 留痕
    from .common import log_admin
    log_admin(conn, admin_id or 0, "攻击检测自动封禁", f"user_id={user_id}, {reason[:200]}")
    # 系统通知
    from .routers.notify import add_system_message
    add_system_message("system", "账号已被封禁", f"因检测到攻击性内容，账号（ID={user_id}）已被系统自动封禁。原因：{reason[:200]}")