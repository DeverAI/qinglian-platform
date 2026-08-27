"""统一响应、业务异常、分页与转义等公共工具。"""


class BizError(Exception):
    """业务异常：code 非 0，由全局处理器转为统一响应。

    约定码段：400x 参数类；4010 未登录/令牌失效；4030 权限/CSRF；4040 资源不存在。
    """

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def ok(data=None, message: str = "success") -> dict:
    return {"code": 0, "message": message, "data": data}


def fail(code: int, message: str) -> dict:
    return {"code": code, "message": message, "data": None}


def page_args(page: int, limit: int) -> tuple[int, int, int]:
    """规范化分页参数，返回 (page, limit, offset)。limit 上限 100 防拉垮。"""
    page = max(1, int(page or 1))
    limit = min(100, max(1, int(limit or 20)))
    return page, limit, (page - 1) * limit


def escape_html(text: str) -> str:
    """HTML 转义，防 XSS。输出到页面前对用户内容统一调用。"""
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def row_to_dict(row) -> dict:
    return {k: row[k] for k in row.keys()}


def rows_to_list(rows) -> list:
    return [row_to_dict(r) for r in rows]


def add_points(conn, user_id: int, delta: int, reason: str, ref_type: str = "", ref_id: int | None = None) -> bool:
    """增加用户积分，写 PointLog 流水并更新 users.points 冗余缓存。扣分请使用 spend_points。

    对 point_logs 的唯一约束冲突做静默处理，保证并发或重复调用时积分只发放一次。
    返回 True 表示实际写入并加分；False 表示因幂等约束跳过（未加分）。
    """
    import sqlite3

    if delta <= 0:
        raise ValueError("add_points 的 delta 必须为正数")
    try:
        conn.execute(
            "INSERT INTO point_logs (user_id, delta, reason, ref_type, ref_id) VALUES (?,?,?,?,?)",
            (user_id, delta, reason, ref_type, ref_id),
        )
    except sqlite3.IntegrityError:
        # 已发放过相同积分，直接跳过（幂等）
        return False
    conn.execute("UPDATE users SET points = points + ? WHERE id = ?", (delta, user_id))
    return True


def spend_points(
    conn,
    user_id: int,
    delta: int,
    reason: str,
    ref_type: str = "",
    ref_id: int | None = None,
    min_balance: int | None = None,
) -> int | None:
    """原子扣减积分：仅当余额 >= min_balance 时才扣减，并写流水。返回扣减后余额，余额不足返回 None。

    当 min_balance 为 None 时，默认要求余额 >= delta，防止扣成负数。
    """
    if delta <= 0:
        raise ValueError("spend_points 的 delta 必须为正数")
    if min_balance is None:
        min_balance = delta
    if min_balance < delta:
        raise ValueError("min_balance 不能小于 delta")
    row = conn.execute(
        "UPDATE users SET points = points - ? WHERE id = ? AND points >= ? RETURNING points",
        (delta, user_id, min_balance),
    ).fetchone()
    if row is None:
        return None
    conn.execute(
        "INSERT INTO point_logs (user_id, delta, reason, ref_type, ref_id) VALUES (?,?,?,?,?)",
        (user_id, -delta, reason, ref_type, ref_id),
    )
    return int(row["points"])


def log_admin(conn, admin_id: int, action: str, detail: str = "") -> None:
    """敏感管理操作留痕。"""
    conn.execute(
        "INSERT INTO admin_logs (admin_id, action, detail) VALUES (?,?,?)",
        (admin_id, action, detail),
    )
