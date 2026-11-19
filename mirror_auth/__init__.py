"""跨安全区网络流量镜像授权模拟器。

仅使用 Python 3.12 标准库与 SQLite，输入全部为本地合成数据，
不进行任何真实抓包、套接字通信或外部服务访问。
"""

__version__ = "1.0.0"

#: 固定基础字段（连接 ID 与原始五元组的每个成员都作为独立字段受同一审批规则约束）
BASE_FIELDS = (
    "connection_id",
    "src_zone",
    "dst_zone",
    "src_ip",
    "dst_ip",
    "protocol",
    "dst_port",
)

#: 可导出的扩展字段（合成诊断字段）
EXTRA_FIELDS = (
    "bytes_total",
    "packets",
    "duration_ms",
    "app_hint",
    "risk_score",
)

#: 全部可导出字段的有序目录（解释/校验时逐字段枚举）
FIELD_CATALOG = BASE_FIELDS + EXTRA_FIELDS

#: 负责方向
DIRECTION_SEND = "send"
DIRECTION_RECV = "recv"
DIRECTIONS = (DIRECTION_SEND, DIRECTION_RECV)

#: 策略事件类型
EVENT_APPROVAL = "approval"
EVENT_DENY = "deny"
EVENT_REVOCATION = "revocation"
EVENT_TYPES = (EVENT_APPROVAL, EVENT_DENY, EVENT_REVOCATION)
