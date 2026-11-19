"""时间处理：统一以 UTC 半开区间 [valid_from, valid_until) 表达。

输入输出均采用带 ``Z`` 后缀的 ISO 8601 字符串（如
``2026-11-20T00:00:00Z``），内部换算为整数微秒纪元值，便于比较与存储。
"""

from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@lru_cache(maxsize=65_536)
def parse_time(value: str) -> int:
    """把 ISO 8601 时间字符串解析为整数微秒纪元值。

    接受 ``...Z`` 与显式偏移两种写法；无时区信息的裸时间一律拒绝，
    避免对本地时区产生隐式依赖。合成输入中时间文本高度重复，
    进程级缓存让同一时间只解析一次。
    """
    if not isinstance(value, str):
        raise ValueError(f"时间必须为字符串: {value!r}")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError(f"时间缺少时区信息（请使用 Z 或显式偏移）: {value!r}")
    dt = dt.astimezone(timezone.utc)
    return int((dt - _EPOCH).total_seconds() * 1_000_000)


def format_time(micros: int) -> str:
    """整数微秒纪元值格式化为 ``...Z`` 形式的规范字符串。"""
    dt = datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc)
    # 微秒精度下直接拼 Z，避免 +00:00 这种不统一拼写
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + (
        f".{dt.microsecond:06d}Z" if dt.microsecond else "Z"
    )


def now_micros() -> int:
    """当前 UTC 时间（微秒）。"""
    return parse_time(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
