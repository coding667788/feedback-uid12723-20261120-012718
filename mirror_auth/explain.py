"""explain 渲染：只输出裁定理由与审批证据，绝不打印实际字段值。

输出为 JSON Lines，每行一条连接的解释：
* 整条被显式拒绝时，给出排序首条拒绝（rule_id、侧别、区、机构）；
* 否则逐字段给出 allowed / evidence / reason，证据取字典序最小的
  合法 (发送审批 ID, 接收审批 ID) 元组；
* 拒绝原因区分缺一侧审批与两侧机构不独立。
"""

from __future__ import annotations

from typing import Any, TextIO

from . import FIELD_CATALOG
from .engine import (
    REASON_MISSING_SIDE,
    REASON_SAME_AUTHORITY,
    PolicyEngine,
    build_snapshot,
)
from .storage import Storage
from .streaming import iter_connections

REASON_TEXT = {
    REASON_MISSING_SIDE: "缺少发送侧或接收侧的任一方审批",
    REASON_SAME_AUTHORITY: "两侧审批签发机构相同，机构不独立",
    "connection_explicitly_denied": "连接命中显式拒绝策略",
}


def explain_connection(verdict: dict[str, Any]) -> dict[str, Any]:
    """把引擎裁定转成面向用户的解释对象（不含字段值）。"""
    view: dict[str, Any] = {
        "connection_id": verdict["connection_id"],
        "denied": verdict["denied"],
    }
    if verdict["denied"]:
        view["first_deny"] = verdict["first_deny"]
        view["fields"] = {
            name: {
                "allowed": False,
                "evidence": None,
                "reason": REASON_TEXT["connection_explicitly_denied"],
            }
            for name in FIELD_CATALOG
        }
        return view

    fields: dict[str, Any] = {}
    for name in FIELD_CATALOG:
        decision = verdict["fields"][name]
        if decision["allowed"]:
            fields[name] = {
                "allowed": True,
                "evidence": decision["evidence"],   # [send_approval_id, recv_approval_id]
                "reason": None,
            }
        else:
            fields[name] = {
                "allowed": False,
                "evidence": None,
                "reason": REASON_TEXT.get(decision["reason"], decision["reason"]),
            }
    view["fields"] = fields
    return view


def write_explanations(
    storage: Storage,
    input_path: str,
    out: TextIO,
    generation: int | None = None,
) -> int:
    """对输入文件逐条解释并写 JSONL，返回处理条数。可绑定历史代次。"""
    import json

    with storage.snapshot_transaction():
        current = storage.current_generation()
        target = current if generation is None else generation
        if target > current:
            raise ValueError(
                f"请求代次 {target} 高于当前代次 {current}"
            )
        events = storage.load_events_until(target)
        snapshot = build_snapshot(events, target)

    engine = PolicyEngine(snapshot)
    count = 0
    for conn in iter_connections(input_path):
        verdict = engine.evaluate(conn)
        view = explain_connection(verdict)
        view["policy_generation"] = target
        out.write(json.dumps(view, ensure_ascii=False, sort_keys=True))
        out.write("\n")
        count += 1
    return count
