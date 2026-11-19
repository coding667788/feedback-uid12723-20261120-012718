"""verify：用绑定的策略代次与输入独立核对最终产物。

核对项（任一项失败即整体失败）：

1. 回执存在、输入摘要与重新计算的输入摘要一致；
2. 产物文件存在，文件 SHA-256 与回执中的 artifact_digest 一致；
3. 按回执绑定代次重建快照，对输入逐条重新裁定，重放出的记录序列
   （含每字段审批证据）与产物逐行完全一致——记录数、顺序、字段集合、
   证据元组都必须相同；
4. 产物中不得出现未获准字段，证据的两个审批必须确实存在、分属
   发送/接收两侧且机构相互独立。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import FIELD_CATALOG
from .engine import PolicyEngine, build_snapshot
from .export import _build_record
from .models import dumps_canonical
from .storage import Storage
from .streaming import digest_file, digest_jsonl, iter_connections


class VerificationError(Exception):
    """核对失败，消息给出第一条不一致的具体位置。"""


def verify_receipt(
    storage: Storage, request_id: str, input_path: str | Path
) -> dict[str, Any]:
    """执行完整独立核对，成功返回核对报告字典，失败抛
    :class:`VerificationError`。
    """
    receipt = storage.get_receipt(request_id)
    if receipt is None:
        raise VerificationError(f"回执不存在: {request_id}")

    # 1. 输入摘要
    actual_input_digest = digest_jsonl(input_path)
    if actual_input_digest != receipt["input_digest"]:
        raise VerificationError(
            f"输入摘要不一致: 回执 {receipt['input_digest'][:12]}… "
            f"实际 {actual_input_digest[:12]}…"
        )

    artifact_path = Path(receipt["artifact_path"])
    if not artifact_path.is_file():
        raise VerificationError(f"产物文件缺失: {artifact_path}")

    # 2. 产物文件摘要
    actual_artifact_digest = digest_file(artifact_path)
    if actual_artifact_digest != receipt["artifact_digest"]:
        raise VerificationError(
            "产物摘要不一致: 回执 "
            f"{receipt['artifact_digest'][:12]}… 实际 "
            f"{actual_artifact_digest[:12]}…"
        )

    # 3. 按绑定代次独立重建快照并重放
    bound_generation = receipt["generation"]
    meta = storage.generation_meta(bound_generation)
    if meta is None:
        raise VerificationError(f"绑定代次 {bound_generation} 已不存在")
    with storage.snapshot_transaction():
        events = storage.load_events_until(bound_generation)
        snapshot = build_snapshot(events, bound_generation)

    # 审批 ID -> 规则视图，供证据独立性核查
    approval_by_id = {rule.rule_id: rule for rule in snapshot.approvals}
    engine = PolicyEngine(snapshot)

    expected_records: list[dict[str, Any]] = []
    seq = 0
    for conn in iter_connections(input_path):
        if conn.dst_zone != receipt["receiver_zone"]:
            continue
        verdict = engine.evaluate(conn)
        if verdict["denied"]:
            continue
        allowed = [
            name for name in FIELD_CATALOG
            if verdict["fields"][name]["allowed"]
        ]
        if not allowed:
            continue
        seq += 1
        expected_records.append(_build_record(conn, verdict, seq))

    actual_records = _read_artifact(artifact_path)
    if len(actual_records) != len(expected_records):
        raise VerificationError(
            f"记录数不一致: 产物 {len(actual_records)} 条, "
            f"重算 {len(expected_records)} 条"
        )
    if receipt["record_count"] != len(actual_records):
        raise VerificationError(
            f"回执 record_count={receipt['record_count']} "
            f"与产物实际条数 {len(actual_records)} 不符"
        )

    for idx, (actual, expected) in enumerate(
        zip(actual_records, expected_records), start=1
    ):
        if dumps_canonical(actual) != dumps_canonical(expected):
            raise VerificationError(
                f"第 {idx} 条记录与重算结果不一致:\n"
                f"  产物: {dumps_canonical(actual)}\n"
                f"  重算: {dumps_canonical(expected)}"
            )
        _check_evidence_integrity(actual, approval_by_id, idx)

    return {
        "request_id": request_id,
        "generation": bound_generation,
        "input_digest": actual_input_digest,
        "artifact_digest": actual_artifact_digest,
        "record_count": len(actual_records),
        "ok": True,
    }


def _read_artifact(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                raise VerificationError(
                    f"产物 {path}:{lineno} 不是合法 JSON"
                ) from exc
            records.append(record)
    return records


def _check_evidence_integrity(
    record: dict[str, Any],
    approval_by_id: dict[str, Any],
    idx: int,
) -> None:
    fields = record.get("fields", {})
    evidence = record.get("evidence", {})
    if set(fields) != set(evidence):
        raise VerificationError(
            f"第 {idx} 条记录的 fields 与 evidence 字段集合不一致"
        )
    for name, pair in evidence.items():
        if not (isinstance(pair, list) and len(pair) == 2):
            raise VerificationError(f"第 {idx} 条记录字段 {name} 证据不是二元组")
        send_id, recv_id = pair
        send_rule = approval_by_id.get(send_id)
        recv_rule = approval_by_id.get(recv_id)
        if send_rule is None or recv_rule is None:
            raise VerificationError(
                f"第 {idx} 条记录字段 {name} 引用了不存在的审批 {pair}"
            )
        if send_rule.direction != "send" or recv_rule.direction != "recv":
            raise VerificationError(
                f"第 {idx} 条记录字段 {name} 证据方向错误: {pair}"
            )
        if send_rule.authority == recv_rule.authority:
            raise VerificationError(
                f"第 {idx} 条记录字段 {name} 证据机构不独立: "
                f"{send_rule.authority}"
            )
        if name not in send_rule.fields or name not in recv_rule.fields:
            raise VerificationError(
                f"第 {idx} 条记录字段 {name} 的审批未覆盖该字段"
            )
