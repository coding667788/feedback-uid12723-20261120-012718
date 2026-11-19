"""导出流水线：流式暂存、代次核对、回执原子公布与故障恢复。

发布协议（关键顺序）：

1. 先在快照事务内绑定当前策略代次并构建不可变快照；
2. 以输入顺序逐条裁定，流式写入“不可变暂存路径”
   （``.partial`` 写完后 ``os.replace`` 成最终文件，之后永不修改）；
3. 提交阶段在 ``BEGIN IMMEDIATE`` 事务内重新核对代次：
   代次已变化 -> 回滚、删除暂存产物、返回 ``stale``；
   代次一致 -> 同事务插入回执并提交。
4. 读者只通过回执中的 artifact_path 查看结果；没有回执的文件
   对任何命令都不可见，:func:`reconcile_artifacts` 可在故障后清理。

重放语义：相同 request_id + 相同输入摘要 -> 返回原回执；
相同 request_id + 不同输入 -> 拒绝（冲突）。
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Any, Callable

from . import FIELD_CATALOG
from .engine import (
    PolicyEngine,
    allowed_fields,
    build_snapshot,
)
from .models import Connection, dumps_canonical
from .storage import Storage
from .streaming import compute_input_digest, iter_connections_with_digest
from .timeutil import now_micros

#: 退出状态（CLI 与库调用共用）
STATUS_PUBLISHED = "published"
STATUS_REPLAYED = "replayed"
STATUS_STALE = "stale"
STATUS_CONFLICT = "conflict"


class InputConflictError(Exception):
    """同一 request_id 绑定了不同输入摘要。"""

    def __init__(self, request_id: str, existing_digest: str, new_digest: str):
        super().__init__(
            f"请求 ID {request_id!r} 已绑定不同输入: "
            f"已存 {existing_digest[:12]}…, 本次 {new_digest[:12]}…"
        )
        self.request_id = request_id
        self.existing_digest = existing_digest
        self.new_digest = new_digest


def _artifacts_dir(workdir: str | Path) -> Path:
    path = Path(workdir) / "artifacts"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _build_record(conn: Connection, verdict: dict[str, Any], seq: int) -> dict[str, Any]:
    """组装单条导出记录：只写获准字段，证据逐字段携带。

    连接 ID 与五元组成员仅在对应字段获准时出现在 ``fields`` 中；
    记录内不含任何未授权字段值。
    """
    fields: dict[str, Any] = {}
    evidence: dict[str, list[str]] = {}
    for name in FIELD_CATALOG:
        decision = verdict["fields"][name]
        if decision["allowed"]:
            fields[name] = conn.field_value(name)
            evidence[name] = decision["evidence"]
    return {"seq": seq, "fields": fields, "evidence": evidence}


def _stream_artifact(
    input_path: str | Path,
    engine: PolicyEngine,
    receiver_zone: str,
    final_path: Path,
) -> tuple[str, str, int]:
    """单趟流式处理，返回 (输入摘要, 产物摘要, 记录数)。

    每行输入只解析一次：其规范字节累积进输入摘要，裁定获准的记录
    累积进产物摘要。全程只保留单条连接在内存。
    """
    partial_path = final_path.with_suffix(final_path.suffix + ".partial")
    input_digest = hashlib.sha256()
    artifact_digest = hashlib.sha256()
    record_count = 0
    seq = 0
    try:
        # newline="" 关闭 Windows 文本模式的 \n -> \r\n 转换，
        # 保证落盘字节与参与摘要的字节逐字节一致
        with open(partial_path, "w", encoding="utf-8", newline="") as fh:
            for conn, canonical in iter_connections_with_digest(input_path):
                input_digest.update(canonical)
                # 接收区视图只收录目的区等于接收区的连接
                if conn.dst_zone != receiver_zone:
                    continue
                verdict = engine.evaluate(conn)
                if verdict["denied"]:
                    continue
                if not allowed_fields(verdict):
                    continue
                seq += 1
                record = _build_record(conn, verdict, seq)
                line = dumps_canonical(record) + "\n"
                fh.write(line)
                artifact_digest.update(line.encode("utf-8"))
                record_count += 1
        # 不可变落地：替换后路径内容永不改变
        os.replace(partial_path, final_path)
    except BaseException:
        # 流式阶段任何失败都清理半成品，不留可被误读的文件
        for p in (partial_path, final_path):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    return input_digest.hexdigest(), artifact_digest.hexdigest(), record_count


def run_export(
    storage: Storage,
    workdir: str | Path,
    input_path: str | Path,
    receiver_zone: str,
    request_id: str,
    on_before_commit: Callable[[Storage, int], None] | None = None,
) -> dict[str, Any]:
    """执行一次导出请求，返回含 status 与 receipt 的结果字典。

    ``on_before_commit`` 仅用于测试：在产物写完、事务提交前注入动作
    （例如发布新一代策略），以验证代次竞态保护。
    """
    if not request_id or not isinstance(request_id, str):
        raise ValueError("request_id 必须为非空字符串")
    if not receiver_zone or not isinstance(receiver_zone, str):
        raise ValueError("receiver_zone 必须为非空字符串")

    # 重放/冲突快路径：仅在 request_id 已存在回执时才计算输入摘要，
    # 全新请求完全不做这一额外趟次（摘要在下方单趟内顺带产出）
    existing = storage.get_receipt(request_id)
    if existing is not None:
        input_digest = compute_input_digest(input_path)
        if existing["input_digest"] != input_digest:
            raise InputConflictError(
                request_id, existing["input_digest"], input_digest
            )
        if existing["receiver_zone"] != receiver_zone:
            raise InputConflictError(
                request_id, existing["input_digest"], input_digest
            )
        return {"status": STATUS_REPLAYED, "receipt": existing}

    # 绑定代次：整个快照读取在一个读事务内，看不到半批策略
    with storage.snapshot_transaction():
        bound_generation = storage.current_generation()
        events = storage.load_events_until(bound_generation)
        snapshot = build_snapshot(events, bound_generation)

    # 规则索引只构建一次，供整份连接流复用
    engine = PolicyEngine(snapshot)

    artifacts = _artifacts_dir(workdir)
    nonce = uuid.uuid4().hex
    final_path = artifacts / f"{request_id}.{nonce}.jsonl"

    # 单趟：输入摘要、裁定、产物摘要同时完成（每行只解析一次）
    input_digest, artifact_digest, record_count = _stream_artifact(
        input_path, engine, receiver_zone, final_path
    )

    # 测试注入点：模拟提交前另一会话发布了新代次
    if on_before_commit is not None:
        on_before_commit(storage, bound_generation)

    # 原子公布：同一事务核对代次 + 写回执
    conn = storage.conn
    conn.execute("BEGIN IMMEDIATE;")
    try:
        current = storage.current_generation()
        if current != bound_generation:
            conn.execute("ROLLBACK;")
            _safe_unlink(final_path)
            return {
                "status": STATUS_STALE,
                "bound_generation": bound_generation,
                "current_generation": current,
            }
        raced = storage.get_receipt(request_id)
        if raced is not None:
            conn.execute("ROLLBACK;")
            _safe_unlink(final_path)
            if raced["input_digest"] != input_digest:
                raise InputConflictError(
                    request_id, raced["input_digest"], input_digest
                )
            return {"status": STATUS_REPLAYED, "receipt": raced}

        receipt = {
            "request_id": request_id,
            "receiver_zone": receiver_zone,
            "input_digest": input_digest,
            "generation": bound_generation,
            "artifact_path": str(final_path),
            "artifact_digest": artifact_digest,
            "record_count": record_count,
            "published_at_us": now_micros(),
        }
        storage.insert_receipt(receipt)
        conn.execute("COMMIT;")
    except Exception:
        conn.execute("ROLLBACK;")
        _safe_unlink(final_path)
        raise

    return {"status": STATUS_PUBLISHED, "receipt": receipt}


def reconcile_artifacts(storage: Storage, workdir: str | Path) -> dict[str, int]:
    """故障恢复：删除任何没有回执指向的暂存/孤儿产物。

    回执公布前崩溃留下的 ``.partial`` 与不可变孤儿文件都在此回收；
    已公布产物因被回执引用而保留。返回删除/保留计数。
    """
    artifacts = _artifacts_dir(workdir)
    referenced = {Path(p).name for p in storage.list_artifact_paths()}
    removed = kept = 0
    for entry in artifacts.iterdir():
        if not entry.is_file():
            continue
        if entry.name.endswith(".partial") or entry.name not in referenced:
            _safe_unlink(entry)
            removed += 1
        else:
            kept += 1
    return {"removed": removed, "kept": kept}


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
