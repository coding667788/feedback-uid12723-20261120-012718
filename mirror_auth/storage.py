"""SQLite 存储层：策略代次、事件日志、导出回执。

并发与隔离策略：
* WAL 模式 + ``busy_timeout``，读写互不阻塞；
* 每一批策略在单个事务里提交，读者要么看到整代、要么看不到
  （事件表只随代次行一起可见，不存在半批状态）；
* 快照查询在单个只读事务（DEFERRED + 固定代次）内完成，
  读取期间即使其他连接发布新代次，本事务仍保持旧视图。
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import EVENT_APPROVAL, EVENT_REVOCATION

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS generations (
    generation  INTEGER PRIMARY KEY,
    published_at_us INTEGER NOT NULL,
    event_count INTEGER NOT NULL,
    batch_digest TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_events (
    event_id    TEXT PRIMARY KEY,
    generation  INTEGER NOT NULL REFERENCES generations(generation),
    event_json  TEXT NOT NULL,
    seq_in_batch INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policy_events_gen
    ON policy_events(generation);

CREATE TABLE IF NOT EXISTS export_receipts (
    request_id      TEXT PRIMARY KEY,
    receiver_zone   TEXT NOT NULL,
    input_digest    TEXT NOT NULL,
    generation      INTEGER NOT NULL,
    artifact_path   TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    record_count    INTEGER NOT NULL,
    published_at_us INTEGER NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('published'))
);
"""


class Storage:
    """封装数据库连接与所有持久化操作。"""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            isolation_level=None,       # 显式事务，杜绝驱动自动开始
            check_same_thread=False,
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=FULL;")
        self.conn.execute("PRAGMA busy_timeout=30000;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(_SCHEMA)
        row = self.conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO schema_meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        elif int(row["value"]) != SCHEMA_VERSION:
            raise RuntimeError(
                f"数据库 schema 版本 {row['value']} 与程序 {SCHEMA_VERSION} 不兼容"
            )

    def close(self) -> None:
        self.conn.close()

    # ---------------------------------------------------------------- 代次
    def current_generation(self) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(MAX(generation), 0) AS g FROM generations"
        ).fetchone()
        return int(row["g"])

    def publish_generation(
        self, events: list[dict[str, Any]], batch_digest: str, now_us: int
    ) -> int:
        """单事务原子发布一批事件，返回新代次号（从 1 单调递增）。"""
        if not events:
            raise ValueError("空策略批次不允许发布")
        ids = [e["event_id"] for e in events]
        if len(set(ids)) != len(ids):
            raise ValueError("同一批次内 event_id 重复")
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE;")
        try:
            dup = conn.execute(
                "SELECT event_id FROM policy_events WHERE event_id IN (%s)"
                % ",".join("?" * len(ids)),
                ids,
            ).fetchall()
            if dup:
                raise ValueError(
                    "event_id 已存在: " + ", ".join(r["event_id"] for r in dup)
                )

            # 撤回引用完整性：目标审批必须是已存在事件或本批审批。
            # 同批内允许前向引用（撤回排在审批之前），故合并两侧 ID 核对。
            batch_approval_ids = {
                e["event_id"] for e in events
                if e["event_type"] == EVENT_APPROVAL
            }
            revocations = [
                e for e in events if e["event_type"] == EVENT_REVOCATION
            ]
            if revocations:
                known_rows = conn.execute(
                    "SELECT event_id, event_json FROM policy_events"
                ).fetchall()
                known_approval_ids = {
                    r["event_id"] for r in known_rows
                    if json.loads(r["event_json"])["event_type"] == EVENT_APPROVAL
                } | batch_approval_ids
                dangling = [
                    e["target_approval_id"] for e in revocations
                    if e["target_approval_id"] not in known_approval_ids
                ]
                if dangling:
                    raise ValueError(
                        "撤回引用了不存在的审批: " + ", ".join(sorted(set(dangling)))
                    )

            gen = int(
                conn.execute(
                    "SELECT COALESCE(MAX(generation), 0) + 1 AS g FROM generations"
                ).fetchone()["g"]
            )
            conn.execute(
                "INSERT INTO generations(generation, published_at_us, "
                "event_count, batch_digest) VALUES (?, ?, ?, ?)",
                (gen, now_us, len(events), batch_digest),
            )
            conn.executemany(
                "INSERT INTO policy_events(event_id, generation, event_json, "
                "seq_in_batch) VALUES (?, ?, ?, ?)",
                [
                    (e["event_id"], gen, json.dumps(e, ensure_ascii=False, sort_keys=True), idx)
                    for idx, e in enumerate(events)
                ],
            )
            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        return gen

    @contextmanager
    def snapshot_transaction(self) -> Iterator[sqlite3.Connection]:
        """打开一个只读快照事务：提交前其他连接的写入对本事务不可见。"""
        conn = self.conn
        conn.execute("BEGIN;")  # DEFERRED：首次读时取 WAL 当前快照
        try:
            yield conn
        finally:
            conn.execute("COMMIT;")

    def load_events_until(self, generation: int | None = None) -> list[dict[str, Any]]:
        """加载截至指定代次（默认当前代次）的全部事件，按代次与批内序排列。

        必须在 :meth:`snapshot_transaction` 内调用，以保证读不到半批。
        """
        if generation is None:
            generation = self.current_generation()
        rows = self.conn.execute(
            "SELECT event_json FROM policy_events WHERE generation <= ? "
            "ORDER BY generation, seq_in_batch",
            (generation,),
        ).fetchall()
        return [json.loads(r["event_json"]) for r in rows]

    def generation_meta(self, generation: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM generations WHERE generation=?", (generation,)
        ).fetchone()
        return dict(row) if row else None

    # ---------------------------------------------------------------- 回执
    def get_receipt(self, request_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM export_receipts WHERE request_id=?", (request_id,)
        ).fetchone()
        return dict(row) if row else None

    def insert_receipt(self, receipt: dict[str, Any]) -> None:
        """在已开启的事务内插入回执（由 export 流程控制事务边界）。"""
        self.conn.execute(
            "INSERT INTO export_receipts(request_id, receiver_zone, input_digest, "
            "generation, artifact_path, artifact_digest, record_count, "
            "published_at_us, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'published')",
            (
                receipt["request_id"],
                receipt["receiver_zone"],
                receipt["input_digest"],
                receipt["generation"],
                receipt["artifact_path"],
                receipt["artifact_digest"],
                receipt["record_count"],
                receipt["published_at_us"],
            ),
        )

    def list_artifact_paths(self) -> set[str]:
        rows = self.conn.execute(
            "SELECT artifact_path FROM export_receipts"
        ).fetchall()
        return {r["artifact_path"] for r in rows}

    def list_receipts(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM export_receipts ORDER BY published_at_us"
        ).fetchall()
        return [dict(r) for r in rows]
