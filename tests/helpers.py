"""测试共享夹具：临时工作目录、三代策略发布、演示连接落盘。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mirror_auth.generator import (
    crafted_connections,
    crafted_policy_batches,
    write_jsonl,
)
from mirror_auth.models import validate_event
from mirror_auth.storage import Storage
from mirror_auth.timeutil import now_micros


class FixtureTestCase(unittest.TestCase):
    """每个用例独立临时目录与全新数据库。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.db_path = self.tmp / "policy.db"
        self.workdir = self.tmp / "work"
        self.workdir.mkdir()
        self.conn_path = self.tmp / "connections.jsonl"
        write_jsonl(self.conn_path, crafted_connections())
        self.storage = Storage(self.db_path)
        self.generations = self._publish_crafted()

    def tearDown(self) -> None:
        self.storage.close()
        self._tmp.cleanup()

    def _publish_crafted(self) -> list[int]:
        generations = []
        for batch in crafted_policy_batches():
            events = [validate_event(raw) for raw in batch]
            gen = self.storage.publish_generation(events, "test-digest", now_micros())
            generations.append(gen)
        return generations

    def conn_by_id(self, conn_id: str) -> dict:
        for raw in crafted_connections():
            if raw["connection_id"] == conn_id:
                return raw
        raise KeyError(conn_id)

    def snapshot_at(self, generation: int):
        from mirror_auth.engine import build_snapshot
        with self.storage.snapshot_transaction():
            events = self.storage.load_events_until(generation)
            return build_snapshot(events, generation)
