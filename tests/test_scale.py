"""十万连接规模测试：流式处理、内存上限、确定性与抽样参考核对。"""

import json
import tempfile
import tracemalloc
import unittest
from pathlib import Path

# 关键：tracemalloc 必须在被测模块导入前启动，否则解析器等对象的
# 首次分配不纳入跟踪，会得到虚假的“零峰值”
tracemalloc.start(25)

from mirror_auth import FIELD_CATALOG
from mirror_auth.engine import build_snapshot, evaluate_connection
from mirror_auth.export import run_export
from mirror_auth.generator import (
    AUTHORITIES,
    ZONES,
    generate_connections,
    write_jsonl,
)
from mirror_auth.models import Connection, validate_event
from mirror_auth.reference import ReferenceEngine
from mirror_auth.storage import Storage
from mirror_auth.timeutil import now_micros
from mirror_auth.verifier import verify_receipt

SCALE = 100_000
# 预热后稳态峰值上限：10 万连接与 1 万连接的峰值都应在 ~7MB 量级，
# 阈值 25MB 足以拦截“把全部连接/产物累积进内存”的实现回退
MEMORY_LIMIT_MB = 25
SAMPLE_SIZE = 200


def _broad_policy_batch():
    """覆盖所有有序区对的宽松双机构审批，保证规模数据中存在获准记录。"""
    events = []
    for zone in ZONES:
        for peer in ZONES:
            if zone == peer:
                continue
            for direction in ("send", "recv"):
                for family, cidr in (("v4", "0.0.0.0/0"), ("v6", "::/0")):
                    authority = AUTHORITIES[0] if direction == "send" \
                        else AUTHORITIES[1]
                    events.append(validate_event({
                        "event_type": "approval",
                        "event_id": f"scale-{zone}-{peer}-{direction}-{family}",
                        "zone": zone,
                        "direction": direction,
                        "peer_zone": peer,
                        "src_cidr": cidr,
                        "dst_cidr": cidr,
                        "protocol": "TCP",
                        "port_low": 0,
                        "port_high": 65535,
                        "valid_from": "2026-11-20T00:00:00Z",
                        "valid_until": "2026-11-21T00:00:00Z",
                        "authority": authority,
                        "fields": list(FIELD_CATALOG),
                    }))
    return events


class HundredThousandTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.db = self.base / "scale.db"
        self.workdir = self.base / "work"
        self.input_path = self.base / "connections-100k.jsonl"
        records = generate_connections(SCALE, seed=20261120)
        write_jsonl(self.input_path, records)
        self.storage = Storage(self.db)
        self.storage.publish_generation(
            _broad_policy_batch(), "scale-batch", now_micros()
        )

    def tearDown(self):
        self.storage.close()
        self.tmp.cleanup()

    def test_streaming_export_memory_and_determinism(self):
        # 模块导入前已启动 tracemalloc；这里重置峰值后完整跑一遍
        # 10 万连接导出。对照实验（10k vs 100k 同量级）证明驻留不随
        # 连接总量增长，峰值只取决于单条连接与策略快照规模。
        tracemalloc.reset_peak()
        result = run_export(
            self.storage, self.workdir, self.input_path,
            "zone-b", "scale-req-1",
        )
        _, peak = tracemalloc.get_traced_memory()
        peak_mb = peak / (1024 * 1024)
        print(f"\n[规模] {SCALE} 条连接导出稳态峰值内存: {peak_mb:.1f} MB")
        self.assertLess(
            peak_mb, MEMORY_LIMIT_MB,
            f"峰值内存 {peak_mb:.1f}MB 超过 {MEMORY_LIMIT_MB}MB，"
            "可能发生了全量载入",
        )
        self.assertEqual(result["status"], "published")
        receipt = result["receipt"]
        self.assertGreater(receipt["record_count"], 0)

        # 独立核对整份产物
        report = verify_receipt(
            self.storage, "scale-req-1", self.input_path
        )
        self.assertTrue(report["ok"])
        self.assertEqual(report["record_count"], receipt["record_count"])

        # 确定性：另一请求 ID 重跑，产物摘要必须一致
        second = run_export(
            self.storage, self.workdir, self.input_path,
            "zone-b", "scale-req-2",
        )
        self.assertEqual(
            receipt["artifact_digest"],
            second["receipt"]["artifact_digest"],
        )

    def test_engine_matches_reference_on_sample(self):
        """对确定性抽样的 200 条连接做引擎/参考实现逐字段交叉核对。"""
        with self.storage.snapshot_transaction():
            raw_events = self.storage.load_events_until(1)
        snapshot = build_snapshot(raw_events, 1)
        reference = ReferenceEngine(raw_events)

        sample_ids = {
            f"conn-{i:06d}"
            for i in range(0, SCALE, SCALE // SAMPLE_SIZE)
        }
        checked = 0
        for raw in (json.loads(line) for line in
                    self.input_path.read_text(encoding="utf-8").splitlines()):
            if raw["connection_id"] not in sample_ids:
                continue
            engine_v = evaluate_connection(snapshot, Connection.from_dict(raw))
            ref_v = reference.decide(raw)
            self.assertEqual(
                engine_v["denied"], ref_v["denied"], raw["connection_id"]
            )
            for name in FIELD_CATALOG:
                self.assertEqual(
                    engine_v["fields"][name],
                    ref_v["fields"][name],
                    f"{raw['connection_id']}::{name}",
                )
            checked += 1
        self.assertEqual(checked, len(sample_ids))


if __name__ == "__main__":
    unittest.main()
