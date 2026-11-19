"""export/verify 全流程测试。"""

import json
from pathlib import Path

from mirror_auth.engine import evaluate_connection
from mirror_auth.export import (
    STATUS_PUBLISHED,
    STATUS_REPLAYED,
    STATUS_STALE,
    InputConflictError,
    reconcile_artifacts,
    run_export,
)
from mirror_auth.models import Connection, validate_event
from mirror_auth.timeutil import now_micros
from mirror_auth.verifier import VerificationError, verify_receipt

from .helpers import FixtureTestCase

RECEIVER = "zone-b"
REQUEST_ID = "req-001"


class ExportFlowTest(FixtureTestCase):

    def _publish_fresh_generation(self, storage, bound_generation):
        """注入用：在导出提交前发布新一代，制造代次竞态。"""
        event = validate_event({
            "event_type": "approval",
            "event_id": f"race-ap-{bound_generation}",
            "zone": "zone-c", "direction": "send", "peer_zone": "zone-a",
            "src_cidr": "198.51.100.0/24", "dst_cidr": "192.0.2.0/24",
            "protocol": "UDP", "port_low": 53, "port_high": 53,
            "valid_from": "2026-11-20T00:00:00Z",
            "valid_until": "2026-11-21T00:00:00Z",
            "authority": "auth-charlie", "fields": ["dst_port"],
        })
        storage.publish_generation([event], "race", now_micros())

    def test_export_publishes_receipt_and_minimal_records(self):
        result = run_export(
            self.storage, self.workdir, self.conn_path, RECEIVER, REQUEST_ID
        )
        self.assertEqual(result["status"], STATUS_PUBLISHED)
        receipt = result["receipt"]
        self.assertEqual(receipt["generation"], 3)
        self.assertTrue(Path(receipt["artifact_path"]).is_file())

        records = [
            json.loads(line)
            for line in Path(receipt["artifact_path"]).read_text(
                encoding="utf-8").splitlines()
        ]
        # 至少一个获准字段的连接才出现；被拒绝/零字段/非 zone-b 接收的都不出现
        ids = [r["fields"].get("connection_id") for r in records]
        self.assertIn("c-allowed-01", ids)
        self.assertNotIn("c-narrow-deny-03", ids)       # 显式拒绝
        self.assertNotIn("c-same-auth-02", ids)         # 目的区是 zone-c
        self.assertNotIn("c-revoked-12", ids)           # 撤回后无发送审批
        self.assertIn("c-before-revoke-13", ids)

        # 连接 ID 与五元组仅在字段获准时写入；记录内绝不出现未授权字段
        for record in records:
            self.assertTrue(record["fields"])
            self.assertEqual(set(record["fields"]), set(record["evidence"]))
            self.assertNotIn("packets", record["fields"])  # 接收侧从未批准
            for name, pair in record["evidence"].items():
                self.assertEqual(len(pair), 2)

    def test_receiver_zone_filtering(self):
        result = run_export(
            self.storage, self.workdir, self.conn_path,
            "zone-c", "req-zone-c",
        )
        records = [
            json.loads(line)
            for line in Path(result["receipt"]["artifact_path"]).read_text(
                encoding="utf-8").splitlines()
        ]
        # zone-c 接收的连接全部同机构 -> 没有任何获准字段 -> 空产物
        self.assertEqual(records, [])
        self.assertEqual(result["receipt"]["record_count"], 0)

    def test_replay_same_input_returns_same_receipt(self):
        first = run_export(
            self.storage, self.workdir, self.conn_path, RECEIVER, REQUEST_ID
        )
        second = run_export(
            self.storage, self.workdir, self.conn_path, RECEIVER, REQUEST_ID
        )
        self.assertEqual(second["status"], STATUS_REPLAYED)
        self.assertEqual(
            first["receipt"]["artifact_path"],
            second["receipt"]["artifact_path"],
        )
        self.assertEqual(
            first["receipt"]["artifact_digest"],
            second["receipt"]["artifact_digest"],
        )

    def test_same_request_id_changed_input_rejected(self):
        run_export(
            self.storage, self.workdir, self.conn_path, RECEIVER, REQUEST_ID
        )
        altered = self.tmp / "altered.jsonl"
        lines = self.conn_path.read_text(encoding="utf-8").splitlines()
        payload = json.loads(lines[0])
        payload["dst_port"] = 444
        altered.write_text(
            json.dumps(payload, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        with self.assertRaises(InputConflictError):
            run_export(
                self.storage, self.workdir, altered, RECEIVER, REQUEST_ID
            )
        # 冲突不产生第二条回执
        self.assertEqual(len(self.storage.list_receipts()), 1)

    def test_generation_change_before_commit_returns_stale(self):
        result = run_export(
            self.storage, self.workdir, self.conn_path, RECEIVER,
            "req-stale", on_before_commit=self._publish_fresh_generation,
        )
        self.assertEqual(result["status"], STATUS_STALE)
        self.assertEqual(result["bound_generation"], 3)
        self.assertEqual(result["current_generation"], 4)
        # 过时产物已丢弃，无回执
        self.assertIsNone(self.storage.get_receipt("req-stale"))
        artifacts = list((self.workdir / "artifacts").iterdir())
        self.assertEqual(artifacts, [])

    def test_crash_after_streaming_is_idempotently_recoverable(self):
        artifacts_dir = self.workdir / "artifacts"

        # 场景 1：流式完成、事务前崩溃 -> 留下孤儿不可变文件，无回执
        with self.assertRaises(RuntimeError):
            run_export(
                self.storage, self.workdir, self.conn_path, RECEIVER,
                "req-crash-1", on_before_commit=self._crash_hook,
            )
        self.assertIsNone(self.storage.get_receipt("req-crash-1"))
        orphans = list(artifacts_dir.iterdir())
        self.assertEqual(len(orphans), 1)
        self.assertFalse(orphans[0].name.endswith(".partial"))

        # 恢复清理后重放同一请求 -> 成功且只产生一份产物
        cleanup = reconcile_artifacts(self.storage, self.workdir)
        self.assertEqual(cleanup["removed"], 1)
        again = run_export(
            self.storage, self.workdir, self.conn_path, RECEIVER, "req-crash-1"
        )
        self.assertEqual(again["status"], STATUS_PUBLISHED)
        verify_receipt(self.storage, "req-crash-1", self.conn_path)
        # 场景 2：模拟写一半崩溃 -> 人造 .partial 残留；同时流式阶段
        # 已落地的不可变孤儿文件因事务未提交也无回执，两者都应被回收。
        workdir2 = self.tmp / "work2"
        workdir2.mkdir()
        artifacts_dir2 = workdir2 / "artifacts"

        def partial_crash(storage, bound):
            artifacts_dir2.mkdir(exist_ok=True)
            partial = artifacts_dir2 / "req-crash-2.abc.partial"
            partial.write_bytes(b'{"seq": 1}\n')
            raise RuntimeError("simulated mid-stream crash")

        with self.assertRaises(RuntimeError):
            run_export(
                self.storage, workdir2, self.conn_path, RECEIVER,
                "req-crash-2", on_before_commit=partial_crash,
            )
        leftovers = list(artifacts_dir2.iterdir())
        self.assertTrue(any(p.name.endswith(".partial") for p in leftovers))
        self.assertIsNone(self.storage.get_receipt("req-crash-2"))
        cleanup2 = reconcile_artifacts(self.storage, workdir2)
        self.assertEqual(cleanup2["removed"], len(leftovers))
        self.assertEqual(list(artifacts_dir2.iterdir()), [])
        replayed = run_export(
            self.storage, workdir2, self.conn_path, RECEIVER, "req-crash-2"
        )
        self.assertEqual(replayed["status"], STATUS_PUBLISHED)
        verify_receipt(self.storage, "req-crash-2", self.conn_path)

        # 幂等：对已成功请求做 recover 不删除已公布产物
        cleanup3 = reconcile_artifacts(self.storage, workdir2)
        self.assertEqual(cleanup3["removed"], 0)
        self.assertEqual(cleanup3["kept"], 1)

    @staticmethod
    def _crash_hook(storage, bound_generation):
        raise RuntimeError("simulated crash after staging, before commit")

    def test_verify_passes_and_detects_tampering(self):
        run_export(
            self.storage, self.workdir, self.conn_path, RECEIVER, REQUEST_ID
        )
        report = verify_receipt(self.storage, REQUEST_ID, self.conn_path)
        self.assertTrue(report["ok"])
        self.assertEqual(report["generation"], 3)

        receipt = self.storage.get_receipt(REQUEST_ID)
        artifact = Path(receipt["artifact_path"])

        # 篡改产物内容 -> 摘要核对失败（字节级操作，避免文本换行转换）
        original_bytes = artifact.read_bytes()
        tampered = original_bytes.replace(b'"seq":1', b'"seq":99', 1)
        self.assertNotEqual(tampered, original_bytes)
        artifact.write_bytes(tampered)
        with self.assertRaises(VerificationError):
            verify_receipt(self.storage, REQUEST_ID, self.conn_path)
        artifact.write_bytes(original_bytes)
        self.assertTrue(
            verify_receipt(self.storage, REQUEST_ID, self.conn_path)["ok"]
        )

        # 篡改输入 -> 输入摘要不一致
        altered = self.tmp / "altered.jsonl"
        original_lines = self.conn_path.read_text(
            encoding="utf-8").splitlines()
        payload = json.loads(original_lines[0])
        payload["export_fields"]["bytes_total"] += 1
        altered.write_bytes(
            (json.dumps(payload, ensure_ascii=False) + "\n"
             + "\n".join(original_lines[1:])).encode("utf-8")
        )
        with self.assertRaises(VerificationError):
            verify_receipt(self.storage, REQUEST_ID, altered)

    def test_artifact_records_match_engine_verdicts(self):
        result = run_export(
            self.storage, self.workdir, self.conn_path, RECEIVER, "req-check"
        )
        snapshot = self.snapshot_at(3)
        artifact = Path(result["receipt"]["artifact_path"])
        records = [
            json.loads(line)
            for line in artifact.read_text(encoding="utf-8").splitlines()
        ]
        by_id = {r["fields"]["connection_id"]: r for r in records}
        for raw in [json.loads(x) for x in
                    self.conn_path.read_text(encoding="utf-8").splitlines()]:
            if raw["dst_zone"] != RECEIVER:
                continue
            verdict = evaluate_connection(snapshot, Connection.from_dict(raw))
            allowed = [n for n, d in verdict["fields"].items() if d["allowed"]]
            if not allowed:
                self.assertNotIn(raw["connection_id"], by_id)
                continue
            record = by_id[raw["connection_id"]]
            self.assertEqual(set(record["fields"]), set(allowed))
            conn = Connection.from_dict(raw)
            for name in allowed:
                self.assertEqual(
                    record["fields"][name], conn.field_value(name)
                )
                self.assertEqual(
                    record["evidence"][name],
                    verdict["fields"][name]["evidence"],
                )

    def test_input_digest_contract(self):
        from mirror_auth.streaming import compute_input_digest

        # 同一文件复制 -> 摘要一致（重放绑定的是字节级输入）
        copy_path = self.tmp / "copy.jsonl"
        copy_path.write_bytes(self.conn_path.read_bytes())
        self.assertEqual(
            compute_input_digest(self.conn_path),
            compute_input_digest(copy_path),
        )

        # 仅排版变化（多余空行被逐行跳过）-> 摘要仍一致
        reformatted = self.tmp / "reformatted.jsonl"
        records = [
            json.loads(line)
            for line in self.conn_path.read_text(encoding="utf-8").splitlines()
        ]
        with open(reformatted, "w", encoding="utf-8", newline="") as fh:
            for record in records:
                fh.write(json.dumps(record, ensure_ascii=False))
                fh.write("\n\n")  # 空行被读取器跳过
        self.assertEqual(
            compute_input_digest(self.conn_path),
            compute_input_digest(reformatted),
        )

        # 任意字段值变化 -> 摘要必须不同
        altered = self.tmp / "digest-altered.jsonl"
        records[0]["export_fields"]["bytes_total"] += 1
        with open(altered, "w", encoding="utf-8", newline="") as fh:
            for record in records:
                fh.write(json.dumps(record, ensure_ascii=False))
                fh.write("\n")
        self.assertNotEqual(
            compute_input_digest(self.conn_path),
            compute_input_digest(altered),
        )


if __name__ == "__main__":
    unittest.main()
