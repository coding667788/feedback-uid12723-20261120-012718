"""代次发布、原子性与快照隔离测试。"""

import sqlite3

from mirror_auth.models import validate_event
from mirror_auth.timeutil import now_micros

from .helpers import FixtureTestCase


def _approval(event_id, zone="zone-a", direction="send", peer="zone-b"):
    return validate_event({
        "event_type": "approval",
        "event_id": event_id,
        "zone": zone, "direction": direction, "peer_zone": peer,
        "src_cidr": "192.0.2.0/24", "dst_cidr": "203.0.113.0/24",
        "protocol": "TCP", "port_low": 443, "port_high": 8443,
        "valid_from": "2026-11-20T00:00:00Z",
        "valid_until": "2026-11-21T00:00:00Z",
        "authority": "auth-alpha",
        "fields": ["dst_port"],
    })


class GenerationTest(FixtureTestCase):

    def test_generations_monotonic_and_events_ordered(self):
        self.assertEqual(self.generations, [1, 2, 3])
        with self.storage.snapshot_transaction():
            g1 = self.storage.load_events_until(1)
            g2 = self.storage.load_events_until(2)
        self.assertEqual(len(g1), 7)
        self.assertEqual(len(g2), 10)
        gen2_meta = self.storage.generation_meta(2)
        self.assertEqual(gen2_meta["generation"], 2)

    def test_duplicate_event_id_rejected_atomically(self):
        events = [_approval("dup-id"), _approval("dup-id")]
        with self.assertRaises(ValueError):
            self.storage.publish_generation(events, "d", now_micros())
        # 失败后没有残留代次
        self.assertEqual(self.storage.current_generation(), 3)

    def test_cross_batch_duplicate_event_id_rejected(self):
        with self.assertRaises(ValueError):
            self.storage.publish_generation(
                [_approval("g1-ap-a-send-b-v4")], "d", now_micros()
            )
        self.assertEqual(self.storage.current_generation(), 3)

    def test_empty_batch_rejected(self):
        with self.assertRaises(ValueError):
            self.storage.publish_generation([], "d", now_micros())

    def test_revocation_dangling_target_rejected(self):
        revocation = validate_event({
            "event_type": "revocation",
            "event_id": "rv-ghost",
            "target_approval_id": "no-such-approval",
            "effective_from": "2026-11-20T12:00:00Z",
        })
        with self.assertRaises(ValueError):
            self.storage.publish_generation([revocation], "d", now_micros())
        # 失败批次未产生新一代
        self.assertEqual(self.storage.current_generation(), 3)

    def test_revocation_forward_reference_within_batch_allowed(self):
        # 撤回排在审批之前（同批前向引用）应在整批核对时通过
        revocation = validate_event({
            "event_type": "revocation",
            "event_id": "rv-fwd",
            "target_approval_id": "fwd-ap",
            "effective_from": "2026-11-20T12:00:00Z",
        })
        approval = _approval("fwd-ap")
        gen = self.storage.publish_generation(
            [revocation, approval], "d", now_micros()
        )
        self.assertEqual(gen, 4)

    def test_publish_inside_other_connection_visible_after_commit(self):
        other = sqlite3.connect(str(self.db_path))
        try:
            self.storage.publish_generation(
                [_approval("late-event", zone="zone-c", peer="zone-a")],
                "late", now_micros(),
            )
            other.execute("BEGIN;")
            gen = other.execute(
                "SELECT MAX(generation) AS g FROM generations"
            ).fetchone()[0]
            self.assertEqual(gen, 4)
            other.execute("COMMIT;")
        finally:
            other.close()
        self.assertEqual(self.storage.current_generation(), 4)

    def test_independent_reader_snapshot_isolation(self):
        """读者事务进行中，另一连接发布新代次不改变读者视图。"""
        reader = sqlite3.connect(str(self.db_path))
        writer = sqlite3.connect(str(self.db_path))
        try:
            reader.execute("PRAGMA journal_mode=WAL;")
            reader.execute("BEGIN;")
            count_before = reader.execute(
                "SELECT COUNT(*) AS c FROM policy_events"
            ).fetchone()[0]

            writer.execute("PRAGMA journal_mode=WAL;")
            writer.execute("BEGIN IMMEDIATE;")
            import json
            payload = json.dumps(validate_event({
                "event_type": "approval",
                "event_id": "isolated-late",
                "zone": "zone-c", "direction": "send", "peer_zone": "zone-a",
                "src_cidr": "198.51.100.0/24", "dst_cidr": "192.0.2.0/24",
                "protocol": "UDP", "port_low": 53, "port_high": 53,
                "valid_from": "2026-11-20T00:00:00Z",
                "valid_until": "2026-11-21T00:00:00Z",
                "authority": "auth-charlie", "fields": ["dst_port"],
            }), sort_keys=True)
            writer.execute(
                "INSERT INTO generations(generation, published_at_us, "
                "event_count, batch_digest) VALUES (4, ?, 1, 'x')",
                (now_micros(),),
            )
            writer.execute(
                "INSERT INTO policy_events(event_id, generation, event_json, "
                "seq_in_batch) VALUES ('isolated-late', 4, ?, 0)",
                (payload,),
            )
            writer.execute("COMMIT;")

            count_during = reader.execute(
                "SELECT COUNT(*) AS c FROM policy_events"
            ).fetchone()[0]
            self.assertEqual(count_before, count_during)
            reader.execute("COMMIT;")

            reader.execute("BEGIN;")
            count_after = reader.execute(
                "SELECT COUNT(*) AS c FROM policy_events"
            ).fetchone()[0]
            self.assertEqual(count_after, count_before + 1)
            reader.execute("COMMIT;")
        finally:
            reader.close()
            writer.close()


if __name__ == "__main__":
    unittest.main()
