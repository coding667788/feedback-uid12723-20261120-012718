"""引擎判定测试：覆盖任务要求的全部授权主题，并用独立参考实现交叉核对。"""

from __future__ import annotations

from mirror_auth import FIELD_CATALOG
from mirror_auth.engine import (
    REASON_MISSING_SIDE,
    REASON_SAME_AUTHORITY,
    build_snapshot,
    evaluate_connection,
)
from mirror_auth.models import Connection
from mirror_auth.reference import ReferenceEngine

from .helpers import FixtureTestCase


def _verdict(snapshot, raw_conn):
    return evaluate_connection(snapshot, Connection.from_dict(raw_conn))


class CraftedScenarioTest(FixtureTestCase):
    """演示夹具上的主题判定。"""

    def test_cross_authority_pair_allows_base_fields(self):
        snap = self.snapshot_at(1)
        v = _verdict(snap, self.conn_by_id("c-allowed-01"))
        self.assertFalse(v["denied"])
        base = ("connection_id", "src_zone", "dst_zone", "src_ip",
                "dst_ip", "protocol", "dst_port")
        for name in base:
            self.assertTrue(v["fields"][name]["allowed"], name)
            # 证据必须是发送审批在前、接收审批在后，且字典序最小
            self.assertEqual(
                v["fields"][name]["evidence"],
                ["g1-ap-a-send-b-v4", "g1-ap-b-recv-a-v4"],
            )
        # gen1 接收侧未覆盖 risk_score -> 该字段缺一侧审批
        self.assertFalse(v["fields"]["risk_score"]["allowed"])
        self.assertEqual(
            v["fields"]["risk_score"]["reason"], REASON_MISSING_SIDE
        )

    def test_same_authority_controls_both_zones(self):
        snap = self.snapshot_at(1)
        v = _verdict(snap, self.conn_by_id("c-same-auth-02"))
        self.assertFalse(v["denied"])
        for name in FIELD_CATALOG:
            self.assertFalse(v["fields"][name]["allowed"], name)
            self.assertEqual(
                v["fields"][name]["reason"], REASON_SAME_AUTHORITY
            )

    def test_field_only_passes_with_cross_authority_combo(self):
        # gen2 给接收侧补 risk_score（auth-bravo），与发送侧 auth-alpha 配对
        snap = self.snapshot_at(2)
        v = _verdict(snap, self.conn_by_id("c-allowed-01"))
        self.assertTrue(v["fields"]["risk_score"]["allowed"])
        self.assertEqual(
            v["fields"]["risk_score"]["evidence"],
            ["g1-ap-a-send-b-v4", "g2-ap-b-recv-a-risk"],
        )
        # gen1 下同字段仍不通过
        snap1 = self.snapshot_at(1)
        v1 = _verdict(snap1, self.conn_by_id("c-allowed-01"))
        self.assertFalse(v1["fields"]["risk_score"]["allowed"])

    def test_narrow_prefix_deny_overrides_wide_approval(self):
        snap = self.snapshot_at(2)
        v = _verdict(snap, self.conn_by_id("c-narrow-deny-03"))
        self.assertTrue(v["denied"])
        self.assertEqual(v["first_deny"]["rule_id"], "g1-deny-b-recv-a-narrow")
        self.assertEqual(v["first_deny"]["side"], "recv")
        # 显式拒绝时不再做字段配对
        self.assertTrue(
            all(not d["allowed"] for d in v["fields"].values())
        )

    def test_reverse_flow_has_separate_rules(self):
        snap = self.snapshot_at(1)
        v1 = _verdict(snap, self.conn_by_id("c-reverse-04"))
        # gen1 没有 b->a 规则 -> 全部缺一侧审批
        self.assertFalse(v1["denied"])
        self.assertTrue(
            all(
                not d["allowed"] and d["reason"] == REASON_MISSING_SIDE
                for d in v1["fields"].values()
            )
        )
        snap2 = self.snapshot_at(2)
        v2 = _verdict(snap2, self.conn_by_id("c-reverse-04"))
        base = ("connection_id", "src_zone", "dst_zone", "src_ip",
                "dst_ip", "protocol", "dst_port")
        for name in base:
            self.assertTrue(v2["fields"][name]["allowed"], name)
            self.assertEqual(
                v2["fields"][name]["evidence"],
                ["g2-ap-b-send-a-v4", "g2-ap-a-recv-b-v4"],
            )

    def test_port_closed_interval_both_boundaries(self):
        snap = self.snapshot_at(2)
        low = _verdict(snap, self.conn_by_id("c-port-low-05"))
        high = _verdict(snap, self.conn_by_id("c-port-high-06"))
        edge = _verdict(snap, self.conn_by_id("c-port-edge-07"))
        for v in (low, high):
            self.assertFalse(v["denied"])
            self.assertTrue(
                all(not d["allowed"] for d in v["fields"].values())
            )
        # 8443 恰好等于上界 -> 闭区间命中
        self.assertTrue(edge["fields"]["dst_port"]["allowed"])

    def test_time_half_open_double_boundary(self):
        snap = self.snapshot_at(2)
        at_start = _verdict(snap, self.conn_by_id("c-time-start-08"))
        at_end = _verdict(snap, self.conn_by_id("c-time-end-09"))
        self.assertTrue(at_start["fields"]["dst_port"]["allowed"])
        # 终点时刻不在 [from, until) 内 -> 无任何有效审批
        self.assertTrue(
            all(not d["allowed"] for d in at_end["fields"].values())
        )
        self.assertEqual(
            at_end["fields"]["dst_port"]["reason"], REASON_MISSING_SIDE
        )

    def test_ipv6_equivalent_spellings_same_verdict(self):
        snap = self.snapshot_at(2)
        full = _verdict(snap, self.conn_by_id("c-v6-full-10"))
        compact = _verdict(snap, self.conn_by_id("c-v6-compact-11"))
        self.assertEqual(full["denied"], compact["denied"])
        for name in FIELD_CATALOG:
            self.assertEqual(
                full["fields"][name]["allowed"],
                compact["fields"][name]["allowed"],
                name,
            )
        self.assertTrue(full["fields"]["src_ip"]["allowed"])

    def test_revocation_truncates_approval_window(self):
        # gen3 撤回 g1-ap-a-send-b-v4，自 12:00 起失效
        snap3 = self.snapshot_at(3)
        after = _verdict(snap3, self.conn_by_id("c-revoked-12"))   # 18:00
        before = _verdict(snap3, self.conn_by_id("c-before-revoke-13"))  # 06:00
        self.assertFalse(after["denied"])
        # 发送侧审批窗口已截断 -> 发送侧缺失
        self.assertEqual(
            after["fields"]["dst_port"]["reason"], REASON_MISSING_SIDE
        )
        self.assertTrue(before["fields"]["dst_port"]["allowed"])

        # 旧代次查询必须忠实：gen2 看不到撤回
        snap2 = self.snapshot_at(2)
        old = _verdict(snap2, self.conn_by_id("c-revoked-12"))
        self.assertTrue(old["fields"]["dst_port"]["allowed"])

    def test_lexicographically_smallest_evidence_tuple(self):
        # 再造一对覆盖相同连接的审批，验证证据取字典序最小元组
        extra = [{
            "event_type": "approval",
            "event_id": "g4-ap-a-send-b-alt",
            "zone": "zone-a", "direction": "send", "peer_zone": "zone-b",
            "src_cidr": "192.0.2.0/24", "dst_cidr": "203.0.113.0/24",
            "protocol": "TCP", "port_low": 443, "port_high": 8443,
            "valid_from": "2026-11-20T00:00:00Z",
            "valid_until": "2026-11-21T00:00:00Z",
            "authority": "auth-charlie",
            "fields": ["dst_port"],
        }, {
            "event_type": "approval",
            "event_id": "g4-ap-b-recv-a-alt",
            "zone": "zone-b", "direction": "recv", "peer_zone": "zone-a",
            "src_cidr": "192.0.2.0/24", "dst_cidr": "203.0.113.0/24",
            "protocol": "TCP", "port_low": 443, "port_high": 8443,
            "valid_from": "2026-11-20T00:00:00Z",
            "valid_until": "2026-11-21T00:00:00Z",
            "authority": "auth-charlie",
            "fields": ["dst_port"],
        }]
        from mirror_auth.models import validate_event
        from mirror_auth.timeutil import now_micros
        self.storage.publish_generation(
            [validate_event(e) for e in extra], "x", now_micros()
        )
        snap = self.snapshot_at(4)
        v = _verdict(snap, self.conn_by_id("c-allowed-01"))
        # 合法对若干，最小元组仍以 g1-* 开头
        self.assertEqual(
            v["fields"]["dst_port"]["evidence"],
            ["g1-ap-a-send-b-v4", "g1-ap-b-recv-a-v4"],
        )


class ReferenceCrossCheckTest(FixtureTestCase):
    """引擎与独立暴力参考实现在全部连接、全部代次上逐字段一致。"""

    def test_engine_matches_reference_on_every_generation(self):
        from mirror_auth.generator import crafted_connections
        from mirror_auth.models import dumps_canonical

        for gen in self.generations:
            with self.storage.snapshot_transaction():
                raw_events = self.storage.load_events_until(gen)
            snapshot = build_snapshot(raw_events, gen)
            reference = ReferenceEngine(raw_events)
            for raw_conn in crafted_connections():
                engine_v = evaluate_connection(
                    snapshot, Connection.from_dict(raw_conn)
                )
                ref_v = reference.decide(raw_conn)
                self.assertEqual(
                    dumps_canonical(engine_v["fields"]),
                    dumps_canonical(ref_v["fields"]),
                    f"gen={gen} conn={raw_conn['connection_id']}",
                )
                self.assertEqual(engine_v["denied"], ref_v["denied"])
                self.assertEqual(
                    engine_v["first_deny"], ref_v["first_deny"]
                )


class MixedBatchTest(FixtureTestCase):
    """同一批内追加审批与拒绝必须一起可见（无半批读取）。"""

    def test_approval_and_deny_in_same_batch(self):
        from mirror_auth.models import validate_event
        from mirror_auth.timeutil import now_micros

        batch = [{
            "event_type": "approval",
            "event_id": "mb-ap",
            "zone": "zone-a", "direction": "send", "peer_zone": "zone-b",
            "src_cidr": "192.0.2.0/24", "dst_cidr": "203.0.113.0/24",
            "protocol": "TCP", "port_low": 0, "port_high": 65535,
            "valid_from": "2026-11-20T00:00:00Z",
            "valid_until": "2026-11-21T00:00:00Z",
            "authority": "auth-alpha",
            "fields": ["dst_port"],
        }, {
            "event_type": "deny",
            "event_id": "mb-deny",
            "zone": "zone-b", "direction": "recv", "peer_zone": "zone-a",
            "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
            "protocol": "TCP", "port_low": 0, "port_high": 65535,
            "valid_from": "2026-11-20T00:00:00Z",
            "valid_until": "2026-11-21T00:00:00Z",
            "authority": "auth-bravo", "fields": [],
        }]
        gen = self.storage.publish_generation(
            [validate_event(e) for e in batch], "mb", now_micros()
        )
        snap = self.snapshot_at(gen)
        v = _verdict(snap, self.conn_by_id("c-allowed-01"))
        self.assertTrue(v["denied"])
        self.assertEqual(v["first_deny"]["rule_id"], "mb-deny")


if __name__ == "__main__":
    unittest.main()
