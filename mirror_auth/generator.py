"""合成输入生成器：连接描述与策略事件，全部为虚构数据。

地址只取自保留/文档网段：
* IPv4: 192.0.2.0/24、198.51.100.0/24、203.0.113.0/24（RFC 5737）
* IPv6: 2001:db8::/32（RFC 3849 文档前缀）
不访问网络、不解析真实地址。
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

ZONES = ("zone-a", "zone-b", "zone-c")
AUTHORITIES = ("auth-alpha", "auth-bravo", "auth-charlie")
BASE_TIME = "2026-11-20T00:00:00Z"
WINDOW_END = "2026-11-21T00:00:00Z"

_IPV4_POOLS = {
    "zone-a": ["192.0.2.{}", "198.51.100.{}"],
    "zone-b": ["203.0.113.{}"],
    "zone-c": ["198.51.100.{}"],
}
_IPV6_TEMPLATE = "2001:db8:{zone}::{host}"
_APP_HINTS = ("dns", "http", "ssh", "mtls", "unknown")
_PROTOCOL_PORTS = {"TCP": (443, 8443, 22), "UDP": (53, 123), "ICMP": (0,)}


# ------------------------------------------------------------ 连接生成
def generate_connections(count: int, seed: int) -> list[dict[str, Any]]:
    """生成 ``count`` 条确定性合成连接（同 seed 同结果）。"""
    rng = random.Random(seed)
    connections: list[dict[str, Any]] = []
    for idx in range(count):
        src_zone, dst_zone = rng.sample(ZONES, 2)
        use_v6 = rng.random() < 0.25
        if use_v6:
            src_ip = _IPV6_TEMPLATE.format(
                zone=src_zone[-1], host=format(rng.randint(1, 200), "x")
            )
            dst_ip = _IPV6_TEMPLATE.format(
                zone=dst_zone[-1], host=format(rng.randint(1, 200), "x")
            )
        else:
            src_ip = rng.choice(_IPV4_POOLS[src_zone]).format(rng.randint(1, 254))
            dst_ip = rng.choice(_IPV4_POOLS[dst_zone]).format(rng.randint(1, 254))
        protocol = rng.choice(("TCP", "TCP", "UDP", "ICMP"))
        dst_port = rng.choice(_PROTOCOL_PORTS[protocol])
        # 事件时间落在基准日的 0..23 点
        hour = rng.randint(0, 23)
        minute = rng.randint(0, 59)
        event_time = f"2026-11-20T{hour:02d}:{minute:02d}:00Z"
        record = {
            "connection_id": f"conn-{idx:06d}",
            "event_time": event_time,
            "src_zone": src_zone,
            "dst_zone": dst_zone,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "dst_port": dst_port,
            "export_fields": {
                "bytes_total": rng.randint(200, 10_000_000),
                "packets": rng.randint(1, 100_000),
                "duration_ms": rng.randint(1, 600_000),
                "app_hint": rng.choice(_APP_HINTS),
                "risk_score": rng.randint(0, 100),
            },
        }
        connections.append(record)
    return connections


# ------------------------------------------------------------ 随机策略
def generate_policy_batch(batch_no: int, seed: int) -> list[dict[str, Any]]:
    """生成一批随机但结构合法的策略事件（规模测试用）。"""
    rng = random.Random(seed * 100 + batch_no)
    events: list[dict[str, Any]] = []
    prefix = f"gen{batch_no}"
    for idx, zone in enumerate(ZONES):
        peer = ZONES[(idx + 1) % len(ZONES)]
        authority = AUTHORITIES[idx]
        for direction in ("send", "recv"):
            for family, src_cidr, dst_cidr in (
                ("v4", "0.0.0.0/0", "0.0.0.0/0"),
                ("v6", "::/0", "::/0"),
            ):
                port_low = rng.choice((0, 22, 443))
                port_high = 65535 if port_low == 0 else rng.choice((443, 8443))
                if port_low > port_high:
                    port_low, port_high = port_high, port_low
                events.append({
                    "event_type": "approval",
                    "event_id": f"{prefix}-ap-{zone}-{direction}-{family}-{idx}",
                    "zone": zone,
                    "direction": direction,
                    "peer_zone": peer,
                    "src_cidr": src_cidr,
                    "dst_cidr": dst_cidr,
                    "protocol": "TCP",
                    "port_low": port_low,
                    "port_high": port_high,
                    "valid_from": BASE_TIME,
                    "valid_until": WINDOW_END,
                    "authority": authority,
                    "fields": [
                        "connection_id", "src_zone", "dst_zone",
                        "src_ip", "dst_ip", "protocol", "dst_port",
                        "bytes_total", "risk_score",
                    ],
                })
    return events


# ------------------------------------------------------------ 手工演示夹具
def crafted_connections() -> list[dict[str, Any]]:
    """小样本连接集，覆盖各测试主题（与 crafted_policy_batches 配套）。"""
    base = {
        "export_fields": {
            "bytes_total": 12345,
            "packets": 67,
            "duration_ms": 890,
            "app_hint": "mtls",
            "risk_score": 12,
        }
    }

    def conn(cid, time, sz, dz, sip, dip, proto, port):
        record = dict(base)
        record.update({
            "connection_id": cid,
            "event_time": time,
            "src_zone": sz,
            "dst_zone": dz,
            "src_ip": sip,
            "dst_ip": dip,
            "protocol": proto,
            "dst_port": port,
            "export_fields": dict(base["export_fields"]),
        })
        return record

    return [
        # 1. 跨机构双审批 -> 基础字段与 risk_score 获准（gen2 补 risk_score）
        conn("c-allowed-01", "2026-11-20T10:00:00Z",
             "zone-a", "zone-b", "192.0.2.10", "203.0.113.10", "TCP", 443),
        # 2. 同机构控制两区 -> 全部字段不独立
        conn("c-same-auth-02", "2026-11-20T10:05:00Z",
             "zone-a", "zone-c", "192.0.2.20", "198.51.100.20", "TCP", 443),
        # 3. 窄前缀拒绝覆盖宽前缀审批 -> 整条拒绝
        conn("c-narrow-deny-03", "2026-11-20T11:00:00Z",
             "zone-a", "zone-b", "192.0.2.50", "203.0.113.50", "TCP", 443),
        # 4. 倒向流 b->a 有独立规则
        conn("c-reverse-04", "2026-11-20T12:00:00Z",
             "zone-b", "zone-a", "203.0.113.77", "192.0.2.77", "TCP", 8443),
        # 5. 端口下边界外（21 < 443）
        conn("c-port-low-05", "2026-11-20T10:00:00Z",
             "zone-a", "zone-b", "192.0.2.11", "203.0.113.11", "TCP", 21),
        # 6. 端口上边界外（8444 > 8443）
        conn("c-port-high-06", "2026-11-20T10:00:00Z",
             "zone-a", "zone-b", "192.0.2.12", "203.0.113.12", "TCP", 8444),
        # 7. 端口恰在上边界（闭区间，命中）
        conn("c-port-edge-07", "2026-11-20T10:00:00Z",
             "zone-a", "zone-b", "192.0.2.13", "203.0.113.13", "TCP", 8443),
        # 8. 时间下边界（半开，含起点）
        conn("c-time-start-08", "2026-11-20T00:00:00Z",
             "zone-a", "zone-b", "192.0.2.14", "203.0.113.14", "TCP", 443),
        # 9. 时间上边界（半开，不含终点 -> 无有效策略）
        conn("c-time-end-09", "2026-11-21T00:00:00Z",
             "zone-a", "zone-b", "192.0.2.15", "203.0.113.15", "TCP", 443),
        # 10. IPv6 等价拼写：完整拼写与压缩拼写必须同判
        conn("c-v6-full-10", "2026-11-20T09:00:00Z",
             "zone-a", "zone-b",
             "2001:0db8:0000:0000:0000:0000:0000:000a",
             "2001:0db8:0000:0000:0000:0000:0000:000b",
             "TCP", 443),
        conn("c-v6-compact-11", "2026-11-20T09:05:00Z",
             "zone-a", "zone-b", "2001:db8::a", "2001:db8::b", "TCP", 443),
        # 11. gen3 撤回后：时间在撤回生效点之后，审批窗口被截断 -> 缺审批
        conn("c-revoked-12", "2026-11-20T18:00:00Z",
             "zone-a", "zone-b", "192.0.2.30", "203.0.113.30", "TCP", 443),
        # 12. 撤回点之前，仍在截断窗口内 -> 与 c-allowed-01 同判
        conn("c-before-revoke-13", "2026-11-20T06:00:00Z",
             "zone-a", "zone-b", "192.0.2.31", "203.0.113.31", "TCP", 443),
    ]


def crafted_policy_batches() -> list[list[dict[str, Any]]]:
    """三个代次的手工策略批次，覆盖任务要求的全部判定主题。"""
    all_fields = [
        "connection_id", "src_zone", "dst_zone", "src_ip", "dst_ip",
        "protocol", "dst_port", "bytes_total", "packets",
        "duration_ms", "app_hint", "risk_score",
    ]
    base_fields = [
        "connection_id", "src_zone", "dst_zone", "src_ip", "dst_ip",
        "protocol", "dst_port",
    ]

    gen1 = [
        # a->b：发送侧 auth-alpha 宽审批
        {
            "event_type": "approval", "event_id": "g1-ap-a-send-b-v4",
            "zone": "zone-a", "direction": "send", "peer_zone": "zone-b",
            "src_cidr": "192.0.2.0/24", "dst_cidr": "203.0.113.0/24",
            "protocol": "TCP", "port_low": 443, "port_high": 8443,
            "valid_from": BASE_TIME, "valid_until": WINDOW_END,
            "authority": "auth-alpha", "fields": all_fields,
        },
        # 接收侧 auth-bravo（机构不同 -> 合法对存在）
        {
            "event_type": "approval", "event_id": "g1-ap-b-recv-a-v4",
            "zone": "zone-b", "direction": "recv", "peer_zone": "zone-a",
            "src_cidr": "192.0.2.0/24", "dst_cidr": "203.0.113.0/24",
            "protocol": "TCP", "port_low": 443, "port_high": 8443,
            "valid_from": BASE_TIME, "valid_until": WINDOW_END,
            "authority": "auth-bravo", "fields": base_fields,
        },
        # a->c：两侧同属 auth-alpha（同机构控制两区）
        {
            "event_type": "approval", "event_id": "g1-ap-a-send-c-v4",
            "zone": "zone-a", "direction": "send", "peer_zone": "zone-c",
            "src_cidr": "192.0.2.0/24", "dst_cidr": "198.51.100.0/24",
            "protocol": "TCP", "port_low": 0, "port_high": 65535,
            "valid_from": BASE_TIME, "valid_until": WINDOW_END,
            "authority": "auth-alpha", "fields": all_fields,
        },
        {
            "event_type": "approval", "event_id": "g1-ap-c-recv-a-v4",
            "zone": "zone-c", "direction": "recv", "peer_zone": "zone-a",
            "src_cidr": "192.0.2.0/24", "dst_cidr": "198.51.100.0/24",
            "protocol": "TCP", "port_low": 0, "port_high": 65535,
            "valid_from": BASE_TIME, "valid_until": WINDOW_END,
            "authority": "auth-alpha", "fields": all_fields,
        },
        # 窄前缀显式拒绝（接收侧），覆盖上面的宽前缀审批
        {
            "event_type": "deny", "event_id": "g1-deny-b-recv-a-narrow",
            "zone": "zone-b", "direction": "recv", "peer_zone": "zone-a",
            "src_cidr": "192.0.2.48/30", "dst_cidr": "203.0.113.48/30",
            "protocol": "TCP", "port_low": 0, "port_high": 65535,
            "valid_from": BASE_TIME, "valid_until": WINDOW_END,
            "authority": "auth-bravo", "fields": [],
        },
        # IPv6 双审批（不同机构），2001:db8::/32 文档前缀
        {
            "event_type": "approval", "event_id": "g1-ap-a-send-b-v6",
            "zone": "zone-a", "direction": "send", "peer_zone": "zone-b",
            "src_cidr": "2001:db8::/32", "dst_cidr": "2001:db8::/32",
            "protocol": "TCP", "port_low": 443, "port_high": 443,
            "valid_from": BASE_TIME, "valid_until": WINDOW_END,
            "authority": "auth-alpha", "fields": base_fields,
        },
        {
            "event_type": "approval", "event_id": "g1-ap-b-recv-a-v6",
            "zone": "zone-b", "direction": "recv", "peer_zone": "zone-a",
            "src_cidr": "2001:db8::/32", "dst_cidr": "2001:db8::/32",
            "protocol": "TCP", "port_low": 443, "port_high": 443,
            "valid_from": BASE_TIME, "valid_until": WINDOW_END,
            "authority": "auth-bravo", "fields": base_fields,
        },
    ]

    gen2 = [
        # 接收侧补上 risk_score（只有跨机构组合才让该字段通过）
        {
            "event_type": "approval", "event_id": "g2-ap-b-recv-a-risk",
            "zone": "zone-b", "direction": "recv", "peer_zone": "zone-a",
            "src_cidr": "192.0.2.0/24", "dst_cidr": "203.0.113.0/24",
            "protocol": "TCP", "port_low": 443, "port_high": 8443,
            "valid_from": BASE_TIME, "valid_until": WINDOW_END,
            "authority": "auth-bravo", "fields": ["risk_score"],
        },
        # 倒向流 b->a 的独立规则（auth-bravo 发 / auth-alpha 收）
        {
            "event_type": "approval", "event_id": "g2-ap-b-send-a-v4",
            "zone": "zone-b", "direction": "send", "peer_zone": "zone-a",
            "src_cidr": "203.0.113.0/24", "dst_cidr": "192.0.2.0/24",
            "protocol": "TCP", "port_low": 8443, "port_high": 8443,
            "valid_from": BASE_TIME, "valid_until": WINDOW_END,
            "authority": "auth-bravo", "fields": base_fields,
        },
        {
            "event_type": "approval", "event_id": "g2-ap-a-recv-b-v4",
            "zone": "zone-a", "direction": "recv", "peer_zone": "zone-b",
            "src_cidr": "203.0.113.0/24", "dst_cidr": "192.0.2.0/24",
            "protocol": "TCP", "port_low": 8443, "port_high": 8443,
            "valid_from": BASE_TIME, "valid_until": WINDOW_END,
            "authority": "auth-alpha", "fields": base_fields,
        },
    ]

    gen3 = [
        # 撤回 a->b 发送侧审批，自 12:00 起去除授权（窗口截断为 [00:00,12:00)）
        {
            "event_type": "revocation", "event_id": "g3-rv-a-send-b-v4",
            "target_approval_id": "g1-ap-a-send-b-v4",
            "effective_from": "2026-11-20T12:00:00Z",
        },
    ]
    return [gen1, gen2, gen3]


def write_jsonl(path: str | Path, records: list[dict[str, Any]]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            fh.write("\n")
