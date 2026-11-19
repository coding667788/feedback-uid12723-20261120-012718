"""独立参考实现：用最直白的暴力枚举复算裁定，专供测试交叉核对。

与 :mod:`mirror_auth.engine` 刻意不共享匹配/折叠代码路径：
直接遍历原始事件字典、用 :mod:`ipaddress` 现算 CIDR 包含、
显式枚举每字段的全部审批对。速度不是目标，“显而易见的正确性”才是。
"""

from __future__ import annotations

import ipaddress
from typing import Any

from . import (
    DIRECTION_RECV,
    DIRECTION_SEND,
    EVENT_APPROVAL,
    EVENT_DENY,
    EVENT_REVOCATION,
    FIELD_CATALOG,
)
from .timeutil import parse_time


class ReferenceEngine:
    """对一批截至某代次的原始事件做无索引暴力裁定。"""

    def __init__(self, raw_events: list[dict[str, Any]]):
        self._approvals: dict[str, dict[str, Any]] = {}
        self._revoke_at: dict[str, int] = {}
        self._denies: list[dict[str, Any]] = []
        for event in raw_events:
            etype = event["event_type"]
            if etype == EVENT_APPROVAL:
                self._approvals[event["event_id"]] = dict(event)
            elif etype == EVENT_DENY:
                self._denies.append(dict(event))
            elif etype == EVENT_REVOCATION:
                target = event["target_approval_id"]
                ts = event["effective_from_us"]
                self._revoke_at[target] = min(self._revoke_at.get(target, ts), ts)

    # ------------------------------------------------------------ 匹配
    @staticmethod
    def _ip_in(ip_text: str, cidr_text: str) -> bool:
        addr = ipaddress.ip_address(ip_text)
        net = ipaddress.ip_network(cidr_text, strict=True)
        if addr.version != net.version:
            return False
        return addr in net

    def _rule_covers(self, rule: dict[str, Any], conn: dict[str, Any],
                     side: str) -> bool:
        """一条原始事件规则是否覆盖该连接的指定侧（send/recv）。"""
        if side == DIRECTION_SEND:
            if rule["zone"] != conn["src_zone"]:
                return False
            if rule["peer_zone"] != conn["dst_zone"]:
                return False
        else:
            if rule["zone"] != conn["dst_zone"]:
                return False
            if rule["peer_zone"] != conn["src_zone"]:
                return False
        if rule["direction"] != side:
            return False
        if rule["protocol"] != conn["protocol"]:
            return False
        if not self._ip_in(conn["src_ip"], rule["src_cidr"]):
            return False
        if not self._ip_in(conn["dst_ip"], rule["dst_cidr"]):
            return False
        if not (rule["port_low"] <= conn["dst_port"] <= rule["port_high"]):
            return False
        event_us = parse_time(conn["event_time"])
        from_us = rule["valid_from_us"]
        until_us = rule["valid_until_us"]
        # 撤回与方向无关：审批窗口统一截断到撤回生效点
        if rule["event_id"] in self._revoke_at:
            until_us = min(until_us, self._revoke_at[rule["event_id"]])
        if not (from_us <= event_us < until_us):
            return False
        return True

    def _live_approvals(self) -> list[dict[str, Any]]:
        """撤回后仍有非空有效窗口的审批（暴力版折叠）。"""
        live = []
        for rule in self._approvals.values():
            until = rule["valid_until_us"]
            if rule["event_id"] in self._revoke_at:
                until = min(until, self._revoke_at[rule["event_id"]])
            if rule["valid_from_us"] < until:
                live.append(rule)
        return live

    # ------------------------------------------------------------ 裁定
    def decide(self, conn: dict[str, Any]) -> dict[str, Any]:
        """返回与 engine.evaluate_connection 同构的裁定字典。"""
        hit_denies: list[dict[str, Any]] = []
        for deny in self._denies:
            for side in (DIRECTION_SEND, DIRECTION_RECV):
                if self._rule_covers(deny, conn, side):
                    hit_denies.append(deny)
        if hit_denies:
            first = min(hit_denies, key=lambda d: d["event_id"])
            return {
                "connection_id": conn["connection_id"],
                "denied": True,
                "first_deny": {
                    "rule_id": first["event_id"],
                    "side": first["direction"],
                    "zone": first["zone"],
                    "peer_zone": first["peer_zone"],
                    "authority": first["authority"],
                },
                "fields": {
                    name: {
                        "allowed": False,
                        "evidence": None,
                        "reason": "connection_explicitly_denied",
                    }
                    for name in FIELD_CATALOG
                },
            }

        live = self._live_approvals()
        send_rules = [r for r in live if self._rule_covers(r, conn, DIRECTION_SEND)]
        recv_rules = [r for r in live if self._rule_covers(r, conn, DIRECTION_RECV)]

        fields: dict[str, Any] = {}
        for name in FIELD_CATALOG:
            senders = [r for r in send_rules if name in r.get("fields", [])]
            receivers = [r for r in recv_rules if name in r.get("fields", [])]
            if not senders or not receivers:
                fields[name] = {
                    "allowed": False,
                    "evidence": None,
                    "reason": "missing_one_side_approval",
                }
                continue
            pairs = [
                (s["event_id"], r["event_id"])
                for s in senders
                for r in receivers
                if s["authority"] != r["authority"]
            ]
            if not pairs:
                fields[name] = {
                    "allowed": False,
                    "evidence": None,
                    "reason": "authorities_not_independent",
                }
            else:
                fields[name] = {
                    "allowed": True,
                    "evidence": list(min(pairs)),
                    "reason": None,
                }
        return {
            "connection_id": conn["connection_id"],
            "denied": False,
            "first_deny": None,
            "fields": fields,
        }
