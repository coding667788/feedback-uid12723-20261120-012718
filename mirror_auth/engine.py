"""授权判定引擎。

判定流程（对每条连接）：

1. 按连接方向把策略分为发送侧（zone=src_zone, direction=send）与
   接收侧（zone=dst_zone, direction=recv），并要求 peer_zone 对得上；
2. 两侧各自做地址（同族 CIDR）、协议、目的端口闭区间、事件时间
   半开区间匹配；
3. 任一侧命中显式拒绝 -> 整条连接禁止导出，记录排序首条拒绝；
4. 无拒绝时逐字段判定：必须同时存在一个发送审批与一个接收审批，
   两者都覆盖该字段、都在事件时间有效，且签发机构不同。
   逐字段枚举审批对，绝不把两侧审批拼接成整条连接的批准；
5. 固定基础字段（连接 ID、五元组各成员）与扩展字段受同一规则约束。
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from . import (
    DIRECTION_RECV,
    DIRECTION_SEND,
    EVENT_APPROVAL,
    EVENT_DENY,
    EVENT_REVOCATION,
    FIELD_CATALOG,
)
from .models import Connection, Rule, Snapshot, rule_from_stored

# explain 逐字段缺失原因
REASON_MISSING_SIDE = "missing_one_side_approval"
REASON_SAME_AUTHORITY = "authorities_not_independent"


def build_snapshot(events: list[dict[str, Any]], generation: int) -> Snapshot:
    """把截至某代次的原始事件折叠为不可变快照。

    撤回（revocation）引用一条审批，只从 ``effective_from`` 起去除其
    授权：被撤回审批的有效窗口被截断为
    ``[valid_from, min(valid_until, effective_from))``；多次撤回取最早。
    截断后窗口为空的审批不进入快照。旧代次查询因为只读取截至该代的
    事件，天然看不到之后的撤回，裁定保持忠实。
    """
    approvals: dict[str, dict[str, Any]] = {}
    revocations: list[dict[str, Any]] = []
    denies: list[dict[str, Any]] = []

    for event in events:
        etype = event["event_type"]
        if etype == EVENT_APPROVAL:
            approvals[event["event_id"]] = event
        elif etype == EVENT_DENY:
            denies.append(event)
        elif etype == EVENT_REVOCATION:
            revocations.append(event)

    # 审批 ID -> (最早撤回生效时间, 对应撤回事件 ID)
    # 同一审批被多次撤回时取最早生效点，并记录是哪条撤回事件导致截断
    revoke_at: dict[str, tuple[int, str]] = {}
    for rev in revocations:
        target = rev["target_approval_id"]
        ts = rev["effective_from_us"]
        if target not in revoke_at or ts < revoke_at[target][0]:
            revoke_at[target] = (ts, rev["event_id"])

    approval_rules: list[Rule] = []
    for approval in approvals.values():
        window_from = approval["valid_from_us"]
        window_until = approval["valid_until_us"]
        revoked_by = None
        if approval["event_id"] in revoke_at:
            cut, revoked_by = revoke_at[approval["event_id"]]
            window_until = min(window_until, cut)
        if window_from < window_until:
            approval_rules.append(
                rule_from_stored(approval, window_from, window_until, revoked_by)
            )

    deny_rules = [
        rule_from_stored(
            d, d["valid_from_us"], d["valid_until_us"]
        )
        for d in denies
    ]
    return Snapshot(
        generation=generation,
        approvals=tuple(approval_rules),
        denies=tuple(deny_rules),
    )


class _RuleIndex:
    """按 (zone, direction, peer_zone, protocol) 预分桶的轻量索引。

    策略数量远小于连接数量，分桶后每条连接只需扫描同族的少量规则。
    建索引时一次性把每个 CIDR 预算成整数区间 (low, high)，匹配热路径
    只做整数比较，全程不展开任何 CIDR 地址。
    """

    def __init__(self, rules: Iterable[Rule]):
        self._buckets: dict[tuple[str, str, str, str], list[tuple]] = defaultdict(list)
        for rule in rules:
            key = (rule.zone, rule.direction, rule.peer_zone, rule.protocol)
            entry = (
                rule,
                int(rule.src_net.network_address),
                int(rule.src_net.broadcast_address),
                int(rule.dst_net.network_address),
                int(rule.dst_net.broadcast_address),
                4 if rule.src_net.version == 4 else 6,
            )
            self._buckets[key].append(entry)
        # 桶内按规则 ID 排序，使证据配对可安全地提前终止于最小发送 ID
        for bucket in self._buckets.values():
            bucket.sort(key=lambda entry: entry[0].rule_id)

    def candidates(self, conn: Connection, side: str):
        if side == DIRECTION_SEND:
            key = (conn.src_zone, DIRECTION_SEND, conn.dst_zone, conn.protocol)
        else:
            key = (conn.dst_zone, DIRECTION_RECV, conn.src_zone, conn.protocol)
        return self._buckets.get(key, ())


def _entry_matches(entry, conn: Connection) -> bool:
    """索引条目的整数级快速匹配。"""
    (rule, src_low, src_high, dst_low, dst_high, family) = entry
    if family != conn.addr_family:
        return False
    if not (src_low <= conn.src_int <= src_high):
        return False
    if not (dst_low <= conn.dst_int <= dst_high):
        return False
    if not (rule.port_low <= conn.dst_port <= rule.port_high):
        return False
    if not (rule.valid_from_us <= conn.event_time_us < rule.valid_until_us):
        return False
    return True


def _matched_rules(index: _RuleIndex, conn: Connection, side: str) -> list[Rule]:
    return [entry[0] for entry in index.candidates(conn, side)
            if _entry_matches(entry, conn)]


def _first_deny(denies: list[Rule]) -> Rule | None:
    """排序首条显式拒绝：按规则 ID 字典序，保证输出确定性。"""
    return min(denies, key=lambda r: r.rule_id, default=None)


def evaluate_connection(snapshot: Snapshot, conn: Connection) -> dict[str, Any]:
    """对单条连接做完整裁定（便捷封装）。

    批量处理请直接构建一次 :class:`PolicyEngine` 并复用其索引，
    避免每条连接重复分桶。返回结构见 :meth:`PolicyEngine.evaluate`。
    """
    return PolicyEngine(snapshot).evaluate(conn)


class PolicyEngine:
    """持有快照级规则索引，可对连接流重复使用的裁定器。"""

    def __init__(self, snapshot: Snapshot):
        self.snapshot = snapshot
        self._approval_index = _RuleIndex(snapshot.approvals)
        self._deny_index = _RuleIndex(snapshot.denies)

    def evaluate(self, conn: Connection) -> dict[str, Any]:
        """对单条连接做完整裁定，返回结构化判定（不含任何实际字段值）。

        返回结构::

            {
              "connection_id": ...,
              "denied": bool,
              "first_deny": {...} | None,
              "fields": {
                  字段名: {"allowed": bool,
                           "evidence": [send_id, recv_id] | None,
                           "reason": "..." | None}
              }
            }
        """
        send_denies = _matched_rules(self._deny_index, conn, DIRECTION_SEND)
        recv_denies = _matched_rules(self._deny_index, conn, DIRECTION_RECV)
        all_denies = send_denies + recv_denies
        first_deny = _first_deny(all_denies)

        result: dict[str, Any] = {
            "connection_id": conn.connection_id,
            "denied": first_deny is not None,
            "first_deny": _deny_view(first_deny) if first_deny else None,
            "fields": {},
        }
        if first_deny is not None:
            # 显式拒绝优先：整条连接禁止导出，不再逐字段配对
            for name in FIELD_CATALOG:
                result["fields"][name] = {
                    "allowed": False,
                    "evidence": None,
                    "reason": "connection_explicitly_denied",
                }
            return result

        send_approvals = _matched_rules(
            self._approval_index, conn, DIRECTION_SEND
        )
        recv_approvals = _matched_rules(
            self._approval_index, conn, DIRECTION_RECV
        )

        # 按字段一次性归类匹配到的审批，避免对 12 个字段重复过滤
        send_by_field: dict[str, list[Rule]] = defaultdict(list)
        recv_by_field: dict[str, list[Rule]] = defaultdict(list)
        for rule in send_approvals:
            for name in rule.fields:
                send_by_field[name].append(rule)
        for rule in recv_approvals:
            for name in rule.fields:
                recv_by_field[name].append(rule)

        for name in FIELD_CATALOG:
            result["fields"][name] = _evaluate_field(
                name,
                send_by_field.get(name, ()),
                recv_by_field.get(name, ()),
            )
        return result


def _evaluate_field(
    name: str, send_approvals, recv_approvals
) -> dict[str, Any]:
    """逐字段枚举 (发送审批, 接收审批) 合法对。

    只在需要时枚举：先确定两侧是否都有覆盖审批，再找字典序最小的
    跨机构合法元组，不构造完整笛卡尔积列表。
    """
    if not send_approvals or not recv_approvals:
        return {
            "allowed": False,
            "evidence": None,
            "reason": REASON_MISSING_SIDE,
        }

    # 审批在索引中已按 rule_id 排序，故 send_approvals / recv_approvals
    # 均有序。字典序最小合法对 = 最小的、存在异机构接收的发送 ID，
    # 配该发送下最小的异机构接收 ID。
    best: tuple[str, str] | None = None
    for send in send_approvals:
        for recv in recv_approvals:
            if send.authority != recv.authority:
                best = (send.rule_id, recv.rule_id)
                break
        if best is not None:
            break

    if best is None:
        # 两侧审批都在，但覆盖该字段的审批全部来自同一机构
        return {
            "allowed": False,
            "evidence": None,
            "reason": REASON_SAME_AUTHORITY,
        }
    return {"allowed": True, "evidence": list(best), "reason": None}


def _deny_view(rule: Rule) -> dict[str, Any]:
    return {
        "rule_id": rule.rule_id,
        "side": rule.direction,
        "zone": rule.zone,
        "peer_zone": rule.peer_zone,
        "authority": rule.authority,
    }


def allowed_fields(verdict: dict[str, Any]) -> list[str]:
    """从裁定中按字段目录顺序取出获准字段。"""
    return [
        name
        for name in FIELD_CATALOG
        if verdict["fields"][name]["allowed"]
    ]
