"""数据模型与输入校验：合成连接、策略事件、快照规则。

所有校验在入库/入快照前完成，存储层与引擎只接触已校验的结构。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from . import (
    DIRECTIONS,
    EVENT_APPROVAL,
    EVENT_REVOCATION,
    EVENT_TYPES,
    EXTRA_FIELDS,
    FIELD_CATALOG,
)
from .cidr import (
    IPv4Address,
    IpAddress,
    IpNetwork,
    parse_address,
    parse_network,
)
from .timeutil import parse_time

PROTOCOLS = ("TCP", "UDP", "ICMP")
PORT_MIN, PORT_MAX = 0, 65535


@dataclass(frozen=True)
class Connection:
    """一条不可变合成连接描述。"""

    connection_id: str
    event_time: str                 # 原始 ISO 8601 字符串
    src_zone: str
    dst_zone: str
    src_ip: str
    dst_ip: str
    protocol: str
    dst_port: int
    export_fields: dict[str, Any]  # 仅允许使用 FIELD_CATALOG 中的扩展字段
    event_time_us: int = field(compare=False)
    _src_addr: IpAddress = field(compare=False, repr=False)
    _dst_addr: IpAddress = field(compare=False, repr=False)
    _src_int: int = field(compare=False, repr=False, default=0)
    _dst_int: int = field(compare=False, repr=False, default=0)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Connection":
        if not isinstance(raw, dict):
            raise ValueError("连接记录必须为 JSON 对象")
        required = (
            "connection_id", "event_time", "src_zone", "dst_zone",
            "src_ip", "dst_ip", "protocol", "dst_port",
        )
        for key in required:
            if key not in raw:
                raise ValueError(f"连接缺少必填字段: {key}")
        # 热路径内联非空字符串校验，避免每条连接 7 次函数调用
        conn_id = raw["connection_id"]
        event_time = raw["event_time"]
        src_zone = raw["src_zone"]
        dst_zone = raw["dst_zone"]
        src_ip = raw["src_ip"]
        dst_ip = raw["dst_ip"]
        for name, value in (
            ("connection_id", conn_id), ("event_time", event_time),
            ("src_zone", src_zone), ("dst_zone", dst_zone),
            ("src_ip", src_ip), ("dst_ip", dst_ip),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} 必须为非空字符串")
        protocol = raw["protocol"]
        if not isinstance(protocol, str) or not protocol:
            raise ValueError("protocol 必须为非空字符串")
        protocol = protocol.upper()
        if protocol not in PROTOCOLS:
            raise ValueError(f"不支持的传输协议 {protocol!r}，允许: {PROTOCOLS}")
        dst_port = raw["dst_port"]
        if not isinstance(dst_port, int) or isinstance(dst_port, bool):
            raise ValueError("dst_port 必须为整数")
        if not PORT_MIN <= dst_port <= PORT_MAX:
            raise ValueError(f"dst_port 超出 0..65535: {dst_port}")
        if src_zone == dst_zone:
            raise ValueError(f"连接 {conn_id} 的源区与目的区相同: {src_zone}")

        src_addr = parse_address(src_ip)
        dst_addr = parse_address(dst_ip)
        # 同族五元组：IPv4 连 IPv4，IPv6 连 IPv6
        if type(src_addr) is not type(dst_addr):
            raise ValueError(f"连接 {conn_id} 源/目的 IP 族不一致")

        extras = raw.get("export_fields", {})
        if extras is None:
            extras = {}
        if not isinstance(extras, dict):
            raise ValueError("export_fields 必须为对象")
        for key in extras:
            if key not in EXTRA_FIELDS:
                raise ValueError(
                    f"连接 {conn_id} 含未知可导出字段 {key!r}，"
                    f"允许: {EXTRA_FIELDS}"
                )
        return cls(
            connection_id=conn_id,
            event_time=event_time,
            src_zone=src_zone,
            dst_zone=dst_zone,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            dst_port=dst_port,
            export_fields=dict(extras),
            event_time_us=parse_time(event_time),
            _src_addr=src_addr,
            _dst_addr=dst_addr,
            _src_int=int(src_addr),
            _dst_int=int(dst_addr),
        )

    @property
    def src_addr(self) -> IpAddress:
        return self._src_addr

    @property
    def dst_addr(self) -> IpAddress:
        return self._dst_addr

    @property
    def src_int(self) -> int:
        """源地址整数形式（匹配热路径用，每条连接只算一次）。"""
        return self._src_int

    @property
    def dst_int(self) -> int:
        """目的地址整数形式（匹配热路径用，每条连接只算一次）。"""
        return self._dst_int

    @property
    def addr_family(self) -> int:
        """地址族：4 或 6（源/目的同族，取源即可）。"""
        return 4 if isinstance(self._src_addr, IPv4Address) else 6

    def field_value(self, name: str) -> Any:
        """读取字段值；基础字段来自五元组，扩展字段来自 export_fields。"""
        if name == "connection_id":
            return self.connection_id
        if name == "src_zone":
            return self.src_zone
        if name == "dst_zone":
            return self.dst_zone
        if name == "src_ip":
            return self.src_ip
        if name == "dst_ip":
            return self.dst_ip
        if name == "protocol":
            return self.protocol
        if name == "dst_port":
            return self.dst_port
        return self.export_fields.get(name)


@dataclass(frozen=True)
class Rule:
    """快照内的一条已折叠规则（审批的有效窗口可能已被撤回截断）。"""

    rule_id: str
    kind: str                       # approval / deny
    zone: str                       # 负责安全区
    direction: str                  # send / recv
    peer_zone: str                  # 对端安全区
    src_net: IpNetwork
    dst_net: IpNetwork
    protocol: str
    port_low: int
    port_high: int
    valid_from_us: int
    valid_until_us: int             # None 表示开放上界，这里用极大整数
    authority: str
    fields: frozenset[str]          # 审批允许导出的字段集合（deny 可为空集）
    revoked_by: str | None = None


@dataclass(frozen=True)
class Snapshot:
    """某一代次的不可变策略视图。"""

    generation: int
    approvals: tuple[Rule, ...]
    denies: tuple[Rule, ...]


def _require_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} 必须为非空字符串")
    return value


def validate_event(raw: dict[str, Any]) -> dict[str, Any]:
    """校验单条策略事件，返回规范化后的纯数据字典（可直接入库）。"""
    if not isinstance(raw, dict):
        raise ValueError("策略事件必须为 JSON 对象")
    event_type = raw.get("event_type")
    if event_type not in EVENT_TYPES:
        raise ValueError(f"event_type 非法: {event_type!r}，允许 {EVENT_TYPES}")
    event_id = _require_nonempty_str(raw.get("event_id"), "event_id")

    if event_type == EVENT_REVOCATION:
        target = _require_nonempty_str(raw.get("target_approval_id"),
                                       "target_approval_id")
        effective_from = _require_nonempty_str(
            raw.get("effective_from"), "effective_from"
        )
        return {
            "event_type": event_type,
            "event_id": event_id,
            "target_approval_id": target,
            "effective_from_us": parse_time(effective_from),
            "effective_from": effective_from,
        }

    # approval / deny 的公共结构
    for key in (
        "zone", "direction", "peer_zone", "src_cidr", "dst_cidr",
        "protocol", "port_low", "port_high", "valid_from", "valid_until",
        "authority",
    ):
        if key not in raw:
            raise ValueError(f"事件 {event_id} 缺少字段: {key}")
    direction = raw["direction"]
    if direction not in DIRECTIONS:
        raise ValueError(f"direction 非法: {direction!r}，允许 {DIRECTIONS}")
    zone = _require_nonempty_str(raw["zone"], "zone")
    peer_zone = _require_nonempty_str(raw["peer_zone"], "peer_zone")
    if zone == peer_zone:
        raise ValueError(f"事件 {event_id} 的 zone 与 peer_zone 相同")
    protocol = _require_nonempty_str(raw["protocol"], "protocol").upper()
    if protocol not in PROTOCOLS:
        raise ValueError(f"事件 {event_id} 协议非法: {protocol!r}")
    port_low = raw["port_low"]
    port_high = raw["port_high"]
    for port in (port_low, port_high):
        if not isinstance(port, int) or isinstance(port, bool):
            raise ValueError(f"事件 {event_id} 端口必须为整数")
        if not PORT_MIN <= port <= PORT_MAX:
            raise ValueError(f"事件 {event_id} 端口越界: {port}")
    if port_low > port_high:
        raise ValueError(f"事件 {event_id} port_low 大于 port_high")

    src_net = parse_network(raw["src_cidr"])
    dst_net = parse_network(raw["dst_cidr"])
    if type(src_net) is not type(dst_net):
        raise ValueError(f"事件 {event_id} 两侧 CIDR 必须同族")

    valid_from_us = parse_time(raw["valid_from"])
    valid_until_us = parse_time(raw["valid_until"])
    if valid_from_us >= valid_until_us:
        raise ValueError(
            f"事件 {event_id} 有效时间必须为非空半开区间 "
            "[valid_from, valid_until)"
        )
    authority = _require_nonempty_str(raw["authority"], "authority")

    fields: frozenset[str] = frozenset()
    if event_type == EVENT_APPROVAL:
        raw_fields = raw.get("fields")
        if not isinstance(raw_fields, list) or not raw_fields:
            raise ValueError(f"审批 {event_id} 必须给出非空 fields 列表")
        for name in raw_fields:
            if name not in FIELD_CATALOG:
                raise ValueError(
                    f"审批 {event_id} 含未知字段 {name!r}，允许 {FIELD_CATALOG}"
                )
        fields = frozenset(raw_fields)

    return {
        "event_type": event_type,
        "event_id": event_id,
        "zone": zone,
        "direction": direction,
        "peer_zone": peer_zone,
        "src_cidr": str(src_net),
        "dst_cidr": str(dst_net),
        "protocol": protocol,
        "port_low": port_low,
        "port_high": port_high,
        "valid_from_us": valid_from_us,
        "valid_until_us": valid_until_us,
        "valid_from": raw["valid_from"],
        "valid_until": raw["valid_until"],
        "authority": authority,
        "fields": sorted(fields),
    }


def rule_from_stored(event: dict[str, Any],
                     window_from_us: int,
                     window_until_us: int,
                     revoked_by: str | None = None) -> Rule:
    """把存储事件（连同可能被撤回截断后的窗口）转换为快照规则。"""
    if window_from_us >= window_until_us:
        raise ValueError("折叠后的有效窗口为空")
    return Rule(
        rule_id=event["event_id"],
        kind=event["event_type"],
        zone=event["zone"],
        direction=event["direction"],
        peer_zone=event["peer_zone"],
        src_net=parse_network(event["src_cidr"]),
        dst_net=parse_network(event["dst_cidr"]),
        protocol=event["protocol"],
        port_low=event["port_low"],
        port_high=event["port_high"],
        valid_from_us=window_from_us,
        valid_until_us=window_until_us,
        authority=event["authority"],
        fields=frozenset(event.get("fields", [])),
        revoked_by=revoked_by,
    )


def dumps_canonical(value: Any) -> str:
    """规范 JSON 文本：键排序、无多余空白、保留 Unicode。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
