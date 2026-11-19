"""CIDR 匹配：IPv4 与 IPv6 各自只匹配同族网络，不逐地址展开。

基于标准库 :mod:`ipaddress` 的网络对象做包含判断。连接侧地址在一次
查询内只解析一次并缓存；策略侧网络在构建快照时预解析，因此十万级
连接扫描时没有字符串反复解析或地址枚举开销。
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

#: 同族 (地址, 网络) 二元组的联合类型，仅用于文档提示
IpAddress = IPv4Address | IPv6Address
IpNetwork = IPv4Network | IPv6Network


@lru_cache(maxsize=4096)
def parse_network(value: str) -> IpNetwork:
    """解析 CIDR 字符串，禁止主机位被置位的歧义写法。

    策略事件数量有限且 CIDR 文本高度重复，进程级缓存让快照构建与
    参考实现都只在首次出现时付出解析成本（不展开任何地址）。
    """
    if not isinstance(value, str) or "/" not in value:
        raise ValueError(f"非法 CIDR（要求地址/前缀长度形式）: {value!r}")
    # strict=True：如 10.0.0.5/8 这类主机位非零的写法直接报错
    return ipaddress.ip_network(value.strip(), strict=True)


@lru_cache(maxsize=1_048_576)
def parse_address(value: str) -> IpAddress:
    """解析单个 IP 地址（IPv4/IPv6），返回标准库地址对象。

    缓存按地址文本键控：同一连接在多规则匹配中只解析一次，
    IPv6 的不同拼写经标准库归一后命中同一地址对象。
    """
    if not isinstance(value, str):
        raise ValueError(f"非法 IP 地址: {value!r}")
    return ipaddress.ip_address(value.strip())


def same_family(address: IpAddress, network: IpNetwork) -> bool:
    """地址与网络是否同属 IPv4 或同属 IPv6。"""
    return (
        isinstance(address, IPv4Address) and isinstance(network, IPv4Network)
    ) or (
        isinstance(address, IPv6Address) and isinstance(network, IPv6Network)
    )


def address_in_network(address: IpAddress, network: IpNetwork) -> bool:
    """同族包含判断；跨族（IPv4 地址 vs IPv6 网络等）一律不匹配。"""
    if not same_family(address, network):
        return False
    return address in network


def canonical_address(address: IpAddress) -> str:
    """地址的规范拼写（IPv6 压缩形式），用于等价拼写归一与摘要。"""
    return str(address)


def network_family(network: IpNetwork) -> int:
    """返回网络族：4 或 6。"""
    return 4 if isinstance(network, IPv4Network) else 6
